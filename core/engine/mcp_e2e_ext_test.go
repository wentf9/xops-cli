package engine_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/playbook"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/internal/mcpruntime/protocol"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/ports"
)

func newEngineMCPRig(t *testing.T, threshold security.RiskLevel, autoApprove bool, httpChunk int64) (*fullSimRig, *engine.MCPServer) {
	t.Helper()
	clk := sim.NewSimClock(sim.DefaultBaseTime())
	rng := sim.NewSeededRand(20261127)
	auditClust := sim.NewSimAuditCluster()
	auditSink, err := auditClust.NewSinkFromEntropy(rng.Fork())
	if err != nil {
		t.Fatalf("NewSinkFromEntropy: %v", err)
	}
	scopedFS := sim.NewSimScopedRootFS(clk)
	remoteFS := sim.NewSimRemoteFS(clk)
	for _, dir := range []string{"/tmp", "/srv", "/work", "/stream", "/py"} {
		rp, _ := pathalg.ParseRemotePath(dir)
		if err := remoteFS.MkdirAll(context.Background(), rp, 0o755); err != nil {
			t.Fatalf("remoteFS.MkdirAll(%s): %v", dir, err)
		}
	}
	var emptyGraph inventory.Graph
	invStore, err := sim.NewSimInventoryStore(emptyGraph)
	if err != nil {
		t.Fatalf("NewSimInventoryStore: %v", err)
	}
	journalStore := sim.NewSimJournalStore()
	vault := sim.NewSimVault(rng.Fork())
	innerDialer := sim.NewSimDialer(clk, rng.Fork())
	dialer := &fullFacadeDialer{inner: innerDialer, remoteFS: remoteFS}

	transferRoot, _ := pathalg.ParseLocalDir("/mcp-e2e/transfers")
	artifactRoot, _ := pathalg.ParseLocalDir("/mcp-e2e/artifacts")
	if err := scopedFS.EnsureRoot(transferRoot, 0o700); err != nil {
		t.Fatalf("EnsureRoot transfer: %v", err)
	}
	if err := scopedFS.EnsureRoot(artifactRoot, 0o700); err != nil {
		t.Fatalf("EnsureRoot artifact: %v", err)
	}

	gCfg := engine.DefaultGuardrailConfig()
	gCfg.ApprovalThreshold = threshold
	gCfg.NoElicitFallback = engine.NoElicitFallbackChallenge

	var interact ports.InteractionPort
	if autoApprove {
		ip := sim.NewSimInteractionPort(true)
		ip.SetApprovalPolicy(security.VerdictAllow, nil, false)
		interact = ip
	}
	var zeroLocalID ports.LocalIdentityInfo
	var zeroProbe ports.ShellProbeResult

	eng, err := engine.New(engine.Config{
		Profile:             engine.PolicyProfileStrictAgent,
		Guardrail:           gCfg,
		Clock:               clk,
		Entropy:             rng.Fork(),
		AuditSink:           auditSink,
		Reconciler:          auditClust,
		Interaction:         interact,
		ScopedFS:            scopedFS,
		HostTrust:           sim.NewSimHostTrust(),
		Env:                 sim.NewSimEnvPort(map[string]string{"USER": "ops"}, zeroLocalID),
		Vault:               vault,
		VaultControl:        vault,
		InventoryStore:      invStore,
		JournalStore:        journalStore,
		Importers:           []ports.FormatImporter{sim.NewSimFormatImporter("csv")},
		PrivilegeEscalation: sim.NewSimPrivilegeEscalator(),
		ShellProbe:          sim.NewSimShellProbe(zeroProbe),
		Forwarder:           sim.NewSimForwarder(),
		TUNDevice:           sim.NewSimTUNDevicePort(),
		MuxSocket:           sim.NewSimMuxSocket(innerDialer),
		Dialer:              dialer,
	})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	mcpSrv, err := eng.NewMCPServer(engine.MCPConfig{
		TransferRoot:  algebraic.Some(transferRoot),
		ArtifactRoot:  algebraic.Some(artifactRoot),
		HTTPChunkSize: httpChunk,
	})
	if err != nil {
		_ = eng.Close(context.Background())
		t.Fatalf("NewMCPServer: %v", err)
	}
	rig := &fullSimRig{
		clk: clk, rng: rng, auditClust: auditClust, auditSink: auditSink,
		scopedFS: scopedFS, remoteFS: remoteFS, invStore: invStore,
		journalStore: journalStore, vault: vault, dialer: dialer,
		transferRoot: transferRoot, artifactRoot: artifactRoot, eng: eng,
	}
	return rig, mcpSrv
}

func callEngineMCPTool(t *testing.T, srv *engine.MCPServer, id int64, tool string, args map[string]any) (protocol.CallToolResult, map[string]any) {
	t.Helper()
	rawArgs, err := protocol.MarshalCanonical(args)
	if err != nil {
		t.Fatalf("MarshalCanonical args: %v", err)
	}
	rawReq, err := protocol.MarshalCanonical(map[string]any{
		"jsonrpc": "2.0", "id": id, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": jsontext.Value(rawArgs)},
	})
	if err != nil {
		t.Fatalf("MarshalCanonical req: %v", err)
	}
	respBytes, hasResp, err := srv.HandleMessage(context.Background(), rawReq)
	if err != nil || !hasResp {
		t.Fatalf("HandleMessage(%s): hasResp=%v err=%v", tool, hasResp, err)
	}
	var rpcResp protocol.Response
	if err := jsonv2.Unmarshal(respBytes, &rpcResp); err != nil {
		t.Fatalf("Unmarshal Response: %v", err)
	}
	if rpcResp.Error != nil {
		t.Fatalf("tools/call(%s) JSON-RPC error: %+v", tool, rpcResp.Error)
	}
	var res protocol.CallToolResult
	if err := jsonv2.Unmarshal(rpcResp.Result, &res); err != nil {
		t.Fatalf("Unmarshal CallToolResult: %v", err)
	}
	var body map[string]any
	if len(res.StructuredContent) > 0 {
		if err := jsonv2.Unmarshal(res.StructuredContent, &body); err != nil {
			t.Fatalf("Unmarshal StructuredContent: %v", err)
		}
	}
	return res, body
}

func TestEngineMCP_AllSevenToolsEndToEnd(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig, srv := newEngineMCPRig(t, security.RiskDangerous, true, 4096)
	defer rig.close(t)

	if _, err := srv.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	assertEngineMCPNodesAndExec(t, srv)
	assertEngineMCPPTYTool(t, srv)
	assertEngineMCPFileTool(t, srv)
	assertEngineMCPTransferTool(t, srv)
	assertEngineMCPTunnelTool(t, srv)
	assertEngineMCPGUITool(t, rig, srv)
}

func assertEngineMCPNodesAndExec(t *testing.T, srv *engine.MCPServer) {
	t.Helper()
	hID, _ := inventory.ParseHostID("h-mcp")
	ep, _ := netaddr.ParseEndpoint("10.20.0.1:22")
	hostObj, _ := inventory.NewHost(inventory.HostSpec{ID: hID, Endpoint: ep})
	if res, _ := callEngineMCPTool(t, srv, 1, protocol.ToolNameNodes, map[string]any{"action": "create_host", "host": hostObj}); res.IsError {
		t.Fatalf("nodes create_host: %s", res.StructuredContent)
	}
	idID, _ := inventory.ParseIdentityID("id-mcp")
	uOps, _ := option.ParseUsername("ops")
	authAg, _ := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	identObj, _ := inventory.NewIdentity(inventory.IdentitySpec{ID: idID, User: uOps, Auth: authAg})
	if res, _ := callEngineMCPTool(t, srv, 2, protocol.ToolNameNodes, map[string]any{"action": "create_identity", "identity": identObj}); res.IsError {
		t.Fatalf("nodes create_identity: %s", res.StructuredContent)
	}
	nID, _ := inventory.ParseNodeID("mcp-web")
	nodeObj, err := inventory.NewNode(inventory.NodeSpec{
		ID: nID, HostRef: hID, IdentityRef: idID, Origin: inventory.NewOriginManaged(),
	})
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if res, _ := callEngineMCPTool(t, srv, 3, protocol.ToolNameNodes, map[string]any{"action": "create_node", "node": nodeObj}); res.IsError {
		t.Fatalf("nodes create_node: %s", res.StructuredContent)
	}

	if res, body := callEngineMCPTool(t, srv, 10, protocol.ToolNameTerminalExec, map[string]any{
		"action": "exec", "target": "mcp-web", "command": "uname -s",
	}); res.IsError || !strings.Contains(fmt.Sprint(body["stdout"]), "ok:uname -s") {
		t.Fatalf("terminal_exec exec: isErr=%v body=%+v", res.IsError, body)
	}
	stID, _ := playbook.ParseStepID("s1")
	shAct, _ := playbook.NewStepShell(playbook.StepShellSpec{Command: "echo pb-mcp"})
	st, _ := playbook.NewStep(playbook.StepSpec{ID: stID, Name: "s1", Action: shAct})
	pbID, _ := playbook.ParsePlaybookID("pb-mcp")
	pbSel, _ := playbook.NewTargetSelector(playbook.TargetSelectorSpec{All: true})
	pb, _ := playbook.NewPlaybook(playbook.PlaybookSpec{
		Version: playbook.VersionV2, ID: pbID, Name: "pb-mcp", OnError: playbook.OnErrorFailFast,
		Target: pbSel, Steps: algebraic.NewNonEmpty(st),
	})
	for _, call := range []map[string]any{
		{"action": "exec_privileged", "target": "mcp-web", "command": "id", "privilege_method": "sudo", "non_interactive": true},
		{"action": "probe_shell", "target": "mcp-web"},
		{"action": "batch_exec", "targets": []string{"mcp-web"}, "command": "hostname"},
		{"action": "run_playbook", "targets": []string{"mcp-web"}, "playbook": pb},
	} {
		if res, _ := callEngineMCPTool(t, srv, 11, protocol.ToolNameTerminalExec, call); res.IsError {
			t.Fatalf("terminal_exec %v: %s", call["action"], res.StructuredContent)
		}
	}
}

func assertEngineMCPPTYTool(t *testing.T, srv *engine.MCPServer) {
	t.Helper()
	resOpen, openBody := callEngineMCPTool(t, srv, 20, protocol.ToolNameTerminalSession, map[string]any{
		"action": "open", "target": "mcp-web", "term": "xterm-256color", "cols": 120, "rows": 40,
	})
	if resOpen.IsError {
		t.Fatalf("terminal_session open: %s", resOpen.StructuredContent)
	}
	ptyTok, _ := openBody["handle_token"].(string)
	if res, _ := callEngineMCPTool(t, srv, 21, protocol.ToolNameTerminalSession, map[string]any{
		"action": "write", "handle_token": ptyTok, "data": "hello-mcp-pty\n",
	}); res.IsError {
		t.Fatalf("terminal_session write: %s", res.StructuredContent)
	}
	if res, rBody := callEngineMCPTool(t, srv, 22, protocol.ToolNameTerminalSession, map[string]any{
		"action": "read", "handle_token": ptyTok, "max_bytes": 512, "wait": true,
	}); res.IsError || !strings.Contains(fmt.Sprint(rBody["data"]), "pty:hello-mcp-pty") {
		t.Fatalf("terminal_session read: isErr=%v body=%+v", res.IsError, rBody)
	}
	for _, call := range []map[string]any{
		{"action": "resize", "handle_token": ptyTok, "cols": 140, "rows": 48},
		{"action": "signal", "handle_token": ptyTok, "signal": "INT"},
		{"action": "inspect", "handle_token": ptyTok},
		{"action": "close", "handle_token": ptyTok},
	} {
		if res, _ := callEngineMCPTool(t, srv, 23, protocol.ToolNameTerminalSession, call); res.IsError {
			t.Fatalf("terminal_session %v: %s", call["action"], res.StructuredContent)
		}
	}
}

func assertEngineMCPFileTool(t *testing.T, srv *engine.MCPServer) {
	t.Helper()
	for _, call := range []map[string]any{
		{"action": "mkdir", "target": "mcp-web", "path": "/work/sub", "perm": 0o755},
		{"action": "write", "target": "mcp-web", "path": "/work/sub/app.ini", "content": "env=dev\n"},
		{"action": "stat", "target": "mcp-web", "path": "/work/sub/app.ini"},
		{"action": "patch", "target": "mcp-web", "path": "/work/sub/app.ini", "edits": []map[string]any{{"old_text": "dev", "new_text": "prod"}}},
	} {
		if res, _ := callEngineMCPTool(t, srv, 30, protocol.ToolNameFile, call); res.IsError {
			t.Fatalf("file %v: %s", call["action"], res.StructuredContent)
		}
	}
	if res, body := callEngineMCPTool(t, srv, 31, protocol.ToolNameFile, map[string]any{
		"action": "read", "target": "mcp-web", "path": "/work/sub/app.ini",
	}); res.IsError || body["content"] != "env=prod\n" {
		t.Fatalf("file read: isErr=%v body=%+v", res.IsError, body)
	}
	for _, call := range []map[string]any{
		{"action": "list", "target": "mcp-web", "path": "/work/sub"},
		{"action": "rename", "target": "mcp-web", "old_path": "/work/sub/app.ini", "new_path": "/work/sub/app.bak"},
		{"action": "remove", "target": "mcp-web", "path": "/work/sub/app.bak"},
		{"action": "removedir", "target": "mcp-web", "path": "/work/sub"},
	} {
		if res, _ := callEngineMCPTool(t, srv, 32, protocol.ToolNameFile, call); res.IsError {
			t.Fatalf("file %v: %s", call["action"], res.StructuredContent)
		}
	}
}

func assertEngineMCPTransferTool(t *testing.T, srv *engine.MCPServer) {
	t.Helper()
	payload := []byte("mcp-transfer-payload-0123456789")
	dig := security.DigestBytes(payload)

	res, upBody := callEngineMCPTool(t, srv, 40, protocol.ToolNameTransfer, map[string]any{
		"action": "start", "target": "mcp-web", "direction": "upload",
		"remote_path": "/work/t.bin", "total_bytes": len(payload), "expected_digest": dig.String(),
	})
	if res.IsError {
		t.Fatalf("transfer start upload: %s", res.StructuredContent)
	}
	upTok, _ := upBody["handle_token"].(string)
	upTID, _ := upBody["transfer_id"].(string)
	if res, _ = callEngineMCPTool(t, srv, 41, protocol.ToolNameTransfer, map[string]any{
		"action": "chunk", "target": "mcp-web", "handle_token": upTok,
		"offset": 0, "data_b64": base64.StdEncoding.EncodeToString(payload),
	}); res.IsError {
		t.Fatalf("transfer chunk: %s", res.StructuredContent)
	}
	if res, _ = callEngineMCPTool(t, srv, 42, protocol.ToolNameTransfer, map[string]any{
		"action": "inspect", "target": "mcp-web", "transfer_id": upTID,
	}); res.IsError {
		t.Fatalf("transfer inspect: %s", res.StructuredContent)
	}
	if res, _ = callEngineMCPTool(t, srv, 43, protocol.ToolNameTransfer, map[string]any{
		"action": "commit", "target": "mcp-web", "handle_token": upTok,
	}); res.IsError {
		t.Fatalf("transfer commit upload: %s", res.StructuredContent)
	}

	// download
	res, dlBody := callEngineMCPTool(t, srv, 44, protocol.ToolNameTransfer, map[string]any{
		"action": "start", "target": "mcp-web", "direction": "download",
		"remote_path": "/work/t.bin", "local_dest": "dl/t.bin", "total_bytes": len(payload),
	})
	if res.IsError {
		t.Fatalf("transfer start download: %s", res.StructuredContent)
	}
	dlTok, _ := dlBody["handle_token"].(string)
	if res, _ = callEngineMCPTool(t, srv, 45, protocol.ToolNameTransfer, map[string]any{
		"action": "pull", "target": "mcp-web", "handle_token": dlTok, "max_chunk_bytes": 4096,
	}); res.IsError {
		t.Fatalf("transfer pull: %s", res.StructuredContent)
	}
	if res, _ = callEngineMCPTool(t, srv, 46, protocol.ToolNameTransfer, map[string]any{
		"action": "commit", "target": "mcp-web", "handle_token": dlTok,
	}); res.IsError {
		t.Fatalf("transfer commit download: %s", res.StructuredContent)
	}
}

func assertEngineMCPTunnelTool(t *testing.T, srv *engine.MCPServer) {
	t.Helper()
	res, fBody := callEngineMCPTool(t, srv, 50, protocol.ToolNameTunnel, map[string]any{
		"action": "start_forward", "target": "mcp-web", "direction": "local",
		"bind_kind": "tcp", "bind_addr": "127.0.0.1:0", "target_kind": "tcp", "target_addr": "10.20.0.1:8080",
	})
	if res.IsError {
		t.Fatalf("tunnel start_forward: %s", res.StructuredContent)
	}
	fTok, _ := fBody["handle_token"].(string)
	for _, act := range []string{"inspect_forward", "stop_forward"} {
		if r, _ := callEngineMCPTool(t, srv, 51, protocol.ToolNameTunnel, map[string]any{"action": act, "handle_token": fTok}); r.IsError {
			t.Fatalf("tunnel %s: %s", act, r.StructuredContent)
		}
	}

	res, mBody := callEngineMCPTool(t, srv, 52, protocol.ToolNameTunnel, map[string]any{
		"action": "start_mux", "target": "mcp-web", "socket_path": "/tmp/mcp-e2e-mux.sock",
		"control_master": "auto", "control_persist": "yes",
	})
	if res.IsError {
		t.Fatalf("tunnel start_mux: %s", res.StructuredContent)
	}
	mTok, _ := mBody["handle_token"].(string)
	for _, call := range []map[string]any{
		{"action": "inspect_mux", "handle_token": mTok},
		{"action": "probe_mux", "target": "mcp-web", "socket_path": "/tmp/mcp-e2e-mux.sock"},
		{"action": "control_mux", "target": "mcp-web", "socket_path": "/tmp/mcp-e2e-mux.sock", "mux_action": "check"},
		{"action": "stop_mux", "handle_token": mTok},
	} {
		if r, _ := callEngineMCPTool(t, srv, 53, protocol.ToolNameTunnel, call); r.IsError {
			t.Fatalf("tunnel %v: %s", call["action"], r.StructuredContent)
		}
	}
}

func assertEngineMCPGUITool(t *testing.T, rig *fullSimRig, srv *engine.MCPServer) {
	t.Helper()
	var pngBuf bytes.Buffer
	img := image.NewRGBA(image.Rect(0, 0, 64, 48))
	img.Set(0, 0, color.RGBA{R: 255, G: 120, B: 40, A: 255})
	if err := png.Encode(&pngBuf, img); err != nil {
		t.Fatalf("png.Encode: %v", err)
	}
	framed := "XOPS_GUI_SHOT_BEGIN_V2\n" + base64.StdEncoding.EncodeToString(pngBuf.Bytes()) + "\nXOPS_GUI_SHOT_END_V2\n"
	rig.dialer.mu.Lock()
	rig.dialer.onCmd = func(_ context.Context, _ execution.CommandPlan, stdout, _ io.Writer) (execution.ExecutionOutcome, error) {
		_, _ = io.WriteString(stdout, framed)
		return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	}
	rig.dialer.mu.Unlock()
	defer func() {
		rig.dialer.mu.Lock()
		rig.dialer.onCmd = nil
		rig.dialer.mu.Unlock()
	}()

	res, _ := callEngineMCPTool(t, srv, 60, protocol.ToolNameGUI, map[string]any{
		"action": "exec", "target": "mcp-web", "gui_action": "screenshot",
		"display": ":1", "artifact_file": "mcp-gui.png",
	})
	if res.IsError {
		t.Fatalf("gui exec screenshot: %s", res.StructuredContent)
	}
	hasImage := false
	for _, blk := range res.Content {
		if blk.Type == "image" && blk.Data != "" && blk.MIMEType != "" {
			hasImage = true
		}
	}
	if !hasImage {
		t.Fatalf("gui screenshot 缺少 image 内容块: %+v", res.Content)
	}

	res, gBody := callEngineMCPTool(t, srv, 61, protocol.ToolNameGUI, map[string]any{
		"action": "open_session", "target": "mcp-web", "session_kind": "x11", "display_num": 3,
	})
	if res.IsError {
		t.Fatalf("gui open_session: %s", res.StructuredContent)
	}
	gTok, _ := gBody["handle_token"].(string)
	for _, act := range []string{"inspect_session", "close_session"} {
		if r, _ := callEngineMCPTool(t, srv, 62, protocol.ToolNameGUI, map[string]any{"action": act, "handle_token": gTok}); r.IsError {
			t.Fatalf("gui %s: %s", act, r.StructuredContent)
		}
	}
}

func TestEngineMCP_StreamableHTTP10GiBStreamingTransfer(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig, srv := newEngineMCPRig(t, security.RiskDangerous, true, 4096)
	defer rig.close(t)

	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	baseURL := "http://" + ln.Addr().String()

	tr := &http.Transport{DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}

	srvCtx, stopSrv := context.WithCancel(context.Background())
	defer stopSrv()

	runErr := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if err := n.Go(func(_ context.Context) error { return srv.ServeHTTPListener(srvCtx, ln) }); err != nil {
			return err
		}
		return n.Go(func(_ context.Context) error {
			defer func() { _ = srv.Close(context.Background()) }()
			assertEngineHTTPTransferFlow(t, client, baseURL)
			return nil
		})
	})
	if runErr != nil {
		t.Fatalf("StreamableHTTP transfer run: %v", runErr)
	}
}

func assertEngineHTTPTransferFlow(t *testing.T, client *http.Client, baseURL string) {
	t.Helper()
	initReq, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"go-http","version":"1.0"}}}`))
	initReq.Header.Set("Content-Type", "application/json")
	initResp, err := client.Do(initReq)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	_ = initResp.Body.Close()
	sid := initResp.Header.Get("Mcp-Session-Id")
	if initResp.StatusCode != http.StatusOK || sid == "" {
		t.Fatalf("initialize failed: status=%d sid=%q", initResp.StatusCode, sid)
	}

	payload := make([]byte, 20*1024+123)
	for i := range payload {
		payload[i] = byte((i*31 + 17) % 251)
	}
	wantDigest := security.DigestBytes(payload)

	upStart := postEngineHTTPMCPTool(t, client, baseURL, sid, 10, protocol.ToolNameTransfer, map[string]any{
		"action": "start", "target": "ops@10.20.0.1:22", "direction": "upload",
		"remote_path": "/stream/big.bin", "total_bytes": len(payload), "expected_digest": wantDigest.String(),
	})
	upTid, _ := upStart["transfer_id"].(string)
	putReq, _ := http.NewRequest(http.MethodPut, baseURL+"/transfers/"+upTid+"/stream?commit=true", bytes.NewReader(payload))
	putReq.Header.Set("Mcp-Session-Id", sid)
	putResp, err := client.Do(putReq)
	if err != nil {
		t.Fatalf("PUT stream: %v", err)
	}
	putRaw, _ := io.ReadAll(putResp.Body)
	_ = putResp.Body.Close()
	if putResp.StatusCode != http.StatusOK {
		t.Fatalf("PUT stream status=%d body=%s", putResp.StatusCode, putRaw)
	}
	var upRes map[string]any
	if err := jsonv2.Unmarshal(putRaw, &upRes); err != nil || upRes["committed"] != true || upRes["actual_digest"] != wantDigest.String() {
		t.Fatalf("PUT commit mismatch: res=%+v err=%v", upRes, err)
	}

	// 上传越界返回 413
	overStart := postEngineHTTPMCPTool(t, client, baseURL, sid, 11, protocol.ToolNameTransfer, map[string]any{
		"action": "start", "target": "ops@10.20.0.1:22", "direction": "upload",
		"remote_path": "/stream/over.bin", "total_bytes": 16,
	})
	overTid, _ := overStart["transfer_id"].(string)
	overReq, _ := http.NewRequest(http.MethodPut, baseURL+"/transfers/"+overTid+"/stream", bytes.NewReader(make([]byte, 64)))
	overReq.Header.Set("Mcp-Session-Id", sid)
	overResp, err := client.Do(overReq)
	if err != nil {
		t.Fatalf("PUT overflow: %v", err)
	}
	_ = overResp.Body.Close()
	if overResp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("上传越界期望 413，实际=%d", overResp.StatusCode)
	}

	// 下载流校验 SHA-256 与逐字节一致
	dlStart := postEngineHTTPMCPTool(t, client, baseURL, sid, 12, protocol.ToolNameTransfer, map[string]any{
		"action": "start", "target": "ops@10.20.0.1:22", "direction": "download",
		"remote_path": "/stream/big.bin", "local_dest": "http-dl/big.bin", "total_bytes": len(payload),
	})
	dlTid, _ := dlStart["transfer_id"].(string)
	getReq, _ := http.NewRequest(http.MethodGet, baseURL+"/transfers/"+dlTid+"/stream", nil)
	getReq.Header.Set("Mcp-Session-Id", sid)
	getResp, err := client.Do(getReq)
	if err != nil {
		t.Fatalf("GET stream: %v", err)
	}
	got, _ := io.ReadAll(getResp.Body)
	_ = getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK || !bytes.Equal(got, payload) || getResp.Header.Get("X-Xops-Transfer-Digest") != wantDigest.String() {
		t.Fatalf("GET stream mismatch: status=%d len=%d digest=%q", getResp.StatusCode, len(got), getResp.Header.Get("X-Xops-Transfer-Digest"))
	}
}

func postEngineHTTPMCPTool(t *testing.T, client *http.Client, baseURL, sid string, id int64, tool string, args map[string]any) map[string]any {
	t.Helper()
	rawArgs, err := protocol.MarshalCanonical(args)
	if err != nil {
		t.Fatalf("MarshalCanonical args: %v", err)
	}
	rawReq, err := protocol.MarshalCanonical(map[string]any{
		"jsonrpc": "2.0", "id": id, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": jsontext.Value(rawArgs)},
	})
	if err != nil {
		t.Fatalf("MarshalCanonical req: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp", bytes.NewReader(rawReq))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Mcp-Session-Id", sid)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /mcp: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /mcp status=%d body=%s", resp.StatusCode, body)
	}
	var rpcResp protocol.Response
	if err := jsonv2.Unmarshal(body, &rpcResp); err != nil || rpcResp.Error != nil {
		t.Fatalf("rpcResp err=%v rpcErr=%+v", err, rpcResp.Error)
	}
	var res protocol.CallToolResult
	if err := jsonv2.Unmarshal(rpcResp.Result, &res); err != nil || res.IsError {
		t.Fatalf("CallToolResult err=%v isErr=%v content=%s", err, res.IsError, res.StructuredContent)
	}
	var out map[string]any
	if err := jsonv2.Unmarshal(res.StructuredContent, &out); err != nil {
		t.Fatalf("StructuredContent: %v", err)
	}
	return out
}

// findWorkingPython3 依次探测 PATH 中的 python3 / python 并实际运行主版本校验脚本，
// 规避 Windows 11 默认 Microsoft Store App Execution Alias 占位桩（LookPath 成功但执行返回 exit status 9009）。
func findWorkingPython3(ctx context.Context) (string, error) {
	var lastErr error
	for _, candidate := range []string{"python3", "python"} {
		binPath, err := exec.LookPath(candidate)
		if err != nil {
			lastErr = err
			continue
		}
		probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		probeErr := exec.CommandContext(
			probeCtx,
			binPath,
			"-c",
			"import sys; raise SystemExit(0 if sys.version_info.major == 3 else 1)",
		).Run()
		cancel()
		if probeErr != nil {
			lastErr = fmt.Errorf("%s 探针失败: %w", binPath, probeErr)
			continue
		}
		return binPath, nil
	}
	if lastErr == nil {
		lastErr = errors.New("未找到可用的 Python 3 解释器")
	}
	return "", lastErr
}

// TestEngineMCP_PythonClientInterop_StdioAndHTTP 使用本机独立 Python 3 进程分别通过
// 本地 stdio 管道与 127.0.0.1 回环 Streamable HTTP 端点与真实 Engine.NewMCPServer 互通（0 外部网络）；
// 若当前运行环境未安装可执行 Python 3（含 Win11 Store 占位桩）则仅跳过本 Python 子测，不影响全平台 Go 确定性测试。
func TestEngineMCP_PythonClientInterop_StdioAndHTTP(t *testing.T) {
	defer goleak.VerifyNone(t)
	pythonBin, err := findWorkingPython3(context.Background())
	if err != nil {
		t.Skipf("可执行 Python 3 不可用，跳过独立 Python MCP 客户端互通测试（Go 端全量测试已覆盖三平台）: %v", err)
	}

	t.Run("stdio_with_two_step_approval", func(t *testing.T) {
		runEnginePythonStdio(t, pythonBin)
	})
	t.Run("streamable_http_and_transfer_stream", func(t *testing.T) {
		runEnginePythonHTTP(t, pythonBin)
	})
}

func runEnginePythonStdio(t *testing.T, pythonBin string) {
	t.Helper()
	// autoApprove=false + ApprovalThreshold=RiskModerate：验证 Python 客户端完成真实两步审批挑战闭环！
	rig, srv := newEngineMCPRig(t, security.RiskModerate, false, 4096)
	defer rig.close(t)

	const pyStdio = `
import json, sys

def send(obj):
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()

def recv():
    line = sys.stdin.readline()
    assert line, "unexpected EOF from Go MCP server"
    return json.loads(line)

send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"py-stdio","version":"3.14"}}})
r1 = recv()
assert r1["result"]["protocolVersion"] == "2025-03-26", r1

send({"jsonrpc":"2.0","method":"notifications/initialized"})

send({"jsonrpc":"2.0","id":2,"method":"tools/list"})
r2 = recv()
names = [t["name"] for t in r2["result"]["tools"]]
assert names == ["nodes","terminal_exec","terminal_session","file","transfer","tunnel","gui"], names

# 1) 两步审批闭环：file write 首次触发 approval_required，回传审批信封后二次调用成功
write_args = {"action":"write","target":"ops@10.20.0.1:22","path":"/py/hello.txt","content":"from-python-stdio"}
send({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"file","arguments":write_args}})
r3 = recv()
sc3 = r3["result"]["structuredContent"]
assert r3["result"].get("isError") is True and sc3["code"] == "approval_required", r3
chal = sc3["approval_challenge"]

write_args_ok = dict(write_args)
write_args_ok["approval"] = {
    "verdict": "allow",
    "envelope_digest": chal["envelope_digest"],
    "envelope": chal["envelope"],
    "comment": "python-approved",
}
send({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"file","arguments":write_args_ok}})
r4 = recv()
assert not r4["result"].get("isError"), r4

# 2) file read 验证写入字节完全一致
send({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"file","arguments":{"action":"read","target":"ops@10.20.0.1:22","path":"/py/hello.txt"}}})
r5 = recv()
assert not r5["result"].get("isError") and r5["result"]["structuredContent"]["content"] == "from-python-stdio", r5

# 3) nodes 只读查询无需审批直接成功
send({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"nodes","arguments":{"action":"list_nodes"}}})
r6 = recv()
assert not r6["result"].get("isError"), r6
`

	cmd := exec.CommandContext(context.Background(), pythonBin, "-u", "-c", pyStdio)
	pyStdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	pyStdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	var pyStderr bytes.Buffer
	cmd.Stderr = &pyStderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start: %v", err)
	}

	runErr := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if err := n.Go(func(c context.Context) error {
			defer func() { _ = pyStdin.Close() }()
			return srv.ServeStdio(c, pyStdout, pyStdin)
		}); err != nil {
			return err
		}
		return n.Go(func(_ context.Context) error {
			if wErr := cmd.Wait(); wErr != nil {
				return fmt.Errorf("python stdio client 失败: %w; stderr=%s", wErr, pyStderr.String())
			}
			return nil
		})
	})
	if runErr != nil {
		t.Fatalf("Python stdio interop: %v", runErr)
	}
}

func runEnginePythonHTTP(t *testing.T, pythonBin string) {
	t.Helper()
	rig, srv := newEngineMCPRig(t, security.RiskDangerous, true, 4096)
	defer rig.close(t)

	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	baseURL := "http://" + ln.Addr().String()

	const pyHTTP = `
import hashlib, json, sys, urllib.request

base = sys.argv[1]

def post_mcp(payload, sid=None):
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", "Origin": "http://127.0.0.1"}
    if sid:
        headers["Mcp-Session-Id"] = sid
    req = urllib.request.Request(base + "/mcp", data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=15) as resp:
        assert resp.status == 200, resp.status
        return json.loads(resp.read().decode("utf-8")), resp.headers.get("Mcp-Session-Id")

r1, sid = post_mcp({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"py-http","version":"3.14"}}})
assert sid and r1["result"]["protocolVersion"] == "2025-03-26", (r1, sid)

r2, _ = post_mcp({"jsonrpc":"2.0","id":2,"method":"tools/list"}, sid)
assert len(r2["result"]["tools"]) == 7, r2

# 18 KiB 二进制流跨 5 个 4 KiB 分片经 HTTP PUT 流式上传并原子提交
payload = bytes([(i * 19 + 7) % 256 for i in range(18 * 1024 + 37)])
want_sha = "sha256:" + hashlib.sha256(payload).hexdigest()

r3, _ = post_mcp({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"transfer","arguments":{
    "action":"start","target":"ops@10.20.0.1:22","direction":"upload",
    "remote_path":"/py/stream.bin","total_bytes":len(payload),"expected_digest":want_sha,
}}}, sid)
tid_up = r3["result"]["structuredContent"]["transfer_id"]

put_req = urllib.request.Request(
    base + "/transfers/" + tid_up + "/stream?commit=true",
    data=payload,
    headers={"Mcp-Session-Id": sid, "Content-Type": "application/octet-stream"},
    method="PUT",
)
with urllib.request.urlopen(put_req, timeout=15) as resp:
    assert resp.status == 200, resp.status
    up_res = json.loads(resp.read().decode("utf-8"))
    assert up_res["committed"] is True and up_res["actual_digest"] == want_sha, up_res

# 启动下载并通过 HTTP GET 流式拉回并逐字节与 SHA-256 核验
r4, _ = post_mcp({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"transfer","arguments":{
    "action":"start","target":"ops@10.20.0.1:22","direction":"download",
    "remote_path":"/py/stream.bin","local_dest":"py-dl/stream.bin","total_bytes":len(payload),
}}}, sid)
tid_dl = r4["result"]["structuredContent"]["transfer_id"]

get_req = urllib.request.Request(base + "/transfers/" + tid_dl + "/stream", headers={"Mcp-Session-Id": sid}, method="GET")
with urllib.request.urlopen(get_req, timeout=15) as resp:
    assert resp.status == 200, resp.status
    got = resp.read()
    assert got == payload, (len(got), len(payload))
    assert resp.headers.get("X-Xops-Transfer-Digest") == want_sha, resp.headers

# 显式 DELETE /mcp 关闭会话
del_req = urllib.request.Request(base + "/mcp", headers={"Mcp-Session-Id": sid}, method="DELETE")
with urllib.request.urlopen(del_req, timeout=15) as resp:
    assert resp.status == 204, resp.status
`

	srvCtx, stopSrv := context.WithCancel(context.Background())
	defer stopSrv()

	runErr := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if err := n.Go(func(_ context.Context) error { return srv.ServeHTTPListener(srvCtx, ln) }); err != nil {
			return err
		}
		return n.Go(func(_ context.Context) error {
			defer func() { _ = srv.Close(context.Background()) }()
			cmd := exec.CommandContext(context.Background(), pythonBin, "-u", "-c", pyHTTP, baseURL)
			out, cErr := cmd.CombinedOutput()
			if cErr != nil {
				return fmt.Errorf("python HTTP client 失败: %w; output=%s", cErr, string(out))
			}
			return nil
		})
	})
	if runErr != nil {
		t.Fatalf("Python Streamable HTTP interop: %v", runErr)
	}
}
