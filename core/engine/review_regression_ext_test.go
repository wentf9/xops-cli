package engine_test

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
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
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/internal/mcpruntime/protocol"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/ports"
)

// faultInjectScopedFS 包装 SimScopedRootFS，在目标文件落盘提交后对下一次 WithRoot 注入写头前失败，
// 零借用逃逸（不封装 RootHandle），用于回归验证 HTTP 下载流在 ScopedRootFS 失败时绝不静默返回 200 OK 空体。
type faultInjectScopedFS struct {
	*sim.SimScopedRootFS
	mu           sync.Mutex
	failReadPath string
}

func (f *faultInjectScopedFS) setFailReadPath(p string) {
	f.mu.Lock()
	f.failReadPath = p
	f.mu.Unlock()
}

//xops:syncclosure
//xops:borrowed
func (f *faultInjectScopedFS) WithRoot(dir pathalg.LocalDir, fn func(root ports.RootHandle) error) error {
	f.mu.Lock()
	target := f.failReadPath
	f.mu.Unlock()
	if target != "" {
		dest, pErr := pathalg.ParseLocalRootedDest(target)
		if pErr == nil {
			exists := false
			_ = f.SimScopedRootFS.WithRoot(dir, func(root ports.RootHandle) error {
				if _, sErr := root.Stat(dest); sErr == nil {
					exists = true
				}
				return nil
			})
			if exists {
				return ports.ErrNotFound
			}
		}
	}
	return f.SimScopedRootFS.WithRoot(dir, func(root ports.RootHandle) error { return fn(root) })
}

func newApprovalHTTPRig(t *testing.T, httpChunk int64) (*fullSimRig, *engine.MCPServer, *faultInjectScopedFS) {
	t.Helper()
	clk := sim.NewSimClock(sim.DefaultBaseTime())
	rng := sim.NewSeededRand(20261128)
	auditClust := sim.NewSimAuditCluster()
	auditSink, err := auditClust.NewSinkFromEntropy(rng.Fork())
	if err != nil {
		t.Fatalf("NewSinkFromEntropy: %v", err)
	}
	baseFS := sim.NewSimScopedRootFS(clk)
	faultFS := &faultInjectScopedFS{SimScopedRootFS: baseFS}
	remoteFS := sim.NewSimRemoteFS(clk)
	for _, dir := range []string{"/tmp", "/srv", "/stream"} {
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
	vault := sim.NewUninitializedSimVault(rng.Fork())
	innerDialer := sim.NewSimDialer(clk, rng.Fork())
	dialer := &fullFacadeDialer{inner: innerDialer, remoteFS: remoteFS}

	transferRoot, _ := pathalg.ParseLocalDir("/mcp-approval/transfers")
	artifactRoot, _ := pathalg.ParseLocalDir("/mcp-approval/artifacts")
	if err := baseFS.EnsureRoot(transferRoot, 0o700); err != nil {
		t.Fatalf("EnsureRoot transfer: %v", err)
	}
	if err := baseFS.EnsureRoot(artifactRoot, 0o700); err != nil {
		t.Fatalf("EnsureRoot artifact: %v", err)
	}
	gCfg := engine.DefaultGuardrailConfig()
	gCfg.ApprovalThreshold = security.RiskModerate
	gCfg.NoElicitFallback = engine.NoElicitFallbackChallenge
	var zeroLocalID ports.LocalIdentityInfo
	var zeroProbe ports.ShellProbeResult
	eng, err := engine.New(engine.Config{
		Profile: engine.PolicyProfileStrictAgent, Guardrail: gCfg,
		Clock: clk, Entropy: rng.Fork(), AuditSink: auditSink, Reconciler: auditClust,
		ScopedFS: faultFS, HostTrust: sim.NewSimHostTrust(),
		Env:   sim.NewSimEnvPort(map[string]string{"USER": "ops"}, zeroLocalID),
		Vault: vault, VaultControl: vault, InventoryStore: invStore, JournalStore: journalStore,
		PrivilegeEscalation: sim.NewSimPrivilegeEscalator(), ShellProbe: sim.NewSimShellProbe(zeroProbe),
		Forwarder: sim.NewSimForwarder(), TUNDevice: sim.NewSimTUNDevicePort(),
		MuxSocket: sim.NewSimMuxSocket(innerDialer), Dialer: dialer,
	})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	mcpSrv, err := eng.NewMCPServer(engine.MCPConfig{
		TransferRoot: algebraic.Some(transferRoot), ArtifactRoot: algebraic.Some(artifactRoot), HTTPChunkSize: httpChunk,
	})
	if err != nil {
		_ = eng.Close(context.Background())
		t.Fatalf("NewMCPServer: %v", err)
	}
	rig := &fullSimRig{
		clk: clk, rng: rng, auditClust: auditClust, auditSink: auditSink,
		scopedFS: baseFS, remoteFS: remoteFS, invStore: invStore, journalStore: journalStore,
		vault: vault, dialer: dialer, transferRoot: transferRoot, artifactRoot: artifactRoot, eng: eng,
	}
	return rig, mcpSrv, faultFS
}

func TestEngineMCP_HTTPStreamTwoStepApprovalWraparoundAndReadFailClosed(t *testing.T) {
	defer goleak.VerifyNone(t)
	const chunkSize = 4096
	rig, srv, faultFS := newApprovalHTTPRig(t, chunkSize)
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
			sid := initHTTPMCPSession(t, client, baseURL)
			payload := makeDeterministicBytes(10 * 1024)
			wantDigest := security.DigestBytes(payload)

			// 1. 多分片上传（10 KiB / 4 KiB = 3 片 + commit）在 RiskModerate + Challenge 下完成完整两步审批，零提前摘除与零重放。
			assertApprovedMultiChunkHTTPUpload(t, client, baseURL, sid, payload, wantDigest, chunkSize)
			// 2. 恶意 X-Xops-Start-Offset: MaxUint64 必须返回 413 而非 uint64 回绕。
			assertHTTPUploadOffsetWraparoundRejected(t, client, baseURL, sid)
			// 3. 下载流两步审批：首次 GET 拉满至 Verifying 后返回 428，携 commit 审批二次 GET 跳过拉取直进提交并回传字节。
			assertApprovedHTTPDownload(t, client, baseURL, sid, payload, wantDigest)
			// 4. 下载流 ScopedRootFS 写头前读失败必须返回显式非 200 JSON 错误，绝不静默返回 200 OK 空体。
			assertHTTPDownloadPreHeaderReadFailClosed(t, client, baseURL, sid, faultFS, len(payload))
			return nil
		})
	})
	if runErr != nil {
		t.Fatalf("HTTP two-step approval flow: %v", runErr)
	}
}

func makeDeterministicBytes(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte((i*29 + 11) % 251)
	}
	return out
}

func initHTTPMCPSession(t *testing.T, client *http.Client, baseURL string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"approval-test","version":"1.0"}}}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	_ = resp.Body.Close()
	sid := resp.Header.Get("Mcp-Session-Id")
	if resp.StatusCode != http.StatusOK || sid == "" {
		t.Fatalf("initialize failed: status=%d sid=%q", resp.StatusCode, sid)
	}
	return sid
}

type httpMCPToolReply struct {
	body  map[string]any
	isErr bool
}

func postHTTPMCPToolAllowChallenge(t *testing.T, client *http.Client, baseURL, sid string, id int64, tool string, args map[string]any) map[string]any {
	t.Helper()
	rep := callHTTPMCPToolRaw(t, client, baseURL, sid, id, tool, args)
	if !rep.isErr {
		return rep.body
	}
	if rep.body["code"] != "approval_required" {
		t.Fatalf("工具 %s 预期成功或 approval_required，实际=%+v", tool, rep.body)
	}
	chal, _ := rep.body["approval_challenge"].(map[string]any)
	approved := make(map[string]any, len(args)+1)
	for k, v := range args {
		approved[k] = v
	}
	approved["approval"] = map[string]any{
		"verdict": "allow", "envelope_digest": chal["envelope_digest"], "envelope": chal["envelope"], "comment": "auto-step2",
	}
	rep2 := callHTTPMCPToolRaw(t, client, baseURL, sid, id+1000, tool, approved)
	if rep2.isErr {
		t.Fatalf("工具 %s 审批提交后仍失败: %+v", tool, rep2.body)
	}
	return rep2.body
}

func callHTTPMCPToolRaw(t *testing.T, client *http.Client, baseURL, sid string, id int64, tool string, args map[string]any) httpMCPToolReply {
	t.Helper()
	rawArgs, _ := protocol.MarshalCanonical(args)
	rawReq, _ := protocol.MarshalCanonical(map[string]any{
		"jsonrpc": "2.0", "id": id, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": jsontext.Value(rawArgs)},
	})
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp", bytes.NewReader(rawReq))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Mcp-Session-Id", sid)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /mcp: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /mcp status=%d body=%s", resp.StatusCode, raw)
	}
	var rpcResp protocol.Response
	if err := jsonv2.Unmarshal(raw, &rpcResp); err != nil || rpcResp.Error != nil {
		t.Fatalf("rpcResp err=%v rpcErr=%+v", err, rpcResp.Error)
	}
	var res protocol.CallToolResult
	if err := jsonv2.Unmarshal(rpcResp.Result, &res); err != nil {
		t.Fatalf("CallToolResult: %v", err)
	}
	var out map[string]any
	if len(res.StructuredContent) > 0 {
		_ = jsonv2.Unmarshal(res.StructuredContent, &out)
	}
	return httpMCPToolReply{body: out, isErr: res.IsError}
}

func buildApprovalHeaderFrom428(t *testing.T, raw428 []byte) string {
	t.Helper()
	var payload map[string]any
	if err := jsonv2.Unmarshal(raw428, &payload); err != nil || payload["code"] != "approval_required" {
		t.Fatalf("428 载荷解析失配: raw=%s err=%v", raw428, err)
	}
	chal, _ := payload["approval_challenge"].(map[string]any)
	hdrBytes, err := protocol.MarshalCanonical(map[string]any{
		"verdict": "allow", "envelope_digest": chal["envelope_digest"], "envelope": chal["envelope"], "comment": "http-approved",
	})
	if err != nil {
		t.Fatalf("MarshalCanonical approval header: %v", err)
	}
	return string(hdrBytes)
}

func doStreamHTTP(t *testing.T, client *http.Client, method, url, sid string, offset uint64, hasOffset bool, approvalHdr string, body []byte) (int, http.Header, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Mcp-Session-Id", sid)
	if hasOffset {
		req.Header.Set("X-Xops-Start-Offset", strconv.FormatUint(offset, 10))
	}
	if approvalHdr != "" {
		req.Header.Set("X-Xops-Approval", approvalHdr)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, resp.Header, raw
}

func assertApprovedMultiChunkHTTPUpload(t *testing.T, client *http.Client, baseURL, sid string, payload []byte, wantDigest security.Digest, chunkSize int) {
	t.Helper()
	startRes := postHTTPMCPToolAllowChallenge(t, client, baseURL, sid, 10, protocol.ToolNameTransfer, map[string]any{
		"action": "start", "target": "ops@10.20.0.1:22", "direction": "upload",
		"remote_path": "/stream/approved.bin", "total_bytes": len(payload), "expected_digest": wantDigest.String(),
	})
	tid, _ := startRes["transfer_id"].(string)
	streamURL := baseURL + "/transfers/" + tid + "/stream?commit=true"

	// 首次全量提交（无审批）：第 1 片触发 428，且绑定不被破坏。
	st, _, raw := doStreamHTTP(t, client, http.MethodPut, streamURL, sid, 0, true, "", payload)
	if st != http.StatusPreconditionRequired {
		t.Fatalf("首次上传期望 428，实际=%d body=%s", st, raw)
	}
	// 逐片携带审批提交（传入剩余全量载荷，验证单次审批仅被当前片消费，下片干净返回 428 而绝不报 403 重放）。
	for off := 0; off < len(payload); off += chunkSize {
		appr := buildApprovalHeaderFrom428(t, raw)
		st, _, raw = doStreamHTTP(t, client, http.MethodPut, streamURL, sid, uint64(off), true, appr, payload[off:])
		if st != http.StatusPreconditionRequired {
			t.Fatalf("offset=%d 提交后期望下阶段（下片或 commit）428 挑战，实际=%d body=%s", off, st, raw)
		}
	}
	// 此时全部字节已写入并处于 Verifying，且 raw 为 commit 挑战；发送空体 PUT ?commit=true + X-Xops-Start-Offset + commit 审批完成提交。
	commitAppr := buildApprovalHeaderFrom428(t, raw)
	st, _, raw = doStreamHTTP(t, client, http.MethodPut, streamURL, sid, uint64(len(payload)), true, commitAppr, nil)
	if st != http.StatusOK {
		t.Fatalf("最终 commit 期望 200，实际=%d body=%s", st, raw)
	}
	var doneRes map[string]any
	if err := jsonv2.Unmarshal(raw, &doneRes); err != nil || doneRes["committed"] != true || doneRes["actual_digest"] != wantDigest.String() {
		t.Fatalf("最终上传 commit 响应失配: res=%+v err=%v", doneRes, err)
	}
}

func assertHTTPUploadOffsetWraparoundRejected(t *testing.T, client *http.Client, baseURL, sid string) {
	t.Helper()
	startRes := postHTTPMCPToolAllowChallenge(t, client, baseURL, sid, 20, protocol.ToolNameTransfer, map[string]any{
		"action": "start", "target": "ops@10.20.0.1:22", "direction": "upload",
		"remote_path": "/stream/wrap.bin", "total_bytes": 16,
	})
	tid, _ := startRes["transfer_id"].(string)
	st, _, raw := doStreamHTTP(t, client, http.MethodPut, baseURL+"/transfers/"+tid+"/stream", sid, math.MaxUint64, true, "", []byte("12345678"))
	if st != http.StatusRequestEntityTooLarge {
		t.Fatalf("恶意 MaxUint64 偏移必须返回 413，实际=%d body=%s", st, raw)
	}
}

func assertApprovedHTTPDownload(t *testing.T, client *http.Client, baseURL, sid string, wantPayload []byte, wantDigest security.Digest) {
	t.Helper()
	startRes := postHTTPMCPToolAllowChallenge(t, client, baseURL, sid, 30, protocol.ToolNameTransfer, map[string]any{
		"action": "start", "target": "ops@10.20.0.1:22", "direction": "download",
		"remote_path": "/stream/approved.bin", "local_dest": "http-dl/approved.bin", "total_bytes": len(wantPayload),
	})
	tid, _ := startRes["transfer_id"].(string)
	streamURL := baseURL + "/transfers/" + tid + "/stream"

	// 1. 首次 GET：PullTransferChunk(RiskSafe) 自动拉完分片进 Verifying，随后 CommitTransfer 返回 428 且保留绑定。
	st1, _, raw1 := doStreamHTTP(t, client, http.MethodGet, streamURL, sid, 0, false, "", nil)
	if st1 != http.StatusPreconditionRequired {
		t.Fatalf("首次下载 GET 期望 428 commit 挑战，实际=%d body=%s", st1, raw1)
	}
	// 2. 携 commit 审批二次 GET：跳过 PullTransferChunk 直进 CommitTransfer 并逐字节回传。
	appr := buildApprovalHeaderFrom428(t, raw1)
	st2, hdr2, got := doStreamHTTP(t, client, http.MethodGet, streamURL, sid, 0, false, appr, nil)
	if st2 != http.StatusOK || !bytes.Equal(got, wantPayload) || hdr2.Get("X-Xops-Transfer-Digest") != wantDigest.String() {
		t.Fatalf("二次审批下载失配: status=%d len=%d digest=%q", st2, len(got), hdr2.Get("X-Xops-Transfer-Digest"))
	}
}

func assertHTTPDownloadPreHeaderReadFailClosed(t *testing.T, client *http.Client, baseURL, sid string, faultFS *faultInjectScopedFS, size int) {
	t.Helper()
	startRes := postHTTPMCPToolAllowChallenge(t, client, baseURL, sid, 40, protocol.ToolNameTransfer, map[string]any{
		"action": "start", "target": "ops@10.20.0.1:22", "direction": "download",
		"remote_path": "/stream/approved.bin", "local_dest": "http-dl/fail-read.bin", "total_bytes": size,
	})
	tid, _ := startRes["transfer_id"].(string)
	streamURL := baseURL + "/transfers/" + tid + "/stream"
	st1, _, raw1 := doStreamHTTP(t, client, http.MethodGet, streamURL, sid, 0, false, "", nil)
	if st1 != http.StatusPreconditionRequired {
		t.Fatalf("读错前置下载期望 428，实际=%d body=%s", st1, raw1)
	}
	faultFS.setFailReadPath("http-dl/fail-read.bin")
	defer faultFS.setFailReadPath("")
	appr := buildApprovalHeaderFrom428(t, raw1)
	st2, _, raw2 := doStreamHTTP(t, client, http.MethodGet, streamURL, sid, 0, false, appr, nil)
	if st2 == http.StatusOK || !strings.Contains(string(raw2), `"code"`) {
		t.Fatalf("ScopedRootFS 写头前读失败绝不可返回 200 OK 空体: status=%d body=%s", st2, raw2)
	}
}

func TestEngineMCP_TransferRecoverAllGatedAndInspectByHandleToken(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig, srv := newEngineMCPRig(t, security.RiskModerate, false, 4096)
	defer rig.close(t)
	if _, err := srv.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	// 1. recover all (prune_superseded=false): RiskSafe 放行并写入 CapTransfer 审计记录。
	res1, _ := callEngineMCPTool(t, srv, 1, protocol.ToolNameTransfer, map[string]any{"action": "recover", "all": true})
	if res1.IsError {
		t.Fatalf("recover all(read-only) 失败: %s", res1.StructuredContent)
	}
	hasRecoverAudit := false
	for _, e := range rig.auditClust.Entries() {
		if e.Binding().Tool() == protocol.ToolNameTransfer && e.Binding().Action() == "recover_all" && e.Phase() == ports.AuditPhaseFinalized {
			hasRecoverAudit = true
			break
		}
	}
	if !hasRecoverAudit {
		t.Fatalf("transfer recover all 必须写入 CapTransfer Finalized 审计条目")
	}

	// 2. recover all (prune_superseded=true): RiskModerate 触发两步审批，审批提交后放行。
	res2, body2 := callEngineMCPTool(t, srv, 2, protocol.ToolNameTransfer, map[string]any{"action": "recover", "all": true, "prune_superseded": true})
	if !res2.IsError || body2["code"] != "approval_required" {
		t.Fatalf("recover all(prune_superseded=true) 期望 approval_required，实际=%+v", body2)
	}
	chal := body2["approval_challenge"].(map[string]any)
	res3, _ := callEngineMCPTool(t, srv, 3, protocol.ToolNameTransfer, map[string]any{
		"action": "recover", "all": true, "prune_superseded": true,
		"approval": map[string]any{"verdict": "allow", "envelope_digest": chal["envelope_digest"], "envelope": chal["envelope"]},
	})
	if res3.IsError {
		t.Fatalf("recover all(prune_superseded=true) 审批提交后失败: %s", res3.StructuredContent)
	}

	// 3. transfer inspect 仅凭 handle_token（不传 transfer_id）即可反查成功。
	startArgs := map[string]any{"action": "start", "target": "ops@10.20.0.1:22", "direction": "upload", "remote_path": "/srv/tok.bin", "total_bytes": 16}
	startBody := callEngineMCPToolApprove(t, srv, 4, protocol.ToolNameTransfer, startArgs)
	tok, _ := startBody["handle_token"].(string)
	resInsp, inspBody := callEngineMCPTool(t, srv, 5, protocol.ToolNameTransfer, map[string]any{
		"action": "inspect", "target": "ops@10.20.0.1:22", "handle_token": tok,
	})
	if resInsp.IsError || inspBody["transfer_id"] != startBody["transfer_id"] {
		t.Fatalf("仅凭 handle_token inspect 失败: isErr=%v body=%+v", resInsp.IsError, inspBody)
	}
}

func callEngineMCPToolApprove(t *testing.T, srv *engine.MCPServer, id int64, tool string, args map[string]any) map[string]any {
	t.Helper()
	res, body := callEngineMCPTool(t, srv, id, tool, args)
	if !res.IsError {
		return body
	}
	if body["code"] != "approval_required" {
		t.Fatalf("callEngineMCPToolApprove(%s) 意外失败: %+v", tool, body)
	}
	chal := body["approval_challenge"].(map[string]any)
	approved := make(map[string]any, len(args)+1)
	for k, v := range args {
		approved[k] = v
	}
	approved["approval"] = map[string]any{"verdict": "allow", "envelope_digest": chal["envelope_digest"], "envelope": chal["envelope"]}
	res2, body2 := callEngineMCPTool(t, srv, id+500, tool, approved)
	if res2.IsError {
		t.Fatalf("callEngineMCPToolApprove(%s) 二次审批失败: %+v", tool, body2)
	}
	return body2
}

func TestEngineMCP_OutcomeUnknownStdinMaxOutputAndTargets(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig, srv := newEngineMCPRig(t, security.RiskDangerous, true, 4096)
	defer rig.close(t)
	ctx := context.Background()
	if _, err := srv.Prepare(ctx); err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	// 1. OutcomeUnknown（无论 execErr 非空或 nil）在 exec 与 exec_privileged 中均映射为 uncertain_outcome（禁止重试）。
	assertOutcomeUnknownMapping(t, rig, srv, errors.New("ssh transport disconnect"))
	assertOutcomeUnknownMapping(t, rig, srv, nil)

	// 2. 恢复正常命令回调，验证 exec_privileged 透传 stdin、16MiB 钳位至 8MiB（不退回 1MiB）、MaxUint64 安全拒错与 batch_exec 拒绝 stdin。
	rig.dialer.mu.Lock()
	rig.dialer.onCmd = func(_ context.Context, _ execution.CommandPlan, stdout, _ io.Writer) (execution.ExecutionOutcome, error) {
		_, _ = stdout.Write(bytes.Repeat([]byte("A"), 2<<20)) // 2 MiB > 1 MiB 默认值，但 < 8 MiB 硬上限
		return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	}
	rig.dialer.mu.Unlock()

	resPriv, privBody := callEngineMCPTool(t, srv, 30, protocol.ToolNameTerminalExec, map[string]any{
		"action": "exec_privileged", "target": "ops@10.20.0.1:22", "command": "cat",
		"privilege_method": "sudo", "non_interactive": true, "stdin": "priv-stdin-payload",
		"max_output_bytes": uint64(16 << 20),
	})
	if resPriv.IsError || privBody["truncated"] == true || len(privBody["stdout"].(string)) != 2<<20 {
		t.Fatalf("exec_privileged(16MiB->8MiB 钳位) 失配: isErr=%v trunc=%v len=%d", resPriv.IsError, privBody["truncated"], len(privBody["stdout"].(string)))
	}
	rig.dialer.mu.Lock()
	gotStdin := rig.dialer.lastStdin
	rig.dialer.onCmd = nil
	rig.dialer.mu.Unlock()
	if gotStdin != "priv-stdin-payload" {
		t.Fatalf("exec_privileged 未透传 stdin: got=%q", gotStdin)
	}
	resHuge, hugeBody := callEngineMCPTool(t, srv, 32, protocol.ToolNameTerminalExec, map[string]any{
		"action": "exec", "target": "ops@10.20.0.1:22", "command": "true",
		"max_output_bytes": uint64(math.MaxUint64),
	})
	if !resHuge.IsError || hugeBody["code"] != "invalid_params" {
		t.Fatalf("MaxUint64 max_output_bytes 必须安全返回 invalid_params: isErr=%v body=%+v", resHuge.IsError, hugeBody)
	}
	resBatchStdin, batchStdinBody := callEngineMCPTool(t, srv, 31, protocol.ToolNameTerminalExec, map[string]any{
		"action": "batch_exec", "targets": []string{"ops@10.20.0.1:22"}, "command": "hostname", "stdin": "unsupported",
	})
	if !resBatchStdin.IsError || batchStdinBody["code"] != "invalid_params" {
		t.Fatalf("batch_exec 非空 stdin 必须拒绝为 invalid_params: isErr=%v body=%+v", resBatchStdin.IsError, batchStdinBody)
	}

	// 3. 托管节点保留 Tags/DefaultProfile，且 IPv6 与同主机多端口 AdHoc 目标生成无冲突合法合成 NodeID。
	assertTargetMetadataAndAdHocSyntheticIDs(t, ctx, rig, srv)
}

func assertOutcomeUnknownMapping(t *testing.T, rig *fullSimRig, srv *engine.MCPServer, causeErr error) {
	t.Helper()
	rig.dialer.mu.Lock()
	rig.dialer.onCmd = func(_ context.Context, _ execution.CommandPlan, _, _ io.Writer) (execution.ExecutionOutcome, error) {
		unk, _ := execution.NewOutcomeUnknown(execution.ExecPhaseRunning, "transport_lost", "connection dropped mid-command")
		return unk, causeErr
	}
	rig.dialer.mu.Unlock()
	for _, args := range []map[string]any{
		{"action": "exec", "target": "ops@10.20.0.1:22", "command": "reboot"},
		{"action": "exec_privileged", "target": "ops@10.20.0.1:22", "command": "reboot", "privilege_method": "sudo", "non_interactive": true},
	} {
		res, body := callEngineMCPTool(t, srv, 25, protocol.ToolNameTerminalExec, args)
		if !res.IsError || body["code"] != "uncertain_outcome" || body["uncertain"] != true || body["retryable"] == true {
			t.Fatalf("%v OutcomeUnknown 分类错误: isErr=%v body=%+v", args["action"], res.IsError, body)
		}
	}
}

func assertTargetMetadataAndAdHocSyntheticIDs(t *testing.T, ctx context.Context, rig *fullSimRig, srv *engine.MCPServer) {
	t.Helper()
	hID, _ := inventory.ParseHostID("h-tag")
	ep, _ := netaddr.ParseEndpoint("10.20.0.9:22")
	hostObj, _ := inventory.NewHost(inventory.HostSpec{ID: hID, Endpoint: ep})
	idID, _ := inventory.ParseIdentityID("id-tag")
	uOps, _ := option.ParseUsername("ops")
	authAg, _ := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	identObj, _ := inventory.NewIdentity(inventory.IdentitySpec{ID: idID, User: uOps, Auth: authAg})
	nID, _ := inventory.ParseNodeID("tagged-web")
	webTag, _ := inventory.ParseTag("web")
	nodeObj, _ := inventory.NewNode(inventory.NodeSpec{
		ID: nID, HostRef: hID, IdentityRef: idID, Origin: inventory.NewOriginManaged(),
		Tags: []inventory.Tag{webTag}, Execution: algebraic.Some(execution.DefaultServerLaunchProfile()),
	})
	if _, err := rig.eng.CreateHost(ctx, engine.HostMutationRequest{Host: hostObj}); err != nil {
		t.Fatalf("CreateHost: %v", err)
	}
	if _, err := rig.eng.CreateIdentity(ctx, engine.IdentityMutationRequest{Identity: identObj}); err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	if _, err := rig.eng.CreateNode(ctx, engine.NodeMutationRequest{Node: nodeObj}); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}

	// 验证托管节点 Tags 完整保留：ExcludeTags:["web"] 生效，且 Playbook when_tags:["web"] 精准命中。
	resolvedTagged, err := rig.eng.ResolveTarget(ctx, engine.ResolveTargetRequest{Target: "tagged-web"})
	if err != nil {
		t.Fatalf("ResolveTarget tagged-web: %v", err)
	}
	cmd, _ := execution.NewCommandPlan(execution.CommandPlanSpec{
		Kind: execution.PlanKindCommand, Profile: execution.DefaultServerLaunchProfile(), Command: "hostname",
	})
	if _, err := rig.eng.BatchExec(ctx, engine.BatchExecRequest{
		Targets: []engine.ResolvedTarget{resolvedTagged}, ExcludeTags: []inventory.Tag{webTag}, Command: cmd,
	}); err == nil {
		t.Fatalf("ExcludeTags=[web] 必须过滤掉带 web 标签的托管目标")
	}
	stID, _ := playbook.ParseStepID("web-only")
	shAct, _ := playbook.NewStepShell(playbook.StepShellSpec{Command: "echo web"})
	st, _ := playbook.NewStep(playbook.StepSpec{ID: stID, Name: "web-only", Action: shAct, WhenTags: []inventory.Tag{webTag}})
	pbID, _ := playbook.ParsePlaybookID("pb-tags")
	pbSel, _ := playbook.NewTargetSelector(playbook.TargetSelectorSpec{All: true})
	pb, _ := playbook.NewPlaybook(playbook.PlaybookSpec{
		Version: playbook.VersionV2, ID: pbID, Name: "pb-tags", OnError: playbook.OnErrorFailFast,
		Target: pbSel, Steps: algebraic.NewNonEmpty(st),
	})
	pbRes, err := rig.eng.RunPlaybook(ctx, engine.PlaybookRequest{Playbook: pb, Targets: []engine.ResolvedTarget{resolvedTagged}})
	if err != nil || len(pbRes.Report().Nodes()) != 1 || pbRes.Report().Nodes()[0].Steps()[0].Status() != playbook.StepStatusChanged {
		t.Fatalf("Playbook when_tags=[web] 应在托管目标上执行变更而非跳过: res=%+v err=%v", pbRes, err)
	}

	// 验证 IPv6 与同主机多端口 AdHoc 目标在 Engine 与 MCP 两侧均可批量执行且无 NodeID 冲突。
	adhocSpecs := []string{"ops@[::1]:22", "ops@127.0.0.1:2221", "ops@127.0.0.1:2222"}
	resolvedAdHoc := make([]engine.ResolvedTarget, 0, len(adhocSpecs))
	for _, sp := range adhocSpecs {
		rt, rErr := rig.eng.ResolveTarget(ctx, engine.ResolveTargetRequest{Target: sp})
		if rErr != nil {
			t.Fatalf("ResolveTarget(%s): %v", sp, rErr)
		}
		resolvedAdHoc = append(resolvedAdHoc, rt)
	}
	engBatch, err := rig.eng.BatchExec(ctx, engine.BatchExecRequest{Targets: resolvedAdHoc, Command: cmd})
	if err != nil || len(engBatch.Results()) != 3 {
		t.Fatalf("Engine BatchExec(IPv6+多端口 AdHoc) 失配: len=%d err=%v", len(engBatch.Results()), err)
	}
	resMCPBatch, mcpBatchBody := callEngineMCPTool(t, srv, 35, protocol.ToolNameTerminalExec, map[string]any{
		"action": "batch_exec", "targets": adhocSpecs, "command": "hostname",
	})
	if resMCPBatch.IsError {
		t.Fatalf("MCP batch_exec(IPv6+多端口 AdHoc) 失败: %+v", mcpBatchBody)
	}
}

func TestEngine_SSHApprovalContractAndPhase5Facades(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()

	// 1. 验证 Engine.Exec / InteractiveSSH / RunSSH 两步审批契约（ErrApprovalRequired + ExtractApprovalChallenge + Approval 透传）。
	assertSSHApprovalRoundTrip(t, ctx)

	// 2. 验证 Phase 5 新增门面：GetHost/GetIdentity/GetNode、WithPendingEnrollment、EnrollEncryptedPrivateKeyIdentity*、
	//    Vault*Interactive/FromBytes/Saga/RotateSecretInteractive/WithPromptedSecret、RealPathRemote/ReadLinkRemote、MCPServer.Close 释放非持久句柄。
	assertPhase5FacadesEndToEnd(t, ctx)
}

func assertSSHApprovalRoundTrip(t *testing.T, ctx context.Context) {
	t.Helper()
	rig, _, _ := newApprovalHTTPRig(t, 4096)
	defer rig.close(t)

	// Exec 两步审批闭环
	var stdout bytes.Buffer
	_, err := rig.eng.Exec(ctx, engine.ExecRequest{TargetSpec: "ops@10.10.0.1:22", Command: "uname", Stdout: &stdout})
	if !errors.Is(err, engine.ErrApprovalRequired) {
		t.Fatalf("Exec 首次未审批必须匹配 engine.ErrApprovalRequired，实际=%v", err)
	}
	ch, ok := engine.ExtractApprovalChallenge(err)
	if !ok || !ch.IsValid() {
		t.Fatalf("Exec 必须可提取有效 ApprovalChallenge")
	}
	sub, err := engine.NewApprovalSubmission(security.VerdictAllow, ch.EnvelopeDigest(), algebraic.Some(ch.Envelope()), "cli-ok")
	if err != nil {
		t.Fatalf("NewApprovalSubmission: %v", err)
	}
	if _, err := rig.eng.Exec(ctx, engine.ExecRequest{
		TargetSpec: "ops@10.10.0.1:22", Command: "uname", Stdout: &stdout, Approval: algebraic.Some(sub),
	}); err != nil {
		t.Fatalf("Exec 携带 Approval 重试失败: %v", err)
	}

	// RunSSH (command 路径) 两步审批闭环
	_, err = rig.eng.RunSSH(ctx, engine.RunSSHRequest{TargetSpec: "ops@10.10.0.1:22", Command: "id", Stdout: &stdout})
	if !errors.Is(err, engine.ErrApprovalRequired) {
		t.Fatalf("RunSSH 首次未审批必须匹配 engine.ErrApprovalRequired，实际=%v", err)
	}
	ch2, ok := engine.ExtractApprovalChallenge(err)
	if !ok {
		t.Fatalf("RunSSH 必须可提取 ApprovalChallenge")
	}
	sub2, _ := engine.NewApprovalSubmission(security.VerdictAllow, ch2.EnvelopeDigest(), algebraic.Some(ch2.Envelope()), "runssh-ok")
	if _, err := rig.eng.RunSSH(ctx, engine.RunSSHRequest{
		TargetSpec: "ops@10.10.0.1:22", Command: "id", Stdout: &stdout, Approval: algebraic.Some(sub2),
	}); err != nil {
		t.Fatalf("RunSSH 携带 Approval 重试失败: %v", err)
	}

	// InteractiveSSH 两步审批闭环
	_, err = rig.eng.InteractiveSSH(ctx, engine.InteractiveSSHRequest{
		TargetSpec: "ops@10.10.0.1:22", RequestTTY: engine.RequestTTYNo, Stdout: &stdout,
	})
	if !errors.Is(err, engine.ErrApprovalRequired) {
		t.Fatalf("InteractiveSSH 首次未审批必须匹配 engine.ErrApprovalRequired，实际=%v", err)
	}
	ch3, ok := engine.ExtractApprovalChallenge(err)
	if !ok {
		t.Fatalf("InteractiveSSH 必须可提取 ApprovalChallenge")
	}
	sub3, _ := engine.NewApprovalSubmission(security.VerdictAllow, ch3.EnvelopeDigest(), algebraic.Some(ch3.Envelope()), "interactive-ok")
	if _, err := rig.eng.InteractiveSSH(ctx, engine.InteractiveSSHRequest{
		TargetSpec: "ops@10.10.0.1:22", RequestTTY: engine.RequestTTYNo, Stdout: &stdout, Approval: algebraic.Some(sub3),
	}); err != nil {
		t.Fatalf("InteractiveSSH 携带 Approval 重试失败: %v", err)
	}
}

func assertPhase5FacadesEndToEnd(t *testing.T, ctx context.Context) {
	t.Helper()
	clk := sim.NewSimClock(sim.DefaultBaseTime())
	rng := sim.NewSeededRand(20261129)
	auditClust := sim.NewSimAuditCluster()
	auditSink, _ := auditClust.NewSinkFromEntropy(rng.Fork())
	defer func() { _ = auditSink.Close() }()
	scopedFS := sim.NewSimScopedRootFS(clk)
	remoteFS := sim.NewSimRemoteFS(clk)
	var emptyGraph inventory.Graph
	invStore, _ := sim.NewSimInventoryStore(emptyGraph)
	vault := sim.NewUninitializedSimVault(rng.Fork())
	interact := sim.NewSimInteractionPort(true)
	interact.SetApprovalPolicy(security.VerdictAllow, nil, false)
	interact.SetReplies("ok", []byte("interactive-master-pass"))

	fp, _ := inventory.ParseKeyFingerprint("SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU")
	pubInfo, err := ports.NewPublicKeyInfo(ports.PublicKeyInfoSpec{
		Algorithm: "ssh-ed25519", Fingerprint: fp, WireBlob: []byte("ed25519-pub-blob"), Comment: "ops@test",
	})
	if err != nil {
		t.Fatalf("NewPublicKeyInfo: %v", err)
	}
	keyPath, _ := inventory.ParseKeyPathSpec("~/.ssh/id_ed25519_enc")
	signer := sim.NewSimKeySigner()
	signer.AddKey(pubInfo, keyPath.String())

	innerDialer := sim.NewSimDialer(clk, rng.Fork())
	dialer := &fullFacadeDialer{inner: innerDialer, remoteFS: remoteFS}
	var zeroLocalID ports.LocalIdentityInfo
	gCfg := engine.DefaultGuardrailConfig()
	gCfg.ApprovalThreshold = security.RiskDangerous
	eng, err := engine.New(engine.Config{
		Profile: engine.PolicyProfileDirectOperator, Guardrail: gCfg,
		Clock: clk, Entropy: rng.Fork(), AuditSink: auditSink, Reconciler: auditClust,
		ScopedFS: scopedFS, HostTrust: sim.NewSimHostTrust(), Interaction: interact,
		Env:   sim.NewSimEnvPort(map[string]string{"USER": "ops"}, zeroLocalID),
		Vault: vault, VaultControl: vault, KeySigner: signer, InventoryStore: invStore,
		KnownStores: []string{"local"}, Dialer: dialer,
	})
	if err != nil {
		t.Fatalf("engine.New phase5: %v", err)
	}
	defer func() { _ = eng.Close(ctx) }()

	assertPhase5VaultAndKeyEnroll(t, ctx, eng, interact, keyPath)
	assertPhase5GetPendingRealPathAndMCPClose(t, ctx, eng, remoteFS, fp)
}

func assertPhase5VaultAndKeyEnroll(t *testing.T, ctx context.Context, eng *engine.Engine, interact *sim.SimInteractionPort, keyPath inventory.KeyPathSpec) {
	t.Helper()
	prompt, err := ports.NewSecretPromptRequest(ports.SecretPromptRequestSpec{Title: "Vault", Prompt: "Enter master passphrase"})
	if err != nil {
		t.Fatalf("NewSecretPromptRequest: %v", err)
	}
	assertPhase5VaultInteractiveControls(t, ctx, eng, prompt)
	assertPhase5KeyEnrollAndVaultSaga(t, ctx, eng, interact, keyPath, prompt)
}

func assertPhase5VaultInteractiveControls(t *testing.T, ctx context.Context, eng *engine.Engine, prompt ports.SecretPromptRequest) {
	t.Helper()
	if err := eng.VaultInitInteractive(ctx, engine.InteractiveVaultOpRequest{Prompt: prompt, ConfirmPrompt: algebraic.Some(prompt)}); err != nil {
		t.Fatalf("VaultInitInteractive: %v", err)
	}
	if err := eng.VaultLock(ctx, engine.VaultOpRequest{}); err != nil {
		t.Fatalf("VaultLock: %v", err)
	}
	if err := eng.VaultUnlockInteractive(ctx, engine.InteractiveVaultOpRequest{Prompt: prompt}); err != nil {
		t.Fatalf("VaultUnlockInteractive: %v", err)
	}
	if err := eng.VaultLock(ctx, engine.VaultOpRequest{}); err != nil {
		t.Fatalf("VaultLock 2: %v", err)
	}
	if err := eng.VaultUnlockFromBytes(ctx, engine.VaultOpRequest{}, []byte("interactive-master-pass")); err != nil {
		t.Fatalf("VaultUnlockFromBytes: %v", err)
	}
	if err := eng.WithPromptedSecret(ctx, prompt, func(box *secret.SecretBox) error {
		if !box.IsValid() {
			return errors.New("prompted SecretBox invalid")
		}
		return nil
	}); err != nil {
		t.Fatalf("WithPromptedSecret: %v", err)
	}
}

func assertPhase5KeyEnrollAndVaultSaga(t *testing.T, ctx context.Context, eng *engine.Engine, interact *sim.SimInteractionPort, keyPath inventory.KeyPathSpec, prompt ports.SecretPromptRequest) {
	t.Helper()
	uOps, _ := option.ParseUsername("ops")
	id1, _ := inventory.ParseIdentityID("enc-key-1")
	if res1, err := eng.EnrollEncryptedPrivateKeyIdentityFromBytes(ctx, engine.EnrollEncryptedPrivateKeyRequest{
		IdentityID: id1, User: uOps, KeyPath: keyPath, TargetStore: "local",
	}, []byte("key-pass-1")); err != nil || !res1.IsValid() {
		t.Fatalf("EnrollEncryptedPrivateKeyIdentityFromBytes: res=%+v err=%v", res1, err)
	}
	id2, _ := inventory.ParseIdentityID("enc-key-2")
	interact.SetReplies("ok", []byte("key-pass-2"))
	if res2, err := eng.EnrollEncryptedPrivateKeyIdentity(ctx, engine.EnrollEncryptedPrivateKeyRequest{
		IdentityID: id2, User: uOps, KeyPath: keyPath, TargetStore: "local", Prompt: prompt,
	}); err != nil || !res2.IsValid() {
		t.Fatalf("EnrollEncryptedPrivateKeyIdentity: res=%+v err=%v", res2, err)
	}
	id3, _ := inventory.ParseIdentityID("enc-key-3")
	if err := secret.WithBytes([]byte("key-pass-3"), func(box *secret.SecretBox) error {
		r3, e3 := eng.EnrollEncryptedPrivateKeyIdentityWithSecret(ctx, engine.EnrollEncryptedPrivateKeyRequest{
			IdentityID: id3, User: uOps, KeyPath: keyPath, TargetStore: "local",
		}, box)
		if e3 != nil || !r3.IsValid() {
			return errors.New("EnrollEncryptedPrivateKeyIdentityWithSecret failed")
		}
		return nil
	}); err != nil {
		t.Fatalf("EnrollEncryptedPrivateKeyIdentityWithSecret: %v", err)
	}

	pwRef, _ := secret.ParseRef("local/saga-pw-1")
	idSaga, _ := inventory.ParseIdentityID("id-saga")
	if sagaRes, err := eng.ExecuteVaultSagaFromBytes(ctx, engine.VaultSagaRequest{
		NewRef: pwRef,
		MutateGraph: func(_ context.Context, snap ports.InventorySnapshot, newRef secret.Ref) (inventory.Graph, error) {
			auth, _ := inventory.NewAuthPassword(newRef)
			ident, _ := inventory.NewIdentity(inventory.IdentitySpec{ID: idSaga, User: uOps, Auth: auth})
			return inventory.NewGraph(inventory.GraphSpec{
				Hosts: snap.Graph().Hosts(), Identities: append(snap.Graph().Identities(), ident), Nodes: snap.Graph().Nodes(),
			})
		},
	}, []byte("saga-secret-1")); err != nil || !sagaRes.IsValid() {
		t.Fatalf("ExecuteVaultSagaFromBytes: res=%+v err=%v", sagaRes, err)
	}
	interact.SetReplies("ok", []byte("saga-secret-2"))
	if rotRes, err := eng.RotateSecretInteractive(ctx, engine.InteractiveRotateSecretRequest{
		Prompt: prompt, Rotate: engine.RotateSecretRequest{OldRef: pwRef, TargetStore: "local"},
	}); err != nil || !rotRes.IsValid() {
		t.Fatalf("RotateSecretInteractive: res=%+v err=%v", rotRes, err)
	}
}

func assertPhase5GetPendingRealPathAndMCPClose(t *testing.T, ctx context.Context, eng *engine.Engine, remoteFS *sim.SimRemoteFS, fp inventory.KeyFingerprint) {
	t.Helper()
	assertPhase5PendingEnrollAndGets(t, ctx, eng, fp)
	assertPhase5RealPathReadLinkAndMCPClose(t, ctx, eng, remoteFS)
}

func assertPhase5PendingEnrollAndGets(t *testing.T, ctx context.Context, eng *engine.Engine, fp inventory.KeyFingerprint) {
	t.Helper()
	hID, _ := inventory.ParseHostID("h-enroll")
	ep, _ := netaddr.ParseEndpoint("10.30.0.5:22")
	hostObj, _ := inventory.NewHost(inventory.HostSpec{ID: hID, Endpoint: ep})
	id1, _ := inventory.ParseIdentityID("enc-key-1")
	nID, _ := inventory.ParseNodeID("enrolled-node")
	nodeObj, _ := inventory.NewNode(inventory.NodeSpec{
		ID: nID, HostRef: hID, IdentityRef: id1, Origin: inventory.NewOriginManaged(),
	})
	enrollRes, err := eng.WithPendingEnrollment(ctx, engine.PendingEnrollmentRequest{
		Host: algebraic.Some(hostObj), Node: nodeObj, TTL: algebraic.FromStdDuration(time.Minute),
	}, func(lCtx context.Context, lease *engine.PendingEnrollmentLease) error {
		if _, pErr := lease.Probe(lCtx, func(context.Context) (inventory.KeyFingerprint, error) { return fp, nil }); pErr != nil {
			return pErr
		}
		_, cErr := lease.Commit(lCtx)
		return cErr
	})
	if err != nil || !enrollRes.IsValid() {
		t.Fatalf("WithPendingEnrollment: res=%+v err=%v", enrollRes, err)
	}
	if h, _, err := eng.GetHost(ctx, hID, engine.InventoryQueryRequest{}); err != nil || !h.ID().Equal(hID) {
		t.Fatalf("GetHost: h=%+v err=%v", h, err)
	}
	if ident, _, err := eng.GetIdentity(ctx, id1, engine.InventoryQueryRequest{}); err != nil || !ident.ID().Equal(id1) {
		t.Fatalf("GetIdentity: ident=%+v err=%v", ident, err)
	}
	if n, _, err := eng.GetNode(ctx, nID, engine.InventoryQueryRequest{}); err != nil || !n.ID().Equal(nID) {
		t.Fatalf("GetNode: n=%+v err=%v", n, err)
	}
}

func assertPhase5RealPathReadLinkAndMCPClose(t *testing.T, ctx context.Context, eng *engine.Engine, remoteFS *sim.SimRemoteFS) {
	t.Helper()
	dir, _ := pathalg.ParseRemotePath("/srv")
	_ = remoteFS.MkdirAll(ctx, dir, 0o755)
	targetFile, _ := pathalg.ParseRemotePath("/srv/real.txt")
	linkPath, _ := pathalg.ParseRemotePath("/srv/link.txt")
	rc := engine.RemoteCall{TargetInput: engine.TargetInput{TargetSpec: "enrolled-node"}}
	if _, err := eng.WriteRemoteFile(ctx, engine.RemoteFileWriteRequest{RemoteCall: rc, Path: targetFile, Content: []byte("hi")}); err != nil {
		t.Fatalf("WriteRemoteFile: %v", err)
	}
	if err := remoteFS.PutSymlink(linkPath, "/srv/real.txt"); err != nil {
		t.Fatalf("PutSymlink: %v", err)
	}
	if rp, err := eng.RealPathRemote(ctx, engine.RemotePathOpRequest{RemoteCall: rc, Path: linkPath}); err != nil || rp.String() != "/srv/real.txt" {
		t.Fatalf("RealPathRemote: rp=%q err=%v", rp, err)
	}
	if rl, err := eng.ReadLinkRemote(ctx, engine.RemotePathOpRequest{RemoteCall: rc, Path: linkPath}); err != nil || rl != "/srv/real.txt" {
		t.Fatalf("ReadLinkRemote: rl=%q err=%v", rl, err)
	}
	mcpSrv, err := eng.NewMCPServer(engine.MCPConfig{})
	if err != nil {
		t.Fatalf("NewMCPServer: %v", err)
	}
	if _, err := mcpSrv.Prepare(ctx); err != nil {
		t.Fatalf("MCPServer.Prepare: %v", err)
	}
	if resOpen, openBody := callEngineMCPTool(t, mcpSrv, 90, protocol.ToolNameTerminalSession, map[string]any{
		"action": "open", "target": "enrolled-node", "term": "xterm",
	}); resOpen.IsError {
		t.Fatalf("terminal_session open: %+v", openBody)
	}
	if err := mcpSrv.Close(ctx); err != nil {
		t.Fatalf("MCPServer.Close: %v", err)
	}
	if !mcpSrv.IsClosed() {
		t.Fatalf("MCPServer 应已关闭")
	}
}
