package mcpruntime_test

import (
	"context"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/mcpruntime"
	"github.com/wentf9/xops-cli/core/internal/mcpruntime/protocol"
	"github.com/wentf9/xops-cli/core/internal/sim"
	uccred "github.com/wentf9/xops-cli/core/internal/usecase/credential"
	ucinv "github.com/wentf9/xops-cli/core/internal/usecase/inventory"
	"github.com/wentf9/xops-cli/core/ports"
)

// mcpUnitRig 在物理零 core/internal/pool 与零 OperatorReadFS 边界下装配 mcpruntime.Server
// （配合 gate + usecase/{inventory,credential} + sim），验证协议分发、启动对账、两步审批与 Halted 熔断。
type mcpUnitRig struct {
	clk          *sim.SimClock
	rng          *sim.SeededRand
	bus          *events.SystemBus
	auditCluster *sim.SimAuditCluster
	auditSink    *sim.SimAuditSink
	scopedFS     *sim.SimScopedRootFS
	invStore     *sim.SimInventoryStore
	vault        *sim.SimVault
	gate         *gate.Gate
	srv          *mcpruntime.Server
}

type mcpUnitOpts struct {
	profile         gate.PolicyProfileKind
	threshold       security.RiskLevel
	fallback        gate.NoElicitFallback
	maxMessageBytes int64
	reconcileErr    error
	allowedOrigins  []string
	allowedHosts    []string
}

func newMCPUnitRig(t *testing.T, opts mcpUnitOpts) *mcpUnitRig {
	t.Helper()
	if opts.profile == 0 {
		opts.profile = gate.PolicyProfileStrictAgent
	}
	if !opts.threshold.IsValid() {
		opts.threshold = security.RiskDangerous
	}

	clk := sim.NewSimClock(sim.DefaultBaseTime())
	rng := sim.NewSeededRand(20260501)
	bus, err := events.NewSystemBus(events.SystemBusConfig{DefaultSubscriberBuffer: 64})
	requireNoErr(t, err, "NewSystemBus")
	auditClust := sim.NewSimAuditCluster()
	auditSink, err := auditClust.NewSinkFromEntropy(rng.Fork())
	requireNoErr(t, err, "NewSinkFromEntropy")
	scopedFS := sim.NewSimScopedRootFS(clk)
	var emptyGraph inventory.Graph
	invStore, err := sim.NewSimInventoryStore(emptyGraph)
	requireNoErr(t, err, "NewSimInventoryStore")
	vault := sim.NewSimVault(rng.Fork())
	importer := sim.NewSimFormatImporter("csv")
	var zeroLocalID ports.LocalIdentityInfo
	envPort := sim.NewSimEnvPort(map[string]string{"USER": "ops"}, zeroLocalID)

	transferRoot, err := pathalg.ParseLocalDir("/sandbox/transfers")
	requireNoErr(t, err, "ParseLocalDir transferRoot")
	requireNoErr(t, scopedFS.EnsureRoot(transferRoot, 0o700), "EnsureRoot transferRoot")

	var interact ports.InteractionPort
	if opts.fallback != gate.NoElicitFallbackChallenge {
		ip := sim.NewSimInteractionPort(true)
		ip.SetApprovalPolicy(security.VerdictAllow, nil, false)
		interact = ip
	}

	pol, err := gate.NewGuardrailPolicy(gate.GuardrailPolicySpec{
		ApprovalThreshold: opts.threshold,
		NoElicitFallback:  opts.fallback,
	})
	requireNoErr(t, err, "NewGuardrailPolicy")
	g, err := gate.NewGate(gate.GateConfig{
		Profile: opts.profile, Policy: pol, AuditSink: auditSink, Reconciler: auditClust,
		Interaction: interact, Clock: clk, Entropy: rng.Fork(), SystemBus: bus,
	})
	requireNoErr(t, err, "NewGate")

	credSvc, err := uccred.NewService(uccred.ServiceConfig{
		Gate: g, Vault: vault, VaultControl: vault, Store: invStore, Clock: clk, Entropy: rng.Fork(),
	})
	requireNoErr(t, err, "uccred.NewService")
	invSvc, err := ucinv.NewService(ucinv.ServiceConfig{
		Store: invStore, Gate: g, Vault: vault, VaultControl: vault, Credential: credSvc,
		Env: envPort, Clock: clk, Entropy: rng.Fork(), Importers: []ports.FormatImporter{importer},
	})
	requireNoErr(t, err, "ucinv.NewService")

	reconcileFn := g.ReconcileCrashedAudits
	if opts.reconcileErr != nil {
		injErr := opts.reconcileErr
		reconcileFn = func(context.Context) (ports.CrashReconcileReport, error) {
			var zero ports.CrashReconcileReport
			return zero, injErr
		}
	}

	srv, err := mcpruntime.NewServer(mcpruntime.ServerConfig{
		Gate:               g,
		ReconcileAudits:    reconcileFn,
		Inventory:          invSvc,
		ScopedFS:           scopedFS,
		TransferRoot:       algebraic.Some(transferRoot),
		Clock:              clk,
		Entropy:            rng.Fork(),
		SystemBus:          bus,
		MaxMessageBytes:    opts.maxMessageBytes,
		HTTPAllowedOrigins: opts.allowedOrigins,
		HTTPAllowedHosts:   opts.allowedHosts,
	})
	requireNoErr(t, err, "mcpruntime.NewServer")
	return &mcpUnitRig{
		clk: clk, rng: rng, bus: bus, auditCluster: auditClust, auditSink: auditSink,
		scopedFS: scopedFS, invStore: invStore, vault: vault, gate: g, srv: srv,
	}
}

func (r *mcpUnitRig) close(t *testing.T) {
	t.Helper()
	if r.srv != nil {
		if err := r.srv.Close(context.Background()); err != nil {
			t.Errorf("srv.Close: %v", err)
		}
	}
	if r.auditSink != nil {
		_ = r.auditSink.Close()
	}
	if r.bus != nil {
		r.bus.Close()
	}
}

func callRPC(t *testing.T, srv *mcpruntime.Server, id int64, method string, params any) protocol.Response {
	t.Helper()
	reqObj := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		b, err := protocol.MarshalCanonical(params)
		requireNoErr(t, err, "MarshalCanonical params")
		reqObj["params"] = jsontext.Value(b)
	}
	raw, err := protocol.MarshalCanonical(reqObj)
	requireNoErr(t, err, "MarshalCanonical request")
	respBytes, hasResp, err := srv.HandleMessage(context.Background(), raw)
	requireNoErr(t, err, "HandleMessage "+method)
	if !hasResp {
		t.Fatalf("方法 %s 期望有响应却无响应", method)
	}
	var resp protocol.Response
	requireNoErr(t, jsonv2.Unmarshal(respBytes, &resp), "Unmarshal Response")
	return resp
}

func callToolJSON(t *testing.T, srv *mcpruntime.Server, id int64, toolName string, args map[string]any) (protocol.CallToolResult, map[string]any) {
	t.Helper()
	argsRaw, err := protocol.MarshalCanonical(args)
	requireNoErr(t, err, "MarshalCanonical tool args")
	resp := callRPC(t, srv, id, "tools/call", map[string]any{
		"name":      toolName,
		"arguments": jsontext.Value(argsRaw),
	})
	if resp.Error != nil {
		t.Fatalf("tools/call(%s) 返回 JSON-RPC 级错误: %+v", toolName, resp.Error)
	}
	var res protocol.CallToolResult
	requireNoErr(t, jsonv2.Unmarshal(resp.Result, &res), "Unmarshal CallToolResult")
	var structured map[string]any
	if len(res.StructuredContent) > 0 {
		requireNoErr(t, jsonv2.Unmarshal(res.StructuredContent, &structured), "Unmarshal StructuredContent")
	}
	return res, structured
}

func requireNoErr(t *testing.T, err error, msg string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", msg, err)
	}
}

func TestMCPRuntime_InitializeListNodesAndUnknownToolFailClosed(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newMCPUnitRig(t, mcpUnitOpts{})
	defer rig.close(t)

	assertMCPHandshakeAndList(t, rig.srv)
	assertMCPNodesCRUDAndImport(t, rig.srv)

	unknownToolResp := callRPC(t, rig.srv, 16, "tools/call", map[string]any{"name": "evil_tool", "arguments": map[string]any{}})
	if unknownToolResp.Error == nil || unknownToolResp.Error.Code != protocol.CodeInvalidParams {
		t.Fatalf("未知工具期望 CodeInvalidParams(-32602)，实际=%+v", unknownToolResp.Error)
	}
	unknownMethodResp := callRPC(t, rig.srv, 18, "evil/method", nil)
	if unknownMethodResp.Error == nil || unknownMethodResp.Error.Code != protocol.CodeMethodNotFound {
		t.Fatalf("未知 JSON-RPC 方法期望 CodeMethodNotFound(-32601)，实际=%+v", unknownMethodResp.Error)
	}
	badFieldRes, badBody := callToolJSON(t, rig.srv, 17, protocol.ToolNameNodes, map[string]any{"action": "list_nodes", "unknown_field": 1})
	if !badFieldRes.IsError || badBody["code"] != "invalid_params" {
		t.Fatalf("未知参数字段必须拒绝为 invalid_params: isErr=%v body=%+v", badFieldRes.IsError, badBody)
	}
}

func assertMCPHandshakeAndList(t *testing.T, srv *mcpruntime.Server) {
	t.Helper()
	rep, err := srv.Prepare(context.Background())
	requireNoErr(t, err, "Prepare")
	if !rep.IsValid() {
		t.Fatalf("StartupReport 无效: %+v", rep)
	}
	if initResp := callRPC(t, srv, 1, "initialize", map[string]any{
		"protocolVersion": protocol.LatestProtocolVersion,
		"clientInfo":      map[string]any{"name": "unit-go", "version": "1.0.0"},
	}); initResp.Error != nil {
		t.Fatalf("initialize 失败: %+v", initResp.Error)
	}
	_, hasResp, err := srv.HandleMessage(context.Background(), []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	requireNoErr(t, err, "notifications/initialized")
	if hasResp {
		t.Fatalf("notification 不得返回响应")
	}
	if pingResp := callRPC(t, srv, 2, "ping", nil); pingResp.Error != nil {
		t.Fatalf("ping 失败: %+v", pingResp.Error)
	}
	listResp := callRPC(t, srv, 3, "tools/list", nil)
	if listResp.Error != nil {
		t.Fatalf("tools/list 失败: %+v", listResp.Error)
	}
	var listRes protocol.ListToolsResult
	requireNoErr(t, jsonv2.Unmarshal(listResp.Result, &listRes), "Unmarshal ListToolsResult")
	if len(listRes.Tools) != 7 {
		t.Fatalf("期望 7 个判别式工具，实际=%d", len(listRes.Tools))
	}
}

func assertMCPNodesCRUDAndImport(t *testing.T, srv *mcpruntime.Server) {
	t.Helper()
	hostID, err := inventory.ParseHostID("h-web1")
	requireNoErr(t, err, "ParseHostID")
	ep, err := netaddr.ParseEndpoint("10.0.0.10:22")
	requireNoErr(t, err, "ParseEndpoint")
	hostObj, err := inventory.NewHost(inventory.HostSpec{ID: hostID, Endpoint: ep})
	requireNoErr(t, err, "NewHost")
	res, body := callToolJSON(t, srv, 10, protocol.ToolNameNodes, map[string]any{"action": "create_host", "host": hostObj})
	if res.IsError || body["revision"] == "" {
		t.Fatalf("nodes create_host 失败: isErr=%v body=%+v", res.IsError, body)
	}

	identID, err := inventory.ParseIdentityID("id-ops")
	requireNoErr(t, err, "ParseIdentityID")
	userOps, err := option.ParseUsername("ops")
	requireNoErr(t, err, "ParseUsername")
	authAgent, err := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	requireNoErr(t, err, "NewAuthAgent")
	identObj, err := inventory.NewIdentity(inventory.IdentitySpec{ID: identID, User: userOps, Auth: authAgent})
	requireNoErr(t, err, "NewIdentity")
	if r, _ := callToolJSON(t, srv, 11, protocol.ToolNameNodes, map[string]any{"action": "create_identity", "identity": identObj}); r.IsError {
		t.Fatalf("nodes create_identity 失败: %s", r.StructuredContent)
	}

	nodeID, err := inventory.ParseNodeID("web-1")
	requireNoErr(t, err, "ParseNodeID")
	nodeObj, err := inventory.NewNode(inventory.NodeSpec{
		ID: nodeID, HostRef: hostID, IdentityRef: identID, Origin: inventory.NewOriginManaged(),
	})
	requireNoErr(t, err, "NewNode")
	if r, _ := callToolJSON(t, srv, 12, protocol.ToolNameNodes, map[string]any{"action": "create_node", "node": nodeObj}); r.IsError {
		t.Fatalf("nodes create_node 失败: %s", r.StructuredContent)
	}

	for _, args := range []map[string]any{
		{"action": "list_hosts"}, {"action": "list_identities"}, {"action": "list_nodes"},
		{"action": "validate_dag"}, {"action": "doctor"}, {"action": "list_import_formats"},
		{"action": "resolve", "target": "web-1"},
		{"action": "apply_import", "format": "csv", "source_name": "seed.csv", "content": "db-1,10.0.0.20,22,ops\n"},
	} {
		if r, _ := callToolJSON(t, srv, 13, protocol.ToolNameNodes, args); r.IsError {
			t.Fatalf("nodes %v 失败: %s", args["action"], r.StructuredContent)
		}
	}
}

func TestMCPRuntime_TwoStepApprovalAndReplayRejection(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newMCPUnitRig(t, mcpUnitOpts{
		profile:   gate.PolicyProfileStrictAgent,
		threshold: security.RiskModerate,
		fallback:  gate.NoElicitFallbackChallenge,
	})
	defer rig.close(t)
	_, err := rig.srv.Prepare(context.Background())
	requireNoErr(t, err, "Prepare")

	hostID, _ := inventory.ParseHostID("h-approved")
	ep, _ := netaddr.ParseEndpoint("10.0.0.55:22")
	hostObj, err := inventory.NewHost(inventory.HostSpec{ID: hostID, Endpoint: ep})
	requireNoErr(t, err, "NewHost")

	// 1. 首次写操作触发两步审批挑战
	baseArgs := map[string]any{"action": "create_host", "host": hostObj}
	res1, body1 := callToolJSON(t, rig.srv, 100, protocol.ToolNameNodes, baseArgs)
	if !res1.IsError || body1["code"] != "approval_required" {
		t.Fatalf("期望返回 approval_required 挑战，实际: isErr=%v body=%+v", res1.IsError, body1)
	}
	chalMap, ok := body1["approval_challenge"].(map[string]any)
	if !ok || chalMap["envelope_digest"] == "" || chalMap["envelope"] == nil {
		t.Fatalf("审批挑战载荷缺失 envelope/envelope_digest: %+v", body1)
	}

	// 2. 篡改摘要提交必须拒绝
	resBad, _ := callToolJSON(t, rig.srv, 101, protocol.ToolNameNodes, map[string]any{
		"action": "create_host", "host": hostObj,
		"approval": map[string]any{
			"verdict":         "allow",
			"envelope_digest": security.DigestBytes([]byte("wrong")).String(),
			"envelope":        chalMap["envelope"],
		},
	})
	if !resBad.IsError {
		t.Fatalf("篡改摘要的审批提交必须被拒绝")
	}

	// 3. 合法审批提交成功放行
	approvedArgs := map[string]any{
		"action": "create_host", "host": hostObj,
		"approval": map[string]any{
			"verdict":         "allow",
			"envelope_digest": chalMap["envelope_digest"],
			"envelope":        chalMap["envelope"],
			"comment":         "operator confirmed",
		},
	}
	res2, _ := callToolJSON(t, rig.srv, 102, protocol.ToolNameNodes, approvedArgs)
	if res2.IsError {
		t.Fatalf("合法两步审批提交应成功: %s", res2.StructuredContent)
	}

	// 4. 重放已消费审批信封必须被防重放缓存拒绝
	resReplay, _ := callToolJSON(t, rig.srv, 103, protocol.ToolNameNodes, approvedArgs)
	if !resReplay.IsError {
		t.Fatalf("重放审批信封必须被拒绝")
	}
}

func TestMCPRuntime_StartupCrashReconcileFailClosedAndHalted(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newMCPUnitRig(t, mcpUnitOpts{profile: gate.PolicyProfileStrictAgent})
	defer rig.close(t)
	ctx := context.Background()

	// 1. 制造崩溃同级进程残留锁与未闭合 Authorized 审计记录，验证 Prepare 自动执行 O(1) 崩溃对账
	deadSink, err := rig.auditCluster.NewSinkFromEntropy(rig.rng.Fork())
	requireNoErr(t, err, "NewSinkFromEntropy dead")
	crashedOpID, err := security.ParseOperationID("op-mcp-crash-1")
	requireNoErr(t, err, "ParseOperationID crashed")
	crashedTID, err := security.ParseTraceID("trace-mcp-crash-1")
	requireNoErr(t, err, "ParseTraceID crashed")
	binding, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityKindOf[security.CapExecute](), Tool: "terminal_exec", Action: "exec", NodeID: "web-1",
	})
	requireNoErr(t, err, "NewOperationBinding")
	requireNoErr(t, deadSink.StageOperation(ctx, crashedOpID), "StageOperation crashed")
	authEntry, err := ports.NewAuditEntry(ports.AuditEntrySpec{
		ProcessID: deadSink.ProcessInstanceID(), TraceID: crashedTID, OperationID: crashedOpID,
		Phase: ports.AuditPhaseAuthorized, Outcome: ports.AuditOutcomePending,
		Risk: security.RiskSafe, Decision: security.DecisionKindAllow, Binding: binding,
		Timestamp: rig.clk.Now().UTC(), Reason: "authorized before crash",
	})
	requireNoErr(t, err, "NewAuditEntry crashed")
	requireNoErr(t, deadSink.Record(ctx, authEntry), "Record crashed")
	deadSink.SimulateSIGKILL()

	rep, err := rig.srv.Prepare(ctx)
	requireNoErr(t, err, "Prepare")
	auditRep, hasAudit := rep.AuditReport().Get()
	if !hasAudit || auditRep.DeadLocksClaimed() != 1 || len(auditRep.AbortedOperations()) != 1 || auditRep.AbortedOperations()[0] != crashedOpID {
		t.Fatalf("启动期 O(1) 崩溃对账失配: has=%v rep=%+v", hasAudit, auditRep)
	}

	// 2. 启动期对账失败必须 Fail-Closed 拒绝启动
	failRig := newMCPUnitRig(t, mcpUnitOpts{reconcileErr: errors.New("lock dir io error")})
	defer failRig.close(t)
	if _, err := failRig.srv.Prepare(ctx); !errors.Is(err, mcpruntime.ErrStartupReconcileFailed) {
		t.Fatalf("对账器 I/O 失败期望 ErrStartupReconcileFailed，实际=%v", err)
	}

	// 3. 终态审计落盘 ENOSPC 触发 StrictAgentProfile 不可逆 Halted 熔断
	rig.auditSink.SetBoundaryHook(func(b sim.AuditBoundary, _ security.OperationID) {
		if b == sim.AuditBoundaryAfterAuthorized {
			rig.auditCluster.SetENOSPC(true)
		}
	})
	trigResp := callRPC(t, rig.srv, 301, "tools/call", map[string]any{
		"name": protocol.ToolNameNodes, "arguments": map[string]any{"action": "list_nodes"},
	})
	rig.auditSink.SetBoundaryHook(nil)
	rig.auditCluster.SetENOSPC(false)

	if !rig.gate.IsHalted() || trigResp.Error == nil || trigResp.Error.Code != protocol.CodeGateHalted {
		t.Fatalf("终态审计落盘失败后必须立即进入 Halted 并返回 -32001: halted=%v err=%+v", rig.gate.IsHalted(), trigResp.Error)
	}
	haltedResp := callRPC(t, rig.srv, 302, "tools/call", map[string]any{
		"name": protocol.ToolNameNodes, "arguments": map[string]any{"action": "list_nodes"},
	})
	if haltedResp.Error == nil || haltedResp.Error.Code != protocol.CodeGateHalted {
		t.Fatalf("Halted 后 JSON-RPC 必须返回 CodeGateHalted(-32001)，实际=%+v", haltedResp.Error)
	}

	// Halted 后 HTTP /mcp 与 /healthz 立即返回 503
	h := rig.srv.Handler()
	for _, p := range []struct{ method, path, body string }{
		{http.MethodPost, "/mcp", `{"jsonrpc":"2.0","id":1,"method":"ping"}`},
		{http.MethodGet, "/healthz", ""},
	} {
		req := httptest.NewRequest(p.method, "http://127.0.0.1:8080"+p.path, strings.NewReader(p.body))
		req.Host = "127.0.0.1:8080"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("Halted 后 %s %s 期望 503，实际=%d", p.method, p.path, rec.Code)
		}
	}
}
