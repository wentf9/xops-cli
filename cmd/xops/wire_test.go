package main

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/entry/cli"
)

func setupIsolatedRootEnv(t *testing.T) (homeDir, xopsHome pathalg.LocalDir) {
	t.Helper()
	base := t.TempDir()
	hRaw := filepath.Join(base, "home")
	xRaw := filepath.Join(base, "xops")
	var err error
	homeDir, err = pathalg.ParseLocalDir(hRaw)
	if err != nil {
		t.Fatalf("ParseLocalDir(home): %v", err)
	}
	xopsHome, err = pathalg.ParseLocalDir(xRaw)
	if err != nil {
		t.Fatalf("ParseLocalDir(xops): %v", err)
	}
	rootFS := osfs.NewScopedRootFS()
	if err := rootFS.EnsureRoot(homeDir, 0o700); err != nil {
		t.Fatalf("EnsureRoot(home): %v", err)
	}
	if err := rootFS.EnsureRoot(xopsHome, 0o700); err != nil {
		t.Fatalf("EnsureRoot(xops): %v", err)
	}
	t.Setenv("HOME", hRaw)
	t.Setenv("USERPROFILE", hRaw)
	t.Setenv("XOPS_HOME", xRaw)
	return homeDir, xopsHome
}

func TestShutdownStack_StrictReverseOrderIdempotentAndErrorsJoin(t *testing.T) {
	defer goleak.VerifyNone(t)
	stack := newShutdownStack(2 * time.Second)
	var order []string
	var sawCleanDeadline bool
	errVault := errors.New("vault lock error")
	errAudit := errors.New("audit close error")

	stack.onStage = func(stage string) { order = append(order, stage) }
	stack.Add("sys", func(c context.Context) error {
		_, dl := c.Deadline()
		sawCleanDeadline = dl && c.Err() == nil
		return nil
	})
	stack.Add("audit", func(context.Context) error { return errAudit })
	stack.Add("store", func(context.Context) error { return nil })
	stack.Add("vault", func(context.Context) error { return errVault })
	stack.Add("engine", func(context.Context) error { return nil })
	stack.Add("entry", func(context.Context) error { return nil })

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	err1 := stack.Close(canceledCtx)
	err2 := stack.Close(context.Background())
	if !errors.Is(err1, errVault) || !errors.Is(err1, errAudit) {
		t.Fatalf("停机错误必须经 errors.Join 完整聚合: %v", err1)
	}
	if !errors.Is(err2, errVault) || !errors.Is(err2, errAudit) || err1.Error() != err2.Error() {
		t.Fatalf("重复 Close 必须幂等返回相同聚合错误: err1=%v err2=%v", err1, err2)
	}
	wantOrder := []string{"entry", "engine", "vault", "store", "audit", "sys"}
	if !slices.Equal(order, wantOrder) {
		t.Fatalf("逆序停机顺序失配: got=%v want=%v", order, wantOrder)
	}
	if !sawCleanDeadline {
		t.Fatal("已取消父上下文传入 Close 时，子阶段必须收到剥离取消且带有限超时的上下文")
	}
}

func TestWireRuntime_ConfigDocumentAndReverseShutdownOrder(t *testing.T) {
	defer goleak.VerifyNone(t)
	_, xopsHome := setupIsolatedRootEnv(t)

	cfgYAML := `version: 2
vault:
  default_store: primary
  stores:
    primary:
      kind: offline_aead
      path: vault_primary
    oskey:
      kind: os_keychain
    disabled:
      kind: none
    exthelper:
      kind: external_helper
      command: /bin/true
      timeout: 3s
policy:
  cli_default: strict
  mcp_default: strict_agent
  guardrail:
    approval_threshold: dangerous
    no_elicit_fallback: challenge
    audit_log: custom_audit.jsonl
    protected_paths:
      - "/etc/**"
      - "/boot/**"
    node_overrides:
      "prod-*":
        approval_threshold: safe
        decision_floor: need_approval
    approval_ttl: 3m
options:
  server_alive_interval: 15s
  strict_host_key_checking: "yes"
inventory:
  known_stores:
    - primary
    - oskey
`
	rootFS := osfs.NewScopedRootFS()
	cfgDest, _ := pathalg.ParseLocalRootedDest("config.yaml")
	if err := rootFS.WithRoot(xopsHome, func(root ports.RootHandle) error {
		return root.AtomicReplace(cfgDest, 0o600, func(w io.Writer) error {
			_, wErr := io.WriteString(w, cfgYAML)
			return wErr
		})
	}); err != nil {
		t.Fatalf("写入 config.yaml 失败: %v", err)
	}

	ctx := context.Background()
	rt, err := wireRuntime(ctx, cli.EngineInitOptions{OpenSSHConfigFile: "none"}, runtimeModeCLI, strings.NewReader(""), io.Discard)
	if err != nil {
		t.Fatalf("wireRuntime(CLI): %v", err)
	}
	assertWiredCLIConfig(t, rt)

	// 验证按 Entry -> Engine -> Vault -> Store -> Audit -> Sys 严格逆序关闭。
	var closedOrder []string
	rt.shutdown.Add("entry", func(context.Context) error { return nil })
	rt.shutdown.onStage = func(stage string) { closedOrder = append(closedOrder, stage) }
	if err := rt.Close(ctx); err != nil {
		t.Fatalf("rt.Close: %v", err)
	}
	wantOrder := []string{"entry", "engine", "vault", "store", "audit", "sys"}
	if !slices.Equal(closedOrder, wantOrder) {
		t.Fatalf("wireRuntime 逆序停机违背约定: got=%v want=%v", closedOrder, wantOrder)
	}

	// 验证显式 CLI --policy 覆写优先于 config.yaml cli_default。
	rt2, err := wireRuntime(ctx, cli.EngineInitOptions{
		OpenSSHConfigFile: "none",
		PolicyProfile:     engine.PolicyProfileDirectOperator,
	}, runtimeModeCLI, strings.NewReader(""), io.Discard)
	if err != nil {
		t.Fatalf("wireRuntime(CLI override): %v", err)
	}
	defer func() {
		if cErr := rt2.Close(ctx); cErr != nil {
			t.Errorf("rt2.Close: %v", cErr)
		}
	}()
	if rt2.engineCfg.Profile != engine.PolicyProfileDirectOperator {
		t.Fatalf("显式 --policy 覆写未生效: got=%s", rt2.engineCfg.Profile)
	}
}

func assertWiredCLIConfig(t *testing.T, rt *wiredRuntime) {
	t.Helper()
	if !rt.reconciled {
		t.Fatal("CLI 模式启动必须执行 O(1) ReconcileCrashedAudits")
	}
	if rt.engineCfg.Profile != engine.PolicyProfileStrictOperator {
		t.Fatalf("未传 --policy 时应采用 config.yaml cli_default=strict，实际=%s", rt.engineCfg.Profile)
	}
	if rt.engineCfg.OperatorReadFS == nil || rt.engineCfg.Vault == nil || rt.engineCfg.VaultControl == nil ||
		rt.engineCfg.InventoryStore == nil || rt.engineCfg.JournalStore == nil || len(rt.engineCfg.Importers) != 2 ||
		rt.engineCfg.Agent == nil || rt.engineCfg.TUNDevice == nil || rt.engineCfg.SSHFPLookup == nil || rt.engineCfg.Interaction == nil {
		t.Fatalf("CLI 模式缺少 Phase 4 真实宿主适配器装配: %+v", rt.engineCfg)
	}
	if rt.engineCfg.Guardrail.ApprovalThreshold != security.RiskDangerous ||
		rt.engineCfg.Guardrail.NoElicitFallback != engine.NoElicitFallbackChallenge ||
		rt.engineCfg.Guardrail.NodeOverrides.IsNone() ||
		rt.engineCfg.Guardrail.ApprovalTTL.IsNone() {
		t.Fatalf("GuardrailConfigDTO 未完整解码: %+v", rt.engineCfg.Guardrail)
	}
	if rt.engineCfg.GlobalOptions.ServerAliveInterval().IsNone() {
		t.Fatal("Tier-3 GlobalOptions 未从 config.yaml options 段加载")
	}
	if !slices.Contains(rt.engineCfg.KnownStores, "primary") || !slices.Contains(rt.engineCfg.KnownStores, "exthelper") {
		t.Fatalf("KnownStores 未汇总全部路由器存储: %v", rt.engineCfg.KnownStores)
	}
}

func TestWireRuntime_MCPModePhysicallyIsolatesOperatorReadFS(t *testing.T) {
	defer goleak.VerifyNone(t)
	setupIsolatedRootEnv(t)

	ctx := context.Background()
	rt, err := wireRuntime(ctx, cli.EngineInitOptions{}, runtimeModeMCP, strings.NewReader(""), io.Discard)
	if err != nil {
		t.Fatalf("wireRuntime(MCP): %v", err)
	}
	defer func() {
		if cErr := rt.Close(ctx); cErr != nil {
			t.Errorf("rt.Close(MCP): %v", cErr)
		}
	}()

	if rt.engineCfg.OperatorReadFS != nil {
		t.Fatal("MCP 模式严禁向 engine.Config 注入 OperatorReadFS")
	}
	if rt.engineCfg.Interaction != nil || rt.engineCfg.Terminal != nil || rt.engineCfg.SSHFPLookup != nil {
		t.Fatal("MCP 模式严禁注入本地交互终端或 OperatorReadFS 派生适配器")
	}
	if rt.engineCfg.ScopedFS == nil {
		t.Fatal("MCP 模式必须注入 ScopedRootFS")
	}
	if rt.engineCfg.Profile != engine.PolicyProfileStrictAgent {
		t.Fatalf("MCP 模式默认策略配置档应为 StrictAgent，实际=%s", rt.engineCfg.Profile)
	}
	if rt.reconciled {
		t.Fatal("MCP 模式应由 MCPServer.Prepare(ctx) 统一执行启动对账与 WAL 恢复，不应重复执行")
	}

	srv, err := rt.engine.NewMCPServer(engine.MCPConfig{ServerName: "xops-mcp", ServerVersion: "2.0.0"})
	if err != nil {
		t.Fatalf("NewMCPServer: %v", err)
	}
	report, err := srv.Prepare(ctx)
	if err != nil || !report.IsValid() {
		t.Fatalf("MCPServer.Prepare 失败: report=%+v err=%v", report, err)
	}
	if err := srv.Close(ctx); err != nil {
		t.Fatalf("MCPServer.Close: %v", err)
	}
}

func TestHooks_ReadAuditLogOperatorFileWorkDirAndLocalFS(t *testing.T) {
	defer goleak.VerifyNone(t)
	homeDir, xopsHome := setupIsolatedRootEnv(t)
	ctx := context.Background()

	assertReadAuditLogHook(t, ctx, xopsHome)
	assertOperatorFileAndLocalFSHooks(t, ctx, homeDir)
}

func assertReadAuditLogHook(t *testing.T, ctx context.Context, xopsHome pathalg.LocalDir) {
	t.Helper()
	// 1. audit.jsonl 缺失时零副作用返回空结果。
	emptyRes, err := readAuditLogHook(ctx, cli.AuditQueryRequest{Limit: 10})
	if err != nil || emptyRes.TotalMatched != 0 || len(emptyRes.Entries) != 0 {
		t.Fatalf("空审计日志期望返回空结果，实际 res=%+v err=%v", emptyRes, err)
	}

	// 2. 写入两条脱敏审计记录并验证过滤、Limit 与 Tail。
	trace1, _ := security.NewTraceIDFrom(rand.Reader)
	op1, _ := security.NewOperationIDFrom(rand.Reader)
	op2, _ := security.NewOperationIDFrom(rand.Reader)
	procID, _ := ports.NewProcessInstanceIDFrom(rand.Reader)
	b1, _ := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityExecute, Tool: "ssh", Action: "exec", NodeID: "node-alpha",
	})
	b2, _ := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityFileRead, Tool: "sftp", Action: "read", NodeID: "node-beta",
	})
	e1, _ := ports.NewAuditEntry(ports.AuditEntrySpec{
		ProcessID: procID, TraceID: trace1, OperationID: op1,
		Phase: ports.AuditPhaseAuthorized, Outcome: ports.AuditOutcomePending,
		Risk: security.RiskModerate, Decision: security.DecisionKindAllow,
		Binding: b1, Timestamp: time.Now().UTC().Add(-2 * time.Second).Round(0),
	})
	e2, _ := ports.NewAuditEntry(ports.AuditEntrySpec{
		ProcessID: procID, TraceID: trace1, OperationID: op2,
		Phase: ports.AuditPhaseFinalized, Outcome: ports.AuditOutcomeSucceeded,
		Risk: security.RiskSafe, Decision: security.DecisionKindAllow,
		Binding: b2, Timestamp: time.Now().UTC().Round(0),
	})
	raw1, _ := e1.CanonicalJSON()
	raw2, _ := e2.CanonicalJSON()
	rootFS := osfs.NewScopedRootFS()
	auditDest, _ := pathalg.ParseLocalRootedDest("audit.jsonl")
	if err := rootFS.WithRoot(xopsHome, func(root ports.RootHandle) error {
		if aErr := root.AppendLine(auditDest, 0o600, raw1); aErr != nil {
			return aErr
		}
		return root.AppendLine(auditDest, 0o600, raw2)
	}); err != nil {
		t.Fatalf("写入测试 audit.jsonl 失败: %v", err)
	}

	tailRes, err := readAuditLogHook(ctx, cli.AuditQueryRequest{Limit: 1, Tail: true})
	if err != nil || tailRes.TotalMatched != 2 || !tailRes.Truncated || len(tailRes.Entries) != 1 || tailRes.Entries[0].NodeID != "node-beta" {
		t.Fatalf("Tail 审计查询失配: res=%+v err=%v", tailRes, err)
	}
	filtRes, err := readAuditLogHook(ctx, cli.AuditQueryRequest{
		Phase:       "authorized",
		OperationID: algebraic.Some(op1),
		TraceID:     algebraic.Some(trace1),
		NodeID:      "node-alpha",
	})
	if err != nil || filtRes.TotalMatched != 1 || len(filtRes.Entries) != 1 || filtRes.Entries[0].Tool != "ssh" {
		t.Fatalf("多条件过滤审计查询失配: res=%+v err=%v", filtRes, err)
	}
}

func assertOperatorFileAndLocalFSHooks(t *testing.T, ctx context.Context, homeDir pathalg.LocalDir) {
	t.Helper()
	// 3. ReadOperatorFile 正常读取与超限拒绝。
	sampleFile := filepath.Join(filepath.FromSlash(homeDir.String()), "sample.txt")
	if err := os.WriteFile(sampleFile, []byte("hello-operator-read"), 0o600); err != nil {
		t.Fatalf("写入 sample.txt 失败: %v", err)
	}
	srcPath, err := pathalg.ParseLocalSourcePath(sampleFile)
	if err != nil {
		t.Fatalf("ParseLocalSourcePath: %v", err)
	}
	got, err := readOperatorFileHook(ctx, srcPath, pathalg.SymlinkFollowOperatorSource, 64)
	if err != nil || string(got) != "hello-operator-read" {
		t.Fatalf("readOperatorFileHook 失配: got=%q err=%v", string(got), err)
	}
	if _, err := readOperatorFileHook(ctx, srcPath, pathalg.SymlinkFollowOperatorSource, 4); !errors.Is(err, engine.ErrLimitExceeded) {
		t.Fatalf("超过 maxBytes 应返回 ErrLimitExceeded，实际=%v", err)
	}

	// 4. ResolveWorkDir 与 scopedLocalFSAdapter（目录/常规文件/缺失路径区分与 ReadDir）。
	wd, err := resolveWorkDir()
	if err != nil || !wd.IsValid() {
		t.Fatalf("resolveWorkDir 失败: wd=%v err=%v", wd, err)
	}
	localFS := newScopedLocalFSAdapter(osfs.NewScopedRootFS())
	isDir, err := localFS.IsDir(ctx, homeDir)
	if err != nil || !isDir {
		t.Fatalf("IsDir(homeDir) 期望 true: isDir=%v err=%v", isDir, err)
	}
	fileAsDir, _ := pathalg.ParseLocalDir(sampleFile)
	isDirFile, err := localFS.IsDir(ctx, fileAsDir)
	if err != nil || isDirFile {
		t.Fatalf("IsDir(regularFile) 期望 (false, nil): isDir=%v err=%v", isDirFile, err)
	}
	missingDir, _ := homeDir.JoinComponent("does-not-exist")
	isDirMissing, err := localFS.IsDir(ctx, missingDir)
	if err != nil || isDirMissing {
		t.Fatalf("IsDir(missingDir) 期望 (false, nil): isDir=%v err=%v", isDirMissing, err)
	}
	entries, err := localFS.ReadDir(ctx, homeDir)
	if err != nil || len(entries) != 1 || entries[0].Name != "sample.txt" || entries[0].IsDir {
		t.Fatalf("ReadDir(homeDir) 失配: entries=%+v err=%v", entries, err)
	}
}
