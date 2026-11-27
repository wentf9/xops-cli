package cli_test

import (
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli"
)

func TestApp_HostsVaultAndConfigCommands(t *testing.T) {
	defer goleak.VerifyNone(t)

	h := newFullAppHarness(t, func(cfg *cli.AppConfig) {
		cfg.ReadOperatorFile = func(_ context.Context, _ pathalg.LocalSourcePath, _ pathalg.SymlinkPolicy, _ int64) ([]byte, error) {
			return []byte("Host demo\n  HostName 10.0.0.1\n"), nil
		}
	}, strings.NewReader("host,ip\nweb,10.0.0.2\n"))

	jsonCmds := [][]string{
		{"hosts", "list", "--kind", "nodes", "--tag", "prod", "--json"},
		{"hosts", "list", "--kind", "hosts", "--json"},
		{"hosts", "list", "--kind", "identities", "--json"},
		{"hosts", "get", "--kind", "node", "web-1", "--json"},
		{"hosts", "get", "--kind", "host", "web-host", "--json"},
		{"hosts", "get", "--kind", "identity", "deploy-id", "--json"},
		{"hosts", "resolve", "-p", "2200", "web-1", "--json"},
		{"hosts", "validate-dag", "--json"},
		{"hosts", "check-secret-refs", "--ref", "vault/pw", "--json"},
		{"creds", "status", "--json"},
		{"vault", "init", "--json"},
		{"vault", "unlock", "--json"},
		{"vault", "lock", "--json"},
		{"vault", "doctor", "--skip-probe", "--json"},
		{"vault", "refs", "vault/pw", "--json"},
		{"vault", "delete", "vault/pw", "--json"},
		{"vault", "gc", "vault/old1", "vault/old2", "--json"},
		{"config", "formats", "--json"},
	}
	for _, args := range jsonCmds {
		h.stdout.Reset()
		h.stderr.Reset()
		if code := h.app.Run(context.Background(), args); code != 0 {
			t.Fatalf("命令 %v 失败: code=%d stderr=%q", args, code, h.stderr.String())
		}
		var decoded map[string]any
		if err := jsonv2.Unmarshal(h.stdout.Bytes(), &decoded); err != nil {
			t.Fatalf("命令 %v 输出非合法 JSON/v2: err=%v out=%q", args, err, h.stdout.String())
		}
	}

	// 验证资产 CRUD、enroll-key 与 config import 路由与参数透传。
	textCmds := [][]string{
		{"hosts", "create-host", "--id", "h1", "--address", "10.0.0.10:22", "--tag", "prod"},
		{"hosts", "update-host", "--id", "h1", "--address", "10.0.0.11:22", "--expected-revision", "rev-1"},
		{"hosts", "create-identity", "--id", "id1", "--user", "ops", "--auth-kind", "password", "--password-ref", "vault/ops"},
		{"hosts", "create-node", "--id", "n1", "--host", "h1", "--identity", "id1", "--jump", "bastion", "--dialect", "posix"},
		{"hosts", "delete-node", "n1", "--delete-unused-secrets", "--require-unreferenced"},
		{"vault", "enroll-key", "--id", "key-id", "--user", "ops", "--key-path", "/home/ops/.ssh/id_ed25519"},
		{"vault", "enroll-password", "--id", "pw-id", "--user", "ops", "--store", "offline"},
		{"vault", "set-node-privilege", "--node", "n1", "--ref", "offline/sudo-pw"},
		{"vault", "rotate", "offline/old-pw", "--store", "offline"},
		{"config", "import", "--format", "openssh", "--file", "/tmp/ssh_config", "--plan"},
		{"config", "import", "--format", "csv", "--stdin", "--dry-run"},
	}
	for _, args := range textCmds {
		h.stdout.Reset()
		h.stderr.Reset()
		if code := h.app.Run(context.Background(), args); code != 0 {
			t.Fatalf("命令 %v 失败: code=%d stderr=%q", args, code, h.stderr.String())
		}
	}
	if !h.eng.lastDeleteReq.DeleteUnusedSecrets || !h.eng.lastDeleteReq.RequireSecretsUnreferenced {
		t.Fatalf("delete-node 标志未透传: %+v", h.eng.lastDeleteReq)
	}
	if h.eng.lastImportReq.Format != "csv" || !h.eng.lastImportReq.DryRun {
		t.Fatalf("config import 参数未透传: %+v", h.eng.lastImportReq)
	}
}

func TestApp_PlaybookDoctorAuditAndSubEntries(t *testing.T) {
	defer goleak.VerifyNone(t)

	validYAML := `version: 2
id: deploy-check
name: Deploy Health Check
on_error: fail_fast
target:
  all: true
steps:
  - id: ping
    name: Check Uptime
    action:
      kind: shell
      command: uptime
`
	// 1) playbook validate 绝不初始化 Engine，支持 YAML 与 JSON，拒绝 YAML 别名。
	hVal := newFullAppHarness(t, nil, strings.NewReader(validYAML))
	if code := hVal.app.Run(context.Background(), []string{"playbook", "validate", "--stdin", "--json"}); code != 0 {
		t.Fatalf("playbook validate YAML 失败: code=%d stderr=%q", code, hVal.stderr.String())
	}
	if hVal.factoryCalls != 0 || !strings.Contains(hVal.stdout.String(), `"id":"deploy-check"`) {
		t.Fatalf("playbook validate 不得调用 EngineFactory 且应输出 id: calls=%d out=%q", hVal.factoryCalls, hVal.stdout.String())
	}

	aliasYAML := "a: &anchor 1\nb: *anchor\n"
	hBadYAML := newFullAppHarness(t, nil, strings.NewReader(aliasYAML))
	if code := hBadYAML.app.Run(context.Background(), []string{"playbook", "validate", "--stdin"}); code != 2 || hBadYAML.factoryCalls != 0 {
		t.Fatalf("YAML 别名应返回退出码 2 且不初始化 Engine: code=%d calls=%d", code, hBadYAML.factoryCalls)
	}

	// 2) playbook run 正确透传 ExtraVars 与 Concurrency。
	hRunPB := newFullAppHarness(t, nil, strings.NewReader(validYAML))
	hRunPB.eng.runPlaybookFn = func(_ context.Context, _ engine.PlaybookRequest) (res engine.PlaybookRunResult, err error) {
		return res, errors.New("stub-run")
	}
	_ = hRunPB.app.Run(context.Background(), []string{"play", "run", "--stdin", "--var", "env=prod", "--concurrency", "3"})
	if !hRunPB.eng.hasCall("RunPlaybook") || hRunPB.eng.lastPlaybookReq.Concurrency != 3 || hRunPB.eng.lastPlaybookReq.ExtraVars["env"] != "prod" {
		t.Fatalf("playbook run 参数未透传: %+v", hRunPB.eng.lastPlaybookReq)
	}

	// 3) doctor：--scope all 下容忍 ErrVaultUnavailable，不健康时返回退出码 1。
	hDoc := newFullAppHarness(t, nil, nil)
	hDoc.eng.vaultDoctorFn = func(context.Context, engine.VaultDoctorRequest) (engine.CredentialDoctorRep, error) {
		return engine.CredentialDoctorRep{}, engine.ErrVaultUnavailable
	}
	if code := hDoc.app.Run(context.Background(), []string{"doctor", "--scope", "all", "--json"}); code != 0 || !strings.Contains(hDoc.stdout.String(), `"vault_note":"vault not configured"`) {
		t.Fatalf("doctor 应优雅降级 VaultUnavailable: code=%d out=%q err=%q", code, hDoc.stdout.String(), hDoc.stderr.String())
	}
	hDoc.eng.invDoctorFn = func(context.Context, engine.InventoryDoctorRequest) (engine.InventoryDoctorRep, error) {
		return engine.InventoryDoctorRep{Healthy: false, ErrorCount: 1}, nil
	}
	if code := hDoc.app.Run(context.Background(), []string{"doctor", "--scope", "inventory", "--json"}); code != 1 {
		t.Fatalf("不健康诊断应返回退出码 1，实际=%d", code)
	}

	// 4) audit reconcile (Engine) + audit list/tail/inspect (ReadAuditLog 钩子及 nil 失败关闭)。
	assertAuditAndSubEntries(t)
}

func assertAuditAndSubEntries(t *testing.T) {
	t.Helper()
	assertAuditReconcileAndNilHooks(t)
	assertAuditQueryAndSubEntryHooks(t)
}

func assertAuditReconcileAndNilHooks(t *testing.T) {
	t.Helper()
	hNil := newFullAppHarness(t, nil, nil)
	if code := hNil.app.Run(context.Background(), []string{"audit", "reconcile", "--json"}); code != 0 || !strings.Contains(hNil.stdout.String(), `"scanned_locks":2`) {
		t.Fatalf("audit reconcile --json 失败: code=%d out=%q err=%q", code, hNil.stdout.String(), hNil.stderr.String())
	}
	for _, nilArgs := range [][]string{{"audit", "list"}, {"tui"}, {"mcp", "serve"}} {
		if code := hNil.app.Run(context.Background(), nilArgs); code != 1 {
			t.Fatalf("未注入钩子时 %v 应失败关闭返回 1，实际=%d", nilArgs, code)
		}
	}
}

func assertAuditQueryAndSubEntryHooks(t *testing.T) {
	t.Helper()
	tr, _ := security.ParseTraceID("0123456789abcdef0123456789abcdef")
	op, _ := security.ParseOperationID("fedcba9876543210")
	var gotAuditReq cli.AuditQueryRequest
	var gotTUIReq cli.TUIStartRequest
	var gotMCPReq cli.MCPStartRequest
	h := newFullAppHarness(t, func(cfg *cli.AppConfig) {
		cfg.ReadAuditLog = func(_ context.Context, req cli.AuditQueryRequest) (cli.AuditQueryResult, error) {
			gotAuditReq = req
			return cli.AuditQueryResult{
				TotalMatched: 1,
				Entries: []cli.AuditRecordView{{
					ProcessID:   "proc-1",
					TraceID:     tr,
					OperationID: op,
					Phase:       "finalized",
					Outcome:     "succeeded",
					Risk:        security.RiskSafe,
					Decision:    security.DecisionKindAllow,
					Capability:  security.CapabilityExecute,
					Tool:        "exec",
					Action:      "run",
					Timestamp:   time.Unix(1700000000, 0).UTC(),
					Duration:    algebraic.Some(algebraic.FromStdDuration(250 * time.Millisecond)),
				}},
			}, nil
		}
		cfg.RunTUI = func(_ context.Context, req cli.TUIStartRequest) error {
			gotTUIReq = req
			return nil
		}
		cfg.RunMCP = func(_ context.Context, req cli.MCPStartRequest) error {
			gotMCPReq = req
			return nil
		}
	}, nil)

	if code := h.app.Run(context.Background(), []string{"audit", "tail", "--limit", "5", "--phase", "finalized", "--json"}); code != 0 {
		t.Fatalf("audit tail 失败: code=%d stderr=%q", code, h.stderr.String())
	}
	if gotAuditReq.Limit != 5 || !gotAuditReq.Tail || gotAuditReq.Phase != "finalized" || !strings.Contains(h.stdout.String(), `"duration":"250ms"`) {
		t.Fatalf("audit tail 请求或 algebraic.Duration 序列化异常: req=%+v out=%q", gotAuditReq, h.stdout.String())
	}
	if code := h.app.Run(context.Background(), []string{"audit", "list", "--limit", "3"}); code != 0 || gotAuditReq.Tail || gotAuditReq.Limit != 3 {
		t.Fatalf("audit list 请求异常: code=%d req=%+v", code, gotAuditReq)
	}

	if code := h.app.Run(context.Background(), []string{"--policy", "strict_agent", "tui", "--node", "web-1", "--refresh", "2s", "--no-alt-screen"}); code != 0 {
		t.Fatalf("tui 失败: code=%d stderr=%q", code, h.stderr.String())
	}
	if gotTUIReq.InitialNode != "web-1" || !gotTUIReq.NoAltScreen || gotTUIReq.InitOptions.PolicyProfile != engine.PolicyProfileStrictAgent {
		t.Fatalf("TUIStartRequest 失配: %+v", gotTUIReq)
	}

	if code := h.app.Run(context.Background(), []string{
		"--policy", "strict_agent", "mcp", "serve", "--transport", "http",
		"--listen", "127.0.0.1:9090", "--transfer-root", "/tmp", "--allowed-origin", "http://localhost",
	}); code != 0 {
		t.Fatalf("mcp serve 失败: code=%d stderr=%q", code, h.stderr.String())
	}
	if gotMCPReq.Transport != "http" || gotMCPReq.ListenAddr != "127.0.0.1:9090" || gotMCPReq.InitOptions.PolicyProfile != engine.PolicyProfileStrictAgent {
		t.Fatalf("MCPStartRequest 失配: %+v", gotMCPReq)
	}
}

func TestApp_GlobalFlagsVersionJSONAndAllHelpTopics(t *testing.T) {
	defer goleak.VerifyNone(t)

	h := newFullAppHarness(t, nil, nil)

	// 1) version --json 与 --json version 均不得触发 EngineFactory。
	for _, args := range [][]string{{"version", "--json"}, {"--json", "version"}} {
		h.stdout.Reset()
		if code := h.app.Run(context.Background(), args); code != 0 {
			t.Fatalf("%v 失败: code=%d stderr=%q", args, code, h.stderr.String())
		}
		var vv cli.VersionView
		if err := jsonv2.Unmarshal(h.stdout.Bytes(), &vv); err != nil || vv.Version != "v2.3.3" || vv.Commit != "deadbeef" {
			t.Fatalf("%v JSON 解析异常: err=%v view=%+v", args, err, vv)
		}
	}

	// 2) 非法 --policy 在触发 EngineFactory 前返回退出码 2。
	if code := h.app.Run(context.Background(), []string{"--policy", "bogus", "ssh", "web"}); code != 2 {
		t.Fatalf("非法 --policy 应返回 2，实际=%d", code)
	}

	// 3) 全部 15 个帮助主题与别名均返回 0 且绝不触发 EngineFactory。
	topics := []string{
		"ssh", "exec", "tunnel", "forward", "mux", "scp", "sftp",
		"hosts", "host", "inventory", "creds", "cred", "vault",
		"config", "playbook", "play", "doctor", "audit", "mcp", "tui", "version",
	}
	for _, topic := range topics {
		h.stdout.Reset()
		if code := h.app.Run(context.Background(), []string{"help", topic}); code != 0 || h.stdout.Len() == 0 {
			t.Fatalf("help %s 失败: code=%d len=%d", topic, code, h.stdout.Len())
		}
	}
	if h.factoryCalls != 0 {
		t.Fatalf("version/help/非法全局标志绝不应调用 EngineFactory，实际=%d", h.factoryCalls)
	}

	// 4) 全局 --policy + -F 正确透传到 EngineInitOptions。
	if code := h.app.Run(context.Background(), []string{"--policy", "direct_operator", "-F", "/tmp/global.cfg", "ssh", "web", "id"}); code != 0 {
		t.Fatalf("全局 --policy/-F 透传失败: code=%d stderr=%q", code, h.stderr.String())
	}
	if h.lastInitOpts.PolicyProfile != engine.PolicyProfileDirectOperator || h.lastInitOpts.OpenSSHConfigFile != "/tmp/global.cfg" {
		t.Fatalf("EngineInitOptions 失配: %+v", h.lastInitOpts)
	}
}
