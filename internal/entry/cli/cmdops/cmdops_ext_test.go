package cmdops_test

import (
	"bytes"
	"context"
	jsonv2 "encoding/json/v2"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
	"github.com/wentf9/xops-cli/internal/entry/cli/cmdops"
)

type opsStub struct {
	lastPlaybookReq engine.PlaybookRequest
	runPlaybookErr  error
}

var (
	_ clikit.AutomationClient = (*opsStub)(nil)
	_ clikit.InventoryClient  = (*opsStub)(nil)
	_ clikit.VaultClient      = (*opsStub)(nil)
	_ clikit.ReconcileClient  = (*opsStub)(nil)
)

func (s *opsStub) Close(_ context.Context) error { return nil }
func (s *opsStub) RunSSH(_ context.Context, _ engine.RunSSHRequest) (execution.ExecutionOutcome, error) {
	out, _ := execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	return out, nil
}
func (s *opsStub) ResolveTarget(_ context.Context, _ engine.ResolveTargetRequest) (res engine.ResolvedTarget, err error) {
	return res, nil
}
func (s *opsStub) NewOperationStream(_ context.Context, _ int) (*events.OperationStream, error) {
	return nil, nil
}
func (s *opsStub) BatchExec(_ context.Context, _ engine.BatchExecRequest) (rep engine.BatchExecReport, err error) {
	return rep, nil
}
func (s *opsStub) RunPlaybook(_ context.Context, req engine.PlaybookRequest) (res engine.PlaybookRunResult, err error) {
	s.lastPlaybookReq = req
	return res, s.runPlaybookErr
}
func (s *opsStub) GetInventorySnapshot(_ context.Context, _ engine.InventoryQueryRequest) (snap engine.InventorySnapshot, err error) {
	return snap, nil
}
func (s *opsStub) GetHost(_ context.Context, _ inventory.HostID, _ engine.InventoryQueryRequest) (h inventory.Host, rev engine.Revision, err error) {
	return h, rev, nil
}
func (s *opsStub) GetIdentity(_ context.Context, _ inventory.IdentityID, _ engine.InventoryQueryRequest) (id inventory.Identity, rev engine.Revision, err error) {
	return id, rev, nil
}
func (s *opsStub) GetNode(_ context.Context, _ inventory.NodeID, _ engine.InventoryQueryRequest) (n inventory.Node, rev engine.Revision, err error) {
	return n, rev, nil
}
func (s *opsStub) ListHosts(_ context.Context, _ engine.InventoryQueryRequest) (out []inventory.Host, rev engine.Revision, err error) {
	return out, rev, nil
}
func (s *opsStub) ListIdentities(_ context.Context, _ engine.InventoryQueryRequest) (out []inventory.Identity, rev engine.Revision, err error) {
	return out, rev, nil
}
func (s *opsStub) ListNodes(_ context.Context, _ engine.InventoryQueryRequest) (out []inventory.Node, rev engine.Revision, err error) {
	return out, rev, nil
}
func (s *opsStub) CreateHost(_ context.Context, _ engine.HostMutationRequest) (res engine.MutationResult, err error) {
	return res, nil
}
func (s *opsStub) UpdateHost(_ context.Context, _ engine.HostMutationRequest) (res engine.MutationResult, err error) {
	return res, nil
}
func (s *opsStub) DeleteHost(_ context.Context, _ engine.DeleteAssetRequest) (res engine.MutationResult, err error) {
	return res, nil
}
func (s *opsStub) CreateIdentity(_ context.Context, _ engine.IdentityMutationRequest) (res engine.MutationResult, err error) {
	return res, nil
}
func (s *opsStub) UpdateIdentity(_ context.Context, _ engine.IdentityMutationRequest) (res engine.MutationResult, err error) {
	return res, nil
}
func (s *opsStub) DeleteIdentity(_ context.Context, _ engine.DeleteAssetRequest) (res engine.MutationResult, err error) {
	return res, nil
}
func (s *opsStub) CreateNode(_ context.Context, _ engine.NodeMutationRequest) (res engine.MutationResult, err error) {
	return res, nil
}
func (s *opsStub) UpdateNode(_ context.Context, _ engine.NodeMutationRequest) (res engine.MutationResult, err error) {
	return res, nil
}
func (s *opsStub) DeleteNode(_ context.Context, _ engine.DeleteAssetRequest) (res engine.MutationResult, err error) {
	return res, nil
}
func (s *opsStub) ValidateDAG(_ context.Context, _ engine.InventoryQueryRequest) (inventory.DAGReport, error) {
	return inventory.DAGReport{}, nil
}
func (s *opsStub) CheckSecretReferences(_ context.Context, _ engine.SecretRefCheckRequest) ([]inventory.SecretReference, error) {
	return nil, nil
}
func (s *opsStub) InventoryDoctor(_ context.Context, _ engine.InventoryDoctorRequest) (engine.InventoryDoctorRep, error) {
	return engine.InventoryDoctorRep{Healthy: true}, nil
}
func (s *opsStub) SupportedImportFormats() []string { return nil }
func (s *opsStub) PlanImport(_ context.Context, _ engine.ImportRequest) (p engine.ImportPreview, err error) {
	return p, nil
}
func (s *opsStub) ApplyImport(_ context.Context, _ engine.ImportRequest) (r engine.ImportResult, err error) {
	return r, nil
}
func (s *opsStub) EnrollEncryptedPrivateKeyIdentity(_ context.Context, _ engine.EnrollEncryptedPrivateKeyRequest) (r engine.EnrollEncryptedPrivateKeyResult, err error) {
	return r, nil
}
func (s *opsStub) VaultStatus(_ context.Context, _ engine.VaultOpRequest) (st engine.VaultStatus, err error) {
	return st, nil
}
func (s *opsStub) VaultInitInteractive(_ context.Context, _ engine.InteractiveVaultOpRequest) error {
	return nil
}
func (s *opsStub) VaultUnlockInteractive(_ context.Context, _ engine.InteractiveVaultOpRequest) error {
	return nil
}
func (s *opsStub) VaultLock(_ context.Context, _ engine.VaultOpRequest) error { return nil }
func (s *opsStub) VaultDoctor(_ context.Context, _ engine.VaultDoctorRequest) (engine.CredentialDoctorRep, error) {
	return engine.CredentialDoctorRep{Healthy: true}, nil
}
func (s *opsStub) FindSecretReferences(_ context.Context, _ engine.FindSecretReferencesRequest) ([]inventory.SecretReference, error) {
	return nil, nil
}
func (s *opsStub) DeleteSecret(_ context.Context, _ engine.DeleteSecretRequest) error { return nil }
func (s *opsStub) GCUnreferencedSecrets(_ context.Context, _ engine.GCUnreferencedRequest) (engine.GCUnreferencedResult, error) {
	return engine.GCUnreferencedResult{}, nil
}
func (s *opsStub) ExecuteVaultSagaInteractive(_ context.Context, _ engine.InteractiveVaultSagaRequest) (res engine.SagaResult, err error) {
	return res, nil
}
func (s *opsStub) RotateSecretInteractive(_ context.Context, _ engine.InteractiveRotateSecretRequest) (res engine.SagaResult, err error) {
	return res, nil
}
func (s *opsStub) ReconcileCrashedAudits(_ context.Context) (rep engine.ReconcileReport, err error) {
	return rep, nil
}

func newOpsRuntime(stub *opsStub, stdin string) (*clikit.Runtime, *bytes.Buffer, *bytes.Buffer) {
	var stdout, stderr bytes.Buffer
	rt := &clikit.Runtime{
		Stdin:           strings.NewReader(stdin),
		Stdout:          &stdout,
		Stderr:          &stderr,
		ShutdownTimeout: time.Second,
		EngineFactory: func(context.Context, clikit.EngineInitOptions) (clikit.EngineHandle, error) {
			return clikit.EngineHandle{Runner: stub}, nil
		},
	}
	return rt, &stdout, &stderr
}

func TestDecodePlaybookDocument_YAMLTimestampAndSafety(t *testing.T) {
	defer goleak.VerifyNone(t)

	// YAML 未加引号的 ISO 日期标量（!!timestamp）必须保留原始文本而非强转为 RFC3339 time.Time。
	yamlDoc := `version: 2
id: release-check
name: Release 2026-11-27
on_error: fail_fast
vars:
  release_date: 2026-11-27
target:
  all: true
steps:
  - id: s1
    name: 2026-11-27
    action:
      kind: shell
      command: echo ok
`
	pb, err := cmdops.DecodePlaybookDocument([]byte(yamlDoc))
	if err != nil {
		t.Fatalf("DecodePlaybookDocument(YAML timestamp) 失败: %v", err)
	}
	firstStep, ok := pb.Steps().Head()
	if !ok || firstStep.Name() != "2026-11-27" {
		t.Fatalf("YAML !!timestamp 必须保留原始值 2026-11-27，实际=%q ok=%v", firstStep.Name(), ok)
	}

	// 顶层 JSON 数组、空输入、YAML 别名与重复键一律拒绝。
	for _, bad := range []string{
		"",
		`[{"version":2}]`,
		"a: &x 1\nb: *x\n",
		"version: 2\nversion: 2\n",
	} {
		if _, err := cmdops.DecodePlaybookDocument([]byte(bad)); err == nil {
			t.Fatalf("非法文档 %q 应解码失败", bad)
		}
	}
}

func TestRunPlaybook_NonPOSIXProfileAndJSONErrors(t *testing.T) {
	defer goleak.VerifyNone(t)

	yamlDoc := "version: 2\nid: pb1\nname: pb\non_error: fail_fast\ntarget:\n  all: true\nsteps:\n  - id: s1\n    name: s1\n    action:\n      kind: shell\n      command: Get-Date\n"
	stub := &opsStub{runPlaybookErr: engine.ErrEngineHalted}
	rt, out, _ := newOpsRuntime(stub, yamlDoc)
	code := cmdops.RunPlaybook(context.Background(), rt, []string{"run", "--stdin", "--dialect", "powershell", "--json"})
	if code != clikit.ExitGeneral {
		t.Fatalf("RunPlaybook 返回错误时必须返回 ExitGeneral，实际=%d", code)
	}
	if lp, ok := stub.lastPlaybookReq.DefaultProfile.Get(); !ok || lp.Dialect() != execution.DialectPowerShell {
		t.Fatalf("--dialect powershell 未构造 DefaultProfile: ok=%v lp=%v", ok, lp)
	}
	var env clikit.ErrorEnvelope
	if err := jsonv2.Unmarshal(out.Bytes(), &env); err != nil || env.OK || env.ErrorCode != "engine_halted" {
		t.Fatalf("RunPlaybook 失败 JSON 信封异常: err=%v env=%+v", err, env)
	}
}

func TestRunAuditDoctorTUIAndMCP_StrictValidation(t *testing.T) {
	defer goleak.VerifyNone(t)

	// 1) audit --phase / --outcome 白名单校验。
	rtAud, _, _ := newOpsRuntime(&opsStub{}, "")
	rtAud.Hooks.ReadAuditLog = func(_ context.Context, _ clikit.AuditQueryRequest) (clikit.AuditQueryResult, error) {
		return clikit.AuditQueryResult{}, nil
	}
	if code := cmdops.RunAudit(context.Background(), rtAud, []string{"list", "--phase", "finalized", "--outcome", "outcome_unknown", "--json"}); code != 0 {
		t.Fatalf("合法 audit 过滤参数不应失败: code=%d", code)
	}
	for _, bad := range [][]string{
		{"list", "--phase", "post", "--json"},
		{"list", "--outcome", "bogus", "--json"},
		{"list", "limit", "5", "--json"},
		{"reconcile", "extra", "--json"},
		{"unknown", "--json"},
	} {
		rtBad, outBad, _ := newOpsRuntime(&opsStub{}, "")
		if code := cmdops.RunAudit(context.Background(), rtBad, bad); code != clikit.ExitUsage {
			t.Fatalf("非法 audit %v 应返回 ExitUsage，实际=%d", bad, code)
		}
		assertOpsUsageJSON(t, outBad.Bytes(), bad)
	}

	// 2) tui 拒绝 --json，支持紧凑 -F/path，拒绝裸词/未知单横杠；mcp 同样校验。
	var gotTUI clikit.TUIStartRequest
	var gotMCP clikit.MCPStartRequest
	rtSub, _, errSub := newOpsRuntime(&opsStub{}, "")
	rtSub.Hooks.RunTUI = func(_ context.Context, req clikit.TUIStartRequest) error { gotTUI = req; return nil }
	rtSub.Hooks.RunMCP = func(_ context.Context, req clikit.MCPStartRequest) error { gotMCP = req; return nil }
	if code := cmdops.RunTUI(context.Background(), rtSub, []string{"-F/tmp/tui.cfg", "--node", "web-1"}); code != 0 || gotTUI.InitOptions.OpenSSHConfigFile != "/tmp/tui.cfg" {
		t.Fatalf("tui -F/tmp/tui.cfg 失败: code=%d cfg=%q stderr=%q", code, gotTUI.InitOptions.OpenSSHConfigFile, errSub.String())
	}
	if code := cmdops.RunMCP(context.Background(), rtSub, []string{"serve", "-F/tmp/mcp.cfg", "--transport", "stdio"}); code != 0 || gotMCP.InitOptions.OpenSSHConfigFile != "/tmp/mcp.cfg" {
		t.Fatalf("mcp -F/tmp/mcp.cfg 失败: code=%d cfg=%q stderr=%q", code, gotMCP.InitOptions.OpenSSHConfigFile, errSub.String())
	}

	for _, fn := range []struct {
		name string
		run  func(*clikit.Runtime) int
	}{
		{"tui_json", func(rt *clikit.Runtime) int { return cmdops.RunTUI(context.Background(), rt, []string{"--json"}) }},
		{"tui_bare", func(rt *clikit.Runtime) int {
			return cmdops.RunTUI(context.Background(), rt, []string{"node", "web", "--json"})
		}},
		{"mcp_bare", func(rt *clikit.Runtime) int {
			return cmdops.RunMCP(context.Background(), rt, []string{"transport", "http", "--json"})
		}},
		{"mcp_short", func(rt *clikit.Runtime) int { return cmdops.RunMCP(context.Background(), rt, []string{"-x", "--json"}) }},
		{"doctor_bare", func(rt *clikit.Runtime) int {
			return cmdops.RunDoctor(context.Background(), rt, []string{"scope", "vault", "--json"})
		}},
	} {
		rtBad, outBad, _ := newOpsRuntime(&opsStub{}, "")
		if code := fn.run(rtBad); code != clikit.ExitUsage {
			t.Fatalf("%s 应返回 ExitUsage，实际=%d", fn.name, code)
		}
		assertOpsUsageJSON(t, outBad.Bytes(), []string{fn.name})
	}
}

func assertOpsUsageJSON(t *testing.T, raw []byte, args []string) {
	t.Helper()
	var env clikit.ErrorEnvelope
	if err := jsonv2.Unmarshal(raw, &env); err != nil || env.OK || env.ErrorCode != "usage_error" {
		t.Fatalf("命令 %v 应输出合法 JSON usage_error 信封: err=%v env=%+v raw=%q", args, err, env, string(raw))
	}
}
