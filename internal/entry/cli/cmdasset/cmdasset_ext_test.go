package cmdasset_test

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
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
	"github.com/wentf9/xops-cli/internal/entry/cli/cmdasset"
)

type assetStub struct {
	lastNodeMut   engine.NodeMutationRequest
	lastImportReq engine.ImportRequest
	lastVaultSaga engine.InteractiveVaultSagaRequest
	lastRotateReq engine.InteractiveRotateSecretRequest
	rotateErr     error
	lastInitOpts  clikit.EngineInitOptions
}

var (
	_ clikit.InventoryClient = (*assetStub)(nil)
	_ clikit.VaultClient     = (*assetStub)(nil)
)

func (s *assetStub) Close(_ context.Context) error { return nil }
func (s *assetStub) RunSSH(_ context.Context, _ engine.RunSSHRequest) (execution.ExecutionOutcome, error) {
	out, _ := execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	return out, nil
}
func (s *assetStub) ResolveTarget(_ context.Context, _ engine.ResolveTargetRequest) (res engine.ResolvedTarget, err error) {
	return res, nil
}
func (s *assetStub) GetInventorySnapshot(_ context.Context, _ engine.InventoryQueryRequest) (snap engine.InventorySnapshot, err error) {
	return snap, nil
}
func (s *assetStub) GetHost(_ context.Context, _ inventory.HostID, _ engine.InventoryQueryRequest) (h inventory.Host, rev engine.Revision, err error) {
	return h, rev, nil
}
func (s *assetStub) GetIdentity(_ context.Context, _ inventory.IdentityID, _ engine.InventoryQueryRequest) (id inventory.Identity, rev engine.Revision, err error) {
	return id, rev, nil
}
func (s *assetStub) GetNode(_ context.Context, _ inventory.NodeID, _ engine.InventoryQueryRequest) (n inventory.Node, rev engine.Revision, err error) {
	return n, rev, nil
}
func (s *assetStub) ListHosts(_ context.Context, _ engine.InventoryQueryRequest) (out []inventory.Host, rev engine.Revision, err error) {
	return out, rev, nil
}
func (s *assetStub) ListIdentities(_ context.Context, _ engine.InventoryQueryRequest) (out []inventory.Identity, rev engine.Revision, err error) {
	return out, rev, nil
}
func (s *assetStub) ListNodes(_ context.Context, _ engine.InventoryQueryRequest) (out []inventory.Node, rev engine.Revision, err error) {
	return out, rev, nil
}
func (s *assetStub) CreateHost(_ context.Context, _ engine.HostMutationRequest) (res engine.MutationResult, err error) {
	return res, nil
}
func (s *assetStub) UpdateHost(_ context.Context, _ engine.HostMutationRequest) (res engine.MutationResult, err error) {
	return res, nil
}
func (s *assetStub) DeleteHost(_ context.Context, _ engine.DeleteAssetRequest) (res engine.MutationResult, err error) {
	return res, nil
}
func (s *assetStub) CreateIdentity(_ context.Context, _ engine.IdentityMutationRequest) (res engine.MutationResult, err error) {
	return res, nil
}
func (s *assetStub) UpdateIdentity(_ context.Context, _ engine.IdentityMutationRequest) (res engine.MutationResult, err error) {
	return res, nil
}
func (s *assetStub) DeleteIdentity(_ context.Context, _ engine.DeleteAssetRequest) (res engine.MutationResult, err error) {
	return res, nil
}
func (s *assetStub) CreateNode(_ context.Context, req engine.NodeMutationRequest) (res engine.MutationResult, err error) {
	s.lastNodeMut = req
	return res, nil
}
func (s *assetStub) UpdateNode(_ context.Context, req engine.NodeMutationRequest) (res engine.MutationResult, err error) {
	s.lastNodeMut = req
	return res, nil
}
func (s *assetStub) DeleteNode(_ context.Context, _ engine.DeleteAssetRequest) (res engine.MutationResult, err error) {
	return res, nil
}
func (s *assetStub) ValidateDAG(_ context.Context, _ engine.InventoryQueryRequest) (inventory.DAGReport, error) {
	return inventory.DAGReport{}, nil
}
func (s *assetStub) CheckSecretReferences(_ context.Context, _ engine.SecretRefCheckRequest) ([]inventory.SecretReference, error) {
	return nil, nil
}
func (s *assetStub) InventoryDoctor(_ context.Context, _ engine.InventoryDoctorRequest) (engine.InventoryDoctorRep, error) {
	return engine.InventoryDoctorRep{Healthy: true}, nil
}
func (s *assetStub) SupportedImportFormats() []string { return []string{"csv", "openssh"} }
func (s *assetStub) PlanImport(_ context.Context, req engine.ImportRequest) (p engine.ImportPreview, err error) {
	s.lastImportReq = req
	return p, nil
}
func (s *assetStub) ApplyImport(_ context.Context, req engine.ImportRequest) (r engine.ImportResult, err error) {
	s.lastImportReq = req
	return r, nil
}
func (s *assetStub) EnrollEncryptedPrivateKeyIdentity(_ context.Context, _ engine.EnrollEncryptedPrivateKeyRequest) (r engine.EnrollEncryptedPrivateKeyResult, err error) {
	return r, nil
}
func (s *assetStub) VaultStatus(_ context.Context, _ engine.VaultOpRequest) (st engine.VaultStatus, err error) {
	return st, nil
}
func (s *assetStub) VaultInitInteractive(_ context.Context, _ engine.InteractiveVaultOpRequest) error {
	return nil
}
func (s *assetStub) VaultUnlockInteractive(_ context.Context, _ engine.InteractiveVaultOpRequest) error {
	return nil
}
func (s *assetStub) VaultLock(_ context.Context, _ engine.VaultOpRequest) error { return nil }
func (s *assetStub) VaultDoctor(_ context.Context, _ engine.VaultDoctorRequest) (engine.CredentialDoctorRep, error) {
	return engine.CredentialDoctorRep{Healthy: true}, nil
}
func (s *assetStub) FindSecretReferences(_ context.Context, _ engine.FindSecretReferencesRequest) ([]inventory.SecretReference, error) {
	return nil, nil
}
func (s *assetStub) DeleteSecret(_ context.Context, _ engine.DeleteSecretRequest) error { return nil }
func (s *assetStub) GCUnreferencedSecrets(_ context.Context, _ engine.GCUnreferencedRequest) (engine.GCUnreferencedResult, error) {
	return engine.GCUnreferencedResult{}, nil
}
func (s *assetStub) ExecuteVaultSagaInteractive(_ context.Context, req engine.InteractiveVaultSagaRequest) (res engine.SagaResult, err error) {
	s.lastVaultSaga = req
	if req.Saga.MutateGraph == nil || (req.Saga.NewRef.IsValid() == (req.Saga.TargetStore != "")) {
		return res, engine.ErrInvalidRequest
	}
	return res, nil
}
func (s *assetStub) RotateSecretInteractive(_ context.Context, req engine.InteractiveRotateSecretRequest) (res engine.SagaResult, err error) {
	s.lastRotateReq = req
	if !req.Rotate.OldRef.IsValid() || (req.Rotate.NewRef.IsValid() == (req.Rotate.TargetStore != "")) {
		return res, engine.ErrInvalidRequest
	}
	return res, s.rotateErr
}

func newAssetRuntime(stub *assetStub, stdin string) (*clikit.Runtime, *bytes.Buffer, *bytes.Buffer) {
	var stdout, stderr bytes.Buffer
	rt := &clikit.Runtime{
		Stdin:           strings.NewReader(stdin),
		Stdout:          &stdout,
		Stderr:          &stderr,
		ShutdownTimeout: time.Second,
		EngineFactory: func(_ context.Context, opts clikit.EngineInitOptions) (clikit.EngineHandle, error) {
			stub.lastInitOpts = opts
			return clikit.EngineHandle{Runner: stub}, nil
		},
	}
	return rt, &stdout, &stderr
}

func TestRunVault_EnrollPasswordSetNodePrivilegeAndRotate(t *testing.T) {
	defer goleak.VerifyNone(t)

	// 1) enroll-password（--store 二选一，零明文参数）。
	stub := &assetStub{}
	rt, _, stderr := newAssetRuntime(stub, "")
	if code := cmdasset.RunVault(context.Background(), rt, []string{"enroll-password", "--id", "pw-1", "--user", "ops", "--store", "offline", "--json"}); code != 0 {
		t.Fatalf("vault enroll-password 失败: code=%d stderr=%q", code, stderr.String())
	}
	if stub.lastVaultSaga.Saga.TargetStore != "offline" || stub.lastVaultSaga.Saga.MutateGraph == nil {
		t.Fatalf("enroll-password 请求构造异常: %+v", stub.lastVaultSaga.Saga)
	}

	// 2) set-node-privilege（--ref 指定）。
	if code := cmdasset.RunVault(context.Background(), rt, []string{"set-node-privilege", "--node", "web-1", "--ref", "offline/sudo", "--json"}); code != 0 {
		t.Fatalf("vault set-node-privilege 失败: code=%d stderr=%q", code, stderr.String())
	}
	wantRef, _ := secret.ParseRef("offline/sudo")
	if !stub.lastVaultSaga.Saga.NewRef.Equal(wantRef) || stub.lastVaultSaga.Saga.MutateGraph == nil {
		t.Fatalf("set-node-privilege 请求构造异常: %+v", stub.lastVaultSaga.Saga)
	}

	// 3) rotate 成功路径与 UncertainDurability 失败关闭路径（do_not_retry=true）。
	if code := cmdasset.RunVault(context.Background(), rt, []string{"rotate", "offline/old", "--new-ref", "offline/new", "--expected-revision", "rev-3", "--json"}); code != 0 {
		t.Fatalf("vault rotate 失败: code=%d stderr=%q", code, stderr.String())
	}
	if stub.lastRotateReq.Rotate.OldRef.String() != "offline/old" || stub.lastRotateReq.Rotate.NewRef.String() != "offline/new" {
		t.Fatalf("rotate 请求构造异常: %+v", stub.lastRotateReq.Rotate)
	}

	stubUnc := &assetStub{rotateErr: engine.ErrUncertainDurability}
	rtUnc, outUnc, _ := newAssetRuntime(stubUnc, "")
	if code := cmdasset.RunVault(context.Background(), rtUnc, []string{"rotate", "offline/old", "--store", "offline", "--json"}); code != clikit.ExitGeneral {
		t.Fatalf("UncertainDurability 必须返回 ExitGeneral，实际=%d", code)
	}
	if !strings.Contains(outUnc.String(), `"do_not_retry":true`) || !strings.Contains(outUnc.String(), `"error_code":"uncertain_durability"`) {
		t.Fatalf("UncertainDurability JSON 视图缺失关键字段: %q", outUnc.String())
	}

	// 4) --ref 与 --store 同时提供必须返回 ExitUsage。
	if code := cmdasset.RunVault(context.Background(), rt, []string{"enroll-password", "--id", "pw-1", "--user", "ops", "--ref", "offline/p", "--store", "offline"}); code != clikit.ExitUsage {
		t.Fatalf("同时指定 --ref 与 --store 应返回 ExitUsage，实际=%d", code)
	}
}

func TestCmdAsset_StrictFlagValidationAndNonPOSIXNodeProfile(t *testing.T) {
	defer goleak.VerifyNone(t)

	// 1) create-node 支持 powershell 与 server 非 POSIX LaunchProfile。
	stub := &assetStub{}
	rt, _, stderr := newAssetRuntime(stub, "")
	if code := cmdasset.RunHosts(context.Background(), rt, []string{"create-node", "--id", "win-1", "--host", "h1", "--identity", "id1", "--dialect", "powershell"}); code != 0 {
		t.Fatalf("create-node --dialect powershell 失败: code=%d stderr=%q", code, stderr.String())
	}
	if lp, ok := stub.lastNodeMut.Node.Execution().Get(); !ok || lp.Dialect() != execution.DialectPowerShell {
		t.Fatalf("Node LaunchProfile 失配: ok=%v lp=%v", ok, lp)
	}

	// 2) config import 支持紧凑 -F/path 并在语法错误时拒绝非法单横杠与裸词。
	rtImp, _, errImp := newAssetRuntime(stub, "host,ip\nweb,10.0.0.1\n")
	if code := cmdasset.RunConfig(context.Background(), rtImp, []string{"import", "-F/tmp/ssh.cfg", "--format", "csv", "--stdin", "--plan"}); code != 0 {
		t.Fatalf("config import -F/tmp/ssh.cfg 失败: code=%d stderr=%q", code, errImp.String())
	}
	if stub.lastInitOpts.OpenSSHConfigFile != "/tmp/ssh.cfg" {
		t.Fatalf("紧凑 -F 参数未透传: %q", stub.lastInitOpts.OpenSSHConfigFile)
	}

	// 3) 全部解析器严格拒绝裸词与非法单横杠，并在携带 --json 时返回规范 ErrorEnvelope。
	badHostCmds := [][]string{
		{"list", "kind", "nodes", "--json"},
		{"get", "-x", "web-1", "--json"},
		{"create-host", "id", "h1", "--json"},
		{"create-identity", "user", "ops", "--json"},
		{"create-node", "host", "h1", "--json"},
		{"delete-node", "-x", "n1", "--json"},
		{"check-secret-refs", "ref", "a/b", "--json"},
	}
	for _, args := range badHostCmds {
		rtBad, outBad, _ := newAssetRuntime(&assetStub{}, "")
		if code := cmdasset.RunHosts(context.Background(), rtBad, args); code != clikit.ExitUsage {
			t.Fatalf("hosts %v 应返回 ExitUsage，实际=%d", args, code)
		}
		assertUsageJSONEnvelope(t, outBad.Bytes(), args)
	}

	badVaultCmds := [][]string{
		{"doctor", "skip", "--json"},
		{"enroll-key", "id", "k1", "--json"},
		{"enroll-password", "id", "p1", "--json"},
		{"set-node-privilege", "node", "n1", "--json"},
		{"rotate", "-x", "offline/old", "--json"},
	}
	for _, args := range badVaultCmds {
		rtBad, outBad, _ := newAssetRuntime(&assetStub{}, "")
		if code := cmdasset.RunVault(context.Background(), rtBad, args); code != clikit.ExitUsage {
			t.Fatalf("vault %v 应返回 ExitUsage，实际=%d", args, code)
		}
		assertUsageJSONEnvelope(t, outBad.Bytes(), args)
	}

	for _, args := range [][]string{{"import", "format", "csv", "--json"}, {"import", "-x", "--json"}} {
		rtBad, outBad, _ := newAssetRuntime(&assetStub{}, "")
		if code := cmdasset.RunConfig(context.Background(), rtBad, args); code != clikit.ExitUsage {
			t.Fatalf("config %v 应返回 ExitUsage，实际=%d", args, code)
		}
		assertUsageJSONEnvelope(t, outBad.Bytes(), args)
	}
}

func assertUsageJSONEnvelope(t *testing.T, raw []byte, args []string) {
	t.Helper()
	var env clikit.ErrorEnvelope
	if err := jsonv2.Unmarshal(raw, &env); err != nil || env.OK || env.ErrorCode != "usage_error" {
		t.Fatalf("命令 %v 应输出合法 JSON usage_error 信封: err=%v env=%+v raw=%q", args, err, env, string(raw))
	}
}
