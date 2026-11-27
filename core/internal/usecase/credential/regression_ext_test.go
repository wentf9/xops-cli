package credential_test

import (
	"context"
	"encoding"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/internal/usecase/credential"
	"github.com/wentf9/xops-cli/core/ports"
)

// 编译期接口断言：DoctorSeverity 完整实现 TextAppender / TextMarshaler / TextUnmarshaler。
var _ encoding.TextUnmarshaler = (*credential.DoctorSeverity)(nil)

// countingInteractionPort 统计 PromptSecret 调用次数，验证 Gate 拒绝/Halted 时零前置交互泄漏。
type countingInteractionPort struct {
	base       ports.InteractionPort
	promptHits atomic.Int32
}

func (c *countingInteractionPort) CanInteract() bool { return c.base.CanInteract() }
func (c *countingInteractionPort) Confirm(ctx context.Context, req ports.ConfirmRequest) (security.Verdict, error) {
	return c.base.Confirm(ctx, req)
}
func (c *countingInteractionPort) PromptApproval(ctx context.Context, env security.ApprovalEnvelope) (ports.ApprovalDecisionResponse, error) {
	return c.base.PromptApproval(ctx, env)
}
func (c *countingInteractionPort) PromptText(ctx context.Context, req ports.TextPromptRequest) (string, error) {
	return c.base.PromptText(ctx, req)
}

//xops:syncclosure
//xops:borrowed
func (c *countingInteractionPort) PromptSecret(ctx context.Context, req ports.SecretPromptRequest, fn func(box *secret.SecretBox) error) error {
	c.promptHits.Add(1)
	return c.base.PromptSecret(ctx, req, func(box *secret.SecretBox) error { return fn(box) })
}

// commitErrInventoryStore 模拟底层存储异常返回 (DurabilityCommitted, nonNilErr) 的矛盾结果。
type commitErrInventoryStore struct {
	base      ports.InventoryStore
	commitErr error
}

func (s *commitErrInventoryStore) Load(ctx context.Context) (ports.InventorySnapshot, error) {
	return s.base.Load(ctx)
}
func (s *commitErrInventoryStore) CommitCAS(ctx context.Context, expected ports.Revision, next inventory.Graph) (ports.DurabilityOutcome, error) {
	out, err := s.base.CommitCAS(ctx, expected, next)
	if err != nil {
		return out, err
	}
	return out, s.commitErr
}

// panicVaultControl 在 Lock 时主动 panic，验证 VaultControl defer 仍发射失败终态事件。
type panicVaultControl struct {
	base ports.VaultControlPort
}

func (p *panicVaultControl) Init(ctx context.Context,
	//xops:borrowed
	pass *secret.SecretBox,
) error {
	return p.base.Init(ctx, pass)
}
func (p *panicVaultControl) Unlock(ctx context.Context,
	//xops:borrowed
	pass *secret.SecretBox,
) error {
	return p.base.Unlock(ctx, pass)
}
func (p *panicVaultControl) Lock(context.Context) error { panic("vault-control-boom") }
func (p *panicVaultControl) Status(ctx context.Context) (ports.VaultStatus, error) {
	return p.base.Status(ctx)
}

// newStrictAgentCredHarness 构造 StrictAgent 门控夹具（支持真实触发不可逆 Gate.Halted 与前置交互计数）。
func newStrictAgentCredHarness(t *testing.T, initial inventory.Graph) (*credHarness, *countingInteractionPort) {
	t.Helper()
	clk := sim.NewSimClock(time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC))
	rng := sim.NewSeededRand(77)
	v := sim.NewSimVault(rng.Fork())
	st, err := sim.NewSimInventoryStore(initial)
	if err != nil {
		t.Fatalf("NewSimInventoryStore: %v", err)
	}
	procID, err := ports.ParseProcessInstanceID("proc-cred-strict")
	if err != nil {
		t.Fatalf("ParseProcessInstanceID: %v", err)
	}
	cluster := sim.NewSimAuditCluster()
	sink, err := cluster.NewSink(procID)
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	ui := sim.NewSimInteractionPort(true)
	ui.SetReplies("", []byte("prompt-secret-val"))
	cui := &countingInteractionPort{base: ui}
	pol, err := gate.NewGuardrailPolicy(gate.GuardrailPolicySpec{
		ApprovalThreshold: security.RiskDangerous,
		NoElicitFallback:  gate.NoElicitFallbackDeny,
	})
	if err != nil {
		t.Fatalf("NewGuardrailPolicy: %v", err)
	}
	g, err := gate.NewGate(gate.GateConfig{
		Profile:     gate.PolicyProfileStrictAgent,
		Policy:      pol,
		AuditSink:   sink,
		Interaction: nil, // StrictAgent 无审批交互端口 + NoElicitFallbackDeny -> RiskDangerous 确定拒绝
		Clock:       clk,
		Entropy:     rng.Fork(),
	})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	pending := &stubPendingProvider{}
	svc, err := credential.NewService(credential.ServiceConfig{
		Gate:         g,
		Vault:        v,
		VaultControl: v,
		Store:        st,
		Interaction:  cui,
		Clock:        clk,
		Entropy:      rng.Fork(),
		PendingRefs:  pending,
	})
	if err != nil {
		t.Fatalf("credential.NewService: %v", err)
	}
	return &credHarness{clk, rng, v, st, cluster, sink, ui, g, pending, svc}, cui
}

func triggerGateHalted(t *testing.T, h *credHarness) {
	t.Helper()
	h.auditCluster.Faults().InjectOnce("audit.record."+ports.AuditPhaseFinalized.String(), io.ErrUnexpectedEOF)
	_, err := h.svc.Status(context.Background(), credential.StatusRequest{})
	if !errors.Is(err, ports.ErrAuditPostWrite) || !h.gate.IsHalted() {
		t.Fatalf("StrictAgent 终态审计失败应触发 Halted: err=%v halted=%v", err, h.gate.IsHalted())
	}
}

func TestDoctorSeverity_ParseAndJSONv2RoundTrip(t *testing.T) {
	defer goleak.VerifyNone(t)
	for _, tc := range []struct {
		raw  string
		want credential.DoctorSeverity
	}{
		{"info", credential.DoctorSeverityInfo},
		{"warn", credential.DoctorSeverityWarn},
		{"error", credential.DoctorSeverityError},
	} {
		got, err := credential.ParseDoctorSeverity(tc.raw)
		if err != nil || got != tc.want {
			t.Fatalf("ParseDoctorSeverity(%q) = (%v, %v), want %v", tc.raw, got, err, tc.want)
		}
	}
	for _, bad := range []string{"", "invalid", "INFO", "warning", "1"} {
		if got, err := credential.ParseDoctorSeverity(bad); !errors.Is(err, credential.ErrInvalidRequest) || got != credential.DoctorSeverityInvalid {
			t.Fatalf("ParseDoctorSeverity(%q) 应失败关闭返回 ErrInvalidRequest，实际 (%v, %v)", bad, got, err)
		}
	}
	orig := credential.DoctorReport{
		Healthy:         false,
		ReferencedCount: 2,
		Findings: []credential.DoctorFinding{
			{Severity: credential.DoctorSeverityInfo, Code: "pin", Subject: "s/a", Message: "pinned"},
			{Severity: credential.DoctorSeverityWarn, Code: "locked", Subject: "s/b", Message: "locked"},
			{Severity: credential.DoctorSeverityError, Code: "missing", Subject: "s/c", Message: "missing"},
		},
	}
	raw, err := jsonv2.Marshal(orig, jsonv2.Deterministic(true))
	if err != nil {
		t.Fatalf("jsonv2.Marshal: %v", err)
	}
	var decoded credential.DoctorReport
	if err := jsonv2.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("jsonv2.Unmarshal: %v", err)
	}
	if decoded.Healthy != orig.Healthy || len(decoded.Findings) != 3 || decoded.Findings[2].Severity != credential.DoctorSeverityError {
		t.Fatalf("DoctorReport JSON v2 往返失配: got=%+v", decoded)
	}
	// 非法枚举字符串与数字枚举在反序列化时必须严格失败关闭。
	for _, badJSON := range []string{`{"severity":"bogus","code":"x"}`, `{"severity":1,"code":"x"}`, `{"severity":"invalid","code":"x"}`} {
		var f credential.DoctorFinding
		if err := jsonv2.Unmarshal([]byte(badJSON), &f); err == nil {
			t.Fatalf("非法 severity JSON %s 必须反序列化失败", badJSON)
		}
	}
}

func TestDoctor_AuthoritativeKnownStoresAndPendingOnStoreFailure(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()

	// 1. 构造含已下线存储 legacy-store 的历史图，同时实时 VaultControl 仅承认 sim-aes256gcm。
	rLegacy := mustRef(t, "legacy-store", "old-k")
	ep, err := netaddr.ParseEndpoint("198.51.100.10:22")
	if err != nil {
		t.Fatalf("ParseEndpoint: %v", err)
	}
	hid, _ := inventory.ParseHostID("h-leg")
	host, err := inventory.NewHost(inventory.HostSpec{ID: hid, Endpoint: ep})
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	user, _ := option.ParseUsername("ops")
	auth, err := inventory.NewAuthPassword(rLegacy)
	if err != nil {
		t.Fatalf("NewAuthPassword: %v", err)
	}
	iid, _ := inventory.ParseIdentityID("id-leg")
	ident, err := inventory.NewIdentity(inventory.IdentitySpec{ID: iid, User: user, Auth: auth})
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	g, err := inventory.NewGraph(inventory.GraphSpec{
		Hosts:       []inventory.Host{host},
		Identities:  []inventory.Identity{ident},
		KnownStores: []string{"legacy-store", "sim-aes256gcm"},
	})
	if err != nil {
		t.Fatalf("NewGraph: %v", err)
	}
	h := newCredHarness(t, g, false)
	rep, err := h.svc.Doctor(ctx, credential.DoctorRequest{SkipSecretProbe: true})
	if err != nil || rep.Healthy || !hasCredFinding(rep.Findings, credential.DoctorSeverityError, "unknown_secret_store") {
		t.Fatalf("历史图陈旧 KnownStores 不得掩盖已下线存储: rep=%+v err=%v", rep, err)
	}

	// 2. store.Load 失败时仍必须保留活跃 Pending 引用并探活其缺失。
	rPend := mustRef(t, "sim-aes256gcm", "pending-missing")
	h.pending.Set(inventory.PendingSecretRef{OwnerID: "pending:lease-9", Ref: rPend})
	h.store.Faults().InjectOnce("store.load", io.ErrUnexpectedEOF)
	repLoadFail, err := h.svc.Doctor(ctx, credential.DoctorRequest{})
	if err != nil || repLoadFail.Healthy || !hasCredFinding(repLoadFail.Findings, credential.DoctorSeverityError, "store_load_failed") ||
		!hasCredFinding(repLoadFail.Findings, credential.DoctorSeverityError, "secret_not_found") {
		t.Fatalf("store.Load 失败时须保留 Pending 参与诊断: rep=%+v err=%v", repLoadFail, err)
	}
	assertCredDoctorFindingsLocalized(t, repLoadFail.Findings, io.ErrUnexpectedEOF)

	// 3. InspectVaultAndSecrets 在 ProbeSecrets=true 且 Vault==nil 时必须发出 Warn(vault_unavailable)。
	vRes := credential.InspectVaultAndSecrets(ctx, credential.VaultSecretCheckSpec{
		Vault: nil, VaultControl: nil, ProbeSecrets: true,
	})
	if !hasCredFinding(vRes.Findings, credential.DoctorSeverityWarn, "vault_unavailable") {
		t.Fatalf("ProbeSecrets=true 且 Vault==nil 应发出 vault_unavailable Warn: %+v", vRes.Findings)
	}
	if msg, ok := vRes.Findings[0].Localized.Get(); !ok || msg.ID() != domi18n.KeyUCDoctorVaultUnavailable {
		t.Fatalf("vault_unavailable 必须绑定 KeyUCDoctorVaultUnavailable: %+v", vRes.Findings[0])
	}
}

func assertCredDoctorFindingsLocalized(t *testing.T, findings []credential.DoctorFinding, wantStoreCause error) {
	t.Helper()
	for _, f := range findings {
		if msg, ok := f.Localized.Get(); !ok || !msg.IsValid() {
			t.Fatalf("DoctorFinding(%s) 必须携带有效 Localized 结构化主句: %+v", f.Code, f)
		}
		if f.Code == "store_load_failed" && !errors.Is(f.Cause, wantStoreCause) {
			t.Fatalf("store_load_failed 必须保留下层结构化 Cause，实际=%v", f.Cause)
		}
	}
}

func TestGateEnforcement_HaltedAndPreGatePromptBlocking(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	h, cui := newStrictAgentCredHarness(t, inventory.EmptyGraph())
	p1, p2 := mustPrompt(t, "Secret"), mustPrompt(t, "Confirm")

	// 1. UnlockInteractive 显式传入 ConfirmPrompt 必须失败关闭返回 ErrInvalidRequest 且零交互。
	if err := h.svc.UnlockInteractive(ctx, credential.InteractiveVaultControlRequest{
		Prompt: p1, ConfirmPrompt: algebraic.Some(p2),
	}); !errors.Is(err, credential.ErrInvalidRequest) || cui.promptHits.Load() != 0 {
		t.Fatalf("UnlockInteractive 应拒绝 ConfirmPrompt 且不提示输入: err=%v hits=%d", err, cui.promptHits.Load())
	}

	// 2. 策略拒绝（RiskDangerous 无审批提交）时 ExecuteVaultSagaInteractive 绝不可提前调用 PromptSecret。
	rDenied := mustRef(t, "sim-aes256gcm", "policy-denied")
	_, err := h.svc.ExecuteVaultSagaInteractive(ctx, credential.InteractiveVaultSagaRequest{
		Prompt: p1,
		Saga: credential.VaultSagaRequest{
			NewRef: rDenied,
			Risk:   algebraic.Some(security.RiskDangerous),
			MutateGraph: func(_ context.Context, snap ports.InventorySnapshot, _ secret.Ref) (inventory.Graph, error) {
				return snap.Graph(), nil
			},
		},
	})
	if err == nil || cui.promptHits.Load() != 0 {
		t.Fatalf("策略拒绝场景绝不可在门控前调用 PromptSecret: err=%v hits=%d", err, cui.promptHits.Load())
	}

	// 3. 触发 Gate 不可逆 Halted 后，WithPromptedSecret、空候选 GC 与 InteractiveSaga 均须被 Gate 物理拒绝且零交互。
	triggerGateHalted(t, h)
	if err := h.svc.WithPromptedSecret(ctx, p1, func(*secret.SecretBox) error { return nil }); !errors.Is(err, gate.ErrGateHalted) || cui.promptHits.Load() != 0 {
		t.Fatalf("Halted 下 WithPromptedSecret 应被 Gate 拒绝且零交互: err=%v hits=%d", err, cui.promptHits.Load())
	}
	if _, err := h.svc.GCUnreferencedSecrets(ctx, credential.GCUnreferencedRequest{}); !errors.Is(err, gate.ErrGateHalted) {
		t.Fatalf("Halted 下空候选 GCUnreferencedSecrets 绝不可绕过 Gate: err=%v", err)
	}
	_, err = h.svc.ExecuteVaultSagaInteractive(ctx, credential.InteractiveVaultSagaRequest{
		Prompt: p1,
		Saga: credential.VaultSagaRequest{
			NewRef: rDenied,
			MutateGraph: func(_ context.Context, snap ports.InventorySnapshot, _ secret.Ref) (inventory.Graph, error) {
				return snap.Graph(), nil
			},
		},
	})
	if !errors.Is(err, gate.ErrGateHalted) || cui.promptHits.Load() != 0 {
		t.Fatalf("Halted 下 ExecuteVaultSagaInteractive 应返回 ErrGateHalted 且零交互: err=%v hits=%d", err, cui.promptHits.Load())
	}
}

func TestVaultSaga_AdversarialEdgeCases(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	rOld := mustRef(t, "sim-aes256gcm", "edge-old")
	g0 := buildFiveLocationGraph(t, rOld, mustRef(t, "sim-aes256gcm", "k"), mustRef(t, "sim-aes256gcm", "t"), mustRef(t, "sim-aes256gcm", "r"), mustRef(t, "sim-aes256gcm", "p"))
	h := newCredHarness(t, g0, false)

	// (a) 旧凭据在 Vault 中已缺失时，RotateSecret 仍应幂等完成（ErrSecretNotFound 视为删旧已满足）。
	rRepaired := mustRef(t, "sim-aes256gcm", "edge-repaired")
	var rotRes credential.SagaResult
	err := secret.WithBytes([]byte("repaired-pass"), func(box *secret.SecretBox) error {
		var rErr error
		rotRes, rErr = h.svc.RotateSecret(ctx, credential.RotateSecretRequest{OldRef: rOld, NewRef: rRepaired}, box)
		return rErr
	})
	if err != nil || rotRes.StateKind() != fsm.VaultSagaKindCompleted || !rotRes.OldDeleted() {
		t.Fatalf("缺失旧凭据修复轮换应幂等成功: kind=%s oldDel=%v err=%v", rotRes.StateKind(), rotRes.OldDeleted(), err)
	}

	// (b) VerifyNewRef 中上下文取消后，仍须在 WithoutCancel 中完成补偿删除新凭据，零孤儿。
	rCancel := mustRef(t, "sim-aes256gcm", "edge-verify-cancel")
	cancelCtx, cancel := context.WithCancel(ctx)
	resCancel, err := h.svc.ExecuteVaultSagaFromBytes(cancelCtx, credential.VaultSagaRequest{
		NewRef: rCancel,
		VerifyNewRef: func(context.Context, secret.Ref) error {
			cancel()
			return cancelCtx.Err()
		},
		MutateGraph: rotateMutator(rRepaired),
	}, []byte("cancel-pass"))
	if !errors.Is(err, credential.ErrSagaRolledBack) || !errors.Is(err, context.Canceled) || !resCancel.Compensated() {
		t.Fatalf("VerifyNewRef 取消后应回滚补偿: kind=%s comp=%v err=%v", resCancel.StateKind(), resCancel.Compensated(), err)
	}
	assertSecretAbsent(t, h.vault, rCancel)

	// (c) 补偿删除失败须通过 errors.Join 同时保留原始 Verify 错误与补偿删除错误。
	assertSagaCompensateJoinsBothErrors(t, ctx, h, rRepaired)
	// (d) (DurabilityCommitted, nonNilErr) 必须失败关闭为 FailedUncertain、不删旧凭据并写 AuditOutcomeUnknown。
	assertSagaCommittedWithErrFailClosed(t, ctx, h, rRepaired)
	// (e) Saga 与 VaultControl 回调 panic 均须向 OperationStream 发射 Succeeded=false, Code="panic"。
	assertSagaAndControlPanicEmitFailedEvent(t, ctx, h, rRepaired)
}

func assertSagaCompensateJoinsBothErrors(t *testing.T, ctx context.Context, h *credHarness, oldRef secret.Ref) {
	t.Helper()
	errVerify := errors.New("verify-boom-cause")
	errCompDel := errors.New("compensate-delete-boom")
	rNew := mustRef(t, "sim-aes256gcm", "edge-join-err")
	_, err := h.svc.ExecuteVaultSagaFromBytes(ctx, credential.VaultSagaRequest{
		NewRef: rNew,
		VerifyNewRef: func(context.Context, secret.Ref) error {
			h.vault.Faults().InjectOnce("vault.delete", errCompDel)
			return errVerify
		},
		MutateGraph: rotateMutator(oldRef),
	}, []byte("join-err-pass"))
	if !errors.Is(err, credential.ErrSagaUncertain) || !errors.Is(err, errVerify) || !errors.Is(err, errCompDel) {
		t.Fatalf("补偿失败必须同时保留 ErrSagaUncertain、原始根因与补偿错误，实际=%v", err)
	}
}

func assertSagaCommittedWithErrFailClosed(t *testing.T, ctx context.Context, h *credHarness, oldRef secret.Ref) {
	t.Helper()
	wrapStore := &commitErrInventoryStore{base: h.store, commitErr: io.ErrUnexpectedEOF}
	svc, err := credential.NewService(credential.ServiceConfig{
		Gate: h.gate, Vault: h.vault, VaultControl: h.vault,
		Store: wrapStore, Interaction: h.ui, Clock: h.clock, Entropy: h.rng.Fork(),
	})
	if err != nil {
		t.Fatalf("NewService(wrapStore): %v", err)
	}
	rNew := mustRef(t, "sim-aes256gcm", "edge-committed-err")
	res, err := svc.ExecuteVaultSagaFromBytes(ctx, credential.VaultSagaRequest{
		NewRef: rNew, OldRef: algebraic.Some(oldRef), MutateGraph: rotateMutator(oldRef),
	}, []byte("committed-err-pass"))
	if !errors.Is(err, credential.ErrSagaUncertain) || !res.IsFailedUncertain() {
		t.Fatalf("(DurabilityCommitted, err) 必须失败关闭为 FailedUncertain: kind=%s err=%v", res.StateKind(), err)
	}
	mustAssertSecretEquals(t, h.vault, oldRef, "repaired-pass")
	assertLastAuditOutcomeUnknown(t, h.auditCluster)
}

func assertSagaAndControlPanicEmitFailedEvent(t *testing.T, ctx context.Context, h *credHarness, oldRef secret.Ref) {
	t.Helper()
	// 1. VaultSaga VerifyNewRef panic -> OperationCompletedEvent{Succeeded: false, Code: "panic"}。
	s1 := mustNewCredStream(t, h.rng)
	var rec1 any
	func() {
		defer func() { rec1 = recover() }()
		_, _ = h.svc.ExecuteVaultSagaFromBytes(ctx, credential.VaultSagaRequest{
			NewRef:          mustRef(t, "sim-aes256gcm", "edge-panic-saga"),
			VerifyNewRef:    func(context.Context, secret.Ref) error { panic("saga-verify-panic") },
			MutateGraph:     rotateMutator(oldRef),
			OperationStream: s1,
		}, []byte("panic-pass"))
	}()
	if rec1 != "saga-verify-panic" {
		t.Fatalf("Saga panic 应原样传播，实际=%v", rec1)
	}
	assertStreamCompletedWithCode(t, ctx, s1, false, "panic")

	// 2. VaultControl Lock panic -> OperationCompletedEvent{Succeeded: false, Code: "panic"}。
	pSvc, err := credential.NewService(credential.ServiceConfig{
		Gate: h.gate, Vault: h.vault, VaultControl: &panicVaultControl{base: h.vault},
		Store: h.store, Interaction: h.ui, Clock: h.clock, Entropy: h.rng.Fork(),
	})
	if err != nil {
		t.Fatalf("NewService(panicVaultControl): %v", err)
	}
	s2 := mustNewCredStream(t, h.rng)
	var rec2 any
	func() {
		defer func() { rec2 = recover() }()
		_ = pSvc.Lock(ctx, credential.VaultControlRequest{OperationStream: s2})
	}()
	if rec2 != "vault-control-boom" {
		t.Fatalf("VaultControl panic 应原样传播，实际=%v", rec2)
	}
	assertStreamCompletedWithCode(t, ctx, s2, false, "panic")
}

func TestDeleteAndGC_OutcomeUnknownAuditReporting(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	h := newCredHarness(t, inventory.EmptyGraph(), false)

	// 1. DeleteSecret 遇到未知 I/O 错误必须上报 AuditOutcomeUnknown。
	rUnk := mustRef(t, "sim-aes256gcm", "del-unk")
	mustPutSecret(t, h.vault, rUnk, "val-unk")
	h.vault.Faults().InjectOnce("vault.delete", io.ErrUnexpectedEOF)
	if err := h.svc.DeleteSecret(ctx, credential.DeleteSecretRequest{Ref: rUnk}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("DeleteSecret 未知故障期望 io.ErrUnexpectedEOF，实际=%v", err)
	}
	assertLastAuditOutcomeUnknown(t, h.auditCluster)

	// 2. GCUnreferencedSecrets 在 store.Load 阶段失败（零删除尝试）不得误报 AuditOutcomeUnknown。
	h.store.Faults().InjectOnce("store.load", io.ErrUnexpectedEOF)
	if _, err := h.svc.GCUnreferencedSecrets(ctx, credential.GCUnreferencedRequest{Candidates: []secret.Ref{rUnk}}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("GC store.Load 故障期望 io.ErrUnexpectedEOF，实际=%v", err)
	}
	entries := h.auditCluster.Entries()
	if last := entries[len(entries)-1]; last.Outcome() == ports.AuditOutcomeUnknown {
		t.Fatalf("删除前 store.Load 失败不得误报 AuditOutcomeUnknown，实际=%s", last.Outcome())
	}

	// 3. GCUnreferencedSecrets 部分删除后第 2 条失败 -> 已产生半生效副作用，必须上报 AuditOutcomeUnknown。
	rA := mustRef(t, "sim-aes256gcm", "gc-part-a")
	rB := mustRef(t, "sim-aes256gcm", "gc-part-b")
	mustPutSecret(t, h.vault, rA, "val-a")
	mustPutSecret(t, h.vault, rB, "val-b")
	// rA 排在 rB 之前，先删除 rA 成功，再对第 2 次 vault.delete 注入故障。
	delBase := h.vault.Faults().Count("vault.delete")
	h.vault.Faults().SetHook("vault.delete", func(call uint64) error {
		if call == delBase+2 {
			return ports.ErrVaultLocked
		}
		return nil
	})
	defer h.vault.Faults().Clear("vault.delete")
	gcRes, err := h.svc.GCUnreferencedSecrets(ctx, credential.GCUnreferencedRequest{Candidates: []secret.Ref{rA, rB}})
	if !errors.Is(err, ports.ErrVaultLocked) || len(gcRes.Deleted) != 1 || !gcRes.Deleted[0].Equal(rA) {
		t.Fatalf("部分 GC 失败期望 1 条已删且返错: deleted=%v err=%v", gcRes.Deleted, err)
	}
	assertLastAuditOutcomeUnknown(t, h.auditCluster)
}

func mustNewCredStream(t *testing.T, rng *sim.SeededRand) *events.OperationStream {
	t.Helper()
	tid, err := security.NewTraceIDFrom(rng)
	if err != nil {
		t.Fatalf("NewTraceIDFrom: %v", err)
	}
	oid, err := security.NewOperationIDFrom(rng)
	if err != nil {
		t.Fatalf("NewOperationIDFrom: %v", err)
	}
	s, err := events.NewOperationStream(events.OperationStreamConfig{
		TraceID: tid, OperationID: oid, OperationBuffer: 32,
	})
	if err != nil {
		t.Fatalf("NewOperationStream: %v", err)
	}
	return s
}

func hasCredFinding(findings []credential.DoctorFinding, sev credential.DoctorSeverity, code string) bool {
	for _, f := range findings {
		if f.Severity == sev && f.Code == code {
			return true
		}
	}
	return false
}

func assertStreamCompletedWithCode(t *testing.T, ctx context.Context, stream *events.OperationStream, wantOK bool, wantCode string) {
	t.Helper()
	var saw bool
	for ev, err := range stream.All(ctx) {
		if err != nil {
			t.Fatalf("stream.All: %v", err)
		}
		if ce, ok := ev.(*events.OperationCompletedEvent); ok {
			saw = true
			if ce.Succeeded() != wantOK || (wantCode != "" && !strings.EqualFold(ce.Code(), wantCode)) {
				t.Fatalf("OperationCompletedEvent 不符: ok=%v code=%q (want ok=%v code=%q)", ce.Succeeded(), ce.Code(), wantOK, wantCode)
			}
		}
	}
	if !saw {
		t.Fatalf("OperationStream 缺失 OperationCompletedEvent")
	}
}
