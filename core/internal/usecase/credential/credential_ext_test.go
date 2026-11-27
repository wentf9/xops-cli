package credential_test

import (
	"context"
	"encoding"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"strings"
	"sync"
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

// 编译期接口断言统一置于外置 *_ext_test.go。
var (
	_ encoding.TextAppender   = credential.DoctorSeverityInfo
	_ encoding.TextMarshaler  = credential.DoctorSeverityInfo
	_ error                   = (*credential.SecretReferencedError)(nil)
	_ domi18n.LocalizableNode = (*credential.SecretReferencedError)(nil)
)

type stubPendingProvider struct {
	mu   sync.Mutex
	refs []inventory.PendingSecretRef
}

func (p *stubPendingProvider) Set(refs ...inventory.PendingSecretRef) {
	p.mu.Lock()
	p.refs = append([]inventory.PendingSecretRef(nil), refs...)
	p.mu.Unlock()
}

func (p *stubPendingProvider) ActivePendingSecretRefs() []inventory.PendingSecretRef {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]inventory.PendingSecretRef(nil), p.refs...)
}

// sequenceInteractionPort 支持在单次交互中按次序返回不同机密（验证二次确认口令不一致场景）。
type sequenceInteractionPort struct {
	base    *sim.SimInteractionPort
	mu      sync.Mutex
	secrets [][]byte
	idx     int
}

func (s *sequenceInteractionPort) CanInteract() bool { return s.base.CanInteract() }
func (s *sequenceInteractionPort) Confirm(ctx context.Context, req ports.ConfirmRequest) (security.Verdict, error) {
	return s.base.Confirm(ctx, req)
}
func (s *sequenceInteractionPort) PromptApproval(ctx context.Context, env security.ApprovalEnvelope) (ports.ApprovalDecisionResponse, error) {
	return s.base.PromptApproval(ctx, env)
}
func (s *sequenceInteractionPort) PromptText(ctx context.Context, req ports.TextPromptRequest) (string, error) {
	return s.base.PromptText(ctx, req)
}

//xops:syncclosure
//xops:borrowed
func (s *sequenceInteractionPort) PromptSecret(ctx context.Context, req ports.SecretPromptRequest, fn func(box *secret.SecretBox) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !req.IsValid() {
		return ports.ErrInvalidArgument
	}
	s.mu.Lock()
	var raw []byte
	if s.idx < len(s.secrets) {
		raw = append([]byte(nil), s.secrets[s.idx]...)
		s.idx++
	}
	s.mu.Unlock()
	return secret.WithBytes(raw, func(box *secret.SecretBox) error { return fn(box) })
}

type credHarness struct {
	clock        *sim.SimClock
	rng          *sim.SeededRand
	vault        *sim.SimVault
	store        *sim.SimInventoryStore
	auditCluster *sim.SimAuditCluster
	audit        *sim.SimAuditSink
	ui           *sim.SimInteractionPort
	gate         *gate.Gate
	pending      *stubPendingProvider
	svc          *credential.Service
}

func newCredHarness(t *testing.T, initial inventory.Graph, uninitVault bool) *credHarness {
	t.Helper()
	clk := sim.NewSimClock(time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC))
	rng := sim.NewSeededRand(42)
	var v *sim.SimVault
	if uninitVault {
		v = sim.NewUninitializedSimVault(rng.Fork())
	} else {
		v = sim.NewSimVault(rng.Fork())
	}
	st, err := sim.NewSimInventoryStore(initial)
	if err != nil {
		t.Fatalf("NewSimInventoryStore: %v", err)
	}
	procID, err := ports.ParseProcessInstanceID("proc-cred-test")
	if err != nil {
		t.Fatalf("ParseProcessInstanceID: %v", err)
	}
	cluster := sim.NewSimAuditCluster()
	auditSink, err := cluster.NewSink(procID)
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	t.Cleanup(func() { _ = auditSink.Close() })
	ui := sim.NewSimInteractionPort(true)
	pol, err := gate.NewGuardrailPolicy(gate.GuardrailPolicySpec{
		ApprovalThreshold: security.RiskDangerous,
		NoElicitFallback:  gate.NoElicitFallbackDeny,
	})
	if err != nil {
		t.Fatalf("NewGuardrailPolicy: %v", err)
	}
	g, err := gate.NewGate(gate.GateConfig{
		Profile:     gate.PolicyProfileDirectOperator,
		Policy:      pol,
		AuditSink:   auditSink,
		Interaction: ui,
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
		Interaction:  ui,
		Clock:        clk,
		Entropy:      rng.Fork(),
		PendingRefs:  pending,
	})
	if err != nil {
		t.Fatalf("credential.NewService: %v", err)
	}
	return &credHarness{clk, rng, v, st, cluster, auditSink, ui, g, pending, svc}
}

func mustRef(t *testing.T, store, item string) secret.Ref {
	t.Helper()
	ref, err := secret.NewRef(store, item)
	if err != nil {
		t.Fatalf("secret.NewRef(%s/%s): %v", store, item, err)
	}
	return ref
}

func mustFP(t *testing.T) inventory.KeyFingerprint {
	t.Helper()
	fp, err := inventory.ParseKeyFingerprint("SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU")
	if err != nil {
		t.Fatalf("ParseKeyFingerprint: %v", err)
	}
	return fp
}

func mustPutSecret(t *testing.T, v ports.SecretVault, ref secret.Ref, val string) {
	t.Helper()
	err := secret.WithBytes([]byte(val), func(box *secret.SecretBox) error {
		return v.PutAndVerify(context.Background(), ref, box)
	})
	if err != nil {
		t.Fatalf("PutAndVerify(%s): %v", ref, err)
	}
}

func mustAssertSecretEquals(t *testing.T, v ports.SecretVault, ref secret.Ref, want string) {
	t.Helper()
	err := secret.WithBytes([]byte(want), func(exp *secret.SecretBox) error {
		return v.WithSecret(context.Background(), ref, func(got *secret.SecretBox) error {
			if !got.Equal(exp) {
				t.Fatalf("凭据 %s 常量时间比对失配", ref)
			}
			return nil
		})
	})
	if err != nil {
		t.Fatalf("WithSecret(%s): %v", ref, err)
	}
}

func mustPrompt(t *testing.T, text string) ports.SecretPromptRequest {
	t.Helper()
	p, err := ports.NewSecretPromptRequest(ports.SecretPromptRequestSpec{Prompt: text})
	if err != nil {
		t.Fatalf("NewSecretPromptRequest: %v", err)
	}
	return p
}

// buildFiveLocationGraph 构造同时覆盖全部 5 处 SecretReference 位置的合法资产图。
func buildFiveLocationGraph(t *testing.T, rPass, rKey, rTOTP, rRule, rPriv secret.Ref) inventory.Graph {
	t.Helper()
	ep, _ := netaddr.ParseEndpoint("198.51.100.10:22")
	hid, _ := inventory.ParseHostID("h-1")
	host, err := inventory.NewHost(inventory.HostSpec{ID: hid, Endpoint: ep})
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	user, _ := option.ParseUsername("ops")

	idPassID, _ := inventory.ParseIdentityID("id-pass")
	authPass, _ := inventory.NewAuthPassword(rPass)
	idPass, _ := inventory.NewIdentity(inventory.IdentitySpec{ID: idPassID, User: user, Auth: authPass})

	kp, _ := inventory.ParseKeyPathSpec("~/.ssh/id_ed25519")
	kpNE, _ := algebraic.NonEmptyFromSlice([]inventory.KeyPathSpec{kp})
	kb, _ := inventory.NewKeyPassphraseBinding(rKey, mustFP(t))
	authKey, _ := inventory.NewAuthPrivateKey(kpNE, algebraic.Some(kb), nil)
	ruleTOTP, _ := inventory.NewRuleTOTP(inventory.ChallengeRuleMeta{Name: "otp", PromptPattern: "OTP:"}, rTOTP)
	ruleSec, _ := inventory.NewRuleSecretRef(inventory.ChallengeRuleMeta{Name: "pin", PromptPattern: "PIN:"}, rRule)
	rulesNE, _ := algebraic.NonEmptyFromSlice([]inventory.ChallengeRule{ruleTOTP, ruleSec})
	authKI, _ := inventory.NewAuthKeyboardInteractive(rulesNE)
	compNE, _ := algebraic.NonEmptyFromSlice([]inventory.AuthMethod{authKey, authKI})
	authComp, _ := inventory.NewAuthComposite(compNE)
	idCompID, _ := inventory.ParseIdentityID("id-comp")
	idComp, _ := inventory.NewIdentity(inventory.IdentitySpec{ID: idCompID, User: user, Auth: authComp})

	nid1, _ := inventory.ParseNodeID("node-1")
	n1, _ := inventory.NewNode(inventory.NodeSpec{
		ID: nid1, HostRef: hid, IdentityRef: idPassID,
		PrivilegePasswordRef: algebraic.Some(rPriv), Origin: inventory.NewOriginManaged(),
	})
	nid2, _ := inventory.ParseNodeID("node-2")
	n2, _ := inventory.NewNode(inventory.NodeSpec{
		ID: nid2, HostRef: hid, IdentityRef: idCompID, Origin: inventory.NewOriginManaged(),
	})
	g, err := inventory.NewGraph(inventory.GraphSpec{
		Hosts:       []inventory.Host{host},
		Identities:  []inventory.Identity{idPass, idComp},
		Nodes:       []inventory.Node{n1, n2},
		KnownStores: []string{"sim-aes256gcm"},
	})
	if err != nil {
		t.Fatalf("NewGraph: %v", err)
	}
	return g
}

func TestVaultLifecycleAndConfirmMismatch(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	h := newCredHarness(t, inventory.EmptyGraph(), true)

	var zeroSvc credential.Service
	if _, err := zeroSvc.Status(ctx, credential.StatusRequest{}); !errors.Is(err, credential.ErrServiceNotInitialized) {
		t.Fatalf("零值 Service 期望 ErrServiceNotInitialized，实际=%v", err)
	}
	st, err := h.svc.Status(ctx, credential.StatusRequest{})
	if err != nil || st.State() != ports.VaultStateUninitialized {
		t.Fatalf("期望 Uninitialized，实际 state=%v err=%v", st.State(), err)
	}

	// 二次确认口令不一致必须失败关闭且保持 Uninitialized。
	assertInitConfirmMismatchRejected(t, h)

	p1, p2 := mustPrompt(t, "Enter master passphrase"), mustPrompt(t, "Confirm master passphrase")
	h.ui.SetReplies("", []byte("master-pass-123"))
	if err := h.svc.InitInteractive(ctx, credential.InteractiveVaultControlRequest{
		Prompt: p1, ConfirmPrompt: algebraic.Some(p2),
	}); err != nil {
		t.Fatalf("InitInteractive: %v", err)
	}
	assertLockAndUnlockCycle(t, h, p1)
}

func assertInitConfirmMismatchRejected(t *testing.T, h *credHarness) {
	t.Helper()
	seqUI := &sequenceInteractionPort{base: h.ui, secrets: [][]byte{[]byte("pass-A"), []byte("pass-B")}}
	mismatchSvc, err := credential.NewService(credential.ServiceConfig{
		Gate: h.gate, Vault: h.vault, VaultControl: h.vault,
		Store: h.store, Interaction: seqUI, Clock: h.clock, Entropy: h.rng.Fork(),
	})
	if err != nil {
		t.Fatalf("NewService(seqUI): %v", err)
	}
	p1, p2 := mustPrompt(t, "Master 1"), mustPrompt(t, "Master 2")
	if err := mismatchSvc.InitInteractive(context.Background(), credential.InteractiveVaultControlRequest{
		Prompt: p1, ConfirmPrompt: algebraic.Some(p2),
	}); !errors.Is(err, credential.ErrPassphraseConfirmMismatch) {
		t.Fatalf("二次确认失配期望 ErrPassphraseConfirmMismatch，实际=%v", err)
	}
}

func assertLockAndUnlockCycle(t *testing.T, h *credHarness, prompt ports.SecretPromptRequest) {
	t.Helper()
	ctx := context.Background()
	if err := h.svc.Lock(ctx, credential.VaultControlRequest{}); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	wrongBuf := []byte("wrong-master")
	if err := h.svc.UnlockFromBytes(ctx, credential.VaultControlRequest{}, wrongBuf); !errors.Is(err, ports.ErrAuthFailed) {
		t.Fatalf("错误口令 UnlockFromBytes 期望 ErrAuthFailed，实际=%v", err)
	}
	for _, b := range wrongBuf {
		if b != 0 {
			t.Fatalf("UnlockFromBytes 必须清零调用方原始字节缓冲")
		}
	}
	if err := h.svc.UnlockInteractive(ctx, credential.InteractiveVaultControlRequest{Prompt: prompt}); err != nil {
		t.Fatalf("UnlockInteractive: %v", err)
	}
}

func TestScopedSecretAccessAndPromptedSecret(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	h := newCredHarness(t, inventory.EmptyGraph(), false)

	ref := mustRef(t, "sim-aes256gcm", "item-scoped")
	mustPutSecret(t, h.vault, ref, "top-secret-value")
	if err := secret.WithBytes([]byte("top-secret-value"), func(exp *secret.SecretBox) error {
		return h.svc.WithSecret(ctx, credential.WithSecretRequest{Ref: ref}, func(got *secret.SecretBox) error {
			if !got.IsValid() || !got.Equal(exp) {
				t.Fatalf("WithSecret 借出 SecretBox 常量时间比对失败")
			}
			return nil
		})
	}); err != nil {
		t.Fatalf("WithSecret: %v", err)
	}

	p := mustPrompt(t, "Secret input")
	h.ui.SetReplies("", []byte("prompted-secret"))
	if err := secret.WithBytes([]byte("prompted-secret"), func(exp *secret.SecretBox) error {
		return h.svc.WithPromptedSecret(ctx, p, func(got *secret.SecretBox) error {
			if !got.Equal(exp) {
				t.Fatalf("WithPromptedSecret 借出 SecretBox 失配")
			}
			return nil
		})
	}); err != nil {
		t.Fatalf("WithPromptedSecret: %v", err)
	}
}

func TestVaultSaga_HappyPathRotationAndStreamEvents(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	rPass := mustRef(t, "sim-aes256gcm", "pass-old")
	rKey := mustRef(t, "sim-aes256gcm", "key-old")
	rTOTP := mustRef(t, "sim-aes256gcm", "totp-old")
	rRule := mustRef(t, "sim-aes256gcm", "rule-old")
	rPriv := mustRef(t, "sim-aes256gcm", "priv-old")

	g0 := buildFiveLocationGraph(t, rPass, rKey, rTOTP, rRule, rPriv)
	h := newCredHarness(t, g0, false)
	for _, r := range []secret.Ref{rPass, rKey, rTOTP, rRule, rPriv} {
		mustPutSecret(t, h.vault, r, "old-value-"+r.Item())
	}

	tid, _ := security.NewTraceIDFrom(h.rng)
	oid, _ := security.NewOperationIDFrom(h.rng)
	stream, err := events.NewOperationStream(events.OperationStreamConfig{
		TraceID: tid, OperationID: oid, OperationBuffer: 32,
	})
	if err != nil {
		t.Fatalf("NewOperationStream: %v", err)
	}

	rPassNew := mustRef(t, "sim-aes256gcm", "pass-new")
	var res credential.SagaResult
	err = secret.WithBytes([]byte("new-password-v2"), func(box *secret.SecretBox) error {
		var rErr error
		res, rErr = h.svc.RotateSecret(ctx, credential.RotateSecretRequest{
			OldRef: rPass, NewRef: rPassNew, OperationStream: stream,
		}, box)
		return rErr
	})
	if err != nil || !res.IsValid() || res.StateKind() != fsm.VaultSagaKindCompleted || !res.OldDeleted() {
		t.Fatalf("RotateSecret(pass) 失败: kind=%s oldDel=%v err=%v", res.StateKind(), res.OldDeleted(), err)
	}
	mustAssertSecretEquals(t, h.vault, rPassNew, "new-password-v2")
	if err := h.vault.WithSecret(ctx, rPass, func(*secret.SecretBox) error { return nil }); !errors.Is(err, ports.ErrSecretNotFound) {
		t.Fatalf("旧凭据应已 GC 删除，实际=%v", err)
	}
	assertStreamSawVaultSagaLifecycle(t, stream)
	assertRotateRemainingFourLocations(t, h, rKey, rTOTP, rRule, rPriv)
	assertPendingPinDefersOldGC(t, h, mustRef(t, "sim-aes256gcm", "key-new"))
}

func assertRotateRemainingFourLocations(t *testing.T, h *credHarness, rKey, rTOTP, rRule, rPriv secret.Ref) {
	t.Helper()
	ctx := context.Background()
	p := mustPrompt(t, "New secret")
	for _, tc := range []struct {
		oldRef secret.Ref
		newIt  string
	}{
		{rKey, "key-new"},
		{rTOTP, "totp-new"},
		{rRule, "rule-new"},
		{rPriv, "priv-new"},
	} {
		h.ui.SetReplies("", []byte("rotated-"+tc.newIt))
		rNew := mustRef(t, "sim-aes256gcm", tc.newIt)
		rotRes, err := h.svc.RotateSecretInteractive(ctx, credential.InteractiveRotateSecretRequest{
			Prompt: p,
			Rotate: credential.RotateSecretRequest{OldRef: tc.oldRef, NewRef: rNew},
		})
		if err != nil || !rotRes.OldDeleted() {
			t.Fatalf("RotateSecretInteractive(%s): kind=%v err=%v", tc.oldRef, rotRes.StateKind(), err)
		}
		mustAssertSecretEquals(t, h.vault, rNew, "rotated-"+tc.newIt)
	}
}

func assertPendingPinDefersOldGC(t *testing.T, h *credHarness, oldRef secret.Ref) {
	t.Helper()
	h.pending.Set(inventory.PendingSecretRef{OwnerID: "pending_enroll:lease-1", Ref: oldRef})
	rV3 := mustRef(t, "sim-aes256gcm", "key-v3")
	var res credential.SagaResult
	err := secret.WithBytes([]byte("key-pass-v3"), func(box *secret.SecretBox) error {
		var rErr error
		res, rErr = h.svc.RotateSecret(context.Background(), credential.RotateSecretRequest{OldRef: oldRef, NewRef: rV3}, box)
		return rErr
	})
	if err != nil || res.StateKind() != fsm.VaultSagaKindCompleted || res.OldDeleted() {
		t.Fatalf("SecretLocPending 钉住态必须延迟 GC (OldDeleted=false)，实际 kind=%s oldDel=%v err=%v", res.StateKind(), res.OldDeleted(), err)
	}
	mustAssertSecretEquals(t, h.vault, oldRef, "rotated-key-new")
}

func assertStreamSawVaultSagaLifecycle(t *testing.T, stream *events.OperationStream) {
	t.Helper()
	var sawStart, sawFSM, sawDone bool
	for ev, err := range stream.All(context.Background()) {
		if err != nil {
			t.Fatalf("stream.All: %v", err)
		}
		switch ev.Kind() {
		case events.EventKindOperationStarted:
			sawStart = true
		case events.EventKindFSMTransition:
			sawFSM = true
		case events.EventKindOperationCompleted:
			sawDone = true
		}
	}
	if !sawStart || !sawFSM || !sawDone {
		t.Fatalf("OperationStream 缺少完整事件周期: start=%v fsm=%v done=%v", sawStart, sawFSM, sawDone)
	}
}

func TestVaultSaga_CompensationAndRollbackPaths(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	rOld := mustRef(t, "sim-aes256gcm", "old-cred")
	g0 := buildFiveLocationGraph(t, rOld, mustRef(t, "sim-aes256gcm", "k"), mustRef(t, "sim-aes256gcm", "t"), mustRef(t, "sim-aes256gcm", "r"), mustRef(t, "sim-aes256gcm", "p"))
	h := newCredHarness(t, g0, false)
	mustPutSecret(t, h.vault, rOld, "original-pass")

	// 1. VerifyNewRef 失败 -> 自动补偿删除新凭据。
	rFailVerify := mustRef(t, "sim-aes256gcm", "fail-verify")
	res, err := h.svc.ExecuteVaultSagaFromBytes(ctx, credential.VaultSagaRequest{
		NewRef:       rFailVerify,
		OldRef:       algebraic.Some(rOld),
		VerifyNewRef: func(context.Context, secret.Ref) error { return ports.ErrAuthFailed },
		MutateGraph:  rotateMutator(rOld),
	}, []byte("bad-passphrase"))
	if !errors.Is(err, credential.ErrSagaRolledBack) || !errors.Is(err, ports.ErrAuthFailed) || !res.Compensated() {
		t.Fatalf("VerifyNewRef 失败应触发补偿回滚: kind=%s comp=%v err=%v", res.StateKind(), res.Compensated(), err)
	}
	assertSecretAbsent(t, h.vault, rFailVerify)

	// 2. CAS Revision 冲突 -> DurabilityNotApplied -> 自动补偿删除新凭据。
	staleRev, _ := ports.ParseRevision("rev-stale-999")
	rFailCAS := mustRef(t, "sim-aes256gcm", "fail-cas")
	res, err = h.svc.ExecuteVaultSagaFromBytes(ctx, credential.VaultSagaRequest{
		NewRef:           rFailCAS,
		OldRef:           algebraic.Some(rOld),
		ExpectedRevision: algebraic.Some(staleRev),
		MutateGraph:      rotateMutator(rOld),
	}, []byte("cas-conflict-pass"))
	if !errors.Is(err, credential.ErrSagaRolledBack) || !errors.Is(err, ports.ErrRevisionConflict) || !res.Compensated() {
		t.Fatalf("CAS 冲突应触发补偿回滚: kind=%s comp=%v err=%v", res.StateKind(), res.Compensated(), err)
	}
	assertSecretAbsent(t, h.vault, rFailCAS)

	// 3. Vault 锁定时写入 -> SideEffectFailedNotApplied -> RolledBack(compensated=false)。
	if err := h.vault.Lock(ctx); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	rLocked := mustRef(t, "sim-aes256gcm", "locked-new")
	res, err = h.svc.ExecuteVaultSagaFromBytes(ctx, credential.VaultSagaRequest{
		NewRef: rLocked, MutateGraph: rotateMutator(rOld),
	}, []byte("locked-pass"))
	if !errors.Is(err, credential.ErrSagaRolledBack) || !errors.Is(err, ports.ErrVaultLocked) || res.Compensated() {
		t.Fatalf("锁定态写入期望 RolledBack(compensated=false): kind=%s comp=%v err=%v", res.StateKind(), res.Compensated(), err)
	}
}

func TestVaultSaga_AppliedNotDurableAndOutcomeUnknownZeroRetry(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	rOld := mustRef(t, "sim-aes256gcm", "old-cred")
	g0 := buildFiveLocationGraph(t, rOld, mustRef(t, "sim-aes256gcm", "k"), mustRef(t, "sim-aes256gcm", "t"), mustRef(t, "sim-aes256gcm", "r"), mustRef(t, "sim-aes256gcm", "p"))
	h := newCredHarness(t, g0, false)
	mustPutSecret(t, h.vault, rOld, "original-pass")

	// 1. Applied && !Durable -> UncertainDurability，严禁重试、严禁删新旧凭据，审计记 AuditOutcomeUnknown。
	revNext, _ := ports.ParseRevision("rev-uncertain-1")
	durAND, _ := ports.NewDurabilityAppliedNotDurable(algebraic.Some(revNext), "fsync failed after rename")
	h.store.InjectNextDurability(durAND)
	rAND := mustRef(t, "sim-aes256gcm", "applied-not-durable")
	res, err := h.svc.ExecuteVaultSagaFromBytes(ctx, credential.VaultSagaRequest{
		NewRef: rAND, OldRef: algebraic.Some(rOld), MutateGraph: rotateMutator(rOld),
	}, []byte("durable-uncertain-pass"))
	if !errors.Is(err, credential.ErrUncertainDurability) || !res.IsUncertainDurability() {
		t.Fatalf("Applied && !Durable 期望 UncertainDurability: kind=%s err=%v", res.StateKind(), err)
	}
	mustAssertSecretEquals(t, h.vault, rAND, "durable-uncertain-pass")
	mustAssertSecretEquals(t, h.vault, rOld, "original-pass")
	assertLastAuditOutcomeUnknown(t, h.auditCluster)

	// 2. DurabilityOutcomeUnknown -> FailedUncertain，零重试零删凭据，审计记 AuditOutcomeUnknown。
	durUnk, _ := ports.NewDurabilityOutcomeUnknown("disk timeout during commit")
	h.store.InjectNextDurability(durUnk)
	rCommitUnk := mustRef(t, "sim-aes256gcm", "commit-unknown")
	res, err = h.svc.ExecuteVaultSagaFromBytes(ctx, credential.VaultSagaRequest{
		NewRef: rCommitUnk, OldRef: algebraic.Some(rAND), MutateGraph: rotateMutator(rAND),
	}, []byte("commit-unk-pass"))
	if !errors.Is(err, credential.ErrSagaUncertain) || !res.IsFailedUncertain() {
		t.Fatalf("DurabilityOutcomeUnknown 期望 FailedUncertain: kind=%s err=%v", res.StateKind(), err)
	}
	mustAssertSecretEquals(t, h.vault, rCommitUnk, "commit-unk-pass")
	mustAssertSecretEquals(t, h.vault, rAND, "durable-uncertain-pass")
	assertLastAuditOutcomeUnknown(t, h.auditCluster)

	// 3. PutAndVerify 未知 I/O 故障 -> FailedUncertain，零重试。
	h.vault.Faults().InjectOnce("vault.put", io.ErrUnexpectedEOF)
	rPutUnk := mustRef(t, "sim-aes256gcm", "put-unknown")
	res, err = h.svc.ExecuteVaultSagaFromBytes(ctx, credential.VaultSagaRequest{
		NewRef: rPutUnk, MutateGraph: rotateMutator(rAND),
	}, []byte("put-unk-pass"))
	if !errors.Is(err, credential.ErrSagaUncertain) || !res.IsFailedUncertain() {
		t.Fatalf("PutAndVerify 未知故障期望 FailedUncertain: kind=%s err=%v", res.StateKind(), err)
	}
}

func rotateMutator(oldRef secret.Ref) credential.GraphMutator {
	return func(_ context.Context, snap ports.InventorySnapshot, newRef secret.Ref) (inventory.Graph, error) {
		ng, _, err := credential.ReplaceSecretRefInGraph(snap.Graph(), oldRef, newRef)
		return ng, err
	}
}

func assertSecretAbsent(t *testing.T, v ports.SecretVault, ref secret.Ref) {
	t.Helper()
	if err := v.WithSecret(context.Background(), ref, func(*secret.SecretBox) error { return nil }); !errors.Is(err, ports.ErrSecretNotFound) {
		t.Fatalf("凭据 %s 应不存在，实际=%v", ref, err)
	}
}

func assertLastAuditOutcomeUnknown(t *testing.T, cluster *sim.SimAuditCluster) {
	t.Helper()
	entries := cluster.Entries()
	if len(entries) == 0 {
		t.Fatalf("审计记录不能为空")
	}
	if last := entries[len(entries)-1]; last.Outcome() != ports.AuditOutcomeUnknown {
		t.Fatalf("不确定终态必须向审计写入 AuditOutcomeUnknown，实际=%s", last.Outcome())
	}
}

func TestDeleteSecretFiveLocationsAndPendingBlock(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	rPass := mustRef(t, "sim-aes256gcm", "loc-pass")
	rKey := mustRef(t, "sim-aes256gcm", "loc-key")
	rTOTP := mustRef(t, "sim-aes256gcm", "loc-totp")
	rRule := mustRef(t, "sim-aes256gcm", "loc-rule")
	rPriv := mustRef(t, "sim-aes256gcm", "loc-priv")
	rPend := mustRef(t, "sim-aes256gcm", "loc-pending")
	rFree := mustRef(t, "sim-aes256gcm", "loc-free")

	g0 := buildFiveLocationGraph(t, rPass, rKey, rTOTP, rRule, rPriv)
	h := newCredHarness(t, g0, false)
	h.pending.Set(inventory.PendingSecretRef{OwnerID: "pending_enroll:op-9", Ref: rPend})
	for _, r := range []secret.Ref{rPass, rKey, rTOTP, rRule, rPriv, rPend, rFree} {
		mustPutSecret(t, h.vault, r, "secret-material-"+r.Item())
	}

	assertAllSixLocationsBlockDelete(t, h, rPass, rKey, rTOTP, rRule, rPriv, rPend)

	gcRes, err := h.svc.GCUnreferencedSecrets(ctx, credential.GCUnreferencedRequest{
		Candidates: []secret.Ref{rPass, rPend, rFree},
	})
	if err != nil || len(gcRes.Deleted) != 1 || !gcRes.Deleted[0].Equal(rFree) || len(gcRes.Retained) != 2 {
		t.Fatalf("GC 结果失配: deleted=%v retained=%v err=%v", gcRes.Deleted, gcRes.Retained, err)
	}
}

func assertAllSixLocationsBlockDelete(t *testing.T, h *credHarness, rPass, rKey, rTOTP, rRule, rPriv, rPend secret.Ref) {
	t.Helper()
	wantLocs := []struct {
		ref secret.Ref
		loc inventory.SecretRefLocation
	}{
		{rPass, inventory.SecretLocAuthPassword},
		{rKey, inventory.SecretLocPrivateKeyPassphrase},
		{rTOTP, inventory.SecretLocChallengeTOTP},
		{rRule, inventory.SecretLocChallengeSecret},
		{rPriv, inventory.SecretLocNodePrivilege},
		{rPend, inventory.SecretLocPending},
	}
	for _, tc := range wantLocs {
		err := h.svc.DeleteSecret(context.Background(), credential.DeleteSecretRequest{Ref: tc.ref})
		refErr, ok := errors.AsType[*credential.SecretReferencedError](err)
		if !errors.Is(err, credential.ErrSecretStillReferenced) || !ok || !refErr.IsValid() || len(refErr.References()) != 1 || refErr.References()[0].Location != tc.loc {
			t.Fatalf("位置 %s 必须阻断删除并返回精确 SecretReferencedError，实际=%v", tc.loc, err)
		}
		assertCredSecretRefLocalizable(t, refErr, tc.ref, tc.loc)
	}
}

func assertCredSecretRefLocalizable(t *testing.T, refErr *credential.SecretReferencedError, wantRef secret.Ref, wantLoc inventory.SecretRefLocation) {
	t.Helper()
	view, ok := domi18n.InspectNode(refErr)
	if !ok || !errors.Is(view.Sentinel, credential.ErrSecretStillReferenced) || view.Message.ID() != domi18n.KeyUCCredSecretRefDetail {
		t.Fatalf("SecretReferencedError.LocalizableView 失配: ok=%v view=%+v", ok, view)
	}
	if id, okID := domi18n.ErrorID(refErr); !okID || id != domi18n.KeyUCCredSecretRefDetail {
		t.Fatalf("ErrorID 期望 %s，实际 ok=%v id=%s", domi18n.KeyUCCredSecretRefDetail, okID, id)
	}
	gotText := refErr.Error()
	if gotText != domi18n.CanonicalError(refErr) || !strings.Contains(gotText, wantRef.String()) || !strings.Contains(gotText, wantLoc.String()) {
		t.Fatalf("SecretReferencedError.Error 与 CanonicalError 失配: got=%q", gotText)
	}
}

func TestSecretReferencedError_NilAndZeroLocalizableSafety(t *testing.T) {
	defer goleak.VerifyNone(t)
	var nilErr *credential.SecretReferencedError
	var zeroVal credential.SecretReferencedError
	zeroErr := &zeroVal
	want := credential.ErrSecretStillReferenced.Error()
	for name, e := range map[string]*credential.SecretReferencedError{"nil": nilErr, "zero": zeroErr} {
		if e.IsValid() || e.Unwrap() != nil || errors.Is(e, credential.ErrSecretStillReferenced) {
			t.Fatalf("%s SecretReferencedError 必须零值失效且 Unwrap==nil", name)
		}
		view := e.LocalizableView()
		if !errors.Is(view.Sentinel, credential.ErrSecretStillReferenced) || view.Message.IsValid() {
			t.Fatalf("%s LocalizableView 必须退化为纯哨兵视图: %+v", name, view)
		}
		if e.Error() != want || domi18n.CanonicalError(e) != want {
			t.Fatalf("%s Error/CanonicalError 期望 %q，实际 err=%q canon=%q", name, want, e.Error(), domi18n.CanonicalError(e))
		}
	}
}

func TestDoctorReadOnlyAndZeroSecretLeak(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	rPass := mustRef(t, "sim-aes256gcm", "doc-pass")
	rKey := mustRef(t, "sim-aes256gcm", "doc-key")
	rTOTP := mustRef(t, "sim-aes256gcm", "doc-totp")
	rRule := mustRef(t, "sim-aes256gcm", "doc-rule")
	rPriv := mustRef(t, "sim-aes256gcm", "doc-priv")

	h := newCredHarness(t, buildFiveLocationGraph(t, rPass, rKey, rTOTP, rRule, rPriv), false)
	for _, r := range []secret.Ref{rPass, rKey, rRule, rPriv} {
		mustPutSecret(t, h.vault, r, "top-secret-plain-"+r.Item())
	}
	// rTOTP 故意缺失，验证 Doctor 报错且不修改存储、不泄露任何明文。
	docRep, err := h.svc.Doctor(ctx, credential.DoctorRequest{})
	if err != nil || docRep.Healthy || docRep.ReferencedCount != 5 {
		t.Fatalf("Doctor 报告失配: %+v err=%v", docRep, err)
	}
	rawJSON, err := jsonv2.Marshal(docRep, jsonv2.Deterministic(true))
	if err != nil {
		t.Fatalf("jsonv2.Marshal(DoctorReport): %v", err)
	}
	if strings.Contains(string(rawJSON), "top-secret-plain-") {
		t.Fatalf("Doctor 报告严禁泄露任何明文机密: %s", string(rawJSON))
	}
}
