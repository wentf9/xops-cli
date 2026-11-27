package inventory_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/usecase/credential"
	ucinv "github.com/wentf9/xops-cli/core/internal/usecase/inventory"
	"github.com/wentf9/xops-cli/core/ports"
)

func TestPendingEnrollment_VerifyBeforeEnrollHappyPathAndPinGuard(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	h := newInvHarness(t, nil)

	stagedRef := mustTestRef(t, "enroll-staged-pwd")
	putTestSecret(t, h.vault, stagedRef, "enroll-secret-01")
	authPwd, _ := inventory.NewAuthPassword(stagedRef)
	stagedHost := mustTestHost(t, "h-enroll", "198.51.100.91", 22)
	stagedID := mustTestIdentity(t, "id-enroll", "ops", authPwd)
	stagedNode := mustTestNode(t, "n-enroll", "h-enroll", "id-enroll", nil, nil, algebraic.None[secret.Ref](), nil)
	wantFP := mustTestFP(t, 42)

	tid, _ := security.NewTraceIDFrom(h.rng)
	oid, _ := security.NewOperationIDFrom(h.rng)
	stream, err := events.NewOperationStream(events.OperationStreamConfig{
		TraceID: tid, OperationID: oid, OperationBuffer: 32,
	})
	if err != nil {
		t.Fatalf("NewOperationStream: %v", err)
	}
	var nilLease *ucinv.PendingEnrollmentLease
	if nilLease.IsValid() {
		t.Fatalf("nil PendingEnrollmentLease 必须无效")
	}
	if _, lErr := nilLease.Commit(ctx); !errors.Is(lErr, ucinv.ErrLeaseExpired) {
		t.Fatalf("nil 租约调用 Commit 应返回 ErrLeaseExpired，实际=%v", lErr)
	}
	res, err := h.svc.WithPendingEnrollment(ctx, ucinv.PendingEnrollmentRequest{
		Host: algebraic.Some(stagedHost), Identity: algebraic.Some(stagedID), Node: stagedNode,
		PinnedRefs: []secret.Ref{stagedRef}, OperationStream: stream,
	}, func(scopeCtx context.Context, lease *ucinv.PendingEnrollmentLease) error {
		assertVerifyBeforeEnrollScope(t, scopeCtx, h, lease, stagedRef, wantFP)
		return nil
	})
	if err != nil || !res.IsValid() || res.Phase() != fsm.PendingEnrollPhaseEnrolled || !res.Revision().IsSome() {
		t.Fatalf("WithPendingEnrollment 终态异常: res=%+v err=%v", res, err)
	}
	if len(h.svc.ActivePendingSecretRefs()) != 0 {
		t.Fatalf("Enrolled 后应释放全部暂存凭据钉住")
	}
	assertPendingEnrollStreamLifecycle(t, ctx, stream)
}

func assertVerifyBeforeEnrollScope(
	t *testing.T, scopeCtx context.Context, h *invTestHarness,
	//xops:borrowed
	lease *ucinv.PendingEnrollmentLease,
	stagedRef secret.Ref, wantFP inventory.KeyFingerprint,
) {
	t.Helper()
	if !lease.IsValid() || lease.Phase() != fsm.PendingEnrollPhaseStaged {
		t.Fatalf("进入作用域时应处于 Staged，实际=%s", lease.Phase())
	}
	// 1. 先验证后入库：跳过 Probe 直接 Commit 必须被 PendingEnrollFSM 返回 ErrIllegalTransition！
	if _, cErr := lease.Commit(scopeCtx); !errors.Is(cErr, fsm.ErrIllegalTransition) {
		t.Fatalf("跳过 Probe 直接 Commit 应返回 fsm.ErrIllegalTransition，实际=%v", cErr)
	}
	// 2. 钉住保护：活跃租约期间 credential.DeleteSecret 必须因 SecretLocPending 拒绝删除！
	if dErr := h.credSvc.DeleteSecret(scopeCtx, credential.DeleteSecretRequest{Ref: stagedRef}); !errors.Is(dErr, credential.ErrSecretStillReferenced) {
		t.Fatalf("活跃暂存租约期间应阻止删除已钉住凭据，实际=%v", dErr)
	}
	// 3. Probe 验证通过 -> Verified -> Commit 落盘 Enrolled。
	fp, pErr := lease.Probe(scopeCtx, func(context.Context) (inventory.KeyFingerprint, error) { return wantFP, nil })
	if pErr != nil || !fp.Equal(wantFP) || lease.Phase() != fsm.PendingEnrollPhaseVerified {
		t.Fatalf("Probe 失败: fp=%v phase=%s err=%v", fp, lease.Phase(), pErr)
	}
	rev, cErr := lease.Commit(scopeCtx)
	if cErr != nil || !rev.IsValid() || lease.Phase() != fsm.PendingEnrollPhaseEnrolled {
		t.Fatalf("Commit 失败: rev=%v phase=%s err=%v", rev, lease.Phase(), cErr)
	}
}

func assertPendingEnrollStreamLifecycle(t *testing.T, ctx context.Context, stream *events.OperationStream) {
	t.Helper()
	var started, transitions, completed int
	for ev, evErr := range stream.All(ctx) {
		if evErr != nil {
			t.Fatalf("stream.All: %v", evErr)
		}
		switch ev.Kind() {
		case events.EventKindOperationStarted:
			started++
		case events.EventKindFSMTransition:
			transitions++
		case events.EventKindOperationCompleted:
			completed++
		}
	}
	if started != 1 || transitions < 4 || completed != 1 {
		t.Fatalf("事件流计数异常: started=%d transitions=%d completed=%d", started, transitions, completed)
	}
}

func TestPendingEnrollment_CleanupOnAbortExpiryPanicAndUncertain(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	h := newInvHarness(t, nil)

	// 预置一个已入库的共享凭据，确认回滚清理绝不会误删已引用凭据！
	sharedRef := mustTestRef(t, "enroll-shared")
	putTestSecret(t, h.vault, sharedRef, "shared-val")
	aShared, err := inventory.NewAuthPassword(sharedRef)
	if err != nil {
		t.Fatalf("NewAuthPassword: %v", err)
	}
	if _, err := h.svc.CreateHost(ctx, ucinv.HostMutationRequest{Host: mustTestHost(t, "h-base", "198.51.100.1", 22)}); err != nil {
		t.Fatalf("CreateHost(h-base): %v", err)
	}
	if _, err := h.svc.CreateIdentity(ctx, ucinv.IdentityMutationRequest{Identity: mustTestIdentity(t, "id-base", "ops", aShared)}); err != nil {
		t.Fatalf("CreateIdentity(id-base): %v", err)
	}

	// 场景 1：Probe 失败 -> 自动清理独占暂存凭据、保留共享凭据、释放钉住。
	assertPendingProbeFailureCleanup(t, ctx, h, sharedRef)
	// 场景 2：回调 panic -> defer 自动清理暂存凭据并原样重抛 panic。
	assertPendingPanicCleanup(t, ctx, h)
	// 场景 3：TTL 过期 -> Probe 触发过期清理 Aborted。
	assertPendingTTLExpiryCleanup(t, ctx, h)
	// 场景 4：Commit 遇 AppliedNotDurable -> 停机 Uncertain，不删凭据且保留钉住，上报 AuditOutcomeUnknown！
	assertPendingUncertainKeepsPins(t, ctx, h)
}

func assertPendingProbeFailureCleanup(t *testing.T, ctx context.Context, h *invTestHarness, sharedRef secret.Ref) {
	t.Helper()
	stagedOnly := mustTestRef(t, "enroll-probe-fail")
	putTestSecret(t, h.vault, stagedOnly, "ephemeral-secret")
	node := mustTestNode(t, "n-fail", "h-base", "id-base", nil, nil, algebraic.None[secret.Ref](), nil)
	res, err := h.svc.WithPendingEnrollment(ctx, ucinv.PendingEnrollmentRequest{
		Node: node, PinnedRefs: []secret.Ref{stagedOnly, sharedRef},
	}, func(c context.Context, lease *ucinv.PendingEnrollmentLease) error {
		_, pErr := lease.Probe(c, func(context.Context) (inventory.KeyFingerprint, error) {
			return zeroTest[inventory.KeyFingerprint](), ports.ErrAuthFailed
		})
		return pErr
	})
	if !errors.Is(err, ucinv.ErrEnrollmentAborted) || res.Phase() != fsm.PendingEnrollPhaseAborted {
		t.Fatalf("Probe 失败应进入 Aborted: res=%+v err=%v", res, err)
	}
	if _, ok := h.vault.CiphertextFor(stagedOnly); ok {
		t.Fatalf("Probe 失败后独占暂存凭据必须被清理删除")
	}
	if _, ok := h.vault.CiphertextFor(sharedRef); !ok {
		t.Fatalf("Probe 失败清理绝不可误删已入库共享凭据")
	}
	if len(h.svc.ActivePendingSecretRefs()) != 0 {
		t.Fatalf("Aborted 后必须释放钉住")
	}
}

func assertPendingPanicCleanup(t *testing.T, ctx context.Context, h *invTestHarness) {
	t.Helper()
	panicRef := mustTestRef(t, "enroll-panic-ref")
	putTestSecret(t, h.vault, panicRef, "panic-secret")
	node := mustTestNode(t, "n-panic", "h-base", "id-base", nil, nil, algebraic.None[secret.Ref](), nil)
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		_, _ = h.svc.WithPendingEnrollment(ctx, ucinv.PendingEnrollmentRequest{
			Node: node, PinnedRefs: []secret.Ref{panicRef},
		}, func(context.Context, *ucinv.PendingEnrollmentLease) error {
			panic("boom-in-pending-scope")
		})
	}()
	if recovered != "boom-in-pending-scope" {
		t.Fatalf("回调 panic 必须原样传播，实际=%v", recovered)
	}
	if _, ok := h.vault.CiphertextFor(panicRef); ok {
		t.Fatalf("回调 panic 后 defer 必须清理独占暂存凭据")
	}
	if len(h.svc.ActivePendingSecretRefs()) != 0 {
		t.Fatalf("回调 panic 清理后必须释放钉住")
	}
}

func assertPendingTTLExpiryCleanup(t *testing.T, ctx context.Context, h *invTestHarness) {
	t.Helper()
	expRef := mustTestRef(t, "enroll-expire-ref")
	putTestSecret(t, h.vault, expRef, "expire-secret")
	node := mustTestNode(t, "n-expire", "h-base", "id-base", nil, nil, algebraic.None[secret.Ref](), nil)
	res, err := h.svc.WithPendingEnrollment(ctx, ucinv.PendingEnrollmentRequest{
		Node: node, PinnedRefs: []secret.Ref{expRef}, TTL: algebraic.FromStdDuration(10 * time.Second),
	}, func(c context.Context, lease *ucinv.PendingEnrollmentLease) error {
		h.clock.Advance(15 * time.Second)
		_, pErr := lease.Probe(c, func(context.Context) (inventory.KeyFingerprint, error) { return mustTestFP(t, 7), nil })
		return pErr
	})
	if !errors.Is(err, ucinv.ErrEnrollmentAborted) || res.Phase() != fsm.PendingEnrollPhaseAborted {
		t.Fatalf("TTL 过期后应中止清理: phase=%s err=%v", res.Phase(), err)
	}
	if _, ok := h.vault.CiphertextFor(expRef); ok {
		t.Fatalf("TTL 过期后暂存凭据必须被清理")
	}
}

func assertPendingUncertainKeepsPins(t *testing.T, ctx context.Context, h *invTestHarness) {
	t.Helper()
	uncRef := mustTestRef(t, "enroll-uncertain-ref")
	putTestSecret(t, h.vault, uncRef, "uncertain-secret")
	node := mustTestNode(t, "n-unc", "h-base", "id-base", nil, nil, algebraic.None[secret.Ref](), nil)
	uncRev, _ := ports.ParseRevision("rev-enroll-unc")
	uncOut, _ := ports.NewDurabilityAppliedNotDurable(algebraic.Some(uncRev), "dir sync lost")
	h.store.InjectNextDurability(uncOut)

	res, err := h.svc.WithPendingEnrollment(ctx, ucinv.PendingEnrollmentRequest{
		Node: node, PinnedRefs: []secret.Ref{uncRef},
	}, func(c context.Context, lease *ucinv.PendingEnrollmentLease) error {
		if _, pErr := lease.Probe(c, func(context.Context) (inventory.KeyFingerprint, error) { return mustTestFP(t, 8), nil }); pErr != nil {
			return pErr
		}
		_, cErr := lease.Commit(c)
		return cErr
	})
	if !errors.Is(err, ucinv.ErrEnrollmentUncertain) || res.Phase() != fsm.PendingEnrollPhaseUncertain {
		t.Fatalf("AppliedNotDurable 应停机 Uncertain: phase=%s err=%v", res.Phase(), err)
	}
	if _, ok := h.vault.CiphertextFor(uncRef); !ok {
		t.Fatalf("Uncertain 终态绝不可删除凭据")
	}
	if len(h.svc.ActivePendingSecretRefs()) != 1 || !h.svc.ActivePendingSecretRefs()[0].Ref.Equal(uncRef) {
		t.Fatalf("Uncertain 终态必须继续钉住凭据防 GC，实际=%v", h.svc.ActivePendingSecretRefs())
	}
}

func TestEnrollEncryptedPrivateKey_InteractiveVaultSagaAndRollbackGC(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	h := newInvHarness(t, nil)

	kp, _ := inventory.ParseKeyPathSpec("~/.ssh/prod_ed25519")
	user, _ := option.ParseUsername("deploy")
	id1, _ := inventory.ParseIdentityID("id-prod-key")
	fp1 := mustTestFP(t, 55)
	h.signer.Register(kp.String(), "correct-pass-v1", fp1)

	// 1. 错误口令解密失败 -> VaultSagaFSM 必须回滚 GC 删除已写入凭据，绝不留孤儿凭据！
	badRef := mustTestRef(t, "key-bad-pass")
	h.ui.SetReplies("", []byte("wrong-pass"))
	badRes, err := h.svc.EnrollEncryptedPrivateKeyIdentity(ctx, ucinv.EnrollEncryptedPrivateKeyRequest{
		IdentityID: id1, User: user, KeyPath: kp, NewRef: badRef,
	})
	if !errors.Is(err, ports.ErrAuthFailed) || !badRes.SagaResult().Compensated() {
		t.Fatalf("口令错应返回 ErrAuthFailed 并补偿删除新凭据: err=%v comp=%v", err, badRes.SagaResult().Compensated())
	}
	if _, exists := h.vault.CiphertextFor(badRef); exists {
		t.Fatalf("解密失败后绝不能遗留孤儿凭据 %s", badRef)
	}

	// 2. 预期指纹失配 -> 自动回滚 GC，零孤儿凭据！
	fpBadRef := mustTestRef(t, "key-fp-mismatch")
	h.ui.SetReplies("", []byte("correct-pass-v1"))
	fpRes, err := h.svc.EnrollEncryptedPrivateKeyIdentity(ctx, ucinv.EnrollEncryptedPrivateKeyRequest{
		IdentityID: id1, User: user, KeyPath: kp, NewRef: fpBadRef, ExpectedFingerprint: algebraic.Some(mustTestFP(t, 99)),
	})
	if !errors.Is(err, ucinv.ErrKeyFingerprintMismatch) || !fpRes.SagaResult().Compensated() {
		t.Fatalf("指纹失配应回滚 GC: err=%v comp=%v", err, fpRes.SagaResult().Compensated())
	}
	if _, exists := h.vault.CiphertextFor(fpBadRef); exists {
		t.Fatalf("指纹失配后绝不能遗留孤儿凭据 %s", fpBadRef)
	}

	// 3. 正确口令交互式登记成功 -> 绑定真实指纹与凭据引用并提交 CAS。
	okRef := mustTestRef(t, "key-pass-v1")
	h.ui.SetReplies("", []byte("correct-pass-v1"))
	okRes, err := h.svc.EnrollEncryptedPrivateKeyIdentity(ctx, ucinv.EnrollEncryptedPrivateKeyRequest{
		IdentityID: id1, User: user, KeyPath: kp, NewRef: okRef, ExpectedFingerprint: algebraic.Some(fp1),
	})
	if err != nil || !okRes.IsValid() || !okRes.Fingerprint().Equal(fp1) || !okRes.PassphraseRef().Equal(okRef) {
		t.Fatalf("交互式加密私钥登记失败: res=%+v err=%v", okRes, err)
	}

	// 4. 重复登记未开 ReplaceExisting -> 拒绝并回滚 GC 新凭据。
	dupRef := mustTestRef(t, "key-pass-dup")
	rawBytes := []byte("correct-pass-v1")
	dupRes, err := h.svc.EnrollEncryptedPrivateKeyIdentityFromBytes(ctx, ucinv.EnrollEncryptedPrivateKeyRequest{
		IdentityID: id1, User: user, KeyPath: kp, NewRef: dupRef,
	}, rawBytes)
	if !errors.Is(err, ucinv.ErrAssetAlreadyExists) || !dupRes.SagaResult().Compensated() {
		t.Fatalf("重复登记未开启 ReplaceExisting 应回滚 GC: err=%v comp=%v", err, dupRes.SagaResult().Compensated())
	}
	if !bytes.Equal(rawBytes, make([]byte, len(rawBytes))) {
		t.Fatalf("EnrollEncryptedPrivateKeyIdentityFromBytes 必须清零调用方原始口令切片")
	}
	if _, exists := h.vault.CiphertextFor(dupRef); exists {
		t.Fatalf("重复登记失败后绝不可留孤儿凭据")
	}

	// 5. ReplaceExisting=true 轮换口令 -> 自动回收旧口令 okRef；随后 AppliedNotDurable 保留新旧双凭据！
	assertKeyEnrollReplaceAndUncertain(t, ctx, h, id1, user, kp, okRef)
}

func assertKeyEnrollReplaceAndUncertain(
	t *testing.T, ctx context.Context, h *invTestHarness,
	id1 inventory.IdentityID, user option.Username, kp inventory.KeyPathSpec, oldRef secret.Ref,
) {
	t.Helper()
	fp2 := mustTestFP(t, 66)
	h.signer.Register(kp.String(), "correct-pass-v2", fp2)
	v2Ref := mustTestRef(t, "key-pass-v2")
	h.ui.SetReplies("", []byte("correct-pass-v2"))
	repRes, err := h.svc.EnrollEncryptedPrivateKeyIdentity(ctx, ucinv.EnrollEncryptedPrivateKeyRequest{
		IdentityID: id1, User: user, KeyPath: kp, NewRef: v2Ref, ReplaceExisting: true,
	})
	if err != nil || !repRes.IsValid() || !repRes.SagaResult().OldDeleted() {
		t.Fatalf("ReplaceExisting 应提交新口令并回收旧口令: err=%v oldDeleted=%v", err, repRes.SagaResult().OldDeleted())
	}
	if _, exists := h.vault.CiphertextFor(oldRef); exists {
		t.Fatalf("替换成功后无引用旧口令 %s 应被安全 GC", oldRef)
	}

	// AppliedNotDurable 时绝不删新凭据也绝不删旧凭据！
	fp3 := mustTestFP(t, 77)
	h.signer.Register(kp.String(), "correct-pass-v3", fp3)
	v3Ref := mustTestRef(t, "key-pass-v3")
	uncRev, _ := ports.ParseRevision("rev-key-unc")
	uncOut, _ := ports.NewDurabilityAppliedNotDurable(algebraic.Some(uncRev), "power loss during fsync")
	h.store.InjectNextDurability(uncOut)
	h.ui.SetReplies("", []byte("correct-pass-v3"))
	uncRes, err := h.svc.EnrollEncryptedPrivateKeyIdentity(ctx, ucinv.EnrollEncryptedPrivateKeyRequest{
		IdentityID: id1, User: user, KeyPath: kp, NewRef: v3Ref, ReplaceExisting: true,
	})
	if !errors.Is(err, credential.ErrUncertainDurability) || !uncRes.SagaResult().IsUncertainDurability() {
		t.Fatalf("AppliedNotDurable 应停机 UncertainDurability: err=%v kind=%s", err, uncRes.SagaResult().StateKind())
	}
	if _, hasOld := h.vault.CiphertextFor(v2Ref); !hasOld {
		t.Fatalf("UncertainDurability 绝不可删除旧凭据 %s", v2Ref)
	}
	if _, hasNew := h.vault.CiphertextFor(v3Ref); !hasNew {
		t.Fatalf("UncertainDurability 绝不可删除新凭据 %s", v3Ref)
	}
}

type recordingKeyEnrollUI struct {
	base    ports.InteractionPort
	secrets []ports.SecretPromptRequest
}

func (r *recordingKeyEnrollUI) CanInteract() bool { return r.base.CanInteract() }
func (r *recordingKeyEnrollUI) Confirm(ctx context.Context, req ports.ConfirmRequest) (security.Verdict, error) {
	return r.base.Confirm(ctx, req)
}
func (r *recordingKeyEnrollUI) PromptApproval(ctx context.Context, env security.ApprovalEnvelope) (ports.ApprovalDecisionResponse, error) {
	return r.base.PromptApproval(ctx, env)
}
func (r *recordingKeyEnrollUI) PromptText(ctx context.Context, req ports.TextPromptRequest) (string, error) {
	return r.base.PromptText(ctx, req)
}

//xops:syncclosure
//xops:borrowed
func (r *recordingKeyEnrollUI) PromptSecret(ctx context.Context, req ports.SecretPromptRequest, fn func(box *secret.SecretBox) error) error {
	r.secrets = append(r.secrets, req)
	return r.base.PromptSecret(ctx, req, func(box *secret.SecretBox) error { return fn(box) })
}

func TestEnrollEncryptedPrivateKey_DefaultStructuredPromptMessage(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	h := newInvHarness(t, nil)
	h.ui.SetReplies("", []byte("key-pass-struct"))
	recUI := &recordingKeyEnrollUI{base: h.ui}
	svc, err := ucinv.NewService(ucinv.ServiceConfig{
		Env: mustLocalEnv(t, nil), Store: h.store, Gate: h.gate, Vault: h.vault,
		VaultControl: h.vault, KeySigner: h.signer, Interaction: recUI, Clock: h.clock, Entropy: h.rng.Fork(),
		KnownStores: []string{testStoreName},
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	kp, _ := inventory.ParseKeyPathSpec("~/.ssh/struct_ed25519")
	user, _ := option.ParseUsername("deploy")
	id, _ := inventory.ParseIdentityID("id-struct-key")
	fp := mustTestFP(t, 88)
	h.signer.Register(kp.String(), "key-pass-struct", fp)
	ref := mustTestRef(t, "key-struct-ref")
	res, err := svc.EnrollEncryptedPrivateKeyIdentity(ctx, ucinv.EnrollEncryptedPrivateKeyRequest{
		IdentityID: id, User: user, KeyPath: kp, NewRef: ref,
	})
	if err != nil || !res.IsValid() || len(recUI.secrets) != 1 {
		t.Fatalf("默认加密私钥登记提示采集异常: res=%+v err=%v count=%d", res, err, len(recUI.secrets))
	}
	got := recUI.secrets[0]
	wantT := domi18n.NewMessage(domi18n.KeyInteractKeyPassphraseTitle)
	wantB := domi18n.NewMessage(domi18n.KeyInteractKeyPassphraseBody)
	gotT, okT := got.TitleMessage().Get()
	gotB, okB := got.BodyMessage().Get()
	if got.Title() != wantT.Canonical() || got.Prompt() != wantB.Canonical() ||
		!okT || !gotT.Equal(wantT) || !okB || !gotB.Equal(wantB) {
		t.Fatalf("默认私钥口令提示缺少匹配的结构化消息: title=%q prompt=%q", got.Title(), got.Prompt())
	}
}
