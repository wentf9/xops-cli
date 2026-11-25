package fsm

import (
	"crypto/sha256"
	jsonv2 "encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
)

func testOpID(b byte) security.OperationID {
	var raw [16]byte
	raw[0], raw[15] = b, 0xA5
	return security.OperationIDFromBytes(raw)
}

func testDigest(tag string) security.Digest {
	return security.DigestFromSHA256(sha256.Sum256([]byte(tag)))
}

func mustSecretRef(t *testing.T, store, item string) secret.Ref {
	t.Helper()
	ref, err := secret.NewRef(store, item)
	if err != nil {
		t.Fatalf("secret.NewRef(%q, %q) 失败: %v", store, item, err)
	}
	return ref
}

func mustVaultCtx(t *testing.T, withOld bool) VaultSagaContext {
	t.Helper()
	var old algebraic.Option[secret.Ref]
	if withOld {
		old = algebraic.Some(mustSecretRef(t, "vault", "old-key"))
	}
	ctx, err := NewVaultSagaContext(VaultSagaContextSpec{
		SagaID:             testOpID(1),
		NewRef:             mustSecretRef(t, "vault", "new-key"),
		OldRef:             old,
		ExpectedCASVersion: 7,
		ExpectedDigest:     testDigest("expected-secret"),
	})
	if err != nil {
		t.Fatalf("NewVaultSagaContext 失败: %v", err)
	}
	return ctx
}

func TestClassifyDurabilityAndContextValidation(t *testing.T) {
	if ClassifyDurability(true, true, true) != DurabilityCommitted {
		t.Fatalf("applied && durable 应映射为 DurabilityCommitted")
	}
	if d := ClassifyDurability(true, false, true); d != DurabilityAppliedNotDurable || !d.Applied() || d.Durable() {
		t.Fatalf("applied && !durable 应映射为 DurabilityAppliedNotDurable: %v", d)
	}
	if ClassifyDurability(false, false, true) != DurabilityNotApplied {
		t.Fatalf("!applied && !durable 应映射为 DurabilityNotApplied")
	}
	if ClassifyDurability(true, false, false) != DurabilityOutcomeUnknown {
		t.Fatalf("!outcomeKnown 应映射为 DurabilityOutcomeUnknown")
	}
	// 矛盾组合 (!applied && durable) 必须失败关闭返回 DurabilityUnknown
	if d := ClassifyDurability(false, true, true); d != DurabilityUnknown || d.IsValid() {
		t.Fatalf("矛盾组合 (!applied && durable) 必须失败关闭，实际 %v", d)
	}

	// NewRef == OldRef 必须拒绝
	ref := mustSecretRef(t, "vault", "same")
	if _, err := NewVaultSagaContext(VaultSagaContextSpec{
		SagaID: testOpID(2), NewRef: ref, OldRef: algebraic.Some(ref), ExpectedDigest: testDigest("x"),
	}); !errors.Is(err, ErrInvalidContext) {
		t.Fatalf("old_ref == new_ref 必须返回 ErrInvalidContext，实际 %v", err)
	}
}

func TestVaultSagaTerminalFailClosedAndUTF8ReasonTruncation(t *testing.T) {
	var (
		nilInit *VaultSagaInit
		nilDone *VaultSagaCompleted
		nilRB   *VaultSagaRolledBack
		nilUnc  *VaultSagaUncertainDurability
		nilFail *VaultSagaFailedUncertain
	)
	if nilInit.IsValid() || nilInit.Kind() != VaultSagaKindInvalid || VaultSagaContextOf(nilInit).IsValid() || VaultSagaContextOf(nil).IsValid() {
		t.Fatalf("typed-nil *VaultSagaInit 应失败关闭")
	}
	if nilUnc.Reason() != "" || nilFail.Step() != VaultSagaKindInvalid || nilFail.Reason() != "" {
		t.Fatalf("typed-nil 终态变体应安全返回零值")
	}
	for _, st := range []VaultSagaState{nilDone, nilRB, nilUnc, nilFail, &VaultSagaCompleted{}, &VaultSagaRolledBack{}, &VaultSagaUncertainDurability{}, &VaultSagaFailedUncertain{}} {
		if st.IsTerminal() || st.IsValid() {
			t.Fatalf("零值或 typed-nil 终态 %T 的 IsTerminal/IsValid 必须返回 false", st)
		}
	}
	// 多字节 CJK 与 4 字节 Emoji 截断必须严格落在 UTF-8 符文边界并可被 json/v2 编码
	for _, raw := range []string{strings.Repeat("汉", 300), "a" + strings.Repeat("🚀", 200)} {
		clean := sanitizeReason(raw)
		if !utf8.ValidString(clean) || len(clean) > maxReasonBytes || len(clean) == 0 {
			t.Fatalf("sanitizeReason 破坏了 UTF-8 完整性或越界: len=%d valid=%v", len(clean), utf8.ValidString(clean))
		}
		if _, err := jsonv2.Marshal(clean); err != nil {
			t.Fatalf("截断后的诊断文本无法通过 json/v2 UTF-8 编码: %v", err)
		}
	}
}

func assertVaultStep(t *testing.T, next VaultSagaState, effs []VaultSagaEffect, evs []VaultSagaEvent, err error, wantSt VaultSagaStateKind, wantEff VaultSagaEffectKind) {
	t.Helper()
	if err != nil || next.Kind() != wantSt || len(evs) == 0 {
		t.Fatalf("got=(%v, %v) want=%v", next, err, wantSt)
	}
	if wantEff == VaultEffectInvalid && len(effs) != 0 {
		t.Fatalf("终态 %s 不应产生副作用: %v", wantSt, effs)
	}
	if wantEff != VaultEffectInvalid && (len(effs) != 1 || effs[0].Kind() != wantEff) {
		t.Fatalf("期望副作用 %v，实际 %v", wantEff, effs)
	}
}

func TestVaultSagaHappyPathAndRefRetention(t *testing.T) {
	ctx := mustVaultCtx(t, true)
	okIn := mustVaultIn(t)
	st, err := NewVaultSagaState(ctx)
	if err != nil {
		t.Fatalf("NewVaultSagaState 失败: %v", err)
	}
	var cur VaultSagaState = st
	steps := []struct {
		in      VaultSagaInput
		wantSt  VaultSagaStateKind
		wantEff VaultSagaEffectKind
	}{
		{VaultInputStart(), VaultSagaKindWritingNew, VaultEffectWriteNew},
		{okIn(VaultInputWriteNewResult(SideEffectSucceeded, "")), VaultSagaKindVerifyingReadback, VaultEffectVerifyReadback},
		{okIn(VaultInputReadbackResult(true, ctx.ExpectedDigest(), "")), VaultSagaKindCommittingConfig, VaultEffectCommitConfigCAS},
		{okIn(VaultInputCommitCASResult(DurabilityCommitted, "")), VaultSagaKindCheckingOldRefs, VaultEffectCheckOldRefs},
		{okIn(VaultInputOldRefsResult(true, 0, "")), VaultSagaKindDeletingOld, VaultEffectDeleteOld},
		{okIn(VaultInputDeleteOldResult(SideEffectSucceeded, "")), VaultSagaKindCompleted, VaultEffectInvalid},
	}
	for _, tc := range steps {
		next, effs, evs, err := TransitionVaultSaga(cur, tc.in)
		assertVaultStep(t, next, effs, evs, err, tc.wantSt, tc.wantEff)
		cur = next
	}
	done, ok := cur.(*VaultSagaCompleted)
	if !ok || !done.OldDeleted() || !done.IsTerminal() {
		t.Fatalf("期望 Completed(oldDeleted=true)，实际 %#v", cur)
	}

	// 旧凭据仍有引用（refCount > 0）时禁止删除旧凭据，直接 Completed(oldDeleted=false)
	chk := &VaultSagaCheckingOldRefs{sealedVaultMixin{ctx, true}}
	next, effs, evs, err := TransitionVaultSaga(chk, okIn(VaultInputOldRefsResult(true, 2, "")))
	assertVaultStep(t, next, effs, evs, err, VaultSagaKindCompleted, VaultEffectInvalid)
	if next.(*VaultSagaCompleted).OldDeleted() {
		t.Fatalf("存在旧引用时 OldDeleted 必须为 false")
	}

	// 无旧凭据时 CAS Committed 直接 Completed
	commNoOld := &VaultSagaCommittingConfig{sealedVaultMixin{mustVaultCtx(t, false), true}}
	next, effs, evs, err = TransitionVaultSaga(commNoOld, okIn(VaultInputCommitCASResult(DurabilityCommitted, "")))
	assertVaultStep(t, next, effs, evs, err, VaultSagaKindCompleted, VaultEffectInvalid)
}

func TestVaultSagaAppliedNotDurableInvariant(t *testing.T) {
	// 核心安全不变量：Applied && !Durable 停机于 UncertainDurability，严格 ZERO 重试、ZERO 删新/旧凭据！
	ctx := mustVaultCtx(t, true)
	okIn := mustVaultIn(t)
	comm := &VaultSagaCommittingConfig{sealedVaultMixin{ctx, true}}
	inUncertain := okIn(VaultInputCommitCASResult(ClassifyDurability(true, false, true), "fsync failed"))
	next, effs, evs, err := TransitionVaultSaga(comm, inUncertain)
	assertVaultStep(t, next, effs, evs, err, VaultSagaKindUncertainDurability, VaultEffectInvalid)
	if !next.IsTerminal() || len(evs) != 1 || evs[0].Kind() != VaultEventUncertainDurability {
		t.Fatalf("应进入 UncertainDurability 终态并发出对应事件: next=%v evs=%v", next, evs)
	}
}

func TestVaultSagaCompensationAndOutcomeUnknownNoRetry(t *testing.T) {
	ctx := mustVaultCtx(t, true)
	okIn := mustVaultIn(t)
	// Readback 不匹配 -> Compensating(CompensateDeleteNew) -> RolledBack(compensated=true)
	rb := &VaultSagaVerifyingReadback{sealedVaultMixin{ctx, true}}
	next, effs, _, err := TransitionVaultSaga(rb, okIn(VaultInputReadbackResult(true, testDigest("wrong"), "")))
	if err != nil || next.Kind() != VaultSagaKindCompensating || len(effs) != 1 || effs[0].Kind() != VaultEffectCompensateDeleteNew {
		t.Fatalf("回读摘要不匹配应触发补偿删除新凭据: next=%v effs=%v err=%v", next, effs, err)
	}
	next, effs, _, err = TransitionVaultSaga(next, okIn(VaultInputCompensateResult(SideEffectSucceeded, "")))
	if err != nil || next.Kind() != VaultSagaKindRolledBack || len(effs) != 0 || !next.(*VaultSagaRolledBack).Compensated() {
		t.Fatalf("补偿成功应进入 RolledBack(compensated=true): next=%v effs=%v err=%v", next, effs, err)
	}

	// CAS DurabilityNotApplied -> 同样补偿删除新凭据
	comm := &VaultSagaCommittingConfig{sealedVaultMixin{ctx, true}}
	next, effs, _, err = TransitionVaultSaga(comm, okIn(VaultInputCommitCASResult(DurabilityNotApplied, "cas conflict")))
	if err != nil || next.Kind() != VaultSagaKindCompensating || len(effs) != 1 || effs[0].Kind() != VaultEffectCompensateDeleteNew {
		t.Fatalf("CAS 未生效失败应补偿删除新凭据: next=%v effs=%v err=%v", next, effs, err)
	}

	// 任意副作用阶段遇 OutcomeUnknown 必须进入 FailedUncertain 且 0 副作用（严禁盲目重试）
	unknownCases := []struct {
		st VaultSagaState
		in VaultSagaInput
	}{
		{&VaultSagaWritingNew{sealedVaultMixin{ctx, true}}, okIn(VaultInputWriteNewResult(SideEffectOutcomeUnknown, "timeout"))},
		{&VaultSagaCommittingConfig{sealedVaultMixin{ctx, true}}, okIn(VaultInputCommitCASResult(DurabilityOutcomeUnknown, "io_err"))},
		{&VaultSagaCheckingOldRefs{sealedVaultMixin{ctx, true}}, okIn(VaultInputOldRefsResult(false, 0, "scan_err"))},
		{&VaultSagaDeletingOld{sealedVaultMixin{ctx, true}}, okIn(VaultInputDeleteOldResult(SideEffectOutcomeUnknown, "timeout"))},
		{&VaultSagaCompensating{sealedVaultMixin{ctx, true}, "rb"}, okIn(VaultInputCompensateResult(SideEffectOutcomeUnknown, "timeout"))},
	}
	for i, tc := range unknownCases {
		res, effs, _, err := TransitionVaultSaga(tc.st, tc.in)
		if err != nil || res.Kind() != VaultSagaKindFailedUncertain || !res.IsTerminal() || len(effs) != 0 {
			t.Fatalf("unknownCases[%d] 应停机于 FailedUncertain 且 0 副作用: res=%v effs=%v err=%v", i, res, effs, err)
		}
	}
}

func TestVaultSagaInvalidStateAndInput(t *testing.T) {
	ctx := mustVaultCtx(t, true)
	initSt := &VaultSagaInit{sealedVaultMixin{ctx, true}}
	if _, _, _, err := TransitionVaultSaga(nil, VaultInputStart()); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("nil 状态应返回 ErrInvalidState: %v", err)
	}
	if _, _, _, err := TransitionVaultSaga(&VaultSagaInit{}, VaultInputStart()); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("零值状态应返回 ErrInvalidState: %v", err)
	}
	if _, _, _, err := TransitionVaultSaga(initSt, VaultSagaInput{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("零值输入应返回 ErrInvalidInput: %v", err)
	}
}

func TestVaultSagaExhaustiveStateInputMatrix(t *testing.T) {
	ctx := mustVaultCtx(t, true)
	okIn := mustVaultIn(t)
	allStates := []VaultSagaState{
		&VaultSagaInit{sealedVaultMixin{ctx, true}},
		&VaultSagaWritingNew{sealedVaultMixin{ctx, true}},
		&VaultSagaVerifyingReadback{sealedVaultMixin{ctx, true}},
		&VaultSagaCommittingConfig{sealedVaultMixin{ctx, true}},
		&VaultSagaCheckingOldRefs{sealedVaultMixin{ctx, true}},
		&VaultSagaDeletingOld{sealedVaultMixin{ctx, true}},
		&VaultSagaCompensating{sealedVaultMixin{ctx, true}, "err"},
		&VaultSagaCompleted{sealedVaultMixin{ctx, true}, true, "ok"},
		&VaultSagaRolledBack{sealedVaultMixin{ctx, true}, true, "rb"},
		&VaultSagaUncertainDurability{sealedVaultMixin{ctx, true}, "dur"},
		&VaultSagaFailedUncertain{sealedVaultMixin{ctx, true}, VaultSagaKindWritingNew, "unk"},
	}
	allInputs := []VaultSagaInput{
		VaultInputStart(),
		okIn(VaultInputWriteNewResult(SideEffectSucceeded, "")),
		okIn(VaultInputReadbackResult(true, ctx.ExpectedDigest(), "")),
		okIn(VaultInputCommitCASResult(DurabilityCommitted, "")),
		okIn(VaultInputOldRefsResult(true, 0, "")),
		okIn(VaultInputDeleteOldResult(SideEffectSucceeded, "")),
		okIn(VaultInputCompensateResult(SideEffectSucceeded, "")),
	}
	// 11 × 7 穷尽矩阵：仅对角线 i==j && i<7 合法，其余全部 ErrIllegalTransition 且原状态无损
	for i, st := range allStates {
		for j, in := range allInputs {
			next, effs, evs, err := TransitionVaultSaga(st, in)
			wantOK := i < 7 && i == j
			if wantOK && err != nil {
				t.Fatalf("矩阵(%s, %d) 期望合法，实际错误: %v", st.Kind(), j, err)
			}
			if !wantOK && (!errors.Is(err, ErrIllegalTransition) || next != st || len(effs) != 0 || len(evs) != 0) {
				t.Fatalf("矩阵(%s, %d) 应失败关闭且不破坏原状态: next=%v err=%v", st.Kind(), j, next, err)
			}
		}
	}
}

func mustVaultIn(t *testing.T) func(VaultSagaInput, error) VaultSagaInput {
	return func(in VaultSagaInput, err error) VaultSagaInput {
		t.Helper()
		if err != nil {
			t.Fatalf("构造 VaultSagaInput 失败: %v", err)
		}
		return in
	}
}
