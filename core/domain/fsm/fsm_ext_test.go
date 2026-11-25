package fsm_test

import (
	"crypto/sha256"
	"encoding"
	jsonv2 "encoding/json/v2"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
)

// TestExternalInterfaceContracts 在外部测试包编译期锁定 fsm 包导出编解码与封闭和类型接口契约。
func TestExternalInterfaceContracts(t *testing.T) {
	var (
		dur fsm.DurabilityStatus
		seo fsm.SideEffectOutcome
		vsk fsm.VaultSagaStateKind
		vek fsm.VaultSagaEffectKind
		vev fsm.VaultSagaEventKind
		aph fsm.ApprovalPhase
		aef fsm.ApprovalEffectKind
		aev fsm.ApprovalEventKind
		tdr fsm.TransferDirection
		ver fsm.JournalVersion
		rk  fsm.JournalRecordKind
		tsk fsm.TransferStateKind
		tef fsm.TransferEffectKind
		tev fsm.TransferEventKind
		eph fsm.EnsurePhase
		eef fsm.EnsureEffectKind
		eev fsm.EnsureEventKind
		pph fsm.PendingEnrollPhase
		pef fsm.PendingEnrollEffectKind
		pev fsm.PendingEnrollEventKind
		dst fsm.TransferDest
		rec fsm.TransferJournalRecord
		vEv fsm.VaultSagaEvent
		aEv fsm.ApprovalEvent
		pEv fsm.PendingEnrollEvent
		tEv fsm.TransferEvent
		eEv fsm.EnsureEvent
	)
	var (
		_ encoding.TextAppender    = dur
		_ encoding.TextMarshaler   = dur
		_ encoding.TextUnmarshaler = &dur
		_ encoding.TextAppender    = seo
		_ encoding.TextMarshaler   = seo
		_ encoding.TextUnmarshaler = &seo
		_ encoding.TextAppender    = vsk
		_ encoding.TextMarshaler   = vsk
		_ encoding.TextUnmarshaler = &vsk
		_ encoding.TextAppender    = vek
		_ encoding.TextMarshaler   = vek
		_ encoding.TextUnmarshaler = &vek
		_ encoding.TextAppender    = vev
		_ encoding.TextMarshaler   = vev
		_ encoding.TextUnmarshaler = &vev
		_ encoding.TextAppender    = aph
		_ encoding.TextMarshaler   = aph
		_ encoding.TextUnmarshaler = &aph
		_ encoding.TextAppender    = aef
		_ encoding.TextMarshaler   = aef
		_ encoding.TextUnmarshaler = &aef
		_ encoding.TextAppender    = aev
		_ encoding.TextMarshaler   = aev
		_ encoding.TextUnmarshaler = &aev
		_ encoding.TextAppender    = tdr
		_ encoding.TextMarshaler   = tdr
		_ encoding.TextUnmarshaler = &tdr
		_ encoding.TextAppender    = ver
		_ encoding.TextMarshaler   = ver
		_ encoding.TextUnmarshaler = &ver
		_ encoding.TextAppender    = rk
		_ encoding.TextMarshaler   = rk
		_ encoding.TextUnmarshaler = &rk
		_ encoding.TextAppender    = tsk
		_ encoding.TextMarshaler   = tsk
		_ encoding.TextUnmarshaler = &tsk
		_ encoding.TextAppender    = tef
		_ encoding.TextMarshaler   = tef
		_ encoding.TextUnmarshaler = &tef
		_ encoding.TextAppender    = tev
		_ encoding.TextMarshaler   = tev
		_ encoding.TextUnmarshaler = &tev
		_ encoding.TextAppender    = eph
		_ encoding.TextMarshaler   = eph
		_ encoding.TextUnmarshaler = &eph
		_ encoding.TextAppender    = eef
		_ encoding.TextMarshaler   = eef
		_ encoding.TextUnmarshaler = &eef
		_ encoding.TextAppender    = eev
		_ encoding.TextMarshaler   = eev
		_ encoding.TextUnmarshaler = &eev
		_ encoding.TextAppender    = pph
		_ encoding.TextMarshaler   = pph
		_ encoding.TextUnmarshaler = &pph
		_ encoding.TextAppender    = pef
		_ encoding.TextMarshaler   = pef
		_ encoding.TextUnmarshaler = &pef
		_ encoding.TextAppender    = pev
		_ encoding.TextMarshaler   = pev
		_ encoding.TextUnmarshaler = &pev
		_ jsonv2.MarshalerTo       = dst
		_ jsonv2.UnmarshalerFrom   = &dst
		_ jsonv2.MarshalerTo       = rec
		_ jsonv2.UnmarshalerFrom   = &rec
		_ jsonv2.MarshalerTo       = vEv
		_ jsonv2.UnmarshalerFrom   = &vEv
		_ jsonv2.MarshalerTo       = aEv
		_ jsonv2.UnmarshalerFrom   = &aEv
		_ jsonv2.MarshalerTo       = pEv
		_ jsonv2.UnmarshalerFrom   = &pEv
		_ jsonv2.MarshalerTo       = tEv
		_ jsonv2.UnmarshalerFrom   = &tEv
		_ jsonv2.MarshalerTo       = eEv
		_ jsonv2.UnmarshalerFrom   = &eEv

		_ fsm.VaultSagaState = (*fsm.VaultSagaInit)(nil)
		_ fsm.VaultSagaState = (*fsm.VaultSagaWritingNew)(nil)
		_ fsm.VaultSagaState = (*fsm.VaultSagaVerifyingReadback)(nil)
		_ fsm.VaultSagaState = (*fsm.VaultSagaCommittingConfig)(nil)
		_ fsm.VaultSagaState = (*fsm.VaultSagaCheckingOldRefs)(nil)
		_ fsm.VaultSagaState = (*fsm.VaultSagaDeletingOld)(nil)
		_ fsm.VaultSagaState = (*fsm.VaultSagaCompensating)(nil)
		_ fsm.VaultSagaState = (*fsm.VaultSagaCompleted)(nil)
		_ fsm.VaultSagaState = (*fsm.VaultSagaRolledBack)(nil)
		_ fsm.VaultSagaState = (*fsm.VaultSagaUncertainDurability)(nil)
		_ fsm.VaultSagaState = (*fsm.VaultSagaFailedUncertain)(nil)

		_ fsm.TransferState = (*fsm.TransferInitialized)(nil)
		_ fsm.TransferState = (*fsm.TransferStreaming)(nil)
		_ fsm.TransferState = (*fsm.TransferVerifying)(nil)
		_ fsm.TransferState = (*fsm.TransferCommitting)(nil)
		_ fsm.TransferState = (*fsm.TransferCommitted)(nil)
		_ fsm.TransferState = (*fsm.TransferAborted)(nil)
		_ fsm.TransferState = (*fsm.TransferUncertainCommit)(nil)
	)
}

func classifyVaultState(state fsm.VaultSagaState) string {
	switch s := state.(type) {
	case *fsm.VaultSagaInit:
		return s.Kind().String()
	case *fsm.VaultSagaWritingNew:
		return s.Kind().String()
	case *fsm.VaultSagaVerifyingReadback:
		return s.Kind().String()
	case *fsm.VaultSagaCommittingConfig:
		return s.Kind().String()
	case *fsm.VaultSagaCheckingOldRefs:
		return s.Kind().String()
	case *fsm.VaultSagaDeletingOld:
		return s.Kind().String()
	case *fsm.VaultSagaCompensating:
		return s.Kind().String() + ":" + s.Reason()
	case *fsm.VaultSagaCompleted:
		return s.Kind().String()
	case *fsm.VaultSagaRolledBack:
		return s.Kind().String()
	case *fsm.VaultSagaUncertainDurability:
		return "halt:" + s.Reason()
	case *fsm.VaultSagaFailedUncertain:
		return "uncertain:" + s.Step().String()
	default:
		return "invalid"
	}
}

func classifyTransferState(state fsm.TransferState) string {
	switch s := state.(type) {
	case *fsm.TransferInitialized:
		return s.Kind().String()
	case *fsm.TransferStreaming:
		return s.Kind().String()
	case *fsm.TransferVerifying:
		return s.Kind().String()
	case *fsm.TransferCommitting:
		return s.Kind().String()
	case *fsm.TransferCommitted:
		return s.Kind().String()
	case *fsm.TransferAborted:
		return "aborted:" + s.Reason()
	case *fsm.TransferUncertainCommit:
		return "uncertain:" + s.Reason()
	default:
		return "invalid"
	}
}

func TestExternalSealedADTsAndEndToEndFlow(t *testing.T) {
	var rawID [16]byte
	rawID[0] = 0x55
	opID := security.OperationIDFromBytes(rawID)
	dig := security.DigestFromSHA256(sha256.Sum256([]byte("ext-fsm")))
	newRef, err := secret.NewRef("vault", "k-new")
	if err != nil {
		t.Fatalf("secret.NewRef 失败: %v", err)
	}
	vCtx, err := fsm.NewVaultSagaContext(fsm.VaultSagaContextSpec{
		SagaID: opID, NewRef: newRef, ExpectedCASVersion: 1,
	})
	if err != nil {
		t.Fatalf("NewVaultSagaContext 失败: %v", err)
	}
	vInit, err := fsm.NewVaultSagaState(vCtx)
	if err != nil {
		t.Fatalf("NewVaultSagaState 失败: %v", err)
	}
	if got := classifyVaultState(vInit); got != "init" {
		t.Fatalf("VaultSagaState 穷尽分类异常: %q", got)
	}
	_, _, vEvs, err := fsm.TransitionVaultSaga(vInit, fsm.VaultInputStart())
	if err != nil || len(vEvs) != 1 {
		t.Fatalf("VaultSaga 启动失败: err=%v evs=%v", err, vEvs)
	}
	assertExternalVaultEventJSON(t, vEvs[0])

	destPath, _ := pathalg.ParseRemotePath("/tmp/ext.bin")
	dest, err := fsm.NewUploadDest(destPath)
	if err != nil {
		t.Fatalf("NewUploadDest 失败: %v", err)
	}
	meta, err := fsm.NewTransferMeta(fsm.TransferMetaSpec{
		TransferID: opID, Dest: dest, TotalBytes: 0, ExpectedDigest: algebraic.Some(dig), JournalVersion: fsm.JournalVersionV2, Generation: 1,
	})
	if err != nil {
		t.Fatalf("NewTransferMeta 失败: %v", err)
	}
	tInit, err := fsm.NewTransferState(meta)
	if err != nil {
		t.Fatalf("NewTransferState 失败: %v", err)
	}
	tNext, effs, tEvs, err := fsm.TransitionTransfer(tInit, fsm.TransferInputStart())
	if err != nil || classifyTransferState(tNext) != "verifying" || len(effs) != 2 || len(tEvs) != 1 {
		t.Fatalf("外部包 TransferFSM 启动异常: st=%v effs=%d err=%v", tNext, len(effs), err)
	}
	assertExternalTransferEnsureAndEnumJSON(t, opID, tEvs[0])
	_ = algebraic.None[secret.Ref]()
}

func assertExternalVaultEventJSON(t *testing.T, ev fsm.VaultSagaEvent) {
	t.Helper()
	rawVEv, err := jsonv2.Marshal(ev, jsonv2.Deterministic(true))
	if err != nil {
		t.Fatalf("Marshal VaultSagaEvent 失败: %v", err)
	}
	var rtVEv fsm.VaultSagaEvent
	if err := jsonv2.Unmarshal(rawVEv, &rtVEv); err != nil || !rtVEv.Equal(ev) {
		t.Fatalf("VaultSagaEvent JSON 往返失败: raw=%s err=%v", rawVEv, err)
	}
	for _, bad := range []string{`null`, `{}`, `{"kind":"started","extra":1}`, `{"kind":"started","detail":"bad\u0000"}`} {
		var tmp fsm.VaultSagaEvent
		if err := jsonv2.Unmarshal([]byte(bad), &tmp); err == nil || tmp.IsValid() {
			t.Fatalf("恶意 VaultSagaEvent JSON %s 必须拒绝", bad)
		}
	}
}

func assertExternalTransferEnsureAndEnumJSON(t *testing.T, opID security.OperationID, tEv fsm.TransferEvent) {
	t.Helper()
	rawTEv, err := jsonv2.Marshal(tEv, jsonv2.Deterministic(true))
	var rtTEv fsm.TransferEvent
	if err != nil || jsonv2.Unmarshal(rawTEv, &rtTEv) != nil || !rtTEv.Equal(tEv) {
		t.Fatalf("TransferEvent JSON 往返失败: raw=%s err=%v", rawTEv, err)
	}
	eCtx, _ := fsm.NewEnsureContext(opID, "ext-ensure", 1)
	eInit, _ := fsm.NewEnsureState(eCtx)
	_, _, eEvs, err := fsm.TransitionEnsure(eInit, fsm.EnsureInputStart())
	if err != nil || len(eEvs) != 1 {
		t.Fatalf("TransitionEnsure 启动失败: err=%v", err)
	}
	rawEEv, err := jsonv2.Marshal(eEvs[0], jsonv2.Deterministic(true))
	var rtEEv fsm.EnsureEvent
	if err != nil || jsonv2.Unmarshal(rawEEv, &rtEEv) != nil || !rtEEv.Equal(eEvs[0]) {
		t.Fatalf("EnsureEvent JSON 往返失败: raw=%s err=%v", rawEEv, err)
	}
	rawDur, err := jsonv2.Marshal(fsm.DurabilityAppliedNotDurable, jsonv2.Deterministic(true))
	var rtDur fsm.DurabilityStatus
	if err != nil || jsonv2.Unmarshal(rawDur, &rtDur) != nil || rtDur != fsm.DurabilityAppliedNotDurable {
		t.Fatalf("DurabilityStatus JSON 往返失败: raw=%s err=%v rt=%v", rawDur, err, rtDur)
	}
	rawSEO, err := jsonv2.Marshal(fsm.SideEffectOutcomeUnknown, jsonv2.Deterministic(true))
	var rtSEO fsm.SideEffectOutcome
	if err != nil || jsonv2.Unmarshal(rawSEO, &rtSEO) != nil || rtSEO != fsm.SideEffectOutcomeUnknown {
		t.Fatalf("SideEffectOutcome JSON 往返失败: raw=%s err=%v rt=%v", rawSEO, err, rtSEO)
	}
}
