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
		ver fsm.JournalVersion
		rk  fsm.JournalRecordKind
		rec fsm.TransferJournalRecord
	)
	var (
		_ encoding.TextAppender    = ver
		_ encoding.TextMarshaler   = ver
		_ encoding.TextUnmarshaler = &ver
		_ encoding.TextAppender    = rk
		_ encoding.TextMarshaler   = rk
		_ encoding.TextUnmarshaler = &rk
		_ jsonv2.MarshalerTo       = rec
		_ jsonv2.UnmarshalerFrom   = &rec

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
		SagaID: opID, NewRef: newRef, ExpectedCASVersion: 1, ExpectedDigest: dig,
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

	dest, _ := pathalg.ParseRemotePath("/tmp/ext.bin")
	meta, err := fsm.NewTransferMeta(fsm.TransferMetaSpec{
		TransferID: opID, Dest: dest, TotalBytes: 0, ExpectedDigest: dig, JournalVersion: fsm.JournalVersionV2, Generation: 1,
	})
	if err != nil {
		t.Fatalf("NewTransferMeta 失败: %v", err)
	}
	tInit, err := fsm.NewTransferState(meta)
	if err != nil {
		t.Fatalf("NewTransferState 失败: %v", err)
	}
	tNext, effs, _, err := fsm.TransitionTransfer(tInit, fsm.TransferInputStart())
	if err != nil || classifyTransferState(tNext) != "verifying" || len(effs) != 2 {
		t.Fatalf("外部包 TransferFSM 启动异常: st=%v effs=%d err=%v", tNext, len(effs), err)
	}
	_ = algebraic.None[secret.Ref]()
}
