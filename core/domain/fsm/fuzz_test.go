package fsm

import (
	"bytes"
	"crypto/sha256"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
)

func FuzzTransferJournalJSON(f *testing.F) {
	dest, _ := pathalg.ParseRemotePath("/var/tmp/f.bin")
	rec, _ := NewTransferJournalRecord(TransferJournalRecordSpec{
		Version: JournalVersionV2, Generation: 1, Seq: 1, Kind: JournalRecordInit,
		TransferID: testOpID(60), Dest: algebraic.Some(dest), TotalBytes: 1024, Digest: algebraic.Some(testDigest("f")),
	})
	seed, _ := jsonv2.Marshal(rec, jsonv2.Deterministic(true))
	f.Add(seed)
	f.Add([]byte(`null`))
	f.Add([]byte(`{}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		verifyFuzzTransferJournal(t, data)
	})
}

func verifyFuzzTransferJournal(t *testing.T, data []byte) {
	t.Helper()
	var streamed TransferJournalRecord
	if err := streamed.UnmarshalJSONFrom(jsontext.NewDecoder(bytes.NewReader(data))); err != nil && streamed.IsValid() {
		t.Fatalf("UnmarshalJSONFrom 失败后 TransferJournalRecord 必须保持零值无效")
	}
	var dst TransferJournalRecord
	if err := jsonv2.Unmarshal(data, &dst); err != nil {
		return
	}
	if !dst.IsValid() || dst.TotalBytes() > MaxTransferBytes {
		t.Fatalf("解码成功的 Journal 记录违反不变量")
	}
	raw, err := jsonv2.Marshal(dst, jsonv2.Deterministic(true))
	if err != nil {
		t.Fatalf("有效 Journal 编码失败: %v", err)
	}
	var rt TransferJournalRecord
	if err := jsonv2.Unmarshal(raw, &rt); err != nil || !dst.Equal(rt) {
		t.Fatalf("Journal JSON 往返不一致: err=%v", err)
	}
}

func FuzzRecoverTransferFromJournal(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4, 5, 6}, uint64(1024), uint8(1))
	f.Add([]byte{1, 2, 4, 5}, MaxTransferBytes, uint8(2))
	f.Add([]byte{1, 5, 6}, uint64(0), uint8(2))

	f.Fuzz(func(t *testing.T, ops []byte, total uint64, verRaw uint8) {
		runFuzzRecoverTransfer(t, ops, total%(MaxTransferBytes+1), pickIf(verRaw%2 == 0, JournalVersionV1, JournalVersionV2))
	})
}

func runFuzzRecoverTransfer(t *testing.T, ops []byte, total uint64, ver JournalVersion) {
	t.Helper()
	dest, _ := pathalg.ParseRemotePath("/tmp/fuzz.bin")
	dig := security.DigestFromSHA256(sha256.Sum256(ops))
	initRec, err := NewTransferJournalRecord(TransferJournalRecordSpec{
		Version: ver, Generation: 1, Seq: 1, Kind: JournalRecordInit,
		TransferID: testOpID(61), Dest: algebraic.Some(dest), TotalBytes: total, Digest: algebraic.Some(dig),
	})
	if err != nil {
		return
	}
	recs := []TransferJournalRecord{initRec}
	var off uint64
	for i, b := range ops {
		if i >= 16 {
			break
		}
		prev := pickIf(ver == JournalVersionV2, algebraic.Some(recs[len(recs)-1].RecordDigest()), algebraic.None[security.Digest]())
		spec, nextOff := buildFuzzJournalSpec(ver, uint64(len(recs)+1), b, off, total, dig, prev)
		off = nextOff
		if r, err := NewTransferJournalRecord(spec); err == nil {
			recs = append(recs, r)
		}
	}
	st, effs, _, _ := RecoverTransferFromJournal(recs)
	if st != nil && st.Kind() == TransferKindUncertainCommit && len(effs) != 0 {
		t.Fatalf("UncertainCommit 严禁产出重试或清理副作用: %v", effs)
	}
}

func buildFuzzJournalSpec(ver JournalVersion, seq uint64, b byte, off, total uint64, dig security.Digest, prev algebraic.Option[security.Digest]) (TransferJournalRecordSpec, uint64) {
	noDest := algebraic.None[pathalg.RemotePath]()
	noDig := algebraic.None[security.Digest]()
	switch b % 5 {
	case 0:
		chunkLen := uint64(b%64) + 1
		if off < total && chunkLen > total-off {
			chunkLen = total - off
		}
		return TransferJournalRecordSpec{ver, 1, seq, JournalRecordChunk, testOpID(61), noDest, off, chunkLen, total, algebraic.Some(dig), prev}, off + chunkLen
	case 1:
		return TransferJournalRecordSpec{ver, 1, seq, JournalRecordVerified, testOpID(61), noDest, 0, 0, total, algebraic.Some(dig), prev}, off
	case 2:
		return TransferJournalRecordSpec{ver, 1, seq, JournalRecordCommitStarted, testOpID(61), noDest, 0, 0, total, noDig, prev}, off
	case 3:
		return TransferJournalRecordSpec{ver, 1, seq, JournalRecordCommitted, testOpID(61), noDest, 0, 0, total, noDig, prev}, off
	default:
		return TransferJournalRecordSpec{ver, 1, seq, JournalRecordAborted, testOpID(61), noDest, 0, 0, total, noDig, prev}, off
	}
}

func FuzzVaultSagaTransitions(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5})
	f.Add([]byte{0, 1, 2, 9, 5})
	f.Add([]byte{0, 1, 8, 6})

	f.Fuzz(func(t *testing.T, script []byte) {
		runFuzzVaultSaga(t, script)
	})
}

func runFuzzVaultSaga(t *testing.T, script []byte) {
	t.Helper()
	newRef, _ := secret.NewRef("vault", "fuzz-new")
	oldRef, _ := secret.NewRef("vault", "fuzz-old")
	dig := testDigest("fuzz-secret")
	ctx, err := NewVaultSagaContext(VaultSagaContextSpec{
		SagaID: testOpID(62), NewRef: newRef, OldRef: algebraic.Some(oldRef), ExpectedCASVersion: 1, ExpectedDigest: dig,
	})
	if err != nil {
		t.Fatalf("NewVaultSagaContext 失败: %v", err)
	}
	var st VaultSagaState
	st, _ = NewVaultSagaState(ctx)
	for _, op := range script {
		next, effs, _, err := TransitionVaultSaga(st, fuzzVaultInput(op, dig))
		if err != nil {
			if next != st || len(effs) != 0 {
				t.Fatalf("非法转移不得改变原状态或产生副作用")
			}
			continue
		}
		if (next.Kind() == VaultSagaKindUncertainDurability || next.Kind() == VaultSagaKindFailedUncertain) && len(effs) != 0 {
			t.Fatalf("不确定停机态 %s 严禁产生任何副作用: %v", next.Kind(), effs)
		}
		st = next
	}
}

func fuzzVaultInput(op byte, dig security.Digest) VaultSagaInput {
	switch op % 11 {
	case 0:
		return VaultInputStart()
	case 1:
		in, _ := VaultInputWriteNewResult(SideEffectSucceeded, "ok")
		return in
	case 2:
		in, _ := VaultInputReadbackResult(true, dig, "ok")
		return in
	case 3:
		in, _ := VaultInputCommitCASResult(DurabilityCommitted, "ok")
		return in
	case 4:
		in, _ := VaultInputOldRefsResult(true, 0, "ok")
		return in
	case 5:
		in, _ := VaultInputDeleteOldResult(SideEffectSucceeded, "ok")
		return in
	case 6:
		in, _ := VaultInputCompensateResult(SideEffectSucceeded, "ok")
		return in
	case 7:
		in, _ := VaultInputWriteNewResult(SideEffectOutcomeUnknown, "unk")
		return in
	case 8:
		in, _ := VaultInputReadbackResult(false, zeroVal[security.Digest](), "mismatch")
		return in
	case 9:
		in, _ := VaultInputCommitCASResult(DurabilityAppliedNotDurable, "fsync")
		return in
	default:
		in, _ := VaultInputCommitCASResult(DurabilityNotApplied, "cas")
		return in
	}
}

func FuzzEnsureTransitions(f *testing.F) {
	f.Add([]byte{0, 1, 2, 1}, uint8(2))
	f.Add([]byte{0, 3, 3, 3, 4}, uint8(3))
	f.Add([]byte{0, 4, 3}, MaxEnsureRetries)

	f.Fuzz(func(t *testing.T, script []byte, maxRetries uint8) {
		runFuzzEnsure(t, script, maxRetries%(MaxEnsureRetries+1))
	})
}

func runFuzzEnsure(t *testing.T, script []byte, maxRetries uint8) {
	t.Helper()
	ctx, err := NewEnsureContext(testOpID(63), "fuzz-ensure", maxRetries)
	if err != nil {
		t.Fatalf("NewEnsureContext 失败: %v", err)
	}
	st, _ := NewEnsureState(ctx)
	for _, op := range script {
		next, effs, _, err := TransitionEnsure(st, fuzzEnsureInput(op))
		if err != nil {
			if next.Phase() != st.Phase() || len(effs) != 0 {
				t.Fatalf("Ensure 非法转移不得破坏原状态或产生副作用")
			}
			continue
		}
		if next.Phase() == EnsurePhaseUncertainOutcome && len(effs) != 0 {
			t.Fatalf("Ensure 遇 OutcomeUnknown 严禁产生任何重试副作用: %v", effs)
		}
		st = next
	}
}

func fuzzEnsureInput(op byte) EnsureInput {
	switch op % 5 {
	case 0:
		return EnsureInputStart()
	case 1:
		out, _ := execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
		in, _ := EnsureInputOutcome(out)
		return in
	case 2:
		out, _ := execution.NewOutcomeCompleted(execution.NewExitCode(1), false)
		in, _ := EnsureInputOutcome(out)
		return in
	case 3:
		out, _ := execution.NewOutcomeNotStarted(execution.StartPhaseDial, "E_DIAL", "dial")
		in, _ := EnsureInputOutcome(out)
		return in
	default:
		out, _ := execution.NewOutcomeUnknown(execution.ExecPhaseRunning, "E_LOST", "lost")
		in, _ := EnsureInputOutcome(out)
		return in
	}
}
