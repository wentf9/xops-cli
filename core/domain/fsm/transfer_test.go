package fsm

import (
	"bytes"
	jsonv2 "encoding/json/v2"
	"errors"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
)

func mustTransferMeta(t *testing.T, total uint64, ver JournalVersion, gen uint64) TransferMeta {
	t.Helper()
	dest, err := pathalg.ParseRemotePath("/var/data/archive.tar.zst")
	if err != nil {
		t.Fatalf("ParseRemotePath 失败: %v", err)
	}
	m, err := NewTransferMeta(TransferMetaSpec{
		TransferID:     testOpID(20),
		Dest:           dest,
		TotalBytes:     total,
		ExpectedDigest: testDigest("full-payload"),
		JournalVersion: ver,
		Generation:     gen,
	})
	if err != nil {
		t.Fatalf("NewTransferMeta 失败: %v", err)
	}
	return m
}

func collectJournalEffects(t *testing.T, effs []TransferEffect, out *[]TransferJournalRecord) {
	t.Helper()
	for _, e := range effs {
		if e.Kind() != TransferEffectWriteJournal {
			continue
		}
		rec, ok := e.Record().Get()
		if !ok || !rec.IsValid() {
			t.Fatalf("WriteJournal 副作用必须携带有效记录")
		}
		*out = append(*out, rec)
	}
}

func mustStepTransfer(t *testing.T, st TransferState, in TransferInput, journal *[]TransferJournalRecord) (TransferState, []TransferEffect) {
	t.Helper()
	next, effs, _, err := TransitionTransfer(st, in)
	if err != nil {
		t.Fatalf("TransitionTransfer 失败: %v", err)
	}
	collectJournalEffects(t, effs, journal)
	return next, effs
}

func driveTransferAndCollectJournal(t *testing.T, meta TransferMeta, chunks []uint64, commitDur DurabilityStatus) (TransferState, []TransferJournalRecord, []TransferEffect) {
	t.Helper()
	initSt, err := NewTransferState(meta)
	if err != nil {
		t.Fatalf("NewTransferState 失败: %v", err)
	}
	var st TransferState = initSt
	var journal []TransferJournalRecord
	st, _ = mustStepTransfer(t, st, TransferInputStart(), &journal)
	var offset uint64
	for _, n := range chunks {
		inC, err := TransferInputChunk(offset, n, testDigest("chunk"))
		if err != nil {
			t.Fatalf("TransferInputChunk 失败: %v", err)
		}
		st, _ = mustStepTransfer(t, st, inC, &journal)
		offset += n
	}
	inVer, _ := TransferInputVerifyResult(true, meta.ExpectedDigest(), "")
	st, _ = mustStepTransfer(t, st, inVer, &journal)
	inCom, _ := TransferInputCommitResult(commitDur, "commit_status")
	st, effs := mustStepTransfer(t, st, inCom, &journal)
	return st, journal, effs
}

func TestTransfer10GiBAndZeroByteBoundaries(t *testing.T) {
	dest, _ := pathalg.ParseRemotePath("/data/big.bin")
	if _, err := NewTransferMeta(TransferMetaSpec{
		TransferID: testOpID(21), Dest: dest, TotalBytes: MaxTransferBytes + 1,
		ExpectedDigest: testDigest("over"), JournalVersion: JournalVersionV2, Generation: 1,
	}); !errors.Is(err, ErrTransferSizeExceeded) {
		t.Fatalf("超过 10 GiB 必须返回 ErrTransferSizeExceeded，实际 %v", err)
	}

	// 10 GiB 精确边界（160 个 64 MiB 分片 = 10 GiB）与 V2 哈希链全量流转
	meta10G := mustTransferMeta(t, MaxTransferBytes, JournalVersionV2, 1)
	chunks10G := make([]uint64, MaxTransferBytes/MaxTransferChunkBytes)
	for i := range chunks10G {
		chunks10G[i] = MaxTransferChunkBytes
	}
	st, journalV2, _ := driveTransferAndCollectJournal(t, meta10G, chunks10G, DurabilityCommitted)
	if st.Kind() != TransferKindCommitted || len(journalV2) != len(chunks10G)+4 {
		t.Fatalf("10 GiB 传输终态或 Journal 长度异常: kind=%v len=%d", st.Kind(), len(journalV2))
	}

	// 0 字节文件直接进入 Verifying -> Committing -> Committed
	meta0 := mustTransferMeta(t, 0, JournalVersionV1, 1)
	st0, journalV1, _ := driveTransferAndCollectJournal(t, meta0, nil, DurabilityCommitted)
	if st0.Kind() != TransferKindCommitted || len(journalV1) != 4 {
		t.Fatalf("0 字节传输失败: kind=%v len=%d", st0.Kind(), len(journalV1))
	}
}

func TestTransferJournalJSONRoundTripAndChunkGuards(t *testing.T) {
	_, journalV1, _ := driveTransferAndCollectJournal(t, mustTransferMeta(t, 0, JournalVersionV1, 1), nil, DurabilityCommitted)
	_, journalV2, _ := driveTransferAndCollectJournal(t, mustTransferMeta(t, 512, JournalVersionV2, 1), []uint64{512}, DurabilityCommitted)
	for _, rec := range []TransferJournalRecord{journalV1[0], journalV2[0], journalV2[1], journalV2[len(journalV2)-1]} {
		assertJournalRoundTrip(t, rec)
	}

	// 分片偏移不连续或超出剩余字节数必须拒绝
	initSt, _ := NewTransferState(mustTransferMeta(t, 1024, JournalVersionV2, 1))
	streamSt, _, _, _ := TransitionTransfer(initSt, TransferInputStart())
	badOff, _ := TransferInputChunk(16, 16, testDigest("c"))
	if _, _, _, err := TransitionTransfer(streamSt, badOff); !errors.Is(err, ErrInvalidChunkOffset) {
		t.Fatalf("非连续偏移必须返回 ErrInvalidChunkOffset: %v", err)
	}
	overLen, _ := TransferInputChunk(0, 2048, testDigest("c"))
	if _, _, _, err := TransitionTransfer(streamSt, overLen); !errors.Is(err, ErrTransferSizeExceeded) {
		t.Fatalf("超长分片必须返回 ErrTransferSizeExceeded: %v", err)
	}

	// Applied && !Durable / OutcomeUnknown 停机于 TransferUncertainCommit 且严格 0 副作用
	for _, dur := range []DurabilityStatus{DurabilityAppliedNotDurable, DurabilityOutcomeUnknown} {
		endSt, _, effs := driveTransferAndCollectJournal(t, mustTransferMeta(t, 512, JournalVersionV2, 2), []uint64{512}, dur)
		if endSt.Kind() != TransferKindUncertainCommit || !endSt.IsTerminal() || len(effs) != 0 {
			t.Fatalf("dur=%v 必须停机于 TransferUncertainCommit 且 0 副作用: st=%v effs=%v", dur, endSt.Kind(), effs)
		}
	}
}

func assertJournalRoundTrip(t *testing.T, rec TransferJournalRecord) {
	t.Helper()
	raw1, err := jsonv2.Marshal(rec, jsonv2.Deterministic(true))
	if err != nil {
		t.Fatalf("Journal Marshal 失败: %v", err)
	}
	raw2, _ := jsonv2.Marshal(rec, jsonv2.Deterministic(true))
	if !bytes.Equal(raw1, raw2) {
		t.Fatalf("Journal JSON 编码不满足确定性")
	}
	var rt TransferJournalRecord
	if err := jsonv2.Unmarshal(raw1, &rt); err != nil || !rec.Equal(rt) {
		t.Fatalf("Journal JSON 往返不一致: err=%v", err)
	}
	tampered := strings.Replace(string(raw1), rec.RecordDigest().String(), "sha256:"+strings.Repeat("f", 64), 1)
	var bad TransferJournalRecord
	if err := jsonv2.Unmarshal([]byte(tampered), &bad); !errors.Is(err, ErrCorruptJournal) || bad.IsValid() {
		t.Fatalf("篡改 record_digest 必须返回 ErrCorruptJournal: %v", err)
	}
}

func TestTransferSingleJournalCrashRecovery(t *testing.T) {
	// 收集完整 6 条 V2 记录：Init(1), Chunk(2), Chunk(3), Verified(4), CommitStarted(5), Committed(6)
	_, fullG1, _ := driveTransferAndCollectJournal(t, mustTransferMeta(t, 1000, JournalVersionV2, 1), []uint64{400, 600}, DurabilityCommitted)
	if len(fullG1) != 6 {
		t.Fatalf("期望 6 条记录，实际 %d", len(fullG1))
	}
	cases := []struct {
		name     string
		prefix   []TransferJournalRecord
		wantKind TransferStateKind
		wantEff  int
	}{
		{"crash_after_init", fullG1[:1], TransferKindStreaming, 0},
		{"crash_mid_stream", fullG1[:2], TransferKindStreaming, 0},
		{"crash_after_last_chunk", fullG1[:3], TransferKindVerifying, 1},
		{"crash_after_verified", fullG1[:4], TransferKindVerifying, 1},
		{"crash_after_commit_started", fullG1[:5], TransferKindUncertainCommit, 0},
		{"crash_after_committed", fullG1[:6], TransferKindCommitted, 0},
	}
	for _, tc := range cases {
		st, effs, _, err := RecoverTransferFromJournal(tc.prefix)
		if err != nil || st.Kind() != tc.wantKind || len(effs) != tc.wantEff {
			t.Fatalf("%s: got=(%v, effs=%d, err=%v) want=(%v, effs=%d)", tc.name, st, len(effs), err, tc.wantKind, tc.wantEff)
		}
	}
	// V2 哈希链损坏：提交前损坏 -> *TransferAborted + CleanupStaging；CommitStarted 后损坏 -> *TransferUncertainCommit + 0 副作用
	brokenPre := []TransferJournalRecord{fullG1[0], fullG1[2]}
	if st, effs, _, err := RecoverTransferFromJournal(brokenPre); !errors.Is(err, ErrCorruptJournal) || st.Kind() != TransferKindAborted || len(effs) != 1 || effs[0].Kind() != TransferEffectCleanupStaging {
		t.Fatalf("提交前 Journal 损坏应失败关闭至 Aborted+Cleanup: st=%v effs=%v err=%v", st, effs, err)
	}
	brokenPost := []TransferJournalRecord{fullG1[0], fullG1[1], fullG1[2], fullG1[3], fullG1[4], fullG1[1]}
	if st, effs, _, err := RecoverTransferFromJournal(brokenPost); !errors.Is(err, ErrCorruptJournal) || st.Kind() != TransferKindUncertainCommit || len(effs) != 0 {
		t.Fatalf("CommitStarted 后损坏必须停机于 UncertainCommit 且 0 副作用: st=%v effs=%v err=%v", st, effs, err)
	}
}

func TestTransferDualGenerationCrashRecovery(t *testing.T) {
	_, fullG1, _ := driveTransferAndCollectJournal(t, mustTransferMeta(t, 1000, JournalVersionV2, 1), []uint64{400, 600}, DurabilityCommitted)
	_, fullG2, _ := driveTransferAndCollectJournal(t, mustTransferMeta(t, 1000, JournalVersionV2, 2), []uint64{1000}, DurabilityCommitted)
	// fullG2: [Init(0), Chunk(1), Verified(2), CommitStarted(3), Committed(4)]；跳过 Chunk(1) 构造 gen=2 提交前损坏
	brokenG2 := []TransferJournalRecord{fullG2[0], fullG2[2]}

	if st, _, _, err := RecoverTransferFromDualJournal(fullG1[:2], fullG2[:4]); err != nil || st.Kind() != TransferKindUncertainCommit {
		t.Fatalf("任一代在 CommitStarted 悬停时必须优先返回 UncertainCommit: st=%v err=%v", st, err)
	}
	if st, _, _, err := RecoverTransferFromDualJournal(fullG1[:2], fullG2[:2]); err != nil || TransferMetaOf(st).Generation() != 2 {
		t.Fatalf("双代均完好时应选择更高世代 gen=2: st=%v err=%v", st, err)
	}
	if st, _, _, err := RecoverTransferFromDualJournal(fullG1[:2], brokenG2); err != nil || TransferMetaOf(st).Generation() != 1 || st.Kind() != TransferKindStreaming {
		t.Fatalf("gen=2 提交前损坏应安全回退至完好 active(gen=1): st=%v err=%v", st, err)
	}
	if _, _, _, err := RecoverTransferFromDualJournal(fullG1[:2], fullG1[:3]); !errors.Is(err, ErrCorruptJournal) {
		t.Fatalf("同世代重复双代 Journal 应失败关闭: %v", err)
	}
	// 低世代 Committed vs 高世代未提交脑裂必须失败关闭
	if st, effs, _, err := RecoverTransferFromDualJournal(fullG1, fullG2[:2]); !errors.Is(err, ErrCorruptJournal) || st != nil || len(effs) != 0 {
		t.Fatalf("低世代 Committed 与高世代 Streaming 脑裂必须失败关闭: st=%v effs=%v err=%v", st, effs, err)
	}
	// 损坏的高世代 active(gen=2) 严禁回退至低世代 staging(gen=1)
	if st, effs, _, err := RecoverTransferFromDualJournal(brokenG2, fullG1[:2]); !errors.Is(err, ErrCorruptJournal) || st != nil || len(effs) != 0 {
		t.Fatalf("高世代 active 损坏严禁回退至低世代 staging: st=%v effs=%v err=%v", st, effs, err)
	}
}

func TestTransferVerifiedResumeBisimulationAndCommitNotApplied(t *testing.T) {
	// 1. 端到端多崩溃互模拟：Verified(4) 后崩溃 -> 恢复 Verifying -> VerifyResult(true) 写 Verified(5)+CommitStarted(6) -> 再次崩溃/提交 -> 均可正确回放
	meta := mustTransferMeta(t, 1000, JournalVersionV2, 1)
	_, full, _ := driveTransferAndCollectJournal(t, meta, []uint64{400, 600}, DurabilityCommitted)
	recVer, _, _, err := RecoverTransferFromJournal(full[:4])
	if err != nil || recVer.Kind() != TransferKindVerifying {
		t.Fatalf("Verified(4) 后崩溃应恢复为 Verifying: st=%v err=%v", recVer, err)
	}
	resumedLog := append([]TransferJournalRecord(nil), full[:4]...)
	inVer, _ := TransferInputVerifyResult(true, meta.ExpectedDigest(), "")
	commSt, _ := mustStepTransfer(t, recVer, inVer, &resumedLog)
	if st, effs, _, err := RecoverTransferFromJournal(resumedLog); err != nil || st.Kind() != TransferKindUncertainCommit || len(effs) != 0 {
		t.Fatalf("复验后于 CommitStarted 崩溃必须恢复为 UncertainCommit(0 副作用): st=%v effs=%v err=%v", st, effs, err)
	}
	inCom, _ := TransferInputCommitResult(DurabilityCommitted, "")
	_, _ = mustStepTransfer(t, commSt, inCom, &resumedLog)
	if st, effs, _, err := RecoverTransferFromJournal(resumedLog); err != nil || st.Kind() != TransferKindCommitted || len(effs) != 0 {
		t.Fatalf("复验后提交完成必须恢复为 Committed: st=%v effs=%v err=%v", st, effs, err)
	}

	// 2. DurabilityNotApplied 必须写入 JournalRecordAborted + CleanupStaging，且回放恢复为 Aborted（绝不毒化双代恢复）
	metaAbort := mustTransferMeta(t, 512, JournalVersionV2, 3)
	abSt, abLog, abEffs := driveTransferAndCollectJournal(t, metaAbort, []uint64{512}, DurabilityNotApplied)
	if abSt.Kind() != TransferKindAborted || len(abEffs) != 2 || abEffs[0].Kind() != TransferEffectWriteJournal || abEffs[1].Kind() != TransferEffectCleanupStaging {
		t.Fatalf("DurabilityNotApplied 应产出 WriteJournal(Aborted)+CleanupStaging: st=%v effs=%v", abSt, abEffs)
	}
	if st, effs, _, err := RecoverTransferFromJournal(abLog); err != nil || st.Kind() != TransferKindAborted || len(effs) != 1 {
		t.Fatalf("CommitStarted->Aborted 日志应干净恢复为 Aborted: st=%v effs=%v err=%v", st, effs, err)
	}
	// 3. 尾随损坏但日志后段存在 CommitStarted 标记时必须失败关闭为 UncertainCommit(0 副作用)
	tailWithCommit := []TransferJournalRecord{full[0], full[2], full[4]}
	if st, effs, _, err := RecoverTransferFromJournal(tailWithCommit); !errors.Is(err, ErrCorruptJournal) || st.Kind() != TransferKindUncertainCommit || len(effs) != 0 {
		t.Fatalf("损坏记录后存在 CommitStarted 必须进入 UncertainCommit(0 副作用): st=%v effs=%v err=%v", st, effs, err)
	}
}

func TestTransferJournalFieldBoundsAndTerminalFailClosed(t *testing.T) {
	// 1. 分片超出 TotalBytes 与非分片记录携带非零 Offset/Length 均必须拒绝
	if _, err := NewTransferJournalRecord(TransferJournalRecordSpec{
		Version: JournalVersionV1, Generation: 1, Seq: 2, Kind: JournalRecordChunk,
		TransferID: testOpID(25), Offset: 500, Length: 600, TotalBytes: 1000, Digest: algebraic.Some(testDigest("c")),
	}); !errors.Is(err, ErrInvalidJournal) {
		t.Fatalf("超出 total_bytes 的分片记录必须拒绝: %v", err)
	}
	if _, err := NewTransferJournalRecord(TransferJournalRecordSpec{
		Version: JournalVersionV1, Generation: 1, Seq: 2, Kind: JournalRecordVerified,
		TransferID: testOpID(25), Offset: 10, Length: 0, TotalBytes: 1000, Digest: algebraic.Some(testDigest("v")),
	}); !errors.Is(err, ErrInvalidJournal) {
		t.Fatalf("verified 记录携带非零 offset 必须拒绝: %v", err)
	}
	// 2. 零值与 typed-nil 终态指针变体 IsTerminal() 必须失败关闭返回 false
	var (
		nilCom *TransferCommitted
		nilAb  *TransferAborted
		nilUnc *TransferUncertainCommit
	)
	for _, st := range []TransferState{nilCom, nilAb, nilUnc, &TransferCommitted{}, &TransferAborted{}, &TransferUncertainCommit{}} {
		if st.IsTerminal() || st.IsValid() {
			t.Fatalf("零值或 typed-nil 终态变体 %T 的 IsTerminal/IsValid 必须返回 false", st)
		}
	}
	// 3. 回放时 totalBytes 漂移与双代异 Dest 即使单侧尾损坏均必须拒绝
	meta1 := mustTransferMeta(t, 1000, JournalVersionV1, 1)
	init1, _ := buildInitRecord(meta1)
	badTotalChunk, _ := NewTransferJournalRecord(TransferJournalRecordSpec{
		Version: JournalVersionV1, Generation: 1, Seq: 2, Kind: JournalRecordChunk,
		TransferID: meta1.TransferID(), Offset: 0, Length: 100, TotalBytes: 2000, Digest: algebraic.Some(testDigest("c")),
	})
	if _, _, _, err := RecoverTransferFromJournal([]TransferJournalRecord{init1, badTotalChunk}); !errors.Is(err, ErrCorruptJournal) {
		t.Fatalf("回放中 total_bytes 漂移必须返回 ErrCorruptJournal: %v", err)
	}
	otherDest, _ := pathalg.ParseRemotePath("/var/data/other.bin")
	metaOther, _ := NewTransferMeta(TransferMetaSpec{
		TransferID: meta1.TransferID(), Dest: otherDest, TotalBytes: 1000, ExpectedDigest: meta1.ExpectedDigest(), JournalVersion: JournalVersionV1, Generation: 2,
	})
	initOther, _ := buildInitRecord(metaOther)
	if _, _, _, err := RecoverTransferFromDualJournal([]TransferJournalRecord{init1}, []TransferJournalRecord{initOther, badTotalChunk}); !errors.Is(err, ErrCorruptJournal) {
		t.Fatalf("双代 Dest 不一致即使单侧尾损坏也必须拒绝: %v", err)
	}
}

func TestTransferInvalidInputsAndTypedNil(t *testing.T) {
	meta := mustTransferMeta(t, 100, JournalVersionV2, 1)
	initSt := &TransferInitialized{sealedTransferMixin{meta, true}}
	if _, _, _, err := TransitionTransfer(nil, TransferInputStart()); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("nil 状态应返回 ErrInvalidState: %v", err)
	}
	if _, _, _, err := TransitionTransfer(initSt, TransferInput{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("零值输入应返回 ErrInvalidInput: %v", err)
	}
	var nilStream *TransferStreaming
	if nilStream.IsValid() || nilStream.Offset() != 0 || TransferMetaOf(nilStream).IsValid() {
		t.Fatalf("typed-nil *TransferStreaming 应安全返回零值")
	}
	if _, _, _, err := RecoverTransferFromJournal(nil); !errors.Is(err, ErrCorruptJournal) {
		t.Fatalf("空 Journal 应返回 ErrCorruptJournal: %v", err)
	}
	var zRec TransferJournalRecord
	if _, err := jsonv2.Marshal(zRec); err == nil {
		t.Fatalf("零值 Journal 记录编码必须失败")
	}
	_ = algebraic.None[TransferJournalRecord]()
}

func TestTransferExhaustiveStateInputMatrix(t *testing.T) {
	meta := mustTransferMeta(t, 100, JournalVersionV2, 1)
	dig := testDigest("last")
	states := []TransferState{
		&TransferInitialized{sealedTransferMixin{meta, true}},
		&TransferStreaming{sealedTransferMixin{meta, true}, 0, 0, 2, dig},
		&TransferVerifying{sealedTransferMixin{meta, true}, 1, 3, dig},
		&TransferCommitting{sealedTransferMixin{meta, true}, 5, dig},
		&TransferCommitted{sealedTransferMixin{meta, true}},
		&TransferAborted{sealedTransferMixin{meta, true}, "ab"},
		&TransferUncertainCommit{sealedTransferMixin{meta, true}, "unc"},
	}
	inChunk, _ := TransferInputChunk(0, 50, testDigest("c"))
	inVer, _ := TransferInputVerifyResult(true, meta.ExpectedDigest(), "")
	inCom, _ := TransferInputCommitResult(DurabilityCommitted, "")
	inputs := []TransferInput{TransferInputStart(), inChunk, inVer, inCom, TransferInputAbort("cancel")}
	allowed := map[[2]int]bool{
		{0, 0}: true, {0, 4}: true,
		{1, 1}: true, {1, 4}: true,
		{2, 2}: true, {2, 4}: true,
		{3, 3}: true,
	}
	for i, st := range states {
		for j, in := range inputs {
			next, effs, evs, err := TransitionTransfer(st, in)
			if allowed[[2]int{i, j}] && err != nil {
				t.Fatalf("Transfer 矩阵(%s, %d) 期望合法，实际 %v", st.Kind(), j, err)
			}
			if !allowed[[2]int{i, j}] && (!errors.Is(err, ErrIllegalTransition) || next != st || len(effs) != 0 || len(evs) != 0) {
				t.Fatalf("Transfer 矩阵(%s, %d) 应失败关闭: next=%v err=%v", st.Kind(), j, next, err)
			}
		}
	}
}
