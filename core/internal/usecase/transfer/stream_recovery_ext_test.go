package transfer_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strconv"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/internal/usecase/transfer"
	"github.com/wentf9/xops-cli/core/ports"
)

func TestStreamTransfer_UploadDownloadZeroBytesAndManagedHandleLifecycle(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newTransferRig(t, rigOptions{omitOperatorRead: true}) // MCP 10 GiB 路径物理零 OperatorReadFS
	defer rig.close()
	ctx := context.Background()

	// 1. 超过 10 GiB 上限必须拒绝
	upDest, err := fsm.NewUploadDest(mustRemotePath(t, "/srv/huge.bin"))
	requireNoErr(t, err, "NewUploadDest")
	_, err = rig.svc.StartTransfer(ctx, transfer.StartTransferRequest{CallBase: rig.callBase(nil), Dest: upDest, TotalBytes: fsm.MaxTransferBytes + 1})
	requireErrIs(t, err, fsm.ErrTransferSizeExceeded, "超出 10 GiB 必须拒绝")

	// 2. 完整分片上传 + 托管句柄跨越 WithLease 存活 + 事件流断言
	payload := makePatternPayload(10000)
	expDig := security.DigestBytes(payload)
	requireNoErr(t, rig.remoteFS.MkdirAll(ctx, mustRemotePath(t, "/srv"), 0o755), "MkdirAll /srv")
	streamStart := mustNewOpStream(t, rig.rng)
	info, err := rig.svc.StartTransfer(ctx, transfer.StartTransferRequest{
		CallBase: rig.callBase(streamStart), Dest: upDest, TotalBytes: uint64(len(payload)), ExpectedDigest: algebraic.Some(expDig),
	})
	requireNoErr(t, err, "StartTransfer upload")
	assertHasStartedAndCompleted(t, drainOpStream(t, streamStart), true)

	// StartTransfer 的 WithLease 已归还（ActiveLeases == 0），托管句柄仍稳固存活（ActiveHandles == 1），EvictIdle 不得误驱逐
	stats := rig.pool.Stats()
	if stats.ActiveLeases != 0 || stats.ActiveHandles != 1 || rig.pool.EvictIdle() != 0 {
		t.Fatalf("托管句柄池状态异常: stats=%+v", stats)
	}
	// 非连续偏移分片被 TransferFSM 拒绝
	_, err = rig.svc.WriteTransferChunk(ctx, transfer.WriteTransferChunkRequest{CallBase: rig.callBase(nil), Handle: info.Handle, Offset: 4096, Data: payload[4096:8192]})
	requireErrIs(t, err, fsm.ErrInvalidChunkOffset, "跳跃偏移必须拒绝")

	w1, err := rig.svc.WriteTransferChunk(ctx, transfer.WriteTransferChunkRequest{CallBase: rig.callBase(nil), Handle: info.Handle, Offset: 0, Data: payload[:4096]})
	requireNoErr(t, err, "chunk 1")
	w2, err := rig.svc.WriteTransferChunk(ctx, transfer.WriteTransferChunkRequest{CallBase: rig.callBase(nil), Handle: info.Handle, Offset: 4096, Data: payload[4096:]})
	requireNoErr(t, err, "chunk 2")
	if w1.StateKind != fsm.TransferKindStreaming || w2.StateKind != fsm.TransferKindVerifying {
		t.Fatalf("状态推进异常: w1=%s w2=%s", w1.StateKind, w2.StateKind)
	}
	snap, err := rig.svc.InspectTransfer(ctx, transfer.InspectTransferRequest{CallBase: rig.callBase(nil), TransferID: info.TransferID})
	requireNoErr(t, err, "InspectTransfer live")
	if !snap.LiveHandle || snap.StateKind != fsm.TransferKindVerifying || snap.Offset != uint64(len(payload)) {
		t.Fatalf("InspectTransfer 快照异常: %+v", snap)
	}
	comRes, err := rig.svc.CommitTransfer(ctx, transfer.CommitTransferRequest{CallBase: rig.callBase(nil), Handle: info.Handle})
	requireNoErr(t, err, "CommitTransfer upload")
	if comRes.State.Kind() != fsm.TransferKindCommitted || !bytes.Equal(mustReadRemote(t, rig.remoteFS, "/srv/huge.bin"), payload) {
		t.Fatalf("CommitTransfer 上传结果异常: %+v", comRes)
	}
	if rig.pool.Stats().ActiveHandles != 0 {
		t.Fatalf("提交后必须释放托管句柄，实际=%d", rig.pool.Stats().ActiveHandles)
	}

	// 3. 0 字节上传直达 Verifying -> CommitTransfer；AbortTransfer 清理暂存并释放句柄
	zeroDest, err := fsm.NewUploadDest(mustRemotePath(t, "/srv/empty.bin"))
	requireNoErr(t, err, "zeroDest")
	zInfo, err := rig.svc.StartTransfer(ctx, transfer.StartTransferRequest{CallBase: rig.callBase(nil), Dest: zeroDest, TotalBytes: 0})
	requireNoErr(t, err, "StartTransfer 0-byte")
	if zInfo.State.Kind() != fsm.TransferKindVerifying {
		t.Fatalf("0 字节传输应直达 Verifying，实际=%s", zInfo.State.Kind())
	}
	_, err = rig.svc.CommitTransfer(ctx, transfer.CommitTransferRequest{CallBase: rig.callBase(nil), Handle: zInfo.Handle})
	requireNoErr(t, err, "CommitTransfer 0-byte")

	abDest, err := fsm.NewUploadDest(mustRemotePath(t, "/srv/abort.bin"))
	requireNoErr(t, err, "abDest")
	abInfo, err := rig.svc.StartTransfer(ctx, transfer.StartTransferRequest{CallBase: rig.callBase(nil), Dest: abDest, TotalBytes: 8})
	requireNoErr(t, err, "StartTransfer abort")
	_, err = rig.svc.WriteTransferChunk(ctx, transfer.WriteTransferChunkRequest{CallBase: rig.callBase(nil), Handle: abInfo.Handle, Offset: 0, Data: []byte("1234")})
	requireNoErr(t, err, "write partial before abort")
	requireNoErr(t, rig.svc.AbortTransfer(ctx, transfer.AbortTransferRequest{CallBase: rig.callBase(nil), Handle: abInfo.Handle, Reason: "user cancel"}), "AbortTransfer")
	if rig.pool.Stats().ActiveHandles != 0 {
		t.Fatalf("AbortTransfer 后句柄未释放")
	}
}

func TestStreamTransfer_DownloadScopedCommitTimesAndNoClobberAbort(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newTransferRig(t, rigOptions{omitOperatorRead: true})
	defer rig.close()
	ctx := context.Background()

	payload := makePatternPayload(10000)
	expDig := security.DigestBytes(payload)
	remTime := time.Date(2025, time.September, 2, 7, 15, 0, 0, time.UTC)
	mustWriteRemote(t, rig.remoteFS, "/srv/huge.bin", payload)
	requireNoErr(t, rig.remoteFS.Chtimes(ctx, mustRemotePath(t, "/srv/huge.bin"), remTime, remTime), "Chtimes")

	dlDest, err := fsm.NewDownloadDest(mustLocalDest(t, "stream/dl.bin"))
	requireNoErr(t, err, "NewDownloadDest")
	dlInfo, err := rig.svc.StartTransfer(ctx, transfer.StartTransferRequest{
		CallBase: rig.callBase(nil), Dest: dlDest, ExpectedDigest: algebraic.Some(expDig),
		TransferSessionOptions: transfer.TransferSessionOptions{
			LocalRoot: algebraic.Some(rig.localRoot), RemoteSource: algebraic.Some(mustRemotePath(t, "/srv/huge.bin")), PreserveTimes: true,
		},
	})
	requireNoErr(t, err, "StartTransfer download")
	for {
		pRes, pErr := rig.svc.PullTransferChunk(ctx, transfer.PullTransferChunkRequest{CallBase: rig.callBase(nil), Handle: dlInfo.Handle, MaxChunkBytes: 4096})
		requireNoErr(t, pErr, "PullTransferChunk")
		if pRes.StateKind == fsm.TransferKindVerifying {
			break
		}
	}
	dlCom, err := rig.svc.CommitTransfer(ctx, transfer.CommitTransferRequest{CallBase: rig.callBase(nil), Handle: dlInfo.Handle})
	requireNoErr(t, err, "CommitTransfer download")
	if dlCom.State.Kind() != fsm.TransferKindCommitted || !bytes.Equal(mustReadLocal(t, rig.scopedFS, rig.localRoot, "stream/dl.bin"), payload) {
		t.Fatalf("流式下载落盘内容异常")
	}

	// 下载 NoClobber 确定性 NotApplied -> 转 Aborted 并清理暂存、释放句柄
	ncInfo, err := rig.svc.StartTransfer(ctx, transfer.StartTransferRequest{
		CallBase: rig.callBase(nil), Dest: dlDest,
		TransferSessionOptions: transfer.TransferSessionOptions{
			LocalRoot: algebraic.Some(rig.localRoot), RemoteSource: algebraic.Some(mustRemotePath(t, "/srv/huge.bin")), NoClobber: true,
		},
	})
	requireNoErr(t, err, "StartTransfer download noClobber")
	for {
		pRes, pErr := rig.svc.PullTransferChunk(ctx, transfer.PullTransferChunkRequest{CallBase: rig.callBase(nil), Handle: ncInfo.Handle, MaxChunkBytes: 8192})
		requireNoErr(t, pErr, "PullTransferChunk noClobber")
		if pRes.StateKind == fsm.TransferKindVerifying {
			break
		}
	}
	ncCom, err := rig.svc.CommitTransfer(ctx, transfer.CommitTransferRequest{CallBase: rig.callBase(nil), Handle: ncInfo.Handle})
	requireErrIs(t, err, ports.ErrAlreadyExists, "本地 NoClobber 冲突应确定性 NotApplied")
	if ncCom.State == nil || ncCom.State.Kind() != fsm.TransferKindAborted || rig.pool.Stats().ActiveHandles != 0 {
		t.Fatalf("确定性 NotApplied 必须转 Aborted 并释放句柄: %+v", ncCom)
	}
}

func TestStreamTransfer_CrashResumeSameGenAndNextGenPrune(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newTransferRig(t, rigOptions{omitOperatorRead: true})
	defer rig.close()
	ctx := context.Background()

	payload := makePatternPayload(12000)
	expDig := security.DigestBytes(payload)
	requireNoErr(t, rig.remoteFS.MkdirAll(ctx, mustRemotePath(t, "/resume"), 0o755), "MkdirAll /resume")
	dest, err := fsm.NewUploadDest(mustRemotePath(t, "/resume/item.bin"))
	requireNoErr(t, err, "NewUploadDest")

	// 1. 写入一半后模拟进程崩溃（池关闭重启，但 RemoteFS 与 JournalStore 持久留存）
	info1, err := rig.svc.StartTransfer(ctx, transfer.StartTransferRequest{
		CallBase: rig.callBase(nil), Dest: dest, TotalBytes: uint64(len(payload)), ExpectedDigest: algebraic.Some(expDig),
	})
	requireNoErr(t, err, "StartTransfer")
	_, err = rig.svc.WriteTransferChunk(ctx, transfer.WriteTransferChunkRequest{CallBase: rig.callBase(nil), Handle: info1.Handle, Offset: 0, Data: payload[:4096]})
	requireNoErr(t, err, "WriteTransferChunk part1")

	// 模拟句柄因跳板吊销丢失 -> 同代恢复继续写入剩余分片 -> CommitTransfer 全量回读远端暂存核验 SHA-256
	hopDig, _ := rig.plan.HopDigestAt(0)
	requireNoErr(t, rig.pool.RetireHop(hopDig), "RetireHop")
	rec, err := rig.svc.RecoverTransfer(ctx, transfer.RecoverTransferRequest{CallBase: rig.callBase(nil), TransferID: info1.TransferID})
	requireNoErr(t, err, "RecoverTransfer mid-stream")
	if rec.State.Kind() != fsm.TransferKindStreaming || rec.SelectedGen != 1 {
		t.Fatalf("恢复状态异常: %+v", rec)
	}
	resInfo, err := rig.svc.ResumeTransfer(ctx, transfer.ResumeTransferRequest{CallBase: rig.callBase(nil), TransferID: info1.TransferID, StartNextGen: false})
	requireNoErr(t, err, "ResumeTransfer same gen")
	_, err = rig.svc.WriteTransferChunk(ctx, transfer.WriteTransferChunkRequest{CallBase: rig.callBase(nil), Handle: resInfo.Handle, Offset: 4096, Data: payload[4096:]})
	requireNoErr(t, err, "WriteTransferChunk part2")
	comRes, err := rig.svc.CommitTransfer(ctx, transfer.CommitTransferRequest{CallBase: rig.callBase(nil), Handle: resInfo.Handle})
	requireNoErr(t, err, "CommitTransfer after resume (full remote re-hash)")
	if comRes.State.Kind() != fsm.TransferKindCommitted || !bytes.Equal(mustReadRemote(t, rig.remoteFS, "/resume/item.bin"), payload) {
		t.Fatalf("同代续传提交结果异常: %+v", comRes)
	}

	// 2. StartNextGen=true 派生 gen 2，恢复并裁剪旧代 gen 1
	dest2, err := fsm.NewUploadDest(mustRemotePath(t, "/resume/nextgen.bin"))
	requireNoErr(t, err, "dest2")
	g1Info, err := rig.svc.StartTransfer(ctx, transfer.StartTransferRequest{CallBase: rig.callBase(nil), Dest: dest2, TotalBytes: 8})
	requireNoErr(t, err, "start g1")
	g2Info, err := rig.svc.ResumeTransfer(ctx, transfer.ResumeTransferRequest{CallBase: rig.callBase(nil), TransferID: g1Info.TransferID, StartNextGen: true})
	requireNoErr(t, err, "ResumeTransfer StartNextGen")
	if g2Info.Meta.Generation() != 2 {
		t.Fatalf("期望 generation=2，实际=%d", g2Info.Meta.Generation())
	}
	_, err = rig.svc.WriteTransferChunk(ctx, transfer.WriteTransferChunkRequest{CallBase: rig.callBase(nil), Handle: g2Info.Handle, Offset: 0, Data: []byte("12345678")})
	requireNoErr(t, err, "write g2")
	_, err = rig.svc.CommitTransfer(ctx, transfer.CommitTransferRequest{CallBase: rig.callBase(nil), Handle: g2Info.Handle})
	requireNoErr(t, err, "commit g2")

	rec2, err := rig.svc.RecoverTransfer(ctx, transfer.RecoverTransferRequest{CallBase: rig.callBase(nil), TransferID: g1Info.TransferID, PruneSuperseded: true})
	requireNoErr(t, err, "RecoverTransfer prune gen 1")
	if rec2.SelectedGen != 2 || len(rec2.PrunedGenerations) != 1 || rec2.PrunedGenerations[0] != 1 {
		t.Fatalf("高代恢复裁剪旧代异常: %+v", rec2)
	}
	snaps, err := rig.journals.LoadGenerations(ctx, g1Info.TransferID)
	requireNoErr(t, err, "LoadGenerations after prune")
	if len(snaps) != 1 || snaps[0].Generation() != 2 {
		t.Fatalf("裁剪后应仅剩 gen 2: %+v", snaps)
	}
}

func TestRecoveryIronRules_CorruptHighGenAndEmptyPrefixNeverFallback(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newTransferRig(t, rigOptions{omitOperatorRead: true})
	defer rig.close()
	ctx := context.Background()
	dest, err := fsm.NewUploadDest(mustRemotePath(t, "/iron/file.bin"))
	requireNoErr(t, err, "NewUploadDest")

	// 铁律 1：Gen 1 健康 + Gen 2 非空前缀损坏 -> 严禁回退 Gen 1，0 副作用
	id1 := seedHealthyGen(t, rig, dest, 1, 16, false, false)
	seedPartialGen(t, rig, id1, dest, 2, 16, false, false)
	rig.journals.inner.CorruptGeneration(id1, 2, errors.New("crc mismatch on gen 2"))
	p0, d0 := rig.journals.mutationCounts()
	_, err = rig.svc.RecoverTransfer(ctx, transfer.RecoverTransferRequest{CallBase: rig.callBase(nil), TransferID: id1, PruneSuperseded: true})
	requireErrIs(t, err, transfer.ErrCorruptJournal, "铁律 1：高世代损坏严禁回退低世代")
	assertZeroJournalMutations(t, rig.journals, p0, d0, "铁律 1")
	_, err = rig.svc.ResumeTransfer(ctx, transfer.ResumeTransferRequest{CallBase: rig.callBase(nil), TransferID: id1})
	requireErrIs(t, err, transfer.ErrCorruptJournal, "损坏高世代严禁 Resume")

	// 铁律 3：Gen 1 健康 + Gen 2 空前缀损坏（PartialRecords() 为空）-> Fail-Closed，严禁回退 Gen 1，0 副作用
	idEmpty := seedHealthyGen(t, rig, dest, 1, 16, true, true)
	rig.journals.inner.CorruptGeneration(idEmpty, 2, errors.New("truncated header gen 2"))
	p1, d1 := rig.journals.mutationCounts()
	_, err = rig.svc.RecoverTransfer(ctx, transfer.RecoverTransferRequest{CallBase: rig.callBase(nil), TransferID: idEmpty, PruneSuperseded: true})
	requireErrIs(t, err, transfer.ErrCorruptJournal, "铁律 3：空前缀高世代损坏必须 Fail-Closed")
	assertZeroJournalMutations(t, rig.journals, p1, d1, "铁律 3")

	// 正常互补路径：Gen 1 损坏（空前缀或同元数据提交前前缀）+ Gen 2 健康 Committed -> 采纳 Gen 2 并允许裁剪 Gen 1
	idLowBad := mustOpID(t, rig)
	rig.journals.inner.CorruptGeneration(idLowBad, 1, errors.New("empty gen 1 header corrupt"))
	seedGenWithID(t, rig, idLowBad, dest, 2, 8, true, true)
	recLowBad, err := rig.svc.RecoverTransfer(ctx, transfer.RecoverTransferRequest{CallBase: rig.callBase(nil), TransferID: idLowBad, PruneSuperseded: true})
	requireNoErr(t, err, "健康高代可安全覆盖空前缀损坏低代")
	if recLowBad.SelectedGen != 2 || len(recLowBad.PrunedGenerations) != 1 || recLowBad.PrunedGenerations[0] != 1 {
		t.Fatalf("应选 gen 2 并裁剪 gen 1: %+v", recLowBad)
	}

	// 损坏低代元数据（Dest）与高代不一致 -> Fail-Closed 拒绝且 0 副作用
	idMismatch := mustOpID(t, rig)
	otherDest, err := fsm.NewUploadDest(mustRemotePath(t, "/iron/other.bin"))
	requireNoErr(t, err, "otherDest")
	seedPartialGen(t, rig, idMismatch, otherDest, 1, 8, false, false)
	rig.journals.inner.CorruptGeneration(idMismatch, 1, errors.New("gen 1 mid-stream corrupt"))
	seedGenWithID(t, rig, idMismatch, dest, 2, 8, true, true)
	p2, d2 := rig.journals.mutationCounts()
	_, err = rig.svc.RecoverTransfer(ctx, transfer.RecoverTransferRequest{CallBase: rig.callBase(nil), TransferID: idMismatch, PruneSuperseded: true})
	requireErrIs(t, err, transfer.ErrCorruptJournal, "损坏低代元数据不一致必须 Fail-Closed")
	assertZeroJournalMutations(t, rig.journals, p2, d2, "低代元数据不一致")

	// 铁律 1b：Gen 1 健康 + Gen 2 V2 哈希链断裂（记录自身完整但 PrevRecordDigest 篡改）-> ErrCorruptJournal，严禁回退 Gen 1
	idBadChain := seedHealthyGen(t, rig, dest, 1, 8, false, false)
	seedGenWithID(t, rig, idBadChain, dest, 2, 8, false, false)
	tamperedRec, err := fsm.NewTransferJournalRecord(fsm.TransferJournalRecordSpec{
		Version: fsm.JournalVersionV2, Generation: 2, Seq: 3, Kind: fsm.JournalRecordChunk,
		TransferID: idBadChain, Offset: 4, Length: 4, TotalBytes: 8,
		Digest: algebraic.Some(security.DigestBytes([]byte("5678"))), PrevDigest: algebraic.Some(security.DigestBytes([]byte("forged-prev"))),
	})
	requireNoErr(t, err, "tamperedRec")
	requireNoErr(t, rig.journals.inner.Append(ctx, tamperedRec), "append tamperedRec")
	pChain, dChain := rig.journals.mutationCounts()
	_, err = rig.svc.RecoverTransfer(ctx, transfer.RecoverTransferRequest{CallBase: rig.callBase(nil), TransferID: idBadChain, PruneSuperseded: true})
	requireErrIs(t, err, transfer.ErrCorruptJournal, "铁律 1b：高代 V2 哈希链断裂严禁回退低代")
	assertZeroJournalMutations(t, rig.journals, pChain, dChain, "铁律 1b")

	// 双代脑裂：Gen 1 健康 Committed + Gen 2 健康 Streaming -> ErrCorruptJournal 0 副作用
	idSplit := seedHealthyGen(t, rig, dest, 1, 8, true, true)
	seedPartialGen(t, rig, idSplit, dest, 2, 8, false, false)
	p3, d3 := rig.journals.mutationCounts()
	_, err = rig.svc.RecoverTransfer(ctx, transfer.RecoverTransferRequest{CallBase: rig.callBase(nil), TransferID: idSplit, PruneSuperseded: true})
	requireErrIs(t, err, transfer.ErrCorruptJournal, "双代脑裂必须 Fail-Closed")
	assertZeroJournalMutations(t, rig.journals, p3, d3, "双代脑裂")
}

func TestRecoveryIronRule2_UncertainCommitAndLiveAmbiguousCommitZeroSideEffects(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newTransferRig(t, rigOptions{omitOperatorRead: true})
	defer rig.close()
	ctx := context.Background()
	dest, err := fsm.NewUploadDest(mustRemotePath(t, "/uncertain/data.bin"))
	requireNoErr(t, err, "NewUploadDest")

	// 情况 A：损坏高代 PartialRecords() 含 CommitStarted（即使低代健康）-> TransferUncertainCommit 0 副作用
	idA := seedHealthyGen(t, rig, dest, 1, 8, false, false)
	seedGenWithID(t, rig, idA, dest, 2, 8, true, false) // 写到 CommitStarted
	rig.journals.inner.CorruptGeneration(idA, 2, errors.New("trailing garbage after commit_started"))
	assertUncertainZeroSideEffects(t, rig, idA, 2, "损坏高代含 CommitStarted")

	// 情况 B：损坏高代 PartialRecords() 含 Committed（Committed 后落盘损坏）-> 仍停留 TransferUncertainCommit 0 副作用
	idB := seedHealthyGen(t, rig, dest, 1, 8, false, false)
	seedGenWithID(t, rig, idB, dest, 2, 8, true, true) // 含 CommitStarted + Committed
	rig.journals.inner.CorruptGeneration(idB, 2, errors.New("trailing bytes after committed"))
	assertUncertainZeroSideEffects(t, rig, idB, 2, "损坏高代含 Committed")

	// 情况 C：损坏低代 PartialRecords() 含 CommitStarted 且高代健康 -> 仍停留 TransferUncertainCommit 0 副作用
	idC := mustOpID(t, rig)
	seedGenWithID(t, rig, idC, dest, 1, 8, true, false)
	rig.journals.inner.CorruptGeneration(idC, 1, errors.New("gen 1 corrupt after commit_started"))
	seedGenWithID(t, rig, idC, dest, 2, 8, true, true)
	assertUncertainZeroSideEffects(t, rig, idC, 1, "损坏低代含 CommitStarted")

	// 情况 D：健康单代停在 CommitStarted -> TransferUncertainCommit 0 副作用
	idD := seedHealthyGen(t, rig, dest, 1, 8, true, false)
	assertUncertainZeroSideEffects(t, rig, idD, 1, "健康单代悬停 CommitStarted")

	// 情况 E：实时 CommitTransfer 在 RenameAtomic 时发生歧义传输丢失（ports.ErrClosed）-> UncertainCommit + OutcomeUnknown 审计
	requireNoErr(t, rig.remoteFS.MkdirAll(ctx, mustRemotePath(t, "/uncertain"), 0o755), "MkdirAll")
	liveDest, err := fsm.NewUploadDest(mustRemotePath(t, "/uncertain/live.bin"))
	requireNoErr(t, err, "liveDest")
	liveInfo, err := rig.svc.StartTransfer(ctx, transfer.StartTransferRequest{CallBase: rig.callBase(nil), Dest: liveDest, TotalBytes: 4})
	requireNoErr(t, err, "StartTransfer live")
	_, err = rig.svc.WriteTransferChunk(ctx, transfer.WriteTransferChunkRequest{CallBase: rig.callBase(nil), Handle: liveInfo.Handle, Offset: 0, Data: []byte("abcd")})
	requireNoErr(t, err, "write live")
	rig.dialer.mu.Lock()
	rig.dialer.onBeforeRenameAtomic = func(_ context.Context, _, _ pathalg.RemotePath) error { return ports.ErrClosed }
	rig.dialer.mu.Unlock()
	comRes, err := rig.svc.CommitTransfer(ctx, transfer.CommitTransferRequest{CallBase: rig.callBase(nil), Handle: liveInfo.Handle})
	requireErrIs(t, err, transfer.ErrUncertainCommit, "RenameAtomic 歧义断连必须返回 ErrUncertainCommit")
	if comRes.State == nil || comRes.State.Kind() != fsm.TransferKindUncertainCommit {
		t.Fatalf("实时歧义提交必须进入 TransferUncertainCommit: %+v", comRes)
	}
	assertAuditContainsUnknownOutcome(t, rig.auditClust.Entries())
	// 恢复该实时任务仍必须停留 UncertainCommit 且 0 副作用
	assertUncertainZeroSideEffects(t, rig, liveInfo.TransferID, 1, "实时歧义提交后恢复")

	// 情况 F：CommitTransfer 原子重命名成功但写 Committed Journal 失败 -> ErrUncertainCommit
	rig.dialer.mu.Lock()
	rig.dialer.onBeforeRenameAtomic = nil
	rig.dialer.mu.Unlock()
	jFailDest, err := fsm.NewUploadDest(mustRemotePath(t, "/uncertain/jfail.bin"))
	requireNoErr(t, err, "jFailDest")
	jfInfo, err := rig.svc.StartTransfer(ctx, transfer.StartTransferRequest{CallBase: rig.callBase(nil), Dest: jFailDest, TotalBytes: 4})
	requireNoErr(t, err, "StartTransfer jfail")
	_, err = rig.svc.WriteTransferChunk(ctx, transfer.WriteTransferChunkRequest{CallBase: rig.callBase(nil), Handle: jfInfo.Handle, Offset: 0, Data: []byte("wxyz")})
	requireNoErr(t, err, "write jfail")
	rig.journals.mu.Lock()
	rig.journals.failOnAppendKind = fsm.JournalRecordCommitted
	rig.journals.appendErr = errors.New("disk full on committed journal")
	rig.journals.mu.Unlock()
	_, err = rig.svc.CommitTransfer(ctx, transfer.CommitTransferRequest{CallBase: rig.callBase(nil), Handle: jfInfo.Handle})
	requireErrIs(t, err, transfer.ErrUncertainCommit, "Committed WAL 写盘失败必须返回 ErrUncertainCommit")
	rig.journals.mu.Lock()
	rig.journals.appendErr = nil
	rig.journals.mu.Unlock()

	// 情况 G：RecoverAllTransfers 批量扫描不因单条损坏/不确定提交中断
	allRes, err := rig.svc.RecoverAllTransfers(ctx, transfer.RecoverAllRequest{PruneSuperseded: false})
	requireNoErr(t, err, "RecoverAllTransfers")
	if len(allRes.Entries) < 5 {
		t.Fatalf("RecoverAllTransfers 应扫描全部活跃任务，实际=%d", len(allRes.Entries))
	}
}

func TestInspectTransfer_GateBeforeExistenceCheck(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newTransferRig(t, rigOptions{
		profile:          gate.PolicyProfileStrictAgent,
		approvalThresh:   security.RiskSafe, // Safe 也需要审批（无交互自动拒绝）
		omitOperatorRead: true,
	})
	defer rig.close()
	unknownID := mustOpID(t, rig)
	_, err := rig.svc.InspectTransfer(context.Background(), transfer.InspectTransferRequest{CallBase: rig.callBase(nil), TransferID: unknownID})
	if err == nil || errors.Is(err, transfer.ErrTransferNotFound) {
		t.Fatalf("INV-E5：InspectTransfer 必须先经 Gate 拒绝，严禁泄露 ErrTransferNotFound，实际=%v", err)
	}
	_, err = rig.svc.ResumeTransfer(context.Background(), transfer.ResumeTransferRequest{CallBase: rig.callBase(nil), TransferID: unknownID})
	if err == nil || errors.Is(err, transfer.ErrTransferNotFound) {
		t.Fatalf("INV-E5：ResumeTransfer 对未知 ID 必须先经 Gate 拒绝，实际=%v", err)
	}
}

// TestDST_TransferDualGenCrashRecovery 执行单种子可复现的双代/多代崩溃恢复随机仿真（支持 XOPS_DST_SEEDS / XOPS_DST_SEED），
// 在全部种子上强制校验三条恢复铁律与 0 副作用不变量。
func TestDST_TransferDualGenCrashRecovery(t *testing.T) {
	defer goleak.VerifyNone(t)
	seeds := resolveTransferDSTSeeds(t)
	rig := newTransferRig(t, rigOptions{omitOperatorRead: true})
	defer rig.close()
	dest, err := fsm.NewUploadDest(mustRemotePath(t, "/dst/payload.bin"))
	requireNoErr(t, err, "NewUploadDest")
	for _, seed := range seeds {
		runOneRecoveryDSTSeed(t, rig, dest, seed)
	}
}

func resolveTransferDSTSeeds(t *testing.T) []uint64 {
	t.Helper()
	if raw := os.Getenv("XOPS_DST_SEED"); raw != "" {
		v, err := strconv.ParseUint(raw, 10, 64)
		requireNoErr(t, err, "parse XOPS_DST_SEED")
		return []uint64{v}
	}
	n := 64
	if raw := os.Getenv("XOPS_DST_SEEDS"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v <= 0 {
			t.Fatalf("无效 XOPS_DST_SEEDS=%q: %v", raw, err)
		}
		n = v
	}
	seeds := make([]uint64, n)
	for i := range n {
		seeds[i] = uint64(i) + 1
	}
	return seeds
}

func runOneRecoveryDSTSeed(t *testing.T, rig *transferTestRig, dest fsm.TransferDest, seed uint64) {
	t.Helper()
	rng := sim.NewSeededRand(seed)
	id, err := security.NewOperationIDFrom(rng)
	requireNoErr(t, err, "NewOperationIDFrom")
	scenario := rng.IntN(6)
	p0, d0 := rig.journals.mutationCounts()
	ctx := context.Background()
	switch scenario {
	case 0: // 铁律 1：高代非空前缀损坏绝不回退低代
		seedGenWithID(t, rig, id, dest, 1, 8, false, false)
		seedGenWithID(t, rig, id, dest, 2, 8, false, false)
		rig.journals.inner.CorruptGeneration(id, 2, errors.New("dst corrupt high"))
		_, recErr := rig.svc.RecoverTransfer(ctx, transfer.RecoverTransferRequest{CallBase: rig.callBase(nil), TransferID: id, PruneSuperseded: true})
		requireErrIs(t, recErr, transfer.ErrCorruptJournal, "DST seed 铁律1")
		assertZeroJournalMutations(t, rig.journals, p0, d0, "DST 铁律1")
	case 1: // 铁律 2：高代含 CommitStarted 损坏 -> UncertainCommit 0 副作用
		seedGenWithID(t, rig, id, dest, 1, 8, false, false)
		seedGenWithID(t, rig, id, dest, 2, 8, true, false)
		rig.journals.inner.CorruptGeneration(id, 2, errors.New("dst corrupt after commit_started"))
		res, recErr := rig.svc.RecoverTransfer(ctx, transfer.RecoverTransferRequest{CallBase: rig.callBase(nil), TransferID: id, PruneSuperseded: true})
		requireErrIs(t, recErr, transfer.ErrUncertainCommit, "DST seed 铁律2(CommitStarted)")
		if !res.UncertainCommit || res.State == nil || res.State.Kind() != fsm.TransferKindUncertainCommit {
			t.Fatalf("seed=%d 未进入 UncertainCommit: %+v", seed, res)
		}
		assertZeroJournalMutations(t, rig.journals, p0, d0, "DST 铁律2")
	case 2: // 铁律 2b：高代含 Committed 后损坏 -> 仍 UncertainCommit 0 副作用
		seedGenWithID(t, rig, id, dest, 1, 8, false, false)
		seedGenWithID(t, rig, id, dest, 2, 8, true, true)
		rig.journals.inner.CorruptGeneration(id, 2, errors.New("dst corrupt after committed"))
		res, recErr := rig.svc.RecoverTransfer(ctx, transfer.RecoverTransferRequest{CallBase: rig.callBase(nil), TransferID: id, PruneSuperseded: true})
		requireErrIs(t, recErr, transfer.ErrUncertainCommit, "DST seed 铁律2(Committed)")
		if !res.UncertainCommit {
			t.Fatalf("seed=%d 必须停留 UncertainCommit", seed)
		}
		assertZeroJournalMutations(t, rig.journals, p0, d0, "DST 铁律2b")
	case 3: // 铁律 3：空前缀高代损坏 -> Fail-Closed 0 副作用
		seedGenWithID(t, rig, id, dest, 1, 8, true, true)
		rig.journals.inner.CorruptGeneration(id, 2, errors.New("dst empty high corrupt"))
		_, recErr := rig.svc.RecoverTransfer(ctx, transfer.RecoverTransferRequest{CallBase: rig.callBase(nil), TransferID: id, PruneSuperseded: true})
		requireErrIs(t, recErr, transfer.ErrCorruptJournal, "DST seed 铁律3")
		assertZeroJournalMutations(t, rig.journals, p0, d0, "DST 铁律3")
	case 4: // 健康高代 + 提交前损坏低代 -> 采纳高代并裁剪低代
		seedGenWithID(t, rig, id, dest, 1, 8, false, false)
		rig.journals.inner.CorruptGeneration(id, 1, errors.New("dst corrupt low pre-commit"))
		seedGenWithID(t, rig, id, dest, 2, 8, true, true)
		res, recErr := rig.svc.RecoverTransfer(ctx, transfer.RecoverTransferRequest{CallBase: rig.callBase(nil), TransferID: id, PruneSuperseded: true})
		requireNoErr(t, recErr, "DST seed 健康高代覆盖损坏低代")
		if res.SelectedGen != 2 || len(res.PrunedGenerations) != 1 || res.PrunedGenerations[0] != 1 {
			t.Fatalf("seed=%d 裁剪结果异常: %+v", seed, res)
		}
	default: // 双代脑裂：低代 Committed + 高代 Streaming -> ErrCorruptJournal 0 副作用
		seedGenWithID(t, rig, id, dest, 1, 8, true, true)
		seedGenWithID(t, rig, id, dest, 2, 8, false, false)
		_, recErr := rig.svc.RecoverTransfer(ctx, transfer.RecoverTransferRequest{CallBase: rig.callBase(nil), TransferID: id, PruneSuperseded: true})
		requireErrIs(t, recErr, transfer.ErrCorruptJournal, "DST seed 双代脑裂")
		assertZeroJournalMutations(t, rig.journals, p0, d0, "DST 脑裂")
	}
}

func assertUncertainZeroSideEffects(t *testing.T, rig *transferTestRig, id security.OperationID, expectGen uint64, label string) {
	t.Helper()
	ctx := context.Background()
	p0, d0 := rig.journals.mutationCounts()
	res, err := rig.svc.RecoverTransfer(ctx, transfer.RecoverTransferRequest{CallBase: rig.callBase(nil), TransferID: id, PruneSuperseded: true})
	requireErrIs(t, err, transfer.ErrUncertainCommit, label+" RecoverTransfer")
	if !res.UncertainCommit || res.SelectedGen != expectGen || res.State == nil || res.State.Kind() != fsm.TransferKindUncertainCommit {
		t.Fatalf("%s 必须返回 TransferUncertainCommit(gen=%d): %+v", label, expectGen, res)
	}
	assertZeroJournalMutations(t, rig.journals, p0, d0, label)
	_, err = rig.svc.ResumeTransfer(ctx, transfer.ResumeTransferRequest{CallBase: rig.callBase(nil), TransferID: id, StartNextGen: true})
	requireErrIs(t, err, transfer.ErrUncertainCommit, label+" ResumeTransfer 必须拒绝")
	assertZeroJournalMutations(t, rig.journals, p0, d0, label+" after resume")
}

func assertZeroJournalMutations(t *testing.T, js *spyJournalStore, prevPrunes, prevDeletes int, label string) {
	t.Helper()
	p, d := js.mutationCounts()
	if p != prevPrunes || d != prevDeletes {
		t.Fatalf("%s 违反零副作用铁律: prunes %d->%d deletes %d->%d", label, prevPrunes, p, prevDeletes, d)
	}
}

func assertAuditContainsUnknownOutcome(t *testing.T, entries []ports.AuditEntry) {
	t.Helper()
	for _, e := range entries {
		if e.Phase() == ports.AuditPhaseFinalized && e.Outcome() == ports.AuditOutcomeUnknown {
			return
		}
	}
	t.Fatalf("审计日志缺少 AuditOutcomeUnknown 记录")
}

func mustOpID(t *testing.T, rig *transferTestRig) security.OperationID {
	t.Helper()
	id, err := security.NewOperationIDFrom(rig.rng)
	requireNoErr(t, err, "NewOperationIDFrom")
	return id
}

func seedHealthyGen(t *testing.T, rig *transferTestRig, dest fsm.TransferDest, gen, total uint64, toCommitStarted, toCommitted bool) security.OperationID {
	t.Helper()
	id := mustOpID(t, rig)
	seedGenWithID(t, rig, id, dest, gen, total, toCommitStarted, toCommitted)
	return id
}

func seedPartialGen(t *testing.T, rig *transferTestRig, id security.OperationID, dest fsm.TransferDest, gen, total uint64, toCommitStarted, toCommitted bool) {
	t.Helper()
	seedGenWithID(t, rig, id, dest, gen, total, toCommitStarted, toCommitted)
}

func seedGenWithID(t *testing.T, rig *transferTestRig, id security.OperationID, dest fsm.TransferDest, gen, total uint64, toCommitStarted, toCommitted bool) {
	t.Helper()
	meta, err := fsm.NewTransferMeta(fsm.TransferMetaSpec{TransferID: id, Dest: dest, TotalBytes: total, JournalVersion: fsm.JournalVersionV2, Generation: gen})
	requireNoErr(t, err, "NewTransferMeta")
	initSt, err := fsm.NewTransferState(meta)
	requireNoErr(t, err, "NewTransferState")
	st, effs, _, err := fsm.TransitionTransfer(initSt, fsm.TransferInputStart())
	requireNoErr(t, err, "Start")
	appendTestEffs(t, rig, effs)
	half := max(total/2, 1)
	if !toCommitStarted {
		in, iErr := fsm.TransferInputChunk(0, half, security.DigestBytes(make([]byte, half)))
		requireNoErr(t, iErr, "TransferInputChunk half")
		_, effs, _, err = fsm.TransitionTransfer(st, in)
		requireNoErr(t, err, "Transition half")
		appendTestEffs(t, rig, effs)
		return
	}
	inAll, err := fsm.TransferInputChunk(0, total, security.DigestBytes(make([]byte, total)))
	requireNoErr(t, err, "TransferInputChunk all")
	st, effs, _, err = fsm.TransitionTransfer(st, inAll)
	requireNoErr(t, err, "Transition all")
	appendTestEffs(t, rig, effs)
	vIn, err := fsm.TransferInputVerifyResult(true, security.DigestBytes(make([]byte, total)), "")
	requireNoErr(t, err, "TransferInputVerifyResult")
	st, effs, _, err = fsm.TransitionTransfer(st, vIn)
	requireNoErr(t, err, "Transition verify")
	appendTestEffs(t, rig, effs)
	if !toCommitted {
		return
	}
	cIn, err := fsm.TransferInputCommitResult(fsm.DurabilityCommitted, "ok")
	requireNoErr(t, err, "TransferInputCommitResult")
	_, effs, _, err = fsm.TransitionTransfer(st, cIn)
	requireNoErr(t, err, "Transition commit")
	appendTestEffs(t, rig, effs)
}

func appendTestEffs(t *testing.T, rig *transferTestRig, effs []fsm.TransferEffect) {
	t.Helper()
	for _, eff := range effs {
		if eff.Kind() == fsm.TransferEffectWriteJournal {
			rec, ok := eff.Record().Get()
			if !ok {
				t.Fatalf("missing journal record")
			}
			requireNoErr(t, rig.journals.inner.Append(context.Background(), rec), "Append test journal")
		}
	}
}
