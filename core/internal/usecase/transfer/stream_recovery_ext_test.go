package transfer_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
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
	if g2Info.Meta.Generation() != 2 || rig.pool.Stats().ActiveHandles != 1 {
		t.Fatalf("期望 generation=2 且旧代句柄已原子释放: gen=%d active=%d", g2Info.Meta.Generation(), rig.pool.Stats().ActiveHandles)
	}
	_, err = rig.svc.WriteTransferChunk(ctx, transfer.WriteTransferChunkRequest{CallBase: rig.callBase(nil), Handle: g1Info.Handle, Offset: 0, Data: []byte("1234")})
	requireErrIs(t, err, pool.ErrHandleNotFound, "StartNextGen=true 必须撤销旧代 g1 活跃句柄")
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

func TestResumeTransfer_INVE5AntiOracleOnExistingTasksAndRound2ProtectedPath(t *testing.T) {
	defer goleak.VerifyNone(t)
	denyRule, err := security.NewNodeOverrideRuleWithFloor("node-*", security.RiskDangerous, security.DecisionKindDeny)
	requireNoErr(t, err, "NewNodeOverrideRule")
	denyOvr, err := security.NewNodeOverrides(denyRule)
	requireNoErr(t, err, "NewNodeOverrides")
	rig := newTransferRig(t, rigOptions{
		profile: gate.PolicyProfileStrictAgent, approvalThresh: security.RiskDangerous,
		nodeOverrides: algebraic.Some(denyOvr), omitOperatorRead: true,
	})
	defer rig.close()
	ctx := context.Background()
	dest, err := fsm.NewUploadDest(mustRemotePath(t, "/tmp/oracle.bin"))
	requireNoErr(t, err, "dest")

	// 预置 5 种真实已存在任务态（Committed/Aborted/UncertainCommit/Corrupt/Streaming）
	idCommitted := seedHealthyGen(t, rig, dest, 1, 8, true, true)
	idUncertain := seedHealthyGen(t, rig, dest, 1, 8, true, false)
	idStreaming := seedHealthyGen(t, rig, dest, 1, 8, false, false)
	idCorrupt := mustOpID(t, rig)
	rig.journals.inner.CorruptGeneration(idCorrupt, 1, errors.New("corrupt"))
	idAborted := seedAbortedGen(t, rig, dest, 1, 8)

	sub, err := rig.bus.Subscribe()
	requireNoErr(t, err, "Subscribe bus")
	loadsBefore := rig.journals.loadGenCalls.Load()
	entriesBefore := len(rig.auditClust.Entries())

	for _, id := range []security.OperationID{idCommitted, idAborted, idUncertain, idCorrupt, idStreaming} {
		_, rErr := rig.svc.ResumeTransfer(ctx, transfer.ResumeTransferRequest{CallBase: rig.callBase(nil), TransferID: id})
		requireErrIs(t, rErr, gate.ErrAuthorizationDenied, "INV-E5：已存在任务被拒前严禁泄露存在性或状态")
	}
	sub.Close()
	if rig.journals.loadGenCalls.Load() != loadsBefore {
		t.Fatalf("Gate 拒绝前不应读取 JournalStore: before=%d after=%d", loadsBefore, rig.journals.loadGenCalls.Load())
	}
	assertNoTransferDiagnostics(t, sub)
	if !hasAuditOutcomeSince(rig.auditClust.Entries()[entriesBefore:], ports.AuditOutcomeDenied) {
		t.Fatalf("审计日志缺少 AuditOutcomeDenied 记录")
	}

	// 允许节点但持久化目标经软链指向 /etc -> Round-2 makeResumeCanonicalizer 必须拦截
	strictRig := newTransferRig(t, rigOptions{profile: gate.PolicyProfileStrictAgent, approvalThresh: security.RiskDangerous, omitOperatorRead: true})
	defer strictRig.close()
	requireNoErr(t, strictRig.remoteFS.MkdirAll(ctx, mustRemotePath(t, "/tmp"), 0o755), "MkdirAll /tmp")
	requireNoErr(t, strictRig.remoteFS.PutSymlink(mustRemotePath(t, "/tmp/res_link"), "/etc"), "PutSymlink /tmp/res_link")
	escDest, err := fsm.NewUploadDest(mustRemotePath(t, "/tmp/res_link/pwn.conf"))
	requireNoErr(t, err, "escDest")
	escID := seedHealthyGen(t, strictRig, escDest, 1, 8, false, false)
	_, err = strictRig.svc.ResumeTransfer(ctx, transfer.ResumeTransferRequest{CallBase: strictRig.callBase(nil), TransferID: escID})
	requireErrIs(t, err, gate.ErrApprovalRequired, "ResumeTransfer Round-2 必须拦截经软链指向 /etc 的持久化目标")
}

func TestRecovery_UncertainCommitOutcomeUnknownAuditAndHealthyLowerCommitStarted(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newTransferRig(t, rigOptions{omitOperatorRead: true})
	defer rig.close()
	ctx := context.Background()
	dest, err := fsm.NewUploadDest(mustRemotePath(t, "/unc/audit.bin"))
	requireNoErr(t, err, "dest")

	// 1. 健康 gen 1 悬停于 CommitStarted + 损坏 gen 2（无提交标记）-> 须判 ErrUncertainCommit（非 ErrCorruptJournal）
	idMix := seedHealthyGen(t, rig, dest, 1, 8, true, false)
	seedPartialGen(t, rig, idMix, dest, 2, 8, false, false)
	rig.journals.inner.CorruptGeneration(idMix, 2, errors.New("gen 2 tail corrupt"))

	// RecoverTransfer 必须记录 AuditOutcomeUnknown 且 OperationCompletedEvent 投影 OutcomeKindUnknown
	beforeRec := len(rig.auditClust.Entries())
	stRec := mustNewOpStream(t, rig.rng)
	res, err := rig.svc.RecoverTransfer(ctx, transfer.RecoverTransferRequest{CallBase: rig.callBase(stRec), TransferID: idMix, PruneSuperseded: true})
	requireErrIs(t, err, transfer.ErrUncertainCommit, "健康低代 CommitStarted + 损坏高代须判 ErrUncertainCommit")
	if !res.UncertainCommit || res.SelectedGen != 1 {
		t.Fatalf("应选中 UncertainCommit gen=1: %+v", res)
	}
	if !hasAuditOutcomeSince(rig.auditClust.Entries()[beforeRec:], ports.AuditOutcomeUnknown) {
		t.Fatalf("RecoverTransfer 命中 UncertainCommit 必须写入 AuditOutcomeUnknown")
	}
	assertStreamCompletedOutcomeKind(t, drainOpStream(t, stRec), execution.OutcomeKindUnknown)

	// ResumeTransfer 同样必须记录 AuditOutcomeUnknown 且投影 OutcomeKindUnknown
	beforeRes := len(rig.auditClust.Entries())
	stRes := mustNewOpStream(t, rig.rng)
	_, err = rig.svc.ResumeTransfer(ctx, transfer.ResumeTransferRequest{CallBase: rig.callBase(stRes), TransferID: idMix})
	requireErrIs(t, err, transfer.ErrUncertainCommit, "ResumeTransfer 命中 UncertainCommit 须返回 ErrUncertainCommit")
	if !hasAuditOutcomeSince(rig.auditClust.Entries()[beforeRes:], ports.AuditOutcomeUnknown) {
		t.Fatalf("ResumeTransfer 命中 UncertainCommit 必须写入 AuditOutcomeUnknown")
	}
	assertStreamCompletedOutcomeKind(t, drainOpStream(t, stRes), execution.OutcomeKindUnknown)
}

func TestTransferAdmission_GenerationLockDuplicateIDAndLiveHandleMutex(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newTransferRig(t, rigOptions{omitOperatorRead: true})
	defer rig.close()
	ctx := context.Background()
	requireNoErr(t, rig.remoteFS.MkdirAll(ctx, mustRemotePath(t, "/adm"), 0o755), "MkdirAll /adm")
	dest, err := fsm.NewUploadDest(mustRemotePath(t, "/adm/f.bin"))
	requireNoErr(t, err, "dest")

	// 1. StartTransfer 锁定起始 Generation=1，拒绝 Generation > 1
	_, err = rig.svc.StartTransfer(ctx, transfer.StartTransferRequest{CallBase: rig.callBase(nil), Dest: dest, TotalBytes: 4, Generation: 2})
	requireErrIs(t, err, transfer.ErrInvalidRequest, "StartTransfer 禁止指定 Generation > 1")

	// 2. 已存在 Committed / UncertainCommit 的 TransferID 禁止重复 StartTransfer
	idCom := seedHealthyGen(t, rig, dest, 1, 4, true, true)
	idUnc := seedHealthyGen(t, rig, dest, 1, 4, true, false)
	for _, existingID := range []security.OperationID{idCom, idUnc} {
		_, err = rig.svc.StartTransfer(ctx, transfer.StartTransferRequest{
			CallBase: rig.callBase(nil), TransferID: algebraic.Some(existingID), Dest: dest, TotalBytes: 4,
		})
		requireErrIs(t, err, ports.ErrAlreadyExists, "已落盘 TransferID 禁止重复 StartTransfer")
	}

	// 3. 活跃句柄存在时，重复 StartTransfer 与同代 ResumeTransfer(StartNextGen=false) 均须拒绝
	liveID := mustOpID(t, rig)
	info, err := rig.svc.StartTransfer(ctx, transfer.StartTransferRequest{
		CallBase: rig.callBase(nil), TransferID: algebraic.Some(liveID), Dest: dest, TotalBytes: 4,
	})
	requireNoErr(t, err, "StartTransfer live")
	_, err = rig.svc.StartTransfer(ctx, transfer.StartTransferRequest{
		CallBase: rig.callBase(nil), TransferID: algebraic.Some(liveID), Dest: dest, TotalBytes: 4,
	})
	requireErrIs(t, err, ports.ErrAlreadyExists, "活跃句柄存在时禁止重复 StartTransfer")
	_, err = rig.svc.ResumeTransfer(ctx, transfer.ResumeTransferRequest{
		CallBase: rig.callBase(nil), TransferID: liveID, StartNextGen: false,
	})
	requireErrIs(t, err, ports.ErrAlreadyExists, "同代句柄活跃时禁止双活 ResumeTransfer")
	requireNoErr(t, rig.svc.AbortTransfer(ctx, transfer.AbortTransferRequest{CallBase: rig.callBase(nil), Handle: info.Handle, Reason: "cleanup"}), "cleanup abort")
}

func TestTransferRegister_AuditPostWriteErrorRollsBackHandle(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newTransferRig(t, rigOptions{profile: gate.PolicyProfileDirectOperator, omitOperatorRead: true})
	defer rig.close()
	ctx := context.Background()
	dest, err := fsm.NewUploadDest(mustRemotePath(t, "/rb/out.bin"))
	requireNoErr(t, err, "dest")

	// 1. StartTransfer 遭遇 AuditPostWriteError 时回滚释放句柄并返回零 TransferHandleInfo
	rig.auditSink.SetBoundaryHook(func(b sim.AuditBoundary, _ security.OperationID) {
		if b == sim.AuditBoundaryAfterAuthorized {
			rig.auditClust.SetENOSPC(true)
		}
	})
	info, err := rig.svc.StartTransfer(ctx, transfer.StartTransferRequest{CallBase: rig.callBase(nil), Dest: dest, TotalBytes: 4})
	rig.auditSink.SetBoundaryHook(nil)
	rig.auditClust.SetENOSPC(false)
	requireErrIs(t, err, ports.ErrAuditPostWrite, "StartTransfer 终态审计失败须返回 ErrAuditPostWrite")
	if info.Handle.IsValid() || rig.pool.Stats().ActiveHandles != 0 {
		t.Fatalf("StartTransfer 审计失败必须回滚句柄并返回零值: handleValid=%v active=%d", info.Handle.IsValid(), rig.pool.Stats().ActiveHandles)
	}

	// 2. ResumeTransfer 遭遇 AuditPostWriteError 同样回滚释放句柄并返回零值
	resumeID := seedHealthyGen(t, rig, dest, 1, 4, false, false)
	rig.auditSink.SetBoundaryHook(func(b sim.AuditBoundary, _ security.OperationID) {
		if b == sim.AuditBoundaryAfterAuthorized {
			rig.auditClust.SetENOSPC(true)
		}
	})
	resInfo, err := rig.svc.ResumeTransfer(ctx, transfer.ResumeTransferRequest{CallBase: rig.callBase(nil), TransferID: resumeID})
	rig.auditSink.SetBoundaryHook(nil)
	rig.auditClust.SetENOSPC(false)
	requireErrIs(t, err, ports.ErrAuditPostWrite, "ResumeTransfer 终态审计失败须返回 ErrAuditPostWrite")
	if resInfo.Handle.IsValid() || rig.pool.Stats().ActiveHandles != 0 {
		t.Fatalf("ResumeTransfer 审计失败必须回滚句柄并返回零值: handleValid=%v active=%d", resInfo.Handle.IsValid(), rig.pool.Stats().ActiveHandles)
	}
}

func TestCommitTransfer_TransientVerifyPartialWALAndCommittedWALUncertainState(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newTransferRig(t, rigOptions{omitOperatorRead: true})
	defer rig.close()
	ctx := context.Background()
	requireNoErr(t, rig.remoteFS.MkdirAll(ctx, mustRemotePath(t, "/cm"), 0o755), "MkdirAll /cm")

	// 1. 瞬态核验失败保留 Verifying 与暂存，重连后 CommitTransfer 可成功；2. Verified 后 CommitStarted WAL 失败释放句柄可同代恢复
	assertTransientVerifyAndPartialWALRecovery(t, rig)

	// 3. Committed WAL 写盘失败 -> 确定性转 *fsm.TransferUncertainCommit + FSM 事件 + AuditOutcomeUnknown
	dest3, err := fsm.NewUploadDest(mustRemotePath(t, "/cm/cwal.bin"))
	requireNoErr(t, err, "dest3")
	info3, err := rig.svc.StartTransfer(ctx, transfer.StartTransferRequest{CallBase: rig.callBase(nil), Dest: dest3, TotalBytes: 4})
	requireNoErr(t, err, "start3")
	_, err = rig.svc.WriteTransferChunk(ctx, transfer.WriteTransferChunkRequest{CallBase: rig.callBase(nil), Handle: info3.Handle, Offset: 0, Data: []byte("abcd")})
	requireNoErr(t, err, "write3")
	rig.journals.mu.Lock()
	rig.journals.failOnAppendKind, rig.journals.appendErr = fsm.JournalRecordCommitted, errors.New("disk full")
	rig.journals.mu.Unlock()
	beforeAud := len(rig.auditClust.Entries())
	stCom := mustNewOpStream(t, rig.rng)
	comRes, err := rig.svc.CommitTransfer(ctx, transfer.CommitTransferRequest{CallBase: rig.callBase(stCom), Handle: info3.Handle})
	rig.journals.mu.Lock()
	rig.journals.appendErr = nil
	rig.journals.mu.Unlock()
	requireErrIs(t, err, transfer.ErrUncertainCommit, "Committed WAL 写盘失败须返回 ErrUncertainCommit")
	if comRes.State == nil || comRes.State.Kind() != fsm.TransferKindUncertainCommit {
		t.Fatalf("Committed WAL 失败必须确定性转 TransferUncertainCommit，实际=%+v", comRes.State)
	}
	if !hasAuditOutcomeSince(rig.auditClust.Entries()[beforeAud:], ports.AuditOutcomeUnknown) {
		t.Fatalf("Committed WAL 失败必须写入 AuditOutcomeUnknown")
	}
	evs := drainOpStream(t, stCom)
	assertStreamCompletedOutcomeKind(t, evs, execution.OutcomeKindUnknown)
	assertStreamHasTransferState(t, evs, fsm.TransferKindUncertainCommit)
}

func assertTransientVerifyAndPartialWALRecovery(t *testing.T, rig *transferTestRig) {
	t.Helper()
	ctx := context.Background()
	dest, err := fsm.NewUploadDest(mustRemotePath(t, "/cm/tv.bin"))
	requireNoErr(t, err, "dest")
	info, err := rig.svc.StartTransfer(ctx, transfer.StartTransferRequest{CallBase: rig.callBase(nil), Dest: dest, TotalBytes: 4})
	requireNoErr(t, err, "start")
	_, err = rig.svc.WriteTransferChunk(ctx, transfer.WriteTransferChunkRequest{CallBase: rig.callBase(nil), Handle: info.Handle, Offset: 0, Data: []byte("1234")})
	requireNoErr(t, err, "write")
	// 吊销并恢复使 hasher=nil（触发远端回读 verifyStagedDigest）
	hopDig, _ := rig.plan.HopDigestAt(0)
	requireNoErr(t, rig.pool.RetireHop(hopDig), "RetireHop")
	resumed, err := rig.svc.ResumeTransfer(ctx, transfer.ResumeTransferRequest{CallBase: rig.callBase(nil), TransferID: info.TransferID})
	requireNoErr(t, err, "ResumeTransfer")

	rig.dialer.mu.Lock()
	rig.dialer.onReadChunk = func(context.Context, pathalg.RemotePath, int64, int64) error { return ports.ErrClosed }
	rig.dialer.mu.Unlock()
	_, err = rig.svc.CommitTransfer(ctx, transfer.CommitTransferRequest{CallBase: rig.callBase(nil), Handle: resumed.Handle})
	requireErrIs(t, err, ports.ErrClosed, "瞬态读盘失败须原样返回且不中止")
	rig.dialer.mu.Lock()
	rig.dialer.onReadChunk = nil
	rig.dialer.mu.Unlock()
	snap, err := rig.svc.InspectTransfer(ctx, transfer.InspectTransferRequest{CallBase: rig.callBase(nil), TransferID: info.TransferID})
	requireNoErr(t, err, "InspectTransfer after transient verify error")
	if !snap.LiveHandle || snap.StateKind != fsm.TransferKindVerifying {
		t.Fatalf("瞬态核验失败必须保留 Verifying 与活跃句柄: %+v", snap)
	}

	// 在 Verified 落盘后的 CommitStarted 追加处失败 -> 释放句柄防内存 nextSeq 漂移 -> 恢复并重试 CommitTransfer 成功
	rig.journals.mu.Lock()
	rig.journals.failOnAppendKind, rig.journals.appendErr = fsm.JournalRecordCommitStarted, errors.New("wal transient")
	rig.journals.mu.Unlock()
	_, err = rig.svc.CommitTransfer(ctx, transfer.CommitTransferRequest{CallBase: rig.callBase(nil), Handle: resumed.Handle})
	rig.journals.mu.Lock()
	rig.journals.appendErr = nil
	rig.journals.mu.Unlock()
	if err == nil || rig.pool.Stats().ActiveHandles != 0 {
		t.Fatalf("部分 WAL 落盘失败必须返回错误并释放句柄: err=%v active=%d", err, rig.pool.Stats().ActiveHandles)
	}
	resumed2, err := rig.svc.ResumeTransfer(ctx, transfer.ResumeTransferRequest{CallBase: rig.callBase(nil), TransferID: info.TransferID})
	requireNoErr(t, err, "ResumeTransfer after partial WAL")
	com2, err := rig.svc.CommitTransfer(ctx, transfer.CommitTransferRequest{CallBase: rig.callBase(nil), Handle: resumed2.Handle})
	requireNoErr(t, err, "CommitTransfer retry after partial WAL")
	if com2.State.Kind() != fsm.TransferKindCommitted || string(mustReadRemote(t, rig.remoteFS, "/cm/tv.bin")) != "1234" {
		t.Fatalf("恢复后重试提交失败: %+v", com2)
	}
}

func TestStreamTransfer_CrossRequestSymlinkDriftAndEnrichedAuditParams(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newTransferRig(t, rigOptions{profile: gate.PolicyProfileStrictAgent, approvalThresh: security.RiskDangerous, omitOperatorRead: true})
	defer rig.close()
	ctx := context.Background()
	requireNoErr(t, rig.remoteFS.MkdirAll(ctx, mustRemotePath(t, "/tmp/drift1"), 0o755), "MkdirAll drift1")
	requireNoErr(t, rig.remoteFS.MkdirAll(ctx, mustRemotePath(t, "/tmp/drift2"), 0o755), "MkdirAll drift2")
	requireNoErr(t, rig.remoteFS.MkdirAll(ctx, mustRemotePath(t, "/etc"), 0o755), "MkdirAll /etc")

	// 1. WriteTransferChunk 前将父目录替换为指向 /etc 的软链 -> ErrScopeEscalated 且 0 远端写分片
	dest1, err := fsm.NewUploadDest(mustRemotePath(t, "/tmp/drift1/a.bin"))
	requireNoErr(t, err, "dest1")
	info1, err := rig.svc.StartTransfer(ctx, transfer.StartTransferRequest{CallBase: rig.callBase(nil), Dest: dest1, TotalBytes: 4})
	requireNoErr(t, err, "start1")
	requireNoErr(t, rig.remoteFS.RemoveDir(ctx, mustRemotePath(t, "/tmp/drift1")), "rm drift1")
	requireNoErr(t, rig.remoteFS.PutSymlink(mustRemotePath(t, "/tmp/drift1"), "/etc"), "symlink drift1->/etc")
	var chunkWrites atomic.Int64
	rig.dialer.mu.Lock()
	rig.dialer.onWriteChunk = func(context.Context, pathalg.RemotePath, int64, int64) error { chunkWrites.Add(1); return nil }
	rig.dialer.mu.Unlock()
	beforeW := len(rig.auditClust.Entries())
	_, err = rig.svc.WriteTransferChunk(ctx, transfer.WriteTransferChunkRequest{CallBase: rig.callBase(nil), Handle: info1.Handle, Offset: 0, Data: []byte("evil")})
	rig.dialer.mu.Lock()
	rig.dialer.onWriteChunk = nil
	rig.dialer.mu.Unlock()
	requireErrIs(t, err, gate.ErrScopeEscalated, "WriteTransferChunk 跨请求软链漂移必须返回 ErrScopeEscalated")
	if chunkWrites.Load() != 0 {
		t.Fatalf("漂移拦截后不得调用远端 WriteChunk，实际=%d", chunkWrites.Load())
	}
	assertAuditParamsContainTransferID(t, rig.auditClust.Entries()[beforeW:], info1.TransferID.String())
	requireNoErr(t, rig.svc.AbortTransfer(ctx, transfer.AbortTransferRequest{CallBase: rig.callBase(nil), Handle: info1.Handle, Reason: "drift"}), "abort1")

	// 2. CommitTransfer 前将父目录替换为指向 /etc 的软链 -> ErrScopeEscalated(DurabilityNotApplied) 转 Aborted，0 重命名进 /etc
	dest2, err := fsm.NewUploadDest(mustRemotePath(t, "/tmp/drift2/b.bin"))
	requireNoErr(t, err, "dest2")
	info2, err := rig.svc.StartTransfer(ctx, transfer.StartTransferRequest{CallBase: rig.callBase(nil), Dest: dest2, TotalBytes: 4})
	requireNoErr(t, err, "start2")
	_, err = rig.svc.WriteTransferChunk(ctx, transfer.WriteTransferChunkRequest{CallBase: rig.callBase(nil), Handle: info2.Handle, Offset: 0, Data: []byte("abcd")})
	requireNoErr(t, err, "write2")
	// 先留出暂存外路径，再将 /tmp/drift2 目录换为软链（SimRemoteFS 要求空目录，故直接给目标文件位置放软链 /tmp/drift2/b.bin -> /etc/b.bin）
	requireNoErr(t, rig.remoteFS.PutSymlink(mustRemotePath(t, "/tmp/drift2/b.bin"), "/etc/b.bin"), "symlink b.bin->/etc/b.bin")
	com2, err := rig.svc.CommitTransfer(ctx, transfer.CommitTransferRequest{CallBase: rig.callBase(nil), Handle: info2.Handle})
	requireErrIs(t, err, gate.ErrScopeEscalated, "CommitTransfer 跨请求软链漂移必须返回 ErrScopeEscalated")
	if com2.State == nil || com2.State.Kind() != fsm.TransferKindAborted {
		t.Fatalf("CommitTransfer 漂移拦截应按 DurabilityNotApplied 转 Aborted: %+v", com2)
	}
	if _, sErr := rig.remoteFS.Lstat(ctx, mustRemotePath(t, "/etc/b.bin")); sErr == nil {
		t.Fatalf("/etc/b.bin 不得被写入")
	}
}

func seedAbortedGen(t *testing.T, rig *transferTestRig, dest fsm.TransferDest, gen, total uint64) security.OperationID {
	t.Helper()
	id := mustOpID(t, rig)
	meta, err := fsm.NewTransferMeta(fsm.TransferMetaSpec{TransferID: id, Dest: dest, TotalBytes: total, JournalVersion: fsm.JournalVersionV2, Generation: gen})
	requireNoErr(t, err, "meta")
	initSt, err := fsm.NewTransferState(meta)
	requireNoErr(t, err, "initSt")
	st, effs, _, err := fsm.TransitionTransfer(initSt, fsm.TransferInputStart())
	requireNoErr(t, err, "start")
	appendTestEffs(t, rig, effs)
	_, effs, _, err = fsm.TransitionTransfer(st, fsm.TransferInputAbort("seeded"))
	requireNoErr(t, err, "abort")
	appendTestEffs(t, rig, effs)
	return id
}

func hasAuditOutcomeSince(entries []ports.AuditEntry, want ports.AuditOutcome) bool {
	for _, e := range entries {
		if e.Outcome() == want {
			return true
		}
	}
	return false
}

func assertAuditParamsContainTransferID(t *testing.T, entries []ports.AuditEntry, wantID string) {
	t.Helper()
	for _, e := range entries {
		if e.Binding().Parameters()["transfer_id"] == wantID {
			return
		}
	}
	t.Fatalf("审计记录缺少 transfer_id=%s 参数上下文", wantID)
}

func assertStreamCompletedOutcomeKind(t *testing.T, evs []events.Event, want execution.OutcomeKind) {
	t.Helper()
	for _, ev := range evs {
		if c, ok := ev.(*events.OperationCompletedEvent); ok {
			out, has := c.Outcome().Get()
			if !has || out.Kind() != want {
				t.Fatalf("OperationCompletedEvent.Outcome=%v(has=%v), want %s", out, has, want)
			}
			return
		}
	}
	t.Fatalf("事件流缺少 OperationCompletedEvent")
}

func assertStreamHasTransferState(t *testing.T, evs []events.Event, want fsm.TransferStateKind) {
	t.Helper()
	for _, ev := range evs {
		if f, ok := ev.(*events.FSMTransitionEvent); ok && f.ToState() == want.String() {
			return
		}
	}
	t.Fatalf("事件流缺少目标状态 %s 的 FSMTransitionEvent", want)
}

func assertNoTransferDiagnostics(t *testing.T, sub *events.SystemSubscription) {
	t.Helper()
	for {
		ev, ok, err := sub.Next(context.Background())
		requireNoErr(t, err, "SystemSubscription.Next")
		if !ok {
			return
		}
		if d, ok := ev.(*events.DiagnosticEvent); ok && d.Scope() == events.DiagnosticScopeTransfer {
			t.Fatalf("Gate 拒绝前不应向 SystemBus 发射 transfer 诊断事件: code=%s msg=%s", d.Code(), d.Message())
		}
	}
}

func TestStreamTransfer_TwoStepApprovalWithoutTransferIDAndConsistentAuditParams(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newTransferRig(t, rigOptions{
		profile:          gate.PolicyProfileStrictAgent,
		approvalThresh:   security.RiskDangerous,
		fallback:         gate.NoElicitFallbackChallenge,
		omitOperatorRead: true,
	})
	defer rig.close()
	ctx := context.Background()
	requireNoErr(t, rig.remoteFS.MkdirAll(ctx, mustRemotePath(t, "/etc"), 0o755), "MkdirAll /etc")
	requireNoErr(t, rig.remoteFS.MkdirAll(ctx, mustRemotePath(t, "/tmp"), 0o755), "MkdirAll /tmp")

	// 1. TransferID=None 指向受保护 /etc/approved.bin -> 首轮发 Challenge，次轮携带 ApprovalSubmission 复验精确匹配通过
	dest, err := fsm.NewUploadDest(mustRemotePath(t, "/etc/approved.bin"))
	requireNoErr(t, err, "NewUploadDest")
	baseReq := transfer.StartTransferRequest{CallBase: rig.callBase(nil), Dest: dest, TotalBytes: 4}
	_, err = rig.svc.StartTransfer(ctx, baseReq)
	var chErr *gate.ApprovalChallengeError
	if !errors.As(err, &chErr) {
		t.Fatalf("首轮 StartTransfer(TransferID=None) 应返回 ApprovalChallengeError，实际=%v", err)
	}
	resp, err := ports.NewApprovalDecisionResponse(security.VerdictAllow, chErr.EnvelopeDigest(), "approved")
	requireNoErr(t, err, "NewApprovalDecisionResponse")
	sub, err := gate.NewApprovalSubmission(gate.ApprovalSubmissionSpec{Envelope: algebraic.Some(chErr.Envelope()), Response: resp})
	requireNoErr(t, err, "NewApprovalSubmission")

	approvedReq := baseReq
	approvedReq.Approval = algebraic.Some(sub)
	info, err := rig.svc.StartTransfer(ctx, approvedReq)
	requireNoErr(t, err, "携带 ApprovalSubmission 重试 StartTransfer(TransferID=None) 必须成功")
	if !info.TransferID.IsValid() || !info.Handle.IsValid() {
		t.Fatalf("受权后句柄与 TransferID 必须有效: %+v", info)
	}
	beforeWrite := len(rig.auditClust.Entries())
	_, err = rig.svc.WriteTransferChunk(ctx, transfer.WriteTransferChunkRequest{CallBase: rig.callBase(nil), Handle: info.Handle, Offset: 0, Data: []byte("okay")})
	requireNoErr(t, err, "WriteTransferChunk after 2-step approval")
	_, err = rig.svc.CommitTransfer(ctx, transfer.CommitTransferRequest{CallBase: rig.callBase(nil), Handle: info.Handle})
	requireNoErr(t, err, "CommitTransfer after 2-step approval")
	if string(mustReadRemote(t, rig.remoteFS, "/etc/approved.bin")) != "okay" {
		t.Fatalf("两步审批后远端文件内容不符")
	}
	assertAuditParamsContainTransferMeta(t, rig.auditClust.Entries()[beforeWrite:], info.TransferID.String(), "upload", dest.String())

	// 2. StrictAgent 下 ResumeTransfer 经 Round-2 发现持久化目标并触发两步审批，审批通过登记句柄后，
	// 后续句柄操作审计参数同样携带一致的 transfer_id / direction / target。
	resDest, err := fsm.NewUploadDest(mustRemotePath(t, "/tmp/res_params.bin"))
	requireNoErr(t, err, "resDest")
	resID := seedHealthyGen(t, rig, resDest, 1, 8, false, false)
	resReq := transfer.ResumeTransferRequest{CallBase: rig.callBase(nil), TransferID: resID}
	_, err = rig.svc.ResumeTransfer(ctx, resReq)
	var resChErr *gate.ApprovalChallengeError
	if !errors.As(err, &resChErr) {
		t.Fatalf("StrictAgent 首轮 ResumeTransfer 应触发 Round-2 ApprovalChallengeError，实际=%v", err)
	}
	resResp, err := ports.NewApprovalDecisionResponse(security.VerdictAllow, resChErr.EnvelopeDigest(), "approved-resume")
	requireNoErr(t, err, "NewApprovalDecisionResponse resume")
	resSub, err := gate.NewApprovalSubmission(gate.ApprovalSubmissionSpec{Envelope: algebraic.Some(resChErr.Envelope()), Response: resResp})
	requireNoErr(t, err, "NewApprovalSubmission resume")
	resReq.Approval = algebraic.Some(resSub)
	resInfo, err := rig.svc.ResumeTransfer(ctx, resReq)
	requireNoErr(t, err, "携带 ApprovalSubmission 重试 ResumeTransfer 必须成功")
	beforeResOp := len(rig.auditClust.Entries())
	requireNoErr(t, rig.svc.AbortTransfer(ctx, transfer.AbortTransferRequest{CallBase: rig.callBase(nil), Handle: resInfo.Handle, Reason: "audit-check"}), "AbortTransfer")
	assertAuditParamsContainTransferMeta(t, rig.auditClust.Entries()[beforeResOp:], resID.String(), "upload", resDest.String())
}

func assertAuditParamsContainTransferMeta(t *testing.T, entries []ports.AuditEntry, wantID, wantDir, wantTarget string) {
	t.Helper()
	for _, e := range entries {
		p := e.Binding().Parameters()
		if p["transfer_id"] == wantID && p["direction"] == wantDir && p["target"] == wantTarget {
			return
		}
	}
	t.Fatalf("审计记录缺少完整传输上下文: transfer_id=%s direction=%s target=%s", wantID, wantDir, wantTarget)
}

func TestStreamDownload_LstatSymlinkRejectAndCrossRequestDriftAndAnchorPinning(t *testing.T) {
	defer goleak.VerifyNone(t)
	assertStreamDownloadSymlinkRejectAndDrift(t)
	assertStreamDownloadAnchorMismatchPullAndCommit(t)
}

func assertStreamDownloadSymlinkRejectAndDrift(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	// 1. DirectOperator 下 StartTransfer(Download) 经 Lstat 拒绝软链源（不跟随软链读取 /etc/shadow）
	opRig := newTransferRig(t, rigOptions{omitOperatorRead: true})
	defer opRig.close()
	mustWriteRemote(t, opRig.remoteFS, "/etc/shadow", []byte("root:secret"))
	requireNoErr(t, opRig.remoteFS.MkdirAll(ctx, mustRemotePath(t, "/tmp"), 0o755), "MkdirAll /tmp")
	requireNoErr(t, opRig.remoteFS.PutSymlink(mustRemotePath(t, "/tmp/sym_src"), "/etc/shadow"), "PutSymlink sym_src")
	dlDest, err := fsm.NewDownloadDest(mustLocalDest(t, "stream/sym.bin"))
	requireNoErr(t, err, "NewDownloadDest")
	_, err = opRig.svc.StartTransfer(ctx, transfer.StartTransferRequest{
		CallBase: opRig.callBase(nil), Dest: dlDest,
		TransferSessionOptions: transfer.TransferSessionOptions{
			LocalRoot: algebraic.Some(opRig.localRoot), RemoteSource: algebraic.Some(mustRemotePath(t, "/tmp/sym_src")),
		},
	})
	requireErrIs(t, err, ports.ErrSymlinkRejected, "StartTransfer(Download) 必须经 Lstat 拒绝软链源")

	// 2. StrictAgent 下 StartTransfer 后将远端文件替换为指向 /etc/shadow 的软链 -> PullTransferChunk 返回 ErrScopeEscalated 且 0 读分片
	strictRig := newTransferRig(t, rigOptions{profile: gate.PolicyProfileStrictAgent, approvalThresh: security.RiskDangerous, omitOperatorRead: true})
	defer strictRig.close()
	srcPath := mustRemotePath(t, "/tmp/pub/a.bin")
	mustWriteRemote(t, strictRig.remoteFS, srcPath.String(), []byte("12345678"))
	mustWriteRemote(t, strictRig.remoteFS, "/etc/shadow", []byte("root:secret"))
	dlDestA, err := fsm.NewDownloadDest(mustLocalDest(t, "stream/a.bin"))
	requireNoErr(t, err, "dlDestA")
	info, err := strictRig.svc.StartTransfer(ctx, transfer.StartTransferRequest{
		CallBase: strictRig.callBase(nil), Dest: dlDestA,
		TransferSessionOptions: transfer.TransferSessionOptions{
			LocalRoot: algebraic.Some(strictRig.localRoot), RemoteSource: algebraic.Some(srcPath),
		},
	})
	requireNoErr(t, err, "StartTransfer download a.bin")
	requireNoErr(t, strictRig.remoteFS.Remove(ctx, srcPath), "remove a.bin")
	requireNoErr(t, strictRig.remoteFS.PutSymlink(srcPath, "/etc/shadow"), "swap a.bin->/etc/shadow")
	var readCalls atomic.Int64
	strictRig.dialer.mu.Lock()
	strictRig.dialer.onReadChunk = func(context.Context, pathalg.RemotePath, int64, int64) error { readCalls.Add(1); return nil }
	strictRig.dialer.mu.Unlock()
	_, err = strictRig.svc.PullTransferChunk(ctx, transfer.PullTransferChunkRequest{CallBase: strictRig.callBase(nil), Handle: info.Handle, MaxChunkBytes: 4})
	strictRig.dialer.mu.Lock()
	strictRig.dialer.onReadChunk = nil
	strictRig.dialer.mu.Unlock()
	requireErrIs(t, err, gate.ErrScopeEscalated, "PullTransferChunk 跨请求软链漂移必须返回 ErrScopeEscalated")
	if readCalls.Load() != 0 {
		t.Fatalf("漂移拦截后不得读取远端分片，实际=%d", readCalls.Load())
	}
	requireNoErr(t, strictRig.svc.AbortTransfer(ctx, transfer.AbortTransferRequest{CallBase: strictRig.callBase(nil), Handle: info.Handle, Reason: "cleanup"}), "abort drift")
}

func assertStreamDownloadAnchorMismatchPullAndCommit(t *testing.T) {
	t.Helper()
	rig := newTransferRig(t, rigOptions{omitOperatorRead: true})
	defer rig.close()
	ctx := context.Background()

	// 1. 拉取首片后远端源文件被同大小覆写（新 inode/anchor）-> 下次 PullTransferChunk 必须返回 ErrRemoteAnchorMismatch
	srcB := mustRemotePath(t, "/tmp/pub/b.bin")
	mustWriteRemote(t, rig.remoteFS, srcB.String(), []byte("12345678"))
	dlB, err := fsm.NewDownloadDest(mustLocalDest(t, "stream/b.bin"))
	requireNoErr(t, err, "dlB")
	infoB, err := rig.svc.StartTransfer(ctx, transfer.StartTransferRequest{
		CallBase: rig.callBase(nil), Dest: dlB,
		TransferSessionOptions: transfer.TransferSessionOptions{LocalRoot: algebraic.Some(rig.localRoot), RemoteSource: algebraic.Some(srcB)},
	})
	requireNoErr(t, err, "start b.bin")
	_, err = rig.svc.PullTransferChunk(ctx, transfer.PullTransferChunkRequest{CallBase: rig.callBase(nil), Handle: infoB.Handle, MaxChunkBytes: 4})
	requireNoErr(t, err, "pull b.bin first half")
	mustWriteRemote(t, rig.remoteFS, srcB.String(), []byte("ABCD5678"))
	_, err = rig.svc.PullTransferChunk(ctx, transfer.PullTransferChunkRequest{CallBase: rig.callBase(nil), Handle: infoB.Handle, MaxChunkBytes: 4})
	requireErrIs(t, err, ports.ErrRemoteAnchorMismatch, "拉片间隙远端换源必须触发 ErrRemoteAnchorMismatch")
	requireNoErr(t, rig.svc.AbortTransfer(ctx, transfer.AbortTransferRequest{CallBase: rig.callBase(nil), Handle: infoB.Handle, Reason: "anchor-drift"}), "abort b.bin")

	// 2. 拉完全部分片进入 Verifying 后远端换源 -> CommitTransfer 必须在 root.Rename 前阻断并按 DurabilityNotApplied 转 Aborted
	srcC := mustRemotePath(t, "/tmp/pub/c.bin")
	mustWriteRemote(t, rig.remoteFS, srcC.String(), []byte("12345678"))
	dlC, err := fsm.NewDownloadDest(mustLocalDest(t, "stream/c.bin"))
	requireNoErr(t, err, "dlC")
	infoC, err := rig.svc.StartTransfer(ctx, transfer.StartTransferRequest{
		CallBase: rig.callBase(nil), Dest: dlC,
		TransferSessionOptions: transfer.TransferSessionOptions{LocalRoot: algebraic.Some(rig.localRoot), RemoteSource: algebraic.Some(srcC)},
	})
	requireNoErr(t, err, "start c.bin")
	pRes, err := rig.svc.PullTransferChunk(ctx, transfer.PullTransferChunkRequest{CallBase: rig.callBase(nil), Handle: infoC.Handle, MaxChunkBytes: 8})
	requireNoErr(t, err, "pull c.bin all")
	if pRes.StateKind != fsm.TransferKindVerifying {
		t.Fatalf("应进入 Verifying，实际=%s", pRes.StateKind)
	}
	mustWriteRemote(t, rig.remoteFS, srcC.String(), []byte("ZZZZZZZZ"))
	comC, err := rig.svc.CommitTransfer(ctx, transfer.CommitTransferRequest{CallBase: rig.callBase(nil), Handle: infoC.Handle})
	requireErrIs(t, err, ports.ErrRemoteAnchorMismatch, "CommitTransfer 前远端换源必须触发 ErrRemoteAnchorMismatch")
	if comC.State == nil || comC.State.Kind() != fsm.TransferKindAborted || rig.pool.Stats().ActiveHandles != 0 {
		t.Fatalf("CommitTransfer 锚点失配必须转 Aborted 并释放句柄: %+v active=%d", comC, rig.pool.Stats().ActiveHandles)
	}
	requireNoErr(t, rig.scopedFS.WithRoot(rig.localRoot, func(root ports.RootHandle) error {
		_, lErr := root.Lstat(mustLocalDest(t, "stream/c.bin"))
		requireErrIs(t, lErr, ports.ErrNotFound, "提交阻断后本地目标文件不得存在")
		return nil
	}), "verify no local c.bin")
}

func TestResumeTransfer_CanonicalizerStoreErrorAndConcurrentSlotMutex(t *testing.T) {
	defer goleak.VerifyNone(t)
	assertResumeCanonicalizerStoreError(t)
	assertConcurrentResumeSlotMutex(t)
}

func assertResumeCanonicalizerStoreError(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	strictRig := newTransferRig(t, rigOptions{profile: gate.PolicyProfileStrictAgent, approvalThresh: security.RiskDangerous, omitOperatorRead: true})
	defer strictRig.close()
	dest, err := fsm.NewUploadDest(mustRemotePath(t, "/tmp/ioerr.bin"))
	requireNoErr(t, err, "dest")
	tidErr := seedHealthyGen(t, strictRig, dest, 1, 8, false, false)
	ioErr := errors.New("journal backend io timeout")
	strictRig.journals.mu.Lock()
	strictRig.journals.loadGenErr = ioErr
	strictRig.journals.mu.Unlock()
	_, err = strictRig.svc.ResumeTransfer(ctx, transfer.ResumeTransferRequest{CallBase: strictRig.callBase(nil), TransferID: tidErr})
	strictRig.journals.mu.Lock()
	strictRig.journals.loadGenErr = nil
	strictRig.journals.mu.Unlock()
	requireErrIs(t, err, ioErr, "Round-2 LoadGenerations 非 ErrNotFound 存储故障必须 Fail-Closed")
}

func assertConcurrentResumeSlotMutex(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	rig := newTransferRig(t, rigOptions{omitOperatorRead: true})
	defer rig.close()
	dest, err := fsm.NewUploadDest(mustRemotePath(t, "/tmp/race.bin"))
	requireNoErr(t, err, "dest")
	tidRace := seedHealthyGen(t, rig, dest, 1, 8, false, false)

	var ready atomic.Int32
	goCh := make(chan struct{})
	var resMu sync.Mutex
	var winners []transfer.TransferHandleInfo
	var dupErrs int
	runOne := func(c context.Context) error {
		if ready.Add(1) == 2 {
			close(goCh)
		}
		select {
		case <-goCh:
		case <-c.Done():
			return c.Err()
		}
		info, rErr := rig.svc.ResumeTransfer(c, transfer.ResumeTransferRequest{CallBase: rig.callBase(nil), TransferID: tidRace, StartNextGen: false})
		resMu.Lock()
		defer resMu.Unlock()
		if rErr == nil {
			winners = append(winners, info)
			return nil
		}
		if errors.Is(rErr, ports.ErrAlreadyExists) {
			dupErrs++
			return nil
		}
		return rErr
	}
	requireNoErr(t, conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		for range 2 {
			if gErr := n.Go(runOne); gErr != nil {
				return gErr
			}
		}
		return nil
	}), "concurrent ResumeTransfer race")
	if len(winners) != 1 || dupErrs != 1 || rig.pool.Stats().ActiveHandles != 1 {
		t.Fatalf("并发同代 ResumeTransfer 互斥异常: winners=%d dupErrs=%d active=%d", len(winners), dupErrs, rig.pool.Stats().ActiveHandles)
	}
	requireNoErr(t, rig.svc.AbortTransfer(ctx, transfer.AbortTransferRequest{CallBase: rig.callBase(nil), Handle: winners[0].Handle, Reason: "cleanup"}), "cleanup winner")
}
