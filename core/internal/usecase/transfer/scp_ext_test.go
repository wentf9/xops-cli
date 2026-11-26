package transfer_test

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/usecase/transfer"
	"github.com/wentf9/xops-cli/core/ports"
)

func TestSCPUpload_DualModalityParallelResumeTimesAndEvents(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()

	// 1. OperatorReadFS 缺席时，Operator 源 Fail-Closed，Scoped 源仍完整可用（MCP 零 OperatorReadFS 路径）
	mcpRig := newTransferRig(t, rigOptions{omitOperatorRead: true})
	defer mcpRig.close()
	opSrc, err := transfer.NewOperatorUploadSource(mustLocalSource(t, "/home/op/app.bin"), pathalg.SymlinkReject)
	requireNoErr(t, err, "NewOperatorUploadSource")
	_, err = mcpRig.svc.SCPUpload(ctx, transfer.SCPUploadRequest{CallBase: mcpRig.callBase(nil), Source: opSrc, RemoteDest: mustRemotePath(t, "/srv/app.bin")})
	requireErrIs(t, err, transfer.ErrOperatorReadUnavailable, "无 OperatorReadFS 时必须 Fail-Closed")

	payload := makePatternPayload(20*1024 + 333)
	expDig := security.DigestBytes(payload)
	srcMtime := time.Date(2025, time.June, 15, 10, 20, 30, 0, time.UTC)
	requireNoErr(t, mcpRig.scopedFS.WithRoot(mcpRig.localRoot, func(root ports.RootHandle) error {
		dest := mustLocalDest(t, "staging/app.bin")
		if err := root.MkdirAll(mustLocalDest(t, "staging"), 0o755); err != nil {
			return err
		}
		if _, err := root.WriteChunk(dest, 0, bytes.NewReader(payload), int64(len(payload)), 0o640); err != nil {
			return err
		}
		return root.Chtimes(dest, srcMtime, srcMtime)
	}), "prepare scoped upload file")

	scopedSrc, err := transfer.NewScopedUploadSource(mcpRig.localRoot, mustLocalDest(t, "staging/app.bin"))
	requireNoErr(t, err, "NewScopedUploadSource")
	requireNoErr(t, mcpRig.remoteFS.MkdirAll(ctx, mustRemotePath(t, "/srv"), 0o755), "MkdirAll /srv")
	stream := mustNewOpStream(t, mcpRig.rng)
	upRes, err := mcpRig.svc.SCPUpload(ctx, transfer.SCPUploadRequest{
		CallBase: mcpRig.callBase(stream), Source: scopedSrc, RemoteDest: mustRemotePath(t, "/srv/app.bin"),
		ChunkSize: 4096, Concurrency: 4, PreserveMode: true, PreserveTimes: true, ExpectedDigest: algebraic.Some(expDig),
	})
	requireNoErr(t, err, "Scoped SCPUpload")
	if !upRes.Digest.Equal(expDig) || upRes.BytesTransferred != int64(len(payload)) || !upRes.ModTimePreserved || upRes.ChunksTransferred != 6 {
		t.Fatalf("Scoped SCPUpload 结果异常: %+v", upRes)
	}
	if !bytes.Equal(mustReadRemote(t, mcpRig.remoteFS, "/srv/app.bin"), payload) {
		t.Fatalf("远端内容与上传载荷不一致")
	}
	st, err := mcpRig.remoteFS.Stat(ctx, mustRemotePath(t, "/srv/app.bin"))
	requireNoErr(t, err, "Stat uploaded")
	if !st.ModTime().Equal(srcMtime) || st.Perm() != 0o640 {
		t.Fatalf("PreserveMode/PreserveTimes 未生效: perm=%#o mtime=%v", st.Perm(), st.ModTime())
	}
	evs := drainOpStream(t, stream)
	assertHasStartedAndCompleted(t, evs, true)

	// 2. OperatorReadFS 软链策略 + 断点续传 + 0 字节上传 + 摘要不匹配清理暂存
	rig := newTransferRig(t, rigOptions{})
	defer rig.close()
	requireNoErr(t, rig.opReadFS.PutFile(mustLocalSource(t, "/data/real.bin"), payload), "PutFile real")
	requireNoErr(t, rig.opReadFS.PutSymlink(mustLocalSource(t, "/data/link.bin"), mustLocalSource(t, "/data/real.bin")), "PutSymlink")
	requireNoErr(t, rig.opReadFS.PutFile(mustLocalSource(t, "/data/empty.bin"), nil), "PutFile empty")
	requireNoErr(t, rig.remoteFS.MkdirAll(ctx, mustRemotePath(t, "/dst"), 0o755), "MkdirAll /dst")

	rejectSrc, err := transfer.NewOperatorUploadSource(mustLocalSource(t, "/data/link.bin"), pathalg.SymlinkReject)
	requireNoErr(t, err, "rejectSrc")
	_, err = rig.svc.SCPUpload(ctx, transfer.SCPUploadRequest{CallBase: rig.callBase(nil), Source: rejectSrc, RemoteDest: mustRemotePath(t, "/dst/out.bin")})
	requireErrIs(t, err, ports.ErrSymlinkRejected, "SymlinkReject 必须拒绝软链源")

	followSrc, err := transfer.NewOperatorUploadSource(mustLocalSource(t, "/data/link.bin"), pathalg.SymlinkFollowOperatorSource)
	requireNoErr(t, err, "followSrc")
	// 摘要不匹配应失败并清理暂存
	badDig := security.DigestBytes([]byte("wrong"))
	_, err = rig.svc.SCPUpload(ctx, transfer.SCPUploadRequest{
		CallBase: rig.callBase(nil), Source: followSrc, RemoteDest: mustRemotePath(t, "/dst/out.bin"),
		ChunkSize: 4096, ExpectedDigest: algebraic.Some(badDig),
	})
	requireErrIs(t, err, transfer.ErrDigestMismatch, "摘要不匹配须拒绝")

	// 预置真实中断后的分片暂存以验证 Resume=true（模拟前次传输落盘 2 个分片后取消）
	var onceCancel atomic.Bool
	rig.dialer.mu.Lock()
	rig.dialer.onBeforeRenameAtomic = func(_ context.Context, _, _ pathalg.RemotePath) error {
		if onceCancel.CompareAndSwap(false, true) {
			return ports.ErrClosed
		}
		return nil
	}
	rig.dialer.mu.Unlock()
	_, err = rig.svc.SCPUpload(ctx, transfer.SCPUploadRequest{
		CallBase: rig.callBase(nil), Source: followSrc, RemoteDest: mustRemotePath(t, "/dst/out.bin"),
		ChunkSize: 4096, Concurrency: 4, Resume: true,
	})
	requireErrIs(t, err, ports.ErrClosed, "首次模拟中断应保留 Resume 暂存文件")

	opMtime := time.Date(2025, time.July, 1, 12, 0, 0, 0, time.UTC)
	resFollow, err := rig.svc.SCPUpload(ctx, transfer.SCPUploadRequest{
		CallBase: rig.callBase(nil), Source: followSrc, RemoteDest: mustRemotePath(t, "/dst/out.bin"),
		ChunkSize: 4096, Concurrency: 4, Resume: true, PreserveTimes: true, ModTime: algebraic.Some(opMtime),
	})
	requireNoErr(t, err, "Resume SCPUpload")
	if !resFollow.Digest.Equal(expDig) || !resFollow.ModTimePreserved || resFollow.ResumedBytes <= 0 {
		t.Fatalf("Operator Resume SCPUpload 结果异常: %+v", resFollow)
	}

	emptySrc, err := transfer.NewOperatorUploadSource(mustLocalSource(t, "/data/empty.bin"), pathalg.SymlinkReject)
	requireNoErr(t, err, "emptySrc")
	emptyRes, err := rig.svc.SCPUpload(ctx, transfer.SCPUploadRequest{CallBase: rig.callBase(nil), Source: emptySrc, RemoteDest: mustRemotePath(t, "/dst/empty.bin")})
	requireNoErr(t, err, "0-byte SCPUpload")
	if emptyRes.BytesTransferred != 0 || len(mustReadRemote(t, rig.remoteFS, "/dst/empty.bin")) != 0 {
		t.Fatalf("0 字节上传结果异常: %+v", emptyRes)
	}
}

func TestSCPUpload_SinglePassExpandAndDanglingSymlinkNoClobber(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newTransferRig(t, rigOptions{})
	defer rig.close()
	ctx := context.Background()

	requireNoErr(t, rig.opReadFS.PutFile(mustLocalSource(t, "/src/conf.yml"), []byte("k: v")), "PutFile")
	src, err := transfer.NewOperatorUploadSource(mustLocalSource(t, "/src/conf.yml"), pathalg.SymlinkReject)
	requireNoErr(t, err, "NewOperatorUploadSource")

	// 1. ExpandIntoDir=false 禁止覆写目录；ExpandIntoDir=true 单次展开到 /dir/conf.yml
	requireNoErr(t, rig.remoteFS.MkdirAll(ctx, mustRemotePath(t, "/dir"), 0o755), "MkdirAll /dir")
	_, err = rig.svc.SCPUpload(ctx, transfer.SCPUploadRequest{CallBase: rig.callBase(nil), Source: src, RemoteDest: mustRemotePath(t, "/dir"), ExpandIntoDir: false})
	requireErrIs(t, err, ports.ErrRemoteIsDir, "ExpandIntoDir=false 必须拒绝目录目标")
	res, err := rig.svc.SCPUpload(ctx, transfer.SCPUploadRequest{CallBase: rig.callBase(nil), Source: src, RemoteDest: mustRemotePath(t, "/dir"), ExpandIntoDir: true})
	requireNoErr(t, err, "ExpandIntoDir=true 单次展开")
	if res.RemotePath.String() != "/dir/conf.yml" {
		t.Fatalf("展开路径=%s, want /dir/conf.yml", res.RemotePath)
	}

	// 2. INV-B4：展开目标若仍是目录，禁止二次展开
	requireNoErr(t, rig.remoteFS.MkdirAll(ctx, mustRemotePath(t, "/nested/conf.yml"), 0o755), "MkdirAll /nested/conf.yml")
	_, err = rig.svc.SCPUpload(ctx, transfer.SCPUploadRequest{CallBase: rig.callBase(nil), Source: src, RemoteDest: mustRemotePath(t, "/nested"), ExpandIntoDir: true})
	requireErrIs(t, err, ports.ErrRemoteIsDir, "禁止二次容器目录展开")

	// 3. Lstat 悬空软链：NoClobber=true 拒绝，NoClobber=false 替换
	requireNoErr(t, rig.remoteFS.PutSymlink(mustRemotePath(t, "/dir/dangling"), "/nonexistent/target"), "PutSymlink dangling")
	_, err = rig.svc.SCPUpload(ctx, transfer.SCPUploadRequest{CallBase: rig.callBase(nil), Source: src, RemoteDest: mustRemotePath(t, "/dir/dangling"), NoClobber: true})
	requireErrIs(t, err, ports.ErrAlreadyExists, "悬空软链必须触发 NoClobber")
	_, err = rig.svc.SCPUpload(ctx, transfer.SCPUploadRequest{CallBase: rig.callBase(nil), Source: src, RemoteDest: mustRemotePath(t, "/dir/dangling"), NoClobber: false})
	requireNoErr(t, err, "NoClobber=false 应替换悬空软链")
	if string(mustReadRemote(t, rig.remoteFS, "/dir/dangling")) != "k: v" {
		t.Fatalf("替换悬空软链后内容不符")
	}
}

func TestSCPDownload_ParallelSingleFileZeroOpReadResumeTimesAndRejectSpecial(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newTransferRig(t, rigOptions{omitOperatorRead: true}) // 强制验证零 OperatorReadFS 依赖
	defer rig.close()
	ctx := context.Background()

	payload := makePatternPayload(22*1024 + 511)
	expDig := security.DigestBytes(payload)
	remTime := time.Date(2025, time.August, 5, 9, 0, 0, 0, time.UTC)
	mustWriteRemote(t, rig.remoteFS, "/pub/pkg.tar", payload)
	requireNoErr(t, rig.remoteFS.Chtimes(ctx, mustRemotePath(t, "/pub/pkg.tar"), remTime, remTime), "remote Chtimes")
	mustWriteRemote(t, rig.remoteFS, "/pub/zero.bin", nil)

	res, err := rig.svc.SCPDownload(ctx, transfer.SCPDownloadRequest{
		CallBase: rig.callBase(nil), RemoteSource: mustRemotePath(t, "/pub/pkg.tar"),
		LocalRoot: rig.localRoot, LocalDest: mustLocalDest(t, "dl/pkg.tar"),
		SymlinkPolicy: pathalg.SymlinkReject, ChunkSize: 4096, Concurrency: 4, PreserveTimes: true,
		ExpectedDigest: algebraic.Some(expDig),
	})
	requireNoErr(t, err, "parallel SCPDownload")
	if res.FilesDownloaded != 1 || res.BytesTransferred != int64(len(payload)) || !res.ModTimePreserved || res.ChunksTransferred != 6 {
		t.Fatalf("SCPDownload 结果异常: %+v", res)
	}
	if !bytes.Equal(mustReadLocal(t, rig.scopedFS, rig.localRoot, "dl/pkg.tar"), payload) {
		t.Fatalf("本地落盘内容不符")
	}
	requireNoErr(t, rig.scopedFS.WithRoot(rig.localRoot, func(root ports.RootHandle) error {
		info, sErr := root.Stat(mustLocalDest(t, "dl/pkg.tar"))
		requireNoErr(t, sErr, "local Stat")
		if !info.ModTime().Equal(remTime) {
			t.Fatalf("本地 mtime=%v, want %v", info.ModTime(), remTime)
		}
		return nil
	}), "verify local mtime")

	// NoClobber 拦截已存在本地目标
	_, err = rig.svc.SCPDownload(ctx, transfer.SCPDownloadRequest{
		CallBase: rig.callBase(nil), RemoteSource: mustRemotePath(t, "/pub/pkg.tar"),
		LocalRoot: rig.localRoot, LocalDest: mustLocalDest(t, "dl/pkg.tar"),
		SymlinkPolicy: pathalg.SymlinkReject, NoClobber: true,
	})
	requireErrIs(t, err, ports.ErrAlreadyExists, "本地 NoClobber 必须拦截")

	// 0 字节下载
	zRes, err := rig.svc.SCPDownload(ctx, transfer.SCPDownloadRequest{
		CallBase: rig.callBase(nil), RemoteSource: mustRemotePath(t, "/pub/zero.bin"),
		LocalRoot: rig.localRoot, LocalDest: mustLocalDest(t, "dl/zero.bin"),
		SymlinkPolicy: pathalg.SymlinkReject,
	})
	requireNoErr(t, err, "0-byte SCPDownload")
	if zRes.BytesTransferred != 0 || len(mustReadLocal(t, rig.scopedFS, rig.localRoot, "dl/zero.bin")) != 0 {
		t.Fatalf("0 字节下载异常: %+v", zRes)
	}

	// 单软链下载：SymlinkReject 拒绝，SymlinkContainedRelative 安全相对允许，越界相对拒绝
	requireNoErr(t, rig.remoteFS.PutSymlink(mustRemotePath(t, "/pub/safe_link"), "pkg.tar"), "PutSymlink safe_link")
	requireNoErr(t, rig.remoteFS.PutSymlink(mustRemotePath(t, "/pub/esc_link"), "../../../etc/passwd"), "PutSymlink esc_link")
	_, err = rig.svc.SCPDownload(ctx, transfer.SCPDownloadRequest{
		CallBase: rig.callBase(nil), RemoteSource: mustRemotePath(t, "/pub/safe_link"),
		LocalRoot: rig.localRoot, LocalDest: mustLocalDest(t, "dl/safe_link"), SymlinkPolicy: pathalg.SymlinkReject,
	})
	requireErrIs(t, err, transfer.ErrSymlinkPolicyDenied, "SymlinkReject 须拒绝单软链下载")
	slRes, err := rig.svc.SCPDownload(ctx, transfer.SCPDownloadRequest{
		CallBase: rig.callBase(nil), RemoteSource: mustRemotePath(t, "/pub/safe_link"),
		LocalRoot: rig.localRoot, LocalDest: mustLocalDest(t, "dl/safe_link"), SymlinkPolicy: pathalg.SymlinkContainedRelative,
	})
	requireNoErr(t, err, "SymlinkContainedRelative 安全单软链下载")
	if slRes.SymlinksCreated != 1 {
		t.Fatalf("SymlinksCreated=%d, want 1", slRes.SymlinksCreated)
	}
	_, err = rig.svc.SCPDownload(ctx, transfer.SCPDownloadRequest{
		CallBase: rig.callBase(nil), RemoteSource: mustRemotePath(t, "/pub/esc_link"),
		LocalRoot: rig.localRoot, LocalDest: mustLocalDest(t, "dl/esc_link"), SymlinkPolicy: pathalg.SymlinkContainedRelative,
	})
	requireErrIs(t, err, transfer.ErrSymlinkPolicyDenied, "越界单软链必须拒绝")

	// 拒绝 SymlinkFollowOperatorSource 与 RemoteFileOther 特殊对象
	_, err = rig.svc.SCPDownload(ctx, transfer.SCPDownloadRequest{
		CallBase: rig.callBase(nil), RemoteSource: mustRemotePath(t, "/pub/pkg.tar"),
		LocalRoot: rig.localRoot, LocalDest: mustLocalDest(t, "dl/other.tar"),
		SymlinkPolicy: pathalg.SymlinkFollowOperatorSource,
	})
	requireErrIs(t, err, transfer.ErrSymlinkPolicyDenied, "下载禁止 SymlinkFollowOperatorSource")

	fifoAnchor, err := ports.NewRemoteFileAnchor(ports.RemoteFileOther, false, 0, 0)
	requireNoErr(t, err, "NewRemoteFileAnchor(Other)")
	fifoStat, err := ports.NewRemoteFileStat(ports.RemoteFileStatSpec{Path: mustRemotePath(t, "/pub/fifo"), Anchor: fifoAnchor})
	requireNoErr(t, err, "NewRemoteFileStat(Other)")
	rig.dialer.mu.Lock()
	rig.dialer.onLstatOverride = func(p pathalg.RemotePath) (ports.RemoteFileStat, bool) {
		return fifoStat, p.String() == "/pub/fifo"
	}
	rig.dialer.mu.Unlock()
	_, err = rig.svc.SCPDownload(ctx, transfer.SCPDownloadRequest{
		CallBase: rig.callBase(nil), RemoteSource: mustRemotePath(t, "/pub/fifo"),
		LocalRoot: rig.localRoot, LocalDest: mustLocalDest(t, "dl/fifo"),
		SymlinkPolicy: pathalg.SymlinkReject,
	})
	requireErrIs(t, err, transfer.ErrRemoteObjectUnsupported, "必须拒绝 RemoteFileOther 特殊对象")
}

func TestSCPDownload_RecursiveTreeSymlinkPolicyCollisionsAndDirMtime(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newTransferRig(t, rigOptions{omitOperatorRead: true})
	defer rig.close()
	ctx := context.Background()

	// 构造正常递归目录树 + 安全相对软链 + 目录 mtime
	subTime := time.Date(2025, time.April, 20, 14, 0, 0, 0, time.UTC)
	mustWriteRemote(t, rig.remoteFS, "/tree/sub/a.txt", []byte("hello-a"))
	mustWriteRemote(t, rig.remoteFS, "/tree/root.txt", []byte("hello-root"))
	requireNoErr(t, rig.remoteFS.PutSymlink(mustRemotePath(t, "/tree/sub/rel_link"), "../root.txt"), "safe rel symlink")
	requireNoErr(t, rig.remoteFS.Chtimes(ctx, mustRemotePath(t, "/tree/sub"), subTime, subTime), "dir chtimes")

	// SymlinkReject 拒绝含软链目录树
	_, err := rig.svc.SCPDownload(ctx, transfer.SCPDownloadRequest{
		CallBase: rig.callBase(nil), RemoteSource: mustRemotePath(t, "/tree"),
		LocalRoot: rig.localRoot, LocalDest: mustLocalDest(t, "out-reject"),
		Recursive: true, SymlinkPolicy: pathalg.SymlinkReject,
	})
	requireErrIs(t, err, transfer.ErrSymlinkPolicyDenied, "SymlinkReject 须拒绝目录树内软链")

	// SymlinkContainedRelative 允许封闭相对软链并自底向上保留目录 mtime
	res, err := rig.svc.SCPDownload(ctx, transfer.SCPDownloadRequest{
		CallBase: rig.callBase(nil), RemoteSource: mustRemotePath(t, "/tree"),
		LocalRoot: rig.localRoot, LocalDest: mustLocalDest(t, "out-ok"),
		Recursive: true, SymlinkPolicy: pathalg.SymlinkContainedRelative, PreserveTimes: true,
	})
	requireNoErr(t, err, "recursive SCPDownload with safe relative symlink")
	if res.FilesDownloaded != 2 || res.DirsCreated != 2 || res.SymlinksCreated != 1 || !res.ModTimePreserved {
		t.Fatalf("递归下载结果异常: %+v", res)
	}
	requireNoErr(t, rig.scopedFS.WithRoot(rig.localRoot, func(root ports.RootHandle) error {
		info, sErr := root.Lstat(mustLocalDest(t, "out-ok/sub"))
		requireNoErr(t, sErr, "Lstat out-ok/sub")
		if !info.ModTime().Equal(subTime) {
			t.Fatalf("目录 mtime 未自底向上保留: got=%v want=%v", info.ModTime(), subTime)
		}
		return nil
	}), "verify dir mtime")

	// 对抗 1：越界相对软链 ../../etc/passwd 必须在落盘前被 ValidateContainedSymlinkSet 阻断
	mustWriteRemote(t, rig.remoteFS, "/badtree/sub/f.txt", []byte("x"))
	requireNoErr(t, rig.remoteFS.PutSymlink(mustRemotePath(t, "/badtree/sub/esc"), "../../../../etc/passwd"), "escaping symlink")
	_, err = rig.svc.SCPDownload(ctx, transfer.SCPDownloadRequest{
		CallBase: rig.callBase(nil), RemoteSource: mustRemotePath(t, "/badtree"),
		LocalRoot: rig.localRoot, LocalDest: mustLocalDest(t, "out-esc"),
		Recursive: true, SymlinkPolicy: pathalg.SymlinkContainedRelative,
	})
	requireErrIs(t, err, transfer.ErrSymlinkPolicyDenied, "越界相对软链必须拒绝")

	// 对抗 2：跨 OS 大小写碰撞（Cafe vs cafe）必须被 CheckPathCollisions 阻断
	mustWriteRemote(t, rig.remoteFS, "/coltree/Cafe", []byte("1"))
	mustWriteRemote(t, rig.remoteFS, "/coltree/cafe", []byte("2"))
	_, err = rig.svc.SCPDownload(ctx, transfer.SCPDownloadRequest{
		CallBase: rig.callBase(nil), RemoteSource: mustRemotePath(t, "/coltree"),
		LocalRoot: rig.localRoot, LocalDest: mustLocalDest(t, "out-col"),
		Recursive: true, SymlinkPolicy: pathalg.SymlinkReject,
	})
	requireErrIs(t, err, transfer.ErrSymlinkPolicyDenied, "大小写碰撞路径必须拒绝")

	// 对抗 3：Windows 保留名 CON 必须被 LocalRootedDest 拒绝
	mustWriteRemote(t, rig.remoteFS, "/wintree/CON", []byte("x"))
	_, err = rig.svc.SCPDownload(ctx, transfer.SCPDownloadRequest{
		CallBase: rig.callBase(nil), RemoteSource: mustRemotePath(t, "/wintree"),
		LocalRoot: rig.localRoot, LocalDest: mustLocalDest(t, "out-win"),
		Recursive: true, SymlinkPolicy: pathalg.SymlinkReject,
	})
	if err == nil {
		t.Fatalf("Windows 保留名 CON 必须拒绝")
	}

	// 对抗 4：MaxFiles 边界拦截
	_, err = rig.svc.SCPDownload(ctx, transfer.SCPDownloadRequest{
		CallBase: rig.callBase(nil), RemoteSource: mustRemotePath(t, "/tree"),
		LocalRoot: rig.localRoot, LocalDest: mustLocalDest(t, "out-limit"),
		Recursive: true, SymlinkPolicy: pathalg.SymlinkContainedRelative, MaxFiles: 2,
	})
	requireErrIs(t, err, ports.ErrLimitExceeded, "超出 MaxFiles 必须拒绝")
}

func assertHasStartedAndCompleted(t *testing.T, evs []events.Event, expectSucceeded bool) {
	t.Helper()
	var sawStart, sawDone bool
	for _, ev := range evs {
		switch v := ev.(type) {
		case *events.OperationStartedEvent:
			sawStart = true
		case *events.OperationCompletedEvent:
			sawDone = true
			if v.Succeeded() != expectSucceeded {
				t.Fatalf("OperationCompleted.Succeeded=%v, want %v", v.Succeeded(), expectSucceeded)
			}
		case *events.ApprovalChallengeEvent, *events.AuditRecordEvent, *events.BusDroppedEvent,
			*events.DiagnosticEvent, *events.FSMTransitionEvent, *events.MetricSampleEvent,
			*events.OutputChunkEvent, *events.PoolStateEvent, *events.StepEvent, *events.TransferProgressEvent:
		default:
			t.Fatalf("未知事件变体: %T", ev)
		}
	}
	if !sawStart || !sawDone {
		t.Fatalf("事件流缺少 Started/Completed: sawStart=%v sawDone=%v total=%d", sawStart, sawDone, len(evs))
	}
}
