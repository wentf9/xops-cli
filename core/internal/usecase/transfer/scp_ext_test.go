package transfer_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
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
	rig.dialer.onLstatOverride = func(p pathalg.RemotePath) (ports.RemoteFileStat, bool, error) {
		return fifoStat, p.String() == "/pub/fifo", nil
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

func TestSCPUpload_ExpandIntoDirRound2ProtectionAndDrift(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newTransferRig(t, rigOptions{
		profile: gate.PolicyProfileStrictAgent, approvalThresh: security.RiskDangerous,
		protectedPats: []string{"/etc/**", "/root/**", "/**/authorized_keys"},
	})
	defer rig.close()
	ctx := context.Background()

	// 1. ExpandIntoDir=true 展开命中受保护规则 **/authorized_keys（直接目录与目录软链）须被 Round-2 拦截且 0 写入
	requireNoErr(t, rig.remoteFS.MkdirAll(ctx, mustRemotePath(t, "/home/ops/.ssh"), 0o700), "MkdirAll .ssh")
	requireNoErr(t, rig.remoteFS.MkdirAll(ctx, mustRemotePath(t, "/tmp"), 0o755), "MkdirAll /tmp")
	requireNoErr(t, rig.remoteFS.PutSymlink(mustRemotePath(t, "/tmp/link_ssh"), "/home/ops/.ssh"), "PutSymlink link_ssh")
	requireNoErr(t, rig.opReadFS.PutFile(mustLocalSource(t, "/local/authorized_keys"), []byte("ssh-ed25519 AAAA")), "PutFile authorized_keys")
	akSrc, err := transfer.NewOperatorUploadSource(mustLocalSource(t, "/local/authorized_keys"), pathalg.SymlinkReject)
	requireNoErr(t, err, "NewOperatorUploadSource")

	for _, target := range []string{"/home/ops/.ssh", "/tmp/link_ssh"} {
		_, err = rig.svc.SCPUpload(ctx, transfer.SCPUploadRequest{
			CallBase: rig.callBase(nil), Source: akSrc, RemoteDest: mustRemotePath(t, target), ExpandIntoDir: true,
		})
		requireErrIs(t, err, gate.ErrApprovalRequired, "ExpandIntoDir 展开至 "+target+"/authorized_keys 必须被 Round-2 拦截")
	}
	if _, sErr := rig.remoteFS.Lstat(ctx, mustRemotePath(t, "/home/ops/.ssh/authorized_keys")); sErr == nil {
		t.Fatalf("/home/ops/.ssh/authorized_keys 不得被写入")
	}

	// 2. TOCTOU 漂移：Round-2 通过后将 /tmp/drop 替换为指向 /etc 的软链 -> 执行期 verifyRemotePathAuthorized 返回 ErrScopeEscalated
	requireNoErr(t, rig.remoteFS.MkdirAll(ctx, mustRemotePath(t, "/tmp/drop"), 0o755), "MkdirAll /tmp/drop")
	requireNoErr(t, rig.remoteFS.MkdirAll(ctx, mustRemotePath(t, "/etc"), 0o755), "MkdirAll /etc")
	requireNoErr(t, rig.opReadFS.PutFile(mustLocalSource(t, "/local/normal.txt"), []byte("hello")), "PutFile normal.txt")
	normSrc, err := transfer.NewOperatorUploadSource(mustLocalSource(t, "/local/normal.txt"), pathalg.SymlinkReject)
	requireNoErr(t, err, "normSrc")
	var lstatHits atomic.Int64
	rig.dialer.mu.Lock()
	rig.dialer.onLstatOverride = func(p pathalg.RemotePath) (ports.RemoteFileStat, bool, error) {
		var z ports.RemoteFileStat
		if p.String() == "/tmp/drop" && lstatHits.Add(1) == 2 {
			if rErr := rig.remoteFS.RemoveDir(ctx, mustRemotePath(t, "/tmp/drop")); rErr != nil {
				return z, false, rErr
			}
			if sErr := rig.remoteFS.PutSymlink(mustRemotePath(t, "/tmp/drop"), "/etc"); sErr != nil {
				return z, false, sErr
			}
		}
		return z, false, nil
	}
	rig.dialer.mu.Unlock()
	_, err = rig.svc.SCPUpload(ctx, transfer.SCPUploadRequest{
		CallBase: rig.callBase(nil), Source: normSrc, RemoteDest: mustRemotePath(t, "/tmp/drop"), ExpandIntoDir: true,
	})
	requireErrIs(t, err, gate.ErrScopeEscalated, "ExpandIntoDir 漂移至 /etc 必须触发 ErrScopeEscalated")
	if _, sErr := rig.remoteFS.Lstat(ctx, mustRemotePath(t, "/etc/normal.txt")); sErr == nil {
		t.Fatalf("/etc/normal.txt 不得被写入")
	}
}

func TestSCPUpload_ResumePrefixVerificationResistsSparseHolesAndSwappedSource(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newTransferRig(t, rigOptions{})
	defer rig.close()
	ctx := context.Background()

	const chunkSz = 4096
	payloadA := makePatternPayload(3 * chunkSz)
	payloadB := bytes.Repeat([]byte{0x5a, 0xa5, 0x3c, 0xc3}, 3*chunkSz/4)
	requireNoErr(t, rig.remoteFS.MkdirAll(ctx, mustRemotePath(t, "/up"), 0o755), "MkdirAll /up")
	dest := mustRemotePath(t, "/up/file.bin")
	sum := sha256.Sum256([]byte("xops.scp.upload.v1\x00" + dest.String()))
	stagePath := mustRemotePath(t, "/up/.xops-stage-"+hex.EncodeToString(sum[:12])+".part")

	// 1. 远端暂存存在稀疏空洞（仅 chunk 1 与 chunk 2 有效，chunk 0 为全零空洞）-> 续传须重传 chunk 0 并跳过已验分片
	requireNoErr(t, rig.remoteFS.WriteChunk(ctx, stagePath, chunkSz, bytes.NewReader(payloadA[chunkSz:2*chunkSz]), chunkSz), "seed chunk 1")
	requireNoErr(t, rig.remoteFS.WriteChunk(ctx, stagePath, 2*chunkSz, bytes.NewReader(payloadA[2*chunkSz:]), chunkSz), "seed chunk 2")
	requireNoErr(t, rig.opReadFS.PutFile(mustLocalSource(t, "/local/a.bin"), payloadA), "PutFile a.bin")
	srcA, err := transfer.NewOperatorUploadSource(mustLocalSource(t, "/local/a.bin"), pathalg.SymlinkReject)
	requireNoErr(t, err, "srcA")
	resA, err := rig.svc.SCPUpload(ctx, transfer.SCPUploadRequest{
		CallBase: rig.callBase(nil), Source: srcA, RemoteDest: dest, ChunkSize: chunkSz, Concurrency: 4, Resume: true,
	})
	requireNoErr(t, err, "SCPUpload Resume sparse hole repair")
	if resA.ResumedBytes != 2*chunkSz || resA.ChunksTransferred != 1 || !bytes.Equal(mustReadRemote(t, rig.remoteFS, dest.String()), payloadA) {
		t.Fatalf("稀疏空洞修复结果异常: res=%+v", resA)
	}

	// 2. 同大小换源：远端残留 payloadA 全长暂存，改传同长 payloadB -> 逐片回读失配全部重传，ResumedBytes=0 且字节精确
	requireNoErr(t, rig.remoteFS.WriteChunk(ctx, stagePath, 0, bytes.NewReader(payloadA), int64(len(payloadA))), "seed stale payloadA stage")
	requireNoErr(t, rig.opReadFS.PutFile(mustLocalSource(t, "/local/b.bin"), payloadB), "PutFile b.bin")
	srcB, err := transfer.NewOperatorUploadSource(mustLocalSource(t, "/local/b.bin"), pathalg.SymlinkReject)
	requireNoErr(t, err, "srcB")
	resB, err := rig.svc.SCPUpload(ctx, transfer.SCPUploadRequest{
		CallBase: rig.callBase(nil), Source: srcB, RemoteDest: dest, ChunkSize: chunkSz, Concurrency: 4, Resume: true,
	})
	requireNoErr(t, err, "SCPUpload Resume swapped source")
	if resB.ResumedBytes != 0 || resB.ChunksTransferred != 3 || !bytes.Equal(mustReadRemote(t, rig.remoteFS, dest.String()), payloadB) {
		t.Fatalf("换源续传结果异常: res=%+v", resB)
	}
}

func TestSCPDownload_OrderedWindowResumeIsolationAndSymlinkOverwrite(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newTransferRig(t, rigOptions{omitOperatorRead: true})
	defer rig.close()
	ctx := context.Background()

	const chunkSz = 4096
	payload1 := makePatternPayload(4 * chunkSz)
	t1 := time.Date(2025, time.October, 1, 10, 0, 0, 0, time.UTC)
	mustWriteRemote(t, rig.remoteFS, "/dl/data.bin", payload1)
	requireNoErr(t, rig.remoteFS.Chtimes(ctx, mustRemotePath(t, "/dl/data.bin"), t1, t1), "Chtimes t1")

	// 1. 4 分片 + 3 并发滑动窗口确定性乱序对抗：
	//    slot 容量=3，故收到 offset=3*chunkSz 在数学上等价于 consumer 已落盘 chunk 0 并释放 slot；
	//    待 chunk 2 与 chunk 3 均读回后令 chunk 1 断连，验证本地暂存严格仅落盘 4096B（0 稀疏空洞）。
	chunk2Read := make(chan struct{})
	chunk0Written := make(chan struct{})
	rig.dialer.mu.Lock()
	rig.dialer.onReadChunk = func(rCtx context.Context, _ pathalg.RemotePath, offset, _ int64) error {
		switch offset {
		case 2 * chunkSz:
			close(chunk2Read)
		case 3 * chunkSz:
			close(chunk0Written)
		case chunkSz:
			select {
			case <-chunk2Read:
			case <-rCtx.Done():
				return rCtx.Err()
			}
			select {
			case <-chunk0Written:
			case <-rCtx.Done():
				return rCtx.Err()
			}
			return ports.ErrClosed
		}
		return nil
	}
	rig.dialer.mu.Unlock()
	_, err := rig.svc.SCPDownload(ctx, transfer.SCPDownloadRequest{
		CallBase: rig.callBase(nil), RemoteSource: mustRemotePath(t, "/dl/data.bin"),
		LocalRoot: rig.localRoot, LocalDest: mustLocalDest(t, "ordered/data.bin"),
		SymlinkPolicy: pathalg.SymlinkReject, ChunkSize: chunkSz, Concurrency: 3, Resume: true,
	})
	requireErrIs(t, err, ports.ErrClosed, "chunk 1 模拟中断应失败并保留严格连续前缀")
	rig.dialer.mu.Lock()
	rig.dialer.onReadChunk = nil
	rig.dialer.mu.Unlock()

	// 验证同源 Resume=true 从 4096 精准续传剩余 3 片且字节完全一致
	resResume, err := rig.svc.SCPDownload(ctx, transfer.SCPDownloadRequest{
		CallBase: rig.callBase(nil), RemoteSource: mustRemotePath(t, "/dl/data.bin"),
		LocalRoot: rig.localRoot, LocalDest: mustLocalDest(t, "ordered/data.bin"),
		SymlinkPolicy: pathalg.SymlinkReject, ChunkSize: chunkSz, Concurrency: 3, Resume: true,
	})
	requireNoErr(t, err, "有序续传 SCPDownload")
	if resResume.ResumedBytes != chunkSz || resResume.ChunksTransferred != 3 || !bytes.Equal(mustReadLocal(t, rig.scopedFS, rig.localRoot, "ordered/data.bin"), payload1) {
		t.Fatalf("有序续传结果异常: %+v", resResume)
	}

	// 2. 源变更隔离：旧 stageToken 绑定源元信息，远端更换内容与 mtime 后 Resume=true 不得复用旧暂存
	payload2 := bytes.Repeat([]byte{0x77, 0x88, 0x99, 0xaa}, chunkSz)
	t2 := t1.Add(time.Hour)
	mustWriteRemote(t, rig.remoteFS, "/dl/data.bin", payload2)
	requireNoErr(t, rig.remoteFS.Chtimes(ctx, mustRemotePath(t, "/dl/data.bin"), t2, t2), "Chtimes t2")
	resChanged, err := rig.svc.SCPDownload(ctx, transfer.SCPDownloadRequest{
		CallBase: rig.callBase(nil), RemoteSource: mustRemotePath(t, "/dl/data.bin"),
		LocalRoot: rig.localRoot, LocalDest: mustLocalDest(t, "ordered/data.bin"),
		SymlinkPolicy: pathalg.SymlinkReject, ChunkSize: chunkSz, Concurrency: 3, Resume: true,
	})
	requireNoErr(t, err, "换源后 SCPDownload Resume")
	if resChanged.ResumedBytes != 0 || !bytes.Equal(mustReadLocal(t, rig.scopedFS, rig.localRoot, "ordered/data.bin"), payload2) {
		t.Fatalf("远端源变更后不得复用旧暂存: %+v", resChanged)
	}

	// 3. 软链覆写语义：NoClobber=false 可覆写已有常规文件与旧软链，拒绝覆写目录；NoClobber=true 返回 ErrAlreadyExists
	assertLocalSymlinkOverwriteSemantics(t, rig)
}

func assertLocalSymlinkOverwriteSemantics(t *testing.T, rig *transferTestRig) {
	t.Helper()
	ctx := context.Background()
	requireNoErr(t, rig.remoteFS.PutSymlink(mustRemotePath(t, "/dl/sym"), "target.txt"), "PutSymlink /dl/sym")
	requireNoErr(t, rig.scopedFS.WithRoot(rig.localRoot, func(root ports.RootHandle) error {
		if _, err := root.WriteChunk(mustLocalDest(t, "sym_over_file"), 0, bytes.NewReader([]byte("old")), 3, 0o600); err != nil {
			return err
		}
		if err := root.CreateSymlink(mustLocalDest(t, "sym_over_sym"), "old.txt"); err != nil {
			return err
		}
		return root.MkdirAll(mustLocalDest(t, "sym_over_dir"), 0o755)
	}), "seed local overwrite targets")

	for _, name := range []string{"sym_over_file", "sym_over_sym"} {
		_, err := rig.svc.SCPDownload(ctx, transfer.SCPDownloadRequest{
			CallBase: rig.callBase(nil), RemoteSource: mustRemotePath(t, "/dl/sym"),
			LocalRoot: rig.localRoot, LocalDest: mustLocalDest(t, name),
			SymlinkPolicy: pathalg.SymlinkContainedRelative, NoClobber: true,
		})
		requireErrIs(t, err, ports.ErrAlreadyExists, "NoClobber=true 必须阻断软链覆写 "+name)
		res, err := rig.svc.SCPDownload(ctx, transfer.SCPDownloadRequest{
			CallBase: rig.callBase(nil), RemoteSource: mustRemotePath(t, "/dl/sym"),
			LocalRoot: rig.localRoot, LocalDest: mustLocalDest(t, name),
			SymlinkPolicy: pathalg.SymlinkContainedRelative, NoClobber: false,
		})
		requireNoErr(t, err, "NoClobber=false 覆写 "+name)
		if res.SymlinksCreated != 1 {
			t.Fatalf("SymlinksCreated=%d, want 1", res.SymlinksCreated)
		}
	}
	_, err := rig.svc.SCPDownload(ctx, transfer.SCPDownloadRequest{
		CallBase: rig.callBase(nil), RemoteSource: mustRemotePath(t, "/dl/sym"),
		LocalRoot: rig.localRoot, LocalDest: mustLocalDest(t, "sym_over_dir"),
		SymlinkPolicy: pathalg.SymlinkContainedRelative, NoClobber: false,
	})
	if !errors.Is(err, ports.ErrRemoteIsDir) {
		t.Fatalf("软链禁止覆写已有目录: got %v, want ErrRemoteIsDir", err)
	}
}

func TestSCPDownload_MidTransferSourceSwapAndSymlinkDriftBeforeRename(t *testing.T) {
	defer goleak.VerifyNone(t)
	assertSCPDownloadAnchorSwapRejected(t)
	assertSCPDownloadSymlinkDriftRejected(t)
}

func assertSCPDownloadAnchorSwapRejected(t *testing.T) {
	t.Helper()
	rig := newTransferRig(t, rigOptions{omitOperatorRead: true})
	defer rig.close()
	ctx := context.Background()

	const chunkSz = 4096
	orig := makePatternPayload(2 * chunkSz)
	swapped := bytes.Repeat([]byte{0xde, 0xad, 0xbe, 0xef}, 2*chunkSz/4)
	srcPath := mustRemotePath(t, "/pub/swap.bin")
	mustWriteRemote(t, rig.remoteFS, srcPath.String(), orig)

	var injected atomic.Bool
	rig.dialer.mu.Lock()
	rig.dialer.onReadChunk = func(_ context.Context, p pathalg.RemotePath, offset, _ int64) error {
		if p.Equal(srcPath) && offset == chunkSz && injected.CompareAndSwap(false, true) {
			mustWriteRemote(t, rig.remoteFS, srcPath.String(), swapped)
		}
		return nil
	}
	rig.dialer.mu.Unlock()

	_, err := rig.svc.SCPDownload(ctx, transfer.SCPDownloadRequest{
		CallBase: rig.callBase(nil), RemoteSource: srcPath,
		LocalRoot: rig.localRoot, LocalDest: mustLocalDest(t, "dl/swap.bin"),
		SymlinkPolicy: pathalg.SymlinkReject, ChunkSize: chunkSz, Concurrency: 1, Resume: true,
	})
	requireErrIs(t, err, ports.ErrRemoteAnchorMismatch, "SCPDownload 传输窗口内远端换源必须在 Rename 前拒绝")
	requireNoErr(t, rig.scopedFS.WithRoot(rig.localRoot, func(root ports.RootHandle) error {
		_, lErr := root.Lstat(mustLocalDest(t, "dl/swap.bin"))
		requireErrIs(t, lErr, ports.ErrNotFound, "失配后本地目标文件不得提交落盘")
		return nil
	}), "check no local swap.bin")

	rig.dialer.mu.Lock()
	rig.dialer.onReadChunk = nil
	rig.dialer.mu.Unlock()
	res, err := rig.svc.SCPDownload(ctx, transfer.SCPDownloadRequest{
		CallBase: rig.callBase(nil), RemoteSource: srcPath,
		LocalRoot: rig.localRoot, LocalDest: mustLocalDest(t, "dl/swap.bin"),
		SymlinkPolicy: pathalg.SymlinkReject, ChunkSize: chunkSz, Concurrency: 2, Resume: true,
	})
	requireNoErr(t, err, "清理暂存后重新下载应成功")
	if res.ResumedBytes != 0 || !bytes.Equal(mustReadLocal(t, rig.scopedFS, rig.localRoot, "dl/swap.bin"), swapped) {
		t.Fatalf("重下不得复用已清理的混合暂存: res=%+v", res)
	}
}

func assertSCPDownloadSymlinkDriftRejected(t *testing.T) {
	t.Helper()
	rig := newTransferRig(t, rigOptions{profile: gate.PolicyProfileStrictAgent, approvalThresh: security.RiskDangerous, omitOperatorRead: true})
	defer rig.close()
	ctx := context.Background()

	const chunkSz = 4096
	srcPath := mustRemotePath(t, "/tmp/pub/drift.bin")
	mustWriteRemote(t, rig.remoteFS, srcPath.String(), makePatternPayload(2*chunkSz))
	mustWriteRemote(t, rig.remoteFS, "/etc/shadow", bytes.Repeat([]byte("S"), 2*chunkSz))

	var drifted atomic.Bool
	rig.dialer.mu.Lock()
	rig.dialer.onReadChunk = func(hCtx context.Context, p pathalg.RemotePath, offset, _ int64) error {
		if p.Equal(srcPath) && offset == chunkSz && drifted.CompareAndSwap(false, true) {
			if rErr := rig.remoteFS.Remove(hCtx, srcPath); rErr != nil {
				return rErr
			}
			return rig.remoteFS.PutSymlink(srcPath, "/etc/shadow")
		}
		return nil
	}
	rig.dialer.mu.Unlock()

	_, err := rig.svc.SCPDownload(ctx, transfer.SCPDownloadRequest{
		CallBase: rig.callBase(nil), RemoteSource: srcPath,
		LocalRoot: rig.localRoot, LocalDest: mustLocalDest(t, "dl/drift.bin"),
		SymlinkPolicy: pathalg.SymlinkReject, ChunkSize: chunkSz, Concurrency: 1,
	})
	requireErrIs(t, err, gate.ErrScopeEscalated, "StrictAgent 下 SCPDownload 传输中软链漂移至 /etc/shadow 必须返回 ErrScopeEscalated")
	requireNoErr(t, rig.scopedFS.WithRoot(rig.localRoot, func(root ports.RootHandle) error {
		_, lErr := root.Lstat(mustLocalDest(t, "dl/drift.bin"))
		requireErrIs(t, lErr, ports.ErrNotFound, "漂移拦截后本地目标文件不得落盘")
		return nil
	}), "check no local drift.bin")
}
