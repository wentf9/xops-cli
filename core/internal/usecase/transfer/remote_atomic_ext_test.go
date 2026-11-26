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
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/usecase/transfer"
	"github.com/wentf9/xops-cli/core/ports"
)

func TestRemoteAtomic_ReadWriteAndPreconditionExclusivity(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newTransferRig(t, rigOptions{omitOperatorRead: true, omitScopedFS: true, omitJournals: true})
	defer rig.close()
	ctx := context.Background()

	// WriteFile CreateParents + NoClobber + ReadFile Anchor
	p := mustRemotePath(t, "/app/cfg/service.toml")
	w1, err := rig.svc.WriteFile(ctx, transfer.WriteFileRequest{
		CallBase: rig.callBase(nil), Path: p, Content: []byte("port = 8080\n"), CreateParents: true, NoClobber: true,
	})
	requireNoErr(t, err, "WriteFile create")
	if w1.BytesWritten != 12 || !w1.Stat.Anchor().IsValid() {
		t.Fatalf("WriteFile 结果异常: %+v", w1)
	}
	// NoClobber 阻断覆写
	_, err = rig.svc.WriteFile(ctx, transfer.WriteFileRequest{
		CallBase: rig.callBase(nil), Path: p, Content: []byte("port = 9090\n"), NoClobber: true,
	})
	requireErrIs(t, err, ports.ErrAlreadyExists, "WriteFile NoClobber 必须阻断覆写")

	// ReadFile 返回内容、摘要与锚点；超出 MaxBytes 失败；读目录返回 ErrRemoteIsDir
	r1, err := rig.svc.ReadFile(ctx, transfer.ReadFileRequest{CallBase: rig.callBase(nil), Path: p})
	requireNoErr(t, err, "ReadFile")
	if string(r1.Content) != "port = 8080\n" || !r1.Digest.Equal(w1.Digest) || !r1.Stat.Anchor().Equal(w1.Stat.Anchor()) {
		t.Fatalf("ReadFile 快照不一致: %+v", r1)
	}
	_, err = rig.svc.ReadFile(ctx, transfer.ReadFileRequest{CallBase: rig.callBase(nil), Path: p, MaxBytes: 4})
	requireErrIs(t, err, ports.ErrLimitExceeded, "超出 MaxBytes 必须拒绝")
	_, err = rig.svc.ReadFile(ctx, transfer.ReadFileRequest{CallBase: rig.callBase(nil), Path: mustRemotePath(t, "/app/cfg")})
	requireErrIs(t, err, ports.ErrRemoteIsDir, "读取目录必须返回 ErrRemoteIsDir")

	// ExpectedAnchor 匹配允许更新，过期锚点返回 ErrRemoteAnchorMismatch
	w2, err := rig.svc.WriteFile(ctx, transfer.WriteFileRequest{
		CallBase: rig.callBase(nil), Path: p, Content: []byte("port = 8443\n"), ExpectedAnchor: algebraic.Some(r1.Stat.Anchor()),
	})
	requireNoErr(t, err, "WriteFile with matching ExpectedAnchor")
	_, err = rig.svc.WriteFile(ctx, transfer.WriteFileRequest{
		CallBase: rig.callBase(nil), Path: p, Content: []byte("stale"), ExpectedAnchor: algebraic.Some(r1.Stat.Anchor()),
	})
	requireErrIs(t, err, ports.ErrRemoteAnchorMismatch, "过期锚点写入必须失败")

	// 互斥 NoClobber + ExpectedAnchor 在进入 Gate/Pool 前快速失败（0 拨号）
	rigZeroDial := newTransferRig(t, rigOptions{omitOperatorRead: true, omitScopedFS: true, omitJournals: true})
	defer rigZeroDial.close()
	_, err = rigZeroDial.svc.WriteFile(ctx, transfer.WriteFileRequest{
		CallBase: rigZeroDial.callBase(nil), Path: p, Content: []byte("x"),
		NoClobber: true, ExpectedAnchor: algebraic.Some(w2.Stat.Anchor()),
	})
	requireErrIs(t, err, ports.ErrInvalidArgument, "互斥 NoClobber+ExpectedAnchor 必须拒绝")
	if rigZeroDial.dialer.dialCount.Load() != 0 {
		t.Fatalf("互斥前置校验失败前不应拨号，实际=%d", rigZeroDial.dialer.dialCount.Load())
	}
}

func TestRemoteAtomic_PatchFileAndConcurrentLostUpdatePrevention(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newTransferRig(t, rigOptions{omitOperatorRead: true, omitScopedFS: true, omitJournals: true})
	defer rig.close()
	ctx := context.Background()

	p := mustRemotePath(t, "/etc/app/config.ini")
	st0 := mustWriteRemote(t, rig.remoteFS, "/etc/app/config.ini", []byte("mode=dev\nlog=info\nlog=info\n"))

	// 1. 歧义匹配（ReplaceAll=false 命中 2 处）与未命中均必须失败且不改文件
	ambEdit, err := transfer.NewTextEdit("log=info", "log=warn", false)
	requireNoErr(t, err, "ambEdit")
	_, err = rig.svc.PatchFile(ctx, transfer.PatchFileRequest{CallBase: rig.callBase(nil), Path: p, Edits: []transfer.TextEdit{ambEdit}})
	requireErrIs(t, err, transfer.ErrPatchAmbiguous, "多处命中且非 ReplaceAll 必须返回 ErrPatchAmbiguous")
	missEdit, err := transfer.NewTextEdit("nonexistent", "x", false)
	requireNoErr(t, err, "missEdit")
	_, err = rig.svc.PatchFile(ctx, transfer.PatchFileRequest{CallBase: rig.callBase(nil), Path: p, Edits: []transfer.TextEdit{missEdit}})
	requireErrIs(t, err, transfer.ErrPatchNoMatch, "未命中必须返回 ErrPatchNoMatch")

	// 2. 正常多条补丁（含 ReplaceAll=true）成功应用
	e1, err := transfer.NewTextEdit("mode=dev", "mode=prod", false)
	requireNoErr(t, err, "e1")
	e2, err := transfer.NewTextEdit("log=info", "log=warn", true)
	requireNoErr(t, err, "e2")
	pRes, err := rig.svc.PatchFile(ctx, transfer.PatchFileRequest{
		CallBase: rig.callBase(nil), Path: p, Edits: []transfer.TextEdit{e1, e2},
		ExpectedAnchor: algebraic.Some(st0.Anchor()),
	})
	requireNoErr(t, err, "PatchFile success")
	if pRes.Replacements != 3 || string(mustReadRemote(t, rig.remoteFS, "/etc/app/config.ini")) != "mode=prod\nlog=warn\nlog=warn\n" {
		t.Fatalf("PatchFile 结果异常: %+v", pRes)
	}

	// 3. 对抗测试：读-写间隙出现并发写入者修改目标文件，FSTAT 锚定必须阻断 Lost Update 并保留并发写入内容
	var injected atomic.Bool
	rig.dialer.mu.Lock()
	rig.dialer.onBeforeWriteAtomic = func(hCtx context.Context, target pathalg.RemotePath) error {
		if target.Equal(p) && injected.CompareAndSwap(false, true) {
			spec, _ := ports.NewRemoteWriteSpec(ports.RemoteWriteSpecInput{Perm: 0o644, AtomicRename: true})
			_, wErr := rig.remoteFS.WriteFileAtomic(hCtx, p, spec, bytes.NewReader([]byte("concurrent-writer-won\n")))
			return wErr
		}
		return nil
	}
	rig.dialer.mu.Unlock()

	e3, err := transfer.NewTextEdit("mode=prod", "mode=stale-overwrite", false)
	requireNoErr(t, err, "e3")
	_, err = rig.svc.PatchFile(ctx, transfer.PatchFileRequest{CallBase: rig.callBase(nil), Path: p, Edits: []transfer.TextEdit{e3}})
	requireErrIs(t, err, ports.ErrRemoteAnchorMismatch, "并发修改必须触发 ErrRemoteAnchorMismatch 防止 Lost Update")
	if string(mustReadRemote(t, rig.remoteFS, "/etc/app/config.ini")) != "concurrent-writer-won\n" {
		t.Fatalf("并发写入者内容遭到覆写！")
	}
}

func TestRemoteAtomic_RenameFilePreconditionsAndRound2Redirect(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newTransferRig(t, rigOptions{omitOperatorRead: true, omitScopedFS: true, omitJournals: true})
	defer rig.close()
	ctx := context.Background()

	oldP := mustRemotePath(t, "/work/a.tmp")
	newP := mustRemotePath(t, "/work/b.cfg")
	mustWriteRemote(t, rig.remoteFS, "/work/a.tmp", []byte("new-v2"))
	stB := mustWriteRemote(t, rig.remoteFS, "/work/b.cfg", []byte("old-v1"))

	// NoClobber 阻止覆盖已有目标
	err := rig.svc.RenameFile(ctx, transfer.RenameFileRequest{CallBase: rig.callBase(nil), OldPath: oldP, NewPath: newP, NoClobber: true})
	requireErrIs(t, err, ports.ErrAlreadyExists, "RenameFile NoClobber 必须阻断")

	// 互斥 NoClobber + ExpectedAnchor 必须拒绝
	err = rig.svc.RenameFile(ctx, transfer.RenameFileRequest{
		CallBase: rig.callBase(nil), OldPath: oldP, NewPath: newP, NoClobber: true, ExpectedAnchor: algebraic.Some(stB.Anchor()),
	})
	requireErrIs(t, err, ports.ErrInvalidArgument, "RenameFile 互斥前提必须拒绝")

	// 错误 ExpectedAnchor 必须阻断；匹配 ExpectedAnchor 成功重命名
	wrongAnc, err := ports.NewRemoteFileAnchor(ports.RemoteFileRegular, true, 99, 99999)
	requireNoErr(t, err, "wrongAnc")
	err = rig.svc.RenameFile(ctx, transfer.RenameFileRequest{
		CallBase: rig.callBase(nil), OldPath: oldP, NewPath: newP, ExpectedAnchor: algebraic.Some(wrongAnc),
	})
	requireErrIs(t, err, ports.ErrRemoteAnchorMismatch, "不匹配锚点必须阻断 RenameFile")

	requireNoErr(t, rig.svc.RenameFile(ctx, transfer.RenameFileRequest{
		CallBase: rig.callBase(nil), OldPath: oldP, NewPath: newP, ExpectedAnchor: algebraic.Some(stB.Anchor()),
	}), "匹配锚点 RenameFile")
	if string(mustReadRemote(t, rig.remoteFS, "/work/b.cfg")) != "new-v2" {
		t.Fatalf("重命名后内容不符")
	}

	// StrictAgent 下 NewPath 经软链重定向到 /etc/passwd 必须被 Round-2 拦截
	strictRig := newTransferRig(t, rigOptions{profile: gate.PolicyProfileStrictAgent, approvalThresh: security.RiskDangerous, omitOperatorRead: true})
	defer strictRig.close()
	mustWriteRemote(t, strictRig.remoteFS, "/tmp/src.txt", []byte("evil"))
	mustWriteRemote(t, strictRig.remoteFS, "/etc/passwd", []byte("root:x:0:0"))
	requireNoErr(t, strictRig.remoteFS.PutSymlink(mustRemotePath(t, "/tmp/target-link"), "/etc/passwd"), "PutSymlink target-link")
	err = strictRig.svc.RenameFile(ctx, transfer.RenameFileRequest{
		CallBase: strictRig.callBase(nil), OldPath: mustRemotePath(t, "/tmp/src.txt"), NewPath: mustRemotePath(t, "/tmp/target-link"),
	})
	if err == nil {
		t.Fatalf("StrictAgent Round-2 必须阻断重命名覆盖 /etc/passwd 软链目标")
	}
	if string(mustReadRemote(t, strictRig.remoteFS, "/etc/passwd")) != "root:x:0:0" {
		t.Fatalf("/etc/passwd 不得被篡改")
	}
}

func TestRound2Canonicalization_MultiHopIntermediateDanglingAndRelativeAnchoring(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newTransferRig(t, rigOptions{profile: gate.PolicyProfileStrictAgent, approvalThresh: security.RiskDangerous, omitOperatorRead: true})
	defer rig.close()
	ctx := context.Background()

	// 1. 多跳悬空软链：/tmp/h1 -> /tmp/h2 -> /etc/cron.d/pwn（均不存在）必须在 Round-2 拦截
	requireNoErr(t, rig.remoteFS.MkdirAll(ctx, mustRemotePath(t, "/tmp"), 0o755), "MkdirAll /tmp")
	requireNoErr(t, rig.remoteFS.PutSymlink(mustRemotePath(t, "/tmp/h1"), "/tmp/h2"), "PutSymlink h1")
	requireNoErr(t, rig.remoteFS.PutSymlink(mustRemotePath(t, "/tmp/h2"), "/etc/cron.d/pwn"), "PutSymlink h2")
	_, err := rig.svc.WriteFile(ctx, transfer.WriteFileRequest{CallBase: rig.callBase(nil), Path: mustRemotePath(t, "/tmp/h1"), Content: []byte("pwn")})
	requireErrIs(t, err, gate.ErrApprovalRequired, "多跳悬空软链指向 /etc/cron.d/pwn 必须在 Round-2 拦截")

	// 2. 中间悬空目录软链 + CreateParents=true / MkdirAll 必须在 Round-2 展开并拦截
	requireNoErr(t, rig.remoteFS.PutSymlink(mustRemotePath(t, "/tmp/dangling_dir"), "/etc/newdir"), "PutSymlink dangling_dir")
	_, err = rig.svc.WriteFile(ctx, transfer.WriteFileRequest{
		CallBase: rig.callBase(nil), Path: mustRemotePath(t, "/tmp/dangling_dir/evil.conf"), Content: []byte("x"), CreateParents: true,
	})
	requireErrIs(t, err, gate.ErrApprovalRequired, "中间悬空目录软链 WriteFile(CreateParents) 必须拦截")
	err = rig.svc.MkdirAll(ctx, transfer.MkdirAllRequest{CallBase: rig.callBase(nil), Path: mustRemotePath(t, "/tmp/dangling_dir/sub")})
	requireErrIs(t, err, gate.ErrApprovalRequired, "中间悬空目录软链 MkdirAll 必须拦截")
	if _, sErr := rig.remoteFS.Lstat(ctx, mustRemotePath(t, "/etc/newdir")); sErr == nil {
		t.Fatalf("/etc/newdir 不得被创建")
	}

	// 3. 相对路径含前导 ..（cwd=/tmp, req=../etc/shadow）须经 RealPath(".") 锚定后阻断
	rig.dialer.mu.Lock()
	rig.dialer.onRealPath = func(_ context.Context, p pathalg.RemotePath) (pathalg.RemotePath, bool, error) {
		if p.String() == "." {
			return mustRemotePath(t, "/tmp"), true, nil
		}
		var z pathalg.RemotePath
		return z, false, nil
	}
	rig.dialer.mu.Unlock()
	_, err = rig.svc.WriteFile(ctx, transfer.WriteFileRequest{CallBase: rig.callBase(nil), Path: mustRemotePath(t, "../etc/shadow"), Content: []byte("pwn")})
	requireErrIs(t, err, gate.ErrApprovalRequired, "相对路径 ../etc/shadow 必须锚定工作目录并被 Round-2 阻断")
	rig.dialer.mu.Lock()
	rig.dialer.onRealPath = nil
	rig.dialer.mu.Unlock()

	// 4. 悬空软链环路（即使 RealPath 返回 ErrNotFound）必须受 MaxSymlinkHops 有界预算保护并 Fail-Closed
	requireNoErr(t, rig.remoteFS.PutSymlink(mustRemotePath(t, "/tmp/loop1"), "/tmp/loop2"), "PutSymlink loop1")
	requireNoErr(t, rig.remoteFS.PutSymlink(mustRemotePath(t, "/tmp/loop2"), "/tmp/loop1"), "PutSymlink loop2")
	_, err = rig.svc.WriteFile(ctx, transfer.WriteFileRequest{CallBase: rig.callBase(nil), Path: mustRemotePath(t, "/tmp/loop1"), Content: []byte("x")})
	requireErrIs(t, err, gate.ErrAuthorizationDenied, "RealPath 检出软链环路必须 Fail-Closed 拒绝")
	rig.dialer.mu.Lock()
	rig.dialer.onRealPath = func(_ context.Context, _ pathalg.RemotePath) (pathalg.RemotePath, bool, error) {
		var z pathalg.RemotePath
		return z, true, ports.ErrNotFound
	}
	rig.dialer.mu.Unlock()
	_, err = rig.svc.WriteFile(ctx, transfer.WriteFileRequest{CallBase: rig.callBase(nil), Path: mustRemotePath(t, "/tmp/loop1"), Content: []byte("x")})
	requireErrIs(t, err, transfer.ErrSymlinkPolicyDenied, "悬空软链展开环路必须受 MaxSymlinkHops 预算拦截")
}

func TestRemoteAtomic_ReadFileModTimeChangeAndRelativeSingleSegmentWrite(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newTransferRig(t, rigOptions{omitOperatorRead: true, omitScopedFS: true, omitJournals: true})
	defer rig.close()
	ctx := context.Background()

	// 1. 同大小原地覆写导致 ModTime 变化时，ReadFile 必须触发 ErrRemoteAnchorMismatch
	p := mustRemotePath(t, "/app/same.txt")
	mustWriteRemote(t, rig.remoteFS, "/app/same.txt", []byte("abcd"))
	newMod := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	var mutated atomic.Bool
	rig.dialer.mu.Lock()
	rig.dialer.onAfterWithReadFile = func(hCtx context.Context, target pathalg.RemotePath) error {
		if target.Equal(p) && mutated.CompareAndSwap(false, true) {
			return rig.remoteFS.Chtimes(hCtx, p, newMod, newMod)
		}
		return nil
	}
	rig.dialer.mu.Unlock()
	_, err := rig.svc.ReadFile(ctx, transfer.ReadFileRequest{CallBase: rig.callBase(nil), Path: p})
	requireErrIs(t, err, ports.ErrRemoteAnchorMismatch, "读取窗口内 ModTime 变更必须触发 ErrRemoteAnchorMismatch")

	// 2. 单段相对路径 WriteFile(CreateParents=true) 不应调用 MkdirAll(".")
	wRes, err := rig.svc.WriteFile(ctx, transfer.WriteFileRequest{
		CallBase: rig.callBase(nil), Path: mustRemotePath(t, "hello.txt"), Content: []byte("hi"), CreateParents: true,
	})
	requireNoErr(t, err, "单段相对路径 WriteFile(CreateParents=true)")
	if wRes.BytesWritten != 2 {
		t.Fatalf("BytesWritten=%d, want 2", wRes.BytesWritten)
	}
}
