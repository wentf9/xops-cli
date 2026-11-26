package transfer_test

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"

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
