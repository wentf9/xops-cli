package tck

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"testing"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
)

// ScopedRootFSFixture 描述 ScopedRootFS 契约测试夹具。
type ScopedRootFSFixture struct {
	// NewRoot 返回隔离的 ScopedRootFS 与测试沙箱根目录（每次调用应返回全新空白目录）。
	NewRoot func(t *testing.T) (ports.ScopedRootFS, pathalg.LocalDir)
	// CheckSymlink 为 true 时在全平台绝对/逃逸拒绝检查之外，额外验证合法相对符号链接创建与 Lstat；
	// 在无符号链接权限的 Windows 环境下可留 false，避免因 OS 权限导致误报。
	CheckSymlink bool
}

// OperatorReadFSFixture 描述 OperatorReadFS 双模态只读源契约测试夹具。
type OperatorReadFSFixture struct {
	// NewReader 返回待测 OperatorReadFS 实例。
	NewReader func(t *testing.T) ports.OperatorReadFS
	// RegularFile 指向存在的常规文件及其预期内容。
	RegularFile     pathalg.LocalSourcePath
	ExpectedContent []byte
	// MissingFile 指向不存在的文件路径。
	MissingFile pathalg.LocalSourcePath
	// SymlinkFile 指向有效符号链接（可选；提供时验证 SymlinkReject 拒绝而 SymlinkFollowOperatorSource 放行）。
	SymlinkFile pathalg.LocalSourcePath
}

// RunScopedRootFSSuite 验证 ScopedRootFS 全部沙箱读写、有界读取、回滚、软链安全、旁路文件锁与崩溃清理契约。
func RunScopedRootFSSuite(t *testing.T, fx ScopedRootFSFixture) {
	t.Helper()
	requireTrue(t, fx.NewRoot != nil, "ScopedRootFSFixture.NewRoot 不能为 nil")

	t.Run("ValidationAndNilGuards", func(t *testing.T) {
		fsPort, dir := fx.NewRoot(t)
		var zeroDir pathalg.LocalDir

		requireErrIs(t, fsPort.WithRoot(dir, nil), ports.ErrNilCallback, "WithRoot(nil fn)")
		requireErr(t, fsPort.WithRoot(zeroDir, func(ports.RootHandle) error { return nil }), "WithRoot(zero dir)")
	})

	t.Run("CreateReadReplaceAppendAndSymlinkOps", func(t *testing.T) {
		fsPort, dir := fx.NewRoot(t)
		err := fsPort.WithRoot(dir, func(root ports.RootHandle) error {
			verifyRootFileLifecycle(t, root, fx.CheckSymlink)
			return nil
		})
		requireNoErr(t, err, "WithRoot(CreateReadReplaceAppendAndSymlinkOps)")
	})

	t.Run("LockedFileSharedExclusiveAndCancellation", func(t *testing.T) {
		defer VerifyNoLeaks(t)
		fsPort, dir := fx.NewRoot(t)
		verifyRootLockingContract(t, fsPort, dir)
	})
}

func verifyRootFileLifecycle(t *testing.T, root ports.RootHandle, checkSymlink bool) {
	t.Helper()
	subDir, err := pathalg.ParseLocalRootedDest("nested/sub")
	requireNoErr(t, err, "ParseLocalRootedDest(subDir)")
	requireNoErr(t, root.MkdirAll(subDir, 0o700), "MkdirAll")

	fileRel, err := pathalg.ParseLocalRootedDest("nested/sub/config.yaml")
	requireNoErr(t, err, "ParseLocalRootedDest(fileRel)")
	requireErrIs(t, root.CreateExclusive(fileRel, 0o600, nil), ports.ErrNilCallback, "CreateExclusive(nil fn)")
	requireNoErr(t, root.CreateExclusive(fileRel, 0o600, func(w io.Writer) error {
		_, wErr := w.Write([]byte("v1-payload"))
		return wErr
	}), "CreateExclusive")
	requireErrIs(t, root.CreateExclusive(fileRel, 0o600, func(w io.Writer) error {
		_, wErr := w.Write([]byte("dup"))
		return wErr
	}), ports.ErrAlreadyExists, "重复 CreateExclusive")

	lim, err := ports.NewReadLimits(1024)
	requireNoErr(t, err, "NewReadLimits")
	got, err := root.ReadAllBounded(fileRel, lim)
	requireNoErr(t, err, "ReadAllBounded")
	requireTrue(t, bytes.Equal(got, []byte("v1-payload")), "ReadAllBounded 内容不匹配")

	smallLim, err := ports.NewReadLimits(4)
	requireNoErr(t, err, "NewReadLimits(small)")
	_, err = root.ReadAllBounded(fileRel, smallLim)
	requireErrIs(t, err, ports.ErrLimitExceeded, "超出 ReadLimits 须返回 ErrLimitExceeded")

	requireErrIs(t, root.WithReadRegular(fileRel, lim, nil), ports.ErrNilCallback, "WithReadRegular(nil fn)")
	requireErrIs(t, root.AtomicReplace(fileRel, 0o600, nil), ports.ErrNilCallback, "AtomicReplace(nil fn)")
	requireNoErr(t, root.AtomicReplace(fileRel, 0o600, func(w io.Writer) error {
		_, wErr := w.Write([]byte("v2-replaced"))
		return wErr
	}), "AtomicReplace")

	var streamed []byte
	err = root.WithReadRegular(fileRel, lim, func(r io.Reader, size int64) error {
		requireTrue(t, size == int64(len("v2-replaced")), "WithReadRegular 报告大小不匹配")
		var rErr error
		streamed, rErr = io.ReadAll(r)
		return rErr
	})
	requireNoErr(t, err, "WithReadRegular")
	requireTrue(t, bytes.Equal(streamed, []byte("v2-replaced")), "AtomicReplace 后读取内容不匹配")

	verifyRootAppendAndLimits(t, root, fileRel, lim)
	verifyRootRollbackAndSymlink(t, root, fileRel, lim, checkSymlink)
	verifyRootMetadataAndRemove(t, root, subDir, fileRel)
}

func verifyRootAppendAndLimits(t *testing.T, root ports.RootHandle, fileRel pathalg.LocalRootedDest, lim ports.ReadLimits) {
	t.Helper()
	var zeroLim ports.ReadLimits
	_, err := root.ReadAllBounded(fileRel, zeroLim)
	requireErr(t, err, "ReadAllBounded(zero limits)")
	requireErr(t, root.WithReadRegular(fileRel, zeroLim, func(io.Reader, int64) error { return nil }), "WithReadRegular(zero limits)")

	logRel, err := pathalg.ParseLocalRootedDest("audit.jsonl")
	requireNoErr(t, err, "ParseLocalRootedDest(audit.jsonl)")
	requireNoErr(t, root.AppendLine(logRel, 0o600, []byte(`{"seq":1}`)), "AppendLine(1)")
	requireNoErr(t, root.AppendLine(logRel, 0o600, []byte(`{"seq":2}`)), "AppendLine(2)")
	requireErrIs(t, root.AppendLine(logRel, 0o600, []byte("bad\nline")), ports.ErrInvalidArgument, "AppendLine 须拒绝内嵌 LF")
	requireErrIs(t, root.AppendLine(logRel, 0o600, []byte("bad\rline")), ports.ErrInvalidArgument, "AppendLine 须拒绝内嵌 CR")

	logBytes, err := root.ReadAllBounded(logRel, lim)
	requireNoErr(t, err, "ReadAllBounded(audit.jsonl)")
	wantLog := []byte("{\"seq\":1}\n{\"seq\":2}\n")
	requireTrue(t, bytes.Equal(logBytes, wantLog), "AppendLine 精确换行帧内容不匹配")
}

func verifyRootRollbackAndSymlink(t *testing.T, root ports.RootHandle, fileRel pathalg.LocalRootedDest, lim ports.ReadLimits, checkSymlink bool) {
	t.Helper()
	abortErr := errors.New("tck callback abort")

	abortedRel, err := pathalg.ParseLocalRootedDest("nested/sub/aborted.tmp")
	requireNoErr(t, err, "ParseLocalRootedDest(aborted)")
	err = root.CreateExclusive(abortedRel, 0o600, func(w io.Writer) error {
		_, _ = w.Write([]byte("partial"))
		return abortErr
	})
	requireErrIs(t, err, abortErr, "CreateExclusive 回调失败须透传错误")
	_, err = root.Stat(abortedRel)
	requireErrIs(t, err, ports.ErrNotFound, "CreateExclusive 回调失败不得残留半成品文件")

	err = root.AtomicReplace(fileRel, 0o600, func(w io.Writer) error {
		_, _ = w.Write([]byte("corrupt-overwrite"))
		return abortErr
	})
	requireErrIs(t, err, abortErr, "AtomicReplace 回调失败须透传错误")
	preserved, err := root.ReadAllBounded(fileRel, lim)
	requireNoErr(t, err, "AtomicReplace 失败后重读原文件")
	requireTrue(t, bytes.Equal(preserved, []byte("v2-replaced")), "AtomicReplace 回调失败必须保留原有文件内容")

	// 绝对路径与沙箱逃逸软链目标在全平台均须拒绝。
	badLink, err := pathalg.ParseLocalRootedDest("nested/sub/bad.link")
	requireNoErr(t, err, "ParseLocalRootedDest(bad.link)")
	requireErr(t, root.CreateSymlink(badLink, "/etc/passwd"), "CreateSymlink 必须拒绝绝对目标路径")
	requireErr(t, root.CreateSymlink(badLink, "../../../escape"), "CreateSymlink 必须拒绝逃逸沙箱根的相对路径")

	if checkSymlink {
		relLink, lErr := pathalg.ParseLocalRootedDest("nested/sub/cfg.link")
		requireNoErr(t, lErr, "ParseLocalRootedDest(cfg.link)")
		requireNoErr(t, root.CreateSymlink(relLink, "config.yaml"), "CreateSymlink(relative)")
		lst, sErr := root.Lstat(relLink)
		requireNoErr(t, sErr, "Lstat(cfg.link)")
		requireTrue(t, lst.IsValid() && lst.IsSymlink(), "Lstat 须准确报告 IsSymlink()")
		requireNoErr(t, root.Remove(relLink), "Remove(cfg.link)")
	}
}

func verifyRootMetadataAndRemove(t *testing.T, root ports.RootHandle, subDir, fileRel pathalg.LocalRootedDest) {
	t.Helper()
	info, err := root.Stat(fileRel)
	requireNoErr(t, err, "Stat")
	requireTrue(t, info.IsValid() && info.IsRegular() && info.Size() == int64(len("v2-replaced")), "Stat 元信息无效")
	linfo, err := root.Lstat(fileRel)
	requireNoErr(t, err, "Lstat")
	requireTrue(t, linfo.IsValid() && linfo.IsRegular(), "Lstat 元信息无效")

	entries, err := root.ReadDir(algebraic.Some(subDir))
	requireNoErr(t, err, "ReadDir(subDir)")
	requireTrue(t, len(entries) == 1 && entries[0].IsValid() && entries[0].Name() == "config.yaml", "ReadDir(subDir) 结果不匹配")

	rootEntries, err := root.ReadDir(algebraic.None[pathalg.LocalRootedDest]())
	requireNoErr(t, err, "ReadDir(root)")
	requireTrue(t, len(rootEntries) >= 1, "ReadDir(None) 须列举沙箱根目录内容")

	requireNoErr(t, root.Remove(fileRel), "Remove")
	requireErrIs(t, root.Remove(fileRel), ports.ErrNotFound, "重复 Remove 须返回 ErrNotFound")
}

func verifyRootLockingContract(t *testing.T, fsPort ports.ScopedRootFS, dir pathalg.LocalDir) {
	t.Helper()
	lockRel, err := pathalg.ParseLocalRootedDest("proc-01.lock")
	requireNoErr(t, err, "ParseLocalRootedDest(lock)")
	missingLock, err := pathalg.ParseLocalRootedDest("missing-no-create.lock")
	requireNoErr(t, err, "ParseLocalRootedDest(missingLock)")

	ctx := context.Background()
	err = fsPort.WithRoot(dir, func(root ports.RootHandle) error {
		verifyLockGuardsAndWriteTruncate(t, ctx, root, lockRel, missingLock)
		return nil
	})
	requireNoErr(t, err, "WithRoot(LockWriteTruncate)")

	verifyExclusiveLockContention(t, ctx, fsPort, dir, lockRel)
	verifySharedLockConcurrency(t, ctx, fsPort, dir, lockRel)

	err = fsPort.WithRoot(dir, func(root ports.RootHandle) error {
		return root.Remove(lockRel)
	})
	requireNoErr(t, err, "锁释放后 Remove")
}

func verifyLockGuardsAndWriteTruncate(t *testing.T, ctx context.Context, root ports.RootHandle, lockRel, missingLock pathalg.LocalRootedDest) {
	t.Helper()
	var nilCtx context.Context
	requireErrIs(t, root.WithLockedFile(nilCtx, lockRel, ports.LockExclusive, true, 0o600, func(ports.LockedFile) error { return nil }), ports.ErrNilContext, "WithLockedFile(nil ctx)")
	requireErrIs(t, root.WithLockedFile(ctx, lockRel, ports.LockExclusive, true, 0o600, nil), ports.ErrNilCallback, "WithLockedFile(nil fn)")
	requireErr(t, root.WithLockedFile(ctx, lockRel, ports.LockModeInvalid, true, 0o600, func(ports.LockedFile) error { return nil }), "WithLockedFile(invalid mode)")
	_, err := root.TryWithLockedFile(lockRel, ports.LockExclusive, true, 0o600, nil)
	requireErrIs(t, err, ports.ErrNilCallback, "TryWithLockedFile(nil fn)")
	_, err = root.TryWithLockedFile(lockRel, ports.LockModeInvalid, true, 0o600, func(ports.LockedFile) error { return nil })
	requireErr(t, err, "TryWithLockedFile(invalid mode)")
	_, err = root.TryWithLockedFile(missingLock, ports.LockExclusive, false, 0o600, func(ports.LockedFile) error { return nil })
	requireErrIs(t, err, ports.ErrNotFound, "TryWithLockedFile(create=false, missing)")

	err = root.WithLockedFile(ctx, lockRel, ports.LockExclusive, true, 0o600, func(lf ports.LockedFile) error {
		_, wErr := lf.Write([]byte("+op-1\n-op-1\n"))
		requireNoErr(t, wErr, "LockedFile.Write")
		_, sErr := lf.Seek(0, io.SeekStart)
		requireNoErr(t, sErr, "LockedFile.Seek")
		raw, rErr := io.ReadAll(lf)
		requireNoErr(t, rErr, "LockedFile.ReadAll")
		requireTrue(t, bytes.Equal(raw, []byte("+op-1\n-op-1\n")), "持锁读写内容不匹配")
		st, stErr := lf.Stat()
		requireNoErr(t, stErr, "LockedFile.Stat")
		requireTrue(t, st.IsValid() && st.Size() == int64(len(raw)), "LockedFile.Stat 大小不匹配")
		requireNoErr(t, lf.Truncate(0), "Truncate(0)")
		return lf.Sync()
	})
	requireNoErr(t, err, "WithLockedFile(WriteTruncate)")
}

func verifyExclusiveLockContention(t *testing.T, ctx context.Context, fsPort ports.ScopedRootFS, dir pathalg.LocalDir, lockRel pathalg.LocalRootedDest) {
	t.Helper()
	err := fsPort.WithRoot(dir, func(root ports.RootHandle) error {
		var skipped atomic.Int32
		wErr := root.WithLockedFile(ctx, lockRel, ports.LockExclusive, true, 0o600, func(ports.LockedFile) error {
			return runLockContentionPeers(ctx, fsPort, dir, lockRel, &skipped)
		})
		requireNoErr(t, wErr, "独占锁竞争闭包")
		requireTrue(t, skipped.Load() == 1, "持锁期间 TryWithLockedFile 必须非阻塞返回 (false, nil)")
		return nil
	})
	requireNoErr(t, err, "独占锁非阻塞探活与取消契约")
}

func runLockContentionPeers(ctx context.Context, fsPort ports.ScopedRootFS, dir pathalg.LocalDir, lockRel pathalg.LocalRootedDest, skipped *atomic.Int32) error {
	return conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		if err := n.Go(func(context.Context) error {
			return probePeerLock(fsPort, dir, lockRel, ports.LockExclusive, false, skipped)
		}); err != nil {
			return err
		}
		return n.Go(func(c context.Context) error {
			return probeCanceledLock(c, fsPort, dir, lockRel)
		})
	})
}

func probeCanceledLock(ctx context.Context, fsPort ports.ScopedRootFS, dir pathalg.LocalDir, lockRel pathalg.LocalRootedDest) error {
	return fsPort.WithRoot(dir, func(peer ports.RootHandle) error {
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		lErr := peer.WithLockedFile(cctx, lockRel, ports.LockExclusive, false, 0o600, func(ports.LockedFile) error { return nil })
		if !errors.Is(lErr, context.Canceled) {
			if lErr == nil {
				return errors.New("WithLockedFile(canceled ctx) 返回 nil，期望 context.Canceled")
			}
			return fmt.Errorf("WithLockedFile(canceled ctx) = %w, 期望 context.Canceled", lErr)
		}
		return nil
	})
}

func verifySharedLockConcurrency(t *testing.T, ctx context.Context, fsPort ports.ScopedRootFS, dir pathalg.LocalDir, lockRel pathalg.LocalRootedDest) {
	t.Helper()
	err := fsPort.WithRoot(dir, func(root ports.RootHandle) error {
		var sharedOK, exclBlocked atomic.Int32
		wErr := root.WithLockedFile(ctx, lockRel, ports.LockShared, false, 0o600, func(ports.LockedFile) error {
			return runSharedLockPeers(ctx, fsPort, dir, lockRel, &sharedOK, &exclBlocked)
		})
		requireNoErr(t, wErr, "共享锁并发验证闭包")
		requireTrue(t, sharedOK.Load() == 1 && exclBlocked.Load() == 1, "LockShared 须允许并发共享锁且互斥独占锁")
		return nil
	})
	requireNoErr(t, err, "共享锁并发契约")
}

func runSharedLockPeers(ctx context.Context, fsPort ports.ScopedRootFS, dir pathalg.LocalDir, lockRel pathalg.LocalRootedDest, sharedOK, exclBlocked *atomic.Int32) error {
	return conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		if err := n.Go(func(context.Context) error {
			return probePeerLock(fsPort, dir, lockRel, ports.LockShared, true, sharedOK)
		}); err != nil {
			return err
		}
		return n.Go(func(context.Context) error {
			return probePeerLock(fsPort, dir, lockRel, ports.LockExclusive, false, exclBlocked)
		})
	})
}

func probePeerLock(fsPort ports.ScopedRootFS, dir pathalg.LocalDir, lockRel pathalg.LocalRootedDest, mode ports.LockMode, wantAcq bool, counter *atomic.Int32) error {
	return fsPort.WithRoot(dir, func(peer ports.RootHandle) error {
		acq, err := peer.TryWithLockedFile(lockRel, mode, false, 0o600, func(ports.LockedFile) error { return nil })
		if err == nil && acq == wantAcq {
			counter.Add(1)
		}
		return err
	})
}

// RunOperatorReadFSSuite 验证 OperatorReadFS 操作员显式配置/密钥只读边界与符号链接策略契约。
func RunOperatorReadFSSuite(t *testing.T, fx OperatorReadFSFixture) {
	t.Helper()
	requireTrue(t, fx.NewReader != nil && fx.RegularFile.IsValid() && fx.MissingFile.IsValid(), "OperatorReadFSFixture 缺少必需夹具字段")

	t.Run("ValidationAndRegularRead", func(t *testing.T) {
		reader := fx.NewReader(t)
		var nilCtx context.Context
		var zeroPath pathalg.LocalSourcePath

		requireErrIs(t, reader.WithOperatorRead(nilCtx, fx.RegularFile, pathalg.SymlinkReject, func(io.Reader, int64) error { return nil }), ports.ErrNilContext, "nil ctx")
		requireErrIs(t, reader.WithOperatorRead(context.Background(), fx.RegularFile, pathalg.SymlinkReject, nil), ports.ErrNilCallback, "nil fn")
		requireErr(t, reader.WithOperatorRead(context.Background(), zeroPath, pathalg.SymlinkReject, func(io.Reader, int64) error { return nil }), "zero path")

		var got []byte
		err := reader.WithOperatorRead(context.Background(), fx.RegularFile, pathalg.SymlinkReject, func(r io.Reader, size int64) error {
			requireTrue(t, size == int64(len(fx.ExpectedContent)), "文件大小与预期不符")
			var rErr error
			got, rErr = io.ReadAll(r)
			return rErr
		})
		requireNoErr(t, err, "WithOperatorRead(regular)")
		requireTrue(t, bytes.Equal(got, fx.ExpectedContent), "WithOperatorRead 内容与预期不符")

		err = reader.WithOperatorRead(context.Background(), fx.MissingFile, pathalg.SymlinkReject, func(io.Reader, int64) error { return nil })
		requireErrIs(t, err, ports.ErrNotFound, "读取不存在文件须返回 ErrNotFound")
	})

	if fx.SymlinkFile.IsValid() {
		t.Run("SymlinkPolicyEnforcement", func(t *testing.T) {
			reader := fx.NewReader(t)
			err := reader.WithOperatorRead(context.Background(), fx.SymlinkFile, pathalg.SymlinkReject, func(io.Reader, int64) error { return nil })
			requireErrIs(t, err, ports.ErrSymlinkRejected, "SymlinkReject 必须拒绝符号链接")

			var got []byte
			err = reader.WithOperatorRead(context.Background(), fx.SymlinkFile, pathalg.SymlinkFollowOperatorSource, func(r io.Reader, _ int64) error {
				var rErr error
				got, rErr = io.ReadAll(r)
				return rErr
			})
			requireNoErr(t, err, "SymlinkFollowOperatorSource 应允许读取受控操作员源软链")
			requireTrue(t, bytes.Equal(got, fx.ExpectedContent), "软链读取内容不匹配")
		})
	}
}
