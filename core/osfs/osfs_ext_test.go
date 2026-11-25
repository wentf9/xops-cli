package osfs_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
	"go.uber.org/goleak"
)

// 编译期接口契约断言（ADR-007：ScopedFS 与 OperatorFS 严格单向实现各自端口）。
var (
	_ ports.ScopedRootFS   = (*osfs.ScopedFS)(nil)
	_ ports.OperatorReadFS = (*osfs.OperatorFS)(nil)
)

func probeSymlinkErr(t *testing.T) error {
	t.Helper()
	probeDir := t.TempDir()
	target := filepath.Join(probeDir, "target.txt")
	if err := os.WriteFile(target, []byte("ok"), 0o600); err != nil {
		return err
	}
	return os.Symlink("target.txt", filepath.Join(probeDir, "probe.link"))
}

func mustLocalDir(t *testing.T, raw string) pathalg.LocalDir {
	t.Helper()
	d, err := pathalg.ParseLocalDir(raw)
	if err != nil {
		t.Fatalf("ParseLocalDir(%q) 失败: %v", raw, err)
	}
	return d
}

func mustLocalDest(t *testing.T, raw string) pathalg.LocalRootedDest {
	t.Helper()
	d, err := pathalg.ParseLocalRootedDest(raw)
	if err != nil {
		t.Fatalf("ParseLocalRootedDest(%q) 失败: %v", raw, err)
	}
	return d
}

func mustLocalSource(t *testing.T, raw string) pathalg.LocalSourcePath {
	t.Helper()
	s, err := pathalg.ParseLocalSourcePath(raw)
	if err != nil {
		t.Fatalf("ParseLocalSourcePath(%q) 失败: %v", raw, err)
	}
	return s
}

func TestTCKScopedRootFSSuite(t *testing.T) {
	tck.RunScopedRootFSSuite(t, tck.ScopedRootFSFixture{
		NewRoot: func(t *testing.T) (ports.ScopedRootFS, pathalg.LocalDir) {
			return osfs.NewScopedRootFS(), mustLocalDir(t, t.TempDir())
		},
		CheckSymlink: probeSymlinkErr(t) == nil,
	})
}

func TestTCKOperatorReadFSSuite(t *testing.T) {
	dir := t.TempDir()
	regPath := filepath.Join(dir, "source.conf")
	want := []byte("operator-readable-secret-or-archive-payload\n")
	if err := os.WriteFile(regPath, want, 0o600); err != nil {
		t.Fatalf("写入测试源文件失败: %v", err)
	}
	fx := tck.OperatorReadFSFixture{
		NewReader:       func(*testing.T) ports.OperatorReadFS { return osfs.NewOperatorReadFS() },
		RegularFile:     mustLocalSource(t, regPath),
		ExpectedContent: want,
		MissingFile:     mustLocalSource(t, filepath.Join(dir, "missing.conf")),
	}
	if probeSymlinkErr(t) == nil {
		symPath := filepath.Join(dir, "source.link")
		if err := os.Symlink(regPath, symPath); err != nil {
			t.Fatalf("创建测试软链失败: %v", err)
		}
		fx.SymlinkFile = mustLocalSource(t, symPath)
	}
	tck.RunOperatorReadFSSuite(t, fx)
}

func TestDualModalityIsolationAndZeroValues(t *testing.T) {
	var scopedAny any = osfs.NewScopedRootFS()
	if _, ok := scopedAny.(ports.OperatorReadFS); ok {
		t.Fatal("ScopedFS 严禁实现 OperatorReadFS，防止 MCP 运行时越权断言")
	}
	var opAny any = osfs.NewOperatorReadFS()
	if _, ok := opAny.(ports.ScopedRootFS); ok {
		t.Fatal("OperatorFS 严禁实现 ScopedRootFS")
	}

	var zeroScoped osfs.ScopedFS
	if err := zeroScoped.WithRoot(mustLocalDir(t, t.TempDir()), func(ports.RootHandle) error { return nil }); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("零值 ScopedFS.WithRoot = %v, 期望 ErrInvalidArgument", err)
	}
	var zeroOp osfs.OperatorFS
	src := mustLocalSource(t, filepath.Join(t.TempDir(), "a.txt"))
	if err := zeroOp.WithOperatorRead(context.Background(), src, pathalg.SymlinkReject, func(io.Reader, int64) error { return nil }); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("零值 OperatorFS.WithOperatorRead = %v, 期望 ErrInvalidArgument", err)
	}
	var zeroSock osfs.ControlSocketPath
	if zeroSock.IsValid() || !zeroSock.IsZero() || zeroSock.Dir() != "" || zeroSock.Name() != "" || zeroSock.NativePath() != "" || zeroSock.String() != "" {
		t.Fatal("零值 ControlSocketPath 必须无效且访问器返回空串")
	}
	var zeroProbe osfs.SocketProbeStatus
	if zeroProbe != osfs.SocketProbeUnknown || zeroProbe.IsValid() || zeroProbe.String() != "unknown" {
		t.Fatalf("零值 SocketProbeStatus = %v (valid=%v, str=%q), 期望 unknown 且无效", zeroProbe, zeroProbe.IsValid(), zeroProbe.String())
	}
	var zeroCred osfs.PeerCred
	if zeroCred.IsValid() || !zeroCred.IsZero() || zeroCred.HasUID() || zeroCred.HasGID() || zeroCred.HasPID() {
		t.Fatal("零值 PeerCred 必须无效")
	}
}

func readRegularContent(root ports.RootHandle, dest pathalg.LocalRootedDest, lim ports.ReadLimits) ([]byte, error) {
	var got []byte
	err := osfs.OpenRegular(root, dest, lim, func(r io.Reader, size int64) error {
		var rErr error
		got, rErr = io.ReadAll(r)
		if rErr == nil && int64(len(got)) != size {
			return errors.New("大小不一致")
		}
		return rErr
	})
	return got, err
}

func TestSidecarLockAndAtomicReplacePrimitives(t *testing.T) {
	defer goleak.VerifyNone(t)
	fsPort := osfs.NewScopedRootFS()
	rootDir := mustLocalDir(t, t.TempDir())
	target, subDir := mustLocalDest(t, "state/config.yaml"), mustLocalDest(t, "state")
	lockDest, err := osfs.SidecarLockDest(target)
	if err != nil || lockDest.String() != "state/config.yaml.lock" {
		t.Fatalf("SidecarLockDest = (%v, %v), 期望 state/config.yaml.lock", lockDest, err)
	}
	lim, err := ports.NewReadLimits(4096)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	err = fsPort.WithRoot(rootDir, func(root ports.RootHandle) error {
		return verifySidecarReplaceFlow(t, ctx, root, subDir, target, lockDest, lim)
	})
	if err != nil {
		t.Fatalf("旁路锁与原子替换测试失败: %v", err)
	}
}

func verifySidecarReplaceFlow(t *testing.T, ctx context.Context, root ports.RootHandle, subDir, target, lockDest pathalg.LocalRootedDest, lim ports.ReadLimits) error {
	t.Helper()
	if err := root.MkdirAll(subDir, 0o700); err != nil {
		return err
	}
	if err := osfs.CreateExclusive(root, target, 0o600, func(w io.Writer) error {
		_, wErr := w.Write([]byte("version: 2\nseq: 0\n"))
		return wErr
	}); err != nil {
		return err
	}
	if err := osfs.AtomicReplaceWithSidecarLock(ctx, root, target, 0o600, func(w io.Writer) error {
		_, wErr := w.Write([]byte("version: 2\nseq: 1\n"))
		return wErr
	}); err != nil {
		return err
	}
	if _, err := root.Stat(lockDest); err != nil {
		return err
	}
	got, err := readRegularContent(root, target, lim)
	if err != nil {
		return err
	}
	if string(got) != "version: 2\nseq: 1\n" {
		t.Fatalf("替换后内容 = %q, 期望 version: 2\\nseq: 1\\n", string(got))
	}
	return osfs.WithSidecarLock(ctx, root, target, ports.LockShared, 0o600, func(f ports.LockedFile) error {
		_, stErr := f.Stat()
		return stErr
	})
}

func verifyLockContentionWhileHeld(t *testing.T, ctx context.Context, root ports.RootHandle, lockDest pathalg.LocalRootedDest) error {
	t.Helper()
	removed, rmErr := osfs.RemoveLockedFileSafely(root, lockDest)
	if rmErr != nil || removed {
		t.Errorf("活跃锁 RemoveLockedFileSafely = (%v, %v), 期望 (false, nil)", removed, rmErr)
	}
	waitCtx, cancel := context.WithCancel(ctx)
	return conc.RunWait(ctx, func(_ context.Context, inner *conc.Nursery) error {
		if err := inner.Go(func(context.Context) error { cancel(); return nil }); err != nil {
			return err
		}
		lErr := osfs.OpenLockedContext(waitCtx, root, lockDest, ports.LockExclusive, false, 0o600, func(ports.LockedFile) error { return nil })
		if !errors.Is(lErr, context.Canceled) {
			t.Errorf("等待锁取消返回 %v, 期望 context.Canceled", lErr)
		}
		return nil
	})
}

func verifyLockRemovedIdempotently(t *testing.T, root ports.RootHandle, lockDest pathalg.LocalRootedDest) error {
	t.Helper()
	removed, rmErr := osfs.RemoveLockedFileSafely(root, lockDest)
	if rmErr != nil || !removed {
		t.Fatalf("释放后 RemoveLockedFileSafely = (%v, %v), 期望 (true, nil)", removed, rmErr)
	}
	again, againErr := osfs.RemoveLockedFileSafely(root, lockDest)
	if againErr != nil || again {
		t.Fatalf("重复 RemoveLockedFileSafely = (%v, %v), 期望 (false, nil)", again, againErr)
	}
	if _, stErr := root.Stat(lockDest); !errors.Is(stErr, ports.ErrNotFound) {
		t.Fatalf("删除后 Stat = %v, 期望 ErrNotFound", stErr)
	}
	return nil
}

func TestRemoveLockedFileSafelyAndContentionCancellation(t *testing.T) {
	defer goleak.VerifyNone(t)
	fsPort := osfs.NewScopedRootFS()
	rootDir := mustLocalDir(t, t.TempDir())
	lockDest := mustLocalDest(t, "proc-42.lock")
	ctx := context.Background()

	if err := fsPort.WithRoot(rootDir, func(root ports.RootHandle) error {
		return root.AppendLine(lockDest, 0o600, []byte("+op-dead-1"))
	}); err != nil {
		t.Fatalf("准备残留锁文件失败: %v", err)
	}

	held, release := make(chan struct{}), make(chan struct{})
	err := conc.RunWait(ctx, func(runCtx context.Context, n *conc.Nursery) error {
		if err := n.Go(func(c context.Context) error {
			return fsPort.WithRoot(rootDir, func(root ports.RootHandle) error {
				return osfs.OpenLockedContext(c, root, lockDest, ports.LockExclusive, false, 0o600, func(ports.LockedFile) error {
					close(held)
					<-release
					return nil
				})
			})
		}); err != nil {
			return err
		}
		<-held
		return fsPort.WithRoot(rootDir, func(root ports.RootHandle) error {
			defer close(release)
			return verifyLockContentionWhileHeld(t, runCtx, root, lockDest)
		})
	})
	if err != nil {
		t.Fatalf("锁竞争与安全删锁并发验证失败: %v", err)
	}
	if err := fsPort.WithRoot(rootDir, func(root ports.RootHandle) error {
		return verifyLockRemovedIdempotently(t, root, lockDest)
	}); err != nil {
		t.Fatalf("释放后清理校验失败: %v", err)
	}
}

func runReplaceWorker(ctx context.Context, fsPort ports.ScopedRootFS, rootDir pathalg.LocalDir, target pathalg.LocalRootedDest, fill byte) error {
	return fsPort.WithRoot(rootDir, func(root ports.RootHandle) error {
		payload := bytes.Repeat([]byte{fill}, 128)
		for range 6 {
			if err := osfs.AtomicReplaceWithSidecarLock(ctx, root, target, 0o600, func(w io.Writer) error {
				_, wErr := w.Write(payload)
				return wErr
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

func verifyNoTempResidual(t *testing.T, root ports.RootHandle, target pathalg.LocalRootedDest, lim ports.ReadLimits) error {
	t.Helper()
	got, rErr := root.ReadAllBounded(target, lim)
	if rErr != nil {
		return rErr
	}
	if len(got) != 128 || !bytes.Equal(got, bytes.Repeat(got[:1], 128)) {
		t.Fatalf("并发原子替换产生撕裂内容: len=%d", len(got))
	}
	entries, dErr := root.ReadDir(algebraic.None[pathalg.LocalRootedDest]())
	if dErr != nil {
		return dErr
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".xops-tmp-") {
			t.Fatalf("残留未清理的临时文件: %q", e.Name())
		}
	}
	return nil
}

func TestConcurrentAtomicReplaceWithSidecarLock(t *testing.T) {
	defer goleak.VerifyNone(t)
	fsPort := osfs.NewScopedRootFS()
	rootDir := mustLocalDir(t, t.TempDir())
	target := mustLocalDest(t, "inventory.yaml")
	lim, err := ports.NewReadLimits(4096)
	if err != nil {
		t.Fatal(err)
	}
	err = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		for worker := range 4 {
			fill := byte('a' + worker)
			if err := n.Go(func(c context.Context) error {
				return runReplaceWorker(c, fsPort, rootDir, target, fill)
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("并发旁路锁原子替换失败: %v", err)
	}
	if err := fsPort.WithRoot(rootDir, func(root ports.RootHandle) error {
		return verifyNoTempResidual(t, root, target, lim)
	}); err != nil {
		t.Fatalf("并发替换结果核验失败: %v", err)
	}
}

func verifySymlinkAdversarialOps(t *testing.T, root ports.RootHandle, lim ports.ReadLimits) error {
	t.Helper()
	link := mustLocalDest(t, "keep.link")
	if err := root.CreateSymlink(link, "keep.txt"); err != nil {
		return err
	}
	if _, err := root.ReadAllBounded(link, lim); !errors.Is(err, ports.ErrSymlinkRejected) {
		t.Fatalf("ReadAllBounded(symlink) = %v, 期望 ErrSymlinkRejected", err)
	}
	if err := root.AppendLine(link, 0o600, []byte("x")); !errors.Is(err, ports.ErrSymlinkRejected) {
		t.Fatalf("AppendLine(symlink) = %v, 期望 ErrSymlinkRejected", err)
	}
	if err := root.AtomicReplace(link, 0o600, func(io.Writer) error { return nil }); !errors.Is(err, ports.ErrSymlinkRejected) {
		t.Fatalf("AtomicReplace(symlink) = %v, 期望 ErrSymlinkRejected", err)
	}
	if err := root.MkdirAll(mustLocalDest(t, "keep.link/sub"), 0o700); !errors.Is(err, ports.ErrSymlinkRejected) {
		t.Fatalf("MkdirAll(through symlink) = %v, 期望 ErrSymlinkRejected", err)
	}
	return nil
}

func verifyPanicRollbackAndMaxInt64(t *testing.T, root ports.RootHandle, target pathalg.LocalRootedDest, lim ports.ReadLimits) error {
	t.Helper()
	got, rErr := root.ReadAllBounded(target, lim)
	if rErr != nil || string(got) != "original" {
		t.Fatalf("panic 回滚后读取 = (%q, %v), 期望 original", string(got), rErr)
	}
	maxLim, lErr := ports.NewReadLimits(math.MaxInt64)
	if lErr != nil {
		return lErr
	}
	if gotMax, mErr := root.ReadAllBounded(target, maxLim); mErr != nil || string(gotMax) != "original" {
		t.Fatalf("ReadAllBounded(MaxInt64) = (%q, %v), 期望 original（禁 int64 溢出）", string(gotMax), mErr)
	}
	if probeSymlinkErr(t) == nil {
		return verifySymlinkAdversarialOps(t, root, lim)
	}
	return nil
}

func TestScopedFSAdversarialSymlinkAndPanicRollback(t *testing.T) {
	fsPort := osfs.NewScopedRootFS()
	rootDir := mustLocalDir(t, t.TempDir())
	lim, err := ports.NewReadLimits(1024)
	if err != nil {
		t.Fatal(err)
	}
	target := mustLocalDest(t, "keep.txt")
	if err := fsPort.WithRoot(rootDir, func(root ports.RootHandle) error {
		return root.CreateExclusive(target, 0o600, func(w io.Writer) error {
			_, wErr := w.Write([]byte("original"))
			return wErr
		})
	}); err != nil {
		t.Fatal(err)
	}
	panicked := false
	func() {
		defer func() {
			if recover() != nil {
				panicked = true
			}
		}()
		_ = fsPort.WithRoot(rootDir, func(root ports.RootHandle) error {
			return osfs.AtomicReplace(root, target, 0o600, func(w io.Writer) error {
				_, _ = w.Write([]byte("corrupt"))
				panic("simulated crash")
			})
		})
	}()
	if !panicked {
		t.Fatal("期望 panic 透传")
	}
	if err := fsPort.WithRoot(rootDir, func(root ports.RootHandle) error {
		return verifyPanicRollbackAndMaxInt64(t, root, target, lim)
	}); err != nil {
		t.Fatalf("对抗校验失败: %v", err)
	}
}

func verifyScopedRootFullOps(ctx context.Context, root ports.RootHandle, subDir, fileDest, logDest pathalg.LocalRootedDest) error {
	if err := root.MkdirAll(subDir, 0o700); err != nil {
		return err
	}
	if err := root.CreateExclusive(fileDest, 0o600, func(w io.Writer) error {
		_, wErr := w.Write([]byte("initial"))
		return wErr
	}); err != nil {
		return err
	}
	if err := root.AppendLine(logDest, 0o600, []byte("+op-1")); err != nil {
		return err
	}
	if err := osfs.WithSidecarLock(ctx, root, fileDest, ports.LockExclusive, 0o600, func(lf ports.LockedFile) error {
		return lf.Sync()
	}); err != nil {
		return err
	}
	return osfs.AtomicReplaceWithSidecarLock(ctx, root, fileDest, 0o600, func(w io.Writer) error {
		_, wErr := w.Write([]byte("replaced"))
		return wErr
	})
}
