package sim

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"math"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/internal/sim/memtree"
	"github.com/wentf9/xops-cli/core/ports"
)

// SimScopedRootFS 实现 ports.ScopedRootFS，纯内存仿真 *os.Root、旁路锁、策略 (b) 软链与 ENOSPC。
//
//xops:opaque
//xops:failclosed
type SimScopedRootFS struct {
	simBase
	clock  ports.Clock
	enospc atomic.Bool
	roots  map[string]*memtree.Tree
}

// NewSimScopedRootFS 创建纯内存 ScopedRootFS 仿真器。
func NewSimScopedRootFS(clk ports.Clock) *SimScopedRootFS {
	if clk == nil {
		clk = NewSimClock(DefaultBaseTime())
	}
	return &SimScopedRootFS{simBase: newSimBase(nil), clock: clk, roots: make(map[string]*memtree.Tree)}
}

// SetENOSPC 开启或关闭模拟磁盘满（ENOSPC）故障。
func (f *SimScopedRootFS) SetENOSPC(en bool) {
	if f.ok() {
		f.enospc.Store(en)
	}
}
func (f *SimScopedRootFS) checkOp(op string) error {
	if op == "fs.write" && f.enospc.Load() {
		return ErrSimulatedENOSPC
	}
	if op != "" {
		return f.faults.Check(op)
	}
	return nil
}

// EnsureRoot 幂等确保沙箱根目录 dir 存在，校验 perm 为非零标准权限位且受故障注入约束。
func (f *SimScopedRootFS) EnsureRoot(dir pathalg.LocalDir, perm fs.FileMode) error {
	if err := f.check(context.Background(), "fs.ensure_root", dir.IsValid(), perm != 0 && perm == perm.Perm()); err != nil {
		return err
	}
	if f.enospc.Load() {
		return ErrSimulatedENOSPC
	}
	f.withLock(func() {
		if f.roots[dir.String()] == nil {
			f.roots[dir.String()] = memtree.New(f.clock, true, perm)
		}
	})
	return nil
}

// WithRoot 在同步作用域内借出绑定至 dir 的 RootHandle，退出即失效借用哨兵。
//
//xops:syncclosure
//xops:borrowed
func (f *SimScopedRootFS) WithRoot(dir pathalg.LocalDir, fn func(root ports.RootHandle) error) error {
	if err := f.checkFn(context.Background(), fn != nil, "fs.root", dir.IsValid()); err != nil {
		return err
	}
	tree := withLockRet(&f.simBase, nil, func() *memtree.Tree {
		if f.roots[dir.String()] == nil {
			f.roots[dir.String()] = memtree.New(f.clock, true, 0o700)
		}
		return f.roots[dir.String()]
	})
	h := &simRootHandle{fs: f, tree: tree, valid: true}
	defer h.expired.Store(true)
	return fn(h)
}

type simRootHandle struct {
	fs      *SimScopedRootFS
	tree    *memtree.Tree
	valid   bool
	expired atomic.Bool
}

func (h *simRootHandle) checkHandleFn(hasFn, valid bool) error {
	switch {
	case h == nil || !h.valid || h.expired.Load():
		return ports.ErrHandleExpired
	case !hasFn:
		return ports.ErrNilCallback
	case !valid:
		return ports.ErrInvalidArgument
	default:
		return nil
	}
}
func (h *simRootHandle) withTree(op string, valid bool, fn func() error) error {
	if err := firstErr(h.checkHandleFn(true, valid), h.fs.checkOp(op)); err != nil {
		return err
	}
	h.tree.Mu.Lock()
	defer h.tree.Mu.Unlock()
	return fn()
}
func (h *simRootHandle) ReadAllBounded(dest pathalg.LocalRootedDest, limits ports.ReadLimits) (out []byte, err error) {
	if !limits.IsValid() {
		return nil, firstErr(h.checkHandleFn(true, dest.IsValid()), ports.ErrInvalidReadLimits)
	}
	return out, h.withTree("fs.read", dest.IsValid(), func() (e error) {
		out, e = h.tree.ReadRegularLocked(memtree.NormPath(dest.String()), false, false, true, limits, ports.ErrNotRegularFile)
		return e
	})
}

// WithReadRegular 以有界随机只读句柄借出常规文件读取器（支持顺序 Read 与并发安全 ReadAt）。
//
//xops:syncclosure
//xops:borrowed
func (h *simRootHandle) WithReadRegular(dest pathalg.LocalRootedDest, limits ports.ReadLimits, fn func(r ports.BoundedReadHandle, size int64) error) error {
	if err := h.checkHandleFn(fn != nil, true); err != nil {
		return err
	}
	data, err := h.ReadAllBounded(dest, limits)
	if err != nil {
		return err
	}
	r, expire := memtree.NewScopedReader(data, limits.MaxBytes())
	defer expire()
	return fn(r, int64(len(data)))
}

// CreateExclusive 独占创建常规文件；进入回调前先核验父目录与 O_EXCL/O_NOFOLLOW 约束，回调失败零残留。
//
//xops:syncclosure
//xops:borrowed
func (h *simRootHandle) CreateExclusive(dest pathalg.LocalRootedDest, perm fs.FileMode, fn func(w io.Writer) error) error {
	return h.writeViaCallback(dest, perm, true, fn)
}

// AtomicReplace 原子替换常规文件；拒绝末段符号链接，回调失败保留旧内容。
//
//xops:syncclosure
//xops:borrowed
func (h *simRootHandle) AtomicReplace(dest pathalg.LocalRootedDest, perm fs.FileMode, fn func(w io.Writer) error) error {
	return h.writeViaCallback(dest, perm, false, fn)
}
func (h *simRootHandle) writeViaCallback(dest pathalg.LocalRootedDest, perm fs.FileMode, exclusive bool, fn func(w io.Writer) error) error {
	if err := firstErr(h.checkHandleFn(fn != nil, dest.IsValid()), h.fs.checkOp("fs.write")); err != nil {
		return err
	}
	abs := memtree.NormPath(dest.String())
	if err := h.withTree("", true, func() error { _, e := h.tree.CheckRegularSlotLocked(abs, exclusive); return e }); err != nil {
		return err
	}
	var buf bytes.Buffer
	var expired atomic.Bool
	defer expired.Store(true)
	if err := fn(memtree.NewScopedWriter(&buf, &expired, func() error { return h.fs.checkOp("fs.write") })); err != nil {
		return err
	}
	expired.Store(true)
	return h.withTree("fs.write", true, func() error {
		if _, err := h.tree.CheckRegularSlotLocked(abs, exclusive); err != nil {
			return err
		}
		h.tree.Nodes[abs] = &memtree.Node{Kind: ports.RemoteFileRegular, Mode: perm.Perm(), Data: bytes.Clone(buf.Bytes()), ModTime: h.tree.Now(), Ino: h.tree.AllocIno()}
		return nil
	})
}

// WriteChunk 向暂存文件 dest 的 offset 处非截断写入来自 r 的精确 length 字节；流提前结束返回 (已写字节, io.ErrUnexpectedEOF)。
func (h *simRootHandle) WriteChunk(dest pathalg.LocalRootedDest, offset int64, r io.Reader, length int64, perm fs.FileMode) (int64, error) {
	validArgs := dest.IsValid() && offset >= 0 && length >= 0 && offset <= math.MaxInt64-length && r != nil && perm != 0 && perm == perm.Perm()
	if err := firstErr(h.checkHandleFn(true, validArgs), h.fs.checkOp("fs.write")); err != nil {
		return 0, err
	}
	chunk := make([]byte, length)
	n, readErr := io.ReadFull(r, chunk)
	if errors.Is(readErr, io.EOF) && length > 0 {
		readErr = io.ErrUnexpectedEOF
	}
	if readErr != nil && !errors.Is(readErr, io.ErrUnexpectedEOF) {
		return 0, readErr
	}
	if err := h.withTree("fs.write", true, func() error {
		return h.tree.WriteChunkLocalLocked(memtree.NormPath(dest.String()), offset, chunk[:n], perm)
	}); err != nil {
		return 0, err
	}
	return int64(n), readErr
}

// Rename 在沙箱根内原子重命名 oldDest -> newDest（拒绝符号链接源/目标与跨类型非法覆盖）。
func (h *simRootHandle) Rename(oldDest, newDest pathalg.LocalRootedDest) error {
	return h.withTree("fs.write", oldDest.IsValid() && newDest.IsValid(), func() error {
		return h.tree.RenameLocalLocked(memtree.NormPath(oldDest.String()), memtree.NormPath(newDest.String()))
	})
}

// WithLockedFile 在 ctx 取消控制下获取共享/独占文件锁并借出 LockedFile。
//
//xops:syncclosure
//xops:borrowed
func (h *simRootHandle) WithLockedFile(ctx context.Context, dest pathalg.LocalRootedDest, mode ports.LockMode, create bool, perm fs.FileMode, fn func(f ports.LockedFile) error) error {
	_, err := h.acquireLockAndRun(ctx, dest, mode, create, perm, true, fn)
	return err
}

// TryWithLockedFile 非阻塞尝试获取文件锁并借出 LockedFile。
//
//xops:syncclosure
//xops:borrowed
func (h *simRootHandle) TryWithLockedFile(dest pathalg.LocalRootedDest, mode ports.LockMode, create bool, perm fs.FileMode, fn func(f ports.LockedFile) error) (bool, error) {
	return h.acquireLockAndRun(context.Background(), dest, mode, create, perm, false, fn)
}
func (h *simRootHandle) acquireLockAndRun(ctx context.Context, dest pathalg.LocalRootedDest, mode ports.LockMode, create bool, perm fs.FileMode, blocking bool, fn func(f ports.LockedFile) error) (bool, error) {
	if err := firstErr(h.checkHandleFn(true, true), checkCtx(ctx), h.checkHandleFn(fn != nil, dest.IsValid())); err != nil {
		return false, err
	}
	if !mode.IsValid() {
		return false, ports.ErrInvalidLockMode
	}
	if err := h.fs.faults.Check("fs.lock"); err != nil {
		return false, err
	}
	abs := memtree.NormPath(dest.String())
	checkWrite := func() error { return h.fs.checkOp("fs.write") }
	for {
		granted, waitCh, err := h.tree.TryAcquireLock(abs, mode, create, perm, checkWrite)
		if err != nil || (!granted && !blocking) {
			return false, err
		}
		if granted {
			lf := memtree.NewLockedFile(h.tree, abs, mode == ports.LockExclusive, checkWrite)
			defer func() { lf.Expire(); h.tree.ReleaseLock(abs, mode) }()
			return true, fn(lf)
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-waitCh:
		}
	}
}
func (h *simRootHandle) AppendLine(dest pathalg.LocalRootedDest, perm fs.FileMode, line []byte) error {
	return h.withTree("fs.write", dest.IsValid() && !bytes.ContainsAny(line, "\r\n"), func() error {
		nd, err := h.tree.OpenOrCreateRegularLocked(memtree.NormPath(dest.String()), true, nil, perm)
		if err == nil {
			nd.Data, nd.ModTime = append(append(nd.Data, line...), '\n'), h.tree.Now()
		}
		return err
	})
}
func (h *simRootHandle) Stat(dest pathalg.LocalRootedDest) (ports.LocalFileInfo, error) {
	return h.statPath(dest, true)
}
func (h *simRootHandle) Lstat(dest pathalg.LocalRootedDest) (ports.LocalFileInfo, error) {
	return h.statPath(dest, false)
}
func (h *simRootHandle) statPath(dest pathalg.LocalRootedDest, follow bool) (out ports.LocalFileInfo, err error) {
	return out, h.withTree("", dest.IsValid(), func() error {
		_, nd, e := h.tree.WalkPathLocked(memtree.NormPath(dest.String()), follow, follow, false)
		if e == nil {
			out, e = ports.NewLocalFileInfo(ports.LocalFileInfoSpec{Name: dest.Base(), Size: int64(len(nd.Data)), Mode: nd.Mode, ModTime: nd.ModTime})
		}
		return e
	})
}
func (h *simRootHandle) ReadDir(dir algebraic.Option[pathalg.LocalRootedDest]) (out []ports.LocalDirEntry, err error) {
	abs, ok := "/", true
	if d, has := dir.Get(); has {
		abs, ok = memtree.NormPath(d.String()), d.IsValid()
	}
	return out, h.withTree("", ok, func() (e error) {
		out, e = h.tree.ListLocalDirLocked(abs)
		return e
	})
}
func (h *simRootHandle) MkdirAll(dir pathalg.LocalRootedDest, perm fs.FileMode) error {
	return h.withTree("fs.write", dir.IsValid(), func() error { return h.tree.MkdirAllLocked(memtree.NormPath(dir.String()), perm, false) })
}
func (h *simRootHandle) CreateSymlink(link pathalg.LocalRootedDest, target string) error {
	return h.withTree("fs.write", link.IsValid(), func() error { return h.tree.CreateSymlinkLocalLocked(link, target) })
}
func (h *simRootHandle) Chtimes(dest pathalg.LocalRootedDest, atime, mtime time.Time) error {
	return h.withTree("fs.write", dest.IsValid() && !atime.IsZero() && !mtime.IsZero(), func() error {
		return h.tree.ChtimesLocalLocked(memtree.NormPath(dest.String()), atime, mtime)
	})
}
func (h *simRootHandle) Remove(dest pathalg.LocalRootedDest) error {
	return h.withTree("fs.remove", dest.IsValid(), func() error { return h.tree.RemoveLocked(memtree.NormPath(dest.String()), false, true) })
}
