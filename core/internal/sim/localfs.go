package sim

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
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
	roots  map[string]*simMemTree
}

// NewSimScopedRootFS 创建纯内存 ScopedRootFS 仿真器。
func NewSimScopedRootFS(clk ports.Clock) *SimScopedRootFS {
	if clk == nil {
		clk = NewSimClock(DefaultBaseTime())
	}
	return &SimScopedRootFS{simBase: newSimBase(nil), clock: clk, roots: make(map[string]*simMemTree)}
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

// WithRoot 在同步作用域内借出绑定至 dir 的 RootHandle，退出即失效借用哨兵。
//
//xops:syncclosure
//xops:borrowed
func (f *SimScopedRootFS) WithRoot(dir pathalg.LocalDir, fn func(root ports.RootHandle) error) error {
	if err := f.checkFn(context.Background(), fn != nil, "fs.root", dir.IsValid()); err != nil {
		return err
	}
	tree := withLockRet(&f.simBase, nil, func() *simMemTree {
		if f.roots[dir.String()] == nil {
			f.roots[dir.String()] = newSimMemTree(f.clock, true, 0o700)
		}
		return f.roots[dir.String()]
	})
	h := &simRootHandle{fs: f, tree: tree, valid: true}
	defer h.expired.Store(true)
	return fn(h)
}

type simRootHandle struct {
	fs      *SimScopedRootFS
	tree    *simMemTree
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
	h.tree.mu.Lock()
	defer h.tree.mu.Unlock()
	return fn()
}
func (h *simRootHandle) checkRegularSlotLocked(abs string, exclusive bool) (*simMemNode, error) {
	if _, err := h.tree.resolveParentLocked(abs, false, true); err != nil {
		return nil, err
	}
	nd := h.tree.nodes[abs]
	switch {
	case nd == nil:
		return nil, nil
	case nd.kind == ports.RemoteFileSymlink:
		return nil, ports.ErrSymlinkRejected
	case exclusive:
		return nil, ports.ErrAlreadyExists
	case nd.kind != ports.RemoteFileRegular:
		return nil, ports.ErrNotRegularFile
	default:
		return nd, nil
	}
}
func (h *simRootHandle) openOrCreateRegularLocked(abs string, create, checkWrite bool, perm fs.FileMode) (*simMemNode, error) {
	nd, err := h.checkRegularSlotLocked(abs, false)
	if err != nil || nd != nil {
		return nd, err
	}
	if !create {
		return nil, ports.ErrNotFound
	}
	if checkWrite {
		if err := h.fs.checkOp("fs.write"); err != nil {
			return nil, err
		}
	}
	nd = &simMemNode{kind: ports.RemoteFileRegular, mode: perm.Perm(), modTime: h.tree.now(), ino: h.tree.allocIno()}
	h.tree.nodes[abs] = nd
	return nd, nil
}
func (h *simRootHandle) ReadAllBounded(dest pathalg.LocalRootedDest, limits ports.ReadLimits) (out []byte, err error) {
	if !limits.IsValid() {
		return nil, firstErr(h.checkHandleFn(true, dest.IsValid()), ports.ErrInvalidReadLimits)
	}
	return out, h.withTree("fs.read", dest.IsValid(), func() (e error) {
		out, e = h.tree.readRegularLocked(normTreePath(dest.String()), false, false, true, limits, ports.ErrNotRegularFile)
		return e
	})
}

// WithReadRegular 以有界只读流借出常规文件读取器。
//
//xops:syncclosure
//xops:borrowed
func (h *simRootHandle) WithReadRegular(dest pathalg.LocalRootedDest, limits ports.ReadLimits, fn func(r io.Reader, size int64) error) error {
	if err := h.checkHandleFn(fn != nil, true); err != nil {
		return err
	}
	data, err := h.ReadAllBounded(dest, limits)
	if err != nil {
		return err
	}
	return withScopedReader(data, fn)
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
	abs := normTreePath(dest.String())
	if err := h.withTree("", true, func() error { _, e := h.checkRegularSlotLocked(abs, exclusive); return e }); err != nil {
		return err
	}
	var buf bytes.Buffer
	var expired atomic.Bool
	defer expired.Store(true)
	if err := fn(&simScopedWriter{buf: &buf, expired: &expired, checkWrite: func() error { return h.fs.checkOp("fs.write") }}); err != nil {
		return err
	}
	expired.Store(true)
	return h.withTree("fs.write", true, func() error {
		if _, err := h.checkRegularSlotLocked(abs, exclusive); err != nil {
			return err
		}
		h.tree.nodes[abs] = &simMemNode{kind: ports.RemoteFileRegular, mode: perm.Perm(), data: bytes.Clone(buf.Bytes()), modTime: h.tree.now(), ino: h.tree.allocIno()}
		return nil
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
	abs := normTreePath(dest.String())
	for {
		granted, waitCh, err := h.tryAcquireLock(abs, mode, create, perm)
		if err != nil || !granted && !blocking {
			return false, err
		}
		if granted {
			lf := &simLockedFile{fs: h.fs, tree: h.tree, abs: abs, writable: mode == ports.LockExclusive, valid: true}
			defer func() { lf.expired.Store(true); h.releaseLock(abs, mode) }()
			return true, fn(lf)
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-waitCh:
		}
	}
}
func (h *simRootHandle) tryAcquireLock(abs string, mode ports.LockMode, create bool, perm fs.FileMode) (bool, <-chan struct{}, error) {
	h.tree.mu.Lock()
	defer h.tree.mu.Unlock()
	if _, err := h.openOrCreateRegularLocked(abs, create, true, perm); err != nil {
		return false, nil, err
	}
	lk := h.tree.locks[abs]
	if lk == nil {
		lk = &simFileLock{changed: make(chan struct{})}
		h.tree.locks[abs] = lk
	}
	switch {
	case mode == ports.LockShared && !lk.exclusive:
		lk.shared++
		return true, nil, nil
	case mode == ports.LockExclusive && !lk.exclusive && lk.shared == 0:
		lk.exclusive = true
		return true, nil, nil
	default:
		return false, lk.changed, nil
	}
}
func (h *simRootHandle) releaseLock(abs string, mode ports.LockMode) {
	h.tree.mu.Lock()
	defer h.tree.mu.Unlock()
	lk := h.tree.locks[abs]
	if lk == nil {
		return
	}
	if mode == ports.LockExclusive {
		lk.exclusive = false
	} else if lk.shared > 0 {
		lk.shared--
	}
	close(lk.changed)
	lk.changed = make(chan struct{})
	if !lk.exclusive && lk.shared == 0 {
		delete(h.tree.locks, abs)
	}
}
func (h *simRootHandle) AppendLine(dest pathalg.LocalRootedDest, perm fs.FileMode, line []byte) error {
	return h.withTree("fs.write", dest.IsValid() && !bytes.ContainsAny(line, "\r\n"), func() error {
		nd, err := h.openOrCreateRegularLocked(normTreePath(dest.String()), true, false, perm)
		if err == nil {
			nd.data, nd.modTime = append(append(nd.data, line...), '\n'), h.tree.now()
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
		_, nd, e := h.tree.walkPathLocked(normTreePath(dest.String()), follow, follow, false)
		if e == nil {
			out, e = ports.NewLocalFileInfo(ports.LocalFileInfoSpec{Name: dest.Base(), Size: int64(len(nd.data)), Mode: nd.mode, ModTime: nd.modTime})
		}
		return e
	})
}
func (h *simRootHandle) ReadDir(dir algebraic.Option[pathalg.LocalRootedDest]) (out []ports.LocalDirEntry, err error) {
	abs, ok := "/", true
	if d, has := dir.Get(); has {
		abs, ok = normTreePath(d.String()), d.IsValid()
	}
	return out, h.withTree("", ok, func() error {
		items, e := h.tree.listDirLocked(abs, false, false, true)
		for _, it := range items {
			if e == nil {
				var ent ports.LocalDirEntry
				ent, e = ports.NewLocalDirEntry(it.name, it.node.mode, int64(len(it.node.data)))
				out = append(out, ent)
			}
		}
		return e
	})
}
func (h *simRootHandle) MkdirAll(dir pathalg.LocalRootedDest, perm fs.FileMode) error {
	return h.withTree("fs.write", dir.IsValid(), func() error { return h.tree.mkdirAllLocked(normTreePath(dir.String()), perm, false) })
}
func (h *simRootHandle) CreateSymlink(link pathalg.LocalRootedDest, target string) error {
	return h.withTree("fs.write", link.IsValid(), func() error {
		abs := normTreePath(link.String())
		if _, err := h.tree.resolveParentLocked(abs, false, true); err != nil {
			return err
		}
		if h.tree.nodes[abs] != nil {
			return ports.ErrAlreadyExists
		}
		if err := pathalg.ValidateContainedSymlinkChain(link, target, h.tree.collectSymlinksLocked()); err != nil {
			return fmt.Errorf("%w: %w", ports.ErrSymlinkRejected, err)
		}
		h.tree.nodes[abs] = &simMemNode{kind: ports.RemoteFileSymlink, mode: fs.ModeSymlink | 0o777, target: target, modTime: h.tree.now(), ino: h.tree.allocIno()}
		return nil
	})
}
func (h *simRootHandle) Remove(dest pathalg.LocalRootedDest) error {
	return h.withTree("fs.remove", dest.IsValid(), func() error { return h.tree.removeLocked(normTreePath(dest.String()), false, true) })
}

type simLockedFile struct {
	fs       *SimScopedRootFS
	tree     *simMemTree
	abs      string
	offset   int64
	writable bool
	valid    bool
	expired  atomic.Bool
}

func (lf *simLockedFile) doReg(needWrite, checkFault bool, fn func(*simMemNode) error) error {
	if lf == nil || !lf.valid || lf.expired.Load() {
		return ports.ErrHandleExpired
	}
	if needWrite && !lf.writable {
		return ports.ErrPermissionDenied
	}
	if checkFault && lf.fs != nil {
		if err := lf.fs.checkOp("fs.write"); err != nil {
			return err
		}
	}
	lf.tree.mu.Lock()
	defer lf.tree.mu.Unlock()
	if nd := lf.tree.nodes[lf.abs]; nd != nil && nd.kind == ports.RemoteFileRegular {
		return fn(nd)
	}
	return ports.ErrNotFound
}
func (lf *simLockedFile) Read(p []byte) (n int, err error) {
	return n, lf.doReg(false, false, func(nd *simMemNode) error {
		if lf.offset >= int64(len(nd.data)) {
			return io.EOF
		}
		n = copy(p, nd.data[lf.offset:])
		lf.offset += int64(n)
		return nil
	})
}
func (lf *simLockedFile) Write(p []byte) (n int, err error) {
	return n, lf.doReg(true, true, func(nd *simMemNode) error {
		nd.data = growBytes(nd.data, lf.offset+int64(len(p)))
		n = copy(nd.data[lf.offset:], p)
		lf.offset += int64(n)
		return nil
	})
}
func (lf *simLockedFile) Seek(offset int64, whence int) (next int64, err error) {
	return next, lf.doReg(false, false, func(nd *simMemNode) error {
		bases := [3]int64{0, lf.offset, int64(len(nd.data))}
		if whence < 0 || whence > 2 || bases[whence]+offset < 0 {
			return ports.ErrInvalidArgument
		}
		next, lf.offset = bases[whence]+offset, bases[whence]+offset
		return nil
	})
}
func (lf *simLockedFile) Truncate(size int64) error {
	if size < 0 {
		return ports.ErrInvalidArgument
	}
	return lf.doReg(true, true, func(nd *simMemNode) error {
		nd.data = bytes.Clone(growBytes(nd.data, size)[:size])
		return nil
	})
}
func (lf *simLockedFile) Sync() error {
	return lf.doReg(false, true, func(*simMemNode) error { return nil })
}
func (lf *simLockedFile) Stat() (out ports.LocalFileInfo, err error) {
	return out, lf.doReg(false, false, func(nd *simMemNode) (e error) {
		out, e = ports.NewLocalFileInfo(ports.LocalFileInfoSpec{Name: path.Base(lf.abs), Size: int64(len(nd.data)), Mode: nd.mode, ModTime: nd.modTime})
		return e
	})
}
