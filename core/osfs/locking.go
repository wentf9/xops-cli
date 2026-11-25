package osfs

import (
	"context"
	"errors"
	"fmt"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
	"io"
	"io/fs"
	"os"
	"sync/atomic"
	"time"
)

const (
	maxSameFileLockRetries = 16
	initialLockBackoff     = time.Millisecond
	maxLockBackoff         = 25 * time.Millisecond
)

type lockedFile struct {
	file   *os.File
	name   string
	active *atomic.Bool
}

func (l *lockedFile) checkActive() error {
	return pickIf[error](l != nil && l.active != nil && l.active.Load() && l.file != nil, nil, ports.ErrHandleExpired)
}
func lockedIO[T any](l *lockedFile, fn func(*os.File) (T, error)) (T, error) {
	if err := l.checkActive(); err != nil {
		return zeroVal[T](), err
	}
	return fn(l.file)
}
func (l *lockedFile) Read(p []byte) (int, error) {
	return lockedIO(l, func(f *os.File) (int, error) { return f.Read(p) })
}
func (l *lockedFile) Write(p []byte) (int, error) {
	return lockedIO(l, func(f *os.File) (int, error) { return f.Write(p) })
}
func (l *lockedFile) Seek(off int64, w int) (int64, error) {
	return lockedIO(l, func(f *os.File) (int64, error) { return f.Seek(off, w) })
}
func (l *lockedFile) Sync() error {
	_, err := lockedIO(l, func(f *os.File) (int, error) { return 0, mapOSError(f.Sync()) })
	return err
}
func (l *lockedFile) Truncate(size int64) error {
	if err := l.checkActive(); err != nil {
		return err
	}
	if size < 0 {
		return fmt.Errorf("%w: Truncate 大小不能为负", ports.ErrInvalidArgument)
	}
	return mapOSError(l.file.Truncate(size))
}
func (l *lockedFile) Stat() (ports.LocalFileInfo, error) {
	return lockedIO(l, func(f *os.File) (ports.LocalFileInfo, error) {
		fi, err := f.Stat()
		if err != nil {
			return zeroVal[ports.LocalFileInfo](), mapOSError(err)
		}
		return fileInfoToLocalFileInfo(l.name, fi)
	})
}
func (h *rootHandle) checkLockArgs(dest pathalg.LocalRootedDest, mode ports.LockMode, fnNil bool) error {
	if err := h.checkActiveDest(dest); err != nil {
		return err
	}
	return pickIf[error](fnNil, ports.ErrNilCallback, pickIf[error](!mode.IsValid(), ports.ErrInvalidLockMode, nil))
}

// WithLockedFile 在 ctx 取消控制下获取内核文件锁并校验 SameFile（INV-A2），零后台协程退避等待。
//
//xops:syncclosure
//xops:borrowed
func (h *rootHandle) WithLockedFile(ctx context.Context, dest pathalg.LocalRootedDest, mode ports.LockMode, create bool, perm fs.FileMode, fn func(f ports.LockedFile) error) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := h.checkLockArgs(dest, mode, fn == nil); err != nil {
		return err
	}
	var f *os.File
	if err := retryLockBackoff(ctx, func() (ok bool, tErr error) {
		f, ok, tErr = h.tryAcquireLockedHandle(dest, mode, create, perm)
		return ok, tErr
	}); err != nil {
		return err
	}
	return runWithLockedFile(f, dest.Base(), fn)
}

// TryWithLockedFile 非阻塞尝试获取文件锁并校验 SameFile；锁忙立即返回 (false, nil)。
//
//xops:syncclosure
//xops:borrowed
func (h *rootHandle) TryWithLockedFile(dest pathalg.LocalRootedDest, mode ports.LockMode, create bool, perm fs.FileMode, fn func(f ports.LockedFile) error) (bool, error) {
	if err := h.checkLockArgs(dest, mode, fn == nil); err != nil {
		return false, err
	}
	f, acquired, err := h.tryAcquireLockedHandle(dest, mode, create, perm)
	if err != nil || !acquired {
		return false, err
	}
	return true, runWithLockedFile(f, dest.Base(), fn)
}

//xops:syncclosure
func runWithLockedFile(f *os.File, baseName string, fn func(f ports.LockedFile) error) (retErr error) {
	var active atomic.Bool
	active.Store(true)
	defer func() {
		active.Store(false)
		retErr = errors.Join(retErr, mapOSError(errors.Join(unlockFileOS(f), f.Close())))
	}()
	return fn(&lockedFile{file: f, name: baseName, active: &active})
}

//xops:syncclosure
func retryLockBackoff(ctx context.Context, tryFn func() (bool, error)) error {
	for backoff := initialLockBackoff; ; backoff = min(backoff*2, maxLockBackoff) {
		if err := ctx.Err(); err != nil {
			return err
		}
		if ok, err := tryFn(); err != nil || ok {
			return err
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
func lockFileWithContext(ctx context.Context, f *os.File, exclusive bool) error {
	return retryLockBackoff(ctx, func() (bool, error) {
		err := tryLockFileOS(f, exclusive)
		if err == nil || errors.Is(err, ports.ErrLockBusy) {
			return err == nil, nil
		}
		return false, mapOSError(err)
	})
}
func (h *rootHandle) tryAcquireLockedHandle(dest pathalg.LocalRootedDest, mode ports.LockMode, create bool, perm fs.FileMode) (*os.File, bool, error) {
	op := pickIf(create, leafOpLockCreate, pickIf(mode == ports.LockExclusive, leafOpLockRW, leafOpLockRO))
	createPerm := pickIf(create, sanitizeFilePerm(perm, defaultFilePerm), 0)
	for range maxSameFileLockRetries {
		f, err := openLeafInRootOS(h.root, dest, op, createPerm)
		if err != nil {
			return nil, false, err
		}
		if lockErr := tryLockFileOS(f, mode == ports.LockExclusive); lockErr != nil {
			_ = f.Close()
			return nil, false, pickIf[error](errors.Is(lockErr, ports.ErrLockBusy), nil, mapOSError(lockErr))
		}
		same, vErr := verifyRegularSameFile(h.root, dest.String(), f, true)
		if vErr == nil && same {
			return f, true, nil
		}
		_ = errors.Join(unlockFileOS(f), f.Close())
		if vErr != nil {
			return nil, false, vErr
		}
	}
	return nil, false, fmt.Errorf("%w: 加锁目标 %q 持续发生替换", ErrSameFileMismatch, dest.String())
}

// SidecarLockDest 为目标文件构造同目录旁路锁路径 <name>.lock（ADR-007）。
func SidecarLockDest(dest pathalg.LocalRootedDest) (pathalg.LocalRootedDest, error) {
	if !dest.IsValid() {
		return zeroVal[pathalg.LocalRootedDest](), fmt.Errorf("%w: 无效沙箱目标路径", ports.ErrInvalidArgument)
	}
	return siblingDest(dest, dest.Base()+".lock")
}

// RemoveLockedFileSafely 按三平台安全删锁协议清理已退役的单进程实例锁文件：
// 持独占锁截断清空刷盘 -> 解锁关句柄 -> Remove（忽略 ErrNotFound），消除 Windows 共享冲突。
func RemoveLockedFileSafely(root ports.RootHandle, lockDest pathalg.LocalRootedDest) (bool, error) {
	if root == nil || !lockDest.IsValid() {
		return false, fmt.Errorf("%w: 无效 RootHandle 或锁文件路径", ports.ErrInvalidArgument)
	}
	acquired, err := root.TryWithLockedFile(lockDest, ports.LockExclusive, false, 0, func(lf ports.LockedFile) error {
		return errors.Join(lf.Truncate(0), lf.Sync())
	})
	if errors.Is(err, ports.ErrNotFound) || (err == nil && !acquired) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if rmErr := root.Remove(lockDest); rmErr != nil && !errors.Is(rmErr, ports.ErrNotFound) {
		return false, rmErr
	}
	return true, nil
}

// OpenRegularFunc / WriteFileFunc / LockedFileFunc 定义包级作用域闭包原语的借用回调契约。
//
//xops:syncclosure
//xops:borrowed
type OpenRegularFunc func(r ports.BoundedReadHandle, size int64) error

//xops:syncclosure
//xops:borrowed
type WriteFileFunc func(w io.Writer) error

//xops:syncclosure
//xops:borrowed
type LockedFileFunc func(f ports.LockedFile) error

func checkRootCB(root ports.RootHandle, fnNil bool) error {
	return pickIf[error](root == nil, fmt.Errorf("%w: RootHandle 不能为 nil", ports.ErrInvalidArgument), pickIf[error](fnNil, ports.ErrNilCallback, nil))
}

// OpenRegular / CreateExclusive / OpenLockedContext / AtomicReplace 为 ports.RootHandle 提供包级显式作用域原语（ADR-007）。
//
//xops:syncclosure
//xops:borrowed
func OpenRegular(r ports.RootHandle, d pathalg.LocalRootedDest, l ports.ReadLimits, fn OpenRegularFunc) error {
	if err := checkRootCB(r, fn == nil); err != nil {
		return err
	}
	return r.WithReadRegular(d, l, fn)
}

//xops:syncclosure
//xops:borrowed
func CreateExclusive(r ports.RootHandle, d pathalg.LocalRootedDest, p fs.FileMode, fn WriteFileFunc) error {
	if err := checkRootCB(r, fn == nil); err != nil {
		return err
	}
	return r.CreateExclusive(d, p, fn)
}

//xops:syncclosure
//xops:borrowed
func OpenLockedContext(ctx context.Context, r ports.RootHandle, d pathalg.LocalRootedDest, m ports.LockMode, c bool, p fs.FileMode, fn LockedFileFunc) error {
	if err := checkRootCB(r, fn == nil); err != nil {
		return err
	}
	return r.WithLockedFile(ctx, d, m, c, p, fn)
}

//xops:syncclosure
//xops:borrowed
func AtomicReplace(r ports.RootHandle, d pathalg.LocalRootedDest, p fs.FileMode, fn WriteFileFunc) error {
	if err := checkRootCB(r, fn == nil); err != nil {
		return err
	}
	return r.AtomicReplace(d, p, fn)
}

// WithSidecarLock 锁定 target 同目录旁路锁文件 <target>.lock 并同步执行回调（ADR-007）。
//
//xops:syncclosure
//xops:borrowed
func WithSidecarLock(ctx context.Context, root ports.RootHandle, target pathalg.LocalRootedDest, mode ports.LockMode, perm fs.FileMode, fn LockedFileFunc) error {
	if err := checkRootCB(root, fn == nil); err != nil {
		return err
	}
	lockDest, err := SidecarLockDest(target)
	if err != nil {
		return err
	}
	return root.WithLockedFile(ctx, lockDest, mode, true, sanitizeFilePerm(perm, defaultFilePerm), fn)
}

// AtomicReplaceWithSidecarLock 持有同目录旁路独占锁 <dest>.lock（绝不锁目标文件）并原子替换 dest（ADR-007）；
// 完全通过 ports.RootHandle 接口委派，零具体类型断言，同时兼容真实 osfs、仿真器及包装适配器。
//
//xops:syncclosure
//xops:borrowed
func AtomicReplaceWithSidecarLock(ctx context.Context, root ports.RootHandle, dest pathalg.LocalRootedDest, perm fs.FileMode, fn WriteFileFunc) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := checkRootCB(root, fn == nil); err != nil {
		return err
	}
	if !dest.IsValid() {
		return fmt.Errorf("%w: 无效沙箱目标路径", ports.ErrInvalidArgument)
	}
	mode := sanitizeFilePerm(perm, defaultFilePerm)
	return WithSidecarLock(ctx, root, dest, ports.LockExclusive, mode, func(ports.LockedFile) error {
		return root.AtomicReplace(dest, mode, func(w io.Writer) error { return fn(w) })
	})
}
