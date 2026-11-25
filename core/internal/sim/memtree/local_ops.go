package memtree

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
)

// CheckRegularSlotLocked 校验 abs 的父目录与目标槽位是否满足常规文件（及可选独占）前置条件。
func (t *Tree) CheckRegularSlotLocked(abs string, exclusive bool) (*Node, error) {
	if _, err := t.ResolveParentLocked(abs, false, true); err != nil {
		return nil, err
	}
	nd := t.Nodes[abs]
	switch {
	case nd == nil:
		return nil, nil
	case nd.Kind == ports.RemoteFileSymlink:
		return nil, ports.ErrSymlinkRejected
	case exclusive:
		return nil, ports.ErrAlreadyExists
	case nd.Kind != ports.RemoteFileRegular:
		return nil, ports.ErrNotRegularFile
	default:
		return nd, nil
	}
}

// OpenOrCreateRegularLocked 打开已有常规文件或在 create==true 时新建常规文件节点。
func (t *Tree) OpenOrCreateRegularLocked(abs string, create bool, checkWrite func() error, perm fs.FileMode) (*Node, error) {
	nd, err := t.CheckRegularSlotLocked(abs, false)
	if err != nil || nd != nil {
		return nd, err
	}
	if !create {
		return nil, ports.ErrNotFound
	}
	if checkWrite != nil {
		if err := checkWrite(); err != nil {
			return nil, err
		}
	}
	nd = &Node{Kind: ports.RemoteFileRegular, Mode: perm.Perm(), ModTime: t.Now(), Ino: t.AllocIno()}
	t.Nodes[abs] = nd
	return nd, nil
}

func isValidRFC3339Time(t time.Time) bool {
	return !t.IsZero() && t.UTC().Year() >= 1 && t.UTC().Year() <= 9999
}

// ChtimesLocalLocked 校验合法 RFC 3339 时间戳与无软链路径并更新沙箱常规文件或目录的修改时间。
func (t *Tree) ChtimesLocalLocked(abs string, atime, mtime time.Time) error {
	if !isValidRFC3339Time(atime) || !isValidRFC3339Time(mtime) {
		return ports.ErrInvalidArgument
	}
	key, err := t.ResolveParentLocked(abs, false, true)
	if err != nil {
		return err
	}
	nd := t.Nodes[key]
	switch {
	case nd == nil:
		return ports.ErrNotFound
	case nd.Kind == ports.RemoteFileSymlink:
		return ports.ErrSymlinkRejected
	case nd.Kind != ports.RemoteFileRegular && nd.Kind != ports.RemoteFileDir:
		return ports.ErrNotRegularFile
	default:
		nd.ModTime = mtime.UTC().Round(0)
		return nil
	}
}

// RenameLocalLocked 在沙箱根内校验非符号链接与类型兼容性并原子重命名 oldAbs -> newAbs。
func (t *Tree) RenameLocalLocked(oldAbs, newAbs string) error {
	oldKey, e1 := t.ResolveParentLocked(oldAbs, false, true)
	newKey, e2 := t.ResolveParentLocked(newAbs, false, true)
	if err := FirstErr(e1, e2); err != nil {
		return err
	}
	src := t.Nodes[oldKey]
	if err := t.checkLocalRenameTargetLocked(oldKey, newKey, src, t.Nodes[newKey]); err != nil {
		return err
	}
	if oldKey != newKey {
		t.RelocateSubtreeLocked(oldKey, newKey, src)
	}
	return nil
}

func (t *Tree) checkLocalRenameTargetLocked(oldKey, newKey string, src, dst *Node) error {
	switch {
	case src == nil:
		return ports.ErrNotFound
	case src.Kind == ports.RemoteFileSymlink || (dst != nil && dst.Kind == ports.RemoteFileSymlink):
		return ports.ErrSymlinkRejected
	case oldKey == newKey:
		return nil
	case src.Kind == ports.RemoteFileDir && strings.HasPrefix(newKey, oldKey+"/"):
		return ports.ErrInvalidArgument
	case dst == nil:
		return nil
	case src.Kind != ports.RemoteFileDir && dst.Kind == ports.RemoteFileDir:
		return ports.ErrNotRegularFile
	case src.Kind == ports.RemoteFileDir && (dst.Kind != ports.RemoteFileDir || t.HasChildrenLocked(newKey)):
		return ports.ErrInvalidArgument
	default:
		return nil
	}
}

// TryAcquireLock 尝试对 abs 加共享或独占锁；冲突时返回等待唤醒通道。
func (t *Tree) TryAcquireLock(abs string, mode ports.LockMode, create bool, perm fs.FileMode, checkWrite func() error) (bool, <-chan struct{}, error) {
	t.Mu.Lock()
	defer t.Mu.Unlock()
	if _, err := t.OpenOrCreateRegularLocked(abs, create, checkWrite, perm); err != nil {
		return false, nil, err
	}
	lk := t.Locks[abs]
	if lk == nil {
		lk = &FileLock{Changed: make(chan struct{})}
		t.Locks[abs] = lk
	}
	switch {
	case mode == ports.LockShared && !lk.Exclusive:
		lk.Shared++
		return true, nil, nil
	case mode == ports.LockExclusive && !lk.Exclusive && lk.Shared == 0:
		lk.Exclusive = true
		return true, nil, nil
	default:
		return false, lk.Changed, nil
	}
}

// ReleaseLock 释放 abs 上的指定模式文件锁并广播唤醒等待者。
func (t *Tree) ReleaseLock(abs string, mode ports.LockMode) {
	t.Mu.Lock()
	defer t.Mu.Unlock()
	lk := t.Locks[abs]
	if lk == nil {
		return
	}
	if mode == ports.LockExclusive {
		lk.Exclusive = false
	} else if lk.Shared > 0 {
		lk.Shared--
	}
	close(lk.Changed)
	lk.Changed = make(chan struct{})
	if !lk.Exclusive && lk.Shared == 0 {
		delete(t.Locks, abs)
	}
}

// LockedFile 实现 ports.LockedFile，带运行时失效哨兵、共享/独占写保护与可选写故障检查。
type LockedFile struct {
	tree       *Tree
	abs        string
	offset     int64
	writable   bool
	valid      bool
	expired    atomic.Bool
	checkWrite func() error
}

// NewLockedFile 构造绑定至树节点 abs 的持锁文件句柄。
func NewLockedFile(tree *Tree, abs string, writable bool, checkWrite func() error) *LockedFile {
	return &LockedFile{tree: tree, abs: abs, writable: writable, valid: true, checkWrite: checkWrite}
}

// Expire 置位失效哨兵，阻断回调退出后的任何逃逸访问。
func (lf *LockedFile) Expire() { lf.expired.Store(true) }

func (lf *LockedFile) doReg(needWrite, checkFault bool, fn func(*Node) error) error {
	if lf == nil || !lf.valid || lf.expired.Load() {
		return ports.ErrHandleExpired
	}
	if needWrite && !lf.writable {
		return ports.ErrPermissionDenied
	}
	if checkFault && lf.checkWrite != nil {
		if err := lf.checkWrite(); err != nil {
			return err
		}
	}
	lf.tree.Mu.Lock()
	defer lf.tree.Mu.Unlock()
	if nd := lf.tree.Nodes[lf.abs]; nd != nil && nd.Kind == ports.RemoteFileRegular {
		return fn(nd)
	}
	return ports.ErrNotFound
}
func (lf *LockedFile) Read(p []byte) (n int, err error) {
	return n, lf.doReg(false, false, func(nd *Node) error {
		if lf.offset >= int64(len(nd.Data)) {
			return io.EOF
		}
		n = copy(p, nd.Data[lf.offset:])
		lf.offset += int64(n)
		return nil
	})
}
func (lf *LockedFile) Write(p []byte) (n int, err error) {
	return n, lf.doReg(true, true, func(nd *Node) error {
		nd.Data = GrowBytes(nd.Data, lf.offset+int64(len(p)))
		n = copy(nd.Data[lf.offset:], p)
		lf.offset += int64(n)
		return nil
	})
}
func (lf *LockedFile) Seek(offset int64, whence int) (next int64, err error) {
	return next, lf.doReg(false, false, func(nd *Node) error {
		bases := [3]int64{0, lf.offset, int64(len(nd.Data))}
		if whence < 0 || whence > 2 || bases[whence]+offset < 0 {
			return ports.ErrInvalidArgument
		}
		next, lf.offset = bases[whence]+offset, bases[whence]+offset
		return nil
	})
}
func (lf *LockedFile) Truncate(size int64) error {
	if size < 0 {
		return ports.ErrInvalidArgument
	}
	return lf.doReg(true, true, func(nd *Node) error {
		nd.Data = bytes.Clone(GrowBytes(nd.Data, size)[:size])
		return nil
	})
}
func (lf *LockedFile) Sync() error { return lf.doReg(false, true, func(*Node) error { return nil }) }
func (lf *LockedFile) Stat() (out ports.LocalFileInfo, err error) {
	return out, lf.doReg(false, false, func(nd *Node) (e error) {
		out, e = ports.NewLocalFileInfo(ports.LocalFileInfoSpec{Name: path.Base(lf.abs), Size: int64(len(nd.Data)), Mode: nd.Mode, ModTime: nd.ModTime})
		return e
	})
}

// WriteChunkLocalLocked 在树锁保护下向常规暂存文件写入分片数据。
func (t *Tree) WriteChunkLocalLocked(abs string, offset int64, chunk []byte, perm fs.FileMode) error {
	nd, err := t.OpenOrCreateRegularLocked(abs, true, nil, perm)
	if err != nil {
		return err
	}
	if len(chunk) > 0 {
		nd.Data = GrowBytes(nd.Data, offset+int64(len(chunk)))
		copy(nd.Data[offset:], chunk)
	}
	nd.ModTime = t.Now()
	return nil
}

// ListLocalDirLocked 在树锁保护下将目录项转换为已校验 LocalDirEntry 列表。
func (t *Tree) ListLocalDirLocked(abs string) ([]ports.LocalDirEntry, error) {
	items, err := t.ListDirLocked(abs, false, false, true)
	if err != nil {
		return nil, err
	}
	out := make([]ports.LocalDirEntry, 0, len(items))
	for _, it := range items {
		ent, e := ports.NewLocalDirEntry(it.Name, it.Node.Mode, int64(len(it.Node.Data)))
		if e != nil {
			return nil, e
		}
		out = append(out, ent)
	}
	return out, nil
}

// CreateSymlinkLocalLocked 在树锁保护下按策略 (b) 校验并创建沙箱内相对符号链接。
func (t *Tree) CreateSymlinkLocalLocked(link pathalg.LocalRootedDest, target string) error {
	abs := NormPath(link.String())
	if _, err := t.ResolveParentLocked(abs, false, true); err != nil {
		return err
	}
	if t.Nodes[abs] != nil {
		return ports.ErrAlreadyExists
	}
	if err := pathalg.ValidateContainedSymlinkChain(link, target, t.CollectSymlinksLocked()); err != nil {
		return fmt.Errorf("%w: %w", ports.ErrSymlinkRejected, err)
	}
	t.Nodes[abs] = &Node{Kind: ports.RemoteFileSymlink, Mode: fs.ModeSymlink | 0o777, Target: target, ModTime: t.Now(), Ino: t.AllocIno()}
	return nil
}
