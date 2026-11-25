package sim

import (
	"context"
	"io"
	"io/fs"
	"maps"
	"path"
	"strings"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
)

// SimRemoteFS 是纯内存远端 POSIX/SFTP 文件系统仿真器（ADR-016，仅使用 path 包，支持中间目录软链解析、(dev,ino) 锚点与原子子树重命名）。
//
//xops:opaque
//xops:failclosed
type SimRemoteFS struct {
	simBase
	closed bool
	enospc atomic.Bool
	tree   *simMemTree
}

// NewSimRemoteFS 创建预置根目录 "/" 的远端 POSIX 文件系统仿真器。
func NewSimRemoteFS(clk ports.Clock) *SimRemoteFS {
	return &SimRemoteFS{simBase: newSimBase(nil), tree: newSimMemTree(clk, false, 0o755)}
}

// SetENOSPC / PutSymlink 提供远端磁盘满故障与软链重定向夹具支持。
func (r *SimRemoteFS) SetENOSPC(en bool) {
	if r.ok() {
		r.enospc.Store(en)
	}
}
func (r *SimRemoteFS) PutSymlink(linkPath pathalg.RemotePath, target string) error {
	return r.doTree(context.Background(), "", linkPath, target != "", func(key string) error {
		if err := r.tree.mkdirAllLocked(path.Dir(key), 0o755, true); err != nil {
			return err
		}
		resolved, err := r.tree.resolveParentLocked(key, true, false)
		if err == nil {
			r.tree.nodes[resolved] = &simMemNode{kind: ports.RemoteFileSymlink, mode: fs.ModeSymlink | 0o777, target: target, modTime: r.tree.now(), ino: r.tree.allocIno()}
		}
		return err
	})
}
func (r *SimRemoteFS) doTree(ctx context.Context, op string, p pathalg.RemotePath, ok bool, fn func(key string) error) error {
	if err := r.check(ctx, "", p.IsValid(), ok); err != nil {
		return err
	}
	if withLockRet(&r.simBase, true, func() bool { return r.closed }) {
		return ports.ErrClosed
	}
	if op != "" {
		if op != "rfs.remove" && op != "rfs.read" && r.enospc.Load() {
			return ErrSimulatedENOSPC
		}
		if err := r.faults.Check(op); err != nil {
			return err
		}
	}
	r.tree.mu.Lock()
	defer r.tree.mu.Unlock()
	return fn(normTreePath(p.String()))
}
func (r *SimRemoteFS) RealPath(ctx context.Context, p pathalg.RemotePath) (out pathalg.RemotePath, err error) {
	return out, r.doTree(ctx, "", p, true, func(key string) error {
		res, _, e := r.tree.walkPathLocked(key, true, true, false)
		if e == nil {
			out, e = pathalg.ParseRemotePath(res)
		}
		return e
	})
}
func (r *SimRemoteFS) Stat(ctx context.Context, p pathalg.RemotePath) (ports.RemoteFileStat, error) {
	return r.statRemote(ctx, p, true)
}
func (r *SimRemoteFS) Lstat(ctx context.Context, p pathalg.RemotePath) (ports.RemoteFileStat, error) {
	return r.statRemote(ctx, p, false)
}
func (r *SimRemoteFS) statRemote(ctx context.Context, p pathalg.RemotePath, followLeaf bool) (out ports.RemoteFileStat, err error) {
	return out, r.doTree(ctx, "", p, true, func(key string) error {
		res, node, e := r.tree.walkPathLocked(key, true, followLeaf, false)
		if e == nil && followLeaf {
			p, e = pathalg.ParseRemotePath(res)
		}
		if e == nil {
			out, e = buildRemoteStat(p, node)
		}
		return e
	})
}
func (r *SimRemoteFS) ReadLink(ctx context.Context, p pathalg.RemotePath) (target string, err error) {
	return target, r.doTree(ctx, "", p, true, func(key string) error {
		_, n, e := r.tree.walkPathLocked(key, true, false, false)
		if e != nil || n.kind != ports.RemoteFileSymlink {
			return firstErr(e, ports.ErrInvalidArgument)
		}
		target = n.target
		return nil
	})
}
func (r *SimRemoteFS) ReadDir(ctx context.Context, dir pathalg.RemotePath) (out []ports.RemoteDirEntry, err error) {
	return out, r.doTree(ctx, "", dir, true, func(key string) error {
		items, e := r.tree.listDirLocked(key, true, true, false)
		for _, it := range items {
			if e == nil {
				rn, e1 := pathalg.ParseRemoteName(it.name)
				ent, e2 := ports.NewRemoteDirEntry(ports.RemoteDirEntrySpec{Name: rn, FileType: it.node.kind, Size: int64(len(it.node.data)), Mode: it.node.mode, ModTime: it.node.modTime})
				e, out = firstErr(e1, e2), append(out, ent)
			}
		}
		return e
	})
}

// WithReadFile 在 limits 上限内以同步闭包借出远端文件只读流。
//
//xops:syncclosure
//xops:borrowed
func (r *SimRemoteFS) WithReadFile(ctx context.Context, p pathalg.RemotePath, limits ports.ReadLimits, fn func(rd io.Reader, size int64) error) error {
	if fn == nil {
		return ports.ErrNilCallback
	}
	if !limits.IsValid() {
		return firstErr(r.check(ctx, "", p.IsValid()), ports.ErrInvalidReadLimits)
	}
	var data []byte
	if err := r.doTree(ctx, "rfs.read", p, true, func(key string) (e error) {
		data, e = r.tree.readRegularLocked(key, true, true, false, limits, ports.ErrRemoteIsDir)
		return e
	}); err != nil {
		return err
	}
	return withScopedReader(data, fn)
}
func (r *SimRemoteFS) WriteFileAtomic(ctx context.Context, p pathalg.RemotePath, spec ports.RemoteWriteSpec, src io.Reader) (out ports.RemoteFileStat, err error) {
	if err = r.check(ctx, "", p.IsValid(), spec.IsValid(), src != nil); err != nil {
		return out, err
	}
	payload, err := io.ReadAll(src)
	if err != nil {
		return out, err
	}
	return out, r.doTree(ctx, "rfs.write", p, true, func(rawKey string) error {
		key, e := r.checkWriteTargetLocked(rawKey, spec)
		if e != nil {
			return e
		}
		n := &simMemNode{kind: ports.RemoteFileRegular, mode: spec.Perm(), data: payload, modTime: r.tree.now(), ino: r.tree.allocIno()}
		r.tree.nodes[key] = n
		out, e = buildRemoteStat(p, n)
		return e
	})
}
func (r *SimRemoteFS) checkWriteTargetLocked(rawKey string, spec ports.RemoteWriteSpec) (string, error) {
	key, err := r.tree.resolveParentLocked(rawKey, true, false)
	if err != nil {
		return "", err
	}
	if ex := r.tree.nodes[key]; ex != nil && spec.NoClobber() {
		return "", ports.ErrAlreadyExists
	} else if ex != nil && ex.kind == ports.RemoteFileDir {
		return "", ports.ErrRemoteIsDir
	}
	if anc, ok := spec.ExpectedAnchor().Get(); ok {
		return key, r.verifyAnchorLocked(key, anc)
	}
	return key, nil
}
func (r *SimRemoteFS) WriteChunk(ctx context.Context, p pathalg.RemotePath, offset int64, src io.Reader, length int64) error {
	if err := r.check(ctx, "", p.IsValid(), offset >= 0, length >= 0, src != nil); err != nil {
		return err
	}
	chunk := make([]byte, length)
	if _, err := io.ReadFull(src, chunk); err != nil {
		return err
	}
	return r.doTree(ctx, "rfs.write", p, true, func(rawKey string) error {
		key, err := r.tree.resolveParentLocked(rawKey, true, false)
		if err != nil {
			return err
		}
		n := r.tree.nodes[key]
		if n == nil {
			n = &simMemNode{kind: ports.RemoteFileRegular, mode: 0o600, ino: r.tree.allocIno()}
			r.tree.nodes[key] = n
		} else if n.kind != ports.RemoteFileRegular {
			return ports.ErrNotRegularFile
		}
		n.data, n.modTime = growBytes(n.data, offset+length), r.tree.now()
		copy(n.data[offset:], chunk)
		return nil
	})
}
func (r *SimRemoteFS) RenameAtomic(ctx context.Context, oldPath, newPath pathalg.RemotePath, expectedAnchor algebraic.Option[ports.RemoteFileAnchor]) error {
	return r.doTree(ctx, "rfs.rename", oldPath, newPath.IsValid(), func(rawOld string) error {
		oldKey, e1 := r.tree.resolveParentLocked(rawOld, true, false)
		newKey, e2 := r.tree.resolveParentLocked(normTreePath(newPath.String()), true, false)
		if err := firstErr(e1, e2); err != nil {
			return err
		}
		if oldKey == "/" || newKey == "/" {
			return ports.ErrPermissionDenied
		}
		src := r.tree.nodes[oldKey]
		if src == nil {
			return ports.ErrNotFound
		}
		if err := r.validateRenameLocked(oldKey, newKey, src, expectedAnchor); err != nil {
			return err
		}
		if oldKey != newKey {
			r.relocateSubtreeLocked(oldKey, newKey, src)
		}
		return nil
	})
}
func (r *SimRemoteFS) validateRenameLocked(oldKey, newKey string, src *simMemNode, expected algebraic.Option[ports.RemoteFileAnchor]) error {
	if src.kind == ports.RemoteFileDir && strings.HasPrefix(newKey, oldKey+"/") {
		return ports.ErrInvalidArgument
	}
	if anc, ok := expected.Get(); ok {
		if err := r.verifyAnchorLocked(newKey, anc); err != nil {
			return err
		}
	}
	dst := r.tree.nodes[newKey]
	switch {
	case dst == nil || oldKey == newKey:
		return nil
	case src.kind != ports.RemoteFileDir && dst.kind == ports.RemoteFileDir:
		return ports.ErrRemoteIsDir
	case src.kind == ports.RemoteFileDir && (dst.kind != ports.RemoteFileDir || r.tree.hasChildrenLocked(newKey)):
		return ports.ErrInvalidArgument
	default:
		return nil
	}
}
func (r *SimRemoteFS) relocateSubtreeLocked(oldKey, newKey string, src *simMemNode) {
	delete(r.tree.nodes, oldKey)
	r.tree.nodes[newKey] = src
	if src.kind == ports.RemoteFileDir {
		moved := make(map[string]*simMemNode)
		for k, v := range r.tree.nodes {
			if strings.HasPrefix(k, oldKey+"/") {
				moved[newKey+k[len(oldKey):]] = v
				delete(r.tree.nodes, k)
			}
		}
		maps.Copy(r.tree.nodes, moved)
	}
}
func (r *SimRemoteFS) MkdirAll(ctx context.Context, dir pathalg.RemotePath, perm fs.FileMode) error {
	return r.doTree(ctx, "rfs.write", dir, true, func(key string) error { return r.tree.mkdirAllLocked(key, perm, true) })
}
func (r *SimRemoteFS) Remove(ctx context.Context, p pathalg.RemotePath) error {
	return r.doTree(ctx, "rfs.remove", p, true, func(key string) error { return r.tree.removeLocked(key, true, false) })
}
func (r *SimRemoteFS) Close() error { r.withLock(func() { r.closed = true }); return nil }
func (r *SimRemoteFS) verifyAnchorLocked(key string, expected ports.RemoteFileAnchor) error {
	if ex := r.tree.nodes[key]; ex != nil {
		if obs, err := ports.NewRemoteFileAnchor(ex.kind, true, 1, ex.ino); err == nil && expected.Matches(obs) {
			return nil
		}
	}
	return ports.ErrRemoteAnchorMismatch
}
func buildRemoteStat(p pathalg.RemotePath, n *simMemNode) (out ports.RemoteFileStat, err error) {
	anc, err := ports.NewRemoteFileAnchor(n.kind, true, 1, n.ino)
	if err != nil {
		return out, err
	}
	return ports.NewRemoteFileStat(ports.RemoteFileStatSpec{Path: p, Size: int64(len(n.data)), Mode: n.mode, ModTime: n.modTime, Anchor: anc})
}
