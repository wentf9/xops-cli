package sim

import (
	"context"
	"io"
	"io/fs"
	"path"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/internal/sim/memtree"
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
	tree   *memtree.Tree
}

// NewSimRemoteFS 创建预置根目录 "/" 的远端 POSIX 文件系统仿真器。
func NewSimRemoteFS(clk ports.Clock) *SimRemoteFS {
	return &SimRemoteFS{simBase: newSimBase(nil), tree: memtree.New(clk, false, 0o755)}
}

// SetENOSPC / PutSymlink 提供远端磁盘满故障与软链重定向夹具支持。
func (r *SimRemoteFS) SetENOSPC(en bool) {
	if r.ok() {
		r.enospc.Store(en)
	}
}
func (r *SimRemoteFS) PutSymlink(linkPath pathalg.RemotePath, target string) error {
	return r.doTree(context.Background(), "", linkPath, target != "", func(key string) error {
		if err := r.tree.MkdirAllLocked(path.Dir(key), 0o755, true); err != nil {
			return err
		}
		resolved, err := r.tree.ResolveParentLocked(key, true, false)
		if err == nil {
			r.tree.Nodes[resolved] = &memtree.Node{Kind: ports.RemoteFileSymlink, Mode: fs.ModeSymlink | 0o777, Target: target, ModTime: r.tree.Now(), Ino: r.tree.AllocIno()}
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
	r.tree.Mu.Lock()
	defer r.tree.Mu.Unlock()
	return fn(memtree.NormPath(p.String()))
}
func (r *SimRemoteFS) RealPath(ctx context.Context, p pathalg.RemotePath) (out pathalg.RemotePath, err error) {
	return out, r.doTree(ctx, "", p, true, func(key string) error {
		res, _, e := r.tree.WalkPathLocked(key, true, true, false)
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
		res, node, e := r.tree.WalkPathLocked(key, true, followLeaf, false)
		if e == nil && followLeaf {
			p, e = pathalg.ParseRemotePath(res)
		}
		if e == nil {
			out, e = memtree.BuildRemoteStat(p, node)
		}
		return e
	})
}
func (r *SimRemoteFS) ReadLink(ctx context.Context, p pathalg.RemotePath) (target string, err error) {
	return target, r.doTree(ctx, "", p, true, func(key string) error {
		_, n, e := r.tree.WalkPathLocked(key, true, false, false)
		if e != nil || n.Kind != ports.RemoteFileSymlink {
			return firstErr(e, ports.ErrInvalidArgument)
		}
		target = n.Target
		return nil
	})
}
func (r *SimRemoteFS) ReadDir(ctx context.Context, dir pathalg.RemotePath) (out []ports.RemoteDirEntry, err error) {
	return out, r.doTree(ctx, "", dir, true, func(key string) error {
		items, e := r.tree.ListDirLocked(key, true, true, false)
		for _, it := range items {
			if e == nil {
				rn, e1 := pathalg.ParseRemoteName(it.Name)
				ent, e2 := ports.NewRemoteDirEntry(ports.RemoteDirEntrySpec{Name: rn, FileType: it.Node.Kind, Size: int64(len(it.Node.Data)), Mode: it.Node.Mode, ModTime: it.Node.ModTime})
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
		data, e = r.tree.ReadRegularLocked(key, true, true, false, limits, ports.ErrRemoteIsDir)
		return e
	}); err != nil {
		return err
	}
	rd, expire := memtree.NewScopedReader(data, 0)
	defer expire()
	return fn(rd, int64(len(data)))
}

// ReadChunk 从远端常规文件 offset 处读取至多 length 字节写入 dst；读满返回 (length, nil)，遇 EOF 返回 (实际字节数, io.EOF)。
func (r *SimRemoteFS) ReadChunk(ctx context.Context, p pathalg.RemotePath, offset int64, dst io.Writer, length int64) (int64, error) {
	var chunk []byte
	var hitEOF bool
	if err := r.doTree(ctx, "rfs.read", p, offset >= 0 && length >= 0 && dst != nil, func(key string) (e error) {
		chunk, hitEOF, e = r.tree.ReadRemoteChunkLocked(key, offset, length)
		return e
	}); err != nil {
		return 0, err
	}
	if len(chunk) == 0 {
		if hitEOF {
			return 0, io.EOF
		}
		return 0, nil
	}
	n, wErr := dst.Write(chunk)
	if wErr != nil {
		return int64(n), wErr
	}
	if hitEOF {
		return int64(n), io.EOF
	}
	return int64(n), nil
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
		key, e := r.tree.CheckRemoteWriteTargetLocked(rawKey, spec)
		if e != nil {
			return e
		}
		n := &memtree.Node{Kind: ports.RemoteFileRegular, Mode: spec.Perm(), Data: payload, ModTime: r.tree.Now(), Ino: r.tree.AllocIno()}
		r.tree.Nodes[key] = n
		out, e = memtree.BuildRemoteStat(p, n)
		return e
	})
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
		return r.tree.WriteRemoteChunkLocked(rawKey, offset, chunk)
	})
}
func (r *SimRemoteFS) RenameAtomic(ctx context.Context, oldPath, newPath pathalg.RemotePath, expectedAnchor algebraic.Option[ports.RemoteFileAnchor]) error {
	return r.doTree(ctx, "rfs.rename", oldPath, newPath.IsValid(), func(rawOld string) error {
		return r.tree.RenameRemoteLocked(rawOld, memtree.NormPath(newPath.String()), expectedAnchor)
	})
}

// Chmod 修改远端目标对象标准权限位（仅允许 0o001..0o777，拒绝零值及特殊权限位）。
func (r *SimRemoteFS) Chmod(ctx context.Context, p pathalg.RemotePath, perm fs.FileMode) error {
	return r.doTree(ctx, "rfs.write", p, perm != 0 && perm == perm.Perm(), func(key string) error {
		return r.tree.ChmodRemoteLocked(key, perm)
	})
}
func (r *SimRemoteFS) MkdirAll(ctx context.Context, dir pathalg.RemotePath, perm fs.FileMode) error {
	return r.doTree(ctx, "rfs.write", dir, true, func(key string) error { return r.tree.MkdirAllLocked(key, perm, true) })
}
func (r *SimRemoteFS) Remove(ctx context.Context, p pathalg.RemotePath) error {
	return r.doTree(ctx, "rfs.remove", p, true, func(key string) error { return r.tree.RemoveLocked(key, true, false) })
}
func (r *SimRemoteFS) Close() error { r.withLock(func() { r.closed = true }); return nil }
