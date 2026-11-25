package sim

import (
	"bytes"
	"context"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/internal/sim/memtree"
	"github.com/wentf9/xops-cli/core/ports"
	"io/fs"
	"path"
)

// SimOperatorReadFS 实现 ports.OperatorReadFS 的人工只读源内存仿真器（复用 memtree.Tree）。
//
//xops:opaque
//xops:failclosed
type SimOperatorReadFS struct {
	simBase
	tree *memtree.Tree
}

// NewSimOperatorReadFS 创建空白的操作员只读源仿真器。
func NewSimOperatorReadFS() *SimOperatorReadFS {
	return &SimOperatorReadFS{simBase: newSimBase(nil), tree: memtree.New(nil, false, 0o755)}
}

// PutFile 与 PutSymlink 注册仿真只读常规文件与符号链接夹具。
func (o *SimOperatorReadFS) PutFile(p pathalg.LocalSourcePath, data []byte) error {
	return o.putNode(p, true, &memtree.Node{Kind: ports.RemoteFileRegular, Mode: 0o600, Data: bytes.Clone(data)})
}
func (o *SimOperatorReadFS) PutSymlink(linkPath, targetPath pathalg.LocalSourcePath) error {
	return o.putNode(linkPath, targetPath.IsValid(), &memtree.Node{Kind: ports.RemoteFileSymlink, Mode: fs.ModeSymlink | 0o777, Target: memtree.NormPath(targetPath.String())})
}
func (o *SimOperatorReadFS) putNode(p pathalg.LocalSourcePath, ok bool, node *memtree.Node) error {
	if err := o.check(context.Background(), "", p.IsValid(), ok); err != nil {
		return err
	}
	o.tree.Mu.Lock()
	abs := memtree.NormPath(p.String())
	_ = o.tree.MkdirAllLocked(path.Dir(abs), 0o755, false)
	o.tree.Nodes[abs] = node
	o.tree.Mu.Unlock()
	return nil
}

// WithOperatorRead 按 SymlinkPolicy 逐段解析并打开只读源，在同步闭包内借出受哨兵保护的随机读取句柄。
//
//xops:syncclosure
//xops:borrowed
func (o *SimOperatorReadFS) WithOperatorRead(ctx context.Context, srcPath pathalg.LocalSourcePath, policy pathalg.SymlinkPolicy, fn func(r ports.BoundedReadHandle, size int64) error) error {
	if err := o.checkFn(ctx, fn != nil, "opread.open", srcPath.IsValid(), policy.IsValid()); err != nil {
		return err
	}
	follow := policy.AllowsOperatorFollow()
	o.tree.Mu.Lock()
	_, node, err := o.tree.WalkPathLocked(memtree.NormPath(srcPath.String()), follow, follow, !follow)
	var data []byte
	if err == nil && node.Kind != ports.RemoteFileRegular {
		err = ports.ErrNotRegularFile
	} else if err == nil {
		data = bytes.Clone(node.Data)
	}
	o.tree.Mu.Unlock()
	if err != nil {
		return err
	}
	r, expire := memtree.NewScopedReader(data, 0)
	defer expire()
	return fn(r, int64(len(data)))
}
