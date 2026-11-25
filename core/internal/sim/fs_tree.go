package sim

import (
	"bytes"
	"cmp"
	"context"
	"io"
	"io/fs"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
)

type simMemNode struct {
	kind    ports.RemoteFileType
	mode    fs.FileMode
	data    []byte
	target  string
	modTime time.Time
	ino     uint64
}
type simFileLock struct {
	shared    int
	exclusive bool
	changed   chan struct{}
}
type simDirItem struct {
	name string
	node *simMemNode
}

// simMemTree 统一采用前导 "/" 规范路径封装纯内存 POSIX 目录树（本地沙箱、操作员只读与远端共用），
// 通过逐段符号链接步进器 walkPathLocked 共享单一 pathalg.MaxSymlinkHops 预算。
type simMemTree struct {
	mu           sync.Mutex
	strictParent bool
	clock        ports.Clock
	nextIno      uint64
	nodes        map[string]*simMemNode
	locks        map[string]*simFileLock
}

func newSimMemTree(clk ports.Clock, strictParent bool, rootPerm fs.FileMode) *simMemTree {
	if clk == nil {
		clk = NewSimClock(DefaultBaseTime())
	}
	return &simMemTree{
		strictParent: strictParent, clock: clk, nextIno: 1,
		nodes: map[string]*simMemNode{"/": {kind: ports.RemoteFileDir, mode: fs.ModeDir | rootPerm, modTime: clk.Now().UTC().Round(0), ino: 1}},
		locks: make(map[string]*simFileLock),
	}
}
func (t *simMemTree) now() time.Time   { return t.clock.Now().UTC().Round(0) }
func (t *simMemTree) allocIno() uint64 { t.nextIno++; return t.nextIno }
func normTreePath(p string) string     { return path.Clean("/" + p) }

// walkPathLocked 逐段解析 abs，在中间目录段与末段共享 MaxSymlinkHops 软链跳数上限。
func (t *simMemTree) walkPathLocked(abs string, followParent, followLeaf, rejectSymlink bool) (string, *simMemNode, error) {
	if abs == "/" {
		return "/", t.nodes["/"], nil
	}
	segs, cur, hops := strings.Split(abs[1:], "/"), "/", pathalg.MaxSymlinkHops
	for i := 0; i < len(segs); i++ {
		next, isLeaf := path.Join(cur, segs[i]), i == len(segs)-1
		nd := t.nodes[next]
		if nd == nil {
			return "", nil, ports.ErrNotFound
		}
		if nd.kind == ports.RemoteFileSymlink {
			newSegs, done, err := t.handleSymlinkLocked(next, nd, segs[i+1:], isLeaf, followParent, followLeaf, rejectSymlink, &hops)
			if err != nil {
				return "", nil, err
			}
			if done != "" {
				return done, t.nodes[done], nil
			}
			cur, segs, i = "/", newSegs, -1
			continue
		}
		if !isLeaf && nd.kind != ports.RemoteFileDir {
			return "", nil, ports.ErrInvalidArgument
		}
		cur = next
	}
	return cur, t.nodes[cur], nil
}
func (t *simMemTree) handleSymlinkLocked(next string, nd *simMemNode, rest []string, isLeaf, followParent, followLeaf, rejectSymlink bool, hops *int) ([]string, string, error) {
	if (!isLeaf && !followParent) || (isLeaf && !followLeaf) {
		if rejectSymlink {
			return nil, "", ports.ErrSymlinkRejected
		}
		if isLeaf {
			return nil, next, nil
		}
		return nil, "", ports.ErrInvalidArgument
	}
	if *hops--; *hops < 0 || (t.strictParent && strings.HasPrefix(nd.target, "/")) {
		return nil, "", ports.ErrSymlinkRejected
	}
	resolved := path.Clean(path.Dir(next) + "/" + nd.target)
	if strings.HasPrefix(nd.target, "/") {
		resolved = path.Clean(nd.target)
	}
	if resolved != "/" {
		return append(strings.Split(resolved[1:], "/"), rest...), "", nil
	}
	if len(rest) > 0 {
		return rest, "", nil
	}
	if t.strictParent {
		return nil, "", ports.ErrSymlinkRejected
	}
	return nil, "/", nil
}
func (t *simMemTree) resolveParentLocked(abs string, followParent, rejectSymlink bool) (string, error) {
	dir := path.Dir(abs)
	if abs == "/" || dir == "/" {
		return abs, nil
	}
	parentAbs, pNode, err := t.walkPathLocked(dir, followParent, followParent, rejectSymlink)
	if err != nil {
		return "", err
	}
	if pNode.kind != ports.RemoteFileDir {
		return "", ports.ErrInvalidArgument
	}
	return path.Join(parentAbs, path.Base(abs)), nil
}
func (t *simMemTree) mkdirAllLocked(abs string, perm fs.FileMode, followParent bool) error {
	if abs == "/" {
		return nil
	}
	now, cur := t.now(), "/"
	for seg := range strings.SplitSeq(abs[1:], "/") {
		next := path.Join(cur, seg)
		if n := t.nodes[next]; n != nil {
			res, err := t.stepDirLocked(next, n, followParent)
			if err != nil {
				return err
			}
			cur = res
			continue
		}
		t.nodes[next] = &simMemNode{kind: ports.RemoteFileDir, mode: fs.ModeDir | perm.Perm(), modTime: now, ino: t.allocIno()}
		cur = next
	}
	return nil
}
func (t *simMemTree) stepDirLocked(next string, n *simMemNode, followParent bool) (string, error) {
	switch {
	case n.kind == ports.RemoteFileDir:
		return next, nil
	case n.kind != ports.RemoteFileSymlink:
		return "", ports.ErrAlreadyExists
	case !followParent:
		return "", ports.ErrSymlinkRejected
	}
	res, target, err := t.walkPathLocked(next, true, true, false)
	if err != nil || target.kind != ports.RemoteFileDir {
		return "", firstErr(err, ports.ErrAlreadyExists)
	}
	return res, nil
}
func (t *simMemTree) readRegularLocked(abs string, followParent, followLeaf, rejectSymlink bool, limits ports.ReadLimits, dirErr error) ([]byte, error) {
	_, node, err := t.walkPathLocked(abs, followParent, followLeaf, rejectSymlink)
	if err != nil {
		return nil, err
	}
	switch {
	case node.kind == ports.RemoteFileDir:
		return nil, dirErr
	case node.kind != ports.RemoteFileRegular:
		return nil, ports.ErrNotRegularFile
	case int64(len(node.data)) > limits.MaxBytes():
		return nil, ports.ErrLimitExceeded
	default:
		return bytes.Clone(node.data), nil
	}
}
func (t *simMemTree) listDirLocked(abs string, followParent, followLeaf, rejectSymlink bool) (items []simDirItem, err error) {
	resolved, parent, err := t.walkPathLocked(abs, followParent, followLeaf, rejectSymlink)
	if err != nil || parent.kind != ports.RemoteFileDir {
		return nil, firstErr(err, ports.ErrInvalidArgument)
	}
	for k, n := range t.nodes {
		if k != "/" && path.Dir(k) == resolved {
			items = append(items, simDirItem{path.Base(k), n})
		}
	}
	slices.SortFunc(items, func(a, b simDirItem) int { return cmp.Compare(a.name, b.name) })
	return items, nil
}
func (t *simMemTree) hasChildrenLocked(dirAbs string) bool {
	for k := range t.nodes {
		if strings.HasPrefix(k, dirAbs+"/") {
			return true
		}
	}
	return false
}
func (t *simMemTree) removeLocked(abs string, followParent, rejectSymlink bool) error {
	if abs == "/" {
		return ports.ErrPermissionDenied
	}
	key, err := t.resolveParentLocked(abs, followParent, rejectSymlink)
	if err != nil {
		return err
	}
	node := t.nodes[key]
	if node == nil {
		return ports.ErrNotFound
	}
	if node.kind == ports.RemoteFileDir && t.hasChildrenLocked(key) {
		return ports.ErrInvalidArgument
	}
	delete(t.nodes, key)
	return nil
}
func (t *simMemTree) collectSymlinksLocked() (out []pathalg.SymlinkBinding) {
	for k, n := range t.nodes {
		if d, e := pathalg.ParseLocalRootedDest(k[1:]); n.kind == ports.RemoteFileSymlink && e == nil {
			if b, be := pathalg.NewSymlinkBinding(d, n.target); be == nil {
				out = append(out, b)
			}
		}
	}
	return out
}

// SimOperatorReadFS 实现 ports.OperatorReadFS 的人工只读源内存仿真器（复用 simMemTree）。
//
//xops:opaque
//xops:failclosed
type SimOperatorReadFS struct {
	simBase
	tree *simMemTree
}

// NewSimOperatorReadFS 创建空白的操作员只读源仿真器。
func NewSimOperatorReadFS() *SimOperatorReadFS {
	return &SimOperatorReadFS{simBase: newSimBase(nil), tree: newSimMemTree(nil, false, 0o755)}
}

// PutFile 与 PutSymlink 注册仿真只读常规文件与符号链接夹具。
func (o *SimOperatorReadFS) PutFile(p pathalg.LocalSourcePath, data []byte) error {
	return o.putNode(p, true, &simMemNode{kind: ports.RemoteFileRegular, mode: 0o600, data: bytes.Clone(data)})
}
func (o *SimOperatorReadFS) PutSymlink(linkPath, targetPath pathalg.LocalSourcePath) error {
	return o.putNode(linkPath, targetPath.IsValid(), &simMemNode{kind: ports.RemoteFileSymlink, mode: fs.ModeSymlink | 0o777, target: normTreePath(targetPath.String())})
}
func (o *SimOperatorReadFS) putNode(p pathalg.LocalSourcePath, ok bool, node *simMemNode) error {
	if err := o.check(context.Background(), "", p.IsValid(), ok); err != nil {
		return err
	}
	o.tree.mu.Lock()
	abs := normTreePath(p.String())
	_ = o.tree.mkdirAllLocked(path.Dir(abs), 0o755, false)
	o.tree.nodes[abs] = node
	o.tree.mu.Unlock()
	return nil
}

// WithOperatorRead 按 SymlinkPolicy 逐段解析并打开只读源，在同步闭包内借出受哨兵保护的流。
//
//xops:syncclosure
//xops:borrowed
func (o *SimOperatorReadFS) WithOperatorRead(ctx context.Context, srcPath pathalg.LocalSourcePath, policy pathalg.SymlinkPolicy, fn func(r io.Reader, size int64) error) error {
	if err := o.checkFn(ctx, fn != nil, "opread.open", srcPath.IsValid(), policy.IsValid()); err != nil {
		return err
	}
	follow := policy.AllowsOperatorFollow()
	o.tree.mu.Lock()
	_, node, err := o.tree.walkPathLocked(normTreePath(srcPath.String()), follow, follow, !follow)
	var data []byte
	if err == nil && node.kind != ports.RemoteFileRegular {
		err = ports.ErrNotRegularFile
	} else if err == nil {
		data = bytes.Clone(node.data)
	}
	o.tree.mu.Unlock()
	if err != nil {
		return err
	}
	return withScopedReader(data, fn)
}
