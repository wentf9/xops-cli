// Package memtree 为 core/internal/sim 提供共享的纯内存 POSIX 目录树、符号链接步进器与作用域读写句柄。
//
// 本包仅由 core/internal/sim 内部复用（0 生产可达），零 os/path/filepath/time.Now/nolint 依赖。
package memtree

import (
	"bytes"
	"cmp"
	"io/fs"
	"maps"
	"path"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
)

// Node 表示纯内存目录树中的单个文件、目录或符号链接节点。
type Node struct {
	Kind    ports.RemoteFileType
	Mode    fs.FileMode
	Data    []byte
	Target  string
	ModTime time.Time
	Ino     uint64
}

// FileLock 记录纯内存句柄级共享/独占锁状态及等待唤醒通道。
type FileLock struct {
	Shared    int
	Exclusive bool
	Changed   chan struct{}
}

// DirItem 表示按名称排序的目录枚举项。
type DirItem struct {
	Name string
	Node *Node
}

// Tree 统一采用前导 "/" 规范路径封装纯内存 POSIX 目录树（本地沙箱、操作员只读与远端共用），
// 通过逐段符号链接步进器 WalkPathLocked 共享单一 pathalg.MaxSymlinkHops 预算。
type Tree struct {
	Mu           sync.Mutex
	StrictParent bool
	Clock        ports.Clock
	NextIno      uint64
	Nodes        map[string]*Node
	Locks        map[string]*FileLock
}

// New 创建仅含根目录 "/" 的纯内存目录树。
func New(clk ports.Clock, strictParent bool, rootPerm fs.FileMode) *Tree {
	now := time.Date(2026, time.May, 1, 12, 0, 0, 0, time.UTC)
	if clk != nil {
		now = clk.Now().UTC().Round(0)
	}
	return &Tree{
		StrictParent: strictParent,
		Clock:        clk,
		NextIno:      1,
		Nodes:        map[string]*Node{"/": {Kind: ports.RemoteFileDir, Mode: fs.ModeDir | rootPerm, ModTime: now, Ino: 1}},
		Locks:        make(map[string]*FileLock),
	}
}

// Now 返回当前确定性 UTC 时间戳。
func (t *Tree) Now() time.Time {
	if t.Clock == nil {
		return time.Date(2026, time.May, 1, 12, 0, 0, 0, time.UTC)
	}
	return t.Clock.Now().UTC().Round(0)
}

// AllocIno 分配单调递增的虚拟 inode 编号（调用方须持有 t.Mu）。
func (t *Tree) AllocIno() uint64 { t.NextIno++; return t.NextIno }

// NormPath 将相对或绝对路径规范化为带前导 "/" 的 POSIX 树键。
func NormPath(p string) string { return path.Clean("/" + p) }

// GrowBytes 确保字节切片长度至少为 size，不足时零值扩容返回新切片。
func GrowBytes(buf []byte, size int64) []byte {
	if size <= int64(len(buf)) {
		return buf
	}
	out := make([]byte, size)
	copy(out, buf)
	return out
}

// FirstErr 返回首个非 nil 错误。
func FirstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// WalkPathLocked 逐段解析 abs，在中间目录段与末段共享 MaxSymlinkHops 软链跳数上限（调用方须持有 t.Mu）。
func (t *Tree) WalkPathLocked(abs string, followParent, followLeaf, rejectSymlink bool) (string, *Node, error) {
	if abs == "/" {
		return "/", t.Nodes["/"], nil
	}
	segs, cur, hops := strings.Split(abs[1:], "/"), "/", pathalg.MaxSymlinkHops
	for i := 0; i < len(segs); i++ {
		next, isLeaf := path.Join(cur, segs[i]), i == len(segs)-1
		nd := t.Nodes[next]
		if nd == nil {
			return "", nil, ports.ErrNotFound
		}
		if nd.Kind == ports.RemoteFileSymlink {
			newSegs, done, err := t.handleSymlinkLocked(next, nd, segs[i+1:], isLeaf, followParent, followLeaf, rejectSymlink, &hops)
			if err != nil {
				return "", nil, err
			}
			if done != "" {
				return done, t.Nodes[done], nil
			}
			cur, segs, i = "/", newSegs, -1
			continue
		}
		if !isLeaf && nd.Kind != ports.RemoteFileDir {
			return "", nil, ports.ErrInvalidArgument
		}
		cur = next
	}
	return cur, t.Nodes[cur], nil
}

func (t *Tree) handleSymlinkLocked(next string, nd *Node, rest []string, isLeaf, followParent, followLeaf, rejectSymlink bool, hops *int) ([]string, string, error) {
	if (!isLeaf && !followParent) || (isLeaf && !followLeaf) {
		if rejectSymlink {
			return nil, "", ports.ErrSymlinkRejected
		}
		if isLeaf {
			return nil, next, nil
		}
		return nil, "", ports.ErrInvalidArgument
	}
	if *hops--; *hops < 0 || (t.StrictParent && strings.HasPrefix(nd.Target, "/")) {
		return nil, "", ports.ErrSymlinkRejected
	}
	resolved := path.Clean(path.Dir(next) + "/" + nd.Target)
	if strings.HasPrefix(nd.Target, "/") {
		resolved = path.Clean(nd.Target)
	}
	if resolved != "/" {
		return append(strings.Split(resolved[1:], "/"), rest...), "", nil
	}
	if len(rest) > 0 {
		return rest, "", nil
	}
	if t.StrictParent {
		return nil, "", ports.ErrSymlinkRejected
	}
	return nil, "/", nil
}

// ResolveParentLocked 解析 abs 的父目录并拼接末段基名返回目标树键（调用方须持有 t.Mu）。
func (t *Tree) ResolveParentLocked(abs string, followParent, rejectSymlink bool) (string, error) {
	dir := path.Dir(abs)
	if abs == "/" || dir == "/" {
		return abs, nil
	}
	parentAbs, pNode, err := t.WalkPathLocked(dir, followParent, followParent, rejectSymlink)
	if err != nil {
		return "", err
	}
	if pNode.Kind != ports.RemoteFileDir {
		return "", ports.ErrInvalidArgument
	}
	return path.Join(parentAbs, path.Base(abs)), nil
}

// MkdirAllLocked 递归创建目录链，按 followParent 决定是否跟随已有中间符号链接（调用方须持有 t.Mu）。
func (t *Tree) MkdirAllLocked(abs string, perm fs.FileMode, followParent bool) error {
	if abs == "/" {
		return nil
	}
	now, cur := t.Now(), "/"
	for seg := range strings.SplitSeq(abs[1:], "/") {
		next := path.Join(cur, seg)
		if n := t.Nodes[next]; n != nil {
			res, err := t.stepDirLocked(next, n, followParent)
			if err != nil {
				return err
			}
			cur = res
			continue
		}
		t.Nodes[next] = &Node{Kind: ports.RemoteFileDir, Mode: fs.ModeDir | perm.Perm(), ModTime: now, Ino: t.AllocIno()}
		cur = next
	}
	return nil
}

func (t *Tree) stepDirLocked(next string, n *Node, followParent bool) (string, error) {
	switch {
	case n.Kind == ports.RemoteFileDir:
		return next, nil
	case n.Kind != ports.RemoteFileSymlink:
		return "", ports.ErrAlreadyExists
	case !followParent:
		return "", ports.ErrSymlinkRejected
	}
	res, target, err := t.WalkPathLocked(next, true, true, false)
	if err != nil || target.Kind != ports.RemoteFileDir {
		return "", FirstErr(err, ports.ErrAlreadyExists)
	}
	return res, nil
}

// ReadRegularLocked 校验目标为常规文件且未超出 limits 上限后返回数据副本（调用方须持有 t.Mu）。
func (t *Tree) ReadRegularLocked(abs string, followParent, followLeaf, rejectSymlink bool, limits ports.ReadLimits, dirErr error) ([]byte, error) {
	_, node, err := t.WalkPathLocked(abs, followParent, followLeaf, rejectSymlink)
	if err != nil {
		return nil, err
	}
	switch {
	case node.Kind == ports.RemoteFileDir:
		return nil, dirErr
	case node.Kind != ports.RemoteFileRegular:
		return nil, ports.ErrNotRegularFile
	case int64(len(node.Data)) > limits.MaxBytes():
		return nil, ports.ErrLimitExceeded
	default:
		return bytes.Clone(node.Data), nil
	}
}

// ListDirLocked 按字典序枚举指定目录直接子节点（调用方须持有 t.Mu）。
func (t *Tree) ListDirLocked(abs string, followParent, followLeaf, rejectSymlink bool) (items []DirItem, err error) {
	resolved, parent, err := t.WalkPathLocked(abs, followParent, followLeaf, rejectSymlink)
	if err != nil || parent.Kind != ports.RemoteFileDir {
		return nil, FirstErr(err, ports.ErrInvalidArgument)
	}
	for k, n := range t.Nodes {
		if k != "/" && path.Dir(k) == resolved {
			items = append(items, DirItem{Name: path.Base(k), Node: n})
		}
	}
	slices.SortFunc(items, func(a, b DirItem) int { return cmp.Compare(a.Name, b.Name) })
	return items, nil
}

// HasChildrenLocked 判断 dirAbs 下是否存在任意子孙节点（调用方须持有 t.Mu）。
func (t *Tree) HasChildrenLocked(dirAbs string) bool {
	for k := range t.Nodes {
		if strings.HasPrefix(k, dirAbs+"/") {
			return true
		}
	}
	return false
}

// RemoveLocked 删除文件、符号链接或空目录（拒绝删除根目录与非空目录，调用方须持有 t.Mu）。
func (t *Tree) RemoveLocked(abs string, followParent, rejectSymlink bool) error {
	if abs == "/" {
		return ports.ErrPermissionDenied
	}
	key, err := t.ResolveParentLocked(abs, followParent, rejectSymlink)
	if err != nil {
		return err
	}
	node := t.Nodes[key]
	if node == nil {
		return ports.ErrNotFound
	}
	if node.Kind == ports.RemoteFileDir && t.HasChildrenLocked(key) {
		return ports.ErrInvalidArgument
	}
	delete(t.Nodes, key)
	return nil
}

// RelocateSubtreeLocked 将 oldKey（及其目录子树）原子迁移至 newKey（调用方须持有 t.Mu 且已完成前置校验）。
func (t *Tree) RelocateSubtreeLocked(oldKey, newKey string, src *Node) {
	delete(t.Nodes, oldKey)
	t.Nodes[newKey] = src
	if src.Kind == ports.RemoteFileDir {
		moved := make(map[string]*Node)
		for k, v := range t.Nodes {
			if strings.HasPrefix(k, oldKey+"/") {
				moved[newKey+k[len(oldKey):]] = v
				delete(t.Nodes, k)
			}
		}
		maps.Copy(t.Nodes, moved)
	}
}

// CollectSymlinksLocked 收集树内全部可映射为 LocalRootedDest 的符号链接绑定，供域层闭环校验使用。
func (t *Tree) CollectSymlinksLocked() (out []pathalg.SymlinkBinding) {
	for k, n := range t.Nodes {
		if d, e := pathalg.ParseLocalRootedDest(k[1:]); n.Kind == ports.RemoteFileSymlink && e == nil {
			if b, be := pathalg.NewSymlinkBinding(d, n.Target); be == nil {
				out = append(out, b)
			}
		}
	}
	return out
}

// ScopedReader 实现 ports.BoundedReadHandle（io.Reader + io.ReaderAt），带运行时失效哨兵与字节上限守卫。
type ScopedReader struct {
	r        *bytes.Reader
	maxBytes int64
	expired  *atomic.Bool
}

// Read 顺序读取字节流；回调退出后立即返回 ports.ErrHandleExpired。
func (sr *ScopedReader) Read(p []byte) (int, error) {
	if sr == nil || sr.expired == nil || sr.expired.Load() {
		return 0, ports.ErrHandleExpired
	}
	return sr.r.Read(p)
}

// ReadAt 在任意非负偏移处随机读取；回调退出后立即返回 ports.ErrHandleExpired，负偏移返回 ports.ErrInvalidArgument。
func (sr *ScopedReader) ReadAt(p []byte, off int64) (int, error) {
	if sr == nil || sr.expired == nil || sr.expired.Load() {
		return 0, ports.ErrHandleExpired
	}
	if off < 0 {
		return 0, ports.ErrInvalidArgument
	}
	if sr.maxBytes > 0 && off >= sr.maxBytes && off < sr.r.Size() {
		return 0, ports.ErrLimitExceeded
	}
	return sr.r.ReadAt(p, off)
}

// NewScopedReader 构造受运行时失效哨兵保护的 *ScopedReader（同时满足 ports.BoundedReadHandle 与 io.Reader），
// 并返回调用方须经 defer 执行的失效函数。
func NewScopedReader(data []byte, maxBytes int64) (*ScopedReader, func()) {
	var expired atomic.Bool
	return &ScopedReader{r: bytes.NewReader(data), maxBytes: maxBytes, expired: &expired}, func() { expired.Store(true) }
}

// ScopedWriter 为作用域写回调提供失效哨兵与可选写故障检查。
type ScopedWriter struct {
	buf        *bytes.Buffer
	expired    *atomic.Bool
	checkWrite func() error
}

// NewScopedWriter 构造受 expired 哨兵保护的作用域写入器。
func NewScopedWriter(buf *bytes.Buffer, expired *atomic.Bool, checkWrite func() error) *ScopedWriter {
	return &ScopedWriter{buf: buf, expired: expired, checkWrite: checkWrite}
}

// Write 写入缓冲前检查失效哨兵与故障注入。
func (sw *ScopedWriter) Write(p []byte) (int, error) {
	if sw == nil || sw.expired == nil || sw.expired.Load() {
		return 0, ports.ErrHandleExpired
	}
	if sw.checkWrite != nil {
		if err := sw.checkWrite(); err != nil {
			return 0, err
		}
	}
	return sw.buf.Write(p)
}
