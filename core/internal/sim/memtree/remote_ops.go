package memtree

import (
	"bytes"
	"io/fs"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
)

// BuildRemoteStat 将内存树节点投影为携带 (dev=1, ino) 锚点的不可变 ports.RemoteFileStat。
func BuildRemoteStat(p pathalg.RemotePath, n *Node) (out ports.RemoteFileStat, err error) {
	anc, err := ports.NewRemoteFileAnchor(n.Kind, true, 1, n.Ino)
	if err != nil {
		return out, err
	}
	return ports.NewRemoteFileStat(ports.RemoteFileStatSpec{Path: p, Size: int64(len(n.Data)), Mode: n.Mode, ModTime: n.ModTime, Anchor: anc})
}

// VerifyAnchorLocked 核验远端树节点与期望 (type, dev, ino) 锚点是否一致。
func (t *Tree) VerifyAnchorLocked(key string, expected ports.RemoteFileAnchor) error {
	if ex := t.Nodes[key]; ex != nil {
		if obs, err := ports.NewRemoteFileAnchor(ex.Kind, true, 1, ex.Ino); err == nil && expected.Matches(obs) {
			return nil
		}
	}
	return ports.ErrRemoteAnchorMismatch
}

// ReadRemoteChunkLocked 在持有 t.Mu 下读取远端常规文件 [offset, offset+length) 区间副本与 EOF 标记。
func (t *Tree) ReadRemoteChunkLocked(key string, offset, length int64) ([]byte, bool, error) {
	_, node, err := t.WalkPathLocked(key, true, true, false)
	if err != nil {
		return nil, false, err
	}
	if node.Kind == ports.RemoteFileDir {
		return nil, false, ports.ErrRemoteIsDir
	}
	if node.Kind != ports.RemoteFileRegular {
		return nil, false, ports.ErrNotRegularFile
	}
	if length == 0 {
		return nil, false, nil
	}
	if offset >= int64(len(node.Data)) {
		return nil, true, nil
	}
	avail := node.Data[offset:]
	if int64(len(avail)) > length {
		return bytes.Clone(avail[:length]), false, nil
	}
	return bytes.Clone(avail), int64(len(avail)) < length, nil
}

// CheckRemoteWriteTargetLocked 校验远端原子写入目标的父目录、NoClobber、目录冲突与期望锚点。
func (t *Tree) CheckRemoteWriteTargetLocked(rawKey string, spec ports.RemoteWriteSpec) (string, error) {
	key, err := t.ResolveParentLocked(rawKey, true, false)
	if err != nil {
		return "", err
	}
	if ex := t.Nodes[key]; ex != nil && spec.NoClobber() {
		return "", ports.ErrAlreadyExists
	} else if ex != nil && ex.Kind == ports.RemoteFileDir {
		return "", ports.ErrRemoteIsDir
	}
	if anc, ok := spec.ExpectedAnchor().Get(); ok {
		return key, t.VerifyAnchorLocked(key, anc)
	}
	return key, nil
}

// WriteRemoteChunkLocked 向远端常规文件 offset 处非截断写入分片数据。
func (t *Tree) WriteRemoteChunkLocked(rawKey string, offset int64, chunk []byte) error {
	key, err := t.ResolveParentLocked(rawKey, true, false)
	if err != nil {
		return err
	}
	n := t.Nodes[key]
	if n == nil {
		n = &Node{Kind: ports.RemoteFileRegular, Mode: 0o600, Ino: t.AllocIno()}
		t.Nodes[key] = n
	} else if n.Kind != ports.RemoteFileRegular {
		return ports.ErrNotRegularFile
	}
	n.Data, n.ModTime = GrowBytes(n.Data, offset+int64(len(chunk))), t.Now()
	copy(n.Data[offset:], chunk)
	return nil
}

// RenameRemoteLocked 执行远端 POSIX 原子重命名（支持 RemoteRenameSpec 的互斥 NoClobber/ExpectedAnchor 校验与目录子树迁移）。
func (t *Tree) RenameRemoteLocked(rawOld, rawNew string, spec ports.RemoteRenameSpec) error {
	if !spec.IsValid() {
		return ports.ErrInvalidArgument
	}
	oldKey, e1 := t.ResolveParentLocked(rawOld, true, false)
	newKey, e2 := t.ResolveParentLocked(rawNew, true, false)
	if err := FirstErr(e1, e2); err != nil {
		return err
	}
	if oldKey == "/" || newKey == "/" {
		return ports.ErrPermissionDenied
	}
	src := t.Nodes[oldKey]
	if src == nil {
		return ports.ErrNotFound
	}
	if err := t.validateRemoteRenameLocked(oldKey, newKey, src, spec); err != nil {
		return err
	}
	if oldKey != newKey {
		t.RelocateSubtreeLocked(oldKey, newKey, src)
	}
	return nil
}

func (t *Tree) validateRemoteRenameLocked(oldKey, newKey string, src *Node, spec ports.RemoteRenameSpec) error {
	if src.Kind == ports.RemoteFileDir && strings.HasPrefix(newKey, oldKey+"/") {
		return ports.ErrInvalidArgument
	}
	dst := t.Nodes[newKey]
	if spec.NoClobber() && dst != nil && oldKey != newKey {
		return ports.ErrAlreadyExists
	}
	if anc, ok := spec.ExpectedAnchor().Get(); ok {
		if err := t.VerifyAnchorLocked(newKey, anc); err != nil {
			return err
		}
	}
	switch {
	case dst == nil || oldKey == newKey:
		return nil
	case src.Kind != ports.RemoteFileDir && dst.Kind == ports.RemoteFileDir:
		return ports.ErrRemoteIsDir
	case src.Kind == ports.RemoteFileDir && (dst.Kind != ports.RemoteFileDir || t.HasChildrenLocked(newKey)):
		return ports.ErrInvalidArgument
	default:
		return nil
	}
}

// ChmodRemoteLocked 保留文件类型位并更新远端对象标准权限位与修改时间。
func (t *Tree) ChmodRemoteLocked(key string, perm fs.FileMode) error {
	_, node, err := t.WalkPathLocked(key, true, true, false)
	if err != nil {
		return err
	}
	node.Mode = (node.Mode &^ fs.ModePerm) | perm
	node.ModTime = t.Now()
	return nil
}

// ChtimesRemoteLocked 校验合法 RFC 3339 时间戳并更新远端对象修改时间（支撑 scp -p）。
func (t *Tree) ChtimesRemoteLocked(key string, atime, mtime time.Time) error {
	if !isValidRFC3339Time(atime) || !isValidRFC3339Time(mtime) {
		return ports.ErrInvalidArgument
	}
	_, node, err := t.WalkPathLocked(key, true, true, false)
	if err != nil {
		return err
	}
	node.ModTime = mtime.UTC().Round(0)
	return nil
}

// RemoveRemoteFileLocked 仅删除远端常规文件或符号链接；若目标为目录则返回 ports.ErrRemoteIsDir。
func (t *Tree) RemoveRemoteFileLocked(abs string) error {
	if abs == "/" {
		return ports.ErrRemoteIsDir
	}
	key, err := t.ResolveParentLocked(abs, true, false)
	if err != nil {
		return err
	}
	node := t.Nodes[key]
	if node == nil {
		return ports.ErrNotFound
	}
	if node.Kind == ports.RemoteFileDir {
		return ports.ErrRemoteIsDir
	}
	delete(t.Nodes, key)
	return nil
}

// RemoveRemoteDirLocked 仅删除远端空目录（SFTP SSH_FXP_RMDIR）；非目录或非空目录返回 ports.ErrInvalidArgument。
func (t *Tree) RemoveRemoteDirLocked(abs string) error {
	if abs == "/" {
		return ports.ErrPermissionDenied
	}
	key, err := t.ResolveParentLocked(abs, true, false)
	if err != nil {
		return err
	}
	node := t.Nodes[key]
	if node == nil {
		return ports.ErrNotFound
	}
	if node.Kind != ports.RemoteFileDir || t.HasChildrenLocked(key) {
		return ports.ErrInvalidArgument
	}
	delete(t.Nodes, key)
	return nil
}
