package ports

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
)

// RemoteFileType 标识远端 SFTP 文件系统对象类型；零值 RemoteFileTypeInvalid 严格失败关闭。
//
//xops:opaque
//xops:failclosed
type RemoteFileType uint8

const (
	RemoteFileTypeInvalid RemoteFileType = iota // 无效类型（零值失败关闭）
	RemoteFileRegular                           // 常规文件
	RemoteFileDir                               // 目录
	RemoteFileSymlink                           // 符号链接
	RemoteFileOther                             // 非常规特殊对象（下载路径一律拒绝）
)

// RemoteFileAnchor 表示 SFTP 写路径纵深防御所需的 SSH_FXP_FSTAT 类型与可选 (dev, ino) 锚点（ADR-016）。
//
//xops:opaque
//xops:failclosed
type RemoteFileAnchor struct {
	fileType  RemoteFileType
	hasDevIno bool
	dev, ino  uint64
	valid     bool
}

// NewRemoteFileAnchor 校验文件类型与可选 (dev, ino) 并构造不可变 RemoteFileAnchor。
func NewRemoteFileAnchor(fileType RemoteFileType, hasDevIno bool, dev, ino uint64) (RemoteFileAnchor, error) {
	if !fileType.IsValid() || (!hasDevIno && (dev != 0 || ino != 0)) {
		return RemoteFileAnchor{}, fmt.Errorf("%w: RemoteFileAnchor 类型无效或 dev/ino 冲突", ErrInvalidArgument)
	}
	return RemoteFileAnchor{fileType: fileType, hasDevIno: hasDevIno, dev: dev, ino: ino, valid: true}, nil
}
func (a RemoteFileAnchor) IsValid() bool { return a.valid && a.fileType.IsValid() }
func (a RemoteFileAnchor) IsZero() bool  { return !a.IsValid() }
func (a RemoteFileAnchor) FileType() RemoteFileType {
	return pickIf(a.IsValid(), a.fileType, RemoteFileTypeInvalid)
}
func (a RemoteFileAnchor) HasDevIno() bool { return a.IsValid() && a.hasDevIno }
func (a RemoteFileAnchor) Dev() uint64     { return pickIf(a.HasDevIno(), a.dev, 0) }
func (a RemoteFileAnchor) Ino() uint64     { return pickIf(a.HasDevIno(), a.ino, 0) }
func (a RemoteFileAnchor) Matches(observed RemoteFileAnchor) bool {
	return a.IsValid() && observed.IsValid() && a.fileType == observed.fileType &&
		(!a.hasDevIno || (observed.hasDevIno && a.dev == observed.dev && a.ino == observed.ino))
}
func (a RemoteFileAnchor) Equal(o RemoteFileAnchor) bool {
	return a.IsValid() && o.IsValid() && a.fileType == o.fileType && a.hasDevIno == o.hasDevIno && a.dev == o.dev && a.ino == o.ino
}

// RemoteFileStatSpec 是构造不可变 RemoteFileStat 的显式入参规格。
type RemoteFileStatSpec struct {
	Path    pathalg.RemotePath
	Size    int64
	Mode    fs.FileMode
	ModTime time.Time
	Anchor  RemoteFileAnchor
}

// RemoteFileStat 表示远端文件或目录的已校验元信息快照（强制 Size >= 0）；零值恒无效。
//
//xops:opaque
//xops:failclosed
type RemoteFileStat struct {
	path    pathalg.RemotePath
	size    int64
	mode    fs.FileMode
	modTime time.Time
	anchor  RemoteFileAnchor
	valid   bool
}

// NewRemoteFileStat 校验远端路径、非负大小、时间戳与锚点并构造不可变 RemoteFileStat。
func NewRemoteFileStat(spec RemoteFileStatSpec) (RemoteFileStat, error) {
	if !spec.Path.IsValid() || !spec.Anchor.IsValid() || spec.Size < 0 {
		return RemoteFileStat{}, fmt.Errorf("%w: RemoteFileStat 路径、锚点无效或大小为负", ErrInvalidArgument)
	}
	modUTC, err := normalizeOptionalModTime(spec.ModTime)
	return RemoteFileStat{path: spec.Path, size: spec.Size, mode: spec.Mode, modTime: modUTC, anchor: spec.Anchor, valid: err == nil}, err
}
func (s RemoteFileStat) IsValid() bool {
	return s.valid && s.path.IsValid() && s.size >= 0 && s.anchor.IsValid()
}
func (s RemoteFileStat) IsZero() bool             { return !s.IsValid() }
func (s RemoteFileStat) Path() pathalg.RemotePath { return s.path }
func (s RemoteFileStat) Size() int64              { return pickIf(s.IsValid(), s.size, 0) }
func (s RemoteFileStat) Mode() fs.FileMode        { return pickIf(s.IsValid(), s.mode, 0) }
func (s RemoteFileStat) Perm() fs.FileMode        { return pickIf(s.IsValid(), s.mode.Perm(), 0) }
func (s RemoteFileStat) ModTime() time.Time       { return s.modTime }
func (s RemoteFileStat) Anchor() RemoteFileAnchor { return s.anchor }
func (s RemoteFileStat) FileType() RemoteFileType { return s.anchor.FileType() }
func (s RemoteFileStat) IsRegular() bool {
	return s.IsValid() && s.anchor.fileType == RemoteFileRegular
}
func (s RemoteFileStat) IsDir() bool { return s.IsValid() && s.anchor.fileType == RemoteFileDir }
func (s RemoteFileStat) IsSymlink() bool {
	return s.IsValid() && s.anchor.fileType == RemoteFileSymlink
}
func (s RemoteFileStat) Equal(o RemoteFileStat) bool {
	return s.IsValid() && o.IsValid() && s.path.Equal(o.path) && s.size == o.size && s.mode == o.mode && s.modTime.Equal(o.modTime) && s.anchor.Equal(o.anchor)
}

// RemoteDirEntrySpec 是构造不可变 RemoteDirEntry 的显式入参规格。
type RemoteDirEntrySpec struct {
	Name     pathalg.RemoteName
	FileType RemoteFileType
	Size     int64
	Mode     fs.FileMode
	ModTime  time.Time
}

// RemoteDirEntry 表示经 pathalg.RemoteName 校验的远端目录项（INV-B1）；零值恒无效。
//
//xops:opaque
//xops:failclosed
type RemoteDirEntry struct {
	name     pathalg.RemoteName
	fileType RemoteFileType
	size     int64
	mode     fs.FileMode
	modTime  time.Time
	valid    bool
}

// NewRemoteDirEntry 校验远端目录项名、文件类型、非负大小与时间戳并构造不可变 RemoteDirEntry。
func NewRemoteDirEntry(spec RemoteDirEntrySpec) (RemoteDirEntry, error) {
	if !spec.Name.IsValid() || !spec.FileType.IsValid() || spec.Size < 0 {
		return RemoteDirEntry{}, fmt.Errorf("%w: RemoteDirEntry 名称、类型无效或大小为负", ErrInvalidArgument)
	}
	modUTC, err := normalizeOptionalModTime(spec.ModTime)
	return RemoteDirEntry{name: spec.Name, fileType: spec.FileType, size: spec.Size, mode: spec.Mode, modTime: modUTC, valid: err == nil}, err
}
func (e RemoteDirEntry) IsValid() bool {
	return e.valid && e.name.IsValid() && e.fileType.IsValid() && e.size >= 0
}
func (e RemoteDirEntry) IsZero() bool             { return !e.IsValid() }
func (e RemoteDirEntry) Name() pathalg.RemoteName { return e.name }
func (e RemoteDirEntry) FileType() RemoteFileType {
	return pickIf(e.IsValid(), e.fileType, RemoteFileTypeInvalid)
}
func (e RemoteDirEntry) Size() int64        { return pickIf(e.IsValid(), e.size, 0) }
func (e RemoteDirEntry) Mode() fs.FileMode  { return pickIf(e.IsValid(), e.mode, 0) }
func (e RemoteDirEntry) Perm() fs.FileMode  { return pickIf(e.IsValid(), e.mode.Perm(), 0) }
func (e RemoteDirEntry) ModTime() time.Time { return e.modTime }
func (e RemoteDirEntry) Equal(o RemoteDirEntry) bool {
	return e.IsValid() && o.IsValid() && e.name.Equal(o.name) && e.fileType == o.fileType && e.size == o.size && e.mode == o.mode && e.modTime.Equal(o.modTime)
}

// RemoteWriteSpecInput 是构造不可变 RemoteWriteSpec 的显式入参规格。
type RemoteWriteSpecInput struct {
	Perm                    fs.FileMode
	ExpectedAnchor          algebraic.Option[RemoteFileAnchor]
	NoClobber, AtomicRename bool
}

// RemoteWriteSpec 描述远端安全写路径策略（ADR-016）：非零标准权限位、可选 FSTAT 锚点、NoClobber 与原子重命名。
//
//xops:opaque
//xops:failclosed
type RemoteWriteSpec struct {
	perm                    fs.FileMode
	expectedAnchor          algebraic.Option[RemoteFileAnchor]
	noClobber, atomicRename bool
	valid                   bool
}

// NewRemoteWriteSpec 校验标准权限位（0o001..0o777）与可选 FSTAT 锚点并构造不可变 RemoteWriteSpec。
func NewRemoteWriteSpec(in RemoteWriteSpecInput) (RemoteWriteSpec, error) {
	if in.Perm == 0 || in.Perm != in.Perm.Perm() {
		return RemoteWriteSpec{}, fmt.Errorf("%w: 远端写权限 %#o 非法", ErrInvalidArgument, in.Perm)
	}
	if anc, ok := in.ExpectedAnchor.Get(); ok && (!anc.IsValid() || in.NoClobber) {
		return RemoteWriteSpec{}, fmt.Errorf("%w: expected_anchor 无效或与 no_clobber 互斥", ErrInvalidArgument)
	}
	return RemoteWriteSpec{perm: in.Perm, expectedAnchor: in.ExpectedAnchor, noClobber: in.NoClobber, atomicRename: in.AtomicRename, valid: true}, nil
}
func (s RemoteWriteSpec) IsValid() bool                                      { return s.valid && s.perm != 0 && s.perm == s.perm.Perm() }
func (s RemoteWriteSpec) IsZero() bool                                       { return !s.IsValid() }
func (s RemoteWriteSpec) Perm() fs.FileMode                                  { return pickIf(s.IsValid(), s.perm, 0) }
func (s RemoteWriteSpec) ExpectedAnchor() algebraic.Option[RemoteFileAnchor] { return s.expectedAnchor }
func (s RemoteWriteSpec) NoClobber() bool                                    { return s.IsValid() && s.noClobber }
func (s RemoteWriteSpec) AtomicRename() bool                                 { return s.IsValid() && s.atomicRename }
func (s RemoteWriteSpec) Equal(o RemoteWriteSpec) bool {
	return s.IsValid() && o.IsValid() && s.perm == o.perm && s.noClobber == o.noClobber && s.atomicRename == o.atomicRename && optEqualFunc(s.expectedAnchor, o.expectedAnchor, RemoteFileAnchor.Equal)
}

// RemoteFSPort 定义协议库无关的远端 SFTP v3 安全文件访问出站端口（ADR-008 / ADR-016，严禁裸客户端逃生口）。
type RemoteFSPort interface {
	RealPath(ctx context.Context, p pathalg.RemotePath) (pathalg.RemotePath, error)
	Stat(ctx context.Context, p pathalg.RemotePath) (RemoteFileStat, error)
	Lstat(ctx context.Context, p pathalg.RemotePath) (RemoteFileStat, error)
	ReadLink(ctx context.Context, p pathalg.RemotePath) (string, error)
	ReadDir(ctx context.Context, dir pathalg.RemotePath) ([]RemoteDirEntry, error)
	// WithReadFile 在 limits 字节上限内打开远端常规文件并在同步闭包内借出只读流与文件大小。
	//
	//xops:syncclosure
	//xops:borrowed
	WithReadFile(ctx context.Context, p pathalg.RemotePath, limits ReadLimits, fn func(r io.Reader, size int64) error) error
	// ReadChunk 从远端常规文件 p 的 offset 处读取至多 length 字节写入 dst；读满返回 (length, nil)，遇 EOF 返回 (实际字节数, io.EOF)。
	ReadChunk(ctx context.Context, p pathalg.RemotePath, offset int64, dst io.Writer, length int64) (int64, error)
	WriteFileAtomic(ctx context.Context, p pathalg.RemotePath, spec RemoteWriteSpec, r io.Reader) (RemoteFileStat, error)
	WriteChunk(ctx context.Context, p pathalg.RemotePath, offset int64, r io.Reader, length int64) error
	RenameAtomic(ctx context.Context, oldPath, newPath pathalg.RemotePath, expectedAnchor algebraic.Option[RemoteFileAnchor]) error
	// Chmod 修改远端对象标准权限位（0o001..0o777，拒绝零值及特殊权限位，支撑 scp -p 与 sftpshell）。
	Chmod(ctx context.Context, p pathalg.RemotePath, perm fs.FileMode) error
	MkdirAll(ctx context.Context, dir pathalg.RemotePath, perm fs.FileMode) error
	Remove(ctx context.Context, p pathalg.RemotePath) error
	Close() error
}
