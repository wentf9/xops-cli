package ports

import (
	"context"
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
	fileType         RemoteFileType
	dev, ino         uint64
	hasDevIno, valid bool
}

// NewRemoteFileAnchor 校验文件类型与可选 (dev, ino) 并构造不可变 RemoteFileAnchor。
func NewRemoteFileAnchor(fileType RemoteFileType, hasDevIno bool, dev, ino uint64) (RemoteFileAnchor, error) {
	if !fileType.IsValid() || (!hasDevIno && (dev != 0 || ino != 0)) {
		return RemoteFileAnchor{}, fieldErr(ErrInvalidArgument, "remote_file_anchor")
	}
	return RemoteFileAnchor{fileType: fileType, hasDevIno: hasDevIno, dev: dev, ino: ino, valid: true}, nil
}
func (a RemoteFileAnchor) IsValid() bool            { return a.valid && a.fileType.IsValid() }
func (a RemoteFileAnchor) IsZero() bool             { return !a.IsValid() }
func (a RemoteFileAnchor) FileType() RemoteFileType { return orZero(a.IsValid(), a.fileType) }
func (a RemoteFileAnchor) HasDevIno() bool          { return a.IsValid() && a.hasDevIno }
func (a RemoteFileAnchor) Dev() uint64              { return orZero(a.HasDevIno(), a.dev) }
func (a RemoteFileAnchor) Ino() uint64              { return orZero(a.HasDevIno(), a.ino) }
func (a RemoteFileAnchor) Matches(o RemoteFileAnchor) bool {
	return a.IsValid() && o.IsValid() && a.fileType == o.fileType && (!a.hasDevIno || (o.hasDevIno && a.dev == o.dev && a.ino == o.ino))
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
	s     RemoteFileStatSpec
	valid bool
}

// NewRemoteFileStat 校验远端路径、非负大小、时间戳与锚点并构造不可变 RemoteFileStat。
func NewRemoteFileStat(spec RemoteFileStatSpec) (RemoteFileStat, error) {
	if !spec.Path.IsValid() || !spec.Anchor.IsValid() || spec.Size < 0 {
		return RemoteFileStat{}, fieldErr(ErrInvalidArgument, "remote_file_stat")
	}
	modUTC, err := normalizeOptionalModTime(spec.ModTime)
	spec.ModTime = modUTC
	return pickIf(err == nil, RemoteFileStat{s: spec, valid: true}, RemoteFileStat{}), err
}
func (s RemoteFileStat) IsValid() bool {
	return s.valid && s.s.Path.IsValid() && s.s.Size >= 0 && s.s.Anchor.IsValid()
}
func (s RemoteFileStat) IsZero() bool             { return !s.IsValid() }
func (s RemoteFileStat) Path() pathalg.RemotePath { return s.s.Path }
func (s RemoteFileStat) Size() int64              { return orZero(s.IsValid(), s.s.Size) }
func (s RemoteFileStat) Mode() fs.FileMode        { return orZero(s.IsValid(), s.s.Mode) }
func (s RemoteFileStat) Perm() fs.FileMode        { return orZero(s.IsValid(), s.s.Mode.Perm()) }
func (s RemoteFileStat) ModTime() time.Time       { return s.s.ModTime }
func (s RemoteFileStat) Anchor() RemoteFileAnchor { return s.s.Anchor }
func (s RemoteFileStat) FileType() RemoteFileType { return s.s.Anchor.FileType() }
func (s RemoteFileStat) IsRegular() bool          { return s.IsValid() && s.FileType() == RemoteFileRegular }
func (s RemoteFileStat) IsDir() bool              { return s.IsValid() && s.FileType() == RemoteFileDir }
func (s RemoteFileStat) IsSymlink() bool          { return s.IsValid() && s.FileType() == RemoteFileSymlink }
func (s RemoteFileStat) Equal(o RemoteFileStat) bool {
	return s.IsValid() && o.IsValid() && s.s.Path.Equal(o.s.Path) && s.s.Size == o.s.Size && s.s.Mode == o.s.Mode && s.s.ModTime.Equal(o.s.ModTime) && s.s.Anchor.Equal(o.s.Anchor)
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
	s     RemoteDirEntrySpec
	valid bool
}

// NewRemoteDirEntry 校验远端目录项名、文件类型、非负大小与时间戳并构造不可变 RemoteDirEntry。
func NewRemoteDirEntry(spec RemoteDirEntrySpec) (RemoteDirEntry, error) {
	if !spec.Name.IsValid() || !spec.FileType.IsValid() || spec.Size < 0 {
		return RemoteDirEntry{}, fieldErr(ErrInvalidArgument, "remote_dir_entry")
	}
	modUTC, err := normalizeOptionalModTime(spec.ModTime)
	spec.ModTime = modUTC
	return pickIf(err == nil, RemoteDirEntry{s: spec, valid: true}, RemoteDirEntry{}), err
}
func (e RemoteDirEntry) IsValid() bool {
	return e.valid && e.s.Name.IsValid() && e.s.FileType.IsValid() && e.s.Size >= 0
}
func (e RemoteDirEntry) IsZero() bool             { return !e.IsValid() }
func (e RemoteDirEntry) Name() pathalg.RemoteName { return e.s.Name }
func (e RemoteDirEntry) FileType() RemoteFileType { return orZero(e.IsValid(), e.s.FileType) }
func (e RemoteDirEntry) Size() int64              { return orZero(e.IsValid(), e.s.Size) }
func (e RemoteDirEntry) Mode() fs.FileMode        { return orZero(e.IsValid(), e.s.Mode) }
func (e RemoteDirEntry) Perm() fs.FileMode        { return orZero(e.IsValid(), e.s.Mode.Perm()) }
func (e RemoteDirEntry) ModTime() time.Time       { return e.s.ModTime }
func (e RemoteDirEntry) Equal(o RemoteDirEntry) bool {
	return e.IsValid() && o.IsValid() && e.s.Name.Equal(o.s.Name) && e.s.FileType == o.s.FileType && e.s.Size == o.s.Size && e.s.Mode == o.s.Mode && e.s.ModTime.Equal(o.s.ModTime)
}

// RemoteWriteSpecInput 是构造不可变 RemoteWriteSpec 的显式入参规格。
type RemoteWriteSpecInput struct {
	Perm           fs.FileMode                        `json:"perm"`
	ExpectedAnchor algebraic.Option[RemoteFileAnchor] `json:"expected_anchor,omitzero"`
	NoClobber      bool                               `json:"no_clobber,omitzero"`
	AtomicRename   bool                               `json:"atomic_rename,omitzero"`
}

// RemoteWriteSpec 描述远端安全写路径策略（ADR-016）：非零标准权限位、可选 FSTAT 锚点、NoClobber 与原子重命名。
//
//xops:opaque
//xops:failclosed
type RemoteWriteSpec struct {
	in    RemoteWriteSpecInput
	valid bool
}

func validRemotePrecond(noClobber bool, anc algebraic.Option[RemoteFileAnchor]) bool {
	a, ok := anc.Get()
	return !ok || (a.IsValid() && !noClobber)
}

// NewRemoteWriteSpec 校验标准权限位（0o001..0o777）与可选 FSTAT 锚点并构造不可变 RemoteWriteSpec。
func NewRemoteWriteSpec(in RemoteWriteSpecInput) (RemoteWriteSpec, error) {
	if in.Perm == 0 || in.Perm != in.Perm.Perm() || !validRemotePrecond(in.NoClobber, in.ExpectedAnchor) {
		return RemoteWriteSpec{}, fieldErr(ErrInvalidArgument, "remote_write_spec")
	}
	return RemoteWriteSpec{in: in, valid: true}, nil
}
func (s RemoteWriteSpec) IsValid() bool {
	return s.valid && s.in.Perm != 0 && s.in.Perm == s.in.Perm.Perm()
}
func (s RemoteWriteSpec) IsZero() bool       { return !s.IsValid() }
func (s RemoteWriteSpec) Perm() fs.FileMode  { return orZero(s.IsValid(), s.in.Perm) }
func (s RemoteWriteSpec) NoClobber() bool    { return s.IsValid() && s.in.NoClobber }
func (s RemoteWriteSpec) AtomicRename() bool { return s.IsValid() && s.in.AtomicRename }
func (s RemoteWriteSpec) ExpectedAnchor() algebraic.Option[RemoteFileAnchor] {
	return s.in.ExpectedAnchor
}
func (s RemoteWriteSpec) Equal(o RemoteWriteSpec) bool {
	return s.IsValid() && o.IsValid() && s.in.Perm == o.in.Perm && s.in.NoClobber == o.in.NoClobber && s.in.AtomicRename == o.in.AtomicRename && optEqualFunc(s.in.ExpectedAnchor, o.in.ExpectedAnchor, RemoteFileAnchor.Equal)
}

// RemoteRenameSpecInput 是构造不可变 RemoteRenameSpec 的显式入参规格。
type RemoteRenameSpecInput struct {
	ExpectedAnchor algebraic.Option[RemoteFileAnchor]
	NoClobber      bool
}

// RemoteRenameSpec 描述远端原子重命名策略（ADR-016）：支持互斥的 NoClobber 或 ExpectedAnchor 校验；零值恒无效。
//
//xops:opaque
//xops:failclosed
type RemoteRenameSpec struct {
	in    RemoteRenameSpecInput
	valid bool
}

// NewRemoteRenameSpec 校验互斥的 NoClobber 与可选 FSTAT ExpectedAnchor 并构造不可变 RemoteRenameSpec。
func NewRemoteRenameSpec(in RemoteRenameSpecInput) (RemoteRenameSpec, error) {
	if !validRemotePrecond(in.NoClobber, in.ExpectedAnchor) {
		return RemoteRenameSpec{}, fieldErr(ErrInvalidArgument, "remote_rename_spec")
	}
	return RemoteRenameSpec{in: in, valid: true}, nil
}
func (s RemoteRenameSpec) IsValid() bool {
	return s.valid && validRemotePrecond(s.in.NoClobber, s.in.ExpectedAnchor)
}
func (s RemoteRenameSpec) IsZero() bool    { return !s.IsValid() }
func (s RemoteRenameSpec) NoClobber() bool { return s.IsValid() && s.in.NoClobber }
func (s RemoteRenameSpec) ExpectedAnchor() algebraic.Option[RemoteFileAnchor] {
	return s.in.ExpectedAnchor
}
func (s RemoteRenameSpec) Equal(o RemoteRenameSpec) bool {
	return s.IsValid() && o.IsValid() && s.in.NoClobber == o.in.NoClobber && optEqualFunc(s.in.ExpectedAnchor, o.in.ExpectedAnchor, RemoteFileAnchor.Equal)
}

// RemoteFSPort 定义协议库无关的远端 SFTP v3 安全文件访问出站端口（ADR-008 / ADR-016，严禁裸客户端逃生口）。
type RemoteFSPort interface {
	RealPath(ctx context.Context, p pathalg.RemotePath) (pathalg.RemotePath, error)
	Stat(ctx context.Context, p pathalg.RemotePath) (RemoteFileStat, error)
	Lstat(ctx context.Context, p pathalg.RemotePath) (RemoteFileStat, error)
	ReadLink(ctx context.Context, p pathalg.RemotePath) (string, error)
	ReadDir(ctx context.Context, dir pathalg.RemotePath) ([]RemoteDirEntry, error)
	// WithReadFile 在 limits 字节上限内打开远端常规文件并在同步闭包内借出只读流与文件大小。
	//xops:syncclosure
	//xops:borrowed
	WithReadFile(ctx context.Context, p pathalg.RemotePath, limits ReadLimits, fn func(r io.Reader, size int64) error) error
	// ReadChunk 从远端常规文件 p 的 offset 处读取至多 length 字节写入 dst；读满返回 (length, nil)，遇 EOF 返回 (实际字节数, io.EOF)。
	ReadChunk(ctx context.Context, p pathalg.RemotePath, offset int64, dst io.Writer, length int64) (int64, error)
	WriteFileAtomic(ctx context.Context, p pathalg.RemotePath, spec RemoteWriteSpec, r io.Reader) (RemoteFileStat, error)
	WriteChunk(ctx context.Context, p pathalg.RemotePath, offset int64, r io.Reader, length int64) error
	// RenameAtomic 按已校验 RemoteRenameSpec（支持互斥 NoClobber / ExpectedAnchor）执行远端原子重命名。
	RenameAtomic(ctx context.Context, oldPath, newPath pathalg.RemotePath, spec RemoteRenameSpec) error
	// Chmod 修改远端对象标准权限位（0o001..0o777，拒绝零值及特殊权限位，支撑 scp -p 与 sftpshell）。
	Chmod(ctx context.Context, p pathalg.RemotePath, perm fs.FileMode) error
	// Chtimes 修改远端对象访问与修改时间（拒绝零值及超出 RFC 3339 年份 [1,9999] 的时间戳，支撑 scp -p 时间戳保留）。
	Chtimes(ctx context.Context, p pathalg.RemotePath, atime, mtime time.Time) error
	MkdirAll(ctx context.Context, dir pathalg.RemotePath, perm fs.FileMode) error
	// Remove 仅删除常规文件或符号链接（SFTP SSH_FXP_REMOVE）；若目标为目录须返回 ErrRemoteIsDir。
	Remove(ctx context.Context, p pathalg.RemotePath) error
	// RemoveDir 仅删除空目录（SFTP SSH_FXP_RMDIR）；非目录或非空目录须返回 ErrInvalidArgument，不存在返回 ErrNotFound。
	RemoveDir(ctx context.Context, dir pathalg.RemotePath) error
	Close() error
}
