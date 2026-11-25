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
	RemoteFileOther                             // 非常规特殊对象（FIFO/设备/套接字等，下载路径一律拒绝）
)

// RemoteFileAnchor 表示 SFTP 写路径纵深防御所需的 SSH_FXP_FSTAT 类型与可选 (dev, ino) 身份锚点（ADR-016）。
// 零值恒无效并拒绝匹配，防止写操作在两阶段规范化与非截断打开之间遭遇目标替换。
//
//xops:opaque
//xops:failclosed
type RemoteFileAnchor struct {
	fileType  RemoteFileType
	hasDevIno bool
	dev       uint64
	ino       uint64
	valid     bool
}

// NewRemoteFileAnchor 校验文件类型与可选设备/inode 标识并构造不可变 RemoteFileAnchor。
func NewRemoteFileAnchor(fileType RemoteFileType, hasDevIno bool, dev, ino uint64) (RemoteFileAnchor, error) {
	if !fileType.IsValid() {
		return RemoteFileAnchor{}, fmt.Errorf("%w: RemoteFileAnchor 需要有效的 RemoteFileType", ErrInvalidArgument)
	}
	if !hasDevIno && (dev != 0 || ino != 0) {
		return RemoteFileAnchor{}, fmt.Errorf("%w: has_dev_ino 为 false 时 dev/ino 必须为 0", ErrInvalidArgument)
	}
	return RemoteFileAnchor{fileType: fileType, hasDevIno: hasDevIno, dev: dev, ino: ino, valid: true}, nil
}

// RemoteFileAnchor 只读访问器、FSTAT 锚点比对与等价判定。
func (a RemoteFileAnchor) IsValid() bool { return a.valid && a.fileType.IsValid() }
func (a RemoteFileAnchor) IsZero() bool  { return !a.IsValid() }
func (a RemoteFileAnchor) FileType() RemoteFileType {
	return pickIf(a.IsValid(), a.fileType, RemoteFileTypeInvalid)
}
func (a RemoteFileAnchor) HasDevIno() bool { return a.IsValid() && a.hasDevIno }
func (a RemoteFileAnchor) Dev() uint64     { return pickIf(a.HasDevIno(), a.dev, 0) }
func (a RemoteFileAnchor) Ino() uint64     { return pickIf(a.HasDevIno(), a.ino, 0) }

// Matches 严格比对当前预期锚点与实测 FSTAT 锚点是否一致（ADR-016）：
// 若任一无效或类型不等则返回 false；若预期侧携带 (dev, ino)，则实测侧也必须携带且两者完全相等。
func (a RemoteFileAnchor) Matches(observed RemoteFileAnchor) bool {
	if !a.IsValid() || !observed.IsValid() || a.fileType != observed.fileType {
		return false
	}
	return !a.hasDevIno || (observed.hasDevIno && a.dev == observed.dev && a.ino == observed.ino)
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

// RemoteFileStat 表示远端文件或目录的已校验元信息快照（强制 Size >= 0，见 INV-B3）；零值恒无效。
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

// NewRemoteFileStat 校验远端路径、非负大小、合法时间戳与锚点并构造不可变 RemoteFileStat。
func NewRemoteFileStat(spec RemoteFileStatSpec) (RemoteFileStat, error) {
	if !spec.Path.IsValid() || !spec.Anchor.IsValid() || spec.Size < 0 {
		return RemoteFileStat{}, fmt.Errorf("%w: RemoteFileStat 路径、锚点无效或大小为负", ErrInvalidArgument)
	}
	modUTC, err := normalizeOptionalModTime(spec.ModTime)
	if err != nil {
		return RemoteFileStat{}, err
	}
	return RemoteFileStat{path: spec.Path, size: spec.Size, mode: spec.Mode, modTime: modUTC, anchor: spec.Anchor, valid: true}, nil
}

// RemoteFileStat 只读访问器与等价比对（Perm 剥离 setuid/setgid/sticky 特殊位）。
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
	return s.IsValid() && o.IsValid() && s.path.Equal(o.path) && s.size == o.size &&
		s.mode == o.mode && s.modTime.Equal(o.modTime) && s.anchor.Equal(o.anchor)
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
	if err != nil {
		return RemoteDirEntry{}, err
	}
	return RemoteDirEntry{name: spec.Name, fileType: spec.FileType, size: spec.Size, mode: spec.Mode, modTime: modUTC, valid: true}, nil
}

// RemoteDirEntry 只读访问器与等价比对。
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
	return e.IsValid() && o.IsValid() && e.name.Equal(o.name) && e.fileType == o.fileType &&
		e.size == o.size && e.mode == o.mode && e.modTime.Equal(o.modTime)
}

// RemoteWriteSpecInput 是构造不可变 RemoteWriteSpec 的显式入参规格。
type RemoteWriteSpecInput struct {
	Perm           fs.FileMode
	ExpectedAnchor algebraic.Option[RemoteFileAnchor]
	NoClobber      bool
	AtomicRename   bool
}

// RemoteWriteSpec 描述远端安全写路径策略（ADR-016）：
// 显式要求非零标准权限位、携带可选 FSTAT 身份锚点、支持 --no-clobber 禁覆写与原子 posix-rename@openssh.com。
//
//xops:opaque
//xops:failclosed
type RemoteWriteSpec struct {
	perm           fs.FileMode
	expectedAnchor algebraic.Option[RemoteFileAnchor]
	noClobber      bool
	atomicRename   bool
	valid          bool
}

// NewRemoteWriteSpec 校验权限位（标准 0o001..0o777）与可选 FSTAT 锚点并构造不可变 RemoteWriteSpec。
func NewRemoteWriteSpec(in RemoteWriteSpecInput) (RemoteWriteSpec, error) {
	if in.Perm == 0 || in.Perm != in.Perm.Perm() {
		return RemoteWriteSpec{}, fmt.Errorf("%w: 远端写权限 %#o 必须为非零标准权限位", ErrInvalidArgument, in.Perm)
	}
	if anc, ok := in.ExpectedAnchor.Get(); ok {
		if !anc.IsValid() || in.NoClobber {
			return RemoteWriteSpec{}, fmt.Errorf("%w: expected_anchor 无效或与 no_clobber 互斥", ErrInvalidArgument)
		}
	}
	return RemoteWriteSpec{
		perm: in.Perm, expectedAnchor: in.ExpectedAnchor, noClobber: in.NoClobber, atomicRename: in.AtomicRename, valid: true,
	}, nil
}

// RemoteWriteSpec 只读访问器与等价比对。
func (s RemoteWriteSpec) IsValid() bool                                      { return s.valid && s.perm != 0 && s.perm == s.perm.Perm() }
func (s RemoteWriteSpec) IsZero() bool                                       { return !s.IsValid() }
func (s RemoteWriteSpec) Perm() fs.FileMode                                  { return pickIf(s.IsValid(), s.perm, 0) }
func (s RemoteWriteSpec) ExpectedAnchor() algebraic.Option[RemoteFileAnchor] { return s.expectedAnchor }
func (s RemoteWriteSpec) NoClobber() bool                                    { return s.IsValid() && s.noClobber }
func (s RemoteWriteSpec) AtomicRename() bool                                 { return s.IsValid() && s.atomicRename }
func (s RemoteWriteSpec) Equal(o RemoteWriteSpec) bool {
	return s.IsValid() && o.IsValid() && s.perm == o.perm && s.noClobber == o.noClobber &&
		s.atomicRename == o.atomicRename && optEqualFunc(s.expectedAnchor, o.expectedAnchor, RemoteFileAnchor.Equal)
}

// RemoteFSPort 定义协议库无关的远端 SFTP v3 安全文件访问出站端口（ADR-008 / ADR-016 / INV-B1..B4）。
// 严禁暴露 Do(*pkgsftp.Client) 等逃生口；全部路径使用 pathalg.RemotePath 且目录列举返回 pathalg.RemoteName。
type RemoteFSPort interface {
	// RealPath 解析远端规范化绝对 POSIX 路径（供两阶段护栏规范化与软链升级判定使用，INV-E5）。
	RealPath(ctx context.Context, p pathalg.RemotePath) (pathalg.RemotePath, error)
	// Stat 跟随符号链接获取远端目标元信息（含 FSTAT 锚点）。
	Stat(ctx context.Context, p pathalg.RemotePath) (RemoteFileStat, error)
	// Lstat 不跟随末段符号链接获取远端路径元信息（供悬空软链与 --no-clobber 检查，INV-B4）。
	Lstat(ctx context.Context, p pathalg.RemotePath) (RemoteFileStat, error)
	// ReadLink 读取远端符号链接的原始目标字符串。
	ReadLink(ctx context.Context, p pathalg.RemotePath) (string, error)
	// ReadDir 列举远端目录并逐项返回经 pathalg.ParseRemoteName 校验的目录项（INV-B1）。
	ReadDir(ctx context.Context, dir pathalg.RemotePath) ([]RemoteDirEntry, error)
	// WithReadFile 在 limits 字节上限内打开远端常规文件，并在同步作用域闭包内借出只读流与文件大小；回调退出即关闭句柄。
	//
	//xops:syncclosure
	//xops:borrowed
	WithReadFile(ctx context.Context, p pathalg.RemotePath, limits ReadLimits, fn func(r io.Reader, size int64) error) error
	// WriteFileAtomic 按 spec 执行远端安全写路径：检查 no-clobber / FSTAT 锚点（不匹配返回 ErrRemoteAnchorMismatch），
	// 并写入目标路径（开启 AtomicRename 时走同目录临时文件与原子 posix-rename@openssh.com）。
	WriteFileAtomic(ctx context.Context, p pathalg.RemotePath, spec RemoteWriteSpec, r io.Reader) (RemoteFileStat, error)
	// WriteChunk 向远端暂存文件的指定偏移 offset 写入长度为 length 的分片（用于 10 GiB 可恢复流式上传）。
	WriteChunk(ctx context.Context, p pathalg.RemotePath, offset int64, r io.Reader, length int64) error
	// RenameAtomic 将远端暂存文件 oldPath 原子重命名为 newPath，携带 expectedAnchor 时在提交前复核目标锚点。
	RenameAtomic(ctx context.Context, oldPath, newPath pathalg.RemotePath, expectedAnchor algebraic.Option[RemoteFileAnchor]) error
	// MkdirAll 逐级确保远端目录树存在。
	MkdirAll(ctx context.Context, dir pathalg.RemotePath, perm fs.FileMode) error
	// Remove 删除远端单个文件或空目录；不存在时返回 ErrNotFound。
	Remove(ctx context.Context, p pathalg.RemotePath) error
	// Close 关闭远端 SFTP 子系统会话（幂等）。
	Close() error
}
