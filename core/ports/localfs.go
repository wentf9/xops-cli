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

// LockMode 定义句柄级本地文件锁的加锁模式（INV-A5）；零值 LockModeInvalid 严格失败关闭。
//
//xops:opaque
//xops:failclosed
type LockMode uint8

const (
	LockModeInvalid LockMode = iota // 无效锁模式（零值失败关闭）
	LockShared                      // 共享读锁
	LockExclusive                   // 独占写锁
)

// ReadLimits 定义有界文件读取的字节上限值对象（INV-A5）；零值严格失败关闭。
//
//xops:opaque
//xops:failclosed
type ReadLimits struct {
	maxBytes int64
	valid    bool
}

// NewReadLimits 校验上限严格为正整数后构造不可变 ReadLimits。
func NewReadLimits(maxBytes int64) (ReadLimits, error) {
	if maxBytes <= 0 {
		return ReadLimits{}, fmt.Errorf("%w: max_bytes=%d 必须大于 0", ErrInvalidReadLimits, maxBytes)
	}
	return ReadLimits{maxBytes: maxBytes, valid: true}, nil
}
func (l ReadLimits) IsValid() bool   { return l.valid && l.maxBytes > 0 }
func (l ReadLimits) IsZero() bool    { return !l.IsValid() }
func (l ReadLimits) MaxBytes() int64 { return pickIf(l.IsValid(), l.maxBytes, 0) }
func (l ReadLimits) Equal(o ReadLimits) bool {
	return l.IsValid() && o.IsValid() && l.maxBytes == o.maxBytes
}

// LocalFileInfoSpec 是构造不可变 LocalFileInfo 的显式入参规格。
type LocalFileInfoSpec struct {
	Name    string
	Size    int64
	Mode    fs.FileMode
	ModTime time.Time
}

// LocalFileInfo 表示沙箱内单个本地对象的只读元信息快照；零值恒无效。
//
//xops:opaque
//xops:failclosed
type LocalFileInfo struct {
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
	valid   bool
}

// NewLocalFileInfo 校验名称分量、非负大小与合法时间戳并构造不可变 LocalFileInfo。
func NewLocalFileInfo(spec LocalFileInfoSpec) (LocalFileInfo, error) {
	if err := pathalg.ValidateLocalComponent(spec.Name); err != nil {
		return LocalFileInfo{}, fmt.Errorf("%w: 非法本地文件名 %q: %w", ErrInvalidArgument, spec.Name, err)
	}
	if spec.Size < 0 {
		return LocalFileInfo{}, fmt.Errorf("%w: 文件大小不能为负", ErrInvalidArgument)
	}
	modUTC, err := normalizeOptionalModTime(spec.ModTime)
	return LocalFileInfo{name: spec.Name, size: spec.Size, mode: spec.Mode, modTime: modUTC, valid: err == nil}, err
}

func normalizeOptionalModTime(t time.Time) (time.Time, error) {
	if t.IsZero() {
		return time.Time{}, nil
	}
	if !isValidRFC3339Time(t) {
		return time.Time{}, fmt.Errorf("%w: 修改时间超出 RFC 3339 合法年份范围", ErrInvalidArgument)
	}
	return t.UTC().Round(0), nil
}
func (i LocalFileInfo) IsValid() bool      { return i.valid && i.name != "" && i.size >= 0 }
func (i LocalFileInfo) IsZero() bool       { return !i.IsValid() }
func (i LocalFileInfo) Name() string       { return i.name }
func (i LocalFileInfo) Size() int64        { return pickIf(i.IsValid(), i.size, 0) }
func (i LocalFileInfo) Mode() fs.FileMode  { return pickIf(i.IsValid(), i.mode, 0) }
func (i LocalFileInfo) Perm() fs.FileMode  { return pickIf(i.IsValid(), i.mode.Perm(), 0) }
func (i LocalFileInfo) ModTime() time.Time { return i.modTime }
func (i LocalFileInfo) IsRegular() bool    { return i.IsValid() && i.mode.IsRegular() }
func (i LocalFileInfo) IsDir() bool        { return i.IsValid() && i.mode.IsDir() }
func (i LocalFileInfo) IsSymlink() bool    { return i.IsValid() && i.mode&fs.ModeSymlink != 0 }
func (i LocalFileInfo) Equal(o LocalFileInfo) bool {
	return i.IsValid() && o.IsValid() && i.name == o.name && i.size == o.size && i.mode == o.mode && i.modTime.Equal(o.modTime)
}

// LocalDirEntry 表示沙箱目录枚举返回的单个已校验目录项；零值恒无效。
//
//xops:opaque
//xops:failclosed
type LocalDirEntry struct {
	name  string
	mode  fs.FileMode
	size  int64
	valid bool
}

// NewLocalDirEntry 校验目录项名称分量与非负大小并构造不可变 LocalDirEntry。
func NewLocalDirEntry(name string, mode fs.FileMode, size int64) (LocalDirEntry, error) {
	if err := pathalg.ValidateLocalComponent(name); err != nil {
		return LocalDirEntry{}, fmt.Errorf("%w: 非法本地目录项名 %q: %w", ErrInvalidArgument, name, err)
	}
	if size < 0 {
		return LocalDirEntry{}, fmt.Errorf("%w: 目录项大小不能为负", ErrInvalidArgument)
	}
	return LocalDirEntry{name: name, mode: mode, size: size, valid: true}, nil
}
func (e LocalDirEntry) IsValid() bool     { return e.valid && e.name != "" && e.size >= 0 }
func (e LocalDirEntry) IsZero() bool      { return !e.IsValid() }
func (e LocalDirEntry) Name() string      { return e.name }
func (e LocalDirEntry) Mode() fs.FileMode { return pickIf(e.IsValid(), e.mode, 0) }
func (e LocalDirEntry) Size() int64       { return pickIf(e.IsValid(), e.size, 0) }
func (e LocalDirEntry) IsRegular() bool   { return e.IsValid() && e.mode.IsRegular() }
func (e LocalDirEntry) IsDir() bool       { return e.IsValid() && e.mode.IsDir() }
func (e LocalDirEntry) IsSymlink() bool   { return e.IsValid() && e.mode&fs.ModeSymlink != 0 }
func (e LocalDirEntry) Equal(o LocalDirEntry) bool {
	return e.IsValid() && o.IsValid() && e.name == o.name && e.mode == o.mode && e.size == o.size
}

// BoundedReadHandle 是本地沙箱或操作员只读源在同步闭包内借出的有界随机读取句柄（顺序 io.Reader + 并发安全 io.ReaderAt）；
// 回调退出后一切读写必须返回 ErrHandleExpired，且严禁突破绑定的 ReadLimits 上限。
type BoundedReadHandle interface {
	io.Reader
	io.ReaderAt
}

// LockedFile 是 RootHandle.WithLockedFile / TryWithLockedFile 在同步回调内借出的持锁文件句柄。
type LockedFile interface {
	io.Reader
	io.Writer
	io.Seeker
	// Truncate 截断持锁文件至指定字节长度；重要契约：Truncate(0) 不重置内核文件偏移（O_RDWR 非 O_APPEND），
	// 截断后继续写入前必须紧跟 Seek(0, io.SeekStart)，避免在旧偏移处写入稀疏 NUL 空洞破坏锁日志。
	Truncate(size int64) error
	Sync() error
	Stat() (LocalFileInfo, error)
}

// RootHandle 是 ScopedRootFS.WithRoot 在同步回调内借出的沙箱目录根句柄（ADR-007 / INV-A1..A5）。
// 全部路径须为已校验 LocalRootedDest；写锁一律加在同根旁路锁 <name>.lock，绝不对数据文件本身加锁后再 Rename。
type RootHandle interface {
	ReadAllBounded(dest pathalg.LocalRootedDest, limits ReadLimits) ([]byte, error)
	// WithReadRegular 以有界随机只读句柄在同步闭包内借出常规文件，退出后自动失效关闭。
	//
	//xops:syncclosure
	//xops:borrowed
	WithReadRegular(dest pathalg.LocalRootedDest, limits ReadLimits, fn func(r BoundedReadHandle, size int64) error) error
	// CreateExclusive 以 O_CREAT|O_EXCL|O_NOFOLLOW 独占创建常规文件并写入内容。
	//
	//xops:syncclosure
	//xops:borrowed
	CreateExclusive(dest pathalg.LocalRootedDest, perm fs.FileMode, fn func(w io.Writer) error) error
	// AtomicReplace 写同目录随机临时文件、刷盘后原子替换目标文件。
	//
	//xops:syncclosure
	//xops:borrowed
	AtomicReplace(dest pathalg.LocalRootedDest, perm fs.FileMode, fn func(w io.Writer) error) error
	// WriteChunk 向暂存文件 dest 的 offset 处非截断写入来自 r 的精确 length 字节并刷盘；流提前结束返回 (已写字节数, io.ErrUnexpectedEOF)。
	WriteChunk(dest pathalg.LocalRootedDest, offset int64, r io.Reader, length int64, perm fs.FileMode) (int64, error)
	// Rename 在沙箱根内原子重命名 oldDest -> newDest（非软链校验 + os.Root.Rename + 父目录同步）。
	Rename(oldDest, newDest pathalg.LocalRootedDest) error
	// WithLockedFile 在 ctx 取消控制下获取文件锁并校验 SameFile 后借出 LockedFile。
	//
	//xops:syncclosure
	//xops:borrowed
	WithLockedFile(ctx context.Context, dest pathalg.LocalRootedDest, mode LockMode, create bool, perm fs.FileMode, fn func(f LockedFile) error) error
	// TryWithLockedFile 非阻塞尝试抢锁：锁忙立即返回 (false, nil)，成功则同步执行 fn。
	//
	//xops:syncclosure
	//xops:borrowed
	TryWithLockedFile(dest pathalg.LocalRootedDest, mode LockMode, create bool, perm fs.FileMode, fn func(f LockedFile) error) (acquired bool, err error)
	AppendLine(dest pathalg.LocalRootedDest, perm fs.FileMode, line []byte) error
	Stat(dest pathalg.LocalRootedDest) (LocalFileInfo, error)
	Lstat(dest pathalg.LocalRootedDest) (LocalFileInfo, error)
	ReadDir(dir algebraic.Option[pathalg.LocalRootedDest]) ([]LocalDirEntry, error)
	MkdirAll(dir pathalg.LocalRootedDest, perm fs.FileMode) error
	CreateSymlink(link pathalg.LocalRootedDest, target string) error
	Remove(dest pathalg.LocalRootedDest) error
}

// ScopedRootFS 定义基于 Go *os.Root 的沙箱本地文件系统出站端口（ADR-007）。
type ScopedRootFS interface {
	// EnsureRoot 跨平台安全确保根目录 dir 存在且末段非软链（Unix 按 perm/0700，Windows 0700 附 Owner-Only DACL）。
	EnsureRoot(dir pathalg.LocalDir, perm fs.FileMode) error
	// WithRoot 打开绑定至 dir 的沙箱根句柄并在同步闭包内借出；退出前无条件关闭。
	//
	//xops:syncclosure
	//xops:borrowed
	WithRoot(dir pathalg.LocalDir, fn func(root RootHandle) error) error
}

// OperatorReadFS 定义面向 CLI/Playbook 的人工显式只读源端口（ADR-007）；xopsvet/archbound 物理封禁 mcpruntime 引用。
type OperatorReadFS interface {
	// WithOperatorRead 按 policy 管控软链打开只读源文件并在同步闭包内借出随机只读句柄与大小。
	//
	//xops:syncclosure
	//xops:borrowed
	WithOperatorRead(ctx context.Context, path pathalg.LocalSourcePath, policy pathalg.SymlinkPolicy, fn func(r BoundedReadHandle, size int64) error) error
}
