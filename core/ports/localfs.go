package ports

import (
	"context"
	"io"
	"io/fs"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
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
		return ReadLimits{}, domi18n.EF(ErrInvalidReadLimits, domi18n.KeyCommonFieldPositive, domi18n.Str("field", "max_bytes"))
	}
	return ReadLimits{maxBytes: maxBytes, valid: true}, nil
}
func (l ReadLimits) IsValid() bool   { return l.valid && l.maxBytes > 0 }
func (l ReadLimits) IsZero() bool    { return !l.IsValid() }
func (l ReadLimits) MaxBytes() int64 { return orZero(l.IsValid(), l.maxBytes) }
func (l ReadLimits) Equal(o ReadLimits) bool {
	return l.IsValid() && o.IsValid() && l.maxBytes == o.maxBytes
}

type localMeta struct {
	name  string
	size  int64
	mode  fs.FileMode
	valid bool
}

func (m localMeta) ok() bool            { return m.valid && m.name != "" && m.size >= 0 }
func (m localMeta) eq(o localMeta) bool { return m.ok() && o.ok() && m == o }
func validateLocalNameSize(name string, size int64) error {
	if err := pathalg.ValidateLocalComponent(name); err != nil {
		return domi18n.WrapS(ErrInvalidArgument, err, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "name"), domi18n.BoundStr("value", name))
	}
	return pickIf[error](size < 0, domi18n.EF(ErrInvalidArgument, domi18n.KeyCommonFieldNegative, domi18n.Str("field", "size")), nil)
}
func normalizeOptionalModTime(t time.Time) (time.Time, error) {
	if !t.IsZero() && !isValidRFC3339Time(t) {
		return time.Time{}, domi18n.EF(ErrInvalidArgument, domi18n.KeyPortsModTimeOutOfRange)
	}
	return pickIf(t.IsZero(), time.Time{}, t.UTC().Round(0)), nil
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
	meta    localMeta
	modTime time.Time
}

// NewLocalFileInfo 校验名称分量、非负大小与合法时间戳并构造不可变 LocalFileInfo。
func NewLocalFileInfo(spec LocalFileInfoSpec) (LocalFileInfo, error) {
	modUTC, e2 := normalizeOptionalModTime(spec.ModTime)
	err := firstErr(validateLocalNameSize(spec.Name, spec.Size), e2)
	return pickIf(err == nil, LocalFileInfo{localMeta{spec.Name, spec.Size, spec.Mode, true}, modUTC}, LocalFileInfo{}), err
}
func (i LocalFileInfo) IsValid() bool      { return i.meta.ok() }
func (i LocalFileInfo) IsZero() bool       { return !i.IsValid() }
func (i LocalFileInfo) Name() string       { return i.meta.name }
func (i LocalFileInfo) Size() int64        { return orZero(i.IsValid(), i.meta.size) }
func (i LocalFileInfo) Mode() fs.FileMode  { return orZero(i.IsValid(), i.meta.mode) }
func (i LocalFileInfo) Perm() fs.FileMode  { return orZero(i.IsValid(), i.meta.mode.Perm()) }
func (i LocalFileInfo) ModTime() time.Time { return i.modTime }
func (i LocalFileInfo) IsRegular() bool    { return i.IsValid() && i.meta.mode.IsRegular() }
func (i LocalFileInfo) IsDir() bool        { return i.IsValid() && i.meta.mode.IsDir() }
func (i LocalFileInfo) IsSymlink() bool    { return i.IsValid() && i.meta.mode&fs.ModeSymlink != 0 }
func (i LocalFileInfo) Equal(o LocalFileInfo) bool {
	return i.meta.eq(o.meta) && i.modTime.Equal(o.modTime)
}

// LocalDirEntry 表示沙箱目录枚举返回的单个已校验目录项；零值恒无效。
//
//xops:opaque
//xops:failclosed
type LocalDirEntry struct{ meta localMeta }

// NewLocalDirEntry 校验目录项名称分量与非负大小并构造不可变 LocalDirEntry。
func NewLocalDirEntry(name string, mode fs.FileMode, size int64) (LocalDirEntry, error) {
	err := validateLocalNameSize(name, size)
	return LocalDirEntry{meta: localMeta{name, size, mode, err == nil}}, err
}
func (e LocalDirEntry) IsValid() bool              { return e.meta.ok() }
func (e LocalDirEntry) IsZero() bool               { return !e.IsValid() }
func (e LocalDirEntry) Name() string               { return e.meta.name }
func (e LocalDirEntry) Mode() fs.FileMode          { return orZero(e.IsValid(), e.meta.mode) }
func (e LocalDirEntry) Size() int64                { return orZero(e.IsValid(), e.meta.size) }
func (e LocalDirEntry) IsRegular() bool            { return e.IsValid() && e.meta.mode.IsRegular() }
func (e LocalDirEntry) IsDir() bool                { return e.IsValid() && e.meta.mode.IsDir() }
func (e LocalDirEntry) IsSymlink() bool            { return e.IsValid() && e.meta.mode&fs.ModeSymlink != 0 }
func (e LocalDirEntry) Equal(o LocalDirEntry) bool { return e.meta.eq(o.meta) }

// BoundedReadHandle 是同步闭包内借出的有界随机只读句柄（顺序 Reader + 并发安全 ReaderAt），退出后返回 ErrHandleExpired。
type BoundedReadHandle interface {
	io.Reader
	io.ReaderAt
}

// LockedFile 是 RootHandle.WithLockedFile / TryWithLockedFile 在同步回调内借出的持锁文件句柄。
type LockedFile interface {
	io.Reader
	io.Writer
	io.Seeker
	// Truncate 截断持锁文件至指定长度；注意 Truncate(0) 不重置内核偏移，后续写入前须 Seek(0, io.SeekStart)。
	Truncate(size int64) error
	Sync() error
	Stat() (LocalFileInfo, error)
}

// RootHandle 是 ScopedRootFS.WithRoot 在同步回调内借出的沙箱目录根句柄（ADR-007 / INV-A1..A5）。
// 全部路径须为已校验 LocalRootedDest；写锁一律加在同根旁路锁 <name>.lock，绝不对数据文件本身加锁后再 Rename。
type RootHandle interface {
	ReadAllBounded(dest pathalg.LocalRootedDest, limits ReadLimits) ([]byte, error)
	// WithReadRegular 以有界随机只读句柄在同步闭包内借出常规文件，退出后自动失效关闭。
	//xops:syncclosure
	//xops:borrowed
	WithReadRegular(dest pathalg.LocalRootedDest, limits ReadLimits, fn func(r BoundedReadHandle, size int64) error) error
	// CreateExclusive 以 O_CREAT|O_EXCL|O_NOFOLLOW 独占创建常规文件并写入内容。
	//xops:syncclosure
	//xops:borrowed
	CreateExclusive(dest pathalg.LocalRootedDest, perm fs.FileMode, fn func(w io.Writer) error) error
	// AtomicReplace 写同目录随机临时文件、刷盘后原子替换目标文件。
	//xops:syncclosure
	//xops:borrowed
	AtomicReplace(dest pathalg.LocalRootedDest, perm fs.FileMode, fn func(w io.Writer) error) error
	// WriteChunk 向暂存文件 dest 的 offset 处非截断写入来自 r 的精确 length 字节并刷盘；流提前结束返回 (已写字节数, io.ErrUnexpectedEOF)。
	WriteChunk(dest pathalg.LocalRootedDest, offset int64, r io.Reader, length int64, perm fs.FileMode) (int64, error)
	// Rename 在沙箱根内原子重命名 oldDest -> newDest（非软链校验 + os.Root.Rename + 父目录同步）。
	Rename(oldDest, newDest pathalg.LocalRootedDest) error
	// WithLockedFile 在 ctx 取消控制下获取文件锁并校验 SameFile 后借出 LockedFile。
	//xops:syncclosure
	//xops:borrowed
	WithLockedFile(ctx context.Context, dest pathalg.LocalRootedDest, mode LockMode, create bool, perm fs.FileMode, fn func(f LockedFile) error) error
	// TryWithLockedFile 非阻塞尝试抢锁：锁忙立即返回 (false, nil)，成功则同步执行 fn。
	//xops:syncclosure
	//xops:borrowed
	TryWithLockedFile(dest pathalg.LocalRootedDest, mode LockMode, create bool, perm fs.FileMode, fn func(f LockedFile) error) (acquired bool, err error)
	AppendLine(dest pathalg.LocalRootedDest, perm fs.FileMode, line []byte) error
	Stat(dest pathalg.LocalRootedDest) (LocalFileInfo, error)
	Lstat(dest pathalg.LocalRootedDest) (LocalFileInfo, error)
	ReadDir(dir algebraic.Option[pathalg.LocalRootedDest]) ([]LocalDirEntry, error)
	MkdirAll(dir pathalg.LocalRootedDest, perm fs.FileMode) error
	CreateSymlink(link pathalg.LocalRootedDest, target string) error
	// Chtimes 修改沙箱内常规文件或目录的访问与修改时间（拒绝符号链接、零值及超出 RFC 3339 年份 [1,9999] 的时间戳，支撑 scp -p）。
	Chtimes(dest pathalg.LocalRootedDest, atime, mtime time.Time) error
	Remove(dest pathalg.LocalRootedDest) error
}

// ScopedRootFS 定义基于 Go *os.Root 的沙箱本地文件系统出站端口（ADR-007）。
type ScopedRootFS interface {
	// EnsureRoot 跨平台安全确保根目录 dir 存在且末段非软链（Unix 按 perm/0700，Windows 0700 附 Owner-Only DACL）。
	EnsureRoot(dir pathalg.LocalDir, perm fs.FileMode) error
	// WithRoot 打开绑定至 dir 的沙箱根句柄并在同步闭包内借出；退出前无条件关闭。
	//xops:syncclosure
	//xops:borrowed
	WithRoot(dir pathalg.LocalDir, fn func(root RootHandle) error) error
}

// OperatorReadFS 定义面向 CLI/Playbook 的人工显式只读源端口（ADR-007）；xopsvet/archbound 物理封禁 mcpruntime 引用。
type OperatorReadFS interface {
	// WithOperatorRead 按 policy 管控软链打开只读源文件并在同步闭包内借出随机只读句柄与大小。
	//xops:syncclosure
	//xops:borrowed
	WithOperatorRead(ctx context.Context, path pathalg.LocalSourcePath, policy pathalg.SymlinkPolicy, fn func(r BoundedReadHandle, size int64) error) error
}
