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
	LockShared                      // 共享读锁（允许并发只读持有者）
	LockExclusive                   // 独占写锁（互斥所有读写持有者）
)

// ReadLimits 定义有界文件读取的字节上限值对象（INV-A5）；零值（MaxBytes == 0）严格失败关闭，
// 绝不隐式放开读取大小限制以防恶意大文件或 FIFO 触发内存耗尽。
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

// ReadLimits 只读访问器与等价比对（无效零值永不相等）。
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

// LocalFileInfo 表示沙箱内单个本地文件、目录或符号链接的只读元信息快照；零值恒无效。
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
		return LocalFileInfo{}, fmt.Errorf("%w: 文件大小 %d 不能为负", ErrInvalidArgument, spec.Size)
	}
	modUTC, err := normalizeOptionalModTime(spec.ModTime)
	if err != nil {
		return LocalFileInfo{}, err
	}
	return LocalFileInfo{name: spec.Name, size: spec.Size, mode: spec.Mode, modTime: modUTC, valid: true}, nil
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

// LocalFileInfo 只读访问器与严格等价比对。
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
		return LocalDirEntry{}, fmt.Errorf("%w: 目录项大小 %d 不能为负", ErrInvalidArgument, size)
	}
	return LocalDirEntry{name: name, mode: mode, size: size, valid: true}, nil
}

// LocalDirEntry 只读访问器与严格等价比对。
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

// LockedFile 是 RootHandle.WithLockedFile / TryWithLockedFile 在同步回调内借出的持锁文件句柄。
// 所有读写、截断与落盘均严格绑定该句柄；回调退出后句柄立即解锁关闭，后续误用须返回 ErrHandleExpired。
type LockedFile interface {
	io.Reader
	io.Writer
	io.Seeker
	// Truncate 将当前持锁文件截断至指定字节长度（常用于解锁删除前清空崩溃对账 .lock 文件，Plan §4.5）。
	Truncate(size int64) error
	// Sync 将当前持锁文件数据与元信息刷入稳定存储。
	Sync() error
	// Stat 返回当前持锁文件句柄对应的元信息快照。
	Stat() (LocalFileInfo, error)
}

// RootHandle 是 ScopedRootFS.WithRoot 在同步回调内借出的沙箱目录根句柄（对应 Go *os.Root 能力）。
//
// 安全与跨平台不变量（ADR-007 / INV-A1..A5 / Plan §4.5）：
//   - 全部相对路径必须为经 pathalg.ParseLocalRootedDest 校验的 LocalRootedDest，严禁路径穿越与符号链接逃逸；
//   - 所有写锁一律施加于同根目录下的旁路锁文件 <name>.lock，绝不对数据文件本身加锁后再 Rename；
//   - CreateExclusive 与 AtomicReplace 在 Unix 使用 O_NOFOLLOW + 0600 语义，在 Windows 创建即附带 Owner-Only DACL。
type RootHandle interface {
	// ReadAllBounded 在 limits 上限内以句柄安全方式读取整个常规文件；非常规文件返回 ErrNotRegularFile，超限返回 ErrLimitExceeded。
	ReadAllBounded(dest pathalg.LocalRootedDest, limits ReadLimits) ([]byte, error)
	// WithReadRegular 以有界只读流方式在同步作用域内借出常规文件读取器，回调退出自动关闭句柄。
	//
	//xops:syncclosure
	//xops:borrowed
	WithReadRegular(dest pathalg.LocalRootedDest, limits ReadLimits, fn func(r io.Reader, size int64) error) error
	// CreateExclusive 以 O_CREAT|O_EXCL|O_NOFOLLOW 语义独占创建新常规文件并通过回调写入内容；已存在时返回 ErrAlreadyExists。
	//
	//xops:syncclosure
	//xops:borrowed
	CreateExclusive(dest pathalg.LocalRootedDest, perm fs.FileMode, fn func(w io.Writer) error) error
	// AtomicReplace 在同目录下写入随机临时文件、刷盘后原子替换目标文件（绝不锁目标文件本身后 Rename）。
	//
	//xops:syncclosure
	//xops:borrowed
	AtomicReplace(dest pathalg.LocalRootedDest, perm fs.FileMode, fn func(w io.Writer) error) error
	// WithLockedFile 在 ctx 取消控制下获取文件锁并校验 SameFile 后，于同步回调内借出 LockedFile 句柄。
	//
	//xops:syncclosure
	//xops:borrowed
	WithLockedFile(ctx context.Context, dest pathalg.LocalRootedDest, mode LockMode, create bool, perm fs.FileMode, fn func(f LockedFile) error) error
	// TryWithLockedFile 非阻塞尝试获取文件锁：锁被占用时立即返回 (false, nil)，抢锁成功则同步执行 fn 并在退出时解锁关闭。
	// 本方法支撑 O(1) 崩溃对账对死亡进程 run/*.lock 的跨终端独占抢占与安全清理（Plan §4.4 / §4.5）。
	//
	//xops:syncclosure
	//xops:borrowed
	TryWithLockedFile(dest pathalg.LocalRootedDest, mode LockMode, create bool, perm fs.FileMode, fn func(f LockedFile) error) (acquired bool, err error)
	// AppendLine 以只追加语义原子向常规文件末尾写入 line 并自动附加单个 '\n'（不存在时按 perm 安全创建）；
	// line 严禁包含内嵌 '\r' 或 '\n'（违反时失败关闭返回 ErrInvalidArgument），防止 JSONL/.lock 记录注入。
	AppendLine(dest pathalg.LocalRootedDest, perm fs.FileMode, line []byte) error
	// Stat 返回沙箱内目标路径的元信息快照（不逃逸根目录）。
	Stat(dest pathalg.LocalRootedDest) (LocalFileInfo, error)
	// Lstat 返回沙箱内目标路径自身（不跟随末段软链）的元信息快照。
	Lstat(dest pathalg.LocalRootedDest) (LocalFileInfo, error)
	// ReadDir 列举沙箱内目录内容；当 dir 为 None 时列举沙箱根目录自身（供扫描 run/*.lock 使用）。
	ReadDir(dir algebraic.Option[pathalg.LocalRootedDest]) ([]LocalDirEntry, error)
	// MkdirAll 在沙箱根内逐段安全创建子目录树（绝不穿透符号链接）。
	MkdirAll(dir pathalg.LocalRootedDest, perm fs.FileMode) error
	// CreateSymlink 在沙箱根内创建经策略 (b) 校验的相对 POSIX 符号链接（绝不允许绝对或逃逸目标）。
	CreateSymlink(link pathalg.LocalRootedDest, target string) error
	// Remove 删除沙箱内单个文件或空目录；目标不存在时返回 ErrNotFound。
	Remove(dest pathalg.LocalRootedDest) error
}

// ScopedRootFS 定义基于 Go *os.Root 的沙箱本地文件系统出站端口（ADR-007 / RFC §3.2）。
// 全仓所有写操作、~/.xops 配置/Vault/WAL/审计日志、SCP 下载落盘与全部 MCP/Agent 路径均强制走此端口。
type ScopedRootFS interface {
	// WithRoot 打开绑定至目录 dir 的沙箱根句柄并在同步作用域闭包 fn 内借出；
	// 无论 fn 正常返回、返回错误还是 panic，退出前均无条件关闭底层根目录句柄。
	//
	//xops:syncclosure
	//xops:borrowed
	WithRoot(dir pathalg.LocalDir, fn func(root RootHandle) error) error
}

// OperatorReadFS 定义面向 CLI/Playbook DirectOperatorProfile 的人工显式只读源端口（ADR-007 / RFC §3.2）。
//
// 架构隔离铁律（xopsvet/archbound 符号级强制）：
// 本接口精确驻留于 core/ports/localfs.go，物理上严禁被 core/internal/mcpruntime 引用或注入；
// 仅用于读取操作员显式传入的跨盘符路径（如 C:\Temp\a.tgz）与受 pathalg.SymlinkPolicy 管控的只读源文件（如软链私钥）。
type OperatorReadFS interface {
	// WithOperatorRead 按 policy 管控符号链接行为打开只读源文件，并在同步作用域闭包内借出读取器与字节长度；
	// 回调退出后立即关闭底层文件句柄。
	//
	//xops:syncclosure
	//xops:borrowed
	WithOperatorRead(ctx context.Context, path pathalg.LocalSourcePath, policy pathalg.SymlinkPolicy, fn func(r io.Reader, size int64) error) error
}
