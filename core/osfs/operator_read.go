package osfs

import (
	"context"
	"errors"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
	"io"
	"io/fs"
	"sync/atomic"
)

// EnsureDir 跨平台安全确保本地根目录 dir 存在且末段非符号链接：
// Unix 逐段使用 Mkdirat + O_DIRECTORY|O_NOFOLLOW 建目录（默认 0700）；Windows 当 perm&0o077==0 时附带 Owner-Only DACL。
func EnsureDir(dir pathalg.LocalDir, perm fs.FileMode) error {
	if !dir.IsValid() || perm == 0 || perm != perm.Perm() {
		return errField(ports.ErrInvalidArgument, "dir/perm")
	}
	nativeDir, err := localPathToNativeOS(dir.Kind(), dir.String())
	if err != nil {
		return err
	}
	return ensureDirOS(nativeDir, perm)
}

// EnsureOwnerOnlyDir 跨平台确保目录 dir 存在且仅所有者可访问（Unix 0700 + 非软链；Windows Owner-Only DACL）。
func EnsureOwnerOnlyDir(dir pathalg.LocalDir) error { return EnsureDir(dir, defaultDirPerm) }

// OperatorFS 是面向 CLI/Playbook DirectOperatorProfile 的人工显式本地只读源适配器，
// 仅实现 ports.OperatorReadFS（物理上绝不注入 mcpruntime，零值失败关闭）。
//
//xops:opaque
//xops:failclosed
type OperatorFS struct{ valid bool }

// NewOperatorReadFS 构造可用的操作员只读源文件适配器实例（ports.OperatorReadFS 生产实现）。
func NewOperatorReadFS() *OperatorFS { return &OperatorFS{valid: true} }

// WithOperatorRead 按 policy 管控符号链接行为打开只读常规文件，并在同步闭包内借出随机只读句柄与字节长度；
// 回调退出后立即使借出句柄失效并关闭底层文件句柄。
//
//xops:syncclosure
//xops:borrowed
func (o *OperatorFS) WithOperatorRead(ctx context.Context, path pathalg.LocalSourcePath, policy pathalg.SymlinkPolicy, fn func(r ports.BoundedReadHandle, size int64) error) error {
	if err := checkOperatorReadArgs(ctx, o, path, policy, fn == nil); err != nil {
		return err
	}
	nativePath, err := localPathToNativeOS(path.Kind(), path.String())
	if err != nil {
		return err
	}
	f, size, err := openOperatorReadOS(nativePath, policy)
	if err != nil {
		return err
	}
	var active atomic.Bool
	active.Store(true)
	defer func() { active.Store(false); _ = f.Close() }()
	return fn(&borrowedReader{r: f, active: &active}, size)
}
func checkOperatorReadArgs(ctx context.Context, o *OperatorFS, path pathalg.LocalSourcePath, policy pathalg.SymlinkPolicy, fnNil bool) error {
	switch {
	case ctx == nil:
		return ports.ErrNilContext
	case fnNil:
		return ports.ErrNilCallback
	case o == nil || !o.valid || !path.IsValid() || !policy.IsValid():
		return errField(ports.ErrInvalidArgument, "operator_read")
	default:
		return ctx.Err()
	}
}

// borrowedReader / borrowedWriter 在作用域关闭后拒绝一切读写，并对读取施加溢出安全字节上限。
type borrowedReader struct {
	r                   ports.BoundedReadHandle
	remaining, maxBytes int64
	limited             bool
	active              *atomic.Bool
}

func (b *borrowedReader) isActive() bool {
	return b != nil && b.active != nil && b.active.Load() && b.r != nil
}
func (b *borrowedReader) Read(p []byte) (int, error) {
	if !b.isActive() {
		return 0, ports.ErrHandleExpired
	}
	if !b.limited {
		return b.r.Read(p)
	}
	if b.remaining <= 0 {
		var probe [1]byte
		return 0, mapProbeEOF(b.r.Read(probe[:]))
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.r.Read(p)
	b.remaining -= int64(n)
	return n, err
}

// ReadAt 在不修改顺序读游标的前提下执行并发安全随机偏移读，并强制执行句柄失效哨兵与 ReadLimits 上限。
func (b *borrowedReader) ReadAt(p []byte, off int64) (int, error) {
	if !b.isActive() {
		return 0, ports.ErrHandleExpired
	}
	if off < 0 {
		return 0, domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyCommonFieldNegative, domi18n.Str("field", "offset"))
	}
	if len(p) == 0 || !b.limited {
		return pickIf(len(p) == 0, func() (int, error) { return 0, nil }, func() (int, error) { return b.r.ReadAt(p, off) })()
	}
	if off >= b.maxBytes {
		var probe [1]byte
		return 0, mapProbeEOF(b.r.ReadAt(probe[:], off))
	}
	if avail := b.maxBytes - off; int64(len(p)) > avail {
		n, err := b.r.ReadAt(p[:avail], off)
		if err != nil || int64(n) < avail {
			return n, err
		}
		var probe [1]byte
		return n, mapProbeEOF(b.r.ReadAt(probe[:], b.maxBytes))
	}
	return b.r.ReadAt(p, off)
}
func mapProbeEOF(n int, err error) error {
	if n > 0 {
		return ports.ErrLimitExceeded
	}
	return pickIf[error](err != nil && !errors.Is(err, io.EOF), err, io.EOF)
}

type borrowedWriter struct {
	w      io.Writer
	active *atomic.Bool
}

func (b *borrowedWriter) Write(p []byte) (int, error) {
	if b == nil || b.active == nil || !b.active.Load() {
		return 0, ports.ErrHandleExpired
	}
	return b.w.Write(p)
}
