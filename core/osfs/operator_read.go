package osfs

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
)

// OperatorFS 是面向 CLI/Playbook DirectOperatorProfile 的人工显式本地只读源适配器，
// 仅实现 ports.OperatorReadFS（物理上绝不注入 mcpruntime，零值失败关闭）。
//
//xops:opaque
//xops:failclosed
type OperatorFS struct{ valid bool }

// NewOperatorReadFS 构造可用的操作员只读源文件适配器实例（ports.OperatorReadFS 生产实现）。
func NewOperatorReadFS() *OperatorFS { return &OperatorFS{valid: true} }

// WithOperatorRead 按 policy 管控符号链接行为打开只读常规文件，并在同步闭包内借出读取器与字节长度；
// 回调退出后立即使借出读取器失效并关闭底层文件句柄。
//
//xops:syncclosure
//xops:borrowed
func (o *OperatorFS) WithOperatorRead(ctx context.Context, path pathalg.LocalSourcePath, policy pathalg.SymlinkPolicy, fn func(r io.Reader, size int64) error) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if fn == nil {
		return ports.ErrNilCallback
	}
	if o == nil || !o.valid || !path.IsValid() || !policy.IsValid() {
		return fmt.Errorf("%w: OperatorFS 未初始化或本地只读源路径/软链策略无效", ports.ErrInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	nativePath, err := localSourceToNativePath(path)
	if err != nil {
		return err
	}
	f, size, err := openOperatorReadOS(nativePath, policy)
	if err != nil {
		return err
	}
	var readerActive atomic.Bool
	readerActive.Store(true)
	defer func() { readerActive.Store(false); _ = f.Close() }()
	return fn(&borrowedReader{r: f, active: &readerActive}, size)
}
