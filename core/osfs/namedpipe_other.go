//go:build !windows

package osfs

import (
	"context"
	"github.com/wentf9/xops-cli/core/ports"
	"net"
)

// DialWindowsNamedPipeVerified 在非 Windows 平台上固定返回 ports.ErrUnsupported。
func DialWindowsNamedPipeVerified(ctx context.Context, _ string) (net.Conn, error) {
	return nil, pickIf[error](ctx == nil, ports.ErrNilContext, ports.ErrUnsupported)
}
