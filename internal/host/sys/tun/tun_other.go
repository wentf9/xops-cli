//go:build !linux && !darwin

package tun

import (
	"context"
	"fmt"
	"io"

	"github.com/wentf9/xops-cli/core/ports"
)

func openLocalTUNOS(_ context.Context, _ ports.TUNSpec) (io.ReadWriteCloser, string, error) {
	return nil, "", fmt.Errorf("%w: 当前平台暂不支持原生本机 TUN/TAP 设备", ports.ErrUnsupported)
}
