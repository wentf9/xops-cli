//go:build !linux && !darwin

package tun

import (
	"context"
	"io"

	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/i18n"
)

func openLocalTUNOS(_ context.Context, _ ports.TUNSpec) (io.ReadWriteCloser, string, error) {
	return nil, "", i18n.EF(ports.ErrUnsupported, i18n.KeyHostTUNPlatformUnsupported)
}
