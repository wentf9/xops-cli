//go:build !linux && !darwin

package ssh

import (
	"fmt"
	"runtime"
)

func openPlatformTunnelDevice(mode TunnelMode, localUnit int) (TunnelDevice, error) {
	return nil, fmt.Errorf("%w: local tunnel device (%s) is not supported on %s", ErrTunnelDeviceUnsupported, mode, runtime.GOOS)
}
