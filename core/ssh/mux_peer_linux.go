//go:build linux

package ssh

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func getPeerUID(fd int) (uint32, error) {
	ucred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, fmt.Errorf("getsockopt SO_PEERCRED failed: %w", err)
	}
	return ucred.Uid, nil
}
