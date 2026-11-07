//go:build darwin

package ssh

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func getPeerUID(fd int) (uint32, error) {
	xucred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, fmt.Errorf("getsockopt LOCAL_PEERCRED failed: %w", err)
	}
	return xucred.Uid, nil
}
