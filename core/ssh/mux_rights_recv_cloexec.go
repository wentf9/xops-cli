//go:build linux || freebsd

package ssh

import (
	"errors"
	"io"
	"syscall"

	"golang.org/x/sys/unix"
)

func recvOneControlMsgCloexec(rawConn syscall.RawConn, data, oob []byte) ([]int, int, error, error) {
	var (
		n       int
		oobn    int
		flags   int
		recvErr error
	)
	readErr := rawConn.Read(func(fd uintptr) bool {
		for {
			n, oobn, flags, _, recvErr = unix.Recvmsg(int(fd), data, oob, unix.MSG_CMSG_CLOEXEC)
			if recvErr == nil {
				if n == 0 && oobn == 0 {
					recvErr = io.EOF
				}
				return true
			}
			if errors.Is(recvErr, syscall.EINTR) {
				continue
			}
			if errors.Is(recvErr, syscall.EAGAIN) || errors.Is(recvErr, syscall.EWOULDBLOCK) {
				return false
			}
			return true
		}
	})
	if readErr != nil {
		return nil, 0, nil, readErr
	}
	if recvErr != nil {
		return nil, 0, nil, recvErr
	}
	received, parseCtrlErr := extractReceivedFDsMarkCloexec(oob[:oobn])
	return received, flags, parseCtrlErr, nil
}
