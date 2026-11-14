//go:build darwin

package ssh

import (
	"errors"
	"io"
	"syscall"

	"golang.org/x/sys/unix"
)

// recvOneControlMsgCloexec falls back on Darwin (which lacks MSG_CMSG_CLOEXEC)
// to holding syscall.ForkLock.RLock across the non-blocking recvmsg and the
// immediate CloseOnExec marking so concurrent fork/exec helpers never inherit
// passenger descriptors. ForkLock is released before returning false on EAGAIN
// so it is never held across a runtime netpoll wait.
func recvOneControlMsgCloexec(rawConn syscall.RawConn, data, oob []byte) ([]int, int, error, error) {
	var (
		received     []int
		flags        int
		parseCtrlErr error
		recvErr      error
	)
	readErr := rawConn.Read(func(fd uintptr) bool {
		for {
			syscall.ForkLock.RLock()
			n, oobn, recvFlags, _, err := unix.Recvmsg(int(fd), data, oob, 0)
			if err == nil {
				flags = recvFlags
				if n == 0 && oobn == 0 {
					syscall.ForkLock.RUnlock()
					recvErr = io.EOF
					return true
				}
				received, parseCtrlErr = extractReceivedFDsMarkCloexec(oob[:oobn])
				syscall.ForkLock.RUnlock()
				recvErr = nil
				return true
			}
			syscall.ForkLock.RUnlock()
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				return false
			}
			recvErr = err
			return true
		}
	})
	if readErr != nil {
		return nil, 0, nil, readErr
	}
	if recvErr != nil {
		return nil, 0, nil, recvErr
	}
	return received, flags, parseCtrlErr, nil
}
