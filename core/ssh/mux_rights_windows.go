//go:build windows

package ssh

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/wentf9/xops-cli/core/fsx"
	"github.com/wentf9/xops-cli/core/winsec"
)

var errPassengerUnsupported = errors.New("passenger mode with fd passing is not supported on Windows; use MUX_C_PROXY")

func bindAndLinkSocket(targetPath string) (*fsx.SocketSlot, error) {
	if err := validateWindowsSocketPath(targetPath); err != nil {
		return nil, err
	}
	maxPathLen := MaxControlPathLength() - 1
	if len(targetPath) > maxPathLen {
		return nil, fmt.Errorf("control path %q exceeds maximum Unix socket path length (%d bytes)", targetPath, maxPathLen)
	}
	slot, err := fsx.BindSocketSlot(targetPath, nil)
	if err != nil {
		if errors.Is(err, fsx.ErrSlotOccupied) {
			return nil, fmt.Errorf("%w: %s", ErrMasterAlreadyExists, targetPath)
		}
		return nil, err
	}
	return slot, nil
}

// checkPeerUID verifies the connected Windows AF_UNIX peer process token user
// SID matches the current user via WSAIoctl(SIO_AF_UNIX_GETPEERPID). Any
// failure fails closed with ErrUnauthorizedPeer (and additionally wraps
// ErrUnsupportedMuxPlatform when SIO_AF_UNIX_GETPEERPID is unsupported on
// legacy Windows).
func checkPeerUID(conn net.Conn, _ uint32) error {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return fmt.Errorf("%w: connection does not support raw socket control", ErrUnauthorizedPeer)
	}
	rawConn, err := sc.SyscallConn()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnauthorizedPeer, err)
	}

	var peerErr error
	if err := rawConn.Control(func(fd uintptr) {
		peerErr = winsec.VerifyAFUnixPeerCurrentUser(fd)
	}); err != nil {
		return fmt.Errorf("%w: %w", ErrUnauthorizedPeer, err)
	}
	if peerErr != nil {
		if errors.Is(peerErr, winsec.ErrUnsupportedPeerPID) {
			return fmt.Errorf("%w: %w: %w", ErrUnauthorizedPeer, ErrUnsupportedMuxPlatform, peerErr)
		}
		return fmt.Errorf("%w: %w", ErrUnauthorizedPeer, peerErr)
	}
	return nil
}

// localPeerUID returns 0 on Windows because peer verification compares the
// Windows process token user SID against the current user rather than a POSIX UID.
func localPeerUID() uint32 {
	return 0
}

func handlePassengerSession(s *MuxServer, conn net.Conn, reqID uint32, payload []byte) error {
	return sendFailure(conn, reqID, errPassengerUnsupported.Error())
}

func handlePassengerStdioFwd(s *MuxServer, conn net.Conn, reqID uint32, payload []byte) error {
	return sendFailure(conn, reqID, errPassengerUnsupported.Error())
}
