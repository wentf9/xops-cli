//go:build windows

package ssh

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/wentf9/xops-cli/core/winsec"
)

var errPassengerUnsupported = errors.New("passenger mode with fd passing is not supported on Windows; use MUX_C_PROXY")

func bindAndLinkSocket(targetPath string) (net.Listener, os.FileInfo, error) {
	if err := validateWindowsSocketPath(targetPath); err != nil {
		return nil, nil, err
	}
	maxPathLen := MaxControlPathLength() - 1
	if len(targetPath) > maxPathLen {
		return nil, nil, fmt.Errorf("control path %q exceeds maximum Unix socket path length (%d bytes)", targetPath, maxPathLen)
	}
	if err := winsec.EnsureOwnerOnlyDirectory(filepath.Dir(targetPath)); err != nil {
		return nil, nil, fmt.Errorf("prepare secure control socket directory failed: %w", err)
	}
	if _, err := os.Lstat(targetPath); err == nil {
		return nil, nil, fmt.Errorf("%w: %s", ErrMasterAlreadyExists, targetPath)
	}

	// Windows AF_UNIX does not support hard-linking socket reparse points.
	// Bind targetPath directly inside the verified owner-only directory, then
	// apply a protected owner-only DACL on the socket file as defense-in-depth.
	listener, err := net.Listen("unix", targetPath)
	if err != nil {
		var sysErr syscall.Errno
		errStr := strings.ToLower(err.Error())
		if (errors.As(err, &sysErr) && (sysErr == syscall.EADDRINUSE || sysErr == syscall.EEXIST || sysErr == syscall.Errno(10048))) ||
			strings.Contains(errStr, "address already in use") ||
			strings.Contains(errStr, "only one usage of each socket address") ||
			strings.Contains(errStr, "file exists") ||
			(strings.Contains(errStr, "access is denied") && socketPathExistsOrOccupied(targetPath)) {
			return nil, nil, fmt.Errorf("%w: %s", ErrMasterAlreadyExists, targetPath)
		}
		return nil, nil, err
	}
	if unixLn, ok := listener.(*net.UnixListener); ok {
		unixLn.SetUnlinkOnClose(false)
	}
	if err := winsec.HardenFileOwnerOnly(targetPath); err != nil {
		_ = listener.Close()
		_ = os.Remove(targetPath)
		return nil, nil, fmt.Errorf("harden control socket DACL failed: %w", err)
	}
	origFi, lstatErr := os.Lstat(targetPath)
	if lstatErr != nil {
		_ = listener.Close()
		_ = os.Remove(targetPath)
		return nil, nil, fmt.Errorf("stat control socket failed: %w", lstatErr)
	}
	if err := winsec.VerifyOwnerOnlySocketFile(targetPath); err != nil {
		_ = listener.Close()
		_ = os.Remove(targetPath)
		return nil, nil, fmt.Errorf("verify control socket security failed: %w", err)
	}
	return listener, origFi, nil
}

func socketPathExistsOrOccupied(targetPath string) bool {
	_, err := os.Lstat(targetPath)
	return err == nil
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
