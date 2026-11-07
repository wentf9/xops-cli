//go:build !(linux || darwin || freebsd)

package ssh

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

var errPassengerUnsupported = errors.New("passenger mode with fd passing is not supported on Windows; use MUX_C_PROXY")

func bindAndLinkSocket(targetPath string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(targetPath), 0700); err != nil {
		return nil, fmt.Errorf("create socket directory failed: %w", err)
	}
	if _, err := os.Lstat(targetPath); err == nil {
		return nil, fmt.Errorf("%w: %s", ErrMasterAlreadyExists, targetPath)
	}

	// Windows AF_UNIX does not support hard-linking socket reparse points.
	// Bind targetPath directly.
	listener, err := net.Listen("unix", targetPath)
	if err != nil {
		var sysErr syscall.Errno
		errStr := strings.ToLower(err.Error())
		if (errors.As(err, &sysErr) && (sysErr == syscall.EADDRINUSE || sysErr == syscall.EEXIST || sysErr == syscall.Errno(10048))) ||
			strings.Contains(errStr, "address already in use") ||
			strings.Contains(errStr, "only one usage of each socket address") ||
			strings.Contains(errStr, "access is denied") ||
			strings.Contains(errStr, "file exists") {
			return nil, fmt.Errorf("%w: %s", ErrMasterAlreadyExists, targetPath)
		}
		return nil, err
	}
	if unixLn, ok := listener.(*net.UnixListener); ok {
		unixLn.SetUnlinkOnClose(false)
	}
	return listener, nil
}

func checkPeerUID(conn net.Conn, expectedUID uint32) error {
	// On Windows, AF_UNIX sockets are protected by NTFS DACLs / security descriptors.
	// SO_PEERCRED is not available in Winsock.
	return nil
}

// localPeerUID reports zero because this platform exposes no peer credentials.
func localPeerUID() uint32 {
	return 0
}

func handlePassengerSession(s *MuxServer, conn net.Conn, reqID uint32, payload []byte) error {
	return sendFailure(conn, reqID, errPassengerUnsupported.Error())
}

func handlePassengerStdioFwd(s *MuxServer, conn net.Conn, reqID uint32, payload []byte) error {
	return sendFailure(conn, reqID, errPassengerUnsupported.Error())
}
