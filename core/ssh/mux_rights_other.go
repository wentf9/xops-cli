//go:build !(linux || darwin || freebsd)

package ssh

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

var errPassengerUnsupported = errors.New("passenger mode with fd passing is not supported on Windows; use MUX_C_PROXY")

func bindAndLinkSocket(targetPath string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(targetPath), 0700); err != nil {
		return nil, fmt.Errorf("create socket directory failed: %w", err)
	}

	// Windows AF_UNIX does not support hard-linking socket reparse points.
	// Bind targetPath directly.
	listener, err := net.Listen("unix", targetPath)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "address already in use") || strings.Contains(strings.ToLower(err.Error()), "access is denied") {
			return nil, fmt.Errorf("%w: %s", ErrMasterAlreadyExists, targetPath)
		}
		return nil, err
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
