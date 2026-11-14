//go:build !linux && !darwin && !freebsd && !windows

package ssh

import (
	"net"
	"os"
	"runtime"
)

func bindAndLinkSocket(targetPath string) (net.Listener, error) {
	return unsupportedUnixBindControlSocket(targetPath, runtime.GOOS)
}

func checkPeerUID(conn net.Conn, expectedUID uint32) error {
	return unsupportedUnixCheckPeerUID(runtime.GOOS)
}

func localPeerUID() uint32 {
	euid := os.Geteuid()
	if euid < 0 {
		return 0
	}
	return uint32(euid)
}

func handlePassengerSession(s *MuxServer, conn net.Conn, reqID uint32, payload []byte) error {
	return sendPermissionDenied(conn, reqID, unsupportedUnixCheckPeerUID(runtime.GOOS).Error())
}

func handlePassengerStdioFwd(s *MuxServer, conn net.Conn, reqID uint32, payload []byte) error {
	return sendPermissionDenied(conn, reqID, unsupportedUnixCheckPeerUID(runtime.GOOS).Error())
}
