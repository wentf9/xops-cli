//go:build windows

package mux

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"

	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
)

// isMuxUnavailableErr 判断 Windows AF_UNIX 套接字探测/连接错误是否表示 ControlMaster 未运行。
func isMuxUnavailableErr(err error) bool {
	return errors.Is(err, os.ErrNotExist) ||
		errors.Is(err, ports.ErrNotFound) ||
		errors.Is(err, windows.WSAECONNREFUSED) ||
		errors.Is(err, windows.WSAECONNRESET) ||
		errors.Is(err, windows.ERROR_FILE_NOT_FOUND) ||
		errors.Is(err, windows.ERROR_PATH_NOT_FOUND) ||
		errors.Is(err, osfs.ErrNotSocket)
}

// formatPeerDetail 将 Windows SIO_AF_UNIX_GETPEERPID 对端凭据格式化为非敏感诊断标签。
func formatPeerDetail(cred osfs.PeerCred) string {
	pid, hasPID := cred.PID()
	if hasPID {
		return fmt.Sprintf("windows(pid=%d)", pid)
	}
	return "windows(verified)"
}
