//go:build unix

package mux

import (
	"errors"
	"os"
	"syscall"

	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
)

// isMuxUnavailableErr 判断 Unix 套接字探测/连接错误是否表示 ControlMaster 未运行或已失联。
func isMuxUnavailableErr(err error) bool {
	return errors.Is(err, os.ErrNotExist) ||
		errors.Is(err, ports.ErrNotFound) ||
		errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ENOENT) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, osfs.ErrNotSocket)
}
