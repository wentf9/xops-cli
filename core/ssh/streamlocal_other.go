//go:build !(linux || darwin || freebsd)

package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
)

func listenLocalStreamLocal(ctx context.Context, socketPath string, _ uint32, bindUnlink bool) (net.Listener, error) {
	// POSIX StreamLocalBindMask mode bits do not apply to Windows AF_UNIX socket endpoints.
	if socketPath == "" {
		return nil, errors.New("streamlocal socket path cannot be empty")
	}
	if len(socketPath) >= MaxControlPathLength() {
		return nil, fmt.Errorf("streamlocal socket path %q exceeds maximum length %d", socketPath, MaxControlPathLength())
	}
	if bindUnlink {
		fi, statErr := os.Lstat(socketPath)
		if statErr == nil {
			if fi.IsDir() {
				return nil, fmt.Errorf("cannot unlink streamlocal socket %q: is a directory", socketPath)
			}
			_ = os.Remove(socketPath)
		}
	}
	lc := net.ListenConfig{}
	listener, err := lc.Listen(ctx, "unix", socketPath)
	if err != nil {
		return nil, err
	}
	if unixLn, ok := listener.(*net.UnixListener); ok {
		unixLn.SetUnlinkOnClose(false)
	}
	origFi, _ := os.Lstat(socketPath)
	return &streamLocalListener{
		Listener:   listener,
		socketPath: socketPath,
		origFi:     origFi,
	}, nil
}
