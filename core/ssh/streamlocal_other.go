//go:build !(linux || darwin || freebsd || windows)

package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
)

func unlinkExistingStreamLocalSocket(socketPath string) error {
	fi, statErr := os.Lstat(socketPath)
	if statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat existing streamlocal path %q failed: %w", socketPath, statErr)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("cannot unlink non-socket path %q (mode %s)", socketPath, fi.Mode())
	}
	if err := os.Remove(socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("unlink existing streamlocal socket %q failed: %w", socketPath, err)
	}
	return nil
}

func listenLocalStreamLocal(ctx context.Context, socketPath string, _ uint32, bindUnlink bool) (net.Listener, error) {
	if socketPath == "" {
		return nil, errors.New("streamlocal socket path cannot be empty")
	}
	if len(socketPath) >= MaxControlPathLength() {
		return nil, fmt.Errorf("streamlocal socket path %q exceeds maximum length %d", socketPath, MaxControlPathLength())
	}
	if bindUnlink {
		if err := unlinkExistingStreamLocalSocket(socketPath); err != nil {
			return nil, err
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
	origFi, lstatErr := os.Lstat(socketPath)
	if lstatErr != nil {
		_ = listener.Close()
		_ = os.Remove(socketPath)
		return nil, fmt.Errorf("stat streamlocal socket failed: %w", lstatErr)
	}
	return &streamLocalListener{
		Listener:   listener,
		socketPath: socketPath,
		origFi:     origFi,
	}, nil
}
