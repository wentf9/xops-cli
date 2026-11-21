//go:build linux || darwin || freebsd

package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

func listenLocalStreamLocal(ctx context.Context, socketPath string, bindMask uint32, bindUnlink bool) (net.Listener, error) {
	if socketPath == "" {
		return nil, errors.New("streamlocal socket path cannot be empty")
	}
	if len(socketPath) >= MaxControlPathLength() {
		return nil, fmt.Errorf("streamlocal socket path %q exceeds maximum length %d", socketPath, MaxControlPathLength())
	}

	perm := os.FileMode(0o666) &^ os.FileMode(bindMask&0o777)
	maxPathLen := MaxControlPathLength() - 1
	targetLen := len(socketPath)
	suffixBudget := maxPathLen - targetLen
	dir := filepath.Dir(socketPath)
	dirBudget := maxPathLen - (len(dir) + 1)

	useSuffixTemp := suffixBudget >= 8
	useDirTemp := !useSuffixTemp && dirBudget >= 8

	if !useSuffixTemp && !useDirTemp {
		return listenStreamLocalDirect(ctx, socketPath, perm, bindUnlink)
	}
	return listenStreamLocalTempLink(ctx, socketPath, dir, perm, useSuffixTemp, bindUnlink)
}

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

// listenStreamLocalDirect runs only when socketPath is within 8 bytes of sun_path
// capacity (so neither a sibling staging directory nor a suffix temp path fits).
// Because Go cannot safely mutate process-global umask per-goroutine, os.Chmod
// narrows permissions immediately after Listen before returning the listener.
func listenStreamLocalDirect(ctx context.Context, socketPath string, perm os.FileMode, bindUnlink bool) (net.Listener, error) {
	if bindUnlink {
		if err := unlinkExistingStreamLocalSocket(socketPath); err != nil {
			return nil, err
		}
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "unix", socketPath)
	if err != nil {
		return nil, err
	}
	disableUnixListenerUnlinkOnClose(listener)
	if err := os.Chmod(socketPath, perm); err != nil {
		_ = listener.Close()
		_ = os.Remove(socketPath)
		return nil, fmt.Errorf("chmod streamlocal socket failed: %w", err)
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

func listenStreamLocalTempLink(ctx context.Context, socketPath, dir string, perm os.FileMode, useSuffixTemp, bindUnlink bool) (net.Listener, error) {
	var (
		listener net.Listener
		tempPath string
		err      error
	)
	for attempt := 0; attempt < 4; attempt++ {
		val := nextMuxTempToken()
		if useSuffixTemp {
			tempPath = fmt.Sprintf("%s.s%04x.t", socketPath, val)
		} else {
			tempPath = filepath.Join(dir, fmt.Sprintf(".s%04x.t", val))
		}
		listener, err = (&net.ListenConfig{}).Listen(ctx, "unix", tempPath)
		if err == nil {
			break
		}
		if !isAddressAlreadyInUse(err) {
			return nil, fmt.Errorf("listen on temp streamlocal socket failed: %w", err)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("listen on temp streamlocal socket failed: %w", err)
	}
	disableUnixListenerUnlinkOnClose(listener)
	defer func() {
		_ = os.Remove(tempPath)
	}()

	if err := os.Chmod(tempPath, perm); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("chmod temp streamlocal socket failed: %w", err)
	}
	// Capture our socket inode identity before publishing via hard link so a
	// post-link path swap cannot trick Close into unlinking another file.
	origFi, lstatErr := os.Lstat(tempPath)
	if lstatErr != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("stat temp streamlocal socket failed: %w", lstatErr)
	}

	if err := linkStreamLocalSocket(tempPath, socketPath, bindUnlink); err != nil {
		_ = listener.Close()
		return nil, err
	}

	return &streamLocalListener{
		Listener:   listener,
		socketPath: socketPath,
		origFi:     origFi,
	}, nil
}

func linkStreamLocalSocket(tempPath, socketPath string, bindUnlink bool) error {
	err := os.Link(tempPath, socketPath)
	if err == nil {
		return nil
	}
	if !errors.Is(err, os.ErrExist) && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("link streamlocal socket failed: %w", err)
	}
	if !bindUnlink {
		return fmt.Errorf("streamlocal socket %q already exists: %w", socketPath, err)
	}
	if unlinkErr := unlinkExistingStreamLocalSocket(socketPath); unlinkErr != nil {
		return unlinkErr
	}
	if retryErr := os.Link(tempPath, socketPath); retryErr != nil {
		return fmt.Errorf("link streamlocal socket failed after unlink: %w", retryErr)
	}
	return nil
}
