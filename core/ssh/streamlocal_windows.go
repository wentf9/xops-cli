//go:build windows

package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/wentf9/xops-cli/core/winsec"
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

func removeIfSameStreamLocalFile(socketPath string, origFi os.FileInfo) {
	if origFi == nil {
		_ = os.Remove(socketPath)
		return
	}
	currFi, err := os.Lstat(socketPath)
	if err != nil || !os.SameFile(origFi, currFi) {
		return
	}
	_ = os.Remove(socketPath)
}

func listenLocalStreamLocal(ctx context.Context, socketPath string, bindMask uint32, bindUnlink bool) (net.Listener, error) {
	if socketPath == "" {
		return nil, errors.New("streamlocal socket path cannot be empty")
	}
	if err := validateWindowsSocketPath(socketPath); err != nil {
		return nil, err
	}
	if len(socketPath) >= MaxControlPathLength() {
		return nil, fmt.Errorf("streamlocal socket path %q exceeds maximum length %d", socketPath, MaxControlPathLength())
	}

	// Enforce strict owner-only Windows NTFS directory and socket DACL hardening
	// when StreamLocalBindMask strips group/other bits (including default 0177).
	ownerOnly := bindMask&0o077 == 0o077
	if ownerOnly {
		if err := winsec.EnsureOwnerOnlyDirectory(filepath.Dir(socketPath)); err != nil {
			return nil, fmt.Errorf("prepare secure streamlocal socket directory failed: %w", err)
		}
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

	if ownerOnly {
		if err := winsec.HardenFileOwnerOnly(socketPath); err != nil {
			_ = listener.Close()
			removeIfSameStreamLocalFile(socketPath, origFi)
			return nil, fmt.Errorf("harden streamlocal socket DACL failed: %w", err)
		}
		if err := winsec.VerifyOwnerOnlySocketFile(socketPath); err != nil {
			_ = listener.Close()
			removeIfSameStreamLocalFile(socketPath, origFi)
			return nil, fmt.Errorf("verify streamlocal socket security failed: %w", err)
		}
	}

	return &streamLocalListener{
		Listener:   listener,
		socketPath: socketPath,
		origFi:     origFi,
	}, nil
}
