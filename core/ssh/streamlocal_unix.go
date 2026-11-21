//go:build linux || darwin || freebsd

package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/wentf9/xops-cli/core/fsx"
)

func listenLocalStreamLocal(ctx context.Context, socketPath string, bindMask uint32, bindUnlink bool) (net.Listener, error) {
	if socketPath == "" {
		return nil, errors.New("streamlocal socket path cannot be empty")
	}
	if len(socketPath) >= MaxControlPathLength() {
		return nil, fmt.Errorf("streamlocal socket path %q exceeds maximum length %d", socketPath, MaxControlPathLength())
	}

	listenFn := func(addr string) (net.Listener, error) {
		return (&net.ListenConfig{}).Listen(ctx, "unix", addr)
	}
	var (
		slot *fsx.SocketSlot
		err  error
	)
	if bindUnlink {
		// StreamLocalBindUnlink=yes explicitly requests replacing an existing
		// socket entry (never non-socket files/symlinks/directories, which
		// fsx.ReplaceStaleSocketSlot refuses under the directory lock).
		slot, err = fsx.ReplaceStaleSocketSlot(socketPath, listenFn, func() bool { return true })
	} else {
		slot, err = fsx.BindSocketSlot(socketPath, listenFn)
	}
	if err != nil {
		if strings.Contains(err.Error(), "is not a socket") {
			return nil, fmt.Errorf("cannot unlink non-socket path %q: %w", socketPath, err)
		}
		return nil, err
	}

	perm := os.FileMode(0o666) &^ os.FileMode(bindMask&0o777)
	if perm != fsx.OwnerOnlyPerm {
		if chmodErr := os.Chmod(slot.Path(), perm); chmodErr != nil {
			_ = slot.Release()
			return nil, fmt.Errorf("chmod streamlocal socket failed: %w", chmodErr)
		}
	}
	return &streamLocalListener{slot: slot}, nil
}
