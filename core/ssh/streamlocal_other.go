//go:build !(linux || darwin || freebsd || windows)

package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/wentf9/xops-cli/core/fsx"
)

func listenLocalStreamLocal(ctx context.Context, socketPath string, _ uint32, bindUnlink bool) (net.Listener, error) {
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
	return &streamLocalListener{slot: slot}, nil
}
