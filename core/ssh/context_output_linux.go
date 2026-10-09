//go:build linux

package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func prepareFileOutput(ctx context.Context, source *os.File, perWrite time.Duration) (io.Writer, func() error, error) {
	info, err := source.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("inspect terminal output: %w", err)
	}
	if info.Mode()&(os.ModeNamedPipe|os.ModeCharDevice) == 0 {
		return nil, nil, fmt.Errorf("cancelable PTY output requires a terminal or pipe; use a ContextWriter for regular files")
	}
	// Reopen, rather than dup: O_NONBLOCK on a duplicated file description
	// would change the borrowed caller descriptor's flags. No shared offsets or
	// deadlines are changed, and only this owned handle is closed.
	var descriptor uintptr
	raw, err := source.SyscallConn()
	if err != nil {
		return nil, nil, fmt.Errorf("access terminal output descriptor: %w", err)
	}
	if err := raw.Control(func(fd uintptr) { descriptor = fd }); err != nil {
		return nil, nil, fmt.Errorf("inspect terminal output descriptor: %w", err)
	}
	owned, err := os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", descriptor), os.O_WRONLY|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open owned terminal output: %w", err)
	}
	if err := owned.SetWriteDeadline(time.Now().Add(terminalWriteTimeout)); err != nil {
		return nil, nil, errors.Join(fmt.Errorf("terminal output does not support deadlines: %w", err), closeResource(owned, "owned terminal output"))
	}
	canceled := make(chan error, 1)
	stop := context.AfterFunc(ctx, func() { canceled <- owned.SetWriteDeadline(time.Now()) })
	closeFn := func() error {
		var cancelErr error
		if !stop() {
			cancelErr = <-canceled
		}
		return errors.Join(cancelErr, closeResource(owned, "owned terminal output"))
	}
	return contextOutput{ctx, fileContextOutput{owned, perWrite}}, closeFn, nil
}
