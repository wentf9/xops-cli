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

const terminalWriteTimeout = 10 * time.Second

type fileContextOutput struct{ file *os.File }

func (w fileContextOutput) WriteContext(ctx context.Context, data []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	deadline := time.Now().Add(terminalWriteTimeout)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	if err := w.file.SetWriteDeadline(deadline); err != nil {
		return 0, fmt.Errorf("set terminal output deadline: %w", err)
	}
	// Cancellation may have set an immediate deadline just before this write
	// installed its per-write limit. Never overwrite it and enter a blocking I/O.
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	n, err := w.file.Write(data)
	if err != nil {
		cause := ctx.Err()
		// The file deadline and context timer can fire independently. Preserve
		// a stable timeout classification even before ctx.Err becomes visible.
		if cause == nil && errors.Is(err, os.ErrDeadlineExceeded) {
			cause = context.DeadlineExceeded
		}
		return n, errors.Join(cause, fmt.Errorf("write terminal output: %w", err))
	}
	return n, nil
}

func prepareFileOutput(ctx context.Context, source *os.File) (io.Writer, func() error, error) {
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
	close := func() error {
		var cancelErr error
		if !stop() {
			cancelErr = <-canceled
		}
		return errors.Join(cancelErr, closeResource(owned, "owned terminal output"))
	}
	return contextOutput{ctx, fileContextOutput{owned}}, close, nil
}
