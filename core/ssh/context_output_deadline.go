//go:build linux || darwin

package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

type fileContextOutput struct {
	file     *os.File
	perWrite time.Duration
}

func (w fileContextOutput) WriteContext(ctx context.Context, data []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	var deadline time.Time
	if w.perWrite > 0 {
		deadline = time.Now().Add(w.perWrite)
	}
	if end, ok := ctx.Deadline(); ok && (deadline.IsZero() || end.Before(deadline)) {
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

// bindOwnedFileOutput takes ownership of an independently opened terminal or
// a duplicate of an already nonblocking pipe. Only its deadlines and handle
// are changed; callers join writes before releasing the binding.
func bindOwnedFileOutput(ctx context.Context, owned *os.File, source io.Writer, perWrite time.Duration) (io.Writer, func() error, error) {
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
	return contextOutput{ctx, fileContextOutput{owned, perWrite}, source}, closeFn, nil
}
