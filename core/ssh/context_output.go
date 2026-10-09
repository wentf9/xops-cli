package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const terminalWriteTimeout = 10 * time.Second

// ContextWriter is an explicit output capability. Implementations must return
// when ctx is canceled, perform no writes after returning, and not retain data.
// Ordinary io.Writer callbacks cannot provide that guarantee automatically.
type ContextWriter interface {
	WriteContext(context.Context, []byte) (int, error)
}

type contextOutput struct {
	ctx    context.Context
	target ContextWriter
}

func (w contextOutput) Write(data []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	return w.target.WriteContext(w.ctx, data)
}

// Finite memory sinks are serialized by the session's output pump.
type memoryContextOutput struct{ io.Writer }

func (w memoryContextOutput) WriteContext(ctx context.Context, data []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return w.Write(data)
}

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

func prepareContextOutput(ctx context.Context, target io.Writer) (io.Writer, func() error, error) {
	return prepareContextOutputWithLimit(ctx, target, terminalWriteTimeout)
}

// perWriteLimit bounds each native file write; zero leaves only ctx's own
// deadline and cancellation, for consumers that may legitimately stall.
func prepareContextOutputWithLimit(ctx context.Context, target io.Writer, perWriteLimit time.Duration) (io.Writer, func() error, error) {
	if nilCapability(target) {
		return nil, nil, fmt.Errorf("terminal output is nil")
	}
	if output, ok := target.(ContextWriter); ok {
		return contextOutput{ctx, output}, func() error { return nil }, nil
	}
	switch value := target.(type) {
	case *bytes.Buffer, *strings.Builder:
		return contextOutput{ctx, memoryContextOutput{target}}, func() error { return nil }, nil
	case *os.File:
		return prepareFileOutput(ctx, value, perWriteLimit)
	}
	if target == io.Discard {
		return contextOutput{ctx, memoryContextOutput{target}}, func() error { return nil }, nil
	}
	return nil, nil, fmt.Errorf("unsupported terminal output %T: provide a ContextWriter", target)
}
