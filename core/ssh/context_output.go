package ssh

import (
	"bytes"
	"context"
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
// The built-in regular-file adapter has a weaker contract: cancellation is
// checked between writes, and an in-flight kernel write must finish before return.
type ContextWriter interface {
	WriteContext(context.Context, []byte) (int, error)
}

type contextOutput struct {
	ctx    context.Context
	target ContextWriter
	source io.Writer
}

func (w contextOutput) Write(data []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, &OutputError{Target: w.source, Err: err}
	}
	n, err := w.target.WriteContext(w.ctx, data)
	if err == nil && n < len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		err = &OutputError{Target: w.source, Err: err}
	}
	return n, err
}

// Finite memory sinks are serialized by the session's output pump.
type memoryContextOutput struct{ io.Writer }

func (w memoryContextOutput) WriteContext(ctx context.Context, data []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return w.Write(data)
}

func prepareContextOutput(ctx context.Context, target io.Writer) (io.Writer, func() error, error) {
	return prepareContextOutputWithLimit(ctx, target, terminalWriteTimeout)
}

// perWriteLimit bounds native terminal/pipe writes; zero leaves only ctx's own
// deadline and cancellation, for consumers that may legitimately stall. Regular
// files use the shared synchronous adapter instead: no deadline can interrupt an
// in-flight kernel write, and the session must join it before returning.
func prepareContextOutputWithLimit(ctx context.Context, target io.Writer, perWriteLimit time.Duration) (io.Writer, func() error, error) {
	if nilCapability(target) {
		return nil, nil, fmt.Errorf("terminal output is nil")
	}
	if output, ok := target.(ContextWriter); ok {
		return contextOutput{ctx, output, target}, func() error { return nil }, nil
	}
	switch value := target.(type) {
	case *bytes.Buffer, *strings.Builder:
		return contextOutput{ctx, memoryContextOutput{target}, target}, func() error { return nil }, nil
	case *os.File:
		info, err := value.Stat()
		if err != nil {
			return nil, nil, fmt.Errorf("inspect output file: %w", err)
		}
		if info.Mode().IsRegular() {
			// Borrow the caller's file, offset and flags. No background write is
			// started, and cleanup never closes or syncs the borrowed file.
			return contextOutput{ctx, regularFileOutput{value}, value}, func() error { return nil }, nil
		}
		return prepareFileOutput(ctx, value, perWriteLimit)
	}
	if target == io.Discard {
		return contextOutput{ctx, memoryContextOutput{target}, target}, func() error { return nil }, nil
	}
	return nil, nil, fmt.Errorf("unsupported terminal output %T: provide a ContextWriter", target)
}
