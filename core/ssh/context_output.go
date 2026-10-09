package ssh

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
)

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

func prepareContextOutput(ctx context.Context, target io.Writer) (io.Writer, func() error, error) {
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
		return prepareFileOutput(ctx, value)
	}
	if target == io.Discard {
		return contextOutput{ctx, memoryContextOutput{target}}, func() error { return nil }, nil
	}
	return nil, nil, fmt.Errorf("unsupported terminal output %T: provide a ContextWriter", target)
}
