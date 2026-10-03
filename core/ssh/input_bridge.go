package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// InputBridge owns only duplicated input and cancellation handles. The caller
// owns the supplied terminal streams and the remote writer.
type InputBridge interface {
	Start(context.Context, InteractiveIO, io.Writer) (InputCopy, error)
}

// InputCopy.Close interrupts reading; Wait joins the copy within its context.
// Closing a copy must not close any borrowed process standard stream.
type InputCopy interface {
	Close() error
	Wait(context.Context) error
}

type inputCopy struct {
	cancel func() error
	done   chan struct{}
	err    error
}

// NewInputCopy adapts a cancellable input pump. The pump must send exactly one
// completion result and exit when interrupted; cancellation must be bounded.
// The returned copy owns cancellation and joins the completion collector.
func NewInputCopy(ctx context.Context, cancel func() error, done <-chan error) (InputCopy, error) {
	if ctx == nil || cancel == nil || done == nil {
		return nil, fmt.Errorf("input copy requires context, cancellation, and completion")
	}
	copy := &inputCopy{cancel: sync.OnceValue(cancel), done: make(chan struct{})}
	cancelDone := make(chan error, 1)
	stop := context.AfterFunc(ctx, func() { cancelDone <- copy.cancel() })
	// The pump exits on EOF or cancellation; its result is joined by Wait.
	go func() {
		result := <-done
		var cancelErr error
		if !stop() {
			cancelErr = <-cancelDone
		}
		copy.err = errors.Join(result, cancelErr, copy.cancel())
		close(copy.done)
	}()
	return copy, nil
}

func (c *inputCopy) Close() error { return c.cancel() }

func (c *inputCopy) Wait(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("input copy wait context is required")
	}
	select {
	case <-c.done:
		return c.err
	case <-ctx.Done():
		return errors.Join(ctx.Err(), c.cancel())
	}
}

func startInputCopy(ctx context.Context, bridge InputBridge, streams InteractiveIO, dst io.Writer) (func() error, <-chan error, error) {
	if nilCapability(bridge) {
		return copyStdinTo(streams.Stdin, dst)
	}
	copy, err := bridge.Start(ctx, streams, dst)
	if err != nil {
		return nil, nil, fmt.Errorf("start input bridge: %w", err)
	}
	if nilCapability(copy) {
		return nil, nil, fmt.Errorf("input bridge returned a nil copy")
	}
	done := make(chan error, 1)
	stopping := make(chan struct{})
	stopCopy := sync.OnceValue(func() error { close(stopping); return copy.Close() })
	// Normal input may remain open for the entire session. Operation cancellation
	// requests Close, then a separate context bounds and joins the input cleanup.
	waitCtx, cancelWait := context.WithCancel(context.WithoutCancel(ctx))
	waited := make(chan error, 1)
	go func() { waited <- copy.Wait(waitCtx) }()
	go func() {
		defer close(done)
		defer cancelWait()
		select {
		case err := <-waited:
			done <- errors.Join(err, stopCopy())
			return
		case <-ctx.Done():
		case <-stopping:
		}
		closeErr := stopCopy()
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), inputCleanupTimeout)
		defer cancel()
		select {
		case err := <-waited:
			done <- errors.Join(err, closeErr)
		case <-cleanup.Done():
			cancelWait()
			// InputCopy.Wait must honor cancellation; join the waiter before return.
			done <- errors.Join(fmt.Errorf("join input cleanup: %w", cleanup.Err()), closeErr, <-waited)
		}
	}()
	return stopCopy, done, nil
}

const inputCleanupTimeout = time.Second
