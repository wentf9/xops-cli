package sshexec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"
)

func TestForwardStopErrorPreservesUnexpectedFailures(t *testing.T) {
	if err := forwardStopError(errors.Join(fmt.Errorf("accept forwarded connection failed: %w", io.EOF), context.Canceled)); err != nil {
		t.Fatalf("expected stop survived: %v", err)
	}
	if err := forwardStopError(&net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}); err != nil {
		t.Fatalf("owned cancelled transport reset survived: %v", err)
	}
	marker := errors.New("unexpected listener cleanup failure")
	err := forwardStopError(errors.Join(fmt.Errorf("connection lost: %w", io.EOF), marker))
	if !errors.Is(err, marker) {
		t.Fatalf("unexpected close failure was discarded: %v", err)
	}
}
