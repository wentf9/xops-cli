package sshfixture

import (
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"
)

func TestRecordPeerClosure(t *testing.T) {
	unexpected := errors.New("unexpected fixture failure")
	for _, tc := range []struct {
		name   string
		err    error
		retain bool
	}{
		{name: "EOF", err: io.EOF},
		{name: "closed connection", err: net.ErrClosed},
		{name: "peer reset", err: &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}},
		{name: "broken pipe", err: fmt.Errorf("reply after disconnect: %w", syscall.EPIPE)},
		{name: "joined peer closure", err: errors.Join(io.EOF, syscall.ECONNRESET)},
		{name: "unexpected", err: unexpected, retain: true},
		{name: "similar text", err: errors.New("connection reset by peer"), retain: true},
		{name: "mixed failure", err: errors.Join(syscall.ECONNRESET, unexpected), retain: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := &Server{ctx: t.Context()}
			server.record(tc.err)
			if tc.retain {
				if len(server.errors) != 1 || !errors.Is(server.errors[0], tc.err) {
					t.Fatalf("fixture error was lost: %v", server.errors)
				}
			} else if len(server.errors) != 0 {
				t.Fatalf("peer closure became a fixture failure: %v", server.errors)
			}
		})
	}
}
