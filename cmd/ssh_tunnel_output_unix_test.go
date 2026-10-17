//go:build !windows

package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
)

// Unix pipe writes commit partial data before cancellation. No reader drains
// the pipe, so the canceled large write leaves its available capacity filled.
func fillTunnelOutputPipe(t *testing.T, writer *os.File) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	bound, closeOutput, supported, err := ssh.BindOutput(ctx, writer)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := closeOutput(); err != nil {
			t.Error(err)
		}
	}()
	if !supported {
		t.Skip("native cancelable pipe binding unavailable")
	}
	n, err := bound.Write(bytes.Repeat([]byte("x"), 4<<20))
	if n == 0 || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("pipe was not filled and canceled: n=%d err=%v", n, err)
	}
}
