package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	"golang.org/x/sys/windows"
)

// Canceling an oversized Windows pipe write can discard its pending data. Fill
// the advertised quota with a completed write first, then prove a single byte
// cannot fit. The original canceled 4 MiB write did not establish this condition.
func fillTunnelOutputPipe(t *testing.T, writer *os.File) {
	t.Helper()
	raw, err := writer.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var flags, outbound, inbound uint32
	var infoErr error
	if err := raw.Control(func(fd uintptr) {
		infoErr = windows.GetNamedPipeInfo(windows.Handle(fd), &flags, &outbound, &inbound, nil)
	}); err != nil {
		t.Fatal(err)
	}
	if infoErr != nil {
		t.Fatal(infoErr)
	}
	quota := inbound // CreatePipe's write handle is the client end.
	if flags&windows.PIPE_SERVER_END != 0 {
		quota = outbound
	}
	if quota == 0 || quota > 1<<20 {
		t.Fatalf("unexpected pipe quota: %d", quota)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
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
		t.Fatal("Windows pipe binding unavailable")
	}
	n, err := bound.Write(bytes.Repeat([]byte("x"), int(quota)))
	if err != nil || n != int(quota) {
		t.Fatalf("pipe fill was not committed: n=%d quota=%d err=%v", n, quota, err)
	}
	probeCtx, stopProbe := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer stopProbe()
	probe, closeProbe, _, err := ssh.BindOutput(probeCtx, writer)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := closeProbe(); err != nil {
			t.Error(err)
		}
	}()
	if n, err := probe.Write([]byte("x")); n != 0 || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("pipe still has room after committed fill: n=%d err=%v", n, err)
	}
}
