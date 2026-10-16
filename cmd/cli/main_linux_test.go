//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/cmd"
	"golang.org/x/sys/unix"
)

// The child owns its process; the parent owns and closes both pipe ends.
// Aliased full standard streams must not block reporting or a nonzero exit.
func TestReportErrorFullPipeExit(t *testing.T) {
	if stream := os.Getenv("XOPS_TEST_FAILED_SCP_OUTPUT"); stream != "" {
		reportError(errors.Join(errors.New("transfer failed"), &cmd.SCPOutputError{Stream: stream, Err: context.DeadlineExceeded}))
		os.Exit(1)
	}
	for _, stream := range []string{"stderr", "stdout"} {
		t.Run(stream, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = reader.Close(); _ = writer.Close() }()
			capacity, err := unix.FcntlInt(writer.Fd(), unix.F_GETPIPE_SZ, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write(make([]byte, capacity)); err != nil {
				t.Fatal(err)
			}
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, exe, "-test.run=^TestReportErrorFullPipeExit$")
			child.Env = append(os.Environ(), "XOPS_TEST_FAILED_SCP_OUTPUT="+stream)
			child.Stderr = writer
			child.Stdout = writer
			err = child.Run()
			var exit *exec.ExitError
			if ctx.Err() != nil || !errors.As(err, &exit) || exit.ExitCode() != 1 {
				t.Fatalf("failed standard stream blocked exit or lost failure status: %v (context: %v)", err, ctx.Err())
			}
		})
	}
}
