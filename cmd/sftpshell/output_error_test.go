package sftpshell

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
)

type outputFailureProbe struct{ writes int }

func (w *outputFailureProbe) Write(p []byte) (int, error) {
	w.writes++
	return len(p), nil
}

func TestReportCommandOutputFailureIsFatalWithoutDiagnosticWrite(t *testing.T) {
	for _, mode := range []string{"direct", "wrapped", "joined", "batch"} {
		t.Run(mode, func(t *testing.T) {
			// Standard streams often share the same console or ConPTY. Even
			// diagnosing a stdout failure on raw stderr can block indefinitely.
			sink := &outputFailureProbe{}
			shell := &Shell{stdout: sink, stderr: sink, batch: mode == "batch"}
			outputErr := &ssh.OutputError{Target: sink, Err: context.DeadlineExceeded}
			var err error = outputErr
			switch mode {
			case "wrapped":
				err = fmt.Errorf("exec: %w", err)
			case "joined":
				err = errors.Join(errors.New("other cleanup failed"), ErrPromptInterrupted, err)
			}
			got := shell.reportCommandError(err)
			if !errors.Is(got, outputErr) || !errors.Is(got, context.DeadlineExceeded) {
				t.Fatalf("output failure was swallowed: %v", got)
			}
			if sink.writes != 0 {
				t.Fatalf("wrote %d diagnostics to failed console", sink.writes)
			}
		})
	}
}
