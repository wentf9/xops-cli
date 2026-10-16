package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/playbook"
)

func TestCommandResultNativePipeCancellation(t *testing.T) {
	for _, mode := range []string{"exec result", "play report", "play dry run"} {
		t.Run(mode, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = reader.Close(); _ = writer.Close() }()
			_, release, supported, err := ssh.BindOutput(t.Context(), writer)
			if err != nil {
				t.Fatal(err)
			}
			if err := release(); err != nil {
				t.Fatal(err)
			}
			if !supported {
				t.Skip("native pipe binding unavailable")
			}
			payload := strings.Repeat("x", 2<<20)
			ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				switch mode {
				case "exec result":
					o := NewExecOptions()
					o.stdout = writer
					done <- o.printTaskResult(ctx, execHostTask{host: "fixture"}, payload, nil, &sync.Mutex{})
				case "play report":
					done <- (&PlayOptions{Out: writer}).writeReport(ctx, &playbook.Report{PlaybookName: payload}, nil)
				case "play dry run":
					done <- (&PlayOptions{Out: writer}).printDryRun(ctx, &playbook.Playbook{Name: payload})
				}
			}()
			select {
			case err := <-done:
				var outputErr *ssh.OutputError
				if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &outputErr) {
					t.Fatalf("lost output cancellation: %v", err)
				}
			case <-time.After(2 * time.Second):
				_ = reader.Close()
				<-done
				t.Fatal("result rendering ignored cancellation")
			}
			if _, err := writer.Stat(); err != nil {
				t.Fatalf("borrowed output closed: %v", err)
			}
		})
	}
}

func TestPlayReportPreservesExecutionAndOutputErrors(t *testing.T) {
	runErr := errors.New("engine failed")
	stepErr := errors.New("remote failed")
	writeErr := errors.New("sink failed")
	report := &playbook.Report{Hosts: []playbook.HostReport{{NodeID: "fixture", Steps: []playbook.StepResult{{Status: playbook.StatusFailed, Err: stepErr}}}}}
	err := (&PlayOptions{Out: playErrorWriter{err: writeErr}}).writeReport(t.Context(), report, runErr)
	for _, want := range []error{runErr, stepErr, writeErr} {
		if !errors.Is(err, want) {
			t.Fatalf("lost %v in %v", want, err)
		}
	}
}

func TestExecResultDoesNotRetryFailedOutput(t *testing.T) {
	writer := &unsupportedSCPDiagnosticWriter{}
	o := NewExecOptions()
	o.stderr = writer
	if err := o.printTaskResult(t.Context(), execHostTask{}, "partial output", &ssh.OutputError{Target: os.Stdout, Err: io.ErrClosedPipe}, &sync.Mutex{}); err != nil {
		t.Fatal(err)
	}
	if writer.calls.Load() != 0 {
		t.Fatal("failed stream was written again")
	}
}

func TestExecResultPreservesPartialOutputAfterLogFailure(t *testing.T) {
	log, err := os.CreateTemp(t.TempDir(), "command.log")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	var stderr bytes.Buffer
	o := NewExecOptions()
	o.stderr = &stderr
	failure := &ssh.OutputError{Target: log, Err: os.ErrPermission}
	if err := o.printTaskResult(t.Context(), execHostTask{host: "fixture"}, "partial output", failure, &sync.Mutex{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "partial output") {
		t.Fatal("independent log failure suppressed result rendering")
	}
}

func TestHasStandardOutputErrorChecksJoinedTargets(t *testing.T) {
	log, err := os.CreateTemp(t.TempDir(), "command.log")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	logErr := &ssh.OutputError{Target: log, Err: os.ErrPermission}
	standardErr := &ssh.OutputError{Target: ssh.NewLockedWriter(&sync.Mutex{}, os.Stdout), Err: io.ErrClosedPipe}
	if HasStandardOutputError(errors.Join(logErr, errors.New("execution failed"))) {
		t.Fatal("log failure classified as standard output")
	}
	for _, err := range []error{errors.Join(logErr, standardErr), errors.Join(standardErr, logErr)} {
		if !HasStandardOutputError(err) {
			t.Fatal("standard-stream failure hidden by another joined error")
		}
	}
}

func TestSSHOutputRoutingUsesCapability(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = file, file
	defer func() { os.Stdout, os.Stderr = stdout, stderr; _ = file.Close() }()
	if supported, err := commandOutputSupported(t.Context()); err != nil || !supported {
		t.Fatalf("regular output not supported: %v %v", supported, err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if supported, err := commandOutputSupported(t.Context()); err != nil || supported {
		t.Fatalf("invalid output advertised as supported: %v %v", supported, err)
	}
}
