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

	corelog "github.com/wentf9/xops-cli/core/log"
	"github.com/wentf9/xops-cli/core/ssh"
)

func TestSSHDiagnosticFlags(t *testing.T) {
	for _, tc := range []struct {
		flags []string
		level int
	}{
		{nil, 3}, {[]string{"-v"}, 5}, {[]string{"-vv"}, 6}, {[]string{"-vvv"}, 7},
		{[]string{"-vvvvv"}, 7}, {[]string{"-qv"}, 5}, {[]string{"-vq"}, 0},
		{[]string{"-vqv"}, 1}, {[]string{"-qvv"}, 6}, {[]string{"--verbose", "--verbose"}, 6},
		{[]string{"-v", "--verbose=false"}, 3},
	} {
		o := NewSshOptions()
		command := newCmdSshWithOptions(o)
		if err := command.ParseFlags(tc.flags); err != nil {
			t.Fatal(err)
		}
		if o.diagnostic.level != tc.level {
			t.Errorf("%v: level=%d want=%d", tc.flags, o.diagnostic.level, tc.level)
		}
	}
	for _, args := range [][]string{
		{"-vvv", "host", "printf", "-v"}, {"host", "-vv", "printf", "-v"},
		{"--host", "host", "-v", "printf", "-v"},
	} {
		o := NewSshOptions()
		command := newCmdSshWithOptions(o)
		if err := command.ParseFlags(preprocessSubArgs(args, command)); err != nil {
			t.Fatal(err)
		}
		remaining := command.Flags().Args()
		if len(remaining) < 2 || remaining[len(remaining)-1] != "-v" || remaining[len(remaining)-2] != "printf" {
			t.Fatalf("remote verbose consumed as local flag: %v -> %v", args, remaining)
		}
	}
}

func TestSSHDiagnosticLevelsAndRedaction(t *testing.T) {
	for level := 1; level <= 3; level++ {
		var output bytes.Buffer
		d, err := newSSHDiagnostics(t.Context(), &output, level)
		if err != nil {
			t.Fatal(err)
		}
		d.ObserveDiagnostic(corelog.Diagnostic{Kind: corelog.Connecting, Host: "host\x1b[31m\n" + strings.Repeat("x", 5000), Port: 22})
		d.ObserveDiagnostic(corelog.Diagnostic{Kind: corelog.SessionRequest, Level: 2, Operation: "exec", Outcome: "accepted"})
		d.ObserveDiagnostic(corelog.Diagnostic{Kind: corelog.SessionCleanup, Level: 3, Outcome: "completed"})
		d.ObserveDiagnostic(corelog.Diagnostic{Kind: corelog.SessionFinished, Outcome: "unknown"})
		d.ObserveDiagnostic(corelog.Diagnostic{Kind: corelog.SessionFinished, HasExitCode: true, ExitCode: 27})
		if err := d.finish(); err != nil {
			t.Fatal(err)
		}
		text := output.String()
		if strings.Contains(text, "\x1b") || !strings.Contains(text, `\x1b`) || len(text) > 4096 {
			t.Fatalf("unescaped/unbounded output: %q", text)
		}
		if strings.Contains(text, "debug2:") != (level >= 2) || strings.Contains(text, "debug3:") != (level >= 3) {
			t.Fatalf("incorrect level %d: %s", level, text)
		}
		if !strings.Contains(text, "Exit status 27") || strings.Contains(text, "Exit status 0") || !strings.Contains(text, "no confirmed exit status") {
			t.Fatalf("exit result fabricated: %s", text)
		}
	}
}

func TestSSHDiagnosticPromptGateCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	gate := make(chan struct{}, 1) // A prompt owns the token.
	var output bytes.Buffer
	d, err := newSSHDiagnostics(ctx, &output, 3, gate)
	if err != nil {
		t.Fatal(err)
	}
	for range 1000 {
		d.ObserveDiagnostic(corelog.Diagnostic{Kind: corelog.Connecting})
	}
	cancel()
	if err := d.finish(); !errors.Is(err, context.Canceled) {
		t.Fatalf("prompt wait cancellation lost: %v", err)
	}
	if output.Len() != 0 {
		t.Fatal("diagnostics wrote through active prompt")
	}
	// The worker must not release a prompt gate it never acquired.
	select {
	case <-gate:
		t.Fatal("borrowed prompt token fabricated")
	default:
	}
}

func TestSSHDiagnosticPromptGateRelease(t *testing.T) {
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	var output bytes.Buffer
	d, err := newSSHDiagnostics(t.Context(), &output, 1, gate)
	if err != nil {
		t.Fatal(err)
	}
	d.ObserveDiagnostic(corelog.Diagnostic{Kind: corelog.Connected, NodeID: "fixture"})
	if err := d.finish(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Connection established") {
		t.Fatal("gate prevented ordinary diagnostics")
	}
	select {
	case <-gate:
	default:
		t.Fatal("borrowed prompt token not released")
	}
}

func TestSSHDiagnosticOutputFailuresAndUnsupported(t *testing.T) {
	d, err := newSSHDiagnostics(t.Context(), failingSCPDiagnosticWriter{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	d.ObserveDiagnostic(corelog.Diagnostic{Kind: corelog.Connecting})
	var failure *ssh.OutputError
	if err := d.finish(); !errors.Is(err, io.ErrClosedPipe) || !errors.As(err, &failure) {
		t.Fatalf("output identity/error lost: %v", err)
	}
	unsupported := &unsupportedSCPDiagnosticWriter{}
	d, err = newSSHDiagnostics(t.Context(), unsupported, 3)
	if err != nil {
		t.Fatal(err)
	}
	d.ObserveDiagnostic(corelog.Diagnostic{Kind: corelog.Connecting})
	if err := d.finish(); err != nil {
		t.Fatal(err)
	}
	if unsupported.calls.Load() != 0 {
		t.Fatal("unsupported output invoked")
	}
}

func TestSSHDiagnosticQueueBounded(t *testing.T) {
	var output bytes.Buffer
	gate := make(chan struct{})
	var release sync.Once
	d, err := newSSHDiagnostics(t.Context(), &gatedSCPDiagnosticWriter{target: &output, gate: gate}, 3)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { release.Do(func() { close(gate) }); _ = d.finish() })
	var producers sync.WaitGroup
	for range 4 {
		producers.Go(func() {
			for range 500 {
				d.ObserveDiagnostic(corelog.Diagnostic{Kind: corelog.ConnectionReused, NodeID: strings.Repeat("x", 5000)})
			}
		})
	}
	producers.Wait()
	release.Do(func() { close(gate) })
	if err := d.finish(); err != nil {
		t.Fatal(err)
	}
	if output.Len() > 128*1024 || !strings.Contains(output.String(), "omitted") {
		t.Fatal("queue was not bounded")
	}
}

func TestSSHDiagnosticBlockedPipe(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer closeSCPTestResource(t, reader)
	defer closeSCPTestResource(t, writer)
	d, err := newSSHDiagnostics(t.Context(), writer, 3)
	if err != nil {
		t.Fatal(err)
	}
	if d.disabled {
		_ = d.finish()
		t.Skip("platform pipe binding unsupported")
	}
	for range 10000 {
		d.ObserveDiagnostic(corelog.Diagnostic{Kind: corelog.ConnectionReused, NodeID: strings.Repeat("x", 256)})
	}
	start := time.Now()
	if err := d.finish(); err == nil {
		t.Fatal("blocked stderr failure lost")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("blocked diagnostic delayed shutdown")
	}
	if _, err := writer.Stat(); err != nil {
		t.Fatal("borrowed stderr closed")
	}
}
