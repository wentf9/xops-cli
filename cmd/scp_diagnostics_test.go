package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"
	corelog "github.com/wentf9/xops-cli/core/log"
	"github.com/wentf9/xops-cli/core/ssh"
)

func TestSCPQuietVerboseOrder(t *testing.T) {
	for _, tc := range []struct {
		args           []string
		quiet, verbose bool
		level          int
	}{
		{nil, false, false, 3},
		{[]string{"-q"}, true, false, 0},
		{[]string{"-v"}, false, true, 5},
		{[]string{"-qv"}, true, true, 5},
		{[]string{"-vq"}, true, true, 0},
		{[]string{"-vqv"}, true, true, 1},
		{[]string{"-qvv"}, true, true, 6},
		{[]string{"-vvvq"}, true, true, 0},
		{[]string{"--quiet", "--verbose"}, true, true, 5},
	} {
		o := NewScpOptions()
		cmd := &cobra.Command{}
		o.registerOutputFlags(cmd)
		if err := cmd.ParseFlags(tc.args); err != nil {
			t.Fatal(err)
		}
		if o.Quiet != tc.quiet || o.Verbose != tc.verbose || o.sshLogLevel != tc.level {
			t.Errorf("%v: quiet=%v verbose=%v SSH level=%d", tc.args, o.Quiet, o.Verbose, o.sshLogLevel)
		}
	}
	if err := NewCmdScp().ParseFlags([]string{"--progress"}); err == nil {
		t.Fatal("removed --progress accepted")
	}
}

//nolint:gocyclo // Exercise the direction/flag/error matrix with one fixture ownership path.
func TestSCPDiagnosticTransfers(t *testing.T) {
	for _, mode := range []string{"upload", "download", "relay", "selector", "failure", "cancel"} {
		for _, flags := range []string{"-v", "-qv", "-vq", "-vv", "-vvv", "-vvq", "-vvvq", "-vqv"} {
			t.Run(mode+flags, func(t *testing.T) {
				o := NewScpOptions()
				cmd := &cobra.Command{}
				o.registerOutputFlags(cmd)
				if err := cmd.ParseFlags([]string{flags}); err != nil {
					t.Fatal(err)
				}
				var output bytes.Buffer
				d, err := newSCPDiagnostics(t.Context(), &output, "stderr", o.sshLogLevel >= 5, o.verboseLevel)
				if err != nil {
					t.Fatal(err)
				}
				o.diagnostics = d
				fixture := newSCPTransferFixture(t, ssh.WithDiagnostics(d))
				local := filepath.Join(t.TempDir(), "payload.txt")
				writeSCPTestFile(t, local, "file-content-must-not-appear-in-diagnostics")
				writeSCPTestFile(t, filepath.Join(fixture.home, "remote.txt"), "remote-content-must-not-appear-in-diagnostics")
				o.Source, o.Dest = local, "scp-test:uploaded.txt"
				ctx := fixture.ctx
				switch mode {
				case "download":
					o.Source, o.Dest = "scp-test:remote.txt", filepath.Join(t.TempDir(), "download.txt")
				case "relay":
					o.Source, o.Dest = "scp-test:remote.txt", "scp-test:relayed.txt"
				case "selector":
					o.Host, o.Dest = "scp-test", "selected.txt"
				case "failure":
					o.Source = filepath.Join(t.TempDir(), "does-not-exist")
				case "cancel":
					canceled, cancel := context.WithCancel(ctx)
					cancel()
					ctx = canceled
				}
				err = o.runTransfer(ctx, fixture.repo, fixture.connector)
				if mode == "failure" || mode == "cancel" {
					if err == nil {
						t.Fatal("quiet/verbose swallowed transfer error")
					}
					if mode == "cancel" && !errors.Is(err, context.Canceled) {
						t.Fatalf("cancellation lost: %v", err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
				if err := fixture.connector.CloseAll(); err != nil {
					t.Fatal(err)
				}
				if err := d.finish(); err != nil {
					t.Fatal(err)
				}
				text := output.String()
				if !strings.Contains(text, "scp: transfer starting:") {
					t.Fatalf("missing SCP diagnostics: %q", text)
				}
				if got := strings.Contains(text, "debug1: Connecting to"); got != (o.sshLogLevel >= scpSSHDebug1) {
					t.Fatalf("SSH quiet precedence: %q", text)
				}
				if o.sshLogLevel >= scpSSHDebug1 {
					for _, want := range []string{"Connection established", "Server host key", "SHA256:", "Authenticated to", "kex: algorithm:", "SFTP subsystem ready"} {
						if want == "SFTP subsystem ready" && mode == "cancel" {
							continue
						}
						if !strings.Contains(text, want) {
							t.Errorf("missing %q: %s", want, text)
						}
					}
				}
				if mode != "cancel" {
					if got := strings.Contains(text, "scp: debug2:"); got != (o.verboseLevel >= 2) {
						t.Fatalf("DEBUG2 filtering: %s", text)
					}
					if got := strings.Contains(text, "scp: debug3:"); got != (o.verboseLevel >= 3) {
						t.Fatalf("DEBUG3 filtering: %s", text)
					}
				}

				if strings.Contains(text, "content-must-not-appear") || strings.Contains(text, "Next authentication method") {
					t.Fatalf("file contents leaked or none-auth success misreported: %q", text)
				}
			})
		}
	}
}

func TestSCPDiagnosticBoundAndEscape(t *testing.T) {
	var output bytes.Buffer
	gate := make(chan struct{})
	var release sync.Once
	writer := &gatedSCPDiagnosticWriter{target: &output, gate: gate}
	d, err := newSCPDiagnostics(t.Context(), writer, "stderr", true, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		release.Do(func() { close(gate) })
		if err := d.finish(); err != nil {
			t.Error(err)
		}
	})
	var producers sync.WaitGroup
	for range 4 {
		producers.Go(func() {
			for range 500 {
				d.ObserveDiagnostic(corelog.Diagnostic{Kind: corelog.ConnectionReused, NodeID: "host\x1b[31m\n" + strings.Repeat("x", 5000)})
			}
		})
	}
	producers.Wait()
	release.Do(func() { close(gate) })
	if err := d.finish(); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if strings.Contains(text, "\x1b") || !strings.Contains(text, `\x1b`) || !strings.Contains(text, "omitted") || output.Len() > 128*1024 {
		t.Fatalf("unbounded or unescaped diagnostics: size=%d", output.Len())
	}
}

func TestSCPDiagnosticBlockedPipe(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("cancelable file bindings currently require Linux")
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer closeSCPTestResource(t, reader)
	defer closeSCPTestResource(t, writer)
	d, err := newSCPDiagnostics(t.Context(), writer, "stderr", true, 1)
	if err != nil {
		t.Fatal(err)
	}
	for range 10000 {
		d.ObserveDiagnostic(corelog.Diagnostic{Kind: corelog.ConnectionReused, NodeID: strings.Repeat("x", 256)})
	}
	start := time.Now()
	if err := d.finish(); err == nil {
		t.Fatal("blocked sink error lost")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("blocked stderr delayed shutdown")
	}
	// The caller still owns the pipe after the binding has closed.
	if _, err := writer.Stat(); err != nil {
		t.Fatalf("borrowed stderr closed: %v", err)
	}
}

type failingSCPDiagnosticWriter struct{}

func (failingSCPDiagnosticWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (failingSCPDiagnosticWriter) WriteContext(context.Context, []byte) (int, error) {
	return 0, io.ErrClosedPipe
}

type gatedSCPDiagnosticWriter struct {
	target io.Writer
	gate   <-chan struct{}
}

func (w *gatedSCPDiagnosticWriter) Write([]byte) (int, error) { panic("unbound diagnostic write") }
func (w *gatedSCPDiagnosticWriter) WriteContext(ctx context.Context, p []byte) (int, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-w.gate:
		return w.target.Write(p)
	}
}

type unsupportedSCPDiagnosticWriter struct{ calls atomic.Int32 }

func (w *unsupportedSCPDiagnosticWriter) Write([]byte) (int, error) {
	w.calls.Add(1)
	return 0, io.ErrClosedPipe
}

func TestSCPUnsupportedDiagnosticOutputIsNeverWritten(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	writer := &unsupportedSCPDiagnosticWriter{}
	d, err := newSCPDiagnostics(ctx, writer, "stderr", true, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !d.disabled {
		t.Fatal("unsupported output not disabled")
	}
	d.transfer("source", "destination", "completed")
	for range 1000 {
		d.ObserveDiagnostic(corelog.Diagnostic{Kind: corelog.ConnectionReused})
	}
	cancel()
	if err := d.finish(); err != nil {
		t.Fatal(err)
	}
	if err := d.finish(); err != nil {
		t.Fatal(err)
	}
	if writer.calls.Load() != 0 {
		t.Fatal("unsupported writer invoked")
	}
}

func TestSCPDiagnosticWriteError(t *testing.T) {
	d, err := newSCPDiagnostics(t.Context(), failingSCPDiagnosticWriter{}, "stderr", true, 1)
	if err != nil {
		t.Fatal(err)
	}
	d.transfer("source", "destination", "failed")
	if err := d.finish(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("lost sink failure: %v", err)
	}
	var outputErr *SCPOutputError
	if !errors.As(d.finish(), &outputErr) {
		t.Fatal("output failure classification lost")
	}
}

func TestSCPVerboseLargeTransfer(t *testing.T) {
	for _, mode := range []string{"upload", "download", "relay"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newSCPTransferFixture(t)
			payload := strings.Repeat("large-file-private-payload-marker", 65536)
			local := filepath.Join(t.TempDir(), "large.txt")
			writeSCPTestFile(t, local, payload)
			writeSCPTestFile(t, filepath.Join(fixture.home, "large-source.txt"), payload)
			o := NewScpOptions()
			o.Quiet = true
			o.ThreadCount = 4
			var output bytes.Buffer
			d, err := newSCPDiagnostics(fixture.ctx, &output, "stderr", false, 3)
			if err != nil {
				t.Fatal(err)
			}
			o.diagnostics = d
			o.Source, o.Dest = local, "scp-test:large-upload.txt"
			result := filepath.Join(fixture.home, "large-upload.txt")
			switch mode {
			case "download":
				o.Source, o.Dest = "scp-test:large-source.txt", filepath.Join(t.TempDir(), "large-download.txt")
				result = o.Dest
			case "relay":
				o.Source, o.Dest = "scp-test:large-source.txt", "scp-test:large-relay.txt"
				result = filepath.Join(fixture.home, "large-relay.txt")
			}
			transferErr := o.runTransfer(fixture.ctx, fixture.repo, fixture.connector)
			closeErr := fixture.connector.CloseAll()
			outputErr := d.finish()
			if err := errors.Join(transferErr, closeErr, outputErr); err != nil {
				t.Fatal(err)
			}
			assertSCPTestFile(t, result, payload)
			text := output.String()
			if !strings.Contains(text, "SSH2_FXP_STATUS") || !strings.Contains(text, "scp: debug3:") {
				t.Fatalf("no packet diagnostics: %s", text)
			}
			if strings.Contains(text, "private-payload-marker") {
				t.Fatal("file contents leaked")
			}
		})
	}
}
