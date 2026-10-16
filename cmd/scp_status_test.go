package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

// The status call owns its binding and worker; the fixture owns the signal.
// A context-aware sink makes cancellation deterministic without timing sleeps.
type blockedSCPStatusWriter struct{ started chan struct{} }

func (*blockedSCPStatusWriter) Write([]byte) (int, error) { panic("unbound status output") }
func (w *blockedSCPStatusWriter) WriteContext(ctx context.Context, _ []byte) (int, error) {
	close(w.started)
	<-ctx.Done()
	return 0, ctx.Err()
}

func TestSCPTransferStatusCancellation(t *testing.T) {
	for _, stream := range []string{"stderr", "stdout"} {
		t.Run(stream, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			writer := &blockedSCPStatusWriter{started: make(chan struct{})}
			done := make(chan error, 1)
			go func() { done <- NewScpOptions().writeTransferStatus(ctx, writer, stream, "status") }()
			select {
			case <-writer.started:
			case <-time.After(2 * time.Second):
				cancel()
				<-done
				t.Fatal("status write did not start")
			}
			cancel()
			select {
			case err := <-done:
				var outputErr *SCPOutputError
				if !errors.Is(err, context.Canceled) || !errors.As(err, &outputErr) || outputErr.Stream != stream {
					t.Fatalf("output cancellation or stream lost: %v", err)
				}
			case <-time.After(2 * time.Second):
				<-done
				t.Fatal("status writer did not join after cancellation")
			}
		})
	}
}

func TestSCPTransferStatusOutput(t *testing.T) {
	for _, stream := range []string{"stderr", "stdout"} {
		t.Run(stream, func(t *testing.T) {
			options := NewScpOptions()
			var output bytes.Buffer
			if err := options.writeTransferStatus(t.Context(), &output, stream, "status"); err != nil {
				t.Fatal(err)
			}
			if output.String() != "status\n" {
				t.Fatalf("status changed: %q", output.String())
			}
			options.Quiet = true
			if err := options.writeTransferStatus(t.Context(), &output, stream, "hidden"); err != nil {
				t.Fatal(err)
			}
			if output.String() != "status\n" {
				t.Fatalf("quiet status was written: %q", output.String())
			}
			options.Quiet = false
			unsupported := &unsupportedSCPDiagnosticWriter{}
			if err := options.writeTransferStatus(t.Context(), unsupported, stream, "unsupported"); err != nil {
				t.Fatal(err)
			}
			if unsupported.calls.Load() != 0 {
				t.Fatal("unsupported sink was written")
			}
			err := options.writeTransferStatus(t.Context(), failingSCPDiagnosticWriter{}, stream, "failed")
			var outputErr *SCPOutputError
			if !errors.Is(err, io.ErrClosedPipe) || !errors.As(err, &outputErr) || outputErr.Stream != stream {
				t.Fatalf("write failure lost: %v", err)
			}
		})
	}
}
