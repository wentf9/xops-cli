package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	corelog "github.com/wentf9/xops-cli/core/log"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
)

func tunnelOutputFixture(t *testing.T, ctx context.Context) *ssh.Client {
	t.Helper()
	server, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
	})
	host, portText, err := net.SplitHostPort(server.Address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	connector := ssh.NewConnector(tunnelTestProvider{cfg: &ssh.ClientConfig{
		NodeID: "tunnel-output-fixture", Address: host, Port: port, User: "fixture", AuthType: "password", Password: sshfixture.Password,
	}}, ssh.WithHostKeyVerifier(execFixtureVerifier{server.HostKey}))
	t.Cleanup(func() {
		if err := connector.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	client, err := connector.Connect(ctx, "tunnel-output-fixture")
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func unusedTunnelAddresses(t *testing.T) (string, string) {
	t.Helper()
	first, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer closeTunnelTestResource(t, first)
	second, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer closeTunnelTestResource(t, second)
	// Reserve both together so the destination cannot be the forwarding
	// listener itself through immediate ephemeral-port reuse.
	return first.Addr().String(), second.Addr().String()
}

//nolint:gocyclo // Keep pipe, fixture and callback lifetimes together across the forward/verbosity matrix.
func TestSSHTunnelErrorsDoNotRewriteBlockedStderr(t *testing.T) {
	for _, mode := range []string{"local", "remote", "SOCKS5"} {
		for _, verbose := range []bool{false, true} {
			t.Run(mode+"/verbose="+strconv.FormatBool(verbose), func(t *testing.T) {
				reader, writer, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				original := os.Stderr
				os.Stderr = writer
				var group *sshTunnelGroup
				var diagnostics *sshDiagnostics
				drained := make(chan struct{})
				var drainOnce sync.Once
				startDrain := func() { drainOnce.Do(func() { go func() { _, _ = io.Copy(io.Discard, reader); close(drained) }() }) }
				// Registered before fixture cleanup, so no borrowed sink closes while its
				// callbacks can still run. Draining also unblocks the deliberately unfixed
				// implementation when this regression is run through a temporary overlay.
				t.Cleanup(func() {
					startDrain()
					if group != nil {
						_ = group.Close()
					}
					if diagnostics != nil {
						_ = diagnostics.finish()
					}
					os.Stderr = original
					_ = writer.Close()
					<-drained
					_ = reader.Close()
				})
				fillTunnelOutputPipe(t, writer)
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				options := &SshOptions{NoCmd: true}
				if verbose {
					diagnostics, err = newSSHDiagnostics(ctx, writer, 3)
					if err != nil {
						t.Fatal(err)
					}
					options.diagnostics = diagnostics
					diagnostics.ObserveDiagnostic(corelog.Diagnostic{Kind: corelog.Connected, NodeID: "fixture"})
					end := time.Now().Add(3 * time.Second)
					for {
						_, err := diagnostics.writer.Write(nil)
						if errors.Is(err, context.Canceled) {
							break
						}
						if time.Now().After(end) {
							t.Fatal("diagnostic output did not time out")
						}
						time.Sleep(10 * time.Millisecond)
					}
				}
				client := tunnelOutputFixture(t, ctx)
				listenAddr, destination := unusedTunnelAddresses(t)
				switch mode {
				case "local":
					options.LocalForwards = []string{listenAddr + ":" + destination}
				case "remote":
					options.RemoteForwards = []string{listenAddr + ":" + destination}
				case "SOCKS5":
					options.DynamicForward = listenAddr
				}
				// Keep the command's output context separate from cancellation of tunnels
				// and the session, exactly as runConnection does.
				runCtx, stopRun := context.WithCancel(ctx)
				defer stopRun()
				group, err = options.startTunnels(ctx, stopRun, client)
				if err != nil {
					t.Fatal(err)
				}
				// Three rejections exhaust any small remainder left by a canceled write.
				for range 3 {
					requestRejectedTunnelConnection(t, listenAddr, mode == "SOCKS5", destination)
				}
				// Callback entry is synchronous with the protected enqueue. For the old
				// implementation, allow its raw fprintf to start before canceling.
				time.Sleep(30 * time.Millisecond)
				joined := make(chan error, 1)
				go func() { joined <- group.Close() }()
				var closeErr error
				select {
				case closeErr = <-joined:
				case <-time.After(3 * time.Second):
					t.Error("tunnel shutdown blocked writing an already-full stderr")
					startDrain()
					closeErr = <-joined
				}
				if runCtx.Err() == nil {
					t.Fatal("closing tunnels did not stop the session context")
				}
				if verbose {
					if closeErr != nil {
						t.Fatalf("borrowed diagnostic queue closed by tunnels: %v", closeErr)
					}
					closeErr = diagnostics.finish()
				}
				var outputErr *ssh.OutputError
				if !errors.As(closeErr, &outputErr) || !outputErr.TargetsFile(writer) || !HasStandardOutputError(closeErr) {
					t.Fatalf("blocked output identity or error lost: %v", closeErr)
				}
				if _, err := writer.Stat(); err != nil {
					t.Fatalf("borrowed stderr closed: %v", err)
				}
			})
		}
	}
}

func TestSSHTunnelReadyOutputOwnership(t *testing.T) {
	group, _ := newSSHTunnelGroup(t.Context(), nil)
	var output bytes.Buffer
	if err := group.reportReady(t.Context(), &output, "fixture"); err != nil {
		t.Fatal(err)
	}
	if err := group.Close(); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "SSH tunnels established to fixture. Press Ctrl+C to exit.\n" {
		t.Fatalf("stdout status changed: %q", got)
	}
	if err := group.Close(); err != nil {
		t.Fatal(err)
	}
	group, _ = newSSHTunnelGroup(t.Context(), nil)
	if err := group.reportReady(t.Context(), failingSCPDiagnosticWriter{}, "fixture"); err != nil {
		t.Fatal(err)
	}
	if err := group.Close(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("stdout error lost: %v", err)
	}
}

func TestSSHTunnelCloseFlushesOwnedErrorOutput(t *testing.T) {
	ctx, stopCommand := context.WithCancel(t.Context())
	defer stopCommand()
	runCtx, stopRun := context.WithCancel(ctx)
	defer stopRun()
	group, _ := newSSHTunnelGroup(ctx, stopRun)
	t.Cleanup(func() { _ = group.Close() })
	var output bytes.Buffer
	stderr, err := newSSHDiagnostics(ctx, &output, 0)
	if err != nil {
		t.Fatal(err)
	}
	group.stderr, group.ownsStderr = stderr, true
	stderr.message("ssh forwarding failure\n")
	if err := group.Close(); err != nil {
		t.Fatal(err)
	}
	if runCtx.Err() == nil || ctx.Err() != nil {
		t.Fatal("tunnel shutdown canceled the wrong context")
	}
	if output.String() != "ssh forwarding failure\n" {
		t.Fatalf("normal shutdown lost pending errors: %q", output.String())
	}
	output.WriteString("caller")
}

func TestSSHTunnelReadyBlockedSharedOutput(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer closeSCPTestResource(t, reader)
	defer closeSCPTestResource(t, writer)
	fillTunnelOutputPipe(t, writer)
	group, _ := newSSHTunnelGroup(t.Context(), nil)
	start := time.Now()
	// stdout may alias the same full pipe as stderr. Enqueue, never raw fprintf.
	if err := group.reportReady(t.Context(), writer, "fixture"); err != nil {
		t.Fatal(err)
	}
	var outputErr *ssh.OutputError
	if err := group.Close(); !errors.As(err, &outputErr) || !outputErr.TargetsFile(writer) {
		t.Fatalf("blocked stdout error lost: %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("stdout status blocked tunnel cleanup")
	}
	if _, err := writer.Stat(); err != nil {
		t.Fatalf("borrowed stdout closed: %v", err)
	}
}
