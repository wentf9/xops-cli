package sshenv

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	core "github.com/wentf9/xops-cli/core/ssh"
	cryptoSSH "golang.org/x/crypto/ssh"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestHelperProxyRelay is invoked as a subprocess by tests in this package when
// XOPS_SSHENV_HELPER_MODE is set, providing a deterministic zero-dependency child
// binary across Linux, macOS, and Windows.
func TestHelperProxyRelay(t *testing.T) {
	mode := os.Getenv("XOPS_SSHENV_HELPER_MODE")
	if mode == "" {
		return
	}
	switch mode {
	case "echo-with-stderr":
		_, _ = fmt.Fprintln(os.Stderr, "proxy-stderr-diag-1")
		_, _ = fmt.Fprintln(os.Stderr, "proxy-stderr-diag-2")
		_, _ = io.Copy(os.Stdout, os.Stdin)
	case "tcp-relay":
		addr := os.Getenv("XOPS_SSHENV_HELPER_TARGET")
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "relay dial failed: %v\n", err)
			os.Exit(2)
		}
		_, _ = fmt.Fprintln(os.Stderr, "relay-connected")
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = io.Copy(os.Stdout, conn)
		}()
		_, _ = io.Copy(conn, os.Stdin)
		_ = conn.Close()
		<-done
	case "local-cmd":
		inBytes, _ := io.ReadAll(os.Stdin)
		_, _ = fmt.Fprintf(os.Stdout, "stdin-len=%d arg=%s\n", len(inBytes), os.Getenv("XOPS_SSHENV_HELPER_ARG"))
		_, _ = fmt.Fprintln(os.Stderr, "local-cmd-stderr")
	case "local-cmd-fail":
		_, _ = fmt.Fprintln(os.Stderr, "local-cmd-failing")
		os.Exit(7)
	case "hang":
		_, _ = os.Stdout.Write([]byte("R"))
		time.Sleep(30 * time.Second)
	}
	os.Exit(0)
}

func helperSubprocessCommand(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable failed: %v", err)
	}
	return fmt.Sprintf(`"%s" -test.run=^TestHelperProxyRelay$`, exe)
}

func TestDefaultDialProxyCommand_StdioStreamIsolationAndCleanEOF(t *testing.T) {
	t.Setenv("XOPS_SSHENV_HELPER_MODE", "echo-with-stderr")
	baselineGoroutines := runtime.NumGoroutine()

	var stderrBuf syncBuffer
	conn, err := DialProxyCommandWithStderr(t.Context(), helperSubprocessCommand(t), &stderrBuf)
	if err != nil {
		t.Fatalf("DialProxyCommandWithStderr failed: %v", err)
	}

	payload := []byte("\x00\xffSSH-2.0-BinaryFrame\r\n\x01\x02\x03\xfe")
	if _, err := conn.Write(payload); err != nil {
		_ = conn.Close()
		t.Fatalf("conn.Write failed: %v", err)
	}

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		_ = conn.Close()
		t.Fatalf("io.ReadFull failed: %v", err)
	}
	if !bytes.Equal(got, payload) {
		_ = conn.Close()
		t.Fatalf("stdout stream corrupted: got %x, want %x", got, payload)
	}

	// Idempotent Close() joins both cmd.Wait() and stderr forwarder cleanly.
	if err := conn.Close(); err != nil {
		t.Fatalf("first conn.Close() failed: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("second conn.Close() failed: %v", err)
	}

	stderrText := stderrBuf.String()
	if !strings.Contains(stderrText, "proxy-stderr-diag-1") || !strings.Contains(stderrText, "proxy-stderr-diag-2") {
		t.Fatalf("expected stderr lines in stderr writer, got %q", stderrText)
	}

	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Read after Close = %v, want net.ErrClosed", err)
	}
	if _, err := conn.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write after Close = %v, want net.ErrClosed", err)
	}

	assertGoroutinesSettled(t, baselineGoroutines)
}

func TestDefaultDialProxyCommand_DeadlinesAndValidation(t *testing.T) {
	if _, err := DefaultDialProxyCommand(t.Context(), "   "); err == nil {
		t.Fatal("expected empty command to fail")
	}
	if _, err := DefaultDialProxyCommand(t.Context(), "none"); err == nil {
		t.Fatal("expected 'none' command to fail")
	}
	if _, err := DefaultDialProxyCommand(t.Context(), "nc\x00evil"); err == nil {
		t.Fatal("expected NUL byte in command to fail")
	}

	canceledCtx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := DefaultDialProxyCommand(canceledCtx, helperSubprocessCommand(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context error = %v, want context.Canceled", err)
	}

	t.Setenv("XOPS_SSHENV_HELPER_MODE", "hang")
	conn, err := DialProxyCommandWithStderr(t.Context(), helperSubprocessCommand(t), io.Discard)
	if err != nil {
		t.Fatalf("DialProxyCommandWithStderr(hang) failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Wait for child to emit 1-byte readiness marker.
	ready := make([]byte, 1)
	if _, err := io.ReadFull(conn, ready); err != nil {
		t.Fatalf("read ready byte failed: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline failed: %v", err)
	}
	_, err = conn.Read(make([]byte, 8))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read after deadline = %v, want os.ErrDeadlineExceeded", err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("clear SetDeadline failed: %v", err)
	}
}

func TestDefaultRunLocalCommand_DevNullStdinCaptureAndCancel(t *testing.T) {
	t.Setenv("XOPS_SSHENV_HELPER_MODE", "local-cmd")
	t.Setenv("XOPS_SSHENV_HELPER_ARG", "hello-local")

	var stdoutBuf, stderrBuf syncBuffer
	if err := RunLocalCommandWithIO(t.Context(), helperSubprocessCommand(t), &stdoutBuf, &stderrBuf); err != nil {
		t.Fatalf("RunLocalCommandWithIO failed: %v", err)
	}
	if got := strings.TrimSpace(stdoutBuf.String()); got != "stdin-len=0 arg=hello-local" {
		t.Fatalf("LocalCommand stdout = %q, want 'stdin-len=0 arg=hello-local'", got)
	}
	if !strings.Contains(stderrBuf.String(), "local-cmd-stderr") {
		t.Fatalf("LocalCommand stderr = %q, want local-cmd-stderr", stderrBuf.String())
	}

	// Non-zero exit returns error.
	t.Setenv("XOPS_SSHENV_HELPER_MODE", "local-cmd-fail")
	if err := RunLocalCommandWithIO(t.Context(), helperSubprocessCommand(t), io.Discard, io.Discard); err == nil {
		t.Fatal("expected non-zero LocalCommand exit code to return error")
	}

	// Context cancellation kills hung LocalCommand promptly.
	t.Setenv("XOPS_SSHENV_HELPER_MODE", "hang")
	ctx, cancel := context.WithTimeout(t.Context(), 80*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := RunLocalCommandWithIO(ctx, helperSubprocessCommand(t), io.Discard, io.Discard)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled RunLocalCommandWithIO error = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("RunLocalCommandWithIO cancellation took %v, expected prompt termination", elapsed)
	}
}

type singleNodeProvider struct {
	cfg *core.ClientConfig
}

func (p singleNodeProvider) GetConfig(string) (*core.ClientConfig, error) {
	c := *p.cfg
	c.Options = p.cfg.Options.Clone()
	return &c, nil
}

func TestDefaultDialProxyCommand_EndToEndWithSSHConnector(t *testing.T) {
	ln, srvAddr := startLocalTestSSHServer(t, "phase5-relay-pw")
	defer func() { _ = ln.Close() }()

	t.Setenv("XOPS_SSHENV_HELPER_MODE", "tcp-relay")
	t.Setenv("XOPS_SSHENV_HELPER_TARGET", srvAddr)

	opts := &core.Options{}
	if err := opts.Set(core.OptionProxyCommand, helperSubprocessCommand(t)); err != nil {
		t.Fatalf("Set ProxyCommand failed: %v", err)
	}
	_ = opts.Set(core.OptionStrictHostKeyChecking, "no")

	var proxyStderr syncBuffer
	env := Discover()
	env.KnownHostsFile = filepath.Join(t.TempDir(), "known_hosts")
	env.GlobalKnownHostsFiles = nil
	env.DialProxyCommand = func(ctx context.Context, cmd string) (net.Conn, error) {
		return DialProxyCommandWithStderr(ctx, cmd, &proxyStderr)
	}

	connector := core.NewConnector(
		singleNodeProvider{cfg: &core.ClientConfig{
			NodeID:       "relay-node",
			OriginalHost: "relay-node",
			Address:      "10.99.88.77",
			Port:         2222,
			User:         "relayuser",
			AuthType:     "password",
			Password:     "phase5-relay-pw",
			Options:      opts,
		}},
		core.WithEnvironment(env),
	)

	client, err := connector.Connect(t.Context(), "relay-node")
	if err != nil {
		t.Fatalf("Connector.Connect via DefaultDialProxyCommand failed: %v", err)
	}
	// Note: Connector.initializeConnection has already canceled its internal handshake
	// coordinator context here — client.Run verifies ProcessStdioConn survives post-handshake!
	out, err := client.Run(t.Context(), "echo live")
	if err != nil {
		_ = connector.CloseAll()
		t.Fatalf("client.Run after handshake over ProcessStdioConn failed: %v", err)
	}
	if strings.TrimSpace(out) != "relay-ok" {
		_ = connector.CloseAll()
		t.Fatalf("client.Run output = %q, want relay-ok", out)
	}
	if err := connector.CloseAll(); err != nil {
		t.Fatalf("connector.CloseAll failed: %v", err)
	}
	if !strings.Contains(proxyStderr.String(), "relay-connected") {
		t.Fatalf("expected relay stderr diagnostic, got %q", proxyStderr.String())
	}
}

func startLocalTestSSHServer(t *testing.T, password string) (net.Listener, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptoSSH.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	srvCfg := &cryptoSSH.ServerConfig{
		PasswordCallback: func(_ cryptoSSH.ConnMetadata, pass []byte) (*cryptoSSH.Permissions, error) {
			if string(pass) == password {
				return nil, nil
			}
			return nil, errors.New("bad password")
		},
	}
	srvCfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveLocalSSHConn(c, srvCfg)
		}
	}()
	return ln, ln.Addr().String()
}

func serveLocalSSHConn(c net.Conn, srvCfg *cryptoSSH.ServerConfig) {
	sConn, chans, reqs, err := cryptoSSH.NewServerConn(c, srvCfg)
	if err != nil {
		_ = c.Close()
		return
	}
	defer func() { _ = sConn.Close() }()
	go cryptoSSH.DiscardRequests(reqs)
	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			_ = newChan.Reject(cryptoSSH.UnknownChannelType, "unsupported")
			continue
		}
		ch, chReqs, chErr := newChan.Accept()
		if chErr != nil {
			continue
		}
		go func(ch cryptoSSH.Channel, in <-chan *cryptoSSH.Request) {
			defer func() { _ = ch.Close() }()
			for req := range in {
				if req.Type == "exec" {
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
					_, _ = io.WriteString(ch, "relay-ok\n")
					_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{Status: 0}))
					return
				}
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
			}
		}(ch, chReqs)
	}
}

func assertGoroutinesSettled(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= baseline+2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("goroutine count did not settle: got %d, baseline %d", runtime.NumGoroutine(), baseline)
}

type countingCloser struct {
	closed atomic.Int32
}

func (c *countingCloser) Close() error {
	c.closed.Add(1)
	return nil
}

func TestProcessStdioConn_FallbackDeadlineGenerationPreventsStaleClose(t *testing.T) {
	conn := &ProcessStdioConn{}
	readCloser := &countingCloser{}
	writeCloser := &countingCloser{}

	// Arm short deadlines, then immediately clear or extend them; stale callbacks must not close!
	for range 25 {
		if err := conn.setFallbackDeadline(readCloser, time.Now().Add(3*time.Millisecond), true); err != nil {
			t.Fatal(err)
		}
		if err := conn.setFallbackDeadline(readCloser, time.Time{}, true); err != nil {
			t.Fatal(err)
		}
		if err := conn.setFallbackDeadline(writeCloser, time.Now().Add(3*time.Millisecond), false); err != nil {
			t.Fatal(err)
		}
		if err := conn.setFallbackDeadline(writeCloser, time.Now().Add(5*time.Second), false); err != nil {
			t.Fatal(err)
		}
	}

	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 40 {
				_ = conn.setFallbackDeadline(readCloser, time.Now().Add(50*time.Millisecond), true)
				_ = conn.setFallbackDeadline(readCloser, time.Time{}, true)
			}
		})
	}
	wg.Wait()
	_ = conn.setFallbackDeadline(readCloser, time.Time{}, true)
	_ = conn.setFallbackDeadline(writeCloser, time.Time{}, false)

	time.Sleep(25 * time.Millisecond)
	if got := readCloser.closed.Load(); got != 0 {
		t.Fatalf("stale read timer closed pipe %d times after deadline clear", got)
	}
	if got := writeCloser.closed.Load(); got != 0 {
		t.Fatalf("stale write timer closed pipe %d times after deadline clear", got)
	}

	// An un-cleared short fallback deadline DOES fire and mark timedOut.
	if err := conn.setFallbackDeadline(readCloser, time.Now().Add(8*time.Millisecond), true); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for readCloser.closed.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("expected active fallback deadline to close pipe")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := conn.normalizeIOError(os.ErrClosed, true); !errors.Is(got, os.ErrDeadlineExceeded) {
		t.Fatalf("normalizeIOError after fallback expiry = %v, want os.ErrDeadlineExceeded", got)
	}
}

type blockingStderrWriter struct {
	startedOnce sync.Once
	started     chan struct{}
	unblock     chan struct{}
}

func (w *blockingStderrWriter) Write(p []byte) (int, error) {
	w.startedOnce.Do(func() { close(w.started) })
	<-w.unblock
	return len(p), nil
}

func TestProcessStdioConn_CloseDoesNotHangWhenStderrWriterBlocks(t *testing.T) {
	t.Setenv("XOPS_SSHENV_HELPER_MODE", "echo-with-stderr")
	bw := &blockingStderrWriter{
		started: make(chan struct{}),
		unblock: make(chan struct{}),
	}
	t.Cleanup(func() {
		close(bw.unblock)
	})

	conn, err := DialProxyCommandWithStderr(t.Context(), helperSubprocessCommand(t), bw)
	if err != nil {
		t.Fatalf("DialProxyCommandWithStderr failed: %v", err)
	}

	select {
	case <-bw.started:
	case <-time.After(3 * time.Second):
		_ = conn.Close()
		t.Fatal("timed out waiting for child stderr write to enter blocking writer")
	}

	start := time.Now()
	if err := conn.Close(); err != nil {
		t.Fatalf("conn.Close() with blocked stderr writer failed: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("conn.Close() took %v with blocked stderr writer, expected bounded wait", elapsed)
	}
}

type trackingCloser struct {
	closed atomic.Int32
}

func (c *trackingCloser) Close() error {
	c.closed.Add(1)
	return nil
}

func TestRound4_P2_12_FallbackDeadlineClearsWithoutStaleCloseTOCTOU(t *testing.T) {
	for range 200 {
		closer := &trackingCloser{}
		c := &ProcessStdioConn{}
		if err := c.setFallbackDeadline(closer, time.Now().Add(time.Millisecond), true); err != nil {
			t.Fatalf("setFallbackDeadline(arm): %v", err)
		}
		time.Sleep(time.Millisecond)
		if err := c.setFallbackDeadline(closer, time.Time{}, true); err != nil {
			t.Fatalf("setFallbackDeadline(clear): %v", err)
		}
		c.mu.Lock()
		timedOut := c.readTimedOut
		c.mu.Unlock()
		if timedOut {
			t.Fatalf("readTimedOut stayed true immediately after clearing deadline under mutex serialization")
		}
		time.Sleep(2 * time.Millisecond)
		// If timer already fired before clear, closed == 1 and readTimedOut was true BEFORE clear, not set after.
		c.mu.Lock()
		timedOutAfter := c.readTimedOut
		c.mu.Unlock()
		if timedOutAfter {
			t.Fatalf("stale timer mutated readTimedOut after clear")
		}
	}
}
