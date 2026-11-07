package ssh

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
)

// TestProxyRelaysOutputBeyondClientWindow verifies that the master respects the
// receive window and maximum packet size the proxy client advertised. Relaying
// without credit overruns the client's 2 MiB window, and x/crypto then fails
// "ssh: remote side wrote too much" and drops the whole multiplexed connection.
func TestProxyRelaysOutputBeyondClientWindow(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	const total = 6 << 20
	fixture := startMuxFixture(t, ctx, sshfixture.Options{
		ExecHandler: func(_ string, channel cryptoSSH.Channel) {
			chunk := bytes.Repeat([]byte("x"), 32<<10)
			for written := 0; written < total; {
				n, err := channel.Write(chunk)
				written += n
				if err != nil {
					return
				}
			}
			_, _ = channel.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
		},
	})

	client, proxyConn, err := DialControlProxy(ctx, fixture.SocketPath, fixture.Target)
	if err != nil {
		t.Fatalf("DialControlProxy failed: %v", err)
	}
	defer func() {
		_ = client.Close()
		_ = proxyConn.Close()
	}()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	defer func() { _ = session.Close() }()

	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe failed: %v", err)
	}
	if err := session.Start("stream-big"); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Do not consume for a moment: a relay that ignores the client window pushes
	// past it immediately, which is exactly the regression under test.
	time.Sleep(500 * time.Millisecond)

	received, err := io.Copy(io.Discard, stdout)
	if err != nil {
		t.Fatalf("reading %d bytes through the proxy failed: %v", total, err)
	}
	if received != total {
		t.Fatalf("received %d bytes through the proxy, want %d", received, total)
	}
	if err := session.Wait(); err != nil {
		t.Fatalf("remote command through the proxy failed: %v", err)
	}
}

// TestProxyStalledChannelDoesNotBlockOtherChannels verifies that one channel
// whose remote side stopped reading stdin cannot stall the shared proxy read
// loop. Relaying input inline would block every other channel on the session.
func TestProxyStalledChannelDoesNotBlockOtherChannels(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	release := make(chan struct{})
	fixture := startMuxFixture(t, ctx, sshfixture.Options{
		ExecHandler: func(command string, channel cryptoSSH.Channel) {
			if command == "hold-stdin" {
				// Never read stdin: the master's remote channel window fills up.
				<-release
				return
			}
			_, _ = io.WriteString(channel, "fast\n")
			_, _ = channel.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
		},
	})
	defer close(release)

	client, proxyConn, err := DialControlProxy(ctx, fixture.SocketPath, fixture.Target)
	if err != nil {
		t.Fatalf("DialControlProxy failed: %v", err)
	}
	defer func() {
		_ = client.Close()
		_ = proxyConn.Close()
	}()

	stalled, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession for the stalled channel failed: %v", err)
	}
	// No session Close here: closing the session blocks on the channel write lock
	// while the transport write is stalled, so the client teardown below runs first.
	stdin, err := stalled.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe failed: %v", err)
	}
	if err := stalled.Start("hold-stdin"); err != nil {
		t.Fatalf("Start for the stalled channel failed: %v", err)
	}

	// Push more than the window this master advertises so the relay and the
	// client writer both reach a blocked state.
	payload := bytes.Repeat([]byte("x"), 4<<20)
	go func() {
		_, _ = io.Copy(stdin, bytes.NewReader(payload))
	}()
	time.Sleep(500 * time.Millisecond)

	type result struct {
		output []byte
		err    error
	}
	done := make(chan result, 1)
	go func() {
		session, err := client.NewSession()
		if err != nil {
			done <- result{err: err}
			return
		}
		defer func() { _ = session.Close() }()
		output, err := session.Output("echo fast")
		done <- result{output: output, err: err}
	}()

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("unrelated channel failed while another channel stalled: %v", got.err)
		}
		if string(got.output) != "fast\n" {
			t.Fatalf("unrelated channel output = %q, want %q", got.output, "fast\n")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a channel with an exhausted remote window blocked an unrelated channel")
	}
}

// TestMuxServerPrepareHandoffRequiresIdleMaster verifies that a ControlPersist
// handoff is refused while another session or forward depends on the master, or
// after -O stop committed it to shutdown. Releasing it would cut those users off
// or resurrect a stopped master.
func TestMuxServerPrepareHandoffRequiresIdleMaster(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	newServer := func(t *testing.T) *MuxServer {
		t.Helper()
		server, err := NewMuxServer(MuxServerOptions{
			ControlPath:       t.TempDir() + "/handoff.sock",
			SSHClient:         newDummySSHClient(),
			PersistEnabled:    true,
			PersistIndefinite: true,
		})
		if err != nil {
			t.Fatalf("NewMuxServer failed: %v", err)
		}
		go func() { _ = server.Serve() }()
		t.Cleanup(func() { _ = server.Shutdown() })
		return server
	}

	t.Run("idle master is reserved", func(t *testing.T) {
		server := newServer(t)
		if !server.PrepareHandoff() {
			t.Fatal("expected an idle master to be reserved for handoff")
		}
	})

	t.Run("active session blocks handoff", func(t *testing.T) {
		server := newServer(t)
		proxyConn, err := connectTestProxyClient(server.ControlPath())
		if err != nil {
			t.Fatalf("connectTestProxyClient failed: %v", err)
		}
		waitForCondition(t, 5*time.Second, func() bool {
			return server.ActiveSessions() == 1
		}, "proxy session was not counted")
		if server.PrepareHandoff() {
			_ = proxyConn.Close()
			t.Fatal("expected handoff to be refused while a session uses the master")
		}
		_ = proxyConn.Close()
		waitForCondition(t, 5*time.Second, func() bool {
			return server.ActiveSessions() == 0
		}, "proxy session was not released")
	})

	t.Run("owned forward blocks handoff", func(t *testing.T) {
		server := newServer(t)
		client, err := DialMuxClient(ctx, server.ControlPath())
		if err != nil {
			t.Fatalf("DialMuxClient failed: %v", err)
		}
		defer func() { _ = client.Close() }()

		forward := ForwardRequest{Type: ForwardLocal, ListenHost: "127.0.0.1", ConnectHost: "127.0.0.1", ConnectPort: 22}
		if _, err := client.OpenForward(ctx, forward); err != nil {
			t.Fatalf("OpenForward failed: %v", err)
		}
		if server.PrepareHandoff() {
			t.Fatal("expected handoff to be refused while a forward belongs to the master")
		}
		if err := client.CloseForward(ctx, forward); err != nil {
			t.Fatalf("CloseForward failed: %v", err)
		}
		if !server.PrepareHandoff() {
			t.Fatal("expected handoff to be allowed after the forward was cancelled")
		}
	})

	t.Run("stopped master blocks handoff", func(t *testing.T) {
		server := newServer(t)
		client, err := DialMuxClient(ctx, server.ControlPath())
		if err != nil {
			t.Fatalf("DialMuxClient failed: %v", err)
		}
		defer func() { _ = client.Close() }()
		if err := client.StopListening(ctx); err != nil {
			t.Fatalf("StopListening failed: %v", err)
		}
		if server.PrepareHandoff() {
			t.Fatal("expected handoff to be refused after -O stop")
		}
	})
}

func TestMuxServerWaitForDrainAndCancelHandoff(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	server, err := NewMuxServer(MuxServerOptions{
		ControlPath:           t.TempDir() + "/drain.sock",
		SSHClient:             newDummySSHClient(),
		PersistEnabled:        true,
		PersistIndefinite:     true,
		InitialActiveSessions: 1,
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	go func() { _ = server.Serve() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	proxyConn, err := connectTestProxyClient(server.ControlPath())
	if err != nil {
		t.Fatalf("connectTestProxyClient failed: %v", err)
	}
	waitForCondition(t, 5*time.Second, func() bool {
		return server.ActiveSessions() == 2
	}, "proxy session was not counted")

	drained := make(chan error, 1)
	go func() {
		drained <- server.WaitForDrain(ctx, 1)
	}()

	select {
	case err := <-drained:
		t.Fatalf("WaitForDrain returned while secondary session was still active: %v", err)
	case <-time.After(80 * time.Millisecond):
	}

	_ = proxyConn.Close()
	select {
	case err := <-drained:
		if err != nil {
			t.Fatalf("WaitForDrain failed after secondary session closed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WaitForDrain did not unblock after secondary session closed")
	}

	server.RemoveForegroundSession()
	if !server.PrepareHandoff() {
		t.Fatal("expected PrepareHandoff to succeed after foreground session was released")
	}
	server.CancelHandoff()
	if !server.PrepareHandoff() {
		t.Fatal("expected PrepareHandoff to succeed again after CancelHandoff")
	}
}

// TestMuxServerDynamicRemoteForwardCancel verifies that remote forwards opened
// with ListenPort == 0 do not collide with each other and can be cancelled by
// the allocated port or by 0.
func TestMuxServerDynamicRemoteForwardCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	fixture := startMuxFixture(t, ctx, sshfixture.Options{})
	client, err := DialMuxClient(ctx, fixture.SocketPath)
	if err != nil {
		t.Fatalf("DialMuxClient failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	req1 := ForwardRequest{
		Type:        ForwardRemote,
		ListenHost:  "127.0.0.1",
		ListenPort:  0,
		ConnectHost: "127.0.0.1",
		ConnectPort: 8080,
	}
	port1, err := client.OpenForward(ctx, req1)
	if err != nil || port1 == 0 {
		t.Fatalf("first dynamic OpenForward failed: port=%d, err=%v", port1, err)
	}

	req2 := ForwardRequest{
		Type:        ForwardRemote,
		ListenHost:  "127.0.0.1",
		ListenPort:  0,
		ConnectHost: "127.0.0.1",
		ConnectPort: 8081,
	}
	port2, err := client.OpenForward(ctx, req2)
	if err != nil || port2 == 0 {
		t.Fatalf("second dynamic OpenForward failed: port=%d, err=%v", port2, err)
	}

	// Cancel first forward by allocated port
	cancelByAllocated := req1
	cancelByAllocated.ListenPort = port1
	if err := client.CloseForward(ctx, cancelByAllocated); err != nil {
		t.Fatalf("CloseForward by allocated port %d failed: %v", port1, err)
	}

	// Cancel second forward by port 0
	if err := client.CloseForward(ctx, req2); err != nil {
		t.Fatalf("CloseForward by port 0 failed: %v", err)
	}
}

// TestProxyChannel_RemoteEarlyEOFDoesNotTruncateStdin verifies that when a
// remote command closes its stdout early (sending SSH_MSG_CHANNEL_EOF) but
// continues reading client stdin for > 1.5s before exiting, the proxy channel
// does not prematurely send SSH_MSG_CHANNEL_CLOSE and truncate client stdin.
func TestProxyChannel_RemoteEarlyEOFDoesNotTruncateStdin(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	receivedCh := make(chan string, 1)
	fixture := startMuxFixture(t, ctx, sshfixture.Options{
		ExecHandler: func(command string, channel cryptoSSH.Channel) {
			if command != "early-stdout-eof" {
				return
			}
			// Close remote stdout immediately (sends SSH_MSG_CHANNEL_EOF to master).
			_ = channel.CloseWrite()
			data, _ := io.ReadAll(channel)
			receivedCh <- string(data)
			_, _ = channel.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
		},
	})

	client, proxyConn, err := DialControlProxy(ctx, fixture.SocketPath, fixture.Target)
	if err != nil {
		t.Fatalf("DialControlProxy failed: %v", err)
	}
	defer func() {
		_ = client.Close()
		_ = proxyConn.Close()
	}()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	defer func() { _ = session.Close() }()

	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe failed: %v", err)
	}
	if err := session.Start("early-stdout-eof"); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if _, err := io.WriteString(stdin, "part1-"); err != nil {
		t.Fatalf("write part1 failed: %v", err)
	}
	// Sleep longer than the old 1s timeout after remote stdout EOF.
	time.Sleep(1500 * time.Millisecond)
	if _, err := io.WriteString(stdin, "part2"); err != nil {
		t.Fatalf("write part2 after 1.5s failed (channel closed early): %v", err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatalf("stdin.Close failed: %v", err)
	}

	if err := session.Wait(); err != nil {
		t.Fatalf("session.Wait failed: %v", err)
	}

	select {
	case got := <-receivedCh:
		if got != "part1-part2" {
			t.Fatalf("remote command received %q, want %q", got, "part1-part2")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for remote command to finish reading stdin")
	}
}

// TestMuxServer_PrepareHandoffAndWaitForDrain_RespectActiveForwardStreams verifies
// that after -O cancel removes a port-forward listener (forwardCount == 0), an
// already-established forwarded TCP stream (activeForwardStreams > 0) still blocks
// PrepareHandoff and WaitForDrain until the stream finishes.
func TestMuxServer_PrepareHandoffAndWaitForDrain_RespectActiveForwardStreams(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo failed: %v", err)
	}
	defer func() { _ = echoLn.Close() }()
	_, echoPortStr, _ := net.SplitHostPort(echoLn.Addr().String())
	echoPort, _ := strconv.Atoi(echoPortStr)

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	fixture := startMuxFixture(t, ctx, sshfixture.Options{})

	muxCli, err := DialMuxClient(ctx, fixture.SocketPath)
	if err != nil {
		t.Fatalf("DialMuxClient failed: %v", err)
	}
	defer func() { _ = muxCli.Close() }()

	// Bind an ephemeral local port first to know the exact port for OpenForward/CloseForward.
	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen failed: %v", err)
	}
	_, fwdPortStr, _ := net.SplitHostPort(probeLn.Addr().String())
	fwdPort, _ := strconv.Atoi(fwdPortStr)
	_ = probeLn.Close()

	spec := ForwardRequest{
		Type:        ForwardLocal,
		ListenHost:  "127.0.0.1",
		ListenPort:  uint32(fwdPort),
		ConnectHost: "127.0.0.1",
		ConnectPort: uint32(echoPort),
	}

	if _, err := muxCli.OpenForward(ctx, spec); err != nil {
		t.Fatalf("OpenForward failed: %v", err)
	}

	// Open an active TCP stream through the local forward.
	fwdConn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", fwdPort))
	if err != nil {
		t.Fatalf("dial local forward failed: %v", err)
	}
	defer func() { _ = fwdConn.Close() }()

	if _, err := fwdConn.Write([]byte("ping")); err != nil {
		t.Fatalf("write to forward failed: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(fwdConn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("read from forward failed: got %q, err %v", string(buf), err)
	}

	// Cancel the forward listener (-O cancel) while fwdConn is still open.
	if err := muxCli.CloseForward(ctx, spec); err != nil {
		t.Fatalf("CloseForward failed: %v", err)
	}

	// Even though forwardCount() is now 0, activeForwardStreams is still 1.
	if fixture.Master.PrepareHandoff() {
		t.Fatal("expected PrepareHandoff() to return false while forwarded TCP stream is still active")
	}

	drainCtx, drainCancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer drainCancel()
	if err := fixture.Master.WaitForDrain(drainCtx, 0); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected WaitForDrain to block while forwarded stream is active, got %v", err)
	}

	// Close the active stream; WaitForDrain and PrepareHandoff should now succeed.
	_ = fwdConn.Close()
	if err := fixture.Master.WaitForDrain(ctx, 0); err != nil {
		t.Fatalf("expected WaitForDrain to succeed after forwarded stream closed, got %v", err)
	}
	if !fixture.Master.PrepareHandoff() {
		t.Fatal("expected PrepareHandoff() to succeed after forwarded stream closed")
	}
}

// TestDialControlProxy_FailsClosedOnOversizedPacket verifies that
// muxHandshakeInspectorConn fails closed when a control socket peer sends an
// oversized packet length header (> MaxMuxPacketLength).
func TestDialControlProxy_FailsClosedOnOversizedPacket(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sockPath := filepath.Join(t.TempDir(), "oversized.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Listen unix failed: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		var hdr [8]byte
		binary.BigEndian.PutUint32(hdr[0:4], MaxMuxPacketLength+100)
		binary.BigEndian.PutUint32(hdr[4:8], MUX_MSG_HELLO)
		_, _ = conn.Write(hdr[:])
		_, _ = io.Copy(io.Discard, conn)
	}()

	target := TargetContext{Host: "10.0.0.1", Port: 22, User: "alice"}
	_, _, dialErr := DialControlProxy(ctx, sockPath, target)
	if dialErr == nil || !strings.Contains(dialErr.Error(), "invalid mux packet length") {
		t.Fatalf("expected invalid mux packet length error, got %v", dialErr)
	}
}
