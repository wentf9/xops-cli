package sshfixture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestRecordPeerClosure(t *testing.T) {
	unexpected := errors.New("unexpected fixture failure")
	for _, tc := range []struct {
		name   string
		err    error
		retain bool
	}{
		{name: "EOF", err: io.EOF},
		{name: "closed connection", err: net.ErrClosed},
		{name: "peer reset", err: &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}},
		{name: "broken pipe", err: fmt.Errorf("reply after disconnect: %w", syscall.EPIPE)},
		{name: "joined peer closure", err: errors.Join(io.EOF, syscall.ECONNRESET)},
		{name: "unexpected", err: unexpected, retain: true},
		{name: "similar text", err: errors.New("connection reset by peer"), retain: true},
		{name: "mixed failure", err: errors.Join(syscall.ECONNRESET, unexpected), retain: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := &Server{ctx: t.Context()}
			server.record(tc.err)
			if tc.retain {
				if len(server.errors) != 1 || !errors.Is(server.errors[0], tc.err) {
					t.Fatalf("fixture error was lost: %v", server.errors)
				}
			} else if len(server.errors) != 0 {
				t.Fatalf("peer closure became a fixture failure: %v", server.errors)
			}
		})
	}
}

func dialFixtureClient(t *testing.T, s *Server) *ssh.Client {
	t.Helper()
	config := &ssh.ClientConfig{
		User: "testuser",
		Auth: []ssh.AuthMethod{
			ssh.Password(Password),
		},
		HostKeyCallback: ssh.FixedHostKey(s.HostKey),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", s.Address, config)
	if err != nil {
		t.Fatalf("ssh.Dial failed: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestDirectStreamLocal(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	server, err := New(ctx)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer func() {
		if err := server.Close(); err != nil {
			t.Fatalf("server.Close failed: %v", err)
		}
	}()

	client := dialFixtureClient(t, server)

	// 1. Success case: local unix listener
	sockDir := t.TempDir()
	sockPath := filepath.Join(sockDir, "target.sock")
	unixListener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("net.Listen unix failed: %v", err)
	}
	defer func() { _ = unixListener.Close() }()

	go func() {
		conn, err := unixListener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 5)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		_, _ = conn.Write([]byte("pong:" + string(buf)))
	}()

	// Open direct-streamlocal channel
	type streamLocalChannelOpenDirectMsg struct {
		SocketPath string
		Reserved0  string
		Reserved1  uint32
	}
	msg := streamLocalChannelOpenDirectMsg{
		SocketPath: sockPath,
	}
	channel, reqs, err := client.OpenChannel("direct-streamlocal@openssh.com", ssh.Marshal(&msg))
	if err != nil {
		t.Fatalf("OpenChannel failed: %v", err)
	}
	go ssh.DiscardRequests(reqs)
	defer func() { _ = channel.Close() }()

	if _, err := channel.Write([]byte("hello")); err != nil {
		t.Fatalf("channel.Write failed: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(channel, reply); err != nil {
		t.Fatalf("channel read failed: %v", err)
	}
	if string(reply) != "pong:hello" {
		t.Fatalf("expected pong:hello, got %q", string(reply))
	}
	if server.Forwards.Load() < 1 {
		t.Fatalf("expected Forwards >= 1, got %d", server.Forwards.Load())
	}

	// 2. Reject empty path
	invalidMsg := streamLocalChannelOpenDirectMsg{
		SocketPath: "",
	}
	_, _, err = client.OpenChannel("direct-streamlocal@openssh.com", ssh.Marshal(&invalidMsg))
	if err == nil {
		t.Fatal("expected OpenChannel with empty path to fail")
	}
	var openChanErr *ssh.OpenChannelError
	if errors.As(err, &openChanErr) {
		if openChanErr.Reason != ssh.Prohibited {
			t.Fatalf("expected Reason Prohibited, got %v", openChanErr.Reason)
		}
	}

	// 3. Reject unavailable target
	unavailableMsg := streamLocalChannelOpenDirectMsg{
		SocketPath: filepath.Join(sockDir, "nonexistent.sock"),
	}
	_, _, err = client.OpenChannel("direct-streamlocal@openssh.com", ssh.Marshal(&unavailableMsg))
	if err == nil {
		t.Fatal("expected OpenChannel with nonexistent path to fail")
	}
	if errors.As(err, &openChanErr) {
		if openChanErr.Reason != ssh.ConnectionFailed {
			t.Fatalf("expected Reason ConnectionFailed, got %v", openChanErr.Reason)
		}
	}
}

func TestRemoteStreamLocalForward(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	server, err := New(ctx)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer func() {
		if err := server.Close(); err != nil {
			t.Fatalf("server.Close failed: %v", err)
		}
	}()

	client := dialFixtureClient(t, server)
	sockPath := filepath.Join(t.TempDir(), "fwd.sock")

	ln, err := client.ListenUnix(sockPath)
	if err != nil {
		t.Fatalf("ListenUnix failed: %v", err)
	}

	assertRemoteForwardActive(t, server, sockPath)
	assertRemoteForwardEcho(t, ln, sockPath)
	assertDuplicateForwardRejected(t, client, sockPath)

	if err := ln.Close(); err != nil {
		t.Fatalf("ln.Close failed: %v", err)
	}

	if _, err := os.Stat(sockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected socket file to be removed, got err: %v", err)
	}

	assertCancelStreamLocalForwardFails(t, client, sockPath)
}

func assertRemoteForwardActive(t *testing.T, server *Server, sockPath string) {
	t.Helper()
	rf := server.RequestedForwards()
	wantKey := "unix:" + sockPath
	for _, f := range rf {
		if f == wantKey {
			if _, err := os.Stat(sockPath); err != nil {
				t.Fatalf("socket file does not exist: %v", err)
			}
			return
		}
	}
	t.Fatalf("expected RequestedForwards to contain %q, got %v", wantKey, rf)
}

func assertDuplicateForwardRejected(t *testing.T, client *ssh.Client, sockPath string) {
	t.Helper()
	var slPayload struct {
		SocketPath string
	}
	slPayload.SocketPath = sockPath
	ok, _, err := client.SendRequest("streamlocal-forward@openssh.com", true, ssh.Marshal(&slPayload))
	if err != nil {
		t.Fatalf("duplicate streamlocal-forward failed: %v", err)
	}
	if ok {
		t.Fatal("expected duplicate streamlocal-forward to be rejected")
	}
}

func assertCancelStreamLocalForwardFails(t *testing.T, client *ssh.Client, sockPath string) {
	t.Helper()
	var slPayload struct {
		SocketPath string
	}
	slPayload.SocketPath = sockPath
	ok, _, err := client.SendRequest("cancel-streamlocal-forward@openssh.com", true, ssh.Marshal(&slPayload))
	if err != nil {
		t.Fatalf("cancel SendRequest failed: %v", err)
	}
	if ok {
		t.Fatal("expected cancel to return false")
	}
}

func assertRemoteForwardEcho(t *testing.T, ln net.Listener, sockPath string) {
	t.Helper()
	connChan := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		connChan <- c
	}()

	clientConn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("net.Dial unix failed: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	var serverAccepted net.Conn
	select {
	case serverAccepted = <-connChan:
		defer func() { _ = serverAccepted.Close() }()
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for ln.Accept")
	}

	if _, err := clientConn.Write([]byte("ping")); err != nil {
		t.Fatalf("clientConn.Write failed: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(serverAccepted, buf); err != nil {
		t.Fatalf("serverAccepted read failed: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("expected ping, got %q", string(buf))
	}
	if _, err := serverAccepted.Write([]byte("pong")); err != nil {
		t.Fatalf("serverAccepted write failed: %v", err)
	}
	replyBuf := make([]byte, 4)
	if _, err := io.ReadFull(clientConn, replyBuf); err != nil {
		t.Fatalf("clientConn read failed: %v", err)
	}
	if string(replyBuf) != "pong" {
		t.Fatalf("expected pong, got %q", string(replyBuf))
	}
}

func TestTCPIPForwardAndRequestedForwards(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	server, err := New(ctx)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer func() {
		if err := server.Close(); err != nil {
			t.Fatalf("server.Close failed: %v", err)
		}
	}()

	client := dialFixtureClient(t, server)

	// Initially empty RequestedForwards
	if len(server.RequestedForwards()) != 0 {
		t.Fatalf("expected empty RequestedForwards, got %v", server.RequestedForwards())
	}

	// Listen TCP
	ln, err := client.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client.Listen tcp failed: %v", err)
	}
	defer func() { _ = ln.Close() }()

	rf := server.RequestedForwards()
	if len(rf) != 1 || rf[0] != "127.0.0.1:0" {
		t.Fatalf("expected RequestedForwards [127.0.0.1:0], got %v", rf)
	}

	// Also ListenUnix
	sockDir := t.TempDir()
	sockPath := filepath.Join(sockDir, "test.sock")
	uln, err := client.ListenUnix(sockPath)
	if err != nil {
		t.Fatalf("client.ListenUnix failed: %v", err)
	}
	defer func() { _ = uln.Close() }()

	rf = server.RequestedForwards()
	if len(rf) != 2 || rf[0] != "127.0.0.1:0" || rf[1] != "unix:"+sockPath {
		t.Fatalf("expected RequestedForwards [127.0.0.1:0 unix:%s], got %v", sockPath, rf)
	}
}
