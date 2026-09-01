package ssh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type shortWriteConn struct {
	bytes.Buffer
	maxWrite int
}

func (c *shortWriteConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *shortWriteConn) Close() error                     { return nil }
func (c *shortWriteConn) LocalAddr() net.Addr              { return nil }
func (c *shortWriteConn) RemoteAddr() net.Addr             { return nil }
func (c *shortWriteConn) SetDeadline(time.Time) error      { return nil }
func (c *shortWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (c *shortWriteConn) SetWriteDeadline(time.Time) error { return nil }
func (c *shortWriteConn) Write(p []byte) (int, error) {
	if c.maxWrite == 0 {
		return 0, nil
	}
	if len(p) > c.maxWrite {
		p = p[:c.maxWrite]
	}
	return c.Buffer.Write(p)
}

func TestWriteTunnelBytes(t *testing.T) {
	t.Run("continues after short writes", func(t *testing.T) {
		conn := &shortWriteConn{maxWrite: 2}
		if err := writeTunnelBytes(conn, []byte("abcdef")); err != nil {
			t.Fatalf("writeTunnelBytes failed: %v", err)
		}
		if got := conn.String(); got != "abcdef" {
			t.Fatalf("got %q, want %q", got, "abcdef")
		}
	})

	t.Run("rejects zero progress", func(t *testing.T) {
		if err := writeTunnelBytes(&shortWriteConn{}, []byte("x")); !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("got %v, want io.ErrShortWrite", err)
		}
	})

	t.Run("times out unsupported deadline connection", func(t *testing.T) {
		conn := &blockingTunnelConn{closed: make(chan struct{})}
		_, err := runTimedTunnelIO(conn, time.Millisecond, "write", func() (int, error) {
			return conn.Write([]byte("x"))
		})
		if err == nil || !strings.Contains(err.Error(), "tunnel write timed out") {
			t.Fatalf("got %v, want tunnel timeout", err)
		}
	})
}

func TestCopyStream_ClosesPeerAfterWriteFailure(t *testing.T) {
	first, firstPeer := net.Pipe()
	second, secondPeer := net.Pipe()
	defer func() { _ = firstPeer.Close() }()
	defer func() { _ = secondPeer.Close() }()
	if err := secondPeer.Close(); err != nil {
		t.Fatalf("close receiving peer failed: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- (&Client{}).copyStream(context.Background(), first, second)
	}()
	if _, err := firstPeer.Write([]byte("x")); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write source data failed: %v", err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("copyStream() error = nil, want write failure")
		}
	case <-time.After(time.Second):
		t.Fatal("copyStream did not cancel the peer after write failure")
	}
}

func TestRunForwardListener_ConnectionFailureDoesNotStopListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var calls atomic.Int32
	connectionErr := make(chan error, 1)
	secondConnection := make(chan struct{})
	forward := runForwardListener(ctx, listener, forwardOptions{onConnectionError: func(err error) {
		connectionErr <- err
	}}, func(_ context.Context, conn net.Conn) error {
		defer func() {
			if closeErr := conn.Close(); closeErr != nil {
				t.Errorf("close forwarded test connection failed: %v", closeErr)
			}
		}()
		if calls.Add(1) == 1 {
			return errors.New("test connection failure")
		}
		close(secondConnection)
		return nil
	})

	for range 2 {
		conn, dialErr := net.Dial("tcp", listener.Addr().String())
		if dialErr != nil {
			t.Fatalf("dial forwarded listener failed: %v", dialErr)
		}
		if closeErr := conn.Close(); closeErr != nil {
			t.Fatalf("close test connection failed: %v", closeErr)
		}
	}
	select {
	case err := <-connectionErr:
		if !strings.Contains(err.Error(), "test connection failure") {
			t.Fatalf("connection error = %v, want test connection failure", err)
		}
	case <-time.After(time.Second):
		t.Fatal("connection error callback was not called")
	}
	select {
	case <-secondConnection:
	case <-time.After(time.Second):
		t.Fatalf("handler calls = %d, want 2", calls.Load())
	}
	cancel()
	if err := forward.Wait(); err != nil {
		t.Fatalf("forward.Wait() error = %v", err)
	}
}

type blockingTunnelConn struct {
	closed chan struct{}
	once   sync.Once
}

func (c *blockingTunnelConn) Read([]byte) (int, error)  { <-c.closed; return 0, net.ErrClosed }
func (c *blockingTunnelConn) Write([]byte) (int, error) { <-c.closed; return 0, net.ErrClosed }
func (c *blockingTunnelConn) Close() error              { c.once.Do(func() { close(c.closed) }); return nil }
func (c *blockingTunnelConn) LocalAddr() net.Addr       { return nil }
func (c *blockingTunnelConn) RemoteAddr() net.Addr      { return nil }
func (c *blockingTunnelConn) SetDeadline(time.Time) error {
	return errors.New("deadline unsupported")
}
func (c *blockingTunnelConn) SetReadDeadline(time.Time) error {
	return errors.New("deadline unsupported")
}
func (c *blockingTunnelConn) SetWriteDeadline(time.Time) error {
	return errors.New("deadline unsupported")
}

func TestLocalForward(t *testing.T) {
	// 1. Start target TCP server
	targetListener, targetAddr := startMockTargetServer(t)
	defer func() {
		if err := targetListener.Close(); err != nil {
			t.Logf("Close failed: %v", err)
		}
	}()

	// 2. Start SSH server
	sshListener := startMockSSHServer(t)
	defer func() {
		if err := sshListener.Close(); err != nil {
			t.Logf("Close failed: %v", err)
		}
	}()

	// 3. Connect as SSH client
	sshClientConfig := &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.Password("test")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	rawClient, err := ssh.Dial("tcp", sshListener.Addr().String(), sshClientConfig)
	if err != nil {
		t.Fatalf("failed to dial ssh server: %v", err)
	}
	defer func() {
		if err := rawClient.Close(); err != nil {
			t.Logf("Close failed: %v", err)
		}
	}()

	client := &Client{
		sshClient: rawClient,
	}

	// 4. Start LocalForward
	localListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on local addr: %v", err)
	}
	localAddr := localListener.Addr().String()
	if err := localListener.Close(); err != nil {
		t.Logf("Close failed: %v", err)
	} // Close it to let LocalForward bind to it

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	forward, err := client.LocalForward(ctx, localAddr, targetAddr)
	if err != nil {
		t.Fatalf("LocalForward failed: %v", err)
	}

	// 5. Connect to local address, and send request
	localConn, err := net.DialTimeout("tcp", localAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to local forwarded address: %v", err)
	}
	defer func() {
		if err := localConn.Close(); err != nil {
			t.Logf("Close failed: %v", err)
		}
	}()

	// Send message
	msg := []byte("hello xops tunnel")
	_, err = localConn.Write(msg)
	if err != nil {
		t.Fatalf("message write failed: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := localConn.Read(buf)
	if err != nil {
		t.Fatalf("response read failed: %v", err)
	}

	expected := "echo: hello xops tunnel"
	if string(buf[:n]) != expected {
		t.Errorf("expected %q, got %q", expected, string(buf[:n]))
	}

	// 6. Test context cancel cleans up connection
	cancel()
	if err := forward.Wait(); err != nil {
		t.Fatalf("wait for LocalForward failed: %v", err)
	}
	if err := forward.Wait(); err != nil {
		t.Fatalf("second wait for LocalForward failed: %v", err)
	}

	errReadCh := make(chan error, 1)
	go func() {
		temp := make([]byte, 1)
		_, err := localConn.Read(temp)
		errReadCh <- err
	}()

	select {
	case err := <-errReadCh:
		if err == nil {
			t.Error("expected connection to be closed after context cancel, but Read returned nil error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("connection was not closed by tunnel after cancel")
	}
}

func TestSSH_DialSSHContextCancel(t *testing.T) {
	sshListener := startMockSSHServer(t)
	defer func() {
		_ = sshListener.Close()
	}()

	sshClientConfig := &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.Password("test")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	rawClient, err := ssh.Dial("tcp", sshListener.Addr().String(), sshClientConfig)
	if err != nil {
		t.Fatalf("failed to dial ssh server: %v", err)
	}
	defer func() {
		_ = rawClient.Close()
	}()

	client := &Client{sshClient: rawClient}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = client.dialSSH(ctx, "tcp", "10.255.255.1:12345")
	if err == nil {
		t.Fatal("expected error on canceled context dial, got nil")
	}
}
