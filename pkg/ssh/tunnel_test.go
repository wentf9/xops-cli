package ssh

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestLocalForward(t *testing.T) {
	// 1. Start target TCP server
	targetListener, targetAddr := startMockTargetServer(t)
	defer func() { _ = targetListener.Close() }()

	// 2. Start SSH server
	sshListener := startMockSSHServer(t)
	defer func() { _ = sshListener.Close() }()

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
	defer func() { _ = rawClient.Close() }()

	client := &Client{
		sshClient: rawClient,
	}

	// 4. Start LocalForward
	localListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on local addr: %v", err)
	}
	localAddr := localListener.Addr().String()
	_ = localListener.Close() // Close it to let LocalForward bind to it

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := client.LocalForward(ctx, localAddr, targetAddr); err != nil {
		t.Fatalf("LocalForward failed: %v", err)
	}

	// 5. Connect to local address, and send request
	localConn, err := net.DialTimeout("tcp", localAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to local forwarded address: %v", err)
	}
	defer func() { _ = localConn.Close() }()

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
