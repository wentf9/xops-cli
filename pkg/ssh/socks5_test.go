package ssh

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func startMockTargetServer(t *testing.T) (net.Listener, string) {
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start target listener: %v", err)
	}

	go func() {
		for {
			conn, err := targetListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 1024)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				_, _ = c.Write(append([]byte("echo: "), buf[:n]...))
			}(conn)
		}
	}()
	return targetListener, targetListener.Addr().String()
}

func startMockSSHServer(t *testing.T) net.Listener {
	sshConfig := &ssh.ServerConfig{
		NoClientAuth: true,
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	sshConfig.AddHostKey(signer)

	sshListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start ssh listener: %v", err)
	}

	go func() {
		for {
			conn, err := sshListener.Accept()
			if err != nil {
				return
			}
			sConn, chans, reqs, err := ssh.NewServerConn(conn, sshConfig)
			if err != nil {
				_ = conn.Close()
				continue
			}
			go func() {
				_ = sConn.Wait()
			}()
			go ssh.DiscardRequests(reqs)
			go handleMockSSHChannels(chans)
		}
	}()
	return sshListener
}

func handleMockSSHChannels(channels <-chan ssh.NewChannel) {
	for newChan := range channels {
		if newChan.ChannelType() != "direct-tcpip" {
			_ = newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		var payload struct {
			DestAddr   string
			DestPort   uint32
			OriginAddr string
			OriginPort uint32
		}
		if err := ssh.Unmarshal(newChan.ExtraData(), &payload); err != nil {
			_ = newChan.Reject(ssh.ConnectionFailed, "bad payload")
			continue
		}

		targetConn, err := net.Dial("tcp", net.JoinHostPort(payload.DestAddr, fmt.Sprintf("%d", payload.DestPort)))
		if err != nil {
			_ = newChan.Reject(ssh.ConnectionFailed, err.Error())
			continue
		}
		ch, reqs, err := newChan.Accept()
		if err != nil {
			_ = targetConn.Close()
			continue
		}
		go ssh.DiscardRequests(reqs)

		go func() {
			defer func() { _ = ch.Close() }()
			defer func() { _ = targetConn.Close() }()
			_, _ = io.Copy(ch, targetConn)
		}()
		go func() {
			defer func() { _ = ch.Close() }()
			defer func() { _ = targetConn.Close() }()
			_, _ = io.Copy(targetConn, ch)
		}()
	}
}

func performSocks5HandshakeAndConnect(t *testing.T, socksConn net.Conn, targetAddr string) {
	// Handshake
	_, err := socksConn.Write([]byte{0x05, 0x01, 0x00}) // VER=5, NMETHODS=1, METHOD=0
	if err != nil {
		t.Fatalf("handshake write failed: %v", err)
	}
	var resp [2]byte
	_, err = io.ReadFull(socksConn, resp[:])
	if err != nil {
		t.Fatalf("handshake read failed: %v", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("unexpected handshake response: %v", resp)
	}

	// Connect request
	targetHost, targetPortStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		t.Fatalf("failed to split host port: %v", err)
	}
	var targetPort uint16
	_, _ = fmt.Sscanf(targetPortStr, "%d", &targetPort)

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(targetHost))}
	req = append(req, []byte(targetHost)...)
	req = append(req, byte(targetPort>>8), byte(targetPort&0xFF))

	_, err = socksConn.Write(req)
	if err != nil {
		t.Fatalf("connect request write failed: %v", err)
	}

	var connResp [10]byte
	_, err = io.ReadFull(socksConn, connResp[:])
	if err != nil {
		t.Fatalf("connect response read failed: %v", err)
	}
	if connResp[0] != 0x05 || connResp[1] != 0x00 {
		t.Fatalf("unexpected connect response: %v", connResp)
	}
}

func TestSocks5Forward(t *testing.T) {
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

	// 4. Start SOCKS5 forwarder
	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start socks listener: %v", err)
	}
	socksAddr := socksListener.Addr().String()
	_ = socksListener.Close() // Close it to let Socks5Forward bind to it

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := client.Socks5Forward(ctx, socksAddr); err != nil {
		t.Fatalf("Socks5Forward failed: %v", err)
	}

	// 5. Connect SOCKS5 client to socks5 address, and send request to targetAddr
	socksConn, err := net.DialTimeout("tcp", socksAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to socks5 server: %v", err)
	}
	defer func() { _ = socksConn.Close() }()

	performSocks5HandshakeAndConnect(t, socksConn, targetAddr)

	// Send message
	msg := []byte("hello xops socks5")
	_, err = socksConn.Write(msg)
	if err != nil {
		t.Fatalf("message write failed: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := socksConn.Read(buf)
	if err != nil {
		t.Fatalf("response read failed: %v", err)
	}

	expected := "echo: hello xops socks5"
	if string(buf[:n]) != expected {
		t.Errorf("expected %q, got %q", expected, string(buf[:n]))
	}
}
