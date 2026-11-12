package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	logger "github.com/wentf9/xops-cli/core/log"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func startEchoServer(t *testing.T, network, addr string) (net.Listener, string) {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Fatalf("listen %s %s failed: %v", network, addr, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return ln, ln.Addr().String()
}

func newTestClientWithFixture(t *testing.T, ctx context.Context) (*Client, *sshfixture.Server) {
	t.Helper()
	fixtureCtx, fixtureCancel := context.WithTimeout(ctx, 30*time.Second)
	t.Cleanup(fixtureCancel)
	fix, err := sshfixture.NewWithOptions(fixtureCtx, sshfixture.Options{})
	if err != nil {
		t.Fatalf("sshfixture.New failed: %v", err)
	}
	t.Cleanup(func() { _ = fix.Close() })

	rawClient, err := cryptoSSH.Dial("tcp", fix.Address, &cryptoSSH.ClientConfig{
		User:            "test",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password(sshfixture.Password)},
		HostKeyCallback: cryptoSSH.FixedHostKey(fix.HostKey),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("cryptoSSH.Dial failed: %v", err)
	}
	t.Cleanup(func() { _ = rawClient.Close() })

	client := &Client{
		sshClient: rawClient,
	}
	return client, fix
}

func performSocks4Connect(t *testing.T, conn net.Conn, targetIP net.IP, targetPort int) {
	t.Helper()
	ip4 := targetIP.To4()
	if ip4 == nil {
		t.Fatalf("invalid IPv4: %v", targetIP)
	}
	req := []byte{0x04, 0x01, byte(targetPort >> 8), byte(targetPort & 0xff)}
	req = append(req, ip4...)
	req = append(req, []byte("user\x00")...)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write socks4 req failed: %v", err)
	}
	var resp [8]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		t.Fatalf("read socks4 resp failed: %v", err)
	}
	if resp[1] != 0x5a {
		t.Fatalf("socks4 rejected: 0x%02x", resp[1])
	}
}

func performSocks4aConnect(t *testing.T, conn net.Conn, targetHost string, targetPort int) {
	t.Helper()
	req := []byte{0x04, 0x01, byte(targetPort >> 8), byte(targetPort & 0xff), 0, 0, 0, 1}
	req = append(req, []byte("user\x00")...)
	req = append(req, []byte(targetHost+"\x00")...)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write socks4a req failed: %v", err)
	}
	var resp [8]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		t.Fatalf("read socks4a resp failed: %v", err)
	}
	if resp[1] != 0x5a {
		t.Fatalf("socks4a rejected: 0x%02x", resp[1])
	}
}

func performSocks5Connect(t *testing.T, conn net.Conn, targetHost string, targetPort int) {
	t.Helper()
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write socks5 greeting failed: %v", err)
	}
	var greetingResp [2]byte
	if _, err := io.ReadFull(conn, greetingResp[:]); err != nil {
		t.Fatalf("read socks5 greeting failed: %v", err)
	}
	if greetingResp[0] != 0x05 || greetingResp[1] != 0x00 {
		t.Fatalf("socks5 auth rejected: %v", greetingResp)
	}

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(targetHost))}
	req = append(req, []byte(targetHost)...)
	req = append(req, byte(targetPort>>8), byte(targetPort&0xff))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write socks5 connect req failed: %v", err)
	}
	var connectResp [10]byte
	if _, err := io.ReadFull(conn, connectResp[:]); err != nil {
		t.Fatalf("read socks5 connect resp failed: %v", err)
	}
	if connectResp[1] != 0x00 {
		t.Fatalf("socks5 connect failed: 0x%02x", connectResp[1])
	}
}

func verifyEchoRoundtrip(t *testing.T, conn net.Conn, payload string) {
	t.Helper()
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write payload failed: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read payload failed: %v", err)
	}
	if string(buf) != payload {
		t.Fatalf("payload mismatch: want %q, got %q", payload, string(buf))
	}
}

// -----------------------------------------------------------------------------
// Group 1: SOCKS4, SOCKS4a, SOCKS5 Tests
// -----------------------------------------------------------------------------

func TestForwardAlignment_SOCKS4_ConnectSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, _ := newTestClientWithFixture(t, ctx)
	_, echoAddr := startEchoServer(t, "tcp", "127.0.0.1:0")
	_, echoPortStr, _ := net.SplitHostPort(echoAddr)
	echoPort, _ := strconv.Atoi(echoPortStr)

	fwd, err := client.DynamicForwardEndpoint(ctx, ForwardEndpoint{Port: 0}, false)
	if err != nil {
		t.Fatalf("DynamicForwardEndpoint failed: %v", err)
	}
	defer func() {
		cancel()
		_ = fwd.Wait()
	}()

	conn, err := net.Dial("tcp", fwd.Addr().String())
	if err != nil {
		t.Fatalf("dial dynamic forward failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	performSocks4Connect(t, conn, net.IPv4(127, 0, 0, 1), echoPort)
	verifyEchoRoundtrip(t, conn, "hello socks4")
}

func TestForwardAlignment_SOCKS4_BindRejected(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, _ := newTestClientWithFixture(t, ctx)
	fwd, err := client.DynamicForwardEndpoint(ctx, ForwardEndpoint{Port: 0}, false)
	if err != nil {
		t.Fatalf("DynamicForwardEndpoint failed: %v", err)
	}
	defer func() {
		cancel()
		_ = fwd.Wait()
	}()

	conn, err := net.Dial("tcp", fwd.Addr().String())
	if err != nil {
		t.Fatalf("dial dynamic forward failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Send BIND (cmd = 0x02)
	req := []byte{0x04, 0x02, 0x1f, 0x90, 127, 0, 0, 1, 'u', 's', 'e', 'r', 0}
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write BIND req failed: %v", err)
	}
	var resp [8]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		t.Fatalf("read BIND resp failed: %v", err)
	}
	if resp[1] != 0x5b {
		t.Fatalf("expected BIND rejection 0x5b, got 0x%02x", resp[1])
	}
}

func TestForwardAlignment_SOCKS4a_ConnectSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, _ := newTestClientWithFixture(t, ctx)
	_, echoAddr := startEchoServer(t, "tcp", "127.0.0.1:0")
	_, echoPortStr, _ := net.SplitHostPort(echoAddr)
	echoPort, _ := strconv.Atoi(echoPortStr)

	fwd, err := client.DynamicForwardEndpoint(ctx, ForwardEndpoint{Port: 0}, false)
	if err != nil {
		t.Fatalf("DynamicForwardEndpoint failed: %v", err)
	}
	defer func() {
		cancel()
		_ = fwd.Wait()
	}()

	conn, err := net.Dial("tcp", fwd.Addr().String())
	if err != nil {
		t.Fatalf("dial dynamic forward failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	performSocks4aConnect(t, conn, "localhost", echoPort)
	verifyEchoRoundtrip(t, conn, "hello socks4a")
}

func TestForwardAlignment_SOCKS5_TCP_And_UnixSocket(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, _ := newTestClientWithFixture(t, ctx)
	_, echoAddr := startEchoServer(t, "tcp", "127.0.0.1:0")
	_, echoPortStr, _ := net.SplitHostPort(echoAddr)
	echoPort, _ := strconv.Atoi(echoPortStr)

	// 1. TCP Dynamic forward
	fwdTCPCtx, cancelTCP := context.WithCancel(ctx)
	fwdTCP, err := client.DynamicForwardEndpoint(fwdTCPCtx, ForwardEndpoint{Port: 0}, false)
	if err != nil {
		t.Fatalf("DynamicForwardEndpoint TCP failed: %v", err)
	}
	defer func() {
		cancelTCP()
		_ = fwdTCP.Wait()
	}()

	connTCP, err := net.Dial("tcp", fwdTCP.Addr().String())
	if err != nil {
		t.Fatalf("dial TCP dynamic forward failed: %v", err)
	}
	performSocks5Connect(t, connTCP, "127.0.0.1", echoPort)
	verifyEchoRoundtrip(t, connTCP, "socks5 via tcp")
	_ = connTCP.Close()

	// 2. Unix socket Dynamic forward
	sockPath := filepath.Join(shortSocketDir(t), "dyn.sock")
	fwdUnixCtx, cancelUnix := context.WithCancel(ctx)
	fwdUnix, err := client.DynamicForwardEndpoint(fwdUnixCtx, ForwardEndpoint{SocketPath: sockPath}, false)
	if err != nil {
		t.Fatalf("DynamicForwardEndpoint Unix failed: %v", err)
	}
	defer func() {
		cancelUnix()
		_ = fwdUnix.Wait()
	}()

	connUnix, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial Unix dynamic forward failed: %v", err)
	}
	performSocks5Connect(t, connUnix, "127.0.0.1", echoPort)
	verifyEchoRoundtrip(t, connUnix, "socks5 via unix")
	_ = connUnix.Close()
}

// -----------------------------------------------------------------------------
// Group 2: StreamLocal Forwarding across all combinations on Client
// -----------------------------------------------------------------------------

func TestForwardAlignment_LocalForward_Combinations(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, _ := newTestClientWithFixture(t, ctx)

	// 1. TCP -> Unix
	t.Run("TCP_to_Unix", func(t *testing.T) {
		remSock := filepath.Join(shortSocketDir(t), "echo-t2u.sock")
		_, _ = startEchoServer(t, "unix", remSock)

		fwdCtx, cancelFwd := context.WithCancel(ctx)
		fwd, err := client.LocalForwardEndpoint(fwdCtx, ForwardEndpoint{Port: 0}, ForwardEndpoint{SocketPath: remSock}, false)
		if err != nil {
			t.Fatalf("LocalForwardEndpoint failed: %v", err)
		}
		defer func() {
			cancelFwd()
			_ = fwd.Wait()
		}()

		conn, err := net.Dial("tcp", fwd.Addr().String())
		if err != nil {
			t.Fatalf("dial failed: %v", err)
		}
		defer func() { _ = conn.Close() }()
		verifyEchoRoundtrip(t, conn, "tcp-to-unix-payload")
	})

	// 2. Unix -> TCP
	t.Run("Unix_to_TCP", func(t *testing.T) {
		_, remTCP := startEchoServer(t, "tcp", "127.0.0.1:0")
		_, remPortStr, _ := net.SplitHostPort(remTCP)
		remPort, _ := strconv.Atoi(remPortStr)

		localSock := filepath.Join(shortSocketDir(t), "u2t.sock")
		fwdCtx, cancelFwd := context.WithCancel(ctx)
		fwd, err := client.LocalForwardEndpoint(fwdCtx, ForwardEndpoint{SocketPath: localSock}, ForwardEndpoint{Host: "127.0.0.1", Port: uint16(remPort)}, false)
		if err != nil {
			t.Fatalf("LocalForwardEndpoint failed: %v", err)
		}
		defer func() {
			cancelFwd()
			_ = fwd.Wait()
		}()

		conn, err := net.Dial("unix", localSock)
		if err != nil {
			t.Fatalf("dial unix failed: %v", err)
		}
		defer func() { _ = conn.Close() }()
		verifyEchoRoundtrip(t, conn, "unix-to-tcp-payload")
	})

	// 3. Unix -> Unix
	t.Run("Unix_to_Unix", func(t *testing.T) {
		remSock := filepath.Join(shortSocketDir(t), "echo-u2u.sock")
		_, _ = startEchoServer(t, "unix", remSock)

		localSock := filepath.Join(shortSocketDir(t), "u2u.sock")
		fwdCtx, cancelFwd := context.WithCancel(ctx)
		fwd, err := client.LocalForwardEndpoint(fwdCtx, ForwardEndpoint{SocketPath: localSock}, ForwardEndpoint{SocketPath: remSock}, false)
		if err != nil {
			t.Fatalf("LocalForwardEndpoint failed: %v", err)
		}
		defer func() {
			cancelFwd()
			_ = fwd.Wait()
		}()

		conn, err := net.Dial("unix", localSock)
		if err != nil {
			t.Fatalf("dial unix failed: %v", err)
		}
		defer func() { _ = conn.Close() }()
		verifyEchoRoundtrip(t, conn, "unix-to-unix-payload")
	})
}

func TestForwardAlignment_RemoteForward_Combinations(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, fix := newTestClientWithFixture(t, ctx)

	// 1. TCP -> Unix (Remote TCP listens, connects to local Unix)
	t.Run("TCP_to_Unix", func(t *testing.T) {
		localSock := filepath.Join(shortSocketDir(t), "loc-t2u.sock")
		_, _ = startEchoServer(t, "unix", localSock)

		spec := ForwardSpec{
			Bind: ForwardEndpoint{Port: 0},
			Dest: ForwardEndpoint{SocketPath: localSock},
		}
		fwdCtx, cancelFwd := context.WithCancel(ctx)
		fwd, err := client.RemoteForwardEndpoint(fwdCtx, spec)
		if err != nil {
			t.Fatalf("RemoteForwardEndpoint failed: %v", err)
		}
		defer func() {
			cancelFwd()
			_ = fwd.Wait()
		}()

		port := fwd.Addr().(*net.TCPAddr).Port
		conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			t.Fatalf("dial remote TCP failed: %v", err)
		}
		defer func() { _ = conn.Close() }()
		verifyEchoRoundtrip(t, conn, "rem-t2u-payload")
	})

	// 2. Unix -> TCP (Remote Unix listens, connects to local TCP)
	t.Run("Unix_to_TCP", func(t *testing.T) {
		_, locTCP := startEchoServer(t, "tcp", "127.0.0.1:0")
		_, locPortStr, _ := net.SplitHostPort(locTCP)
		locPort, _ := strconv.Atoi(locPortStr)

		remSock := filepath.Join(shortSocketDir(t), "rem-u2t.sock")
		spec := ForwardSpec{
			Bind: ForwardEndpoint{SocketPath: remSock},
			Dest: ForwardEndpoint{Host: "127.0.0.1", Port: uint16(locPort)},
		}
		fwdCtx, cancelFwd := context.WithCancel(ctx)
		fwd, err := client.RemoteForwardEndpoint(fwdCtx, spec)
		if err != nil {
			t.Fatalf("RemoteForwardEndpoint failed: %v", err)
		}
		defer func() {
			cancelFwd()
			_ = fwd.Wait()
		}()

		conn, err := net.Dial("unix", remSock)
		if err != nil {
			t.Fatalf("dial remote unix failed: %v", err)
		}
		defer func() { _ = conn.Close() }()
		verifyEchoRoundtrip(t, conn, "rem-u2t-payload")
	})

	// 3. Unix -> Unix (Remote Unix listens, connects to local Unix)
	t.Run("Unix_to_Unix", func(t *testing.T) {
		localSock := filepath.Join(shortSocketDir(t), "loc-u2u.sock")
		_, _ = startEchoServer(t, "unix", localSock)

		remSock := filepath.Join(shortSocketDir(t), "rem-u2u.sock")
		spec := ForwardSpec{
			Bind: ForwardEndpoint{SocketPath: remSock},
			Dest: ForwardEndpoint{SocketPath: localSock},
		}
		fwdCtx, cancelFwd := context.WithCancel(ctx)
		fwd, err := client.RemoteForwardEndpoint(fwdCtx, spec)
		if err != nil {
			t.Fatalf("RemoteForwardEndpoint failed: %v", err)
		}
		defer func() {
			cancelFwd()
			_ = fwd.Wait()
		}()

		conn, err := net.Dial("unix", remSock)
		if err != nil {
			t.Fatalf("dial remote unix failed: %v", err)
		}
		defer func() { _ = conn.Close() }()
		verifyEchoRoundtrip(t, conn, "rem-u2u-payload")
	})

	// 4. Verify RequestedForwards on fixture: localhost:0 and *:0
	t.Run("RequestedForwards_Normalization", func(t *testing.T) {
		_, locTCP := startEchoServer(t, "tcp", "127.0.0.1:0")
		_, locPortStr, _ := net.SplitHostPort(locTCP)
		locPort, _ := strconv.Atoi(locPortStr)

		// Omitted bind_address
		fwdCtx1, cancelFwd1 := context.WithCancel(ctx)
		fwd1, err := client.RemoteForwardEndpoint(fwdCtx1, ForwardSpec{
			Bind: ForwardEndpoint{Port: 0, HasHost: false},
			Dest: ForwardEndpoint{Host: "127.0.0.1", Port: uint16(locPort)},
		})
		if err != nil {
			t.Fatalf("fwd1 failed: %v", err)
		}
		defer func() {
			cancelFwd1()
			_ = fwd1.Wait()
		}()

		// Wildcard bind_address
		fwdCtx2, cancelFwd2 := context.WithCancel(ctx)
		fwd2, err := client.RemoteForwardEndpoint(fwdCtx2, ForwardSpec{
			Bind: ForwardEndpoint{Port: 0, Wildcard: true},
			Dest: ForwardEndpoint{Host: "127.0.0.1", Port: uint16(locPort)},
		})
		if err != nil {
			t.Fatalf("fwd2 failed: %v", err)
		}
		defer func() {
			cancelFwd2()
			_ = fwd2.Wait()
		}()

		reqs := fix.RequestedForwards()
		hasLocalhost := false
		hasWildcard := false
		for _, r := range reqs {
			if strings.HasPrefix(r, "localhost:0") {
				hasLocalhost = true
			}
			if strings.HasPrefix(r, ":0") {
				hasWildcard = true
			}
		}
		if !hasLocalhost {
			t.Errorf("expected requested forwards to contain localhost:0, got %v", reqs)
		}
		if !hasWildcard {
			t.Errorf("expected requested forwards to contain :0, got %v", reqs)
		}
	})
}

func TestForwardAlignment_ReverseDynamicForward(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, _ := newTestClientWithFixture(t, ctx)
	_, echoAddr := startEchoServer(t, "tcp", "127.0.0.1:0")
	_, echoPortStr, _ := net.SplitHostPort(echoAddr)
	echoPort, _ := strconv.Atoi(echoPortStr)

	// 1. Reverse Dynamic over TCP
	t.Run("TCP_Port_ReverseDynamic", func(t *testing.T) {
		fwdCtx, cancelFwd := context.WithCancel(ctx)
		fwd, err := client.RemoteForwardEndpoint(fwdCtx, ForwardSpec{
			Bind:      ForwardEndpoint{Port: 0},
			IsDynamic: true,
		})
		if err != nil {
			t.Fatalf("RemoteForwardEndpoint dynamic failed: %v", err)
		}
		defer func() {
			cancelFwd()
			_ = fwd.Wait()
		}()

		port := fwd.Addr().(*net.TCPAddr).Port
		remoteAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

		// Test SOCKS4a client against reverse dynamic listener
		conn4, err := net.Dial("tcp", remoteAddr)
		if err != nil {
			t.Fatalf("dial reverse dynamic TCP failed: %v", err)
		}
		performSocks4aConnect(t, conn4, "localhost", echoPort)
		verifyEchoRoundtrip(t, conn4, "socks4a-via-reverse-dynamic")
		_ = conn4.Close()

		// Test SOCKS5 client against reverse dynamic listener
		conn5, err := net.Dial("tcp", remoteAddr)
		if err != nil {
			t.Fatalf("dial reverse dynamic TCP failed: %v", err)
		}
		performSocks5Connect(t, conn5, "127.0.0.1", echoPort)
		verifyEchoRoundtrip(t, conn5, "socks5-via-reverse-dynamic")
		_ = conn5.Close()
	})

	// 2. Reverse Dynamic over remote Unix socket
	t.Run("Unix_Socket_ReverseDynamic", func(t *testing.T) {
		remSock := filepath.Join(shortSocketDir(t), "rem-dyn.sock")
		fwdCtx, cancelFwd := context.WithCancel(ctx)
		fwd, err := client.RemoteForwardEndpoint(fwdCtx, ForwardSpec{
			Bind:      ForwardEndpoint{SocketPath: remSock},
			IsDynamic: true,
		})
		if err != nil {
			t.Fatalf("RemoteForwardEndpoint dynamic unix failed: %v", err)
		}
		defer func() {
			cancelFwd()
			_ = fwd.Wait()
		}()

		conn, err := net.Dial("unix", remSock)
		if err != nil {
			t.Fatalf("dial reverse dynamic unix failed: %v", err)
		}
		performSocks5Connect(t, conn, "127.0.0.1", echoPort)
		verifyEchoRoundtrip(t, conn, "socks5-via-reverse-dynamic-unix")
		_ = conn.Close()
	})
}

func TestForwardAlignment_StreamLocal_BindMask(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping permissions test on Windows")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, _ := newTestClientWithFixture(t, ctx)
	_, echoAddr := startEchoServer(t, "tcp", "127.0.0.1:0")
	_, echoPortStr, _ := net.SplitHostPort(echoAddr)
	echoPort, _ := strconv.Atoi(echoPortStr)
	dest := ForwardEndpoint{Host: "127.0.0.1", Port: uint16(echoPort)}

	sock1 := filepath.Join(shortSocketDir(t), "mask1.sock")
	fwdCtx1, cancel1 := context.WithCancel(ctx)
	fwd1, err := client.LocalForwardEndpoint(fwdCtx1, ForwardEndpoint{SocketPath: sock1}, dest, false, WithStreamLocalBindMask(0o177))
	if err != nil {
		t.Fatalf("fwd1 failed: %v", err)
	}
	defer func() {
		cancel1()
		_ = fwd1.Wait()
	}()
	fi1, err := os.Lstat(sock1)
	if err != nil {
		t.Fatalf("stat sock1 failed: %v", err)
	}
	if fi1.Mode().Perm() != 0o600 {
		t.Errorf("expected 0600 perm, got %04o", fi1.Mode().Perm())
	}

	sock2 := filepath.Join(shortSocketDir(t), "mask2.sock")
	fwdCtx2, cancel2 := context.WithCancel(ctx)
	fwd2, err := client.LocalForwardEndpoint(fwdCtx2, ForwardEndpoint{SocketPath: sock2}, dest, false, WithStreamLocalBindMask(0o117))
	if err != nil {
		t.Fatalf("fwd2 failed: %v", err)
	}
	defer func() {
		cancel2()
		_ = fwd2.Wait()
	}()
	fi2, err := os.Lstat(sock2)
	if err != nil {
		t.Fatalf("stat sock2 failed: %v", err)
	}
	if fi2.Mode().Perm() != 0o660 {
		t.Errorf("expected 0660 perm, got %04o", fi2.Mode().Perm())
	}
}

func TestForwardAlignment_StreamLocal_BindUnlink(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, _ := newTestClientWithFixture(t, ctx)
	_, echoAddr := startEchoServer(t, "tcp", "127.0.0.1:0")
	_, echoPortStr, _ := net.SplitHostPort(echoAddr)
	echoPort, _ := strconv.Atoi(echoPortStr)
	dest := ForwardEndpoint{Host: "127.0.0.1", Port: uint16(echoPort)}

	// 1. BindUnlink false rejects existing file
	t.Run("BindUnlink_False_RejectsExisting", func(t *testing.T) {
		sock := filepath.Join(shortSocketDir(t), "existing.sock")
		if err := os.WriteFile(sock, []byte("data"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := client.LocalForwardEndpoint(ctx, ForwardEndpoint{SocketPath: sock}, dest, false, WithStreamLocalBindUnlink(false))
		if err == nil {
			t.Fatal("expected error on existing file when bindUnlink is false")
		}
		data, err := os.ReadFile(sock)
		if err != nil || string(data) != "data" {
			t.Fatalf("existing file was corrupted or deleted: %v", err)
		}
	})

	// 2. BindUnlink true replaces existing file
	t.Run("BindUnlink_True_ReplacesExisting", func(t *testing.T) {
		sock := filepath.Join(shortSocketDir(t), "replace.sock")
		if err := os.WriteFile(sock, []byte("stale"), 0o600); err != nil {
			t.Fatal(err)
		}
		fwdCtx, cancelFwd := context.WithCancel(ctx)
		fwd, err := client.LocalForwardEndpoint(fwdCtx, ForwardEndpoint{SocketPath: sock}, dest, false, WithStreamLocalBindUnlink(true))
		if err != nil {
			t.Fatalf("expected success with bindUnlink true, got: %v", err)
		}
		defer func() {
			cancelFwd()
			_ = fwd.Wait()
		}()

		conn, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatalf("dial replaced socket failed: %v", err)
		}
		defer func() { _ = conn.Close() }()
		verifyEchoRoundtrip(t, conn, "payload-after-replace")
	})

	// 3. BindUnlink true refuses to delete directory
	t.Run("BindUnlink_True_RefusesDirectory", func(t *testing.T) {
		dir := filepath.Join(shortSocketDir(t), "existing-dir")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		_, err := client.LocalForwardEndpoint(ctx, ForwardEndpoint{SocketPath: dir}, dest, false, WithStreamLocalBindUnlink(true))
		if err == nil {
			t.Fatal("expected error when target is a directory")
		}
		fi, err := os.Lstat(dir)
		if err != nil || !fi.IsDir() {
			t.Fatalf("directory was unexpectedly removed: %v", err)
		}
	})

	// 4. Forward cancellation unlinks socket
	t.Run("Cancellation_UnlinksSocket", func(t *testing.T) {
		sock := filepath.Join(shortSocketDir(t), "unlink-on-cancel.sock")
		fwdCtx, cancelFwd := context.WithCancel(ctx)
		fwd, err := client.LocalForwardEndpoint(fwdCtx, ForwardEndpoint{SocketPath: sock}, dest, false)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(sock); err != nil {
			t.Fatalf("socket should exist while forward is active: %v", err)
		}
		cancelFwd()
		_ = fwd.Wait()
		if _, err := os.Lstat(sock); !os.IsNotExist(err) {
			t.Fatalf("expected socket file to be removed after forward cancel, got err: %v", err)
		}
	})
}

// -----------------------------------------------------------------------------
// Group 3: MuxServer & MuxClient Forwarding Alignment
// -----------------------------------------------------------------------------

func TestForwardAlignment_MuxServer_GatewayPorts(t *testing.T) {
	// GatewayPorts false
	sFalse := &MuxServer{gatewayPorts: false}
	netw, addr, keyHost, err := sFalse.resolveMuxForwardListen(MUX_FWD_LOCAL, "", 8080)
	if err != nil || netw != "tcp" || addr != "127.0.0.1:8080" || keyHost != "127.0.0.1" {
		t.Fatalf("GatewayPorts false empty host failed: %s, %s, %s, %v", netw, addr, keyHost, err)
	}

	// Wildcard "*" with GatewayPorts false
	netw, addr, keyHost, err = sFalse.resolveMuxForwardListen(MUX_FWD_LOCAL, "*", 8080)
	if err != nil || netw != "tcp" || addr != ":8080" || keyHost != "*" {
		t.Fatalf("GatewayPorts false wildcard host failed: %s, %s, %s, %v", netw, addr, keyHost, err)
	}

	// GatewayPorts true
	sTrue := &MuxServer{gatewayPorts: true}
	netw, addr, keyHost, err = sTrue.resolveMuxForwardListen(MUX_FWD_LOCAL, "", 8080)
	if err != nil || netw != "tcp" || addr != ":8080" || keyHost != "*" {
		t.Fatalf("GatewayPorts true empty host failed: %s, %s, %s, %v", netw, addr, keyHost, err)
	}

	// Remote forward empty host -> localhost
	netw, addr, keyHost, err = sFalse.resolveMuxForwardListen(MUX_FWD_REMOTE, "", 8080)
	if err != nil || netw != "tcp" || addr != "localhost:8080" || keyHost != "localhost" {
		t.Fatalf("Remote forward empty host failed: %s, %s, %s, %v", netw, addr, keyHost, err)
	}
}

func TestForwardAlignment_MuxServer_StreamLocal_And_ReverseDynamic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fix, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fix.Close() })

	rawClient, err := cryptoSSH.Dial("tcp", fix.Address, &cryptoSSH.ClientConfig{
		User:            "test",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password(sshfixture.Password)},
		HostKeyCallback: cryptoSSH.FixedHostKey(fix.HostKey),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rawClient.Close() })

	masterSock := filepath.Join(shortSocketDir(t), "master.sock")
	server, err := NewMuxServer(MuxServerOptions{
		ControlPath:       masterSock,
		SSHClient:         rawClient,
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Shutdown() }()

	go func() { _ = server.Serve() }()

	muxCli, err := DialMuxClient(ctx, masterSock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = muxCli.Close() }()

	_, echoTCP := startEchoServer(t, "tcp", "127.0.0.1:0")
	_, echoPortStr, _ := net.SplitHostPort(echoTCP)
	echoPort, _ := strconv.Atoi(echoPortStr)

	// 1. MUX_FWD_LOCAL with StreamLocal destination
	t.Run("MuxLocal_StreamLocal_Dest", func(t *testing.T) {
		echoSock := filepath.Join(shortSocketDir(t), "echo-m-local.sock")
		_, _ = startEchoServer(t, "unix", echoSock)

		req := ForwardRequest{
			Type:        ForwardLocal,
			ListenHost:  "127.0.0.1",
			ListenPort:  0,
			ConnectHost: echoSock,
			ConnectPort: MUX_SPECIAL_PORT_UNIX,
		}
		// Since ListenPort is 0 on local, net.Listen on 127.0.0.1:0 binds an ephemeral port.
		// Wait, MuxClient.OpenForward only returns allocatedPort for ForwardRemote.
		// So let's find an available port to request:
		probeLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		locPort := uint32(probeLn.Addr().(*net.TCPAddr).Port)
		_ = probeLn.Close()
		req.ListenPort = locPort

		_, err = muxCli.OpenForward(ctx, req)
		if err != nil {
			t.Fatalf("OpenForward local failed: %v", err)
		}

		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", locPort))
		if err != nil {
			t.Fatalf("dial local forward failed: %v", err)
		}
		verifyEchoRoundtrip(t, conn, "mux-local-to-streamlocal")
		_ = conn.Close()

		if err := muxCli.CloseForward(ctx, req); err != nil {
			t.Fatalf("CloseForward failed: %v", err)
		}
	})

	// 2. MUX_FWD_REMOTE with reverse dynamic -R
	t.Run("MuxRemote_ReverseDynamic", func(t *testing.T) {
		req := ForwardRequest{
			Type:        ForwardRemote,
			ListenHost:  "localhost",
			ListenPort:  0,
			ConnectHost: "",
			ConnectPort: 0,
		}
		allocPort, err := muxCli.OpenForward(ctx, req)
		if err != nil {
			t.Fatalf("OpenForward reverse dynamic failed: %v", err)
		}
		if allocPort == 0 {
			t.Fatal("expected allocated remote port > 0")
		}

		conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(allocPort))))
		if err != nil {
			t.Fatalf("dial allocated port failed: %v", err)
		}
		defer func() { _ = conn.Close() }()

		performSocks5Connect(t, conn, "127.0.0.1", echoPort)
		verifyEchoRoundtrip(t, conn, "mux-reverse-dynamic-socks5")

		closeReq := req
		closeReq.ListenPort = allocPort
		if err := muxCli.CloseForward(ctx, closeReq); err != nil {
			t.Fatalf("CloseForward reverse dynamic failed: %v", err)
		}
	})
}

func TestForwardAlignment_Passenger_RemoteForwardAndCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fix, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fix.Close() })

	rawClient, err := cryptoSSH.Dial("tcp", fix.Address, &cryptoSSH.ClientConfig{
		User:            "test",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password(sshfixture.Password)},
		HostKeyCallback: cryptoSSH.FixedHostKey(fix.HostKey),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rawClient.Close() })

	masterSock := filepath.Join(shortSocketDir(t), "passenger-master.sock")
	server, err := NewMuxServer(MuxServerOptions{
		ControlPath:       masterSock,
		SSHClient:         rawClient,
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Shutdown() }()

	go func() { _ = server.Serve() }()

	host, portStr, _ := net.SplitHostPort(fix.Address)
	port, _ := strconv.Atoi(portStr)
	target := TargetContext{Host: host, Port: port, User: "test"}

	passengerClient, err := DialControlProxyClient(ctx, masterSock, target, Environment{}, nil, logger.NopLogger)
	if err != nil {
		t.Fatalf("DialControlProxyClient failed: %v", err)
	}
	defer func() { _ = passengerClient.Close() }()

	_, echoTCP := startEchoServer(t, "tcp", "127.0.0.1:0")
	_, echoPortStr, _ := net.SplitHostPort(echoTCP)
	echoPort, _ := strconv.Atoi(echoPortStr)

	// Passenger starts remote forward via RemoteForwardEndpoint
	fwdCtx, cancelFwd := context.WithCancel(ctx)
	fwd, err := passengerClient.RemoteForwardEndpoint(fwdCtx, ForwardSpec{
		Bind: ForwardEndpoint{Port: 0},
		Dest: ForwardEndpoint{Host: "127.0.0.1", Port: uint16(echoPort)},
	})
	if err != nil {
		t.Fatalf("passenger RemoteForwardEndpoint failed: %v", err)
	}

	remoteAddr := fwd.Addr().String()
	_, remPortStr, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		t.Fatalf("invalid fwd Addr: %s", remoteAddr)
	}
	remPort, _ := strconv.Atoi(remPortStr)
	if remPort == 0 {
		t.Fatalf("expected allocated port > 0, got %d", remPort)
	}

	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", remPortStr))
	if err != nil {
		t.Fatalf("dial passenger remote forward failed: %v", err)
	}
	verifyEchoRoundtrip(t, conn, "passenger-roundtrip")
	_ = conn.Close()

	// Cancel passenger forward context
	cancelFwd()
	select {
	case <-fwd.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for forward.Done after cancel")
	}

	// Verify remote forward is closed on MuxServer
	// Trying to dial the remote forward should fail or close promptly
	time.Sleep(50 * time.Millisecond)
	staleConn, dialErr := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", remPortStr), 200*time.Millisecond)
	if dialErr == nil {
		// If dial succeeded (e.g. OS backlog before teardown), writing should fail or EOF promptly
		_ = staleConn.SetDeadline(time.Now().Add(500 * time.Millisecond))
		_, writeErr := staleConn.Write([]byte("ping"))
		var buf [16]byte
		_, readErr := staleConn.Read(buf[:])
		_ = staleConn.Close()
		if writeErr == nil && readErr == nil {
			t.Errorf("expected connection through canceled forward to fail")
		}
	}
}

func TestForwardAlignment_MuxServer_DuplicateRemoteForwardRefCount(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fix, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fix.Close() })

	rawClient, err := cryptoSSH.Dial("tcp", fix.Address, &cryptoSSH.ClientConfig{
		User:            "test",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password(sshfixture.Password)},
		HostKeyCallback: cryptoSSH.FixedHostKey(fix.HostKey),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rawClient.Close() })

	masterSock := filepath.Join(shortSocketDir(t), "dup-fwd-master.sock")
	server, err := NewMuxServer(MuxServerOptions{
		ControlPath:       masterSock,
		SSHClient:         rawClient,
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Shutdown() }()

	go func() { _ = server.Serve() }()

	host, portStr, _ := net.SplitHostPort(fix.Address)
	port, _ := strconv.Atoi(portStr)
	target := TargetContext{Host: host, Port: port, User: "test"}

	passenger1, err := DialControlProxyClient(ctx, masterSock, target, Environment{}, nil, logger.NopLogger)
	if err != nil {
		t.Fatalf("DialControlProxyClient passenger1 failed: %v", err)
	}
	defer func() { _ = passenger1.Close() }()

	passenger2, err := DialControlProxyClient(ctx, masterSock, target, Environment{}, nil, logger.NopLogger)
	if err != nil {
		t.Fatalf("DialControlProxyClient passenger2 failed: %v", err)
	}
	defer func() { _ = passenger2.Close() }()

	_, echoTCP := startEchoServer(t, "tcp", "127.0.0.1:0")
	_, echoPortStr, _ := net.SplitHostPort(echoTCP)
	echoPort, _ := strconv.Atoi(echoPortStr)

	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	freePort := probeLn.Addr().(*net.TCPAddr).Port
	_ = probeLn.Close()

	spec := ForwardSpec{
		Bind: ForwardEndpoint{Port: uint16(freePort)},
		Dest: ForwardEndpoint{Host: "127.0.0.1", Port: uint16(echoPort)},
	}

	fwdCtx1, cancelFwd1 := context.WithCancel(ctx)
	fwd1, err := passenger1.RemoteForwardEndpoint(fwdCtx1, spec)
	if err != nil {
		t.Fatalf("passenger1 RemoteForwardEndpoint failed: %v", err)
	}

	fwdCtx2, cancelFwd2 := context.WithCancel(ctx)
	fwd2, err := passenger2.RemoteForwardEndpoint(fwdCtx2, spec)
	if err != nil {
		t.Fatalf("passenger2 RemoteForwardEndpoint failed: %v", err)
	}

	// Verify traffic echoes initially
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort)))
	if err != nil {
		t.Fatalf("dial remote forward failed: %v", err)
	}
	verifyEchoRoundtrip(t, conn, "passenger-shared-initial")
	_ = conn.Close()

	// Cancel second passenger's context and Wait() for it to finish CloseForward
	cancelFwd2()
	if err := fwd2.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		t.Logf("fwd2.Wait() returned: %v", err)
	}

	// Verify traffic through the remote forward STILL echoes for the first passenger
	connAfterP2, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort)))
	if err != nil {
		t.Fatalf("dial remote forward after passenger2 cancel failed: %v", err)
	}
	verifyEchoRoundtrip(t, connAfterP2, "passenger1-still-active")
	_ = connAfterP2.Close()

	// Cancel first passenger's context and Wait()
	cancelFwd1()
	if err := fwd1.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		t.Logf("fwd1.Wait() returned: %v", err)
	}

	// Verify remote listener is closed
	time.Sleep(50 * time.Millisecond)
	staleConn, dialErr := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort)), 200*time.Millisecond)
	if dialErr == nil {
		_ = staleConn.SetDeadline(time.Now().Add(500 * time.Millisecond))
		_, writeErr := staleConn.Write([]byte("ping"))
		var buf [16]byte
		_, readErr := staleConn.Read(buf[:])
		_ = staleConn.Close()
		if writeErr == nil && readErr == nil {
			t.Errorf("expected connection through canceled forward to fail")
		}
	}
}

func TestForwardAlignment_MuxServer_CancelPortZeroIgnoresStaticRemoteForward(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fix, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fix.Close() })

	rawClient, err := cryptoSSH.Dial("tcp", fix.Address, &cryptoSSH.ClientConfig{
		User:            "test",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password(sshfixture.Password)},
		HostKeyCallback: cryptoSSH.FixedHostKey(fix.HostKey),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rawClient.Close() })

	masterSock := filepath.Join(shortSocketDir(t), "cancel-zero-master.sock")
	server, err := NewMuxServer(MuxServerOptions{
		ControlPath:       masterSock,
		SSHClient:         rawClient,
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Shutdown() }()

	go func() { _ = server.Serve() }()

	muxCli, err := DialMuxClient(ctx, masterSock)
	if err != nil {
		t.Fatalf("DialMuxClient failed: %v", err)
	}
	defer func() { _ = muxCli.Close() }()

	_, echoTCP := startEchoServer(t, "tcp", "127.0.0.1:0")
	_, echoPortStr, _ := net.SplitHostPort(echoTCP)
	echoPort, _ := strconv.Atoi(echoPortStr)

	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	freePort := probeLn.Addr().(*net.TCPAddr).Port
	_ = probeLn.Close()

	// 1. Open a static remote forward (ListenPort > 0) to 127.0.0.1:<echoPort>
	staticReq := ForwardRequest{
		Type:        ForwardRemote,
		ListenHost:  "127.0.0.1",
		ListenPort:  uint32(freePort),
		ConnectHost: "127.0.0.1",
		ConnectPort: uint32(echoPort),
	}
	if _, err := muxCli.OpenForward(ctx, staticReq); err != nil {
		t.Fatalf("OpenForward static failed: %v", err)
	}

	// Verify static forward works
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort)))
	if err != nil {
		t.Fatalf("dial static remote forward failed: %v", err)
	}
	verifyEchoRoundtrip(t, conn, "static-initial")
	_ = conn.Close()

	// 2. Call CloseForward with ListenPort: 0 to the same destination and assert it fails
	// with "forwarding not found" while the static remote forward remains active
	cancelZeroReq := ForwardRequest{
		Type:        ForwardRemote,
		ListenHost:  "127.0.0.1",
		ListenPort:  0,
		ConnectHost: "127.0.0.1",
		ConnectPort: uint32(echoPort),
	}
	err = muxCli.CloseForward(ctx, cancelZeroReq)
	if err == nil || !strings.Contains(err.Error(), "forwarding not found") {
		t.Fatalf("expected 'forwarding not found' error, got %v", err)
	}

	// Verify static remote forward remains active
	connStillStatic, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort)))
	if err != nil {
		t.Fatalf("dial static forward after cancel-zero failed: %v", err)
	}
	verifyEchoRoundtrip(t, connStillStatic, "static-still-active")
	_ = connStillStatic.Close()

	// 3. Open a dynamic (ListenPort: 0) remote forward to the same destination
	dynReq := ForwardRequest{
		Type:        ForwardRemote,
		ListenHost:  "127.0.0.1",
		ListenPort:  0,
		ConnectHost: "127.0.0.1",
		ConnectPort: uint32(echoPort),
	}
	allocPort, err := muxCli.OpenForward(ctx, dynReq)
	if err != nil {
		t.Fatalf("OpenForward dynamic failed: %v", err)
	}
	if allocPort == 0 {
		t.Fatalf("expected allocPort > 0")
	}

	// Verify dynamic forward works
	connDyn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(allocPort))))
	if err != nil {
		t.Fatalf("dial dynamic forward failed: %v", err)
	}
	verifyEchoRoundtrip(t, connDyn, "dyn-active")
	_ = connDyn.Close()

	// 4. Call CloseForward with ListenPort: 0, and assert dynamic forward is closed
	// while the static remote forward STILL remains active
	if err := muxCli.CloseForward(ctx, cancelZeroReq); err != nil {
		t.Fatalf("CloseForward dynamic port 0 failed: %v", err)
	}

	// Verify dynamic forward is closed
	time.Sleep(50 * time.Millisecond)
	staleDynConn, dialErr := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(allocPort))), 200*time.Millisecond)
	if dialErr == nil {
		_ = staleDynConn.SetDeadline(time.Now().Add(500 * time.Millisecond))
		_, writeErr := staleDynConn.Write([]byte("ping"))
		var buf [16]byte
		_, readErr := staleDynConn.Read(buf[:])
		_ = staleDynConn.Close()
		if writeErr == nil && readErr == nil {
			t.Errorf("expected connection to canceled dynamic forward to fail")
		}
	}

	// Verify static remote forward STILL remains active
	connStaticFinal, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort)))
	if err != nil {
		t.Fatalf("dial static forward after dynamic cancel failed: %v", err)
	}
	verifyEchoRoundtrip(t, connStaticFinal, "static-still-active-after-dyn-cancel")
	_ = connStaticFinal.Close()

	// Clean up static forward
	if err := muxCli.CloseForward(ctx, staticReq); err != nil {
		t.Fatalf("CloseForward static failed: %v", err)
	}
}

func reserveFreeLocalTCPPort(t *testing.T) uint32 {
	t.Helper()
	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint32(probeLn.Addr().(*net.TCPAddr).Port)
	_ = probeLn.Close()
	return port
}

func assertMuxSingleCancelClosesPort(t *testing.T, ctx context.Context, muxCli *MuxClient, req ForwardRequest, port uint32) {
	t.Helper()
	if err := muxCli.CloseForward(ctx, req); err != nil {
		t.Fatalf("CloseForward failed: %v", err)
	}
	if err := muxCli.CloseForward(ctx, req); err == nil || !strings.Contains(err.Error(), "forwarding not found") {
		t.Fatalf("expected second CloseForward to fail with forwarding not found, got %v", err)
	}
	if c, dialErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 150*time.Millisecond); dialErr == nil {
		_ = c.Close()
		t.Fatalf("expected port %d to be closed after single CloseForward", port)
	}
}

func TestForwardAlignment_MuxServer_DuplicateLocalAndDynamicIdempotentCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fix, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fix.Close() })

	rawClient, err := cryptoSSH.Dial("tcp", fix.Address, &cryptoSSH.ClientConfig{
		User:            "test",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password(sshfixture.Password)},
		HostKeyCallback: cryptoSSH.FixedHostKey(fix.HostKey),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rawClient.Close() })

	masterSock := filepath.Join(shortSocketDir(t), "idemp-cancel.sock")
	server, err := NewMuxServer(MuxServerOptions{
		ControlPath:       masterSock,
		SSHClient:         rawClient,
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Shutdown() }()
	go func() { _ = server.Serve() }()

	muxCli, err := DialMuxClient(ctx, masterSock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = muxCli.Close() }()

	_, echoTCP := startEchoServer(t, "tcp", "127.0.0.1:0")
	_, echoPortStr, _ := net.SplitHostPort(echoTCP)
	echoPort, _ := strconv.Atoi(echoPortStr)

	t.Run("LocalForward_SingleCancelClosesAfterDuplicateOpen", func(t *testing.T) {
		locPort := reserveFreeLocalTCPPort(t)
		req := ForwardRequest{
			Type:        ForwardLocal,
			ListenHost:  "127.0.0.1",
			ListenPort:  locPort,
			ConnectHost: "127.0.0.1",
			ConnectPort: uint32(echoPort),
		}
		if _, err := muxCli.OpenForward(ctx, req); err != nil {
			t.Fatalf("first OpenForward local failed: %v", err)
		}
		if _, err := muxCli.OpenForward(ctx, req); err != nil {
			t.Fatalf("second OpenForward local failed: %v", err)
		}

		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", locPort))
		if err != nil {
			t.Fatalf("dial local forward failed: %v", err)
		}
		verifyEchoRoundtrip(t, conn, "idemp-local")
		_ = conn.Close()

		assertMuxSingleCancelClosesPort(t, ctx, muxCli, req, locPort)
	})

	t.Run("DynamicForward_SingleCancelClosesAfterDuplicateOpen", func(t *testing.T) {
		dynPort := reserveFreeLocalTCPPort(t)
		req := ForwardRequest{
			Type:       ForwardDynamic,
			ListenHost: "127.0.0.1",
			ListenPort: dynPort,
		}
		if _, err := muxCli.OpenForward(ctx, req); err != nil {
			t.Fatalf("first OpenForward dynamic failed: %v", err)
		}
		if _, err := muxCli.OpenForward(ctx, req); err != nil {
			t.Fatalf("second OpenForward dynamic failed: %v", err)
		}

		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", dynPort))
		if err != nil {
			t.Fatalf("dial dynamic forward failed: %v", err)
		}
		performSocks5Connect(t, conn, "127.0.0.1", echoPort)
		verifyEchoRoundtrip(t, conn, "idemp-dynamic")
		_ = conn.Close()

		assertMuxSingleCancelClosesPort(t, ctx, muxCli, req, dynPort)
	})
}

func TestForwardAlignment_MuxServer_BracketedIPv6AndPortZeroCancelIsolation(t *testing.T) {
	s := &MuxServer{}
	netw, addr, keyHost, err := s.resolveMuxForwardListen(MUX_FWD_LOCAL, "[::1]", 8080)
	if err != nil || netw != "tcp" || addr != "[::1]:8080" || keyHost != "::1" {
		t.Fatalf("bracketed IPv6 listen resolution failed: %s, %s, %s, %v", netw, addr, keyHost, err)
	}
	netw, addr, keyHost, err = s.resolveMuxForwardListen(MUX_FWD_LOCAL, "[*]", 8080)
	if err != nil || netw != "tcp" || addr != ":8080" || keyHost != "*" {
		t.Fatalf("bracketed wildcard listen resolution failed: %s, %s, %s, %v", netw, addr, keyHost, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fix, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fix.Close() })

	rawClient, err := cryptoSSH.Dial("tcp", fix.Address, &cryptoSSH.ClientConfig{
		User:            "test",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password(sshfixture.Password)},
		HostKeyCallback: cryptoSSH.FixedHostKey(fix.HostKey),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rawClient.Close() })

	masterSock := filepath.Join(shortSocketDir(t), "ipv6-mux.sock")
	server, err := NewMuxServer(MuxServerOptions{
		ControlPath:       masterSock,
		SSHClient:         rawClient,
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Shutdown() }()
	go func() { _ = server.Serve() }()

	muxCli, err := DialMuxClient(ctx, masterSock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = muxCli.Close() }()

	// Open a dynamic remote forward (ListenPort: 0) with bracketed ConnectHost "[::1]"
	openReq := ForwardRequest{
		Type:        ForwardRemote,
		ListenHost:  "127.0.0.1",
		ListenPort:  0,
		ConnectHost: "[::1]",
		ConnectPort: 8080,
	}
	allocPort, err := muxCli.OpenForward(ctx, openReq)
	if err != nil {
		t.Fatalf("OpenForward with bracketed [::1] ConnectHost failed: %v", err)
	}
	if allocPort == 0 {
		t.Fatal("expected allocated remote port > 0")
	}

	// Cancel attempt with ConnectHost "1" must NOT false-match "::1" via colon suffix ":1:8080"
	bogusCancel := ForwardRequest{
		Type:        ForwardRemote,
		ListenHost:  "127.0.0.1",
		ListenPort:  0,
		ConnectHost: "1",
		ConnectPort: 8080,
	}
	if err := muxCli.CloseForward(ctx, bogusCancel); err == nil || !strings.Contains(err.Error(), "forwarding not found") {
		t.Fatalf("expected bogus ConnectHost='1' cancel to fail with forwarding not found, got %v", err)
	}

	// Cancel with unbracketed "::1" must match the normalized entry and close it cleanly
	validCancel := ForwardRequest{
		Type:        ForwardRemote,
		ListenHost:  "127.0.0.1",
		ListenPort:  0,
		ConnectHost: "::1",
		ConnectPort: 8080,
	}
	if err := muxCli.CloseForward(ctx, validCancel); err != nil {
		t.Fatalf("expected normalized ConnectHost='::1' cancel to succeed, got %v", err)
	}
}

func TestForwardAlignment_Passenger_ClientCloseWithoutCtxCancelCleansUpRemoteForward(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fix, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fix.Close() })

	rawClient, err := cryptoSSH.Dial("tcp", fix.Address, &cryptoSSH.ClientConfig{
		User:            "test",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password(sshfixture.Password)},
		HostKeyCallback: cryptoSSH.FixedHostKey(fix.HostKey),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rawClient.Close() })

	masterSock := filepath.Join(shortSocketDir(t), "pclose-master.sock")
	server, err := NewMuxServer(MuxServerOptions{
		ControlPath:       masterSock,
		SSHClient:         rawClient,
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Shutdown() }()
	go func() { _ = server.Serve() }()

	host, portStr, _ := net.SplitHostPort(fix.Address)
	port, _ := strconv.Atoi(portStr)
	target := TargetContext{Host: host, Port: port, User: "test"}

	passengerClient, err := DialControlProxyClient(ctx, masterSock, target, Environment{}, nil, logger.NopLogger)
	if err != nil {
		t.Fatalf("DialControlProxyClient failed: %v", err)
	}

	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	freePort := probeLn.Addr().(*net.TCPAddr).Port
	_ = probeLn.Close()

	// Do NOT cancel ctx; close passengerClient directly while master remains running.
	fwd, err := passengerClient.RemoteForwardEndpoint(ctx, ForwardSpec{
		Bind: ForwardEndpoint{Host: "127.0.0.1", Port: uint16(freePort)},
		Dest: ForwardEndpoint{Host: "127.0.0.1", Port: 9},
	})
	if err != nil {
		t.Fatalf("passenger RemoteForwardEndpoint failed: %v", err)
	}

	_ = passengerClient.Close()

	waitErr := fwd.Wait()
	if waitErr == nil {
		t.Fatal("expected error from fwd.Wait() when passenger client transport closed")
	}

	muxCli, err := DialMuxClient(ctx, masterSock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = muxCli.Close() }()

	checkReq := ForwardRequest{
		Type:        ForwardRemote,
		ListenHost:  "127.0.0.1",
		ListenPort:  uint32(freePort),
		ConnectHost: "127.0.0.1",
		ConnectPort: 9,
	}
	if err := muxCli.CloseForward(ctx, checkReq); err == nil || !strings.Contains(err.Error(), "forwarding not found") {
		t.Fatalf("expected passenger remote forward to be cleaned up on master after client.Close(), got %v", err)
	}
}
