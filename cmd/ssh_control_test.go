package cmd

import (
	"bytes"
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
	"syscall"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func createTestMuxMasterServer(t *testing.T) (string, net.Listener) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "ctrl-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	sockPath := filepath.Join(tmpDir, "master.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		t.Fatalf("Listen unix failed: %v", err)
	}
	t.Cleanup(func() {
		_ = ln.Close()
		_ = os.RemoveAll(tmpDir)
	})
	return sockPath, ln
}

func handleTestMasterConnection(conn net.Conn, pid uint32) {
	defer func() { _ = conn.Close() }()

	// Handshake
	pktType, _, err := ssh.ReadMuxPacket(conn)
	if err != nil || pktType != ssh.MUX_MSG_HELLO {
		return
	}
	exts := []ssh.MuxExtension{{Name: "info", Value: "1"}}
	_ = ssh.WriteMuxPacket(conn, ssh.MUX_MSG_HELLO, ssh.EncodeMuxHello(ssh.MuxProtoVersion, exts))

	for {
		msgType, payload, err := ssh.ReadMuxPacket(conn)
		if err != nil {
			return
		}
		switch msgType {
		case ssh.MUX_C_ALIVE_CHECK:
			reqID, _ := ssh.DecodeMuxRequestID(payload)
			_ = ssh.WriteMuxPacket(conn, ssh.MUX_S_ALIVE, ssh.EncodeMuxAlive(reqID, pid))
		case ssh.MUX_C_TERMINATE:
			reqID, _ := ssh.DecodeMuxRequestID(payload)
			_ = ssh.WriteMuxPacket(conn, ssh.MUX_S_OK, ssh.EncodeMuxClientRequestID(reqID))
			return
		case ssh.MUX_C_STOP_LISTENING:
			reqID, _ := ssh.DecodeMuxRequestID(payload)
			_ = ssh.WriteMuxPacket(conn, ssh.MUX_S_OK, ssh.EncodeMuxClientRequestID(reqID))
		case ssh.MUX_C_OPEN_FWD:
			req, _ := ssh.DecodeMuxFwdRequest(payload)
			_ = ssh.WriteMuxPacket(conn, ssh.MUX_S_OK, ssh.EncodeMuxClientRequestID(req.RequestID))
		case ssh.MUX_C_CLOSE_FWD:
			req, _ := ssh.DecodeMuxFwdRequest(payload)
			_ = ssh.WriteMuxPacket(conn, ssh.MUX_S_OK, ssh.EncodeMuxClientRequestID(req.RequestID))
		case ssh.MUX_C_PROXY:
			reqID, _ := ssh.DecodeMuxRequestID(payload)
			_ = ssh.WriteMuxPacket(conn, ssh.MUX_S_PROXY, ssh.EncodeMuxClientRequestID(reqID))
			// Echo server for proxy test
			buf := make([]byte, 1024)
			for {
				n, err := conn.Read(buf)
				if n > 0 {
					_, _ = conn.Write(buf[:n])
				}
				if err != nil {
					return
				}
			}
		case ssh.MUX_C_EXT_INFO:
			reqID, name, _ := ssh.DecodeMuxExtInfo(payload)
			switch name {
			case "connection":
				_ = ssh.WriteMuxPacket(conn, ssh.MUX_S_EXT_INFO, ssh.EncodeMuxExtInfoResponse(reqID, 1, "Master info test connection\n"))
			case "channels":
				_ = ssh.WriteMuxPacket(conn, ssh.MUX_S_EXT_INFO, ssh.EncodeMuxExtInfoResponse(reqID, 1, "Active Forwardings:\n- 1:127.0.0.1:8080\n"))
			default:
				_ = ssh.WriteMuxPacket(conn, ssh.MUX_S_FAILURE, ssh.EncodeMuxError(reqID, "unknown info"))
			}
		}
	}
}

func TestControl_Check_Alive(t *testing.T) {
	sockPath, ln := createTestMuxMasterServer(t)
	expectedPID := uint32(12345)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleTestMasterConnection(conn, expectedPID)
		}
	}()

	var stdout, stderr bytes.Buffer
	streams := controlStreams{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	}

	opts := &SshOptions{
		control: SSHControlFlags{
			CtlCmd:      "check",
			ControlPath: sockPath,
		},
	}

	err := executeControlCommandWithStreams(context.Background(), opts, streams)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedStderr := fmt.Sprintf("Master running (pid=%d)\n", expectedPID)
	if stderr.String() != expectedStderr {
		t.Fatalf("expected stderr %q, got %q", expectedStderr, stderr.String())
	}
}

func TestControl_Check_NoSuchFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ctrl-missing-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	nonExistentSock := filepath.Join(tmpDir, "non_existent.sock")

	var stdout, stderr bytes.Buffer
	streams := controlStreams{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	}

	opts := &SshOptions{
		control: SSHControlFlags{
			CtlCmd:      "check",
			ControlPath: nonExistentSock,
		},
	}

	err = executeControlCommandWithStreams(context.Background(), opts, streams)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	code, ok := ExitCodeFromError(err)
	if !ok || code != 255 {
		t.Fatalf("expected exit code 255, got code=%d (ok=%v)", code, ok)
	}

	expectedPrefix := fmt.Sprintf("Control socket connect(%s): No such file or directory", nonExistentSock)
	if !strings.Contains(stderr.String(), expectedPrefix) {
		t.Fatalf("expected stderr to contain %q, got %q", expectedPrefix, stderr.String())
	}
}

func TestControl_Check_ConnectionRefused(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ctrl-refused-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	staleSock := filepath.Join(tmpDir, "stale.sock")
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("syscall.Socket failed: %v", err)
	}
	sa := &syscall.SockaddrUnix{Name: staleSock}
	if err := syscall.Bind(fd, sa); err != nil {
		_ = syscall.Close(fd)
		t.Fatalf("syscall.Bind failed: %v", err)
	}
	_ = syscall.Close(fd) // Close without unlink creates stale socket file

	var stdout, stderr bytes.Buffer
	streams := controlStreams{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	}

	opts := &SshOptions{
		control: SSHControlFlags{
			CtlCmd:      "check",
			ControlPath: staleSock,
		},
	}

	err = executeControlCommandWithStreams(context.Background(), opts, streams)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	code, ok := ExitCodeFromError(err)
	if !ok || code != 255 {
		t.Fatalf("expected exit code 255, got code=%d (ok=%v)", code, ok)
	}

	expectedPrefix := fmt.Sprintf("Control socket connect(%s): Connection refused", staleSock)
	if !strings.Contains(stderr.String(), expectedPrefix) {
		t.Fatalf("expected stderr to contain %q, got %q", expectedPrefix, stderr.String())
	}
}

func TestControl_Exit_Success(t *testing.T) {
	sockPath, ln := createTestMuxMasterServer(t)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleTestMasterConnection(conn, 12345)
		}
	}()

	var stdout, stderr bytes.Buffer
	streams := controlStreams{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	}

	opts := &SshOptions{
		control: SSHControlFlags{
			CtlCmd:      "exit",
			ControlPath: sockPath,
		},
	}

	err := executeControlCommandWithStreams(context.Background(), opts, streams)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedStderr := "Exit request sent.\n"
	if stderr.String() != expectedStderr {
		t.Fatalf("expected stderr %q, got %q", expectedStderr, stderr.String())
	}
}

func TestControl_Stop_Success(t *testing.T) {
	sockPath, ln := createTestMuxMasterServer(t)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleTestMasterConnection(conn, 12345)
		}
	}()

	var stdout, stderr bytes.Buffer
	streams := controlStreams{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	}

	opts := &SshOptions{
		control: SSHControlFlags{
			CtlCmd:      "stop",
			ControlPath: sockPath,
		},
	}

	err := executeControlCommandWithStreams(context.Background(), opts, streams)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedStderr := "Stop listening request sent.\n"
	if stderr.String() != expectedStderr {
		t.Fatalf("expected stderr %q, got %q", expectedStderr, stderr.String())
	}
}

func TestControl_Forward_LocalRemoteDynamic(t *testing.T) {
	sockPath, ln := createTestMuxMasterServer(t)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleTestMasterConnection(conn, 12345)
		}
	}()

	var stdout, stderr bytes.Buffer
	streams := controlStreams{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	}

	opts := &SshOptions{
		LocalForwards:  []string{"8080:localhost:80"},
		RemoteForwards: []string{"9090:localhost:90"},
		DynamicForward: "1080",
		control: SSHControlFlags{
			CtlCmd:      "forward",
			ControlPath: sockPath,
		},
	}

	err := executeControlCommandWithStreams(context.Background(), opts, streams)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedStderr := "Forwarding request sent.\n"
	if stderr.String() != expectedStderr {
		t.Fatalf("expected stderr %q, got %q", expectedStderr, stderr.String())
	}
}

func TestControl_Cancel_Success(t *testing.T) {
	sockPath, ln := createTestMuxMasterServer(t)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleTestMasterConnection(conn, 12345)
		}
	}()

	var stdout, stderr bytes.Buffer
	streams := controlStreams{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	}

	opts := &SshOptions{
		LocalForwards: []string{"8080:localhost:80"},
		control: SSHControlFlags{
			CtlCmd:      "cancel",
			ControlPath: sockPath,
		},
	}

	err := executeControlCommandWithStreams(context.Background(), opts, streams)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedStderr := "Forwarding cancel request sent.\n"
	if stderr.String() != expectedStderr {
		t.Fatalf("expected stderr %q, got %q", expectedStderr, stderr.String())
	}
}

func TestControl_Proxy_BidirectionalPipe(t *testing.T) {
	sockPath, ln := createTestMuxMasterServer(t)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleTestMasterConnection(conn, 12345)
		}
	}()

	input := "echo hello from test proxy input\n"
	var stdout, stderr bytes.Buffer
	streams := controlStreams{
		Stdin:  strings.NewReader(input),
		Stdout: &stdout,
		Stderr: &stderr,
	}

	opts := &SshOptions{
		control: SSHControlFlags{
			CtlCmd:      "proxy-stream",
			ControlPath: sockPath,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := executeControlCommandWithStreams(ctx, opts, streams)
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unexpected error: %v", err)
	}

	if stdout.String() != input {
		t.Fatalf("expected echoed output %q, got %q", input, stdout.String())
	}
}

func TestControl_Info_ConnectionAndChannels(t *testing.T) {
	sockPath, ln := createTestMuxMasterServer(t)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleTestMasterConnection(conn, 12345)
		}
	}()

	// 1. conninfo
	{
		var stdout, stderr bytes.Buffer
		streams := controlStreams{
			Stdin:  strings.NewReader(""),
			Stdout: &stdout,
			Stderr: &stderr,
		}
		opts := &SshOptions{
			control: SSHControlFlags{
				CtlCmd:      "conninfo",
				ControlPath: sockPath,
			},
		}
		if err := executeControlCommandWithStreams(context.Background(), opts, streams); err != nil {
			t.Fatalf("conninfo error: %v", err)
		}
		if !strings.Contains(stdout.String(), "Master info test connection") {
			t.Fatalf("unexpected conninfo output: %q", stdout.String())
		}
	}

	// 2. channels
	{
		var stdout, stderr bytes.Buffer
		streams := controlStreams{
			Stdin:  strings.NewReader(""),
			Stdout: &stdout,
			Stderr: &stderr,
		}
		opts := &SshOptions{
			control: SSHControlFlags{
				CtlCmd:      "channels",
				ControlPath: sockPath,
			},
		}
		if err := executeControlCommandWithStreams(context.Background(), opts, streams); err != nil {
			t.Fatalf("channels error: %v", err)
		}
		if !strings.Contains(stdout.String(), "Active Forwardings:") {
			t.Fatalf("unexpected channels output: %q", stdout.String())
		}
	}
}

func TestControl_MissingControlPath(t *testing.T) {
	var stdout, stderr bytes.Buffer
	streams := controlStreams{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	}

	// Host not in config, no -S specified
	opts := &SshOptions{
		Host: "non_existent_unconfigured_host_12345",
		control: SSHControlFlags{
			CtlCmd: "check",
		},
	}

	err := executeControlCommandWithStreams(context.Background(), opts, streams)
	if err == nil {
		t.Fatal("expected error on missing ControlPath, got nil")
	}

	code, ok := ExitCodeFromError(err)
	if !ok || code != 255 {
		t.Fatalf("expected exit code 255, got %d", code)
	}

	if !strings.Contains(stderr.String(), "ControlPath must be specified when using -O") {
		t.Fatalf("expected missing ControlPath error, got stderr: %q", stderr.String())
	}
}

// TestControlProxyRejectsForeignMaster verifies that -O proxy performs the same
// peer-UID validation as every other control path instead of hand-rolling the
// handshake and trusting whatever listens on the path.
func TestControlProxyRejectsForeignMaster(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("peer credentials are unavailable on Windows")
	}

	sockPath, ln := createTestMuxMasterServer(t)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleTestMasterConnection(conn, 1)
		}
	}()

	// A raw connection proves the endpoint answers, so a failure below is the
	// client's own validation rather than an unreachable socket.
	raw, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	_ = raw.Close()

	stream, err := ssh.DialMuxProxyStream(context.Background(), sockPath, ssh.WithExpectedPeerUID(uint32(os.Geteuid())+1))
	if err == nil {
		_ = stream.Close()
		t.Fatal("expected the proxy stream to be rejected for a foreign peer UID")
	}
	if !errors.Is(err, ssh.ErrUnauthorizedPeer) {
		t.Fatalf("expected ErrUnauthorizedPeer, got %v", err)
	}

	// The same endpoint is accepted when the expectation matches the owner.
	stream, err = ssh.DialMuxProxyStream(context.Background(), sockPath)
	if err != nil {
		t.Fatalf("DialMuxProxyStream with the local UID failed: %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("close proxy stream failed: %v", err)
	}
}

func TestControl_ForwardAndCancel_ErrorPrefixNotDuplicated(t *testing.T) {
	sockPath, ln := createTestMuxMasterServer(t)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				pktType, _, err := ssh.ReadMuxPacket(c)
				if err != nil || pktType != ssh.MUX_MSG_HELLO {
					return
				}
				_ = ssh.WriteMuxPacket(c, ssh.MUX_MSG_HELLO, ssh.EncodeMuxHello(ssh.MuxProtoVersion, nil))
				msgType, payload, err := ssh.ReadMuxPacket(c)
				if err != nil {
					return
				}
				req, _ := ssh.DecodeMuxFwdRequest(payload)
				switch msgType {
				case ssh.MUX_C_OPEN_FWD:
					_ = ssh.WriteMuxPacket(c, ssh.MUX_S_FAILURE, ssh.EncodeMuxError(req.RequestID, "forwarding already exists"))
				case ssh.MUX_C_CLOSE_FWD:
					_ = ssh.WriteMuxPacket(c, ssh.MUX_S_FAILURE, ssh.EncodeMuxError(req.RequestID, "forwarding not found"))
				}
			}(conn)
		}
	}()

	// 1. Forward error must not duplicate "forwarding request failed: "
	{
		var stdout, stderr bytes.Buffer
		streams := controlStreams{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr}
		opts := &SshOptions{
			LocalForwards: []string{"8080:localhost:80"},
			control:       SSHControlFlags{CtlCmd: "forward", ControlPath: sockPath},
		}
		err := executeControlCommandWithStreams(context.Background(), opts, streams)
		if err == nil {
			t.Fatal("expected forward error, got nil")
		}
		if got := stderr.String(); strings.Count(got, "forwarding request failed:") != 1 {
			t.Fatalf("expected single 'forwarding request failed:' prefix, got: %q", got)
		}
	}

	// 2. Cancel error must not duplicate "cancel forward failed: "
	{
		var stdout, stderr bytes.Buffer
		streams := controlStreams{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr}
		opts := &SshOptions{
			LocalForwards: []string{"8080:localhost:80"},
			control:       SSHControlFlags{CtlCmd: "cancel", ControlPath: sockPath},
		}
		err := executeControlCommandWithStreams(context.Background(), opts, streams)
		if err == nil {
			t.Fatal("expected cancel error, got nil")
		}
		if got := stderr.String(); strings.Count(got, "cancel forward failed:") != 1 {
			t.Fatalf("expected single 'cancel forward failed:' prefix, got: %q", got)
		}
	}
}

func TestControl_Proxy_EmptyStdinReceivesInitialServerPacket(t *testing.T) {
	sockPath, ln := createTestMuxMasterServer(t)

	const serverGreeting = "SSH-PROXY-INITIAL-PACKET\n"
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				pktType, _, err := ssh.ReadMuxPacket(c)
				if err != nil || pktType != ssh.MUX_MSG_HELLO {
					return
				}
				_ = ssh.WriteMuxPacket(c, ssh.MUX_MSG_HELLO, ssh.EncodeMuxHello(ssh.MuxProtoVersion, nil))
				msgType, payload, err := ssh.ReadMuxPacket(c)
				if err != nil || msgType != ssh.MUX_C_PROXY {
					return
				}
				reqID, _ := ssh.DecodeMuxRequestID(payload)
				_ = ssh.WriteMuxPacket(c, ssh.MUX_S_PROXY, ssh.EncodeMuxClientRequestID(reqID))
				// Simulate master writing initial packet and then closing when done
				_, _ = c.Write([]byte(serverGreeting))
			}(conn)
		}
	}()

	var stdout, stderr bytes.Buffer
	streams := controlStreams{
		Stdin:  strings.NewReader(""), // immediate EOF like `< /dev/null`
		Stdout: &stdout,
		Stderr: &stderr,
	}
	opts := &SshOptions{
		control: SSHControlFlags{
			CtlCmd:      "proxy-stream",
			ControlPath: sockPath,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := executeControlCommandWithStreams(ctx, opts, streams); err != nil {
		t.Fatalf("executeControlCommandWithStreams(proxy-stream) failed: %v", err)
	}
	if stdout.String() != serverGreeting {
		t.Fatalf("expected initial server packet %q on stdout, got %q", serverGreeting, stdout.String())
	}
}

func runControlProxyTestCommand(ctx context.Context, t *testing.T, args []string) (string, string, error) {
	t.Helper()
	return runControlProxyTestCommandWithStdin(ctx, t, args, strings.NewReader(""), false)
}

func runControlProxyTestCommandWithStdin(ctx context.Context, t *testing.T, args []string, stdin io.Reader, stdinScript bool) (string, string, error) {
	t.Helper()
	opts := NewSshOptions()
	cmd := newCmdSshWithOptions(opts)
	if err := cmd.Flags().Parse(args); err != nil {
		t.Fatalf("Flags().Parse failed: %v", err)
	}
	if err := opts.Complete(cmd, cmd.Flags().Args()); err != nil {
		t.Fatalf("Complete failed: %v", err)
	}
	opts.stdinScript = stdinScript
	if err := opts.Validate(); err != nil {
		return "", "", err
	}
	var stdout, stderr bytes.Buffer
	err := executeControlCommandWithStreams(ctx, opts, controlStreams{
		Stdin:  stdin,
		Stdout: &stdout,
		Stderr: &stderr,
	})
	return stdout.String(), stderr.String(), err
}

func setupControlProxySessionFixture(ctx context.Context, t *testing.T) (string, string) {
	t.Helper()
	fixture, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		ExecHandler: func(cmd string, ch cryptoSSH.Channel) {
			switch strings.TrimSpace(cmd) {
			case "exit 42":
				_, _ = io.WriteString(ch.Stderr(), "remote-fail-42\n")
				_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{42}))
			default:
				_, _ = io.WriteString(ch, "P1_PROXY_OK:"+cmd+"\n")
				_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
			}
		},
		ShellHandler: func(ch cryptoSSH.Channel, requests <-chan *cryptoSSH.Request) {
			go cryptoSSH.DiscardRequests(requests)
			data, _ := io.ReadAll(ch)
			_, _ = io.WriteString(ch, "SHELL_PIPED:"+strings.TrimSpace(string(data))+"\n")
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
			_ = ch.Close()
		},
	})
	if err != nil {
		t.Fatalf("sshfixture.NewWithOptions failed: %v", err)
	}
	t.Cleanup(func() { _ = fixture.Close() })

	host, portText, err := net.SplitHostPort(fixture.Address)
	if err != nil {
		t.Fatalf("SplitHostPort failed: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("Atoi failed: %v", err)
	}

	rawClient, err := cryptoSSH.Dial("tcp", fixture.Address, &cryptoSSH.ClientConfig{
		User:            "fixture",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password(sshfixture.Password)},
		HostKeyCallback: cryptoSSH.FixedHostKey(fixture.HostKey),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("cryptoSSH.Dial failed: %v", err)
	}
	t.Cleanup(func() { _ = rawClient.Close() })

	tmpDir, err := os.MkdirTemp("", "ctrl-proxy-session-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })
	sockPath := filepath.Join(tmpDir, "master.sock")

	muxServer, err := ssh.NewMuxServer(ssh.MuxServerOptions{
		ControlPath:       sockPath,
		SSHClient:         rawClient,
		Target:            ssh.TargetContext{Host: host, Port: port, User: "fixture"},
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	go func() { _ = muxServer.Serve() }()
	t.Cleanup(func() { _ = muxServer.Shutdown() })

	return sockPath, fmt.Sprintf("fixture@%s:%d", host, port)
}

func TestControl_Proxy_ExecutesSessionAndPropagatesExitCode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	sockPath, targetAddr := setupControlProxySessionFixture(ctx, t)

	// 1. xops ssh -O proxy -S <sock> <host> -- 'echo P1_PROXY_OK'
	stdout, stderr, err := runControlProxyTestCommand(ctx, t, []string{"-O", "proxy", "-S", sockPath, targetAddr, "--", "echo P1_PROXY_OK"})
	if err != nil || strings.TrimSpace(stdout) != "P1_PROXY_OK:echo P1_PROXY_OK" {
		t.Fatalf("unexpected proxy result: err=%v stdout=%q stderr=%q", err, stdout, stderr)
	}

	// 2. Positional <host> with piped script (stdinScript=true) must NOT treat <host> as a command
	stdout, stderr, err = runControlProxyTestCommandWithStdin(ctx, t, []string{"-O", "proxy", "-S", sockPath, targetAddr}, strings.NewReader("echo piped1\n"), true)
	if err != nil || strings.TrimSpace(stdout) != "SHELL_PIPED:echo piped1" {
		t.Fatalf("unexpected piped shell result: err=%v stdout=%q stderr=%q", err, stdout, stderr)
	}

	// 3. Non-TTY stdin (/dev/null, stdinScript=false) without command fails immediately with terminal requirement
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open DevNull failed: %v", err)
	}
	defer func() { _ = devNull.Close() }()
	_, stderr, err = runControlProxyTestCommandWithStdin(ctx, t, []string{"-O", "proxy", "-S", sockPath, targetAddr}, devNull, false)
	if code, ok := ExitCodeFromError(err); !ok || code != 255 || !strings.Contains(stderr, "interactive stdin requires a local terminal") {
		t.Fatalf("expected non-TTY interactive failure (255), got code=%d ok=%v err=%v stderr=%q", code, ok, err, stderr)
	}

	// 4. Missing target host for -O proxy is rejected in Validate() with exit code 255
	_, _, err = runControlProxyTestCommand(ctx, t, []string{"-O", "proxy", "-S", sockPath})
	if code, ok := ExitCodeFromError(err); !ok || code != 255 {
		t.Fatalf("expected missing target host to fail with 255, got code=%d ok=%v err=%v", code, ok, err)
	}

	// 5. Non-zero remote exit code propagation (42)
	_, stderr, err = runControlProxyTestCommand(ctx, t, []string{"-O", "proxy", "-S", sockPath, targetAddr, "--", "exit 42"})
	if code, ok := ExitCodeFromError(err); !ok || code != 42 || !ErrorAlreadyReported(err) || !strings.Contains(stderr, "remote-fail-42") {
		t.Fatalf("unexpected exit 42 result: code=%d ok=%v err=%v stderr=%q", code, ok, err, stderr)
	}

	// 6. Target mismatch fails closed with exit code 255
	_, stderr, err = runControlProxyTestCommand(ctx, t, []string{"-O", "proxy", "-S", sockPath, "fixture@wrong.example.com:22", "--", "echo should_not_run"})
	if code, ok := ExitCodeFromError(err); !ok || code != 255 || !strings.Contains(stderr, "control socket target mismatch") {
		t.Fatalf("unexpected target mismatch result: code=%d ok=%v err=%v stderr=%q", code, ok, err, stderr)
	}
}

func TestControl_Proxy_DeferredInterpreterValidationBeforeDial(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	missingSock := filepath.Join(t.TempDir(), "never_dialed.sock")
	_, stderr, err := runControlProxyTestCommand(ctx, t, []string{"-O", "proxy", "-S", missingSock, "--interpreter", "powershell", "fixture@127.0.0.1:22", "--", "Get-Date"})
	if code, ok := ExitCodeFromError(err); !ok || code != 255 || !strings.Contains(stderr, `powershell interpreter requires cmd or powershell launch dialect`) {
		t.Fatalf("expected deferred interpreter error before socket dial (255), got code=%d ok=%v err=%v stderr=%q", code, ok, err, stderr)
	}
}

func TestProgrammaticGeneralOptions_AppliedWithoutComplete(t *testing.T) {
	// 1. Programmatic SshOptions (without Complete) applies -o Port/User/IdentityFile/ProxyJump,
	// while explicit struct fields take precedence over -o options.
	progOpts := &SshOptions{
		args: []string{"10.11.12.13"},
		control: SSHControlFlags{
			Options: []string{
				"Port=2202",
				"User=optuser",
				"IdentityFile=/tmp/opt_id_ed25519",
				"ProxyJump=jump-opt",
			},
		},
	}
	if err := progOpts.ensureArgsParsed(); err != nil {
		t.Fatalf("progOpts.ensureArgsParsed() failed: %v", err)
	}
	if progOpts.Port != 2202 || progOpts.User != "optuser" || progOpts.IdentityFile != "/tmp/opt_id_ed25519" || progOpts.JumpHost != "jump-opt" {
		t.Fatalf("unexpected programmatic option fields: Port=%d User=%q IdentityFile=%q JumpHost=%q",
			progOpts.Port, progOpts.User, progOpts.IdentityFile, progOpts.JumpHost)
	}
	if progOpts.Target.Port != 2202 || !progOpts.Target.HasPort || progOpts.Target.User != "optuser" || !progOpts.Target.HasUser {
		t.Fatalf("expected Target to reflect -o Port and User, got %+v", progOpts.Target)
	}

	// Explicit struct fields take precedence over -o when flags == nil
	explicitWinsOpts := &SshOptions{
		args:         []string{"10.11.12.13"},
		Port:         2299,
		User:         "explicituser",
		IdentityFile: "/tmp/explicit_key",
		JumpHost:     "explicit-jump",
		control: SSHControlFlags{
			Options: []string{
				"Port=2202",
				"User=optuser",
				"IdentityFile=/tmp/opt_id_ed25519",
				"ProxyJump=jump-opt",
			},
		},
	}
	if err := explicitWinsOpts.ensureArgsParsed(); err != nil {
		t.Fatalf("explicitWinsOpts.ensureArgsParsed() failed: %v", err)
	}
	if explicitWinsOpts.Port != 2299 || explicitWinsOpts.User != "explicituser" ||
		explicitWinsOpts.IdentityFile != "/tmp/explicit_key" || explicitWinsOpts.JumpHost != "explicit-jump" {
		t.Fatalf("expected explicit struct fields to win over -o, got Port=%d User=%q IdentityFile=%q JumpHost=%q",
			explicitWinsOpts.Port, explicitWinsOpts.User, explicitWinsOpts.IdentityFile, explicitWinsOpts.JumpHost)
	}
}

func TestBuildControlProxyClientConfig_NormalizesAndPropagatesJump(t *testing.T) {
	scpOpts := &ScpOptions{
		SshOptions: SshOptions{
			control: SSHControlFlags{
				Options: []string{"Port=2244", "User=scpopt", "ProxyJump=scp-jump"},
			},
		},
	}
	scpTarget, err := scpOpts.resolveTargetForPath(PathInfo{Host: "10.22.33.44", Path: "/tmp/a", IsRemote: true})
	if err != nil {
		t.Fatalf("scpOpts.resolveTargetForPath failed: %v", err)
	}
	if scpTarget.Port != 2244 || !scpTarget.HasPort || scpTarget.User != "scpopt" || !scpTarget.HasUser || scpTarget.ProxyJump != "scp-jump" || !scpTarget.HasProxyJump {
		t.Fatalf("unexpected scpTarget from programmatic -o: %+v", scpTarget)
	}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-zero", models.Host{Address: "10.55.66.77", Port: 0})
	cfg.Identities.Set("id-empty", models.Identity{User: "", AuthType: "password", Password: "pw"})
	cfg.Nodes.Set("node-zero", models.Node{HostRef: "h-zero", IdentityRef: "id-empty"})
	provider := config.NewProviderWithoutOpenSSH(cfg)

	proxyOpts := &SshOptions{
		JumpHost: "10.55.66.1:22",
	}
	targetCtx := ssh.TargetContext{
		Host:     "10.55.66.77",
		Port:     22,
		User:     "fallbackuser",
		JumpHost: "openssh:10.55.66.1:22",
	}
	clientCfg, _ := buildControlProxyClientConfig(targetCtx, provider, "node-zero", proxyOpts)
	if clientCfg == nil {
		t.Fatal("expected non-nil clientCfg from buildControlProxyClientConfig")
	}
	if clientCfg.Port != 22 {
		t.Fatalf("expected clientCfg.Port == 22, got %d", clientCfg.Port)
	}
	if clientCfg.User == "" {
		t.Fatalf("expected non-empty clientCfg.User, got %q", clientCfg.User)
	}
	if clientCfg.ProxyJump != "openssh:10.55.66.1:22" {
		t.Fatalf("expected clientCfg.ProxyJump == 'openssh:10.55.66.1:22', got %q", clientCfg.ProxyJump)
	}

	// Verify controlSocketPath applies -o User/Port even when called directly without Complete()
	directSockOpts := &SshOptions{
		Host: "10.55.66.77",
		control: SSHControlFlags{
			ControlPath: "/tmp/mux-%r@%h:%p",
			Options:     []string{"User=directopt", "Port=2288"},
		},
	}
	sockPath, err := controlSocketPath(directSockOpts, provider, "")
	if err != nil {
		t.Fatalf("controlSocketPath failed: %v", err)
	}
	if sockPath != "/tmp/mux-directopt@10.55.66.77:2288" {
		t.Fatalf("expected expanded socket path '/tmp/mux-directopt@10.55.66.77:2288', got %q", sockPath)
	}
}
