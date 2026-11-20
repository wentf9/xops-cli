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
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/pkg/adapter"
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

func TestControl_Proxy_StdioForward(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	sockPath, targetAddr := setupControlProxySessionFixture(ctx, t)

	bannerLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen for bannerLn failed: %v", err)
	}
	defer func() { _ = bannerLn.Close() }()
	bannerAddr := bannerLn.Addr().String()

	go func() {
		for {
			conn, bErr := bannerLn.Accept()
			if bErr != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.WriteString(c, "BANNER_FROM_DEST\n")
			}(conn)
		}
	}()

	stdout, stderr, err := runControlProxyTestCommandWithStdin(
		ctx, t,
		[]string{"-O", "proxy", "-S", sockPath, "-W", bannerAddr, targetAddr},
		strings.NewReader(""),
		false,
	)
	if err != nil {
		t.Fatalf("-O proxy -W failed: %v, stderr: %q", err, stderr)
	}
	if !strings.Contains(stdout, "BANNER_FROM_DEST\n") {
		t.Fatalf("expected banner in stdout, got: %q", stdout)
	}
}

func TestControl_Proxy_LocalForwardLifecycleAndTeardown(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	sockPath, targetAddr := setupControlProxySessionFixture(ctx, t)

	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen for backend failed: %v", err)
	}
	defer func() { _ = backendLn.Close() }()
	backendAddr := backendLn.Addr().String()

	go func() {
		for {
			conn, acceptErr := backendLn.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	// 1. Verify -O proxy with -L <fwdAddr>:<backend> -N starts local forward listener
	// over control proxy session, successfully proxies traffic, and tears down cleanly when ctx is canceled.
	freeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen for free port failed: %v", err)
	}
	fwdPort := freeLn.Addr().(*net.TCPAddr).Port
	_ = freeLn.Close()
	localFwdSpec := fmt.Sprintf("127.0.0.1:%d:%s", fwdPort, backendAddr)
	localFwdAddr := fmt.Sprintf("127.0.0.1:%d", fwdPort)

	proxyCtx, proxyCancel := context.WithCancel(ctx)
	defer proxyCancel()

	type proxyResult struct {
		stdout string
		stderr string
		err    error
	}
	resCh := make(chan proxyResult, 1)
	go func() {
		out, serr, pErr := runControlProxyTestCommand(
			proxyCtx, t,
			[]string{"-O", "proxy", "-S", sockPath, "-L", localFwdSpec, "-N", targetAddr},
		)
		resCh <- proxyResult{stdout: out, stderr: serr, err: pErr}
	}()

	var fwdConn net.Conn
	dialDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(dialDeadline) {
		c, dErr := net.DialTimeout("tcp", localFwdAddr, 100*time.Millisecond)
		if dErr == nil {
			fwdConn = c
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if fwdConn == nil {
		t.Fatalf("failed to connect to local forward listener at %s", localFwdAddr)
	}
	defer func() { _ = fwdConn.Close() }()

	payload := []byte("ping local forward over proxy\n")
	if _, err := fwdConn.Write(payload); err != nil {
		t.Fatalf("write to fwdConn failed: %v", err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(fwdConn, reply); err != nil {
		t.Fatalf("read from fwdConn failed: %v", err)
	}
	if string(reply) != string(payload) {
		t.Fatalf("got reply %q, want %q", string(reply), string(payload))
	}
	_ = fwdConn.Close()

	// Cancel proxyCtx and ensure clean teardown.
	proxyCancel()

	select {
	case res := <-resCh:
		if res.err != nil {
			t.Fatalf("expected nil error on clean teardown, got: %v (stderr: %q)", res.err, res.stderr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for proxy tunnel session to tear down after ctx cancel")
	}

	// 2. Verify -O proxy with -L 127.0.0.1:0:<backend> -N starts ephemeral listener and tears down cleanly.
	proxyCtx0, proxyCancel0 := context.WithCancel(ctx)
	resCh0 := make(chan proxyResult, 1)
	go func() {
		out, serr, pErr := runControlProxyTestCommand(
			proxyCtx0, t,
			[]string{"-O", "proxy", "-S", sockPath, "-L", "127.0.0.1:0:" + backendAddr, "-N", targetAddr},
		)
		resCh0 <- proxyResult{stdout: out, stderr: serr, err: pErr}
	}()

	time.Sleep(50 * time.Millisecond)
	proxyCancel0()

	select {
	case res := <-resCh0:
		if res.err != nil {
			t.Fatalf("expected nil error on clean teardown of :0 forward, got: %v (stderr: %q)", res.err, res.stderr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for proxy :0 tunnel session to tear down after ctx cancel")
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

func TestDisableSessionControlForParentAndProxySSHOptions(t *testing.T) {
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-zero", models.Host{Address: "10.55.66.77", Port: 0})
	cfg.Identities.Set("id-empty", models.Identity{User: "", AuthType: "password", Password: "pw"})
	cfg.Nodes.Set("node-zero", models.Node{HostRef: "h-zero", IdentityRef: "id-empty"})
	provider := config.NewProviderWithoutOpenSSH(cfg)

	targetCtx := ssh.TargetContext{
		Host:     "10.55.66.77",
		Port:     22,
		User:     "fallbackuser",
		JumpHost: "openssh:10.55.66.1:22",
	}

	// Verify buildControlProxyClientConfig forwards Tier 1 -o SSHOptions to adp.GetConfig(nodeID)
	proxyWithOpts := &SshOptions{
		JumpHost: "10.55.66.1:22",
		control: SSHControlFlags{
			Options: []string{"ConnectTimeout=17", "StrictHostKeyChecking=no"},
		},
	}
	clientCfgWithOpts, _ := buildControlProxyClientConfig(targetCtx, provider, "node-zero", proxyWithOpts)
	if clientCfgWithOpts == nil || clientCfgWithOpts.Options == nil {
		t.Fatalf("expected non-nil clientCfg.Options from buildControlProxyClientConfig, got %+v", clientCfgWithOpts)
	}
	if clientCfgWithOpts.Options.ConnectTimeout() != 17*time.Second ||
		clientCfgWithOpts.Options.StrictHostKeyChecking() != ssh.StrictHostKeyCheckingNo {
		t.Fatalf("expected Tier 1 -o options in proxy clientCfg, got %+v", clientCfgWithOpts.Options)
	}

	// Verify buildControlProxyClientConfig also resolves Options on the ad-hoc (nodeID == "") fallback branch
	clientCfgAdHoc, _ := buildControlProxyClientConfig(targetCtx, provider, "", proxyWithOpts)
	if clientCfgAdHoc == nil || clientCfgAdHoc.Options == nil ||
		clientCfgAdHoc.Options.ConnectTimeout() != 17*time.Second ||
		clientCfgAdHoc.Options.StrictHostKeyChecking() != ssh.StrictHostKeyCheckingNo {
		t.Fatalf("expected Tier 1 -o options in ad-hoc proxy clientCfg, got %+v", clientCfgAdHoc)
	}
}

func TestDisableSessionControlForParentPreservesNonMuxOptions(t *testing.T) {
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-zero", models.Host{Address: "10.55.66.77", Port: 0})
	cfg.Identities.Set("id-empty", models.Identity{User: "", AuthType: "password", Password: "pw"})
	cfg.Nodes.Set("node-zero", models.Node{HostRef: "h-zero", IdentityRef: "id-empty"})

	// Verify disableSessionControlForParent disables multiplexing while preserving Tier 1 -o SSHOptions
	tmpCfgDir := t.TempDir()
	store := config.NewDefaultStore(filepath.Join(tmpCfgDir, "config.yaml"), filepath.Join(tmpCfgDir, "key"))
	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH failed: %v", err)
	}
	parentOpts := NewSshOptions()
	parentOpts.Remember = "never"
	parentOpts.control = SSHControlFlags{
		MasterCount: 1,
		ControlPath: "/tmp/parent-should-not-bind.sock",
		Options:     []string{"ConnectTimeout=19", "StrictHostKeyChecking=no"},
	}
	adpOpts, err := parentOpts.buildAdapterOptions("node-zero", cfg, repo)
	if err != nil {
		t.Fatalf("buildAdapterOptions failed: %v", err)
	}
	adpOpts = append(adpOpts, disableSessionControlForParent("node-zero"))
	adp := adapter.NewSSHAdapter(repo, adpOpts...)
	if ctrl, ctrlErr := adp.GetControlConfig("node-zero"); ctrlErr != nil || ctrl == nil || ctrl.Path != "none" || ctrl.Master != ssh.ControlMasterNo {
		t.Fatalf("expected disabled control config (Path=none, Master=no) for -f parent, got ctrl=%+v err=%v", ctrl, ctrlErr)
	}
	parentClientCfg, err := adp.GetConfig("node-zero")
	if err != nil {
		t.Fatalf("adp.GetConfig(node-zero) failed: %v", err)
	}
	if parentClientCfg.Options == nil ||
		parentClientCfg.Options.ConnectTimeout() != 19*time.Second ||
		parentClientCfg.Options.StrictHostKeyChecking() != ssh.StrictHostKeyCheckingNo {
		t.Fatalf("expected non-mux -o options preserved for -f parent, got %+v", parentClientCfg.Options)
	}
	if parentClientCfg.Options.ControlPath() != "none" || parentClientCfg.Options.ControlMaster() != ssh.ControlMasterNo {
		t.Fatalf("expected ControlPath=none and ControlMaster=no in -f parent Options, got %+v", parentClientCfg.Options.ControlConfig())
	}
}

func TestSshCompleteSkipsStdinSecretsForBgChildAndNonProxyControlCommands(t *testing.T) {
	runCompleteWithOpenPipeStdin := func(t *testing.T, args []string) (*SshOptions, error) {
		t.Helper()
		origStdin := os.Stdin
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("os.Pipe: %v", err)
		}
		os.Stdin = r
		t.Cleanup(func() {
			os.Stdin = origStdin
			_ = r.Close()
			_ = w.Close()
		})

		opts := NewSshOptions()
		sshCmd := newCmdSshWithOptions(opts)
		if err := sshCmd.Flags().Parse(args); err != nil {
			t.Fatalf("Parse(%v): %v", args, err)
		}

		done := make(chan error, 1)
		go func() {
			done <- opts.Complete(sshCmd, sshCmd.Flags().Args())
		}()

		select {
		case err := <-done:
			return opts, err
		case <-time.After(1 * time.Second):
			_ = w.Close()
			t.Fatalf("Complete(%v) blocked trying to read open stdin pipe", args)
			return nil, nil
		}
	}

	t.Run("bg child skips stdin secret flags", func(t *testing.T) {
		t.Setenv("XOPS_CLI_SSH_BG_CHILD", "true")
		opts, err := runCompleteWithOpenPipeStdin(t, []string{"--password-stdin", "--passphrase-stdin", "--otp-stdin", "example.com"})
		if err != nil {
			t.Fatalf("Complete(bg child) failed: %v", err)
		}
		if opts.PasswordStdin || opts.PassphraseStdin || opts.OTPStdin {
			t.Fatalf("expected stdin secret flags cleared in bg child, got pwd=%v pp=%v otp=%v",
				opts.PasswordStdin, opts.PassphraseStdin, opts.OTPStdin)
		}
	})

	t.Run("-O proxy-stream skips stdin secret flags", func(t *testing.T) {
		opts, err := runCompleteWithOpenPipeStdin(t, []string{"-O", "proxy-stream", "-S", "/tmp/test.sock", "--password-stdin", "example.com"})
		if err != nil {
			t.Fatalf("Complete(-O proxy-stream) failed: %v", err)
		}
		if opts.PasswordStdin {
			t.Fatal("expected PasswordStdin cleared for -O proxy-stream")
		}
	})

	t.Run("-O check skips stdin secret flags", func(t *testing.T) {
		opts, err := runCompleteWithOpenPipeStdin(t, []string{"-O", "check", "-S", "/tmp/test.sock", "--passphrase-stdin", "example.com"})
		if err != nil {
			t.Fatalf("Complete(-O check) failed: %v", err)
		}
		if opts.PassphraseStdin {
			t.Fatal("expected PassphraseStdin cleared for -O check")
		}
	})
}

func TestControlCommandsWrapValidationAndCompleteErrorsWithExit255AndUnwrap(t *testing.T) {
	assertControlExit255Unwraps := func(t *testing.T, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("expected non-nil error")
		}
		var ctlErr *ControlExitError
		if !errors.As(err, &ctlErr) {
			t.Fatalf("expected *ControlExitError, got %T (%v)", err, err)
		}
		if ctlErr.ExitCode() != 255 {
			t.Fatalf("expected ExitCode 255, got %d (%v)", ctlErr.ExitCode(), err)
		}
		underlying := ctlErr.Unwrap()
		if underlying == nil {
			t.Fatalf("expected non-nil Unwrap() on ControlExitError: %+v", ctlErr)
		}
		if !errors.Is(err, underlying) {
			t.Fatalf("expected errors.Is(err, err.Unwrap()) to be true for %v", err)
		}
	}

	t.Run("-O check ApplyGeneralOptions in Complete wraps 255", func(t *testing.T) {
		opts := NewSshOptions()
		c := newCmdSshWithOptions(opts)
		if err := c.Flags().Parse([]string{"-O", "check", "-S", "/tmp/test.sock", "-o", "InvalidOptionWithoutEquals", "example.com"}); err != nil {
			t.Fatalf("Parse: %v", err)
		}
		assertControlExit255Unwraps(t, opts.Complete(c, c.Flags().Args()))
	})

	t.Run("-O check validateCommonSSHBaseOptions wraps 255", func(t *testing.T) {
		opts := NewSshOptions()
		c := newCmdSshWithOptions(opts)
		if err := c.Flags().Parse([]string{"-O", "check", "-S", "/tmp/test.sock", "--remember", "invalid", "example.com"}); err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if err := opts.Complete(c, c.Flags().Args()); err != nil {
			t.Fatalf("Complete: %v", err)
		}
		assertControlExit255Unwraps(t, opts.Validate())
	})

	t.Run("-O proxy validateCommonSSHBaseOptions wraps 255", func(t *testing.T) {
		opts := NewSshOptions()
		c := newCmdSshWithOptions(opts)
		if err := c.Flags().Parse([]string{"-O", "proxy", "-S", "/tmp/test.sock", "--remember", "invalid", "example.com"}); err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if err := opts.Complete(c, c.Flags().Args()); err != nil {
			t.Fatalf("Complete: %v", err)
		}
		assertControlExit255Unwraps(t, opts.Validate())
	})

	t.Run("-O proxy prepareCommandPlan wraps 255", func(t *testing.T) {
		opts := NewSshOptions()
		c := newCmdSshWithOptions(opts)
		if err := c.Flags().Parse([]string{"-O", "proxy", "-S", "/tmp/test.sock", "--interpreter", "invalid-shell", "example.com", "id"}); err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if err := opts.Complete(c, c.Flags().Args()); err != nil {
			t.Fatalf("Complete: %v", err)
		}
		assertControlExit255Unwraps(t, opts.Validate())
	})

	t.Run("-O proxy readSecretsFromStdin wraps 255", func(t *testing.T) {
		origStdin := os.Stdin
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("os.Pipe: %v", err)
		}
		_ = w.Close()
		os.Stdin = r
		t.Cleanup(func() {
			os.Stdin = origStdin
			_ = r.Close()
		})

		opts := NewSshOptions()
		c := newCmdSshWithOptions(opts)
		if err := c.Flags().Parse([]string{"-O", "proxy", "-S", "/tmp/test.sock", "--password-stdin", "example.com"}); err != nil {
			t.Fatalf("Parse: %v", err)
		}
		assertControlExit255Unwraps(t, opts.Complete(c, c.Flags().Args()))
	})
}

func TestBuildControlProxyClientConfigStripsProxyCommandPreservesRemoteCommandAndSetEnv(t *testing.T) {
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-1", models.Host{Address: "10.55.66.77", Port: 22})
	cfg.Identities.Set("id-1", models.Identity{User: "cfguser", AuthType: "password", Password: "pw"})
	cfg.Nodes.Set("node-1", models.Node{HostRef: "h-1", IdentityRef: "id-1"})
	provider := config.NewProviderWithoutOpenSSH(cfg)

	targetCtx := ssh.TargetContext{
		Host: "10.55.66.77",
		Port: 22,
		User: "cfguser",
	}

	t.Run("saved node strips ProxyCommand and keeps RemoteCommand and SetEnv", func(t *testing.T) {
		proxyOpts := &SshOptions{
			control: SSHControlFlags{
				Options: []string{"ProxyCommand=nc %h %p", "RemoteCommand=uptime", "SetEnv=FOO=bar"},
			},
		}
		clientCfg, _ := buildControlProxyClientConfig(targetCtx, provider, "node-1", proxyOpts)
		if clientCfg == nil || clientCfg.Options == nil {
			t.Fatalf("expected non-nil clientCfg and Options, got %+v", clientCfg)
		}
		if active := clientCfg.Options.ActiveProxyCommand(); active != "" {
			t.Fatalf("expected ProxyCommand stripped for proxy mode, got ActiveProxyCommand=%q", active)
		}
		if gotRC := clientCfg.Options.RemoteCommand(); gotRC != "uptime" {
			t.Fatalf("expected RemoteCommand=%q, got %q", "uptime", gotRC)
		}
		if gotEnv := clientCfg.Options.SetEnvDirectives(); !slices.Equal(gotEnv, []string{"FOO=bar"}) {
			t.Fatalf("expected SetEnvDirectives=[FOO=bar], got %v", gotEnv)
		}
	})

	t.Run("ad-hoc target with -l override strips ProxyCommand and keeps RemoteCommand and SetEnv", func(t *testing.T) {
		cfgTier3 := config.NewProviderWithoutOpenSSH(nil).Snapshot()
		cfgTier3.Hosts.Set("h-1", models.Host{Address: "10.55.66.77", Port: 22})
		cfgTier3.Identities.Set("id-1", models.Identity{User: "cfguser", AuthType: "password", Password: "pw"})
		cfgTier3.Nodes.Set("node-1", models.Node{
			HostRef:     "h-1",
			IdentityRef: "id-1",
			SSHOptions:  ssh.MustOptions("ProxyCommand", "nc %h %p", "RemoteCommand", "whoami", "SetEnv", "BAZ=qux"),
		})
		provTier3 := config.NewProviderWithoutOpenSSH(cfgTier3)

		targetCtxOverride := ssh.TargetContext{
			Host:         "10.55.66.77",
			Port:         22,
			User:         "overrideuser",
			OriginalHost: "node-1",
		}
		proxyOpts := &SshOptions{
			Host: "node-1",
			User: "overrideuser",
			Target: config.ConnectionTarget{
				Selector: "node-1",
				User:     "overrideuser",
				HasUser:  true,
			},
		}
		clientCfg, _ := buildControlProxyClientConfig(targetCtxOverride, provTier3, "", proxyOpts)
		if clientCfg == nil || clientCfg.Options == nil {
			t.Fatalf("expected non-nil clientCfg and Options, got %+v", clientCfg)
		}
		if clientCfg.User != "overrideuser" {
			t.Fatalf("expected -l overrideuser preserved, got %q", clientCfg.User)
		}
		if active := clientCfg.Options.ActiveProxyCommand(); active != "" {
			t.Fatalf("expected Tier 3 ProxyCommand stripped for ad-hoc proxy mode, got ActiveProxyCommand=%q", active)
		}
		if gotRC := clientCfg.Options.RemoteCommand(); gotRC != "whoami" {
			t.Fatalf("expected RemoteCommand=%q, got %q", "whoami", gotRC)
		}
		if gotEnv := clientCfg.Options.SetEnvDirectives(); !slices.Equal(gotEnv, []string{"BAZ=qux"}) {
			t.Fatalf("expected SetEnvDirectives=[BAZ=qux], got %v", gotEnv)
		}
	})
}

func TestExecuteProxyStreamOpenPipeStdinStdoutDone(t *testing.T) {
	sockPath, ln := createTestMuxMasterServer(t)
	const greeting = "hello-from-mux-master\n"
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
				_, _ = io.WriteString(c, greeting)
			}(conn)
		}
	}()

	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer func() {
		_ = stdinR.Close()
		_ = stdinW.Close()
	}()

	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- executeProxyStream(ctx, sockPath, controlStreams{
			Stdin:  stdinR,
			Stdout: &stdout,
			Stderr: &stderr,
		})
	}()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("executeProxyStream(stdoutDone) unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("executeProxyStream(stdoutDone) hung with open pipe stdin")
	}
	if stdout.String() != greeting {
		t.Fatalf("stdout = %q, want %q", stdout.String(), greeting)
	}

	// Verify caller's pipe FD is still open and no leaked goroutine steals bytes from stdinR.
	if _, err := stdinW.Write([]byte("X")); err != nil {
		t.Fatalf("caller stdinW closed unexpectedly: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(stdinR, buf); err != nil || buf[0] != 'X' {
		t.Fatalf("caller stdinR damaged or stolen by leaked goroutine: buf=%q err=%v", buf, err)
	}
}

func TestExecuteProxyStreamOpenPipeStdinCancel(t *testing.T) {
	sockPath, ln := createTestMuxMasterServer(t)
	serverRelease := make(chan struct{})
	defer close(serverRelease)
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
				<-serverRelease
			}(conn)
		}
	}()

	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer func() {
		_ = stdinR.Close()
		_ = stdinW.Close()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(30*time.Millisecond, cancel)

	var stdout, stderr bytes.Buffer
	errCh := make(chan error, 1)
	go func() {
		errCh <- executeProxyStream(ctx, sockPath, controlStreams{
			Stdin:  stdinR,
			Stdout: &stdout,
			Stderr: &stderr,
		})
	}()

	var streamErr error
	select {
	case streamErr = <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("executeProxyStream(cancel) hung with open pipe stdin")
	}
	if streamErr == nil {
		t.Fatal("expected error on ctx cancellation")
	}
	var ctlErr *ControlExitError
	if !errors.As(streamErr, &ctlErr) || ctlErr.ExitCode() != 255 {
		t.Fatalf("expected *ControlExitError(255), got %T (%v)", streamErr, streamErr)
	}
	if !errors.Is(streamErr, context.Canceled) {
		t.Fatalf("expected errors.Is(err, context.Canceled), got %v", streamErr)
	}

	if _, err := stdinW.Write([]byte("Y")); err != nil {
		t.Fatalf("caller stdinW closed unexpectedly after cancel: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(stdinR, buf); err != nil || buf[0] != 'Y' {
		t.Fatalf("caller stdinR damaged or stolen after cancel: buf=%q err=%v", buf, err)
	}
}

func TestLoadReadOnlyControlProviderBrokenOpenSSHConfigPreservesSavedAndFailsClosedOnOpenSSH(t *testing.T) {
	home := setupTestEnvironment(t)
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(.ssh): %v", err)
	}
	// Empty Host directive fails strict OpenSSH parsing.
	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte("Host\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(.ssh/config): %v", err)
	}

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.SchemaVersion = 2
	cfg.Hosts.Set("h-saved", models.Host{Address: "10.99.0.10", Port: 22})
	cfg.Identities.Set("id-saved", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("saved-node", models.Node{HostRef: "h-saved", IdentityRef: "id-saved"})

	path, key, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatalf("GetConfigFilePath: %v", err)
	}
	if err := config.NewDefaultStore(path, key).Save(cfg); err != nil {
		t.Fatalf("Save config: %v", err)
	}

	provider, err := loadReadOnlyControlProvider()
	if err != nil {
		t.Fatalf("loadReadOnlyControlProvider unexpected error: %v", err)
	}
	if _, _, _, err := provider.Resolve("saved-node"); err != nil {
		t.Fatalf("expected saved node lookup to keep working when ~/.ssh/config is broken, got: %v", err)
	}
	if _, err := config.ResolveTarget(provider, config.ConnectionTarget{Selector: "unmatched-host"}); err == nil {
		t.Fatal("expected unmatched target resolution to fail closed on broken ~/.ssh/config")
	}
}

func TestControlContextCanceledExits255_AndProxyFallbackLookupViaRealControlTarget(t *testing.T) {
	t.Run("resolveControlContext canceled ctx returns ControlExitError 255", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		o := NewSshOptions()
		o.control.CtlCmd = "check"
		_, _, _, _, err := resolveControlContext(ctx, o, &bytes.Buffer{})
		var ctlErr *ControlExitError
		if !errors.As(err, &ctlErr) || ctlErr.Code != 255 {
			t.Fatalf("canceled resolveControlContext err = %v, want *ControlExitError{Code: 255}", err)
		}
	})

	t.Run("resolveControlProxyFallbackLookup preserves saved node under -l override and openssh namespace", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)

		sshCfgPath := filepath.Join(home, "ssh_config")
		if err := os.WriteFile(sshCfgPath, []byte(strings.Join([]string{
			"Host web",
			"  HostName 10.55.66.77",
			"  User other",
		}, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		parser, err := config.NewOpenSSHParserFromPath(sshCfgPath)
		if err != nil {
			t.Fatal(err)
		}

		cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
		cfg.Hosts.Set("10.55.66.77:22", models.Host{Address: "10.55.66.77", Port: 22})
		cfg.Identities.Set("ops@10.55.66.77", models.Identity{User: "ops", AuthType: "auto"})
		cfg.Nodes.Set("node-1", models.Node{HostRef: "10.55.66.77:22", IdentityRef: "ops@10.55.66.77"})
		provider := config.NewProviderWithOpenSSHParser(cfg, parser)

		// 1. Saved node with -l overrideuser driven through real controlTarget (which synthesizes TargetContext.OriginalHost).
		oSaved := NewSshOptions()
		oSaved.User = "overrideuser"
		oSaved.Host = "node-1"
		oSaved.Target = config.ConnectionTarget{
			Selector: "node-1",
			User:     "overrideuser",
			HasUser:  true,
		}
		tSaved := controlTarget(oSaved, provider, "")
		if got := resolveControlProxyFallbackLookup(tSaved, provider, oSaved); got != "node-1" {
			t.Fatalf("saved node -l override fallbackLookup = %q, want %q (target=%+v)", got, "node-1", tSaved)
		}

		// 2. Explicit openssh:other@web sharing the same IP must remain in openssh: namespace.
		oVirtual := NewSshOptions()
		oVirtual.Host = "openssh:other@web"
		oVirtual.Target = config.ConnectionTarget{Selector: "openssh:other@web"}
		tVirtual := controlTarget(oVirtual, provider, "")
		if got := resolveControlProxyFallbackLookup(tVirtual, provider, oVirtual); !config.IsOpenSSHNodeID(got) {
			t.Fatalf("explicit openssh: target collapsed to non-OpenSSH ID %q", got)
		}
	})
}
