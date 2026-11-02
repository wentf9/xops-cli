package ssh

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corelog "github.com/wentf9/xops-cli/core/log"
	cryptoSSH "golang.org/x/crypto/ssh"
)

type sftpStreamServerOptions struct {
	mode                      SudoMode
	password                  string
	missingBinary             bool
	closeStdoutBeforeExit     bool
	exitAfterAck              bool
	exitAfterAckStatus        int
	blockAfterAck             bool
	hangAfterAck              bool
	hangBeforePrompt          bool
	stdoutBannerBeforePrompt  string
	missingBinaryBeforePrompt bool
	coalesceTokens            bool
	stderrBeforeReady         string
	stderrAfterReady          string
	repromptSu                bool
	hangOnEcho                bool
	ptyRequested              *atomic.Bool
	subsystemCalls            *atomic.Int32
	execCalls                 *atomic.Int32
}

func startSFTPStreamTestServer(t *testing.T, opts sftpStreamServerOptions) string {
	t.Helper()
	setTestHome(t)
	config := &cryptoSSH.ServerConfig{
		PasswordCallback: func(_ cryptoSSH.ConnMetadata, value []byte) (*cryptoSSH.Permissions, error) {
			if string(value) == "login" {
				return nil, nil
			}
			return nil, errors.New("login rejected")
		},
	}
	config.AddHostKey(newAuthTestSigner(t))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	var wg sync.WaitGroup

	wg.Go(func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer closePrivilegeTestResource(t, conn)
		server, channels, requests, err := cryptoSSH.NewServerConn(conn, config)
		if err != nil {
			return
		}
		defer func() { _ = closeResource(server, "test SSH server") }()

		wg.Go(func() {
			for req := range requests {
				_ = req.Reply(false, nil)
			}
		})

		for {
			select {
			case <-ctx.Done():
				return
			case chReq, ok := <-channels:
				if !ok {
					return
				}
				channel, reqs, err := chReq.Accept()
				if err != nil {
					return
				}
				wg.Go(func() { serveSFTPStreamChannel(t, channel, reqs, opts) })
			}
		}
	})

	t.Cleanup(func() {
		cancel()
		closePrivilegeTestResource(t, listener)
		wg.Wait()
	})

	return listener.Addr().String()
}

func serveSFTPStreamChannel(t *testing.T, channel cryptoSSH.Channel, requests <-chan *cryptoSSH.Request, opts sftpStreamServerOptions) {
	t.Helper()
	defer func() {
		_ = channel.Close()
	}()

	for req := range requests {
		switch req.Type {
		case "pty-req":
			if opts.ptyRequested != nil {
				opts.ptyRequested.Store(true)
			}
			_ = req.Reply(true, nil)

		case "subsystem":
			if opts.subsystemCalls != nil {
				opts.subsystemCalls.Add(1)
			}
			var payload struct{ Subsystem string }
			_ = cryptoSSH.Unmarshal(req.Payload, &payload)
			if payload.Subsystem == "sftp" {
				_ = req.Reply(true, nil)
				serveEchoStream(channel, channel, opts.hangOnEcho)
				return
			}
			_ = req.Reply(false, nil)

		case "exec":
			var payload struct{ Command string }
			_ = cryptoSSH.Unmarshal(req.Payload, &payload)
			_ = req.Reply(true, nil)
			if strings.Contains(payload.Command, "__XOPS_DIALECT_") {
				_, _ = io.WriteString(channel, "__XOPS_DIALECT_POSIX__:Linux:/bin/bash\n")
				_, _ = channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
				return
			}
			if strings.Contains(payload.Command, "__XOPS_INTERP__") {
				_, _ = io.WriteString(channel, "__XOPS_INTERP__:bash\n__XOPS_INTERP__:sh\n__XOPS_INTERP_END__\n")
				_, _ = channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
				return
			}
			if opts.execCalls != nil {
				opts.execCalls.Add(1)
			}
			serveSFTPStreamExec(t, channel, payload.Command, opts)
			return

		default:
			_ = req.Reply(false, nil)
		}
	}
}

func serveEchoStream(channel cryptoSSH.Channel, in io.Reader, hangOnEcho bool) {
	if hangOnEcho {
		time.Sleep(3 * time.Second)
		return
	}
	buf := make([]byte, 1024)
	for {
		n, err := in.Read(buf)
		if n > 0 {
			if _, wErr := channel.Write(buf[:n]); wErr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func serveExecPasswordChallenge(t *testing.T, channel cryptoSSH.Channel, reader *bufio.Reader, promptToken string, opts sftpStreamServerOptions) bool {
	t.Helper()
	if opts.mode == SudoModeSudo && promptToken != "" {
		_, _ = io.WriteString(channel.Stderr(), promptToken)
		pwd, err := reader.ReadString('\n')
		if err != nil || strings.TrimSpace(pwd) != opts.password {
			_, _ = io.WriteString(channel.Stderr(), "sudo: 1 incorrect password attempt\n")
			sendPrivilegeStatus(t, channel, 1)
			return false
		}
	} else if opts.mode == SudoModeSu {
		_, _ = io.WriteString(channel, "Password: ")
		pwd, err := reader.ReadString('\n')
		if err != nil || strings.TrimSpace(pwd) != opts.password {
			_, _ = io.WriteString(channel, "su: Authentication failure\n")
			sendPrivilegeStatus(t, channel, 1)
			return false
		}
		if opts.repromptSu {
			_, _ = io.WriteString(channel, "Password: ")
			time.Sleep(200 * time.Millisecond)
			sendPrivilegeStatus(t, channel, 1)
			return false
		}
	}
	return true
}

//nolint:gocyclo // Test mock handles multiple tokens and protocol handoff states.
func serveSFTPStreamExec(t *testing.T, channel cryptoSSH.Channel, command string, opts sftpStreamServerOptions) {
	t.Helper()
	reader := bufio.NewReader(channel)

	promptToken := protocolToken(command, "[xops-password-")
	readyToken := protocolToken(command, "[xops-ready-")
	ackToken := protocolToken(command, "[xops-continue-")
	streamToken := protocolToken(command, "[xops-sftp-stream-")

	if opts.hangBeforePrompt {
		time.Sleep(1 * time.Second)
		return
	}

	if opts.stdoutBannerBeforePrompt != "" {
		_, _ = io.WriteString(channel, opts.stdoutBannerBeforePrompt)
	}

	if opts.missingBinaryBeforePrompt {
		_, _ = io.WriteString(channel.Stderr(), "sftp-server binary not found\n")
		sendPrivilegeStatus(t, channel, 127)
		return
	}

	if opts.stderrBeforeReady != "" {
		_, _ = io.WriteString(channel.Stderr(), opts.stderrBeforeReady)
	}

	// 1. Password challenge
	if !serveExecPasswordChallenge(t, channel, reader, promptToken, opts) {
		return
	}

	// 2. Ready token
	if opts.coalesceTokens && readyToken != "" && streamToken != "" {
		_, _ = io.WriteString(channel, readyToken+streamToken)
		ack, err := reader.ReadString('\n')
		if err != nil || strings.TrimSpace(ack) != ackToken {
			sendPrivilegeStatus(t, channel, 125)
			return
		}
		serveEchoStream(channel, reader, opts.hangOnEcho)
		return
	}

	if readyToken != "" {
		_, _ = io.WriteString(channel, readyToken)
	}

	// 3. Wait for ackToken
	ack, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(ack) != ackToken {
		sendPrivilegeStatus(t, channel, 125)
		return
	}

	if opts.closeStdoutBeforeExit {
		_ = channel.CloseWrite()
		time.Sleep(30 * time.Millisecond)
		sendPrivilegeStatus(t, channel, uint32(opts.exitAfterAckStatus))
		return
	}
	if opts.exitAfterAck || opts.exitAfterAckStatus > 0 {
		sendPrivilegeStatus(t, channel, uint32(opts.exitAfterAckStatus))
		return
	}

	if opts.stderrAfterReady != "" {
		_, _ = io.WriteString(channel.Stderr(), opts.stderrAfterReady)
	}

	if opts.blockAfterAck {
		time.Sleep(500 * time.Millisecond)
		return
	}
	if opts.hangAfterAck {
		time.Sleep(1 * time.Second)
		return
	}

	// 4. Missing binary test
	if opts.missingBinary {
		_, _ = io.WriteString(channel.Stderr(), "sftp-server binary not found\n")
		sendPrivilegeStatus(t, channel, 127)
		return
	}

	// 5. Emit streamToken
	if streamToken != "" {
		_, _ = io.WriteString(channel, streamToken)
	}

	// 6. Echo binary stream
	serveEchoStream(channel, reader, opts.hangOnEcho)
}

func TestOpenSFTPStream_Subsystem(t *testing.T) {
	setTestHome(t)
	var subsystemCalls atomic.Int32
	addr := startSFTPStreamTestServer(t, sftpStreamServerOptions{
		subsystemCalls: &subsystemCalls,
	})

	client := exchangeTestClient(t, addr, SudoModeNone, &recoveryTestUI{values: []string{"valid"}}, &testRecorder{})
	stream, err := client.OpenSFTPStream(t.Context(), false)
	if err != nil {
		t.Fatalf("OpenSFTPStream(false) failed: %v", err)
	}
	defer func() { _ = stream.Close() }()

	if subsystemCalls.Load() != 1 {
		t.Errorf("expected 1 subsystem call, got %d", subsystemCalls.Load())
	}

	// Verify read/write
	testPayload := []byte("hello-sftp")
	if _, err := stream.Write(testPayload); err != nil {
		t.Fatalf("stream.Write failed: %v", err)
	}
	buf := make([]byte, len(testPayload))
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatalf("stream.Read failed: %v", err)
	}
	if string(buf) != string(testPayload) {
		t.Fatalf("expected %q, got %q", testPayload, buf)
	}
}

func TestOpenSFTPStream_Root(t *testing.T) {
	setTestHome(t)
	var subsystemCalls atomic.Int32
	var execCalls atomic.Int32
	addr := startSFTPStreamTestServer(t, sftpStreamServerOptions{
		subsystemCalls: &subsystemCalls,
		execCalls:      &execCalls,
	})

	client := exchangeTestClient(t, addr, SudoModeRoot, &recoveryTestUI{values: []string{"valid"}}, &testRecorder{})
	stream, err := client.OpenSFTPStream(t.Context(), true)
	if err != nil {
		t.Fatalf("OpenSFTPStream(true) with SudoModeRoot failed: %v", err)
	}
	defer func() { _ = stream.Close() }()

	if subsystemCalls.Load() != 1 {
		t.Errorf("expected 1 subsystem call for root, got %d", subsystemCalls.Load())
	}
	if execCalls.Load() != 0 {
		t.Errorf("expected 0 exec calls for root, got %d", execCalls.Load())
	}
}

func TestOpenSFTPStream_Sudoer(t *testing.T) {
	setTestHome(t)
	var execCalls atomic.Int32
	addr := startSFTPStreamTestServer(t, sftpStreamServerOptions{
		mode:      SudoModeSudoer,
		execCalls: &execCalls,
	})

	client := exchangeTestClient(t, addr, SudoModeSudoer, &recoveryTestUI{values: []string{"valid"}}, &testRecorder{})
	stream, err := client.OpenSFTPStream(t.Context(), true)
	if err != nil {
		t.Fatalf("OpenSFTPStream(true) with SudoModeSudoer failed: %v", err)
	}
	defer func() { _ = stream.Close() }()

	if execCalls.Load() != 1 {
		t.Errorf("expected 1 exec call for sudoer, got %d", execCalls.Load())
	}

	testPayload := []byte("sudoer-stream-payload")
	if _, err := stream.Write(testPayload); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	buf := make([]byte, len(testPayload))
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(buf) != string(testPayload) {
		t.Fatalf("expected %q, got %q", testPayload, buf)
	}
}

func TestOpenSFTPStream_SudoWithPassword(t *testing.T) {
	setTestHome(t)
	var execCalls atomic.Int32
	addr := startSFTPStreamTestServer(t, sftpStreamServerOptions{
		mode:      SudoModeSudo,
		password:  "secret-sudo-pwd",
		execCalls: &execCalls,
	})

	ui := &recoveryTestUI{values: []string{"secret-sudo-pwd"}}
	recorder := &testRecorder{}
	client := exchangeTestClient(t, addr, SudoModeSudo, ui, recorder)

	stream, err := client.OpenSFTPStream(t.Context(), true)
	if err != nil {
		t.Fatalf("OpenSFTPStream(true) with SudoModeSudo failed: %v", err)
	}
	defer func() { _ = stream.Close() }()

	if execCalls.Load() != 1 {
		t.Errorf("expected 1 exec call for sudo, got %d", execCalls.Load())
	}
	if recorder.lastSuPass != "secret-sudo-pwd" {
		t.Errorf("expected recorder to save password, got %q", recorder.lastSuPass)
	}

	testPayload := []byte("sudo-binary-echo")
	if _, err := stream.Write(testPayload); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	buf := make([]byte, len(testPayload))
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(buf) != string(testPayload) {
		t.Fatalf("expected %q, got %q", testPayload, buf)
	}
}

func TestOpenSFTPStream_SuWithPTY(t *testing.T) {
	setTestHome(t)
	var execCalls atomic.Int32
	var ptyRequested atomic.Bool
	addr := startSFTPStreamTestServer(t, sftpStreamServerOptions{
		mode:         SudoModeSu,
		password:     "secret-su-pwd",
		execCalls:    &execCalls,
		ptyRequested: &ptyRequested,
	})

	ui := &recoveryTestUI{values: []string{"secret-su-pwd"}}
	recorder := &testRecorder{}
	client := exchangeTestClient(t, addr, SudoModeSu, ui, recorder)

	stream, err := client.OpenSFTPStream(t.Context(), true)
	if err != nil {
		t.Fatalf("OpenSFTPStream(true) with SudoModeSu failed: %v", err)
	}
	defer func() { _ = stream.Close() }()

	if !ptyRequested.Load() {
		t.Errorf("expected PTY request for su mode")
	}
	if execCalls.Load() != 1 {
		t.Errorf("expected 1 exec call for su, got %d", execCalls.Load())
	}

	testPayload := []byte("su-stream-data")
	if _, err := stream.Write(testPayload); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	buf := make([]byte, len(testPayload))
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(buf) != string(testPayload) {
		t.Fatalf("expected %q, got %q", testPayload, buf)
	}
}

func TestOpenSFTPStream_MissingBinary127(t *testing.T) {
	setTestHome(t)
	addr := startSFTPStreamTestServer(t, sftpStreamServerOptions{
		mode:          SudoModeSudoer,
		missingBinary: true,
	})

	client := exchangeTestClient(t, addr, SudoModeSudoer, &recoveryTestUI{values: []string{"valid"}}, &testRecorder{})
	_, err := client.OpenSFTPStream(t.Context(), true)
	if err == nil {
		t.Fatal("expected error when sftp-server binary is missing, got nil")
	}
	if !strings.Contains(err.Error(), "remote sftp-server binary not found") {
		t.Fatalf("expected 'remote sftp-server binary not found' in error, got: %v", err)
	}
}

func TestOpenSFTPStream_NonPOSIX(t *testing.T) {
	client := &Client{
		connCfg: ConnectionConfig{
			SudoMode: SudoModeSudo,
			Execution: &ExecutionConfig{
				LaunchDialect: LaunchPowerShell,
				Interpreter:   InterpreterPowerShell,
			},
		},
		sshClient: &cryptoSSH.Client{},
	}

	_, err := client.OpenSFTPStream(t.Context(), true)
	if err == nil {
		t.Fatal("expected error for non-POSIX execution, got nil")
	}
	if !errors.Is(err, ErrExecutionValidation) {
		t.Fatalf("expected ErrExecutionValidation, got: %v", err)
	}
}

func TestOpenSFTPStream_ContextCancel(t *testing.T) {
	setTestHome(t)
	addr := startSFTPStreamTestServer(t, sftpStreamServerOptions{
		mode:          SudoModeSudoer,
		blockAfterAck: true,
	})

	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()

	client := exchangeTestClient(t, addr, SudoModeSudoer, &recoveryTestUI{values: []string{"valid"}}, &testRecorder{})
	_, err := client.OpenSFTPStream(ctx, true)
	if err == nil {
		t.Fatal("expected error on context cancellation, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context error, got: %v", err)
	}
	if strings.Count(err.Error(), context.DeadlineExceeded.Error()) > 1 {
		t.Errorf("context deadline exceeded duplicated in error: %v", err)
	}
	if strings.Count(err.Error(), context.Canceled.Error()) > 1 {
		t.Errorf("context canceled duplicated in error: %v", err)
	}
}

func TestBuildSFTPStreamScript_BSDSyntax(t *testing.T) {
	client := &Client{}
	script := client.buildSFTPStreamScript(SudoModeSu, "ready1", "[prompt1]", "[ack1]", "stream1")

	// Must NOT use GNU-specific -s /bin/sh which breaks on FreeBSD/OpenBSD/macOS
	if strings.Contains(script, "-s /bin/sh") {
		t.Errorf("expected no GNU -s /bin/sh in su script for BSD compatibility, got: %s", script)
	}
	// Must contain portable BSD-compatible syntax
	if !strings.Contains(script, "su - root -c ") || !strings.Contains(script, "exec /bin/sh -c ") {
		t.Errorf("expected su - root -c with exec /bin/sh -c in script, got: %s", script)
	}
	// Verify sftp-server search paths include Gentoo/64-bit locations and sshd_config.d
	if !strings.Contains(script, "/usr/lib/misc/sftp-server") || !strings.Contains(script, "/etc/ssh/sshd_config.d/*.conf") {
		t.Errorf("expected expanded search paths in script, got: %s", script)
	}
}

func TestSFTPStderrBuffer_ZeroDataLoss(t *testing.T) {
	buf := newSFTPStderrBuffer()
	totalChunks := 100
	chunkSize := 128

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range totalChunks {
			data := make([]byte, chunkSize)
			for j := range data {
				data[j] = byte(i % 256)
			}
			if _, err := buf.Write(data); err != nil {
				t.Errorf("write chunk %d failed: %v", i, err)
				return
			}
		}
		buf.CloseWithError(nil)
	}()

	var readData []byte
	readBuf := make([]byte, 256)
	for {
		n, err := buf.Read(readBuf)
		if n > 0 {
			readData = append(readData, readBuf[:n]...)
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatalf("unexpected read error: %v", err)
			}
			break
		}
	}
	wg.Wait()

	expectedLen := totalChunks * chunkSize
	if len(readData) != expectedLen {
		t.Fatalf("expected %d bytes read, got %d", expectedLen, len(readData))
	}
}

func TestOpenSFTPStream_RootUserFastPath(t *testing.T) {
	setTestHome(t)
	var subsystemCalls atomic.Int32
	var execCalls atomic.Int32

	addr := startSFTPStreamTestServer(t, sftpStreamServerOptions{
		mode:           SudoModeRoot,
		subsystemCalls: &subsystemCalls,
		execCalls:      &execCalls,
	})

	// User is configured as "root", SudoMode is unconfigured (SudoModeAuto)
	client := exchangeTestClient(t, addr, SudoModeAuto, &recoveryTestUI{values: []string{"valid"}}, &testRecorder{})
	client.connCfg.User = "root"

	stream, err := client.OpenSFTPStream(t.Context(), true)
	if err != nil {
		t.Fatalf("OpenSFTPStream(true) with User=root failed: %v", err)
	}
	defer func() { _ = stream.Close() }()

	if subsystemCalls.Load() != 1 {
		t.Errorf("expected 1 subsystem call, got %d", subsystemCalls.Load())
	}
	// Fast path should NOT call exec (no id -u detection)
	if execCalls.Load() != 0 {
		t.Errorf("expected 0 exec calls for root user fast-path, got %d", execCalls.Load())
	}
}

func TestOpenSFTPStream_RootUserWithSudoModeNone_Fails(t *testing.T) {
	setTestHome(t)
	var subsystemCalls atomic.Int32
	addr := startSFTPStreamTestServer(t, sftpStreamServerOptions{
		subsystemCalls: &subsystemCalls,
	})

	client := exchangeTestClient(t, addr, SudoModeNone, &recoveryTestUI{values: []string{"valid"}}, &testRecorder{})
	client.connCfg.User = "root"
	client.connCfg.SudoMode = SudoModeNone

	_, err := client.OpenSFTPStream(t.Context(), true)
	if err == nil {
		t.Fatal("expected error when SudoMode is None even if User is root, got nil")
	}
	if !strings.Contains(err.Error(), "privilege escalation is unsupported for sudo mode \"none\"") {
		t.Fatalf("expected unsupported sudo mode error, got: %v", err)
	}
	if subsystemCalls.Load() != 0 {
		t.Errorf("expected 0 subsystem calls, got %d", subsystemCalls.Load())
	}
}

func TestOpenSFTPStream_BuildScriptNoExclamationSingleLine(t *testing.T) {
	client := &Client{}
	script := client.buildSFTPStreamScript(SudoModeSu, "ready-123", "[prompt-token]", "[ack-token]", "stream-456")

	// Must be single-line or not have multi-line breaks in inner payload
	if strings.Contains(script, "!\n") || strings.Contains(script, "!= ") {
		t.Errorf("script must not contain != or !: %s", script)
	}
	if strings.Contains(script, "!") {
		t.Errorf("inner script must not contain exclamation mark (!): %s", script)
	}
	if !strings.Contains(script, `case "$p" in /*)`) {
		t.Errorf("expected case $p in /*) syntax: %s", script)
	}
}

func TestOpenSFTPStream_SuNonZeroExitBeforePassword(t *testing.T) {
	setTestHome(t)
	ui := &recoveryTestUI{}
	recorder := &testRecorder{}

	config := &cryptoSSH.ServerConfig{
		PasswordCallback: func(_ cryptoSSH.ConnMetadata, _ []byte) (*cryptoSSH.Permissions, error) {
			return nil, nil
		},
	}
	config.AddHostKey(newAuthTestSigner(t))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		server, channels, requests, err := cryptoSSH.NewServerConn(conn, config)
		if err != nil {
			return
		}
		defer func() { _ = server.Close() }()
		go func() {
			for req := range requests {
				_ = req.Reply(false, nil)
			}
		}()
		for chReq := range channels {
			channel, reqs, err := chReq.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = channel.Close() }()
				for req := range reqs {
					switch req.Type {
					case "pty-req":
						_ = req.Reply(true, nil)
					case "exec":
						_ = req.Reply(true, nil)
						// Exit with code 1 immediately before any password prompt!
						sendPrivilegeStatus(t, channel, 1)
						return
					default:
						_ = req.Reply(false, nil)
					}
				}
			}()
		}
	}()

	client := exchangeTestClient(t, listener.Addr().String(), SudoModeSu, ui, recorder)
	_, err = client.OpenSFTPStream(t.Context(), true)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// Must NOT be errPrivilegeAuthenticationRejected because no password was entered yet
	if errors.Is(err, errPrivilegeAuthenticationRejected) {
		t.Fatalf("unexpected errPrivilegeAuthenticationRejected on non-zero exit before password entry: %v", err)
	}
	if ui.prompts != 0 {
		t.Errorf("expected 0 recovery prompts, got %d", ui.prompts)
	}
}

func TestOpenSFTPStream_StderrBufferCapacity(t *testing.T) {
	buf := newSFTPStderrBuffer()
	largeData := make([]byte, 300*1024)
	for i := range largeData {
		largeData[i] = 'A'
	}
	copy(largeData[len(largeData)-10:], []byte("TAIL-DATA!"))

	n, err := buf.Write(largeData)
	if err != nil || n != len(largeData) {
		t.Fatalf("write failed: %v", err)
	}
	if buf.buf.Len() > maxSFTPStderrCapacity {
		t.Fatalf("expected buffer len <= %d, got %d", maxSFTPStderrCapacity, buf.buf.Len())
	}
	if !strings.HasSuffix(buf.String(), "TAIL-DATA!") {
		t.Errorf("expected buffer to retain most recent bytes 'TAIL-DATA!', got: %s", buf.String())
	}
}

func TestOpenSFTPStream_SudoRSPromptStripped(t *testing.T) {
	promptToken := "[xops-password-random123]"
	input := []byte("error before [sudo: [xops-password-random123]] Password: error after")
	pattern := regexp.MustCompile(regexp.QuoteMeta(promptToken))

	match, isFallback, incomplete := findSudoPrompt(input, pattern, nil, promptToken, privilegeLineStart)
	if match == nil {
		t.Fatal("expected sudo-rs prompt to be matched")
	}
	if isFallback || incomplete {
		t.Errorf("unexpected fallback=%v or incomplete=%v", isFallback, incomplete)
	}
	matchedText := string(input[match[0]:match[1]])
	if matchedText != "[sudo: [xops-password-random123]] Password:" {
		t.Fatalf("expected matched prompt to encompass full sudo-rs envelope, got: %q", matchedText)
	}
	before := string(input[:match[0]])
	if before != "error before " {
		t.Fatalf("expected before prompt: 'error before ', got: %q", before)
	}
}

type testSinglePromptUI struct {
	mu     sync.Mutex
	secret string
	calls  int
}

func (u *testSinglePromptUI) PromptSecret(ctx context.Context, _ SecretRequest) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.calls++
	return u.secret, nil
}

func (u *testSinglePromptUI) ConfirmHostKey(context.Context, HostKeyConfirmation) (bool, error) {
	return true, nil
}

func TestOpenSFTPStream_ConfirmPrivilegeError(t *testing.T) {
	setTestHome(t)
	var execCalls atomic.Int32
	addr := startSFTPStreamTestServer(t, sftpStreamServerOptions{
		mode:      SudoModeSudo,
		password:  "secret-sudo-pwd",
		execCalls: &execCalls,
	})

	ui := &testSinglePromptUI{secret: "secret-sudo-pwd"}
	recorder := &testRecorder{sudoErr: errors.New("cannot persist credential")}
	client := exchangeTestClient(t, addr, SudoModeSudo, ui, recorder)

	stream, err := client.OpenSFTPStream(t.Context(), true)
	if err == nil {
		if stream != nil {
			_ = stream.Close()
		}
		t.Fatal("expected error from confirmPrivilege, got nil")
	}
	if !strings.Contains(err.Error(), "cannot persist credential") {
		t.Fatalf("expected cannot persist credential error, got: %v", err)
	}
}

func TestOpenSFTPStream_SuLimitOnePasswordSubmission(t *testing.T) {
	setTestHome(t)
	var execCalls atomic.Int32
	addr := startSFTPStreamTestServer(t, sftpStreamServerOptions{
		mode:       SudoModeSu,
		password:   "secret-su-pwd",
		repromptSu: true,
		execCalls:  &execCalls,
	})

	ui := &testSinglePromptUI{secret: "secret-su-pwd"}
	recorder := &testRecorder{}
	client := exchangeTestClient(t, addr, SudoModeSu, ui, recorder)

	_, err := client.OpenSFTPStream(t.Context(), true)
	if err == nil {
		t.Fatal("expected error on reprompt, got nil")
	}
	if !errors.Is(err, errPrivilegeAuthenticationRejected) {
		t.Fatalf("expected errPrivilegeAuthenticationRejected on su re-prompt, got: %v", err)
	}
}

func TestOpenSFTPStream_HandshakeTimeoutAfterAck(t *testing.T) {
	setTestHome(t)
	var execCalls atomic.Int32
	addr := startSFTPStreamTestServer(t, sftpStreamServerOptions{
		mode:         SudoModeSudoer,
		hangAfterAck: true,
		execCalls:    &execCalls,
	})

	client := exchangeTestClient(t, addr, SudoModeSudoer, &recoveryTestUI{}, &testRecorder{})
	client.handshakeTimeout = 100 * time.Millisecond

	ctx := t.Context()
	start := time.Now()
	_, err := client.OpenSFTPStream(ctx, true)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("expected deadline exceeded, got: %v", err)
	}
	if elapsed > 1500*time.Millisecond {
		t.Errorf("handshake timeout took too long: %v", elapsed)
	}
}

func TestOpenSFTPStream_ShutdownTimeoutInterruptsRemote(t *testing.T) {
	setTestHome(t)
	var execCalls atomic.Int32
	addr := startSFTPStreamTestServer(t, sftpStreamServerOptions{
		mode:      SudoModeSudoer,
		execCalls: &execCalls,
	})

	client := exchangeTestClient(t, addr, SudoModeSudoer, &recoveryTestUI{}, &testRecorder{})
	session, err := client.newSessionContext(t.Context())
	if err != nil {
		t.Fatalf("newSessionContext failed: %v", err)
	}

	hangingWaitDone := make(chan error, 1)
	go func() {
		// Wait until sessionShutdownTimeout expires and closer calls c.Interrupt(),
		// then unblock hangingWaitDone.
		time.Sleep(sessionShutdownTimeout + 50*time.Millisecond)
		hangingWaitDone <- io.EOF
	}()

	closer := client.sftpStreamCloser(session, hangingWaitDone, nil)
	err = closer()
	if err == nil {
		t.Fatal("expected error on hanging shutdown, got nil")
	}
	if !strings.Contains(err.Error(), "sftp session shutdown timed out") {
		t.Fatalf("expected sftp session shutdown timed out error, got: %v", err)
	}
}

func TestOpenSFTPStream_AuthPromptTimeout(t *testing.T) {
	setTestHome(t)
	var execCalls atomic.Int32
	addr := startSFTPStreamTestServer(t, sftpStreamServerOptions{
		mode:             SudoModeSudo,
		hangBeforePrompt: true,
		execCalls:        &execCalls,
	})

	client := exchangeTestClient(t, addr, SudoModeSudo, &recoveryTestUI{}, &testRecorder{})
	client.interactionTimeout = 100 * time.Millisecond

	start := time.Now()
	_, err := client.OpenSFTPStream(t.Context(), true)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error during auth prompt phase, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("expected deadline exceeded, got: %v", err)
	}
	if !strings.Contains(err.Error(), "wait for privilege authentication") {
		t.Fatalf("expected 'wait for privilege authentication' error, got: %v", err)
	}
	if elapsed > 1500*time.Millisecond {
		t.Errorf("auth timeout took too long: %v", elapsed)
	}
}

func TestOpenSFTPStream_StderrPreservesPendingAcrossHandoff(t *testing.T) {
	setTestHome(t)
	var execCalls atomic.Int32
	addr := startSFTPStreamTestServer(t, sftpStreamServerOptions{
		mode:              SudoModeSudo,
		password:          "secret-sudo-pwd",
		stderrBeforeReady: "warning: before handoff\n",
		stderrAfterReady:  "error: after handoff\n",
		execCalls:         &execCalls,
	})

	ui := &recoveryTestUI{values: []string{"secret-sudo-pwd"}}
	recorder := &testRecorder{}
	client := exchangeTestClient(t, addr, SudoModeSudo, ui, recorder)

	stream, err := client.OpenSFTPStream(t.Context(), true)
	if err != nil {
		t.Fatalf("OpenSFTPStream failed: %v", err)
	}
	defer func() { _ = stream.Close() }()

	stderrReader := stream.Stderr
	var receivedStderr string
	readBuf := make([]byte, 1024)
	for range 50 {
		n, err := stderrReader.Read(readBuf)
		if n > 0 {
			receivedStderr += string(readBuf[:n])
		}
		if strings.Contains(receivedStderr, "error: after handoff") || (err != nil && errors.Is(err, io.EOF)) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	idxBefore := strings.Index(receivedStderr, "warning: before handoff")
	idxAfter := strings.Index(receivedStderr, "error: after handoff")
	if idxBefore < 0 {
		t.Errorf("expected stderr to contain 'warning: before handoff', got: %q", receivedStderr)
	}
	if idxAfter < 0 {
		t.Errorf("expected stderr to contain 'error: after handoff', got: %q", receivedStderr)
	}
	if idxBefore >= 0 && idxAfter >= 0 && idxBefore > idxAfter {
		t.Errorf("stderr order corrupted: before handoff (%d) appears after after handoff (%d)", idxBefore, idxAfter)
	}
}

func TestOpenSFTPStream_ReadyAndStreamTokenInSameChunk(t *testing.T) {
	setTestHome(t)
	var execCalls atomic.Int32
	addr := startSFTPStreamTestServer(t, sftpStreamServerOptions{
		mode:           SudoModeSudoer,
		coalesceTokens: true,
		execCalls:      &execCalls,
	})

	client := exchangeTestClient(t, addr, SudoModeSudoer, &recoveryTestUI{values: []string{"valid"}}, &testRecorder{})
	stream, err := client.OpenSFTPStream(t.Context(), true)
	if err != nil {
		t.Fatalf("OpenSFTPStream with coalesced tokens failed: %v", err)
	}
	defer func() { _ = stream.Close() }()

	testPayload := []byte("coalesced-stream-payload")
	if _, err := stream.Write(testPayload); err != nil {
		t.Fatalf("stream.Write failed: %v", err)
	}
	buf := make([]byte, len(testPayload))
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatalf("stream.Read failed: %v", err)
	}
	if string(buf) != string(testPayload) {
		t.Fatalf("expected %q, got %q", testPayload, buf)
	}
}

func exchangeTestClientWithDiagnostics(t *testing.T, addr string, mode SudoMode, ui InteractionHandler, recorder CredentialRecorder, observer corelog.DiagnosticObserver, promptPattern ...string) *Client {
	t.Helper()
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	provider := &trackingProvider{cfg: &ClientConfig{NodeID: "node", Address: host, Port: port, User: "user", AuthType: "password", Password: "login", SudoMode: mode, SudoUpdateToken: "sudo"}}
	if len(promptPattern) > 0 {
		provider.cfg.PasswordPromptPattern = promptPattern[0]
	}
	opts := []Option{WithInteractionHandler(ui), WithCredentialRecorder(recorder)}
	if observer != nil {
		opts = append(opts, WithDiagnostics(observer))
	}
	connector := newTestConnector(provider, opts...)
	t.Cleanup(func() {
		if err := connector.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	client, err := connector.Connect(t.Context(), "node")
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestOpenSFTPStream_ExitAfterReadyDoesNotTriggerAuthFailure(t *testing.T) {
	for _, mode := range []SudoMode{SudoModeSu, SudoModeSudo} {
		t.Run(string(mode), func(t *testing.T) {
			setTestHome(t)
			var execCalls atomic.Int32
			addr := startSFTPStreamTestServer(t, sftpStreamServerOptions{
				mode:               mode,
				password:           "secret-valid-pwd",
				exitAfterAckStatus: 1,
				execCalls:          &execCalls,
			})

			ui := &recoveryTestUI{values: []string{"secret-valid-pwd"}}
			recorder := &testRecorder{}
			client := exchangeTestClient(t, addr, mode, ui, recorder)

			_, err := client.OpenSFTPStream(t.Context(), true)
			if err == nil {
				t.Fatal("expected error on abnormal exit after ready, got nil")
			}
			if errors.Is(err, errPrivilegeAuthenticationRejected) {
				t.Fatalf("unexpected errPrivilegeAuthenticationRejected after readyToken was received: %v", err)
			}
			if !strings.Contains(err.Error(), "privilege sftp setup failed") {
				t.Fatalf("expected 'privilege sftp setup failed' error, got: %v", err)
			}
			// In SudoModeSu, if errPrivilegeAuthenticationRejected had been returned,
			// the outer loop would have retried and prompted the user again.
			if ui.prompts != 1 {
				t.Errorf("expected exactly 1 prompt (no false auth recovery retries), got %d", ui.prompts)
			}
		})
	}
}

func TestOpenSFTPStream_Exit0BeforeStreamTokenDoesNotHang(t *testing.T) {
	setTestHome(t)
	var execCalls atomic.Int32
	addr := startSFTPStreamTestServer(t, sftpStreamServerOptions{
		mode:                  SudoModeSudo,
		password:              "secret-valid-pwd",
		closeStdoutBeforeExit: true,
		exitAfterAckStatus:    0,
		execCalls:             &execCalls,
	})

	ui := &recoveryTestUI{values: []string{"secret-valid-pwd"}}
	recorder := &testRecorder{}
	client := exchangeTestClient(t, addr, SudoModeSudo, ui, recorder)

	start := time.Now()
	_, err := client.OpenSFTPStream(t.Context(), true)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error on abnormal exit 0 before stream token, got nil")
	}
	if strings.Contains(err.Error(), "shutdown timed out") {
		t.Fatalf("session shutdown timed out (hit waitDone hang bug): %v", err)
	}
	if elapsed > 900*time.Millisecond {
		t.Errorf("expected fast failure on exit 0, but took %v", elapsed)
	}
	if client.sshClient.Conn == nil {
		t.Errorf("sshClient connection was aborted/interrupted unexpectedly")
	}
}

func TestOpenSFTPStream_BannerWithAuthFailureBefore127(t *testing.T) {
	setTestHome(t)
	var execCalls atomic.Int32
	addr := startSFTPStreamTestServer(t, sftpStreamServerOptions{
		mode:                     SudoModeSu,
		password:                 "secret-su-pwd",
		stdoutBannerBeforePrompt: "Last login: Authentication failure on previous attempt\n",
		missingBinary:            true,
		execCalls:                &execCalls,
	})

	ui := &recoveryTestUI{values: []string{"secret-su-pwd"}}
	recorder := &testRecorder{}
	client := exchangeTestClient(t, addr, SudoModeSu, ui, recorder)

	_, err := client.OpenSFTPStream(t.Context(), true)
	if err == nil {
		t.Fatal("expected error on missing sftp-server, got nil")
	}
	if errors.Is(err, errPrivilegeAuthenticationRejected) {
		t.Fatalf("unexpected errPrivilegeAuthenticationRejected when exit status is 127: %v", err)
	}
	if !strings.Contains(err.Error(), "remote sftp-server binary not found") {
		t.Fatalf("expected 'remote sftp-server binary not found' in error, got: %v", err)
	}
	if ui.prompts != 1 {
		t.Errorf("expected 1 prompt, got %d", ui.prompts)
	}
}

func TestOpenSFTPStream_BannerWithAuthFailureMissingBinaryBeforePassword(t *testing.T) {
	setTestHome(t)
	var execCalls atomic.Int32
	addr := startSFTPStreamTestServer(t, sftpStreamServerOptions{
		mode:                      SudoModeSu,
		stdoutBannerBeforePrompt:  "Authentication failure: 3 previous login attempts\n",
		missingBinaryBeforePrompt: true,
		execCalls:                 &execCalls,
	})

	ui := &recoveryTestUI{values: []string{"any"}}
	recorder := &testRecorder{}
	client := exchangeTestClient(t, addr, SudoModeSu, ui, recorder)

	_, err := client.OpenSFTPStream(t.Context(), true)
	if err == nil {
		t.Fatal("expected error on missing sftp-server before password, got nil")
	}
	if errors.Is(err, errPrivilegeAuthenticationRejected) {
		t.Fatalf("unexpected errPrivilegeAuthenticationRejected when no password was sent: %v", err)
	}
	if !strings.Contains(err.Error(), "remote sftp-server binary not found") {
		t.Fatalf("expected 'remote sftp-server binary not found' in error, got: %v", err)
	}
	if ui.prompts != 0 {
		t.Errorf("expected 0 prompts, got %d", ui.prompts)
	}
}

func TestBuildSFTPStreamScript_PTYFlagsAndRedirect(t *testing.T) {
	client := &Client{}
	scriptSu := client.buildSFTPStreamScript(SudoModeSu, "ready-1", "[prompt-1]", "[ack-1]", "stream-1")
	if !strings.Contains(scriptSu, "-iexten") {
		t.Errorf("expected -iexten in SudoModeSu stty command, got: %s", scriptSu)
	}
	if !strings.Contains(scriptSu, `exec "$xops_sftp_bin" 2>/dev/null`) {
		t.Errorf("expected exec \"$xops_sftp_bin\" 2>/dev/null in SudoModeSu, got: %s", scriptSu)
	}

	scriptSudo := client.buildSFTPStreamScript(SudoModeSudo, "ready-2", "[prompt-2]", "[ack-2]", "stream-2")
	if strings.Contains(scriptSudo, `exec "$xops_sftp_bin" 2>/dev/null`) {
		t.Errorf("expected no 2>/dev/null redirection on exec in SudoModeSudo, got: %s", scriptSudo)
	}
	if !strings.Contains(scriptSudo, `exec "$xops_sftp_bin"; }`) {
		t.Errorf("expected exec \"$xops_sftp_bin\"; in SudoModeSudo, got: %s", scriptSudo)
	}
	if strings.Contains(scriptSudo, "-iexten") {
		t.Errorf("expected no stty in SudoModeSudo script, got: %s", scriptSudo)
	}
}

func TestFindSudoPrompt_XtraceIgnored(t *testing.T) {
	promptToken := "[xops-password-rand42]"
	pattern := regexp.MustCompile(regexp.QuoteMeta(promptToken))

	// Data contains xtrace output echoing command with prompt token, followed by genuine prompt
	data := []byte("+ sudo -S -p [xops-password-rand42] -- /bin/sh -c payload\n[xops-password-rand42] ")

	match, isFallback, incomplete := findSudoPrompt(data, pattern, nil, promptToken, privilegeLineStart)
	if match == nil {
		t.Fatal("expected sudo prompt to be matched")
	}
	if isFallback || incomplete {
		t.Errorf("unexpected fallback=%v or incomplete=%v", isFallback, incomplete)
	}
	if match[0] < len("+ sudo -S -p ") {
		t.Fatalf("matched prompt matched xtrace line instead of real prompt, offset=%d", match[0])
	}
	matched := string(data[match[0]:match[1]])
	if matched != promptToken {
		t.Fatalf("expected %q, got %q", promptToken, matched)
	}
}

func TestFindSudoPrompt_XtraceTruncatedChunk_Ignored(t *testing.T) {
	promptToken := "[xops-password-rand42]"
	pattern := regexp.MustCompile(regexp.QuoteMeta(promptToken))

	// Suppose chunk 1 contained "+ /very/long/path/..." which was > 64 bytes and got truncated.
	// Advancing line prefix over chunk 1 records that we are within an xtrace line.
	chunk1 := []byte("+ /very/long/path/that/exceeds/sixty/four/bytes/and/is/truncated/sudo -S ")
	linePrefix := advancePrivilegeLine(privilegeLineStart, chunk1)

	// Chunk 2 arrives with the prompt token in xtrace, followed by newline and genuine prompt
	chunk2 := []byte("-p [xops-password-rand42] -- /bin/sh -c payload\n[xops-password-rand42] ")

	match, isFallback, incomplete := findSudoPrompt(chunk2, pattern, nil, promptToken, linePrefix)
	if match == nil {
		t.Fatal("expected sudo prompt to be matched")
	}
	if isFallback || incomplete {
		t.Errorf("unexpected fallback=%v or incomplete=%v", isFallback, incomplete)
	}
	if match[0] < len("-p [xops-password-rand42] -- /bin/sh -c payload\n") {
		t.Fatalf("matched prompt matched xtrace line instead of real prompt after truncation, offset=%d", match[0])
	}
	matched := string(chunk2[match[0]:match[1]])
	if matched != promptToken {
		t.Fatalf("expected %q, got %q", promptToken, matched)
	}
}

func TestOpenSFTPStream_DiagnosticsEmitted(t *testing.T) {
	setTestHome(t)
	var execCalls atomic.Int32
	addr := startSFTPStreamTestServer(t, sftpStreamServerOptions{
		mode:      SudoModeSudo,
		password:  "secret-diag-pwd",
		execCalls: &execCalls,
	})

	ui := &recoveryTestUI{values: []string{"secret-diag-pwd"}}
	recorder := &testRecorder{}
	diagRecorder := &diagnosticRecorder{}

	client := exchangeTestClientWithDiagnostics(t, addr, SudoModeSudo, ui, recorder, diagRecorder)
	stream, err := client.OpenSFTPStream(t.Context(), true)
	if err != nil {
		t.Fatalf("OpenSFTPStream failed: %v", err)
	}
	defer func() { _ = stream.Close() }()

	events := diagRecorder.snapshot()
	phases := make(map[string]bool)
	var foundCommandPrepared bool
	for _, e := range events {
		if e.Kind == corelog.PrivilegeLifecycle {
			phases[e.Outcome] = true
			if e.Outcome == "command_prepared" && e.PrivilegeCommand != "" {
				foundCommandPrepared = true
			}
		}
	}

	requiredPhases := []string{
		"command_prepared",
		"password_prompt_pattern",
		"password_prompt_matched",
		"elevated_shell_ready",
		"handoff_ack_sent",
		"sftp_stream_ready",
	}
	for _, p := range requiredPhases {
		if !phases[p] {
			t.Errorf("expected diagnostic phase %q to be emitted, got phases: %v", p, phases)
		}
	}
	if !foundCommandPrepared {
		t.Error("expected PrivilegeCommand to be populated on command_prepared event")
	}
}

func TestOpenSFTPStream_SubsystemSessionFinishedDiagnostic(t *testing.T) {
	setTestHome(t)
	var subsystemCalls atomic.Int32
	addr := startSFTPStreamTestServer(t, sftpStreamServerOptions{
		subsystemCalls: &subsystemCalls,
	})

	diagRecorder := &diagnosticRecorder{}
	client := exchangeTestClientWithDiagnostics(t, addr, SudoModeNone, &recoveryTestUI{}, &testRecorder{}, diagRecorder)

	stream, err := client.OpenSFTPStream(t.Context(), false)
	if err != nil {
		t.Fatalf("OpenSFTPStream(false) failed: %v", err)
	}

	// Close the stream, which must trigger waitSession and emit SessionFinished
	if err := stream.Close(); err != nil {
		t.Fatalf("stream.Close failed: %v", err)
	}

	events := diagRecorder.snapshot()
	var foundStarted, foundFinished bool
	for _, e := range events {
		if e.Kind == corelog.SessionStarted && e.Operation == "sftp subsystem" {
			foundStarted = true
		}
		if e.Kind == corelog.SessionFinished && e.Outcome == "completed" && e.HasExitCode {
			foundFinished = true
		}
	}
	if !foundStarted {
		t.Error("expected SessionStarted diagnostic for sftp subsystem")
	}
	if !foundFinished {
		t.Error("expected SessionFinished diagnostic with HasExitCode on stream close for sftp subsystem")
	}
}

func TestOpenSFTPStream_RootFastPathEmitsPrivilegeDiagnostics(t *testing.T) {
	setTestHome(t)
	var subsystemCalls atomic.Int32
	addr := startSFTPStreamTestServer(t, sftpStreamServerOptions{
		subsystemCalls: &subsystemCalls,
	})

	diagRecorder := &diagnosticRecorder{}
	client := exchangeTestClientWithDiagnostics(t, addr, SudoModeRoot, &recoveryTestUI{}, &testRecorder{}, diagRecorder)

	stream, err := client.OpenSFTPStream(t.Context(), true)
	if err != nil {
		t.Fatalf("OpenSFTPStream(true) with SudoModeRoot failed: %v", err)
	}
	defer func() { _ = stream.Close() }()

	phases := make(map[string]bool)
	for _, e := range diagRecorder.snapshot() {
		if e.Kind == corelog.PrivilegeLifecycle {
			phases[e.Outcome] = true
		}
	}
	if !phases["mode_selected"] {
		t.Errorf("expected mode_selected diagnostic on root fast-path, got: %v", phases)
	}
	if !phases["escalation_not_required"] {
		t.Errorf("expected escalation_not_required diagnostic on root fast-path, got: %v", phases)
	}
}
