package cmd

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

// mockMasterServer runs a mock unix domain socket server implementing OpenSSH PROTOCOL.mux v4.
type mockMasterServer struct {
	listener   net.Listener
	sockPath   string
	extensions []ssh.MuxExtension
	alivePID   uint32
	exitErr    string
	stopErr    string
	infoResp   map[string]string
	infoErr    map[string]string
}

func newMockMasterServer(t *testing.T) *mockMasterServer {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "mock-mux-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	sock := filepath.Join(tmpDir, "master.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		t.Fatalf("Listen unix failed: %v", err)
	}

	m := &mockMasterServer{
		listener: ln,
		sockPath: sock,
		alivePID: uint32(os.Getpid()),
		extensions: []ssh.MuxExtension{
			{Name: "info", Value: "1"},
		},
		infoResp: make(map[string]string),
		infoErr:  make(map[string]string),
	}

	t.Cleanup(func() {
		_ = ln.Close()
		_ = os.RemoveAll(tmpDir)
	})

	go m.serve()
	return m
}

func (m *mockMasterServer) serve() {
	for {
		conn, err := m.listener.Accept()
		if err != nil {
			return
		}
		go m.handleConn(conn)
	}
}

func (m *mockMasterServer) handleConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	// Handshake
	pktType, _, err := ssh.ReadMuxPacket(conn)
	if err != nil || pktType != ssh.MUX_MSG_HELLO {
		return
	}
	_ = ssh.WriteMuxPacket(conn, ssh.MUX_MSG_HELLO, ssh.EncodeMuxHello(ssh.MuxProtoVersion, m.extensions))

	for {
		msgType, payload, err := ssh.ReadMuxPacket(conn)
		if err != nil {
			return
		}
		switch msgType {
		case ssh.MUX_C_ALIVE_CHECK:
			reqID, _ := ssh.DecodeMuxRequestID(payload)
			_ = ssh.WriteMuxPacket(conn, ssh.MUX_S_ALIVE, ssh.EncodeMuxAlive(reqID, m.alivePID))

		case ssh.MUX_C_TERMINATE:
			reqID, _ := ssh.DecodeMuxRequestID(payload)
			if m.exitErr != "" {
				_ = ssh.WriteMuxPacket(conn, ssh.MUX_S_FAILURE, ssh.EncodeMuxError(reqID, m.exitErr))
			} else {
				_ = ssh.WriteMuxPacket(conn, ssh.MUX_S_OK, ssh.EncodeMuxClientRequestID(reqID))
				return
			}

		case ssh.MUX_C_STOP_LISTENING:
			reqID, _ := ssh.DecodeMuxRequestID(payload)
			if m.stopErr != "" {
				_ = ssh.WriteMuxPacket(conn, ssh.MUX_S_FAILURE, ssh.EncodeMuxError(reqID, m.stopErr))
			} else {
				_ = ssh.WriteMuxPacket(conn, ssh.MUX_S_OK, ssh.EncodeMuxClientRequestID(reqID))
			}

		case ssh.MUX_C_EXT_INFO:
			reqID, name, _ := ssh.DecodeMuxExtInfo(payload)
			if errMsg, ok := m.infoErr[name]; ok {
				_ = ssh.WriteMuxPacket(conn, ssh.MUX_S_EXT_INFO, ssh.EncodeMuxExtInfoResponse(reqID, 0, errMsg))
			} else if resp, ok := m.infoResp[name]; ok {
				_ = ssh.WriteMuxPacket(conn, ssh.MUX_S_EXT_INFO, ssh.EncodeMuxExtInfoResponse(reqID, 1, resp))
			} else {
				_ = ssh.WriteMuxPacket(conn, ssh.MUX_S_FAILURE, ssh.EncodeMuxError(reqID, "unsupported info: "+name))
			}

		case ssh.MUX_C_OPEN_FWD:
			req, _ := ssh.DecodeMuxFwdRequest(payload)
			_ = ssh.WriteMuxPacket(conn, ssh.MUX_S_OK, ssh.EncodeMuxClientRequestID(req.RequestID))

		case ssh.MUX_C_CLOSE_FWD:
			req, _ := ssh.DecodeMuxFwdRequest(payload)
			_ = ssh.WriteMuxPacket(conn, ssh.MUX_S_OK, ssh.EncodeMuxClientRequestID(req.RequestID))
		}
	}
}

// 1. Adversarial Test: -M flag variations (single, double, triple, short-flags, flag override of -o)
func TestAdversarial_MasterFlagVariations(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantMaster ssh.ControlMasterMode
	}{
		{
			name:       "single -M",
			args:       []string{"-M", "dummyhost"},
			wantMaster: ssh.ControlMasterYes,
		},
		{
			name:       "double -M -M",
			args:       []string{"-M", "-M", "dummyhost"},
			wantMaster: ssh.ControlMasterAsk,
		},
		{
			name:       "combined -MM",
			args:       []string{"-MM", "dummyhost"},
			wantMaster: ssh.ControlMasterAsk,
		},
		{
			name:       "triple -M -M -M",
			args:       []string{"-M", "-M", "-M", "dummyhost"},
			wantMaster: ssh.ControlMasterAsk,
		},
		{
			name:       "-M overrides -o ControlMaster=auto",
			args:       []string{"-M", "-o", "ControlMaster=auto", "dummyhost"},
			wantMaster: ssh.ControlMasterYes,
		},
		{
			name:       "-M -M overrides -o ControlMaster=no",
			args:       []string{"-M", "-M", "-o", "ControlMaster=no", "dummyhost"},
			wantMaster: ssh.ControlMasterAsk,
		},
		{
			name:       "no -M respects -o ControlMaster=auto",
			args:       []string{"-o", "ControlMaster=auto", "dummyhost"},
			wantMaster: ssh.ControlMasterAuto,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := NewSshOptions()
			cmd := &cobra.Command{Use: "ssh"}
			opts.control.RegisterSSHFlags(cmd)

			if err := cmd.ParseFlags(tc.args); err != nil {
				t.Fatalf("ParseFlags failed: %v", err)
			}
			sessionOpts, err := opts.control.ToSessionControlOptions()
			if err != nil {
				t.Fatalf("ToSessionControlOptions failed: %v", err)
			}
			if sessionOpts.Master == nil || *sessionOpts.Master != tc.wantMaster {
				t.Fatalf("expected Master %q, got %v", tc.wantMaster, sessionOpts.Master)
			}
		})
	}
}

// 2. Adversarial Test: -S none completely disables connection sharing even when lower tiers have ControlMaster auto & ControlPersist
func TestAdversarial_ControlPathNone_DisablesSharing(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Control: &ssh.ControlConfig{
			Master:  ssh.ControlMasterAuto,
			Path:    "/tmp/global.sock",
			Persist: "1h",
		},
	}
	cfg.Hosts.Set("host1", models.Host{Address: "192.168.1.100"})
	cfg.Identities.Set("id1", models.Identity{User: "alice", AuthType: "auto"})
	cfg.Nodes.Set("persistent-node", models.Node{
		HostRef:     "host1",
		IdentityRef: "id1",
		Control: &ssh.ControlConfig{
			Master:  ssh.ControlMasterAuto,
			Path:    "/tmp/lower-tier.sock",
			Persist: "10m",
		},
	})

	provider, err := config.NewProvider(cfg)
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}
	adp := adapter.NewSSHAdapter(provider)

	// Case A: With -S none
	var sessionOptsNone adapter.SessionControlOptions
	sessionOptsNone.SetPath("none")

	resNone, err := adp.ResolveControl("persistent-node", sessionOptsNone)
	if err != nil {
		t.Fatalf("ResolveControl failed: %v", err)
	}
	if resNone == nil {
		t.Fatal("expected non-nil ControlConfig with Master=no and Path=none")
	}
	if resNone.Master != ssh.ControlMasterNo {
		t.Fatalf("expected Master=no, got %q", resNone.Master)
	}
	if resNone.Path != "none" {
		t.Fatalf("expected Path=none, got %q", resNone.Path)
	}
	if resNone.Persist != "" {
		t.Fatalf("expected empty Persist when Path=none, got %q", resNone.Persist)
	}

	// Case B: Verify that without -S none, persistent-node resolves to ControlMasterAuto and Persist 10m
	resNormal, err := adp.ResolveControl("persistent-node", adapter.SessionControlOptions{})
	if err != nil {
		t.Fatalf("ResolveControl failed: %v", err)
	}
	if resNormal == nil || resNormal.Master != ssh.ControlMasterAuto || resNormal.Persist != "10m" {
		t.Fatalf("expected normal resolve to have auto and 10m, got %+v", resNormal)
	}
}

// 3. Adversarial Test: -O check outputs "Master running (pid=<pid>)\n" to stderr, exit 0; exits 255 on missing/dead socket
func TestAdversarial_ControlCheck_AliveAndErrors(t *testing.T) {
	// 3.1 Master is alive
	server := newMockMasterServer(t)
	server.alivePID = 54321

	var stdout, stderr bytes.Buffer
	streams := controlStreams{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr}
	opts := &SshOptions{
		control: SSHControlFlags{
			CtlCmd:      "check",
			ControlPath: server.sockPath,
		},
	}

	err := executeControlCommandWithStreams(context.Background(), opts, streams)
	if err != nil {
		t.Fatalf("unexpected check error: %v", err)
	}
	expectedOutput := "Master running (pid=54321)\n"
	if stderr.String() != expectedOutput {
		t.Fatalf("expected stderr %q, got %q", expectedOutput, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected stdout empty, got %q", stdout.String())
	}

	// 3.2 Socket does not exist -> exit code 255 + stderr exact string
	stderr.Reset()
	missingSock := filepath.Join(os.TempDir(), "non_existent_check_12345.sock")
	optsMissing := &SshOptions{
		control: SSHControlFlags{
			CtlCmd:      "check",
			ControlPath: missingSock,
		},
	}
	err = executeControlCommandWithStreams(context.Background(), optsMissing, streams)
	if err == nil {
		t.Fatal("expected error on missing socket, got nil")
	}
	code, ok := ExitCodeFromError(err)
	if !ok || code != 255 {
		t.Fatalf("expected exit code 255, got code=%d (ok=%v)", code, ok)
	}
	expectedErr := fmt.Sprintf("Control socket connect(%s): No such file or directory\n", missingSock)
	if stderr.String() != expectedErr {
		t.Fatalf("expected stderr %q, got %q", expectedErr, stderr.String())
	}

	// 3.3 Socket is stale (ECONNREFUSED) -> exit code 255 + stderr exact string
	stderr.Reset()
	tmpDir, _ := os.MkdirTemp("", "stale-test-*")
	defer func() { _ = os.RemoveAll(tmpDir) }()
	staleSock := filepath.Join(tmpDir, "stale.sock")
	fd, _ := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	sa := &syscall.SockaddrUnix{Name: staleSock}
	_ = syscall.Bind(fd, sa)
	_ = syscall.Close(fd)

	optsStale := &SshOptions{
		control: SSHControlFlags{
			CtlCmd:      "check",
			ControlPath: staleSock,
		},
	}
	err = executeControlCommandWithStreams(context.Background(), optsStale, streams)
	if err == nil {
		t.Fatal("expected error on stale socket, got nil")
	}
	code, ok = ExitCodeFromError(err)
	if !ok || code != 255 {
		t.Fatalf("expected exit code 255, got %d", code)
	}
	expectedStaleErr := fmt.Sprintf("Control socket connect(%s): Connection refused\n", staleSock)
	if stderr.String() != expectedStaleErr {
		t.Fatalf("expected stderr %q, got %q", expectedStaleErr, stderr.String())
	}
}

// 4. Adversarial Test: -O exit outputs "Exit request sent.\n" to stderr, exit 0; exits 255 on error
func TestAdversarial_ControlExit_SuccessAndFailure(t *testing.T) {
	// 4.1 Success
	server := newMockMasterServer(t)
	var stdout, stderr bytes.Buffer
	streams := controlStreams{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr}
	opts := &SshOptions{
		control: SSHControlFlags{
			CtlCmd:      "exit",
			ControlPath: server.sockPath,
		},
	}

	if err := executeControlCommandWithStreams(context.Background(), opts, streams); err != nil {
		t.Fatalf("unexpected exit error: %v", err)
	}
	if stderr.String() != "Exit request sent.\n" {
		t.Fatalf("expected stderr 'Exit request sent.\\n', got %q", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected stdout empty, got %q", stdout.String())
	}

	// 4.2 Master rejects exit (failure packet) -> exit code 255
	serverFail := newMockMasterServer(t)
	serverFail.exitErr = "active sessions remaining"
	stderr.Reset()
	optsFail := &SshOptions{
		control: SSHControlFlags{
			CtlCmd:      "exit",
			ControlPath: serverFail.sockPath,
		},
	}
	err := executeControlCommandWithStreams(context.Background(), optsFail, streams)
	if err == nil {
		t.Fatal("expected error on exit failure, got nil")
	}
	code, ok := ExitCodeFromError(err)
	if !ok || code != 255 {
		t.Fatalf("expected exit code 255, got %d", code)
	}
	if !strings.Contains(stderr.String(), "active sessions remaining") {
		t.Fatalf("expected stderr to contain error reason, got %q", stderr.String())
	}
}

// 5. Adversarial Test: -O stop outputs "Stop listening request sent.\n" to stderr, exit 0; exits 255 on error
func TestAdversarial_ControlStop_SuccessAndFailure(t *testing.T) {
	// 5.1 Success
	server := newMockMasterServer(t)
	var stdout, stderr bytes.Buffer
	streams := controlStreams{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr}
	opts := &SshOptions{
		control: SSHControlFlags{
			CtlCmd:      "stop",
			ControlPath: server.sockPath,
		},
	}

	if err := executeControlCommandWithStreams(context.Background(), opts, streams); err != nil {
		t.Fatalf("unexpected stop error: %v", err)
	}
	if stderr.String() != "Stop listening request sent.\n" {
		t.Fatalf("expected stderr 'Stop listening request sent.\\n', got %q", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected stdout empty, got %q", stdout.String())
	}

	// 5.2 Server failure -> exit code 255
	serverFail := newMockMasterServer(t)
	serverFail.stopErr = "cannot unlink socket"
	stderr.Reset()
	optsFail := &SshOptions{
		control: SSHControlFlags{
			CtlCmd:      "stop",
			ControlPath: serverFail.sockPath,
		},
	}
	err := executeControlCommandWithStreams(context.Background(), optsFail, streams)
	if err == nil {
		t.Fatal("expected error on stop failure, got nil")
	}
	code, ok := ExitCodeFromError(err)
	if !ok || code != 255 {
		t.Fatalf("expected exit code 255, got %d", code)
	}
	if !strings.Contains(stderr.String(), "cannot unlink socket") {
		t.Fatalf("expected stderr to contain error reason, got %q", stderr.String())
	}
}

// 6. Adversarial Test: -O conninfo and -O channels via MUX_C_EXT_INFO
func TestAdversarial_ControlInfo_ConninfoAndChannels(t *testing.T) {
	server := newMockMasterServer(t)
	server.infoResp["connection"] = "Master socket: /tmp/master.sock\nPID: 123\n"
	server.infoResp["channels"] = "Active Channels:\n- Session 1: pty\n- LocalForward 8080->80\n"

	// 6.1 conninfo
	{
		var stdout, stderr bytes.Buffer
		streams := controlStreams{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr}
		opts := &SshOptions{
			control: SSHControlFlags{
				CtlCmd:      "conninfo",
				ControlPath: server.sockPath,
			},
		}
		if err := executeControlCommandWithStreams(context.Background(), opts, streams); err != nil {
			t.Fatalf("conninfo failed: %v", err)
		}
		if stdout.String() != server.infoResp["connection"] {
			t.Fatalf("expected stdout %q, got %q", server.infoResp["connection"], stdout.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("expected stderr empty, got %q", stderr.String())
		}
	}

	// 6.2 channels
	{
		var stdout, stderr bytes.Buffer
		streams := controlStreams{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr}
		opts := &SshOptions{
			control: SSHControlFlags{
				CtlCmd:      "channels",
				ControlPath: server.sockPath,
			},
		}
		if err := executeControlCommandWithStreams(context.Background(), opts, streams); err != nil {
			t.Fatalf("channels failed: %v", err)
		}
		if stdout.String() != server.infoResp["channels"] {
			t.Fatalf("expected stdout %q, got %q", server.infoResp["channels"], stdout.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("expected stderr empty, got %q", stderr.String())
		}
	}

	// 6.3 Server returns error on query -> exits 255
	{
		server.infoErr["connection"] = "connection query disabled by policy"
		var stdout, stderr bytes.Buffer
		streams := controlStreams{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr}
		opts := &SshOptions{
			control: SSHControlFlags{
				CtlCmd:      "conninfo",
				ControlPath: server.sockPath,
			},
		}
		err := executeControlCommandWithStreams(context.Background(), opts, streams)
		if err == nil {
			t.Fatal("expected error on infoErr, got nil")
		}
		code, ok := ExitCodeFromError(err)
		if !ok || code != 255 {
			t.Fatalf("expected exit code 255, got %d", code)
		}
		if !strings.Contains(stderr.String(), "connection query disabled by policy") {
			t.Fatalf("expected stderr to contain error reason, got %q", stderr.String())
		}
	}
}

// 7. Adversarial Test: Missing forward flags for -O forward and -O cancel exits 255
func TestAdversarial_ForwardCancel_MissingOptions(t *testing.T) {
	server := newMockMasterServer(t)

	// Forward without -L, -R, or -D
	{
		var stdout, stderr bytes.Buffer
		streams := controlStreams{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr}
		opts := &SshOptions{
			control: SSHControlFlags{
				CtlCmd:      "forward",
				ControlPath: server.sockPath,
			},
		}
		err := executeControlCommandWithStreams(context.Background(), opts, streams)
		if err == nil {
			t.Fatal("expected error on empty forward, got nil")
		}
		code, ok := ExitCodeFromError(err)
		if !ok || code != 255 {
			t.Fatalf("expected exit code 255, got %d", code)
		}
		if !strings.Contains(stderr.String(), "no forwardings specified for -O forward") {
			t.Fatalf("unexpected stderr: %q", stderr.String())
		}
	}

	// Cancel without -L, -R, or -D
	{
		var stdout, stderr bytes.Buffer
		streams := controlStreams{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr}
		opts := &SshOptions{
			control: SSHControlFlags{
				CtlCmd:      "cancel",
				ControlPath: server.sockPath,
			},
		}
		err := executeControlCommandWithStreams(context.Background(), opts, streams)
		if err == nil {
			t.Fatal("expected error on empty cancel, got nil")
		}
		code, ok := ExitCodeFromError(err)
		if !ok || code != 255 {
			t.Fatalf("expected exit code 255, got %d", code)
		}
		if !strings.Contains(stderr.String(), "no forwardings specified for -O cancel") {
			t.Fatalf("unexpected stderr: %q", stderr.String())
		}
	}
}

// 8. Adversarial Test: Missing ControlPath on unconfigured host exits 255
func TestAdversarial_MissingControlPath_Exits255(t *testing.T) {
	var stdout, stderr bytes.Buffer
	streams := controlStreams{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr}
	opts := &SshOptions{
		Host: "unconfigured-host-9876",
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
		t.Fatalf("expected missing ControlPath error, got %q", stderr.String())
	}
}
