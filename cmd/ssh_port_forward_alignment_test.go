package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/internal/sshenv"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/models"
	cryptoSSH "golang.org/x/crypto/ssh"
)

type testSyncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *testSyncBuffer) Write(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *testSyncBuffer) WriteContext(ctx context.Context, data []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return s.Write(data)
}

func (s *testSyncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// 1. -g flag & GatewayPorts option precedence & effect on bind addresses
func TestPortForward_GatewayPortsPrecedence(t *testing.T) {
	t.Run("-g flag overrides -o GatewayPorts=no", func(t *testing.T) {
		opts := NewSshOptions()
		cmd := newCmdSshWithOptions(opts)
		if err := cmd.ParseFlags([]string{"-g", "-o", "GatewayPorts=no", "10.0.0.1"}); err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}
		if !opts.GatewayPorts {
			t.Fatal("expected opts.GatewayPorts == true")
		}
		sessionOpts, err := opts.toSessionControlOptions()
		if err != nil {
			t.Fatalf("toSessionControlOptions failed: %v", err)
		}
		if sessionOpts.Options == nil {
			t.Fatal("expected sessionOpts.Options != nil")
		}
		if sessionOpts.Options.Get(ssh.OptionGatewayPorts) != "yes" {
			t.Fatalf("expected GatewayPorts option 'yes', got: %q", sessionOpts.Options.Get(ssh.OptionGatewayPorts))
		}
		cfg, err := opts.resolveSessionForwardConfig()
		if err != nil {
			t.Fatalf("resolveSessionForwardConfig failed: %v", err)
		}
		if !cfg.gatewayPorts {
			t.Fatal("expected cfg.gatewayPorts == true")
		}
	})

	t.Run("GatewayPorts=yes affects local and dynamic listen addresses", func(t *testing.T) {
		opts := NewSshOptions()
		opts.GatewayPorts = true
		opts.LocalForwards = []string{"8080:127.0.0.1:80", "127.0.0.1:8081:127.0.0.1:81"}
		opts.DynamicForwards = []string{"1080", "127.0.0.1:1081"}

		cfg, err := opts.resolveSessionForwardConfig()
		if err != nil {
			t.Fatalf("resolveSessionForwardConfig failed: %v", err)
		}

		// local forward with omitted bind host -> binds on all interfaces (":8080")
		net0, addr0 := cfg.localForwards[0].Bind.LocalListenAddress(cfg.gatewayPorts)
		if net0 != "tcp" || addr0 != ":8080" {
			t.Fatalf("local forward 0 listen addr = %s, %s; want tcp, :8080", net0, addr0)
		}
		// local forward with explicit 127.0.0.1 -> stays 127.0.0.1:8081
		net1, addr1 := cfg.localForwards[1].Bind.LocalListenAddress(cfg.gatewayPorts)
		if net1 != "tcp" || addr1 != "127.0.0.1:8081" {
			t.Fatalf("local forward 1 listen addr = %s, %s; want tcp, 127.0.0.1:8081", net1, addr1)
		}

		// dynamic forward with omitted bind host -> binds on all interfaces (":1080")
		dNet0, dAddr0 := cfg.dynamicForwards[0].LocalListenAddress(cfg.gatewayPorts)
		if dNet0 != "tcp" || dAddr0 != ":1080" {
			t.Fatalf("dynamic forward 0 listen addr = %s, %s; want tcp, :1080", dNet0, dAddr0)
		}
		// dynamic forward with explicit 127.0.0.1 -> stays 127.0.0.1:1081
		dNet1, dAddr1 := cfg.dynamicForwards[1].LocalListenAddress(cfg.gatewayPorts)
		if dNet1 != "tcp" || dAddr1 != "127.0.0.1:1081" {
			t.Fatalf("dynamic forward 1 listen addr = %s, %s; want tcp, 127.0.0.1:1081", dNet1, dAddr1)
		}
	})
}

// 2. -L and -R StringArrayVarP preserves commas in socket paths
func TestPortForward_StringArrayFlagPreservesCommas(t *testing.T) {
	opts := NewSshOptions()
	cmd := newCmdSshWithOptions(opts)
	args := []string{
		"-L", "/tmp/a,b.sock:/tmp/c,d.sock",
		"-R", "/tmp/e,f.sock:/tmp/g,h.sock",
		"10.0.0.1",
	}
	if err := cmd.ParseFlags(args); err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}

	if len(opts.LocalForwards) != 1 {
		t.Fatalf("expected 1 LocalForward, got %d: %v", len(opts.LocalForwards), opts.LocalForwards)
	}
	if opts.LocalForwards[0] != "/tmp/a,b.sock:/tmp/c,d.sock" {
		t.Fatalf("LocalForward[0] = %q, want %q", opts.LocalForwards[0], "/tmp/a,b.sock:/tmp/c,d.sock")
	}

	if len(opts.RemoteForwards) != 1 {
		t.Fatalf("expected 1 RemoteForward, got %d: %v", len(opts.RemoteForwards), opts.RemoteForwards)
	}
	if opts.RemoteForwards[0] != "/tmp/e,f.sock:/tmp/g,h.sock" {
		t.Fatalf("RemoteForward[0] = %q, want %q", opts.RemoteForwards[0], "/tmp/e,f.sock:/tmp/g,h.sock")
	}
}

// 3. muxDaemonArgs preserves GatewayPorts, StreamLocalBindUnlink, StreamLocalBindMask
func TestPortForward_MuxDaemonArgsPreservation(t *testing.T) {
	opts := NewSshOptions()
	opts.GatewayPorts = true
	opts.control.Options = []string{
		"GatewayPorts=yes",
		"StreamLocalBindUnlink=yes",
		"StreamLocalBindMask=0177",
		"LocalForward=8080:127.0.0.1:80",
		"RemoteForward=9090:127.0.0.1:90",
		"DynamicForward=1080",
		"Tunnel=point-to-point",
		"TunnelDevice=0:1",
		"RequestTTY=yes",
		"ForkAfterAuthentication=yes",
		"StdinNull=yes",
		"SessionType=none",
	}
	opts.targetNodeIDs = []string{"node1"}

	args := opts.muxDaemonArgs("node1", "/tmp/sock", nil)
	joined := strings.Join(args, " ")

	// Preserved
	for _, preserved := range []string{"GatewayPorts=yes", "StreamLocalBindUnlink=yes", "StreamLocalBindMask=0177"} {
		if !strings.Contains(joined, preserved) {
			t.Fatalf("expected muxDaemonArgs to contain %q, got: %s", preserved, joined)
		}
	}
	if !strings.Contains(joined, "ClearAllForwardings=yes") {
		t.Fatalf("expected muxDaemonArgs to contain ClearAllForwardings=yes, got: %s", joined)
	}

	// Stripped
	for _, stripped := range []string{
		"LocalForward",
		"RemoteForward",
		"DynamicForward",
		"Tunnel=",
		"TunnelDevice",
		"RequestTTY",
		"ForkAfterAuthentication",
		"StdinNull",
		"SessionType",
	} {
		if strings.Contains(joined, stripped) {
			t.Fatalf("muxDaemonArgs must NOT contain stripped option %q, got: %s", stripped, joined)
		}
	}

	// normalizeForMuxDaemon resets BgRun
	opts.BgRun = true
	opts.normalizeForMuxDaemon()
	if opts.BgRun {
		t.Fatal("expected normalizeForMuxDaemon to reset opts.BgRun = false")
	}
}

// 4. -f / ForkAfterAuthentication validation & behavior
func TestPortForward_ForkAfterAuthentication_Validation(t *testing.T) {
	t.Run("-f without -N and without command fails Validate", func(t *testing.T) {
		opts := NewSshOptions()
		opts.BgRun = true
		opts.args = []string{"10.0.0.1"}
		if err := opts.Validate(); err == nil {
			t.Fatal("expected error for -f without command or -N, got nil")
		} else if !strings.Contains(err.Error(), i18n.T("ssh_err_background_requires_nocmd")) {
			t.Fatalf("unexpected error message: %v", err)
		}
	})

	t.Run("-f with explicit command passes Validate", func(t *testing.T) {
		opts := NewSshOptions()
		opts.BgRun = true
		opts.args = []string{"10.0.0.1", "sleep", "10"}
		if err := opts.Validate(); err != nil {
			t.Fatalf("unexpected error for -f with command: %v", err)
		}
	})

	t.Run("-f with -N passes Validate", func(t *testing.T) {
		opts := NewSshOptions()
		opts.BgRun = true
		opts.NoCmd = true
		opts.args = []string{"10.0.0.1"}
		if err := opts.Validate(); err != nil {
			t.Fatalf("unexpected error for -f -N: %v", err)
		}
	})

	t.Run("ForkAfterAuthentication=yes and SessionType=none pass Validate", func(t *testing.T) {
		opts := NewSshOptions()
		opts.control.Options = []string{"ForkAfterAuthentication=yes", "SessionType=none"}
		opts.args = []string{"10.0.0.1"}
		if err := opts.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !opts.effectiveBgRun() {
			t.Fatal("expected effectiveBgRun() == true")
		}
		if !opts.effectiveNoCmd() {
			t.Fatal("expected effectiveNoCmd() == true")
		}
		if !opts.effectiveStdinNull() {
			t.Fatal("expected effectiveStdinNull() == true")
		}
	})

	t.Run("-f implies StdinNull and piped stdin does not turn into stdinScript", func(t *testing.T) {
		opts := NewSshOptions()
		cmd := newCmdSshWithOptions(opts)
		if err := cmd.ParseFlags([]string{"-f", "10.0.0.1"}); err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}
		if !opts.effectiveStdinNull() {
			t.Fatal("expected effectiveStdinNull() == true when BgRun == true")
		}
		// When effectiveStdinNull() == true, Complete should not set stdinScript
		if err := opts.Complete(cmd, cmd.Flags().Args()); err != nil {
			t.Fatalf("Complete failed: %v", err)
		}
		if opts.stdinScript {
			t.Fatal("expected stdinScript == false when effectiveStdinNull() is true")
		}
		// Validate should then fail because there is no command and no -N
		if err := opts.Validate(); err == nil {
			t.Fatal("expected Validate() to fail for -f with piped stdin and no command, got nil")
		}
	})

	t.Run("-f cannot be combined with one-time OTP", func(t *testing.T) {
		opts := NewSshOptions()
		opts.BgRun = true
		opts.NoCmd = true
		opts.OTP = "123456"
		opts.args = []string{"10.0.0.1"}
		if err := opts.Validate(); err == nil {
			t.Fatal("expected error combining -f with OTP, got nil")
		} else if !strings.Contains(err.Error(), "background mode (-f) cannot be combined with one-time --otp") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})
}

// 5. -N / SessionType=none vs remote command conflict
func TestPortForward_NoCmdVsCommandConflict(t *testing.T) {
	t.Run("-N with command is rejected", func(t *testing.T) {
		opts := NewSshOptions()
		opts.NoCmd = true
		opts.args = []string{"10.0.0.1", "whoami"}
		if err := opts.Validate(); err == nil {
			t.Fatal("expected error for -N with command, got nil")
		} else if !strings.Contains(err.Error(), i18n.T("ssh_err_nocmd_with_command")) {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("-o SessionType=none with command is rejected", func(t *testing.T) {
		opts := NewSshOptions()
		opts.control.Options = []string{"SessionType=none"}
		opts.args = []string{"10.0.0.1", "whoami"}
		if err := opts.Validate(); err == nil {
			t.Fatal("expected error for SessionType=none with command, got nil")
		} else if !strings.Contains(err.Error(), i18n.T("ssh_err_nocmd_with_command")) {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("Tier 2 node config SessionType=none with command is rejected", func(t *testing.T) {
		opts := NewSshOptions()
		opts.args = []string{"target-node", "whoami"}
		if err := opts.ensureArgsParsed(); err != nil {
			t.Fatalf("ensureArgsParsed failed: %v", err)
		}

		cfgModel := &config.Configuration{
			Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
			Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
			Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		}
		cfgModel.Hosts.Set("host1", models.Host{Address: "127.0.0.1", Port: 22})
		cfgModel.Identities.Set("id1", models.Identity{User: "alice", AuthType: "auto"})
		cfgModel.Nodes.Set("target-node", models.Node{
			HostRef:     "host1",
			IdentityRef: "id1",
			SSHOptions:  ssh.MustOptions(ssh.OptionSessionType, "none"),
		})
		provider, err := config.NewProvider(cfgModel)
		if err != nil {
			t.Fatalf("config.NewProvider failed: %v", err)
		}

		if _, err := opts.resolveAndCacheSessionOptions(provider, "target-node"); err != nil {
			t.Fatalf("resolveAndCacheSessionOptions failed: %v", err)
		}
		if err := opts.validatePostResolutionSessionInvariants(); err == nil {
			t.Fatal("expected validatePostResolutionSessionInvariants to reject SessionType=none with command, got nil")
		} else if !strings.Contains(err.Error(), i18n.T("ssh_err_nocmd_with_command")) {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("-W with command is rejected with dedicated message", func(t *testing.T) {
		opts := NewSshOptions()
		opts.StdioForward = "127.0.0.1:80"
		opts.args = []string{"10.0.0.1", "whoami"}
		if err := opts.Validate(); err == nil {
			t.Fatal("expected error for -W with command, got nil")
		} else if !strings.Contains(err.Error(), i18n.T("ssh_err_stdio_forward_with_cmd")) {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

// 6. StreamLocal path token expansion (%h, %p, %r, %C, ~ on local vs NOT expanding ~ on remote)
func TestPortForward_StreamLocalTokenExpansion(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	env := sshenv.Discover()
	target := ssh.TargetContext{
		Host:         "myhost.example.com",
		Port:         2222,
		User:         "myuser",
		OriginalHost: "myalias",
	}

	opts := NewSshOptions()
	opts.resolvedTarget = &target
	opts.LocalForwards = []string{"~/local_%h_%p.sock:~/remote_%r_%C.sock"}
	opts.RemoteForwards = []string{"~/remote_%h_%p.sock:~/local_%r_%C.sock"}
	opts.DynamicForwards = []string{"~/dynamic_%u_%p.sock"}

	cfg, err := opts.resolveSessionForwardConfig()
	if err != nil {
		t.Fatalf("resolveSessionForwardConfig failed: %v", err)
	}

	// LocalForward:
	// Bind is local socket -> expands ~ to home, %h to host, %p to port
	wantLocalBind := filepath.Join(home, "local_myhost.example.com_2222.sock")
	if cfg.localForwards[0].Bind.SocketPath != wantLocalBind {
		t.Fatalf("LocalForward Bind = %q, want %q", cfg.localForwards[0].Bind.SocketPath, wantLocalBind)
	}
	// Dest is remote socket -> does NOT expand ~ (keeps ~/), expands %r to user, %C to hash
	if !strings.HasPrefix(cfg.localForwards[0].Dest.SocketPath, "~/") {
		t.Fatalf("LocalForward Dest must NOT expand remote ~, got: %q", cfg.localForwards[0].Dest.SocketPath)
	}
	if !strings.Contains(cfg.localForwards[0].Dest.SocketPath, "myuser") {
		t.Fatalf("LocalForward Dest must expand %%r to myuser, got: %q", cfg.localForwards[0].Dest.SocketPath)
	}

	// RemoteForward:
	// Bind is remote socket -> does NOT expand ~ (keeps ~/)
	if !strings.HasPrefix(cfg.remoteForwards[0].Bind.SocketPath, "~/") {
		t.Fatalf("RemoteForward Bind must NOT expand remote ~, got: %q", cfg.remoteForwards[0].Bind.SocketPath)
	}
	if !strings.Contains(cfg.remoteForwards[0].Bind.SocketPath, "myhost.example.com") {
		t.Fatalf("RemoteForward Bind must expand %%h, got: %q", cfg.remoteForwards[0].Bind.SocketPath)
	}
	// Dest is local socket -> expands ~ to home
	wantRemoteDest := filepath.Join(home, "local_myuser_")
	if !strings.HasPrefix(cfg.remoteForwards[0].Dest.SocketPath, wantRemoteDest) {
		t.Fatalf("RemoteForward Dest must expand local ~, got: %q, want prefix: %q", cfg.remoteForwards[0].Dest.SocketPath, wantRemoteDest)
	}

	// DynamicForward:
	// Local socket -> expands ~ to home
	wantDynamic := filepath.Join(home, fmt.Sprintf("dynamic_%s_2222.sock", env.LocalUser))
	if cfg.dynamicForwards[0].SocketPath != wantDynamic {
		t.Fatalf("DynamicForward = %q, want %q", cfg.dynamicForwards[0].SocketPath, wantDynamic)
	}

	// Also verify parseForwardRequestsFromOptionsWithTarget expands tokens identically
	reqs, err := parseForwardRequestsFromOptionsWithTarget(opts, target)
	if err != nil {
		t.Fatalf("parseForwardRequestsFromOptionsWithTarget failed: %v", err)
	}
	if len(reqs) != 3 {
		t.Fatalf("expected 3 reqs, got %d", len(reqs))
	}
	// Local req:
	if reqs[0].ListenHost != wantLocalBind {
		t.Fatalf("reqs[0].ListenHost = %q, want %q", reqs[0].ListenHost, wantLocalBind)
	}
	if !strings.HasPrefix(reqs[0].ConnectHost, "~/") {
		t.Fatalf("reqs[0].ConnectHost must keep remote ~, got: %q", reqs[0].ConnectHost)
	}
	// Remote req:
	if !strings.HasPrefix(reqs[1].ListenHost, "~/") {
		t.Fatalf("reqs[1].ListenHost must keep remote ~, got: %q", reqs[1].ListenHost)
	}
	if !strings.HasPrefix(reqs[1].ConnectHost, wantRemoteDest) {
		t.Fatalf("reqs[1].ConnectHost must expand local ~, got: %q", reqs[1].ConnectHost)
	}
	// Dynamic req:
	if reqs[2].ListenHost != wantDynamic {
		t.Fatalf("reqs[2].ListenHost = %q, want %q", reqs[2].ListenHost, wantDynamic)
	}
}

// 7. Foreground remote forward :0 dynamic port reporting
func TestPortForward_ForegroundAllocatedPortReporting(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	server, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New failed: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	host, portText, err := net.SplitHostPort(server.Address)
	if err != nil {
		t.Fatalf("SplitHostPort failed: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("Atoi failed: %v", err)
	}

	connector := ssh.NewConnector(tunnelTestProvider{cfg: &ssh.ClientConfig{
		NodeID: "fixture", Address: host, Port: port, User: "fixture", AuthType: "password", Password: sshfixture.Password,
	}}, ssh.WithHostKeyVerifier(execFixtureVerifier{server.HostKey}))
	t.Cleanup(func() { _ = connector.CloseAll() })

	t.Run("Allocated port is reported on stderr when not quiet", func(t *testing.T) {
		client, err := connector.Connect(ctx, "fixture")
		if err != nil {
			t.Fatalf("Connect failed: %v", err)
		}
		defer func() { _ = client.Close() }()

		var stderr testSyncBuffer
		opts := NewSshOptions()
		opts.NoCmd = true
		opts.RemoteForwards = []string{"0:127.0.0.1:8080"}

		tunnels, err := opts.startTunnelsWithStderr(ctx, nil, client, &stderr)
		if err != nil {
			t.Fatalf("startTunnelsWithStderr failed: %v", err)
		}
		_ = tunnels.Close()

		gotStderr := stderr.String()
		if !strings.Contains(gotStderr, "Allocated port ") || !strings.Contains(gotStderr, "for remote forward to 127.0.0.1:8080") {
			t.Fatalf("expected allocated port message on stderr, got: %q", gotStderr)
		}
	})

	t.Run("Allocated port is suppressed on stderr when quiet", func(t *testing.T) {
		client, err := connector.Connect(ctx, "fixture")
		if err != nil {
			t.Fatalf("Connect failed: %v", err)
		}
		defer func() { _ = client.Close() }()

		var stderr testSyncBuffer
		opts := NewSshOptions()
		opts.NoCmd = true
		opts.diagnostic.quiet = true
		opts.RemoteForwards = []string{"0:127.0.0.1:8080"}

		tunnels, err := opts.startTunnelsWithStderr(ctx, nil, client, &stderr)
		if err != nil {
			t.Fatalf("startTunnelsWithStderr failed: %v", err)
		}
		_ = tunnels.Close()

		gotStderr := stderr.String()
		if strings.Contains(gotStderr, "Allocated port ") {
			t.Fatalf("expected allocated port message to be suppressed with -q, got: %q", gotStderr)
		}
	})
}

// 8. -O forward & -O cancel alignment against a live ssh.MuxServer
func TestPortForward_MuxControlForwardAndCancel_Alignment(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	sockPath, targetAddr := setupControlProxySessionFixture(ctx, t)

	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend net.Listen failed: %v", err)
	}
	defer func() { _ = backendLn.Close() }()
	_, backendPortStr, _ := net.SplitHostPort(backendLn.Addr().String())

	// A: -O forward with -R 0:127.0.0.1:<backendPort> prints allocated port to stdout and sent to stderr
	{
		var stdout, stderr bytes.Buffer
		streams := controlStreams{
			Stdin:  strings.NewReader(""),
			Stdout: &stdout,
			Stderr: &stderr,
		}
		opts := NewSshOptions()
		opts.RemoteForwards = []string{"0:127.0.0.1:" + backendPortStr}
		opts.control = SSHControlFlags{
			CtlCmd:      "forward",
			ControlPath: sockPath,
		}
		opts.args = []string{targetAddr}

		if err := executeControlCommandWithStreams(ctx, opts, streams); err != nil {
			t.Fatalf("executeControlCommand (forward) failed: %v (stderr: %q)", err, stderr.String())
		}

		outStr := strings.TrimSpace(stdout.String())
		allocPort, parseErr := strconv.Atoi(outStr)
		if parseErr != nil || allocPort <= 0 {
			t.Fatalf("expected allocated port number on stdout, got: %q (parseErr: %v)", outStr, parseErr)
		}
		if !strings.Contains(stderr.String(), "Forwarding request sent.") {
			t.Fatalf("expected 'Forwarding request sent.' on stderr, got: %q", stderr.String())
		}

		// Cancel it
		var cancelStdout, cancelStderr bytes.Buffer
		cancelStreams := controlStreams{
			Stdin:  strings.NewReader(""),
			Stdout: &cancelStdout,
			Stderr: &cancelStderr,
		}
		cancelOpts := NewSshOptions()
		cancelOpts.RemoteForwards = []string{fmt.Sprintf("%d:127.0.0.1:%s", allocPort, backendPortStr)}
		cancelOpts.control = SSHControlFlags{
			CtlCmd:      "cancel",
			ControlPath: sockPath,
		}
		cancelOpts.args = []string{targetAddr}

		if err := executeControlCommandWithStreams(ctx, cancelOpts, cancelStreams); err != nil {
			t.Fatalf("executeControlCommand (cancel) failed: %v (stderr: %q)", err, cancelStderr.String())
		}
		if !strings.Contains(cancelStderr.String(), "Forwarding cancel request sent.") {
			t.Fatalf("expected 'Forwarding cancel request sent.' on stderr, got: %q", cancelStderr.String())
		}
	}

	// B: -O forward and -O cancel with StreamLocal Unix domain socket
	{
		tmpDir := t.TempDir()
		localSock := filepath.Join(tmpDir, "local.sock")

		var stdout, stderr bytes.Buffer
		streams := controlStreams{
			Stdin:  strings.NewReader(""),
			Stdout: &stdout,
			Stderr: &stderr,
		}
		opts := NewSshOptions()
		opts.LocalForwards = []string{fmt.Sprintf("%s:127.0.0.1:%s", localSock, backendPortStr)}
		opts.control = SSHControlFlags{
			CtlCmd:      "forward",
			ControlPath: sockPath,
		}
		opts.args = []string{targetAddr}

		if err := executeControlCommandWithStreams(ctx, opts, streams); err != nil {
			t.Fatalf("executeControlCommand (forward unix socket) failed: %v (stderr: %q)", err, stderr.String())
		}
		if !strings.Contains(stderr.String(), "Forwarding request sent.") {
			t.Fatalf("expected 'Forwarding request sent.' on stderr, got: %q", stderr.String())
		}

		// Verify socket file was created and is listening
		if _, statErr := os.Stat(localSock); statErr != nil {
			t.Fatalf("expected unix domain socket file %q to exist: %v", localSock, statErr)
		}

		// Cancel unix domain socket forwarding
		var cancelStdout, cancelStderr bytes.Buffer
		cancelStreams := controlStreams{
			Stdin:  strings.NewReader(""),
			Stdout: &cancelStdout,
			Stderr: &cancelStderr,
		}
		cancelOpts := NewSshOptions()
		cancelOpts.LocalForwards = []string{fmt.Sprintf("%s:127.0.0.1:%s", localSock, backendPortStr)}
		cancelOpts.control = SSHControlFlags{
			CtlCmd:      "cancel",
			ControlPath: sockPath,
		}
		cancelOpts.args = []string{targetAddr}

		if err := executeControlCommandWithStreams(ctx, cancelOpts, cancelStreams); err != nil {
			t.Fatalf("executeControlCommand (cancel unix socket) failed: %v (stderr: %q)", err, cancelStderr.String())
		}
		if !strings.Contains(cancelStderr.String(), "Forwarding cancel request sent.") {
			t.Fatalf("expected 'Forwarding cancel request sent.' on stderr, got: %q", cancelStderr.String())
		}
	}

	// C: -O forward with reverse dynamic forwarding (-R 0)
	{
		var stdout, stderr bytes.Buffer
		streams := controlStreams{
			Stdin:  strings.NewReader(""),
			Stdout: &stdout,
			Stderr: &stderr,
		}
		opts := NewSshOptions()
		opts.RemoteForwards = []string{"0"}
		opts.control = SSHControlFlags{
			CtlCmd:      "forward",
			ControlPath: sockPath,
		}
		opts.args = []string{targetAddr}

		if err := executeControlCommandWithStreams(ctx, opts, streams); err != nil {
			t.Fatalf("executeControlCommand (reverse dynamic forward) failed: %v (stderr: %q)", err, stderr.String())
		}
		outStr := strings.TrimSpace(stdout.String())
		allocPort, parseErr := strconv.Atoi(outStr)
		if parseErr != nil || allocPort <= 0 {
			t.Fatalf("expected allocated port number for reverse dynamic forward on stdout, got: %q (parseErr: %v)", outStr, parseErr)
		}
		if !strings.Contains(stderr.String(), "Forwarding request sent.") {
			t.Fatalf("expected 'Forwarding request sent.' on stderr, got: %q", stderr.String())
		}

		// Cancel reverse dynamic forward
		var cancelStdout, cancelStderr bytes.Buffer
		cancelStreams := controlStreams{
			Stdin:  strings.NewReader(""),
			Stdout: &cancelStdout,
			Stderr: &cancelStderr,
		}
		cancelOpts := NewSshOptions()
		cancelOpts.RemoteForwards = []string{strconv.Itoa(allocPort)}
		cancelOpts.control = SSHControlFlags{
			CtlCmd:      "cancel",
			ControlPath: sockPath,
		}
		cancelOpts.args = []string{targetAddr}

		if err := executeControlCommandWithStreams(ctx, cancelOpts, cancelStreams); err != nil {
			t.Fatalf("executeControlCommand (cancel reverse dynamic) failed: %v (stderr: %q)", err, cancelStderr.String())
		}
		if !strings.Contains(cancelStderr.String(), "Forwarding cancel request sent.") {
			t.Fatalf("expected 'Forwarding cancel request sent.' on stderr, got: %q", cancelStderr.String())
		}
	}
}

func setupMuxServerWithGatewayPorts(ctx context.Context, t *testing.T, gatewayPorts bool) (string, string, int) {
	t.Helper()
	fixture, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
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

	tmpDir, err := os.MkdirTemp("", "ctrl-gw-session-*")
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
		GatewayPorts:      gatewayPorts,
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	go func() { _ = muxServer.Serve() }()
	t.Cleanup(func() { _ = muxServer.Shutdown() })

	return sockPath, host, port
}

// 9. Regression: -O forward & -O cancel against managed node with persistent LocalForward & GatewayPorts=no
// verifies that -O forward ONLY opens the CLI-specified forward without trying to bind the node's persistent
// LocalForward (e.g. 15432:127.0.0.1:5432), does NOT override Master's GatewayPorts: true with the node's
// GatewayPorts=no, and -O cancel ONLY cancels the CLI-specified forward.
func TestPortForward_ControlForwardAndCancel_ManagedNodeIsolation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cfgDir := t.TempDir()
	t.Setenv("XOPS_CONFIG_DIR", cfgDir)

	sockPath, host, port := setupMuxServerWithGatewayPorts(ctx, t, true)

	unusedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("unused port listen failed: %v", err)
	}
	unusedNodePort := unusedLn.Addr().(*net.TCPAddr).Port
	_ = unusedLn.Close()

	// Managed node with persistent LocalForward and GatewayPorts=no
	cfgContent := fmt.Sprintf(`schema_version: 2
hosts:
  h-target:
    address: %s
    port: %d
identities:
  id-target:
    user: fixture
    auth_type: auto
nodes:
  target-node:
    host_ref: h-target
    identity_ref: id-target
    ssh_options:
      LocalForward: "%d:127.0.0.1:5432"
      GatewayPorts: "no"
`, host, port, unusedNodePort)

	if err := os.WriteFile(filepath.Join(cfgDir, "xops_config.yaml"), []byte(cfgContent), 0o600); err != nil {
		t.Fatalf("write xops_config.yaml failed: %v", err)
	}

	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend net.Listen failed: %v", err)
	}
	defer func() { _ = backendLn.Close() }()
	_, backendPortStr, _ := net.SplitHostPort(backendLn.Addr().String())
	backendPort, _ := strconv.Atoi(backendPortStr)

	fwdLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port listen failed: %v", err)
	}
	fwdPort := fwdLn.Addr().(*net.TCPAddr).Port
	_ = fwdLn.Close()

	// 1. Execute -O forward -L <fwdPort>:127.0.0.1:<backendPort> against target-node
	var stdout, stderr bytes.Buffer
	streams := controlStreams{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	}
	opts := NewSshOptions()
	opts.LocalForwards = []string{fmt.Sprintf("%d:127.0.0.1:%d", fwdPort, backendPort)}
	opts.control = SSHControlFlags{
		CtlCmd:      "forward",
		ControlPath: sockPath,
	}
	opts.args = []string{"target-node"}

	if err := executeControlCommandWithStreams(ctx, opts, streams); err != nil {
		t.Fatalf("executeControlCommand (forward) failed: %v (stderr: %q)", err, stderr.String())
	}
	if !strings.Contains(stderr.String(), "Forwarding request sent.") {
		t.Fatalf("expected 'Forwarding request sent.' on stderr, got: %q", stderr.String())
	}

	// 2. Query active forwardings via -O channels
	var chanStdout, chanStderr bytes.Buffer
	chanStreams := controlStreams{
		Stdin:  strings.NewReader(""),
		Stdout: &chanStdout,
		Stderr: &chanStderr,
	}
	chanOpts := NewSshOptions()
	chanOpts.control = SSHControlFlags{
		CtlCmd:      "channels",
		ControlPath: sockPath,
	}
	chanOpts.args = []string{"target-node"}
	if err := executeControlCommandWithStreams(ctx, chanOpts, chanStreams); err != nil {
		t.Fatalf("executeControlCommand (channels) failed: %v (stderr: %q)", err, chanStderr.String())
	}

	chanOut := chanStdout.String()
	// Master was started with GatewayPorts: true. Since no -g or -o GatewayPorts override was passed
	// on the CLI, gwOverride is nil and Master uses its own GatewayPorts: true -> keyHost is '*'
	wantFwdKey := fmt.Sprintf("1:*:%d:127.0.0.1:%d", fwdPort, backendPort)
	if !strings.Contains(chanOut, wantFwdKey) {
		t.Fatalf("expected active forward %q in channels output, got:\n%s", wantFwdKey, chanOut)
	}
	// Must NOT contain persistent LocalForward from managed node config
	if strings.Contains(chanOut, fmt.Sprintf(":%d:127.0.0.1:5432", unusedNodePort)) {
		t.Fatalf("node config persistent LocalForward %d was wrongly forwarded, got:\n%s", unusedNodePort, chanOut)
	}

	// Verify connecting to the forwarded port succeeds
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", fwdPort), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial forwarded port %d: %v", fwdPort, err)
	}
	_ = conn.Close()

	// Node config's persistent port must NOT be listening
	if c, dialErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", unusedNodePort), 100*time.Millisecond); dialErr == nil {
		_ = c.Close()
		t.Fatalf("port %d from node config should not be listening", unusedNodePort)
	}

	// 3. Execute -O cancel -L <fwdPort>:127.0.0.1:<backendPort> against target-node
	var cancelStdout, cancelStderr bytes.Buffer
	cancelStreams := controlStreams{
		Stdin:  strings.NewReader(""),
		Stdout: &cancelStdout,
		Stderr: &cancelStderr,
	}
	cancelOpts := NewSshOptions()
	cancelOpts.LocalForwards = []string{fmt.Sprintf("%d:127.0.0.1:%d", fwdPort, backendPort)}
	cancelOpts.control = SSHControlFlags{
		CtlCmd:      "cancel",
		ControlPath: sockPath,
	}
	cancelOpts.args = []string{"target-node"}

	if err := executeControlCommandWithStreams(ctx, cancelOpts, cancelStreams); err != nil {
		t.Fatalf("executeControlCommand (cancel) failed: %v (stderr: %q)", err, cancelStderr.String())
	}
	if !strings.Contains(cancelStderr.String(), "Forwarding cancel request sent.") {
		t.Fatalf("expected 'Forwarding cancel request sent.' on stderr, got: %q", cancelStderr.String())
	}

	// 4. Verify channels after cancel
	chanStdout.Reset()
	chanStderr.Reset()
	if err := executeControlCommandWithStreams(ctx, chanOpts, chanStreams); err != nil {
		t.Fatalf("executeControlCommand (channels after cancel) failed: %v", err)
	}
	if strings.Contains(chanStdout.String(), wantFwdKey) {
		t.Fatalf("expected forward %q to be cancelled, still found in:\n%s", wantFwdKey, chanStdout.String())
	}
}

// 10. Regression: toSessionControlOptions projects -f, -N, -n, and -g into Tier 1 Options
// overriding conflicting -o options.
func TestPortForward_ToSessionControlOptions_ProjectsFlagsOverConflictingOptions(t *testing.T) {
	opts := NewSshOptions()
	opts.control.Options = []string{
		"ForkAfterAuthentication=no",
		"SessionType=default",
		"StdinNull=no",
		"GatewayPorts=no",
	}
	opts.BgRun = true
	opts.NoCmd = true
	opts.StdinRedirect = true
	opts.GatewayPorts = true

	sessionOpts, err := opts.toSessionControlOptions()
	if err != nil {
		t.Fatalf("toSessionControlOptions failed: %v", err)
	}
	eff, err := ssh.EffectiveOptions(sessionOpts.ToSSHOptions())
	if err != nil {
		t.Fatalf("EffectiveOptions failed: %v", err)
	}
	if fork, ok := eff.ForkAfterAuthentication(); !ok || !fork {
		t.Errorf("expected ForkAfterAuthentication == true, got %v (ok=%v)", fork, ok)
	}
	if eff.SessionType() != ssh.SessionTypeNone {
		t.Errorf("expected SessionType == %q, got %q", ssh.SessionTypeNone, eff.SessionType())
	}
	if sn, ok := eff.StdinNull(); !ok || !sn {
		t.Errorf("expected StdinNull == true, got %v (ok=%v)", sn, ok)
	}
	if gw, ok := eff.GatewayPorts(); !ok || !gw {
		t.Errorf("expected GatewayPorts == true, got %v (ok=%v)", gw, ok)
	}

	// Verify that when flags are false, -o values are respected
	optsDefault := NewSshOptions()
	optsDefault.control.Options = []string{
		"ForkAfterAuthentication=no",
		"SessionType=default",
		"StdinNull=no",
		"GatewayPorts=no",
	}
	sessionOptsDefault, err := optsDefault.toSessionControlOptions()
	if err != nil {
		t.Fatalf("toSessionControlOptions failed: %v", err)
	}
	effDefault, err := ssh.EffectiveOptions(sessionOptsDefault.ToSSHOptions())
	if err != nil {
		t.Fatalf("EffectiveOptions failed: %v", err)
	}
	if fork, ok := effDefault.ForkAfterAuthentication(); !ok || fork {
		t.Errorf("expected ForkAfterAuthentication == false, got %v (ok=%v)", fork, ok)
	}
	if effDefault.SessionType() != ssh.SessionTypeDefault {
		t.Errorf("expected SessionType == %q, got %q", ssh.SessionTypeDefault, effDefault.SessionType())
	}
	if sn, ok := effDefault.StdinNull(); !ok || sn {
		t.Errorf("expected StdinNull == false, got %v (ok=%v)", sn, ok)
	}
	if gw, ok := effDefault.GatewayPorts(); !ok || gw {
		t.Errorf("expected GatewayPorts == false, got %v (ok=%v)", gw, ok)
	}
}

// 11. Regression: -O proxy enforces post-resolution invariants when ForkAfterAuthentication=yes
// comes from managed node configuration (rejecting -W + ForkAfterAuthentication and bare shell + ForkAfterAuthentication).
func TestPortForward_ControlProxy_PostResolutionForkAfterAuthInvariants(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cfgDir := t.TempDir()
	t.Setenv("XOPS_CONFIG_DIR", cfgDir)

	sockPath, host, port := setupMuxServerWithGatewayPorts(ctx, t, false)

	cfgContent := fmt.Sprintf(`schema_version: 2
hosts:
  h-target:
    address: %s
    port: %d
identities:
  id-target:
    user: fixture
    auth_type: auto
nodes:
  bg-node:
    host_ref: h-target
    identity_ref: id-target
    ssh_options:
      ForkAfterAuthentication: "yes"
`, host, port)

	if err := os.WriteFile(filepath.Join(cfgDir, "xops_config.yaml"), []byte(cfgContent), 0o600); err != nil {
		t.Fatalf("write xops_config.yaml failed: %v", err)
	}

	t.Run("RejectsStdioForwardWithNodeForkAfterAuth", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		opts := NewSshOptions()
		opts.StdioForward = "127.0.0.1:80"
		opts.control = SSHControlFlags{
			CtlCmd:      "proxy",
			ControlPath: sockPath,
		}
		opts.args = []string{"bg-node"}

		err := executeControlCommandWithStreams(ctx, opts, controlStreams{
			Stdin:  strings.NewReader(""),
			Stdout: &stdout,
			Stderr: &stderr,
		})
		var exitErr *ControlExitError
		if !errors.As(err, &exitErr) || exitErr.Code != 255 {
			t.Fatalf("expected ControlExitError(255), got %v", err)
		}
		if !strings.Contains(stderr.String(), i18n.T("ssh_err_stdio_forward_with_bg")) {
			t.Fatalf("expected %q in stderr, got %q", i18n.T("ssh_err_stdio_forward_with_bg"), stderr.String())
		}
	})

	t.Run("RejectsNoCommandWithoutNoCmdWhenNodeForkAfterAuth", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		opts := NewSshOptions()
		opts.control = SSHControlFlags{
			CtlCmd:      "proxy",
			ControlPath: sockPath,
		}
		opts.args = []string{"bg-node"}

		err := executeControlCommandWithStreams(ctx, opts, controlStreams{
			Stdin:  strings.NewReader(""),
			Stdout: &stdout,
			Stderr: &stderr,
		})
		var exitErr *ControlExitError
		if !errors.As(err, &exitErr) || exitErr.Code != 255 {
			t.Fatalf("expected ControlExitError(255), got %v", err)
		}
		if !strings.Contains(stderr.String(), i18n.T("ssh_err_background_requires_nocmd")) {
			t.Fatalf("expected %q in stderr, got %q", i18n.T("ssh_err_background_requires_nocmd"), stderr.String())
		}
	})
}

// 12. Regression: -f -O proxy -N -L detaches into a background child after validating
// the control socket and local forward, keeping the forwarded port active until the master stops.
func TestPortForward_ControlProxy_BackgroundFlagSpawnsDetachedSession(t *testing.T) {
	if helperSock := os.Getenv("XOPS_TEST_PROXY_BG_SOCK"); helperSock != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		opts := NewSshOptions()
		opts.BgRun = true
		opts.NoCmd = true
		opts.LocalForwards = []string{os.Getenv("XOPS_TEST_PROXY_BG_SPEC")}
		opts.control = SSHControlFlags{
			CtlCmd:      "proxy",
			ControlPath: helperSock,
		}
		opts.args = []string{os.Getenv("XOPS_TEST_PROXY_BG_TARGET")}
		var stdout, stderr bytes.Buffer
		if err := executeControlCommandWithStreams(ctx, opts, controlStreams{
			Stdin:  strings.NewReader(""),
			Stdout: &stdout,
			Stderr: &stderr,
		}); err != nil {
			// When the parent test shuts down the MuxServer, the detached child exits with SSH connection lost.
			if os.Getenv(sshBackgroundChildEnv) == "true" {
				os.Exit(0)
			}
			t.Fatalf("helper executeControlCommandWithStreams failed: %v (stderr: %q)", err, stderr.String())
		}
		os.Exit(0)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cfgDir := t.TempDir()
	sockPath, host, port := setupMuxServerWithGatewayPorts(ctx, t, false)

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen failed: %v", err)
	}
	defer func() { _ = echoLn.Close() }()
	go func() {
		for {
			c, acceptErr := echoLn.Accept()
			if acceptErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	echoPort := echoLn.Addr().(*net.TCPAddr).Port

	fwdLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fwd probe listen failed: %v", err)
	}
	fwdPort := fwdLn.Addr().(*net.TCPAddr).Port
	_ = fwdLn.Close()

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable failed: %v", err)
	}
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestPortForward_ControlProxy_BackgroundFlagSpawnsDetachedSession$")
	cmd.Env = append(os.Environ(),
		"XOPS_CONFIG_DIR="+cfgDir,
		"XOPS_TEST_PROXY_BG_SOCK="+sockPath,
		fmt.Sprintf("XOPS_TEST_PROXY_BG_SPEC=127.0.0.1:%d:127.0.0.1:%d", fwdPort, echoPort),
		fmt.Sprintf("XOPS_TEST_PROXY_BG_TARGET=fixture@%s:%d", host, port),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("foreground -f -O proxy helper failed: %v (output: %s)", err, string(out))
	}

	// Poll briefly for the detached background child to re-bind fwdPort and forward traffic.
	waitForForwardedPortEcho(t, fwdPort, "bg-proxy-ping", 5*time.Second)
}

func waitForForwardedPortEcho(t *testing.T, port int, msg string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	payload := []byte(msg)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := tryPortEchoRoundtrip(port, payload); err != nil {
			lastErr = err
			time.Sleep(30 * time.Millisecond)
			continue
		}
		return
	}
	t.Fatalf("detached -f -O proxy forward did not become ready on port %d: %v", port, lastErr)
}

func tryPortEchoRoundtrip(port int, payload []byte) error {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if string(reply) != string(payload) {
		return fmt.Errorf("echo mismatch: got %q, want %q", string(reply), string(payload))
	}
	return nil
}
