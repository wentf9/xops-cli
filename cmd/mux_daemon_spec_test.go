package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func roundTripMuxDaemonSpecThroughPipe(t *testing.T, spec MuxDaemonSpec) MuxDaemonSpec {
	t.Helper()
	payload, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("json.Marshal(spec): %v", err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	writeErrCh := make(chan error, 1)
	go func() {
		defer func() { _ = w.Close() }()
		_, writeErr := w.Write(payload)
		writeErrCh <- writeErr
	}()
	defer func() { _ = r.Close() }()

	got, err := readMuxDaemonSpec(r)
	if writeErr := <-writeErrCh; writeErr != nil {
		t.Fatalf("pipe write failed: %v", writeErr)
	}
	if err != nil {
		t.Fatalf("readMuxDaemonSpec(pipe): %v", err)
	}
	return got
}

func TestMuxDaemonSpec_PipeRoundTripPreservesTypesAndOrders(t *testing.T) {
	client, _ := newTunnelTestClient(t)
	sockPath := filepath.Join(t.TempDir(), "spec.sock")
	master, err := ssh.NewMuxServer(ssh.MuxServerOptions{
		ControlPath: sockPath,
		SSHClient:   client.SSHClient(),
		Target: ssh.TargetContext{
			Host:         "fe80::1%eth0",
			Port:         2222,
			User:         "ops",
			OriginalHost: "app-alias",
			Control: &ssh.ControlConfig{
				Master:  ssh.ControlMasterAsk,
				Path:    sockPath,
				Persist: "5m",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewMuxServer: %v", err)
	}
	t.Cleanup(func() { _ = master.Shutdown() })

	opts := NewSshOptions()
	opts.Host = "openssh:app-alias"
	opts.IdentityFiles = []string{"/tmp/k1", "none", "/tmp/k2"}
	opts.syncIdentityFiles()
	opts.GatewayPorts = true
	opts.control.ConfigFile = "/tmp/custom_cfg"
	opts.control.AddressFamily = "inet6"
	opts.CipherSpec = "aes256-gcm@openssh.com"
	opts.targetNodeIDs = []string{"openssh:app-alias"}
	opts.control.Options = []string{
		"ProxyCommand=none",
		"ProxyCommand=nc %h %p",
		"ServerAliveInterval=15",
		"LocalForward=8080 127.0.0.1:80",
		"ClearAllForwardings=no",
		"ControlMaster=yes",
		"ControlPath=/tmp/stale.sock",
	}

	built := opts.buildMuxDaemonSpec("openssh:app-alias", sockPath, master)
	decoded := roundTripMuxDaemonSpecThroughPipe(t, built)

	if !decoded.OpenSSHNamespace {
		t.Fatalf("expected OpenSSHNamespace=true, got false")
	}
	if decoded.DialHost != "fe80::1%eth0" {
		t.Fatalf("expected verbatim IPv6 zone DialHost fe80::1%%eth0, got %q", decoded.DialHost)
	}
	if decoded.OriginalHost != "app-alias" {
		t.Fatalf("expected OriginalHost app-alias, got %q", decoded.OriginalHost)
	}
	wantIDs := []string{"/tmp/k1", "none", "/tmp/k2"}
	if !slices.Equal(decoded.IdentityFiles, wantIDs) {
		t.Fatalf("IdentityFiles = %v, want %v", decoded.IdentityFiles, wantIDs)
	}
	if !slices.Contains(decoded.Options, "ProxyCommand=none") {
		t.Fatalf("expected ProxyCommand=none in decoded.Options, got %v", decoded.Options)
	}
	if slices.Contains(decoded.Options, "ControlMaster=yes") || slices.Contains(decoded.Options, "ControlPath=/tmp/stale.sock") {
		t.Fatalf("stale control options leaked into decoded.Options: %v", decoded.Options)
	}

	childOpts := NewSshOptions()
	if err := childOpts.applyMuxDaemonSpec(decoded); err != nil {
		t.Fatalf("applyMuxDaemonSpec: %v", err)
	}
	assertAppliedRoundTripMuxDaemonSpec(t, childOpts, wantIDs)
}

func assertAppliedRoundTripMuxDaemonSpec(t *testing.T, childOpts *SshOptions, wantIDs []string) {
	t.Helper()
	if !childOpts.isMuxDaemon() || !childOpts.NoCmd || !childOpts.StdinRedirect {
		t.Fatalf("expected mux daemon flags applied: isMuxDaemon=%v NoCmd=%v StdinRedirect=%v",
			childOpts.isMuxDaemon(), childOpts.NoCmd, childOpts.StdinRedirect)
	}
	if childOpts.Host != "openssh:app-alias" {
		t.Fatalf("childOpts.Host = %q, want openssh:app-alias", childOpts.Host)
	}
	if childOpts.originalHost != "app-alias" {
		t.Fatalf("childOpts.originalHost = %q, want app-alias", childOpts.originalHost)
	}
	effHost, err := childOpts.effectiveHostName()
	if err != nil {
		t.Fatalf("effectiveHostName: %v", err)
	}
	if effHost != "fe80::1%eth0" {
		t.Fatalf("effectiveHostName = %q, want verbatim fe80::1%%eth0", effHost)
	}
	if !slices.Equal(childOpts.IdentityFiles, wantIDs) {
		t.Fatalf("childOpts.IdentityFiles = %v, want %v", childOpts.IdentityFiles, wantIDs)
	}
	if !slices.Contains(childOpts.control.Options, "ClearAllForwardings=yes") ||
		!slices.Contains(childOpts.control.Options, "ControlMaster=ask") ||
		!slices.Contains(childOpts.control.Options, "ControlPersist=5m") {
		t.Fatalf("expected authoritative control options on child, got %v", childOpts.control.Options)
	}
}

func TestMuxDaemonSpec_OpenSSHNamespaceAvodingManagedCollision(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	cfg.Hosts.Set("h-managed", models.Host{Address: "192.0.2.99", Port: 22})
	cfg.Identities.Set("id-managed", models.Identity{User: "managed"})
	cfg.Nodes.Set("web", models.Node{HostRef: "h-managed", IdentityRef: "id-managed"})

	sshCfgPath := filepath.Join(tmpDir, "ssh_config")
	if err := os.WriteFile(sshCfgPath, []byte("Host web\n  HostName 10.10.10.10\n  User ossh\n"), 0o600); err != nil {
		t.Fatalf("write ssh_config: %v", err)
	}
	parser, err := config.NewOpenSSHParserFromPath(sshCfgPath)
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromPath: %v", err)
	}
	provider := config.NewProviderWithOpenSSHParser(cfg, parser)

	opts := NewSshOptions()
	spec := opts.buildMuxDaemonSpec("openssh:web", filepath.Join(tmpDir, "web.sock"), nil)
	decoded := roundTripMuxDaemonSpecThroughPipe(t, spec)

	child := NewSshOptions()
	if err := child.applyMuxDaemonSpec(decoded); err != nil {
		t.Fatalf("applyMuxDaemonSpec: %v", err)
	}
	if err := child.Validate(); err != nil {
		t.Fatalf("child.Validate: %v", err)
	}
	resolved, err := config.ResolveTarget(provider, child.Target)
	if err != nil {
		t.Fatalf("ResolveTarget: %v", err)
	}
	if resolved.NodeID != "openssh:web" || resolved.Host != "10.10.10.10" || resolved.User != "ossh" {
		t.Fatalf("OpenSSH namespace collision leaked managed node: %+v", resolved)
	}
}

func TestMuxDaemonSpecSubprocessFDHandoff(t *testing.T) {
	t.Setenv("XOPS_TEST_MUX_SPEC_SUBPROCESS", "1")
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open devnull: %v", err)
	}
	defer func() { _ = devNull.Close() }()

	spec := MuxDaemonSpec{
		Version:          muxDaemonSpecVersion,
		TargetHost:       "app-alias",
		OpenSSHNamespace: true,
		DialHost:         "fe80::1%eth0",
		OriginalHost:     "app-alias",
		Port:             2222,
		User:             "secret-operator",
		ControlPath:      "/tmp/super-secret-ctl.sock",
		ControlMaster:    ssh.ControlMasterAsk,
		ControlPersist:   "5m",
		IdentityFiles:    []string{"/tmp/secret-key-one", "none"},
		Options:          []string{"ProxyCommand=none", "ServerAliveInterval=15"},
	}

	cmd, err := startMuxDaemonCommandWithPrefix(exe, []string{"-test.run=^TestMuxDaemonSpecSubprocessHelper$", "--"}, spec, devNull)
	if err != nil {
		t.Fatalf("startMuxDaemonCommandWithPrefix: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("subprocess failed: %v", err)
	}
}

func TestMuxDaemonSpecSubprocessHelper(t *testing.T) {
	if os.Getenv("XOPS_TEST_MUX_SPEC_SUBPROCESS") != "1" {
		return
	}
	sepIdx := slices.Index(os.Args, "--")
	if sepIdx < 0 || sepIdx+1 >= len(os.Args) {
		t.Fatalf("expected '-- --mux-daemon-spec-fd <fd>' in os.Args, got %v", os.Args)
	}
	subArgs := os.Args[sepIdx+1:]
	joinedArgv := strings.Join(os.Args, " ")
	for _, sensitive := range []string{
		"app-alias",
		"fe80::1%eth0",
		"secret-operator",
		"super-secret-ctl.sock",
		"secret-key-one",
		"ProxyCommand",
		"ServerAliveInterval",
	} {
		if strings.Contains(joinedArgv, sensitive) {
			t.Fatalf("sensitive spec field %q leaked into subprocess argv: %q", sensitive, joinedArgv)
		}
	}

	opts := NewSshOptions()
	sshCmd := newCmdSshWithOptions(opts)
	if err := sshCmd.ParseFlags(subArgs); err != nil {
		t.Fatalf("ParseFlags(%v): %v", subArgs, err)
	}
	if err := opts.Complete(sshCmd, sshCmd.Flags().Args()); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if err := opts.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if opts.Host != "openssh:app-alias" || opts.HostName != "fe80::1%eth0" || opts.originalHost != "app-alias" ||
		opts.User != "secret-operator" || opts.Port != 2222 || opts.control.ControlPath != "/tmp/super-secret-ctl.sock" {
		t.Fatalf("unexpected child opts state after FD handoff: Host=%q HostName=%q orig=%q User=%q Port=%d CP=%q",
			opts.Host, opts.HostName, opts.originalHost, opts.User, opts.Port, opts.control.ControlPath)
	}
	if !opts.isMuxDaemon() || !opts.NoCmd || !opts.StdinRedirect {
		t.Fatalf("expected mux daemon normalization applied in child")
	}
}

func TestMuxDaemonSpec_FailClosedValidation(t *testing.T) {
	t.Run("zero_value_SshOptions_does_not_read_fd_0", func(t *testing.T) {
		o := &SshOptions{}
		c := newCmdSshWithOptions(o)
		if err := c.ParseFlags([]string{"example.com"}); err != nil {
			t.Fatalf("ParseFlags: %v", err)
		}
		if err := o.Complete(c, []string{"example.com"}); err != nil {
			t.Fatalf("Complete on zero-value SshOptions should not attempt FD 0 read: %v", err)
		}
	})

	t.Run("spec_validate_rejects_invalid_fields", func(t *testing.T) {
		invalid := []MuxDaemonSpec{
			{Version: 0, TargetHost: "web", ControlPath: "/tmp/c.sock", ControlMaster: ssh.ControlMasterYes},
			{Version: 2, TargetHost: "web", ControlPath: "/tmp/c.sock", ControlMaster: ssh.ControlMasterYes},
			{Version: 1, TargetHost: "  ", ControlPath: "/tmp/c.sock", ControlMaster: ssh.ControlMasterYes},
			{Version: 1, TargetHost: "web", ControlPath: "", ControlMaster: ssh.ControlMasterYes},
			{Version: 1, TargetHost: "web", ControlPath: "none", ControlMaster: ssh.ControlMasterYes},
			{Version: 1, TargetHost: "web", ControlPath: "/tmp/c.sock", ControlMaster: ssh.ControlMasterNo},
			{Version: 1, TargetHost: "web", ControlPath: "/tmp/c.sock", ControlMaster: ssh.ControlMasterAuto},
		}
		for i, s := range invalid {
			if err := s.Validate(); err == nil {
				t.Errorf("case %d: expected Validate() error for %+v", i, s)
			}
			if _, err := startMuxDaemonCommandWithPrefix("/nonexistent", nil, s, nil); err == nil {
				t.Errorf("case %d: expected startMuxDaemonCommandWithPrefix to reject invalid spec before spawning", i)
			}
		}
	})

	t.Run("readMuxDaemonSpec_rejects_malformed_and_oversized", func(t *testing.T) {
		if _, err := readMuxDaemonSpec(nil); err == nil {
			t.Fatal("expected nil reader error")
		}
		if _, err := readMuxDaemonSpec(bytes.NewReader(nil)); err == nil {
			t.Fatal("expected empty payload error")
		}
		if _, err := readMuxDaemonSpec(bytes.NewReader([]byte("{not-json"))); err == nil {
			t.Fatal("expected malformed JSON error")
		}
		oversized := bytes.Repeat([]byte("a"), maxMuxDaemonSpecBytes+16)
		if _, err := readMuxDaemonSpec(bytes.NewReader(oversized)); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("expected oversized error, got %v", err)
		}
	})

	if runtime.GOOS != "windows" {
		t.Run("rejects_std_descriptors_below_3", func(t *testing.T) {
			for _, badFD := range []int{-1, 0, 1, 2} {
				if _, err := readMuxDaemonSpecFromFD(badFD); err == nil {
					t.Errorf("expected readMuxDaemonSpecFromFD(%d) to fail", badFD)
				}
			}
		})
	}
}
