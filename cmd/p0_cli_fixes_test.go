package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestP0_CLIIdentityFlag_PreservesTokensEnvAndNone(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}

	cases := []struct {
		name          string
		args          []string
		wantFiles     []string
		wantPersistID string
	}{
		{
			name:          "percent_tokens_preserved_and_not_persisted",
			args:          []string{"-i", "%d/.ssh/id_%r", "web"},
			wantFiles:     []string{"%d/.ssh/id_%r"},
			wantPersistID: "",
		},
		{
			name:          "env_var_preserved_and_not_persisted",
			args:          []string{"-i", "${SSH_KEY_PATH}", "web"},
			wantFiles:     []string{"${SSH_KEY_PATH}"},
			wantPersistID: "",
		},
		{
			name:          "literal_dash_i_none_resolves_to_cwd_none_matching_openssh",
			args:          []string{"-i", "none", "web"},
			wantFiles:     []string{filepath.Join(cwd, "none")},
			wantPersistID: filepath.Join(cwd, "none"),
		},
		{
			name:          "option_IdentityFile_none_preserved_as_sentinel_and_not_persisted",
			args:          []string{"-o", "IdentityFile=none", "web"},
			wantFiles:     []string{"none"},
			wantPersistID: "",
		},
		{
			name:          "token_followed_by_persistable_picks_first_persistable",
			args:          []string{"-i", "%d/.ssh/id_%r", "-i", "${SSH_KEY_PATH}", "-i", "~/keys/real_id", "web"},
			wantFiles:     []string{"%d/.ssh/id_%r", "${SSH_KEY_PATH}", filepath.Join(home, "keys", "real_id")},
			wantPersistID: filepath.Join(home, "keys", "real_id"),
		},
		{
			name:          "concrete_key_normalized_and_persisted",
			args:          []string{"-i", "~/keys/id_ed25519", "web"},
			wantFiles:     []string{filepath.Join(home, "keys", "id_ed25519")},
			wantPersistID: filepath.Join(home, "keys", "id_ed25519"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := NewSshOptions()
			if slices.Contains(tc.args, "-i") {
				o.IdentityFile = "/stale/preexisting/key"
			}
			c := newCmdSshWithOptions(o)
			if err := c.Flags().Parse(tc.args); err != nil {
				t.Fatalf("Parse(%v): %v", tc.args, err)
			}
			if err := ApplyGeneralOptions(o, o.control.Options, c.Flags()); err != nil {
				t.Fatalf("ApplyGeneralOptions(%v): %v", tc.args, err)
			}
			if !slices.Equal(o.IdentityFiles, tc.wantFiles) {
				t.Fatalf("IdentityFiles = %v, want %v", o.IdentityFiles, tc.wantFiles)
			}
			if o.IdentityFile != tc.wantPersistID {
				t.Fatalf("IdentityFile = %q, want %q", o.IdentityFile, tc.wantPersistID)
			}
		})
	}

	// Verify exec and scp share the same preservation via Complete.
	execOpts := NewExecOptions()
	execCmd := newCmdExecWithOptions(execOpts)
	if err := execCmd.Flags().Parse([]string{"-i", "%d/.ssh/id_%r", "--host", "web", "-c", "id"}); err != nil {
		t.Fatalf("exec Parse: %v", err)
	}
	if err := execOpts.Complete(execCmd, execCmd.Flags().Args()); err != nil {
		t.Fatalf("exec Complete: %v", err)
	}
	if !slices.Equal(execOpts.IdentityFiles, []string{"%d/.ssh/id_%r"}) || execOpts.IdentityFile != "" {
		t.Fatalf("exec identity state corrupted: files=%v single=%q", execOpts.IdentityFiles, execOpts.IdentityFile)
	}

	scpOpts := NewScpOptions()
	scpCmd := NewCmdScp()
	if err := scpCmd.Flags().Parse([]string{"-i", "${SSH_KEY_PATH}", "/tmp/a", "web:/tmp/b"}); err != nil {
		t.Fatalf("scp Parse: %v", err)
	}
	scpOpts.IdentityFiles = []string{"${SSH_KEY_PATH}"}
	if err := ApplyGeneralOptions(&scpOpts.SshOptions, nil, scpCmd.Flags()); err != nil {
		t.Fatalf("scp ApplyGeneralOptions: %v", err)
	}
	if !slices.Equal(scpOpts.IdentityFiles, []string{"${SSH_KEY_PATH}"}) || scpOpts.IdentityFile != "" {
		t.Fatalf("scp identity state corrupted: files=%v single=%q", scpOpts.IdentityFiles, scpOpts.IdentityFile)
	}
}

func TestP0_ExecAndScp_FailClosedExcludeAndTaskCount(t *testing.T) {
	badExcludeArgs := [][]string{
		{"--exclude", ""},
		{"--exclude", " "},
		{"--exclude", ","},
		{"--exclude", "web1,,web2"},
		{"--exclude", "web1,"},
		{"--exclude", ",web1"},
		{"--exclude", "web1", "--exclude", ""},
	}

	for i, exArgs := range badExcludeArgs {
		t.Run(fmt.Sprintf("exec_rejects_bad_exclude_%d", i), func(t *testing.T) {
			o := NewExecOptions()
			c := newCmdExecWithOptions(o)
			args := append(slices.Clone(exArgs), "--host", "web1,web2", "-c", "id")
			if err := c.Flags().Parse(args); err == nil {
				t.Fatalf("exec Parse(%v) accepted malformed exclude args %v", args, exArgs)
			}
		})

		t.Run(fmt.Sprintf("scp_rejects_bad_exclude_%d", i), func(t *testing.T) {
			c := NewCmdScp()
			c.SilenceErrors = true
			c.SilenceUsage = true
			c.SetOut(&bytes.Buffer{})
			c.SetErr(&bytes.Buffer{})
			args := append(slices.Clone(exArgs), "--host", "web1,web2", "/tmp/src", "/tmp/dst")
			c.SetArgs(args)
			if err := c.Execute(); err == nil {
				t.Fatalf("scp accepted malformed exclude args %v", exArgs)
			}
		})
	}

	// Negative / zero / excessive --task values must fail cleanly without panicking.
	for _, badTask := range []int{-1, 0, maxBatchTaskCount + 1} {
		t.Run(fmt.Sprintf("exec_rejects_task_%d", badTask), func(t *testing.T) {
			o := NewExecOptions()
			o.Host = "web1"
			o.Command = "id"
			o.TaskCount = badTask
			if err := o.Validate(); err == nil {
				t.Fatalf("ExecOptions.Validate accepted TaskCount=%d", badTask)
			}
		})
		t.Run(fmt.Sprintf("scp_rejects_task_%d", badTask), func(t *testing.T) {
			o := NewScpOptions()
			o.Source = "/tmp/src"
			o.Dest = "web1:/tmp/dst"
			o.TaskCount = badTask
			if err := o.Validate(); err == nil {
				t.Fatalf("ScpOptions.Validate accepted TaskCount=%d", badTask)
			}
		})
	}

	// Valid --task and --exclude still succeed Validate().
	validExec := NewExecOptions()
	validExecCmd := newCmdExecWithOptions(validExec)
	if err := validExecCmd.Flags().Parse([]string{"--task", "4", "--exclude", "web1,web2", "--host", "web1,web2,web3", "-c", "id"}); err != nil {
		t.Fatalf("Parse valid exec: %v", err)
	}
	if err := validExec.Complete(validExecCmd, validExecCmd.Flags().Args()); err != nil {
		t.Fatalf("valid exec Complete: %v", err)
	}
	if err := validExec.Validate(); err != nil {
		t.Fatalf("valid exec Validate: %v", err)
	}
}

func TestP0_MuxDaemonSpec_AuthorityOrderingValidationAndFieldClearing(t *testing.T) {
	t.Run("authoritative_options_precede_spec_options_and_transient_fields_cleared", func(t *testing.T) {
		spec := MuxDaemonSpec{
			Version:        muxDaemonSpecVersion,
			TargetHost:     "app",
			ControlPath:    "/tmp/p0-auth.sock",
			ControlMaster:  ssh.ControlMasterAsk,
			ControlPersist: "10m",
			Options:        []string{"ServerAliveInterval=15", "GatewayPorts=yes", "ProxyCommand=none"},
		}
		if err := spec.Validate(); err != nil {
			t.Fatalf("valid spec rejected: %v", err)
		}

		child := NewSshOptions()
		child.control.CtlCmd = "check"
		child.control.ctlCmdSet = true
		child.Sudo = true
		child.OTP = "123456"
		child.DisableTTY = true
		child.ForceTTYCount = 2
		child.cliTTYMode = ssh.RequestTTYForce

		if err := child.applyMuxDaemonSpec(spec); err != nil {
			t.Fatalf("applyMuxDaemonSpec: %v", err)
		}
		if len(child.control.Options) < 6 {
			t.Fatalf("unexpected child.control.Options: %v", child.control.Options)
		}
		if child.control.Options[0] != "ControlMaster=ask" ||
			child.control.Options[1] != "ClearAllForwardings=yes" ||
			child.control.Options[2] != "ControlPersist=10m" {
			t.Fatalf("authoritative options must appear before spec.Options, got: %v", child.control.Options)
		}
		if child.control.CtlCmd != "" || child.control.ctlCmdSet || child.Sudo || child.OTP != "" ||
			child.DisableTTY || child.ForceTTYCount != 0 || child.cliTTYMode != "" {
			t.Fatalf("transient fields were not cleared: CtlCmd=%q ctlCmdSet=%v Sudo=%v OTP=%q DisableTTY=%v ForceTTYCount=%d cliTTYMode=%q",
				child.control.CtlCmd, child.control.ctlCmdSet, child.Sudo, child.OTP, child.DisableTTY, child.ForceTTYCount, child.cliTTYMode)
		}
	})

	t.Run("spec_validate_rejects_disallowed_and_malformed_options", func(t *testing.T) {
		badOptions := []string{
			"MalformedWithoutValue",
			"UnknownOption=yes",
			"ServerAliveInterval=not-a-duration",
			"ControlMaster=no",
			"ControlPath=/tmp/override.sock",
			"ControlPersist=no",
			"ClearAllForwardings=no",
			"LocalForward=8080:127.0.0.1:80",
			"RemoteForward=9090:127.0.0.1:90",
			"DynamicForward=1080",
			"ForwardAgent=yes",
			"Tunnel=point-to-point",
			"TunnelDevice=0:0",
			"ForkAfterAuthentication=yes",
			"StdinNull=no",
			"SessionType=default",
			"RequestTTY=yes",
			"RemoteCommand=id",
			"SendEnv=FOO",
			"SetEnv=FOO=1",
			"ProxyCommand=nc %h %p",
			"LocalCommand=id",
			"PermitLocalCommand=yes",
			"PermitLocalCommand=no",
			"Port=2222",
			"User=evil",
			"HostName=evil.example",
			"ProxyJump=evil",
			"IdentityFile=/tmp/k",
		}
		for _, opt := range badOptions {
			spec := MuxDaemonSpec{
				Version:       muxDaemonSpecVersion,
				TargetHost:    "app",
				ControlPath:   "/tmp/p0-bad.sock",
				ControlMaster: ssh.ControlMasterYes,
				Options:       []string{opt},
			}
			if err := spec.Validate(); err == nil {
				t.Errorf("MuxDaemonSpec.Validate accepted disallowed option %q", opt)
			}
		}

		badPersist := MuxDaemonSpec{
			Version:        muxDaemonSpecVersion,
			TargetHost:     "app",
			ControlPath:    "/tmp/p0-bad.sock",
			ControlMaster:  ssh.ControlMasterYes,
			ControlPersist: "not-a-duration",
		}
		if err := badPersist.Validate(); err == nil {
			t.Error("MuxDaemonSpec.Validate accepted invalid ControlPersist")
		}
	})
}

func TestP0_AskpassCommandEnv_StripsInternalDaemonMarkers(t *testing.T) {
	t.Parallel()

	base := []string{
		"PATH=/usr/bin",
		"DISPLAY=:0",
		"SSH_ASKPASS_PROMPT=stale",
		sshMuxDaemonEnv + "=true",
		sshBackgroundChildEnv + "=true",
		strings.ToLower(sshMuxDaemonEnv) + "=1",
		strings.ToLower(sshBackgroundChildEnv) + "=1",
	}
	got := askpassCommandEnv(base)
	for _, kv := range got {
		upper := strings.ToUpper(kv)
		if strings.HasPrefix(upper, sshMuxDaemonEnv+"=") || strings.HasPrefix(upper, sshBackgroundChildEnv+"=") {
			t.Fatalf("askpassCommandEnv leaked internal daemon env marker %q in %v", kv, got)
		}
		if strings.HasPrefix(upper, "SSH_ASKPASS_PROMPT=") && kv != "SSH_ASKPASS_PROMPT=confirm" {
			t.Fatalf("askpassCommandEnv left stale prompt %q in %v", kv, got)
		}
	}
	if !slices.Contains(got, "SSH_ASKPASS_PROMPT=confirm") || !slices.Contains(got, "DISPLAY=:0") || !slices.Contains(got, "PATH=/usr/bin") {
		t.Fatalf("askpassCommandEnv missing expected entries: %v", got)
	}
}

func TestP0_ReadMuxDaemonSpecFromFD_RequiresExactFD3(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix FD check only applies on non-Windows platforms")
	}
	for _, badFD := range []int{-1, 0, 1, 2, 4, 5, 99} {
		if _, err := readMuxDaemonSpecFromFD(badFD); err == nil {
			t.Errorf("readMuxDaemonSpecFromFD(%d) unexpectedly succeeded", badFD)
		}
	}
}

func TestP0_WaitForControlSocketPID_VerifiesDaemonPID(t *testing.T) {
	client, _ := newTunnelTestClient(t)
	sockPath := filepath.Join(shortControlTempDir(t), "pidcheck.sock")
	master, err := ssh.NewMuxServer(ssh.MuxServerOptions{
		ControlPath: sockPath,
		SSHClient:   client.SSHClient(),
		Target: ssh.TargetContext{
			Host: "127.0.0.1",
			Port: 22,
			User: "fixture",
		},
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatalf("NewMuxServer: %v", err)
	}
	go func() { _ = master.Serve() }()
	t.Cleanup(func() { _ = master.Shutdown() })

	// Matching PID succeeds.
	if err := waitForControlSocketPID(t.Context(), sockPath, 2*time.Second, nil, os.Getpid()); err != nil {
		t.Fatalf("waitForControlSocketPID(matching pid) failed: %v", err)
	}
	// Legacy expectedPID == 0 succeeds.
	if err := waitForControlSocket(t.Context(), sockPath, 2*time.Second, nil); err != nil {
		t.Fatalf("waitForControlSocket failed: %v", err)
	}
	// Wrong PID must be rejected rather than falsely accepting another master.
	wrongPID := os.Getpid() + 99999
	err = waitForControlSocketPID(t.Context(), sockPath, 250*time.Millisecond, nil, wrongPID)
	if err == nil || !strings.Contains(err.Error(), "expected daemon pid") {
		t.Fatalf("waitForControlSocketPID(wrong pid) = %v, want PID mismatch error", err)
	}
}

func TestP0_SshBackgroundFlag_DefersWhenConfigSuppliesSessionOrRemoteCmd(t *testing.T) {
	home := t.TempDir()
	cfgDir := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XOPS_CONFIG_DIR", cfgDir)

	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("MkdirAll .ssh: %v", err)
	}
	sshConfig := strings.Join([]string{
		"Host bg-nocmd",
		"  HostName 10.0.0.10",
		"  SessionType none",
		"",
		"Host bg-rcmd",
		"  HostName 10.0.0.11",
		"  RemoteCommand sleep 30",
		"",
		"Host plain-host",
		"  HostName 10.0.0.12",
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte(sshConfig), 0o600); err != nil {
		t.Fatalf("write ssh config: %v", err)
	}

	// Saved node with session_type: none in xops_config.yaml.
	cfgPath, keyPath, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatalf("GetConfigFilePath: %v", err)
	}
	store := config.NewDefaultStore(cfgPath, keyPath)
	cfg := &config.Configuration{
		SchemaVersion: 2,
		Hosts:         concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities:    concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Nodes:         concurrent.NewMap[string, models.Node](concurrent.HashString),
	}
	cfg.Hosts.Set("10.0.0.20:22", models.Host{Address: "10.0.0.20", Port: 22})
	cfg.Identities.Set("ops@10.0.0.20", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("ops@10.0.0.20:22", models.Node{
		HostRef:     "10.0.0.20:22",
		IdentityRef: "ops@10.0.0.20",
		Alias:       []string{"saved-bg"},
		SSHOptions:  ssh.MustOptions(ssh.OptionSessionType, "none"),
	})
	if err := store.Save(cfg); err != nil {
		t.Fatalf("store.Save: %v", err)
	}

	// 1. Config-supplied SessionType=none and RemoteCommand pass Validate() without mutating o.
	for _, host := range []string{"bg-nocmd", "bg-rcmd", "saved-bg"} {
		t.Run("defers_for_"+host, func(t *testing.T) {
			o := NewSshOptions()
			cmd := newCmdSshWithOptions(o)
			if err := cmd.Flags().Parse([]string{"-f", host}); err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if err := o.Complete(cmd, cmd.Flags().Args()); err != nil {
				t.Fatalf("Complete: %v", err)
			}
			if err := o.Validate(); err != nil {
				t.Fatalf("Validate(-f %s) unexpected error: %v", host, err)
			}
			if o.syncedTargetHosts {
				t.Fatalf("Validate(-f %s) must not mutate o.syncedTargetHosts", host)
			}
		})
	}

	// 2. Host without SessionType=none or RemoteCommand still fails Validate() eagerly.
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"plain_host", []string{"-f", "plain-host"}},
		{"F_none_disables_ssh_config", []string{"-f", "-F", "none", "bg-nocmd"}},
		{"cli_locks_session_and_remote_cmd", []string{"-f", "-o", "SessionType=default", "-o", "RemoteCommand=none", "bg-nocmd"}},
		{"eager_credential_invariant_otp", []string{"-f", "--otp", "123456", "bg-nocmd"}},
		{"eager_credential_invariant_password_stdin", []string{"-f", "--password-stdin", "bg-nocmd"}},
	} {
		t.Run("rejects_"+tc.name, func(t *testing.T) {
			o := NewSshOptions()
			cmd := newCmdSshWithOptions(o)
			if err := cmd.Flags().Parse(tc.args); err != nil {
				t.Fatalf("Parse(%v): %v", tc.args, err)
			}
			err := o.Complete(cmd, cmd.Flags().Args())
			if err == nil {
				err = o.Validate()
			}
			if err == nil {
				t.Fatalf("expected error for %v, got nil", tc.args)
			}
		})
	}

	// 3. -O proxy -f on plain-host still exits 255.
	oProxy := NewSshOptions()
	cmdProxy := newCmdSshWithOptions(oProxy)
	if err := cmdProxy.Flags().Parse([]string{"-O", "proxy", "-f", "plain-host"}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := oProxy.Complete(cmdProxy, cmdProxy.Flags().Args()); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	err = oProxy.Validate()
	var ctlErr *ControlExitError
	if !errors.As(err, &ctlErr) || ctlErr.Code != 255 {
		t.Fatalf("Validate(-O proxy -f plain-host) = %v, want *ControlExitError(255)", err)
	}
}

func TestP0_SshStdinNull_DoesNotStarveInteractiveAuthBeforeConnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cfgDir := t.TempDir()
	homeDir := t.TempDir()
	t.Setenv("XOPS_CONFIG_DIR", cfgDir)
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)

	server, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	host, portStr, err := net.SplitHostPort(server.Address)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi: %v", err)
	}

	// Pipe supplies interactive host-key confirmation + password during connectClient,
	// plus trailing payload that MUST NOT be forwarded to the remote command once -n
	// redirects session stdin to /dev/null after authentication completes.
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe(stdin): %v", err)
	}
	defer func() { _ = inR.Close() }()
	_, _ = inW.WriteString("yes\n" + sshfixture.Password + "\nSHOULD_NOT_REACH_REMOTE\n")
	_ = inW.Close()

	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe(stdout): %v", err)
	}
	defer func() { _ = outR.Close() }()

	origStdin, origStdout, origStderr := os.Stdin, os.Stdout, os.Stderr
	os.Stdin = inR
	os.Stdout = outW
	os.Stderr = outW
	t.Cleanup(func() {
		os.Stdin = origStdin
		os.Stdout = origStdout
		os.Stderr = origStderr
	})

	o := NewSshOptions()
	c := newCmdSshWithOptions(o)
	args := []string{
		"-n",
		"-F", "none",
		"-o", "StrictHostKeyChecking=ask",
		"-o", "UserKnownHostsFile=" + filepath.Join(homeDir, "known_hosts"),
		"-o", "PubkeyAuthentication=no",
		"--remember", "never",
		fmt.Sprintf("fixture@%s:%d", host, port),
		"cat",
	}
	if err := c.Flags().Parse(args); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := o.Complete(c, c.Flags().Args()); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if err := o.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	runErr := o.RunContext(ctx)
	_ = outW.Close()

	var outBuf bytes.Buffer
	_, _ = outBuf.ReadFrom(outR)

	if runErr != nil {
		t.Fatalf("ssh -n RunContext failed (interactive auth starved by premature os.Stdin redirect?): %v (output=%q)", runErr, outBuf.String())
	}
	if strings.Contains(outBuf.String(), "SHOULD_NOT_REACH_REMOTE") {
		t.Fatalf("ssh -n leaked stdin payload to remote command: %q", outBuf.String())
	}
}

func TestP0_DocsAndI18n_NoResidualTunTapInHostsOrLocales(t *testing.T) {
	for _, lang := range []string{"en", "zh"} {
		if err := i18n.Init(lang); err != nil {
			t.Fatalf("i18n.Init(%q): %v", lang, err)
		}
		got := i18n.T("ssh_flag_tunnel_device")
		lower := strings.ToLower(got)
		if !strings.Contains(lower, "tun") || strings.Contains(lower, "tap") {
			t.Errorf("locale %q ssh_flag_tunnel_device = %q, want Layer-3 tun wording without tap", lang, got)
		}
	}
	t.Cleanup(func() { _ = i18n.Init("en") })

	for _, rel := range []string{
		filepath.Join("..", "docs", "guide", "hosts.md"),
		filepath.Join("..", "docs", "en", "guide", "hosts.md"),
	} {
		data, err := os.ReadFile(rel)
		if err != nil {
			t.Fatalf("ReadFile(%q): %v", rel, err)
		}
		content := string(data)
		if strings.Contains(strings.ToLower(content), "tun/tap") {
			t.Errorf("%s still contains residual 'tun/tap'", rel)
		}
		if !strings.Contains(content, "`tunnel_device`") {
			t.Errorf("%s missing tunnel_device table entry", rel)
		}
	}
}
