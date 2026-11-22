package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/core/fsx"
	"github.com/wentf9/xops-cli/core/sftp"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

type p5FakePostAuthLocalRunner struct {
	called bool
}

func (f *p5FakePostAuthLocalRunner) RunPostAuthLocalCommand(context.Context) error {
	f.called = true
	return nil
}

// Finding 4.7: Inherited XOPS_CLI_SSH_MUX_DAEMON=true and XOPS_CLI_SSH_BG_CHILD=true
// must have zero effect on normal xops ssh / xops sftp runs.
func TestP5_EnvVarsCannotHijackSshOrSftp(t *testing.T) {
	t.Setenv(sshMuxDaemonEnv, "true")
	t.Setenv(sshBackgroundChildEnv, "true")

	t.Run("ssh_ignores_inherited_daemon_and_bg_env_vars", func(t *testing.T) {
		opts := NewSshOptions()
		if opts.isMuxDaemon() {
			t.Fatal("isMuxDaemon() = true from env var alone, want false")
		}
		if opts.isBackgroundChild() {
			t.Fatal("isBackgroundChild() = true from env var alone, want false")
		}

		sshCmd := newCmdSshWithOptions(opts)
		if err := sshCmd.ParseFlags([]string{"-o", "SendEnv=LANG", "-o", "ForwardAgent=yes", "-o", "LocalCommand=echo hi", "-o", "PermitLocalCommand=yes", "web.example.com", "uptime"}); err != nil {
			t.Fatalf("ParseFlags: %v", err)
		}
		if err := opts.Complete(sshCmd, sshCmd.Flags().Args()); err != nil {
			t.Fatalf("Complete: %v", err)
		}
		if err := opts.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
		if opts.isMuxDaemon() || opts.isBackgroundChild() {
			t.Fatalf("env vars hijacked ssh mode: isMuxDaemon=%v isBackgroundChild=%v", opts.isMuxDaemon(), opts.isBackgroundChild())
		}
		if opts.NoCmd {
			t.Fatal("env vars silently forced NoCmd=true on normal ssh invocation")
		}
		if opts.Command != "uptime" {
			t.Fatalf("Command = %q, want %q (must not be dropped by mux env var)", opts.Command, "uptime")
		}
		if opts.StdinRedirect {
			t.Fatal("env vars silently forced StdinRedirect=true")
		}

		eff, err := opts.resolveAndCacheSessionOptions(nil, "")
		if err != nil {
			t.Fatalf("resolveAndCacheSessionOptions: %v", err)
		}
		if len(eff.SendEnvPatterns()) == 0 || eff.ForwardAgent() != "yes" || eff.LocalCommand() != "echo hi" {
			t.Fatalf("env vars stripped session/local-exec options on normal ssh: sendenv=%v fa=%q lc=%q",
				eff.SendEnvPatterns(), eff.ForwardAgent(), eff.LocalCommand())
		}

		runner := &p5FakePostAuthLocalRunner{}
		if err := runPostAuthLocalCommand(t.Context(), runner, eff, &bytes.Buffer{}, opts.isBackgroundChild()); err != nil {
			t.Fatalf("runPostAuthLocalCommand: %v", err)
		}
		if !runner.called {
			t.Fatal("env vars suppressed LocalCommand on normal foreground ssh session")
		}
	})

	t.Run("sftp_ignores_inherited_bg_env_var", func(t *testing.T) {
		origStdin := os.Stdin
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("os.Pipe: %v", err)
		}
		_, _ = w.WriteString("secret-pass\n")
		_ = w.Close()
		os.Stdin = r
		t.Cleanup(func() {
			os.Stdin = origStdin
			_ = r.Close()
		})

		sftpOpts := NewSftpOptions()
		sftpCmd := newCmdSftpWithOptions(sftpOpts)
		if err := sftpCmd.ParseFlags([]string{"--password-stdin", "web.example.com"}); err != nil {
			t.Fatalf("sftp ParseFlags: %v", err)
		}
		// On non-terminal piped stdin, sftp must reject --password-stdin rather than
		// silently skipping stdin handling due to XOPS_CLI_SSH_BG_CHILD=true.
		if err := sftpOpts.Complete(sftpCmd, sftpCmd.Flags().Args()); err == nil {
			t.Fatal("sftp Complete unexpectedly succeeded with --password-stdin on piped stdin; env var must not bypass stdin checks")
		}
	})
}

func TestP5_BgChildSpecPipeRoundTripAndFailClosed(t *testing.T) {
	t.Run("subprocess_pipe_fd_roundtrip_sets_bgChildMode_without_env_vars", testP5BgChildSubprocessRoundTrip)
	t.Run("mux_daemon_subprocess_does_not_inject_legacy_env_vars", testP5MuxDaemonNoLegacyEnvSubprocess)
	t.Run("readBgChildSpec_validation_and_bounds", testP5ReadBgChildSpecValidation)
	t.Run("fd_flag_fail_closed_and_mutually_exclusive", testP5BgChildFDFlagFailClosed)
	t.Run("injectBackgroundChildSpecFDFlag_preserves_root_flags_and_dash_separator", testP5InjectBgChildSpecFDFlag)
}

func testP5BgChildSubprocessRoundTrip(t *testing.T) {
	t.Setenv("XOPS_TEST_BG_SPEC_SUBPROCESS", "1")
	t.Setenv(sshMuxDaemonEnv, "")
	t.Setenv(sshBackgroundChildEnv, "")

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open devnull: %v", err)
	}
	defer func() { _ = devNull.Close() }()

	cmd, err := startBackgroundSSHCommand(
		exe,
		[]string{"-test.run=^TestP5_BgChildSpecSubprocessHelper$", "--", "-f", "-N", "example.com"},
		devNull,
	)
	if err != nil {
		t.Fatalf("startBackgroundSSHCommand: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("bg child subprocess failed: %v", err)
	}
}

func testP5MuxDaemonNoLegacyEnvSubprocess(t *testing.T) {
	t.Setenv("XOPS_TEST_MUX_NO_ENV_SUBPROCESS", "1")
	t.Setenv(sshMuxDaemonEnv, "")
	t.Setenv(sshBackgroundChildEnv, "")

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
		Version:       muxDaemonSpecVersion,
		TargetHost:    "example.com",
		ControlPath:   filepath.Join(t.TempDir(), "ctl.sock"),
		ControlMaster: ssh.ControlMasterYes,
	}
	cmd, err := startMuxDaemonCommandWithPrefix(
		exe,
		[]string{"-test.run=^TestP5_MuxNoEnvSubprocessHelper$", "--"},
		spec,
		devNull,
	)
	if err != nil {
		t.Fatalf("startMuxDaemonCommandWithPrefix: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("mux daemon subprocess failed: %v", err)
	}
}

func testP5ReadBgChildSpecValidation(t *testing.T) {
	if _, err := readBgChildSpec(nil); err == nil {
		t.Error("expected nil reader error")
	}
	if _, err := readBgChildSpec(bytes.NewReader(nil)); err == nil {
		t.Error("expected empty payload error")
	}
	if _, err := readBgChildSpec(bytes.NewReader([]byte("{bad"))); err == nil {
		t.Error("expected malformed JSON error")
	}
	if _, err := readBgChildSpec(bytes.NewReader([]byte(`{"version":2,"bg_child":true}`))); err == nil {
		t.Error("expected wrong version error")
	}
	if _, err := readBgChildSpec(bytes.NewReader([]byte(`{"version":1,"bg_child":false}`))); err == nil {
		t.Error("expected bg_child=false error")
	}
	oversized := bytes.Repeat([]byte(" "), maxBgChildSpecBytes+16)
	if _, err := readBgChildSpec(bytes.NewReader(oversized)); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("expected oversized error, got %v", err)
	}
	got, err := readBgChildSpec(bytes.NewReader([]byte(`{"version":1,"bg_child":true}`)))
	if err != nil || !got.BgChild || got.Version != 1 {
		t.Fatalf("valid bgChildSpec failed: got=%+v err=%v", got, err)
	}
}

func testP5BgChildFDFlagFailClosed(t *testing.T) {
	if runtime.GOOS != "windows" {
		for _, badFD := range []int{-1, 0, 1, 2, 4, 99} {
			if _, err := readBgChildSpecFromFD(badFD); err == nil {
				t.Errorf("readBgChildSpecFromFD(%d) unexpectedly succeeded", badFD)
			}
		}
	}

	// Zero-value SshOptions must not read FD 0 when --bg-child-spec-fd is not changed.
	zero := &SshOptions{}
	c := newCmdSshWithOptions(zero)
	if err := c.ParseFlags([]string{"example.com"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	if err := zero.Complete(c, []string{"example.com"}); err != nil {
		t.Fatalf("Complete on zero-value SshOptions failed: %v", err)
	}
	if zero.isBackgroundChild() {
		t.Fatal("zero-value SshOptions became background child without pipe FD")
	}

	// Both --mux-daemon-spec-fd and --bg-child-spec-fd together must fail closed.
	both := NewSshOptions()
	bc := newCmdSshWithOptions(both)
	if err := bc.ParseFlags([]string{"--mux-daemon-spec-fd", "3", "--bg-child-spec-fd", "3"}); err != nil {
		t.Fatalf("ParseFlags(both): %v", err)
	}
	if err := both.Complete(bc, nil); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutually exclusive error, got %v", err)
	}
}

func testP5InjectBgChildSpecFDFlag(t *testing.T) {
	cases := []struct {
		args []string
		want []string
	}{
		{
			args: []string{"ssh", "-f", "-N", "web"},
			want: []string{"ssh", "--bg-child-spec-fd", "3", "-f", "-N", "web"},
		},
		{
			args: []string{"--lang", "en", "--debug", "ssh", "-f", "web", "--", "sleep", "1"},
			want: []string{"--lang", "en", "--debug", "ssh", "--bg-child-spec-fd", "3", "-f", "web", "--", "sleep", "1"},
		},
		{
			args: []string{"-test.run=^TestFoo$", "--", "-f", "-N", "web"},
			want: []string{"-test.run=^TestFoo$", "--", "--bg-child-spec-fd", "3", "-f", "-N", "web"},
		},
		{
			args: []string{"-test.run=^TestFoo$", "--"},
			want: []string{"-test.run=^TestFoo$", "--", "--bg-child-spec-fd", "3"},
		},
	}
	for _, tc := range cases {
		got := injectBackgroundChildSpecFDFlag(tc.args, 3)
		if !slices.Equal(got, tc.want) {
			t.Errorf("injectBackgroundChildSpecFDFlag(%v, 3) = %v, want %v", tc.args, got, tc.want)
		}
	}
}

func TestP5_BgChildSpecSubprocessHelper(t *testing.T) {
	if os.Getenv("XOPS_TEST_BG_SPEC_SUBPROCESS") != "1" {
		return
	}
	if os.Getenv(sshBackgroundChildEnv) == "true" || os.Getenv(sshMuxDaemonEnv) == "true" {
		t.Fatalf("startBackgroundSSHCommand must not inject legacy env vars: bg=%q mux=%q",
			os.Getenv(sshBackgroundChildEnv), os.Getenv(sshMuxDaemonEnv))
	}
	sepIdx := slices.Index(os.Args, "--")
	if sepIdx < 0 || sepIdx+1 >= len(os.Args) {
		t.Fatalf("missing '--' args in subprocess: %v", os.Args)
	}
	opts := NewSshOptions()
	sshCmd := newCmdSshWithOptions(opts)
	if err := sshCmd.ParseFlags(os.Args[sepIdx+1:]); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	if err := opts.Complete(sshCmd, sshCmd.Flags().Args()); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if !opts.bgChildMode || !opts.isBackgroundChild() || opts.isMuxDaemon() {
		t.Fatalf("unexpected child mode flags: bgChildMode=%v isBackgroundChild=%v isMuxDaemon=%v",
			opts.bgChildMode, opts.isBackgroundChild(), opts.isMuxDaemon())
	}
	if err := opts.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestP5_MuxNoEnvSubprocessHelper(t *testing.T) {
	if os.Getenv("XOPS_TEST_MUX_NO_ENV_SUBPROCESS") != "1" {
		return
	}
	if os.Getenv(sshBackgroundChildEnv) == "true" || os.Getenv(sshMuxDaemonEnv) == "true" {
		t.Fatalf("startMuxDaemonCommandWithPrefix must not inject legacy env vars: bg=%q mux=%q",
			os.Getenv(sshBackgroundChildEnv), os.Getenv(sshMuxDaemonEnv))
	}
	sepIdx := slices.Index(os.Args, "--")
	if sepIdx < 0 || sepIdx+1 >= len(os.Args) {
		t.Fatalf("missing '--' args in subprocess: %v", os.Args)
	}
	opts := NewSshOptions()
	sshCmd := newCmdSshWithOptions(opts)
	if err := sshCmd.ParseFlags(os.Args[sepIdx+1:]); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	if err := opts.Complete(sshCmd, sshCmd.Flags().Args()); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if !opts.isMuxDaemon() || !opts.isBackgroundChild() {
		t.Fatalf("expected mux daemon mode from pipe FD, got isMuxDaemon=%v isBackgroundChild=%v",
			opts.isMuxDaemon(), opts.isBackgroundChild())
	}
}

// Finding 3.18: Fail-closed CLI selectors in xops play and xops exec.
func TestP5_PlayLimitSelectorFailsClosed(t *testing.T) {
	playbookPath := filepath.Join(t.TempDir(), "playbook.yaml")
	content := []byte("name: test\ntargets:\n  nodes: [web-1, web-2]\nsteps:\n  - name: check\n    shell: 'true'\n")
	if err := os.WriteFile(playbookPath, content, 0o600); err != nil {
		t.Fatalf("write playbook fixture: %v", err)
	}

	for _, badLimit := range []string{"", "   ", ",", "web-1,,web-2", ",web-1", "web-1,", "web-1, ,web-2"} {
		t.Run("reject_"+badLimit, func(t *testing.T) {
			var out bytes.Buffer
			cmd := NewCmdPlay()
			cmd.SetOut(&out)
			cmd.SetArgs([]string{playbookPath, "--dry-run", "--limit", badLimit})
			if err := cmd.ExecuteContext(t.Context()); err == nil {
				t.Fatalf("play --limit %q unexpectedly succeeded (output=%q); must fail closed", badLimit, out.String())
			}
			if bytes.Contains(out.Bytes(), []byte("web-1")) || bytes.Contains(out.Bytes(), []byte("web-2")) {
				t.Fatalf("play --limit %q fell back to playbook targets: %q", badLimit, out.String())
			}
		})
	}

	t.Run("valid_limit_trims_segments", func(t *testing.T) {
		var out bytes.Buffer
		cmd := NewCmdPlay()
		cmd.SetOut(&out)
		cmd.SetArgs([]string{playbookPath, "--dry-run", "--limit", " only-one , only-two "})
		if err := cmd.ExecuteContext(t.Context()); err != nil {
			t.Fatalf("play --limit valid failed: %v", err)
		}
		if !strings.Contains(out.String(), "nodes=[only-one only-two]") {
			t.Fatalf("unexpected dry-run targets output: %q", out.String())
		}
	})

	t.Run("programmatic_invalid_limit_fails_closed", func(t *testing.T) {
		o := &PlayOptions{FilePath: playbookPath, Limit: "a,,b", DryRun: true, Out: &bytes.Buffer{}}
		if err := o.RunContext(t.Context()); err == nil {
			t.Fatal("programmatic PlayOptions with Limit='a,,b' unexpectedly succeeded")
		}
	})
}

func TestP5_ExecEmptySelectorsFailClosed(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		wantFlag string
	}{
		{name: "empty_host", args: []string{"--host", "", "uptime"}, wantFlag: "--host"},
		{name: "whitespace_host", args: []string{"--host", "   ", "uptime"}, wantFlag: "--host"},
		{name: "empty_tag", args: []string{"--tag", "", "id"}, wantFlag: "--tag"},
		{name: "whitespace_tag", args: []string{"--tag", "\t ", "id"}, wantFlag: "--tag"},
		{name: "empty_ifile", args: []string{"--ifile", "", "--", "id"}, wantFlag: "--ifile"},
		{name: "whitespace_short_ifile", args: []string{"-I", "  ", "id"}, wantFlag: "--ifile"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := NewExecOptions()
			execCmd := newCmdExecWithOptions(opts)
			err := execCmd.ParseFlags(tc.args)
			if err == nil {
				t.Fatalf("ParseFlags(%v) succeeded (Host=%q), want error for %s",
					tc.args, opts.Host, tc.wantFlag)
			}
			if !strings.Contains(err.Error(), tc.wantFlag) {
				t.Fatalf("ParseFlags(%v) error = %v, want mention of %s", tc.args, err, tc.wantFlag)
			}
		})
	}

	t.Run("programmatic_whitespace_selectors_rejected_in_Validate", func(t *testing.T) {
		for _, setup := range []func(*ExecOptions){
			func(o *ExecOptions) { o.Host = "   " },
			func(o *ExecOptions) { o.Tag = " \t " },
			func(o *ExecOptions) { o.HostFile = "  " },
		} {
			o := NewExecOptions()
			o.Command = "id"
			setup(o)
			if err := o.Validate(); err == nil {
				t.Fatalf("Validate accepted whitespace-only selector on %+v", o)
			}
		}
	})
}

// Finding 4.2: Close CLI IdentityFile=none leaks across ssh, exec, and mux daemon spec.
func TestP5_IdentityFileNoneTruncationAndNoPostNoneLeaks(t *testing.T) {
	t.Run("post_none_option_does_not_leak_or_overwrite_IdentityFile", testP5PostNoneOptionNoLeak)
	t.Run("standalone_IdentityFiles_none_without_option_flag_truncates_lower_tier", testP5StandaloneIdentityFilesNone)
	t.Run("exec_with_IdentityFile_none_truncates_lower_tier_keys", testP5ExecIdentityFileNone)
	t.Run("mux_daemon_truncates_IdentityFiles_and_isTargetOnly_fails_closed", testP5MuxDaemonIdentityTruncationAndFailClosed)
}

func testP5PostNoneOptionNoLeak(t *testing.T) {
	opts := NewSshOptions()
	c := newCmdSshWithOptions(opts)
	if err := c.ParseFlags([]string{"-o", "IdentityFile=none", "-o", "IdentityFile=/tmp/after_none", "web"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	if err := opts.Complete(c, c.Flags().Args()); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if !slices.Equal(opts.IdentityFiles, []string{"none"}) {
		t.Fatalf("opts.IdentityFiles = %v, want [none]", opts.IdentityFiles)
	}
	if opts.IdentityFile != "" {
		t.Fatalf("opts.IdentityFile = %q, want empty (post-none key must not overwrite)", opts.IdentityFile)
	}
	if got := opts.absIdentityFiles(); !slices.Equal(got, []string{"none"}) {
		t.Fatalf("opts.absIdentityFiles() = %v, want [none]", got)
	}

	// Syntax errors after IdentityFile=none must still fail closed.
	badOpts := NewSshOptions()
	bc := newCmdSshWithOptions(badOpts)
	if err := bc.ParseFlags([]string{"-o", "IdentityFile=none", "-o", "IdentityFile=/tmp/bad_%k", "web"}); err != nil {
		t.Fatalf("ParseFlags(bad): %v", err)
	}
	if err := badOpts.Complete(bc, bc.Flags().Args()); err == nil {
		t.Fatal("expected invalid IdentityFile syntax after none to fail closed")
	}
}

func testP5StandaloneIdentityFilesNone(t *testing.T) {
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader("Host edge\n  HostName 10.0.0.5\n  User ops\n  IdentityFile /tmp/ssh_cfg_key\n"))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	prov := config.NewProviderWithOpenSSHParser(&config.Configuration{}, parser)

	opts := NewSshOptions()
	opts.IdentityFiles = []string{"none"} // no -o IdentityFile=, no muxDaemonMode
	sessionOpts, err := opts.toSessionControlOptions()
	if err != nil {
		t.Fatalf("toSessionControlOptions: %v", err)
	}
	adp := adapter.NewSSHAdapter(prov)
	pol, err := adp.Resolve(t.Context(), adapter.ResolveRequest{NodeID: config.OpenSSHNodePrefix + "edge", SessionControl: &sessionOpts})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	eff := pol.Options()
	if !slices.Equal(eff.IdentityFiles(), []string{"none"}) {
		t.Fatalf("Resolve IdentityFiles = %v, want [none] (lower-tier key leaked)", eff.IdentityFiles())
	}
}

func testP5ExecIdentityFileNone(t *testing.T) {
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader("Host edge\n  HostName 10.0.0.5\n  User ops\n  IdentityFile /tmp/ssh_cfg_key\n"))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	prov := config.NewProviderWithOpenSSHParser(cfg, parser)

	execOpts := NewExecOptions()
	execCmd := newCmdExecWithOptions(execOpts)
	if err := execCmd.ParseFlags([]string{"-o", "IdentityFile=none", "edge", "--", "id"}); err != nil {
		t.Fatalf("exec ParseFlags: %v", err)
	}
	if err := execOpts.Complete(execCmd, execCmd.Flags().Args()); err != nil {
		t.Fatalf("exec Complete: %v", err)
	}
	if err := execOpts.Validate(); err != nil {
		t.Fatalf("exec Validate: %v", err)
	}
	tasks := []execHostTask{{nodeID: config.OpenSSHNodePrefix + "edge", host: "edge", originalHost: "edge"}}
	adpOpts, err := execOpts.buildAdapterOptions(tasks, cfg, prov)
	if err != nil {
		t.Fatalf("exec buildAdapterOptions: %v", err)
	}
	adp := adapter.NewSSHAdapter(prov, adpOpts...)
	clientCfg, err := adp.GetConfig(config.OpenSSHNodePrefix + "edge")
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if slices.Contains(clientCfg.KeyPaths, "/tmp/ssh_cfg_key") {
		t.Fatalf("exec leaked ~/.ssh/config IdentityFile despite -o IdentityFile=none: KeyPaths=%v", clientCfg.KeyPaths)
	}
	if clientCfg.Options == nil || !slices.Equal(clientCfg.Options.IdentityFiles(), []string{"none"}) {
		t.Fatalf("exec effective Options.IdentityFiles = %v, want [none]", clientCfg.Options.IdentityFiles())
	}
}

func testP5MuxDaemonIdentityTruncationAndFailClosed(t *testing.T) {
	opts := NewSshOptions()
	opts.Host = "edge"
	opts.IdentityFiles = []string{"/tmp/k1", "none", "/tmp/after"}
	got := opts.resolveMuxDaemonIdentityFiles("openssh:edge", nil, true)
	if !slices.Equal(got, []string{"/tmp/k1", "none"}) {
		t.Fatalf("resolveMuxDaemonIdentityFiles = %v, want [/tmp/k1 none]", got)
	}

	child := NewSshOptions()
	if err := child.applyMuxDaemonSpec(MuxDaemonSpec{
		Version:       muxDaemonSpecVersion,
		TargetHost:    "edge",
		ControlPath:   filepath.Join(t.TempDir(), "m.sock"),
		ControlMaster: ssh.ControlMasterYes,
		IdentityFiles: []string{"none", "/tmp/after"},
	}); err != nil {
		t.Fatalf("applyMuxDaemonSpec: %v", err)
	}
	if !slices.Equal(child.IdentityFiles, []string{"none"}) {
		t.Fatalf("applyMuxDaemonSpec IdentityFiles = %v, want [none]", child.IdentityFiles)
	}

	for _, malformed := range []string{"", "   ", "NoDelimiter", "=val", "ServerAliveInterval=", "StrictHostKeyChecking=", "UnknownOption=1"} {
		if targetOnly, _ := isTargetOnlyMuxDaemonOption(malformed); !targetOnly {
			t.Errorf("isTargetOnlyMuxDaemonOption(%q) = false, want true (fail closed)", malformed)
		}
	}
	for _, connWide := range []string{"StrictHostKeyChecking=yes", "ConnectTimeout=5", "BatchMode=yes", "UserKnownHostsFile=/tmp/kh"} {
		if targetOnly, err := isTargetOnlyMuxDaemonOption(connWide); err != nil || targetOnly {
			t.Errorf("isTargetOnlyMuxDaemonOption(%q) = (%v, %v), want (false, nil) (connection-wide)", connWide, targetOnly, err)
		}
	}
}

// R2/R5: SCP local path component hardening, unsafe remote dir fail-closed, and fail-closed exclude errors.
func TestP5_SCPLocalPathComponentHardeningAndUnsafeDirFailClosed(t *testing.T) {
	t.Run("fsx_ValidateLocalComponent_matrix", func(t *testing.T) {
		unsafeCases := []string{
			"", ".", "..", "a/b", `a\b`, "/abs", `\abs`,
			"file:stream", "C:drive", "foo:bar:$DATA",
			"a*b", "a?b", `a"b`, "a<b", "a>b", "a|b",
			"a\x00b", "a\nb", "a\rb", "a\tb", "a\x1fb", "a\x7fb",
			"trailing.", "trailing..", "trailing ",
			"CON", "con", "PRN", "AUX", "NUL",
			"COM1", "com9", "LPT1", "lpt9",
			"COM\u00b9", "LPT\u00b3",
			"CON.txt", "nul.tar.gz", "COM3.log", "LPT2.bak", "CON .txt",
		}
		for _, name := range unsafeCases {
			if err := fsx.ValidateLocalComponent(name); err == nil {
				t.Errorf("fsx.ValidateLocalComponent(%q) = nil, want error", name)
			}
		}
		safeCases := []string{
			"release", "app.log", ".hidden", "v1.2-rc1",
			"my file.txt", "console", "COM0", "LPT0", "null.txt",
		}
		for _, name := range safeCases {
			if err := fsx.ValidateLocalComponent(name); err != nil {
				t.Errorf("fsx.ValidateLocalComponent(%q) unexpected error: %v", name, err)
			}
		}
	})

	t.Run("ParseRemoteDownloadPath_contentsOnly_matrix", func(t *testing.T) {
		for _, allowed := range []string{"/", "///", ".", "./", "sub/."} {
			_, contentsOnly, err := sftp.ParseRemoteDownloadPath(allowed)
			if err != nil || !contentsOnly {
				t.Errorf("ParseRemoteDownloadPath(%q) = (contentsOnly=%v, err=%v), want (true, nil)", allowed, contentsOnly, err)
			}
		}
		for _, rejected := range []string{"", "..", "/tmp/.."} {
			if _, _, err := sftp.ParseRemoteDownloadPath(rejected); err == nil {
				t.Errorf("ParseRemoteDownloadPath(%q) = nil, want error", rejected)
			}
		}
		for _, named := range []string{"/tmp/CON", "/tmp/release"} {
			_, contentsOnly, err := sftp.ParseRemoteDownloadPath(named)
			if err != nil || contentsOnly {
				t.Errorf("ParseRemoteDownloadPath(%q) = (contentsOnly=%v, err=%v), want (false, nil)", named, contentsOnly, err)
			}
		}
	})

	t.Run("unsafe_remote_directory_name_fails_closed", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Windows filesystem forbids creating local fixture directories named CON")
		}
		fixture := newSCPTransferFixture(t)
		unsafeDirName := "CON"
		remoteUnsafeDir := filepath.Join(fixture.home, unsafeDirName)
		if err := os.MkdirAll(remoteUnsafeDir, 0o700); err != nil {
			t.Fatal(err)
		}
		writeSCPTestFile(t, filepath.Join(remoteUnsafeDir, "secret.txt"), "do-not-dump")

		localDestDir := t.TempDir()
		options := NewScpOptions()
		options.Recursive = true
		options.Force = true
		err := options.runDownload(fixture.ctx, PathInfo{Host: "scp-test", Path: "~/" + unsafeDirName}, localDestDir, fixture.repo, fixture.connector)
		if err == nil || !strings.Contains(err.Error(), "unsafe remote filename") {
			t.Fatalf("runDownload unsafe dir %q error = %v, want unsafe remote filename error", unsafeDirName, err)
		}
		if entries, readErr := os.ReadDir(localDestDir); readErr != nil || len(entries) != 0 {
			t.Fatalf("localDestDir polluted after unsafe remote dir error: entries=%v err=%v", entries, readErr)
		}
	})
}

func TestP5_SCPExcludeErrorsPropagatedNotSwallowed(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	brokenProv := config.NewProviderWithOpenSSHParser(cfg, config.NewBrokenOpenSSHParser(errors.New("broken ssh_config")))

	o := NewScpOptions()
	o.Host = "web-1,web-2"
	o.Exclude = []string{"web-1"}
	o.Source = "./local.txt"
	o.Dest = "/tmp/remote.txt"

	// 1. isCollectedPathExcluded must return the error instead of swallowing it as false.
	excluded, err := o.isCollectedPathExcluded(brokenProv, map[string]struct{}{"web-1": {}}, PathInfo{Host: "web-1", IsRemote: true})
	if err == nil {
		t.Fatalf("isCollectedPathExcluded swallowed broken provider error (excluded=%v)", excluded)
	}

	// 2. collectTargetPathsWithExcludesChecked must propagate isCollectedPathExcluded errors.
	if paths, err := o.collectTargetPathsWithExcludesChecked(brokenProv, map[string]struct{}{"web-1": {}}); err == nil {
		t.Fatalf("collectTargetPathsWithExcludesChecked swallowed exclude error, returned paths=%+v", paths)
	}

	// 3. collectTargetPaths must propagate resolveExcludes errors rather than returning unfiltered targets.
	if paths, err := o.collectTargetPaths(brokenProv); err == nil {
		t.Fatalf("collectTargetPaths swallowed resolveExcludes error, returned unfiltered paths=%+v", paths)
	}

	// 4. appendScpSessionAuthOverrides must fail closed.
	var adpOpts []adapter.Option
	if err := o.appendScpSessionAuthOverrides(&adpOpts, brokenProv, false, true); err == nil {
		t.Fatal("appendScpSessionAuthOverrides succeeded despite broken exclude resolution")
	}
}

// R8: cmd/init.go:loadOpenSSHHosts rejects non-regular files (except os.DevNull) and caps read size.
func TestP5_InitLoadOpenSSHHostsBoundedRegularFile(t *testing.T) {
	t.Parallel()
	t.Run("devnull_returns_empty_without_error", testP5InitDevNull)
	t.Run("directory_rejected", testP5InitDirectoryRejected)
	t.Run("non_regular_unix_devices_and_fifo_rejected", testP5InitNonRegularUnixRejected)
	t.Run("missing_file_preserves_ErrNotExist", testP5InitMissingPreservesErrNotExist)
	t.Run("oversized_file_rejected", testP5InitOversizedFileRejected)
}

func testP5InitDevNull(t *testing.T) {
	t.Parallel()
	hosts, err := loadOpenSSHHosts(os.DevNull, "ops")
	if err != nil {
		t.Fatalf("loadOpenSSHHosts(os.DevNull) error = %v, want nil", err)
	}
	if len(hosts) != 0 {
		t.Fatalf("loadOpenSSHHosts(os.DevNull) = %+v, want empty", hosts)
	}
}

func testP5InitDirectoryRejected(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if _, err := loadOpenSSHHosts(dir, "ops"); err == nil {
		t.Fatal("loadOpenSSHHosts(directory) succeeded, want error")
	}
}

func testP5InitNonRegularUnixRejected(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("Unix device/FIFO checks apply to non-Windows platforms")
	}
	if _, err := os.Stat("/dev/zero"); err == nil {
		if _, err := loadOpenSSHHosts("/dev/zero", "ops"); err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("loadOpenSSHHosts(/dev/zero) err = %v, want regular file error", err)
		}
	}
	dir := t.TempDir()
	nullLink := filepath.Join(dir, "null_link")
	if err := os.Symlink(os.DevNull, nullLink); err == nil {
		hosts, err := loadOpenSSHHosts(nullLink, "ops")
		if err != nil || len(hosts) != 0 {
			t.Fatalf("loadOpenSSHHosts(symlink->/dev/null) = (%v, %v), want (empty, nil)", hosts, err)
		}
	}
	if mkfifoPath, err := exec.LookPath("mkfifo"); err == nil {
		fifoPath := filepath.Join(dir, "ssh_config.fifo")
		if out, mkErr := exec.Command(mkfifoPath, fifoPath).CombinedOutput(); mkErr != nil {
			t.Fatalf("mkfifo failed: %v (%s)", mkErr, string(out))
		}
		if _, err := loadOpenSSHHosts(fifoPath, "ops"); err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("loadOpenSSHHosts(fifo) err = %v, want non-blocking regular file error", err)
		}
	}
}

func testP5InitMissingPreservesErrNotExist(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	_, err := loadOpenSSHHosts(missing, "ops")
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("loadOpenSSHHosts(missing) err = %v, want wrapped os.ErrNotExist", err)
	}
}

func testP5InitOversizedFileRejected(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	smallPath := filepath.Join(dir, "small_over_limit")
	if err := os.WriteFile(smallPath, bytes.Repeat([]byte("#"), 128), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOpenSSHHostsWithLimit(smallPath, "ops", 64); err == nil || !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Fatalf("loadOpenSSHHostsWithLimit(128, 64) err = %v, want exceeds maximum size error", err)
	}

	// Also verify the real 16 MiB default cap via a sparse file without allocating 16 MiB in RAM.
	sparsePath := filepath.Join(dir, "sparse_over_16mib")
	f, err := os.OpenFile(sparsePath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxInitOpenSSHConfigBytes + 1); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOpenSSHHosts(sparsePath, "ops"); err == nil || !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Fatalf("loadOpenSSHHosts(16MiB+1) err = %v, want exceeds maximum size error", err)
	}
}
