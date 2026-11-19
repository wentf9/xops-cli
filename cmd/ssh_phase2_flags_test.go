package cmd

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
)

func TestPhase2Flags_RegistrationAndRouting(t *testing.T) {
	root := newRootCmd()
	initRootFlags(root)
	registerCommands(root)

	sshCmd, _, err := root.Find([]string{"ssh"})
	if err != nil {
		t.Fatalf("find ssh: %v", err)
	}
	if f := sshCmd.Flags().ShorthandLookup("s"); f == nil || f.Name != "subsystem" {
		t.Fatalf("ssh -s should be --subsystem, got %+v", f)
	}
	if f := sshCmd.Flags().ShorthandLookup("e"); f == nil || f.Name != "escape-char" {
		t.Fatalf("ssh -e should be --escape-char, got %+v", f)
	}

	for _, sub := range []string{"scp", "sftp", "exec"} {
		c, _, _ := root.Find([]string{sub})
		if f := c.Flags().ShorthandLookup("s"); f != nil {
			t.Fatalf("%s must not register -s, got %+v", sub, f)
		}
		if f := c.Flags().ShorthandLookup("e"); f != nil {
			t.Fatalf("%s must not register -e, got %+v", sub, f)
		}
	}

	got := normalizeCommandArgs(root, []string{"ssh", "-s", "-e", "^A", "myhost", "sftp"})
	want := []string{"ssh", "-s", "-e", "^A", "myhost", "--", "sftp"}
	if !slices.Equal(got, want) {
		t.Fatalf("normalizeCommandArgs() = %v, want %v", got, want)
	}
}

func TestPhase2Flags_SubsystemValidation(t *testing.T) {
	t.Run("requires non-empty subsystem name", func(t *testing.T) {
		opts := NewSshOptions()
		opts.Host = "myhost"
		opts.Subsystem = true
		opts.parsedArgs = true
		if err := opts.Validate(); err == nil {
			t.Fatalf("expected error when -s has no subsystem name")
		}
	})

	t.Run("rejects incompatible flags", func(t *testing.T) {
		cases := []struct {
			name  string
			setup func(*SshOptions)
		}{
			{name: "-N", setup: func(o *SshOptions) { o.NoCmd = true }},
			{name: "-W", setup: func(o *SshOptions) { o.StdioForward = "127.0.0.1:80" }},
			{name: "--sudo", setup: func(o *SshOptions) { o.Sudo = true }},
			{name: "stdinScript", setup: func(o *SshOptions) { o.stdinScript = true }},
			{name: "--no-login", setup: func(o *SshOptions) { o.NoLoginShell = true }},
			{name: "--interpreter", setup: func(o *SshOptions) { o.execution.interpreter = "sh" }},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				opts := NewSshOptions()
				opts.Host = "myhost"
				opts.Subsystem = true
				opts.Command = "sftp"
				opts.parsedArgs = true
				tc.setup(opts)
				if err := opts.Validate(); err == nil {
					t.Fatalf("expected error combining -s with %s", tc.name)
				}
			})
		}
	})

	t.Run("accepts valid subsystem invocation", func(t *testing.T) {
		opts := NewSshOptions()
		opts.Host = "myhost"
		opts.Subsystem = true
		opts.Command = "sftp"
		opts.parsedArgs = true
		if err := opts.Validate(); err != nil {
			t.Fatalf("Validate() unexpected error: %v", err)
		}
	})
}

func TestPhase2Flags_MuxDaemonClearsSubsystemAndEscapeChar(t *testing.T) {
	opts := NewSshOptions()
	opts.Subsystem = true
	opts.EscapeCharSpec = "^A"
	opts.Command = "sftp"
	opts.normalizeForMuxDaemon()
	if opts.Subsystem || opts.EscapeCharSpec != "" || opts.Command != "" || !opts.NoCmd {
		t.Fatalf("normalizeForMuxDaemon did not clear session fields: %+v", opts)
	}
}

func TestPhase2Flags_EscapeCharTier1OverrideAndValidation(t *testing.T) {
	t.Run("-e overrides -o EscapeChar", func(t *testing.T) {
		opts := NewSshOptions()
		opts.Host = "myhost"
		opts.parsedArgs = true
		opts.control.Options = []string{"EscapeChar=~"}
		opts.EscapeCharSpec = "^A"

		ctrl, err := opts.toSessionControlOptions()
		if err != nil {
			t.Fatalf("toSessionControlOptions() error = %v", err)
		}
		if got := ctrl.ToSSHOptions().EscapeChar(); got != "^A" {
			t.Fatalf("EscapeChar() = %q, want %q", got, "^A")
		}
	})

	t.Run("invalid -e fails validation", func(t *testing.T) {
		opts := NewSshOptions()
		opts.Host = "myhost"
		opts.parsedArgs = true
		opts.EscapeCharSpec = "invalid-escape"
		if err := opts.Validate(); err == nil {
			t.Fatalf("expected error for invalid -e EscapeChar")
		}
	})
}

func TestPhase2Flags_SubsystemAllocatePTY(t *testing.T) {
	t.Run("default no PTY for subsystem", func(t *testing.T) {
		opts := NewSshOptions()
		opts.Subsystem = true
		opts.Command = "sftp"
		if opts.subsystemAllocatePTY(strings.NewReader("")) {
			t.Fatalf("expected subsystemAllocatePTY=false by default")
		}
	})

	t.Run("RequestTTY=yes without terminal does not allocate PTY", func(t *testing.T) {
		opts := NewSshOptions()
		opts.Subsystem = true
		opts.Command = "sftp"
		opts.ForceTTYCount = 1
		if opts.subsystemAllocatePTY(strings.NewReader("")) {
			t.Fatalf("expected subsystemAllocatePTY=false when stdin is not a terminal")
		}
	})

	t.Run("-t -t / RequestTTY=force allocates PTY even without terminal", func(t *testing.T) {
		opts := NewSshOptions()
		opts.Subsystem = true
		opts.Command = "sftp"
		opts.ForceTTYCount = 2
		if !opts.subsystemAllocatePTY(strings.NewReader("")) {
			t.Fatalf("expected subsystemAllocatePTY=true for -t -t")
		}
	})
}

func TestPhase2Flags_ResolveEffectiveRemoteCommand(t *testing.T) {
	target := ssh.TargetContext{
		Host:         "10.0.0.10",
		OriginalHost: "web-prod",
		Port:         2222,
		User:         "deploy",
	}

	t.Run("expands RemoteCommand when no CLI command", func(t *testing.T) {
		opts := NewSshOptions()
		opts.control.Options = []string{"RemoteCommand=echo %r@%h:%p %%"}
		got, err := opts.resolveEffectiveRemoteCommand(target)
		if err != nil {
			t.Fatalf("resolveEffectiveRemoteCommand() error = %v", err)
		}
		if got != "echo deploy@10.0.0.10:2222 %" {
			t.Fatalf("resolveEffectiveRemoteCommand() = %q, want %q", got, "echo deploy@10.0.0.10:2222 %")
		}
	})

	t.Run("RemoteCommand=none clears lower tier RemoteCommand", func(t *testing.T) {
		opts := NewSshOptions()
		sshOpts, err := ssh.NewOptions()
		if err != nil {
			t.Fatalf("NewOptions() error = %v", err)
		}
		if err := sshOpts.Set(ssh.OptionRemoteCommand, "none"); err != nil {
			t.Fatalf("Set(RemoteCommand=none) error = %v", err)
		}
		opts.effectiveSSHOptions = sshOpts
		got, err := opts.resolveEffectiveRemoteCommand(target)
		if err != nil {
			t.Fatalf("resolveEffectiveRemoteCommand() error = %v", err)
		}
		if got != "" {
			t.Fatalf("expected empty RemoteCommand for none, got %q", got)
		}
	})

	t.Run("suppressed by CLI command, -N, -W, -s, stdinScript", func(t *testing.T) {
		cases := []struct {
			name  string
			setup func(*SshOptions)
		}{
			{name: "CLI command", setup: func(o *SshOptions) { o.Command = "uname -a" }},
			{name: "-N", setup: func(o *SshOptions) { o.NoCmd = true }},
			{name: "-W", setup: func(o *SshOptions) { o.StdioForward = "127.0.0.1:80" }},
			{name: "-s", setup: func(o *SshOptions) { o.Subsystem = true }},
			{name: "stdinScript", setup: func(o *SshOptions) { o.stdinScript = true }},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				opts := NewSshOptions()
				opts.control.Options = []string{"RemoteCommand=top -b"}
				tc.setup(opts)
				got, err := opts.resolveEffectiveRemoteCommand(target)
				if err != nil {
					t.Fatalf("resolveEffectiveRemoteCommand() error = %v", err)
				}
				if got != "" {
					t.Fatalf("expected RemoteCommand suppressed for %s, got %q", tc.name, got)
				}
			})
		}
	})
}

func TestPhase2Flags_MuxDaemonStripsOptionClassSession(t *testing.T) {
	t.Setenv("XOPS_CLI_SSH_MUX_DAEMON", "true")

	openSSH := `
Host mux-target
    HostName 10.0.0.20
    User ops
    SendEnv LANG
    SetEnv FOO=bar
    RemoteCommand echo hi
    EscapeChar ^
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(openSSH))
	if err != nil {
		t.Fatalf("parse OpenSSH config failed: %v", err)
	}
	provider := config.NewProviderWithOpenSSHParser(nil, parser)

	opts := NewSshOptions()
	opts.Host = config.OpenSSHNodePrefix + "mux-target"
	opts.control.Options = []string{"SendEnv=LC_ALL", "SetEnv=BAZ=qux", "RemoteCommand=ls", "EscapeChar=~", "ConnectTimeout=5"}

	eff, err := opts.resolveAndCacheSessionOptions(provider, opts.Host)
	if err != nil {
		t.Fatalf("resolveAndCacheSessionOptions() error = %v", err)
	}
	if len(eff.SendEnvPatterns()) != 0 || len(eff.SetEnvDirectives()) != 0 || eff.RemoteCommand() != "" || eff.EscapeChar() != "" {
		t.Fatalf("expected OptionClassSession stripped in mux daemon child, got sendenv=%v setenv=%v rc=%q escape=%q",
			eff.SendEnvPatterns(), eff.SetEnvDirectives(), eff.RemoteCommand(), eff.EscapeChar())
	}
	if eff.Get(ssh.OptionConnectTimeout) != "5" {
		t.Fatalf("expected transport option ConnectTimeout=5 preserved, got %q", eff.Get(ssh.OptionConnectTimeout))
	}

	spec := opts.buildMuxDaemonSpec(opts.Host, "/tmp/phase2.sock", nil)
	if !slices.Equal(spec.Options, []string{"ConnectTimeout=5"}) {
		t.Fatalf("buildMuxDaemonSpec().Options = %v, want [ConnectTimeout=5]", spec.Options)
	}
}

func TestPhase2Flags_SendEnvDenylistAndSetEnvOverride(t *testing.T) {
	opts, err := ssh.NewOptions()
	if err != nil {
		t.Fatalf("NewOptions() error = %v", err)
	}
	if err := opts.Set(ssh.OptionSendEnv, "*"); err != nil {
		t.Fatalf("Set(SendEnv) error = %v", err)
	}
	if err := opts.Set(ssh.OptionSetEnv, "LANG=C.UTF-8 FOO=override"); err != nil {
		t.Fatalf("Set(SetEnv) error = %v", err)
	}
	envVars, err := ssh.ResolveSessionEnv(opts, func() []string {
		return []string{
			"GITHUB_TOKEN=ghp_secret",
			"XOPS_SECRET=secret",
			"LD_PRELOAD=/tmp/evil.so",
			"SSH_AUTH_SOCK=/tmp/agent.sock",
			"LANG=en_US.UTF-8",
			"FOO=from_host",
			"MY_APP_ENV=prod",
		}
	})
	if err != nil {
		t.Fatalf("ResolveSessionEnv() error = %v", err)
	}
	got := make(map[string]string, len(envVars))
	for _, ev := range envVars {
		got[ev.Name] = ev.Value
	}
	for _, blocked := range []string{"GITHUB_TOKEN", "XOPS_SECRET", "LD_PRELOAD", "SSH_AUTH_SOCK"} {
		if _, ok := got[blocked]; ok {
			t.Fatalf("denylisted env %s must never be sent via SendEnv *", blocked)
		}
	}
	if got["MY_APP_ENV"] != "prod" {
		t.Fatalf("expected MY_APP_ENV=prod forwarded, got %q", got["MY_APP_ENV"])
	}
	if got["LANG"] != "C.UTF-8" || got["FOO"] != "override" {
		t.Fatalf("expected SetEnv override to win, got LANG=%q FOO=%q", got["LANG"], got["FOO"])
	}
}

func TestPhase2Flags_SubsystemWithPipedStdinAndPostResolutionSessionTypeNone(t *testing.T) {
	t.Run("piped stdin does not trigger stdinScript when -s is set", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("os.Pipe() error = %v", err)
		}
		defer func() {
			_ = r.Close()
			_ = w.Close()
		}()
		origStdin := os.Stdin
		os.Stdin = r
		defer func() { os.Stdin = origStdin }()

		opts := NewSshOptions()
		sshCmd := newCmdSshWithOptions(opts)
		opts.Subsystem = true
		if err := opts.Complete(sshCmd, []string{"myhost", "sftp"}); err != nil {
			t.Fatalf("Complete() error = %v", err)
		}
		if opts.stdinScript {
			t.Fatalf("expected stdinScript=false when -s is set with piped stdin")
		}
		if err := opts.Validate(); err != nil {
			t.Fatalf("Validate() unexpected error with piped stdin and -s: %v", err)
		}
	})

	t.Run("post-resolution SessionType=none rejects -s", func(t *testing.T) {
		opts := NewSshOptions()
		opts.Host = "myhost"
		opts.Subsystem = true
		opts.Command = "sftp"
		opts.parsedArgs = true
		eff, err := ssh.NewOptions()
		if err != nil {
			t.Fatalf("NewOptions() error = %v", err)
		}
		if err := eff.Set(ssh.OptionSessionType, "none"); err != nil {
			t.Fatalf("Set(SessionType=none) error = %v", err)
		}
		opts.effectiveSSHOptions = eff
		if err := opts.validatePostResolutionSessionInvariants(); err == nil {
			t.Fatalf("expected validatePostResolutionSessionInvariants() to reject -s with SessionType=none")
		}
	})
}

func TestPhase2Flags_BackgroundWithRemoteCommand(t *testing.T) {
	openSSH := `
Host bg-rc
    HostName 10.0.0.30
    User ops
    ForkAfterAuthentication yes
    RemoteCommand sleep 5

Host bg-none
    HostName 10.0.0.31
    User ops
    ForkAfterAuthentication yes
    RemoteCommand none
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(openSSH))
	if err != nil {
		t.Fatalf("parse OpenSSH config failed: %v", err)
	}
	provider := config.NewProviderWithOpenSSHParser(nil, parser)

	t.Run("-f with -o RemoteCommand passes Validate", func(t *testing.T) {
		opts := NewSshOptions()
		opts.BgRun = true
		opts.Host = "10.0.0.30"
		opts.parsedArgs = true
		opts.control.Options = []string{"RemoteCommand=sleep 5"}
		if err := opts.Validate(); err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
	})

	t.Run("Tier 4 ForkAfterAuthentication=yes with RemoteCommand passes post-resolution", func(t *testing.T) {
		opts := NewSshOptions()
		opts.Host = config.OpenSSHNodePrefix + "bg-rc"
		opts.parsedArgs = true
		if err := opts.Validate(); err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
		if _, err := opts.resolveAndCacheSessionOptions(provider, opts.Host); err != nil {
			t.Fatalf("resolveAndCacheSessionOptions() error = %v", err)
		}
		if err := opts.validatePostResolutionSessionInvariants(); err != nil {
			t.Fatalf("validatePostResolutionSessionInvariants() error = %v", err)
		}
	})

	t.Run("Tier 4 ForkAfterAuthentication=yes with RemoteCommand=none fails post-resolution validation", func(t *testing.T) {
		opts := NewSshOptions()
		opts.Host = config.OpenSSHNodePrefix + "bg-none"
		opts.parsedArgs = true
		if err := opts.Validate(); err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
		if _, err := opts.resolveAndCacheSessionOptions(provider, opts.Host); err != nil {
			t.Fatalf("resolveAndCacheSessionOptions() error = %v", err)
		}
		if err := opts.validatePostResolutionSessionInvariants(); err == nil {
			t.Fatalf("expected validatePostResolutionSessionInvariants() to fail when RemoteCommand=none")
		}
	})
}
