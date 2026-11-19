package cmd

import (
	"slices"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
)

func TestPhase3Flags_RegistrationRoutingAndPrecedence(t *testing.T) {
	root := newRootCmd()
	initRootFlags(root)
	registerCommands(root)

	sshCmd, _, err := root.Find([]string{"ssh"})
	if err != nil {
		t.Fatalf("find ssh: %v", err)
	}
	if f := sshCmd.Flags().ShorthandLookup("A"); f == nil || f.Name != "forward-agent" {
		t.Fatalf("ssh -A should be --forward-agent, got %+v", f)
	}
	if f := sshCmd.Flags().ShorthandLookup("a"); f == nil || f.Name != "no-forward-agent" {
		t.Fatalf("ssh -a should be --no-forward-agent, got %+v", f)
	}

	for _, sub := range []string{"scp", "sftp", "exec"} {
		c, _, _ := root.Find([]string{sub})
		if f := c.Flags().ShorthandLookup("A"); f != nil {
			t.Fatalf("%s must not register -A, got %+v", sub, f)
		}
		if f := c.Flags().ShorthandLookup("a"); f != nil {
			t.Fatalf("%s must not register -a, got %+v", sub, f)
		}
	}

	got := normalizeCommandArgs(root, []string{"ssh", "-A", "-a", "myhost", "uname", "-a"})
	want := []string{"ssh", "-A", "-a", "myhost", "--", "uname", "-a"}
	if !slices.Equal(got, want) {
		t.Fatalf("normalizeCommandArgs() = %v, want %v", got, want)
	}

	t.Run("-A -a last flag wins", func(t *testing.T) {
		opts := NewSshOptions()
		c := newCmdSshWithOptions(opts)
		if err := c.ParseFlags([]string{"-A", "-a"}); err != nil {
			t.Fatalf("ParseFlags(-A -a) error = %v", err)
		}
		if opts.ForwardAgentSpec != "no" {
			t.Fatalf("ForwardAgentSpec = %q, want %q", opts.ForwardAgentSpec, "no")
		}

		opts2 := NewSshOptions()
		c2 := newCmdSshWithOptions(opts2)
		if err := c2.ParseFlags([]string{"-a", "-A"}); err != nil {
			t.Fatalf("ParseFlags(-a -A) error = %v", err)
		}
		if opts2.ForwardAgentSpec != "yes" {
			t.Fatalf("ForwardAgentSpec = %q, want %q", opts2.ForwardAgentSpec, "yes")
		}
	})
}

func TestPhase3Flags_MuxDaemonClearsForwardAgentSpec(t *testing.T) {
	opts := NewSshOptions()
	opts.ForwardAgentSpec = "yes"
	opts.normalizeForMuxDaemon()
	if opts.ForwardAgentSpec != "" {
		t.Fatalf("normalizeForMuxDaemon() did not clear ForwardAgentSpec: %q", opts.ForwardAgentSpec)
	}
}

func TestPhase3Flags_ForwardAgentTier1OverridesAndCircuitBreaker(t *testing.T) {
	openSSH := `
Host agent-host
    HostName 10.0.0.40
    User ops
    ForwardAgent yes
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(openSSH))
	if err != nil {
		t.Fatalf("parse OpenSSH config failed: %v", err)
	}
	provider := config.NewProviderWithOpenSSHParser(nil, parser)

	t.Run("-a overrides -o ForwardAgent=yes and ~/.ssh/config ForwardAgent=yes", func(t *testing.T) {
		opts := NewSshOptions()
		opts.Host = config.OpenSSHNodePrefix + "agent-host"
		opts.parsedArgs = true
		opts.control.Options = []string{"ForwardAgent=yes"}
		opts.ForwardAgentSpec = "no"

		eff, err := opts.resolveAndCacheSessionOptions(provider, opts.Host)
		if err != nil {
			t.Fatalf("resolveAndCacheSessionOptions() error = %v", err)
		}
		if got := eff.ForwardAgent(); got != "no" {
			t.Fatalf("ForwardAgent() = %q, want %q", got, "no")
		}
	})

	t.Run("-A overrides -o ForwardAgent=no", func(t *testing.T) {
		opts := NewSshOptions()
		opts.Host = config.OpenSSHNodePrefix + "agent-host"
		opts.parsedArgs = true
		opts.control.Options = []string{"ForwardAgent=no"}
		opts.ForwardAgentSpec = "yes"

		eff, err := opts.resolveAndCacheSessionOptions(provider, opts.Host)
		if err != nil {
			t.Fatalf("resolveAndCacheSessionOptions() error = %v", err)
		}
		if got := eff.ForwardAgent(); got != "yes" {
			t.Fatalf("ForwardAgent() = %q, want %q", got, "yes")
		}
	})
}

func TestPhase3Flags_MuxDaemonForwardsCertAndAgentAuthWhileStrippingForwardAgent(t *testing.T) {
	opts := NewSshOptions()
	opts.Host = config.OpenSSHNodePrefix + "agent-host"
	opts.ForwardAgentSpec = "yes"
	opts.control.Options = []string{
		"CertificateFile=~/.ssh/id_ed25519-cert.pub",
		"IdentityAgent=/tmp/agent.sock",
		"ForwardAgent=yes",
		"ConnectTimeout=5",
	}

	spec := opts.buildMuxDaemonSpec(opts.Host, "/tmp/phase3.sock", nil)
	want := []string{
		"CertificateFile=~/.ssh/id_ed25519-cert.pub",
		"IdentityAgent=/tmp/agent.sock",
		"ConnectTimeout=5",
	}
	if !slices.Equal(spec.Options, want) {
		t.Fatalf("buildMuxDaemonSpec().Options = %v, want %v", spec.Options, want)
	}

	t.Setenv("XOPS_CLI_SSH_MUX_DAEMON", "true")
	openSSH := `
Host agent-host
    HostName 10.0.0.40
    User ops
    CertificateFile ~/.ssh/id_ed25519-cert.pub
    IdentityAgent /tmp/agent.sock
    ForwardAgent yes
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(openSSH))
	if err != nil {
		t.Fatalf("parse OpenSSH config failed: %v", err)
	}
	provider := config.NewProviderWithOpenSSHParser(nil, parser)
	eff, err := opts.resolveAndCacheSessionOptions(provider, opts.Host)
	if err != nil {
		t.Fatalf("resolveAndCacheSessionOptions() error = %v", err)
	}
	if eff.ForwardAgent() != "" {
		t.Fatalf("expected ForwardAgent stripped in mux daemon child, got %q", eff.ForwardAgent())
	}
	if len(eff.CertificateFiles()) != 1 || eff.IdentityAgent() != "/tmp/agent.sock" {
		t.Fatalf("expected CertificateFile and IdentityAgent preserved in mux daemon child, got certs=%v agent=%q",
			eff.CertificateFiles(), eff.IdentityAgent())
	}
}

func TestPhase3Flags_ExecScpSftpStripForwardAgent(t *testing.T) {
	openSSH := `
Host target
    HostName 10.0.0.50
    User ops
    ForwardAgent yes
    SendEnv LANG
    CertificateFile ~/.ssh/id_ed25519-cert.pub
    IdentityAgent /tmp/agent.sock
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(openSSH))
	if err != nil {
		t.Fatalf("parse OpenSSH config failed: %v", err)
	}
	provider := config.NewProviderWithOpenSSHParser(nil, parser)
	cliOpts, err := adapter.ParseOptionStrings([]string{"ForwardAgent=yes", "SendEnv=LC_ALL"})
	if err != nil {
		t.Fatalf("ParseOptionStrings() error = %v", err)
	}

	t.Run("exec adapter strips ForwardAgent while keeping SendEnv and auth options", func(t *testing.T) {
		adp := adapter.NewNonInteractiveSSHAdapter(provider, adapter.WithForwardOptions(false))
		opts, err := adp.ResolveSSHOptions(config.OpenSSHNodePrefix+"target", cliOpts)
		if err != nil {
			t.Fatalf("ResolveSSHOptions() error = %v", err)
		}
		if opts.ForwardAgent() != "" {
			t.Fatalf("expected ForwardAgent stripped for exec, got %q", opts.ForwardAgent())
		}
		if len(opts.SendEnvPatterns()) != 2 {
			t.Fatalf("expected SendEnv preserved for exec, got %v", opts.SendEnvPatterns())
		}
		if len(opts.CertificateFiles()) != 1 || opts.IdentityAgent() != "/tmp/agent.sock" {
			t.Fatalf("expected auth options preserved for exec, got certs=%v agent=%q", opts.CertificateFiles(), opts.IdentityAgent())
		}
	})

	t.Run("scp/sftp adapter strips ForwardAgent and SendEnv while keeping auth options", func(t *testing.T) {
		adp := adapter.NewSSHAdapter(provider, adapter.WithLocalExecution(true), adapter.WithSessionAndForwardOptions(false))
		opts, err := adp.ResolveSSHOptions(config.OpenSSHNodePrefix+"target", cliOpts)
		if err != nil {
			t.Fatalf("ResolveSSHOptions() error = %v", err)
		}
		if opts.ForwardAgent() != "" || len(opts.SendEnvPatterns()) != 0 {
			t.Fatalf("expected ForwardAgent and SendEnv stripped for scp/sftp, got forward=%q sendenv=%v",
				opts.ForwardAgent(), opts.SendEnvPatterns())
		}
		if len(opts.CertificateFiles()) != 1 || opts.IdentityAgent() != "/tmp/agent.sock" {
			t.Fatalf("expected auth options preserved for scp/sftp, got certs=%v agent=%q", opts.CertificateFiles(), opts.IdentityAgent())
		}
	})
}

func TestPhase3Flags_MuxDaemonPreservesGatewayPortsAndStreamLocalBind(t *testing.T) {
	t.Setenv("XOPS_CLI_SSH_MUX_DAEMON", "true")

	openSSH := `
Host mux-srv
    HostName 10.0.0.60
    User ops
    GatewayPorts clientspecified
    StreamLocalBindUnlink yes
    StreamLocalBindMask 0177
    ForwardAgent yes
    SendEnv LANG
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(openSSH))
	if err != nil {
		t.Fatalf("parse OpenSSH config failed: %v", err)
	}
	provider := config.NewProviderWithOpenSSHParser(nil, parser)

	opts := NewSshOptions()
	opts.Host = config.OpenSSHNodePrefix + "mux-srv"
	opts.parsedArgs = true
	opts.control.Options = []string{
		"GatewayPorts=clientspecified",
		"StreamLocalBindUnlink=yes",
		"StreamLocalBindMask=0177",
		"ForwardAgent=yes",
		"SendEnv=LC_ALL",
	}

	eff, err := opts.resolveAndCacheSessionOptions(provider, opts.Host)
	if err != nil {
		t.Fatalf("resolveAndCacheSessionOptions() error = %v", err)
	}
	if eff.Get(ssh.OptionGatewayPorts) != ssh.GatewayPortsClientSpecified {
		t.Fatalf("GatewayPorts = %q, want %q", eff.Get(ssh.OptionGatewayPorts), ssh.GatewayPortsClientSpecified)
	}
	if !eff.EffectiveStreamLocalBindUnlink() {
		t.Fatalf("expected StreamLocalBindUnlink=true preserved")
	}
	if mask, ok := eff.StreamLocalBindMask(); !ok || mask != 0o177 {
		t.Fatalf("StreamLocalBindMask = (%o, %v), want (0177, true)", mask, ok)
	}
	if eff.ForwardAgent() != "" || len(eff.SendEnvPatterns()) != 0 {
		t.Fatalf("expected ForwardAgent and SendEnv stripped, got forward=%q sendenv=%v", eff.ForwardAgent(), eff.SendEnvPatterns())
	}

	// Verify mux-daemon GetConfig adapter path preserves GatewayPorts/StreamLocalBind* while stripping ForwardAgent and SendEnv.
	sessionCtrl, err := opts.toSessionControlOptions()
	if err != nil {
		t.Fatalf("toSessionControlOptions() error = %v", err)
	}
	adp := adapter.NewSSHAdapter(
		provider,
		adapter.WithNonInteractive(true),
		adapter.WithSessionOptions(false),
		adapter.WithGlobalSessionControl(sessionCtrl),
	)
	cfg, err := adp.GetConfig(opts.Host)
	if err != nil {
		t.Fatalf("GetConfig() error = %v", err)
	}
	if cfg.Options.Get(ssh.OptionGatewayPorts) != ssh.GatewayPortsClientSpecified {
		t.Fatalf("GetConfig GatewayPorts = %q, want %q", cfg.Options.Get(ssh.OptionGatewayPorts), ssh.GatewayPortsClientSpecified)
	}
	if !cfg.Options.EffectiveStreamLocalBindUnlink() {
		t.Fatalf("GetConfig expected StreamLocalBindUnlink=true preserved")
	}
	if mask, ok := cfg.Options.StreamLocalBindMask(); !ok || mask != 0o177 {
		t.Fatalf("GetConfig StreamLocalBindMask = (%o, %v), want (0177, true)", mask, ok)
	}
	if cfg.Options.ForwardAgent() != "" || len(cfg.Options.SendEnvPatterns()) != 0 {
		t.Fatalf("GetConfig expected ForwardAgent and SendEnv stripped, got forward=%q sendenv=%v",
			cfg.Options.ForwardAgent(), cfg.Options.SendEnvPatterns())
	}
}
