package adapter

import (
	"errors"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestAdapter_Phase5LocalExecGateAndFencing(t *testing.T) {
	openSSH := `
Host edge
    HostName 10.10.0.5
    User ops
    ProxyCommand nc -X 5 -x 127.0.0.1:1080 %h %p
    LocalCommand echo connected-%n
    PermitLocalCommand yes

Host passive-local
    HostName 10.10.0.6
    User ops
    ProxyCommand none
    LocalCommand echo passive
    PermitLocalCommand no
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(openSSH))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader() error = %v", err)
	}
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	cfg.Hosts.Set("h1", models.Host{Address: "192.168.1.50", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("edge", models.Node{HostRef: "h1", IdentityRef: "id1"})
	provider := config.NewProviderWithOpenSSHParser(cfg, parser)

	t.Run("non-interactive adapter fails closed on active ProxyCommand", func(t *testing.T) {
		nonInt := NewNonInteractiveSSHAdapter(provider)
		_, err := nonInt.Resolve(t.Context(), ResolveRequest{NodeID: config.OpenSSHNodePrefix + "edge"})
		if !errors.Is(err, ErrLocalExecutionDisabled) {
			t.Fatalf("expected ErrLocalExecutionDisabled, got %v", err)
		}
	})

	t.Run("non-interactive adapter strips LocalCommand/PermitLocalCommand and allows ProxyCommand=none", func(t *testing.T) {
		nonInt := NewNonInteractiveSSHAdapter(provider)
		pol, err := nonInt.Resolve(t.Context(), ResolveRequest{NodeID: config.OpenSSHNodePrefix + "passive-local"})
		if err != nil {
			t.Fatalf("Resolve(passive-local) unexpected error = %v", err)
		}
		if opts := pol.Options(); opts != nil && (opts.LocalCommand() != "" || opts.PermitLocalCommand() || opts.ActiveProxyCommand() != "") {
			t.Fatalf("expected local_exec options stripped when localExecution=false, got %+v", opts)
		}
	})

	t.Run("managed XOps node never inherits local_exec from Tier 4", func(t *testing.T) {
		fg := NewSSHAdapter(provider, WithLocalExecution(true))
		pol, err := fg.Resolve(t.Context(), ResolveRequest{NodeID: "edge"})
		if err != nil {
			t.Fatalf("Resolve(managed edge) error = %v", err)
		}
		if opts := pol.Options(); opts != nil && (opts.ActiveProxyCommand() != "" || opts.LocalCommand() != "" || opts.PermitLocalCommand()) {
			t.Fatalf("Gate 2 violation: managed node inherited Tier 4 local_exec: %+v", opts)
		}
	})

	t.Run("foreground adapter with WithLocalExecution(true) resolves virtual node local_exec", func(t *testing.T) {
		fg := NewSSHAdapter(provider, WithLocalExecution(true))
		pol, err := fg.Resolve(t.Context(), ResolveRequest{NodeID: config.OpenSSHNodePrefix + "edge"})
		if err != nil {
			t.Fatalf("Resolve(openssh:edge) error = %v", err)
		}
		opts := pol.Options()
		if opts == nil || opts.ActiveProxyCommand() != "nc -X 5 -x 127.0.0.1:1080 %h %p" {
			t.Fatalf("expected ProxyCommand resolved, got %+v", opts)
		}
		if opts.LocalCommand() != "echo connected-%n" || !opts.PermitLocalCommand() {
			t.Fatalf("expected LocalCommand+PermitLocalCommand resolved, got local=%q permit=%v", opts.LocalCommand(), opts.PermitLocalCommand())
		}
	})

	t.Run("WithLocalExecution(true)+WithNonInteractive(true) fails closed with ErrLocalExecutionDisabled", func(t *testing.T) {
		batchAdp := NewSSHAdapter(provider, WithLocalExecution(true), WithNonInteractive(true))
		_, err := batchAdp.Resolve(t.Context(), ResolveRequest{NodeID: config.OpenSSHNodePrefix + "edge"})
		if !errors.Is(err, ErrLocalExecutionDisabled) {
			t.Fatalf("expected ErrLocalExecutionDisabled when nonInteractive=true, got %v", err)
		}
	})
}

func TestAdapter_Phase5CrossTierProxyJumpVsProxyCommandPrecedence(t *testing.T) {
	openSSH := `
Host v-jump
    HostName 10.20.0.10
    User ops
    ProxyJump bastion

Host v-cmd
    HostName 10.20.0.11
    User ops
    ProxyCommand nc %h %p
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(openSSH))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader() error = %v", err)
	}
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	cfg.Hosts.Set("h1", models.Host{Address: "10.30.0.1", Port: 22})
	cfg.Hosts.Set("hb", models.Host{Address: "10.30.0.254", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("bastion", models.Node{HostRef: "hb", IdentityRef: "id1"})
	t2Cmd, _ := ssh.NewOptions()
	_ = t2Cmd.Set(ssh.OptionProxyCommand, "ssh -W %h:%p t2jump")
	cfg.Nodes.Set("m-cmd", models.Node{HostRef: "h1", IdentityRef: "id1", SSHOptions: t2Cmd})
	cfg.Nodes.Set("m-jump", models.Node{HostRef: "h1", IdentityRef: "id1", ProxyJump: "bastion"})

	t3Cmd, _ := ssh.NewOptions()
	_ = t3Cmd.Set(ssh.OptionProxyCommand, "nc -x 127.0.0.1:9050 %h %p")
	cfg.SSHOptions = t3Cmd

	provider := config.NewProviderWithOpenSSHParser(cfg, parser)

	t.Run("Tier 1 -J clears Tier 2 and Tier 3 ProxyCommand", func(t *testing.T) {
		adp := NewSSHAdapter(provider, WithLocalExecution(true), WithSessionAuthOverride("m-cmd", SessionAuth{
			ProxyJump: "bastion",
		}))
		clientCfg, err := adp.GetConfig("m-cmd")
		if err != nil {
			t.Fatalf("GetConfig() error = %v", err)
		}
		if clientCfg.ProxyJump != "bastion" {
			t.Fatalf("ProxyJump = %q, want %q", clientCfg.ProxyJump, "bastion")
		}
		if clientCfg.Options != nil && clientCfg.Options.ActiveProxyCommand() != "" {
			t.Fatalf("Tier 1 -J must clear lower-tier ProxyCommand, got %q", clientCfg.Options.ActiveProxyCommand())
		}
	})

	t.Run("Tier 1 -o ProxyCommand clears Tier 2 ProxyJump", func(t *testing.T) {
		cliOpts, err := ParseSessionOptions([]string{"ProxyCommand=ssh -W %h:%p cli-jump"}, "")
		if err != nil {
			t.Fatalf("ParseSessionOptions() error = %v", err)
		}
		adp := NewSSHAdapter(provider, WithLocalExecution(true), WithSessionControlOverride("m-jump", cliOpts))
		clientCfg, err := adp.GetConfig("m-jump")
		if err != nil {
			t.Fatalf("GetConfig() error = %v", err)
		}
		if clientCfg.ProxyJump != "" {
			t.Fatalf("Tier 1 -o ProxyCommand must clear Tier 2 ProxyJump, got %q", clientCfg.ProxyJump)
		}
		if clientCfg.Options == nil || clientCfg.Options.ActiveProxyCommand() != "ssh -W %h:%p cli-jump" {
			t.Fatalf("expected Tier 1 ProxyCommand, got %+v", clientCfg.Options)
		}
	})

	t.Run("Tier 2 ProxyJump clears Tier 3 ProxyCommand", func(t *testing.T) {
		adp := NewSSHAdapter(provider, WithLocalExecution(true))
		clientCfg, err := adp.GetConfig("m-jump")
		if err != nil {
			t.Fatalf("GetConfig() error = %v", err)
		}
		if clientCfg.ProxyJump != "bastion" {
			t.Fatalf("ProxyJump = %q, want %q", clientCfg.ProxyJump, "bastion")
		}
		if clientCfg.Options != nil && clientCfg.Options.ActiveProxyCommand() != "" {
			t.Fatalf("Tier 2 ProxyJump must clear Tier 3 ProxyCommand, got %q", clientCfg.Options.ActiveProxyCommand())
		}
	})

	t.Run("Tier 3 ProxyCommand clears Tier 4 ProxyJump on virtual node", func(t *testing.T) {
		adp := NewSSHAdapter(provider, WithLocalExecution(true))
		clientCfg, err := adp.GetConfig(config.OpenSSHNodePrefix + "v-jump")
		if err != nil {
			t.Fatalf("GetConfig() error = %v", err)
		}
		if clientCfg.ProxyJump != "" {
			t.Fatalf("Tier 3 ProxyCommand must clear Tier 4 ProxyJump, got %q", clientCfg.ProxyJump)
		}
		if clientCfg.Options == nil || clientCfg.Options.ActiveProxyCommand() != "nc -x 127.0.0.1:9050 %h %p" {
			t.Fatalf("expected Tier 3 ProxyCommand, got %+v", clientCfg.Options)
		}
	})
}

func TestAdapter_Phase5ProxyNonePrecedence(t *testing.T) {
	openSSH := `
Host v-jump
    HostName 10.20.0.10
    User ops
    ProxyJump bastion
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(openSSH))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader() error = %v", err)
	}
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	cfg.Hosts.Set("h1", models.Host{Address: "10.30.0.1", Port: 22})
	cfg.Hosts.Set("hb", models.Host{Address: "10.30.0.254", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("bastion", models.Node{HostRef: "hb", IdentityRef: "id1"})
	t2Cmd, _ := ssh.NewOptions()
	_ = t2Cmd.Set(ssh.OptionProxyCommand, "ssh -W %h:%p t2jump")
	cfg.Nodes.Set("m-cmd", models.Node{HostRef: "h1", IdentityRef: "id1", SSHOptions: t2Cmd})
	cfg.Nodes.Set("m-jump", models.Node{HostRef: "h1", IdentityRef: "id1", ProxyJump: "bastion"})
	provider := config.NewProviderWithOpenSSHParser(cfg, parser)

	t.Run("Tier 1 -J none preserves ProxyCommand", func(t *testing.T) {
		adp := NewSSHAdapter(provider, WithLocalExecution(true), WithSessionAuthOverride("m-cmd", SessionAuth{
			ProxyJump: "none",
		}))
		clientCfg, err := adp.GetConfig("m-cmd")
		if err != nil {
			t.Fatalf("GetConfig() error = %v", err)
		}
		if clientCfg.Options == nil || clientCfg.Options.ActiveProxyCommand() != "ssh -W %h:%p t2jump" {
			t.Fatalf("expected -J none to preserve ProxyCommand, got %+v", clientCfg.Options)
		}
	})

	t.Run("Tier 1 -J bastion clears Tier 1 -o ProxyCommand on merged options", func(t *testing.T) {
		cliOpts, err := ParseSessionOptions([]string{"ProxyCommand=nc %h %p"}, "")
		if err != nil {
			t.Fatalf("ParseSessionOptions() error = %v", err)
		}
		adp := NewSSHAdapter(provider, WithLocalExecution(true),
			WithSessionAuthOverride("m-cmd", SessionAuth{ProxyJump: "bastion"}),
			WithSessionControlOverride("m-cmd", cliOpts),
		)
		pol, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: "m-cmd", SessionControl: &cliOpts})
		if err != nil {
			t.Fatalf("Resolve() error = %v", err)
		}
		if opts := pol.Options(); opts != nil && opts.ActiveProxyCommand() != "" {
			t.Fatalf("expected Tier 1 -J bastion to clear ActiveProxyCommand, got %q", opts.ActiveProxyCommand())
		}
	})

	t.Run("Tier 1 -o ProxyCommand=none disables Tier 2 ProxyJump (OpenSSH semantics)", func(t *testing.T) {
		cliOpts, err := ParseSessionOptions([]string{"ProxyCommand=none"}, "")
		if err != nil {
			t.Fatalf("ParseSessionOptions() error = %v", err)
		}
		adp := NewSSHAdapter(provider, WithLocalExecution(true), WithSessionControlOverride("m-jump", cliOpts))
		clientCfg, err := adp.GetConfig("m-jump")
		if err != nil {
			t.Fatalf("GetConfig() error = %v", err)
		}
		if clientCfg.ProxyJump != "" {
			t.Fatalf("expected -o ProxyCommand=none to disable Tier 2 ProxyJump, got %q", clientCfg.ProxyJump)
		}
	})

	t.Run("Tier 3 ProxyCommand=none disables Tier 4 ProxyJump (OpenSSH semantics)", func(t *testing.T) {
		cfgNone := &config.Configuration{
			Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
			Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
			Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		}
		t3None, _ := ssh.NewOptions()
		_ = t3None.Set(ssh.OptionProxyCommand, "none")
		cfgNone.SSHOptions = t3None
		provNone := config.NewProviderWithOpenSSHParser(cfgNone, parser)
		adp := NewSSHAdapter(provNone, WithLocalExecution(true))
		clientCfg, err := adp.GetConfig(config.OpenSSHNodePrefix + "v-jump")
		if err != nil {
			t.Fatalf("GetConfig() error = %v", err)
		}
		if clientCfg.ProxyJump != "" {
			t.Fatalf("expected Tier 3 ProxyCommand=none to disable Tier 4 ProxyJump, got %q", clientCfg.ProxyJump)
		}
	})
}
