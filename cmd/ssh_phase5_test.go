package cmd

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestPhase5_TargetSpecificLocalExecOptions(t *testing.T) {
	for _, opt := range []string{
		"ProxyCommand=nc %h %p",
		"proxy_command=nc %h %p",
		"LocalCommand=echo ok",
		"local_command=echo ok",
		"PermitLocalCommand=yes",
		"permit_local_command=yes",
	} {
		if !isTargetSpecificOption(opt) {
			t.Fatalf("isTargetSpecificOption(%q) = false, want true", opt)
		}
	}
}

func TestPhase5_ShouldSkipMasterHandoffForProxyCommand(t *testing.T) {
	opts := NewSshOptions()
	effActive, err := ssh.NewOptions()
	if err != nil {
		t.Fatalf("NewOptions() error = %v", err)
	}
	if err := effActive.Set(ssh.OptionProxyCommand, "nc %h %p"); err != nil {
		t.Fatalf("Set(ProxyCommand) error = %v", err)
	}
	opts.effectiveSSHOptions = effActive
	if !opts.shouldSkipMasterHandoff(t.Context(), nil, nil, "") {
		t.Fatalf("expected shouldSkipMasterHandoff=true when active ProxyCommand is set")
	}

	effNone, err := ssh.NewOptions()
	if err != nil {
		t.Fatalf("NewOptions() error = %v", err)
	}
	if err := effNone.Set(ssh.OptionProxyCommand, "none"); err != nil {
		t.Fatalf("Set(ProxyCommand=none) error = %v", err)
	}
	opts.effectiveSSHOptions = effNone
	if opts.shouldSkipMasterHandoff(t.Context(), nil, nil, "") {
		t.Fatalf("expected shouldSkipMasterHandoff=false when ProxyCommand=none")
	}

	// Jump hop with active ProxyCommand also skips master handoff.
	openSSH := `
Host jump-cmd
    HostName 10.0.0.2
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
	provider := config.NewProviderWithOpenSSHParser(cfg, parser)
	optsJump := NewSshOptions()
	optsJump.JumpHost = "jump-cmd"
	if !optsJump.shouldSkipMasterHandoff(t.Context(), nil, provider, "") {
		t.Fatalf("expected shouldSkipMasterHandoff=true when jump hop has active ProxyCommand")
	}
}

func TestPhase5_ResolveAndCacheSessionOptions_JumpOverridesProxyCommand(t *testing.T) {
	openSSH := `
Host edge
    HostName 10.0.0.10
    User ops
    ProxyCommand nc %h %p

Host bastion
    HostName 10.0.0.1
    User ops
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
	provider := config.NewProviderWithOpenSSHParser(cfg, parser)

	opts := NewSshOptions()
	opts.Host = "edge"
	opts.JumpHost = "bastion"
	opts.Target = config.ConnectionTarget{Selector: "edge", RawSelector: "edge"}
	eff, err := opts.resolveAndCacheSessionOptions(provider, config.OpenSSHNodePrefix+"edge")
	if err != nil {
		t.Fatalf("resolveAndCacheSessionOptions() error = %v", err)
	}
	if eff != nil && eff.ActiveProxyCommand() != "" {
		t.Fatalf("expected -J bastion to clear ProxyCommand in resolveAndCacheSessionOptions, got %q", eff.ActiveProxyCommand())
	}
}

type fakePostAuthLocalRunner struct {
	calls int
	err   error
}

func (f *fakePostAuthLocalRunner) RunPostAuthLocalCommand(_ context.Context) error {
	f.calls++
	return f.err
}

func TestPhase5_RunPostAuthLocalCommand(t *testing.T) {
	t.Run("ExitOnForwardFailure=yes returns error on LocalCommand failure", func(t *testing.T) {
		opts, _ := ssh.NewOptions()
		_ = opts.Set(ssh.OptionPermitLocalCommand, "yes")
		_ = opts.Set(ssh.OptionLocalCommand, "echo %h")
		_ = opts.Set(ssh.OptionExitOnForwardFailure, "yes")

		client := &fakePostAuthLocalRunner{err: errors.New("exit status 1")}
		var stderr bytes.Buffer
		err := runPostAuthLocalCommand(t.Context(), client, opts, &stderr, false)
		if err == nil {
			t.Fatalf("expected error when ExitOnForwardFailure=yes and LocalCommand fails")
		}
		if client.calls != 1 {
			t.Fatalf("RunPostAuthLocalCommand calls = %d, want 1", client.calls)
		}
	})

	t.Run("ExitOnForwardFailure=no warns to stderr and proceeds", func(t *testing.T) {
		opts, _ := ssh.NewOptions()
		_ = opts.Set(ssh.OptionPermitLocalCommand, "yes")
		_ = opts.Set(ssh.OptionLocalCommand, "echo %h")
		_ = opts.Set(ssh.OptionExitOnForwardFailure, "no")

		client := &fakePostAuthLocalRunner{err: errors.New("exit status 2")}
		var stderr bytes.Buffer
		err := runPostAuthLocalCommand(t.Context(), client, opts, &stderr, false)
		if err != nil {
			t.Fatalf("expected nil error when ExitOnForwardFailure=no, got %v", err)
		}
		if client.calls != 1 {
			t.Fatalf("RunPostAuthLocalCommand calls = %d, want 1", client.calls)
		}
		if !strings.Contains(stderr.String(), "Warning: LocalCommand failed") {
			t.Fatalf("expected warning on stderr, got %q", stderr.String())
		}
	})

	t.Run("PermitLocalCommand=no skips execution", func(t *testing.T) {
		opts, _ := ssh.NewOptions()
		_ = opts.Set(ssh.OptionPermitLocalCommand, "no")
		_ = opts.Set(ssh.OptionLocalCommand, "echo %h")

		client := &fakePostAuthLocalRunner{}
		if err := runPostAuthLocalCommand(t.Context(), client, opts, &bytes.Buffer{}, false); err != nil {
			t.Fatalf("unexpected error = %v", err)
		}
		if client.calls != 0 {
			t.Fatalf("expected LocalCommand NOT to run when PermitLocalCommand=no, got %d calls", client.calls)
		}
	})

	t.Run("background -f child skips LocalCommand", func(t *testing.T) {
		opts, _ := ssh.NewOptions()
		_ = opts.Set(ssh.OptionPermitLocalCommand, "yes")
		_ = opts.Set(ssh.OptionLocalCommand, "echo %h")

		client := &fakePostAuthLocalRunner{}
		if err := runPostAuthLocalCommand(t.Context(), client, opts, &bytes.Buffer{}, true); err != nil {
			t.Fatalf("unexpected error = %v", err)
		}
		if client.calls != 0 {
			t.Fatalf("expected LocalCommand NOT to run inside -f background child, got %d calls", client.calls)
		}
	})
}
