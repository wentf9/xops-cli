package cmd

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestPhase4_FormatHostKeyPromptSSHFPStatus(t *testing.T) {
	baseReq := ssh.HostKeyConfirmation{
		Hostname:    "db.example.com",
		Algorithm:   "ssh-ed25519",
		Fingerprint: "SHA256:abcdef",
	}

	if got := formatHostKeyPrompt(baseReq); strings.Contains(got, "DNS") {
		t.Fatalf("expected no DNS line for SSHFPStatusNone, got %q", got)
	}

	reqVerified := baseReq
	reqVerified.SSHFPStatus = ssh.SSHFPStatusMatchedVerified
	if got := formatHostKeyPrompt(reqVerified); !strings.Contains(got, "DNSSEC verified") {
		t.Fatalf("expected DNSSEC verified message, got %q", got)
	}

	reqUnverified := baseReq
	reqUnverified.SSHFPStatus = ssh.SSHFPStatusMatchedUnverified
	if got := formatHostKeyPrompt(reqUnverified); !strings.Contains(got, "NOT DNSSEC verified") {
		t.Fatalf("expected NOT DNSSEC verified message, got %q", got)
	}

	reqMismatch := baseReq
	reqMismatch.SSHFPStatus = ssh.SSHFPStatusMismatch
	if got := formatHostKeyPrompt(reqMismatch); !strings.Contains(got, "DOES NOT MATCH") {
		t.Fatalf("expected SSHFP mismatch warning, got %q", got)
	}
}

type phase4FakeResolver struct {
	hosts map[string][]string
}

func (f *phase4FakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if addrs, ok := f.hosts[host]; ok && len(addrs) > 0 {
		return addrs, nil
	}
	return nil, errors.New("not found")
}

func (f *phase4FakeResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	return host + ".", nil
}

func TestPhase4_ApplyHostnameCanonicalizationPreservesOriginalHost(t *testing.T) {
	openSSH := `
Host web.corp.example.com
    User corp-ops
    Port 2222

Host *
    CanonicalizeHostname yes
    CanonicalDomains corp.example.com
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
	cfg.Hosts.Set("h1", models.Host{Address: "10.0.0.99", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "saved", AuthType: "auto"})
	cfg.Nodes.Set("saved-web", models.Node{HostRef: "h1", IdentityRef: "id1"})

	provider := config.NewProviderWithOpenSSHParser(cfg, parser)
	resolver := &phase4FakeResolver{
		hosts: map[string][]string{
			"web.corp.example.com":       {"10.20.30.40"},
			"saved-web.corp.example.com": {"10.20.30.41"},
		},
	}

	t.Run("canonicalizes ad-hoc host and preserves %n originalHostForExpansion", func(t *testing.T) {
		opts := NewSshOptions()
		opts.Host = "web"
		opts.Target = config.ConnectionTarget{Selector: "web", RawSelector: "web"}
		if err := opts.applyHostnameCanonicalization(t.Context(), provider, resolver); err != nil {
			t.Fatalf("applyHostnameCanonicalization() error = %v", err)
		}

		if opts.Host != "web.corp.example.com" || opts.Target.Selector != "web.corp.example.com" {
			t.Fatalf("expected canonicalized Host/Selector, got Host=%q Selector=%q", opts.Host, opts.Target.Selector)
		}
		if gotOrig := opts.originalHostForExpansion(); gotOrig != "web" {
			t.Fatalf("originalHostForExpansion() = %q, want %q", gotOrig, "web")
		}
	})

	t.Run("skips saved XOps managed node with explicit Host.Address", func(t *testing.T) {
		opts := NewSshOptions()
		opts.Host = "saved-web"
		opts.Target = config.ConnectionTarget{Selector: "saved-web", RawSelector: "saved-web"}
		if err := opts.applyHostnameCanonicalization(t.Context(), provider, resolver); err != nil {
			t.Fatalf("applyHostnameCanonicalization() error = %v", err)
		}

		if opts.Host != "saved-web" || opts.Target.Selector != "saved-web" {
			t.Fatalf("expected saved node NOT canonicalized, got Host=%q Selector=%q", opts.Host, opts.Target.Selector)
		}
	})
}

func TestPhase4_OriginalHostVsCanonicalHostControlPath(t *testing.T) {
	openSSH := `
Host web.corp.example.com
    User corp-ops
    Port 2222

Host *
    CanonicalizeHostname yes
    CanonicalDomains corp.example.com
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
	resolver := &phase4FakeResolver{
		hosts: map[string][]string{
			"web.corp.example.com": {"10.20.30.40"},
		},
	}

	opts := NewSshOptions()
	opts.Host = "web"
	opts.Target = config.ConnectionTarget{Selector: "web", RawSelector: "web"}
	opts.control.ControlPath = "/tmp/cm-%n-%h-%p-%r"
	if err := opts.applyHostnameCanonicalization(t.Context(), provider, resolver); err != nil {
		t.Fatalf("applyHostnameCanonicalization() error = %v", err)
	}

	// Simulate -O check / resolveControlContext target construction after canonicalization.
	nodeID, err := resolveControlNodeID(provider, effectiveConnectionTarget(opts, ""))
	if err != nil {
		t.Fatalf("resolveControlNodeID() error = %v", err)
	}
	target := controlTarget(opts, provider, nodeID)
	if target.OriginalHost != "web" {
		t.Fatalf("controlTarget.OriginalHost = %q, want %q", target.OriginalHost, "web")
	}
	if target.Host != "web.corp.example.com" {
		t.Fatalf("controlTarget.Host = %q, want %q", target.Host, "web.corp.example.com")
	}
	if target.User != "corp-ops" || target.Port != 2222 {
		t.Fatalf("controlTarget user/port = (%q, %d), want (%q, %d)", target.User, target.Port, "corp-ops", 2222)
	}

	ctlExpanded, err := expandControlSocketPath(opts, provider, nodeID, target, io.Discard)
	if err != nil {
		t.Fatalf("expandControlSocketPath() error = %v", err)
	}
	wantPath := "/tmp/cm-web-web.corp.example.com-2222-corp-ops"
	if ctlExpanded != wantPath {
		t.Fatalf("expandControlSocketPath() = %q, want %q", ctlExpanded, wantPath)
	}

	// Verify ssh -M side (adapter.ExpandControlPath with SessionAuth.OriginalHost) produces identical socket path.
	adp := adapter.NewNonInteractiveSSHAdapter(provider, adapter.WithSessionAuthOverride(nodeID, adapter.SessionAuth{
		OriginalHost: opts.originalHostForExpansion(),
	}))
	masterExpanded, err := adp.ExpandControlPath(nodeID, opts.control.ControlPath)
	if err != nil {
		t.Fatalf("adapter.ExpandControlPath() error = %v", err)
	}
	if masterExpanded != ctlExpanded {
		t.Fatalf("master socket %q != control -O socket %q", masterExpanded, ctlExpanded)
	}
}
