package cmd

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestP7W5c_D5H1_ToSessionControlOptionsWithJumpValidatesWithoutDashO(t *testing.T) {
	t.Parallel()

	badJumps := []string{",", " , ", "none,", ",none", "bastion,", ",bastion", "a,,b", "bastion,none", "none,bastion", "bastion\x00"}
	for _, bad := range badJumps {
		f := &SSHControlFlags{}
		if _, err := f.ToSessionControlOptionsWithJump(bad); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("ToSessionControlOptionsWithJump(%q) with empty -o err = %v, want ErrSSHOptionsValidation", bad, err)
		}
	}

	for _, okJump := range []string{"bastion", "jump1,jump2", "none", "none,none"} {
		f := &SSHControlFlags{}
		got, err := f.ToSessionControlOptionsWithJump(okJump)
		if err != nil {
			t.Errorf("ToSessionControlOptionsWithJump(%q) unexpected error: %v", okJump, err)
			continue
		}
		if got.IsEmpty() {
			t.Errorf("ToSessionControlOptionsWithJump(%q) returned empty SessionControlOptions", okJump)
		}
	}
}

func TestP7W5c_D5L1_ProxyCommandPathCheckerRespectsProxyCommandNone(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host bastion-cmd
    HostName 10.0.0.1
    User jumpops
    ProxyCommand nc %h %p

Host app-via-bastion
    HostName 10.0.0.2
    User appops
    ProxyJump bastion-cmd
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-bastion", models.Host{Address: "10.0.0.1", Port: 22})
	cfg.Hosts.Set("h-app", models.Host{Address: "10.0.0.3", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("bastion-node", models.Node{
		HostRef:     "h-bastion",
		IdentityRef: "id-ops",
		SSHOptions:  ssh.MustOptions(ssh.OptionProxyCommand, "nc %h %p"),
	})
	cfg.Nodes.Set("app-saved", models.Node{
		HostRef:     "h-app",
		IdentityRef: "id-ops",
		ProxyJump:   "bastion-node",
	})
	provider := config.NewProviderWithOpenSSHParser(cfg, parser)

	// 1. Saved node with ProxyJump -> bastion-node (which has ProxyCommand):
	//    without override it detects ProxyCommand; with -o ProxyCommand=none it must NOT walk stale ProxyJump.
	baseOpts := &SshOptions{}
	if hasProxy, err := baseOpts.hasActiveProxyCommandInPath(provider, "app-saved", nil); err != nil || !hasProxy {
		t.Fatalf("app-saved without override = (%v, %v), want (true, nil)", hasProxy, err)
	}
	cancelOpts := &SshOptions{control: SSHControlFlags{Options: []string{"ProxyCommand=none"}}}
	if hasProxy, err := cancelOpts.hasActiveProxyCommandInPath(provider, "app-saved", nil); err != nil || hasProxy {
		t.Fatalf("app-saved with -o ProxyCommand=none = (%v, %v), want (false, nil)", hasProxy, err)
	}

	// 2. OpenSSH virtual node with Tier-4 ProxyJump -> bastion-cmd (which has ProxyCommand):
	//    with -o ProxyCommand=none it must NOT walk stale ProxyJump.
	virtID := config.OpenSSHNodePrefix + "app-via-bastion"
	if hasProxy, err := baseOpts.hasActiveProxyCommandInPath(provider, virtID, nil); err != nil || !hasProxy {
		t.Fatalf("virtual app without override = (%v, %v), want (true, nil)", hasProxy, err)
	}
	if hasProxy, err := cancelOpts.hasActiveProxyCommandInPath(provider, virtID, nil); err != nil || hasProxy {
		t.Fatalf("virtual app with -o ProxyCommand=none = (%v, %v), want (false, nil)", hasProxy, err)
	}

	// 3. Intermediate OpenSSH hop whose Tier-4 ProxyJump -> bastion-cmd is canceled by Tier-3 global
	//    ProxyCommand=none: checkNode on the intermediate hop must respect pol.Proxy() and NOT walk stale bastion-cmd.
	cfgGlobalCancel := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfgGlobalCancel.Hosts.Set("h-app", models.Host{Address: "10.0.0.3", Port: 22})
	cfgGlobalCancel.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfgGlobalCancel.SSHOptions = ssh.MustOptions(ssh.OptionProxyCommand, "none")
	cfgGlobalCancel.Nodes.Set("app-via-t4-mid", models.Node{
		HostRef:     "h-app",
		IdentityRef: "id-ops",
		ProxyJump:   config.OpenSSHNodePrefix + "app-via-bastion",
	})
	provGlobalCancel := config.NewProviderWithOpenSSHParser(cfgGlobalCancel, parser)
	if hasProxy, err := baseOpts.hasActiveProxyCommandInPath(provGlobalCancel, "app-via-t4-mid", nil); err != nil || hasProxy {
		t.Fatalf("app-via-t4-mid with Tier-3 ProxyCommand=none canceling mid hop = (%v, %v), want (false, nil)", hasProxy, err)
	}
}

type countingCanonicalResolver struct {
	lookups int
}

func (r *countingCanonicalResolver) LookupHost(_ context.Context, _ string) ([]string, error) {
	r.lookups++
	return []string{"10.0.0.99"}, nil
}

func (r *countingCanonicalResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	return host, nil
}

func TestP7W5c_D5L3_CaseInsensitiveOpenSSHPrefixAcrossCmdHelpers(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host *
    CanonicalizeHostname yes
    CanonicalDomains corp.example
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	provider := config.NewProviderWithOpenSSHParser(nil, parser)

	// 1. cmd/ssh.go: applyHostnameCanonicalization skips mixed/uppercase OPENSSH: selectors.
	for _, sel := range []string{"OPENSSH:short", "OpenSSH:short"} {
		res := &countingCanonicalResolver{}
		o := &SshOptions{Host: sel, Target: config.ConnectionTarget{Selector: sel}}
		if err := o.applyHostnameCanonicalization(t.Context(), provider, res); err != nil {
			t.Fatalf("applyHostnameCanonicalization(%q): %v", sel, err)
		}
		if res.lookups != 0 || o.canonicalized {
			t.Fatalf("applyHostnameCanonicalization(%q) attempted canonicalization (lookups=%d, canonicalized=%v)", sel, res.lookups, o.canonicalized)
		}
	}

	// 2. cmd/exec.go: isResolvedSavedNode and resolveExecHostTarget recognize OPENSSH: case-insensitively.
	for _, id := range []string{"OPENSSH:web", "OpenSSH:web", "oPeNsSh:web"} {
		if isResolvedSavedNode(config.ResolvedTarget{Host: "10.0.0.1", MatchedNodeID: id, BaseNodeID: id}) {
			t.Errorf("isResolvedSavedNode(%q) = true, want false", id)
		}
		res := &countingCanonicalResolver{}
		eo := &ExecOptions{SshOptions: SshOptions{canonicalResolver: res}}
		target, _, _, _, _, err := eo.resolveExecHostTarget(t.Context(), provider, config.ConnectionTarget{Selector: id})
		if err != nil {
			t.Fatalf("resolveExecHostTarget(%q): %v", id, err)
		}
		if res.lookups != 0 || target.Selector != id {
			t.Fatalf("resolveExecHostTarget(%q) attempted canonicalization (lookups=%d, selector=%q)", id, res.lookups, target.Selector)
		}
	}

	// 3. cmd/mux_daemon_spec.go: extractMuxDaemonTargetComponents strips OPENSSH: case-insensitively.
	for _, raw := range []string{"OPENSSH:alice@web:2222", "OpenSSH:alice@web:2222"} {
		host, user, port, preserve := extractMuxDaemonTargetComponents(nil, raw)
		if host != "web" || user != "alice" || port != 2222 || preserve {
			t.Errorf("extractMuxDaemonTargetComponents(%q) = (%q, %q, %d, %v), want (\"web\", \"alice\", 2222, false)",
				raw, host, user, port, preserve)
		}
	}
}
