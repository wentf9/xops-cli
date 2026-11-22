package utils

import (
	"errors"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestP7W12c_FG12M1_ExcludeWithTier1ProxyCommandCancelsLowerTierCycle(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host loop
    HostName 10.221.0.1
    User ops
    ProxyJump loop

Host short.corp.example.com
    HostName 10.221.0.5
    User ops
    ProxyJump short.corp.example.com

Host badport
    HostName 10.221.0.2
    Port 99999

Host *
    CanonicalizeHostname always
    CanonicalDomains corp.example.com
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-ok", models.Host{Address: "10.221.0.10", Port: 22})
	cfg.Hosts.Set("h-saved-loop", models.Host{Address: "10.221.0.11", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("web-ok", models.Node{HostRef: "h-ok", IdentityRef: "id-ops"})
	cfg.Nodes.Set("saved-loop", models.Node{HostRef: "h-saved-loop", IdentityRef: "id-ops", ProxyJump: "openssh:loop"})
	prov := config.NewProviderWithOpenSSHParser(cfg, parser)

	cancelCases := []struct {
		name    string
		rawOpts []string
		cliJump string
	}{
		{"ProxyCommand_active", []string{"ProxyCommand=nc %h %p"}, ""},
		{"ProxyCommand_none", []string{"ProxyCommand=none"}, ""},
		{"ProxyJump_none_opt", []string{"ProxyJump=none"}, ""},
		{"ProxyCommand_before_cyclic_ProxyJump", []string{"ProxyCommand=nc %h %p", "ProxyJump=loop"}, ""},
		{"ProxyJump_none_cli", nil, "none"},
	}

	for _, tc := range cancelCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, spec := range []string{"loop", "openssh:loop", "ops@loop", "deploy@saved-loop", "short"} {
				ex, err := ResolveExcludesForTargetsWithOptions(prov, []string{spec}, nil, tc.rawOpts, tc.cliJump)
				if err != nil || len(ex) == 0 {
					t.Errorf("ResolveExcludesForTargetsWithOptions(%s, %q) = (%v, %v), want non-empty exclude set",
						tc.name, spec, ex, err)
				}
			}
			// Non-ProxyJump errors such as badport must still fail closed.
			if got, err := ResolveExcludesForTargetsWithOptions(prov, []string{"badport"}, nil, tc.rawOpts, tc.cliJump); err == nil || !strings.Contains(err.Error(), "99999") {
				t.Errorf("ResolveExcludesForTargetsWithOptions(%s, badport) = (%v, %v), want invalid port error",
					tc.name, got, err)
			}
		})
	}

	// Control: without Tier-1 override, excluding cyclic Host loop still fails closed with *ssh.ProxyCycleError.
	var cycleErr *ssh.ProxyCycleError
	if got, err := ResolveExcludesForTargetsWithOptions(prov, []string{"loop"}, nil, nil, ""); !errors.As(err, &cycleErr) {
		t.Errorf("ResolveExcludesForTargetsWithOptions(no override, loop) = (%v, %v), want *ssh.ProxyCycleError", got, err)
	}
}
