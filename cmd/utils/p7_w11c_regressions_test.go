package utils

import (
	"errors"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestP7W11c_FG11M1_CompositeSavedNodeExcludeNeverCanonicalizes(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host prod-db.corp.example.com
    HostName 10.220.9.9
    Port 99999

Host Prod-Mixed.corp.example.com
    HostName 10.220.9.10
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
	cfg.Hosts.Set("h-db", models.Host{Address: "10.220.0.1", Port: 22})
	cfg.Hosts.Set("h-db-fqdn", models.Host{Address: "prod-db.corp.example.com", Port: 22})
	cfg.Hosts.Set("h-mixed", models.Host{Address: "10.220.0.2", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("prod-db", models.Node{HostRef: "h-db", IdentityRef: "id-ops"})
	cfg.Nodes.Set("prod-db-fqdn", models.Node{HostRef: "h-db-fqdn", IdentityRef: "id-ops"})
	cfg.Nodes.Set("Prod-Mixed", models.Node{HostRef: "h-mixed", IdentityRef: "id-ops"})
	prov := config.NewProviderWithOpenSSHParser(cfg, parser)

	candidates := []ExcludeTargetInfo{
		{
			NodeID:        "prod-db",
			MatchedNodeID: "prod-db",
			BaseNodeID:    "prod-db",
			ResolvedHost:  "10.220.0.1",
			User:          "ops",
			Port:          22,
		},
		{
			NodeID:        "prod-db-fqdn",
			MatchedNodeID: "prod-db-fqdn",
			BaseNodeID:    "prod-db-fqdn",
			ResolvedHost:  "prod-db.corp.example.com",
			User:          "ops",
			Port:          22,
		},
		{
			NodeID:        "Prod-Mixed",
			MatchedNodeID: "Prod-Mixed",
			BaseNodeID:    "Prod-Mixed",
			ResolvedHost:  "10.220.0.2",
			User:          "ops",
			Port:          22,
		},
	}

	for _, spec := range []string{"ops@prod-db", "ops@prod-db:22"} {
		excludes, err := ResolveExcludesForTargets(prov, []string{spec}, candidates)
		if err != nil {
			t.Fatalf("ResolveExcludesForTargets([%q]) unexpectedly failed (canonicalized saved node?): %v", spec, err)
		}
		if !IsTargetExcluded(excludes, candidates[0]) {
			t.Fatalf("ResolveExcludesForTargets([%q]) did not exclude prod-db: %v", spec, excludes)
		}
		if IsTargetExcluded(excludes, candidates[1]) {
			t.Fatalf("ResolveExcludesForTargets([%q]) falsely excluded unrelated prod-db-fqdn: %v", spec, excludes)
		}
	}

	// Mixed-case saved node ID with composite user@ selector also skips canonicalization.
	excludesMixed, err := ResolveExcludesForTargets(prov, []string{"ops@Prod-Mixed"}, candidates)
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets([ops@Prod-Mixed]) failed: %v", err)
	}
	if !IsTargetExcluded(excludesMixed, candidates[2]) || IsTargetExcluded(excludesMixed, candidates[1]) {
		t.Fatalf("unexpected exclude matches for ops@Prod-Mixed: %v", excludesMixed)
	}
}

func TestP7W11c_FG11L1_ExcludeEmptyCandidatesFailClosedAndDisabledProxyJump(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host loop
    HostName 10.221.0.1
    User ops
    ProxyJump loop

Host loop-only
    HostName 10.221.0.2
    User ops
    ProxyJump loop-only

Host badport
    HostName 10.221.0.3
    Port 99999
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-a", models.Host{Address: "10.221.0.10", Port: 22})
	cfg.Hosts.Set("h-b", models.Host{Address: "10.221.0.11", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("saved-cyc-a", models.Node{HostRef: "h-a", IdentityRef: "id-ops", ProxyJump: "saved-cyc-b"})
	cfg.Nodes.Set("saved-cyc-b", models.Node{HostRef: "h-b", IdentityRef: "id-ops", ProxyJump: "saved-cyc-a"})
	prov := config.NewProviderWithOpenSSHParser(cfg, parser)

	t.Run("ResolveExcludes_with_empty_candidates_fails_closed", func(t *testing.T) {
		t.Parallel()
		if got, err := ResolveExcludes(prov, []string{"badport"}); err == nil || !strings.Contains(err.Error(), "99999") {
			t.Fatalf("ResolveExcludes([badport]) = (%v, %v), want invalid port 99999 error", got, err)
		}
		var cycleErr *ssh.ProxyCycleError
		if got, err := ResolveExcludes(prov, []string{"loop"}); !errors.As(err, &cycleErr) {
			t.Fatalf("ResolveExcludes([loop]) = (%v, %v), want *ssh.ProxyCycleError", got, err)
		}
	})

	t.Run("disabled_cliProxyJump_none_allows_excluding_cyclic_hosts_while_badport_still_fails", func(t *testing.T) {
		t.Parallel()
		for _, disabledJump := range []string{"none", "NONE", "none,none"} {
			for _, spec := range []string{"loop", "deploy@loop-only", "deploy@saved-cyc-a"} {
				ex, err := ResolveExcludesForTargetsWithOptions(prov, []string{spec}, nil, nil, disabledJump)
				if err != nil || len(ex) == 0 {
					t.Errorf("ResolveExcludesForTargetsWithOptions(%q, cliJump=%q) = (%v, %v), want non-empty exclude set", spec, disabledJump, ex, err)
				}
			}
			if got, err := ResolveExcludesForTargetsWithOptions(prov, []string{"badport"}, nil, nil, disabledJump); err == nil || !strings.Contains(err.Error(), "99999") {
				t.Errorf("ResolveExcludesForTargetsWithOptions(badport, cliJump=%q) = (%v, %v), want invalid port error", disabledJump, got, err)
			}
		}
	})
}
