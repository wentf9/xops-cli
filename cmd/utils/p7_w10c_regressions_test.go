package utils

import (
	"errors"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

type w10cCustomOpenSSHProvider struct {
	config.ConfigProvider
}

func TestP7W10c_FG10M1_ExcludeFailClosedOnResolveTargetErrors(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host loop
    HostName 10.120.0.1
    User ops
    ProxyJump loop

Host loop-only
    HostName 10.120.0.99
    User ops
    ProxyJump loop-only

Host badport
    HostName 10.120.0.2
    Port 99999

Host good-ssh
    HostName 10.120.0.3
    User ops

Host *
    CanonicalizeHostname always
    CanonicalDomains corp.example.com
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-1", models.Host{Address: "10.120.0.1", Port: 22})
	cfg.Hosts.Set("h-2", models.Host{Address: "10.120.0.10", Port: 22})
	cfg.Hosts.Set("h-3", models.Host{Address: "10.120.0.11", Port: 22})
	cfg.Hosts.Set("h-4", models.Host{Address: "10.120.0.12", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("saved-loop-ip", models.Node{HostRef: "h-1", IdentityRef: "id-ops"})
	cfg.Nodes.Set("saved-badjump", models.Node{HostRef: "h-2", IdentityRef: "id-ops", ProxyJump: "bastion,,hop2"})
	cfg.Nodes.Set("saved-cyc-a", models.Node{HostRef: "h-4", IdentityRef: "id-ops", ProxyJump: "saved-cyc-b"})
	cfg.Nodes.Set("saved-cyc-b", models.Node{HostRef: "h-3", IdentityRef: "id-ops", ProxyJump: "saved-cyc-a"})
	prov := config.NewProviderWithOpenSSHParser(cfg, parser)

	candidates := []ExcludeTargetInfo{
		{
			NodeID:        "saved-loop-ip",
			MatchedNodeID: "saved-loop-ip",
			BaseNodeID:    "saved-loop-ip",
			ResolvedHost:  "10.120.0.1",
			User:          "ops",
			Port:          22,
		},
		{
			NodeID:        "openssh:good-ssh",
			MatchedNodeID: "openssh:good-ssh",
			BaseNodeID:    "openssh:good-ssh",
			OpenSSHAlias:  "good-ssh",
			ResolvedHost:  "10.120.0.3",
			User:          "ops",
			Port:          22,
		},
	}

	t.Run("resolveSingleExcludeBySelector_propagates_ResolveTarget_errors_fail_closed", func(t *testing.T) {
		t.Parallel()
		var cycleErr *ssh.ProxyCycleError
		if got, err := ResolveExcludesForTargets(prov, []string{"loop"}, candidates); !errors.As(err, &cycleErr) {
			t.Fatalf("ResolveExcludesForTargets([loop]) = (%v, %v), want *ssh.ProxyCycleError", got, err)
		}
		if got, err := ResolveExcludesForTargets(prov, []string{"badport"}, candidates); err == nil || !strings.Contains(err.Error(), "99999") {
			t.Fatalf("ResolveExcludesForTargets([badport]) = (%v, %v), want invalid port error", got, err)
		}
	})

	t.Run("resolveExcludeViaTarget_propagates_non_ErrNodeNotFound_errors_fail_closed", func(t *testing.T) {
		t.Parallel()
		var cycleErr *ssh.ProxyCycleError
		for _, spec := range []string{"deploy@loop-only", "openssh:loop", "deploy@saved-cyc-a"} {
			if got, err := ResolveExcludesForTargets(prov, []string{spec}, candidates); !errors.As(err, &cycleErr) {
				t.Errorf("ResolveExcludesForTargets([%q]) = (%v, %v), want *ssh.ProxyCycleError", spec, got, err)
			}
		}
		if got, err := ResolveExcludesForTargets(prov, []string{"deploy@saved-badjump"}, candidates); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("ResolveExcludesForTargets([deploy@saved-badjump]) = (%v, %v), want ErrSSHOptionsValidation", got, err)
		}
		if got, err := ResolveExcludesForTargets(prov, []string{"deploy@badport"}, candidates); err == nil || !strings.Contains(err.Error(), "99999") {
			t.Errorf("ResolveExcludesForTargets([deploy@badport]) = (%v, %v), want invalid port error", got, err)
		}
	})

	t.Run("custom_provider_without_GetOpenSSHParser_fails_closed_on_ResolveTarget_error", func(t *testing.T) {
		t.Parallel()
		customProv := w10cCustomOpenSSHProvider{ConfigProvider: prov}
		if got, err := ResolveExcludesForTargets(customProv, []string{"badport"}, candidates); err == nil {
			t.Fatalf("ResolveExcludesForTargets(custom provider, [badport]) = %v, want fail-closed error", got)
		}
	})

	t.Run("valid_excludes_and_unmatched_entries_still_behave_normally", func(t *testing.T) {
		t.Parallel()
		ex, err := ResolveExcludesForTargets(prov, []string{"good-ssh"}, candidates)
		if err != nil {
			t.Fatalf("ResolveExcludesForTargets([good-ssh]): %v", err)
		}
		if !IsTargetExcluded(ex, candidates[1]) || IsTargetExcluded(ex, candidates[0]) {
			t.Fatalf("unexpected exclude match for good-ssh: %v", ex)
		}
		if _, err := ResolveExcludesForTargets(prov, []string{"no-such-host"}, candidates); err == nil || !strings.Contains(err.Error(), "no matching node") {
			t.Fatalf("ResolveExcludesForTargets([no-such-host]) err = %v, want unmatched error", err)
		}
	})
}
