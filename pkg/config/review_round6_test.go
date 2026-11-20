package config

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/wentf9/xops-cli/pkg/models"
)

func TestRound6_P2_5_OpenSSHOriginAtomicAndNoChimeras(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host alias-a",
		"  HostName 10.6.0.1",
		"  User ops",
		"",
		"Host alias-b",
		"  HostName 10.6.0.1",
		"  User ops",
	}, "\n") + "\n"
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	cfg := cloneConfiguration(nil)
	cfg.Hosts.Set("h1", models.Host{Address: "10.6.0.1", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops"})
	cfg.Nodes.Set("ops@10.6.0.1:22", models.Node{HostRef: "h1", IdentityRef: "id1"})

	store := NewDefaultStore(filepath.Join(t.TempDir(), "c.yaml"), filepath.Join(t.TempDir(), "c.key"))
	repo, err := NewRepositoryWithOpenSSHParser(cfg, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}

	// 1. SetNodeOpenSSHAlias clears stale CanonicalHost when alias changes, and clears both on "".
	repo.SetNodeOpenSSHOrigin("ops@10.6.0.1:22", OpenSSHOrigin{Alias: "alias-a", CanonicalHost: "alias-a.corp.example.com"})
	if got := repo.NodeOpenSSHOrigin("ops@10.6.0.1:22"); got.Alias != "alias-a" || got.CanonicalHost != "alias-a.corp.example.com" {
		t.Fatalf("initial origin = %+v", got)
	}
	// ResolveTarget matching saved node via non-canonicalized alias-b must NOT graft stale CanonicalHost.
	resolved, err := ResolveTarget(repo, ConnectionTarget{Selector: "alias-b", User: "ops", HasUser: true})
	if err != nil {
		t.Fatalf("ResolveTarget(alias-b): %v", err)
	}
	if resolved.OpenSSHAlias != "alias-b" || resolved.CanonicalHost != "" {
		t.Fatalf("ResolveTarget(alias-b) formed chimera: alias=%q canon=%q", resolved.OpenSSHAlias, resolved.CanonicalHost)
	}

	// Changing alias via legacy SetNodeOpenSSHAlias clears stale CanonicalHost.
	repo.SetNodeOpenSSHAlias("ops@10.6.0.1:22", "alias-b")
	if got := repo.NodeOpenSSHOrigin("ops@10.6.0.1:22"); got.Alias != "alias-b" || got.CanonicalHost != "" {
		t.Fatalf("SetNodeOpenSSHAlias(new) left stale canon: %+v", got)
	}
	// Setting empty alias clears the entire origin.
	repo.SetNodeOpenSSHAlias("ops@10.6.0.1:22", "")
	if got := repo.NodeOpenSSHOrigin("ops@10.6.0.1:22"); !got.IsZero() {
		t.Fatalf("SetNodeOpenSSHAlias(empty) did not clear origin: %+v", got)
	}
	// Atomic setOpenSSHMetadataLocked("", "only.corp") clears stale Alias.
	repo.SetNodeOpenSSHOrigin("ops@10.6.0.1:22", OpenSSHOrigin{Alias: "old-alias", CanonicalHost: "old.corp"})
	repo.provider.setSavedNodeOpenSSHMetadataIfPresent("ops@10.6.0.1:22", "", "only.corp")
	if got := repo.NodeOpenSSHOrigin("ops@10.6.0.1:22"); got.Alias != "" || got.CanonicalHost != "only.corp" {
		t.Fatalf("setSavedNodeOpenSSHMetadataIfPresent(canon-only) left stale alias: %+v", got)
	}

	// 2. Multi-candidate consistentCandidateOpenSSHOrigin never mixes fields across candidates.
	cfgMulti := cloneConfiguration(nil)
	cfgMulti.Hosts.Set("h1", models.Host{Address: "10.6.0.2", Port: 22})
	cfgMulti.Identities.Set("id1", models.Identity{User: "alice"})
	cfgMulti.Identities.Set("id2", models.Identity{User: "bob"})
	cfgMulti.Nodes.Set("n1", models.Node{HostRef: "h1", IdentityRef: "id1"})
	cfgMulti.Nodes.Set("n2", models.Node{HostRef: "h1", IdentityRef: "id2"})
	repoMulti, err := NewRepositoryWithoutOpenSSH(cfgMulti, &abortSaveStore{})
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	repoMulti.SetNodeOpenSSHOrigin("n1", OpenSSHOrigin{Alias: "a", CanonicalHost: "shared.corp"})
	repoMulti.SetNodeOpenSSHOrigin("n2", OpenSSHOrigin{Alias: "b", CanonicalHost: "shared.corp"})
	if got := repoMulti.consistentCandidateOpenSSHOrigin(repoMulti.Snapshot(), []string{"n1", "n2"}); !got.IsZero() {
		t.Fatalf("mismatched multi-candidate origins synthesized chimera: %+v", got)
	}
}

type inspectSavedTransientStore struct {
	mu          sync.Mutex
	cfg         *Configuration
	sawMetaSave bool
}

func (s *inspectSavedTransientStore) Load() (*Configuration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneConfiguration(s.cfg), nil
}

func (s *inspectSavedTransientStore) Save(cfg *Configuration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cfg != nil && cfg.Nodes != nil {
		for _, id := range cfg.Nodes.Keys() {
			if n, ok := cfg.Nodes.Get(id); ok && (n.OpenSSHAlias != "" || n.CanonicalHost != "") {
				s.sawMetaSave = true
			}
		}
	}
	s.cfg = cloneConfiguration(cfg)
	return nil
}

func TestRound6_P3_5_PrepareConfigurationStripsBeforePersist(t *testing.T) {
	t.Parallel()

	store := &inspectSavedTransientStore{cfg: cloneConfiguration(nil)}
	repo, err := NewRepositoryWithoutOpenSSH(nil, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	if _, err := repo.ImportOpenSSHHostsContext(t.Context(), []OpenSSHHost{{
		Name:     "imp-strip",
		Host:     models.Host{Address: "10.6.0.9", Port: 22},
		Identity: models.Identity{User: "ops"},
		Node:     models.Node{OpenSSHAlias: "imp-strip", CanonicalHost: "imp-strip.corp"},
	}}); err != nil {
		t.Fatalf("ImportOpenSSHHostsContext: %v", err)
	}
	if store.sawMetaSave {
		t.Fatal("Store.Save observed unstripped transient OpenSSHAlias/CanonicalHost")
	}
}

func TestRound6_P1_1_And_P3_5_IPv6IndexingLookupAndSymmetricZoneComparison(t *testing.T) {
	t.Parallel()

	// P3-5: SameHostAddress must be symmetric and transitive for IPv6 zone IDs and IPv4-mapped IPv6.
	if !SameHostAddress("fe80::0001%eth0", "fe80::1%eth0") {
		t.Fatal("SameHostAddress failed for equivalent IPv6 with identical zone")
	}
	if SameHostAddress("fe80::1%eth0", "fe80::1%ETH0") || SameHostAddress("fe80::0001%eth0", "fe80::1%ETH0") {
		t.Fatal("SameHostAddress must compare IPv6 zone IDs symmetrically (case-sensitive)")
	}
	if !SameHostAddress("::ffff:10.0.0.1", "::ffff:0a00:0001") {
		t.Fatal("SameHostAddress failed for equivalent IPv4-mapped IPv6 forms")
	}
	if SameHostAddress("::ffff:10.0.0.1", "10.0.0.1") {
		t.Fatal("SameHostAddress must keep IPv4-mapped IPv6 distinct from IPv4")
	}

	// P1-1 root cause: ResolveSelector & ResolveTarget must match canonical & non-canonical IPv6 symmetrically.
	cfg := cloneConfiguration(nil)
	cfg.Hosts.Set("h-canon", models.Host{Address: "2001:db8::1", Port: 22})
	cfg.Hosts.Set("h-raw", models.Host{Address: "2001:0DB8::2", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops"})
	cfg.Nodes.Set("my-v6-box", models.Node{HostRef: "h-canon", IdentityRef: "id1"})
	cfg.Nodes.Set("my-v6-raw", models.Node{HostRef: "h-raw", IdentityRef: "id1"})

	prov := NewProviderWithoutOpenSSH(cfg)
	for _, tc := range []struct {
		selector string
		wantID   string
	}{
		{"2001:0DB8::1", "my-v6-box"},
		{"[2001:0DB8::1]", "my-v6-box"},
		{"ops@[2001:0DB8::1]:22", "my-v6-box"},
		{"2001:db8::2", "my-v6-raw"},
		{"ops@2001:db8::2", "my-v6-raw"},
	} {
		got, err := prov.ResolveSelector(tc.selector)
		if err != nil || got != tc.wantID {
			t.Errorf("ResolveSelector(%q) = (%q, %v), want (%q, nil)", tc.selector, got, err, tc.wantID)
		}
	}

	res, err := ResolveTarget(prov, ConnectionTarget{Selector: "2001:0DB8::1", User: "ops", HasUser: true})
	if err != nil {
		t.Fatalf("ResolveTarget(2001:0DB8::1): %v", err)
	}
	if res.MatchedNodeID != "my-v6-box" || res.BaseNodeID != "my-v6-box" {
		t.Fatalf("ResolveTarget(2001:0DB8::1) = (matched=%q, base=%q), want my-v6-box", res.MatchedNodeID, res.BaseNodeID)
	}
}
