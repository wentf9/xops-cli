package utils

import (
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestParseExcludeFlag(t *testing.T) {
	tests := []struct {
		name   string
		input  []string
		expect []string
	}{
		{"empty", nil, nil},
		{"single value", []string{"web-01"}, []string{"web-01"}},
		{"comma separated", []string{"web-01,web-02"}, []string{"web-01", "web-02"}},
		{"multiple flags", []string{"web-01", "web-02"}, []string{"web-01", "web-02"}},
		{"mixed", []string{"web-01,web-02", "db-01"}, []string{"web-01", "web-02", "db-01"}},
		{"trim spaces", []string{" web-01 , web-02 "}, []string{"web-01", "web-02"}},
		{"deduplicate", []string{"web-01,web-01"}, []string{"web-01"}},
		{"skip empty", []string{",,web-01,"}, []string{"web-01"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseExcludeFlag(tt.input)
			if len(got) != len(tt.expect) {
				t.Fatalf("expected %v, got %v", tt.expect, got)
			}
			for i, v := range tt.expect {
				if got[i] != v {
					t.Errorf("at index %d expected %q, got %q", i, v, got[i])
				}
			}
		})
	}
}

func newTestProvider(nodes map[string]models.Node, hosts map[string]models.Host, identities map[string]models.Identity) *config.Provider {
	cfg := &config.Configuration{
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
	}
	for id, n := range nodes {
		cfg.Nodes.Set(id, n)
	}
	for id, host := range hosts {
		cfg.Hosts.Set(id, host)
	}
	for id, identity := range identities {
		cfg.Identities.Set(id, identity)
	}
	return config.NewProviderWithoutOpenSSH(cfg)
}

func TestResolveExcludes(t *testing.T) {
	// 构造测试配置:
	// nodeID: web-01  alias: [frontend-1] address: 192.168.1.10
	// nodeID: web-02  alias: [frontend-2] address: 192.168.1.11
	nodes := map[string]models.Node{
		"web-01": {
			HostRef:     "host-web-1",
			IdentityRef: "id-web-1",
			Alias:       []string{"frontend-1"},
		},
		"web-02": {
			HostRef:     "host-web-2",
			IdentityRef: "id-web-2",
			Alias:       []string{"frontend-2"},
		},
	}
	provider := newTestProvider(nodes,
		map[string]models.Host{
			"host-web-1": {Address: "192.168.1.10", Port: 22},
			"host-web-2": {Address: "192.168.1.11", Port: 22},
		},
		map[string]models.Identity{
			"id-web-1": {User: "root"},
			"id-web-2": {User: "root"},
		},
	)

	t.Run("empty input returns nil", func(t *testing.T) {
		got, err := ResolveExcludes(provider, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != nil {
			t.Fatalf("expected nil, got %v", got)
		}
	})

	t.Run("match by node id", func(t *testing.T) {
		got, err := ResolveExcludes(provider, []string{"web-01"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(got))
		}
		if _, ok := got["web-01"]; !ok {
			t.Fatalf("expected web-01 in result, got %v", got)
		}
	})

	t.Run("match by alias", func(t *testing.T) {
		got, err := ResolveExcludes(provider, []string{"frontend-1"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(got))
		}
		if _, ok := got["web-01"]; !ok {
			t.Fatalf("expected web-01 in result, got %v", got)
		}
	})

	t.Run("match by ip", func(t *testing.T) {
		got, err := ResolveExcludes(provider, []string{"192.168.1.11"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(got))
		}
		if _, ok := got["web-02"]; !ok {
			t.Fatalf("expected web-02 in result, got %v", got)
		}
	})

	t.Run("match multiple", func(t *testing.T) {
		got, err := ResolveExcludes(provider, []string{"web-01", "frontend-2"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("expected 2 entries, got %d", len(got))
		}
		if _, ok := got["web-01"]; !ok {
			t.Fatalf("expected web-01 in result, got %v", got)
		}
		if _, ok := got["web-02"]; !ok {
			t.Fatalf("expected web-02 in result, got %v", got)
		}
	})

	t.Run("unmatched returns error", func(t *testing.T) {
		_, err := ResolveExcludes(provider, []string{"non-existent"})
		if err == nil {
			t.Fatal("expected error for unmatched exclude, got nil")
		}
	})
}

func TestIsTargetExcluded(t *testing.T) {
	t.Run("empty excludes returns false", func(t *testing.T) {
		if IsTargetExcluded(nil, ExcludeTargetInfo{NodeID: "ops@10.0.0.5:22"}) {
			t.Fatal("expected false for nil excludes")
		}
	})

	t.Run("openssh alias matches BaseNodeID and OpenSSHAlias", func(t *testing.T) {
		excludes := map[string]struct{}{"openssh:web": {}}
		info := ExcludeTargetInfo{
			NodeID:       "ops@10.0.0.5:22",
			BaseNodeID:   "openssh:web",
			OpenSSHAlias: "web",
			User:         "ops",
			Port:         22,
		}
		if !IsTargetExcluded(excludes, info) {
			t.Fatal("expected OpenSSH alias web to be excluded")
		}
	})

	t.Run("disambiguated openssh:user@alias:port matches openssh:alias", func(t *testing.T) {
		excludes := map[string]struct{}{"openssh:role-b": {}}
		info := ExcludeTargetInfo{
			NodeID:       "openssh:ops@role-b:22",
			BaseNodeID:   "openssh:role-b",
			OpenSSHAlias: "role-b",
			User:         "ops",
			Port:         22,
		}
		if !IsTargetExcluded(excludes, info) {
			t.Fatal("expected disambiguated openssh:ops@role-b:22 to match openssh:role-b")
		}
	})

	t.Run("pre-canonicalized unmanaged host matches openssh:rawHost", func(t *testing.T) {
		excludes := map[string]struct{}{"openssh:web": {}}
		info := ExcludeTargetInfo{
			NodeID:         "ops@web.corp.example.com:22",
			UnmanagedHosts: []string{"web", "web.corp.example.com", "web"},
		}
		if !IsTargetExcluded(excludes, info) {
			t.Fatal("expected pre-canonicalized unmanaged host to match openssh:web")
		}
	})

	t.Run("saved node different user not falsely excluded via BaseNodeID", func(t *testing.T) {
		excludes := map[string]struct{}{"ops@web.corp.example.com:22": {}}
		info := ExcludeTargetInfo{
			NodeID:         "root@web.corp.example.com:22",
			BaseNodeID:     "ops@web.corp.example.com:22",
			User:           "root",
			Port:           22,
			UnmanagedHosts: []string{"web.corp.example.com"},
		}
		if IsTargetExcluded(excludes, info) {
			t.Fatal("expected root@web.corp.example.com:22 NOT to be excluded when only ops@web.corp.example.com:22 is excluded")
		}
	})

	t.Run("canonicalized openssh MatchedNodeID still matches pre-canonicalized UnmanagedHosts", func(t *testing.T) {
		excludes := map[string]struct{}{"openssh:web": {}}
		info := ExcludeTargetInfo{
			NodeID:         "openssh:web.corp.example.com",
			MatchedNodeID:  "openssh:web.corp.example.com",
			BaseNodeID:     "openssh:web.corp.example.com",
			User:           "ops",
			Port:           22,
			UnmanagedHosts: []string{"web", "web.corp.example.com", "web"},
		}
		if !IsTargetExcluded(excludes, info) {
			t.Fatal("expected canonicalized openssh virtual node to match openssh:web via UnmanagedHosts")
		}
	})

	t.Run("saved node with user override does not match openssh: prefix", func(t *testing.T) {
		excludes := map[string]struct{}{"openssh:prod-web": {}}
		info := ExcludeTargetInfo{
			NodeID:         "root@10.238.221.181:22",
			BaseNodeID:     "iaas@10.238.221.181:22",
			User:           "root",
			Port:           22,
			UnmanagedHosts: []string{"prod-web", "10.238.221.181"},
		}
		if IsTargetExcluded(excludes, info) {
			t.Fatal("expected saved node override NOT to match openssh:prod-web")
		}
	})
}

func TestPass5_M4_ResolveExcludesForTargets(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	sshCfg := `
Host web
  HostName 10.0.0.10
  User ops
  Port 22

Host role-a
  HostName 10.0.0.20
  User ops
  Port 22

Host role-b
  HostName 10.0.0.20
  User ops
  Port 22
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader failed: %v", err)
	}
	cfg := &config.Configuration{
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
	}
	cfg.Hosts.Set("h-saved", models.Host{Address: "10.238.221.181", Port: 22})
	cfg.Identities.Set("id-iaas", models.Identity{User: "iaas", AuthType: "auto"})
	cfg.Nodes.Set("iaas@10.238.221.181:22", models.Node{
		HostRef:     "h-saved",
		IdentityRef: "id-iaas",
		Alias:       []string{"prod-web"},
	})
	openSSHProv := config.NewProviderWithOpenSSHParser(cfg, parser)
	noSSHProv := config.NewProviderWithoutOpenSSH(cfg)

	verifyPass5CompositeOpenSSHExcludes(t, openSSHProv)
	verifyPass5IPv6AndAdHocExcludes(t, openSSHProv, noSSHProv)
	verifyPass5SavedNodeOverrideExcludes(t, noSSHProv)
}

func verifyPass5CompositeOpenSSHExcludes(t *testing.T, openSSHProv config.ConfigProvider) {
	t.Helper()
	t.Run("composite openssh alias user isolation", func(t *testing.T) {
		aliceCand := ExcludeTargetInfo{
			NodeID:       "alice@10.0.0.10:22",
			BaseNodeID:   "openssh:web",
			OpenSSHAlias: "web",
			User:         "alice",
			Port:         22,
		}
		bobCand := ExcludeTargetInfo{
			NodeID:       "bob@10.0.0.10:22",
			BaseNodeID:   "openssh:web",
			OpenSSHAlias: "web",
			User:         "bob",
			Port:         22,
		}
		excludes, err := ResolveExcludesForTargets(openSSHProv, []string{"alice@web"}, []ExcludeTargetInfo{aliceCand, bobCand})
		if err != nil {
			t.Fatalf("ResolveExcludesForTargets(alice@web) failed: %v", err)
		}
		if !IsTargetExcluded(excludes, aliceCand) {
			t.Fatal("expected alice@web to be excluded")
		}
		if IsTargetExcluded(excludes, bobCand) {
			t.Fatal("expected bob@web NOT to be excluded when only alice@web was excluded")
		}
	})

	t.Run("disambiguated openssh:ops@role-b:22 isolates shared IP aliases", func(t *testing.T) {
		roleACand := ExcludeTargetInfo{
			NodeID:       "openssh:ops@role-a:22",
			BaseNodeID:   "openssh:role-a",
			OpenSSHAlias: "role-a",
			User:         "ops",
			Port:         22,
		}
		roleBCand := ExcludeTargetInfo{
			NodeID:       "openssh:ops@role-b:22",
			BaseNodeID:   "openssh:role-b",
			OpenSSHAlias: "role-b",
			User:         "ops",
			Port:         22,
		}
		excludes, err := ResolveExcludesForTargets(openSSHProv, []string{"openssh:ops@role-b:22"}, []ExcludeTargetInfo{roleACand, roleBCand})
		if err != nil {
			t.Fatalf("ResolveExcludesForTargets(openssh:ops@role-b:22) failed: %v", err)
		}
		if !IsTargetExcluded(excludes, roleBCand) {
			t.Fatal("expected role-b to be excluded")
		}
		if IsTargetExcluded(excludes, roleACand) {
			t.Fatal("expected role-a NOT to be excluded")
		}
	})
}

func verifyPass5IPv6AndAdHocExcludes(t *testing.T, openSSHProv, noSSHProv config.ConfigProvider) {
	t.Helper()
	t.Run("ipv6 literal excludes work with and without openssh config", func(t *testing.T) {
		v6Cand1 := ExcludeTargetInfo{
			NodeID:         "ops@[2001:db8::1]:22",
			User:           "ops",
			Port:           22,
			UnmanagedHosts: []string{"[2001:db8::1]", "2001:db8::1"},
		}
		v6Cand2 := ExcludeTargetInfo{
			NodeID:         "ops@[2001:db8::2]:22",
			User:           "ops",
			Port:           22,
			UnmanagedHosts: []string{"[2001:db8::2]", "2001:db8::2"},
		}
		for _, prov := range []config.ConfigProvider{openSSHProv, noSSHProv} {
			for _, ex := range []string{"[2001:db8::1]", "2001:db8::1"} {
				excludes, err := ResolveExcludesForTargets(prov, []string{ex}, []ExcludeTargetInfo{v6Cand1, v6Cand2})
				if err != nil {
					t.Fatalf("ResolveExcludesForTargets(%q) failed: %v", ex, err)
				}
				if !IsTargetExcluded(excludes, v6Cand1) {
					t.Fatalf("expected 2001:db8::1 to be excluded by %q", ex)
				}
				if IsTargetExcluded(excludes, v6Cand2) {
					t.Fatalf("expected 2001:db8::2 NOT to be excluded by %q", ex)
				}
			}
		}
	})

	t.Run("-F none ad-hoc host user isolation and fail-closed typo", func(t *testing.T) {
		aliceAdHoc := ExcludeTargetInfo{
			NodeID:         "alice@10.0.0.99:22",
			User:           "alice",
			Port:           22,
			UnmanagedHosts: []string{"10.0.0.99"},
		}
		bobAdHoc := ExcludeTargetInfo{
			NodeID:         "bob@10.0.0.99:22",
			User:           "bob",
			Port:           22,
			UnmanagedHosts: []string{"10.0.0.99"},
		}
		excludesUser, err := ResolveExcludesForTargets(noSSHProv, []string{"alice@10.0.0.99"}, []ExcludeTargetInfo{aliceAdHoc, bobAdHoc})
		if err != nil {
			t.Fatalf("ResolveExcludesForTargets(-F none alice@10.0.0.99) failed: %v", err)
		}
		if !IsTargetExcluded(excludesUser, aliceAdHoc) {
			t.Fatal("expected alice@10.0.0.99 to be excluded")
		}
		if IsTargetExcluded(excludesUser, bobAdHoc) {
			t.Fatal("expected bob@10.0.0.99 NOT to be excluded")
		}

		excludesHost, err := ResolveExcludesForTargets(noSSHProv, []string{"10.0.0.99"}, []ExcludeTargetInfo{aliceAdHoc, bobAdHoc})
		if err != nil {
			t.Fatalf("ResolveExcludesForTargets(-F none 10.0.0.99) failed: %v", err)
		}
		if !IsTargetExcluded(excludesHost, aliceAdHoc) || !IsTargetExcluded(excludesHost, bobAdHoc) {
			t.Fatal("expected bare --exclude 10.0.0.99 to exclude both users on 10.0.0.99")
		}

		if _, err := ResolveExcludesForTargets(noSSHProv, []string{"typo-host"}, []ExcludeTargetInfo{aliceAdHoc, bobAdHoc}); err == nil || !strings.Contains(err.Error(), "no matching node for: typo-host") {
			t.Fatalf("expected fail-closed error on nonexistent exclude, got: %v", err)
		}
	})
}

func verifyPass5SavedNodeOverrideExcludes(t *testing.T, noSSHProv config.ConfigProvider) {
	t.Helper()
	t.Run("saved node bare alias vs user-qualified exclude under -u override", func(t *testing.T) {
		savedRootOverride := ExcludeTargetInfo{
			NodeID:         "root@10.238.221.181:22",
			BaseNodeID:     "iaas@10.238.221.181:22",
			User:           "root",
			Port:           22,
			UnmanagedHosts: []string{"prod-web", "10.238.221.181"},
		}
		bareExcl, err := ResolveExcludesForTargets(noSSHProv, []string{"prod-web"}, []ExcludeTargetInfo{savedRootOverride})
		if err != nil {
			t.Fatalf("ResolveExcludesForTargets(prod-web) failed: %v", err)
		}
		if !IsTargetExcluded(bareExcl, savedRootOverride) {
			t.Fatal("expected bare --exclude prod-web to exclude -u root overridden saved node")
		}

		iaasExcl, err := ResolveExcludesForTargets(noSSHProv, []string{"iaas@prod-web"}, []ExcludeTargetInfo{savedRootOverride})
		if err != nil {
			t.Fatalf("ResolveExcludesForTargets(iaas@prod-web) failed: %v", err)
		}
		if IsTargetExcluded(iaasExcl, savedRootOverride) {
			t.Fatal("expected --exclude iaas@prod-web NOT to exclude -u root overridden saved node")
		}
	})
}

func newPass6WildcardOpenSSHFixtures(t *testing.T) (config.ConfigProvider, config.ConfigProvider, *config.Repository) {
	t.Helper()
	sshCfg := `
Host web
  HostName 10.0.0.10
  User ops
  Port 22

Host *.corp.example.com
  User ops
  Port 2222

Host *
  ServerAliveInterval 15
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader failed: %v", err)
	}
	cfg := &config.Configuration{
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
	}
	cfg.Hosts.Set("h-saved", models.Host{Address: "10.238.221.181", Port: 22})
	cfg.Identities.Set("id-iaas", models.Identity{User: "iaas", AuthType: "auto"})
	cfg.Nodes.Set("iaas@10.238.221.181:22", models.Node{
		HostRef:     "h-saved",
		IdentityRef: "id-iaas",
		Alias:       []string{"prod-web"},
	})
	openSSHProv := config.NewProviderWithOpenSSHParser(cfg, parser)
	noSSHProv := config.NewProviderWithoutOpenSSH(cfg)
	repo, err := config.NewRepositoryWithOpenSSHParser(cfg, pass6NoopStore{}, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser failed: %v", err)
	}
	return openSSHProv, noSSHProv, repo
}

type pass6NoopStore struct{}

func (pass6NoopStore) Load() (*config.Configuration, error) { return nil, nil }
func (pass6NoopStore) Save(*config.Configuration) error     { return nil }

func TestPass6_H2_OpenSSHConcreteHostFailClosed(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	openSSHProv, noSSHProv, repo := newPass6WildcardOpenSSHFixtures(t)
	frozenProv := repo.Frozen()

	for _, prov := range []config.ConfigProvider{openSSHProv, frozenProv} {
		for _, concrete := range []string{"web", "openssh:web", "openssh:alice@web:2222"} {
			if !providerOpenSSHHasConcreteHost(prov, concrete) {
				t.Fatalf("expected providerOpenSSHHasConcreteHost(%T, %q) == true", prov, concrete)
			}
		}
		for _, nonConcrete := range []string{"", "typo-host", "openssh:typo-host", "wild.corp.example.com", "openssh:wild.corp.example.com", "prod-web", "openssh:prod-web"} {
			if providerOpenSSHHasConcreteHost(prov, nonConcrete) {
				t.Fatalf("expected providerOpenSSHHasConcreteHost(%T, %q) == false", prov, nonConcrete)
			}
		}
	}
	if providerOpenSSHHasConcreteHost(noSSHProv, "web") || providerOpenSSHHasConcreteHost(nil, "web") {
		t.Fatal("expected providerOpenSSHHasConcreteHost to be false without loaded ssh_config")
	}

	savedCand := ExcludeTargetInfo{
		NodeID:         "iaas@10.238.221.181:22",
		MatchedNodeID:  "iaas@10.238.221.181:22",
		BaseNodeID:     "iaas@10.238.221.181:22",
		User:           "iaas",
		Port:           22,
		UnmanagedHosts: []string{"prod-web", "10.238.221.181"},
	}
	unmatchedSpecs := []string{
		"typo-host",
		"openssh:typo-host",
		"openssh:ops@typo-host:22",
		"alice@typo-host",
		"typo-host:2222",
		"wild.corp.example.com",
		"openssh:wild.corp.example.com",
		"openssh:prod-web",
	}
	for _, spec := range unmatchedSpecs {
		if _, err := ResolveExcludes(openSSHProv, []string{spec}); err == nil || !strings.Contains(err.Error(), "no matching node") {
			t.Fatalf("ResolveExcludes(%q) expected fail-closed error, got: %v", spec, err)
		}
		if _, err := ResolveExcludesForTargets(openSSHProv, []string{spec}, []ExcludeTargetInfo{savedCand}); err == nil || !strings.Contains(err.Error(), "no matching node") {
			t.Fatalf("ResolveExcludesForTargets(%q) expected fail-closed error, got: %v", spec, err)
		}
	}

	wildCand := ExcludeTargetInfo{
		NodeID:         "ops@wild.corp.example.com:2222",
		User:           "ops",
		Port:           2222,
		UnmanagedHosts: []string{"wild.corp.example.com"},
	}
	exclWild, err := ResolveExcludesForTargets(openSSHProv, []string{"wild.corp.example.com"}, []ExcludeTargetInfo{savedCand, wildCand})
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets(wild target in candidates) failed: %v", err)
	}
	if !IsTargetExcluded(exclWild, wildCand) || IsTargetExcluded(exclWild, savedCand) {
		t.Fatal("expected wildcard-matched ad-hoc candidate to be excluded without affecting savedCand")
	}
}

func TestPass6_H3_AddSavedBaseCandidatesUserPortOverrides(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	openSSHProv, noSSHProv, _ := newPass6WildcardOpenSSHFixtures(t)

	savedDefault := ExcludeTargetInfo{
		NodeID:         "iaas@10.238.221.181:22",
		MatchedNodeID:  "iaas@10.238.221.181:22",
		BaseNodeID:     "iaas@10.238.221.181:22",
		User:           "iaas",
		Port:           22,
		UnmanagedHosts: []string{"prod-web", "10.238.221.181"},
	}
	savedPortOverride := ExcludeTargetInfo{
		NodeID:         "iaas@10.238.221.181:2222",
		BaseNodeID:     "iaas@10.238.221.181:22",
		User:           "iaas",
		Port:           2222,
		UnmanagedHosts: []string{"prod-web", "10.238.221.181"},
	}
	savedRootOverride := ExcludeTargetInfo{
		NodeID:         "root@10.238.221.181:22",
		BaseNodeID:     "iaas@10.238.221.181:22",
		User:           "root",
		Port:           22,
		UnmanagedHosts: []string{"prod-web", "10.238.221.181"},
	}
	savedRootPortOverride := ExcludeTargetInfo{
		NodeID:         "root@10.238.221.181:2222",
		BaseNodeID:     "iaas@10.238.221.181:22",
		User:           "root",
		Port:           2222,
		UnmanagedHosts: []string{"prod-web", "10.238.221.181"},
	}
	allCands := []ExcludeTargetInfo{savedPortOverride, savedRootOverride, savedRootPortOverride}

	for _, prov := range []config.ConfigProvider{noSSHProv, openSSHProv} {
		verifySavedUserPortExcludeCases(t, prov, savedDefault, savedPortOverride, savedRootOverride, savedRootPortOverride, allCands)
	}
}

func verifySavedUserPortExcludeCases(
	t *testing.T,
	prov config.ConfigProvider,
	savedDefault, savedPortOverride, savedRootOverride, savedRootPortOverride ExcludeTargetInfo,
	allCands []ExcludeTargetInfo,
) {
	t.Helper()
	exclIaas, err := ResolveExcludesForTargets(prov, []string{"iaas@prod-web"}, allCands)
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets(iaas@prod-web) failed: %v", err)
	}
	if !IsTargetExcluded(exclIaas, savedPortOverride) {
		t.Fatal("expected --exclude iaas@prod-web to exclude -p 2222 overridden iaas@10.238.221.181:2222")
	}
	if IsTargetExcluded(exclIaas, savedRootOverride) || IsTargetExcluded(exclIaas, savedRootPortOverride) {
		t.Fatal("expected --exclude iaas@prod-web NOT to exclude -u root overridden targets")
	}

	exclPort22, err := ResolveExcludesForTargets(prov, []string{"iaas@prod-web:22"}, allCands)
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets(iaas@prod-web:22) failed: %v", err)
	}
	if IsTargetExcluded(exclPort22, savedPortOverride) {
		t.Fatal("expected --exclude iaas@prod-web:22 NOT to exclude -p 2222 target")
	}
	if !IsTargetExcluded(exclPort22, savedDefault) {
		t.Fatal("expected --exclude iaas@prod-web:22 to exclude port 22 target")
	}

	exclPort2222, err := ResolveExcludesForTargets(prov, []string{"iaas@prod-web:2222"}, allCands)
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets(iaas@prod-web:2222) failed: %v", err)
	}
	if !IsTargetExcluded(exclPort2222, savedPortOverride) || IsTargetExcluded(exclPort2222, savedRootPortOverride) {
		t.Fatal("expected --exclude iaas@prod-web:2222 to exclude only iaas on port 2222")
	}

	exclRoot, err := ResolveExcludesForTargets(prov, []string{"root@prod-web"}, allCands)
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets(root@prod-web) failed: %v", err)
	}
	if !IsTargetExcluded(exclRoot, savedRootOverride) || !IsTargetExcluded(exclRoot, savedRootPortOverride) || IsTargetExcluded(exclRoot, savedPortOverride) {
		t.Fatal("expected --exclude root@prod-web to exclude root overrides and preserve iaas")
	}
}

func TestExclude_OpenSSHUserAndDistinctAliasScoping(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	sshCfg := `
Host ssh-web
  HostName 10.238.221.181
  User iaas
  Port 22

Host app-a
  HostName 10.238.221.182
  User ops
  Port 22

Host app-b
  HostName 10.238.221.182
  User ops
  Port 22
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader failed: %v", err)
	}
	cfg := &config.Configuration{
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
	}
	openSSHProv := config.NewProviderWithOpenSSHParser(cfg, parser)

	t.Run("user-qualified OpenSSH exclude does not exclude other user on same alias", func(t *testing.T) {
		iaasCand := ExcludeTargetInfo{
			NodeID:         "iaas@10.238.221.181:22",
			MatchedNodeID:  "openssh:ssh-web",
			OpenSSHAlias:   "ssh-web",
			User:           "iaas",
			Port:           22,
			UnmanagedHosts: []string{"10.238.221.181", "ssh-web"},
		}
		bobCand := ExcludeTargetInfo{
			NodeID:         "bob@10.238.221.181:22",
			MatchedNodeID:  "openssh:ssh-web",
			OpenSSHAlias:   "ssh-web",
			User:           "bob",
			Port:           22,
			UnmanagedHosts: []string{"10.238.221.181", "ssh-web"},
		}
		excl, err := ResolveExcludesForTargets(openSSHProv, []string{"iaas@ssh-web"}, []ExcludeTargetInfo{iaasCand, bobCand})
		if err != nil {
			t.Fatalf("ResolveExcludesForTargets(iaas@ssh-web) failed: %v", err)
		}
		if !IsTargetExcluded(excl, iaasCand) {
			t.Fatal("expected --exclude iaas@ssh-web to exclude iaas@ssh-web")
		}
		if IsTargetExcluded(excl, bobCand) {
			t.Fatal("expected --exclude iaas@ssh-web NOT to exclude bob@ssh-web")
		}
	})

	t.Run("distinct OpenSSH aliases sharing IP/user/port exclude independently", func(t *testing.T) {
		candA := ExcludeTargetInfo{
			NodeID:         "ops@10.238.221.182:22",
			OpenSSHAlias:   "app-a",
			User:           "ops",
			Port:           0, // exercises 0 -> 22 normalization
			UnmanagedHosts: []string{"10.238.221.182", "app-a"},
		}
		candB := ExcludeTargetInfo{
			NodeID:         "ops@10.238.221.182:22",
			OpenSSHAlias:   "app-b",
			User:           "ops",
			Port:           22,
			UnmanagedHosts: []string{"10.238.221.182", "app-b"},
		}
		exclA, err := ResolveExcludesForTargets(openSSHProv, []string{"ops@app-a"}, []ExcludeTargetInfo{candA, candB})
		if err != nil {
			t.Fatalf("ResolveExcludesForTargets(ops@app-a) failed: %v", err)
		}
		if !IsTargetExcluded(exclA, candA) {
			t.Fatal("expected --exclude ops@app-a to exclude ops@app-a")
		}
		if IsTargetExcluded(exclA, candB) {
			t.Fatal("expected --exclude ops@app-a NOT to exclude ops@app-b sharing IP/user/port")
		}
	})
}
