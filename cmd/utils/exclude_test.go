package utils

import (
	"errors"
	"testing"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
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

func TestResolveFirstSelectorRejectsAmbiguousCandidate(t *testing.T) {
	provider := newTestProvider(
		map[string]models.Node{
			"one": {HostRef: "host-one", IdentityRef: "identity-one"},
			"two": {HostRef: "host-two", IdentityRef: "identity-two"},
		},
		map[string]models.Host{
			"host-one": {Address: "shared.example", Port: 22},
			"host-two": {Address: "shared.example", Port: 22},
		},
		map[string]models.Identity{
			"identity-one": {User: "root"},
			"identity-two": {User: "deploy"},
		},
	)

	_, err := resolveFirstSelector(provider, "shared.example")
	if !errors.Is(err, config.ErrAmbiguousNode) {
		t.Fatalf("resolveFirstSelector() error = %v, want ErrAmbiguousNode", err)
	}
}
