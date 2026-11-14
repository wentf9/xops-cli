package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestPass5_H3_MultiCandidateSavedNodesPreserveBaseNodeID(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	t.Run("resolveConsistentCandidates sets saved BaseNodeID under user override", func(t *testing.T) {
		cfg := &Configuration{
			Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
			Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
			Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		}
		cfg.Hosts.Set("h-shared", models.Host{
			Address: "10.0.0.50",
			Port:    22,
			Alias:   []string{"Prod Shared Web"},
		})
		cfg.Identities.Set("id-alice", models.Identity{User: "alice", AuthType: "auto"})
		cfg.Identities.Set("id-bob", models.Identity{User: "bob", AuthType: "auto"})
		cfg.Nodes.Set("alice@10.0.0.50:22", models.Node{HostRef: "h-shared", IdentityRef: "id-alice"})
		cfg.Nodes.Set("bob@10.0.0.50:22", models.Node{HostRef: "h-shared", IdentityRef: "id-bob"})

		provider := NewProviderWithoutOpenSSH(cfg)
		res, err := ResolveTarget(provider, ConnectionTarget{
			Selector: "Prod Shared Web",
			User:     "root",
			HasUser:  true,
		})
		if err != nil {
			t.Fatalf("ResolveTarget failed: %v", err)
		}
		if res.MatchedNodeID != "" {
			t.Fatalf("MatchedNodeID = %q, want empty for non-matching user override", res.MatchedNodeID)
		}
		validCandidates := []string{"alice@10.0.0.50:22", "bob@10.0.0.50:22"}
		if !slices.Contains(validCandidates, res.BaseNodeID) {
			t.Fatalf("BaseNodeID = %q, want one of %v", res.BaseNodeID, validCandidates)
		}
		if strings.HasPrefix(res.BaseNodeID, OpenSSHNodePrefix) {
			t.Fatalf("BaseNodeID = %q, must not have openssh: prefix", res.BaseNodeID)
		}
		if res.NodeID != "root@10.0.0.50:22" || res.Host != "10.0.0.50" || res.Port != 22 || res.User != "root" {
			t.Fatalf("unexpected ResolvedTarget: %+v", res)
		}
	})

	t.Run("resolveCandidateAddressFallback sets saved BaseNodeID under user and port override", func(t *testing.T) {
		cfg := &Configuration{
			Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
			Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
			Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		}
		cfg.Hosts.Set("h-p22", models.Host{
			Address: "10.0.0.60",
			Port:    22,
			Alias:   []string{"Multi Port Box"},
		})
		cfg.Hosts.Set("h-p2222", models.Host{
			Address: "10.0.0.60",
			Port:    2222,
			Alias:   []string{"Multi Port Box"},
		})
		cfg.Identities.Set("id-alice", models.Identity{User: "alice", AuthType: "auto"})
		cfg.Identities.Set("id-bob", models.Identity{User: "bob", AuthType: "auto"})
		cfg.Nodes.Set("alice@10.0.0.60:22", models.Node{HostRef: "h-p22", IdentityRef: "id-alice"})
		cfg.Nodes.Set("bob@10.0.0.60:2222", models.Node{HostRef: "h-p2222", IdentityRef: "id-bob"})

		provider := NewProviderWithoutOpenSSH(cfg)
		res, err := ResolveTarget(provider, ConnectionTarget{
			Selector: "Multi Port Box",
			User:     "deploy",
			HasUser:  true,
			Port:     2200,
			HasPort:  true,
		})
		if err != nil {
			t.Fatalf("ResolveTarget failed: %v", err)
		}
		if res.MatchedNodeID != "" {
			t.Fatalf("MatchedNodeID = %q, want empty", res.MatchedNodeID)
		}
		validCandidates := []string{"alice@10.0.0.60:22", "bob@10.0.0.60:2222"}
		if !slices.Contains(validCandidates, res.BaseNodeID) {
			t.Fatalf("BaseNodeID = %q, want one of %v", res.BaseNodeID, validCandidates)
		}
		if res.NodeID != "deploy@10.0.0.60:2200" || res.Host != "10.0.0.60" || res.Port != 2200 || res.User != "deploy" {
			t.Fatalf("unexpected ResolvedTarget: %+v", res)
		}
	})
}

func TestPass5_HasOpenSSHConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if HasOpenSSHConfig(nil) {
		t.Fatal("HasOpenSSHConfig(nil) = true, want false")
	}
	noSSH := NewProviderWithoutOpenSSH(&Configuration{})
	if HasOpenSSHConfig(noSSH) {
		t.Fatal("HasOpenSSHConfig(NewProviderWithoutOpenSSH) = true, want false")
	}

	parser, err := NewOpenSSHParserFromReader(strings.NewReader("Host web\n  HostName 10.0.0.1\n"))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader failed: %v", err)
	}
	withSSH := NewProviderWithOpenSSHParser(&Configuration{}, parser)
	if !HasOpenSSHConfig(withSSH) {
		t.Fatal("HasOpenSSHConfig(NewProviderWithOpenSSHParser) = false, want true")
	}

	noneOverride, err := WithOpenSSHConfigOverride(withSSH, "none")
	if err != nil {
		t.Fatalf("WithOpenSSHConfigOverride(none) failed: %v", err)
	}
	if HasOpenSSHConfig(noneOverride) {
		t.Fatal("HasOpenSSHConfig(-F none) = true, want false")
	}

	customFile := filepath.Join(t.TempDir(), "ssh_config")
	if err := os.WriteFile(customFile, []byte("Host custom\n  HostName 10.0.0.2\n"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	fileOverride, err := WithOpenSSHConfigOverride(noSSH, customFile)
	if err != nil {
		t.Fatalf("WithOpenSSHConfigOverride(customFile) failed: %v", err)
	}
	if !HasOpenSSHConfig(fileOverride) {
		t.Fatal("HasOpenSSHConfig(customFile) = false, want true")
	}
}
