package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/pkg/models"
)

func newP7W2dMemoryRepo(t *testing.T, initial *Configuration) *Repository {
	t.Helper()
	store := NewDefaultStore(filepath.Join(t.TempDir(), "config.yaml"), filepath.Join(t.TempDir(), "key"))
	repo, err := NewRepositoryWithOpenSSHParser(initial, store, &OpenSSHParser{})
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}
	return repo
}

// TestP7Repro_MED5_CyclicAndSelfProxyJump_RejectedAtWriteBoundaries verifies MED-5:
// cyclic and self-referential ProxyJump graphs are rejected at ValidateV2, Repository
// commit (CreateNodeContext / ReplaceNodeAtRefContext / NewRepository), and ImportOpenSSHHostsContext.
func TestP7Repro_MED5_CyclicAndSelfProxyJump_RejectedAtWriteBoundaries(t *testing.T) {
	t.Parallel()

	t.Run("ValidateV2_rejects_self_ProxyJump", func(t *testing.T) {
		t.Parallel()
		cfg := &ConfigurationV2{
			SchemaVersion: 2,
			Credential:    CredentialConfig{Stores: map[string]StoreConfig{}},
			Hosts:         map[string]models.Host{"h-a": {Address: "10.0.0.1", Port: 22}},
			Identities:    map[string]IdentityV2{"id-a": {User: "ops", AuthType: "auto"}},
			Nodes: map[string]NodeV2{
				"node-a": {HostRef: "h-a", IdentityRef: "id-a", ProxyJump: "node-a", SudoMode: models.SudoModeAuto},
			},
		}
		if err := ValidateV2(cfg); err == nil {
			t.Fatal("MED-5: ValidateV2 accepted self-referential ProxyJump (node-a -> node-a)")
		}
	})

	t.Run("ValidateV2_rejects_two_node_ProxyJump_cycle", func(t *testing.T) {
		t.Parallel()
		cfg := &ConfigurationV2{
			SchemaVersion: 2,
			Credential:    CredentialConfig{Stores: map[string]StoreConfig{}},
			Hosts: map[string]models.Host{
				"h-a": {Address: "10.0.0.1", Port: 22},
				"h-b": {Address: "10.0.0.2", Port: 22},
			},
			Identities: map[string]IdentityV2{"id": {User: "ops", AuthType: "auto"}},
			Nodes: map[string]NodeV2{
				"node-a": {HostRef: "h-a", IdentityRef: "id", ProxyJump: "node-b", SudoMode: models.SudoModeAuto},
				"node-b": {HostRef: "h-b", IdentityRef: "id", ProxyJump: "node-a", SudoMode: models.SudoModeAuto},
			},
		}
		if err := ValidateV2(cfg); err == nil {
			t.Fatal("MED-5: ValidateV2 accepted cyclic ProxyJump (node-a -> node-b -> node-a)")
		}
	})

	t.Run("Repository_CreateNodeContext_rejects_self_and_cycle", func(t *testing.T) {
		t.Parallel()
		repo := newP7W2dMemoryRepo(t, nil)

		_, err := repo.CreateNodeContext(
			t.Context(),
			"self-node",
			models.Node{HostRef: "h-self", IdentityRef: "id-self", ProxyJump: "self-node", SudoMode: models.SudoModeAuto},
			models.Host{Address: "10.0.1.1", Port: 22},
			models.Identity{User: "ops", AuthType: "auto"},
		)
		if err == nil {
			t.Errorf("MED-5: Repository.CreateNodeContext committed self-referential ProxyJump (self-node -> self-node)")
		}

		_, errA := repo.CreateNodeContext(
			t.Context(),
			"cycle-a",
			models.Node{HostRef: "h-ca", IdentityRef: "id-ca", ProxyJump: "cycle-b", SudoMode: models.SudoModeAuto},
			models.Host{Address: "10.0.1.2", Port: 22},
			models.Identity{User: "ops", AuthType: "auto"},
		)
		_, errB := repo.CreateNodeContext(
			t.Context(),
			"cycle-b",
			models.Node{HostRef: "h-cb", IdentityRef: "id-cb", ProxyJump: "cycle-a", SudoMode: models.SudoModeAuto},
			models.Host{Address: "10.0.1.3", Port: 22},
			models.Identity{User: "ops", AuthType: "auto"},
		)
		if errA == nil && errB == nil {
			t.Errorf("MED-5: Repository.CreateNodeContext committed 2-node ProxyJump cycle (cycle-a <-> cycle-b)")
		}
	})

	t.Run("ImportOpenSSHHostsContext_rejects_self_and_cycle", func(t *testing.T) {
		t.Parallel()
		repo := newP7W2dMemoryRepo(t, nil)

		hosts := []OpenSSHHost{
			{
				Name:     "imp-self",
				Host:     models.Host{Address: "10.0.2.1", Port: 22},
				Identity: models.Identity{User: "ops", AuthType: "auto"},
				Node:     models.Node{Alias: []string{"imp-self"}, ProxyJump: "imp-self", SudoMode: models.SudoModeAuto},
			},
			{
				Name:     "imp-a",
				Host:     models.Host{Address: "10.0.2.2", Port: 22},
				Identity: models.Identity{User: "ops", AuthType: "auto"},
				Node:     models.Node{Alias: []string{"imp-a"}, ProxyJump: "imp-b", SudoMode: models.SudoModeAuto},
			},
			{
				Name:     "imp-b",
				Host:     models.Host{Address: "10.0.2.3", Port: 22},
				Identity: models.Identity{User: "ops", AuthType: "auto"},
				Node:     models.Node{Alias: []string{"imp-b"}, ProxyJump: "imp-a", SudoMode: models.SudoModeAuto},
			},
		}

		res, err := repo.ImportOpenSSHHostsContext(t.Context(), hosts)
		if err == nil {
			snap := repo.Snapshot()
			if _, ok := snap.Nodes.Get("imp-self"); ok {
				t.Errorf("MED-5: ImportOpenSSHHostsContext persisted self-loop node imp-self (res=%+v)", res)
			}
			_, hasA := snap.Nodes.Get("imp-a")
			_, hasB := snap.Nodes.Get("imp-b")
			if hasA && hasB {
				t.Errorf("MED-5: ImportOpenSSHHostsContext persisted cyclic nodes imp-a <-> imp-b (res=%+v)", res)
			}
		}
	})

	t.Run("Load_nonconforming_config_fails_closed_with_doctor_hint", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "xops_config.yaml")
		raw := strings.Join([]string{
			"schema_version: 2",
			"credential:",
			"  stores: {}",
			"hosts:",
			"  h-a:",
			"    address: 10.0.0.1",
			"    port: 22",
			"identities:",
			"  id-a:",
			"    user: ops",
			"    auth_type: auto",
			"nodes:",
			"  node-a:",
			"    host_ref: h-a",
			"    identity_ref: id-a",
			"    proxy_jump: node-a",
			"    sudo_mode: auto",
		}, "\n") + "\n"
		if err := os.WriteFile(cfgPath, []byte(raw), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		store := NewDefaultStore(cfgPath, filepath.Join(dir, "key"))
		_, err := store.Load()
		if err == nil {
			t.Fatal("store.Load() accepted cyclic config, want fail-closed error")
		}
		if !errors.Is(err, ErrSchemaValidation) {
			t.Errorf("store.Load() err = %v, want ErrSchemaValidation", err)
		}
		if !strings.Contains(err.Error(), "xops config doctor") {
			t.Errorf("store.Load() err = %q, want actionable 'xops config doctor' hint", err.Error())
		}
	})
}

// TestP7Repro_MED14_ProxyJumpAndTargetRef_DoublePrefixAndCaseDrift verifies MED-14:
// ResolveProxyJumpChain rejects double-prefixed `openssh:openssh:22` and `openssh:OPENSSH:22`,
// never emits double-prefixed fallback targets, and enforces one case-insensitive reserved
// `openssh:` prefix rule across ParseTargetRef, IsOpenSSHNodeID, and ResolveProxyJumpChain.
func TestP7Repro_MED14_ProxyJumpAndTargetRef_DoublePrefixAndCaseDrift(t *testing.T) {
	t.Parallel()

	emptyCfg := &Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	emptyParser := &OpenSSHParser{}

	t.Run("ResolveProxyJumpChain_rejects_openssh_openssh_22", func(t *testing.T) {
		t.Parallel()
		got, err := ResolveProxyJumpChainWithConfig(emptyCfg, emptyParser, "openssh:openssh:22")
		if err == nil {
			t.Fatalf("MED-14: ResolveProxyJumpChain(\"openssh:openssh:22\") accepted and emitted %q, want error", got)
		}
	})

	t.Run("ResolveProxyJumpChain_fallback_does_not_emit_double_prefix", func(t *testing.T) {
		t.Parallel()
		cfg := &Configuration{
			Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
			Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
			Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		}
		cfg.Hosts.Set("h-ossh", models.Host{Address: "openssh", Port: 22})
		cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "auto"})
		cfg.Nodes.Set("box", models.Node{HostRef: "h-ossh", IdentityRef: "id1"})

		got, err := ResolveProxyJumpChainWithConfig(cfg, emptyParser, "box:2222")
		if err == nil && strings.HasPrefix(strings.ToLower(got), "openssh:openssh:") {
			t.Fatalf("MED-14: ResolveProxyJumpChain(\"box:2222\") emitted double-prefixed %q", got)
		}
	})

	t.Run("OPENSSH_uppercase_case_drift_in_ProxyJump_and_TargetRef", func(t *testing.T) {
		t.Parallel()

		if got, err := ResolveProxyJumpChainWithConfig(emptyCfg, emptyParser, "openssh:OPENSSH:22"); err == nil {
			t.Errorf("MED-14: ResolveProxyJumpChain(\"openssh:OPENSSH:22\") accepted and emitted %q, want error", got)
		}
		if got, err := ResolveProxyJumpChainWithConfig(emptyCfg, emptyParser, "OPENSSH:22"); err == nil {
			t.Errorf("MED-14: ResolveProxyJumpChain(\"OPENSSH:22\") accepted and emitted %q instead of treating OPENSSH: as reserved prefix", got)
		}
		if ref, err := ParseTargetRef("OPENSSH:bastion"); err != nil || !ref.OpenSSH || ref.Host != "bastion" {
			t.Errorf("MED-14: ParseTargetRef(\"OPENSSH:bastion\") = (%+v, %v), want OpenSSH=true Host=\"bastion\" (case-insensitive prefix)", ref, err)
		}
		if ref, err := ParseTargetRef("openssh:OPENSSH:22"); err == nil {
			t.Errorf("MED-14: ParseTargetRef(\"openssh:OPENSSH:22\") accepted double prefix as %+v, want error", ref)
		}
		if !IsOpenSSHNodeID("OPENSSH:bastion") {
			t.Errorf("MED-14: IsOpenSSHNodeID(\"OPENSSH:bastion\") = false, want true (case-insensitive parity with ValidateNodeAlias)")
		}
	})
}

// TestP7Repro_LOW2_ValidateNodeAlias_RejectsAtColonAndControlChars verifies LOW-2:
// ValidateNodeAlias enforces the single strict rule rejecting '@', ':', and control chars
// across direct calls, ValidateV2, and Repository write paths.
func TestP7Repro_LOW2_ValidateNodeAlias_RejectsAtColonAndControlChars(t *testing.T) {
	t.Parallel()

	badAliases := []string{
		"ops@web",
		"web:2222",
		"web\nprod",
		"web\rprod",
		"web\x00prod",
		"web\tprod",
	}

	t.Run("ValidateNodeAlias_direct", func(t *testing.T) {
		t.Parallel()
		for _, alias := range badAliases {
			if err := ValidateNodeAlias(alias); err == nil {
				t.Errorf("LOW-2: ValidateNodeAlias(%q) = nil, want error", alias)
			}
		}
	})

	t.Run("ValidateV2_and_Repository_reject_invalid_Node_Alias", func(t *testing.T) {
		t.Parallel()
		for _, alias := range badAliases {
			cfgV2 := &ConfigurationV2{
				SchemaVersion: 2,
				Credential:    CredentialConfig{Stores: map[string]StoreConfig{}},
				Hosts:         map[string]models.Host{"h1": {Address: "10.0.0.1", Port: 22}},
				Identities:    map[string]IdentityV2{"id1": {User: "ops", AuthType: "auto"}},
				Nodes: map[string]NodeV2{
					"web-node": {
						HostRef:     "h1",
						IdentityRef: "id1",
						Alias:       []string{alias},
						SudoMode:    models.SudoModeAuto,
					},
				},
			}
			if err := ValidateV2(cfgV2); err == nil {
				t.Errorf("LOW-2: ValidateV2 accepted invalid Node.Alias %q", alias)
			}

			repo := newP7W2dMemoryRepo(t, nil)
			if _, err := repo.CreateNodeContext(
				t.Context(),
				"web-node",
				models.Node{HostRef: "h1", IdentityRef: "id1", Alias: []string{alias}, SudoMode: models.SudoModeAuto},
				models.Host{Address: "10.0.0.1", Port: 22},
				models.Identity{User: "ops", AuthType: "auto"},
			); err == nil {
				t.Errorf("LOW-2: Repository.CreateNodeContext accepted invalid Node.Alias %q", alias)
			}
		}
	})
}
