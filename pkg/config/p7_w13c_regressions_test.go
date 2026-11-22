package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/fsx"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
)

func newW13cTwoNodeRepo(t *testing.T, sharedIdentity bool) (*Repository, Store) {
	t.Helper()
	dir := t.TempDir()
	store := NewDefaultStore(filepath.Join(dir, "config.yaml"), filepath.Join(dir, "config.key"))
	baseCfg := cloneConfiguration(nil)
	baseCfg.SchemaVersion = 2
	baseCfg.Credential = &CredentialConfig{
		DefaultStore:     "test-store",
		RememberPrompted: "always",
		Stores: map[string]StoreConfig{
			"test-store": {
				Type:   StoreTypeEncryptedFile,
				Path:   filepath.Join(dir, "vault"),
				Unlock: "prompt",
			},
		},
	}
	if err := store.Save(baseCfg); err != nil {
		t.Fatalf("store.Save: %v", err)
	}
	repo, err := NewRepositoryWithoutOpenSSH(baseCfg, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	bastionIdentRef := "id-bastion"
	appIdentRef := "id-app"
	if sharedIdentity {
		bastionIdentRef = "id-shared"
		appIdentRef = "id-shared"
	}
	if _, err := repo.CreateNodeContext(t.Context(), "saved-bastion",
		models.Node{HostRef: "h-bastion", IdentityRef: bastionIdentRef},
		models.Host{Address: "10.230.0.1", Port: 22},
		models.Identity{User: "ops", AuthType: "auto"},
	); err != nil {
		t.Fatalf("CreateNodeContext(saved-bastion): %v", err)
	}
	if _, err := repo.CreateNodeContext(t.Context(), "saved-app",
		models.Node{HostRef: "h-app", IdentityRef: appIdentRef},
		models.Host{Address: "10.230.0.2", Port: 22},
		models.Identity{User: "ops", AuthType: "auto"},
	); err != nil {
		t.Fatalf("CreateNodeContext(saved-app): %v", err)
	}
	return repo, store
}

func TestP7W13c_L4_13_M1_PublishWithActionPreservesIsUpdatePendingEntries(t *testing.T) {
	t.Parallel()

	t.Run("remote_to_remote_two_leases_src_confirm_preserves_dst_isUpdate", func(t *testing.T) {
		t.Parallel()
		assertW13cRemoteToRemoteIsUpdatePreserved(t)
	})

	for _, shared := range []bool{false, true} {
		name := "bastion_secret_bind_separate_identity_preserves_app_isUpdate"
		if shared {
			name = "bastion_secret_bind_shared_identity_preserves_app_isUpdate"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assertW13cBastionSecretBindPreservesAppIsUpdate(t, shared)
		})
	}

	t.Run("concurrent_edit_to_same_node_detects_ErrConfigConflict_on_confirm", func(t *testing.T) {
		t.Parallel()
		assertW13cConcurrentEditTriggersConflict(t)
	})
}

func assertW13cRemoteToRemoteIsUpdatePreserved(t *testing.T) {
	t.Helper()
	repo, store := newW13cTwoNodeRepo(t, false)

	err := repo.WithPendingNode(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "saved-app"},
		ExistingUpdate: PendingNodeUpdate{
			Enabled:  true,
			JumpHost: "saved-bastion",
			Alias:    "app-dst",
			Tags:     []string{"dst"},
		},
	}, func(dstLease PendingLease) error {
		if dstLease.NodeID() != "saved-app" || !repo.IsPendingNode("saved-app") {
			t.Fatalf("expected saved-app pending, got id=%q pending=%v", dstLease.NodeID(), repo.IsPendingNode("saved-app"))
		}
		if innerErr := repo.WithPendingNode(t.Context(), EnsureNodeOptions{
			Target: ConnectionTarget{Selector: "ops@10.230.0.99:22"},
		}, func(srcNewLease PendingLease) error {
			return srcNewLease.Confirm(t.Context())
		}); innerErr != nil {
			return innerErr
		}
		if !repo.IsPendingNode("saved-app") {
			t.Fatal("unrelated new-node commit wiped active isUpdate pending entry for saved-app")
		}

		if innerErr := repo.WithPendingNode(t.Context(), EnsureNodeOptions{
			Target: ConnectionTarget{Selector: "saved-bastion"},
			ExistingUpdate: PendingNodeUpdate{
				Enabled: true,
				Tags:    []string{"src"},
			},
		}, func(srcUpdateLease PendingLease) error {
			return srcUpdateLease.Confirm(t.Context())
		}); innerErr != nil {
			return innerErr
		}
		if !repo.IsPendingNode("saved-app") {
			t.Fatal("unrelated isUpdate commit wiped active isUpdate pending entry for saved-app")
		}

		stagedNode, _, _, rErr := repo.Resolve("saved-app")
		if rErr != nil || stagedNode.ProxyJump != "saved-bastion" {
			t.Fatalf("staged Resolve(saved-app) = (%+v, %v), want ProxyJump=saved-bastion", stagedNode, rErr)
		}
		return dstLease.Confirm(t.Context())
	})
	if err != nil {
		t.Fatalf("WithPendingNode: %v", err)
	}
	if repo.IsPendingNode("saved-app") {
		t.Fatal("saved-app remained pending after Confirm")
	}
	disk, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	persisted, ok := disk.Nodes.Get("saved-app")
	if !ok || persisted.ProxyJump != "saved-bastion" || len(persisted.Alias) != 1 || persisted.Alias[0] != "app-dst" {
		t.Fatalf("persisted saved-app = (%+v, %v), want ProxyJump=saved-bastion Alias=[app-dst]", persisted, ok)
	}
}

func assertW13cBastionSecretBindPreservesAppIsUpdate(t *testing.T, shared bool) {
	t.Helper()
	repo, store := newW13cTwoNodeRepo(t, shared)
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	bastionRef := &credential.Ref{StoreID: "test-store", ItemID: "bastion-login-pw"}
	appRef := &credential.Ref{StoreID: "test-store", ItemID: "app-passphrase"}

	err := repo.WithPendingNode(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "saved-app"},
		ExistingUpdate: PendingNodeUpdate{
			Enabled:      true,
			JumpHost:     "saved-bastion",
			RememberAuth: true,
			IdentityFile: keyPath,
		},
	}, func(appLease PendingLease) error {
		appSnapBefore, rErr := repo.ResolveConnection("saved-app")
		if rErr != nil || appSnapBefore.UpdateRef == nil {
			t.Fatalf("ResolveConnection(saved-app) before Confirm: (%+v, %v)", appSnapBefore, rErr)
		}
		appAuthVer := string(appSnapBefore.UpdateRef.AuthVersion[:])

		bastionSnap, bErr := repo.ResolveConnection("saved-bastion")
		if bErr != nil || bastionSnap.UpdateRef == nil {
			t.Fatalf("ResolveConnection(saved-bastion): (%+v, %v)", bastionSnap, bErr)
		}
		updater := NewRepositoryConfigUpdater(repo)
		outcome, _, bindErr := updater.ApplyCredentialRefAtVersion(
			t.Context(),
			credential.Target{NodeID: "saved-bastion", Kind: credential.KindLoginPassword},
			string(bastionSnap.UpdateRef.AuthVersion[:]),
			bastionRef,
		)
		if bindErr != nil || !outcome.Applied {
			t.Fatalf("bastion ApplyCredentialRefAtVersion: outcome=%+v err=%v", outcome, bindErr)
		}
		if !repo.IsPendingNode("saved-app") {
			t.Fatal("bastion credential commit wiped active isUpdate pending entry for saved-app")
		}
		if cErr := appLease.Confirm(t.Context()); cErr != nil {
			return cErr
		}
		appOutcome, _, appBindErr := updater.ApplyCredentialRefAtVersion(
			t.Context(),
			credential.Target{NodeID: "saved-app", Kind: credential.KindPassphrase, KeyFingerprint: "SHA256:w13c-app-fp"},
			appAuthVer,
			appRef,
		)
		if appBindErr != nil || !appOutcome.Applied {
			t.Fatalf("app ApplyCredentialRefAtVersion after Confirm: outcome=%+v err=%v", appOutcome, appBindErr)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithPendingNode: %v", err)
	}
	disk, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	appNode, _ := disk.Nodes.Get("saved-app")
	appIdent, _ := disk.Identities.Get(appNode.IdentityRef)
	if appNode.ProxyJump != "saved-bastion" || appIdent.PassphraseRef == nil || appIdent.PassphraseRef.ItemID != appRef.ItemID {
		t.Fatalf("persisted saved-app = (node=%+v ident=%+v), want ProxyJump=saved-bastion and PassphraseRef=%+v", appNode, appIdent, appRef)
	}
	bastionNode, _ := disk.Nodes.Get("saved-bastion")
	bastionIdent, _ := disk.Identities.Get(bastionNode.IdentityRef)
	if bastionIdent.LoginPasswordRef == nil || bastionIdent.LoginPasswordRef.ItemID != bastionRef.ItemID {
		t.Fatalf("persisted saved-bastion ident = %+v, want LoginPasswordRef=%+v", bastionIdent, bastionRef)
	}
}

func assertW13cConcurrentEditTriggersConflict(t *testing.T) {
	t.Helper()
	repo, store := newW13cTwoNodeRepo(t, false)

	var confirmErr error
	err := repo.WithPendingNode(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "saved-app"},
		ExistingUpdate: PendingNodeUpdate{
			Enabled:  true,
			JumpHost: "saved-bastion",
			Tags:     []string{"staged-tag"},
		},
	}, func(lease PendingLease) error {
		if _, tagErr := repo.UpdateNodeTagsContext(t.Context(), []string{"saved-app"}, []string{"concurrent-tag"}, true); tagErr != nil {
			t.Fatalf("UpdateNodeTagsContext: %v", tagErr)
		}
		if !repo.IsPendingNode("saved-app") {
			t.Fatal("concurrent edit to saved-app wiped isUpdate entry instead of preserving CAS conflict detection")
		}
		confirmErr = lease.Confirm(t.Context())
		return confirmErr
	})
	if !errors.Is(err, ErrConfigConflict) || !errors.Is(confirmErr, ErrConfigConflict) {
		t.Fatalf("Confirm after concurrent edit = %v, want ErrConfigConflict", err)
	}
	if repo.IsPendingNode("saved-app") {
		t.Fatal("failed Confirm leaked pending entry for saved-app after WithPendingNode returned")
	}
	disk, loadErr := store.Load()
	if loadErr != nil {
		t.Fatalf("store.Load: %v", loadErr)
	}
	persisted, _ := disk.Nodes.Get("saved-app")
	if persisted.ProxyJump != "" || len(persisted.Tags) != 1 || persisted.Tags[0] != "concurrent-tag" {
		t.Fatalf("persisted saved-app = %+v, want concurrent-tag preserved without staged overwrite", persisted)
	}
}

func TestP7W13c_L4_13_M2_ValidateSavedNodeJumpCycleNormalizesAddressAndOpenSSH(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host ssh-bastion
    HostName 10.231.0.1
    Port 22
    User ops

Host ssh-gw-to-app
    HostName 10.231.0.50
    Port 22
    User ops
    ProxyJump ssh-app-ep

Host ssh-app-ep
    HostName 10.231.0.1
    Port 22
    User ops

Host ssh-edited-ep
    HostName 10.231.0.99
    Port 22
    User ops

Host ssh-mid-to-edited
    HostName 10.231.0.60
    Port 22
    User ops
    ProxyJump 10.231.0.99
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}

	makeBase := func() *Configuration {
		cfg := cloneConfiguration(nil)
		cfg.Hosts.Set("h-a", models.Host{Address: "10.231.0.1", Port: 22})
		cfg.Hosts.Set("h-b", models.Host{Address: "10.231.0.2", Port: 22})
		cfg.Hosts.Set("h-c", models.Host{Address: "10.231.0.99", Port: 22})
		cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
		cfg.Nodes.Set("node-a", models.Node{HostRef: "h-a", IdentityRef: "id-ops"})
		cfg.Nodes.Set("node-b", models.Node{HostRef: "h-b", IdentityRef: "id-ops"})
		cfg.Nodes.Set("node-c", models.Node{HostRef: "h-c", IdentityRef: "id-ops"})
		return cfg
	}

	t.Run("unique_host_address_hop_2hop_cycle_through_openssh", func(t *testing.T) {
		t.Parallel()
		cfg := makeBase()
		cfg.Nodes.Set("node-a", models.Node{HostRef: "h-a", IdentityRef: "id-ops", ProxyJump: "10.231.0.2"})
		cfg.Nodes.Set("node-b", models.Node{HostRef: "h-b", IdentityRef: "id-ops", ProxyJump: "openssh:ssh-bastion"})

		var cycleErr *ssh.ProxyCycleError
		if err := ValidateSavedNodeJumpCycleWithOpenSSH(cfg, parser, "node-a"); !errors.As(err, &cycleErr) {
			t.Errorf("ValidateSavedNodeJumpCycleWithOpenSSH(node-a via 10.231.0.2 -> openssh:ssh-bastion) = %v, want *ssh.ProxyCycleError", err)
		}
		// Reverse reachability when editing node-b: node-a reaches node-b via unique Host.Address "10.231.0.2".
		if err := ValidateSavedNodeJumpCycleWithOpenSSH(cfg, parser, "node-b"); !errors.As(err, &cycleErr) {
			t.Errorf("ValidateSavedNodeJumpCycleWithOpenSSH(node-b reverse from node-a via 10.231.0.2) = %v, want *ssh.ProxyCycleError", err)
		}
	})

	t.Run("unprefixed_openssh_alias_1hop_and_2hop_cycles", func(t *testing.T) {
		t.Parallel()
		for _, jump := range []string{"ssh-bastion", "ssh-gw-to-app"} {
			cfg := makeBase()
			cfg.Nodes.Set("node-a", models.Node{HostRef: "h-a", IdentityRef: "id-ops", ProxyJump: jump})
			var cycleErr *ssh.ProxyCycleError
			if err := ValidateSavedNodeJumpCycleWithOpenSSH(cfg, parser, "node-a"); !errors.As(err, &cycleErr) {
				t.Errorf("ValidateSavedNodeJumpCycleWithOpenSSH(node-a, unprefixed %q) = %v, want *ssh.ProxyCycleError", jump, err)
			}
		}
	})

	t.Run("reverse_reachability_through_openssh_duplicate_hop_on_endpoint_edit", func(t *testing.T) {
		t.Parallel()
		cfg := makeBase()
		// node-a jumps via "10.231.0.99,openssh:ssh-edited-ep"; node-c was just edited to 10.231.0.99.
		cfg.Nodes.Set("node-a", models.Node{HostRef: "h-a", IdentityRef: "id-ops", ProxyJump: "10.231.0.99,openssh:ssh-edited-ep"})
		var cycleErr *ssh.ProxyCycleError
		if err := ValidateSavedNodeJumpCycleWithOpenSSH(cfg, parser, "node-c"); !errors.As(err, &cycleErr) {
			t.Errorf("ValidateSavedNodeJumpCycleWithOpenSSH(node-c duplicate hop in node-a) = %v, want *ssh.ProxyCycleError", err)
		}
	})

	t.Run("unrelated_broken_node_does_not_fail_edit_of_unrelated_node", func(t *testing.T) {
		t.Parallel()
		cfg := makeBase()
		cfg.Hosts.Set("h-broken", models.Host{Address: "10.231.0.200", Port: 22})
		cfg.Nodes.Set("broken-unrelated", models.Node{HostRef: "h-broken", IdentityRef: "id-ops", ProxyJump: "missing-unknown-hop"})
		if err := ValidateSavedNodeJumpCycleWithOpenSSH(cfg, parser, "node-c"); err != nil {
			t.Fatalf("ValidateSavedNodeJumpCycleWithOpenSSH(unrelated node-c) failed because of unrelated broken node: %v", err)
		}
	})

	t.Run("staged_pending_update_normalizes_unprefixed_hop", func(t *testing.T) {
		t.Parallel()
		cfg := makeBase()
		cfg.Nodes.Set("node-a", models.Node{HostRef: "h-a", IdentityRef: "id-ops", ProxyJump: "10.231.0.2"})
		cfg.Nodes.Set("node-b", models.Node{HostRef: "h-b", IdentityRef: "id-ops", ProxyJump: "openssh:ssh-bastion"})
		repo, err := NewRepositoryWithOpenSSHParser(cfg, &repositoryTestStore{}, parser)
		if err != nil {
			t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
		}
		var cycleErr *ssh.ProxyCycleError
		if err := repo.WithPendingNode(t.Context(), EnsureNodeOptions{
			Target: ConnectionTarget{Selector: "node-a"},
			ExistingUpdate: PendingNodeUpdate{
				Enabled: true,
				Tags:    []string{"prod"},
			},
		}, func(PendingLease) error {
			t.Fatal("callback must not run on cyclic staged update")
			return nil
		}); !errors.As(err, &cycleErr) {
			t.Fatalf("WithPendingNode(node-a with cyclic Host.Address jump) = %v, want *ssh.ProxyCycleError", err)
		}
	})
}

func TestP7W13c_L3_13_M1_Tier3ProxyCommandShadowsTier4ProxyJumpInConfig(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host loop
    HostName 10.232.0.1
    Port 22
    User ops
    ProxyJump loop

Host ssh-app
    HostName 10.232.0.2
    Port 22
    User ops
    ProxyJump ssh-bastion

Host ssh-bastion
    HostName 10.232.0.10
    Port 22
    User ops

Host bad-syntax
    HostName 10.232.0.3
    Port 22
    User ops
    ProxyJump openssh:openssh:bad
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}

	for _, tc := range []struct {
		name     string
		proxyCmd string
	}{
		{"Tier3_active_ProxyCommand", "nc %h %p"},
		{"Tier3_ProxyCommand_none", "none"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertW13cTier3ProxyCommandShadowsTier4Case(t, parser, tc.proxyCmd)
		})
	}
}

func assertW13cTier3ProxyCommandShadowsTier4Case(t *testing.T, parser *OpenSSHParser, proxyCmd string) {
	t.Helper()
	cfg := cloneConfiguration(nil)
	opts := &ssh.Options{}
	if setErr := opts.Set(ssh.OptionProxyCommand, proxyCmd); setErr != nil {
		t.Fatalf("Set ProxyCommand=%q: %v", proxyCmd, setErr)
	}
	cfg.SSHOptions = opts
	cfg.Hosts.Set("h-saved-loop", models.Host{Address: "10.232.0.20", Port: 22})
	cfg.Hosts.Set("h-saved-valid", models.Host{Address: "10.232.0.21", Port: 22})
	cfg.Hosts.Set("h-bastion", models.Host{Address: "10.232.0.30", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("bastion", models.Node{HostRef: "h-bastion", IdentityRef: "id-ops"})
	cfg.Nodes.Set("saved-loop", models.Node{HostRef: "h-saved-loop", IdentityRef: "id-ops", ProxyJump: "openssh:loop"})
	cfg.Nodes.Set("saved-valid", models.Node{HostRef: "h-saved-valid", IdentityRef: "id-ops", ProxyJump: "bastion"})

	dir := t.TempDir()
	store := NewDefaultStore(filepath.Join(dir, "config.yaml"), filepath.Join(dir, "config.key"))
	if saveErr := store.Save(cfg); saveErr != nil {
		t.Fatalf("store.Save: %v", saveErr)
	}
	repo, rErr := NewRepositoryWithOpenSSHParser(cfg, store, parser)
	if rErr != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", rErr)
	}
	readOnlyProv := NewProviderWithOpenSSHParser(cfg, parser)

	for _, tgt := range []ConnectionTarget{
		{Selector: "loop"},
		{Selector: "openssh:loop"},
		{Selector: "loop", User: "alice", HasUser: true},
		{Selector: "loop", Port: 2222, HasPort: true},
		{Selector: "ssh-app"},
		{Selector: "ssh-app", User: "alice", HasUser: true},
	} {
		res, resolveErr := ResolveTarget(readOnlyProv, tgt)
		if resolveErr != nil || res.ProxyJump != "" {
			t.Errorf("ResolveTarget(%+v) = (jump=%q, err=%v), want empty ProxyJump and nil err", tgt, res.ProxyJump, resolveErr)
		}
	}

	if wpErr := WithPendingNode(t.Context(), readOnlyProv, EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "loop"},
	}, func(lease PendingLease) error {
		if lease.NodeID() != "openssh:loop" {
			t.Errorf("read-only WithPendingNode(loop) NodeID = %q, want openssh:loop", lease.NodeID())
		}
		return nil
	}); wpErr != nil {
		t.Fatalf("read-only WithPendingNode(loop): %v", wpErr)
	}

	var confirmedDerivedID string
	if wpErr := repo.WithPendingNode(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "ssh-app", User: "alice", HasUser: true},
	}, func(lease PendingLease) error {
		confirmedDerivedID = lease.NodeID()
		return lease.Confirm(t.Context())
	}); wpErr != nil {
		t.Fatalf("repo.WithPendingNode(alice@ssh-app): %v", wpErr)
	}
	savedDerived, ok := repo.GetNode(confirmedDerivedID)
	if !ok || savedDerived.ProxyJump != "" {
		t.Fatalf("confirmed derived node %q = (%+v, %v), want empty ProxyJump (must not promote shadowed Tier-4 jump to Tier 2)",
			confirmedDerivedID, savedDerived, ok)
	}

	ensured, ensErr := repo.EnsureNodeContext(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "ssh-app", Port: 2222, HasPort: true},
	})
	if ensErr != nil {
		t.Fatalf("EnsureNodeContext(ssh-app:2222): %v", ensErr)
	}
	ensuredNode, ok := repo.GetNode(ensured.NodeID)
	if !ok || ensuredNode.ProxyJump != "" {
		t.Fatalf("EnsureNodeContext node %q = (%+v, %v), want empty ProxyJump", ensured.NodeID, ensuredNode, ok)
	}

	assertW13cTier3DoesNotShadowHigherTiersOrBadSyntax(t, readOnlyProv)
}

func assertW13cTier3DoesNotShadowHigherTiersOrBadSyntax(t *testing.T, readOnlyProv *Provider) {
	t.Helper()
	resValid, vErr := ResolveTarget(readOnlyProv, ConnectionTarget{Selector: "saved-valid"})
	if vErr != nil || resValid.ProxyJump != "bastion" {
		t.Fatalf("ResolveTarget(saved-valid) = (jump=%q, err=%v), want ProxyJump=bastion", resValid.ProxyJump, vErr)
	}
	var cycleErr *ssh.ProxyCycleError
	if _, cErr := ResolveTarget(readOnlyProv, ConnectionTarget{Selector: "saved-loop"}); !errors.As(cErr, &cycleErr) {
		t.Fatalf("ResolveTarget(saved-loop) = %v, want *ssh.ProxyCycleError (Tier 2 > Tier 3)", cErr)
	}
	resT1, t1Err := ResolveTarget(readOnlyProv, ConnectionTarget{
		Selector:     "ssh-app",
		ProxyJump:    "bastion",
		HasProxyJump: true,
	})
	if t1Err != nil || resT1.ProxyJump != "bastion" {
		t.Fatalf("ResolveTarget(ssh-app, -J bastion) = (jump=%q, err=%v), want bastion", resT1.ProxyJump, t1Err)
	}
	if _, badErr := ResolveTarget(readOnlyProv, ConnectionTarget{Selector: "bad-syntax"}); badErr == nil {
		t.Fatal("ResolveTarget(bad-syntax) unexpectedly succeeded under Tier-3 ProxyCommand")
	}
}

func TestP7W13c_L4_13_L1_MigrationFilesHandleBoundVerificationAndSync(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	keyPath := filepath.Join(dir, "secret.key")
	m, err := NewCredentialMigrator(cfgPath, keyPath)
	if err != nil {
		t.Fatalf("NewCredentialMigrator: %v", err)
	}

	t.Run("ensureBackup_verifies_content_and_mode_on_single_handle", func(t *testing.T) {
		t.Parallel()
		sub := t.TempDir()
		content := []byte("schema_version: 2\n")

		// Valid 0600 backup succeeds.
		okPath := filepath.Join(sub, "ok.bak")
		if err := os.WriteFile(okPath, content, 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if err := m.ensureBackup(okPath, content); err != nil {
			t.Fatalf("ensureBackup(valid 0600): %v", err)
		}

		// Symlink backup fails closed with fsx.ErrSymlink.
		linkPath := filepath.Join(sub, "link.bak")
		if err := os.Symlink(okPath, linkPath); err == nil {
			if err := m.ensureBackup(linkPath, content); !errors.Is(err, fsx.ErrSymlink) {
				t.Errorf("ensureBackup(symlink) = %v, want fsx.ErrSymlink", err)
			}
		}

		// Loose mode on Unix fails closed from the same handle Stat.
		if runtime.GOOS != "windows" {
			loosePath := filepath.Join(sub, "loose.bak")
			if err := os.WriteFile(loosePath, content, 0o644); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			if err := os.Chmod(loosePath, 0o644); err != nil {
				t.Fatalf("Chmod: %v", err)
			}
			if err := m.ensureBackup(loosePath, content); err == nil || !strings.Contains(err.Error(), "0600") {
				t.Errorf("ensureBackup(0644) = %v, want mode 0600 error", err)
			}
		}
	})

	t.Run("readAndSyncMigrationConfiguration_rejects_symlink_dir_and_mismatch", func(t *testing.T) {
		t.Parallel()
		sub := t.TempDir()
		content := []byte("schema_version: 2\nnodes: {}\n")
		goodPath := filepath.Join(sub, "config.yaml")
		if err := os.WriteFile(goodPath, content, 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		digest := migrationDigest(content)

		got, err := readAndSyncMigrationConfiguration(goodPath, digest, "conflict")
		if err != nil || string(got) != string(content) {
			t.Fatalf("readAndSyncMigrationConfiguration(good) = (%q, %v), want %q", got, err, content)
		}

		// Digest mismatch returns ErrConfigConflict.
		if _, err := readAndSyncMigrationConfiguration(goodPath, migrationDigest([]byte("other")), "changed"); !errors.Is(err, ErrConfigConflict) {
			t.Errorf("readAndSyncMigrationConfiguration(mismatch) = %v, want ErrConfigConflict", err)
		}

		// Symlink target fails closed with fsx.ErrSymlink.
		linkPath := filepath.Join(sub, "config.link.yaml")
		if err := os.Symlink(goodPath, linkPath); err == nil {
			if _, err := readAndSyncMigrationConfiguration(linkPath, digest, "conflict"); !errors.Is(err, fsx.ErrSymlink) {
				t.Errorf("readAndSyncMigrationConfiguration(symlink) = %v, want fsx.ErrSymlink", err)
			}
		}

		// Directory target fails closed with fsx.ErrNonRegular.
		dirPath := filepath.Join(sub, "as-dir")
		if err := os.MkdirAll(dirPath, 0o700); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if _, err := readAndSyncMigrationConfiguration(dirPath, digest, "conflict"); !errors.Is(err, fsx.ErrNonRegular) {
			t.Errorf("readAndSyncMigrationConfiguration(dir) = %v, want fsx.ErrNonRegular", err)
		}
	})
}
