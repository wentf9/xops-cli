package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/fsx"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
)

func newW14cOpenSSHRepoFixture(t *testing.T, sshCfg string) (*Repository, Store) {
	t.Helper()
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	dir := t.TempDir()
	store := NewDefaultStore(filepath.Join(dir, "config.yaml"), filepath.Join(dir, "config.key"))
	baseCfg := cloneConfiguration(nil)
	baseCfg.SchemaVersion = 2
	baseCfg.Credential = &CredentialConfig{
		DefaultStore:     "mem-store",
		RememberPrompted: "always",
		Stores: map[string]StoreConfig{
			"mem-store": {Type: StoreTypeEncryptedFile, Path: filepath.Join(dir, "vault"), Unlock: "prompt"},
		},
	}
	if err := store.Save(baseCfg); err != nil {
		t.Fatalf("store.Save: %v", err)
	}
	repo, err := NewRepositoryWithOpenSSHParser(baseCfg, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}
	return repo, store
}

func TestP7W14c_L4_14_M1_RepositoryEnforcesOpenSSHJumpCyclesAcrossAllMutationPaths(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host ssh-app-a
    HostName 10.241.0.1
    Port 22
    User ops

Host ssh-app-b
    HostName 10.241.0.2
    Port 22
    User ops

Host ssh-gw-99
    HostName 10.241.0.99
    Port 22
    User ops
`

	t.Run("WithPendingNode_staged_update_rejects_reverse_openssh_cycle_and_alias_dup_hop", func(t *testing.T) {
		t.Parallel()
		assertW14cStagedPendingUpdateCycles(t, sshCfg)
	})

	t.Run("confirmPendingEntry_catches_concurrent_upstream_edit_forming_openssh_cycle", func(t *testing.T) {
		t.Parallel()
		assertW14cConfirmConcurrentCycle(t, sshCfg)
	})

	t.Run("EnsureNodeContext_and_CreateNodeContext_reject_reverse_openssh_cycles", func(t *testing.T) {
		t.Parallel()
		assertW14cCreateAndEnsureCycles(t, sshCfg)
	})

	t.Run("ReplaceNodeAtRef_and_NodeCredentialEdit_enforce_cycles_but_allow_non_routing_and_clear_repair", func(t *testing.T) {
		t.Parallel()
		assertW14cReplaceAndCredEditCycles(t, sshCfg)
	})
}

func assertW14cStagedPendingUpdateCycles(t *testing.T, sshCfg string) {
	t.Helper()
	repo, _ := newW14cOpenSSHRepoFixture(t, sshCfg)
	if _, err := repo.CreateNodeContext(t.Context(), "app-b",
		models.Node{HostRef: "h-b", IdentityRef: "id-ops"},
		models.Host{Address: "10.241.0.2", Port: 22},
		models.Identity{User: "ops", AuthType: "auto"},
	); err != nil {
		t.Fatalf("CreateNodeContext(app-b): %v", err)
	}
	if _, err := repo.CreateNodeContext(t.Context(), "app-a",
		models.Node{HostRef: "h-a", IdentityRef: "id-ops", ProxyJump: "app-b"},
		models.Host{Address: "10.241.0.1", Port: 22},
		models.Identity{User: "ops", AuthType: "auto"},
	); err != nil {
		t.Fatalf("CreateNodeContext(app-a): %v", err)
	}
	var cycleErr *ssh.ProxyCycleError
	err := repo.WithPendingNode(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "app-b"},
		ExistingUpdate: PendingNodeUpdate{
			Enabled:  true,
			JumpHost: "ssh-app-a",
		},
	}, func(PendingLease) error {
		t.Fatal("callback must not run when staged update closes reverse OpenSSH cycle")
		return nil
	})
	if !errors.As(err, &cycleErr) {
		t.Fatalf("WithPendingNode(app-b -J ssh-app-a) = %v, want *ssh.ProxyCycleError", err)
	}

	if _, err := repo.CreateNodeContext(t.Context(), "app-dup",
		models.Node{HostRef: "h-dup", IdentityRef: "id-ops", ProxyJump: "dup-alias.example.com,openssh:ssh-app-b"},
		models.Host{Address: "10.241.0.3", Port: 22},
		models.Identity{User: "ops", AuthType: "auto"},
	); err != nil {
		t.Fatalf("CreateNodeContext(app-dup): %v", err)
	}
	err = repo.WithPendingNode(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "app-b"},
		ExistingUpdate: PendingNodeUpdate{
			Enabled: true,
			Alias:   "dup-alias.example.com",
		},
	}, func(PendingLease) error {
		t.Fatal("callback must not run when staged alias creates duplicate OpenSSH hop")
		return nil
	})
	if !errors.As(err, &cycleErr) {
		t.Fatalf("WithPendingNode(app-b alias dup-alias.example.com) = %v, want *ssh.ProxyCycleError", err)
	}
}

func assertW14cConfirmConcurrentCycle(t *testing.T, sshCfg string) {
	t.Helper()
	repo, store := newW14cOpenSSHRepoFixture(t, sshCfg)
	if _, err := repo.CreateNodeContext(t.Context(), "app-a",
		models.Node{HostRef: "h-a", IdentityRef: "id-ops"},
		models.Host{Address: "10.241.0.1", Port: 22},
		models.Identity{User: "ops", AuthType: "auto"},
	); err != nil {
		t.Fatalf("CreateNodeContext(app-a): %v", err)
	}
	if _, err := repo.CreateNodeContext(t.Context(), "app-b",
		models.Node{HostRef: "h-b", IdentityRef: "id-ops"},
		models.Host{Address: "10.241.0.2", Port: 22},
		models.Identity{User: "ops", AuthType: "auto"},
	); err != nil {
		t.Fatalf("CreateNodeContext(app-b): %v", err)
	}

	var cycleErr *ssh.ProxyCycleError
	err := repo.WithPendingNode(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "app-b"},
		ExistingUpdate: PendingNodeUpdate{
			Enabled:  true,
			JumpHost: "openssh:ssh-app-a",
		},
	}, func(lease PendingLease) error {
		view := repo.View()
		nodeA, _ := view.Configuration.Nodes.Get("app-a")
		hostA, _ := view.Configuration.Hosts.Get(nodeA.HostRef)
		identA, _ := view.Configuration.Identities.Get(nodeA.IdentityRef)
		nodeA.ProxyJump = "app-b"
		if editErr := repo.ReplaceNodeAtRefContext(t.Context(), view.NodeRefs["app-a"], "app-a", nodeA, hostA, identA); editErr != nil {
			t.Fatalf("concurrent ReplaceNodeAtRefContext(app-a): %v", editErr)
		}
		return lease.Confirm(t.Context())
	})
	if !errors.As(err, &cycleErr) {
		t.Fatalf("lease.Confirm after concurrent upstream edit = %v, want *ssh.ProxyCycleError", err)
	}
	disk, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	if nodeB, _ := disk.Nodes.Get("app-b"); nodeB.ProxyJump != "" {
		t.Fatalf("app-b ProxyJump leaked to disk despite cycle rejection: %+v", nodeB)
	}
}

func assertW14cCreateAndEnsureCycles(t *testing.T, sshCfg string) {
	t.Helper()
	repo, _ := newW14cOpenSSHRepoFixture(t, sshCfg)
	if _, err := repo.CreateNodeContext(t.Context(), "app-a",
		models.Node{HostRef: "h-a", IdentityRef: "id-ops", ProxyJump: "10.241.0.2"},
		models.Host{Address: "10.241.0.1", Port: 22},
		models.Identity{User: "ops", AuthType: "auto"},
	); err != nil {
		t.Fatalf("CreateNodeContext(app-a): %v", err)
	}

	var cycleErr *ssh.ProxyCycleError
	if _, err := repo.EnsureNodeContext(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{
			Selector:     "ops@10.241.0.2:22",
			ProxyJump:    "openssh:ssh-app-a",
			HasProxyJump: true,
		},
	}); !errors.As(err, &cycleErr) {
		t.Errorf("EnsureNodeContext(ops@10.241.0.2:22 -J openssh:ssh-app-a) = %v, want *ssh.ProxyCycleError", err)
	}

	if _, err := repo.CreateNodeContext(t.Context(), "app-b",
		models.Node{HostRef: "h-b", IdentityRef: "id-ops", ProxyJump: "openssh:ssh-app-a"},
		models.Host{Address: "10.241.0.2", Port: 22},
		models.Identity{User: "ops", AuthType: "auto"},
	); !errors.As(err, &cycleErr) {
		t.Errorf("CreateNodeContext(app-b -J openssh:ssh-app-a) = %v, want *ssh.ProxyCycleError", err)
	}

	if _, err := repo.CreateNodeContext(t.Context(), "app-dup",
		models.Node{HostRef: "h-dup", IdentityRef: "id-ops", ProxyJump: "dup-box.example.com,openssh:ssh-gw-99"},
		models.Host{Address: "10.241.0.3", Port: 22},
		models.Identity{User: "ops", AuthType: "auto"},
	); err != nil {
		t.Fatalf("CreateNodeContext(app-dup): %v", err)
	}
	if _, err := repo.CreateNodeContext(t.Context(), "gw-node",
		models.Node{HostRef: "h-gw", IdentityRef: "id-ops", Alias: []string{"dup-box.example.com"}},
		models.Host{Address: "10.241.0.99", Port: 22},
		models.Identity{User: "ops", AuthType: "auto"},
	); !errors.As(err, &cycleErr) {
		t.Errorf("CreateNodeContext(gw-node alias creating duplicate hop) = %v, want *ssh.ProxyCycleError", err)
	}

	if _, err := repo.CreateNodeContext(t.Context(), "fwd-app",
		models.Node{HostRef: "h-fwd-app", IdentityRef: "id-ops", ProxyJump: "future-bastion"},
		models.Host{Address: "10.241.0.1", Port: 22},
		models.Identity{User: "ops", AuthType: "auto"},
	); err != nil {
		t.Fatalf("CreateNodeContext(fwd-app forward ref): %v", err)
	}
	if _, err := repo.CreateNodeContext(t.Context(), "future-bastion",
		models.Node{HostRef: "h-fut-b", IdentityRef: "id-ops", ProxyJump: "openssh:ssh-app-a"},
		models.Host{Address: "10.241.0.50", Port: 22},
		models.Identity{User: "ops", AuthType: "auto"},
	); !errors.As(err, &cycleErr) {
		t.Errorf("CreateNodeContext(future-bastion closing reverse cycle with fwd-app) = %v, want *ssh.ProxyCycleError", err)
	}
}

func assertW14cReplaceAndCredEditCycles(t *testing.T, sshCfg string) {
	t.Helper()
	repo, _ := newW14cOpenSSHRepoFixture(t, sshCfg)
	if _, err := repo.CreateNodeContext(t.Context(), "app-b",
		models.Node{HostRef: "h-b", IdentityRef: "id-b"},
		models.Host{Address: "10.241.0.2", Port: 22},
		models.Identity{User: "ops", AuthType: "auto"},
	); err != nil {
		t.Fatalf("CreateNodeContext(app-b): %v", err)
	}
	if _, err := repo.CreateNodeContext(t.Context(), "app-a",
		models.Node{HostRef: "h-a", IdentityRef: "id-a", ProxyJump: "app-b"},
		models.Host{Address: "10.241.0.1", Port: 22},
		models.Identity{User: "ops", AuthType: "auto"},
	); err != nil {
		t.Fatalf("CreateNodeContext(app-a): %v", err)
	}

	var cycleErr *ssh.ProxyCycleError
	view := repo.View()
	nodeB, _ := view.Configuration.Nodes.Get("app-b")
	hostB, _ := view.Configuration.Hosts.Get(nodeB.HostRef)
	identB, _ := view.Configuration.Identities.Get(nodeB.IdentityRef)
	cyclicNodeB := cloneNode(nodeB)
	cyclicNodeB.ProxyJump = "openssh:ssh-app-a"
	if err := repo.ReplaceNodeAtRefContext(t.Context(), view.NodeRefs["app-b"], "app-b", cyclicNodeB, hostB, identB); !errors.As(err, &cycleErr) {
		t.Errorf("ReplaceNodeAtRefContext(app-b cyclic jump) = %v, want *ssh.ProxyCycleError", err)
	}

	refB := view.NodeRefs["app-b"]
	updater := repo.NodeCredentialEdit(refB, "app-b", cyclicNodeB, hostB, identB)
	_, _, err := updater.ApplyCredentialRefAtVersion(
		t.Context(),
		credential.Target{NodeID: "app-b", Kind: credential.KindLoginPassword},
		string(refB.Version[:]),
		&credential.Ref{StoreID: "mem-store", ItemID: "pw-b"},
	)
	if !errors.As(err, &cycleErr) {
		t.Errorf("NodeCredentialEdit(app-b cyclic jump) = %v, want *ssh.ProxyCycleError", err)
	}

	assertW14cNonRoutingAndClearRepairAllowed(t, sshCfg)
}

func assertW14cNonRoutingAndClearRepairAllowed(t *testing.T, sshCfg string) {
	t.Helper()
	brokenDir := t.TempDir()
	brokenCfg := cloneConfiguration(nil)
	brokenCfg.SchemaVersion = 2
	brokenCfg.Credential = &CredentialConfig{
		DefaultStore:     "mem-store",
		RememberPrompted: "always",
		Stores: map[string]StoreConfig{
			"mem-store": {Type: StoreTypeEncryptedFile, Path: filepath.Join(brokenDir, "vault"), Unlock: "prompt"},
		},
	}
	brokenCfg.Hosts.Set("h-b", models.Host{Address: "10.241.0.2", Port: 22})
	brokenCfg.Hosts.Set("h-a", models.Host{Address: "10.241.0.1", Port: 22})
	brokenCfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	brokenCfg.Nodes.Set("app-b", models.Node{HostRef: "h-b", IdentityRef: "id-ops", ProxyJump: "openssh:ssh-app-a"})
	brokenCfg.Nodes.Set("app-a", models.Node{HostRef: "h-a", IdentityRef: "id-ops", ProxyJump: "app-b"})
	brokenParser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	brokenStore := NewDefaultStore(filepath.Join(brokenDir, "config.yaml"), filepath.Join(brokenDir, "config.key"))
	if saveErr := brokenStore.Save(brokenCfg); saveErr != nil {
		t.Fatalf("brokenStore.Save: %v", saveErr)
	}
	brokenRepo, err := NewRepositoryWithOpenSSHParser(brokenCfg, brokenStore, brokenParser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser(pre-existing OpenSSH cycle): %v", err)
	}

	bView := brokenRepo.View()
	bNodeB, _ := bView.Configuration.Nodes.Get("app-b")
	bHostB, _ := bView.Configuration.Hosts.Get(bNodeB.HostRef)
	bIdentB, _ := bView.Configuration.Identities.Get(bNodeB.IdentityRef)

	tagEdit := cloneNode(bNodeB)
	tagEdit.Tags = []string{"non-routing-tag"}
	tagEdit.SudoMode = models.SudoModeSudo
	if err := brokenRepo.ReplaceNodeAtRefContext(t.Context(), bView.NodeRefs["app-b"], "app-b", tagEdit, bHostB, bIdentB); err != nil {
		t.Fatalf("non-routing ReplaceNodeAtRefContext(Tags/SudoMode) failed unexpectedly: %v", err)
	}

	bView = brokenRepo.View()
	bRefB := bView.NodeRefs["app-b"]
	bNodeB, _ = bView.Configuration.Nodes.Get("app-b")
	bHostB, _ = bView.Configuration.Hosts.Get(bNodeB.HostRef)
	bIdentB, _ = bView.Configuration.Identities.Get(bNodeB.IdentityRef)
	credEdit := brokenRepo.NodeCredentialEdit(bRefB, "app-b", bNodeB, bHostB, bIdentB)
	if outcome, _, cErr := credEdit.ApplyCredentialRefAtVersion(
		t.Context(),
		credential.Target{NodeID: "app-b", Kind: credential.KindLoginPassword},
		string(bRefB.Version[:]),
		&credential.Ref{StoreID: "mem-store", ItemID: "pw-ok"},
	); cErr != nil || !outcome.Applied {
		t.Fatalf("non-routing NodeCredentialEdit = (%+v, %v), want applied", outcome, cErr)
	}

	bView = brokenRepo.View()
	bNodeB, _ = bView.Configuration.Nodes.Get("app-b")
	bHostB, _ = bView.Configuration.Hosts.Get(bNodeB.HostRef)
	bIdentB, _ = bView.Configuration.Identities.Get(bNodeB.IdentityRef)
	repaired := cloneNode(bNodeB)
	repaired.ProxyJump = ""
	if err := brokenRepo.ReplaceNodeAtRefContext(t.Context(), bView.NodeRefs["app-b"], "app-b", repaired, bHostB, bIdentB); err != nil {
		t.Fatalf("repair ReplaceNodeAtRefContext(ProxyJump=\"\") failed: %v", err)
	}
	if got, ok := brokenRepo.GetNode("app-b"); !ok || got.ProxyJump != "" {
		t.Fatalf("repaired app-b = (%+v, %v), want empty ProxyJump", got, ok)
	}
}

func TestP7W14c_L4_14_L1_ReadAndSyncMigrationConfigurationRespectsContext(t *testing.T) {
	t.Parallel()

	sub := t.TempDir()
	content := []byte("schema_version: 2\nnodes: {}\n")
	cfgPath := filepath.Join(sub, "config.yaml")
	if err := os.WriteFile(cfgPath, content, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	digest := migrationDigest(content)

	// 1. Pre-canceled context returns context.Canceled immediately.
	canceledCtx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := readAndSyncMigrationConfiguration(canceledCtx, cfgPath, digest, "conflict"); !errors.Is(err, context.Canceled) {
		t.Errorf("readAndSyncMigrationConfiguration(canceled ctx) = %v, want context.Canceled", err)
	}

	// 2. While another exclusive lock holds the file, readAndSyncMigrationConfiguration must
	//    honor context deadline instead of blocking indefinitely.
	holder, err := fsx.OpenLocked(cfgPath, fsx.LockExclusive, false, 0)
	if err != nil {
		t.Fatalf("fsx.OpenLocked(holder): %v", err)
	}
	held := true
	defer func() {
		if held {
			_ = holder.Close()
		}
	}()

	waitCtx, waitCancel := context.WithTimeout(t.Context(), 120*time.Millisecond)
	defer waitCancel()
	if _, err := readAndSyncMigrationConfiguration(waitCtx, cfgPath, digest, "conflict"); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("readAndSyncMigrationConfiguration(contended lock) = %v, want context.DeadlineExceeded", err)
	}

	// 3. Releasing the lock allows readAndSyncMigrationConfiguration to succeed.
	if err := holder.Close(); err != nil {
		t.Fatalf("holder.Close: %v", err)
	}
	held = false
	got, err := readAndSyncMigrationConfiguration(t.Context(), cfgPath, digest, "conflict")
	if err != nil || string(got) != string(content) {
		t.Fatalf("readAndSyncMigrationConfiguration(after release) = (%q, %v), want %q", got, err, content)
	}
}
