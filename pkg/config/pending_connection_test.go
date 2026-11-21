package config

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/wentf9/xops-cli/pkg/models"
)

func pendingTestOptions(port uint16) EnsureNodeOptions {
	return EnsureNodeOptions{Target: ConnectionTarget{
		Selector: "192.0.2.10", User: "root", HasUser: true, Port: port, HasPort: port != 0,
	}}
}

func pendingDiskRepository(t *testing.T) (*Repository, Store) {
	t.Helper()
	dir := t.TempDir()
	store := NewDefaultStore(filepath.Join(dir, "config.yaml"), filepath.Join(dir, "config.key"))
	cfg := cloneConfiguration(nil)
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	repo, err := NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	return repo, store
}

func TestPreparedConnectionDoesNotPolluteSavedTargets(t *testing.T) {
	repo, store := pendingDiskRepository(t)
	var correctID string
	if err := repo.WithPendingNode(t.Context(), pendingTestOptions(0), func(wrongLease PendingLease) error {
		if wrongLease.NodeID() != "root@192.0.2.10:22" || !repo.IsPendingNode(wrongLease.NodeID()) {
			t.Fatalf("prepare default port = %q", wrongLease.NodeID())
		}
		assertPendingConnectionInvisible(t, repo, store, wrongLease.NodeID())
		// An unrelated durable write must not flush the failed attempt either.
		if _, err := repo.CreateIdentityContext(t.Context(), "manual", models.Identity{User: "admin"}); err != nil {
			t.Fatal(err)
		}
		return repo.WithPendingNode(t.Context(), pendingTestOptions(2222), func(correctLease PendingLease) error {
			correctID = correctLease.NodeID()
			before, err := repo.ResolveConnection(correctID)
			if err != nil {
				t.Fatal(err)
			}
			if err := correctLease.Confirm(t.Context()); err != nil {
				t.Fatal(err)
			}
			after, err := repo.ResolveConnection(correctID)
			if err != nil {
				t.Fatalf("resolve confirmed connection: %v", err)
			}
			assertConfirmedSnapshotPreserved(t, before, after)
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	disk, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(disk.Nodes.Keys()) != 1 || len(disk.Hosts.Keys()) != 1 || len(disk.Identities.Keys()) != 2 {
		t.Fatal("confirmation saved unrelated pending entities or lost an explicit identity")
	}
	reloaded, err := NewRepositoryWithoutOpenSSH(disk, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := reloaded.WithPendingNode(t.Context(), pendingTestOptions(0), func(lease PendingLease) error {
		if lease.NodeID() != correctID || reloaded.IsPendingNode(lease.NodeID()) {
			t.Fatalf("omitted port after successful connection = %q pending=%v, want %q", lease.NodeID(), reloaded.IsPendingNode(lease.NodeID()), correctID)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func assertConfirmedSnapshotPreserved(t *testing.T, before, after ConnectionSnapshot) {
	t.Helper()
	if before.Provenance != ProvenanceAdHocPending || after.Provenance != ProvenanceSavedManaged {
		t.Fatalf("provenance transition = (%s -> %s), want (adhoc_pending -> saved_managed)", before.Provenance, after.Provenance)
	}
	before.Provenance = after.Provenance
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("confirmation changed authenticated target or credential versions: before=%+v after=%+v", before, after)
	}
}

func assertPendingConnectionInvisible(t *testing.T, repo *Repository, store Store, nodeID string) {
	t.Helper()
	if _, err := repo.ResolveConnection(nodeID); err != nil {
		t.Fatalf("pending connection is not resolvable: %v", err)
	}
	if id, err := repo.ResolveSelector("192.0.2.10"); err != nil || id != "" {
		t.Fatalf("pending connection leaked into selectors: %q, %v", id, err)
	}
	disk, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []*Configuration{disk, repo.Snapshot(), repo.View().Configuration} {
		if len(cfg.Nodes.Keys())+len(cfg.Hosts.Keys())+len(cfg.Identities.Keys()) != 0 {
			t.Fatal("preparation published node, host or identity")
		}
	}
}

func TestPreparedConnectionsKeepPortIdentitiesSeparate(t *testing.T) {
	repo, _ := pendingDiskRepository(t)
	if err := repo.WithPendingNode(t.Context(), pendingTestOptions(22), func(first PendingLease) error {
		if err := repo.WithPendingNode(t.Context(), pendingTestOptions(22), func(repeated PendingLease) error {
			if repeated.NodeID() != first.NodeID() {
				t.Fatalf("repeat preparation: %q != %q", repeated.NodeID(), first.NodeID())
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return repo.WithPendingNode(t.Context(), pendingTestOptions(2222), func(second PendingLease) error {
			firstNode, _, _, err := repo.Resolve(first.NodeID())
			if err != nil {
				t.Fatal(err)
			}
			secondNode, _, _, err := repo.Resolve(second.NodeID())
			if err != nil {
				t.Fatal(err)
			}
			if firstNode.IdentityRef == secondNode.IdentityRef {
				t.Fatal("independent pending ports share a credential identity")
			}
			if err := first.Confirm(t.Context()); err != nil {
				t.Fatal(err)
			}
			return second.Confirm(t.Context())
		})
	}); err != nil {
		t.Fatal(err)
	}
	var ambiguous *AmbiguousNodeError
	if err := repo.WithPendingNode(t.Context(), pendingTestOptions(0), func(PendingLease) error { return nil }); !errors.As(err, &ambiguous) {
		t.Fatalf("two saved ports must remain ambiguous: %v", err)
	}
}

func TestConfirmConnectionConcurrentIdempotence(t *testing.T) {
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	repo, err := NewRepositoryWithoutOpenSSH(nil, store)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if err := repo.WithPendingNode(t.Context(), pendingTestOptions(2222), func(lease PendingLease) error {
				return lease.Confirm(t.Context())
			}); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if store.saves != 1 {
		t.Fatalf("concurrent confirmation saved %d times", store.saves)
	}
}

func TestConfirmConnectionSaveOutcomes(t *testing.T) {
	for _, applied := range []bool{false, true} {
		name := "unapplied"
		if applied {
			name = "applied_undurable"
		}
		t.Run(name, func(t *testing.T) {
			want := errors.New("storage failure")
			store := &repositoryTestStore{result: PersistResult{Applied: applied}, err: want}
			repo, err := NewRepositoryWithoutOpenSSH(nil, store)
			if err != nil {
				t.Fatal(err)
			}
			if err := repo.WithPendingNode(t.Context(), pendingTestOptions(2222), func(lease PendingLease) error {
				if store.saves != 0 {
					t.Fatal("preparation attempted storage")
				}
				if err := lease.Confirm(t.Context()); !errors.Is(err, want) {
					t.Fatalf("confirmation error = %v", err)
				}
				if _, exists := repo.GetNode(lease.NodeID()); exists != applied {
					t.Fatalf("saved node exists = %v, applied = %v", exists, applied)
				}
				if _, err := repo.ResolveConnection(lease.NodeID()); err != nil {
					t.Fatalf("failed confirmation lost connection: %v", err)
				}
				store.result = PersistResult{Applied: true, Durable: true}
				store.err = nil
				if err := lease.Confirm(t.Context()); err != nil {
					t.Fatal(err)
				}
				wantSaves := 2
				if applied {
					wantSaves = 1
				}
				if store.saves != wantSaves {
					t.Fatalf("confirmation retried an applied write: saves = %d", store.saves)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestConfirmConnectionRejectsConcurrentEdits(t *testing.T) {
	for _, entity := range []string{"node", "host", "identity"} {
		t.Run(entity, func(t *testing.T) {
			repo, store := pendingDiskRepository(t)
			if err := repo.WithPendingNode(t.Context(), pendingTestOptions(2222), func(lease PendingLease) error {
				nodeID := lease.NodeID()
				node, host, identity, err := repo.Resolve(nodeID)
				if err != nil {
					t.Fatal(err)
				}
				cfg, err := store.Load()
				if err != nil {
					t.Fatal(err)
				}
				switch entity {
				case "node":
					node.Tags = []string{"concurrent-edit"}
					cfg.Nodes.Set(nodeID, node)
					cfg.Hosts.Set(node.HostRef, host)
					cfg.Identities.Set(node.IdentityRef, identity)
				case "host":
					host.Port = 2223
					cfg.Hosts.Set(node.HostRef, host)
				case "identity":
					identity.User = "other-user"
					cfg.Identities.Set(node.IdentityRef, identity)
				}
				if err := store.Save(cfg); err != nil {
					t.Fatal(err)
				}
				if err := lease.Confirm(t.Context()); !errors.Is(err, ErrConfigConflict) {
					t.Fatalf("concurrent %s edit was overwritten: %v", entity, err)
				}
				disk, err := store.Load()
				if err != nil {
					t.Fatal(err)
				}
				want, err := json.Marshal(cfg)
				if err != nil {
					t.Fatal(err)
				}
				got, err := json.Marshal(disk)
				if err != nil {
					t.Fatal(err)
				}
				if string(got) != string(want) {
					t.Fatal("rejected confirmation changed disk configuration")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPrepareConnectionHonorsCancellation(t *testing.T) {
	repo, _ := pendingDiskRepository(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := repo.WithPendingNode(ctx, pendingTestOptions(22), func(PendingLease) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("prepare canceled connection: %v", err)
	}
	if err := repo.WithPendingNode(t.Context(), pendingTestOptions(22), func(lease PendingLease) error {
		if err := lease.Confirm(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("confirm canceled connection: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(repo.Snapshot().Nodes.Keys()) != 0 {
		t.Fatal("canceled confirmation saved a node")
	}
	if n := pendingCount(repo); n != 0 {
		t.Fatalf("canceled confirmation leaked %d pending entries", n)
	}
}

func TestL7_PendingConnectionDistinctOpenSSHAliases(t *testing.T) {
	sshCfgPath := filepath.Join(t.TempDir(), "ssh_config")
	sshCfg := strings.Join([]string{
		"Host role-a",
		"  HostName 10.0.0.5",
		"  User reader",
		"  IdentityFile ~/.ssh/id_a",
		"Host role-b",
		"  HostName 10.0.0.5",
		"  User writer",
		"  IdentityFile ~/.ssh/id_b",
	}, "\n") + "\n"
	if err := os.WriteFile(sshCfgPath, []byte(sshCfg), 0o600); err != nil {
		t.Fatalf("write ssh_config: %v", err)
	}

	repo, _ := pendingDiskRepository(t)
	provider, err := WithOpenSSHConfigOverride(repo, sshCfgPath)
	if err != nil {
		t.Fatalf("WithOpenSSHConfigOverride: %v", err)
	}
	ovProv := provider.(*openSSHOverrideProvider)
	underlyingRepo := ovProv.repo

	if err := ovProv.WithPendingNode(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "role-a", User: "ops", HasUser: true},
	}, func(leaseA PendingLease) error {
		return ovProv.WithPendingNode(t.Context(), EnsureNodeOptions{
			Target: ConnectionTarget{Selector: "role-b", User: "ops", HasUser: true},
		}, func(leaseB PendingLease) error {
			if leaseA.NodeID() == leaseB.NodeID() {
				t.Fatalf("expected distinct pending NodeIDs for role-a and role-b, both got %q", leaseA.NodeID())
			}
			if _, _, identA, err := provider.Resolve(leaseA.NodeID()); err != nil || !strings.HasSuffix(identA.KeyPath, "id_a") {
				t.Fatalf("Resolve(role-a) = (%q, %v), want id_a", identA.KeyPath, err)
			}
			if _, _, identB, err := provider.Resolve(leaseB.NodeID()); err != nil || !strings.HasSuffix(identB.KeyPath, "id_b") {
				t.Fatalf("Resolve(role-b) = (%q, %v), want id_b", identB.KeyPath, err)
			}
			if _, pending := ovProv.PendingNodeExecution(leaseA.NodeID()); pending {
				t.Fatalf("expected read-only override PendingNodeExecution(%q) to be false", leaseA.NodeID())
			}
			if _, pending := underlyingRepo.PendingNodeExecution(leaseA.NodeID()); !pending {
				t.Fatalf("expected underlying repo.PendingNodeExecution(%q) to be true", leaseA.NodeID())
			}
			if _, pending := underlyingRepo.PendingNodeExecution(leaseB.NodeID()); pending {
				t.Fatalf("expected underlying repo.PendingNodeExecution(%q) to be false for OpenSSH-prefixed disambiguated node", leaseB.NodeID())
			}
			if snapB, snapErr := underlyingRepo.ResolveConnection(leaseB.NodeID()); snapErr != nil {
				t.Fatalf("ResolveConnection(%q): %v", leaseB.NodeID(), snapErr)
			} else if snapB.UpdateRef != nil {
				t.Fatalf("expected UpdateRef == nil for OpenSSH-prefixed disambiguated node %q, got %+v", leaseB.NodeID(), snapB.UpdateRef)
			}
			if err := leaseA.(PendingExecutionLease).ConfirmWithExecution(t.Context(), nil); err != nil {
				t.Fatalf("ConfirmWithExecution on read-only override provider failed: %v", err)
			}
			if err := leaseB.Confirm(t.Context()); err != nil {
				t.Fatalf("Confirm(openssh altID) failed: %v", err)
			}
			return nil
		})
	}); err != nil {
		t.Fatalf("WithPendingNode: %v", err)
	}
	for _, id := range repo.Snapshot().Nodes.Keys() {
		if strings.HasPrefix(id, OpenSSHNodePrefix) {
			t.Fatalf("Confirm persisted OpenSSH virtual node ID %q into durable config", id)
		}
	}
}

func TestPendingConnection_ConcurrencyAndAliasIsolation(t *testing.T) {
	sshCfgPath := filepath.Join(t.TempDir(), "ssh_config")
	sshCfg := strings.Join([]string{
		"Host app-alias",
		"  HostName 10.99.0.10",
		"  User ops",
		"  Port 2200",
	}, "\n") + "\n"
	if err := os.WriteFile(sshCfgPath, []byte(sshCfg), 0o600); err != nil {
		t.Fatal(err)
	}
	parser, err := NewOpenSSHParserFromPath(sshCfgPath)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("raw IP does not silently reuse alias-bound pending entry", func(t *testing.T) {
		dir := t.TempDir()
		store := NewDefaultStore(filepath.Join(dir, "config.yaml"), filepath.Join(dir, "config.key"))
		repo, err := NewRepositoryWithOpenSSHParser(cloneConfiguration(nil), store, parser)
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.WithPendingNode(t.Context(), EnsureNodeOptions{
			Target: ConnectionTarget{Selector: "app-alias", Port: 2222, HasPort: true},
		}, func(aliasLease PendingLease) error {
			if err := repo.WithPendingNode(t.Context(), EnsureNodeOptions{
				Target: ConnectionTarget{Selector: "10.99.0.10", User: "ops", HasUser: true, Port: 2222, HasPort: true},
			}, func(PendingLease) error { return nil }); !errors.Is(err, ErrConfigConflict) {
				t.Fatalf("expected raw IP colliding with unconfirmed %s to fail closed with ErrConfigConflict, got %v", aliasLease.NodeID(), err)
			}
			return nil
		}); err != nil {
			t.Fatalf("WithPendingNode(app-alias): %v", err)
		}
	})

	t.Run("concurrent WithPendingNode upgrade and Confirm shares contextGate strictly", func(t *testing.T) {
		var releaseSave = make(chan struct{})
		var saveStarted = make(chan struct{})
		var firstSaveDone atomic.Bool
		var concurrentSaves atomic.Int32
		var maxConcurrent atomic.Int32
		baseStore := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
		blkStore := &blockingUpgradeStore{
			inner:       baseStore,
			saveStarted: saveStarted,
			releaseSave: releaseSave,
			onSave: func(n int32) {
				for {
					cur := maxConcurrent.Load()
					if n <= cur || maxConcurrent.CompareAndSwap(cur, n) {
						break
					}
				}
			},
			concurrent:    &concurrentSaves,
			firstSaveDone: &firstSaveDone,
		}
		repo, err := NewRepositoryWithOpenSSHParser(cloneConfiguration(nil), blkStore, parser)
		if err != nil {
			t.Fatal(err)
		}
		var nodeID string
		if err := repo.WithPendingNode(t.Context(), EnsureNodeOptions{
			Target: ConnectionTarget{Selector: "10.99.0.10", User: "ops", HasUser: true, Port: 2222, HasPort: true},
		}, func(leaseA PendingLease) error {
			nodeID = leaseA.NodeID()
			confirmADone := make(chan error, 1)
			go func() {
				confirmADone <- leaseA.Confirm(t.Context())
			}()
			<-saveStarted

			// Upgrade the same NodeID to app-alias while Confirm A is blocked inside Store.save.
			return repo.WithPendingNode(t.Context(), EnsureNodeOptions{
				Target: ConnectionTarget{Selector: "app-alias", Port: 2222, HasPort: true},
			}, func(leaseB PendingLease) error {
				if leaseB.NodeID() != nodeID {
					close(releaseSave)
					t.Fatalf("upgraded NodeID = %q, want %q", leaseB.NodeID(), nodeID)
				}
				if gotAlias := repo.NodeOpenSSHAlias(nodeID); gotAlias != "app-alias" {
					close(releaseSave)
					t.Fatalf("NodeOpenSSHAlias after upgrade = %q, want app-alias", gotAlias)
				}
				confirmBDone := make(chan error, 1)
				go func() {
					confirmBDone <- leaseB.Confirm(t.Context())
				}()
				close(releaseSave)
				if err := <-confirmADone; err != nil {
					t.Fatalf("Confirm A: %v", err)
				}
				if err := <-confirmBDone; err != nil {
					t.Fatalf("Confirm B: %v", err)
				}
				return nil
			})
		}); err != nil {
			t.Fatal(err)
		}
		if maxConcurrent.Load() != 1 {
			t.Fatalf("max concurrent Store saves = %d, want 1 (shared *contextGate violated)", maxConcurrent.Load())
		}
		if _, pending := repo.PendingNodeExecution(nodeID); pending {
			t.Fatal("pending entry remained after both confirmations finished")
		}
	})
}

func TestWithPendingNode_AutoDiscardsOnPanic(t *testing.T) {
	repo, store := pendingDiskRepository(t)
	var capturedID string
	var panicked bool
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		_ = repo.WithPendingNode(t.Context(), pendingTestOptions(2222), func(lease PendingLease) error {
			capturedID = lease.NodeID()
			if !repo.IsPendingNode(capturedID) {
				t.Fatal("expected IsPendingNode=true inside callback")
			}
			panic("simulated dial panic")
		})
	}()
	if !panicked {
		t.Fatal("expected panic to propagate out of WithPendingNode")
	}
	if repo.IsPendingNode(capturedID) {
		t.Fatalf("pending node %q leaked after panic", capturedID)
	}
	if disk, err := store.Load(); err != nil || disk.Nodes.Count() != 0 {
		t.Fatalf("panic modified disk config: count=%d err=%v", disk.Nodes.Count(), err)
	}
}

func TestWithPendingNode_StagedSavedNodeUpdates(t *testing.T) {
	repo, store := pendingDiskRepository(t)
	for _, n := range []struct {
		id, hRef, idRef, addr string
	}{
		{"bastion", "h-b", "id-b", "10.0.0.1"},
		{"web", "h-w", "id-w", "10.0.0.2"},
	} {
		if _, err := repo.CreateNodeContext(t.Context(), n.id,
			models.Node{HostRef: n.hRef, IdentityRef: n.idRef},
			models.Host{Address: n.addr, Port: 22},
			models.Identity{User: "ops", AuthType: "auto"},
		); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("rejects_cyclic_proxyjump_pre_dial", func(t *testing.T) {
		if err := repo.WithPendingNode(t.Context(), EnsureNodeOptions{
			Target:         ConnectionTarget{Selector: "web"},
			ExistingUpdate: PendingNodeUpdate{Enabled: true, JumpHost: "web"},
		}, func(PendingLease) error {
			t.Fatal("callback should not run on cyclic ProxyJump staged update")
			return nil
		}); err == nil {
			t.Fatal("expected self-jump staged update to fail validation")
		}
	})

	t.Run("discards_staged_update_on_error_without_disk_write", func(t *testing.T) {
		assertStagedUpdateDiscardsOnError(t, repo, store)
	})

	t.Run("persists_staged_update_atomically_on_confirm", func(t *testing.T) {
		assertStagedUpdatePersistsOnConfirm(t, repo, store)
	})
}

func assertStagedUpdateDiscardsOnError(t *testing.T, repo *Repository, store Store) {
	t.Helper()
	dialErr := errors.New("dial failed")
	err := repo.WithPendingNode(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "web"},
		ExistingUpdate: PendingNodeUpdate{
			Enabled: true, JumpHost: "bastion", Alias: "staged-web", Tags: []string{"prod"},
		},
	}, func(lease PendingLease) error {
		if lease.NodeID() != "web" || !repo.IsPendingNode("web") {
			t.Fatalf("expected staged update pending for web, got id=%q pending=%v", lease.NodeID(), repo.IsPendingNode("web"))
		}
		if _, isNewPending := repo.PendingNodeExecution("web"); isNewPending {
			t.Fatal("staged update to saved node must not be treated as new enrollment target")
		}
		stagedNode, _, _, rErr := repo.Resolve("web")
		if rErr != nil || stagedNode.ProxyJump != "bastion" {
			t.Fatalf("Resolve(web) inside callback = (%+v, %v), want ProxyJump=bastion", stagedNode, rErr)
		}
		disk, dErr := store.Load()
		if dErr != nil {
			t.Fatal(dErr)
		}
		if savedNode, _ := disk.Nodes.Get("web"); savedNode.ProxyJump != "" {
			t.Fatalf("pre-confirm staged update leaked to disk: ProxyJump=%q", savedNode.ProxyJump)
		}
		return dialErr
	})
	if !errors.Is(err, dialErr) {
		t.Fatalf("got err=%v, want %v", err, dialErr)
	}
	if repo.IsPendingNode("web") {
		t.Fatal("staged update leaked after failed callback")
	}
	if savedNode, _, _, _ := repo.Resolve("web"); savedNode.ProxyJump != "" || len(savedNode.Alias) != 0 {
		t.Fatalf("unconfirmed staged update mutated saved node: %+v", savedNode)
	}
}

func assertStagedUpdatePersistsOnConfirm(t *testing.T, repo *Repository, store Store) {
	t.Helper()
	if err := repo.WithPendingNode(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "web"},
		ExistingUpdate: PendingNodeUpdate{
			Enabled: true, JumpHost: "bastion", Alias: "confirmed-web", Tags: []string{"prod"},
		},
	}, func(lease PendingLease) error {
		return lease.Confirm(t.Context())
	}); err != nil {
		t.Fatalf("confirm staged update: %v", err)
	}
	if repo.IsPendingNode("web") {
		t.Fatal("staged update remained pending after Confirm")
	}
	disk, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	persisted, _ := disk.Nodes.Get("web")
	if persisted.ProxyJump != "bastion" || len(persisted.Alias) != 1 || persisted.Alias[0] != "confirmed-web" {
		t.Fatalf("persisted node = %+v, want ProxyJump=bastion Alias=[confirmed-web]", persisted)
	}
}

type blockingUpgradeStore struct {
	inner         *repositoryTestStore
	saveStarted   chan struct{}
	releaseSave   chan struct{}
	firstSaveDone *atomic.Bool
	concurrent    *atomic.Int32
	onSave        func(int32)
}

func (s *blockingUpgradeStore) Load() (*Configuration, error) { return s.inner.Load() }
func (s *blockingUpgradeStore) Save(cfg *Configuration) error { return s.inner.Save(cfg) }
func (s *blockingUpgradeStore) save(cfg *Configuration) (PersistResult, error) {
	cur := s.concurrent.Add(1)
	defer s.concurrent.Add(-1)
	if s.onSave != nil {
		s.onSave(cur)
	}
	if s.firstSaveDone.CompareAndSwap(false, true) {
		close(s.saveStarted)
		<-s.releaseSave
	}
	return s.inner.save(cfg)
}
