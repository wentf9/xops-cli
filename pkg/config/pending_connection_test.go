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
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
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
	wrong, err := repo.PrepareNodeContext(t.Context(), pendingTestOptions(0))
	if err != nil || wrong.NodeID != "root@192.0.2.10:22" || !wrong.Created || wrong.Mutation.Outcome.Applied {
		t.Fatalf("prepare default port = %+v, %v", wrong, err)
	}
	assertPendingConnectionInvisible(t, repo, store, wrong.NodeID)
	// An unrelated durable write must not flush the failed attempt either.
	if _, err := repo.CreateIdentityContext(t.Context(), "manual", models.Identity{User: "admin"}); err != nil {
		t.Fatal(err)
	}
	correct, err := repo.PrepareNodeContext(t.Context(), pendingTestOptions(2222))
	if err != nil {
		t.Fatal(err)
	}
	before, err := repo.ResolveConnection(correct.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.ConfirmNodeContext(t.Context(), correct.NodeID); err != nil {
		t.Fatal(err)
	}
	after, err := repo.ResolveConnection(correct.NodeID)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("confirmation changed authenticated target or credential versions: %v", err)
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
	resolved, err := reloaded.PrepareNodeContext(t.Context(), pendingTestOptions(0))
	if err != nil || resolved.Created || resolved.NodeID != correct.NodeID {
		t.Fatalf("omitted port after successful connection = %+v, %v", resolved, err)
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
	first, err := repo.PrepareNodeContext(t.Context(), pendingTestOptions(22))
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := repo.PrepareNodeContext(t.Context(), pendingTestOptions(22))
	if err != nil || repeated.NodeID != first.NodeID {
		t.Fatalf("repeat preparation: %+v, %v", repeated, err)
	}
	second, err := repo.PrepareNodeContext(t.Context(), pendingTestOptions(2222))
	if err != nil {
		t.Fatal(err)
	}
	firstNode, _, _, err := repo.Resolve(first.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	secondNode, _, _, err := repo.Resolve(second.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if firstNode.IdentityRef == secondNode.IdentityRef {
		t.Fatal("independent pending ports share a credential identity")
	}
	for _, id := range []string{first.NodeID, second.NodeID} {
		if err := repo.ConfirmNodeContext(t.Context(), id); err != nil {
			t.Fatal(err)
		}
	}
	var ambiguous *AmbiguousNodeError
	if _, err := repo.PrepareNodeContext(t.Context(), pendingTestOptions(0)); !errors.As(err, &ambiguous) {
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
			prepared, err := repo.PrepareNodeContext(t.Context(), pendingTestOptions(2222))
			if err != nil {
				t.Error(err)
				return
			}
			if err := repo.ConfirmNodeContext(t.Context(), prepared.NodeID); err != nil {
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
			prepared, err := repo.PrepareNodeContext(t.Context(), pendingTestOptions(2222))
			if err != nil || store.saves != 0 {
				t.Fatalf("preparation attempted storage: %v", err)
			}
			if err := repo.ConfirmNodeContext(t.Context(), prepared.NodeID); !errors.Is(err, want) {
				t.Fatalf("confirmation error = %v", err)
			}
			if _, exists := repo.GetNode(prepared.NodeID); exists != applied {
				t.Fatalf("saved node exists = %v, applied = %v", exists, applied)
			}
			if _, err := repo.ResolveConnection(prepared.NodeID); err != nil {
				t.Fatalf("failed confirmation lost connection: %v", err)
			}
			store.result = PersistResult{Applied: true, Durable: true}
			store.err = nil
			if err := repo.ConfirmNodeContext(t.Context(), prepared.NodeID); err != nil {
				t.Fatal(err)
			}
			wantSaves := 2
			if applied {
				wantSaves = 1
			}
			if store.saves != wantSaves {
				t.Fatalf("confirmation retried an applied write: saves = %d", store.saves)
			}
		})
	}
}

func TestConfirmConnectionRejectsConcurrentEdits(t *testing.T) {
	for _, entity := range []string{"node", "host", "identity"} {
		t.Run(entity, func(t *testing.T) {
			repo, store := pendingDiskRepository(t)
			prepared, err := repo.PrepareNodeContext(t.Context(), pendingTestOptions(2222))
			if err != nil {
				t.Fatal(err)
			}
			node, host, identity, err := repo.Resolve(prepared.NodeID)
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
				cfg.Nodes.Set(prepared.NodeID, node)
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
			if err := repo.ConfirmNodeContext(t.Context(), prepared.NodeID); !errors.Is(err, ErrConfigConflict) {
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
		})
	}
}

func TestPrepareConnectionHonorsCancellation(t *testing.T) {
	repo, _ := pendingDiskRepository(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := repo.PrepareNodeContext(ctx, pendingTestOptions(22)); !errors.Is(err, context.Canceled) {
		t.Fatalf("prepare canceled connection: %v", err)
	}
	prepared, err := repo.PrepareNodeContext(t.Context(), pendingTestOptions(22))
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.ConfirmNodeContext(ctx, prepared.NodeID); !errors.Is(err, context.Canceled) {
		t.Fatalf("confirm canceled connection: %v", err)
	}
	if len(repo.Snapshot().Nodes.Keys()) != 0 {
		t.Fatal("canceled confirmation saved a node")
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
	preparer := provider.(interface {
		PrepareNodeContext(context.Context, EnsureNodeOptions) (EnsureNodeResult, error)
		PendingNodeExecution(string) (*ssh.ExecutionConfig, bool)
		ConfirmNodeWithExecutionContext(context.Context, string, *ssh.ExecutionConfig) error
	})

	resA, err := preparer.PrepareNodeContext(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "role-a", User: "ops", HasUser: true},
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext(role-a): %v", err)
	}
	resB, err := preparer.PrepareNodeContext(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "role-b", User: "ops", HasUser: true},
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext(role-b): %v", err)
	}
	if resA.NodeID == resB.NodeID {
		t.Fatalf("expected distinct pending NodeIDs for role-a and role-b, both got %q", resA.NodeID)
	}
	if _, _, identA, err := provider.Resolve(resA.NodeID); err != nil || !strings.HasSuffix(identA.KeyPath, "id_a") {
		t.Fatalf("Resolve(role-a) = (%q, %v), want id_a", identA.KeyPath, err)
	}
	if _, _, identB, err := provider.Resolve(resB.NodeID); err != nil || !strings.HasSuffix(identB.KeyPath, "id_b") {
		t.Fatalf("Resolve(role-b) = (%q, %v), want id_b", identB.KeyPath, err)
	}
	if _, pending := preparer.PendingNodeExecution(resA.NodeID); !pending {
		t.Fatalf("expected PendingNodeExecution(%q) to be true", resA.NodeID)
	}
	if err := preparer.ConfirmNodeWithExecutionContext(t.Context(), resA.NodeID, nil); err != nil {
		t.Fatalf("ConfirmNodeWithExecutionContext on read-only override provider failed: %v", err)
	}
	if err := repo.ConfirmNodeContext(t.Context(), resB.NodeID); err != nil {
		t.Fatalf("ConfirmNodeContext(openssh altID) failed: %v", err)
	}
	for _, id := range repo.Snapshot().Nodes.Keys() {
		if strings.HasPrefix(id, OpenSSHNodePrefix) {
			t.Fatalf("ConfirmNodeContext persisted OpenSSH virtual node ID %q into durable config", id)
		}
	}
}
