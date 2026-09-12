package config

import (
	"errors"
	"testing"

	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestCredentialNodeCreationCommitOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result PersistResult
	}{
		{"not applied", PersistResult{}},
		{"not durable", PersistResult{Applied: true}},
		{"durable", PersistResult{Applied: true, Durable: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &repositoryTestStore{result: tc.result}
			if !tc.result.Durable {
				store.err = errors.New("injected persistence failure")
			}
			repo, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
			if err != nil {
				t.Fatal(err)
			}
			updater := repo.NodeCredentialCreate("local", models.Node{HostRef: "local-host", IdentityRef: "local-id"}, models.Host{Address: "127.0.0.1", Port: 22}, models.Identity{User: "ops", AuthType: "password"})
			ref := &credential.Ref{StoreID: "test", ItemID: "created"}
			outcome, _, err := updater.ApplyCredentialRefAtVersion(t.Context(), credential.Target{NodeID: "local", Kind: credential.KindLoginPassword}, "", ref)
			if outcome.Applied != tc.result.Applied || outcome.Durable != tc.result.Durable || (err == nil) != tc.result.Durable {
				t.Fatalf("incorrect outcome: %+v, %v", outcome, err)
			}
			cfg := repo.Snapshot()
			_, nodeExists := cfg.Nodes.Get("local")
			_, hostExists := cfg.Hosts.Get("local-host")
			id, idExists := cfg.Identities.Get("local-id")
			if nodeExists != outcome.Applied || hostExists != outcome.Applied || idExists != outcome.Applied {
				t.Fatal("partial node bundle was published")
			}
			if outcome.Applied && (id.LoginPasswordRef == nil || *id.LoginPasswordRef != *ref) {
				t.Fatal("applied node is missing its credential reference")
			}
		})
	}
}

func TestCredentialNodeCreationRejectsConcurrentCreation(t *testing.T) {
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	repo, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
	if err != nil {
		t.Fatal(err)
	}
	node := models.Node{HostRef: "local-host", IdentityRef: "local-id"}
	host := models.Host{Address: "127.0.0.1", Port: 22}
	identity := models.Identity{User: "ops", AuthType: "password"}
	updater := repo.NodeCredentialCreate("local", node, host, identity)
	if _, err := repo.CreateNodeContext(t.Context(), "local", node, host, identity); err != nil {
		t.Fatal(err)
	}
	outcome, _, err := updater.ApplyCredentialRefAtVersion(t.Context(), credential.Target{NodeID: "local", Kind: credential.KindLoginPassword}, "", &credential.Ref{StoreID: "test", ItemID: "new"})
	if !errors.Is(err, credential.ErrConfigConflict) || outcome.Applied {
		t.Fatalf("concurrent creation was overwritten: %+v, %v", outcome, err)
	}
	id, _ := repo.Snapshot().Identities.Get("local-id")
	if id.LoginPasswordRef != nil {
		t.Fatal("concurrent identity was modified")
	}
}
