package config

import (
	"errors"
	"testing"

	"github.com/wentf9/xops-cli/pkg/credential"
)

func TestCredentialNodeEditRejectsConcurrentMetadataChange(t *testing.T) {
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	repo, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
	if err != nil {
		t.Fatal(err)
	}
	view := repo.View()
	ref := view.NodeRefs["web-server"]
	node, host, identity, err := repo.Resolve("web-server")
	if err != nil {
		t.Fatal(err)
	}
	desired := identity
	desired.User = "changed"
	updater := repo.NodeCredentialEdit(ref, "renamed", node, host, desired)
	node.Alias = []string{"concurrent"}
	if err := repo.ReplaceNodeAtRefContext(t.Context(), ref, "web-server", node, host, identity); err != nil {
		t.Fatal(err)
	}
	target := credential.Target{NodeID: "renamed", Kind: credential.KindLoginPassword, AuthType: "password", ClearLegacyLoginPassword: true}
	outcome, _, err := updater.ApplyCredentialRefAtVersion(t.Context(), target, string(ref.Version[:]), &credential.Ref{StoreID: "store", ItemID: "new"})
	if !errors.Is(err, credential.ErrConfigConflict) || outcome.Applied {
		t.Fatalf("stale edit applied: %+v, %v", outcome, err)
	}
	if _, exists := repo.GetNode("renamed"); exists {
		t.Fatal("conflicting edit renamed node")
	}
	got, _, current, err := repo.Resolve("web-server")
	if err != nil {
		t.Fatal(err)
	}
	if current.User != identity.User || current.LoginPasswordRef != nil || len(got.Alias) != 1 || got.Alias[0] != "concurrent" {
		t.Fatal("stale edit overwrote concurrent metadata")
	}
}

func TestCredentialIdentityEditPreservesDurabilityOutcome(t *testing.T) {
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	repo, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
	if err != nil {
		t.Fatal(err)
	}
	view := repo.View()
	_, _, identity, err := repo.Resolve("web-server")
	if err != nil {
		t.Fatal(err)
	}
	node, _ := view.Configuration.Nodes.Get("web-server")
	ref := view.IdentityRefs[node.IdentityRef]
	identity.User = "changed"
	updater := repo.IdentityCredentialEdit(ref, identity)
	store.result = PersistResult{Applied: true, Durable: false}
	store.err = errors.New("directory sync failed")
	newRef := &credential.Ref{StoreID: "store", ItemID: "new"}
	outcome, _, err := updater.ApplyCredentialRefAtVersion(t.Context(), credential.Target{IdentityID: ref.ID, Kind: credential.KindLoginPassword, AuthType: "password"}, string(ref.Version[:]), newRef)
	if err == nil || !outcome.Applied || outcome.Durable {
		t.Fatalf("durability outcome lost: %+v, %v", outcome, err)
	}
	got, _ := repo.Snapshot().Identities.Get(ref.ID)
	if got.User != "changed" || got.LoginPasswordRef == nil || *got.LoginPasswordRef != *newRef || got.Password != "" {
		t.Fatal("applied metadata and ref were separated or rolled back")
	}
}
