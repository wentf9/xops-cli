package config

import (
	"errors"
	"testing"

	"github.com/wentf9/xops-cli/pkg/credential"
)

func TestAssetDeletionCollectsAllKindsAndPreservesUncertainCommit(t *testing.T) {
	cfg := newTestProvider().Snapshot()
	node, _ := cfg.Nodes.Get("web-server")
	identity, _ := cfg.Identities.Get(node.IdentityRef)
	login := credential.Ref{StoreID: "memory", ItemID: "login"}
	passphrase := credential.Ref{StoreID: "memory", ItemID: "passphrase"}
	privilege := credential.Ref{StoreID: "memory", ItemID: "privilege"}
	identity.LoginPasswordRef, identity.PassphraseRef = &login, &passphrase
	node.PrivilegePasswordRef = &privilege
	cfg.Identities.Set(node.IdentityRef, identity)
	cfg.Nodes.Set("web-server", node)
	persistent := &memoryPersistStore{cfg: cfg}
	repo, err := NewRepositoryWithoutOpenSSH(cfg, persistent)
	if err != nil {
		t.Fatal(err)
	}
	store := &inMemoryCredStore{data: map[string][]byte{"login": []byte("one"), "passphrase": []byte("two"), "privilege": []byte("three")}}
	registry := credential.NewRegistry()
	if err := registry.Register("memory", store); err != nil {
		t.Fatal(err)
	}
	journal, err := credential.NewJournalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	svc, err := credential.NewService(registry, journal, repo.AsConfigUpdater(), nil)
	if err != nil {
		t.Fatal(err)
	}
	persistent.result = &PersistResult{Applied: true}
	persistent.syncErr = errors.New("directory sync failed")
	err = repo.DeleteNodesWithCredentialsContext(t.Context(), []NodeRef{repo.View().NodeRefs["web-server"]}, svc)
	var durability *DurabilityError
	if !errors.As(err, &durability) {
		t.Fatalf("durability outcome lost: %v", err)
	}
	if _, exists := repo.GetNode("web-server"); exists {
		t.Fatal("applied deletion rolled back")
	}
	if len(store.data) != 3 {
		t.Fatal("uncertain deletion removed credentials")
	}
	// A fresh repository/service must consult disk durability, not a missing
	// target node or the deleting service's transient state.
	restarted, err := NewRepositoryWithoutOpenSSH(persistent.cfg, persistent)
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := credential.NewService(registry, journal, restarted.AsConfigUpdater(), nil)
	if err != nil {
		t.Fatal(err)
	}
	results, err := recovery.GC(t.Context())
	if err != nil || len(results) != 3 {
		t.Fatalf("missing recovery entries: %+v %v", results, err)
	}
	for _, result := range results {
		if result.Err == nil {
			t.Fatal("GC ignored unresolved durability")
		}
	}
	persistent.result = &PersistResult{Applied: true, Durable: true}
	persistent.syncErr = nil
	results, err = recovery.GC(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range results {
		if result.Err != nil {
			t.Fatal(result.Err)
		}
	}
	if len(store.data) != 0 {
		t.Fatal("GC did not collect all secret kinds")
	}
}

func TestAssetDeletionWithoutServiceFailsBeforeChangingReferences(t *testing.T) {
	cfg := newTestProvider().Snapshot()
	node, _ := cfg.Nodes.Get("web-server")
	node.PrivilegePasswordRef = &credential.Ref{StoreID: "missing", ItemID: "retained"}
	cfg.Nodes.Set("web-server", node)
	repo, err := NewRepositoryWithoutOpenSSH(cfg, &memoryPersistStore{cfg: cfg})
	if err != nil {
		t.Fatal(err)
	}
	ref := repo.View().NodeRefs["web-server"]
	err = repo.DeleteNodesWithCredentialsContext(t.Context(), []NodeRef{ref}, nil)
	if !errors.Is(err, credential.ErrCredentialStoreUnavailable) {
		t.Fatalf("missing service: %v", err)
	}
	if _, exists := repo.GetNode("web-server"); !exists {
		t.Fatal("deletion silently bypassed journal")
	}
}
