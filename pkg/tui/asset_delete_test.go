package tui

import (
	"path/filepath"
	"testing"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
)

func TestTUIAssetDeletionRunsCredentialCleanupAsynchronously(t *testing.T) {
	cfg := newFormCredentialTestConfiguration("")
	node, _ := cfg.Nodes.Get(formCredentialTestNodeID)
	identity, _ := cfg.Identities.Get(node.IdentityRef)
	ref := &credential.Ref{StoreID: "mem", ItemID: "old"}
	identity.LoginPasswordRef = ref
	cfg.Identities.Set(node.IdentityRef, identity)
	dir := t.TempDir()
	persistent := config.NewDefaultStore(filepath.Join(dir, "config.yaml"), filepath.Join(dir, "secret.key"))
	if err := persistent.Save(cfg); err != nil {
		t.Fatal(err)
	}
	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, persistent)
	if err != nil {
		t.Fatal(err)
	}
	store := newMemoryCredentialStore()
	store.data[ref.ItemID] = credential.NewSecret([]byte("secret"))
	service := newFormCredentialTestService(t, repo, store)
	m, err := NewModel(repo, WithCredentialService(service))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Errorf("close model: %v", err)
		}
	})
	m.deletePending = true
	updated, cmd := m.handleDelete()
	if cmd == nil {
		t.Fatal("delete did not return an asynchronous command")
	}
	if _, exists := repo.GetNode(formCredentialTestNodeID); !exists {
		t.Fatal("delete blocked Update to mutate configuration")
	}
	m = completeConfigurationMutation(t, &updated, cmd)
	if _, exists := repo.GetNode(formCredentialTestNodeID); exists {
		t.Fatal("asynchronous deletion did not run")
	}
	if len(store.data) != 0 {
		t.Fatal("TUI deletion omitted credential cleanup")
	}
}
