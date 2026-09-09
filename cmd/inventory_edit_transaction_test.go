package cmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	hostcmd "github.com/wentf9/xops-cli/cmd/host"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
	xssh "github.com/wentf9/xops-cli/pkg/ssh"
	sshcrypto "golang.org/x/crypto/ssh"
)

func TestInventoryCombinedEditFailureLeavesConfigurationUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command func() *cobra.Command
		args    []string
	}{
		{"identity", NewCmdIdentity, []string{"edit", "admin", "--user", "changed", "--password", "new-secret"}},
		{"host", hostcmd.NewCmdInventoryEdit, []string{"node", "--user", "changed", "--address", "127.0.0.2", "--port", "2222", "--alias", "renamed", "--password", "new-secret"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			phase6Config(t, config.StoreConfig{Type: config.StoreTypeHelper, Command: os.Args[0]})
			if err := executePhase6(t, NewCmdIdentity(), "edit", "admin", "--password", "old-secret"); err != nil {
				t.Fatal(err)
			}
			path, _, err := utils.GetConfigFilePath()
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("TEST_HELPER_ERROR_CODE", "locked")
			if err := executePhase6(t, tc.command(), tc.args...); !errors.Is(err, credential.ErrCredentialStoreLocked) {
				t.Fatalf("locked edit: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("failed credential write persisted part of the inventory edit")
			}
		})
	}
}

func TestHostCombinedCredentialEditRenamesAtomicallyAndPreservesSharedRecords(t *testing.T) {
	store := phase6Config(t, config.StoreConfig{Type: config.StoreTypeHelper, Command: os.Args[0]})
	if err := executePhase6(t, NewCmdIdentity(), "edit", "admin", "--password", "old-secret"); err != nil {
		t.Fatal(err)
	}
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Nodes.Set("other", models.Node{HostRef: "host", IdentityRef: "admin"})
	old, _ := cfg.Identities.Get("admin")
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if err := executePhase6(t, hostcmd.NewCmdInventoryEdit(), "node", "--user", "changed", "--address", "127.0.0.2", "--port", "2222", "--alias", "renamed", "--password", "new-secret"); err != nil {
		t.Fatal(err)
	}
	cfg, err = store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := cfg.Nodes.Get("node"); exists {
		t.Fatal("old node name retained")
	}
	node, exists := cfg.Nodes.Get("changed@127.0.0.2:2222")
	if !exists {
		t.Fatal("renamed node missing")
	}
	identity, _ := cfg.Identities.Get(node.IdentityRef)
	if identity.User != "changed" || identity.LoginPasswordRef == nil || len(node.Alias) != 1 || node.Alias[0] != "renamed" {
		t.Fatal("metadata and credential were not committed together")
	}
	original, _ := cfg.Identities.Get("admin")
	host, _ := cfg.Hosts.Get("host")
	if original.User != "admin" || host.Address != "127.0.0.1" || *original.LoginPasswordRef != *old.LoginPasswordRef {
		t.Fatal("shared records were modified")
	}
	registry, err := utils.GetCredentialRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := registry.Resolve(t.Context(), *identity.LoginPasswordRef)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret.Value)
	if string(secret.Value) != "new-secret" {
		t.Fatal("new secret mismatch")
	}
}

func inventoryTestPrivateKey(t *testing.T, encrypted bool) string {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if encrypted {
		block, err = sshcrypto.MarshalPrivateKeyWithPassphrase(key, "", []byte("key-password"))
	} else {
		block, err = sshcrypto.MarshalPrivateKey(key, "")
	}
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(block)
	defer clear(data)
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestInventoryUnencryptedKeySwitchUnlinksLockedPassphraseAndRecoversCleanup(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command func() *cobra.Command
		args    []string
	}{
		{"identity", NewCmdIdentity, []string{"edit", "admin"}},
		{"host", hostcmd.NewCmdInventoryEdit, []string{"node"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := phase6Config(t, config.StoreConfig{Type: config.StoreTypeHelper, Command: os.Args[0]})
			if err := executePhase6(t, NewCmdIdentity(), "edit", "admin", "--key", "old-key", "--key-pass", "old-passphrase"); err != nil {
				t.Fatal(err)
			}
			cfg, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			original, _ := cfg.Identities.Get("admin")
			keyPath := inventoryTestPrivateKey(t, false)
			t.Setenv("TEST_HELPER_ERROR_CODE", "locked")
			err = executePhase6(t, tc.command(), append(tc.args, "--key", keyPath)...)
			var cleanup *credential.CleanupError
			if !errors.As(err, &cleanup) || !errors.Is(err, credential.ErrCredentialStoreLocked) {
				t.Fatalf("expected applied edit with pending cleanup: %v", err)
			}
			cfg, err = store.Load()
			if err != nil {
				t.Fatal(err)
			}
			node, _ := cfg.Nodes.Get("node")
			identity, _ := cfg.Identities.Get(node.IdentityRef)
			if identity.PassphraseRef != nil || identity.Passphrase != "" || identity.KeyPath != keyPath || identity.AuthType != "key" {
				t.Fatal("old passphrase still participates in authentication")
			}
			currentRepo, err := config.NewRepositoryWithoutOpenSSH(cfg, store)
			if err != nil {
				t.Fatal(err)
			}
			lockedRegistry, err := utils.GetCredentialRegistry(cfg)
			if err != nil {
				t.Fatal(err)
			}
			resolver := adapter.NewSSHAdapter(currentRepo, adapter.WithCredentialSource(lockedRegistry))
			if _, err := resolver.ResolveSecret(t.Context(), xssh.SecretRequest{NodeID: "node", Kind: xssh.SecretKindPrivateKeyPassphrase}); !errors.Is(err, xssh.ErrInteractionRequired) {
				t.Fatalf("replacement key still reads locked backend: %v", err)
			}
			assertInventoryCleanupRecovery(t, cfg, store, *original.PassphraseRef)
		})
	}
}

func TestInventoryKeySwitchRejectsEncryptedKeyWithoutPassphrase(t *testing.T) {
	phase6Config(t, config.StoreConfig{Type: config.StoreTypeHelper, Command: os.Args[0]})
	path, _, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := executePhase6(t, NewCmdIdentity(), "edit", "admin", "--key", inventoryTestPrivateKey(t, true)); err == nil {
		t.Fatal("encrypted key accepted without a passphrase")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("invalid key changed configuration")
	}
}

func TestInventoryUnencryptedKeyWithoutStoredPassphraseNeedsNoWritableStore(t *testing.T) {
	store := phase6Config(t, config.StoreConfig{Type: config.StoreTypeNone})
	keyPath := inventoryTestPrivateKey(t, false)
	if err := executePhase6(t, NewCmdIdentity(), "edit", "admin", "--user", "changed", "--key", keyPath); err != nil {
		t.Fatal(err)
	}
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := cfg.Identities.Get("admin")
	if identity.User != "changed" || identity.KeyPath != keyPath || identity.AuthType != "key" || identity.PassphraseRef != nil {
		t.Fatal("metadata-only key edit failed")
	}
}

func TestHostUnencryptedKeyKeepsSharedPassphrase(t *testing.T) {
	store := phase6Config(t, config.StoreConfig{Type: config.StoreTypeHelper, Command: os.Args[0]})
	if err := executePhase6(t, NewCmdIdentity(), "edit", "admin", "--key", "old-key", "--key-pass", "shared-passphrase"); err != nil {
		t.Fatal(err)
	}
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Nodes.Set("other", models.Node{HostRef: "host", IdentityRef: "admin"})
	original, _ := cfg.Identities.Get("admin")
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_HELPER_ERROR_CODE", "locked")
	if err := executePhase6(t, hostcmd.NewCmdInventoryEdit(), "node", "--key", inventoryTestPrivateKey(t, false)); err != nil {
		t.Fatal(err)
	}
	cfg, err = store.Load()
	if err != nil {
		t.Fatal(err)
	}
	node, _ := cfg.Nodes.Get("node")
	identity, _ := cfg.Identities.Get(node.IdentityRef)
	peer, _ := cfg.Identities.Get("admin")
	if node.IdentityRef == "admin" || identity.PassphraseRef != nil || peer.PassphraseRef == nil || *peer.PassphraseRef != *original.PassphraseRef {
		t.Fatal("key switch modified the shared identity")
	}
	t.Setenv("TEST_HELPER_ERROR_CODE", "")
	registry, err := utils.GetCredentialRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := registry.Resolve(t.Context(), *peer.PassphraseRef)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret.Value)
	if string(secret.Value) != "shared-passphrase" {
		t.Fatal("shared credential was erased")
	}
}

func assertInventoryCleanupRecovery(t *testing.T, cfg *config.Configuration, store config.Store, oldRef credential.Ref) {
	t.Helper()
	// A fresh process must be able to clean up using only the journal's
	// final target; it must not need the original edit updater or secrets.
	t.Setenv("TEST_HELPER_ERROR_CODE", "")
	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	service, err := utils.GetCredentialService(repo, cfg)
	if err != nil {
		t.Fatal(err)
	}
	results, err := service.Recover(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Err != nil {
		t.Fatalf("cleanup recovery: %+v", results)
	}
	registry, err := utils.GetCredentialRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Resolve(t.Context(), oldRef); !errors.Is(err, credential.ErrCredentialNotFound) {
		t.Fatalf("obsolete credential was not removed: %v", err)
	}
}
