package tui

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/wentf9/xops-cli/pkg/config"
	sshcrypto "golang.org/x/crypto/ssh"
)

func TestV2FormPassphraseIncludesFingerprint(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := sshcrypto.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(path), "linked-key")
	if err := os.Symlink(path, link); err == nil {
		path = link
	} else if runtime.GOOS != "windows" {
		t.Fatal(err)
	} else {
		t.Logf("symlinks unavailable; testing regular key: %v", err)
	}
	cfg := newFormCredentialTestConfiguration("")
	cfg.SchemaVersion = 2
	cfg.Credential.Stores = map[string]config.StoreConfig{"mem": {Type: config.StoreTypeHelper, Command: "/unused"}}
	repo := newTestRepository(t, cfg)
	service := newFormCredentialTestService(t, repo, newMemoryCredentialStore())
	m := newPasswordReplaceFormModel(repo, service, "")
	m.formState.authType = "key"
	m.formState.keyPath = path
	m.formState.passphrase = "fixture-passphrase"
	m.formState.passphraseAction = "replace"
	completeConfigurationMutation(t, m, m.saveFormCmd())
	if _, err := repo.Snapshot().ToV2(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := repo.ResolveConnection(formCredentialTestNodeID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Identity.PassphraseRef == nil || snapshot.Identity.KeyFingerprint == "" {
		t.Fatal("form did not bind passphrase to key")
	}
}
