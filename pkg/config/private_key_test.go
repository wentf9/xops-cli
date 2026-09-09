package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/wentf9/xops-cli/pkg/credential"
	sshcrypto "golang.org/x/crypto/ssh"
)

func privateKeyTestLink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symbolic links unavailable: %v", err)
		}
		t.Fatal(err)
	}
}

func TestPrivateKeyFingerprintFollowsEncryptedKeySymlinks(t *testing.T) {
	dir := t.TempDir()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	passphrase := []byte("fixture-passphrase")
	block, err := sshcrypto.MarshalPrivateKeyWithPassphrase(private, "", passphrase)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	chain := filepath.Join(dir, "chain")
	privateKeyTestLink(t, "key", link)
	privateKeyTestLink(t, "link", chain)
	expected, err := PrivateKeyFingerprint(path, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, chain} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			got, err := PrivateKeyFingerprint(path, passphrase)
			if err != nil || got != expected {
				t.Fatalf("linked key fingerprint mismatch: %v", err)
			}
			target, err := BindPrivateKeyFingerprint(&Configuration{SchemaVersion: 2}, credential.Target{Kind: credential.KindPassphrase, KeyPath: path}, passphrase)
			if err != nil || target.KeyFingerprint != expected || target.KeyPath != path {
				t.Fatalf("v2 binding rejected or rewrote linked path: %v", err)
			}
		})
	}
	if _, err := readMigrationFile(link); err == nil {
		t.Fatal("migration artifacts unexpectedly accept symlinks")
	}
}

func TestPrivateKeySymlinkTargetValidation(t *testing.T) {
	for _, kind := range []string{"directory", "oversized", "missing"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "target")
			switch kind {
			case "directory":
				if err := os.Mkdir(target, 0700); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				if err := os.WriteFile(target, nil, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Truncate(target, privateKeyFileLimit+1); err != nil {
					t.Fatal(err)
				}
			}
			link := filepath.Join(dir, "link")
			privateKeyTestLink(t, target, link)
			if data, err := readPrivateKeyFile(link); err == nil || len(data) != 0 {
				t.Fatal("invalid symlink target accepted")
			}
		})
	}
}

func TestMigrationWithSymlinkedPrivateKey(t *testing.T) {
	m, _, _ := migrationFixture(t)
	cfg, err := NewDefaultStore(m.path, m.keyPath).Load()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := cfg.Identities.Get("ops")
	link := filepath.Join(filepath.Dir(id.KeyPath), "linked-key")
	privateKeyTestLink(t, id.KeyPath, link)
	id.KeyPath = link
	cfg.Identities.Set("ops", id)
	if err := NewDefaultStore(m.path, m.keyPath).Save(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "vault", DryRun: true}); err != nil {
		t.Fatal(err)
	}
	if report, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "vault"}); err != nil || !report.Verified {
		t.Fatalf("linked-key migration failed: %v", err)
	}
	cfg, err = NewDefaultStore(m.path, m.keyPath).Load()
	if err != nil {
		t.Fatal(err)
	}
	id, _ = cfg.Identities.Get("ops")
	if id.KeyPath != link || id.KeyFingerprint == "" || id.PassphraseRef == nil {
		t.Fatal("migration lost linked-key metadata")
	}
	if _, err := m.Finalize(t.Context()); err != nil {
		t.Fatal(err)
	}
}
