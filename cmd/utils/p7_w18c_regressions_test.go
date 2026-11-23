package utils

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	sshcrypto "golang.org/x/crypto/ssh"
)

func writeW18cDecoyKey(t *testing.T, path, pass string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	block, err := sshcrypto.MarshalPrivateKeyWithPassphrase(priv, "", []byte(pass))
	if err != nil {
		t.Fatalf("MarshalPrivateKeyWithPassphrase: %v", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
}

func TestP7W18c_L4_18_L1_CredSetPassphraseRejectsNonConcreteIdentityPaths(t *testing.T) {
	cwd := t.TempDir()
	cfgDir := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XOPS_CONFIG_DIR", cfgDir)
	t.Setenv("XOPS_JOURNAL_DIR", filepath.Join(cfgDir, "journals"))
	t.Chdir(cwd)

	const pass = "decoy-pass"
	for _, decoy := range []string{"none", "NONE", "%h_key", "${HOME}_key"} {
		writeW18cDecoyKey(t, filepath.Join(cwd, decoy), pass)
	}
	tildeDir := filepath.Join(cwd, "~nonexistent_w18c_user")
	if err := os.MkdirAll(tildeDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	writeW18cDecoyKey(t, filepath.Join(tildeDir, "id_ed25519"), pass)

	cfgPath, keyPath, err := GetConfigFilePath()
	if err != nil {
		t.Fatalf("GetConfigFilePath: %v", err)
	}
	store := config.NewDefaultStore(cfgPath, keyPath)
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.SchemaVersion = 2
	cfg.Credential = &config.CredentialConfig{
		DefaultStore: "none",
		Stores: map[string]config.StoreConfig{
			"none": {Type: config.StoreTypeNone},
		},
	}

	cases := []struct {
		idName  string
		keyPath string
	}{
		{idName: "id-none", keyPath: "none"},
		{idName: "id-NONE", keyPath: "NONE"},
		{idName: "id-pct", keyPath: "%h_key"},
		{idName: "id-env", keyPath: "${HOME}_key"},
		{idName: "id-tilde-user", keyPath: "~nonexistent_w18c_user/id_ed25519"},
	}
	for _, tc := range cases {
		cfg.Identities.Set(tc.idName, models.Identity{
			User:     "ops",
			AuthType: "key",
			KeyPath:  tc.keyPath,
		})
	}
	if err := store.Save(cfg); err != nil {
		t.Fatalf("store.Save: %v", err)
	}

	for _, tc := range cases {
		t.Run(tc.idName, func(t *testing.T) {
			cmd := &cobra.Command{}
			cmd.SetIn(strings.NewReader(pass + "\n"))
			opts := &CredentialCommandOptions{
				Scope:           CredentialScopeIdentity,
				KindPassphrase:  true,
				PassphraseStdin: true,
			}
			if err := opts.RunSet(cmd, tc.idName); err == nil {
				t.Fatalf("RunSet(%q, KeyPath=%q) succeeded, want rejection of non-concrete path", tc.idName, tc.keyPath)
			}
		})
	}
}
