package host

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
	sshcrypto "golang.org/x/crypto/ssh"
)

func writeW16cHostUnencryptedKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	block, err := sshcrypto.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("WriteFile key: %v", err)
	}
	return path
}

func runHostAddCLI(args ...string) error {
	cmd := NewCmdInventoryAdd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	return cmd.Execute()
}

func TestP7W16c_L4_16_M3_HostAddAllocatesNonCollidingHostAndIdentityRefs(t *testing.T) {
	homeDir := t.TempDir()
	xopsDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)
	t.Setenv("XOPS_CONFIG_DIR", xopsDir)

	cfgPath, keyPath, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatalf("GetConfigFilePath: %v", err)
	}
	store := config.NewDefaultStore(cfgPath, keyPath)
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.SchemaVersion = 2
	cfg.Hosts.Set("10.0.0.1:22", models.Host{Address: "10.0.0.1", Port: 22, Alias: []string{"web1"}})
	cfg.Identities.Set("ops@10.0.0.1", models.Identity{User: "ops", AuthType: "key", KeyPath: writeW16cHostUnencryptedKey(t)})
	cfg.Identities.Set("shared-tpl", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("ops@10.0.0.1:22", models.Node{
		HostRef:     "10.0.0.1:22",
		IdentityRef: "ops@10.0.0.1",
		SudoMode:    models.SudoModeAuto,
	})
	if err := store.Save(cfg); err != nil {
		t.Fatalf("store.Save: %v", err)
	}

	// 1. Add bob@10.0.0.1:22 on same host:port where Hosts["10.0.0.1:22"] has Alias=["web1"].
	assertW16cHostAddPrivateHostRef(t, store)
	// 2. Add ops@10.0.0.1:2222 with a different key (no -I) -> must allocate private IdentityRef without ErrConfigConflict.
	assertW16cHostAddPrivateIdentityRef(t, store)
	// 3. Explicit -I shared-tpl still reuses the named identity as designed.
	assertW16cHostAddExplicitIdentityTemplate(t, store)
}

func assertW16cHostAddPrivateHostRef(t *testing.T, store config.Store) {
	t.Helper()
	if err := runHostAddCLI("bob@10.0.0.1:22", "--skip-verify"); err != nil {
		t.Fatalf("host add bob@10.0.0.1:22 failed: %v", err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load after bob: %v", err)
	}
	bobNode, ok := loaded.Nodes.Get("bob@10.0.0.1:22")
	if !ok {
		t.Fatal("bob@10.0.0.1:22 missing")
	}
	if bobNode.HostRef == "10.0.0.1:22" {
		t.Fatalf("bob@10.0.0.1:22 reused aliased HostRef 10.0.0.1:22")
	}
	repo, err := config.NewRepositoryWithoutOpenSSH(loaded, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	if resolved, err := repo.ResolveSelector("web1"); err != nil || resolved != "ops@10.0.0.1:22" {
		t.Fatalf("ResolveSelector(web1) = (%q, %v), want ops@10.0.0.1:22", resolved, err)
	}
}

func assertW16cHostAddPrivateIdentityRef(t *testing.T, store config.Store) {
	t.Helper()
	key2 := writeW16cHostUnencryptedKey(t)
	if err := runHostAddCLI("ops@10.0.0.1:2222", "-k", key2, "--skip-verify"); err != nil {
		t.Fatalf("host add ops@10.0.0.1:2222 -k key2 failed: %v", err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load after ops:2222: %v", err)
	}
	ops2222, ok := loaded.Nodes.Get("ops@10.0.0.1:2222")
	if !ok {
		t.Fatal("ops@10.0.0.1:2222 missing")
	}
	if ops2222.IdentityRef == "ops@10.0.0.1" {
		t.Fatalf("ops@10.0.0.1:2222 collided with existing ops@10.0.0.1 identity")
	}
	ident2222, _ := loaded.Identities.Get(ops2222.IdentityRef)
	if ident2222.KeyPath != key2 || ident2222.AuthType != "key" {
		t.Fatalf("ops@10.0.0.1:2222 identity = %+v, want KeyPath=%q AuthType=key", ident2222, key2)
	}
	origIdent, _ := loaded.Identities.Get("ops@10.0.0.1")
	if origIdent.KeyPath == key2 {
		t.Fatalf("original ops@10.0.0.1 identity was overwritten")
	}
}

func assertW16cHostAddExplicitIdentityTemplate(t *testing.T, store config.Store) {
	t.Helper()
	if err := runHostAddCLI("10.0.0.1:2223", "-I", "shared-tpl", "--skip-verify"); err != nil {
		t.Fatalf("host add -I shared-tpl failed: %v", err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load after -I shared-tpl: %v", err)
	}
	ops2223, ok := loaded.Nodes.Get("ops@10.0.0.1:2223")
	if !ok || ops2223.IdentityRef != "shared-tpl" {
		t.Fatalf("ops@10.0.0.1:2223 = (%+v, %v), want IdentityRef=shared-tpl", ops2223, ok)
	}
}

func TestP7W16c_L4_16_M3_HostEditSharedAliasedHostPortChange(t *testing.T) {
	homeDir := t.TempDir()
	xopsDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)
	t.Setenv("XOPS_CONFIG_DIR", xopsDir)

	cfgPath, keyPath, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatalf("GetConfigFilePath: %v", err)
	}
	store := config.NewDefaultStore(cfgPath, keyPath)
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.SchemaVersion = 2
	cfg.Hosts.Set("10.0.0.5:22", models.Host{Address: "10.0.0.5", Port: 22, Alias: []string{"db-primary"}})
	cfg.Identities.Set("deploy@10.0.0.5", models.Identity{User: "deploy", AuthType: "auto"})
	cfg.Identities.Set("audit@10.0.0.5", models.Identity{User: "audit", AuthType: "auto"})
	cfg.Nodes.Set("deploy@10.0.0.5:22", models.Node{HostRef: "10.0.0.5:22", IdentityRef: "deploy@10.0.0.5", SudoMode: models.SudoModeAuto})
	cfg.Nodes.Set("audit@10.0.0.5:22", models.Node{HostRef: "10.0.0.5:22", IdentityRef: "audit@10.0.0.5", SudoMode: models.SudoModeAuto})
	if err := store.Save(cfg); err != nil {
		t.Fatalf("store.Save: %v", err)
	}

	if err := runHostEditCLI("audit@10.0.0.5:22", "-p", "2222"); err != nil {
		t.Fatalf("host edit audit@10.0.0.5:22 -p 2222 failed: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	auditNode, ok := loaded.Nodes.Get("audit@10.0.0.5:2222")
	if !ok {
		t.Fatal("audit@10.0.0.5:2222 missing after port edit")
	}
	forkedHost, _ := loaded.Hosts.Get(auditNode.HostRef)
	if forkedHost.Port != 2222 || len(forkedHost.Alias) != 0 {
		t.Fatalf("forked host = %+v, want Port=2222 and no Alias", forkedHost)
	}
	repo, err := config.NewRepositoryWithoutOpenSSH(loaded, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	if resolved, err := repo.ResolveSelector("db-primary"); err != nil || resolved != "deploy@10.0.0.5:22" {
		t.Fatalf("ResolveSelector(db-primary) = (%q, %v), want deploy@10.0.0.5:22", resolved, err)
	}
}

func TestP7W16c_L4_16_M2_HostEditKeyPreservesHybridAuthTypesAndLoginPassword(t *testing.T) {
	for _, authType := range []string{"auto", "otp", "keyboard-interactive"} {
		t.Run(authType, func(t *testing.T) {
			homeDir := t.TempDir()
			xopsDir := t.TempDir()
			t.Setenv("HOME", homeDir)
			t.Setenv("USERPROFILE", homeDir)
			t.Setenv("XOPS_CONFIG_DIR", xopsDir)

			cfgPath, keyPath, err := utils.GetConfigFilePath()
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
					"mem":  {Type: config.StoreTypeHelper, Command: "/unused"},
				},
			}
			pwRef := &credential.Ref{StoreID: "mem", ItemID: "pw-" + authType}
			cfg.Hosts.Set("10.0.0.9:22", models.Host{Address: "10.0.0.9", Port: 22})
			cfg.Identities.Set("ops@10.0.0.9", models.Identity{
				User:             "ops",
				AuthType:         authType,
				LoginPasswordRef: pwRef.Clone(),
			})
			cfg.Nodes.Set("ops@10.0.0.9:22", models.Node{
				HostRef:     "10.0.0.9:22",
				IdentityRef: "ops@10.0.0.9",
				SudoMode:    models.SudoModeAuto,
			})
			if err := store.Save(cfg); err != nil {
				t.Fatalf("store.Save: %v", err)
			}

			unencKey := writeW16cHostUnencryptedKey(t)
			if err := runHostEditCLI("ops@10.0.0.9:22", "--key", unencKey); err != nil {
				t.Fatalf("host edit --key on %s failed: %v", authType, err)
			}
			loaded, err := store.Load()
			if err != nil {
				t.Fatalf("store.Load: %v", err)
			}
			ident, _ := loaded.Identities.Get("ops@10.0.0.9")
			if ident.AuthType != authType || ident.KeyPath != unencKey {
				t.Fatalf("identity AuthType/KeyPath = (%q, %q), want (%q, %q)", ident.AuthType, ident.KeyPath, authType, unencKey)
			}
			if ident.LoginPasswordRef == nil || *ident.LoginPasswordRef != *pwRef {
				t.Fatalf("LoginPasswordRef lost on %s host edit --key: %+v", authType, ident)
			}
		})
	}
}
