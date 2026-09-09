package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	hostcmd "github.com/wentf9/xops-cli/cmd/host"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/tui"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
)

func phase6Config(t *testing.T, storeCfg config.StoreConfig) config.Store {
	t.Helper()
	dir := setupTestEnvironment(t)
	t.Setenv("TEST_IDENTITY_HELPER", "1")
	t.Setenv("TEST_HELPER_DATA_FILE", filepath.Join(dir, "helper-data"))
	cfg := &config.Configuration{
		SchemaVersion: 2,
		Nodes:         concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:         concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities:    concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Credential:    &config.CredentialConfig{DefaultStore: "test", RememberPrompted: "never", Stores: map[string]config.StoreConfig{"test": storeCfg}},
	}
	cfg.Identities.Set("admin", models.Identity{User: "admin", AuthType: "password"})
	cfg.Hosts.Set("host", models.Host{Address: "127.0.0.1", Port: 22})
	cfg.Nodes.Set("node", models.Node{HostRef: "host", IdentityRef: "admin"})
	path, key, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatal(err)
	}
	store := config.NewDefaultStore(path, key)
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	return store
}

func executePhase6(t *testing.T, cmd *cobra.Command, args ...string) error {
	t.Helper()
	cmd.SetArgs(args)
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetContext(t.Context())
	return cmd.Execute()
}

func TestInventoryCompatibilityFlagsUseCredentialStore(t *testing.T) {
	for _, tc := range []struct {
		name           string
		newCmd         func() *cobra.Command
		args           []string
		identity, node string
	}{
		{"identity add", NewCmdIdentity, []string{"add", "--name", "new", "--user", "admin", "--password", "fixture-secret"}, "new", ""},
		{"identity edit", NewCmdIdentity, []string{"edit", "admin", "--password", "fixture-secret"}, "admin", ""},
		{"host add", hostcmd.NewCmdInventoryAdd, []string{"--address", "127.0.0.2", "--user", "admin", "--password", "fixture-secret"}, "", "admin@127.0.0.2:22"},
		{"host edit", hostcmd.NewCmdInventoryEdit, []string{"node", "--password", "fixture-secret"}, "", "node"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := phase6Config(t, config.StoreConfig{Type: config.StoreTypeHelper, Command: os.Args[0]})
			if err := executePhase6(t, tc.newCmd(), tc.args...); err != nil {
				t.Fatal(err)
			}
			cfg, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			id := tc.identity
			if tc.node != "" {
				node, ok := cfg.Nodes.Get(tc.node)
				if !ok {
					t.Fatal("node missing")
				}
				id = node.IdentityRef
			}
			identity, ok := cfg.Identities.Get(id)
			if !ok || identity.Password != "" || identity.Passphrase != "" || identity.LoginPasswordRef == nil {
				t.Fatal("secret was not replaced by a reference")
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
			if string(secret.Value) != "fixture-secret" {
				t.Fatal("stored secret mismatch")
			}
			path, _, err := utils.GetConfigFilePath()
			if err != nil {
				t.Fatal(err)
			}
			yaml, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(yaml), "password:") || strings.Contains(string(yaml), "fixture-secret") {
				t.Fatal("YAML contains a secret field")
			}
		})
	}
}

func TestInventoryNoneRejectsSecretBeforeMutation(t *testing.T) {
	store := phase6Config(t, config.StoreConfig{Type: config.StoreTypeNone})
	err := executePhase6(t, NewCmdIdentity(), "add", "--name", "new", "--password", "fixture-secret")
	if !errors.Is(err, credential.ErrCredentialStoreReadOnly) {
		t.Fatalf("none write = %v", err)
	}
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Identities.Get("new"); ok {
		t.Fatal("rejected credential created an identity")
	}
}

func TestIdentityCredentialFailurePreservesAuthentication(t *testing.T) {
	store := phase6Config(t, config.StoreConfig{Type: config.StoreTypeHelper, Command: os.Args[0]})
	if err := executePhase6(t, NewCmdIdentity(), "edit", "admin", "--password", "old-secret"); err != nil {
		t.Fatal(err)
	}
	before, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	old, _ := before.Identities.Get("admin")
	t.Setenv("TEST_HELPER_ERROR_CODE", "locked")
	err = executePhase6(t, NewCmdIdentity(), "edit", "admin", "--key", "replacement-key", "--key-pass", "new-secret")
	if !errors.Is(err, credential.ErrCredentialStoreLocked) {
		t.Fatalf("locked write = %v", err)
	}
	after, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	got, _ := after.Identities.Get("admin")
	if got.AuthType != old.AuthType || got.KeyPath != old.KeyPath || got.LoginPasswordRef == nil || *got.LoginPasswordRef != *old.LoginPasswordRef || got.Passphrase != "" {
		t.Fatal("failed replacement changed authentication")
	}
}

func TestDoctorReportsUnavailableAndLockedStores(t *testing.T) {
	for _, tc := range []struct{ name, command, code string }{
		{"missing executable", filepath.Join(t.TempDir(), "missing"), ""},
		{"locked", os.Args[0], "locked"},
		{"denied", os.Args[0], "denied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			phase6Config(t, config.StoreConfig{Type: config.StoreTypeHelper, Command: tc.command, NonInteractive: true})
			t.Setenv("TEST_HELPER_ERROR_CODE", tc.code)
			if err := executePhase6(t, NewCmdCredential(), "doctor"); err == nil {
				t.Fatal("unavailable store reported healthy")
			}
		})
	}
}

func TestTUIConstructionDoesNotRequireAvailableStore(t *testing.T) {
	store := phase6Config(t, config.StoreConfig{Type: config.StoreTypeSystem})
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, configured := range []bool{true, false} {
		if !configured {
			cfg.Credential = nil
		}
		repo, err := config.NewRepository(cfg, store)
		if err != nil {
			t.Fatal(err)
		}
		service, err := utils.GetCredentialService(repo, cfg)
		if err != nil {
			t.Fatal(err)
		}
		registry, err := utils.GetCredentialRegistry(cfg)
		if err != nil {
			t.Fatal(err)
		}
		model, err := tui.NewModel(repo, tui.WithCredentialService(service), tui.WithCredentialRegistry(registry), tui.WithContext(t.Context()))
		if err != nil {
			t.Fatal(err)
		}
		if err := model.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSSHRememberUsesConfiguredPolicyAndExplicitOverride(t *testing.T) {
	for _, tc := range []struct {
		name, configured, override string
		wantStored                 bool
	}{
		{"configured always", "always", "", true},
		{"configured never", "never", "", false},
		{"explicit never", "always", "never", false},
		{"explicit always", "never", "always", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := phase6Config(t, config.StoreConfig{Type: config.StoreTypeHelper, Command: os.Args[0]})
			cfg, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			cfg.Credential.RememberPrompted = tc.configured
			if err := store.Save(cfg); err != nil {
				t.Fatal(err)
			}
			repo, err := config.NewRepositoryWithoutOpenSSH(cfg, store)
			if err != nil {
				t.Fatal(err)
			}
			o := NewSshOptions()
			o.Remember = tc.override
			options, err := o.buildAdapterOptions("node", cfg, repo)
			if err != nil {
				t.Fatal(err)
			}
			adp := adapter.NewSSHAdapter(repo, options...)
			snapshot, err := repo.ResolveConnection("node")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := adp.UpdateAuth(t.Context(), "node", string(snapshot.UpdateRef.AuthVersion[:]), "fixture-secret", "", ""); err != nil {
				t.Fatal(err)
			}
			got, err := repo.ResolveConnection("node")
			if err != nil {
				t.Fatal(err)
			}
			if (got.Identity.LoginPasswordRef != nil) != tc.wantStored || got.Identity.Password != "" {
				t.Fatal("remember policy not applied")
			}
		})
	}
}

func TestHostCredentialReplacementPreservesSharedIdentity(t *testing.T) {
	store := phase6Config(t, config.StoreConfig{Type: config.StoreTypeHelper, Command: os.Args[0]})
	if err := executePhase6(t, NewCmdIdentity(), "edit", "admin", "--password", "shared-secret"); err != nil {
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
	if err := executePhase6(t, hostcmd.NewCmdInventoryEdit(), "node", "--password", "private-secret"); err != nil {
		t.Fatal(err)
	}
	cfg, err = store.Load()
	if err != nil {
		t.Fatal(err)
	}
	original, _ := cfg.Identities.Get("admin")
	node, _ := cfg.Nodes.Get("node")
	private, _ := cfg.Identities.Get(node.IdentityRef)
	if node.IdentityRef == "admin" || original.LoginPasswordRef == nil || private.LoginPasswordRef == nil || *original.LoginPasswordRef != *old.LoginPasswordRef || *private.LoginPasswordRef == *old.LoginPasswordRef {
		t.Fatal("shared identity was overwritten")
	}
	reg, err := utils.GetCredentialRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := reg.Resolve(t.Context(), *old.LoginPasswordRef)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret.Value)
	if string(secret.Value) != "shared-secret" {
		t.Fatal("shared secret was removed")
	}
}

func TestBatchSCPRefusesHelperWithoutNonInteractiveContract(t *testing.T) {
	store := phase6Config(t, config.StoreConfig{Type: config.StoreTypeHelper, Command: os.Args[0]})
	if err := executePhase6(t, NewCmdIdentity(), "edit", "admin", "--password", "fixture-secret"); err != nil {
		t.Fatal(err)
	}
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	o := NewScpOptions()
	o.Host = "first,second"
	o.Remember = "always"
	connector, err := o.credentialConnector(repo, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := connector.CloseAll(); err != nil {
			t.Error(err)
		}
	}()
	_, err = connector.Connect(t.Context(), "node")
	if !errors.Is(err, credential.ErrCredentialStoreUnavailable) || !strings.Contains(err.Error(), "does not declare") {
		t.Fatalf("batch SCP did not enforce backend policy: %v", err)
	}
}

func TestInventoryPassphraseReplacementClearsLegacySecrets(t *testing.T) {
	for _, tc := range []struct {
		name   string
		newCmd func() *cobra.Command
		args   []string
	}{
		{"identity", NewCmdIdentity, []string{"edit", "admin", "--key", "fixture-key", "--key-pass", "fixture-passphrase"}},
		{"host", hostcmd.NewCmdInventoryEdit, []string{"node", "--key", "fixture-key", "--key-pass", "fixture-passphrase"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := phase6Config(t, config.StoreConfig{Type: config.StoreTypeHelper, Command: os.Args[0]})
			cfg, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			cfg.Identities.Set("admin", models.Identity{User: "admin", AuthType: "password", Password: "legacy-login", Passphrase: "legacy-passphrase"})
			if err := store.Save(cfg); err != nil {
				t.Fatal(err)
			}
			if err := executePhase6(t, tc.newCmd(), tc.args...); err != nil {
				t.Fatal(err)
			}
			cfg, err = store.Load()
			if err != nil {
				t.Fatal(err)
			}
			node, _ := cfg.Nodes.Get("node")
			identity, _ := cfg.Identities.Get(node.IdentityRef)
			if identity.Password != "" || identity.Passphrase != "" || identity.AuthType != "key" || identity.KeyPath != utils.ToAbsolutePath("fixture-key") || identity.PassphraseRef == nil {
				t.Fatal("passphrase transaction did not commit authentication metadata or clear legacy fields")
			}
			reg, err := utils.GetCredentialRegistry(cfg)
			if err != nil {
				t.Fatal(err)
			}
			secret, err := reg.Resolve(t.Context(), *identity.PassphraseRef)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(secret.Value)
			if string(secret.Value) != "fixture-passphrase" {
				t.Fatal("passphrase mismatch")
			}
		})
	}
}
