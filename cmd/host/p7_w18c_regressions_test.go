package host

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
)

func seedW18cIdentityIsolationConfig(t *testing.T) (config.Store, models.Identity) {
	t.Helper()
	homeDir := t.TempDir()
	xopsDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)
	t.Setenv("XOPS_CONFIG_DIR", xopsDir)
	t.Setenv("XOPS_JOURNAL_DIR", filepath.Join(xopsDir, "journals"))

	cfgPath, keyPath, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatalf("GetConfigFilePath: %v", err)
	}
	store := config.NewDefaultStore(cfgPath, keyPath)
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.SchemaVersion = 2
	cfg.Credential = &config.CredentialConfig{
		DefaultStore: "vault",
		Stores: map[string]config.StoreConfig{
			"vault": {Type: config.StoreTypeHelper, Command: "/unused-helper"},
		},
	}
	sharedIdent := models.Identity{
		User:             "ops",
		AuthType:         "key",
		KeyPath:          "/keys/shared_id_ed25519",
		KeyFingerprint:   "SHA256:sharedfp123",
		PassphraseRef:    &credential.Ref{StoreID: "vault", ItemID: "pp-shared-keep"},
		LoginPasswordRef: &credential.Ref{StoreID: "vault", ItemID: "pw-shared-keep"},
	}
	cfg.Identities.Set("shared-id", sharedIdent)
	cfg.Hosts.Set("10.18.0.1:22", models.Host{Address: "10.18.0.1", Port: 22})
	cfg.Identities.Set("orig@10.18.0.1", models.Identity{User: "orig", AuthType: "auto"})
	cfg.Nodes.Set("orig@10.18.0.1:22", models.Node{
		HostRef:     "10.18.0.1:22",
		IdentityRef: "orig@10.18.0.1",
		SudoMode:    models.SudoModeAuto,
	})
	if err := store.Save(cfg); err != nil {
		t.Fatalf("store.Save: %v", err)
	}
	return store, sharedIdent
}

func assertW18cSharedIdentityUnchanged(t *testing.T, store config.Store, want models.Identity) {
	t.Helper()
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	got, ok := loaded.Identities.Get("shared-id")
	if !ok {
		t.Fatal("shared-id identity disappeared")
	}
	if got.User != want.User || got.AuthType != want.AuthType || got.KeyPath != want.KeyPath ||
		got.KeyFingerprint != want.KeyFingerprint ||
		got.PassphraseRef == nil || *got.PassphraseRef != *want.PassphraseRef ||
		got.LoginPasswordRef == nil || *got.LoginPasswordRef != *want.LoginPasswordRef {
		t.Fatalf("shared-id identity was mutated:\n got: %+v\nwant: %+v", got, want)
	}
}

func TestP7W18c_L4_18_M1_HostAddAndEditIsolateIdentityTemplate(t *testing.T) {
	store, wantIdent := seedW18cIdentityIsolationConfig(t)
	unencKey := writeW16cHostUnencryptedKey(t)

	verifyCalled := false
	verifier := func(_ context.Context, _ *config.Repository, _ string, _ *inventoryVerification) error {
		verifyCalled = true
		return nil
	}

	rejectAddCases := []struct {
		name string
		args []string
	}{
		{name: "identity_with_key_flag", args: []string{"10.18.0.2", "-I", "shared-id", "-k", unencKey}},
		{name: "identity_with_user_flag", args: []string{"10.18.0.2", "-I", "shared-id", "-u", "bob"}},
		{name: "identity_with_positional_user_at_host", args: []string{"bob@10.18.0.2", "-I", "shared-id"}},
		{name: "identity_with_positional_alias_and_user_at_host", args: []string{"myalias", "bob@10.18.0.2", "-I", "shared-id"}},
		{name: "identity_with_address_flag_user_at_host", args: []string{"-H", "bob@10.18.0.2", "-I", "shared-id"}},
	}
	for _, tc := range rejectAddCases {
		t.Run("add_reject_"+tc.name, func(t *testing.T) {
			verifyCalled = false
			cmd := newCmdInventoryAdd(verifier)
			cmd.SetArgs(tc.args)
			if err := cmd.Execute(); err == nil {
				t.Fatalf("host add %v succeeded, want error", tc.args)
			}
			if verifyCalled {
				t.Fatalf("host add %v invoked verifier before rejecting invalid --identity combination", tc.args)
			}
			assertW18cSharedIdentityUnchanged(t, store, wantIdent)
		})
	}

	t.Run("add_valid_identity_template_links_without_touching_vault_or_template", func(t *testing.T) {
		cmd := newCmdInventoryAdd(verifier)
		cmd.SetArgs([]string{"10.18.0.2:2222", "-I", "shared-id", "--skip-verify"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("host add -I shared-id failed: %v", err)
		}
		loaded, err := store.Load()
		if err != nil {
			t.Fatalf("store.Load: %v", err)
		}
		node, ok := loaded.Nodes.Get("ops@10.18.0.2:2222")
		if !ok || node.IdentityRef != "shared-id" {
			t.Fatalf("created node = (%+v, %v), want ops@10.18.0.2:2222 with IdentityRef=shared-id", node, ok)
		}
		assertW18cSharedIdentityUnchanged(t, store, wantIdent)
	})

	rejectEditCases := []struct {
		name string
		args []string
	}{
		{name: "edit_identity_with_positional_user_at_host", args: []string{"orig@10.18.0.1:22", "bob@10.18.0.9", "-I", "shared-id"}},
		{name: "edit_identity_with_address_flag_user_at_host", args: []string{"orig@10.18.0.1:22", "-H", "bob@10.18.0.9", "-I", "shared-id"}},
		{name: "edit_identity_with_user_flag", args: []string{"orig@10.18.0.1:22", "-u", "bob", "-I", "shared-id"}},
		{name: "edit_identity_with_key_flag", args: []string{"orig@10.18.0.1:22", "-k", unencKey, "-I", "shared-id"}},
	}
	for _, tc := range rejectEditCases {
		t.Run("edit_reject_"+tc.name, func(t *testing.T) {
			cmd := NewCmdInventoryEdit()
			cmd.SetArgs(tc.args)
			if err := cmd.Execute(); err == nil {
				t.Fatalf("host edit %v succeeded, want error", tc.args)
			}
			assertW18cSharedIdentityUnchanged(t, store, wantIdent)
		})
	}
}
