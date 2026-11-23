package cmd

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	hostcmd "github.com/wentf9/xops-cli/cmd/host"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func setupW16cHelperStore(t *testing.T) (config.Store, string) {
	t.Helper()
	tempDir := setupTestEnvironment(t)
	helperDataFile := filepath.Join(tempDir, "helper_data.json")
	t.Setenv("TEST_IDENTITY_HELPER", "1")
	t.Setenv("TEST_HELPER_DATA_FILE", helperDataFile)

	cfgPath, keyPath, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatalf("GetConfigFilePath: %v", err)
	}
	store := config.NewDefaultStore(cfgPath, keyPath)
	cfg := &config.Configuration{
		SchemaVersion: 2,
		Nodes:         concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:         concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities:    concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Credential: &config.CredentialConfig{
			DefaultStore: "helper-store",
			Stores: map[string]config.StoreConfig{
				"helper-store": {
					Type:    config.StoreTypeHelper,
					Command: os.Args[0],
				},
			},
		},
	}
	if err := store.Save(cfg); err != nil {
		t.Fatalf("store.Save: %v", err)
	}
	return store, helperDataFile
}

func readW16cHelperVault(t *testing.T, helperDataFile string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(helperDataFile)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}
		}
		t.Fatalf("ReadFile helper vault: %v", err)
	}
	data := make(map[string]string)
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &data); err != nil {
			t.Fatalf("Unmarshal helper vault: %v", err)
		}
	}
	decoded := make(map[string]string, len(data))
	for k, v := range data {
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			t.Fatalf("base64 decode helper vault entry %q: %v", k, err)
		}
		decoded[k] = string(b)
	}
	return decoded
}

func TestP7W16c_L4_16_H1_CredSetAndHostIdentityEditCrossKindSwitchUnlinksAndCleansVault(t *testing.T) {
	t.Run("cred_set_password_on_encrypted_key_node_unlinks_and_deletes_passphrase", testW16cCredSetPasswordOnEncryptedKeyNode)
	t.Run("cred_set_password_on_encrypted_key_identity_and_shared_node_safety", testW16cCredSetPasswordOnSharedEncryptedKey)
	t.Run("host_edit_cross_kind_switches_unlink_and_clean_vault", testW16cHostEditCrossKindSwitches)
	t.Run("identity_edit_cross_kind_switches_unlink_and_clean_vault", testW16cIdentityEditCrossKindSwitches)
}

func testW16cCredSetPasswordOnEncryptedKeyNode(t *testing.T) {
	store, vaultFile := setupW16cHelperStore(t)
	encKey := inventoryTestPrivateKey(t, true)
	mustExecRoot(t, "key-password\n", "host", "add", "ops@10.40.0.1:22", "--key", encKey, "--passphrase-stdin", "--skip-verify")

	beforeCfg, _ := store.Load()
	beforeNode, _ := beforeCfg.Nodes.Get("ops@10.40.0.1:22")
	beforeIdent, _ := beforeCfg.Identities.Get(beforeNode.IdentityRef)
	if beforeIdent.PassphraseRef == nil || beforeIdent.KeyFingerprint == "" {
		t.Fatalf("initial encrypted-key node missing passphrase/fingerprint: %+v", beforeIdent)
	}
	oldPassItemID := beforeIdent.PassphraseRef.ItemID

	mustExecRoot(t, "new-login-secret\n", "cred", "set", "ops@10.40.0.1:22", "--password", "--password-stdin")

	afterCfg, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	afterNode, _ := afterCfg.Nodes.Get("ops@10.40.0.1:22")
	afterIdent, _ := afterCfg.Identities.Get(afterNode.IdentityRef)
	if afterIdent.AuthType != "password" || afterIdent.KeyPath != "" || afterIdent.KeyFingerprint != "" || afterIdent.PassphraseRef != nil {
		t.Fatalf("cred set --password left stale key fields: %+v", afterIdent)
	}
	if afterIdent.LoginPasswordRef == nil {
		t.Fatal("LoginPasswordRef missing after cred set --password")
	}
	vault := readW16cHelperVault(t, vaultFile)
	if _, leaked := vault[oldPassItemID]; leaked {
		t.Fatalf("displaced passphrase %q remained in helper vault: %v", oldPassItemID, vault)
	}
	if vault[afterIdent.LoginPasswordRef.ItemID] != "new-login-secret" {
		t.Fatalf("new password missing from vault: %v", vault)
	}
}

func testW16cCredSetPasswordOnSharedEncryptedKey(t *testing.T) {
	store, vaultFile := setupW16cHelperStore(t)
	encKey := inventoryTestPrivateKey(t, true)
	mustExecRoot(t, "key-password\n", "identity", "add", "shared-key", "ops", "--key", encKey, "--passphrase-stdin")
	mustExecRoot(t, "", "host", "add", "ops@10.40.0.2:22", "-I", "shared-key", "--skip-verify")
	mustExecRoot(t, "", "host", "add", "ops@10.40.0.3:22", "-I", "shared-key", "--skip-verify")

	cfgBefore, _ := store.Load()
	sharedBefore, _ := cfgBefore.Identities.Get("shared-key")
	sharedPassItemID := sharedBefore.PassphraseRef.ItemID

	mustExecRoot(t, "node1-pw\n", "cred", "set", "ops@10.40.0.2:22", "--password", "--password-stdin")
	vaultMid := readW16cHelperVault(t, vaultFile)
	if vaultMid[sharedPassItemID] != "key-password" {
		t.Fatalf("shared passphrase was deleted while sibling node still referenced it: %v", vaultMid)
	}

	mustExecRoot(t, "shared-pw\n", "cred", "set", "shared-key", "--password", "--password-stdin")
	cfgAfter, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	sharedAfter, _ := cfgAfter.Identities.Get("shared-key")
	if sharedAfter.AuthType != "password" || sharedAfter.KeyPath != "" || sharedAfter.KeyFingerprint != "" || sharedAfter.PassphraseRef != nil {
		t.Fatalf("cred set identity --password left stale key fields: %+v", sharedAfter)
	}
	vaultAfter := readW16cHelperVault(t, vaultFile)
	if _, leaked := vaultAfter[sharedPassItemID]; leaked {
		t.Fatalf("unreferenced shared passphrase %q remained in vault: %v", sharedPassItemID, vaultAfter)
	}
}

func testW16cHostEditCrossKindSwitches(t *testing.T) {
	store, vaultFile := setupW16cHelperStore(t)
	encKey := inventoryTestPrivateKey(t, true)
	unencKey := inventoryTestPrivateKey(t, false)

	mustExecRoot(t, "initial-pw\n", "host", "add", "ops@10.40.0.4:22", "--password-stdin", "--skip-verify")
	cfg1, _ := store.Load()
	n1, _ := cfg1.Nodes.Get("ops@10.40.0.4:22")
	id1, _ := cfg1.Identities.Get(n1.IdentityRef)
	pw1ItemID := id1.LoginPasswordRef.ItemID

	mustExecRoot(t, "", "host", "edit", "ops@10.40.0.4:22", "--key", unencKey)
	cfg2, _ := store.Load()
	id2, _ := cfg2.Identities.Get(n1.IdentityRef)
	if id2.AuthType != "key" || id2.KeyPath != unencKey || id2.LoginPasswordRef != nil {
		t.Fatalf("host edit password->unenc key left stale LoginPasswordRef: %+v", id2)
	}
	if _, leaked := readW16cHelperVault(t, vaultFile)[pw1ItemID]; leaked {
		t.Fatalf("host edit password->unenc key left old password %q in vault", pw1ItemID)
	}

	mustExecRoot(t, "key-password\n", "host", "edit", "ops@10.40.0.4:22", "--key", encKey, "--passphrase-stdin")
	cfg3, _ := store.Load()
	id3, _ := cfg3.Identities.Get(n1.IdentityRef)
	ppItemID := id3.PassphraseRef.ItemID

	mustExecRoot(t, "back-to-pw\n", "host", "edit", "ops@10.40.0.4:22", "--password-stdin")
	cfg4, _ := store.Load()
	id4, _ := cfg4.Identities.Get(n1.IdentityRef)
	if id4.AuthType != "password" || id4.KeyPath != "" || id4.KeyFingerprint != "" || id4.PassphraseRef != nil || id4.LoginPasswordRef == nil {
		t.Fatalf("host edit enc-key->password left stale key fields: %+v", id4)
	}
	if _, leaked := readW16cHelperVault(t, vaultFile)[ppItemID]; leaked {
		t.Fatalf("host edit enc-key->password left old passphrase %q in vault", ppItemID)
	}
}

func testW16cIdentityEditCrossKindSwitches(t *testing.T) {
	store, vaultFile := setupW16cHelperStore(t)
	encKey := inventoryTestPrivateKey(t, true)

	mustExecRoot(t, "id-pw-1\n", "identity", "add", "id-roundtrip", "ops", "--password-stdin")
	cfg5, _ := store.Load()
	id5, _ := cfg5.Identities.Get("id-roundtrip")
	idPWItemID := id5.LoginPasswordRef.ItemID

	mustExecRoot(t, "key-password\n", "identity", "edit", "id-roundtrip", "--key", encKey, "--passphrase-stdin")
	cfg6, _ := store.Load()
	id6, _ := cfg6.Identities.Get("id-roundtrip")
	if id6.AuthType != "key" || id6.LoginPasswordRef != nil || id6.PassphraseRef == nil {
		t.Fatalf("identity edit password->enc-key mismatch: %+v", id6)
	}
	if _, leaked := readW16cHelperVault(t, vaultFile)[idPWItemID]; leaked {
		t.Fatalf("identity edit password->enc-key left old password %q in vault", idPWItemID)
	}
	idPPItemID := id6.PassphraseRef.ItemID

	mustExecRoot(t, "id-pw-2\n", "identity", "edit", "id-roundtrip", "--password-stdin")
	cfg7, _ := store.Load()
	id7, _ := cfg7.Identities.Get("id-roundtrip")
	if id7.AuthType != "password" || id7.KeyPath != "" || id7.KeyFingerprint != "" || id7.PassphraseRef != nil {
		t.Fatalf("identity edit enc-key->password left stale key fields: %+v", id7)
	}
	if _, leaked := readW16cHelperVault(t, vaultFile)[idPPItemID]; leaked {
		t.Fatalf("identity edit enc-key->password left old passphrase %q in vault", idPPItemID)
	}
}

func TestP7W16c_L4_16_M2_CredSetAndHostIdentityEditPreserveAutoAndHybrid(t *testing.T) {
	store, vaultFile := setupW16cHelperStore(t)
	encKey := inventoryTestPrivateKey(t, true)
	unencKey := inventoryTestPrivateKey(t, false)

	assertW16cAutoNodeCredSetAndHostEdit(t, store, vaultFile, encKey)
	for _, authType := range []string{"otp", "keyboard-interactive", "auto"} {
		assertW16cHybridIdentityEditPreservesAuthType(t, store, authType, unencKey, encKey)
	}
	if hostcmd.NewCmdInventoryEdit() == nil {
		t.Fatal("NewCmdInventoryEdit returned nil")
	}
}

func assertW16cAutoNodeCredSetAndHostEdit(t *testing.T, store config.Store, vaultFile, encKey string) {
	t.Helper()
	mustExecRoot(t, "", "host", "add", "ops@10.50.0.1:22", "--skip-verify")
	mustExecRoot(t, "auto-pw-1\n", "cred", "set", "ops@10.50.0.1:22", "--password", "--password-stdin")

	cfg1, _ := store.Load()
	n1, _ := cfg1.Nodes.Get("ops@10.50.0.1:22")
	id1, _ := cfg1.Identities.Get(n1.IdentityRef)
	if id1.AuthType != "auto" || id1.LoginPasswordRef == nil {
		t.Fatalf("cred set --password clobbered auto AuthType: %+v", id1)
	}

	mustExecRoot(t, "key-password\n", "host", "edit", "ops@10.50.0.1:22", "--key", encKey, "--passphrase-stdin")
	cfg2, _ := store.Load()
	id2, _ := cfg2.Identities.Get(n1.IdentityRef)
	if id2.AuthType != "auto" || id2.KeyPath != encKey || id2.PassphraseRef == nil || id2.KeyFingerprint == "" || id2.LoginPasswordRef == nil {
		t.Fatalf("host edit --key --passphrase-stdin clobbered auto hybrid state: %+v", id2)
	}
	ppItemID := id2.PassphraseRef.ItemID

	mustExecRoot(t, "auto-pw-2\n", "cred", "set", "ops@10.50.0.1:22", "--password", "--password-stdin")
	cfg3, _ := store.Load()
	id3, _ := cfg3.Identities.Get(n1.IdentityRef)
	if id3.AuthType != "auto" || id3.KeyPath != encKey || id3.KeyFingerprint == "" || id3.PassphraseRef == nil || id3.PassphraseRef.ItemID != ppItemID {
		t.Fatalf("cred set --password on auto node clobbered key material: %+v", id3)
	}
	if readW16cHelperVault(t, vaultFile)[ppItemID] != "key-password" {
		t.Fatalf("cred set --password on auto node deleted passphrase from vault")
	}

	mustExecRoot(t, "", "cred", "delete", "ops@10.50.0.1:22", "--passphrase")
	cfg4, _ := store.Load()
	id4, _ := cfg4.Identities.Get(n1.IdentityRef)
	if id4.AuthType != "auto" || id4.PassphraseRef != nil || id4.KeyFingerprint != "" || id4.LoginPasswordRef == nil {
		t.Fatalf("cred delete --passphrase corrupted auto node: %+v", id4)
	}
}

func assertW16cHybridIdentityEditPreservesAuthType(t *testing.T, store config.Store, authType, unencKey, encKey string) {
	t.Helper()
	idName := "id-" + authType
	cfgCur, _ := store.Load()
	cfgCur.Identities.Set(idName, models.Identity{User: "ops", AuthType: authType})
	if err := store.Save(cfgCur); err != nil {
		t.Fatalf("seed %s: %v", idName, err)
	}
	mustExecRoot(t, "hybrid-pw\n", "cred", "set", idName, "--password", "--password-stdin")
	mustExecRoot(t, "", "identity", "edit", idName, "--key", unencKey)
	cfgAfterUnenc, _ := store.Load()
	gotUnenc, _ := cfgAfterUnenc.Identities.Get(idName)
	if gotUnenc.AuthType != authType || gotUnenc.KeyPath != unencKey || gotUnenc.LoginPasswordRef == nil {
		t.Fatalf("identity edit --key (unenc) on %s: %+v", authType, gotUnenc)
	}

	mustExecRoot(t, "key-password\n", "identity", "edit", idName, "--key", encKey, "--passphrase-stdin")
	cfgAfterEnc, _ := store.Load()
	gotEnc, _ := cfgAfterEnc.Identities.Get(idName)
	if gotEnc.AuthType != authType || gotEnc.KeyPath != encKey || gotEnc.PassphraseRef == nil || gotEnc.KeyFingerprint == "" || gotEnc.LoginPasswordRef == nil {
		t.Fatalf("identity edit --key --passphrase-stdin on %s: %+v", authType, gotEnc)
	}
}
