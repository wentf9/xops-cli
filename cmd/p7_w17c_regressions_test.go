package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	hostcmd "github.com/wentf9/xops-cli/cmd/host"
	"github.com/wentf9/xops-cli/cmd/utils"
	coreauth "github.com/wentf9/xops-cli/core/auth"
	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/internal/credentialfile"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestP7W17c_L4_17_M1_HostAndIdentityEditPasswordStdinPreservesHybridAuthAndPassphrase(t *testing.T) {
	store, vaultFile := setupW16cHelperStore(t)
	encKey := inventoryTestPrivateKey(t, true)

	for _, authType := range []string{"auto", "otp", "keyboard-interactive"} {
		t.Run("host_edit_"+authType, func(t *testing.T) {
			assertW17cHostEditHybridPassword(t, store, vaultFile, encKey, authType)
		})
		t.Run("identity_edit_"+authType, func(t *testing.T) {
			assertW17cIdentityEditHybridPassword(t, store, vaultFile, encKey, authType)
		})
	}
}

func assertW17cHostEditHybridPassword(t *testing.T, store config.Store, vaultFile, encKey, authType string) {
	t.Helper()
	nodeID := "ops@10.81.0.1:22"
	idName := "id-host-" + authType
	hostRef := "10.81.0.1:22"

	cfgCur, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	cfgCur.Hosts.Set(hostRef, models.Host{Address: "10.81.0.1", Port: 22})
	cfgCur.Identities.Set(idName, models.Identity{User: "ops", AuthType: authType})
	cfgCur.Nodes.Set(nodeID, models.Node{HostRef: hostRef, IdentityRef: idName, SudoMode: models.SudoModeAuto})
	if err := store.Save(cfgCur); err != nil {
		t.Fatalf("store.Save seed: %v", err)
	}

	mustExecRoot(t, "key-password\n", "host", "edit", nodeID, "--key", encKey, "--passphrase-stdin")
	mustExecRoot(t, "pw-initial\n", "host", "edit", nodeID, "--password-stdin")

	cfg1, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load after initial pw: %v", err)
	}
	ident1, _ := cfg1.Identities.Get(idName)
	assertW17cHybridIdentityRefs(t, ident1, authType, encKey)
	ppItemID := ident1.PassphraseRef.ItemID
	oldPWItemID := ident1.LoginPasswordRef.ItemID
	vault1 := readW16cHelperVault(t, vaultFile)
	if vault1[ppItemID] != "key-password" || vault1[oldPWItemID] != "pw-initial" {
		t.Fatalf("vault after initial hybrid password = %v", vault1)
	}

	mustExecRoot(t, "pw-rotated\n", "host", "edit", nodeID, "--password-stdin")

	cfg2, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load after rotate: %v", err)
	}
	ident2, _ := cfg2.Identities.Get(idName)
	assertW17cHybridIdentityRefs(t, ident2, authType, encKey)
	if ident2.KeyFingerprint != ident1.KeyFingerprint || ident2.PassphraseRef.ItemID != ppItemID {
		t.Fatalf("host edit --password-stdin rotate changed passphrase binding: %+v", ident2)
	}
	vault2 := readW16cHelperVault(t, vaultFile)
	if vault2[ppItemID] != "key-password" {
		t.Fatalf("host edit --password-stdin deleted passphrase %q from vault: %v", ppItemID, vault2)
	}
	if _, leaked := vault2[oldPWItemID]; leaked {
		t.Fatalf("old password %q was not cleaned up from vault: %v", oldPWItemID, vault2)
	}
	if vault2[ident2.LoginPasswordRef.ItemID] != "pw-rotated" {
		t.Fatalf("rotated password missing from vault: %v", vault2)
	}
}

func assertW17cIdentityEditHybridPassword(t *testing.T, store config.Store, vaultFile, encKey, authType string) {
	t.Helper()
	idName := "id-standalone-" + authType
	cfgCur, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	cfgCur.Identities.Set(idName, models.Identity{User: "ops", AuthType: authType})
	if err := store.Save(cfgCur); err != nil {
		t.Fatalf("store.Save seed: %v", err)
	}

	mustExecRoot(t, "key-password\n", "identity", "edit", idName, "--key", encKey, "--passphrase-stdin")
	mustExecRoot(t, "id-pw-1\n", "identity", "edit", idName, "--password-stdin")

	cfg1, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	ident1, _ := cfg1.Identities.Get(idName)
	assertW17cHybridIdentityRefs(t, ident1, authType, encKey)
	vault := readW16cHelperVault(t, vaultFile)
	if vault[ident1.PassphraseRef.ItemID] != "key-password" || vault[ident1.LoginPasswordRef.ItemID] != "id-pw-1" {
		t.Fatalf("vault mismatch for hybrid identity %q: %v", authType, vault)
	}
}

func assertW17cHybridIdentityRefs(t *testing.T, ident models.Identity, authType, encKey string) {
	t.Helper()
	if ident.AuthType != authType || ident.KeyPath != encKey || ident.KeyFingerprint == "" ||
		ident.PassphraseRef == nil || ident.LoginPasswordRef == nil {
		t.Fatalf("hybrid %q identity state clobbered: %+v", authType, ident)
	}
}

func setupW17cLockedEncryptedFileVault(t *testing.T) (string, config.Store, func()) {
	t.Helper()
	rawDir := t.TempDir()
	physicalDir, err := filepath.EvalSymlinks(rawDir)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	cfgDir := filepath.Join(physicalDir, "cfg")
	homeDir := filepath.Join(physicalDir, "home")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatalf("MkdirAll cfgDir: %v", err)
	}
	if err := os.MkdirAll(homeDir, 0o700); err != nil {
		t.Fatalf("MkdirAll homeDir: %v", err)
	}
	t.Setenv("XOPS_CONFIG_DIR", cfgDir)
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)
	t.Setenv("SSH_AUTH_SOCK", "")

	cfgPath, keyPath, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatalf("GetConfigFilePath: %v", err)
	}
	store := config.NewDefaultStore(cfgPath, keyPath)
	vaultPath := filepath.Join(cfgDir, "locked-vault")
	vaultKeyPath := filepath.Join(cfgDir, "vault.key")
	realKey := bytes.Repeat([]byte{0x2a}, 32)
	wrongKey := bytes.Repeat([]byte{0x63}, 32)
	if err := os.WriteFile(vaultKeyPath, realKey, 0o600); err != nil {
		t.Fatalf("WriteFile vault key: %v", err)
	}

	cfg := &config.Configuration{
		SchemaVersion: 2,
		Nodes:         concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:         concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities:    concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Credential: &config.CredentialConfig{
			DefaultStore: "offline",
			Stores: map[string]config.StoreConfig{
				"offline": {
					Type:           config.StoreTypeEncryptedFile,
					Path:           vaultPath,
					Unlock:         "key-file",
					KeyFile:        vaultKeyPath,
					NonInteractive: true,
				},
			},
		},
	}
	owner := config.NewEncryptedRuntime(t.Context(), cfgPath, nil)
	detach, err := utils.InstallCredentialRuntime(owner)
	if err != nil {
		t.Fatalf("InstallCredentialRuntime: %v", err)
	}
	t.Cleanup(func() {
		detach()
		if closeErr := owner.Close(); closeErr != nil {
			t.Errorf("owner.Close: %v", closeErr)
		}
	})
	if _, err := owner.Vaults().Init(t.Context(), vaultPath, "offline", credentialfile.Wrapping{
		Mode:    "key-file",
		KeyFile: vaultKeyPath,
	}); err != nil {
		if errors.Is(err, credentialfile.ErrUnsupported) {
			t.Skipf("encrypted-file vault unsupported on this platform: %v", err)
		}
		t.Fatalf("Vaults().Init: %v", err)
	}
	if err := owner.Lock(t.Context()); err != nil {
		t.Fatalf("owner.Lock: %v", err)
	}
	if err := os.WriteFile(vaultKeyPath, wrongKey, 0o600); err != nil {
		t.Fatalf("WriteFile wrong vault key: %v", err)
	}
	if err := store.Save(cfg); err != nil {
		t.Fatalf("store.Save: %v", err)
	}
	unlock := func() {
		t.Helper()
		if err := os.WriteFile(vaultKeyPath, realKey, 0o600); err != nil {
			t.Fatalf("restore vault key: %v", err)
		}
	}
	return cfgPath, store, unlock
}

func TestP7W17c_L4_17_M3_HostAddAndIdentityAddAtomicOnLockedEncryptedFileVault(t *testing.T) {
	encKey := inventoryTestPrivateKey(t, true)

	t.Run("real_locked_encrypted_file_vault_leaves_config_untouched_and_retries_after_unlock", func(t *testing.T) {
		assertW17cRealEncryptedFileVaultAtomicAdds(t, encKey)
	})
	t.Run("locked_then_unlocked_retry_succeeds_without_already_exists", func(t *testing.T) {
		assertW17cHelperVaultAtomicAddsAndRetry(t, encKey)
	})
}

type w17cAddCase struct {
	name string
	cmd  func() error
}

func w17cAddCases(t *testing.T, encKey, ipPrefix, idPrefix string) []w17cAddCase {
	t.Helper()
	return []w17cAddCase{
		{
			name: "host_add_password",
			cmd: func() error {
				return executePhase6WithInput(t, hostcmd.NewCmdInventoryAdd(), "host-pw\n",
					"ops@"+ipPrefix+".1:22", "--password-stdin", "--skip-verify")
			},
		},
		{
			name: "host_add_encrypted_key",
			cmd: func() error {
				return executePhase6WithInput(t, hostcmd.NewCmdInventoryAdd(), "key-password\n",
					"ops@"+ipPrefix+".2:22", "--key", encKey, "--passphrase-stdin", "--skip-verify")
			},
		},
		{
			name: "identity_add_password",
			cmd: func() error {
				return executePhase6WithInput(t, NewCmdIdentity(), "id-pw\n",
					"add", idPrefix+"-pw", "ops", "--password-stdin")
			},
		},
		{
			name: "identity_add_encrypted_key",
			cmd: func() error {
				return executePhase6WithInput(t, NewCmdIdentity(), "key-password\n",
					"add", idPrefix+"-key", "ops", "--key", encKey, "--passphrase-stdin")
			},
		},
	}
}

func assertW17cLockedCasesLeaveConfigUntouched(t *testing.T, cfgPath string, store config.Store, before []byte, cases []w17cAddCase) {
	t.Helper()
	for _, tc := range cases {
		err := tc.cmd()
		if !errors.Is(err, coreauth.ErrCredentialStoreLocked) {
			t.Fatalf("%s on locked vault: err = %v, want ErrCredentialStoreLocked", tc.name, err)
		}
		after, readErr := os.ReadFile(cfgPath)
		if readErr != nil {
			t.Fatalf("ReadFile after %s: %v", tc.name, readErr)
		}
		if !bytes.Equal(before, after) {
			t.Fatalf("%s modified config.yaml despite locked vault", tc.name)
		}
		loaded, loadErr := store.Load()
		if loadErr != nil {
			t.Fatalf("store.Load after %s: %v", tc.name, loadErr)
		}
		if loaded.Nodes.Count() != 0 || loaded.Hosts.Count() != 0 || loaded.Identities.Count() != 0 {
			t.Fatalf("%s left partial inventory on disk: nodes=%d hosts=%d ids=%d",
				tc.name, loaded.Nodes.Count(), loaded.Hosts.Count(), loaded.Identities.Count())
		}
	}
}

func assertW17cRealEncryptedFileVaultAtomicAdds(t *testing.T, encKey string) {
	t.Helper()
	cfgPath, store, unlock := setupW17cLockedEncryptedFileVault(t)
	before, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("ReadFile before: %v", err)
	}
	cases := w17cAddCases(t, encKey, "10.82.0", "locked-id")
	assertW17cLockedCasesLeaveConfigUntouched(t, cfgPath, store, before, cases)

	unlock()
	for _, tc := range cases {
		if err := tc.cmd(); err != nil {
			t.Fatalf("unlocked retry %s failed: %v", tc.name, err)
		}
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load after unlock: %v", err)
	}
	if loaded.Nodes.Count() != 2 {
		t.Fatalf("expected 2 nodes after unlocked retries, got %d", loaded.Nodes.Count())
	}
	if _, ok := loaded.Identities.Get("locked-id-pw"); !ok {
		t.Fatal("locked-id-pw missing after unlocked retry")
	}
	if _, ok := loaded.Identities.Get("locked-id-key"); !ok {
		t.Fatal("locked-id-key missing after unlocked retry")
	}
}

func assertW17cHelperVaultAtomicAddsAndRetry(t *testing.T, encKey string) {
	t.Helper()
	store, vaultFile := setupW16cHelperStore(t)
	cfgPath, _, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatalf("GetConfigFilePath: %v", err)
	}
	before, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("ReadFile before: %v", err)
	}
	cases := w17cAddCases(t, encKey, "10.83.0", "retry-id")

	t.Setenv("TEST_HELPER_ERROR_CODE", "locked")
	assertW17cLockedCasesLeaveConfigUntouched(t, cfgPath, store, before, cases)

	t.Setenv("TEST_HELPER_ERROR_CODE", "")
	for _, tc := range cases {
		if err := tc.cmd(); err != nil {
			t.Fatalf("unlocked retry %s failed: %v", tc.name, err)
		}
	}
	assertW17cHelperUnlockedState(t, store, vaultFile)
}

func assertW17cHelperUnlockedState(t *testing.T, store config.Store, vaultFile string) {
	t.Helper()
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load after unlocked retries: %v", err)
	}
	vault := readW16cHelperVault(t, vaultFile)

	n1, ok := loaded.Nodes.Get("ops@10.83.0.1:22")
	if !ok {
		t.Fatal("ops@10.83.0.1:22 missing")
	}
	id1, _ := loaded.Identities.Get(n1.IdentityRef)
	if id1.LoginPasswordRef == nil || vault[id1.LoginPasswordRef.ItemID] != "host-pw" {
		t.Fatalf("ops@10.83.0.1:22 credential mismatch: %+v", id1)
	}

	n2, ok := loaded.Nodes.Get("ops@10.83.0.2:22")
	if !ok {
		t.Fatal("ops@10.83.0.2:22 missing")
	}
	id2, _ := loaded.Identities.Get(n2.IdentityRef)
	if id2.PassphraseRef == nil || id2.KeyFingerprint == "" || vault[id2.PassphraseRef.ItemID] != "key-password" {
		t.Fatalf("ops@10.83.0.2:22 credential mismatch: %+v", id2)
	}

	idPW, ok := loaded.Identities.Get("retry-id-pw")
	if !ok || idPW.LoginPasswordRef == nil || vault[idPW.LoginPasswordRef.ItemID] != "id-pw" {
		t.Fatalf("retry-id-pw mismatch: (%+v, %v)", idPW, ok)
	}
	idKey, ok := loaded.Identities.Get("retry-id-key")
	if !ok || idKey.PassphraseRef == nil || idKey.KeyFingerprint == "" || vault[idKey.PassphraseRef.ItemID] != "key-password" {
		t.Fatalf("retry-id-key mismatch: (%+v, %v)", idKey, ok)
	}
}
