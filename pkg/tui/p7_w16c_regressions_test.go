package tui

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	coreauth "github.com/wentf9/xops-cli/core/auth"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
	sshcrypto "golang.org/x/crypto/ssh"
)

func newW16cDiskTUIEnv(t *testing.T, defaultStore string) (*config.Repository, config.Store, *memoryCredentialStore, *credential.Service) {
	t.Helper()
	dir := t.TempDir()
	diskStore := config.NewDefaultStore(filepath.Join(dir, "xops_config.yaml"), filepath.Join(dir, "secret.key"))
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.SchemaVersion = 2
	if defaultStore == "" {
		defaultStore = "mem"
	}
	stores := map[string]config.StoreConfig{
		"none": {Type: config.StoreTypeNone},
		"mem":  {Type: config.StoreTypeHelper, Command: "/unused-helper"},
	}
	cfg.Credential = &config.CredentialConfig{
		DefaultStore: defaultStore,
		Stores:       stores,
	}
	if err := diskStore.Save(cfg); err != nil {
		t.Fatalf("diskStore.Save: %v", err)
	}
	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, diskStore)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	memStore := newMemoryCredentialStore()
	svc := newFormCredentialTestService(t, repo, memStore)
	return repo, diskStore, memStore, svc
}

func writeW16cTestKey(t *testing.T, passphrase string) (string, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	var block *pem.Block
	if passphrase != "" {
		block, err = sshcrypto.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	} else {
		block, err = sshcrypto.MarshalPrivateKey(priv, "")
	}
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("WriteFile key: %v", err)
	}
	fp := ""
	if passphrase != "" {
		fp, err = config.PrivateKeyFingerprint(path, []byte(passphrase))
		if err != nil {
			t.Fatalf("PrivateKeyFingerprint: %v", err)
		}
	}
	return path, fp
}

func runFormMutationExpectSuccess(t *testing.T, m *Model) {
	t.Helper()
	cmd := m.saveFormCmd()
	if cmd == nil {
		t.Fatalf("saveFormCmd() returned nil (status=%q)", m.status)
	}
	msg := cmd()
	mutMsg, ok := msg.(configurationMutationMsg)
	if !ok {
		t.Fatalf("cmd() = %T, want configurationMutationMsg", msg)
	}
	if mutMsg.err != nil {
		t.Fatalf("form save failed unexpectedly: %v", mutMsg.err)
	}
	m.Update(mutMsg)
}

func runFormMutationExpectError(t *testing.T, m *Model) error {
	t.Helper()
	cmd := m.saveFormCmd()
	if cmd == nil {
		t.Fatalf("saveFormCmd() returned nil, expected async error (status=%q)", m.status)
	}
	msg := cmd()
	mutMsg, ok := msg.(configurationMutationMsg)
	if !ok {
		t.Fatalf("cmd() = %T, want configurationMutationMsg", msg)
	}
	if mutMsg.err == nil {
		t.Fatalf("expected form save error, got nil")
	}
	m.Update(mutMsg)
	return mutMsg.err
}

func TestP7W16c_L4_16_H1_TUIEditCrossKindSwitchAndVaultCleanupOnRealDisk(t *testing.T) {
	t.Run("encrypted_key_to_password_with_new_password_and_metadata_on_real_disk", testW16cTUIEditEncryptedKeyToPassword)
	t.Run("hybrid_auto_to_password_with_new_password_on_real_disk", testW16cTUIEditHybridAutoToPassword)
	t.Run("password_to_key_unencrypted_cleans_login_password_on_real_disk", func(t *testing.T) {
		testW16cTUIEditPasswordToKey(t, false)
	})
	t.Run("password_to_key_encrypted_cleans_login_password_on_real_disk", func(t *testing.T) {
		testW16cTUIEditPasswordToKey(t, true)
	})
}

func testW16cTUIEditEncryptedKeyToPassword(t *testing.T) {
	repo, diskStore, memStore, svc := newW16cDiskTUIEnv(t, "mem")
	keyPath, keyFP := writeW16cTestKey(t, "old-key-pass")
	passRef := credential.Ref{StoreID: "mem", ItemID: "pp-orig"}
	_ = memStore.Put(t.Context(), passRef, credential.NewSecret([]byte("old-key-pass")))

	if _, err := repo.CreateNodeContext(t.Context(), "ops@10.10.0.1:22",
		models.Node{HostRef: "10.10.0.1:22", IdentityRef: "ops@10.10.0.1", SudoMode: models.SudoModeAuto},
		models.Host{Address: "10.10.0.1", Port: 22},
		models.Identity{User: "ops", AuthType: "key", KeyPath: keyPath, KeyFingerprint: keyFP, PassphraseRef: passRef.Clone()},
	); err != nil {
		t.Fatalf("CreateNodeContext: %v", err)
	}

	m := &Model{repository: repo, credentialService: svc, state: viewForm}
	state, err := m.newNodeFormState("ops@10.10.0.1:22")
	if err != nil {
		t.Fatalf("newNodeFormState: %v", err)
	}
	state.port = "2222"
	state.alias = "web-switched"
	state.tags = "prod,switched"
	state.authType = "password"
	state.password = "brand-new-pw"
	state.passwordAction = "replace"
	m.formState = state

	runFormMutationExpectSuccess(t, m)

	diskCfg, err := diskStore.Load()
	if err != nil {
		t.Fatalf("diskStore.Load: %v", err)
	}
	node, ok := diskCfg.Nodes.Get("ops@10.10.0.1:2222")
	if !ok {
		t.Fatal("renamed node ops@10.10.0.1:2222 missing on disk")
	}
	ident, _ := diskCfg.Identities.Get(node.IdentityRef)
	if ident.AuthType != "password" || ident.KeyPath != "" || ident.KeyFingerprint != "" || ident.PassphraseRef != nil {
		t.Fatalf("stale key fields survived switch to password: %+v", ident)
	}
	if ident.LoginPasswordRef == nil {
		t.Fatal("LoginPasswordRef missing after switch to password")
	}
	gotPW, err := memStore.Get(t.Context(), *ident.LoginPasswordRef)
	if err != nil || string(gotPW.Value) != "brand-new-pw" {
		t.Fatalf("stored password = (%q, %v), want brand-new-pw", string(gotPW.Value), err)
	}
	if _, err := memStore.Get(t.Context(), passRef); !errors.Is(err, coreauth.ErrCredentialNotFound) {
		t.Fatalf("displaced PassphraseRef still in vault: %v", err)
	}
}

func testW16cTUIEditHybridAutoToPassword(t *testing.T) {
	repo, diskStore, memStore, svc := newW16cDiskTUIEnv(t, "mem")
	keyPath, keyFP := writeW16cTestKey(t, "hybrid-pass")
	oldPW := credential.Ref{StoreID: "mem", ItemID: "pw-hybrid"}
	oldPP := credential.Ref{StoreID: "mem", ItemID: "pp-hybrid"}
	_ = memStore.Put(t.Context(), oldPW, credential.NewSecret([]byte("old-pw")))
	_ = memStore.Put(t.Context(), oldPP, credential.NewSecret([]byte("hybrid-pass")))

	if _, err := repo.CreateNodeContext(t.Context(), "ops@10.10.0.2:22",
		models.Node{HostRef: "10.10.0.2:22", IdentityRef: "ops@10.10.0.2", SudoMode: models.SudoModeAuto},
		models.Host{Address: "10.10.0.2", Port: 22},
		models.Identity{
			User:             "ops",
			AuthType:         "auto",
			KeyPath:          keyPath,
			KeyFingerprint:   keyFP,
			LoginPasswordRef: oldPW.Clone(),
			PassphraseRef:    oldPP.Clone(),
		},
	); err != nil {
		t.Fatalf("CreateNodeContext: %v", err)
	}

	m := &Model{repository: repo, credentialService: svc, state: viewForm}
	state, err := m.newNodeFormState("ops@10.10.0.2:22")
	if err != nil {
		t.Fatalf("newNodeFormState: %v", err)
	}
	state.authType = "password"
	state.password = "rotated-pw"
	state.passwordAction = "replace"
	m.formState = state

	runFormMutationExpectSuccess(t, m)

	diskCfg, err := diskStore.Load()
	if err != nil {
		t.Fatalf("diskStore.Load: %v", err)
	}
	node, _ := diskCfg.Nodes.Get("ops@10.10.0.2:22")
	ident, _ := diskCfg.Identities.Get(node.IdentityRef)
	if ident.AuthType != "password" || ident.KeyPath != "" || ident.KeyFingerprint != "" || ident.PassphraseRef != nil {
		t.Fatalf("stale key fields after auto -> password: %+v", ident)
	}
	if _, err := memStore.Get(t.Context(), oldPW); !errors.Is(err, coreauth.ErrCredentialNotFound) {
		t.Fatalf("old password ref still in vault: %v", err)
	}
	if _, err := memStore.Get(t.Context(), oldPP); !errors.Is(err, coreauth.ErrCredentialNotFound) {
		t.Fatalf("old passphrase ref still in vault: %v", err)
	}
}

func testW16cTUIEditPasswordToKey(t *testing.T, encrypted bool) {
	t.Helper()
	repo, diskStore, memStore, svc := newW16cDiskTUIEnv(t, "mem")
	oldPW := credential.Ref{StoreID: "mem", ItemID: "pw-before-key"}
	_ = memStore.Put(t.Context(), oldPW, credential.NewSecret([]byte("old-login-pw")))
	if _, err := repo.CreateNodeContext(t.Context(), "ops@10.10.0.3:22",
		models.Node{HostRef: "10.10.0.3:22", IdentityRef: "ops@10.10.0.3", SudoMode: models.SudoModeAuto},
		models.Host{Address: "10.10.0.3", Port: 22},
		models.Identity{User: "ops", AuthType: "password", LoginPasswordRef: oldPW.Clone()},
	); err != nil {
		t.Fatalf("CreateNodeContext: %v", err)
	}

	pass := ""
	if encrypted {
		pass = "enc-pass"
	}
	keyPath, wantFP := writeW16cTestKey(t, pass)

	m := &Model{repository: repo, credentialService: svc, state: viewForm}
	state, err := m.newNodeFormState("ops@10.10.0.3:22")
	if err != nil {
		t.Fatalf("newNodeFormState: %v", err)
	}
	state.authType = "key"
	state.keyPath = keyPath
	if encrypted {
		state.passphrase = pass
		state.passphraseAction = "replace"
	}
	m.formState = state

	runFormMutationExpectSuccess(t, m)

	diskCfg, err := diskStore.Load()
	if err != nil {
		t.Fatalf("diskStore.Load: %v", err)
	}
	node, _ := diskCfg.Nodes.Get("ops@10.10.0.3:22")
	ident, _ := diskCfg.Identities.Get(node.IdentityRef)
	if ident.AuthType != "key" || ident.KeyPath != keyPath || ident.LoginPasswordRef != nil || ident.Password != "" {
		t.Fatalf("unexpected identity after password -> key: %+v", ident)
	}
	if encrypted && (ident.PassphraseRef == nil || ident.KeyFingerprint != wantFP) {
		t.Fatalf("encrypted key binding mismatch: %+v", ident)
	}
	if !encrypted && (ident.PassphraseRef != nil || ident.KeyFingerprint != "") {
		t.Fatalf("unencrypted key unexpectedly set passphrase/fingerprint: %+v", ident)
	}
	if _, err := memStore.Get(t.Context(), oldPW); !errors.Is(err, coreauth.ErrCredentialNotFound) {
		t.Fatalf("displaced LoginPasswordRef still in vault: %v", err)
	}
}

func TestP7W16c_L4_16_M1_TUICreateAtomicValidationAndRetryPreservesInput(t *testing.T) {
	t.Run("wrong_passphrase_creates_no_node_and_retry_succeeds", testW16cTUICreateWrongPassphraseRetry)
	t.Run("template_key_with_passphrase_rejected_before_create", testW16cTUICreateTemplateKeyRejected)
	t.Run("none_default_store_and_nil_service_rejected_before_create", testW16cTUICreateStoreRejected)
	t.Run("locked_store_put_failure_rolls_back_node_and_retry_succeeds", testW16cTUICreateLockedStoreRollback)
	t.Run("dual_secret_second_put_failure_rolls_back_node_and_first_secret", testW16cTUICreateDualSecretRollback)
}

func testW16cTUICreateWrongPassphraseRetry(t *testing.T) {
	repo, diskStore, memStore, svc := newW16cDiskTUIEnv(t, "mem")
	keyPath, wantFP := writeW16cTestKey(t, "correct-passphrase")

	m := &Model{
		repository:        repo,
		credentialService: svc,
		state:             viewForm,
		formState: &nodeFormState{
			isEdit:           false,
			skipVerify:       true,
			alias:            "prod-web",
			user:             "ops",
			address:          "10.20.0.1",
			port:             "2222",
			authType:         "key",
			keyPath:          keyPath,
			passphrase:       "wrong-passphrase",
			passphraseAction: "replace",
			sudoMode:         string(models.SudoModeAuto),
			tags:             "web,prod",
		},
	}

	err := runFormMutationExpectError(t, m)
	if errors.Is(err, config.ErrConfigConflict) {
		t.Fatalf("unexpected ErrConfigConflict on wrong passphrase: %v", err)
	}
	if m.state != viewForm || m.formConflict {
		t.Fatalf("form state after wrong passphrase: state=%v conflict=%v, want viewForm without conflict lock", m.state, m.formConflict)
	}
	if m.formState == nil || m.formState.alias != "prod-web" || m.formState.tags != "web,prod" {
		t.Fatalf("form draft lost after create failure: %+v", m.formState)
	}
	diskCfg, err := diskStore.Load()
	if err != nil {
		t.Fatalf("diskStore.Load: %v", err)
	}
	if diskCfg.Nodes.Count() != 0 {
		t.Fatalf("broken half-created node leaked to disk: count=%d", diskCfg.Nodes.Count())
	}

	m.formState.passphrase = "correct-passphrase"
	runFormMutationExpectSuccess(t, m)

	diskCfg, err = diskStore.Load()
	if err != nil {
		t.Fatalf("diskStore.Load after retry: %v", err)
	}
	node, ok := diskCfg.Nodes.Get("ops@10.20.0.1:2222")
	if !ok {
		t.Fatal("retried node missing on disk")
	}
	ident, _ := diskCfg.Identities.Get(node.IdentityRef)
	if ident.PassphraseRef == nil || ident.KeyFingerprint != wantFP {
		t.Fatalf("retried node missing passphrase binding: %+v", ident)
	}
	sec, err := memStore.Get(t.Context(), *ident.PassphraseRef)
	if err != nil || string(sec.Value) != "correct-passphrase" {
		t.Fatalf("stored passphrase = (%q, %v), want correct-passphrase", string(sec.Value), err)
	}
}

func testW16cTUICreateTemplateKeyRejected(t *testing.T) {
	repo, diskStore, _, svc := newW16cDiskTUIEnv(t, "mem")
	m := &Model{
		repository:        repo,
		credentialService: svc,
		state:             viewForm,
		formState: &nodeFormState{
			isEdit:           false,
			skipVerify:       true,
			user:             "ops",
			address:          "10.20.0.2",
			port:             "22",
			authType:         "key",
			keyPath:          "%d/.ssh/id_ed25519",
			passphrase:       "secret",
			passphraseAction: "replace",
			sudoMode:         string(models.SudoModeAuto),
		},
	}
	_ = runFormMutationExpectError(t, m)
	diskCfg, _ := diskStore.Load()
	if diskCfg.Nodes.Count() != 0 {
		t.Fatalf("template key + passphrase leaked node onto disk")
	}
}

func testW16cTUICreateStoreRejected(t *testing.T) {
	repoNone, diskNone, _, svcNone := newW16cDiskTUIEnv(t, "none")
	mNone := &Model{
		repository:        repoNone,
		credentialService: svcNone,
		state:             viewForm,
		formState: &nodeFormState{
			isEdit:         false,
			skipVerify:     true,
			user:           "ops",
			address:        "10.20.0.3",
			port:           "22",
			authType:       "password",
			password:       "pw-secret",
			passwordAction: "replace",
			sudoMode:       string(models.SudoModeAuto),
		},
	}
	err := runFormMutationExpectError(t, mNone)
	if !errors.Is(err, credential.ErrCredentialStoreReadOnly) {
		t.Fatalf("defaultStore=none error = %v, want ErrCredentialStoreReadOnly", err)
	}
	if diskCfg, _ := diskNone.Load(); diskCfg.Nodes.Count() != 0 {
		t.Fatalf("defaultStore=none leaked node onto disk")
	}

	repoNil, diskNil, _, _ := newW16cDiskTUIEnv(t, "mem")
	mNil := &Model{
		repository:        repoNil,
		credentialService: nil,
		state:             viewForm,
		formState: &nodeFormState{
			isEdit:         false,
			skipVerify:     true,
			user:           "ops",
			address:        "10.20.0.4",
			port:           "22",
			authType:       "password",
			password:       "pw-secret",
			passwordAction: "replace",
			sudoMode:       string(models.SudoModeAuto),
		},
	}
	_ = runFormMutationExpectError(t, mNil)
	if diskCfg, _ := diskNil.Load(); diskCfg.Nodes.Count() != 0 {
		t.Fatalf("nil credentialService leaked node onto disk")
	}
}

func testW16cTUICreateLockedStoreRollback(t *testing.T) {
	repo, diskStore, _, _ := newW16cDiskTUIEnv(t, "mem")
	flakyStore := &failingCredentialStore{memoryCredentialStore: newMemoryCredentialStore(), failPut: true}
	svc := newFormCredentialTestService(t, repo, flakyStore)
	m := &Model{
		repository:        repo,
		credentialService: svc,
		state:             viewForm,
		formState: &nodeFormState{
			isEdit:         false,
			skipVerify:     true,
			alias:          "retry-node",
			user:           "ops",
			address:        "10.20.0.5",
			port:           "22",
			authType:       "password",
			password:       "pw-secret",
			passwordAction: "replace",
			sudoMode:       string(models.SudoModeAuto),
		},
	}
	_ = runFormMutationExpectError(t, m)
	if diskCfg, _ := diskStore.Load(); diskCfg.Nodes.Count() != 0 {
		t.Fatalf("locked store failure left half-created node on disk")
	}
	if m.formConflict || m.formState.alias != "retry-node" {
		t.Fatalf("form state corrupted after rollback: conflict=%v state=%+v", m.formConflict, m.formState)
	}

	flakyStore.failPut = false
	runFormMutationExpectSuccess(t, m)
	if diskCfg, _ := diskStore.Load(); diskCfg.Nodes.Count() != 1 {
		t.Fatalf("retry after unlock failed to create node")
	}
}

func testW16cTUICreateDualSecretRollback(t *testing.T) {
	repo, diskStore, _, _ := newW16cDiskTUIEnv(t, "mem")
	keyPath, _ := writeW16cTestKey(t, "dual-pass")
	putCalls := 0
	mem := newMemoryCredentialStore()
	flakyStore := &failingCredentialStore{
		memoryCredentialStore: mem,
		onPut: func() error {
			putCalls++
			if putCalls == 2 {
				return coreauth.ErrCredentialStoreLocked
			}
			return nil
		},
	}
	svc := newFormCredentialTestService(t, repo, flakyStore)
	m := &Model{
		repository:        repo,
		credentialService: svc,
		state:             viewForm,
		formState: &nodeFormState{
			isEdit:           false,
			skipVerify:       true,
			user:             "ops",
			address:          "10.20.0.6",
			port:             "22",
			authType:         "auto",
			password:         "first-pw",
			passwordAction:   "replace",
			keyPath:          keyPath,
			passphrase:       "dual-pass",
			passphraseAction: "replace",
			sudoMode:         string(models.SudoModeAuto),
		},
	}
	_ = runFormMutationExpectError(t, m)
	if diskCfg, _ := diskStore.Load(); diskCfg.Nodes.Count() != 0 {
		t.Fatalf("dual-secret partial failure left half-created node on disk")
	}
	if len(mem.data) != 0 {
		t.Fatalf("dual-secret rollback leaked first secret in vault: %d entries", len(mem.data))
	}
}

func TestP7W16c_L4_16_M1_TUIKeyEditClearsOrUnlinksStalePassphraseAndFingerprint(t *testing.T) {
	t.Run("clear_keypath_to_empty", func(t *testing.T) {
		testW16cTUIClearKeyPath(t, "")
	})
	t.Run("clear_keypath_to_none", func(t *testing.T) {
		testW16cTUIClearKeyPath(t, "none")
	})
	t.Run("change_keypath_with_keep_unlinks_stale_passphrase_and_fingerprint", testW16cTUIChangeKeyPathWithKeep)
	t.Run("tag_only_edit_with_tilde_keypath_preserves_passphrase_binding", testW16cTUITagOnlyEditWithTildeKeyPath)
}

func testW16cTUIClearKeyPath(t *testing.T, targetKeyPath string) {
	t.Helper()
	repo, diskStore, memStore, svc := newW16cDiskTUIEnv(t, "mem")
	key1, fp1 := writeW16cTestKey(t, "pass-1")
	pwRef := credential.Ref{StoreID: "mem", ItemID: "pw-keep"}
	ppRef := credential.Ref{StoreID: "mem", ItemID: "pp-drop"}
	_ = memStore.Put(t.Context(), pwRef, credential.NewSecret([]byte("login-pw")))
	_ = memStore.Put(t.Context(), ppRef, credential.NewSecret([]byte("pass-1")))

	if _, err := repo.CreateNodeContext(t.Context(), "ops@10.30.0.1:22",
		models.Node{HostRef: "10.30.0.1:22", IdentityRef: "ops@10.30.0.1", SudoMode: models.SudoModeAuto},
		models.Host{Address: "10.30.0.1", Port: 22},
		models.Identity{
			User:             "ops",
			AuthType:         "auto",
			KeyPath:          key1,
			KeyFingerprint:   fp1,
			LoginPasswordRef: pwRef.Clone(),
			PassphraseRef:    ppRef.Clone(),
		},
	); err != nil {
		t.Fatalf("CreateNodeContext: %v", err)
	}

	m := &Model{repository: repo, credentialService: svc, state: viewForm}
	state, err := m.newNodeFormState("ops@10.30.0.1:22")
	if err != nil {
		t.Fatalf("newNodeFormState: %v", err)
	}
	state.keyPath = targetKeyPath
	m.formState = state

	runFormMutationExpectSuccess(t, m)

	diskCfg, err := diskStore.Load()
	if err != nil {
		t.Fatalf("diskStore.Load: %v", err)
	}
	ident, _ := diskCfg.Identities.Get("ops@10.30.0.1")
	if ident.AuthType != "auto" || ident.KeyPath != targetKeyPath {
		t.Fatalf("identity AuthType/KeyPath = (%q, %q), want (auto, %q)", ident.AuthType, ident.KeyPath, targetKeyPath)
	}
	if ident.PassphraseRef != nil || ident.KeyFingerprint != "" {
		t.Fatalf("stale passphrase/fingerprint remained after clearing keyPath=%q: %+v", targetKeyPath, ident)
	}
	if ident.LoginPasswordRef == nil || *ident.LoginPasswordRef != pwRef {
		t.Fatalf("LoginPasswordRef on auto node lost: %+v", ident)
	}
	if _, err := memStore.Get(t.Context(), ppRef); !errors.Is(err, coreauth.ErrCredentialNotFound) {
		t.Fatalf("dropped PassphraseRef still in vault: %v", err)
	}
}

func testW16cTUIChangeKeyPathWithKeep(t *testing.T) {
	repo, diskStore, memStore, svc := newW16cDiskTUIEnv(t, "mem")
	key1, fp1 := writeW16cTestKey(t, "pass-1")
	key2, _ := writeW16cTestKey(t, "")
	ppRef := credential.Ref{StoreID: "mem", ItemID: "pp-key1"}
	_ = memStore.Put(t.Context(), ppRef, credential.NewSecret([]byte("pass-1")))

	if _, err := repo.CreateNodeContext(t.Context(), "ops@10.30.0.2:22",
		models.Node{HostRef: "10.30.0.2:22", IdentityRef: "ops@10.30.0.2", SudoMode: models.SudoModeAuto},
		models.Host{Address: "10.30.0.2", Port: 22},
		models.Identity{
			User:           "ops",
			AuthType:       "key",
			KeyPath:        key1,
			KeyFingerprint: fp1,
			PassphraseRef:  ppRef.Clone(),
		},
	); err != nil {
		t.Fatalf("CreateNodeContext: %v", err)
	}

	m := &Model{repository: repo, credentialService: svc, state: viewForm}
	state, err := m.newNodeFormState("ops@10.30.0.2:22")
	if err != nil {
		t.Fatalf("newNodeFormState: %v", err)
	}
	state.keyPath = key2
	state.passphraseAction = "keep"
	m.formState = state

	runFormMutationExpectSuccess(t, m)

	diskCfg, err := diskStore.Load()
	if err != nil {
		t.Fatalf("diskStore.Load: %v", err)
	}
	ident, _ := diskCfg.Identities.Get("ops@10.30.0.2")
	if ident.KeyPath != key2 || ident.PassphraseRef != nil || ident.KeyFingerprint != "" {
		t.Fatalf("changing keyPath with keep left stale binding: %+v", ident)
	}
	if _, err := memStore.Get(t.Context(), ppRef); !errors.Is(err, coreauth.ErrCredentialNotFound) {
		t.Fatalf("old key1 passphrase still in vault: %v", err)
	}
}

func testW16cTUITagOnlyEditWithTildeKeyPath(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)
	sshDir := filepath.Join(homeDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("MkdirAll .ssh: %v", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := sshcrypto.MarshalPrivateKeyWithPassphrase(priv, "", []byte("tilde-pass"))
	if err != nil {
		t.Fatal(err)
	}
	absKey := filepath.Join(sshDir, "id_tilde")
	if err := os.WriteFile(absKey, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	fp, err := config.PrivateKeyFingerprint(absKey, []byte("tilde-pass"))
	if err != nil {
		t.Fatal(err)
	}

	repo, diskStore, memStore, svc := newW16cDiskTUIEnv(t, "mem")
	ppRef := credential.Ref{StoreID: "mem", ItemID: "pp-tilde"}
	_ = memStore.Put(t.Context(), ppRef, credential.NewSecret([]byte("tilde-pass")))
	if _, err := repo.CreateNodeContext(t.Context(), "ops@10.30.0.3:22",
		models.Node{HostRef: "10.30.0.3:22", IdentityRef: "ops@10.30.0.3", SudoMode: models.SudoModeAuto},
		models.Host{Address: "10.30.0.3", Port: 22},
		models.Identity{
			User:           "ops",
			AuthType:       "key",
			KeyPath:        "~/.ssh/id_tilde",
			KeyFingerprint: fp,
			PassphraseRef:  ppRef.Clone(),
		},
	); err != nil {
		t.Fatalf("CreateNodeContext: %v", err)
	}

	m := &Model{repository: repo, credentialService: svc, state: viewForm}
	state, err := m.newNodeFormState("ops@10.30.0.3:22")
	if err != nil {
		t.Fatalf("newNodeFormState: %v", err)
	}
	state.tags = "updated-tag"
	m.formState = state

	runFormMutationExpectSuccess(t, m)

	diskCfg, _ := diskStore.Load()
	ident, _ := diskCfg.Identities.Get("ops@10.30.0.3")
	if ident.PassphraseRef == nil || *ident.PassphraseRef != ppRef || ident.KeyFingerprint != fp {
		t.Fatalf("tag-only edit falsely unlinked tilde key binding: %+v", ident)
	}
	if _, err := memStore.Get(t.Context(), ppRef); err != nil {
		t.Fatalf("tag-only edit deleted passphrase from vault: %v", err)
	}
}

func TestP7W16c_L4_16_M3_TUISharedAliasedHostPortEditSucceedsOnRealDisk(t *testing.T) {
	repo, diskStore, _, svc := newW16cDiskTUIEnv(t, "mem")
	sharedHost := models.Host{Address: "10.0.0.5", Port: 22, Alias: []string{"db-primary"}}
	if _, err := repo.CreateNodeContext(t.Context(), "deploy@10.0.0.5:22",
		models.Node{HostRef: "10.0.0.5:22", IdentityRef: "deploy@10.0.0.5", SudoMode: models.SudoModeAuto},
		sharedHost,
		models.Identity{User: "deploy", AuthType: "auto"},
	); err != nil {
		t.Fatalf("CreateNodeContext(deploy): %v", err)
	}
	if _, err := repo.CreateNodeContext(t.Context(), "audit@10.0.0.5:22",
		models.Node{HostRef: "10.0.0.5:22", IdentityRef: "audit@10.0.0.5", SudoMode: models.SudoModeAuto},
		sharedHost,
		models.Identity{User: "audit", AuthType: "auto"},
	); err != nil {
		t.Fatalf("CreateNodeContext(audit): %v", err)
	}

	m := &Model{repository: repo, credentialService: svc, state: viewForm}
	state, err := m.newNodeFormState("audit@10.0.0.5:22")
	if err != nil {
		t.Fatalf("newNodeFormState: %v", err)
	}
	state.port = "2222"
	m.formState = state

	runFormMutationExpectSuccess(t, m)

	diskCfg, err := diskStore.Load()
	if err != nil {
		t.Fatalf("diskStore.Load: %v", err)
	}
	auditNode, ok := diskCfg.Nodes.Get("audit@10.0.0.5:2222")
	if !ok {
		t.Fatal("audit@10.0.0.5:2222 missing on disk")
	}
	forkedHost, _ := diskCfg.Hosts.Get(auditNode.HostRef)
	if forkedHost.Port != 2222 || len(forkedHost.Alias) != 0 {
		t.Fatalf("forked host = %+v, want Port=2222 and no Alias", forkedHost)
	}
	resolved, err := repo.ResolveSelector("db-primary")
	if err != nil || resolved != "deploy@10.0.0.5:22" {
		t.Fatalf("ResolveSelector(db-primary) = (%q, %v), want deploy@10.0.0.5:22", resolved, err)
	}
}
