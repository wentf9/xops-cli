package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
	sshcrypto "golang.org/x/crypto/ssh"
)

func newW16cDiskRepo(t *testing.T) (*Repository, Store) {
	t.Helper()
	dir := t.TempDir()
	store := NewDefaultStore(filepath.Join(dir, "xops_config.yaml"), filepath.Join(dir, "secret.key"))
	cfg := cloneConfiguration(nil)
	cfg.SchemaVersion = 2
	cfg.Credential = &CredentialConfig{
		DefaultStore: "mem",
		Stores: map[string]StoreConfig{
			"mem": {Type: StoreTypeHelper, Command: "/unused-helper"},
		},
	}
	if err := store.Save(cfg); err != nil {
		t.Fatalf("store.Save: %v", err)
	}
	repo, err := NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	return repo, store
}

func writeW16cEncryptedKey(t *testing.T, passphrase string) (string, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	block, err := sshcrypto.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	if err != nil {
		t.Fatalf("MarshalPrivateKeyWithPassphrase: %v", err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("WriteFile key: %v", err)
	}
	fp, err := PrivateKeyFingerprint(path, []byte(passphrase))
	if err != nil {
		t.Fatalf("PrivateKeyFingerprint: %v", err)
	}
	return path, fp
}

func TestP7W16c_L4_16_H1_ValidateGraphEnforcesPassphraseKeyFingerprintInvariant(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name        string
		fingerprint string
		wantErr     bool
	}{
		{name: "empty_fingerprint_rejected", fingerprint: "", wantErr: true},
		{name: "whitespace_fingerprint_rejected", fingerprint: "   ", wantErr: true},
		{name: "valid_fingerprint_accepted", fingerprint: "SHA256:valid-fp", wantErr: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := cloneConfiguration(nil)
			cfg.SchemaVersion = 2
			cfg.Credential = &CredentialConfig{
				DefaultStore: "mem",
				Stores: map[string]StoreConfig{
					"mem": {Type: StoreTypeHelper, Command: "/unused"},
				},
			}
			cfg.Hosts.Set("10.0.0.1:22", models.Host{Address: "10.0.0.1", Port: 22})
			cfg.Identities.Set("id-key", models.Identity{
				User:           "ops",
				AuthType:       "key",
				KeyPath:        "/keys/id_ed25519",
				KeyFingerprint: tc.fingerprint,
				PassphraseRef:  &credential.Ref{StoreID: "mem", ItemID: "pp-1"},
			})
			cfg.Nodes.Set("ops@10.0.0.1:22", models.Node{
				HostRef:     "10.0.0.1:22",
				IdentityRef: "id-key",
				SudoMode:    models.SudoModeAuto,
			})

			err := ValidateGraph(cfg)
			if tc.wantErr {
				if !errors.Is(err, ErrSchemaValidation) {
					t.Fatalf("ValidateGraph(%s) = %v, want ErrSchemaValidation", tc.name, err)
				}
			} else if err != nil {
				t.Fatalf("ValidateGraph(%s) unexpected error: %v", tc.name, err)
			}

			// Verify parity with Schema v2 disk validation (ToV2 -> ValidateV2).
			_, v2Err := cfg.ToV2()
			if tc.wantErr && !errors.Is(v2Err, ErrSchemaValidation) {
				t.Fatalf("ToV2(%s) = %v, want ErrSchemaValidation", tc.name, v2Err)
			}
			if !tc.wantErr && v2Err != nil {
				t.Fatalf("ToV2(%s) unexpected error: %v", tc.name, v2Err)
			}
		})
	}
}

func TestP7W16c_L4_16_H1_AtomicCrossKindUnlinkOnRealDiskStore(t *testing.T) {
	t.Parallel()
	keyPath, keyFP := writeW16cEncryptedKey(t, "key-secret")
	t.Run("node_clear_key_path_unlinks_passphrase_ref_on_disk", func(t *testing.T) {
		t.Parallel()
		testW16cNodeClearKeyPathUnlinksPassphrase(t, keyPath, keyFP)
	})
	t.Run("identity_clear_key_path_unlinks_passphrase_ref_on_disk", func(t *testing.T) {
		t.Parallel()
		testW16cIdentityClearKeyPathUnlinksPassphrase(t, keyPath, keyFP)
	})
	t.Run("node_and_identity_switch_password_to_key_unlinks_login_password_ref", func(t *testing.T) {
		t.Parallel()
		testW16cPasswordToKeyUnlinksLoginPassword(t, keyPath, keyFP)
	})
}

func testW16cNodeClearKeyPathUnlinksPassphrase(t *testing.T, keyPath, keyFP string) {
	t.Helper()
	passRef := &credential.Ref{StoreID: "mem", ItemID: "pp-1"}
	newPWRef := &credential.Ref{StoreID: "mem", ItemID: "pw-2"}
	repo, store := newW16cDiskRepo(t)
	if _, err := repo.CreateNodeContext(t.Context(), "ops@10.1.0.1:22",
		models.Node{HostRef: "10.1.0.1:22", IdentityRef: "ops@10.1.0.1", SudoMode: models.SudoModeAuto},
		models.Host{Address: "10.1.0.1", Port: 22},
		models.Identity{User: "ops", AuthType: "key", KeyPath: keyPath, KeyFingerprint: keyFP, PassphraseRef: passRef.Clone()},
	); err != nil {
		t.Fatalf("CreateNodeContext: %v", err)
	}

	snap, err := repo.ResolveConnection("ops@10.1.0.1:22")
	if err != nil {
		t.Fatalf("ResolveConnection: %v", err)
	}
	target := credential.Target{
		NodeID:                   "ops@10.1.0.1:22",
		Kind:                     credential.KindLoginPassword,
		AuthType:                 "password",
		ClearKeyPath:             true,
		ClearLegacyLoginPassword: true,
		ClearLegacyPassphrase:    true,
	}
	if _, _, err := repo.AsConfigUpdater().ApplyCredentialRefAtVersion(t.Context(), target, string(snap.UpdateRef.AuthVersion[:]), newPWRef); err != nil {
		t.Fatalf("ApplyCredentialRefAtVersion(key -> password) failed on real disk v2 store: %v", err)
	}

	diskCfg, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	ident, _ := diskCfg.Identities.Get("ops@10.1.0.1")
	if ident.AuthType != "password" || ident.KeyPath != "" || ident.KeyFingerprint != "" || ident.PassphraseRef != nil {
		t.Fatalf("stale key fields survived clearKeyPath: %+v", ident)
	}
	if ident.LoginPasswordRef == nil || *ident.LoginPasswordRef != *newPWRef {
		t.Fatalf("LoginPasswordRef = %v, want %v", ident.LoginPasswordRef, newPWRef)
	}
}

func testW16cIdentityClearKeyPathUnlinksPassphrase(t *testing.T, keyPath, keyFP string) {
	t.Helper()
	passRef := &credential.Ref{StoreID: "mem", ItemID: "pp-1"}
	newPWRef := &credential.Ref{StoreID: "mem", ItemID: "pw-2"}
	repo, store := newW16cDiskRepo(t)
	if _, err := repo.CreateIdentityContext(t.Context(), "id-enc", models.Identity{
		User:           "ops",
		AuthType:       "key",
		KeyPath:        keyPath,
		KeyFingerprint: keyFP,
		PassphraseRef:  passRef.Clone(),
	}); err != nil {
		t.Fatalf("CreateIdentityContext: %v", err)
	}
	ref := repo.View().IdentityRefs["id-enc"]
	target := credential.Target{
		IdentityID:               "id-enc",
		Kind:                     credential.KindLoginPassword,
		AuthType:                 "password",
		ClearKeyPath:             true,
		ClearLegacyLoginPassword: true,
		ClearLegacyPassphrase:    true,
	}
	if _, _, err := repo.AsConfigUpdater().ApplyCredentialRefAtVersion(t.Context(), target, string(ref.Version[:]), newPWRef); err != nil {
		t.Fatalf("ApplyCredentialRefAtVersion(identity key -> password) failed on real disk v2 store: %v", err)
	}
	diskCfg, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	ident, _ := diskCfg.Identities.Get("id-enc")
	if ident.AuthType != "password" || ident.KeyPath != "" || ident.KeyFingerprint != "" || ident.PassphraseRef != nil {
		t.Fatalf("stale key fields survived identity update: %+v", ident)
	}
}

func testW16cPasswordToKeyUnlinksLoginPassword(t *testing.T, keyPath, keyFP string) {
	t.Helper()
	pwRef := &credential.Ref{StoreID: "mem", ItemID: "pw-1"}
	newPassRef := &credential.Ref{StoreID: "mem", ItemID: "pp-2"}
	repo, store := newW16cDiskRepo(t)
	if _, err := repo.CreateNodeContext(t.Context(), "ops@10.1.0.2:22",
		models.Node{HostRef: "10.1.0.2:22", IdentityRef: "ops@10.1.0.2", SudoMode: models.SudoModeAuto},
		models.Host{Address: "10.1.0.2", Port: 22},
		models.Identity{User: "ops", AuthType: "password", LoginPasswordRef: pwRef.Clone()},
	); err != nil {
		t.Fatalf("CreateNodeContext: %v", err)
	}
	view := repo.View()
	node, host, ident, err := repo.Resolve("ops@10.1.0.2:22")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	nodeRef := view.NodeRefs["ops@10.1.0.2:22"]
	editUpdater := repo.NodeCredentialEdit(nodeRef, "ops@10.1.0.2:22", node, host, ident)
	target := credential.Target{
		NodeID:         "ops@10.1.0.2:22",
		Kind:           credential.KindPassphrase,
		AuthType:       "key",
		KeyPath:        keyPath,
		KeyFingerprint: keyFP,
	}
	if _, _, err := editUpdater.ApplyCredentialRefAtVersion(t.Context(), target, string(nodeRef.Version[:]), newPassRef); err != nil {
		t.Fatalf("NodeCredentialEdit(password -> key): %v", err)
	}
	diskCfg, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	gotIdent, _ := diskCfg.Identities.Get("ops@10.1.0.2")
	if gotIdent.AuthType != "key" || gotIdent.LoginPasswordRef != nil || gotIdent.Password != "" {
		t.Fatalf("LoginPasswordRef survived password -> key switch: %+v", gotIdent)
	}
	if gotIdent.PassphraseRef == nil || *gotIdent.PassphraseRef != *newPassRef || gotIdent.KeyFingerprint != keyFP {
		t.Fatalf("PassphraseRef/KeyFingerprint mismatch: %+v", gotIdent)
	}

	// Deleting KindPassphrase also clears KeyFingerprint.
	snap, err := repo.ResolveConnection("ops@10.1.0.2:22")
	if err != nil {
		t.Fatalf("ResolveConnection: %v", err)
	}
	if _, _, err := repo.AsConfigUpdater().ApplyCredentialRefAtVersion(t.Context(),
		credential.Target{NodeID: "ops@10.1.0.2:22", Kind: credential.KindPassphrase},
		string(snap.UpdateRef.AuthVersion[:]), nil); err != nil {
		t.Fatalf("delete KindPassphrase: %v", err)
	}
	diskCfg, err = store.Load()
	if err != nil {
		t.Fatalf("store.Load after delete passphrase: %v", err)
	}
	gotIdent, _ = diskCfg.Identities.Get("ops@10.1.0.2")
	if gotIdent.PassphraseRef != nil || gotIdent.KeyFingerprint != "" {
		t.Fatalf("deleting PassphraseRef left stale KeyFingerprint: %+v", gotIdent)
	}
}

func TestP7W16c_L4_16_M2_AutoWritebackPreservesAutoAndHybridAuthTypes(t *testing.T) {
	t.Parallel()
	keyPath, keyFP := writeW16cEncryptedKey(t, "auto-key-pass")

	for _, authType := range []string{"auto", "otp", "keyboard-interactive"} {
		t.Run(authType, func(t *testing.T) {
			t.Parallel()
			repo, store := newW16cDiskRepo(t)
			nodeID := "ops@10.2.0.1:22"
			if _, err := repo.CreateNodeContext(t.Context(), nodeID,
				models.Node{HostRef: "10.2.0.1:22", IdentityRef: "ops@10.2.0.1", SudoMode: models.SudoModeAuto},
				models.Host{Address: "10.2.0.1", Port: 22},
				models.Identity{User: "ops", AuthType: authType, KeyPath: keyPath},
			); err != nil {
				t.Fatalf("CreateNodeContext: %v", err)
			}

			// 1. Writeback passphrase first -> must preserve AuthType.
			snap1, err := repo.ResolveConnection(nodeID)
			if err != nil {
				t.Fatalf("ResolveConnection 1: %v", err)
			}
			passRef := &credential.Ref{StoreID: "mem", ItemID: "pp-" + authType}
			if _, _, err := repo.AsConfigUpdater().ApplyCredentialRefAtVersion(t.Context(), credential.Target{
				NodeID:         nodeID,
				Kind:           credential.KindPassphrase,
				KeyPath:        keyPath,
				KeyFingerprint: keyFP,
			}, string(snap1.UpdateRef.AuthVersion[:]), passRef); err != nil {
				t.Fatalf("writeback passphrase: %v", err)
			}

			// 2. Writeback login password next -> must preserve AuthType AND PassphraseRef/KeyPath/KeyFingerprint.
			snap2, err := repo.ResolveConnection(nodeID)
			if err != nil {
				t.Fatalf("ResolveConnection 2: %v", err)
			}
			pwRef := &credential.Ref{StoreID: "mem", ItemID: "pw-" + authType}
			if _, _, err := repo.AsConfigUpdater().ApplyCredentialRefAtVersion(t.Context(), credential.Target{
				NodeID: nodeID,
				Kind:   credential.KindLoginPassword,
			}, string(snap2.UpdateRef.AuthVersion[:]), pwRef); err != nil {
				t.Fatalf("writeback login password: %v", err)
			}

			diskCfg, err := store.Load()
			if err != nil {
				t.Fatalf("store.Load: %v", err)
			}
			ident, _ := diskCfg.Identities.Get("ops@10.2.0.1")
			if ident.AuthType != authType {
				t.Fatalf("AuthType = %q, want preserved %q", ident.AuthType, authType)
			}
			if ident.LoginPasswordRef == nil || *ident.LoginPasswordRef != *pwRef {
				t.Fatalf("LoginPasswordRef = %v, want %v", ident.LoginPasswordRef, pwRef)
			}
			if ident.PassphraseRef == nil || *ident.PassphraseRef != *passRef || ident.KeyPath != keyPath || ident.KeyFingerprint != keyFP {
				t.Fatalf("key fields clobbered on %s writeback: %+v", authType, ident)
			}
		})
	}
}

func TestP7W16c_L4_16_M3_DetachSharedHostRefClearsAliasOnForkedCopy(t *testing.T) {
	t.Parallel()
	repo, store := newW16cDiskRepo(t)

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

	view := repo.View()
	node, host, ident, err := repo.Resolve("audit@10.0.0.5:22")
	if err != nil {
		t.Fatalf("Resolve(audit): %v", err)
	}
	host.Port = 2222
	if err := repo.ReplaceNodeAtRefContext(t.Context(), view.NodeRefs["audit@10.0.0.5:22"], "audit@10.0.0.5:2222", node, host, ident); err != nil {
		t.Fatalf("ReplaceNodeAtRefContext(audit port 22->2222) failed on shared aliased host: %v", err)
	}

	diskCfg, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	if err := ValidateGraph(diskCfg); err != nil {
		t.Fatalf("ValidateGraph after detaching shared aliased host: %v", err)
	}

	auditNode, ok := diskCfg.Nodes.Get("audit@10.0.0.5:2222")
	if !ok {
		t.Fatal("renamed node audit@10.0.0.5:2222 missing")
	}
	if auditNode.HostRef == "10.0.0.5:22" {
		t.Fatalf("audit node did not fork private HostRef")
	}
	forkedHost, _ := diskCfg.Hosts.Get(auditNode.HostRef)
	if forkedHost.Port != 2222 || len(forkedHost.Alias) != 0 {
		t.Fatalf("forked host = %+v, want Port=2222 and empty Alias", forkedHost)
	}
	origHost, _ := diskCfg.Hosts.Get("10.0.0.5:22")
	if origHost.Port != 22 || len(origHost.Alias) != 1 || origHost.Alias[0] != "db-primary" {
		t.Fatalf("original shared host mutated: %+v", origHost)
	}
	resolved, err := repo.ResolveSelector("db-primary")
	if err != nil || resolved != "deploy@10.0.0.5:22" {
		t.Fatalf("ResolveSelector(db-primary) = (%q, %v), want (deploy@10.0.0.5:22, nil)", resolved, err)
	}
}

func TestP7W16c_L4_16_M3_AllocateNodeHostRefAndIdentityRef(t *testing.T) {
	t.Parallel()
	cfg := cloneConfiguration(nil)
	cfg.Hosts.Set("10.0.0.1:22", models.Host{Address: "10.0.0.1", Port: 22, Alias: []string{"web1"}})
	cfg.Hosts.Set("10.0.0.2:22", models.Host{Address: "10.0.0.2", Port: 22})
	cfg.Identities.Set("ops@10.0.0.1", models.Identity{User: "ops", AuthType: "key", KeyPath: "/keys/k1"})
	cfg.Identities.Set("ops@[2001:db8::1]", models.Identity{User: "ops", AuthType: "auto"})

	// Aliased canonical host must NOT be reused.
	href, h := AllocateNodeHostRef(cfg, "bob@10.0.0.1:22", "10.0.0.1", 22)
	if href == "10.0.0.1:22" || len(h.Alias) != 0 || h.Address != "10.0.0.1" || h.Port != 22 {
		t.Fatalf("AllocateNodeHostRef(aliased) = (%q, %+v), want private unaliased host", href, h)
	}
	// Unaliased host IS reused.
	href2, h2 := AllocateNodeHostRef(cfg, "bob@10.0.0.2:22", "10.0.0.2", 22)
	if href2 != "10.0.0.2:22" || h2.Address != "10.0.0.2" || h2.Port != 22 {
		t.Fatalf("AllocateNodeHostRef(unaliased) = (%q, %+v), want reused 10.0.0.2:22", href2, h2)
	}
	// Existing canonical identity must NOT collide.
	iref := AllocateNodeIdentityRef(cfg, "ops@10.0.0.1:2222", "ops", "10.0.0.1")
	if iref == "ops@10.0.0.1" {
		t.Fatalf("AllocateNodeIdentityRef collided with existing ops@10.0.0.1")
	}
	// IPv6 canonical identity collision allocates private ref.
	irefV6 := AllocateNodeIdentityRef(cfg, "ops@[2001:db8::1]:2222", "ops", "2001:db8::1")
	if irefV6 == "ops@[2001:db8::1]" {
		t.Fatalf("AllocateNodeIdentityRef(IPv6) collided with existing ops@[2001:db8::1]")
	}
	// Unused IPv6 identity gets canonical bracketed form.
	irefV6Fresh := AllocateNodeIdentityRef(cfg, "bob@[2001:db8::1]:22", "bob", "2001:db8::1")
	if irefV6Fresh != "bob@[2001:db8::1]" {
		t.Fatalf("AllocateNodeIdentityRef(fresh IPv6) = %q, want bob@[2001:db8::1]", irefV6Fresh)
	}
}
