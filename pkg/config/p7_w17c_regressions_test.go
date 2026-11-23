package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	coreauth "github.com/wentf9/xops-cli/core/auth"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
	sshcrypto "golang.org/x/crypto/ssh"
)

func newW17cDiskRepo(t *testing.T) (*Repository, Store) {
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

func writeW17cKeyAt(t *testing.T, path, passphrase string) string {
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
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
	fp, err := PrivateKeyFingerprint(path, []byte(passphrase))
	if err != nil {
		t.Fatalf("PrivateKeyFingerprint(%s): %v", path, err)
	}
	return fp
}

func TestP7W17c_L4_17_M2_PendingNodeAuthUpdatePreservesHybridAndUnlinksStaleRefs(t *testing.T) {
	t.Parallel()

	keyDir := t.TempDir()
	encKey := filepath.Join(keyDir, "enc_ed25519")
	encFP := writeW17cKeyAt(t, encKey, "enc-pass")
	unencKey := filepath.Join(keyDir, "unenc_ed25519")
	writeW17cKeyAt(t, unencKey, "")

	t.Run("key_to_different_unenc_key_clears_stale_passphrase_and_fingerprint", func(t *testing.T) {
		t.Parallel()
		assertW17cPendingKeyToUnencKey(t, encKey, encFP, unencKey)
	})
	t.Run("key_to_password_clears_key_fields_and_passes_schema_v2", func(t *testing.T) {
		t.Parallel()
		assertW17cPendingKeyToPassword(t, encKey, encFP)
	})
	t.Run("password_to_key_clears_login_password_ref", func(t *testing.T) {
		t.Parallel()
		assertW17cPendingPasswordToKey(t, unencKey)
	})
	for _, authType := range []string{"auto", "otp", "keyboard-interactive"} {
		t.Run("hybrid_"+authType+"_preserves_auth_type_and_cross_kind_refs", func(t *testing.T) {
			t.Parallel()
			assertW17cPendingHybridUpdates(t, authType, encKey, encFP, unencKey)
		})
	}
}

func confirmW17cPendingUpdate(t *testing.T, repo *Repository, nodeID string, upd PendingNodeUpdate) {
	t.Helper()
	if err := repo.WithPendingNode(t.Context(), EnsureNodeOptions{
		Target:         ConnectionTarget{Selector: nodeID},
		ExistingUpdate: upd,
	}, func(lease PendingLease) error {
		return lease.Confirm(t.Context())
	}); err != nil {
		t.Fatalf("WithPendingNode(%s): %v", nodeID, err)
	}
}

func assertW17cPendingKeyToUnencKey(t *testing.T, encKey, encFP, unencKey string) {
	t.Helper()
	repo, store := newW17cDiskRepo(t)
	nodeID := "ops@10.71.0.1:22"
	if _, err := repo.CreateNodeContext(t.Context(), nodeID,
		models.Node{HostRef: "10.71.0.1:22", IdentityRef: "ops@10.71.0.1", SudoMode: models.SudoModeAuto},
		models.Host{Address: "10.71.0.1", Port: 22},
		models.Identity{
			User:           "ops",
			AuthType:       "key",
			KeyPath:        encKey,
			KeyFingerprint: encFP,
			PassphraseRef:  &credential.Ref{StoreID: "mem", ItemID: "pp-old"},
		},
	); err != nil {
		t.Fatalf("CreateNodeContext: %v", err)
	}
	confirmW17cPendingUpdate(t, repo, nodeID, PendingNodeUpdate{Enabled: true, RememberAuth: true, IdentityFile: unencKey})
	diskCfg, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	got, _ := diskCfg.Identities.Get("ops@10.71.0.1")
	if got.AuthType != "key" || got.KeyPath != unencKey || got.KeyFingerprint != "" || got.Passphrase != "" || got.PassphraseRef != nil {
		t.Fatalf("stale key fields survived key replacement: %+v", got)
	}
}

func assertW17cPendingKeyToPassword(t *testing.T, encKey, encFP string) {
	t.Helper()
	repo, store := newW17cDiskRepo(t)
	nodeID := "ops@10.71.0.2:22"
	if _, err := repo.CreateNodeContext(t.Context(), nodeID,
		models.Node{HostRef: "10.71.0.2:22", IdentityRef: "ops@10.71.0.2", SudoMode: models.SudoModeAuto},
		models.Host{Address: "10.71.0.2", Port: 22},
		models.Identity{
			User:           "ops",
			AuthType:       "key",
			KeyPath:        encKey,
			KeyFingerprint: encFP,
			PassphraseRef:  &credential.Ref{StoreID: "mem", ItemID: "pp-old"},
		},
	); err != nil {
		t.Fatalf("CreateNodeContext: %v", err)
	}
	confirmW17cPendingUpdate(t, repo, nodeID, PendingNodeUpdate{Enabled: true, RememberAuth: true, HasPassword: true})
	diskCfg, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	got, _ := diskCfg.Identities.Get("ops@10.71.0.2")
	if got.AuthType != "password" || got.KeyPath != "" || got.KeyFingerprint != "" || got.Passphrase != "" || got.PassphraseRef != nil || got.Password != "" {
		t.Fatalf("stale key fields survived key -> password transition: %+v", got)
	}
}

func assertW17cPendingPasswordToKey(t *testing.T, unencKey string) {
	t.Helper()
	repo, store := newW17cDiskRepo(t)
	nodeID := "ops@10.71.0.3:22"
	if _, err := repo.CreateNodeContext(t.Context(), nodeID,
		models.Node{HostRef: "10.71.0.3:22", IdentityRef: "ops@10.71.0.3", SudoMode: models.SudoModeAuto},
		models.Host{Address: "10.71.0.3", Port: 22},
		models.Identity{
			User:             "ops",
			AuthType:         "password",
			LoginPasswordRef: &credential.Ref{StoreID: "mem", ItemID: "pw-old"},
		},
	); err != nil {
		t.Fatalf("CreateNodeContext: %v", err)
	}
	confirmW17cPendingUpdate(t, repo, nodeID, PendingNodeUpdate{Enabled: true, RememberAuth: true, IdentityFile: unencKey})
	diskCfg, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	got, _ := diskCfg.Identities.Get("ops@10.71.0.3")
	if got.AuthType != "key" || got.KeyPath != unencKey || got.LoginPasswordRef != nil || got.Password != "" {
		t.Fatalf("LoginPasswordRef survived password -> key transition: %+v", got)
	}
}

func assertW17cPendingHybridUpdates(t *testing.T, authType, encKey, encFP, unencKey string) {
	t.Helper()
	repo, store := newW17cDiskRepo(t)
	nodeID := "ops@10.71.0.4:22"
	pwRef := &credential.Ref{StoreID: "mem", ItemID: "pw-hybrid"}
	ppRef := &credential.Ref{StoreID: "mem", ItemID: "pp-hybrid"}
	if _, err := repo.CreateNodeContext(t.Context(), nodeID,
		models.Node{HostRef: "10.71.0.4:22", IdentityRef: "ops@10.71.0.4", SudoMode: models.SudoModeAuto},
		models.Host{Address: "10.71.0.4", Port: 22},
		models.Identity{
			User:             "ops",
			AuthType:         authType,
			KeyPath:          encKey,
			KeyFingerprint:   encFP,
			PassphraseRef:    ppRef.Clone(),
			LoginPasswordRef: pwRef.Clone(),
		},
	); err != nil {
		t.Fatalf("CreateNodeContext: %v", err)
	}

	assertHybridIntact := func(step string) {
		t.Helper()
		diskCfg, err := store.Load()
		if err != nil {
			t.Fatalf("store.Load(%s): %v", step, err)
		}
		got, _ := diskCfg.Identities.Get("ops@10.71.0.4")
		if got.AuthType != authType || got.KeyPath != encKey || got.KeyFingerprint != encFP ||
			got.PassphraseRef == nil || *got.PassphraseRef != *ppRef ||
			got.LoginPasswordRef == nil || *got.LoginPasswordRef != *pwRef {
			t.Fatalf("hybrid %s mutated on %s: %+v", authType, step, got)
		}
	}

	confirmW17cPendingUpdate(t, repo, nodeID, PendingNodeUpdate{Enabled: true, RememberAuth: true, HasPassword: true})
	assertHybridIntact("HasPassword")

	confirmW17cPendingUpdate(t, repo, nodeID, PendingNodeUpdate{Enabled: true, RememberAuth: true, IdentityFile: encKey})
	assertHybridIntact("same key")

	confirmW17cPendingUpdate(t, repo, nodeID, PendingNodeUpdate{Enabled: true, RememberAuth: true, IdentityFile: unencKey})
	diskCfg, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load(new key): %v", err)
	}
	got3, _ := diskCfg.Identities.Get("ops@10.71.0.4")
	if got3.AuthType != authType || got3.KeyPath != unencKey || got3.KeyFingerprint != "" ||
		got3.PassphraseRef != nil || got3.LoginPasswordRef == nil || *got3.LoginPasswordRef != *pwRef {
		t.Fatalf("hybrid %s after new key = %+v", authType, got3)
	}
}

func TestP7W17c_L4_17_M3_IdentityCredentialCreateAtomicAndConflictSafe(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		result PersistResult
	}{
		{"not_applied", PersistResult{}},
		{"not_durable", PersistResult{Applied: true}},
		{"durable", PersistResult{Applied: true, Durable: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := &repositoryTestStore{result: tc.result}
			if !tc.result.Durable {
				store.err = errors.New("injected persistence failure")
			}
			repo, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
			if err != nil {
				t.Fatal(err)
			}
			updater := repo.IdentityCredentialCreate("new-id", models.Identity{User: "ops", AuthType: "password"})
			ref := &credential.Ref{StoreID: "test", ItemID: "created-pw"}
			outcome, version, err := updater.ApplyCredentialRefAtVersion(t.Context(), credential.Target{IdentityID: "new-id", Kind: credential.KindLoginPassword}, "", ref)
			if outcome.Applied != tc.result.Applied || outcome.Durable != tc.result.Durable || (err == nil) != tc.result.Durable {
				t.Fatalf("outcome=%+v err=%v", outcome, err)
			}
			got, exists := repo.Snapshot().Identities.Get("new-id")
			if exists != outcome.Applied {
				t.Fatalf("exists=%v, want %v", exists, outcome.Applied)
			}
			if outcome.Applied && (version == "" || got.LoginPasswordRef == nil || *got.LoginPasswordRef != *ref) {
				t.Fatalf("applied identity mismatch: ver=%q got=%+v", version, got)
			}
		})
	}

	t.Run("rejects_concurrent_creation_and_preserves_existing", func(t *testing.T) {
		t.Parallel()
		store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
		repo, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
		if err != nil {
			t.Fatal(err)
		}
		updater := repo.IdentityCredentialCreate("dup-id", models.Identity{User: "ops", AuthType: "password"})
		if _, err := repo.CreateIdentityContext(t.Context(), "dup-id", models.Identity{User: "existing", AuthType: "auto"}); err != nil {
			t.Fatal(err)
		}
		outcome, _, err := updater.ApplyCredentialRefAtVersion(t.Context(), credential.Target{IdentityID: "dup-id", Kind: credential.KindLoginPassword}, "", &credential.Ref{StoreID: "test", ItemID: "pw"})
		if !errors.Is(err, coreauth.ErrConfigConflict) || !errors.Is(err, ErrConfigConflict) || outcome.Applied {
			t.Fatalf("concurrent creation: outcome=%+v err=%v, want ErrConfigConflict", outcome, err)
		}
		got, _ := repo.Snapshot().Identities.Get("dup-id")
		if got.User != "existing" || got.LoginPasswordRef != nil {
			t.Fatalf("existing identity overwritten: %+v", got)
		}
	})
}

func TestP7W17c_L4_17_M4_EnsureMatchingHostIsolatesAliasedHosts(t *testing.T) {
	t.Parallel()

	t.Run("never_reuses_unreferenced_aliased_host", func(t *testing.T) {
		t.Parallel()
		assertW17cEnsureHostSkipsUnreferencedAliased(t)
	})
	t.Run("multiple_aliased_hosts_allocates_fresh_unaliased_without_ambiguity", func(t *testing.T) {
		t.Parallel()
		assertW17cEnsureHostMultipleAliased(t)
	})
	t.Run("reuses_single_unaliased_host_even_with_aliased_siblings", func(t *testing.T) {
		t.Parallel()
		cfg := cloneConfiguration(nil)
		cfg.Hosts.Set("web-a", models.Host{Address: "10.72.0.4", Port: 22, Alias: []string{"alias-a"}})
		cfg.Hosts.Set("plain-host", models.Host{Address: "10.72.0.4", Port: 22})

		href, err := ensureMatchingHost(cfg, "10.72.0.4", 22, "bob@10.72.0.4:22")
		if err != nil {
			t.Fatalf("ensureMatchingHost: %v", err)
		}
		if href != "plain-host" {
			t.Fatalf("href = %q, want reused plain-host", href)
		}
	})
	t.Run("multiple_unaliased_hosts_still_reports_ambiguity", func(t *testing.T) {
		t.Parallel()
		cfg := cloneConfiguration(nil)
		cfg.Hosts.Set("plain-a", models.Host{Address: "10.72.0.5", Port: 22})
		cfg.Hosts.Set("plain-b", models.Host{Address: "10.72.0.5", Port: 22})

		_, err := ensureMatchingHost(cfg, "10.72.0.5", 22, "bob@10.72.0.5:22")
		if err == nil || !strings.Contains(err.Error(), "ambiguous host configuration") {
			t.Fatalf("ensureMatchingHost(two unaliased) err = %v, want ambiguous host configuration", err)
		}
	})
}

func assertW17cEnsureHostSkipsUnreferencedAliased(t *testing.T) {
	t.Helper()
	cfg := cloneConfiguration(nil)
	cfg.Hosts.Set("10.72.0.1:22", models.Host{Address: "10.72.0.1", Port: 22, Alias: []string{"orphan-web"}})

	href, err := ensureMatchingHost(cfg, "10.72.0.1", 22, "bob@10.72.0.1:22")
	if err != nil {
		t.Fatalf("ensureMatchingHost(unreferenced aliased): %v", err)
	}
	if href == "10.72.0.1:22" {
		t.Fatalf("reused unreferenced aliased HostRef %q", href)
	}
	got, ok := cfg.Hosts.Get(href)
	if !ok || len(got.Alias) != 0 || got.Address != "10.72.0.1" || got.Port != 22 {
		t.Fatalf("allocated host = (%+v, %v), want unaliased 10.72.0.1:22", got, ok)
	}
	orig, _ := cfg.Hosts.Get("10.72.0.1:22")
	if len(orig.Alias) != 1 || orig.Alias[0] != "orphan-web" {
		t.Fatalf("aliased host mutated: %+v", orig)
	}
}

func assertW17cEnsureHostMultipleAliased(t *testing.T) {
	t.Helper()
	cfg := cloneConfiguration(nil)
	cfg.Hosts.Set("web-a", models.Host{Address: "10.72.0.2", Port: 22, Alias: []string{"alias-a"}})
	cfg.Hosts.Set("web-b", models.Host{Address: "10.72.0.2", Port: 22, Alias: []string{"alias-b"}})

	href, err := ensureMatchingHost(cfg, "10.72.0.2", 22, "bob@10.72.0.2:22")
	if err != nil {
		t.Fatalf("ensureMatchingHost(two aliased hosts) unexpectedly failed: %v", err)
	}
	if href == "web-a" || href == "web-b" {
		t.Fatalf("reused aliased host %q", href)
	}
	got, ok := cfg.Hosts.Get(href)
	if !ok || len(got.Alias) != 0 || got.Address != "10.72.0.2" || got.Port != 22 {
		t.Fatalf("allocated host = (%+v, %v), want fresh unaliased 10.72.0.2:22", got, ok)
	}

	repo, store := newW17cDiskRepo(t)
	diskCfg := repo.Snapshot()
	diskCfg.Hosts.Set("10.72.0.3:22", models.Host{Address: "10.72.0.3", Port: 22, Alias: []string{"primary"}})
	diskCfg.Hosts.Set("secondary-host", models.Host{Address: "10.72.0.3", Port: 22, Alias: []string{"secondary"}})
	diskCfg.Identities.Set("ops@10.72.0.3", models.Identity{User: "ops", AuthType: "auto"})
	diskCfg.Nodes.Set("ops@10.72.0.3:22", models.Node{HostRef: "10.72.0.3:22", IdentityRef: "ops@10.72.0.3", SudoMode: models.SudoModeAuto})
	if err := store.Save(diskCfg); err != nil {
		t.Fatalf("store.Save: %v", err)
	}
	repo, err = NewRepositoryWithoutOpenSSH(diskCfg, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	if err := repo.WithPendingNode(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "bob@10.72.0.3:22"},
	}, func(lease PendingLease) error {
		return lease.Confirm(t.Context())
	}); err != nil {
		t.Fatalf("WithPendingNode(two aliased hosts): %v", err)
	}
	reloaded, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	bobNode, ok := reloaded.Nodes.Get("bob@10.72.0.3:22")
	if !ok || bobNode.HostRef == "10.72.0.3:22" || bobNode.HostRef == "secondary-host" {
		t.Fatalf("bobNode = (%+v, %v), want private unaliased HostRef", bobNode, ok)
	}
	bobHost, _ := reloaded.Hosts.Get(bobNode.HostRef)
	if len(bobHost.Alias) != 0 {
		t.Fatalf("bobHost has unexpected alias: %+v", bobHost)
	}
}

func TestP7W17c_L4_17_L1_PrivateKeyFingerprintExpandsBackslashTilde(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	passphrase := "win-tilde-pass"
	absPath := filepath.Join(home, "id_w17c_ed25519")
	wantFP := writeW17cKeyAt(t, absPath, passphrase)

	for _, input := range []string{"~/id_w17c_ed25519", `~\id_w17c_ed25519`} {
		got, err := PrivateKeyFingerprint(input, []byte(passphrase))
		if err != nil {
			t.Fatalf("PrivateKeyFingerprint(%q) failed: %v", input, err)
		}
		if got != wantFP {
			t.Fatalf("PrivateKeyFingerprint(%q) = %q, want %q", input, got, wantFP)
		}
	}
}

func TestP7W17c_L4_17_L2_StandaloneMalformedKeyFingerprintRejected(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		fingerprint string
		passRef     *credential.Ref
		wantErr     bool
	}{
		{name: "standalone_spaces_only", fingerprint: "   ", passRef: nil, wantErr: true},
		{name: "standalone_embedded_space", fingerprint: "SHA256:bad fp", passRef: nil, wantErr: true},
		{name: "standalone_tab", fingerprint: "SHA256:bad\tfp", passRef: nil, wantErr: true},
		{name: "standalone_newline", fingerprint: "SHA256:bad\nfp", passRef: nil, wantErr: true},
		{name: "standalone_nul", fingerprint: "SHA256:bad\x00fp", passRef: nil, wantErr: true},
		{name: "standalone_control_esc", fingerprint: "SHA256:bad\x1bfp", passRef: nil, wantErr: true},
		{name: "standalone_line_sep", fingerprint: "SHA256:bad\u2028fp", passRef: nil, wantErr: true},
		{name: "empty_ref_malformed_fp", fingerprint: "SHA256:bad fp", passRef: &credential.Ref{}, wantErr: true},
		{name: "standalone_valid_fp", fingerprint: "SHA256:validFingerprintString123+/=", passRef: nil, wantErr: false},
		{name: "standalone_empty_fp", fingerprint: "", passRef: nil, wantErr: false},
	}

	for _, tc := range cases {
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
			cfg.Hosts.Set("10.73.0.1:22", models.Host{Address: "10.73.0.1", Port: 22})
			cfg.Identities.Set("id-fp", models.Identity{
				User:           "ops",
				AuthType:       "key",
				KeyPath:        "/keys/id_ed25519",
				KeyFingerprint: tc.fingerprint,
				PassphraseRef:  tc.passRef,
			})
			cfg.Nodes.Set("ops@10.73.0.1:22", models.Node{
				HostRef:     "10.73.0.1:22",
				IdentityRef: "id-fp",
				SudoMode:    models.SudoModeAuto,
			})

			graphErr := ValidateGraph(cfg)
			_, v2Err := cfg.ToV2()
			if tc.wantErr {
				if !errors.Is(graphErr, ErrSchemaValidation) {
					t.Fatalf("ValidateGraph(%s) = %v, want ErrSchemaValidation", tc.name, graphErr)
				}
				if !errors.Is(v2Err, ErrSchemaValidation) {
					t.Fatalf("ToV2(%s) = %v, want ErrSchemaValidation", tc.name, v2Err)
				}
			} else if graphErr != nil || v2Err != nil {
				t.Fatalf("unexpected error for %s: graphErr=%v v2Err=%v", tc.name, graphErr, v2Err)
			}
		})
	}
}
