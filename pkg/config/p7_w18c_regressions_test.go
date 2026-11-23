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

	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
	sshcrypto "golang.org/x/crypto/ssh"
)

func setupW18cSavedDerivedRepo(t *testing.T) *Repository {
	t.Helper()
	sshCfg := strings.Join([]string{
		"Host app",
		"  CanonicalizeHostname yes",
		"  CanonicalDomains example.com",
		"",
		"Host app.example.com",
		"  HostName 192.0.2.99",
		"  Port 9999",
		"  User eviluser",
		"  ProxyCommand /bin/evil-proxy",
		"  SendEnv LEAK_ENV",
		"",
		"Host pure-ssh",
		"  HostName 10.99.0.1",
		"  Port 2222",
		"  User vops",
		"",
		"Host *.openssh-only.example.com",
		"  Port 2202",
		"  User vops",
	}, "\n") + "\n"
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	cfg := cloneConfiguration(nil)
	cfg.Hosts.Set("h-app", models.Host{Address: "10.10.0.1", Port: 2222})
	cfg.Identities.Set("id-app", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("app.example.com", models.Node{
		HostRef:     "h-app",
		IdentityRef: "id-app",
		Alias:       []string{"app-saved"},
	})
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	repo, err := NewRepositoryWithOpenSSHParser(cfg, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}
	return repo
}

func TestP7W18c_L3_18_H1_SavedNodeDerivedProvenanceNeverPromotedToOpenSSHDerived(t *testing.T) {
	t.Parallel()
	t.Run("saved_node_canonicalized_with_user_or_port_override_stays_adhoc_pending", assertW18cCanonicalizedSavedOverride)
	t.Run("saved_node_with_runtime_NodeOpenSSHOrigin_and_override_stays_adhoc_pending", assertW18cRuntimeOriginSavedOverride)
	t.Run("concurrent_upgrade_never_promotes_saved_derived_to_openssh_derived", assertW18cConcurrentUpgradeSavedDerived)
	t.Run("genuine_openssh_alias_still_gets_openssh_derived_and_raw_without_ssh_config_stays_adhoc", assertW18cGenuineOpenSSHAndNoSSHConfig)
}

func assertW18cCanonicalizedSavedOverride(t *testing.T) {
	t.Parallel()
	repo := setupW18cSavedDerivedRepo(t)
	cases := []struct {
		name   string
		target ConnectionTarget
		wantID string
	}{
		{
			name: "user_override_canonicalized",
			target: ConnectionTarget{
				Selector:     "app.example.com",
				OriginalHost: "app",
				User:         "altuser",
				HasUser:      true,
			},
			wantID: "altuser@10.10.0.1:2222",
		},
		{
			name: "port_override_canonicalized",
			target: ConnectionTarget{
				Selector:     "app.example.com",
				OriginalHost: "app",
				Port:         2223,
				HasPort:      true,
			},
			wantID: "ops@10.10.0.1:2223",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := repo.ResolveTarget(tc.target)
			if err != nil {
				t.Fatalf("ResolveTarget: %v", err)
			}
			if res.NodeID != tc.wantID || res.BaseNodeID != "app.example.com" || res.Provenance != ProvenanceAdHocPending {
				t.Fatalf("ResolveTarget = %+v, want NodeID=%q BaseNodeID=app.example.com Provenance=adhoc_pending", res, tc.wantID)
			}
			if err := repo.WithPendingNode(t.Context(), EnsureNodeOptions{Target: tc.target}, func(lease PendingLease) error {
				if lease.NodeID() != tc.wantID {
					t.Fatalf("lease.NodeID() = %q, want %q", lease.NodeID(), tc.wantID)
				}
				snap, err := repo.ResolveConnection(lease.NodeID())
				if err != nil {
					t.Fatalf("ResolveConnection: %v", err)
				}
				if snap.Provenance != ProvenanceAdHocPending {
					t.Fatalf("pending snap.Provenance = %s, want adhoc_pending", snap.Provenance)
				}
				resDuring, err := repo.ResolveTarget(ConnectionTarget{Selector: lease.NodeID()})
				if err != nil {
					t.Fatalf("ResolveTarget(during pending): %v", err)
				}
				if resDuring.Provenance != ProvenanceAdHocPending {
					t.Fatalf("ResolveTarget during pending Provenance = %s, want adhoc_pending", resDuring.Provenance)
				}
				return nil
			}); err != nil {
				t.Fatalf("WithPendingNode: %v", err)
			}
		})
	}
}

func assertW18cRuntimeOriginSavedOverride(t *testing.T) {
	t.Parallel()
	repo := setupW18cSavedDerivedRepo(t)
	repo.provider.SetNodeOpenSSHOrigin("app.example.com", OpenSSHOrigin{
		Alias:         "app",
		CanonicalHost: "app.example.com",
	})
	target := ConnectionTarget{Selector: "app-saved", User: "altuser", HasUser: true}
	res, err := repo.ResolveTarget(target)
	if err != nil {
		t.Fatalf("ResolveTarget: %v", err)
	}
	if res.NodeID != "altuser@10.10.0.1:2222" || res.BaseNodeID != "app.example.com" || res.Provenance != ProvenanceAdHocPending {
		t.Fatalf("ResolveTarget = %+v, want altuser@10.10.0.1:2222 adhoc_pending", res)
	}
	if err := repo.WithPendingNode(t.Context(), EnsureNodeOptions{Target: target}, func(lease PendingLease) error {
		snap, err := repo.ResolveConnection(lease.NodeID())
		if err != nil {
			t.Fatalf("ResolveConnection: %v", err)
		}
		if snap.Provenance != ProvenanceAdHocPending {
			t.Fatalf("pending snap.Provenance = %s, want adhoc_pending", snap.Provenance)
		}
		return nil
	}); err != nil {
		t.Fatalf("WithPendingNode: %v", err)
	}
}

func assertW18cConcurrentUpgradeSavedDerived(t *testing.T) {
	t.Parallel()
	repo := setupW18cSavedDerivedRepo(t)
	if err := repo.WithPendingNode(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "app-saved", User: "altuser", HasUser: true},
	}, func(lease1 PendingLease) error {
		return repo.WithPendingNode(t.Context(), EnsureNodeOptions{
			Target: ConnectionTarget{
				Selector:     "app.example.com",
				OriginalHost: "app",
				User:         "altuser",
				HasUser:      true,
			},
		}, func(lease2 PendingLease) error {
			if lease2.NodeID() != lease1.NodeID() || IsOpenSSHNodeID(lease2.NodeID()) {
				t.Fatalf("saved-derived concurrent lease IDs = (%q, %q), must stay non-openssh", lease1.NodeID(), lease2.NodeID())
			}
			snap, err := repo.ResolveConnection(lease2.NodeID())
			if err != nil {
				t.Fatalf("ResolveConnection: %v", err)
			}
			if snap.Provenance != ProvenanceAdHocPending {
				t.Fatalf("upgraded saved-derived Provenance = %s, want adhoc_pending", snap.Provenance)
			}
			return nil
		})
	}); err != nil {
		t.Fatalf("WithPendingNode: %v", err)
	}
}

func assertW18cGenuineOpenSSHAndNoSSHConfig(t *testing.T) {
	t.Parallel()
	repo := setupW18cSavedDerivedRepo(t)
	resSSH, err := repo.ResolveTarget(ConnectionTarget{Selector: "pure-ssh", User: "alt", HasUser: true})
	if err != nil {
		t.Fatalf("ResolveTarget(pure-ssh): %v", err)
	}
	if resSSH.Provenance != ProvenanceOpenSSHDerived {
		t.Fatalf("genuine OpenSSH alias Provenance = %s, want openssh_derived", resSSH.Provenance)
	}
	resCanonSSH, err := repo.ResolveTarget(ConnectionTarget{
		Selector:     "box.openssh-only.example.com",
		OriginalHost: "box",
		User:         "alt",
		HasUser:      true,
	})
	if err != nil {
		t.Fatalf("ResolveTarget(canonical pure openssh): %v", err)
	}
	if resCanonSSH.Provenance != ProvenanceOpenSSHDerived {
		t.Fatalf("genuine canonical OpenSSH Provenance = %s, want openssh_derived", resCanonSSH.Provenance)
	}

	noSSHRepo, err := NewRepositoryWithoutOpenSSH(cloneConfiguration(nil), &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}})
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	resNoSSH, err := noSSHRepo.ResolveTarget(ConnectionTarget{
		Selector:     "box.example.com",
		OriginalHost: "box",
		User:         "alt",
		HasUser:      true,
	})
	if err != nil {
		t.Fatalf("ResolveTarget(no ssh_config): %v", err)
	}
	if resNoSSH.Provenance != ProvenanceAdHocPending {
		t.Fatalf("raw target without ssh_config Provenance = %s, want adhoc_pending", resNoSSH.Provenance)
	}
}

func writeW18cEncryptedKey(t *testing.T, path, passphrase string) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	block, err := sshcrypto.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	if err != nil {
		t.Fatalf("MarshalPrivateKeyWithPassphrase: %v", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
	sshPub, err := sshcrypto.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	return sshcrypto.FingerprintSHA256(sshPub)
}

func TestP7W18c_L4_18_L1_PrivateKeyFingerprintRejectsNonConcreteIdentityPaths(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Chdir(cwd)

	const pass = "w18c-passphrase"
	// Create decoy encrypted keys in CWD with non-concrete names to prove
	// PrivateKeyFingerprint rejects them BEFORE attempting any file read.
	for _, decoy := range []string{"none", "NONE", "%h_key", "${HOME}_key"} {
		_ = writeW18cEncryptedKey(t, filepath.Join(cwd, decoy), pass)
	}
	decoyTildeDir := filepath.Join(cwd, "~nonexistent_w18c_user")
	if err := os.MkdirAll(decoyTildeDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	_ = writeW18cEncryptedKey(t, filepath.Join(decoyTildeDir, "id_ed25519"), pass)

	rejected := []string{
		"",
		"   ",
		"none",
		"NONE",
		"%h_key",
		"~/.ssh/%r_%h",
		"${HOME}_key",
		"${HOME}/id_ed25519",
		"~nonexistent_w18c_user/id_ed25519",
		"bad\npath",
	}
	for _, raw := range rejected {
		if fp, err := PrivateKeyFingerprint(raw, []byte(pass)); err == nil || fp != "" {
			t.Errorf("PrivateKeyFingerprint(%q) = (%q, %v), want error", raw, fp, err)
		}
		if _, err := BindPrivateKeyFingerprint(
			&Configuration{SchemaVersion: 2},
			credential.Target{Kind: credential.KindPassphrase, KeyPath: raw},
			[]byte(pass),
		); err == nil {
			t.Errorf("BindPrivateKeyFingerprint(%q) succeeded, want error", raw)
		}
	}

	// Concrete ~/ and ~\ paths still expand and compute the right fingerprint.
	wantFP := writeW18cEncryptedKey(t, filepath.Join(home, "id_w18c_ok"), pass)
	for _, valid := range []string{"~/id_w18c_ok", `~\id_w18c_ok`, filepath.Join(home, "id_w18c_ok")} {
		got, err := PrivateKeyFingerprint(valid, []byte(pass))
		if err != nil || got != wantFP {
			t.Fatalf("PrivateKeyFingerprint(%q) = (%q, %v), want (%q, nil)", valid, got, err, wantFP)
		}
	}
}

func buildW18cStoreParityV2Fixture(mutate func(*ConfigurationV2)) *ConfigurationV2 {
	v2 := &ConfigurationV2{
		SchemaVersion: 2,
		Credential: CredentialConfig{
			DefaultStore: "vault",
			Stores: map[string]StoreConfig{
				"vault": {Type: StoreTypeSystem},
			},
		},
		Hosts: map[string]models.Host{
			"h1": {Address: "10.18.0.1", Port: 22},
		},
		Identities: map[string]IdentityV2{
			"id1": {User: "ops", AuthType: "auto", KeyFingerprint: "SHA256:validfp"},
		},
		Nodes: map[string]NodeV2{
			"n1": {HostRef: "h1", IdentityRef: "id1"},
		},
	}
	if mutate != nil {
		mutate(v2)
	}
	return v2
}

func TestP7W18c_L4_18_L2_ValidateGraphAndNewRepositoryEnforceSchemaV2StoreExistence(t *testing.T) {
	t.Parallel()

	missingRef := &credential.Ref{StoreID: "missing-store", ItemID: "item-1"}
	validRef := &credential.Ref{StoreID: "vault", ItemID: "item-1"}

	refMutations := []struct {
		name      string
		mutateV2  func(*ConfigurationV2)
		mutateRaw func(*Configuration)
	}{
		{
			name: "login_password_ref",
			mutateV2: func(v2 *ConfigurationV2) {
				id := v2.Identities["id1"]
				id.LoginPasswordRef = missingRef.Clone()
				v2.Identities["id1"] = id
			},
			mutateRaw: func(cfg *Configuration) {
				id, _ := cfg.Identities.Get("id1")
				id.LoginPasswordRef = missingRef.Clone()
				cfg.Identities.Set("id1", id)
			},
		},
		{
			name: "passphrase_ref",
			mutateV2: func(v2 *ConfigurationV2) {
				id := v2.Identities["id1"]
				id.PassphraseRef = missingRef.Clone()
				v2.Identities["id1"] = id
			},
			mutateRaw: func(cfg *Configuration) {
				id, _ := cfg.Identities.Get("id1")
				id.PassphraseRef = missingRef.Clone()
				cfg.Identities.Set("id1", id)
			},
		},
		{
			name: "otp_totp_secret_ref",
			mutateV2: func(v2 *ConfigurationV2) {
				id := v2.Identities["id1"]
				id.OTP = &models.OTPConfig{TOTPSecretRef: missingRef.Clone()}
				v2.Identities["id1"] = id
			},
			mutateRaw: func(cfg *Configuration) {
				id, _ := cfg.Identities.Get("id1")
				id.OTP = &models.OTPConfig{TOTPSecretRef: missingRef.Clone()}
				cfg.Identities.Set("id1", id)
			},
		},
		{
			name: "challenge_rule_secret_ref",
			mutateV2: func(v2 *ConfigurationV2) {
				id := v2.Identities["id1"]
				id.KeyboardInteractive = &models.KeyboardInteractiveConfig{
					Rules: []models.ChallengeRule{{
						Name:          "tok",
						PromptPattern: "Token:",
						Source:        models.ChallengeSourceSecret,
						SecretRef:     missingRef.Clone(),
					}},
				}
				v2.Identities["id1"] = id
			},
			mutateRaw: func(cfg *Configuration) {
				id, _ := cfg.Identities.Get("id1")
				id.KeyboardInteractive = &models.KeyboardInteractiveConfig{
					Rules: []models.ChallengeRule{{
						Name:          "tok",
						PromptPattern: "Token:",
						Source:        models.ChallengeSourceSecret,
						SecretRef:     missingRef.Clone(),
					}},
				}
				cfg.Identities.Set("id1", id)
			},
		},
		{
			name: "node_privilege_password_ref",
			mutateV2: func(v2 *ConfigurationV2) {
				n := v2.Nodes["n1"]
				n.PrivilegePasswordRef = missingRef.Clone()
				v2.Nodes["n1"] = n
			},
			mutateRaw: func(cfg *Configuration) {
				n, _ := cfg.Nodes.Get("n1")
				n.PrivilegePasswordRef = missingRef.Clone()
				cfg.Nodes.Set("n1", n)
			},
		},
	}

	for _, tc := range refMutations {
		t.Run("missing_store_"+tc.name, func(t *testing.T) {
			t.Parallel()
			v2 := buildW18cStoreParityV2Fixture(tc.mutateV2)
			if err := ValidateV2(v2); !errors.Is(err, ErrSchemaValidation) {
				t.Fatalf("ValidateV2(%s) = %v, want ErrSchemaValidation", tc.name, err)
			}
			raw := configurationFromV2Unchecked(v2)
			if err := ValidateGraph(raw); !errors.Is(err, ErrSchemaValidation) {
				t.Fatalf("ValidateGraph(%s) = %v, want ErrSchemaValidation", tc.name, err)
			}
			if _, err := NewRepositoryWithoutOpenSSH(raw, &repositoryTestStore{}); !errors.Is(err, ErrSchemaValidation) {
				t.Fatalf("NewRepositoryWithoutOpenSSH(%s) = %v, want ErrSchemaValidation", tc.name, err)
			}

			// SchemaVersion 2 with nil Credential must also reject all 5 ref fields.
			rawNilCred := configurationFromV2Unchecked(buildW18cStoreParityV2Fixture(nil))
			rawNilCred.Credential = nil
			tc.mutateRaw(rawNilCred)
			if err := ValidateGraph(rawNilCred); !errors.Is(err, ErrSchemaValidation) {
				t.Fatalf("ValidateGraph(%s, nil Credential) = %v, want ErrSchemaValidation", tc.name, err)
			}
			if _, err := NewRepositoryWithoutOpenSSH(rawNilCred, &repositoryTestStore{}); !errors.Is(err, ErrSchemaValidation) {
				t.Fatalf("NewRepositoryWithoutOpenSSH(%s, nil Credential) = %v, want ErrSchemaValidation", tc.name, err)
			}
		})
	}

	t.Run("valid_configured_store_passes_all_validators", func(t *testing.T) {
		t.Parallel()
		v2 := buildW18cStoreParityV2Fixture(func(c *ConfigurationV2) {
			id := c.Identities["id1"]
			id.LoginPasswordRef = validRef.Clone()
			id.PassphraseRef = validRef.Clone()
			id.OTP = &models.OTPConfig{TOTPSecretRef: validRef.Clone()}
			id.KeyboardInteractive = &models.KeyboardInteractiveConfig{
				Rules: []models.ChallengeRule{{
					Name:          "tok",
					PromptPattern: "Token:",
					Source:        models.ChallengeSourceSecret,
					SecretRef:     validRef.Clone(),
				}},
			}
			c.Identities["id1"] = id
			n := c.Nodes["n1"]
			n.PrivilegePasswordRef = validRef.Clone()
			c.Nodes["n1"] = n
		})
		if err := ValidateV2(v2); err != nil {
			t.Fatalf("ValidateV2(valid) = %v", err)
		}
		cfg, err := FromV2(v2)
		if err != nil {
			t.Fatalf("FromV2(valid) = %v", err)
		}
		if err := ValidateGraph(cfg); err != nil {
			t.Fatalf("ValidateGraph(valid) = %v", err)
		}
		if _, err := NewRepositoryWithoutOpenSSH(cfg, &repositoryTestStore{}); err != nil {
			t.Fatalf("NewRepositoryWithoutOpenSSH(valid) = %v", err)
		}
	})
}
