package utils

import (
	"path/filepath"
	"testing"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestP7W17c_L4_17_M1_PrepareInventoryCredentialPreservesHybridOnPassword(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XOPS_CONFIG_DIR", dir)
	t.Setenv("XOPS_JOURNAL_DIR", filepath.Join(dir, "journals"))

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.SchemaVersion = 2
	cfg.Credential = &config.CredentialConfig{
		DefaultStore: "helper",
		Stores: map[string]config.StoreConfig{
			"helper": {Type: config.StoreTypeHelper, Command: "/unused-helper"},
		},
	}
	store := config.NewDefaultStore(filepath.Join(dir, "xops_config.yaml"), filepath.Join(dir, "secret.key"))
	if err := store.Save(cfg); err != nil {
		t.Fatalf("store.Save: %v", err)
	}
	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}

	pwRef := &credential.Ref{StoreID: "helper", ItemID: "pw-old"}
	ppRef := &credential.Ref{StoreID: "helper", ItemID: "pp-keep"}

	for _, authType := range []string{"auto", "otp", "keyboard-interactive"} {
		t.Run("hybrid_"+authType, func(t *testing.T) {
			ident := models.Identity{
				User:             "ops",
				AuthType:         authType,
				KeyPath:          "/keys/id_ed25519",
				KeyFingerprint:   "SHA256:keep-fp",
				PassphraseRef:    ppRef.Clone(),
				LoginPasswordRef: pwRef.Clone(),
			}
			write, err := PrepareInventoryCredential(repo, credential.Target{NodeID: "ops@10.0.0.1:22"}, ident, "new-pw", "", "", nil)
			if err != nil {
				t.Fatalf("PrepareInventoryCredential(%q): %v", authType, err)
			}
			defer write.Clear()

			if write.target.AuthType != authType {
				t.Fatalf("target.AuthType = %q, want preserved %q", write.target.AuthType, authType)
			}
			if write.target.ClearKeyPath {
				t.Fatalf("target.ClearKeyPath = true for hybrid %q, want false", authType)
			}
			if write.target.ClearLegacyPassphrase {
				t.Fatalf("target.ClearLegacyPassphrase = true for hybrid %q, want false", authType)
			}
			if !write.target.ClearLegacyLoginPassword {
				t.Fatalf("target.ClearLegacyLoginPassword = false for hybrid %q, want true", authType)
			}
			if len(write.displacedRefs) != 0 {
				t.Fatalf("hybrid %q unexpectedly displaced refs: %+v", authType, write.displacedRefs)
			}
			if write.oldRef == nil || *write.oldRef != *pwRef {
				t.Fatalf("oldRef = %v, want %v", write.oldRef, pwRef)
			}
		})
	}

	t.Run("non_hybrid_key_switches_to_password_and_displaces_passphrase", func(t *testing.T) {
		ident := models.Identity{
			User:           "ops",
			AuthType:       "key",
			KeyPath:        "/keys/id_ed25519",
			KeyFingerprint: "SHA256:old-fp",
			PassphraseRef:  ppRef.Clone(),
		}
		write, err := PrepareInventoryCredential(repo, credential.Target{NodeID: "ops@10.0.0.2:22"}, ident, "switch-pw", "", "", nil)
		if err != nil {
			t.Fatalf("PrepareInventoryCredential(key): %v", err)
		}
		defer write.Clear()

		if write.target.AuthType != "password" || !write.target.ClearKeyPath || !write.target.ClearLegacyPassphrase {
			t.Fatalf("non-hybrid key->password target = %+v, want AuthType=password ClearKeyPath=true ClearLegacyPassphrase=true", write.target)
		}
		if len(write.displacedRefs) != 1 || write.displacedRefs[0] != *ppRef {
			t.Fatalf("displacedRefs = %+v, want [%v]", write.displacedRefs, *ppRef)
		}
	})
}
