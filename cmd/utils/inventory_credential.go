package utils

import (
	"context"
	"fmt"
	sshcrypto "golang.org/x/crypto/ssh"
	"os"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
)

// InventoryCredentialWrite keeps secret material outside inventory models.
// Metadata creation may precede Save; a failed Save never falls back to YAML.
type InventoryCredentialWrite struct {
	service *credential.Service
	updater credential.ConfigUpdater
	target  credential.Target
	oldRef  *credential.Ref
	storeID string
	secret  credential.Secret
}

// PrepareInventoryCredential validates the destination before metadata changes.
// A nil write means that neither a new secret nor a key replacement was supplied.
func PrepareInventoryCredential(repo *config.Repository, target credential.Target, identity models.Identity, password, passphrase, keyPath string, updater credential.ConfigUpdater) (*InventoryCredentialWrite, error) {
	if password == "" && passphrase == "" && keyPath == "" {
		return nil, nil
	}
	if password != "" && (passphrase != "" || keyPath != "") {
		return nil, fmt.Errorf("password and private-key authentication cannot be replaced together")
	}
	cfg := repo.Snapshot()
	credCfg := credentialConfigOrDefault(cfg)
	if password != "" || passphrase != "" {
		if err := validateInventoryCredentialStore(credCfg); err != nil {
			return nil, err
		}
	}
	oldRef := identity.LoginPasswordRef
	value := password
	target.ClearLegacyLoginPassword = true
	target.ClearLegacyPassphrase = true
	target.Kind = credential.KindLoginPassword
	target.AuthType = "password"
	target.ClearKeyPath = true
	if passphrase != "" || keyPath != "" {
		if keyPath == "" {
			keyPath = identity.KeyPath
		}
		if keyPath == "" {
			return nil, fmt.Errorf("private-key path is required for a passphrase")
		}
		target.Kind = credential.KindPassphrase
		target.AuthType = "key"
		target.KeyPath = ToAbsolutePath(keyPath)
		target.ClearKeyPath = false
		oldRef = identity.PassphraseRef
		value = passphrase
	}
	if password == "" && passphrase == "" {
		if err := validateUnencryptedKey(target.KeyPath); err != nil {
			return nil, err
		}
	}
	var bindErr error
	target, bindErr = config.BindPrivateKeyFingerprint(cfg, target, []byte(value))
	if bindErr != nil {
		return nil, bindErr
	}
	if updater == nil {
		updater = repo.AsConfigUpdater()
	}
	service, err := getCredentialService(repo, cfg, updater)
	if err != nil {
		return nil, err
	}
	return &InventoryCredentialWrite{service: service, updater: updater, target: target, oldRef: oldRef.Clone(), storeID: credCfg.DefaultStore, secret: credential.NewSecret([]byte(value))}, nil
}

// Clear releases the write's temporary secret on every caller return path.
func (w *InventoryCredentialWrite) Clear() {
	if w != nil {
		clear(w.secret.Value)
	}
}

// Save commits a secret and its authentication metadata using the exact
// version of the initial edit snapshot. Creation callers use the version of
// their preceding metadata creation. Key-only writes unlink old passphrases.
func (w *InventoryCredentialWrite) Save(ctx context.Context, version string) error {
	if w == nil {
		return nil
	}
	var err error
	if len(w.secret.Value) != 0 {
		_, _, err = w.service.Rotate(ctx, w.target, version, w.oldRef, w.storeID, w.secret)
	} else if w.oldRef != nil && !w.oldRef.IsEmpty() {
		_, err = w.service.Delete(ctx, w.target, version, *w.oldRef)
	} else {
		_, _, err = w.updater.ApplyCredentialRefAtVersion(ctx, w.target, version, nil)
	}
	if err != nil {
		return fmt.Errorf("save inventory credential: %w", err)
	}
	return nil
}

// WarnInventorySecretFlags covers both identity and host compatibility flags.
func WarnInventorySecretFlags(cmd *cobra.Command) {
	for _, flag := range []string{"password", "key-pass"} {
		if cmd.Flags().Changed(flag) {
			replacement := "identity credential set --password-stdin"
			if flag == "key-pass" {
				replacement = "identity credential set --kind passphrase --password-stdin"
			}
			WarnFlagDeprecated(flag, replacement)
		}
	}
}

func validateInventoryCredentialStore(cfg *config.CredentialConfig) error {
	store, ok := cfg.Stores[cfg.DefaultStore]
	if !ok {
		return fmt.Errorf("%w: configure a default credential store first", credential.ErrCredentialStoreUnavailable)
	}
	if store.Type == config.StoreTypeNone || store.ReadOnly {
		return fmt.Errorf("%w: configure a writable credential store before saving a secret", credential.ErrCredentialStoreReadOnly)
	}
	return nil
}

// Never discard a passphrase reference until the replacement key is known to
// work without one. ReadFile closes its file; clear the temporary key bytes.
func validateUnencryptedKey(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read replacement private key: %w", err)
	}
	defer clear(data)
	if _, err := sshcrypto.ParsePrivateKey(data); err != nil {
		return fmt.Errorf("replacement key must be an unencrypted private key, or supply --key-pass: %w", err)
	}
	return nil
}
