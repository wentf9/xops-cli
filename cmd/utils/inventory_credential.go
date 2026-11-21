package utils

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	coreauth "github.com/wentf9/xops-cli/core/auth"
	"github.com/wentf9/xops-cli/core/fsx"
	coreSSH "github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/models"
	sshcrypto "golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// NormalizeIdentityKeyPath expands concrete literal key paths (~/ and relative
// paths) via config.NormalizePersistableIdentityPath while preserving OpenSSH
// templates (%tokens, ${VAR}), the "none" sentinel, and unresolved ~user
// prefixes without CWD mangling.
func NormalizeIdentityKeyPath(raw string) string {
	if abs := config.NormalizePersistableIdentityPath(raw); abs != "" {
		return abs
	}
	setting, err := coreSSH.ParseIdentityPathSetting(raw, true)
	if err != nil {
		if strings.TrimSpace(raw) == "" {
			return ""
		}
		// Preserve invalid syntax/control chars verbatim so downstream
		// validation fails closed instead of mangling or dropping the input.
		return raw
	}
	if setting.Unset() {
		return ""
	}
	return setting.Raw
}

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
		var err error
		target, err = preparePassphraseTarget(target, identity, keyPath, passphrase)
		if err != nil {
			return nil, err
		}
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

func preparePassphraseTarget(target credential.Target, identity models.Identity, keyPath, passphrase string) (credential.Target, error) {
	if keyPath == "" {
		keyPath = identity.KeyPath
	}
	if keyPath == "" {
		return target, fmt.Errorf("private-key path is required for a passphrase")
	}
	setting, err := coreSSH.ParseIdentityPathSetting(keyPath, true)
	if err != nil {
		return target, fmt.Errorf("invalid private-key path: %w", err)
	}
	target.Kind = credential.KindPassphrase
	target.AuthType = "key"
	target.KeyPath = NormalizeIdentityKeyPath(keyPath)
	target.ClearKeyPath = false
	if passphrase != "" && (setting.Disabled() || setting.IsTemplate()) {
		return target, fmt.Errorf("private-key passphrase cannot be bound to non-concrete key path %q", target.KeyPath)
	}
	return target, nil
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

func validateInventoryCredentialStore(cfg *config.CredentialConfig) error {
	store, ok := cfg.Stores[cfg.DefaultStore]
	if !ok {
		return fmt.Errorf("%w: configure a default credential store first", coreauth.ErrCredentialStoreUnavailable)
	}
	if store.Type == config.StoreTypeNone || store.ReadOnly {
		return fmt.Errorf("%w: configure a writable credential store before saving a secret", credential.ErrCredentialStoreReadOnly)
	}
	return nil
}

const maxPrivateKeyCheckBytes = 1 << 20 // 1 MiB

// Never discard a passphrase reference until the replacement key is known to
// work without one. Template paths (%tokens, ${VAR}) and "none" do not denote a
// concrete static on-disk file and skip local file parsing.
func validateUnencryptedKey(path string) error {
	setting, err := coreSSH.ParseIdentityPathSetting(path, true)
	if err != nil {
		return fmt.Errorf("invalid replacement private key path: %w", err)
	}
	if setting.Unset() {
		return fmt.Errorf("replacement private key path cannot be empty")
	}
	if setting.Disabled() || setting.IsTemplate() {
		return nil
	}
	resolved := config.NormalizePersistableIdentityPath(setting.Raw)
	if resolved == "" {
		return fmt.Errorf("replacement private key path %q cannot be resolved to a local file", setting.Raw)
	}
	// OpenSSH follows symlinks for user private keys; fsx.ReadAllBounded opens
	// handle-first without Stat-then-Open and rejects FIFOs/devices/oversize.
	data, err := fsx.ReadAllBounded(resolved, fsx.Limits{MaxBytes: maxPrivateKeyCheckBytes}, fsx.FollowSymlinks())
	if err != nil {
		return fmt.Errorf("read replacement private key: %w", err)
	}
	defer clear(data)
	if _, err := sshcrypto.ParsePrivateKey(data); err != nil {
		return fmt.Errorf("replacement key must be an unencrypted private key, or supply --passphrase-stdin: %w", err)
	}
	return nil
}

// KeyNeedsPassphrase checks whether the private key at path is encrypted and requires a passphrase.
// Template paths (%tokens, ${VAR}) and "none" are not concrete on-disk keys and return (false, nil).
func KeyNeedsPassphrase(path string) (bool, error) {
	setting, err := coreSSH.ParseIdentityPathSetting(path, true)
	if err != nil {
		return false, fmt.Errorf("invalid private key path: %w", err)
	}
	if setting.Unset() || setting.Disabled() || setting.IsTemplate() {
		return false, nil
	}
	resolved := config.NormalizePersistableIdentityPath(setting.Raw)
	if resolved == "" {
		return false, fmt.Errorf("private key path %q cannot be resolved to a local file", setting.Raw)
	}
	// OpenSSH follows symlinks for user private keys; fsx.ReadAllBounded opens
	// handle-first without Stat-then-Open and rejects FIFOs/devices/oversize.
	data, err := fsx.ReadAllBounded(resolved, fsx.Limits{MaxBytes: maxPrivateKeyCheckBytes}, fsx.FollowSymlinks())
	if err != nil {
		return false, err
	}
	defer clear(data)
	_, err = sshcrypto.ParsePrivateKey(data)
	if err == nil {
		return false, nil
	}
	var passMissing *sshcrypto.PassphraseMissingError
	if errors.As(err, &passMissing) {
		return true, nil
	}
	return false, nil
}

// PromptPassphraseIfEncryptedKey prompts for a passphrase on interactive terminals
// when keyPath points to an encrypted private key and no passphrase has been provided.
func PromptPassphraseIfEncryptedKey(keyPath, currentPassphrase string) (string, error) {
	if keyPath == "" || currentPassphrase != "" || !term.IsTerminal(int(os.Stdin.Fd())) {
		return currentPassphrase, nil
	}
	needs, err := KeyNeedsPassphrase(keyPath)
	if err != nil || !needs {
		return currentPassphrase, nil
	}
	resolved := NormalizeIdentityKeyPath(keyPath)
	return ReadPasswordFromTerminal(i18n.Tf("prompt_enter_passphrase", map[string]any{"Path": resolved}))
}
