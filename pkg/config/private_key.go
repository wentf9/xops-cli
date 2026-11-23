package config

import (
	"errors"
	"fmt"

	"github.com/wentf9/xops-cli/core/fsx"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/credential"
	sshcrypto "golang.org/x/crypto/ssh"
)

// PrivateKeyFingerprint verifies a private key and returns its public fingerprint.
// Key material is transient and never included in a returned configuration.
func PrivateKeyFingerprint(path string, passphrase []byte) (string, error) {
	setting, err := ssh.ParseIdentityPathSetting(path, true)
	if err != nil {
		return "", fmt.Errorf("invalid private key path: %w", err)
	}
	if setting.Unset() {
		return "", fmt.Errorf("private key path cannot be empty")
	}
	if setting.Disabled() || setting.IsTemplate() {
		return "", fmt.Errorf("private key path %q is not a concrete local file", setting.Raw)
	}
	resolved := NormalizePersistableIdentityPath(setting.Raw)
	if resolved == "" {
		return "", fmt.Errorf("private key path %q cannot be resolved to a local file", setting.Raw)
	}
	data, err := readPrivateKeyFile(resolved)
	if err != nil {
		return "", fmt.Errorf("read private key: %w", err)
	}
	defer clear(data)
	signer, err := sshcrypto.ParsePrivateKey(data)
	if err != nil {
		signer, err = sshcrypto.ParsePrivateKeyWithPassphrase(data, passphrase)
	}
	if err != nil {
		return "", fmt.Errorf("cannot unlock private key %q with supplied passphrase", resolved)
	}
	return sshcrypto.FingerprintSHA256(signer.PublicKey()), nil
}

// BindPrivateKeyFingerprint prepares v2 passphrase metadata before the caller
// enters a credential transaction. Migration resolves legacy metadata separately.
func BindPrivateKeyFingerprint(cfg *Configuration, target credential.Target, passphrase []byte) (credential.Target, error) {
	if cfg == nil || cfg.SchemaVersion != 2 || target.Kind != credential.KindPassphrase || len(passphrase) == 0 {
		return target, nil
	}
	fingerprint, err := PrivateKeyFingerprint(target.KeyPath, passphrase)
	if err != nil {
		return target, err
	}
	target.KeyFingerprint = fingerprint
	return target, nil
}

const privateKeyFileLimit = 16 << 20

// readPrivateKeyFile follows symbolic links like SSH authentication does while
// opening handle-first via core/fsx to reject non-regular files without blocking
// and bound reads to 16 MiB. Recovery artifacts use readMigrationFile instead
// and continue to reject symlinks.
func readPrivateKeyFile(path string) ([]byte, error) {
	data, err := fsx.ReadAllBounded(path, fsx.Limits{MaxBytes: privateKeyFileLimit}, fsx.FollowSymlinks())
	if err != nil {
		if errors.Is(err, fsx.ErrTooLarge) {
			return nil, fmt.Errorf("private key exceeds 16 MiB: %w", err)
		}
		if errors.Is(err, fsx.ErrNonRegular) {
			return nil, fmt.Errorf("private key target must be a regular file no larger than 16 MiB: %w", err)
		}
		return nil, fmt.Errorf("read private key %q: %w", path, err)
	}
	return data, nil
}
