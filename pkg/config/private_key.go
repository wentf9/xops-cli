package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/wentf9/xops-cli/pkg/credential"
	sshcrypto "golang.org/x/crypto/ssh"
)

// PrivateKeyFingerprint verifies a private key and returns its public fingerprint.
// Key material is transient and never included in a returned configuration.
func PrivateKeyFingerprint(path string, passphrase []byte) (string, error) {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		path = filepath.Join(home, path[2:])
	}
	data, err := readPrivateKeyFile(path)
	if err != nil {
		return "", fmt.Errorf("read private key: %w", err)
	}
	defer clear(data)
	signer, err := sshcrypto.ParsePrivateKey(data)
	if err != nil {
		signer, err = sshcrypto.ParsePrivateKeyWithPassphrase(data, passphrase)
	}
	if err != nil {
		return "", fmt.Errorf("cannot unlock private key %q with supplied passphrase", path)
	}
	return sshcrypto.FingerprintSHA256(signer.PublicKey()), nil
}

// BindPrivateKeyFingerprint prepares v2 passphrase metadata before the caller
// enters a credential transaction. Legacy compatibility is unchanged.
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

// readPrivateKeyFile follows symbolic links like SSH authentication does.
// Check before opening to reject special files, then check the opened target
// again and bound the read in case its size changes. Recovery artifacts use
// readMigrationFile instead and continue to reject symlinks.
func readPrivateKeyFile(path string) (data []byte, retErr error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect private key %q: %w", path, err)
	}
	if err := validatePrivateKeyFile(info); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open private key %q: %w", path, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			clear(data)
			data = nil
			retErr = errors.Join(retErr, fmt.Errorf("close private key: %w", err))
		}
	}()
	info, err = file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened private key: %w", err)
	}
	if err := validatePrivateKeyFile(info); err != nil {
		return nil, err
	}
	data, err = io.ReadAll(io.LimitReader(file, privateKeyFileLimit+1))
	if err != nil {
		clear(data)
		return nil, fmt.Errorf("read private key: %w", err)
	}
	if len(data) > privateKeyFileLimit {
		clear(data)
		return nil, fmt.Errorf("private key exceeds 16 MiB")
	}
	return data, nil
}

func validatePrivateKeyFile(info os.FileInfo) error {
	if !info.Mode().IsRegular() || info.Size() > privateKeyFileLimit {
		return fmt.Errorf("private key target must be a regular file no larger than 16 MiB")
	}
	return nil
}
