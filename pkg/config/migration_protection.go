package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// protectBackendKeys runs both during planning and immediately before cleanup.
// A backend key is live even when no current configuration ref uses that store.
func (m *CredentialMigrator) protectBackendKeys(cfg *CredentialConfig) error {
	if cfg == nil {
		return nil
	}
	reserved := []string{m.keyPath, m.backupPath(), m.backupKeyPath()}
	for _, st := range cfg.Stores {
		if st.Type != StoreTypeEncryptedFile || st.KeyFile == "" {
			continue
		}
		resolved, err := ResolveFileStore(st, m.path)
		if err != nil {
			return err
		}
		key, err := canonicalMigrationPath(resolved.KeyFile)
		if err != nil {
			return err
		}
		for _, path := range reserved {
			candidate, err := canonicalMigrationPath(path)
			if err != nil {
				return err
			}
			if key == candidate {
				return fmt.Errorf("%w: encrypted-file key overlaps legacy cleanup material", ErrConfigConflict)
			}
			a, ae := os.Stat(resolved.KeyFile)
			if ae != nil && !errors.Is(ae, os.ErrNotExist) {
				return ae
			}
			b, be := os.Stat(path)
			if be != nil && !errors.Is(be, os.ErrNotExist) {
				return be
			}
			if ae == nil && be == nil && os.SameFile(a, b) {
				return fmt.Errorf("%w: encrypted-file key aliases legacy cleanup material", ErrConfigConflict)
			}
		}
	}
	return nil
}

// Resolve existing ancestors too, so a not-yet-created backup name cannot hide
// an overlap behind a symlinked directory.
func canonicalMigrationPath(path string) (string, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	var suffix []string
	for {
		resolved, err := filepath.EvalSymlinks(path)
		if err == nil {
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return resolved, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(path)
		if parent == path {
			return "", err
		}
		suffix = append(suffix, filepath.Base(path))
		path = parent
	}
}

func (m *CredentialMigrator) protectFinalizationKeys(raw []byte) error {
	cfg, err := UnmarshalV2(raw)
	if err != nil {
		return err
	}
	return m.protectBackendKeys(&cfg.Credential)
}
