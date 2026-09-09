package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/wentf9/xops-cli/pkg/credential"
)

const migrationFileLimit = 16 << 20

type migrationEntry struct {
	Identity string          `json:"identity,omitempty"`
	Node     string          `json:"node,omitempty"`
	Kind     credential.Kind `json:"kind"`
	Ref      credential.Ref  `json:"ref"`
}

// migrationState never contains secrets, key bytes, or hashes of individual
// secrets. File digests are used only for configuration CAS and backup checks.
type migrationState struct {
	Version       int              `json:"version"`
	Store         string           `json:"store"`
	SourceHash    string           `json:"sourceHash"`
	KeyHash       string           `json:"keyHash,omitempty"`
	CandidateHash string           `json:"candidateHash,omitempty"`
	Phase         string           `json:"phase"`
	Entries       []migrationEntry `json:"entries"`
}

func migrationDigest(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func readMigrationFile(path string) (data []byte, retErr error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > migrationFileLimit {
		return nil, fmt.Errorf("migration input %q must be a regular file no larger than 16 MiB", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open migration input %q: %w", path, err)
	}
	defer func() { retErr = errors.Join(retErr, f.Close()) }()
	data, err = io.ReadAll(io.LimitReader(f, migrationFileLimit+1))
	if err != nil {
		return nil, fmt.Errorf("read migration input %q: %w", path, err)
	}
	if len(data) > migrationFileLimit {
		clear(data)
		return nil, fmt.Errorf("migration input exceeds 16 MiB")
	}
	return data, nil
}

func (m *CredentialMigrator) withConfigLock(ctx context.Context, fn func() error) (retErr error) {
	lock, err := acquireConfigLock(ctx, m.path)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, lock.Close()) }()
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn()
}

func (m *CredentialMigrator) statePath() string     { return m.path + ".migration.json" }
func (m *CredentialMigrator) backupPath() string    { return m.path + ".v1.bak" }
func (m *CredentialMigrator) backupKeyPath() string { return m.path + ".v1.key.bak" }

func (m *CredentialMigrator) loadState() (*migrationState, error) {
	data, err := readMigrationFile(m.statePath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var state migrationState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("invalid migration state")
	}
	if state.Version != 1 || len(state.SourceHash) != 64 || state.Store == "" {
		return nil, fmt.Errorf("invalid migration state header")
	}
	switch state.Phase {
	case "intent", "committed", "verified", "finalizing", "complete":
	default:
		return nil, fmt.Errorf("invalid migration state phase")
	}
	for _, entry := range state.Entries {
		if err := entry.Ref.Validate(); err != nil {
			return nil, fmt.Errorf("invalid migration reference: %w", err)
		}
		if entry.Ref.IsEmpty() || entry.Ref.StoreID != state.Store {
			return nil, fmt.Errorf("migration reference does not match destination")
		}
	}
	return &state, nil
}

func (m *CredentialMigrator) saveState(state *migrationState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode migration state: %w", err)
	}
	result, err := m.write(m.statePath(), data, 0600)
	if err != nil {
		return fmt.Errorf("persist migration state: %w", err)
	}
	if !result.Durable {
		return fmt.Errorf("migration state is not durable")
	}
	return nil
}

func (m *CredentialMigrator) ensureBackup(path string, data []byte) error {
	stored, err := readMigrationFile(path)
	if err == nil {
		defer clear(stored)
		if migrationDigest(stored) != migrationDigest(data) {
			return fmt.Errorf("existing migration backup %q differs from source", path)
		}
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
			return fmt.Errorf("migration backup %q must have mode 0600", path)
		}
		return syncParentDirectory(filepath.Dir(path))
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	result, err := m.write(path, data, 0600)
	if err != nil {
		return fmt.Errorf("write migration backup: %w", err)
	}
	if !result.Durable {
		return fmt.Errorf("migration backup is not durable")
	}
	return nil
}

func (m *CredentialMigrator) step(name string) error {
	if m.checkpoint != nil {
		return m.checkpoint(name)
	}
	return nil
}

// Before deleting rollback material, sync both the current file's contents and
// its directory, including metadata edits made since the migration commit.
func syncMigrationConfiguration(path string) (retErr error) {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open migrated configuration for sync: %w", err)
	}
	defer func() { retErr = errors.Join(retErr, file.Close()) }()
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync migrated configuration: %w", err)
	}
	return syncParentDirectory(filepath.Dir(path))
}
