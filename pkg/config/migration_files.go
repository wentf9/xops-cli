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

	"github.com/wentf9/xops-cli/core/fsx"
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

func classifyMigrationReadError(path string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return err
	}
	if errors.Is(err, fsx.ErrTooLarge) {
		return fmt.Errorf("migration input exceeds 16 MiB: %w", err)
	}
	if errors.Is(err, fsx.ErrNonRegular) || errors.Is(err, fsx.ErrSymlink) {
		return fmt.Errorf("migration input %q must be a regular file no larger than 16 MiB: %w", path, err)
	}
	return fmt.Errorf("read migration input %q: %w", path, err)
}

func readMigrationFileWithInfo(path string) ([]byte, os.FileInfo, error) {
	rf, err := fsx.OpenRegular(path, fsx.Limits{MaxBytes: migrationFileLimit})
	if err != nil {
		return nil, nil, classifyMigrationReadError(path, err)
	}
	defer func() { _ = rf.Close() }()
	info, err := rf.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("stat migration input %q: %w", path, err)
	}
	data, err := rf.ReadAll()
	if err != nil {
		return nil, nil, classifyMigrationReadError(path, err)
	}
	return data, info, nil
}

func readMigrationFile(path string) ([]byte, error) {
	data, _, err := readMigrationFileWithInfo(path)
	return data, err
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
	stored, info, err := readMigrationFileWithInfo(path)
	if err == nil {
		defer clear(stored)
		if migrationDigest(stored) != migrationDigest(data) {
			return fmt.Errorf("existing migration backup %q differs from source", path)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
			return fmt.Errorf("migration backup %q must have mode 0600", path)
		}
		return fsx.SyncDir(filepath.Dir(path))
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

// Before deleting rollback material, verify and sync both the current file's
// contents and its directory on one no-follow, regular-file, os.SameFile-checked
// locked handle so no pathname swap can slip between digest check and fsync.
func readAndSyncMigrationConfiguration(ctx context.Context, path, expectedHash, conflictMsg string) (data []byte, retErr error) {
	lf, err := fsx.OpenLockedContext(ctx, path, fsx.LockExclusive, false, 0)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("open migrated configuration for sync: %w", err)
		}
		return nil, fmt.Errorf("open migrated configuration for sync: %w", classifyMigrationReadError(path, err))
	}
	defer func() { retErr = errors.Join(retErr, lf.Close()) }()
	info, err := lf.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat migrated configuration %q: %w", path, err)
	}
	if info.Size() > migrationFileLimit {
		return nil, fmt.Errorf("migration input exceeds 16 MiB: %w", fsx.ErrTooLarge)
	}
	current, err := io.ReadAll(io.LimitReader(lf, migrationFileLimit+1))
	if err != nil {
		return nil, fmt.Errorf("read migration input %q: %w", path, err)
	}
	if int64(len(current)) > migrationFileLimit {
		clear(current)
		return nil, fmt.Errorf("migration input exceeds 16 MiB: %w", fsx.ErrTooLarge)
	}
	if migrationDigest(current) != expectedHash {
		clear(current)
		return nil, fmt.Errorf("%w: %s", ErrConfigConflict, conflictMsg)
	}
	if err := lf.Sync(); err != nil {
		clear(current)
		return nil, fmt.Errorf("sync migrated configuration: %w", err)
	}
	if err := fsx.SyncDir(filepath.Dir(path)); err != nil {
		clear(current)
		return nil, err
	}
	return current, nil
}
