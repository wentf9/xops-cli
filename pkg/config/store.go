package config

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/pkg/models"
	"gopkg.in/yaml.v3"
)

// Store 定义了配置存储和持久化的接口
type Store interface {
	Load() (*Configuration, error)
	Save(cfg *Configuration) error
}

// Version identifies the exact serialized configuration observed by a
// transaction. It is the SHA-256 digest of the on-disk file bytes; the digest
// of an absent file is SHA-256 of an empty byte slice.
type Version [sha256.Size]byte

// Snapshot is a defensive plaintext configuration copy paired with its
// serialized version.
type Snapshot struct {
	Configuration *Configuration
	Version       Version
}

// CommitResult distinguishes pre-write failures from a replacement that was
// applied but whose crash durability is uncertain.
type CommitResult struct {
	Snapshot Snapshot
	Applied  bool
	Durable  bool
}

// TransactionStore atomically reloads, mutates, validates at the caller, and
// persists configuration while holding the cross-process configuration lock.
// Mutators must be CPU-only and must not perform I/O while the lock is held.
type TransactionStore interface {
	LoadSnapshot(ctx context.Context) (Snapshot, error)
	Transact(ctx context.Context, mutate func(Snapshot) (*Configuration, error)) (CommitResult, error)
}

// PersistResult describes the observable outcome of one configuration write.
// Applied means the destination pathname was replaced. Durable means the
// replacement was also synchronized to the parent directory.
//
// A write can be applied without being durable when the directory sync fails.
// Callers must not retry such a write blindly: the current process already
// observes the new file, while crash recovery durability is uncertain.
type PersistResult struct {
	Applied bool
	Durable bool
}

// Syncer 表示支持显式刷新文件与目录至持久介质的存储。
type Syncer interface {
	Sync(ctx context.Context) error
}

// DurabilityChecker 表示支持查询存储持久介质是否已真正耐久落盘的接口。
type DurabilityChecker interface {
	IsDurable() bool
}

type defaultStore struct {
	Path        string
	gate        contextGate
	writeFile   func(string, []byte, os.FileMode) error
	atomicWrite func(string, []byte, os.FileMode) (PersistResult, error)
}

const defaultConfigLockTimeout = 10 * time.Second

var (
	_ TransactionStore  = (*defaultStore)(nil)
	_ Syncer            = (*defaultStore)(nil)
	_ DurabilityChecker = (*defaultStore)(nil)
)

func (s *defaultStore) IsDurable() bool {
	return true
}

func (s *defaultStore) Sync(ctx context.Context) error {
	if s == nil || s.Path == "" {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.gate.acquire(ctx); err != nil {
		return fmt.Errorf("acquire in-process configuration lock for sync failed: %w", err)
	}
	defer s.gate.release()
	lock, err := acquireConfigLock(ctx, s.Path)
	if err != nil {
		return fmt.Errorf("acquire configuration lock for sync failed: %w", err)
	}
	defer func() {
		_ = lock.Close()
	}()
	dir := filepath.Dir(s.Path)
	return syncParentDirectory(dir)
}

// contextGate serializes in-process configuration access while allowing a
// waiting caller to leave immediately when its context is canceled.
type contextGate struct {
	once sync.Once
	sema chan struct{}
}

func (g *contextGate) acquire(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("configuration lock context is nil")
	}
	g.once.Do(func() { g.sema = make(chan struct{}, 1) })
	select {
	case g.sema <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (g *contextGate) release() {
	<-g.sema
}

func (s *defaultStore) Load() (cfg *Configuration, retErr error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultConfigLockTimeout)
	defer cancel()
	if err := s.gate.acquire(ctx); err != nil {
		return nil, fmt.Errorf("acquire in-process configuration lock for load failed: %w", err)
	}
	defer s.gate.release()
	lock, err := acquireConfigLock(ctx, s.Path)
	if err != nil {
		return nil, fmt.Errorf("acquire configuration lock for load failed: %w", err)
	}
	defer func() {
		if closeErr := lock.Close(); closeErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("release configuration lock after load failed: %w", closeErr))
		}
	}()
	return s.loadLocked()
}

// LoadSnapshot loads one stable plaintext view under the process-wide lock.
func (s *defaultStore) LoadSnapshot(ctx context.Context) (snapshot Snapshot, retErr error) {
	if ctx == nil {
		return Snapshot{}, fmt.Errorf("load configuration snapshot context is nil")
	}
	if err := s.gate.acquire(ctx); err != nil {
		return Snapshot{}, fmt.Errorf("load configuration snapshot canceled before lock acquisition: %w", err)
	}
	defer s.gate.release()
	if err := ctx.Err(); err != nil {
		return Snapshot{}, fmt.Errorf("load configuration snapshot canceled before lock acquisition: %w", err)
	}
	lock, err := acquireConfigLock(ctx, s.Path)
	if err != nil {
		return Snapshot{}, fmt.Errorf("acquire configuration lock for snapshot failed: %w", err)
	}
	defer func() {
		if closeErr := lock.Close(); closeErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("release configuration lock after snapshot failed: %w", closeErr))
		}
	}()
	cfg, err := s.loadLocked()
	if err != nil {
		return Snapshot{}, err
	}
	version, err := configurationVersion(s.Path)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Configuration: cfg, Version: version}, nil
}

// Transact reloads the newest configuration under the permanent lock, applies
// mutate, and writes the result before releasing the lock. A returned result
// with Applied set remains authoritative even when err is non-nil.
func (s *defaultStore) Transact(ctx context.Context, mutate func(Snapshot) (*Configuration, error)) (result CommitResult, retErr error) {
	if ctx == nil {
		return CommitResult{}, fmt.Errorf("transact configuration context is nil")
	}
	if mutate == nil {
		return CommitResult{}, fmt.Errorf("configuration transaction mutation is nil")
	}
	if err := s.gate.acquire(ctx); err != nil {
		return CommitResult{}, fmt.Errorf("configuration transaction canceled before lock acquisition: %w", err)
	}
	defer s.gate.release()
	if err := ctx.Err(); err != nil {
		return CommitResult{}, fmt.Errorf("configuration transaction canceled before lock acquisition: %w", err)
	}
	lock, err := acquireConfigLock(ctx, s.Path)
	if err != nil {
		return CommitResult{}, fmt.Errorf("acquire configuration lock for transaction failed: %w", err)
	}
	defer func() {
		if closeErr := lock.Close(); closeErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("release configuration lock after transaction failed: %w", closeErr))
		}
	}()
	if err := ctx.Err(); err != nil {
		return CommitResult{}, fmt.Errorf("configuration transaction canceled after lock acquisition: %w", err)
	}

	cfg, err := s.loadLocked()
	if err != nil {
		return CommitResult{}, err
	}
	version, err := configurationVersion(s.Path)
	if err != nil {
		return CommitResult{}, err
	}
	updated, err := mutate(Snapshot{Configuration: cloneConfiguration(cfg), Version: version})
	if err != nil {
		return CommitResult{}, err
	}
	// Cancellation is honored through preparation. Once saveLocked starts, the
	// atomic replacement must run to a real terminal outcome; reporting only a
	// cancellation after the pathname was replaced would make Applied unknown.
	if err := ctx.Err(); err != nil {
		return CommitResult{}, fmt.Errorf("configuration transaction canceled before persistence: %w", err)
	}
	persisted, err := s.saveLocked(updated)
	if !persisted.Applied {
		return CommitResult{}, err
	}
	newVersion, versionErr := configurationVersion(s.Path)
	if versionErr != nil {
		return CommitResult{Snapshot: Snapshot{Configuration: cloneConfiguration(updated)}, Applied: true, Durable: persisted.Durable}, errors.Join(err, versionErr)
	}
	result = CommitResult{
		Snapshot: Snapshot{Configuration: cloneConfiguration(updated), Version: newVersion},
		Applied:  true,
		Durable:  persisted.Durable,
	}
	if err != nil {
		return result, err
	}
	if !result.Durable {
		return result, fmt.Errorf("configuration store returned an incomplete durability result")
	}
	return result, nil
}

func configurationVersion(path string) (Version, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return sha256.Sum256(nil), nil
		}
		return Version{}, fmt.Errorf("read configuration for versioning failed: %w", err)
	}
	return sha256.Sum256(data), nil
}

func (s *defaultStore) loadLocked() (*Configuration, error) {
	configuration := Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	// 1. 读取文件
	data, err := os.ReadFile(s.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Only absent configurations receive new-install defaults. Existing
			// files must pass the Schema v2 check before becoming runtime state.
			configuration.SchemaVersion = 2
			configuration.Credential = DefaultCredentialConfig()
			return &configuration, nil
		}
		return nil, fmt.Errorf("failed to read configuration file %s: %w", s.Path, err)
	}
	version, err := DetectSchemaVersion(data)
	if err != nil {
		return nil, err
	}
	if err := ValidateRuntimeSchema(version); err != nil {
		return nil, err
	}
	dto, err := UnmarshalV2(data)
	if err != nil {
		return nil, err
	}
	return FromV2(dto)
}

func (s *defaultStore) Save(cfg *Configuration) error {
	_, err := s.save(cfg)
	return err
}

func (s *defaultStore) save(cfg *Configuration) (result PersistResult, retErr error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultConfigLockTimeout)
	defer cancel()
	if err := s.gate.acquire(ctx); err != nil {
		return PersistResult{}, fmt.Errorf("acquire in-process configuration lock for save failed: %w", err)
	}
	defer s.gate.release()
	lock, err := acquireConfigLock(ctx, s.Path)
	if err != nil {
		return PersistResult{}, fmt.Errorf("acquire configuration lock for save failed: %w", err)
	}
	defer func() {
		if closeErr := lock.Close(); closeErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("release configuration lock after save failed: %w", closeErr))
		}
	}()
	return s.saveLocked(cfg)
}

func (s *defaultStore) saveLocked(cfg *Configuration) (PersistResult, error) {
	if cfg == nil {
		return PersistResult{}, fmt.Errorf("configuration is nil")
	}
	version := cfg.SchemaVersion
	if version == 0 {
		version = 1
	}
	if err := ValidateRuntimeSchema(version); err != nil {
		return PersistResult{}, err
	}
	dto, err := cfg.ToV2()
	if err != nil {
		return PersistResult{}, err
	}
	data, err := yaml.Marshal(dto)
	if err != nil {
		return PersistResult{}, fmt.Errorf("encode schema v2: %w", err)
	}
	return s.writeConfigurationBytes(data)
}

func (s *defaultStore) writeConfigurationBytes(data []byte) (PersistResult, error) {
	writeFile := s.writeFile
	if writeFile != nil {
		if err := writeFile(s.Path, data, 0600); err != nil {
			return PersistResult{}, fmt.Errorf("write configuration file to %s failed: %w", s.Path, err)
		}
		return PersistResult{Applied: true, Durable: true}, nil
	}
	writeAtomic := s.atomicWrite
	if writeAtomic == nil {
		writeAtomic = atomicWriteFile
	}
	result, err := writeAtomic(s.Path, data, 0600)
	if err != nil {
		return result, fmt.Errorf("write configuration file to %s failed: %w", s.Path, err)
	}
	return result, nil
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) (result PersistResult, retErr error) {
	dir := filepath.Dir(path)
	if err := ensureParentDirectory(dir); err != nil {
		return PersistResult{}, fmt.Errorf("create parent directory %q failed: %w", dir, err)
	}

	temporary, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return PersistResult{}, fmt.Errorf("create temporary configuration file failed: %w", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		if !committed {
			if removeErr := os.Remove(temporaryPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				retErr = errors.Join(retErr, fmt.Errorf("remove temporary configuration file failed: %w", removeErr))
			}
		}
	}()
	temporaryClosed := false
	defer func() {
		if !temporaryClosed {
			if closeErr := temporary.Close(); closeErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("close temporary configuration file failed: %w", closeErr))
			}
		}
	}()

	if err := temporary.Chmod(perm); err != nil {
		return PersistResult{}, fmt.Errorf("set temporary configuration file permissions failed: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		return PersistResult{}, fmt.Errorf("write temporary configuration file failed: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return PersistResult{}, fmt.Errorf("sync temporary configuration file failed: %w", err)
	}
	if err := temporary.Close(); err != nil {
		temporaryClosed = true
		return PersistResult{}, fmt.Errorf("close temporary configuration file failed: %w", err)
	}
	temporaryClosed = true
	if err := replaceFile(temporaryPath, path); err != nil {
		return PersistResult{}, fmt.Errorf("replace configuration file failed: %w", err)
	}
	committed = true
	result.Applied = true

	if err := syncParentDirectory(dir); err != nil {
		return result, fmt.Errorf("sync configuration directory failed: %w", err)
	}
	result.Durable = true
	return result, nil
}

// ensureParentDirectory creates directory one component at a time and syncs
// the containing directory after every creation. The final directory itself is
// synced after the replacement in atomicWriteFile; syncing each parent here is
// what makes a newly-created directory chain survive a crash as well.
func ensureParentDirectory(directory string) error {
	return createDirectoryChain(directory, syncParentDirectory)
}

func createDirectoryChain(directory string, syncDirectory func(string) error) error {
	if syncDirectory == nil {
		return fmt.Errorf("sync directory function is nil")
	}

	missing := make([]string, 0)
	current := filepath.Clean(directory)
	for {
		info, err := os.Stat(current)
		if err == nil {
			if !info.IsDir() {
				return fmt.Errorf("parent path %q is not a directory", current)
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect parent directory %q failed: %w", current, err)
		}

		parent := filepath.Dir(current)
		if parent == current {
			return fmt.Errorf("find existing parent directory for %q failed", directory)
		}
		missing = append(missing, current)
		current = parent
	}

	for index := len(missing) - 1; index >= 0; index-- {
		created := missing[index]
		if err := os.Mkdir(created, 0o750); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create directory %q failed: %w", created, err)
		}
		info, err := os.Stat(created)
		if err != nil {
			return fmt.Errorf("inspect created directory %q failed: %w", created, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("created parent path %q is not a directory", created)
		}
		if err := syncDirectory(filepath.Dir(created)); err != nil {
			return fmt.Errorf("sync parent directory after creating %q failed: %w", created, err)
		}
	}

	return nil
}

// NewDefaultStore creates a Schema v2-only configuration store.
// keyPath is retained for source compatibility; legacy keys are used only by
// NewCredentialMigrator and are never read or created by this store.
func NewDefaultStore(path string, _ string) Store {
	return &defaultStore{Path: path}
}
