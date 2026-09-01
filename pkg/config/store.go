package config

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/pkg/crypto"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
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

type defaultStore struct {
	Path        string
	KeyPath     string // 用于加解密配置文件中的敏感字段
	mu          sync.Mutex
	writeFile   func(string, []byte, os.FileMode) error
	atomicWrite func(string, []byte, os.FileMode) (PersistResult, error)
}

const defaultConfigLockTimeout = 10 * time.Second

var _ TransactionStore = (*defaultStore)(nil)

// lockContext acquires a process-local mutex without making a context-aware
// caller wait indefinitely behind an in-process transaction. The file lock
// below remains responsible for cross-process serialization.
func lockContext(ctx context.Context, mu *sync.Mutex) error {
	if ctx == nil {
		return fmt.Errorf("configuration lock context is nil")
	}
	for {
		if mu.TryLock() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
}

// loadOrCreateKeyLocked loads the encryption key while the configuration lock
// is held. A missing key is created only for a new or plaintext configuration;
// generating a replacement for an encrypted file would make existing secrets
// permanently unreadable.
func (s *defaultStore) loadOrCreateKeyLocked(create bool) ([]byte, error) {
	key, err := os.ReadFile(s.KeyPath)
	if err == nil {
		if len(key) != crypto.KeySize {
			return nil, fmt.Errorf("invalid key file size in %q: expected %d, got %d", s.KeyPath, crypto.KeySize, len(key))
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read configuration key %q failed: %w", s.KeyPath, err)
	}
	if !create {
		return nil, fmt.Errorf("configuration key %q is missing for encrypted configuration: %w", s.KeyPath, err)
	}

	key = make([]byte, crypto.KeySize)
	if _, err := cryptorand.Read(key); err != nil {
		return nil, fmt.Errorf("generate configuration key failed: %w", err)
	}
	if _, err := atomicWriteFile(s.KeyPath, key, 0o600); err != nil {
		return nil, fmt.Errorf("write configuration key %q failed: %w", s.KeyPath, err)
	}
	return key, nil
}

func (s *defaultStore) Load() (cfg *Configuration, retErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), defaultConfigLockTimeout)
	defer cancel()
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
	if err := lockContext(ctx, &s.mu); err != nil {
		return Snapshot{}, fmt.Errorf("load configuration snapshot canceled before lock acquisition: %w", err)
	}
	defer s.mu.Unlock()
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
	if err := lockContext(ctx, &s.mu); err != nil {
		return CommitResult{}, fmt.Errorf("configuration transaction canceled before lock acquisition: %w", err)
	}
	defer s.mu.Unlock()
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
			return &configuration, nil
		}
		return nil, fmt.Errorf("failed to read configuration file %s: %w", s.Path, err)
	}
	// 2. yaml.Unmarshal
	if err = yaml.Unmarshal(data, &configuration); err != nil {
		return nil, fmt.Errorf("failed to unmarshal configuration: %w", err)
	}
	// 3. 初始化 Crypter 并解密敏感字段
	key, err := s.loadOrCreateKeyLocked(!bytes.Contains(data, []byte(crypto.Prefix)))
	if err != nil {
		return nil, fmt.Errorf("failed to load or generate decryption key: %w", err)
	}
	crypter, err := crypto.NewCrypter(key)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize decrypter: %w", err)
	}
	migratedIdentities, err := decryptIdentities(crypter, &configuration)
	if err != nil {
		return nil, err
	}
	migratedNodes, err := decryptNodes(crypter, &configuration)
	if err != nil {
		return nil, err
	}
	// 若配置文件中存在明文敏感字段，立即加密回写（一次性迁移）
	if migratedIdentities || migratedNodes {
		if _, err := s.saveLocked(&configuration); err != nil {
			return nil, fmt.Errorf("migrate plaintext configuration secrets failed: %w", err)
		}
	}
	return &configuration, nil
}

// decryptIdentities 解密所有 Identity 中的 Password 和 Passphrase 字段。
// 返回 true 表示发现了明文值（需要触发迁移保存）。
func decryptIdentities(crypter *crypto.Crypter, config *Configuration) (migrated bool, err error) {
	for _, name := range config.Identities.Keys() {
		identity, _ := config.Identities.Get(name)
		changed := false
		if identity.Password != "" {
			if crypto.IsEncrypted(identity.Password) {
				plain, decryptErr := crypter.Decrypt(identity.Password)
				if decryptErr != nil {
					return false, fmt.Errorf("decrypt identity %q password failed: %w", name, decryptErr)
				}
				identity.Password = plain
				changed = true
			} else {
				migrated = true // 明文，需加密回写
			}
		}
		if identity.Passphrase != "" {
			if crypto.IsEncrypted(identity.Passphrase) {
				plain, decryptErr := crypter.Decrypt(identity.Passphrase)
				if decryptErr != nil {
					return false, fmt.Errorf("decrypt identity %q passphrase failed: %w", name, decryptErr)
				}
				identity.Passphrase = plain
				changed = true
			} else {
				migrated = true
			}
		}
		if changed {
			config.Identities.Set(name, identity)
		}
	}
	return migrated, nil
}

// decryptNodes 解密所有 Node 中的 SuPwd 字段。
// 返回 true 表示发现了明文值（需要触发迁移保存）。
func decryptNodes(crypter *crypto.Crypter, config *Configuration) (migrated bool, err error) {
	for _, name := range config.Nodes.Keys() {
		node, _ := config.Nodes.Get(name)
		if node.SuPwd != "" {
			if crypto.IsEncrypted(node.SuPwd) {
				plain, decryptErr := crypter.Decrypt(node.SuPwd)
				if decryptErr != nil {
					return false, fmt.Errorf("decrypt node %q sudo password failed: %w", name, decryptErr)
				}
				node.SuPwd = plain
				config.Nodes.Set(name, node)
			} else {
				migrated = true // 明文，需加密回写
			}
		}
	}
	return migrated, nil
}

func (s *defaultStore) Save(cfg *Configuration) error {
	_, err := s.save(cfg)
	return err
}

func (s *defaultStore) save(cfg *Configuration) (result PersistResult, retErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), defaultConfigLockTimeout)
	defer cancel()
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
	// 初始化 Crypter
	key, err := s.loadOrCreateKeyLocked(true)
	if err != nil {
		return PersistResult{}, fmt.Errorf("failed to load or generate encryption key: %w", err)
	}
	crypter, err := crypto.NewCrypter(key)
	if err != nil {
		return PersistResult{}, fmt.Errorf("failed to initialize encrypter: %w", err)
	}

	// Serialize an encrypted private copy. Store.Save must never mutate caller
	// memory because snapshots can be read concurrently by the rest of the CLI.
	serialized := cloneConfiguration(cfg)
	_, _, err = encryptIdentities(crypter, serialized)
	if err != nil {
		return PersistResult{}, err
	}
	_, err = encryptNodes(crypter, serialized)
	if err != nil {
		return PersistResult{}, err
	}

	data, err := yaml.Marshal(serialized)
	if err != nil {
		return PersistResult{}, fmt.Errorf("failed to marshal configuration: %w", err)
	}
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

func encryptIdentities(crypter *crypto.Crypter, cfg *Configuration) (origPasswords, origPassphrases map[string]string, err error) {
	origPasswords = make(map[string]string)
	origPassphrases = make(map[string]string)
	for _, name := range cfg.Identities.Keys() {
		identity, _ := cfg.Identities.Get(name)
		if identity.Password != "" && !crypto.IsEncrypted(identity.Password) {
			origPasswords[name] = identity.Password
			enc, encryptErr := crypter.Encrypt(identity.Password)
			if encryptErr != nil {
				return origPasswords, origPassphrases, fmt.Errorf("encrypt identity %q password failed: %w", name, encryptErr)
			}
			identity.Password = enc
		}
		if identity.Passphrase != "" && !crypto.IsEncrypted(identity.Passphrase) {
			origPassphrases[name] = identity.Passphrase
			enc, encryptErr := crypter.Encrypt(identity.Passphrase)
			if encryptErr != nil {
				return origPasswords, origPassphrases, fmt.Errorf("encrypt identity %q passphrase failed: %w", name, encryptErr)
			}
			identity.Passphrase = enc
		}
		cfg.Identities.Set(name, identity)
	}
	return origPasswords, origPassphrases, nil
}

func encryptNodes(crypter *crypto.Crypter, cfg *Configuration) (map[string]string, error) {
	origSuPwds := make(map[string]string)
	for _, name := range cfg.Nodes.Keys() {
		node, _ := cfg.Nodes.Get(name)
		if node.SuPwd != "" && !crypto.IsEncrypted(node.SuPwd) {
			origSuPwds[name] = node.SuPwd
			enc, encryptErr := crypter.Encrypt(node.SuPwd)
			if encryptErr != nil {
				return origSuPwds, fmt.Errorf("encrypt node %q sudo password failed: %w", name, encryptErr)
			}
			node.SuPwd = enc
			cfg.Nodes.Set(name, node)
		}
	}
	return origSuPwds, nil
}

// NewDefaultStore 创建一个默认的文件系统配置存储实例
func NewDefaultStore(path string, keyPath string) Store {
	return &defaultStore{
		Path:    path,
		KeyPath: keyPath,
	}
}
