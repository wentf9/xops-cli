package credential

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// OperationType 定义凭据事务操作类型。
type OperationType string

const (
	// OpRotate 表示凭据轮换操作（旧引用切换为新引用）。
	OpRotate OperationType = "rotate"
	// OpDelete 表示凭据删除操作（删除现有引用及后端机密）。
	OpDelete OperationType = "delete"
	// OpCreate 表示新增凭据操作。
	OpCreate OperationType = "create"
	// OpAssetDelete tracks cleanup after an atomic inventory deletion. Recovery
	// checks global reference reachability because the target entity is gone.
	OpAssetDelete OperationType = "asset_delete"
)

// Stage 定义凭据事务日志所处的阶段。
type Stage string

const (
	// StageIntent 表示事务意图已记录，新凭据已写入但配置尚未原子提交。
	StageIntent Stage = "intent"
	// StageAppliedUncertain 表示配置变更已在快照应用，但父目录落盘同步不确定（Durability 失败）。
	// 在此阶段，新旧凭据均保留，绝不能删除旧凭据，也绝不能补偿删除新凭据。
	StageAppliedUncertain Stage = "applied_uncertain"
	// StageCommitted 表示配置变更已持久化生效，旧凭据待清理。
	StageCommitted Stage = "committed"
	// StageCleanup 表示旧凭据清理失败，留待稍后后台 GC。
	StageCleanup Stage = "cleanup"
)

// JournalEntry 记录凭据操作的恢复状态。
// 【安全红线】本结构严禁包含任何机密明文或可逆密文字节，仅记录非敏感的引用元数据与阶段。
type JournalEntry struct {
	ID                       string        `json:"id"`
	Op                       OperationType `json:"op"`
	Stage                    Stage         `json:"stage"`
	OldRef                   *Ref          `json:"oldRef,omitempty"`
	NewRef                   *Ref          `json:"newRef,omitempty"`
	BaseVersion              string        `json:"baseVersion,omitempty"`
	TargetNode               string        `json:"targetNode,omitempty"`
	TargetIdentity           string        `json:"targetIdentity,omitempty"`
	TargetKind               Kind          `json:"targetKind,omitempty"`
	KeyPath                  string        `json:"keyPath,omitempty"`
	KeyFingerprint           string        `json:"keyFingerprint,omitempty"`
	AuthType                 string        `json:"authType,omitempty"`
	ClearKeyPath             bool          `json:"clearKeyPath,omitempty"`
	ClearLegacyLoginPassword bool          `json:"clearLegacyLoginPassword,omitempty"`
	ClearLegacyPassphrase    bool          `json:"clearLegacyPassphrase,omitempty"`
	CreatedAt                time.Time     `json:"createdAt"`
	UpdatedAt                time.Time     `json:"updatedAt"`
}

// Target 返回与该日志条目关联的目标标识。
func (j *JournalEntry) Target() Target {
	if j == nil {
		return Target{}
	}
	return Target{
		NodeID:                   j.TargetNode,
		IdentityID:               j.TargetIdentity,
		Kind:                     j.TargetKind,
		KeyPath:                  j.KeyPath,
		KeyFingerprint:           j.KeyFingerprint,
		AuthType:                 j.AuthType,
		ClearKeyPath:             j.ClearKeyPath,
		ClearLegacyLoginPassword: j.ClearLegacyLoginPassword,
		ClearLegacyPassphrase:    j.ClearLegacyPassphrase,
	}
}

// Validate 校验 JournalEntry 基础合法性。
func (j *JournalEntry) Validate() error {
	if j == nil {
		return fmt.Errorf("%w: entry is nil", ErrJournalCorrupted)
	}
	if err := validateJournalID(j.ID); err != nil {
		return err
	}
	switch j.Op {
	case OpRotate, OpDelete, OpCreate, OpAssetDelete:
	default:
		return fmt.Errorf("%w: invalid operation %q", ErrJournalCorrupted, string(j.Op))
	}
	switch j.Stage {
	case StageIntent, StageAppliedUncertain, StageCommitted, StageCleanup:
	default:
		return fmt.Errorf("%w: invalid stage %q", ErrJournalCorrupted, string(j.Stage))
	}
	if j.OldRef != nil {
		if err := j.OldRef.Validate(); err != nil {
			return fmt.Errorf("%w: oldRef invalid: %w", ErrJournalCorrupted, err)
		}
	}
	if j.NewRef != nil {
		if err := j.NewRef.Validate(); err != nil {
			return fmt.Errorf("%w: newRef invalid: %w", ErrJournalCorrupted, err)
		}
	}
	if j.Op == OpAssetDelete && (j.OldRef == nil || j.OldRef.IsEmpty() || j.NewRef != nil) {
		return fmt.Errorf("%w: asset deletion requires only a nonempty old reference", ErrJournalCorrupted)
	}
	return nil
}

func isJournalIDRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_'
}

func validateJournalID(id string) error {
	trimmed := strings.TrimSpace(id)
	if trimmed == "" {
		return fmt.Errorf("%w: journal ID cannot be empty", ErrJournalCorrupted)
	}
	if len(id) > 128 {
		return fmt.Errorf("%w: journal ID %q too long (max 128 chars)", ErrJournalCorrupted, id)
	}
	for _, r := range id {
		if !isJournalIDRune(r) {
			return fmt.Errorf("%w: journal ID %q contains invalid characters", ErrJournalCorrupted, id)
		}
	}
	return nil
}

// JournalStore 管理非敏感凭据恢复日志文件的持久化与扫描。
type JournalStore struct {
	dir       string
	mu        sync.Mutex
	syncDirFn func(dir string) error
}

// NewJournalStore 创建一个日志存储管理器，确保目录存在且权限为 0700。
func NewJournalStore(dir string) (*JournalStore, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("journal directory cannot be empty")
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve journal directory: %w", err)
	}
	if err := os.MkdirAll(absDir, 0700); err != nil {
		return nil, fmt.Errorf("create journal directory: %w", err)
	}
	return &JournalStore{
		dir: absDir,
	}, nil
}

// GenerateJournalID 生成全局唯一的随机日志 ID。
func GenerateJournalID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("j-%d", time.Now().UnixNano())
	}
	return "j-" + hex.EncodeToString(b)
}

func (s *JournalStore) entryFilePath(id string) (string, error) {
	if err := validateJournalID(id); err != nil {
		return "", err
	}
	targetPath := filepath.Clean(filepath.Join(s.dir, fmt.Sprintf("journal-%s.json", id)))
	rel, err := filepath.Rel(s.dir, targetPath)
	if err != nil || strings.HasPrefix(rel, "..") || rel == "." {
		return "", fmt.Errorf("%w: journal ID %q escapes storage directory", ErrJournalCorrupted, id)
	}
	return targetPath, nil
}

// RecordIntent 记录操作意图。如果 entry.ID 为空，将自动生成唯一 ID。
func (s *JournalStore) RecordIntent(entry *JournalEntry) error {
	if entry == nil {
		return fmt.Errorf("journal entry is nil")
	}
	if entry.ID == "" {
		entry.ID = GenerateJournalID()
	}
	entry.Stage = StageIntent
	now := time.Now().UTC()
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = now
	}
	entry.UpdatedAt = now

	return s.save(entry)
}

// MarkAppliedUncertain 将日志状态推进至 StageAppliedUncertain（配置已应用但持久化不确定）。
func (s *JournalStore) MarkAppliedUncertain(id string) error {
	return s.updateStage(id, StageAppliedUncertain)
}

// MarkCommitted 将日志状态推进至 StageCommitted（配置已持久化提交）。
func (s *JournalStore) MarkCommitted(id string) error {
	return s.updateStage(id, StageCommitted)
}

// MarkCleanup 将日志状态推进至 StageCleanup（清理失败，标记待 GC）。
func (s *JournalStore) MarkCleanup(id string) error {
	return s.updateStage(id, StageCleanup)
}

func (s *JournalStore) lockFilePath(id string) (string, error) {
	if err := validateJournalID(id); err != nil {
		return "", err
	}
	targetPath := filepath.Clean(filepath.Join(s.dir, fmt.Sprintf("journal-%s.lock", id)))
	rel, err := filepath.Rel(s.dir, targetPath)
	if err != nil || strings.HasPrefix(rel, "..") || rel == "." {
		return "", fmt.Errorf("%w: journal ID %q escapes storage directory", ErrJournalCorrupted, id)
	}
	return targetPath, nil
}

// AcquireEntryLock 获取指定日志条目的排他文件锁。若已被持有，返回 ErrLockContended。
func (s *JournalStore) AcquireEntryLock(id string) (*EntryLock, error) {
	lockPath, err := s.lockFilePath(id)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file %q: %w", lockPath, err)
	}
	if err := tryLockFile(file); err != nil {
		_ = file.Close()
		if isLockContended(err) {
			return nil, ErrLockContended
		}
		return nil, fmt.Errorf("lock file %q: %w", lockPath, err)
	}
	return &EntryLock{path: lockPath, file: file}, nil
}

// TryLockEntry 尝试非阻塞获取日志条目排他锁，用于判定是否为活跃进程持有的在途事务。
func (s *JournalStore) TryLockEntry(id string) (*EntryLock, error) {
	return s.AcquireEntryLock(id)
}

func (s *JournalStore) updateStage(id string, stage Stage) error {
	if err := validateJournalID(id); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, err := s.readEntryLocked(id)
	if err != nil {
		return err
	}
	entry.Stage = stage
	entry.UpdatedAt = time.Now().UTC()

	return s.atomicWriteLocked(entry)
}

// Get 获取指定 ID 的日志项。
func (s *JournalStore) Get(id string) (*JournalEntry, error) {
	if err := validateJournalID(id); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readEntryLocked(id)
}

// Remove 成功完成清理或补偿后删除日志条目，并同步目录以保证 durability。
func (s *JournalStore) Remove(id string) error {
	if err := validateJournalID(id); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	p, err := s.entryFilePath(id)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove journal entry %q: %w", id, err)
	}
	if lockPath, err := s.lockFilePath(id); err == nil {
		_ = os.Remove(lockPath)
	}
	if err := s.syncDirLocked(); err != nil {
		return fmt.Errorf("sync journal directory after remove %q: %w", id, err)
	}
	return nil
}

// ListPending 扫描并返回所有未完成的日志条目（按创建时间升序排列）。
func (s *JournalStore) ListPending() ([]JournalEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("read journal directory: %w", err)
	}

	var results []JournalEntry
	for _, de := range entries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		if strings.HasPrefix(name, "journal-") && strings.HasSuffix(name, ".json") {
			id := strings.TrimSuffix(strings.TrimPrefix(name, "journal-"), ".json")
			if err := validateJournalID(id); err != nil {
				return nil, fmt.Errorf("%w: journal filename contains invalid ID %q", ErrJournalCorrupted, id)
			}
			entry, err := s.readEntryLocked(id)
			if err != nil {
				return nil, err
			}
			results = append(results, *entry)
		}
	}
	return results, nil
}

func (s *JournalStore) readEntryLocked(id string) (*JournalEntry, error) {
	p, err := s.entryFilePath(id)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: journal entry %q not found", ErrCredentialNotFound, id)
		}
		return nil, fmt.Errorf("read journal entry %q: %w", id, err)
	}

	var entry JournalEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("%w: parse journal entry %q: %w", ErrJournalCorrupted, id, err)
	}
	if err := entry.Validate(); err != nil {
		return nil, err
	}
	if entry.ID != id {
		return nil, fmt.Errorf("%w: journal ID mismatch (filename %q vs content %q)", ErrJournalCorrupted, id, entry.ID)
	}
	return &entry, nil
}

func (s *JournalStore) save(entry *JournalEntry) error {
	if err := entry.Validate(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.atomicWriteLocked(entry)
}

func (s *JournalStore) atomicWriteLocked(entry *JournalEntry) error {
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize journal entry %q: %w", entry.ID, err)
	}

	destPath, err := s.entryFilePath(entry.ID)
	if err != nil {
		return err
	}
	tmpPath := fmt.Sprintf("%s.tmp.%d", destPath, time.Now().UnixNano())

	// 权限 0600
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create journal temp file: %w", err)
	}

	var writeErr error
	if _, err := f.Write(data); err != nil {
		writeErr = fmt.Errorf("write journal temp file: %w", err)
	} else if err := f.Sync(); err != nil {
		writeErr = fmt.Errorf("sync journal temp file: %w", err)
	}

	if closeErr := f.Close(); closeErr != nil && writeErr == nil {
		writeErr = fmt.Errorf("close journal temp file: %w", closeErr)
	}

	if writeErr != nil {
		_ = os.Remove(tmpPath)
		return writeErr
	}

	// 原子替换
	if err := os.Rename(tmpPath, destPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("atomically rename journal file: %w", err)
	}

	if err := s.syncDirLocked(); err != nil {
		return fmt.Errorf("ensure journal file durability: %w", err)
	}
	return nil
}

func (s *JournalStore) syncDirLocked() error {
	if s.syncDirFn != nil {
		return s.syncDirFn(s.dir)
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	df, err := os.Open(s.dir)
	if err != nil {
		return fmt.Errorf("open journal directory for sync: %w", err)
	}
	var syncErr, closeErr error
	if err := df.Sync(); err != nil {
		syncErr = fmt.Errorf("sync journal directory: %w", err)
	}
	if err := df.Close(); err != nil {
		closeErr = fmt.Errorf("close journal directory: %w", err)
	}
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}
	return nil
}
