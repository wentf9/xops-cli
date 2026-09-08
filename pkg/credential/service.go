package credential

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// GenerateItemID 生成全局唯一、不可变的 32 字符十六进制随机 ItemID。
func GenerateItemID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("item-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// Target 标识凭据写入或引用的目标实体（Node 或 Identity，以及凭据种类）。
type Target struct {
	NodeID     string `json:"nodeID,omitempty"`
	IdentityID string `json:"identityID,omitempty"`
	Kind       Kind   `json:"kind"`
}

// Validate 校验 Target 的完整性与合法性。
func (t Target) Validate() error {
	if t.NodeID == "" && t.IdentityID == "" {
		return fmt.Errorf("%w: target must specify nodeID or identityID", ErrInvalidRef)
	}
	return t.Kind.Validate()
}

// TargetIdentifier 返回目标的非敏感字符串标识。
func (t Target) TargetIdentifier() string {
	if t.NodeID != "" {
		return t.NodeID
	}
	return t.IdentityID
}

// MutationOutcome 描述配置提交的结果状态。
type MutationOutcome struct {
	Applied bool
	Durable bool
}

// ConfigUpdater 定义凭据服务所需的配置版本化 CAS 提交与引用检测契约。
// 该接口由配置仓库层（如 pkg/config.Repository 适配器）实现，避免包间循环引用。
type ConfigUpdater interface {
	// ApplyCredentialRefAtVersion 使用版本号对配置中的凭据引用进行 CAS 原子提交。
	// 若 newRef 为 nil，表示解除该字段凭据引用（用于删除）。
	// 若版本发生冲突，必须返回 ErrConfigConflict。
	// 若配置已替换但父目录未完成落盘同步，必须返回 DurabilityError 且 outcome.Applied = true, outcome.Durable = false。
	ApplyCredentialRefAtVersion(ctx context.Context, target Target, expectedVersion string, newRef *Ref) (outcome MutationOutcome, newVersion string, err error)

	// CheckRefUnreferenced 检查指定 ref 在当前最新已生效配置中是否已完全解绑（全局无任何引用）。
	CheckRefUnreferenced(ctx context.Context, ref Ref) (bool, error)

	// ConfirmRefDurable 从底层权威持久化存储重新检查指定 target 的凭据引用是否已持久化生效（Durable）。
	ConfirmRefDurable(ctx context.Context, target Target, ref *Ref) (bool, error)
}

// CleanupError 表示新凭据与新配置已经权威且持久化生效，但在删除旧凭据时失败。
// 该错误绝不能导致配置回滚，未清理的旧凭据将记录在 journal 中留待稍后后台 GC。
type CleanupError struct {
	OldRef Ref
	Err    error
}

func (e *CleanupError) Error() string {
	return fmt.Sprintf("credential update applied and durable, but cleaning up old credential %s failed: %v", e.OldRef, e.Err)
}

func (e *CleanupError) Unwrap() error {
	return e.Err
}

// RecoveryAction 描述崩溃恢复时采取的具体处置动作。
type RecoveryAction string

const (
	RecoveryActionCompensatedNewRef RecoveryAction = "compensated_new_ref"
	RecoveryActionCommittedCleaned  RecoveryAction = "committed_cleaned_old_ref"
	RecoveryActionScheduledForGC    RecoveryAction = "scheduled_for_gc"
	RecoveryActionRemovedNoOp       RecoveryAction = "removed_noop"
	RecoveryActionSkippedActive     RecoveryAction = "skipped_active"
)

// RecoveryResult 记录单条恢复操作的结果详情。
type RecoveryResult struct {
	EntryID string
	Op      OperationType
	Stage   Stage
	Action  RecoveryAction
	Err     error
}

// Service 协调凭据存储与配置引用的双存储原子写入、轮换、删除与崩溃恢复。
type Service struct {
	registry *Registry
	journal  *JournalStore
	config   ConfigUpdater
	cache    *Cache
	mu       sync.Mutex
	activeTx sync.Map // map[string]struct{} 跟踪本进程当前正在活跃执行的事务 ID
}

// NewService 创建双存储写入协调服务。
func NewService(registry *Registry, journal *JournalStore, config ConfigUpdater, cache *Cache) (*Service, error) {
	if registry == nil {
		return nil, fmt.Errorf("registry cannot be nil")
	}
	if journal == nil {
		return nil, fmt.Errorf("journal store cannot be nil")
	}
	if config == nil {
		return nil, fmt.Errorf("config updater cannot be nil")
	}
	return &Service{
		registry: registry,
		journal:  journal,
		config:   config,
		cache:    cache,
	}, nil
}

func (s *Service) getWritableStore(storeID string) (Store, error) {
	source, err := s.registry.Get(storeID)
	if err != nil {
		return nil, err
	}
	store, ok := source.(Store)
	if !ok {
		return nil, fmt.Errorf("%w: store %q is read-only", ErrCredentialStoreReadOnly, storeID)
	}
	return store, nil
}

// Rotate 执行凭据轮换事务：
// 1. 创建 journal intent，记录旧 ref、新 ref、配置前置版本和阶段；
// 2. Put(newRef, secret)；
// 3. Get(newRef) 读回并常量时间比较；
// 4. Repository 使用配置版本 CAS 切换到新 ref；
// 5. 配置 durable 后，将 journal 标记为 committed；
// 6. 确认旧 ref 当前无引用后删除；
// 7. 清除 journal。
func validateRotateParams(target Target, newStoreID string, oldRef *Ref, secret Secret) error {
	if err := target.Validate(); err != nil {
		return err
	}
	if len(secret.Value) == 0 {
		return fmt.Errorf("%w: secret value cannot be empty", ErrInvalidRef)
	}
	if err := validateRefIdentifier("storeID", newStoreID); err != nil {
		return err
	}
	if oldRef != nil && !oldRef.IsEmpty() {
		if err := oldRef.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) putAndVerifySecret(ctx context.Context, store Store, newRef Ref, secret Secret) error {
	if err := store.Put(ctx, newRef, secret); err != nil {
		return fmt.Errorf("put new credential %s: %w", newRef, err)
	}
	readBack, err := store.Get(ctx, newRef)
	if err != nil {
		return fmt.Errorf("readback verification failed for %s: %w", newRef, err)
	}
	match := subtle.ConstantTimeCompare(readBack.Value, secret.Value) == 1
	readBack.Zero()
	if !match {
		return fmt.Errorf("%w: readback credential content mismatch for %s", ErrCredentialStoreUnavailable, newRef)
	}
	return nil
}

func (s *Service) cleanupOldRefOnRotate(ctx context.Context, entryID string, oldRef *Ref) error {
	if oldRef == nil || oldRef.IsEmpty() {
		return nil
	}
	defer func() {
		if s.cache != nil {
			s.cache.Invalidate(*oldRef)
		}
	}()

	unref, checkErr := s.config.CheckRefUnreferenced(ctx, *oldRef)
	if checkErr != nil {
		_ = s.journal.MarkCleanup(entryID)
		return &CleanupError{OldRef: *oldRef, Err: fmt.Errorf("verify old ref unreferenced: %w", checkErr)}
	}
	if !unref {
		return nil
	}

	oldStore, getErr := s.getWritableStore(oldRef.StoreID)
	if getErr != nil {
		_ = s.journal.MarkCleanup(entryID)
		return &CleanupError{OldRef: *oldRef, Err: getErr}
	}
	if delErr := oldStore.Delete(ctx, *oldRef); delErr != nil && !errors.Is(delErr, ErrCredentialNotFound) {
		_ = s.journal.MarkCleanup(entryID)
		return &CleanupError{OldRef: *oldRef, Err: delErr}
	}
	return nil
}

func (s *Service) compensateNewRef(ctx context.Context, entryID string, store Store, newRef Ref, origErr error) error {
	delErr := store.Delete(context.WithoutCancel(ctx), newRef)
	if delErr != nil && !errors.Is(delErr, ErrCredentialNotFound) {
		return errors.Join(origErr, fmt.Errorf("compensate delete new ref %s failed: %w", newRef, delErr))
	}
	_ = s.journal.Remove(entryID)
	return origErr
}

// Rotate 执行凭据轮换事务：
// 1. 创建 journal intent，记录旧 ref、新 ref、配置前置版本和阶段；
// 2. Put(newRef, secret)；
// 3. Get(newRef) 读回并常量时间比较；
// 4. Repository 使用配置版本 CAS 切换到新 ref；
// 5. 配置 durable 后，将 journal 标记为 committed；
// 6. 确认旧 ref 当前无引用后删除；
// 7. 清除 journal。
func (s *Service) Rotate(
	ctx context.Context,
	target Target,
	expectedVersion string,
	oldRef *Ref,
	newStoreID string,
	secret Secret,
) (*Ref, string, error) {
	if err := validateRotateParams(target, newStoreID, oldRef, secret); err != nil {
		return nil, "", err
	}

	store, err := s.getWritableStore(newStoreID)
	if err != nil {
		return nil, "", err
	}

	newRef := Ref{
		StoreID: newStoreID,
		ItemID:  GenerateItemID(),
	}

	entryID := GenerateJournalID()
	s.activeTx.Store(entryID, struct{}{})
	defer s.activeTx.Delete(entryID)

	lock, lockErr := s.journal.AcquireEntryLock(entryID)
	if lockErr != nil {
		return nil, "", fmt.Errorf("acquire transaction lock: %w", lockErr)
	}
	defer func() {
		_ = lock.Close()
	}()

	entry := &JournalEntry{
		ID:             entryID,
		Op:             OpRotate,
		Stage:          StageIntent,
		OldRef:         oldRef.Clone(),
		NewRef:         newRef.Clone(),
		BaseVersion:    expectedVersion,
		TargetNode:     target.NodeID,
		TargetIdentity: target.IdentityID,
		TargetKind:     target.Kind,
	}
	if oldRef == nil || oldRef.IsEmpty() {
		entry.Op = OpCreate
	}
	if err := s.journal.RecordIntent(entry); err != nil {
		return nil, "", fmt.Errorf("record journal intent: %w", err)
	}

	if err := s.putAndVerifySecret(ctx, store, newRef, secret); err != nil {
		return nil, "", s.compensateNewRef(ctx, entry.ID, store, newRef, err)
	}

	outcome, newVersion, casErr := s.config.ApplyCredentialRefAtVersion(ctx, target, expectedVersion, &newRef)
	if casErr != nil {
		if !outcome.Applied {
			return nil, "", s.compensateNewRef(ctx, entry.ID, store, newRef, casErr)
		}
		// 配置在快照已应用但落盘失败（!outcome.Durable），推进至 StageAppliedUncertain，绝不能标为 StageCommitted，也不删除旧凭据
		_ = s.journal.MarkAppliedUncertain(entry.ID)
		return &newRef, newVersion, casErr
	}

	// 持久化提交成功，推进至 StageCommitted
	_ = s.journal.MarkCommitted(entry.ID)

	if err := s.cleanupOldRefOnRotate(ctx, entry.ID, oldRef); err != nil {
		return &newRef, newVersion, err
	}

	_ = s.journal.Remove(entry.ID)
	return &newRef, newVersion, nil
}

// Create 执行新增凭据事务（oldRef 为空）。
func (s *Service) Create(
	ctx context.Context,
	target Target,
	expectedVersion string,
	storeID string,
	secret Secret,
) (*Ref, string, error) {
	return s.Rotate(ctx, target, expectedVersion, nil, storeID, secret)
}

// Delete 执行删除凭据事务：
// 1. 记录 journal intent（OpDelete, StageIntent）；
// 2. Repository 先删除配置引用并 durable；
// 3. 确认没有任何引用；
// 4. 删除 Store 项；
// 5. 删除失败时保留 cleanup journal，不回滚配置。
func (s *Service) Delete(
	ctx context.Context,
	target Target,
	expectedVersion string,
	refToDelete Ref,
) (string, error) {
	if err := target.Validate(); err != nil {
		return "", err
	}
	if err := refToDelete.Validate(); err != nil {
		return "", err
	}
	if refToDelete.IsEmpty() {
		return "", fmt.Errorf("%w: cannot delete empty reference", ErrInvalidRef)
	}

	entryID := GenerateJournalID()
	s.activeTx.Store(entryID, struct{}{})
	defer s.activeTx.Delete(entryID)

	lock, lockErr := s.journal.AcquireEntryLock(entryID)
	if lockErr != nil {
		return "", fmt.Errorf("acquire transaction lock: %w", lockErr)
	}
	defer func() {
		_ = lock.Close()
	}()

	// 1. 记录 journal intent
	entry := &JournalEntry{
		ID:             entryID,
		Op:             OpDelete,
		Stage:          StageIntent,
		OldRef:         refToDelete.Clone(),
		NewRef:         nil,
		BaseVersion:    expectedVersion,
		TargetNode:     target.NodeID,
		TargetIdentity: target.IdentityID,
		TargetKind:     target.Kind,
	}
	if err := s.journal.RecordIntent(entry); err != nil {
		return "", fmt.Errorf("record journal intent: %w", err)
	}

	// 2. Repository 先从配置中移除凭据引用并确保 durable
	outcome, newVersion, casErr := s.config.ApplyCredentialRefAtVersion(ctx, target, expectedVersion, nil)
	if casErr != nil {
		if !outcome.Applied {
			// 配置未变，清除 journal intent
			_ = s.journal.Remove(entry.ID)
			return "", casErr
		}
		// Applied 但非 Durable，记录 StageAppliedUncertain，绝不能标为 StageCommitted，绝不删除后端凭据
		_ = s.journal.MarkAppliedUncertain(entry.ID)
		return newVersion, casErr
	}

	// 3. 配置已持久化删除引用，推进 journal
	_ = s.journal.MarkCommitted(entry.ID)

	// 4. 确认没有任何地方在引用该凭据
	unref, err := s.config.CheckRefUnreferenced(ctx, refToDelete)
	if err != nil {
		_ = s.journal.MarkCleanup(entry.ID)
		return newVersion, &CleanupError{OldRef: refToDelete, Err: fmt.Errorf("verify unreferenced: %w", err)}
	}
	if !unref {
		// 仍有其它位置引用，不删除后端物理条目，清除 journal
		_ = s.journal.Remove(entry.ID)
		return newVersion, nil
	}

	// 5. 删除 Store 项
	store, err := s.getWritableStore(refToDelete.StoreID)
	if err != nil {
		_ = s.journal.MarkCleanup(entry.ID)
		return newVersion, &CleanupError{OldRef: refToDelete, Err: err}
	}
	if err := store.Delete(ctx, refToDelete); err != nil {
		_ = s.journal.MarkCleanup(entry.ID)
		if s.cache != nil {
			s.cache.Invalidate(refToDelete)
		}
		return newVersion, &CleanupError{OldRef: refToDelete, Err: err}
	}

	if s.cache != nil {
		s.cache.Invalidate(refToDelete)
	}
	_ = s.journal.Remove(entry.ID)
	return newVersion, nil
}

// Recover 扫描未决的恢复日志条目并执行自动恢复或补偿：
// - StageIntent: 检查 NewRef 是否在配置中生效；若未生效，清理孤儿 NewRef 并删除日志；若已生效，推进至 StageCommitted；
// - StageAppliedUncertain: 重新从底层权威存储确认配置是否 Durable，若已持久化则推进至 StageCommitted，否则保持新旧凭据；
// - StageCommitted / StageCleanup: 确认 OldRef 已无引用后尝试删除后端条目，成功则删除日志，失败则保持/推进 StageCleanup。
func (s *Service) Recover(ctx context.Context) ([]RecoveryResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := s.journal.ListPending()
	if err != nil {
		return nil, fmt.Errorf("list pending journal entries: %w", err)
	}

	var results []RecoveryResult
	for _, entry := range entries {
		res := s.recoverSingleEntry(ctx, entry)
		results = append(results, res)
	}
	return results, nil
}

func (s *Service) recoverSingleEntry(ctx context.Context, entry JournalEntry) RecoveryResult {
	res := RecoveryResult{
		EntryID: entry.ID,
		Op:      entry.Op,
		Stage:   entry.Stage,
	}

	// 1. 检查同进程活跃事务
	if _, active := s.activeTx.Load(entry.ID); active {
		res.Action = RecoveryActionSkippedActive
		return res
	}

	// 2. 检查跨进程排他锁：若被外部活跃进程持有，跳过
	lock, err := s.journal.TryLockEntry(entry.ID)
	if err != nil {
		if errors.Is(err, ErrLockContended) {
			res.Action = RecoveryActionSkippedActive
			return res
		}
		res.Action = RecoveryActionScheduledForGC
		res.Err = fmt.Errorf("try lock entry: %w", err)
		return res
	}
	defer func() {
		_ = lock.Close()
	}()

	// 3. 根据阶段进行处理
	switch entry.Stage {
	case StageIntent:
		completed := s.recoverIntentStage(ctx, &entry, &res)
		if completed {
			return res
		}
		if entry.Stage == StageCommitted {
			s.recoverCommittedOrCleanupStage(ctx, &entry, &res)
		}
	case StageAppliedUncertain:
		completed := s.recoverAppliedUncertainStage(ctx, &entry, &res)
		if completed {
			return res
		}
		if entry.Stage == StageCommitted {
			s.recoverCommittedOrCleanupStage(ctx, &entry, &res)
		}
	case StageCommitted, StageCleanup:
		s.recoverCommittedOrCleanupStage(ctx, &entry, &res)
	}

	return res
}

func (s *Service) recoverAppliedUncertainStage(ctx context.Context, entry *JournalEntry, res *RecoveryResult) bool {
	target := entry.Target()
	var expectedRef *Ref
	if entry.Op == OpRotate || entry.Op == OpCreate {
		expectedRef = entry.NewRef
	}

	durable, err := s.config.ConfirmRefDurable(ctx, target, expectedRef)
	if err != nil {
		res.Err = fmt.Errorf("confirm durability for entry %s: %w", entry.ID, err)
		res.Action = RecoveryActionScheduledForGC
		return true
	}
	if !durable {
		res.Action = RecoveryActionScheduledForGC
		res.Err = fmt.Errorf("credential mutation for target %s is not durable in authoritative config", target.TargetIdentifier())
		return true
	}

	if err := s.journal.MarkCommitted(entry.ID); err != nil {
		res.Err = fmt.Errorf("mark committed after durability confirmed: %w", err)
		res.Action = RecoveryActionScheduledForGC
		return true
	}
	entry.Stage = StageCommitted
	return false
}

func (s *Service) recoverIntentStage(ctx context.Context, entry *JournalEntry, res *RecoveryResult) bool {
	if entry.NewRef != nil && !entry.NewRef.IsEmpty() {
		return s.recoverIntentWithNewRef(ctx, entry, res)
	}
	return s.recoverIntentWithoutNewRef(ctx, entry, res)
}

func (s *Service) recoverIntentWithNewRef(ctx context.Context, entry *JournalEntry, res *RecoveryResult) bool {
	unref, err := s.config.CheckRefUnreferenced(ctx, *entry.NewRef)
	if err != nil {
		res.Err = fmt.Errorf("check new ref: %w", err)
		res.Action = RecoveryActionScheduledForGC
		return true
	}
	if unref {
		store, storeErr := s.getWritableStore(entry.NewRef.StoreID)
		if storeErr != nil {
			res.Err = fmt.Errorf("get store %s for compensation: %w", entry.NewRef.StoreID, storeErr)
			res.Action = RecoveryActionScheduledForGC
			return true
		}
		if delErr := store.Delete(ctx, *entry.NewRef); delErr != nil && !errors.Is(delErr, ErrCredentialNotFound) {
			res.Err = fmt.Errorf("compensate delete new ref %s: %w", entry.NewRef, delErr)
			res.Action = RecoveryActionScheduledForGC
			return true
		}
		if s.cache != nil {
			s.cache.Invalidate(*entry.NewRef)
		}
		_ = s.journal.Remove(entry.ID)
		res.Action = RecoveryActionCompensatedNewRef
		return true
	}

	// 新凭据在配置中存在，进一步确认权威存储中是否 Durable
	durable, confErr := s.config.ConfirmRefDurable(ctx, entry.Target(), entry.NewRef)
	if confErr != nil {
		res.Err = fmt.Errorf("confirm new ref durability: %w", confErr)
		res.Action = RecoveryActionScheduledForGC
		return true
	}
	if !durable {
		_ = s.journal.MarkAppliedUncertain(entry.ID)
		entry.Stage = StageAppliedUncertain
		res.Action = RecoveryActionScheduledForGC
		return true
	}

	_ = s.journal.MarkCommitted(entry.ID)
	entry.Stage = StageCommitted
	return false
}

func (s *Service) recoverIntentWithoutNewRef(ctx context.Context, entry *JournalEntry, res *RecoveryResult) bool {
	if entry.OldRef == nil || entry.OldRef.IsEmpty() {
		_ = s.journal.Remove(entry.ID)
		res.Action = RecoveryActionRemovedNoOp
		return true
	}
	unref, err := s.config.CheckRefUnreferenced(ctx, *entry.OldRef)
	if err != nil {
		res.Err = fmt.Errorf("check old ref for delete: %w", err)
		res.Action = RecoveryActionScheduledForGC
		return true
	}
	if unref {
		durable, confErr := s.config.ConfirmRefDurable(ctx, entry.Target(), nil)
		if confErr != nil {
			res.Err = fmt.Errorf("confirm delete durability: %w", confErr)
			res.Action = RecoveryActionScheduledForGC
			return true
		}
		if !durable {
			_ = s.journal.MarkAppliedUncertain(entry.ID)
			entry.Stage = StageAppliedUncertain
			res.Action = RecoveryActionScheduledForGC
			return true
		}
		_ = s.journal.MarkCommitted(entry.ID)
		entry.Stage = StageCommitted
		return false
	}
	_ = s.journal.Remove(entry.ID)
	res.Action = RecoveryActionRemovedNoOp
	return true
}

func (s *Service) recoverCommittedOrCleanupStage(ctx context.Context, entry *JournalEntry, res *RecoveryResult) {
	if entry.OldRef == nil || entry.OldRef.IsEmpty() {
		_ = s.journal.Remove(entry.ID)
		res.Action = RecoveryActionRemovedNoOp
		return
	}

	unref, err := s.config.CheckRefUnreferenced(ctx, *entry.OldRef)
	if err != nil {
		res.Err = fmt.Errorf("check old ref unreferenced: %w", err)
		res.Action = RecoveryActionScheduledForGC
		return
	}
	if !unref {
		_ = s.journal.MarkCleanup(entry.ID)
		res.Action = RecoveryActionScheduledForGC
		res.Err = fmt.Errorf("old ref %s is still referenced or durability is uncertain", entry.OldRef)
		return
	}

	oldStore, err := s.getWritableStore(entry.OldRef.StoreID)
	if err != nil {
		_ = s.journal.MarkCleanup(entry.ID)
		res.Action = RecoveryActionScheduledForGC
		res.Err = err
		return
	}

	if err := oldStore.Delete(ctx, *entry.OldRef); err != nil && !errors.Is(err, ErrCredentialNotFound) {
		_ = s.journal.MarkCleanup(entry.ID)
		res.Action = RecoveryActionScheduledForGC
		res.Err = err
		return
	}

	if s.cache != nil {
		s.cache.Invalidate(*entry.OldRef)
	}
	_ = s.journal.Remove(entry.ID)
	res.Action = RecoveryActionCommittedCleaned
}

// GC 是 Recover 的别名，用于周期性触发或 CLI gc 命令执行未清理孤儿凭据回收。
func (s *Service) GC(ctx context.Context) ([]RecoveryResult, error) {
	return s.Recover(ctx)
}
