package credential

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type memoryStore struct {
	mu       sync.Mutex
	data     map[string][]byte
	putErr   error
	getErr   error
	delErr   error
	readBack []byte // 如果非空，Get 会返回此内容用于注入读回不一致
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		data: make(map[string][]byte),
	}
}

func (m *memoryStore) Get(_ context.Context, ref Ref) (Secret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getErr != nil {
		return Secret{}, m.getErr
	}
	if m.readBack != nil {
		return Secret{Value: bytes.Clone(m.readBack)}, nil
	}
	val, ok := m.data[ref.ItemID]
	if !ok {
		return Secret{}, fmt.Errorf("%w: %s", ErrCredentialNotFound, ref)
	}
	return Secret{Value: bytes.Clone(val)}, nil
}

func (m *memoryStore) Put(_ context.Context, ref Ref, secret Secret) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.putErr != nil {
		return m.putErr
	}
	m.data[ref.ItemID] = bytes.Clone(secret.Value)
	return nil
}

func (m *memoryStore) Delete(_ context.Context, ref Ref) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.delErr != nil {
		return m.delErr
	}
	if _, ok := m.data[ref.ItemID]; !ok {
		return fmt.Errorf("%w: %s", ErrCredentialNotFound, ref)
	}
	delete(m.data, ref.ItemID)
	return nil
}

func (m *memoryStore) List(_ context.Context) ([]Ref, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var refs []Ref
	for id := range m.data {
		refs = append(refs, Ref{StoreID: "test-store", ItemID: id})
	}
	return refs, nil
}

func (m *memoryStore) Ping(_ context.Context) error {
	return nil
}

type mockConfigUpdater struct {
	mu             sync.Mutex
	activeRefs     map[Ref]bool
	version        string
	applyErr       error
	applyOutcome   MutationOutcome
	applyHook      func(target Target, expectedVersion string, newRef *Ref) (MutationOutcome, string, error)
	checkUnrefHook func(ref Ref) (bool, error)
}

func newMockConfigUpdater() *mockConfigUpdater {
	return &mockConfigUpdater{
		activeRefs:   make(map[Ref]bool),
		version:      "version-1",
		applyOutcome: MutationOutcome{Applied: true, Durable: true},
	}
}

func (m *mockConfigUpdater) ApplyCredentialRefAtVersion(
	_ context.Context,
	target Target,
	expectedVersion string,
	newRef *Ref,
) (MutationOutcome, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.applyHook != nil {
		return m.applyHook(target, expectedVersion, newRef)
	}
	if m.applyErr != nil {
		return m.applyOutcome, "", m.applyErr
	}
	if expectedVersion != "" && expectedVersion != m.version {
		return MutationOutcome{Applied: false, Durable: false}, "", fmt.Errorf("config conflict: expected %s, got %s", expectedVersion, m.version)
	}
	if newRef != nil {
		m.activeRefs[*newRef] = true
	}
	m.version = "version-" + GenerateItemID()[:8]
	return m.applyOutcome, m.version, nil
}

func (m *mockConfigUpdater) CheckRefUnreferenced(_ context.Context, ref Ref) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.checkUnrefHook != nil {
		return m.checkUnrefHook(ref)
	}
	isRef, ok := m.activeRefs[ref]
	return !ok || !isRef, nil
}

func setupTestService(t *testing.T) (*Service, *memoryStore, *mockConfigUpdater, *JournalStore, *Cache) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "journals")
	journal, err := NewJournalStore(dir)
	if err != nil {
		t.Fatalf("NewJournalStore failed: %v", err)
	}
	reg := NewRegistry()
	store := newMemoryStore()
	if err := reg.Register("test-store", store); err != nil {
		t.Fatalf("reg.Register failed: %v", err)
	}
	cfg := newMockConfigUpdater()
	cache := NewCache(CacheOptions{Capacity: 16, DefaultTTL: time.Minute})
	svc, err := NewService(reg, journal, cfg, cache)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}
	return svc, store, cfg, journal, cache
}

// ---------------- 正常场景测试 ----------------

func TestService_Create_Success(t *testing.T) {
	svc, store, cfg, journal, _ := setupTestService(t)
	ctx := context.Background()

	target := Target{NodeID: "node-1", Kind: KindLoginPassword}
	secret := Secret{Value: []byte("pass123")}

	newRef, newVer, err := svc.Create(ctx, target, "version-1", "test-store", secret)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if newRef == nil || newRef.IsEmpty() {
		t.Fatalf("expected non-empty newRef")
	}
	if newVer == "" {
		t.Fatalf("expected non-empty newVer")
	}

	// 验证 Store 中存在机密
	stored, err := store.Get(ctx, *newRef)
	if err != nil {
		t.Fatalf("store.Get failed: %v", err)
	}
	if !bytes.Equal(stored.Value, secret.Value) {
		t.Fatalf("stored value mismatch: got %q, want %q", stored.Value, secret.Value)
	}

	// 验证配置中已引用
	unref, err := cfg.CheckRefUnreferenced(ctx, *newRef)
	if err != nil || unref {
		t.Fatalf("expected newRef to be referenced, unref=%v, err=%v", unref, err)
	}

	// 验证 Journal 已经清理
	entries, err := journal.ListPending()
	if err != nil {
		t.Fatalf("ListPending failed: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected journal to be cleared, got %d entries", len(entries))
	}
}

func TestService_Rotate_Success(t *testing.T) {
	svc, store, cfg, journal, cache := setupTestService(t)
	ctx := context.Background()

	// 先放一个旧凭据
	oldRef := Ref{StoreID: "test-store", ItemID: "old-secret-item"}
	_ = store.Put(ctx, oldRef, Secret{Value: []byte("old-secret")})
	cfg.activeRefs[oldRef] = true
	cache.Put(oldRef, Secret{Value: []byte("old-secret")})

	target := Target{NodeID: "node-1", Kind: KindLoginPassword}
	newSecret := Secret{Value: []byte("new-secret")}

	// 解除 oldRef 的配置引用（模拟配置切换到 newRef）
	cfg.applyHook = func(t Target, expectedVersion string, newRef *Ref) (MutationOutcome, string, error) {
		delete(cfg.activeRefs, oldRef)
		if newRef != nil {
			cfg.activeRefs[*newRef] = true
		}
		return MutationOutcome{Applied: true, Durable: true}, "version-2", nil
	}

	newRef, newVer, err := svc.Rotate(ctx, target, "version-1", &oldRef, "test-store", newSecret)
	if err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}
	if newRef == nil || newRef.ItemID == oldRef.ItemID {
		t.Fatalf("expected different newRef, got %v", newRef)
	}
	if newVer != "version-2" {
		t.Fatalf("expected version-2, got %s", newVer)
	}

	// 验证旧凭据从 Store 中被删除
	_, err = store.Get(ctx, oldRef)
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("expected oldRef to be deleted, got err=%v", err)
	}

	// 验证旧凭据缓存已失效
	_, inCache := cache.Get(oldRef)
	if inCache {
		t.Fatalf("expected oldRef to be invalidated from cache")
	}

	// 验证新凭据正常存入
	storedNew, err := store.Get(ctx, *newRef)
	if err != nil {
		t.Fatalf("store.Get(newRef) failed: %v", err)
	}
	if !bytes.Equal(storedNew.Value, newSecret.Value) {
		t.Fatalf("new secret value mismatch")
	}

	// 验证 Journal 已经清理
	entries, _ := journal.ListPending()
	if len(entries) != 0 {
		t.Fatalf("expected journal to be cleared, got %d entries", len(entries))
	}
}

func TestService_Delete_Success(t *testing.T) {
	svc, store, cfg, journal, cache := setupTestService(t)
	ctx := context.Background()

	refToDelete := Ref{StoreID: "test-store", ItemID: "to-delete-item"}
	_ = store.Put(ctx, refToDelete, Secret{Value: []byte("delete-me")})
	cfg.activeRefs[refToDelete] = true
	cache.Put(refToDelete, Secret{Value: []byte("delete-me")})

	cfg.applyHook = func(t Target, expectedVersion string, newRef *Ref) (MutationOutcome, string, error) {
		delete(cfg.activeRefs, refToDelete)
		return MutationOutcome{Applied: true, Durable: true}, "version-deleted", nil
	}

	target := Target{NodeID: "node-1", Kind: KindLoginPassword}
	newVer, err := svc.Delete(ctx, target, "version-1", refToDelete)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if newVer != "version-deleted" {
		t.Fatalf("expected version-deleted, got %s", newVer)
	}

	// 验证 Store 中的条目被删除
	_, err = store.Get(ctx, refToDelete)
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("expected deleted item, got %v", err)
	}

	// 验证缓存已失效
	_, inCache := cache.Get(refToDelete)
	if inCache {
		t.Fatalf("expected cache invalidated")
	}

	// 验证 Journal 已经清理
	entries, _ := journal.ListPending()
	if len(entries) != 0 {
		t.Fatalf("expected journal to be cleared")
	}
}

func TestService_Delete_StillReferenced_KeepsStoreItem(t *testing.T) {
	svc, store, cfg, journal, _ := setupTestService(t)
	ctx := context.Background()

	refShared := Ref{StoreID: "test-store", ItemID: "shared-item"}
	_ = store.Put(ctx, refShared, Secret{Value: []byte("shared-secret")})

	// 模拟虽然 node-1 解除了引用，但 node-2 依然引用该 refShared
	cfg.checkUnrefHook = func(ref Ref) (bool, error) {
		return false, nil // 仍有引用
	}

	target := Target{NodeID: "node-1", Kind: KindLoginPassword}
	_, err := svc.Delete(ctx, target, "version-1", refShared)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Store 中的物理机密不能被删除！
	_, err = store.Get(ctx, refShared)
	if err != nil {
		t.Fatalf("expected store item to be preserved for other nodes, got %v", err)
	}

	// Journal 应当被清除（非错误情况）
	entries, _ := journal.ListPending()
	if len(entries) != 0 {
		t.Fatalf("expected journal to be cleared")
	}
}

// ---------------- 故障注入矩阵测试 ----------------

func TestService_FaultInjection_IntentWriteFailure(t *testing.T) {
	svc, store, _, _, _ := setupTestService(t)
	ctx := context.Background()

	// 使 journal 目录不可写或指向只读文件来注入 RecordIntent 失败
	_ = os.RemoveAll(svc.journal.dir)
	// 将 journal.dir 变成一个只读普通文件，使写入失败
	_ = os.WriteFile(svc.journal.dir, []byte("blocker"), 0400)

	target := Target{NodeID: "node-1", Kind: KindLoginPassword}
	_, _, err := svc.Create(ctx, target, "version-1", "test-store", Secret{Value: []byte("secret")})
	if err == nil {
		t.Fatal("expected error on intent write failure, got nil")
	}

	// 验证 Store 中没有任何新项写入
	list, _ := store.List(ctx)
	if len(list) != 0 {
		t.Fatalf("Store must not contain any items when intent fails")
	}
}

func TestService_FaultInjection_PutFailureOrTimeout(t *testing.T) {
	svc, store, _, journal, _ := setupTestService(t)
	ctx := context.Background()

	store.putErr = errors.New("backend connection timeout")

	target := Target{NodeID: "node-1", Kind: KindLoginPassword}
	_, _, err := svc.Create(ctx, target, "version-1", "test-store", Secret{Value: []byte("secret")})
	if err == nil {
		t.Fatal("expected error on Put failure")
	}

	// 验证 Store 中无孤儿条目
	list, _ := store.List(ctx)
	if len(list) != 0 {
		t.Fatalf("expected no orphan items in store, got %d", len(list))
	}

	// 验证 journal intent 已被清理
	entries, _ := journal.ListPending()
	if len(entries) != 0 {
		t.Fatalf("expected journal to be cleared on Put failure, got %d", len(entries))
	}
}

func TestService_FaultInjection_ReadBackMismatch(t *testing.T) {
	svc, store, _, journal, _ := setupTestService(t)
	ctx := context.Background()

	// 注入读回篡改数据
	store.readBack = []byte("corrupted-secret-value")

	target := Target{NodeID: "node-1", Kind: KindLoginPassword}
	_, _, err := svc.Create(ctx, target, "version-1", "test-store", Secret{Value: []byte("original-secret")})
	if err == nil {
		t.Fatal("expected readback mismatch error, got nil")
	}

	// 验证新写入的凭据被补偿删除
	store.mu.Lock()
	count := len(store.data)
	store.mu.Unlock()
	if count != 0 {
		t.Fatalf("expected compensation delete of corrupted item, store count: %d", count)
	}

	// 验证 journal 已清除
	entries, _ := journal.ListPending()
	if len(entries) != 0 {
		t.Fatalf("expected journal cleared on readback mismatch")
	}
}

func TestService_FaultInjection_ConfigCASConflict(t *testing.T) {
	svc, store, cfg, journal, _ := setupTestService(t)
	ctx := context.Background()

	casConflictErr := errors.New("configuration revision conflict")
	cfg.applyErr = casConflictErr
	cfg.applyOutcome = MutationOutcome{Applied: false, Durable: false}

	target := Target{NodeID: "node-1", Kind: KindLoginPassword}
	_, _, err := svc.Create(ctx, target, "version-1", "test-store", Secret{Value: []byte("secret")})
	if !errors.Is(err, casConflictErr) {
		t.Fatalf("expected casConflictErr, got %v", err)
	}

	// 验证补偿删除了 Store 中的新凭据
	store.mu.Lock()
	count := len(store.data)
	store.mu.Unlock()
	if count != 0 {
		t.Fatalf("new credential must be compensated and deleted on CAS conflict")
	}

	// 验证 journal intent 已清除
	entries, _ := journal.ListPending()
	if len(entries) != 0 {
		t.Fatalf("expected journal cleared on CAS conflict")
	}
}

func TestService_FaultInjection_ConfigNotApplied(t *testing.T) {
	svc, store, cfg, journal, _ := setupTestService(t)
	ctx := context.Background()

	validationErr := errors.New("validation error: invalid host reference")
	cfg.applyErr = validationErr
	cfg.applyOutcome = MutationOutcome{Applied: false, Durable: false}

	target := Target{NodeID: "node-1", Kind: KindLoginPassword}
	_, _, err := svc.Create(ctx, target, "version-1", "test-store", Secret{Value: []byte("secret")})
	if !errors.Is(err, validationErr) {
		t.Fatalf("expected validationErr, got %v", err)
	}

	// 验证补偿删除新凭据
	store.mu.Lock()
	count := len(store.data)
	store.mu.Unlock()
	if count != 0 {
		t.Fatalf("new credential must be compensated when config not applied")
	}

	entries, _ := journal.ListPending()
	if len(entries) != 0 {
		t.Fatalf("expected journal cleared when config not applied")
	}
}

func TestService_FaultInjection_AppliedButParentDirSyncFailed(t *testing.T) {
	svc, store, cfg, journal, _ := setupTestService(t)
	ctx := context.Background()

	// 模拟 Applied 但非 Durable（DurabilityError）
	durErr := errors.New("parent directory sync failed")
	cfg.applyErr = durErr
	cfg.applyOutcome = MutationOutcome{Applied: true, Durable: false}

	target := Target{NodeID: "node-1", Kind: KindLoginPassword}
	newRef, _, err := svc.Create(ctx, target, "version-1", "test-store", Secret{Value: []byte("secret")})
	if !errors.Is(err, durErr) {
		t.Fatalf("expected durErr, got %v", err)
	}
	if newRef == nil {
		t.Fatalf("expected newRef to be returned on DurabilityError")
	}

	// 【核心红线断言】：Applied 但非 Durable 时，新凭据绝不能被补偿删除！
	store.mu.Lock()
	_, exists := store.data[newRef.ItemID]
	store.mu.Unlock()
	if !exists {
		t.Fatalf("new credential must NOT be deleted when config is Applied")
	}

	// Journal 必须被推进到 StageCommitted
	entries, err := journal.ListPending()
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected 1 journal entry, got %d", len(entries))
	}
	if entries[0].Stage != StageCommitted {
		t.Fatalf("expected journal stage committed, got %s", entries[0].Stage)
	}
}

func TestService_FaultInjection_OldRefDeleteFailure(t *testing.T) {
	svc, store, cfg, journal, _ := setupTestService(t)
	ctx := context.Background()

	oldRef := Ref{StoreID: "test-store", ItemID: "old-item"}
	_ = store.Put(ctx, oldRef, Secret{Value: []byte("old-secret")})
	cfg.activeRefs[oldRef] = false

	// 模拟 Store 删除旧项时失败
	store.delErr = errors.New("keychain delete permission denied")

	target := Target{NodeID: "node-1", Kind: KindLoginPassword}
	newSecret := Secret{Value: []byte("new-secret")}

	newRef, newVer, err := svc.Rotate(ctx, target, "version-1", &oldRef, "test-store", newSecret)
	var cleanupErr *CleanupError
	if !errors.As(err, &cleanupErr) {
		t.Fatalf("expected *CleanupError, got %v", err)
	}
	if newRef == nil || newVer == "" {
		t.Fatalf("new ref and version must be returned even when cleanup fails")
	}

	// 新凭据依然权威生效
	stored, err := store.Get(ctx, *newRef)
	if err != nil || !bytes.Equal(stored.Value, newSecret.Value) {
		t.Fatalf("new credential must remain intact")
	}

	// Journal 必须被标记为 StageCleanup 供稍后 GC
	entries, _ := journal.ListPending()
	if len(entries) != 1 {
		t.Fatalf("expected 1 journal entry in cleanup stage, got %d", len(entries))
	}
	if entries[0].Stage != StageCleanup {
		t.Fatalf("expected StageCleanup, got %s", entries[0].Stage)
	}
}

// ---------------- 崩溃恢复（Recover / GC）故障注入测试 ----------------

func TestService_FaultInjection_Recover_CrashAtIntent_ConfigNotApplied(t *testing.T) {
	svc, store, cfg, journal, _ := setupTestService(t)
	ctx := context.Background()

	// 模拟崩溃在 StageIntent：Store 已写入 newRef，但配置中未应用
	orphanRef := Ref{StoreID: "test-store", ItemID: "orphan-new-item"}
	_ = store.Put(ctx, orphanRef, Secret{Value: []byte("orphan-secret")})
	cfg.activeRefs[orphanRef] = false // 未引用

	entry := &JournalEntry{
		ID:        GenerateJournalID(),
		Op:        OpCreate,
		Stage:     StageIntent,
		NewRef:    &orphanRef,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := journal.RecordIntent(entry); err != nil {
		t.Fatalf("RecordIntent failed: %v", err)
	}

	// 执行崩溃恢复
	results, err := svc.Recover(ctx)
	if err != nil {
		t.Fatalf("Recover failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 recovery result, got %d", len(results))
	}
	if results[0].Action != RecoveryActionCompensatedNewRef {
		t.Fatalf("expected RecoveryActionCompensatedNewRef, got %s", results[0].Action)
	}

	// 孤儿凭据应已被补偿删除
	_, err = store.Get(ctx, orphanRef)
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("orphan credential must be deleted during recovery")
	}

	// 日志应已清除
	entries, _ := journal.ListPending()
	if len(entries) != 0 {
		t.Fatalf("journal must be cleared after recovery")
	}
}

func TestService_FaultInjection_Recover_CrashAtIntent_ConfigApplied(t *testing.T) {
	svc, store, cfg, journal, _ := setupTestService(t)
	ctx := context.Background()

	// 模拟崩溃在 StageIntent：配置实际上已经应用了 newRef，进程在推进 StageCommitted 前崩溃
	newRef := Ref{StoreID: "test-store", ItemID: "committed-new-item"}
	oldRef := Ref{StoreID: "test-store", ItemID: "old-abandoned-item"}
	_ = store.Put(ctx, newRef, Secret{Value: []byte("new-secret")})
	_ = store.Put(ctx, oldRef, Secret{Value: []byte("old-secret")})

	cfg.activeRefs[newRef] = true  // 配置中已包含 newRef
	cfg.activeRefs[oldRef] = false // 旧 ref 已无引用

	entry := &JournalEntry{
		ID:        GenerateJournalID(),
		Op:        OpRotate,
		Stage:     StageIntent,
		OldRef:    &oldRef,
		NewRef:    &newRef,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := journal.RecordIntent(entry); err != nil {
		t.Fatalf("RecordIntent failed: %v", err)
	}

	// 执行崩溃恢复
	results, err := svc.Recover(ctx)
	if err != nil {
		t.Fatalf("Recover failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Action != RecoveryActionCommittedCleaned {
		t.Fatalf("expected RecoveryActionCommittedCleaned, got %s", results[0].Action)
	}

	// newRef 完好保留
	if _, err := store.Get(ctx, newRef); err != nil {
		t.Fatalf("newRef must be preserved")
	}
	// oldRef 被成功清理
	if _, err := store.Get(ctx, oldRef); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("oldRef must be deleted")
	}

	entries, _ := journal.ListPending()
	if len(entries) != 0 {
		t.Fatalf("journal must be cleared after recovery")
	}
}

func TestService_FaultInjection_Recover_CrashAtCommittedOrCleanup(t *testing.T) {
	svc, store, cfg, journal, _ := setupTestService(t)
	ctx := context.Background()

	// 模拟崩溃在 StageCommitted 或 StageCleanup
	oldRef := Ref{StoreID: "test-store", ItemID: "old-to-clean"}
	_ = store.Put(ctx, oldRef, Secret{Value: []byte("old")})
	cfg.activeRefs[oldRef] = false // 无引用

	entry := &JournalEntry{
		ID:        GenerateJournalID(),
		Op:        OpRotate,
		Stage:     StageCommitted,
		OldRef:    &oldRef,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := journal.RecordIntent(entry); err != nil {
		t.Fatalf("RecordIntent failed: %v", err)
	}
	if err := journal.MarkCommitted(entry.ID); err != nil {
		t.Fatalf("MarkCommitted failed: %v", err)
	}

	// 执行 GC / Recover
	results, err := svc.GC(ctx)
	if err != nil {
		t.Fatalf("GC failed: %v", err)
	}
	if len(results) != 1 || results[0].Action != RecoveryActionCommittedCleaned {
		t.Fatalf("unexpected recovery result: %+v", results)
	}

	// oldRef 已从 Store 中清除
	if _, err := store.Get(ctx, oldRef); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("oldRef must be cleaned")
	}

	// journal 已清除
	entries, _ := journal.ListPending()
	if len(entries) != 0 {
		t.Fatalf("journal must be cleared")
	}
}

func TestService_FaultInjection_Recover_StoreFailure_RetainsJournal(t *testing.T) {
	svc, store, cfg, journal, _ := setupTestService(t)
	ctx := context.Background()

	oldRef := Ref{StoreID: "test-store", ItemID: "old-unreachable"}
	_ = store.Put(ctx, oldRef, Secret{Value: []byte("old")})
	cfg.activeRefs[oldRef] = false

	entry := &JournalEntry{
		ID:        GenerateJournalID(),
		Op:        OpRotate,
		Stage:     StageCommitted,
		OldRef:    &oldRef,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	_ = journal.RecordIntent(entry)
	_ = journal.MarkCommitted(entry.ID)

	// 模拟 Store 故障（例如网络不可达）
	store.delErr = errors.New("store network timeout")

	results, err := svc.Recover(ctx)
	if err != nil {
		t.Fatalf("Recover should not fail hard: %v", err)
	}
	if len(results) != 1 || results[0].Action != RecoveryActionScheduledForGC {
		t.Fatalf("expected RecoveryActionScheduledForGC, got %+v", results)
	}

	// 日志条目必须被保留在 StageCleanup 阶段！
	entries, err := journal.ListPending()
	if err != nil || len(entries) != 1 {
		t.Fatalf("journal entry must be retained for next GC")
	}
	if entries[0].Stage != StageCleanup {
		t.Fatalf("expected StageCleanup, got %s", entries[0].Stage)
	}
}

func TestService_FaultInjection_Recover_CrashAtIntent_OpDelete(t *testing.T) {
	svc, store, cfg, journal, _ := setupTestService(t)
	ctx := context.Background()

	// 1. 测试用例 A：配置未删除引用，崩溃恢复应作为 NoOp 清除 journal，保留 Store 项
	refA := Ref{StoreID: "test-store", ItemID: "del-ref-a"}
	_ = store.Put(ctx, refA, Secret{Value: []byte("val-a")})
	cfg.activeRefs[refA] = true // 配置中仍存在引用

	entryA := &JournalEntry{
		ID:        GenerateJournalID(),
		Op:        OpDelete,
		Stage:     StageIntent,
		OldRef:    &refA,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	_ = journal.RecordIntent(entryA)

	results, err := svc.Recover(ctx)
	if err != nil {
		t.Fatalf("Recover failed: %v", err)
	}
	if len(results) != 1 || results[0].Action != RecoveryActionRemovedNoOp {
		t.Fatalf("expected RecoveryActionRemovedNoOp, got %+v", results)
	}
	// refA 必须保留在 Store
	if _, err := store.Get(ctx, refA); err != nil {
		t.Fatalf("refA must be kept in store when config still references it")
	}

	// 2. 测试用例 B：配置已删除引用，崩溃恢复应推进 Committed 并清理 Store 项
	refB := Ref{StoreID: "test-store", ItemID: "del-ref-b"}
	_ = store.Put(ctx, refB, Secret{Value: []byte("val-b")})
	cfg.activeRefs[refB] = false // 配置中已无引用

	entryB := &JournalEntry{
		ID:        GenerateJournalID(),
		Op:        OpDelete,
		Stage:     StageIntent,
		OldRef:    &refB,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	_ = journal.RecordIntent(entryB)

	results, err = svc.Recover(ctx)
	if err != nil {
		t.Fatalf("Recover failed: %v", err)
	}
	if len(results) != 1 || results[0].Action != RecoveryActionCommittedCleaned {
		t.Fatalf("expected RecoveryActionCommittedCleaned, got %+v", results)
	}
	// refB 应从 Store 中被删除
	if _, err := store.Get(ctx, refB); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("refB must be deleted from store")
	}
}
