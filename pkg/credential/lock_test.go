package credential

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestEntryLock_ExclusiveAndRelease(t *testing.T) {
	dir := t.TempDir()
	store, err := NewJournalStore(dir)
	if err != nil {
		t.Fatalf("NewJournalStore failed: %v", err)
	}

	entryID := "entry-lock-test"

	// 1. 首次获取锁应成功
	lock1, err := store.AcquireEntryLock(entryID)
	if err != nil {
		t.Fatalf("AcquireEntryLock 1 failed: %v", err)
	}
	defer func() {
		_ = lock1.Close()
	}()

	// 2. 在未释放时再次获取，应返回 ErrLockContended
	_, err = store.TryLockEntry(entryID)
	if !errors.Is(err, ErrLockContended) {
		t.Fatalf("expected ErrLockContended while held, got: %v", err)
	}

	// 3. 释放 lock1
	if err := lock1.Close(); err != nil {
		t.Fatalf("lock1.Close() failed: %v", err)
	}

	// 4. 再次获取应成功
	lock2, err := store.TryLockEntry(entryID)
	if err != nil {
		t.Fatalf("TryLockEntry after release failed: %v", err)
	}
	_ = lock2.Close()
}

func TestEntryLock_RecoverSkipsContendedEntry(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journals")
	journal, err := NewJournalStore(dir)
	if err != nil {
		t.Fatalf("NewJournalStore failed: %v", err)
	}
	reg := NewRegistry()
	store := newMemoryStore()
	_ = reg.Register("test-store", store)
	cfg := newMockConfigUpdater()
	cache := NewCache(CacheOptions{Capacity: 16, DefaultTTL: time.Minute})
	svc, err := NewService(reg, journal, cfg, cache)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	entryID := GenerateJournalID()
	ref := Ref{StoreID: "test-store", ItemID: "contended-item"}
	_ = store.Put(context.Background(), ref, Secret{Value: []byte("val")})

	entry := &JournalEntry{
		ID:        entryID,
		Op:        OpCreate,
		Stage:     StageIntent,
		NewRef:    &ref,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := journal.RecordIntent(entry); err != nil {
		t.Fatalf("RecordIntent failed: %v", err)
	}

	// 模拟外部进程持有排他文件锁
	externalLock, err := journal.AcquireEntryLock(entryID)
	if err != nil {
		t.Fatalf("AcquireEntryLock failed: %v", err)
	}
	defer func() {
		_ = externalLock.Close()
	}()

	// 执行 Recover：必须识别到文件锁冲突并跳过
	results, err := svc.Recover(context.Background())
	if err != nil {
		t.Fatalf("Recover failed: %v", err)
	}
	if len(results) != 1 || results[0].Action != RecoveryActionSkippedActive {
		t.Fatalf("expected RecoveryActionSkippedActive for contended entry, got %+v", results)
	}

	// 外部锁释放后，Recover 可以正常处理
	_ = externalLock.Close()
	results2, err := svc.Recover(context.Background())
	if err != nil {
		t.Fatalf("Recover 2 failed: %v", err)
	}
	if len(results2) != 1 || results2[0].Action != RecoveryActionCompensatedNewRef {
		t.Fatalf("expected RecoveryActionCompensatedNewRef after lock released, got %+v", results2)
	}
}
