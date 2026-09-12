package credential

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestJournalLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewJournalStore(tempDir)
	if err != nil {
		t.Fatalf("NewJournalStore failed: %v", err)
	}

	entry := &JournalEntry{
		ID:          "j-test-1",
		Op:          OpRotate,
		OldRef:      &Ref{StoreID: "system", ItemID: "old-1"},
		NewRef:      &Ref{StoreID: "system", ItemID: "new-1"},
		BaseVersion: "base-ver-123456",
		TargetNode:  "node-a",
		TargetKind:  KindLoginPassword,
	}

	// 1. 记录 Intent
	if err := store.RecordIntent(entry); err != nil {
		t.Fatalf("RecordIntent failed: %v", err)
	}

	got, err := store.Get("j-test-1")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.Stage != StageIntent || got.Op != OpRotate {
		t.Fatalf("unexpected stage or op: %+v", got)
	}
	if got.OldRef.ItemID != "old-1" || got.NewRef.ItemID != "new-1" {
		t.Fatalf("ref mismatch: %+v", got)
	}

	// 2. 推进到 Committed
	if err := store.MarkCommitted("j-test-1"); err != nil {
		t.Fatalf("MarkCommitted failed: %v", err)
	}
	got, err = store.Get("j-test-1")
	if err != nil || got.Stage != StageCommitted {
		t.Fatalf("expected StageCommitted, got: %+v (err: %v)", got, err)
	}

	// 3. 推进到 Cleanup
	if err := store.MarkCleanup("j-test-1"); err != nil {
		t.Fatalf("MarkCleanup failed: %v", err)
	}
	got, err = store.Get("j-test-1")
	if err != nil || got.Stage != StageCleanup {
		t.Fatalf("expected StageCleanup, got: %+v (err: %v)", got, err)
	}

	// 4. 列表查询 pending
	pending, err := store.ListPending()
	if err != nil {
		t.Fatalf("ListPending failed: %v", err)
	}
	if len(pending) != 1 || pending[0].ID != "j-test-1" {
		t.Fatalf("unexpected pending list: %+v", pending)
	}

	// 5. 完成并 Remove
	if err := store.Remove("j-test-1"); err != nil {
		t.Fatalf("Remove failed: %v", err)
	}
	pending, err = store.ListPending()
	if err != nil || len(pending) != 0 {
		t.Fatalf("expected 0 pending after remove, got: %v", len(pending))
	}
}

func TestJournalTarget_PreservesCredentialMetadata(t *testing.T) {
	entry := &JournalEntry{
		TargetNode:               "node-a",
		TargetKind:               KindPassphrase,
		KeyPath:                  "/home/test/.ssh/id_ed25519",
		ClearLegacyLoginPassword: true,
		ClearLegacyPassphrase:    true,
	}

	target := entry.Target()
	if target.KeyPath != entry.KeyPath || !target.ClearLegacyLoginPassword || !target.ClearLegacyPassphrase {
		t.Fatalf("credential metadata mismatch: %+v", target)
	}
}

func TestJournalFilePermissionsAndNonSensitive(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewJournalStore(tempDir)
	if err != nil {
		t.Fatalf("NewJournalStore failed: %v", err)
	}

	entry := &JournalEntry{
		ID:         "sec-check-1",
		Op:         OpCreate,
		NewRef:     &Ref{StoreID: "pass", ItemID: "item-xyz"},
		TargetNode: "prod-srv",
		TargetKind: KindPassphrase,
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}

	if err := store.RecordIntent(entry); err != nil {
		t.Fatalf("RecordIntent failed: %v", err)
	}

	path := filepath.Join(tempDir, "journal-sec-check-1.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat journal file failed: %v", err)
	}

	// 检查 Unix 文件权限为 0600
	if runtime.GOOS != "windows" {
		perm := info.Mode().Perm()
		if perm != 0600 {
			t.Fatalf("expected file permission 0600, got: %04o", perm)
		}
	}

	// 读取文件内容并验证绝对无密码/秘密机密载荷字段泄露
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file failed: %v", err)
	}
	contentStr := strings.ToLower(string(content))
	forbiddenPayloadFields := []string{`"secret"`, `"password"`, `"supwd"`, `"plaintext"`}
	for _, kw := range forbiddenPayloadFields {
		if strings.Contains(contentStr, kw) {
			t.Fatalf("journal file contains sensitive field %q in content: %s", kw, string(content))
		}
	}
}

func TestJournalCorrupted(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewJournalStore(tempDir)
	if err != nil {
		t.Fatalf("NewJournalStore failed: %v", err)
	}

	// 写入损坏文件
	badPath := filepath.Join(tempDir, "journal-bad-1.json")
	if err := os.WriteFile(badPath, []byte("invalid-json{"), 0600); err != nil {
		t.Fatalf("write bad file failed: %v", err)
	}

	_, err = store.Get("bad-1")
	if !errors.Is(err, ErrJournalCorrupted) {
		t.Fatalf("expected ErrJournalCorrupted, got: %v", err)
	}

	_, err = store.ListPending()
	if !errors.Is(err, ErrJournalCorrupted) {
		t.Fatalf("expected ErrJournalCorrupted on ListPending, got: %v", err)
	}
}

func TestJournalIDStaysWithinDirectory(t *testing.T) {
	root := t.TempDir()
	journalDir := filepath.Join(root, "journals")
	s, err := NewJournalStore(journalDir)
	if err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(root, "victim.json")
	if err := os.WriteFile(victim, []byte("synthetic file"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove("x/../../victim"); err == nil {
		t.Fatal("Remove should reject path-escaping ID")
	}
	if _, err := os.Stat(victim); os.IsNotExist(err) {
		t.Fatal("Remove deleted a file outside the journal directory")
	}

	// 尝试通过逃逸 ID 记录或读取
	badEntry := &JournalEntry{
		ID:     "../../escape",
		Op:     OpCreate,
		NewRef: &Ref{StoreID: "s", ItemID: "k"},
	}
	if err := s.RecordIntent(badEntry); err == nil {
		t.Fatal("RecordIntent should reject path-escaping ID")
	}
	if _, err := s.Get("../../escape"); err == nil {
		t.Fatal("Get should reject path-escaping ID")
	}
}

func TestJournalReopenAcrossStages(t *testing.T) {
	dir := t.TempDir()
	store1, err := NewJournalStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	entry := &JournalEntry{
		ID:          "reopen-test-1",
		Op:          OpRotate,
		OldRef:      &Ref{StoreID: "s", ItemID: "old"},
		NewRef:      &Ref{StoreID: "s", ItemID: "new"},
		BaseVersion: "base123",
	}

	// 阶段 1：写入 Intent
	if err := store1.RecordIntent(entry); err != nil {
		t.Fatal(err)
	}

	// 新建实例 2：读取并验证
	store2, err := NewJournalStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got1, err := store2.Get("reopen-test-1")
	if err != nil || got1.Stage != StageIntent {
		t.Fatalf("stage 1 verification failed: got %+v, err %v", got1, err)
	}

	// 阶段 2：推进到 Committed
	if err := store2.MarkCommitted("reopen-test-1"); err != nil {
		t.Fatal(err)
	}

	// 新建实例 3：读取并验证
	store3, err := NewJournalStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got2, err := store3.Get("reopen-test-1")
	if err != nil || got2.Stage != StageCommitted {
		t.Fatalf("stage 2 verification failed: got %+v, err %v", got2, err)
	}

	// 阶段 3：推进到 Cleanup
	if err := store3.MarkCleanup("reopen-test-1"); err != nil {
		t.Fatal(err)
	}

	// 新建实例 4：扫描并验证
	store4, err := NewJournalStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := store4.ListPending()
	if err != nil || len(pending) != 1 || pending[0].Stage != StageCleanup {
		t.Fatalf("stage 3 pending list failed: got %+v, err %v", pending, err)
	}

	// 移除后在新建实例 5 中确认空
	if err := store4.Remove("reopen-test-1"); err != nil {
		t.Fatal(err)
	}
	store5, err := NewJournalStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	pending, err = store5.ListPending()
	if err != nil || len(pending) != 0 {
		t.Fatalf("stage 4 remove verification failed: got %+v, err %v", pending, err)
	}
}

func TestJournalDirectorySyncFailure(t *testing.T) {
	dir := t.TempDir()
	store, err := NewJournalStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	mockErr := errors.New("simulated dir sync error")
	entry := &JournalEntry{
		ID:          "sync-fail-1",
		Op:          OpCreate,
		NewRef:      &Ref{StoreID: "s", ItemID: "k"},
		BaseVersion: "base1",
	}

	// 1. RecordIntent 目录同步失败
	store.syncDirFn = func(string) error {
		return mockErr
	}
	err = store.RecordIntent(entry)
	if !errors.Is(err, mockErr) {
		t.Fatalf("expected simulated sync error on RecordIntent, got: %v", err)
	}

	// 恢复同步，成功写入 Intent
	store.syncDirFn = nil
	if err := store.RecordIntent(entry); err != nil {
		t.Fatalf("RecordIntent failed: %v", err)
	}

	// 2. MarkCommitted 目录同步失败
	store.syncDirFn = func(string) error {
		return mockErr
	}
	err = store.MarkCommitted("sync-fail-1")
	if !errors.Is(err, mockErr) {
		t.Fatalf("expected simulated sync error on MarkCommitted, got: %v", err)
	}

	// 恢复同步，成功标记 Committed
	store.syncDirFn = nil
	if err := store.MarkCommitted("sync-fail-1"); err != nil {
		t.Fatalf("MarkCommitted failed: %v", err)
	}

	// 3. MarkCleanup 目录同步失败
	store.syncDirFn = func(string) error {
		return mockErr
	}
	err = store.MarkCleanup("sync-fail-1")
	if !errors.Is(err, mockErr) {
		t.Fatalf("expected simulated sync error on MarkCleanup, got: %v", err)
	}

	// 恢复同步，成功标记 Cleanup
	store.syncDirFn = nil
	if err := store.MarkCleanup("sync-fail-1"); err != nil {
		t.Fatalf("MarkCleanup failed: %v", err)
	}

	// 4. Remove 目录同步失败
	store.syncDirFn = func(string) error {
		return mockErr
	}
	err = store.Remove("sync-fail-1")
	if !errors.Is(err, mockErr) {
		t.Fatalf("expected simulated sync error on Remove, got: %v", err)
	}

	// 恢复同步，成功删除
	store.syncDirFn = nil
	if err := store.Remove("sync-fail-1"); err != nil {
		t.Fatalf("Remove failed: %v", err)
	}
}

func TestJournalPreservesKeyFingerprint(t *testing.T) {
	store, err := NewJournalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	entry := &JournalEntry{ID: GenerateJournalID(), Op: OpCreate, Stage: StageIntent, TargetIdentity: "identity", TargetKind: KindPassphrase, KeyPath: "/key", KeyFingerprint: "SHA256:public-fingerprint", NewRef: &Ref{StoreID: "store", ItemID: "item"}}
	if err := store.RecordIntent(entry); err != nil {
		t.Fatal(err)
	}
	entries, err := store.ListPending()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Target().KeyFingerprint != entry.KeyFingerprint {
		t.Fatal("recovery lost key fingerprint")
	}
}
