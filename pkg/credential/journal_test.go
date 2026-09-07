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
