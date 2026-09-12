package credentialhelper

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/wentf9/xops-cli/pkg/credential"
)

func TestNewHelperStoreValidation(t *testing.T) {
	opts := ProcessOptions{Command: "echo"}
	if _, err := NewHelperStore("", opts, false); err == nil {
		t.Fatal("expected error for empty storeID")
	}

	if _, err := NewHelperStore("store1", ProcessOptions{}, false); err == nil {
		t.Fatal("expected error for empty command")
	}

	s, err := NewHelperStore("store1", opts, true)
	if err != nil {
		t.Fatalf("NewHelperStore failed: %v", err)
	}
	if s.StoreID() != "store1" || !s.IsReadOnly() {
		t.Fatalf("unexpected properties: id=%s, readonly=%v", s.StoreID(), s.IsReadOnly())
	}
}

func TestHelperStoreGetPutDelete(t *testing.T) {
	ctx := context.Background()
	storageFile := filepath.Join(t.TempDir(), "store.json")
	opts := FakeHelperOptions("storage_file", "HELPER_STORAGE_FILE="+storageFile)
	store, err := NewHelperStore("test-store", opts, false)
	if err != nil {
		t.Fatalf("NewHelperStore failed: %v", err)
	}

	ref := credential.Ref{StoreID: "test-store", ItemID: "my-pwd"}
	secretVal := []byte("topsecret123")

	// 0. 未存储时 Get 应该返回 ErrCredentialNotFound
	_, err = store.Get(ctx, ref)
	if !errors.Is(err, credential.ErrCredentialNotFound) {
		t.Fatalf("expected ErrCredentialNotFound before put, got: %v", err)
	}

	// 1. Put
	if err := store.Put(ctx, ref, credential.NewSecret(secretVal)); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// 2. Get
	got, err := store.Get(ctx, ref)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if string(got.Value) != "topsecret123" {
		t.Fatalf("got %s, want topsecret123", string(got.Value))
	}
	got.Zero()

	// 3. Delete
	if err := store.Delete(ctx, ref); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// 4. Delete 后再次 Get 应该返回 ErrCredentialNotFound
	_, err = store.Get(ctx, ref)
	if !errors.Is(err, credential.ErrCredentialNotFound) {
		t.Fatalf("expected ErrCredentialNotFound after delete, got: %v", err)
	}

	// 5. Mismatched Ref StoreID
	badRef := credential.Ref{StoreID: "other-store", ItemID: "my-pwd"}
	if _, err := store.Get(ctx, badRef); !errors.Is(err, credential.ErrInvalidRef) {
		t.Fatalf("expected ErrInvalidRef on store ID mismatch, got: %v", err)
	}
}

func TestHelperStoreReadOnlyEnforcement(t *testing.T) {
	ctx := context.Background()
	// 使用一个不存在的命令，若调用了外部命令会直接失败；但只读模式下应该直接短路返回 ErrCredentialStoreReadOnly
	opts := ProcessOptions{Command: "non-existent-command-123456789"}
	store, err := NewHelperStore("ro-store", opts, true)
	if err != nil {
		t.Fatalf("NewHelperStore failed: %v", err)
	}

	ref := credential.Ref{StoreID: "ro-store", ItemID: "k"}

	// Put 必须直接返回 ErrCredentialStoreReadOnly
	err = store.Put(ctx, ref, credential.NewSecret([]byte("val")))
	if !errors.Is(err, credential.ErrCredentialStoreReadOnly) {
		t.Fatalf("expected ErrCredentialStoreReadOnly on Put, got: %v", err)
	}

	// Delete 必须直接返回 ErrCredentialStoreReadOnly
	err = store.Delete(ctx, ref)
	if !errors.Is(err, credential.ErrCredentialStoreReadOnly) {
		t.Fatalf("expected ErrCredentialStoreReadOnly on Delete, got: %v", err)
	}
}
