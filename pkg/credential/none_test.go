package credential

import (
	"context"
	"errors"
	"testing"
)

func TestNoneStoreFailClosed(t *testing.T) {
	ctx := context.Background()
	store := NewNoneStore()
	ref := Ref{StoreID: "none", ItemID: "any-item"}

	// 1. Get 总是返回 ErrCredentialNotFound
	_, err := store.Get(ctx, ref)
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("expected ErrCredentialNotFound from NoneStore.Get, got: %v", err)
	}

	// 2. Put 总是返回 ErrCredentialStoreReadOnly
	sec := NewSecret([]byte("secret-pass"))
	err = store.Put(ctx, ref, sec)
	if !errors.Is(err, ErrCredentialStoreReadOnly) {
		t.Fatalf("expected ErrCredentialStoreReadOnly from NoneStore.Put, got: %v", err)
	}

	// 3. Delete 总是返回 ErrCredentialStoreReadOnly
	err = store.Delete(ctx, ref)
	if !errors.Is(err, ErrCredentialStoreReadOnly) {
		t.Fatalf("expected ErrCredentialStoreReadOnly from NoneStore.Delete, got: %v", err)
	}
}
