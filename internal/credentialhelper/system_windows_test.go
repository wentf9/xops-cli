//go:build windows

package credentialhelper

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/pkg/credential"
)

func TestWindowsNativeHelper_DirectRoundtrip(t *testing.T) {
	storeID := "wintest"
	itemID := "token-direct"
	secretPlain := "super-secret-win-payload-123!@#"
	secretB64 := base64.StdEncoding.EncodeToString([]byte(secretPlain))

	// 1. Store
	storeReq := &Request{
		ProtocolVersion: 1,
		StoreID:         storeID,
		ItemID:          itemID,
		Secret:          secretB64,
	}
	resp, code := handlePlatformSystemHelper(ActionStore, storeReq)
	if code != 0 {
		t.Fatalf("Store failed with code %d: %v", code, resp)
	}

	// 2. Get
	getReq := &Request{
		ProtocolVersion: 1,
		StoreID:         storeID,
		ItemID:          itemID,
	}
	resp, code = handlePlatformSystemHelper(ActionGet, getReq)
	if code != 0 {
		t.Fatalf("Get failed with code %d: %v", code, resp)
	}
	if resp.Secret != secretB64 {
		t.Fatalf("Get secret mismatch: got %q, want %q", resp.Secret, secretB64)
	}

	// 3. Erase
	eraseReq := &Request{
		ProtocolVersion: 1,
		StoreID:         storeID,
		ItemID:          itemID,
	}
	resp, code = handlePlatformSystemHelper(ActionErase, eraseReq)
	if code != 0 {
		t.Fatalf("Erase failed with code %d: %v", code, resp)
	}

	// 4. Get after Erase -> not-found
	resp, code = handlePlatformSystemHelper(ActionGet, getReq)
	if code == 0 {
		t.Fatalf("expected non-zero code after erase")
	}
	if resp.Code != "not-found" {
		t.Fatalf("expected 'not-found', got %q", resp.Code)
	}
}

func TestWindowsNativeSystemStore_Integration(t *testing.T) {
	ctx := context.Background()
	store, err := newNativeSystemStore("winsys", SystemStoreConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("newNativeSystemStore failed: %v", err)
	}

	ref := credential.Ref{StoreID: "winsys", ItemID: "integ-key"}
	secVal := []byte("integration-secret-data\n\n\x00\x01")

	// 1. Put
	if err := store.Put(ctx, ref, credential.NewSecret(secVal)); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// 2. Get
	got, err := store.Get(ctx, ref)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if string(got.Value) != string(secVal) {
		t.Fatalf("Get value mismatch: got %q, want %q", got.Value, secVal)
	}
	got.Zero()

	// 3. Delete
	if err := store.Delete(ctx, ref); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// 4. Get after Delete
	_, err = store.Get(ctx, ref)
	if !errors.Is(err, credential.ErrCredentialNotFound) {
		t.Fatalf("expected ErrCredentialNotFound, got: %v", err)
	}
}
