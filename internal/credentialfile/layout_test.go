package credentialfile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInspectLayoutReadOnly(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	vault, key := filepath.Join(dir, "vault"), filepath.Join(dir, "key")
	layout, err := InspectLayout(t.Context(), vault, key)
	if err != nil || layout.Vault || layout.Key {
		t.Fatalf("layout=%+v err=%v", layout, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("inspection created files: %v %v", entries, err)
	}
	if err := os.WriteFile(key, []byte("test-key"), 0600); err != nil {
		t.Fatal(err)
	}
	layout, err = InspectLayout(t.Context(), vault, key)
	if err != nil || layout.Vault || !layout.Key {
		t.Fatalf("key residue lost: %+v %v", layout, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := InspectLayout(ctx, vault, key); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

func TestInspectLayoutRejectsSymlink(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(filepath.Join(dir, "missing"), link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := InspectLayout(t.Context(), filepath.Join(link, "vault"), filepath.Join(dir, "key")); err == nil {
		t.Fatal("dangling ancestor symlink treated as missing")
	}
}
