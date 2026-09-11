//go:build linux && amd64

package credentialfile

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/wentf9/xops-cli/pkg/credential"
)

func TestEnsureWrappingKeyCreatesAndReuses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := ensureWrappingKeyFile(t.Context(), path, fileOps{}); err != nil {
		t.Fatal(err)
	}
	original, err := readKeyFile(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(original)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode().Perm() != 0600 || len(original) != 32 || bytes.Equal(original, make([]byte, 32)) {
		t.Fatal("invalid generated key")
	}
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	if err := ensureWrappingKeyFile(t.Context(), path, fileOps{}); err != nil {
		t.Fatal(err)
	}
	got, err := readKeyFile(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(got)
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) || !os.SameFile(before, after) || after.Mode().Perm() != 0400 {
		t.Fatal("existing key changed")
	}
}

func TestEnsureWrappingKeyRejectsInvalidExisting(t *testing.T) {
	for _, kind := range []string{"short", "permissions", "symlink", "hardlink", "directory", "parent-symlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "key")
			original := bytes.Repeat([]byte{42}, 32)
			target := filepath.Join(dir, "original")
			if err := os.WriteFile(target, original, 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "short":
				err = os.WriteFile(path, []byte("short"), 0600)
			case "permissions":
				err = os.WriteFile(path, original, 0600)
				if err == nil {
					// Set the invalid mode explicitly, independent of the process umask.
					err = os.Chmod(path, 0644)
				}
			case "symlink":
				err = os.Symlink(target, path)
			case "hardlink":
				err = os.Link(target, path)
			case "directory":
				err = os.Mkdir(path, 0700)
			case "parent-symlink":
				err = os.Symlink(dir, filepath.Join(dir, "alias"))
				path = filepath.Join(dir, "alias", "missing")
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := ensureWrappingKeyFile(t.Context(), path, fileOps{}); err == nil {
				t.Fatal("invalid key path accepted")
			}
			got, err := os.ReadFile(target)
			if err != nil || !bytes.Equal(got, original) {
				t.Fatal("existing material altered")
			}
			if kind == "parent-symlink" {
				if _, err := os.Stat(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("followed symlink parent")
				}
			}
		})
	}
}

func TestEnsureWrappingKeyConcurrentPublication(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() { errs <- ensureWrappingKeyFile(t.Context(), path, fileOps{}) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	key, err := readKeyFile(t.Context(), path)
	defer clear(key)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatal("temporary key files remain")
	}
}

func TestEnsureWrappingKeyFaults(t *testing.T) {
	for _, step := range []string{"key-file:create", "key-file:write", "key-file:sync", "key-file:publish", "key-file:directory-sync"} {
		t.Run(step, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "key")
			injected := errors.New("injected key failure")
			ops := fileOps{before: func(at string) error {
				if at == step {
					return injected
				}
				return nil
			}}
			if err := ensureWrappingKeyFile(t.Context(), path, ops); !errors.Is(err, injected) {
				t.Fatalf("missing injected failure: %v", err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			if step == "key-file:directory-sync" {
				want = 1
			}
			if len(entries) != want {
				t.Fatal("unexpected files after failure")
			}
			// A completed key survives a directory-sync failure and can be retried.
			if err := ensureWrappingKeyFile(t.Context(), path, fileOps{}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEnsureWrappingKeyCanceled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := ensureWrappingKeyFile(ctx, path, fileOps{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("key created after cancellation")
	}
}

func TestWrappingKeyMustBeOutsideVault(t *testing.T) {
	root := t.TempDir()
	err := validateWrappingKeyLocation(root, Wrapping{Mode: "key-file", KeyFile: filepath.Join(root, "CURRENT")})
	if !errors.Is(err, credential.ErrCredentialAccessDenied) {
		t.Fatal("accepted key inside vault")
	}
}
