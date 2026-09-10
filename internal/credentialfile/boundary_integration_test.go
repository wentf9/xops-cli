//go:build integration && linux && amd64

package credentialfile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/internal/credentialfile/format"
	"github.com/wentf9/xops-cli/pkg/credential"
	"golang.org/x/sys/unix"
)

func TestFileStoreUnsafeFilesFailClosed(t *testing.T) {
	for _, kind := range []string{"symlink", "fifo", "public", "oversize", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			f := makeFixture(t)
			s := f.open(t, fileOps{})
			path := f.itemPath(t, f.ref)
			outside := filepath.Join(t.TempDir(), "outside")
			writeFixtureFile(t, outside, []byte("outside-public-test-data"))
			switch kind {
			case "symlink":
				if err := os.Symlink(outside, path); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "public":
				writeFixtureFile(t, path, []byte("x"))
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				writeFixtureFile(t, path, nil)
				if err := os.Truncate(path, format.MaxItemBytes+1); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(outside, path); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			secret, err := s.Get(ctx, f.ref)
			secret.Zero()
			want := credential.ErrCredentialAccessDenied
			if kind == "oversize" {
				want = format.ErrCorrupt
			}
			if !errors.Is(err, want) {
				t.Fatalf("unsafe read classification: %v", err)
			}
			value := credential.NewSecret([]byte("replacement"))
			defer value.Zero()
			if err := s.Put(ctx, f.ref, value); !errors.Is(err, want) {
				t.Fatalf("unsafe put: %v", err)
			}
			if err := s.Delete(ctx, f.ref); !errors.Is(err, want) {
				t.Fatalf("unsafe delete: %v", err)
			}
			got, err := os.ReadFile(outside)
			if err != nil || string(got) != "outside-public-test-data" {
				t.Fatal("outside target changed")
			}
			if f.budget(t).Consumed != 3 {
				t.Fatal("unsafe target consumed budget")
			}
		})
	}
}

func TestFileStoreDirectoryAndLockReplacement(t *testing.T) {
	for _, target := range []string{"root", "items", "lock"} {
		t.Run(target, func(t *testing.T) {
			f := makeFixture(t)
			s := f.open(t, fileOps{})
			switch target {
			case "root":
				alias := filepath.Join(t.TempDir(), "alias")
				if err := os.Symlink(f.root, alias); err != nil {
					t.Fatal(err)
				}
				opened, err := Open(t.Context(), alias, "offline", Options{Keys: f.keys})
				if opened != nil {
					if closeErr := opened.Close(); closeErr != nil {
						t.Error(closeErr)
					}
				}
				if !errors.Is(err, credential.ErrCredentialAccessDenied) {
					t.Fatalf("root alias accepted: %v", err)
				}
				return
			case "items":
				path := filepath.Join(f.root, "revisions/1/items")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(t.TempDir(), path); err != nil {
					t.Fatal(err)
				}
			case "lock":
				path := filepath.Join(f.root, "vault.lock")
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				writeFixtureFile(t, path, nil)
			}
			_, err := s.Get(t.Context(), f.ref)
			want := credential.ErrCredentialAccessDenied
			if target == "lock" {
				want = ErrRevisionChanged
			}
			if !errors.Is(err, want) {
				t.Fatalf("replacement: %v", err)
			}
		})
	}
}

func TestFileStoreCancellationAndCloseWait(t *testing.T) {
	f := makeFixture(t)
	attempt := make(chan struct{}, 1)
	s := f.open(t, fileOps{before: func(step string) error {
		if step == "lock:attempt" {
			select {
			case attempt <- struct{}{}:
			default:
			}
		}
		return nil
	}})
	held, err := s.root.open("vault.lock", unix.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := held.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := unix.Flock(int(held.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	_, err = s.Get(ctx, f.ref)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lock timeout: %v", err)
	}
	select {
	case <-attempt:
	default:
	}
	done := make(chan error, 1)
	go func() { secret, err := s.Get(t.Context(), f.ref); secret.Zero(); done <- err }()
	select {
	case <-attempt:
	case <-time.After(time.Second):
		t.Fatal("request never reached file lock")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrClosed) {
		t.Fatalf("close did not cancel waiter: %v", err)
	}
	if _, err := s.Get(t.Context(), f.ref); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed store: %v", err)
	}
}

func TestFileStoreUnlockRunsOutsideFileLock(t *testing.T) {
	f := makeFixture(t)
	other := f.open(t, fileOps{})
	f.keys = unlockFunc(func(ctx context.Context, data []byte) ([]byte, error) {
		lock, err := other.lock(ctx, true)
		if err != nil {
			return nil, err
		}
		if err := lock.close(); err != nil {
			return nil, err
		}
		_, key, err := format.OpenMeta(data, f.data["wrapping_key"], "offline")
		return key, err
	})
	s := f.open(t, fileOps{})
	if _, err := s.Get(t.Context(), f.ref); !errors.Is(err, credential.ErrCredentialNotFound) {
		t.Fatalf("unlock held a lock: %v", err)
	}
}

func TestFileStorePublicationChangesDuringUnlock(t *testing.T) {
	f := makeFixture(t)
	baseKeys := f.keys
	f.keys = unlockFunc(func(ctx context.Context, data []byte) ([]byte, error) {
		key, err := baseKeys.Unlock(ctx, data)
		if err != nil {
			return nil, err
		}
		m, err := format.ParseMeta(data)
		if err != nil {
			clear(key)
			return nil, err
		}
		m.Revision = 2
		m.Salt = bytes.Repeat([]byte{0x42}, 32)
		wrap, err := format.KeyFileWrappingKey(m, f.data["file_key"])
		if err != nil {
			clear(key)
			return nil, err
		}
		defer clear(wrap)
		encoded, err := format.SealMeta(m, wrap, key)
		if err != nil {
			clear(key)
			return nil, err
		}
		path := filepath.Join(f.root, "revisions/2")
		if err := os.Mkdir(path, 0700); err != nil {
			clear(key)
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(path, "vault.meta"), encoded, 0600); err != nil {
			clear(key)
			return nil, err
		}
		current := format.Current{VaultID: m.VaultID, Revision: 2, Generation: 1, MetaHash: sha256.Sum256(encoded)}
		b, err := current.MarshalBinary()
		if err != nil {
			clear(key)
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(f.root, "CURRENT"), b, 0600); err != nil {
			clear(key)
			return nil, err
		}
		return key, nil
	})
	s := f.open(t, fileOps{})
	if _, err := s.Get(t.Context(), f.ref); !errors.Is(err, ErrRevisionChanged) {
		t.Fatalf("publication change ignored: %v", err)
	}
}

func TestFileStorePendingRecoveryAndCorruptBudget(t *testing.T) {
	for _, kind := range []string{"transaction", "budget_temp", "item_temp", "corrupt_budget"} {
		t.Run(kind, func(t *testing.T) {
			f := makeFixture(t)
			s := f.open(t, fileOps{})
			secret := credential.NewSecret([]byte("public-secret"))
			defer secret.Zero()
			if err := s.Put(t.Context(), f.ref, secret); err != nil {
				t.Fatal(err)
			}
			path := "transactions/pending"
			want := ErrMaintenanceRequired
			switch kind {
			case "budget_temp":
				path = "key-state/1/.tmp-residue"
			case "item_temp":
				path = "revisions/1/items/.tmp-residue"
			case "corrupt_budget":
				path = "key-state/1/budget"
				want = format.ErrCorrupt
			}
			writeFixtureFile(t, filepath.Join(f.root, path), []byte("invalid-public-state"))
			got, err := s.Get(t.Context(), f.ref)
			got.Zero()
			if err != nil {
				t.Fatalf("safe reading was blocked: %v", err)
			}
			if err := s.Put(t.Context(), f.ref, secret); !errors.Is(err, want) {
				t.Fatalf("unsafe write allowed: %v", err)
			}
			if err := s.Delete(t.Context(), f.ref); !errors.Is(err, want) {
				t.Fatalf("unsafe cleanup allowed: %v", err)
			}
		})
	}
}

func TestFileStoreBudgetAndExpiryBoundaries(t *testing.T) {
	f := makeFixture(t)
	s := f.open(t, fileOps{})
	secret := credential.NewSecretWithExpiry([]byte("public-secret"), time.Now().Add(time.Hour))
	defer secret.Zero()
	if err := s.Put(t.Context(), f.ref, secret); err != nil {
		t.Fatal(err)
	}
	changed := secret.Clone()
	defer changed.Zero()
	expiry := secret.ExpiresAt.Add(time.Second)
	changed.ExpiresAt = &expiry
	if err := s.Put(t.Context(), f.ref, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("expiry conflict ignored: %v", err)
	}
	b := f.budget(t)
	b.Consumed = format.MaxEncryptions
	b.Sequence = math.MaxUint64
	encoded, err := format.SealBudget(b, f.data["dek"])
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(f.root, "key-state/1/budget"), encoded)
	if err := s.Put(t.Context(), f.ref, secret); err != nil {
		t.Fatalf("same ciphertext retry at budget limit: %v", err)
	}
	ref := f.ref
	ref.ItemID = "new"
	if err := s.Put(t.Context(), ref, secret); !errors.Is(err, ErrKeyUsageExhausted) {
		t.Fatalf("exhausted key used: %v", err)
	}
	if err := s.Delete(t.Context(), f.ref); err != nil {
		t.Fatal(err)
	}
}

func TestFileStoreDoesNotLeakHandlesOnRejectedDirectories(t *testing.T) {
	f := makeFixture(t)
	s := f.open(t, fileOps{})
	count := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, entry := range entries {
			target, err := os.Readlink("/proc/self/fd/" + entry.Name())
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(target, f.root) {
				n++
			}
		}
		return n
	}
	before := count()
	if err := os.Chmod(filepath.Join(f.root, "revisions/1/items"), 0755); err != nil {
		t.Fatal(err)
	}
	for range 20 {
		if _, err := s.Get(t.Context(), f.ref); !errors.Is(err, credential.ErrCredentialAccessDenied) {
			t.Fatalf("unsafe dir: %v", err)
		}
	}
	if after := count(); after != before {
		t.Fatalf("vault handle leak: before=%d after=%d", before, after)
	}
}

func TestFileStoreRechecksRootPermissions(t *testing.T) {
	f := makeFixture(t)
	s := f.open(t, fileOps{})
	if err := os.Chmod(f.root, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(t.Context(), f.ref); !errors.Is(err, credential.ErrCredentialAccessDenied) {
		t.Fatalf("unsafe root accepted: %v", err)
	}
}

func TestFileStoreReadOnlyAndCanceledCalls(t *testing.T) {
	f := makeFixture(t)
	s, err := Open(t.Context(), f.root, "offline", Options{Keys: f.keys, ReadOnly: true})
	if errors.Is(err, ErrUnsupported) {
		t.Skip("required filesystem operations unavailable")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	}()
	secret := credential.NewSecret([]byte("public-secret"))
	defer secret.Zero()
	if err := s.Put(t.Context(), f.ref, secret); !errors.Is(err, credential.ErrCredentialStoreReadOnly) {
		t.Fatal(err)
	}
	if err := s.Delete(t.Context(), f.ref); !errors.Is(err, credential.ErrCredentialStoreReadOnly) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancelCause(t.Context())
	cause := errors.New("caller canceled")
	cancel(cause)
	if _, err := s.Get(ctx, f.ref); !errors.Is(err, cause) {
		t.Fatalf("cancellation cause lost: %v", err)
	}
}

func TestFileStoreUnexpectedTargetIsNeverOverwritten(t *testing.T) {
	f := makeFixture(t)
	path := f.itemPath(t, f.ref)
	winner := []byte("public competing target")
	s := f.open(t, fileOps{before: func(step string) error {
		if step == "put:publish" {
			return os.WriteFile(path, winner, 0600)
		}
		return nil
	}})
	secret := credential.NewSecret([]byte("public new secret"))
	defer secret.Zero()
	if err := s.Put(t.Context(), f.ref, secret); !errors.Is(err, ErrConflict) {
		t.Fatalf("unexpected target overwritten: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, winner) {
		t.Fatal("competing target changed")
	}
	if n := f.budget(t).Consumed; n != 4 {
		t.Fatalf("failed encryption reservation refunded: %d", n)
	}
}

func TestFileStoreDiskFullAndUnsupportedPublish(t *testing.T) {
	for _, tc := range []struct {
		name, step string
		cause      error
	}{
		{"disk_full", "put:write", unix.ENOSPC},
		{"unsupported_publish", "put:publish", unix.ENOSYS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := makeFixture(t)
			s := f.open(t, fileOps{before: func(step string) error {
				if step == tc.step {
					return tc.cause
				}
				return nil
			}})
			secret := credential.NewSecret([]byte("public-secret"))
			defer secret.Zero()
			err := s.Put(t.Context(), f.ref, secret)
			if !errors.Is(err, tc.cause) {
				t.Fatalf("cause lost: %v", err)
			}
			if tc.name == "unsupported_publish" && !errors.Is(err, ErrUnsupported) {
				t.Fatalf("unsupported primitive classification: %v", err)
			}
			if _, err := os.Stat(f.itemPath(t, f.ref)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unexpected publication")
			}
			if f.budget(t).Consumed != 4 {
				t.Fatal("reservation refunded")
			}
		})
	}
}
