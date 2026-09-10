//go:build integration && linux && amd64

package credentialfile

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/internal/credentialfile/format"
	"github.com/wentf9/xops-cli/pkg/credential"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

type unlockFunc func(context.Context, []byte) ([]byte, error)

func (f unlockFunc) Unlock(ctx context.Context, data []byte) ([]byte, error) { return f(ctx, data) }

type fixture struct {
	root string
	data map[string][]byte
	keys KeySource
	ref  credential.Ref
}

func fixtureData(t *testing.T) map[string][]byte {
	t.Helper()
	b, err := os.ReadFile("format/testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]string
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	data := make(map[string][]byte)
	for k, v := range raw {
		b, err := hex.DecodeString(v)
		if err != nil {
			t.Fatal(err)
		}
		data[k] = b
	}
	return data
}

func writeFixtureFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}

func makeFixture(t *testing.T) fixture {
	t.Helper()
	f := fixture{root: t.TempDir(), data: fixtureData(t), ref: credential.Ref{StoreID: "offline", ItemID: "test-item"}}
	if err := os.Chmod(f.root, 0700); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"revisions", "revisions/1", "revisions/1/items", "key-state", "key-state/1", "transactions"} {
		if err := os.Mkdir(filepath.Join(f.root, p), 0700); err != nil {
			t.Fatal(err)
		}
	}
	writeFixtureFile(t, filepath.Join(f.root, "vault.lock"), nil)
	writeFixtureFile(t, filepath.Join(f.root, "CURRENT"), f.data["current"])
	writeFixtureFile(t, filepath.Join(f.root, "revisions/1/vault.meta"), f.data["meta_file"])
	writeFixtureFile(t, filepath.Join(f.root, "key-state/1/budget"), f.data["budget"])
	f.keys = unlockFunc(func(ctx context.Context, b []byte) ([]byte, error) {
		if err := context.Cause(ctx); err != nil {
			return nil, err
		}
		m, err := format.ParseMeta(b)
		if err != nil {
			return nil, err
		}
		wrappingKey, err := format.KeyFileWrappingKey(m, f.data["file_key"])
		if err != nil {
			return nil, err
		}
		defer clear(wrappingKey)
		_, key, err := format.OpenMeta(b, wrappingKey, "offline")
		return key, err
	})
	return f
}

func (f fixture) open(t *testing.T, ops fileOps) *Store {
	t.Helper()
	s, err := openStore(t.Context(), f.root, "offline", Options{Keys: f.keys, Timeout: 2 * time.Second}, ops)
	if errors.Is(err, ErrUnsupported) {
		t.Skipf("native ext4 required: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func (f fixture) budget(t *testing.T) format.Budget {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.root, "key-state/1/budget"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := format.ParseMeta(f.data["meta_file"])
	if err != nil {
		t.Fatal(err)
	}
	budget, err := format.OpenBudget(b, f.data["dek"], m.VaultID, 1, "offline")
	if err != nil {
		t.Fatal(err)
	}
	return budget
}

func (f fixture) itemPath(t *testing.T, ref credential.Ref) string {
	t.Helper()
	name, err := format.ItemFilename(ref.ItemID)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(f.root, "revisions/1/items", name)
}

func TestFileStoreNativeRoundTrip(t *testing.T) {
	f := makeFixture(t)
	s := f.open(t, fileOps{})
	secret := credential.NewSecret([]byte("public-test-secret"))
	defer secret.Zero()
	if err := s.Put(t.Context(), f.ref, secret); err != nil {
		t.Fatal(err)
	}
	if n := f.budget(t).Consumed; n != 4 {
		t.Fatalf("budget=%d", n)
	}
	if err := s.Put(t.Context(), f.ref, secret); err != nil {
		t.Fatal(err)
	}
	if n := f.budget(t).Consumed; n != 4 {
		t.Fatalf("idempotent put consumed budget: %d", n)
	}
	got, err := s.Get(t.Context(), f.ref)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Value, secret.Value) {
		t.Fatal("secret differs")
	}
	got.Zero()
	other := credential.NewSecret([]byte("other-public-secret"))
	defer other.Zero()
	if err := s.Put(t.Context(), f.ref, other); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting put: %v", err)
	}
	if err := s.Delete(t.Context(), f.ref); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(t.Context(), f.ref); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(t.Context(), f.ref); !errors.Is(err, credential.ErrCredentialNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if n := f.budget(t).Consumed; n != 4 {
		t.Fatalf("delete refunded budget: %d", n)
	}
}

func TestFileStoreSyncFailures(t *testing.T) {
	for _, tc := range []struct {
		name, step string
		applied    bool
		consumed   uint64
	}{
		{"budget_write", "budget:write", false, 3},
		{"budget_sync", "budget:file-sync", false, 3},
		{"budget_publish", "budget:publish", false, 3},
		{"budget_dir_sync", "budget:dir-sync", false, 4},
		{"nonce", "item:nonce", false, 4},
		{"item_write", "put:write", false, 4},
		{"item_sync", "put:file-sync", false, 4},
		{"item_publish", "put:publish", false, 4},
		{"item_dir_sync", "put:dir-sync", true, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := makeFixture(t)
			failure := errors.New("injected I/O failure")
			s := f.open(t, fileOps{before: func(step string) error {
				if step == tc.step {
					return failure
				}
				return nil
			}})
			secret := credential.NewSecret([]byte("public-secret"))
			defer secret.Zero()
			err := s.Put(t.Context(), f.ref, secret)
			if !errors.Is(err, failure) {
				t.Fatalf("missing cause: %v", err)
			}
			if n := f.budget(t).Consumed; n != tc.consumed {
				t.Fatalf("budget=%d", n)
			}
			_, statErr := os.Stat(f.itemPath(t, f.ref))
			if (statErr == nil) != tc.applied {
				t.Fatalf("item visibility: %v", statErr)
			}
			if tc.step == "put:dir-sync" {
				var outcome *DurabilityError
				if !errors.As(err, &outcome) || !outcome.Applied || outcome.Durable {
					t.Fatalf("outcome: %v", err)
				}
			}
			// A different handle must be able to retry after ordinary error cleanup.
			retry := f.open(t, fileOps{})
			if err := retry.Put(t.Context(), f.ref, secret); err != nil {
				t.Fatal(err)
			}
			want := tc.consumed
			if !tc.applied {
				want++
			}
			if n := f.budget(t).Consumed; n != want {
				t.Fatalf("retry budget=%d want=%d", n, want)
			}
		})
	}
}

func TestFileStoreRetriesConfirmDurability(t *testing.T) {
	f := makeFixture(t)
	s := f.open(t, fileOps{})
	secret := credential.NewSecret([]byte("public-secret"))
	defer secret.Zero()
	if err := s.Put(t.Context(), f.ref, secret); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("sync failed")
	retry := f.open(t, fileOps{before: func(step string) error {
		if step == "put-retry:dir-sync" {
			return failure
		}
		return nil
	}})
	if err := retry.Put(t.Context(), f.ref, secret); !errors.Is(err, failure) {
		t.Fatalf("idempotent retry skipped sync: %v", err)
	}
	deleting := f.open(t, fileOps{before: func(step string) error {
		if step == "delete:dir-sync" {
			return failure
		}
		return nil
	}})
	for range 2 {
		err := deleting.Delete(t.Context(), f.ref)
		var outcome *DurabilityError
		if !errors.As(err, &outcome) || !outcome.Applied || !errors.Is(err, failure) {
			t.Fatalf("delete retry skipped sync: %v", err)
		}
	}
	if err := s.Delete(t.Context(), f.ref); err != nil {
		t.Fatal(err)
	}
}

func TestFileStoreConcurrentHandles(t *testing.T) {
	f := makeFixture(t)
	a, b := f.open(t, fileOps{}), f.open(t, fileOps{})
	secret := credential.NewSecret([]byte("public-shared-secret"))
	defer secret.Zero()
	errs := make(chan error, 12)
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Go(func() {
			s := a
			if i%2 == 0 {
				s = b
			}
			errs <- s.Put(t.Context(), f.ref, secret)
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := f.budget(t).Consumed; n != 4 {
		t.Fatalf("multiple reservations for one item: %d", n)
	}
	distinctErrors := make(chan error, 12)
	for i := range 12 {
		wg.Go(func() {
			ref := f.ref
			ref.ItemID = fmt.Sprintf("item-%d", i)
			s := a
			if i%2 == 0 {
				s = b
			}
			distinctErrors <- s.Put(t.Context(), ref, secret)
		})
	}
	wg.Wait()
	close(distinctErrors)
	for err := range distinctErrors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := f.budget(t).Consumed; n != 16 {
		t.Fatalf("lost concurrent reservations: %d", n)
	}
}

type limitedRandom struct{ left int }

func (r *limitedRandom) Read(b []byte) (int, error) {
	if r.left == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	n := min(len(b), r.left)
	for i := range n {
		b[i] = byte(i)
	}
	r.left -= n
	return n, nil
}

func TestFileStoreRandomFailureConsumesOnlyReservedBudget(t *testing.T) {
	f := makeFixture(t)
	s := f.open(t, fileOps{random: &limitedRandom{left: 16}})
	secret := credential.NewSecret([]byte("public-secret"))
	defer secret.Zero()
	if err := s.Put(t.Context(), f.ref, secret); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("random failure: %v", err)
	}
	if n := f.budget(t).Consumed; n != 4 {
		t.Fatalf("budget=%d", n)
	}
	if _, err := os.Stat(f.itemPath(t, f.ref)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected item: %v", err)
	}
}
