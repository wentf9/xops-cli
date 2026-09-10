//go:build integration && linux && amd64

package credentialfile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/internal/credentialfile/format"
	"github.com/wentf9/xops-cli/internal/kdfhelper"
	"github.com/wentf9/xops-cli/pkg/credential"
)

func TestMaintenanceSourceChangedWithoutRevision(t *testing.T) {
	f := makeFixture(t)
	s := f.open(t, fileOps{})
	material := adminMaterial(t, f)
	secret := credential.NewSecret([]byte("public-original"))
	defer secret.Zero()
	if err := s.Put(t.Context(), f.ref, secret); err != nil {
		t.Fatal(err)
	}
	stop := errors.New("verified stop")
	s.ops.before = func(step string) error {
		if step == "admin:stage-3" {
			return stop
		}
		return nil
	}
	if _, err := s.Reencrypt(t.Context(), material); !errors.Is(err, stop) {
		t.Fatal(err)
	}
	s.ops = fileOps{}
	// A valid old-program write changes content but does not advance CURRENT.
	changed := credential.NewSecret([]byte("public-changed"))
	defer changed.Zero()
	data, err := format.SealItem(format.ItemIdentity{VaultID: identityVault(t, f), Generation: 1, Ref: f.ref}, [12]byte{42}, f.data["dek"], changed)
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, f.itemPath(t, f.ref), data)
	if _, err := s.Resume(t.Context(), material, material); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed source accepted: %v", err)
	}
	p, err := s.publication(t.Context())
	if err != nil || p.current.Revision != 1 {
		t.Fatalf("published changed source: %+v %v", p.current, err)
	}
}
func identityVault(t *testing.T, f fixture) [16]byte {
	t.Helper()
	m, err := format.ParseMeta(f.data["meta_file"])
	if err != nil {
		t.Fatal(err)
	}
	return m.VaultID
}

func TestMaintenanceExpiredAndUnknownRevision(t *testing.T) {
	f := makeFixture(t)
	s := f.open(t, fileOps{})
	material := adminMaterial(t, f)
	expired := time.Now().Add(-time.Hour).UTC()
	secret := credential.NewSecret([]byte("public-expired"))
	secret.ExpiresAt = &expired
	defer secret.Zero()
	data, err := format.SealItem(format.ItemIdentity{VaultID: identityVault(t, f), Generation: 1, Ref: f.ref}, [12]byte{41}, f.data["dek"], secret)
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, f.itemPath(t, f.ref), data)
	if err := os.Mkdir(filepath.Join(f.root, "revisions/99"), 0700); err != nil {
		t.Fatal(err)
	}
	result, err := s.Reencrypt(t.Context(), material)
	if err != nil {
		t.Fatal(err)
	}
	if result.Revision != 100 {
		t.Fatalf("allocated %+v", result)
	}
	got, err := s.Get(t.Context(), f.ref)
	got.Zero()
	if !errors.Is(err, credential.ErrCredentialNotFound) {
		t.Fatalf("expired visible: %v", err)
	}
	p, err := s.snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	key, err := unlockWrapping(t.Context(), nil, material, p.data)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	dir, err := revisionDir(s.root, result.Revision)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFileTest(t, dir.file)
	items, err := dir.child("items")
	if err != nil {
		t.Fatal(err)
	}
	defer closeFileTest(t, items.file)
	name, err := format.ItemFilename(f.ref.ItemID)
	if err != nil {
		t.Fatal(err)
	}
	b, err := items.read(t.Context(), name, format.MaxItemBytes)
	if err != nil {
		t.Fatal(err)
	}
	got, err = format.OpenItem(b, key, format.ItemIdentity{VaultID: p.current.VaultID, Generation: p.current.Generation, Ref: f.ref})
	if err != nil {
		t.Fatal(err)
	}
	defer got.Zero()
	if !bytes.Equal(got.Value, secret.Value) || !sameExpiry(got.ExpiresAt, secret.ExpiresAt) {
		t.Fatal("expired content changed")
	}
	plan, err := s.Prune(t.Context(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Revisions) != 1 || plan.Revisions[0] != 1 {
		t.Fatalf("unknown included: %+v", plan)
	}
	// The unknown incomplete revision also prevents guessing whether an old budget is unused.
	if _, err := s.Prune(t.Context(), true); !errors.Is(err, ErrMaintenanceRequired) {
		t.Fatalf("unknown budget references ignored: %v", err)
	}
	if _, err := os.Stat(filepath.Join(f.root, "revisions/99")); err != nil {
		t.Fatal(err)
	}
}

func TestMaintenanceInitResume(t *testing.T) {
	for _, point := range []string{"admin:stage-1", "admin:stage-3", "admin:stage-4"} {
		t.Run(point, func(t *testing.T) {
			f := makeFixture(t)
			r := testRuntime(t, nil, nil)
			material := adminMaterial(t, f)
			path := filepath.Join(t.TempDir(), "new")
			stop := errors.New("init stop")
			_, err := r.initialize(t.Context(), path, "offline", material, fileOps{before: func(step string) error {
				if step == point {
					return stop
				}
				return nil
			}})
			if !errors.Is(err, stop) {
				t.Fatal(err)
			}
			s, err := r.OpenStore(t.Context(), path, "offline", Options{}, SessionOptions{Mode: "key-file", KeyFile: material.KeyFile})
			if err != nil {
				t.Fatal(err)
			}
			result, err := s.Resume(t.Context(), Wrapping{}, material)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Durable {
				t.Fatalf("result %+v", result)
			}
		})
	}
}

func TestMaintenanceLockCancelsResumeDerivation(t *testing.T) {
	password := []byte("public-long-master-password")
	var block atomic.Bool
	entered := make(chan struct{})
	derive := deriveFunc(func(ctx context.Context, req kdfhelper.Request) ([]byte, error) {
		if block.Load() {
			close(entered)
			<-ctx.Done()
			return nil, context.Cause(ctx)
		}
		sum := sha256.Sum256(append(bytes.Clone(req.Salt[:]), req.Password...))
		return bytes.Clone(sum[:]), nil
	})
	r := testRuntime(t, promptFunc(func(context.Context, string) ([]byte, error) { return bytes.Clone(password), nil }), derive)
	path := filepath.Join(t.TempDir(), "prompt")
	material := Wrapping{Mode: "prompt", Password: password}
	if _, err := r.Init(t.Context(), path, "offline", material); err != nil {
		t.Fatal(err)
	}
	s, err := r.OpenStore(t.Context(), path, "offline", Options{}, SessionOptions{Mode: "prompt"})
	if err != nil {
		t.Fatal(err)
	}
	stop := errors.New("prepared stop")
	s.ops.before = func(step string) error {
		if step == "admin:stage-1" {
			return stop
		}
		return nil
	}
	if _, err := s.Reencrypt(t.Context(), material); !errors.Is(err, stop) {
		t.Fatal(err)
	}
	s.ops = fileOps{}
	block.Store(true)
	done := make(chan error, 1)
	go func() { _, err := s.Resume(t.Context(), material, material); done <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("derive not started")
	}
	lockCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := s.Lock(lockCtx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, credential.ErrCredentialStoreLocked) {
		t.Fatalf("resume cancellation: %v", err)
	}
}

func TestMaintenanceNonInteractiveAndOverlap(t *testing.T) {
	f := makeFixture(t)
	r := testRuntime(t, nil, nil)
	material := adminMaterial(t, f)
	s := runtimeStore(t, r, f, SessionOptions{Mode: "key-file", KeyFile: material.KeyFile, NonInteractive: true})
	if _, err := s.Rewrap(t.Context(), Wrapping{Mode: "prompt", Password: []byte("public-long-password")}); !errors.Is(err, credential.ErrCredentialStoreLocked) {
		t.Fatalf("noninteractive bypass: %v", err)
	}
	path := filepath.Join(f.root, "nested")
	if _, err := s.Clone(t.Context(), path, "copy", material); !errors.Is(err, ErrConflict) {
		t.Fatalf("nested accepted: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("nested path created: %v", err)
	}
}

func TestMaintenanceTransferResumeAndWrongMarker(t *testing.T) {
	for _, point := range []string{"admin:stage-1", "admin:stage-3", "admin:stage-4", "admin:archive", "admin:unlink"} {
		t.Run(point, func(t *testing.T) {
			f := makeFixture(t)
			source := f.open(t, fileOps{})
			material := adminMaterial(t, f)
			path := filepath.Join(t.TempDir(), "copy")
			stop := errors.New("transfer stop")
			source.ops.before = func(step string) error {
				if step == point {
					return stop
				}
				return nil
			}
			result, err := source.Clone(t.Context(), path, "copy", material)
			if !errors.Is(err, stop) {
				t.Fatal(err)
			}
			source.ops = fileOps{}
			r := testRuntime(t, nil, nil)
			dest, err := r.OpenStore(t.Context(), path, "copy", Options{}, SessionOptions{Mode: "key-file", KeyFile: material.KeyFile})
			if err != nil {
				t.Fatal(err)
			}
			if result.Applied {
				unrelated := makeFixture(t)
				wrong := unrelated.open(t, fileOps{})
				marker := filepath.Join(unrelated.root, "transactions", result.OperationID)
				if err := os.Mkdir(marker, 0700); err != nil {
					t.Fatal(err)
				}
				original := []byte("unrelated state")
				writeFixtureFile(t, filepath.Join(marker, "state"), original)
				if _, err := dest.ResumeFrom(t.Context(), wrong, material, material); err == nil {
					t.Fatal("wrong marker accepted")
				}
				got, err := os.ReadFile(filepath.Join(marker, "state"))
				if err != nil || !bytes.Equal(got, original) {
					t.Fatalf("wrong marker modified: %v", err)
				}
			}
			result, err = dest.ResumeFrom(t.Context(), source, material, material)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Durable {
				t.Fatalf("result %+v", result)
			}
			entries, err := os.ReadDir(filepath.Join(f.root, "transactions"))
			if err != nil || len(entries) != 0 {
				t.Fatalf("source marker retained %v %v", entries, err)
			}
		})
	}
}

func TestMaintenancePruneReportsPartialDeletion(t *testing.T) {
	f := makeFixture(t)
	s := f.open(t, fileOps{})
	material := adminMaterial(t, f)
	if _, err := s.Reencrypt(t.Context(), material); err != nil {
		t.Fatal(err)
	}
	stop := errors.New("sync fail")
	s.ops.before = func(step string) error {
		if step == "admin:rmdir-sync" {
			return stop
		}
		return nil
	}
	result, err := s.Prune(t.Context(), true)
	var durability *DurabilityError
	if !errors.Is(err, stop) || !errors.As(err, &durability) || !durability.Applied || durability.Durable || !result.Maintenance.Changed {
		t.Fatalf("outcome %+v %v", result, err)
	}
	s.ops = fileOps{}
	if _, err := s.Resume(t.Context(), material, material); err != nil {
		t.Fatal(err)
	}
}

func TestMaintenanceVerifiedBudgetUncertain(t *testing.T) {
	f := makeFixture(t)
	s := f.open(t, fileOps{})
	material := adminMaterial(t, f)
	stop := errors.New("verified stop")
	s.ops.before = func(step string) error {
		if step == "admin:stage-3" {
			return stop
		}
		return nil
	}
	previous, err := s.Reencrypt(t.Context(), material)
	if !errors.Is(err, stop) {
		t.Fatal(err)
	}
	s.ops = fileOps{}
	writeFixtureFile(t, filepath.Join(f.root, "key-state/2/.tmp-uncertain"), []byte("partial budget"))
	result, err := s.Resume(t.Context(), material, material)
	if err != nil {
		t.Fatal(err)
	}
	if result.Generation <= previous.Generation {
		t.Fatal("uncertain verified target reused")
	}
}

func TestMaintenanceRestoreMissingReference(t *testing.T) {
	f := makeFixture(t)
	s := f.open(t, fileOps{})
	material := adminMaterial(t, f)
	path := filepath.Join(t.TempDir(), "restore")
	if _, err := s.Restore(t.Context(), path, material, []credential.Ref{{StoreID: "offline", ItemID: "missing"}}); err == nil {
		t.Fatal("missing reference accepted")
	}
	if _, err := os.Stat(filepath.Join(path, "CURRENT")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("incomplete restore published: %v", err)
	}
}

func TestMaintenanceWrappingModeConversion(t *testing.T) {
	f := makeFixture(t)
	fileMaterial := adminMaterial(t, f)
	password := []byte("public-conversion-password")
	derive := deriveFunc(func(_ context.Context, req kdfhelper.Request) ([]byte, error) {
		sum := sha256.Sum256(append(bytes.Clone(req.Salt[:]), req.Password...))
		return bytes.Clone(sum[:]), nil
	})
	prompt := promptFunc(func(context.Context, string) ([]byte, error) { return bytes.Clone(password), nil })
	r := testRuntime(t, prompt, derive)
	s := runtimeStore(t, r, f, SessionOptions{Mode: "key-file", KeyFile: fileMaterial.KeyFile})
	secret := credential.NewSecret([]byte("public-mode-secret"))
	defer secret.Zero()
	if err := s.Put(t.Context(), f.ref, secret); err != nil {
		t.Fatal(err)
	}
	target := Wrapping{Mode: "prompt", Password: password}
	result, err := s.Rewrap(t.Context(), target)
	if err != nil {
		t.Fatal(err)
	}
	if result.Generation != 1 {
		t.Fatal("rewrap rotated DEK")
	}
	got, err := s.Get(t.Context(), f.ref)
	got.Zero()
	if err == nil {
		t.Fatal("old configured mode silently switched")
	}
	if _, err := s.Resume(t.Context(), Wrapping{}, target); err != nil {
		t.Fatal("explicit target recovery failed", err)
	}
	next := testRuntime(t, prompt, derive)
	reader := runtimeStore(t, next, f, SessionOptions{Mode: "prompt"})
	got, err = reader.Get(t.Context(), f.ref)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Zero()
	if !bytes.Equal(got.Value, secret.Value) {
		t.Fatal("conversion changed secret")
	}
}

func TestMaintenanceGuardWaitsForRevocation(t *testing.T) {
	f := makeFixture(t)
	material := adminMaterial(t, f)
	r := testRuntime(t, nil, nil)
	s := runtimeStore(t, r, f, SessionOptions{Mode: "key-file", KeyFile: material.KeyFile})
	a, err := s.admin(t.Context(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := a.close(); err != nil {
			t.Error(err)
		}
	}()
	s.session.requestLock()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	guard := &administration{ctx: ctx, store: s}
	if err := guard.guard(s); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("pending revocation did not wait: %v", err)
	}
	if err := a.close(); err != nil {
		t.Fatal(err)
	}
	guard.ctx = t.Context()
	if err := guard.guard(s); err != nil {
		t.Fatal("could not join after revocation", err)
	}
	if err := guard.close(); err != nil {
		t.Fatal(err)
	}
}
