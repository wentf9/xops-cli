//go:build integration && linux && amd64

package credentialfile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/wentf9/xops-cli/internal/credentialfile/format"
	"github.com/wentf9/xops-cli/pkg/credential"
)

func adminMaterial(t *testing.T, f fixture) Wrapping {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key")
	writeFixtureFile(t, path, f.data["file_key"])
	return Wrapping{Mode: "key-file", KeyFile: path}
}

func TestMaintenanceUpgrade(t *testing.T) {
	for _, rotate := range []bool{false, true} {
		t.Run(map[bool]string{false: "rewrap", true: "reencrypt"}[rotate], func(t *testing.T) {
			f := makeFixture(t)
			s := f.open(t, fileOps{})
			material := adminMaterial(t, f)
			secret := credential.NewSecret([]byte("public-maintenance-value"))
			defer secret.Zero()
			if err := s.Put(t.Context(), f.ref, secret); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(f.itemPath(t, f.ref))
			if err != nil {
				t.Fatal(err)
			}
			var result MaintenanceResult
			if rotate {
				result, err = s.Reencrypt(t.Context(), material)
			} else {
				result, err = s.Rewrap(t.Context(), material)
			}
			if err != nil {
				t.Fatal(err)
			}
			if !result.Applied || !result.Durable || result.Stage != format.Committed {
				t.Fatalf("result %+v", result)
			}
			got, err := s.Get(t.Context(), f.ref)
			if err != nil {
				t.Fatal(err)
			}
			defer got.Zero()
			if !bytes.Equal(got.Value, secret.Value) {
				t.Fatal("changed value")
			}
			pub, err := s.publication(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			d, err := revisionDir(s.root, pub.current.Revision)
			if err != nil {
				t.Fatal(err)
			}
			defer closeFileTest(t, d.file)
			items, err := d.child("items")
			if err != nil {
				t.Fatal(err)
			}
			defer closeFileTest(t, items.file)
			name, err := format.ItemFilename(f.ref.ItemID)
			if err != nil {
				t.Fatal(err)
			}
			after, err := items.read(t.Context(), name, format.MaxItemBytes)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(before, after) == rotate {
				t.Fatal("incorrect ciphertext copy/rotation")
			}
			if err := s.Put(t.Context(), f.ref, secret); err != nil {
				t.Fatal("committed transaction blocks writes", err)
			}
		})
	}
}
func closeFileTest(t *testing.T, f *os.File) {
	t.Helper()
	if err := f.Close(); err != nil {
		t.Error(err)
	}
}

func TestMaintenanceInit(t *testing.T) {
	f := makeFixture(t)
	material := adminMaterial(t, f)
	r := testRuntime(t, nil, nil)
	path := filepath.Join(t.TempDir(), "new")
	result, err := r.Init(t.Context(), path, "offline", material)
	if errors.Is(err, ErrUnsupported) {
		t.Skip("required filesystem operations unavailable")
	}
	if err != nil {
		t.Fatal(err)
	}
	if !result.Durable || result.Revision != 1 || result.Generation != 1 {
		t.Fatalf("result %+v", result)
	}
	s, err := r.OpenStore(t.Context(), path, "offline", Options{}, SessionOptions{Mode: "key-file", KeyFile: material.KeyFile})
	if err != nil {
		t.Fatal(err)
	}
	secret := credential.NewSecret([]byte("public-new-value"))
	defer secret.Zero()
	if err := s.Put(t.Context(), f.ref, secret); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Init(t.Context(), path, "offline", material); !errors.Is(err, ErrConflict) {
		t.Fatalf("repeat init: %v", err)
	}
}

func TestMaintenanceTransfer(t *testing.T) {
	for _, clone := range []bool{true, false} {
		t.Run(map[bool]string{true: "clone", false: "restore"}[clone], func(t *testing.T) {
			f := makeFixture(t)
			s := f.open(t, fileOps{})
			material := adminMaterial(t, f)
			secret := credential.NewSecret([]byte("public-transfer"))
			defer secret.Zero()
			if err := s.Put(t.Context(), f.ref, secret); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "destination")
			id := "offline"
			var result MaintenanceResult
			var err error
			if clone {
				id = "copy"
				result, err = s.Clone(t.Context(), path, id, material)
			} else {
				result, err = s.Restore(t.Context(), path, material, []credential.Ref{f.ref})
			}
			if err != nil {
				t.Fatal(err)
			}
			if !result.Durable {
				t.Fatalf("result %+v", result)
			}
			r := testRuntime(t, nil, nil)
			target, err := r.OpenStore(t.Context(), path, id, Options{}, SessionOptions{Mode: "key-file", KeyFile: material.KeyFile})
			if err != nil {
				t.Fatal(err)
			}
			got, err := target.Get(t.Context(), credential.Ref{StoreID: id, ItemID: f.ref.ItemID})
			if err != nil {
				t.Fatal(err)
			}
			defer got.Zero()
			if !bytes.Equal(got.Value, secret.Value) {
				t.Fatal("changed secret")
			}
			srcPub, err := s.publication(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			dstPub, err := target.publication(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if (srcPub.current.VaultID != dstPub.current.VaultID) != clone {
				t.Fatal("vault identity")
			}
			if err := s.Put(t.Context(), f.ref, secret); err != nil {
				t.Fatal("source remains blocked", err)
			}
		})
	}
}

func TestMaintenanceResume(t *testing.T) {
	for _, point := range []string{"admin:stage-1", "admin:stage-2", "admin:stage-3", "admin:stage-4", "admin:stage-5", "admin:archive"} {
		t.Run(point, func(t *testing.T) {
			f := makeFixture(t)
			s := f.open(t, fileOps{})
			material := adminMaterial(t, f)
			secret := credential.NewSecret([]byte("public-resume"))
			defer secret.Zero()
			if err := s.Put(t.Context(), f.ref, secret); err != nil {
				t.Fatal(err)
			}
			injected := errors.New("injected failure")
			s.ops.before = func(step string) error {
				if step == point {
					return injected
				}
				return nil
			}
			if _, err := s.Reencrypt(t.Context(), material); !errors.Is(err, injected) {
				t.Fatalf("inject: %v", err)
			}
			s.ops = fileOps{}
			result, err := s.Resume(t.Context(), material, material)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Durable {
				t.Fatalf("result %+v", result)
			}
			got, err := s.Get(t.Context(), f.ref)
			if err != nil {
				t.Fatal(err)
			}
			defer got.Zero()
			if !bytes.Equal(got.Value, secret.Value) {
				t.Fatal("changed secret")
			}
			if err := s.Put(t.Context(), f.ref, secret); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMaintenancePrune(t *testing.T) {
	f := makeFixture(t)
	s := f.open(t, fileOps{})
	material := adminMaterial(t, f)
	if _, err := s.Rewrap(t.Context(), material); err != nil {
		t.Fatal(err)
	}
	plan, err := s.Prune(t.Context(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Revisions) != 1 || plan.Revisions[0] != 1 {
		t.Fatalf("plan %+v", plan)
	}
	if _, err := os.Stat(filepath.Join(f.root, "revisions/1")); err != nil {
		t.Fatal("plan deleted", err)
	}
	if _, err := s.Prune(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.root, "key-state/1/budget")); err != nil {
		t.Fatal("shared budget deleted", err)
	}
	if _, err := s.Reencrypt(t.Context(), material); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Prune(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.root, "key-state/1")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old budget retained: %v", err)
	}
	plan, err = s.Prune(t.Context(), false)
	if err != nil || len(plan.Revisions) != 0 {
		t.Fatalf("plan %+v %v", plan, err)
	}
}

func TestMaintenanceBudgetRebuild(t *testing.T) {
	f := makeFixture(t)
	s := f.open(t, fileOps{})
	material := adminMaterial(t, f)
	secret := credential.NewSecret([]byte("public-rebuild"))
	defer secret.Zero()
	if err := s.Put(t.Context(), f.ref, secret); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("building stop")
	s.ops.before = func(step string) error {
		if step == "admin:stage-2" {
			return injected
		}
		return nil
	}
	old, err := s.Reencrypt(t.Context(), material)
	if !errors.Is(err, injected) {
		t.Fatal(err)
	}
	s.ops = fileOps{}
	if err := os.Remove(filepath.Join(f.root, "key-state/2/budget")); err != nil {
		t.Fatal(err)
	}
	result, err := s.Resume(t.Context(), material, material)
	if err != nil {
		t.Fatal(err)
	}
	if result.Generation <= old.Generation || result.Revision <= old.Revision {
		t.Fatalf("reused target: %+v -> %+v", old, result)
	}
	if _, err := s.Prune(t.Context(), true); err != nil {
		t.Fatal(err)
	}
}

func TestMaintenancePruneResume(t *testing.T) {
	for _, point := range []string{"admin:stage-6", "admin:unlink", "admin:rmdir", "admin:prune-archive"} {
		t.Run(point, func(t *testing.T) {
			f := makeFixture(t)
			s := f.open(t, fileOps{})
			material := adminMaterial(t, f)
			if _, err := s.Reencrypt(t.Context(), material); err != nil {
				t.Fatal(err)
			}
			injected := errors.New("prune stop")
			s.ops.before = func(step string) error {
				if step == point {
					return injected
				}
				return nil
			}
			if _, err := s.Prune(t.Context(), true); !errors.Is(err, injected) {
				t.Fatal(err)
			}
			s.ops = fileOps{}
			result, err := s.Resume(t.Context(), material, material)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Durable {
				t.Fatalf("result %+v", result)
			}
		})
	}
}
