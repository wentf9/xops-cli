//go:build integration && linux && amd64

package credentialfile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/wentf9/xops-cli/pkg/credential"
)

func TestMaintenanceBuildingBudgetUndercount(t *testing.T) {
	f := makeFixture(t)
	s := f.open(t, fileOps{})
	material := adminMaterial(t, f)
	secret := credential.NewSecret([]byte("public-budget-recovery"))
	defer secret.Zero()
	refs := []credential.Ref{f.ref, {StoreID: f.ref.StoreID, ItemID: "second"}}
	for _, ref := range refs {
		if err := s.Put(t.Context(), ref, secret); err != nil {
			t.Fatal(err)
		}
	}
	var originalBudget []byte
	stop := errors.New("stop after first target item")
	s.ops.before = func(step string) error {
		if step == "admin:item:dir-sync" {
			return stop
		}
		return nil
	}
	s.ops.after = func(step string) {
		if step == "admin:new-budget:dir-sync" {
			var err error
			originalBudget, err = os.ReadFile(filepath.Join(f.root, "key-state/2/budget"))
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	previous, err := s.Reencrypt(t.Context(), material)
	if !errors.Is(err, stop) {
		t.Fatalf("stop: %+v %v", previous, err)
	}
	s.ops = fileOps{}
	if len(originalBudget) == 0 {
		t.Fatal("missing original budget")
	}
	// Replay the genuine, authenticated initial budget, below the one published item.
	writeFixtureFile(t, filepath.Join(f.root, "key-state/2/budget"), originalBudget)
	result, err := s.Resume(t.Context(), material, material)
	if err != nil {
		t.Fatal(err)
	}
	if result.Generation <= previous.Generation || result.Revision <= previous.Revision || !result.Durable {
		t.Fatalf("uncertain target reused: %+v -> %+v", previous, result)
	}
	for _, ref := range refs {
		got, err := s.Get(t.Context(), ref)
		equal := bytes.Equal(got.Value, secret.Value)
		got.Zero()
		if err != nil || !equal {
			t.Fatalf("restored value: %v", err)
		}
	}
}

func TestMaintenanceCommittedBudgetInvalid(t *testing.T) {
	for _, kind := range []string{"missing", "corrupt", "residue", "undercount"} {
		t.Run(kind, func(t *testing.T) {
			f := makeFixture(t)
			s := f.open(t, fileOps{})
			material := adminMaterial(t, f)
			secret := credential.NewSecret([]byte("public-committed-budget"))
			defer secret.Zero()
			if err := s.Put(t.Context(), f.ref, secret); err != nil {
				t.Fatal(err)
			}
			var originalBudget []byte
			stop := errors.New("stop before archive")
			s.ops.before = func(step string) error {
				if step == "admin:stage-5" {
					return stop
				}
				return nil
			}
			s.ops.after = func(step string) {
				if step == "admin:new-budget:dir-sync" {
					var err error
					originalBudget, err = os.ReadFile(filepath.Join(f.root, "key-state/2/budget"))
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			previous, err := s.Reencrypt(t.Context(), material)
			if !errors.Is(err, stop) {
				t.Fatal(err)
			}
			s.ops = fileOps{}
			budgetPath := filepath.Join(f.root, "key-state/2/budget")
			healthyBudget, err := os.ReadFile(budgetPath)
			if err != nil {
				t.Fatal(err)
			}
			invalidateMaintenanceBudget(t, budgetPath, kind, originalBudget)
			result, err := s.Resume(t.Context(), material, material)
			if err == nil || !result.Applied || result.Durable {
				t.Fatalf("accepted invalid budget: %+v %v", result, err)
			}
			if _, err := os.Stat(filepath.Join(f.root, "transactions", previous.OperationID, "state")); err != nil {
				t.Fatalf("lost recovery intent: %v", err)
			}
			current, err := s.publication(t.Context())
			if err != nil || current.current.Revision != previous.Revision {
				t.Fatalf("changed publication: %v", err)
			}
			// Restore the exact durable test artifact, then confirm the retained task can finish.
			writeFixtureFile(t, budgetPath, healthyBudget)
			if kind == "residue" {
				if err := os.Remove(filepath.Join(f.root, "key-state/2/.tmp-budget")); err != nil {
					t.Fatal(err)
				}
			}
			result, err = s.Resume(t.Context(), material, material)
			if err != nil || !result.Durable {
				t.Fatalf("healthy resume: %+v %v", result, err)
			}
		})
	}
}

func invalidateMaintenanceBudget(t *testing.T, path, kind string, original []byte) {
	t.Helper()
	switch kind {
	case "missing":
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	case "corrupt":
		writeFixtureFile(t, path, []byte("invalid"))
	case "residue":
		writeFixtureFile(t, filepath.Join(filepath.Dir(path), ".tmp-budget"), []byte("partial"))
	case "undercount":
		writeFixtureFile(t, path, original)
	default:
		t.Fatalf("unknown budget fault %q", kind)
	}
}

func TestMaintenanceArchivedBudgetInvalid(t *testing.T) {
	for _, kind := range []string{"missing", "corrupt", "residue", "undercount"} {
		t.Run(kind, func(t *testing.T) {
			f := makeFixture(t)
			source := f.open(t, fileOps{})
			material := adminMaterial(t, f)
			secret := credential.NewSecret([]byte("public-archived-budget"))
			defer secret.Zero()
			if err := source.Put(t.Context(), f.ref, secret); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "clone")
			var original []byte
			stop := errors.New("stop after archive before source cleanup")
			archived := false
			source.ops.before = func(step string) error {
				if archived && step == "admin:unlink" {
					return stop
				}
				return nil
			}
			source.ops.after = func(step string) {
				if step == "admin:archive" {
					archived = true
				}
				if step == "admin:new-budget:dir-sync" {
					var err error
					original, err = os.ReadFile(filepath.Join(path, "key-state/1/budget"))
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			previous, err := source.Clone(t.Context(), path, "clone", material)
			if !errors.Is(err, stop) {
				t.Fatal(err)
			}
			source.ops = fileOps{}
			r := testRuntime(t, nil, nil)
			dest, err := r.OpenStore(t.Context(), path, "clone", Options{}, SessionOptions{Mode: "key-file", KeyFile: material.KeyFile})
			if err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(f.root, "transactions", previous.OperationID, "state")
			before, err := os.ReadFile(marker)
			if err != nil {
				t.Fatal(err)
			}
			budgetPath := filepath.Join(path, "key-state/1/budget")
			invalidateMaintenanceBudget(t, budgetPath, kind, original)
			result, err := dest.ResumeFrom(t.Context(), source, material, material)
			if err == nil || !result.Applied || result.Durable {
				t.Fatalf("accepted archived budget: %+v %v", result, err)
			}
			after, err := os.ReadFile(marker)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("source marker modified: %v", err)
			}
		})
	}
}

func TestMaintenanceArchivedResumeAfterMutations(t *testing.T) {
	f := makeFixture(t)
	s := f.open(t, fileOps{})
	material := adminMaterial(t, f)
	secret := credential.NewSecret([]byte("public-mutable-archive"))
	defer secret.Zero()
	if err := s.Put(t.Context(), f.ref, secret); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reencrypt(t.Context(), material); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(t.Context(), f.ref); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"new-one", "new-two"} {
		if err := s.Put(t.Context(), credential.Ref{StoreID: f.ref.StoreID, ItemID: id}, secret); err != nil {
			t.Fatal(err)
		}
	}
	result, err := s.Resume(t.Context(), material, material)
	if err != nil || !result.Durable {
		t.Fatalf("mutable archive rejected: %+v %v", result, err)
	}
}

func TestMaintenancePruneRejectsUnreliableBudget(t *testing.T) {
	for _, resume := range []bool{false, true} {
		f := makeFixture(t)
		s := f.open(t, fileOps{})
		material := adminMaterial(t, f)
		secret := credential.NewSecret([]byte("public-prune-budget"))
		defer secret.Zero()
		if err := s.Put(t.Context(), f.ref, secret); err != nil {
			t.Fatal(err)
		}
		var initial []byte
		s.ops.after = func(step string) {
			if step == "admin:new-budget:dir-sync" {
				var err error
				initial, err = os.ReadFile(filepath.Join(f.root, "key-state/2/budget"))
				if err != nil {
					t.Fatal(err)
				}
			}
		}
		if _, err := s.Reencrypt(t.Context(), material); err != nil {
			t.Fatal(err)
		}
		s.ops = fileOps{}
		if resume {
			stop := errors.New("prune intent stop")
			s.ops.before = func(step string) error {
				if step == "admin:stage-6" {
					return stop
				}
				return nil
			}
			if _, err := s.Prune(t.Context(), true); !errors.Is(err, stop) {
				t.Fatal(err)
			}
			s.ops = fileOps{}
		}
		writeFixtureFile(t, filepath.Join(f.root, "key-state/2/budget"), initial)
		var result MaintenanceResult
		var err error
		if resume {
			result, err = s.Resume(t.Context(), material, material)
		} else {
			var plan PruneResult
			plan, err = s.Prune(t.Context(), true)
			result = plan.Maintenance
		}
		if !errors.Is(err, ErrMaintenanceRequired) || result.Changed {
			t.Fatalf("uncertain cleanup: %+v %v", result, err)
		}
		if _, err := os.Stat(filepath.Join(f.root, "revisions/1/vault.meta")); err != nil {
			t.Fatal("old revision removed", err)
		}
		entries, err := os.ReadDir(filepath.Join(f.root, "transactions"))
		if err != nil {
			t.Fatal(err)
		}
		expected := 0
		if resume {
			expected = 1
		}
		if len(entries) != expected {
			t.Fatal("unexpected intent mutation")
		}
	}
}
