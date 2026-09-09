package credential

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestAssetDeletionOutcomesAndRecovery(t *testing.T) {
	for _, scenario := range []string{"success", "shared", "conflict", "uncertain", "locked", "intent failure"} {
		t.Run(scenario, func(t *testing.T) {
			svc, store, cfg, journal, _ := setupTestService(t)
			ref := Ref{StoreID: "test-store", ItemID: "old"}
			store.data[ref.ItemID] = []byte("retained-secret")
			cfg.activeRefs[ref] = true
			injected := errors.New("injected deletion failure")
			if scenario == "locked" {
				store.delErr = ErrCredentialStoreLocked
			}
			if scenario == "intent failure" {
				journal.syncDirFn = func(string) error { return injected }
			}
			called := false
			outcome, err := svc.DeleteAssets(t.Context(), []Ref{ref, ref}, func(context.Context) (MutationOutcome, error) {
				called = true
				if scenario == "conflict" {
					return MutationOutcome{}, ErrConfigConflict
				}
				if scenario != "shared" {
					delete(cfg.activeRefs, ref)
				}
				if scenario == "uncertain" {
					return MutationOutcome{Applied: true}, injected
				}
				return MutationOutcome{Applied: true, Durable: true}, nil
			})
			if called == (scenario == "intent failure") {
				t.Fatal("commit ran despite failed intent, or did not run")
			}
			if (err == nil) != (scenario == "success" || scenario == "shared") {
				t.Fatalf("unexpected result: %+v, %v", outcome, err)
			}
			_, exists := store.data[ref.ItemID]
			if exists != (scenario != "success") {
				t.Fatal("credential was removed before a durable successful deletion")
			}
			if scenario == "locked" {
				var cleanup *CleanupError
				if !errors.As(err, &cleanup) || !errors.Is(err, ErrCredentialStoreLocked) {
					t.Fatalf("cleanup outcome lost: %v", err)
				}
			}
			if scenario == "uncertain" {
				cfg.checkUnrefHook = func(Ref) (bool, error) { return false, injected }
				results, err := svc.GC(t.Context())
				if err != nil || len(results) != 1 || results[0].Err == nil {
					t.Fatalf("GC ignored durability failure: %+v %v", results, err)
				}
				if _, exists := store.data[ref.ItemID]; !exists {
					t.Fatal("uncertain credential removed")
				}
				cfg.checkUnrefHook = nil
			}
			wantRetained := cfg.activeRefs[ref]
			assertAssetRecovery(t, svc, store, cfg, journal, ref, wantRetained)
		})
	}
}

func assertAssetRecovery(t *testing.T, svc *Service, store *memoryStore, cfg *mockConfigUpdater, journal *JournalStore, ref Ref, wantRetained bool) {
	t.Helper()
	store.delErr = nil
	journal.syncDirFn = nil
	restarted, err := NewService(svc.registry, journal, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	results, err := restarted.GC(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range results {
		if result.Err != nil {
			t.Fatal(result.Err)
		}
	}
	_, exists := store.data[ref.ItemID]
	if exists != wantRetained {
		t.Fatal("recovery deleted a referenced secret or failed to clean an orphan")
	}
}

func TestAssetDeletionProtectsLiveIntentFromGC(t *testing.T) {
	svc, store, cfg, journal, _ := setupTestService(t)
	ref := Ref{StoreID: "test-store", ItemID: "old"}
	store.data[ref.ItemID] = []byte("secret")
	cfg.activeRefs[ref] = true
	other, err := NewService(svc.registry, journal, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.DeleteAssets(t.Context(), []Ref{ref}, func(context.Context) (MutationOutcome, error) {
		results, err := other.GC(t.Context())
		if err != nil || len(results) != 1 || results[0].Action != RecoveryActionSkippedActive {
			t.Fatalf("GC raced live deletion: %+v %v", results, err)
		}
		delete(cfg.activeRefs, ref)
		return MutationOutcome{Applied: true, Durable: true}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The child exits with journals locked, either before or after committing the
// simulated authoritative ref state. The parent reconstructs the service solely
// from that persisted state and the on-disk journal, with no in-memory intent.
func TestAssetDeleteProcessCrash(t *testing.T) {
	if dir := os.Getenv("XOPS_TEST_ASSET_CRASH_DIR"); dir != "" {
		journal, err := NewJournalStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		registry := NewRegistry()
		if err := registry.Register("test-store", newMemoryStore()); err != nil {
			t.Fatal(err)
		}
		svc, err := NewService(registry, journal, newMockConfigUpdater(), nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = svc.DeleteAssets(t.Context(), []Ref{{StoreID: "test-store", ItemID: "old"}}, func(context.Context) (MutationOutcome, error) {
			if os.Getenv("XOPS_TEST_ASSET_CRASH_COMMIT") == "1" {
				if err := os.WriteFile(filepath.Join(dir, "committed"), []byte("1"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			os.Exit(0)
			return MutationOutcome{}, nil
		})
		t.Fatalf("crash callback did not exit: %v", err)
	}
	for _, commit := range []string{"0", "1"} {
		t.Run(commit, func(t *testing.T) {
			dir := t.TempDir()
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestAssetDeleteProcessCrash$")
			cmd.Env = append(os.Environ(), "XOPS_TEST_ASSET_CRASH_DIR="+dir, "XOPS_TEST_ASSET_CRASH_COMMIT="+commit)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("crash child: %v %s", err, out)
			}
			svc, store, cfg, _, _ := setupTestService(t)
			journal, err := NewJournalStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			svc.journal = journal
			ref := Ref{StoreID: "test-store", ItemID: "old"}
			store.data[ref.ItemID] = []byte("secret")
			_, statErr := os.Stat(filepath.Join(dir, "committed"))
			cfg.activeRefs[ref] = errors.Is(statErr, os.ErrNotExist)
			results, err := svc.GC(t.Context())
			if err != nil || len(results) != 1 || results[0].Err != nil {
				t.Fatalf("crash recovery: %+v %v", results, err)
			}
			_, exists := store.data[ref.ItemID]
			if exists != (commit == "0") {
				t.Fatal("crash recovery ignored authoritative references")
			}
		})
	}
}
