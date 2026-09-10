//go:build integration && linux && amd64

package credentialfile

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/internal/credentialfile/format"
	"github.com/wentf9/xops-cli/pkg/credential"
)

// The helper uses only public fixture data and a dedicated temporary vault.
func TestVaultProcessHelper(t *testing.T) {
	root := os.Getenv("XOPS_TEST_VAULT_ROOT")
	if root == "" {
		return
	}
	data := fixtureData(t)
	keys := unlockFunc(func(ctx context.Context, b []byte) ([]byte, error) {
		if err := context.Cause(ctx); err != nil {
			return nil, err
		}
		_, key, err := format.OpenMeta(b, data["wrapping_key"], "offline")
		return key, err
	})
	crashAt := os.Getenv("XOPS_TEST_VAULT_CRASH")
	ops := fileOps{after: func(step string) {
		if step == crashAt {
			os.Exit(77)
		}
	}}
	s, err := openStore(t.Context(), root, "offline", Options{Keys: keys, Timeout: 5 * time.Second}, ops)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	}()
	secret := credential.NewSecret([]byte("public-child-secret"))
	defer secret.Zero()
	ref := credential.Ref{StoreID: "offline", ItemID: "child-item"}
	if item := os.Getenv("XOPS_TEST_VAULT_ITEM"); item != "" {
		ref.ItemID = item
	}
	if os.Getenv("XOPS_TEST_VAULT_ACTION") == "delete" {
		if err := s.Delete(t.Context(), ref); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := s.Put(t.Context(), ref, secret); err != nil {
		t.Fatal(err)
	}
}

func childCommand(t *testing.T, f fixture, crashAt string) (*exec.Cmd, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestVaultProcessHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), "XOPS_TEST_VAULT_ROOT="+f.root, "XOPS_TEST_VAULT_CRASH="+crashAt)
	cmd.WaitDelay = time.Second
	return cmd, cancel
}

func TestFileStoreRealProcessExitRecovery(t *testing.T) {
	for _, tc := range []struct {
		name, step      string
		consumed        uint64
		exists, pending bool
	}{
		{"lock_held", "lock:attempt", 3, false, false},
		{"budget_temp_synced", "budget:file-sync", 3, false, true},
		{"budget_published", "budget:publish", 4, false, false},
		{"budget_durable", "budget:dir-sync", 4, false, false},
		{"item_temp_synced", "put:file-sync", 4, false, true},
		{"item_published", "put:publish", 4, true, false},
		{"item_durable", "put:dir-sync", 4, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := makeFixture(t)
			s := f.open(t, fileOps{})
			cmd, cancel := childCommand(t, f, tc.step)
			defer cancel()
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 77 {
				t.Fatalf("child did not exit at fault point: %v, %s", err, out)
			}
			if n := f.budget(t).Consumed; n != tc.consumed {
				t.Fatalf("post-exit budget=%d", n)
			}
			ref := credential.Ref{StoreID: "offline", ItemID: "child-item"}
			got, err := s.Get(t.Context(), ref)
			got.Zero()
			if tc.exists && err != nil {
				t.Fatal(err)
			}
			if !tc.exists && !errors.Is(err, credential.ErrCredentialNotFound) {
				t.Fatalf("post-exit visibility: %v", err)
			}
			secret := credential.NewSecret([]byte("public-child-secret"))
			defer secret.Zero()
			err = s.Put(t.Context(), ref, secret)
			if tc.pending {
				if !errors.Is(err, ErrMaintenanceRequired) {
					t.Fatalf("unexplained residue allowed: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("lock remained held or retry failed: %v", err)
			}
			want := tc.consumed
			if !tc.exists {
				want++
			}
			if n := f.budget(t).Consumed; n != want {
				t.Fatalf("recovery budget=%d want=%d", n, want)
			}
		})
	}
}

func TestFileStoreIndependentProcessesSerializeSameItem(t *testing.T) {
	f := makeFixture(t)
	f.open(t, fileOps{})
	first, cancelFirst := childCommand(t, f, "")
	defer cancelFirst()
	second, cancelSecond := childCommand(t, f, "")
	defer cancelSecond()
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	// Always reap the first child, including second-start failure.
	secondErr := second.Start()
	firstErr := first.Wait()
	if secondErr != nil {
		t.Fatal(secondErr)
	}
	secondErr = second.Wait()
	if err := errors.Join(firstErr, secondErr); err != nil {
		t.Fatal(err)
	}
	if n := f.budget(t).Consumed; n != 4 {
		t.Fatalf("cross-process duplicate reservation: %d", n)
	}
}

func TestFileStoreMissingVaultNeverInitializes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	s, err := Open(t.Context(), path, "offline", Options{})
	if s != nil {
		if closeErr := s.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}
	if !errors.Is(err, credential.ErrCredentialStoreUnavailable) {
		t.Fatalf("missing vault: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Open created a vault: %v", err)
	}
	f := makeFixture(t)
	s, err = Open(t.Context(), f.root, "offline", Options{})
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
	if _, err := s.Get(t.Context(), f.ref); !errors.Is(err, credential.ErrCredentialStoreLocked) {
		t.Fatalf("missing KeySource: %v", err)
	}
}

func TestFileStoreRealProcessDeleteRecovery(t *testing.T) {
	for _, step := range []string{"delete:unlink", "delete:dir-sync"} {
		t.Run(step, func(t *testing.T) {
			f := makeFixture(t)
			s := f.open(t, fileOps{})
			ref := credential.Ref{StoreID: "offline", ItemID: "child-item"}
			secret := credential.NewSecret([]byte("public-child-secret"))
			defer secret.Zero()
			if err := s.Put(t.Context(), ref, secret); err != nil {
				t.Fatal(err)
			}
			cmd, cancel := childCommand(t, f, step)
			defer cancel()
			cmd.Env = append(cmd.Env, "XOPS_TEST_VAULT_ACTION=delete")
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 77 {
				t.Fatalf("child fault missing: %v %s", err, out)
			}
			if err := s.Delete(t.Context(), ref); err != nil {
				t.Fatalf("delete recovery: %v", err)
			}
			if _, err := s.Get(t.Context(), ref); !errors.Is(err, credential.ErrCredentialNotFound) {
				t.Fatal(err)
			}
			if f.budget(t).Consumed != 4 {
				t.Fatal("delete refunded budget")
			}
		})
	}
}

func TestFileStoreIndependentProcessesPreserveBudget(t *testing.T) {
	f := makeFixture(t)
	f.open(t, fileOps{})
	first, cancelFirst := childCommand(t, f, "")
	defer cancelFirst()
	second, cancelSecond := childCommand(t, f, "")
	defer cancelSecond()
	first.Env = append(first.Env, "XOPS_TEST_VAULT_ITEM=child-one")
	second.Env = append(second.Env, "XOPS_TEST_VAULT_ITEM=child-two")
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	secondErr := second.Start()
	firstErr := first.Wait()
	if secondErr != nil {
		t.Fatal(secondErr)
	}
	secondErr = second.Wait()
	if err := errors.Join(firstErr, secondErr); err != nil {
		t.Fatal(err)
	}
	if n := f.budget(t).Consumed; n != 5 {
		t.Fatalf("cross-process budget lost: %d", n)
	}
}
