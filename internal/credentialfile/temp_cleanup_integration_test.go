//go:build integration && linux && amd64

package credentialfile

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/internal/credentialfile/format"
	"github.com/wentf9/xops-cli/pkg/credential"
	"golang.org/x/sys/unix"
)

// Run umask changes in a dedicated child, never in the shared integration process.
func TestTempValidationHelper(t *testing.T) {
	stage := os.Getenv("XOPS_TEST_TEMP_FAILURE")
	if stage == "" {
		return
	}
	if stage != "budget" && stage != "item" {
		t.Fatal("unknown test stage")
	}
	f := fixture{root: os.Getenv("XOPS_TEST_VAULT_ROOT"), data: fixtureData(t), ref: credential.Ref{StoreID: "offline", ItemID: "temp-validation"}}
	f.keys = unlockFunc(func(ctx context.Context, b []byte) ([]byte, error) {
		if err := context.Cause(ctx); err != nil {
			return nil, err
		}
		_, key, err := format.OpenMeta(b, f.data["wrapping_key"], "offline")
		return key, err
	})
	previous := -1
	defer func() {
		if previous >= 0 {
			unix.Umask(previous)
		}
	}()
	armed := stage == "item"
	s := f.open(t, fileOps{after: func(step string) {
		if armed && step == "budget:dir-sync" {
			armed = false
			previous = unix.Umask(0777)
		}
	}})
	if stage == "budget" {
		previous = unix.Umask(0777)
	}
	secret := credential.NewSecret([]byte("public-temp-validation-secret"))
	defer secret.Zero()
	err := s.Put(t.Context(), f.ref, secret)
	if previous < 0 {
		t.Fatal("umask injection did not run")
	}
	unix.Umask(previous)
	previous = -1
	if !errors.Is(err, credential.ErrCredentialAccessDenied) {
		t.Fatalf("validation error lost: %v", err)
	}
	for _, dir := range []string{"key-state/1", "revisions/1/items"} {
		entries, err := os.ReadDir(filepath.Join(f.root, dir))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".tmp-") {
				t.Fatalf("validation left a temporary file in %s", dir)
			}
		}
	}
	want := uint64(3)
	if stage == "item" {
		want = 4
	}
	if got := f.budget(t).Consumed; got != want {
		t.Fatalf("failed write budget=%d want=%d", got, want)
	}
	if _, err := os.Stat(f.itemPath(t, f.ref)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed write published an item: %v", err)
	}
	if err := s.Put(t.Context(), f.ref, secret); err != nil {
		t.Fatalf("retry after restoring umask failed: %v", err)
	}
	if got := f.budget(t).Consumed; got != want+1 {
		t.Fatalf("retry budget=%d want=%d", got, want+1)
	}
}

func TestTempValidationFailureCleansUpAndAllowsRetry(t *testing.T) {
	for _, stage := range []string{"budget", "item"} {
		t.Run(stage, func(t *testing.T) {
			f := makeFixture(t)
			f.open(t, fileOps{})
			cmd, cancel := childCommand(t, f, "")
			defer cancel()
			cmd.Args = []string{os.Args[0], "-test.run=^TestTempValidationHelper$", "-test.count=1"}
			cmd.Env = append(cmd.Env, "XOPS_TEST_TEMP_FAILURE="+stage)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("child cleanup regression: %v\n%s", err, out)
			}
		})
	}
}

func TestTempCreationCollisionPreservesExistingFile(t *testing.T) {
	f := makeFixture(t)
	s := f.open(t, fileOps{})
	// Test the creation primitive directly: ordinary operations reject existing
	// unexplained .tmp files even before reaching O_EXCL.
	name := ".tmp-" + strings.Repeat("42", 16)
	path := filepath.Join(f.root, name)
	existing := []byte("public-existing-temporary-file")
	writeFixtureFile(t, path, existing)
	out, err := s.root.write(t.Context(), "unpublished", []byte("public-new-data"), false, "put", fileOps{random: bytes.NewReader(bytes.Repeat([]byte{0x42}, 16))})
	if !errors.Is(err, os.ErrExist) || out.applied {
		t.Fatalf("creation collision outcome: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, existing) {
		t.Fatal("pre-existing temporary file was removed or overwritten")
	}
}
