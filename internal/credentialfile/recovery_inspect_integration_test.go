//go:build integration && linux && amd64

package credentialfile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRecoveryNeedsSourceBeforeTransferPublication(t *testing.T) {
	for _, clone := range []bool{true, false} {
		f := makeFixture(t)
		material := adminMaterial(t, f)
		stop := errors.New("prepared stop")
		source := f.open(t, fileOps{before: func(step string) error {
			if step == "admin:stage-1" {
				return stop
			}
			return nil
		}})
		path := filepath.Join(t.TempDir(), "target")
		id := "offline"
		var err error
		if clone {
			id = "copy"
			_, err = source.Clone(t.Context(), path, id, material)
		} else {
			_, err = source.Restore(t.Context(), path, material, nil)
		}
		if !errors.Is(err, stop) {
			t.Fatal(err)
		}
		r := testRuntime(t, nil, nil)
		target, err := r.OpenStore(t.Context(), path, id, Options{}, SessionOptions{Mode: "key-file", KeyFile: material.KeyFile})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(path, "CURRENT")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("target already published", err)
		}
		needed, err := target.RecoveryNeedsSource(t.Context())
		if err != nil || !needed {
			t.Fatalf("missing source hint: %t %v", needed, err)
		}
		if _, err := target.ResumeFrom(t.Context(), source, material, material); err != nil {
			t.Fatal(err)
		}
		needed, err = target.RecoveryNeedsSource(t.Context())
		if err != nil || needed {
			t.Fatalf("committed hint: %t %v", needed, err)
		}
	}
}

func TestRecoveryNeedsSourceInitAndCorruptState(t *testing.T) {
	f := makeFixture(t)
	r := testRuntime(t, nil, nil)
	material := adminMaterial(t, f)
	path := filepath.Join(t.TempDir(), "init")
	stop := errors.New("prepared init stop")
	result, err := r.initialize(t.Context(), path, "offline", material, fileOps{before: func(step string) error {
		if step == "admin:stage-1" {
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
	needed, err := s.RecoveryNeedsSource(t.Context())
	if err != nil || needed {
		t.Fatalf("init asked for source: %t %v", needed, err)
	}
	writeFixtureFile(t, filepath.Join(path, "transactions", result.OperationID, "state"), []byte("corrupt"))
	if _, err := s.RecoveryNeedsSource(t.Context()); err == nil {
		t.Fatal("corrupt state ignored")
	}
}
