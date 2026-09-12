//go:build (linux || darwin || windows) && (amd64 || arm64)

package credentialfile

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestCompatibilityProbeCleansTemporaryData(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	report, err := ProbeCompatibility(t.Context(), filepath.Join(root, "absent-vault"))
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Checks) != 4 {
		t.Fatalf("incomplete probe: %+v", report)
	}
	files, err := os.ReadDir(root)
	if err != nil || len(files) != 0 {
		t.Fatal("probe left files or initialized a vault")
	}
}

func TestCompatibilityProbeUsesExistingVaultFilesystem(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "vault")
	runtime := NewRuntime(t.Context(), nil, nil)
	defer func() {
		if err := runtime.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, err := runtime.Init(t.Context(), path, "test", Wrapping{Mode: "key-file", KeyFile: filepath.Join(root, "key")}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	report, err := ProbeCompatibility(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	if report.Directory != path {
		t.Fatalf("probed wrong filesystem path: %s", report.Directory)
	}
	after, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	names := func(entries []os.DirEntry) []string {
		var result []string
		for _, entry := range entries {
			result = append(result, entry.Name())
		}
		return result
	}
	if !slices.Equal(names(before), names(after)) {
		t.Fatal("probe altered vault layout")
	}
}

func TestReadonlyKeyFileCanBeReused(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(root, "key")
	runtime := NewRuntime(t.Context(), nil, nil)
	defer func() {
		if err := runtime.Close(); err != nil {
			t.Error(err)
		}
	}()
	material := Wrapping{Mode: "key-file", KeyFile: key}
	if _, err := runtime.Init(t.Context(), filepath.Join(root, "first"), "first", material); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(key, 0400); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chmod(key, 0600); err != nil {
			t.Error(err)
		}
	}()
	before, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before)
	if _, err := runtime.Init(t.Context(), filepath.Join(root, "second"), "second", material); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(after)
	if !slices.Equal(before, after) {
		t.Fatal("read-only key was modified")
	}
}
