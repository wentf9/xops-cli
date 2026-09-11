//go:build (linux || darwin || windows) && (amd64 || arm64)

package credentialfile

import (
	"os"
	"path/filepath"
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
