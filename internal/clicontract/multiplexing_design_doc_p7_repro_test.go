//go:build p7repro

package clicontract

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestP7Repro_LOW4_MultiplexingDesignDocsNoLegacyChildEnvMarkers reproduces LOW-4:
// docs/development/openssh-multiplexing-design.md and its English counterpart still
// document legacy child env markers XOPS_CLI_SSH_MUX_DAEMON and XOPS_CLI_SSH_BG_CHILD,
// which were replaced by pipe-FD spec flags (--mux-daemon-spec-fd / --bg-child-spec-fd).
func TestP7Repro_LOW4_MultiplexingDesignDocsNoLegacyChildEnvMarkers(t *testing.T) {
	t.Parallel()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to locate test file path")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))

	legacyMarkers := []string{
		"XOPS_CLI_SSH_MUX_DAEMON",
		"XOPS_CLI_SSH_BG_CHILD",
	}
	docs := []string{
		filepath.Join(repoRoot, "docs", "development", "openssh-multiplexing-design.md"),
		filepath.Join(repoRoot, "docs", "en", "development", "openssh-multiplexing-design.md"),
	}

	for _, docPath := range docs {
		relPath := filepath.ToSlash(strings.TrimPrefix(docPath, repoRoot+string(filepath.Separator)))
		t.Run(relPath, func(t *testing.T) {
			raw, err := os.ReadFile(docPath)
			if err != nil {
				t.Fatalf("read %s: %v", relPath, err)
			}
			for i, line := range strings.Split(string(raw), "\n") {
				for _, marker := range legacyMarkers {
					if strings.Contains(line, marker) {
						t.Errorf("%s:%d: still mentions removed legacy child env marker %s", relPath, i+1, marker)
					}
				}
			}
		})
	}
}
