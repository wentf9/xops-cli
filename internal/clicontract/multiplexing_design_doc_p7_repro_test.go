package clicontract

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestP7Repro_LOW4_MultiplexingDesignDocsNoLegacyChildEnvMarkers verifies LOW-4:
// docs/development/openssh-multiplexing-design.md and its English counterpart must
// not document removed legacy child env markers XOPS_CLI_SSH_MUX_DAEMON or
// XOPS_CLI_SSH_BG_CHILD, and must document the pipe-FD spec flags
// (--mux-daemon-spec-fd and --bg-child-spec-fd).
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
	requiredFlags := []string{
		"--mux-daemon-spec-fd",
		"--bg-child-spec-fd",
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
			content := string(raw)
			for i, line := range strings.Split(content, "\n") {
				for _, marker := range legacyMarkers {
					if strings.Contains(line, marker) {
						t.Errorf("%s:%d: still mentions removed legacy child env marker %s", relPath, i+1, marker)
					}
				}
			}
			for _, flag := range requiredFlags {
				if !strings.Contains(content, flag) {
					t.Errorf("%s: missing required pipe-FD spec flag documentation %s", relPath, flag)
				}
			}
		})
	}
}
