package mcphost

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/mcp/guardrail"
)

// TestP7W14a_AB14L1_AuditLogHomeShorthandExpansion verifies AB14-L1:
//   - expandAuditLogPath expands "~", "~/...", and "~\..." using os.UserHomeDir().
//   - newAuditLogger with "~\.xops\audit.log" writes under the user home directory.
//   - newAuditLogger with bare "~" expands to the home directory and fails closed
//     on Log rather than creating a literal "./~" file in the working directory.
func TestP7W14a_AB14L1_AuditLogHomeShorthandExpansion(t *testing.T) {
	home := isolateMCPTestEnvironment(t)
	workDir := t.TempDir()
	t.Chdir(workDir)

	tests := []struct {
		in   string
		want string
	}{
		{"~/.xops/audit.log", filepath.Join(home, ".xops", "audit.log")},
		{`~\.xops\audit.log`, filepath.Join(home, ".xops", "audit.log")},
		{"~", home},
		{"~/", home},
		{`~\`, home},
		{"/var/log/xops-audit.log", "/var/log/xops-audit.log"},
		{"", ""},
	}
	for _, tc := range tests {
		if got := expandAuditLogPath(tc.in); got != tc.want {
			t.Errorf("expandAuditLogPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	// Windows-style "~\.xops\audit.log" writes inside the isolated home dir.
	winLogger := newAuditLogger(`~\.xops\win-audit.log`)
	if err := winLogger.Log(guardrail.AuditEntry{OperationID: "op-win", Tool: "nodes", Outcome: "intent"}); err != nil {
		t.Fatalf("newAuditLogger(~\\.xops\\win-audit.log).Log failed: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(home, ".xops", "win-audit.log"))
	if err != nil || !strings.Contains(string(data), `"op_id":"op-win"`) {
		t.Fatalf("expanded ~\\ audit file = (%q, %v)", string(data), err)
	}

	// Bare "~" expands to the home directory and fails closed without creating "./~".
	bareLogger := newAuditLogger("~")
	if err := bareLogger.Log(guardrail.AuditEntry{OperationID: "op-bare", Tool: "nodes", Outcome: "intent"}); err == nil {
		t.Fatal("newAuditLogger(~).Log succeeded on directory path, want error")
	}
	entries, err := os.ReadDir(workDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("bare '~' audit path created unexpected entries in cwd %q: %v", workDir, entries)
	}
}
