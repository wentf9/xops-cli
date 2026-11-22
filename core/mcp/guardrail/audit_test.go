package guardrail

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/wentf9/xops-cli/core/fsx"
)

func TestAuditLogger_RefusesSymlinkTargetsAndAppendsRegular(t *testing.T) {
	dir := t.TempDir()

	t.Run("appends_regular_file", func(t *testing.T) {
		auditPath := filepath.Join(dir, "sub", "audit.jsonl")
		logger := NewAuditLogger(auditPath)
		if err := logger.Log(AuditEntry{OperationID: "op-1", Tool: "exec", Outcome: "intent"}); err != nil {
			t.Fatalf("first Log failed: %v", err)
		}
		if err := logger.Log(AuditEntry{OperationID: "op-1", Tool: "exec", Outcome: "executed"}); err != nil {
			t.Fatalf("second Log failed: %v", err)
		}
		entries := readAuditEntries(t, auditPath)
		if len(entries) != 2 || entries[0].Outcome != "intent" || entries[1].Outcome != "executed" {
			t.Fatalf("unexpected audit entries: %+v", entries)
		}
	})

	t.Run("refuses_symlink_and_dangling_symlink", func(t *testing.T) {
		victim := filepath.Join(dir, "victim.txt")
		if err := os.WriteFile(victim, []byte("original\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "audit.link")
		if err := os.Symlink(victim, link); err != nil {
			if runtime.GOOS == "windows" {
				t.Skipf("symlink creation unavailable on Windows: %v", err)
			}
			t.Fatal(err)
		}
		logger := NewAuditLogger(link)
		if err := logger.Log(AuditEntry{OperationID: "op-sym", Tool: "exec", Outcome: "intent"}); !errors.Is(err, fsx.ErrSymlink) {
			t.Fatalf("AuditLogger.Log(symlink) = %v, want fsx.ErrSymlink", err)
		}
		after, err := os.ReadFile(victim)
		if err != nil || string(after) != "original\n" {
			t.Fatalf("victim file modified via symlink audit log: (%q, %v)", string(after), err)
		}

		missing := filepath.Join(dir, "must-not-be-created.log")
		dangling := filepath.Join(dir, "dangling.link")
		if err := os.Symlink(missing, dangling); err != nil {
			t.Fatal(err)
		}
		if err := NewAuditLogger(dangling).Log(AuditEntry{OperationID: "op-dang"}); !errors.Is(err, fsx.ErrSymlink) {
			t.Fatalf("AuditLogger.Log(dangling symlink) = %v, want fsx.ErrSymlink", err)
		}
		if _, statErr := os.Lstat(missing); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("AuditLogger followed dangling symlink and created %q", missing)
		}
	})
}
