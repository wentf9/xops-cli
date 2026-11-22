//go:build windows

package sftpshell

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/wentf9/xops-cli/core/fsx"
	"github.com/wentf9/xops-cli/core/winsec"
	"golang.org/x/sys/windows"
)

// TestP7W13a_AB13L2_WriteCommandHistoryWindowsProtectedOwnerOnlySD verifies
// AB13-L2 on Windows: writeCommandHistory creates the history file via
// fsx.CreateExclusive so the replaced .xops_sftp_history file carries an
// explicit SE_DACL_PROTECTED owner-only security descriptor rather than
// inheriting parent directory ACEs.
func TestP7W13a_AB13L2_WriteCommandHistoryWindowsProtectedOwnerOnlySD(t *testing.T) {
	dir := t.TempDir()
	historyPath := filepath.Join(dir, ".xops_sftp_history")

	if err := writeCommandHistory(t.Context(), historyPath, []string{"ls", "pwd"}); err != nil {
		t.Fatalf("writeCommandHistory: %v", err)
	}

	f, _, err := fsx.OpenRegularUnbounded(historyPath)
	if err != nil {
		t.Fatalf("OpenRegularUnbounded(%q): %v", historyPath, err)
	}
	defer func() { _ = f.Close() }()

	sd, err := winsec.GetSecurityInfoByHandle(windows.Handle(f.Fd()))
	if err != nil {
		t.Fatalf("GetSecurityInfoByHandle: %v", err)
	}
	ctrl, _, err := sd.Control()
	if err != nil {
		t.Fatalf("sd.Control: %v", err)
	}
	if ctrl&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("expected SE_DACL_PROTECTED on .xops_sftp_history, got control=%#x", ctrl)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("sd.DACL: %v", err)
	}
	if dacl.AceCount != 2 {
		t.Fatalf("expected 2 owner-only ACEs (CurrentUser + SYSTEM), got %d", dacl.AceCount)
	}

	// Verify file content survived atomic replacement cleanly.
	raw, err := os.ReadFile(historyPath)
	if err != nil || string(raw) != "ls\npwd\n" {
		t.Fatalf("history content = %q (err=%v), want %q", raw, err, "ls\npwd\n")
	}
}
