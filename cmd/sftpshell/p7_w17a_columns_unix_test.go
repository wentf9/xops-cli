//go:build !windows

package sftpshell

import (
	"io"
	"strings"
	"testing"
	"time"

	pty "github.com/wentf9/xops-cli/internal/testpty"
)

func TestP7W17a_AB17L3_PrintColumnsReadsShellStdoutPTYWidth(t *testing.T) {
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatalf("pty.Open: %v", err)
	}
	t.Cleanup(func() {
		closeTestResource(t, slave)
		closeTestResource(t, master)
	})

	if err := pty.Setsize(slave, &pty.Winsize{Rows: 24, Cols: 36}); err != nil {
		t.Fatalf("pty.Setsize(36): %v", err)
	}

	sh := &Shell{stdout: slave}
	if got := sh.columnWidth(); got != 36 {
		t.Fatalf("columnWidth() on 36-col PTY = %d, want 36", got)
	}

	// Drain master concurrently so writing to slave never blocks.
	readDone := make(chan string, 1)
	go func() {
		_ = master.SetReadDeadline(time.Now().Add(2 * time.Second))
		data, _ := io.ReadAll(master)
		readDone <- string(data)
	}()

	// 6 names of length 10 => colWidth=12 => 36/12 = 3 columns => 2 rows
	// (under 80-col fallback, 80/12 = 6 columns => 1 row).
	sh.printColumns([]string{
		"name000001", "name000002", "name000003",
		"name000004", "name000005", "name000006",
	})

	// Resize PTY to 120 cols and verify columnWidth tracks s.stdout dynamically.
	if err := pty.Setsize(slave, &pty.Winsize{Rows: 24, Cols: 120}); err != nil {
		t.Fatalf("pty.Setsize(120): %v", err)
	}
	if got := sh.columnWidth(); got != 120 {
		t.Fatalf("columnWidth() on 120-col PTY = %d, want 120", got)
	}

	// Close slave to send EOF to master reader.
	if err := slave.Close(); err != nil {
		t.Fatalf("close PTY slave: %v", err)
	}
	raw := <-readDone
	normalized := strings.ReplaceAll(raw, "\r\n", "\n")
	lines := strings.Split(strings.TrimSuffix(normalized, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("printColumns on 36-col PTY produced %d rows, want 2:\n%q", len(lines), normalized)
	}
}
