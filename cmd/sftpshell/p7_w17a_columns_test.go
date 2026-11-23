package sftpshell

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

type fakeNonTerminalFdWriter struct {
	bytes.Buffer
}

func (*fakeNonTerminalFdWriter) Fd() uintptr {
	return ^uintptr(0)
}

func TestP7W17a_AB17L3_PrintColumnsUsesShellStdoutWidth(t *testing.T) {
	t.Run("non_terminal_buffer_uses_default_80_columns", func(t *testing.T) {
		var buf bytes.Buffer
		sh := &Shell{stdout: &buf}
		if got := sh.columnWidth(); got != 80 {
			t.Fatalf("columnWidth() for bytes.Buffer = %d, want 80", got)
		}
		// 6 names of length 18 => colWidth=20 => 80/20 = 4 columns => 2 rows.
		names := []string{
			"aaaaaaaaaaaaaaaaaa",
			"bbbbbbbbbbbbbbbbbb",
			"cccccccccccccccccc",
			"dddddddddddddddddd",
			"eeeeeeeeeeeeeeeeee",
			"ffffffffffffffffff",
		}
		sh.printColumns(names)
		lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
		if len(lines) != 2 {
			t.Fatalf("printColumns on 80-col default buffer produced %d rows, want 2:\n%s", len(lines), buf.String())
		}
	})

	t.Run("typed_nil_os_file_returns_default_80", func(t *testing.T) {
		var nilFile *os.File
		sh := &Shell{stdout: nilFile}
		if got := sh.columnWidth(); got != 80 {
			t.Fatalf("columnWidth() for (*os.File)(nil) = %d, want 80", got)
		}
	})

	t.Run("non_terminal_fd_writer_returns_default_80", func(t *testing.T) {
		w := &fakeNonTerminalFdWriter{}
		sh := &Shell{stdout: w}
		if got := sh.columnWidth(); got != 80 {
			t.Fatalf("columnWidth() for invalid fd writer = %d, want 80", got)
		}
	})
}
