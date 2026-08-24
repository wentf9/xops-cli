package sftp

import (
	"testing"
)

func TestWordCompleterChinesePath(t *testing.T) {
	s := &Shell{
		cwd:      "/home/iaas",
		localCwd: "/home/iaas",
	}

	tests := []struct {
		name     string
		line     string
		pos      int // rune position
		wantHead string
		wantTail string
	}{
		{
			name:     "put with Chinese partial path",
			line:     "put /home/iaas/部署/文件",
			pos:      len([]rune("put /home/iaas/部署/文件")),
			wantHead: "put ",
			wantTail: "",
		},
		{
			name:     "put with Chinese path cursor in middle",
			line:     "put /home/iaas/部署/文件 extra",
			pos:      len([]rune("put /home/iaas/部署/文件")),
			wantHead: "put ",
			wantTail: " extra",
		},
		{
			name:     "cd with Chinese dir",
			line:     "cd 中文目录",
			pos:      len([]rune("cd 中文目录")),
			wantHead: "cd ",
			wantTail: "",
		},
		{
			name:     "command completion with ASCII",
			line:     "pu",
			pos:      2,
			wantHead: "",
			wantTail: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			head, _, tail := s.wordCompleter(tt.line, tt.pos)
			if head != tt.wantHead {
				t.Errorf("head = %q, want %q", head, tt.wantHead)
			}
			if tail != tt.wantTail {
				t.Errorf("tail = %q, want %q", tail, tt.wantTail)
			}
		})
	}
}

func TestWordCompleterRuneVsByte(t *testing.T) {
	s := &Shell{
		cwd:      "/home/iaas",
		localCwd: "/home/iaas",
	}

	// "put 部署" has 6 runes but 10 bytes for "部署"
	// line editor passes pos=6 (rune count), not pos=14 (byte count)
	line := "put 部署"
	runePos := 6 // len([]rune("put 部署"))

	head, _, tail := s.wordCompleter(line, runePos)
	if head != "put " {
		t.Errorf("head = %q, want %q", head, "put ")
	}
	if tail != "" {
		t.Errorf("tail = %q, want %q", tail, "")
	}

	// Verify that the old byte-based slicing would have been wrong
	if runePos < len(line) {
		// byte slice at rune pos would cut in the middle of a Chinese character
		byteSlice := line[:runePos]
		runeSlice := string([]rune(line)[:runePos])
		if byteSlice == runeSlice {
			t.Error("expected byte-based and rune-based slicing to differ for Chinese text")
		}
	}
}

func TestShellCompleterReturnsUnreadSuffix(t *testing.T) {
	s := &Shell{cwd: "/tmp", localCwd: "/tmp"}
	completer := shellCompleter{shell: s}
	candidates, offset := completer.Do([]rune("pu"), 2)
	if offset != 2 {
		t.Errorf("offset = %d, want 2", offset)
	}
	want := map[string]bool{"t": false}
	for _, candidate := range candidates {
		if _, ok := want[string(candidate)]; ok {
			want[string(candidate)] = true
		}
	}
	for candidate, found := range want {
		if !found {
			t.Errorf("missing completion suffix %q in %q", candidate, candidates)
		}
	}
}
