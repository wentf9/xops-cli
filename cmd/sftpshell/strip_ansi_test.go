package sftpshell

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\a\x1b]*(?:\a|\x1b\\)|\x1b[=>]`)

func stripANSI(raw string) string {
	// ConPTY can encode blank columns between a prompt and echoed input as
	// cursor-forward sequences. Preserve those columns for transcript assertions.
	// This helper normalizes transcripts; it does not emulate a terminal screen.
	return ansiRegex.ReplaceAllStringFunc(raw, func(sequence string) string {
		if strings.HasPrefix(sequence, "\x1b[") && strings.HasSuffix(sequence, "C") {
			parameter := sequence[2 : len(sequence)-1]
			if parameter == "" || parameter == "0" {
				return " "
			}
			columns, err := strconv.Atoi(parameter)
			if err == nil && columns > 0 && columns <= 100 {
				// The integration harness uses a 100-column terminal.
				return strings.Repeat(" ", columns)
			}
		}
		return ""
	})
}

func TestStripANSI(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "ConPTY host key echo from CI",
			raw:  "\x1b[?9001h\x1b[?1004h\x1b[?25l\x1b[2J\x1b[m\x1b[HHOST_KEY_TRUST (yes/no)?\x1b[1C\x1b]0;C:\\temp\\sftpshell.test.exe\a\x1b[?25hyes",
			want: "HOST_KEY_TRUST (yes/no)? yes",
		},
		{
			name: "cursor forward columns",
			raw:  "a\x1b[Cb\x1b[0Cc\x1b[3Cd",
			want: "a b c   d",
		},
		{
			name: "invalid or excessive cursor forward",
			raw:  "a\x1b[?1Cb\x1b[1;2Cc\x1b[999999999999999999999999Cd",
			want: "abcd",
		},
		{
			name: "plain text",
			raw:  "hello world",
			want: "hello world",
		},
		{
			name: "CSI escape codes",
			raw:  "\x1b[2J\x1b[m\x1b[Hhello\x1b[K world\x1b[4;15H",
			want: "hello world",
		},
		{
			name: "OSC title escape code",
			raw:  "\x1b]0;my window title\ahello\x1b]0;other title\x1b\\world",
			want: "helloworld",
		},
		{
			name: "ConPTY prompt output snapshot",
			raw:  "\x1b[?9001h\x1b[?1004h\x1b[?25l\x1b[2J\x1b[m\x1b[H\r\n\x1b]0;C:\\temp\\app.exe\a\x1b[?25hSFTP_PROMPT_1> \x1b[?25l\x1b[HSFTP_PROMPT_1> pwd\x1b[K\r\nHISTORY_READY\x1b[K\r\nSFTP_HISTORY>\x1b[K\r\n\x1b[4;15H\x1b[?25h",
			want: "\r\nSFTP_PROMPT_1> SFTP_PROMPT_1> pwd\r\nHISTORY_READY\r\nSFTP_HISTORY>\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stripANSI(tt.raw); got != tt.want {
				t.Errorf("stripANSI(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}
