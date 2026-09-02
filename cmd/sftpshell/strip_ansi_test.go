package sftpshell

import (
	"regexp"
	"testing"
)

var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\a\x1b]*(?:\a|\x1b\\)|\x1b[=>]`)

func stripANSI(raw string) string {
	return ansiRegex.ReplaceAllString(raw, "")
}

func TestStripANSI(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
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
