package sftpshell

import (
	"errors"
	"reflect"
	"testing"
)

func TestSplitCommandLine(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []string
		wantErr error
	}{
		{
			name:  "empty",
			input: "",
			want:  nil,
		},
		{
			name:  "whitespace only",
			input: "   \t  \n ",
			want:  nil,
		},
		{
			name:  "simple command and args",
			input: "put file1.txt /remote/path",
			want:  []string{"put", "file1.txt", "/remote/path"},
		},
		{
			name:  "multiple spaces between arguments",
			input: "  ls   -l   /var/log  ",
			want:  []string{"ls", "-l", "/var/log"},
		},
		{
			name:  "single quotes preserving spaces",
			input: "put 'Witch of Eclipse' /remote",
			want:  []string{"put", "Witch of Eclipse", "/remote"},
		},
		{
			name:  "double quotes preserving spaces",
			input: `put "Witch of Eclipse" "/remote/path with space"`,
			want:  []string{"put", "Witch of Eclipse", "/remote/path with space"},
		},
		{
			name:  "escaped spaces",
			input: `put Witch\ of\ Eclipse /remote`,
			want:  []string{"put", "Witch of Eclipse", "/remote"},
		},
		{
			name:  "escaped spaces and directory slash",
			input: `put Witch\ of\ Eclipse/ /remote/`,
			want:  []string{"put", "Witch of Eclipse/", "/remote/"},
		},
		{
			name:  "escaped quotes in double quotes",
			input: `echo "hello \"world\""`,
			want:  []string{"echo", `hello "world"`},
		},
		{
			name:  "escaped backslash in double quotes",
			input: `echo "hello\\world"`,
			want:  []string{"echo", `hello\world`},
		},
		{
			name:  "Windows path in double quotes preserves backslash",
			input: `put "C:\Users\wentf\Game"`,
			want:  []string{"put", `C:\Users\wentf\Game`},
		},
		{
			name:  "Windows path without quotes preserves backslash",
			input: `put C:\Users\wentf\Game`,
			want:  []string{"put", `C:\Users\wentf\Game`},
		},
		{
			name:  "mixed quotes and concatenated parts",
			input: `put prefix'with space'"and more"\ done suffix`,
			want:  []string{"put", "prefixwith spaceand more done", "suffix"},
		},
		{
			name:  "empty quoted arguments",
			input: `put "" ''`,
			want:  []string{"put", "", ""},
		},
		{
			name:    "unclosed single quote",
			input:   "put 'unclosed",
			wantErr: errUnclosedQuote,
		},
		{
			name:    "unclosed double quote",
			input:   `put "unclosed`,
			wantErr: errUnclosedQuote,
		},
		{
			name:    "trailing backslash",
			input:   `put trailing\`,
			wantErr: errTrailingBackslash,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := splitCommandLine(tt.input)
			if tt.wantErr != nil {
				if err == nil || !errors.Is(err, tt.wantErr) {
					t.Fatalf("splitCommandLine(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("splitCommandLine(%q) unexpected error: %v", tt.input, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitCommandLine(%q) = %#v, want %#v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParsePassthroughCommand(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantCmd     string
		wantRawArgs string
		wantOk      bool
	}{
		{
			name:        "exec with single quotes and awk",
			input:       "exec awk '{print $1}' /var/log/syslog",
			wantCmd:     "exec",
			wantRawArgs: "awk '{print $1}' /var/log/syslog",
			wantOk:      true,
		},
		{
			name:        "exec with trailing backslash",
			input:       `exec dir C:\`,
			wantCmd:     "exec",
			wantRawArgs: `dir C:\`,
			wantOk:      true,
		},
		{
			name:        "lexec with trailing backslash and quotes",
			input:       `  lexec   dir "C:\Users\"  `,
			wantCmd:     "lexec",
			wantRawArgs: `dir "C:\Users\"`,
			wantOk:      true,
		},
		{
			name:        "exec command only",
			input:       "exec",
			wantCmd:     "exec",
			wantRawArgs: "",
			wantOk:      true,
		},
		{
			name:        "lexec command with whitespace only",
			input:       "lexec    ",
			wantCmd:     "lexec",
			wantRawArgs: "",
			wantOk:      true,
		},
		{
			name:   "command starting with exec prefix but not word boundary",
			input:  "executable foo bar",
			wantOk: false,
		},
		{
			name:   "regular put command with trailing backslash",
			input:  `put C:\`,
			wantOk: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, rawArgs, ok := parsePassthroughCommand(tt.input)
			if ok != tt.wantOk {
				t.Fatalf("parsePassthroughCommand(%q) ok = %v, want %v", tt.input, ok, tt.wantOk)
			}
			if ok {
				if cmd != tt.wantCmd {
					t.Errorf("cmd = %q, want %q", cmd, tt.wantCmd)
				}
				if rawArgs != tt.wantRawArgs {
					t.Errorf("rawArgs = %q, want %q", rawArgs, tt.wantRawArgs)
				}
			}
		})
	}
}
