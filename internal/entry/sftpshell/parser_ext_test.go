package sftpshell_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/wentf9/xops-cli/internal/entry/sftpshell"
)

func TestParseLine_QuotesEscapesCommentsAndErrors(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    []string
		wantErr bool
	}{
		{name: "empty", in: "   \t  ", want: nil},
		{name: "comment_only", in: "  # full line comment", want: nil},
		{name: "simple", in: "put -r ./src /var/www/app", want: []string{"put", "-r", "./src", "/var/www/app"}},
		{name: "single_quotes", in: "write /tmp/a.txt 'hello world #not-comment'", want: []string{"write", "/tmp/a.txt", "hello world #not-comment"}},
		{name: "double_quotes_escape", in: `mv "dir/file \"1\".txt" dir/file\ 2.txt`, want: []string{"mv", `dir/file "1".txt`, "dir/file 2.txt"}},
		{name: "inline_comment", in: "ls -la /tmp # trailing", want: []string{"ls", "-la", "/tmp"}},
		{name: "unclosed_single", in: "cd 'oops", wantErr: true},
		{name: "unclosed_double", in: `cd "oops`, wantErr: true},
		{name: "trailing_backslash", in: `cd foo\`, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sftpshell.ParseLine(tc.in)
			if tc.wantErr {
				if !errors.Is(err, sftpshell.ErrSyntax) {
					t.Fatalf("期望 ErrSyntax，实际 err=%v got=%v", err, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("意外错误: %v", err)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("ParseLine(%q) = %#v，期望 %#v", tc.in, got, tc.want)
			}
		})
	}
}
