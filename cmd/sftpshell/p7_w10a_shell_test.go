package sftpshell

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	pkgsftp "github.com/pkg/sftp"
)

type w10aRealPathShellHandler struct {
	*w8aShellTrackingHandler
	realPath string
}

func (h *w10aRealPathShellHandler) RealPath(string) (string, error) {
	return h.realPath, nil
}

func (h *w10aRealPathShellHandler) handlers() pkgsftp.Handlers {
	return pkgsftp.Handlers{
		FileGet:  h,
		FilePut:  h,
		FileCmd:  h,
		FileList: h,
	}
}

// TestP7W10a_AB10L1_SanitizesCwdInPromptPwdAndEditorModel verifies AB10-L1:
//   - handlePwd sanitizes both s.cwd and s.localCwd before writing to stdout.
//   - newEditorModel sanitizes promptOptions.text so View() and transcript()
//     never emit raw ANSI/CSI/OSC/C1/DEL/line-separator escapes.
//   - Shell.New rejects hostile server CWD responses via (*sftp.Client).Cwd
//     and falls back cleanly to ".".
func TestP7W10a_AB10L1_SanitizesCwdInPromptPwdAndEditorModel(t *testing.T) {
	hostileCwd := "/home/\x1b]52;c;aGVsbG8=\x07\x1b[31muser\x7f\u009b2J\u2028dir"

	t.Run("handlePwd_sanitizes_remote_and_local_cwd", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		sh := &Shell{
			cwd:      hostileCwd,
			localCwd: hostileCwd,
			stdout:   &stdout,
			stderr:   &stderr,
		}
		if err := sh.handlePwd("pwd"); err != nil {
			t.Fatalf("handlePwd(pwd): %v", err)
		}
		if err := sh.handlePwd("lpwd"); err != nil {
			t.Fatalf("handlePwd(lpwd): %v", err)
		}
		out := stdout.String()
		for _, forbidden := range []string{"\x1b", "\x07", "\x7f", "\u009b", "\u2028"} {
			if strings.Contains(out, forbidden) {
				t.Fatalf("handlePwd output leaked raw control sequence %q in %q", forbidden, out)
			}
		}
		if !strings.Contains(out, "/home/user") {
			t.Fatalf("handlePwd output missing readable path portion: %q", out)
		}
	})

	t.Run("editor_model_sanitizes_prompt_text_in_view_and_transcript", func(t *testing.T) {
		rawPrompt := fmt.Sprintf("sftp:%s> ", hostileCwd)
		m := newEditorModel(promptOptions{text: rawPrompt}, nil, nil)
		view := m.View().Content
		transcript := m.transcript()
		for _, rendered := range []string{view, transcript, m.options.text} {
			for _, forbidden := range []string{"\x1b", "\x07", "\x7f", "\u009b", "\u2028"} {
				if strings.Contains(rendered, forbidden) {
					t.Fatalf("editorModel leaked raw control sequence %q in %q", forbidden, rendered)
				}
			}
			if !strings.Contains(rendered, "sftp:/home/user") {
				t.Fatalf("editorModel prompt lost readable content: %q", rendered)
			}
		}
	})

	t.Run("shell_new_rejects_hostile_server_cwd_and_falls_back_to_dot", func(t *testing.T) {
		for _, badCwd := range []string{"", "/home/\x1b]52;c;aGVsbG8=\x07evil", "/home/bad\x00dir"} {
			h := &w10aRealPathShellHandler{
				w8aShellTrackingHandler: newW8aShellTrackingHandler(),
				realPath:                badCwd,
			}
			base := newP7W7bShellWithHandlers(t, h.handlers(), "/", t.TempDir())
			sh, err := New(t.Context(), base.client, base.sshClient, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
			if err != nil {
				t.Fatalf("New(badCwd=%q) failed unexpectedly: %v", badCwd, err)
			}
			if sh.cwd != "." {
				t.Fatalf("New(badCwd=%q) set sh.cwd = %q, want fallback \".\"", badCwd, sh.cwd)
			}
		}
	})
}

// TestP7W10a_AB10L3_ParseCompletionCursorWindowsTrailingBackslashQuote verifies
// AB10-L3: parseCompletionCursor shares splitCommandLine's double-quote
// trailing `\"` rule so `put "bin036\" /rem<Tab>` dispatches to argIndex == 2
// (completeRemotePath) without clobbering argIndex == 1.
func TestP7W10a_AB10L3_ParseCompletionCursorWindowsTrailingBackslashQuote(t *testing.T) {
	t.Run("cursor_cases_match_splitCommandLine", func(t *testing.T) {
		cases := []struct {
			name          string
			content       string
			wantCmd       string
			wantArgIndex  int
			wantPartial   string
			wantQuoteChar rune
			wantHead      string
		}{
			{
				name:          "put_windows_dir_trailing_backslash_quote_then_remote_partial",
				content:       `put "bin036\" /rem`,
				wantCmd:       "put",
				wantArgIndex:  2,
				wantPartial:   "/rem",
				wantQuoteChar: 0,
				wantHead:      `put "bin036\" `,
			},
			{
				name:          "put_windows_dir_trailing_backslash_quote_then_space",
				content:       `put "bin036\" `,
				wantCmd:       "put",
				wantArgIndex:  2,
				wantPartial:   "",
				wantQuoteChar: 0,
				wantHead:      `put "bin036\" `,
			},
			{
				name:          "put_windows_dir_with_spaces_then_quoted_remote_partial",
				content:       `put "C:\my dir\" "/rem`,
				wantCmd:       "put",
				wantArgIndex:  2,
				wantPartial:   "/rem",
				wantQuoteChar: '"',
				wantHead:      `put "C:\my dir\" "`,
			},
			{
				name:          "put_windows_dir_trailing_backslash_quote_at_eol",
				content:       `put "bin036\"`,
				wantCmd:       "put",
				wantArgIndex:  1,
				wantPartial:   `bin036\`,
				wantQuoteChar: 0,
				wantHead:      "put ",
			},
			{
				name:          "put_doubled_backslash_before_closing_quote_then_remote",
				content:       `put "bin036\\" /rem`,
				wantCmd:       "put",
				wantArgIndex:  2,
				wantPartial:   "/rem",
				wantQuoteChar: 0,
				wantHead:      `put "bin036\\" `,
			},
			{
				name:          "escaped_inner_double_quote_not_followed_by_space_stays_quoted",
				content:       `put "hello \"world`,
				wantCmd:       "put",
				wantArgIndex:  1,
				wantPartial:   `hello "world`,
				wantQuoteChar: '"',
				wantHead:      `put "`,
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got := parseCompletionCursor(tc.content)
				if got.cmd != tc.wantCmd || got.argIndex != tc.wantArgIndex || got.partial != tc.wantPartial || got.quoteChar != tc.wantQuoteChar || got.head != tc.wantHead {
					t.Fatalf("parseCompletionCursor(%q) = %+v, want cmd=%q argIndex=%d partial=%q quoteChar=%q head=%q",
						tc.content, got, tc.wantCmd, tc.wantArgIndex, tc.wantPartial, tc.wantQuoteChar, tc.wantHead)
				}
			})
		}
	})

	t.Run("wordCompleter_dispatches_arg2_to_remote_without_clobbering_arg1", func(t *testing.T) {
		h := newW8aShellTrackingHandler()
		h.dirLists["/"] = []os.FileInfo{
			p7ReproFileInfo{name: "remote_target.txt", size: 8, mode: 0o644},
			p7ReproFileInfo{name: "other.txt", size: 4, mode: 0o644},
		}
		localDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(localDir, "remote_local_decoy.txt"), []byte("decoy"), 0o600); err != nil {
			t.Fatal(err)
		}
		sh := newP7W7bShellWithHandlers(t, h.handlers(), "/", localDir)

		line := `put "bin036\" /rem`
		head, completions, tail, err := sh.wordCompleter(t.Context(), line, len([]rune(line)))
		if err != nil {
			t.Fatalf("wordCompleter(%q) err = %v", line, err)
		}
		if head != `put "bin036\" ` {
			t.Fatalf("head = %q, want %q", head, `put "bin036\" `)
		}
		if tail != "" {
			t.Fatalf("tail = %q, want empty", tail)
		}
		wantCands := []string{"/remote_target.txt"}
		if !reflect.DeepEqual(completions, wantCands) {
			t.Fatalf("completions = %#v, want %#v", completions, wantCands)
		}

		completedLine := head + completions[0] + tail
		parsed, err := splitCommandLine(completedLine)
		if err != nil {
			t.Fatalf("splitCommandLine(%q) err = %v", completedLine, err)
		}
		wantArgs := []string{"put", `bin036\`, "/remote_target.txt"}
		if !reflect.DeepEqual(parsed, wantArgs) {
			t.Fatalf("splitCommandLine(%q) = %#v, want %#v", completedLine, parsed, wantArgs)
		}
	})
}
