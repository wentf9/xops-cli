package sftpshell

import (
	"bytes"
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/sftp"
)

// TestP7W9a_NoRawPkgSFTPReadDirInShell verifies AB9-M1 architecturally:
// no production file in cmd/sftpshell may call raw (*pkgsftp.Client).ReadDir or
// ReadDirContext. Only os.ReadDir (local) and validated 2-argument
// (*sftp.Client).ReadDir(ctx, dir) are permitted.
func TestP7W9a_NoRawPkgSFTPReadDirInShell(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("os.ReadDir(.): %v", err)
	}
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, parseErr := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", name, parseErr)
		}
		checkShellFileNoRawReadDir(t, fset, name, file)
	}
}

func checkShellFileNoRawReadDir(t *testing.T, fset *token.FileSet, fileName string, file *ast.File) {
	t.Helper()
	pkgSFTPAlias := ""
	for _, imp := range file.Imports {
		if strings.Trim(imp.Path.Value, `"`) == "github.com/pkg/sftp" {
			if imp.Name != nil {
				pkgSFTPAlias = imp.Name.Name
			} else {
				pkgSFTPAlias = "sftp"
			}
		}
	}
	if fileName == "completer.go" && pkgSFTPAlias != "" {
		t.Errorf("completer.go still imports github.com/pkg/sftp as %q", pkgSFTPAlias)
	}

	rawParamNames := collectPkgSFTPParamNames(file, pkgSFTPAlias)
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name == "ReadDirContext" {
			pos := fset.Position(call.Pos())
			t.Errorf("forbidden raw ReadDirContext call at %s:%d", fileName, pos.Line)
			return true
		}
		if sel.Sel.Name != "ReadDir" {
			return true
		}
		if ident, isIdent := sel.X.(*ast.Ident); isIdent && ident.Name == "os" {
			return true
		}
		pos := fset.Position(call.Pos())
		if subCall, isCall := sel.X.(*ast.CallExpr); isCall {
			if subSel, isSel := subCall.Fun.(*ast.SelectorExpr); isSel && subSel.Sel.Name == "SFTPClient" {
				t.Errorf("forbidden raw SFTPClient().ReadDir call at %s:%d", fileName, pos.Line)
				return true
			}
		}
		if ident, isIdent := sel.X.(*ast.Ident); isIdent && rawParamNames[ident.Name] {
			t.Errorf("forbidden raw *pkgsftp.Client ReadDir call on %q at %s:%d", ident.Name, fileName, pos.Line)
			return true
		}
		if len(call.Args) != 2 {
			t.Errorf("non-os ReadDir call at %s:%d has %d args, want 2 (ctx, dir) on validated *sftp.Client", fileName, pos.Line, len(call.Args))
		}
		return true
	})
}

func collectPkgSFTPParamNames(file *ast.File, pkgAlias string) map[string]bool {
	names := make(map[string]bool)
	if pkgAlias == "" {
		return names
	}
	ast.Inspect(file, func(n ast.Node) bool {
		fl, ok := n.(*ast.FieldList)
		if !ok {
			return true
		}
		for _, field := range fl.List {
			if isPkgSFTPClientType(field.Type, pkgAlias) {
				for _, id := range field.Names {
					names[id.Name] = true
				}
			}
		}
		return true
	})
	return names
}

func isPkgSFTPClientType(expr ast.Expr, pkgAlias string) bool {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	return ok && ident.Name == pkgAlias && sel.Sel.Name == "Client"
}

// TestP7W9a_CompleteRemotePathRejectsHostileReadDir verifies AB9-M1:
// completeRemotePath uses validated (*sftp.Client).ReadDir and fails closed
// with zero candidates on hostile SSH_FXP_NAME entries.
func TestP7W9a_CompleteRemotePathRejectsHostileReadDir(t *testing.T) {
	cases := []struct {
		name       string
		entries    []os.FileInfo
		wantErrIs  error
		wantSubstr string
	}{
		{
			name: "slash_dotdot",
			entries: []os.FileInfo{
				p7ReproFileInfo{name: "rep.txt", size: 4, mode: 0o644},
				p7ReproFileInfo{name: "x/..", mode: os.ModeDir | 0o755},
			},
			wantErrIs: sftp.ErrInvalidRemoteName,
		},
		{
			name: "slash_dot",
			entries: []os.FileInfo{
				p7ReproFileInfo{name: "x/.", mode: os.ModeDir | 0o755},
			},
			wantErrIs: sftp.ErrInvalidRemoteName,
		},
		{
			name: "root_slash",
			entries: []os.FileInfo{
				p7ReproFileInfo{name: "/", mode: os.ModeDir | 0o755},
			},
			wantErrIs: sftp.ErrInvalidRemoteName,
		},
		{
			name: "newline_flag_injection",
			entries: []os.FileInfo{
				p7ReproFileInfo{name: "rep\n-f", size: 4, mode: 0o644},
			},
			wantErrIs: sftp.ErrInvalidRemoteName,
		},
		{
			name: "osc_52_escape",
			entries: []os.FileInfo{
				p7ReproFileInfo{name: "rep\x1b]52;c;aGVsbG8=\x07", size: 4, mode: 0o644},
			},
			wantErrIs: sftp.ErrInvalidRemoteName,
		},
		{
			name: "c1_csi_control",
			entries: []os.FileInfo{
				p7ReproFileInfo{name: "rep\u009b2J", size: 4, mode: 0o644},
			},
			wantErrIs: sftp.ErrInvalidRemoteName,
		},
		{
			name: "duplicate_entry",
			entries: []os.FileInfo{
				p7ReproFileInfo{name: "rep.txt", size: 4, mode: 0o644},
				p7ReproFileInfo{name: "rep.txt", size: 4, mode: 0o644},
			},
			wantSubstr: "duplicate",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newW8aShellTrackingHandler()
			h.dirLists["/remote"] = tc.entries

			sh := newP7W7bShellWithHandlers(t, h.handlers(), "/remote", t.TempDir())
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()

			res := sh.completeLine(ctx, "rm rep", len("rm rep"))
			if res.err == nil {
				t.Fatalf("completeLine(%s) succeeded with candidates %v, want error", tc.name, res.candidates)
			}
			if len(res.candidates) != 0 {
				t.Fatalf("completeLine(%s) returned %v on error, want empty", tc.name, res.candidates)
			}
			if tc.wantErrIs != nil && !errors.Is(res.err, tc.wantErrIs) {
				t.Fatalf("completeLine(%s) err = %v, want errors.Is(_, %v)", tc.name, res.err, tc.wantErrIs)
			}
			if tc.wantSubstr != "" && !strings.Contains(res.err.Error(), tc.wantSubstr) {
				t.Fatalf("completeLine(%s) err = %v, want substring %q", tc.name, res.err, tc.wantSubstr)
			}
		})
	}
}

// TestP7W9a_CompletionEscapingRoundTripAndAttackVectors verifies AB9-M1:
// escapeShellArg and formatCompletionCandidate form a lossless inverse of
// splitCommandLine across unquoted, double-quoted, and single-quoted modes,
// blocking flag injection (`rm rep<TAB>` on `rep\ -f` or `rep\u00a0-f`) and
// destination redirection (`get "rep<TAB>` on `rep" /home/victim/.bashrc `).
func TestP7W9a_CompletionEscapingRoundTripAndAttackVectors(t *testing.T) {
	t.Run("attack_vectors_via_completeLine", testP7W9aCompletionAttackVectors)
	t.Run("multilevel_quoted_dir_completion", testP7W9aMultiLevelQuotedDirCompletion)
	t.Run("property_roundtrip_all_quoting_modes", testP7W9aPropertyRoundTripAllModes)
}

func testP7W9aCompletionAttackVectors(t *testing.T) {
	cases := []struct {
		name      string
		remote    string
		input     string
		wantCmd   string
		wantArg   string
		checkNoFl bool
	}{
		{
			name:      "unquoted_backslash_space_flag_injection",
			remote:    `rep\ -f`,
			input:     "rm rep",
			wantCmd:   "rm",
			wantArg:   `rep\ -f`,
			checkNoFl: true,
		},
		{
			name:      "unquoted_nbsp_flag_injection",
			remote:    "rep\u00a0-f",
			input:     "rm rep",
			wantCmd:   "rm",
			wantArg:   "rep\u00a0-f",
			checkNoFl: true,
		},
		{
			name:      "unquoted_ideographic_space_flag_injection",
			remote:    "rep\u3000-f",
			input:     "rm rep",
			wantCmd:   "rm",
			wantArg:   "rep\u3000-f",
			checkNoFl: true,
		},
		{
			name:    "double_quoted_get_dest_redirection_local_dotfile",
			remote:  `rep" .bashrc `,
			input:   `get "rep`,
			wantCmd: "get",
			wantArg: `rep" .bashrc `,
		},
		{
			name:    "double_quoted_get_dest_redirection_windows_path",
			remote:  `rep" C:\Users\victim\.bashrc `,
			input:   `get "rep`,
			wantCmd: "get",
			wantArg: `rep" C:\Users\victim\.bashrc `,
		},
		{
			name:      "double_quoted_rm_flag_injection",
			remote:    `rep" -f`,
			input:     `rm "rep`,
			wantCmd:   "rm",
			wantArg:   `rep" -f`,
			checkNoFl: true,
		},
		{
			name:      "single_quoted_rm_flag_injection",
			remote:    `rep' -f`,
			input:     `rm 'rep`,
			wantCmd:   "rm",
			wantArg:   `rep' -f`,
			checkNoFl: true,
		},
		{
			name:    "double_quoted_trailing_backslash_file",
			remote:  `rep\`,
			input:   `get "rep`,
			wantCmd: "get",
			wantArg: `rep\`,
		},
		{
			name:    "unquoted_trailing_backslash_file",
			remote:  `rep\`,
			input:   `get rep`,
			wantCmd: "get",
			wantArg: `rep\`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newW8aShellTrackingHandler()
			h.dirLists["/remote"] = []os.FileInfo{
				p7ReproFileInfo{name: tc.remote, size: 10, mode: 0o644},
			}
			sh := newP7W7bShellWithHandlers(t, h.handlers(), "/remote", t.TempDir())
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()

			res := sh.completeLine(ctx, tc.input, len([]rune(tc.input)))
			if res.err != nil {
				t.Fatalf("completeLine(%q) err = %v", tc.input, res.err)
			}
			if len(res.candidates) != 1 {
				t.Fatalf("completeLine(%q) candidates = %#v, want 1", tc.input, res.candidates)
			}

			completed := res.head + res.candidates[0] + res.tail
			args, err := splitCommandLine(completed)
			if err != nil {
				t.Fatalf("splitCommandLine(%q) err = %v", completed, err)
			}
			want := []string{tc.wantCmd, tc.wantArg}
			if !reflect.DeepEqual(args, want) {
				t.Fatalf("splitCommandLine(%q) = %#v, want %#v", completed, args, want)
			}
			if tc.checkNoFl {
				rest, forced := parseForceFlag(args[1:])
				if forced || !reflect.DeepEqual(rest, []string{tc.wantArg}) {
					t.Fatalf("parseForceFlag(%#v) = (%#v, %v), want no forced flag", args[1:], rest, forced)
				}
			}

			withTail := completed + " /safe/dest"
			argsWithTail, err := splitCommandLine(withTail)
			if err != nil {
				t.Fatalf("splitCommandLine(%q) err = %v", withTail, err)
			}
			wantWithTail := []string{tc.wantCmd, tc.wantArg, "/safe/dest"}
			if !reflect.DeepEqual(argsWithTail, wantWithTail) {
				t.Fatalf("splitCommandLine(%q) = %#v, want %#v", withTail, argsWithTail, wantWithTail)
			}
		})
	}
}

func testP7W9aMultiLevelQuotedDirCompletion(t *testing.T) {
	cases := []struct {
		name      string
		dirName   string
		childName string
		quote     string
	}{
		{name: "double_quote_embedded_quote_and_space", dirName: `dir" -f`, childName: `file" 2.txt`, quote: `"`},
		{name: "single_quote_embedded_quote_and_space", dirName: `dir' -f`, childName: `file' 2.txt`, quote: `'`},
		{name: "unquoted_backslash_and_nbsp", dirName: "dir\\\u00a0sub", childName: `child\ -f.txt`, quote: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newW8aShellTrackingHandler()
			h.dirLists["/remote"] = []os.FileInfo{
				p7ReproFileInfo{name: tc.dirName, mode: os.ModeDir | 0o755},
			}
			h.dirLists["/remote/"+tc.dirName] = []os.FileInfo{
				p7ReproFileInfo{name: tc.childName, size: 5, mode: 0o644},
			}
			sh := newP7W7bShellWithHandlers(t, h.handlers(), "/remote", t.TempDir())
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()

			step1Input := "get " + tc.quote + "dir"
			res1 := sh.completeLine(ctx, step1Input, len([]rune(step1Input)))
			if res1.err != nil || len(res1.candidates) != 1 {
				t.Fatalf("step1 completeLine(%q) = %+v", step1Input, res1)
			}
			afterDir := res1.head + res1.candidates[0] + res1.tail

			res2 := sh.completeLine(ctx, afterDir, len([]rune(afterDir)))
			if res2.err != nil || len(res2.candidates) != 1 {
				t.Fatalf("step2 completeLine(%q) = %+v", afterDir, res2)
			}
			finalLine := res2.head + res2.candidates[0] + res2.tail
			args, err := splitCommandLine(finalLine)
			if err != nil {
				t.Fatalf("splitCommandLine(%q) err = %v", finalLine, err)
			}
			want := []string{"get", tc.dirName + "/" + tc.childName}
			if !reflect.DeepEqual(args, want) {
				t.Fatalf("splitCommandLine(%q) = %#v, want %#v", finalLine, args, want)
			}
		})
	}
}

func testP7W9aPropertyRoundTripAllModes(t *testing.T) {
	atoms := []string{
		"a",
		" ",
		"\u00a0",
		"\u2003",
		"\u3000",
		"\t",
		`\`,
		`"`,
		`'`,
		`-f`,
		`中文`,
		`\" `,
		`\\`,
		`''`,
		`""`,
	}

	corpus := make([]string, 0, len(atoms)*len(atoms)+32)
	corpus = append(corpus,
		`rep\ -f`,
		"rep\u00a0-f",
		`rep" .bashrc `,
		`rep' .bashrc `,
		`rep" C:\Users\victim\.bashrc `,
		`a\"b\'c\\d e`,
		`trailing\`,
		`trailing"`,
		`trailing'`,
		`trailing `,
		"trailing\u00a0",
		`"""`,
		`'''`,
		`\\\`,
		`\"\"\" `,
	)
	for _, a := range atoms {
		corpus = append(corpus, a)
		for _, b := range atoms {
			corpus = append(corpus, a+b)
		}
	}

	modes := []struct {
		name      string
		quoteChar rune
		prefix    string
		closeQ    string
	}{
		{name: "unquoted", quoteChar: 0, prefix: "", closeQ: ""},
		{name: "double_quoted", quoteChar: '"', prefix: `"`, closeQ: `"`},
		{name: "single_quoted", quoteChar: '\'', prefix: `'`, closeQ: `'`},
	}

	assertRoundTrip := func(raw string) {
		for _, mode := range modes {
			formatted := formatCompletionCandidate(raw, mode.quoteChar, false)
			line := "cmd " + mode.prefix + formatted
			got, err := splitCommandLine(line)
			if err != nil {
				t.Fatalf("[%s] splitCommandLine(%q) for raw=%q failed: %v", mode.name, line, raw, err)
			}
			want := []string{"cmd", raw}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("[%s] splitCommandLine(%q) = %#v, want %#v", mode.name, line, got, want)
			}

			lineWithNext := line + " nextarg"
			gotNext, err := splitCommandLine(lineWithNext)
			if err != nil {
				t.Fatalf("[%s] splitCommandLine(%q) for raw=%q failed: %v", mode.name, lineWithNext, raw, err)
			}
			wantNext := []string{"cmd", raw, "nextarg"}
			if !reflect.DeepEqual(gotNext, wantNext) {
				t.Fatalf("[%s] splitCommandLine(%q) = %#v, want %#v", mode.name, lineWithNext, gotNext, wantNext)
			}

			dirFormatted := formatCompletionCandidate(raw, mode.quoteChar, true)
			dirLine := "cmd " + mode.prefix + dirFormatted + mode.closeQ
			gotDir, err := splitCommandLine(dirLine)
			if err != nil {
				t.Fatalf("[%s/dir] splitCommandLine(%q) for raw=%q failed: %v", mode.name, dirLine, raw, err)
			}
			if !reflect.DeepEqual(gotDir, want) {
				t.Fatalf("[%s/dir] splitCommandLine(%q) = %#v, want %#v", mode.name, dirLine, gotDir, want)
			}
		}
	}

	for _, raw := range corpus {
		// Every non-tab entry in corpus must also be a valid RemoteName.
		if !strings.ContainsRune(raw, '\t') {
			if _, err := sftp.ParseRemoteName(raw); err != nil {
				t.Fatalf("test corpus entry %q is not a valid RemoteName: %v", raw, err)
			}
		}
		assertRoundTrip(raw)
	}

	// Also verify multi-segment paths containing '/' (e.g., dir/file completions
	// and slash-bearing quote-breakout payloads) round-trip losslessly.
	for _, multiSeg := range []string{
		`rep" /home/victim/.bashrc `,
		`rep' /home/victim/.bashrc `,
		`dir\ with\ space/rep" /home/victim/.bashrc `,
	} {
		assertRoundTrip(multiSeg)
	}
}

// TestP7W9a_AcceptCompletionRejectsControlAndEscapeRunes verifies AB9-M1 & AB9-L1:
// editorModel.acceptCompletion rejects any candidate containing C0/DEL/C1/line-sep
// control or escape runes on both single-candidate and multi-candidate results.
func TestP7W9a_AcceptCompletionRejectsControlAndEscapeRunes(t *testing.T) {
	hostileSingle := []struct {
		name      string
		candidate string
	}{
		{name: "newline_flag_injection", candidate: "rep\n-f"},
		{name: "carriage_return", candidate: "rep\r-f"},
		{name: "osc_52_clipboard", candidate: "rep\x1b]52;c;aGVsbG8=\x07"},
		{name: "csi_sgr_escape", candidate: "rep\x1b[31mred\x1b[0m"},
		{name: "del_char", candidate: "rep\x7fname"},
		{name: "c1_csi_9b", candidate: "rep\u009b2J"},
		{name: "c1_nel_85", candidate: "rep\u0085-f"},
		{name: "unicode_line_sep", candidate: "rep\u2028-f"},
	}

	for _, tc := range hostileSingle {
		t.Run("single/"+tc.name, func(t *testing.T) {
			m := newEditorModel(promptOptions{}, nil, func(uint64, string, int) context.CancelFunc { return func() {} })
			m.input.SetValue("rm rep")
			m.input.CursorEnd()
			m.Update(editorKey("tab"))
			m.Update(completionMsg{
				id:   m.requestID,
				line: "rm rep",
				pos:  6,
				result: completionResult{
					head:       "rm ",
					candidates: []string{tc.candidate},
				},
			})
			if m.input.Value() != "rm rep" {
				t.Fatalf("unsafe single candidate mutated input to %q, want unchanged \"rm rep\"", m.input.Value())
			}
			if m.completion != nil {
				t.Fatalf("unsafe single candidate retained active completion state")
			}
			assertNoTerminalControlRunes(t, m.hint)
		})
	}

	t.Run("multi_filters_out_hostile_and_accepts_safe", func(t *testing.T) {
		m := newEditorModel(promptOptions{}, nil, func(uint64, string, int) context.CancelFunc { return func() {} })
		m.input.SetValue("rm rep")
		m.input.CursorEnd()
		m.Update(editorKey("tab"))
		m.Update(completionMsg{
			id:   m.requestID,
			line: "rm rep",
			pos:  6,
			result: completionResult{
				head:       "rm ",
				candidates: []string{"rep\n-f", "rep\x1b]52;c;aGVsbG8=\x07", "report.txt"},
			},
		})
		if m.input.Value() != "rm report.txt" {
			t.Fatalf("input = %q, want \"rm report.txt\"", m.input.Value())
		}
	})

	t.Run("error_hint_sanitizes_osc_and_controls", func(t *testing.T) {
		m := newEditorModel(promptOptions{}, nil, func(uint64, string, int) context.CancelFunc { return func() {} })
		m.input.SetValue("rm rep")
		m.input.CursorEnd()
		m.Update(editorKey("tab"))
		m.Update(completionMsg{
			id:   m.requestID,
			line: "rm rep",
			pos:  6,
			result: completionResult{
				err: errors.New("boom\x1b]52;c;aGVsbG8=\x07\n\u009b2J"),
			},
		})
		assertNoTerminalControlRunes(t, m.hint)
		if strings.Contains(m.hint, "aGVsbG8=") {
			t.Fatalf("error hint leaked OSC payload: %q", m.hint)
		}
	})
}

// TestP7W9a_ListRemoteOneRejectsHostileReadDirAndSanitizesDisplay verifies AB9-M1 & AB9-L1:
//   - ls / ll on hostile ReadDir fails closed via validated Client.ReadDir with zero stdout output.
//   - Display paths (listRemoteOne, printColumns, sanitizeDisplayText) strip CSI/OSC/DEL/C1
//     control sequences so no unsafe control rune can ever reach s.stdout.
func TestP7W9a_ListRemoteOneRejectsHostileReadDirAndSanitizesDisplay(t *testing.T) {
	t.Run("ls_and_ll_reject_hostile_readdir", func(t *testing.T) {
		cases := []struct {
			name       string
			entries    []os.FileInfo
			wantErrIs  error
			wantSubstr string
		}{
			{
				name: "slash_dotdot",
				entries: []os.FileInfo{
					p7ReproFileInfo{name: "x/..", mode: os.ModeDir | 0o755},
				},
				wantErrIs: sftp.ErrInvalidRemoteName,
			},
			{
				name: "slash_dot",
				entries: []os.FileInfo{
					p7ReproFileInfo{name: "x/.", mode: os.ModeDir | 0o755},
				},
				wantErrIs: sftp.ErrInvalidRemoteName,
			},
			{
				name: "root_slash",
				entries: []os.FileInfo{
					p7ReproFileInfo{name: "/", mode: os.ModeDir | 0o755},
				},
				wantErrIs: sftp.ErrInvalidRemoteName,
			},
			{
				name: "osc_52_name",
				entries: []os.FileInfo{
					p7ReproFileInfo{name: "rep\x1b]52;c;aGVsbG8=\x07", size: 8, mode: 0o644},
				},
				wantErrIs: sftp.ErrInvalidRemoteName,
			},
			{
				name: "newline_name",
				entries: []os.FileInfo{
					p7ReproFileInfo{name: "rep\n-f", size: 8, mode: 0o644},
				},
				wantErrIs: sftp.ErrInvalidRemoteName,
			},
			{
				name: "duplicate_entry",
				entries: []os.FileInfo{
					p7ReproFileInfo{name: "dup.txt", size: 8, mode: 0o644},
					p7ReproFileInfo{name: "dup.txt", size: 8, mode: 0o644},
				},
				wantSubstr: "duplicate",
			},
		}

		for _, cmd := range []string{"ls", "ll"} {
			for _, tc := range cases {
				t.Run(cmd+"/"+tc.name, func(t *testing.T) {
					h := newW8aShellTrackingHandler()
					h.stats["/remote"] = p7ReproFileInfo{name: "remote", mode: os.ModeDir | 0o755}
					h.dirLists["/remote"] = tc.entries

					sh := newP7W7bShellWithHandlers(t, h.handlers(), "/remote", t.TempDir())
					var stdout bytes.Buffer
					sh.stdout = &stdout

					exit, err := sh.dispatchCommand(t.Context(), cmd, nil)
					if exit {
						t.Fatalf("dispatchCommand(%s) signaled exit", cmd)
					}
					if err == nil {
						t.Fatalf("dispatchCommand(%s) succeeded for hostile %s, stdout=%q", cmd, tc.name, stdout.String())
					}
					if tc.wantErrIs != nil && !errors.Is(err, tc.wantErrIs) {
						t.Fatalf("dispatchCommand(%s %s) err = %v, want errors.Is(_, %v)", cmd, tc.name, err, tc.wantErrIs)
					}
					if tc.wantSubstr != "" && !strings.Contains(err.Error(), tc.wantSubstr) {
						t.Fatalf("dispatchCommand(%s %s) err = %v, want substring %q", cmd, tc.name, err, tc.wantSubstr)
					}
					if stdout.Len() != 0 {
						t.Fatalf("dispatchCommand(%s %s) leaked stdout %q despite hostile ReadDir", cmd, tc.name, stdout.String())
					}
				})
			}
		}
	})

	t.Run("display_sanitizes_csi_osc_del_c1_in_ls_ll_and_printColumns", func(t *testing.T) {
		evilNames := []string{
			"ok.txt",
			"csi\x1b[31mred\x1b[0m.txt",
			"osc\x1b]52;c;aGVsbG8=\x07.txt",
			"newline\nforged_line.txt",
			"del\x7f_and_c1_\u0080\u009b2J\u009f.txt",
			"tab\tcol\r\u2028sep.txt",
		}

		var colBuf bytes.Buffer
		sh := &Shell{stdout: &colBuf, stderr: &bytes.Buffer{}}
		sh.printColumns(evilNames)
		assertListingOutputSafe(t, colBuf.String())
		if !strings.Contains(colBuf.String(), "ok.txt") {
			t.Fatalf("printColumns lost normal filename: %q", colBuf.String())
		}
		if strings.Contains(colBuf.String(), "aGVsbG8=") {
			t.Fatalf("printColumns leaked OSC payload: %q", colBuf.String())
		}

		// Also verify listRemoteOne single-file output in both short and long modes.
		for _, long := range []bool{false, true} {
			h := newW8aShellTrackingHandler()
			h.stats["/remote/target"] = p7ReproFileInfo{
				name: "evil\x1b]52;c;aGVsbG8=\x07\x1b[2J\n\x7f\u009b2J.txt",
				size: 42,
				mode: 0o644,
			}
			rsh := newP7W7bShellWithHandlers(t, h.handlers(), "/remote", t.TempDir())
			var out bytes.Buffer
			rsh.stdout = &out

			if err := rsh.listRemoteOne(t.Context(), "/remote/target", long); err != nil {
				t.Fatalf("listRemoteOne(long=%v) err = %v", long, err)
			}
			assertListingOutputSafe(t, out.String())
			if strings.Contains(out.String(), "aGVsbG8=") {
				t.Fatalf("listRemoteOne(long=%v) leaked OSC payload: %q", long, out.String())
			}
		}
	})
}

func assertNoTerminalControlRunes(t *testing.T, s string) {
	t.Helper()
	for i, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == '\u2028' || r == '\u2029' {
			t.Fatalf("unsafe control rune U+%04X at byte %d in %q", r, i, s)
		}
	}
}

func assertListingOutputSafe(t *testing.T, output string) {
	t.Helper()
	for i, r := range output {
		if r == '\n' {
			continue
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == '\u2028' || r == '\u2029' {
			t.Fatalf("unsafe control rune U+%04X at byte %d in listing output %q", r, i, output)
		}
	}
}

// TestP7W9a_ComputeLocalUploadDirSizeSaturatingInt64 verifies AB9-L2:
// saturatingAddInt64 and computeLocalUploadDirSizeWith clamp negative sizes to
// 0 and saturate at math.MaxInt64 instead of wrapping negative on huge totals.
func TestP7W9a_ComputeLocalUploadDirSizeSaturatingInt64(t *testing.T) {
	t.Run("saturatingAddInt64_unit_cases", func(t *testing.T) {
		cases := []struct {
			a, b, want int64
		}{
			{0, 0, 0},
			{10, 20, 30},
			{10, -5, 10},
			{-5, 10, 10},
			{10, math.MinInt64, 10},
			{math.MinInt64, math.MinInt64, 0},
			{math.MaxInt64, 1, math.MaxInt64},
			{math.MaxInt64, math.MaxInt64, math.MaxInt64},
			{math.MaxInt64 - 1, 2, math.MaxInt64},
		}
		for _, tc := range cases {
			if got := saturatingAddInt64(tc.a, tc.b); got != tc.want {
				t.Errorf("saturatingAddInt64(%d, %d) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
		}
	})

	t.Run("overflow_saturates_at_MaxInt64", func(t *testing.T) {
		walkRoot := "/synthetic/root"
		fakeWalk := func(_ string, fn filepath.WalkFunc) error {
			entries := []struct {
				p    string
				info os.FileInfo
			}{
				{walkRoot, p7ReproFileInfo{name: "root", mode: os.ModeDir | 0o755}},
				{walkRoot + "/a.bin", p7ReproFileInfo{name: "a.bin", size: math.MaxInt64, mode: 0o644}},
				{walkRoot + "/b.bin", p7ReproFileInfo{name: "b.bin", size: math.MaxInt64, mode: 0o644}},
				{walkRoot + "/c.bin", p7ReproFileInfo{name: "c.bin", size: 1, mode: 0o644}},
				{walkRoot + "/link", p7ReproFileInfo{name: "link", mode: os.ModeSymlink | 0o777}},
			}
			for _, e := range entries {
				if err := fn(e.p, e.info, nil); err != nil {
					return err
				}
			}
			return nil
		}
		fakeReadlink := func(string) (string, error) { return "target_name", nil }

		got, err := computeLocalUploadDirSizeWith(walkRoot, walkRoot, fakeWalk, fakeReadlink)
		if err != nil {
			t.Fatalf("computeLocalUploadDirSizeWith err = %v", err)
		}
		if got != math.MaxInt64 {
			t.Fatalf("computeLocalUploadDirSizeWith = %d, want math.MaxInt64 (%d)", got, int64(math.MaxInt64))
		}
	})

	t.Run("negative_sizes_clamped_to_zero", func(t *testing.T) {
		walkRoot := "/synthetic/neg"
		fakeWalk := func(_ string, fn filepath.WalkFunc) error {
			entries := []struct {
				p    string
				info os.FileInfo
			}{
				{walkRoot, p7ReproFileInfo{name: "neg", mode: os.ModeDir | 0o755}},
				{walkRoot + "/neg1.bin", p7ReproFileInfo{name: "neg1.bin", size: -50, mode: 0o644}},
				{walkRoot + "/neg2.bin", p7ReproFileInfo{name: "neg2.bin", size: math.MinInt64, mode: 0o644}},
				{walkRoot + "/ok.bin", p7ReproFileInfo{name: "ok.bin", size: 77, mode: 0o644}},
				{walkRoot + "/link", p7ReproFileInfo{name: "link", mode: os.ModeSymlink | 0o777}},
			}
			for _, e := range entries {
				if err := fn(e.p, e.info, nil); err != nil {
					return err
				}
			}
			return nil
		}
		fakeReadlink := func(string) (string, error) { return "abc", nil }

		got, err := computeLocalUploadDirSizeWith(walkRoot, walkRoot, fakeWalk, fakeReadlink)
		if err != nil {
			t.Fatalf("computeLocalUploadDirSizeWith err = %v", err)
		}
		if got != 80 {
			t.Fatalf("computeLocalUploadDirSizeWith = %d, want 80", got)
		}
	})
}
