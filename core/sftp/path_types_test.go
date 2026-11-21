package sftp

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestRemoteName_ValidationAndAccessors(t *testing.T) {
	t.Parallel()

	var zero RemoteName
	if zero.IsValid() || zero.String() != "" || zero.Equal(zero) {
		t.Fatalf("zero RemoteName must be invalid and not equal to itself")
	}

	for _, okName := range []string{"file.txt", ".hidden", "..dots", "a b", "CON.txt", `a\b`, "中文.log"} {
		n, err := ParseRemoteName(okName)
		if err != nil || !n.IsValid() || n.String() != okName || !n.Equal(n) {
			t.Errorf("ParseRemoteName(%q) = (%+v, %v)", okName, n, err)
		}
	}

	for _, bad := range []string{"", ".", "..", "/", "a/b", "/a", "a/", "bad\x00", "bad\n", "bad\r", "bad\x7f", "bad\u2028"} {
		n, err := ParseRemoteName(bad)
		if err == nil || !errors.Is(err, ErrInvalidRemoteName) || n.IsValid() {
			t.Errorf("ParseRemoteName(%q) = (%+v, %v), want ErrInvalidRemoteName", bad, n, err)
		}
	}
}

func TestRemotePath_ParseBaseAndJoin(t *testing.T) {
	t.Parallel()

	var zero RemotePath
	if zero.IsValid() || zero.IsAbs() || zero.String() != "" || zero.Base().IsValid() || zero.Dir().IsValid() || zero.Equal(zero) {
		t.Fatalf("zero RemotePath must be invalid")
	}

	// ParseRemotePath rejects empty, NUL, and control chars; cleans with POSIX path.Clean.
	for _, bad := range []string{"", "a\x00b", "a\nb", "a\rb", "a\x1fb", "a\u2029b"} {
		if p, err := ParseRemotePath(bad); err == nil || !errors.Is(err, ErrInvalidRemotePath) || p.IsValid() {
			t.Errorf("ParseRemotePath(%q) = (%+v, %v), want ErrInvalidRemotePath", bad, p, err)
		}
	}

	// Base uses POSIX path.Base (never filepath.Base): backslash is not a POSIX separator!
	pBackslash, err := ParseRemotePath(`/dir/sub\file.txt`)
	if err != nil {
		t.Fatal(err)
	}
	if base := pBackslash.Base(); !base.IsValid() || base.String() != `sub\file.txt` {
		t.Fatalf("POSIX Base() = %q, want %q", base.String(), `sub\file.txt`)
	}

	// Non-nameable paths return invalid zero RemoteName from Base().
	for _, nonNameable := range []string{"/", ".", "..", "../..", "a/b/../.."} {
		p, err := ParseRemotePath(nonNameable)
		if err != nil {
			t.Fatalf("ParseRemotePath(%q): %v", nonNameable, err)
		}
		if base := p.Base(); base.IsValid() {
			t.Errorf("RemotePath(%q).Base() = %q, want invalid zero RemoteName", p, base)
		}
	}

	// Join fails closed on invalid receiver or invalid RemoteName.
	rootSlash, _ := ParseRemotePath("/")
	if rootSlash.Join(RemoteName{}).IsValid() {
		t.Fatal("Join(zero RemoteName) must fail closed")
	}
	validName, _ := ParseRemoteName("file.txt")
	if zero.Join(validName).IsValid() {
		t.Fatal("zero.Join(validName) must fail closed")
	}
}

func TestRemotePath_RelativeTo(t *testing.T) {
	t.Parallel()

	// RelativeTo table covering root ".", root "/", non-canonical inputs, and escapes (H1).
	relCases := []struct {
		name     string
		root     string
		target   string
		wantSegs []string
		wantErr  bool
	}{
		{"dot_root_same", ".", ".", nil, false},
		{"dot_root_child", ".", "file.txt", []string{"file.txt"}, false},
		{"dot_root_dot_slash_child", ".", "./file.txt", []string{"file.txt"}, false},
		{"dot_root_nested", ".", "sub/dir/file.txt", []string{"sub", "dir", "file.txt"}, false},
		{"dot_root_cleaned_inside", ".", "sub/../file.txt", []string{"file.txt"}, false},
		{"dot_root_escape_dotdot", ".", "..", nil, true},
		{"dot_root_escape_parent", ".", "../etc/passwd", nil, true},
		{"dot_root_escape_nested", ".", "a/../../etc/passwd", nil, true},
		{"dot_root_abs_mismatch", ".", "/etc/passwd", nil, true},
		{"slash_root_same", "/", "/", nil, false},
		{"slash_root_child", "/", "/file.txt", []string{"file.txt"}, false},
		{"slash_root_nested", "/", "/a/b/c.txt", []string{"a", "b", "c.txt"}, false},
		{"slash_root_dirty_slash", "///", "/a//b/", []string{"a", "b"}, false},
		{"slash_root_rel_mismatch", "/", "file.txt", nil, true},
		{"abs_dir_same", "/srv/data/", "/srv/data", nil, false},
		{"abs_dir_child", "/srv/data", "/srv/data/sub/a.txt", []string{"sub", "a.txt"}, false},
		{"abs_dir_sibling_prefix_attack", "/srv/data", "/srv/data2/a.txt", nil, true},
		{"abs_dir_escape", "/srv/data", "/srv/data/../secret", nil, true},
		{"rel_dir_child", "dir/", "dir/sub/f.txt", []string{"sub", "f.txt"}, false},
		{"rel_dir_sibling_prefix", "dir", "dir2/f.txt", nil, true},
		{"parent_root_child", "..", "../sub/f.txt", []string{"sub", "f.txt"}, false},
		{"parent_root_escape", "..", "../../etc/passwd", nil, true},
	}

	for _, tc := range relCases {
		t.Run(tc.name, func(t *testing.T) {
			root, err := ParseRemotePath(tc.root)
			if err != nil {
				t.Fatalf("ParseRemotePath(%q): %v", tc.root, err)
			}
			target, err := ParseRemotePath(tc.target)
			if err != nil {
				t.Fatalf("ParseRemotePath(%q): %v", tc.target, err)
			}
			segs, err := target.RelativeTo(root)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("RelativeTo(%q, %q) succeeded with %v, want error", target, root, segs)
				}
				return
			}
			if err != nil {
				t.Fatalf("RelativeTo(%q, %q) unexpected error: %v", target, root, err)
			}
			got := make([]string, len(segs))
			for i, s := range segs {
				got[i] = s.String()
			}
			if len(tc.wantSegs) == 0 && len(got) != 0 {
				t.Fatalf("got %v, want empty", got)
			}
			if len(tc.wantSegs) > 0 && !slices.Equal(got, tc.wantSegs) {
				t.Fatalf("got %v, want %v", got, tc.wantSegs)
			}
			// Inverse law: root.JoinNames(segs...) == target.
			rebuilt, err := root.JoinNames(segs...)
			if err != nil || !rebuilt.Equal(target) {
				t.Fatalf("JoinNames inverse failed: root=%q segs=%v rebuilt=(%q, %v) want=%q", root, got, rebuilt, err, target)
			}
		})
	}
}

func TestLocalTarget_ResolveAndJoin(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	// Root target (zero names).
	rt, err := ResolveLocalTarget(root)
	if err != nil || !rt.IsValid() || !rt.IsRoot() || rt.Path() != filepath.Clean(root) || rt.RelSlash() != "." {
		t.Fatalf("ResolveLocalTarget(root) = (%+v, %v)", rt, err)
	}

	// Valid multi-segment local target + Join.
	n1, _ := ParseRemoteName("sub")
	n2, _ := ParseRemoteName("report.txt")
	lt, err := ResolveLocalTarget(root, n1, n2)
	if err != nil || !lt.IsValid() || lt.IsRoot() || lt.RelSlash() != "sub/report.txt" {
		t.Fatalf("ResolveLocalTarget(sub, report.txt) = (%+v, %v)", lt, err)
	}
	wantPath := filepath.Join(filepath.Clean(root), "sub", "report.txt")
	if lt.Path() != wantPath || lt.String() != wantPath {
		t.Fatalf("LocalTarget.Path() = %q, want %q", lt.Path(), wantPath)
	}
	joined, err := rt.Join(n1)
	if err != nil {
		t.Fatalf("rt.Join(sub): %v", err)
	}
	joined, err = joined.Join(n2)
	if err != nil || !joined.Equal(lt) {
		t.Fatalf("chained Join = (%+v, %v), want %+v", joined, err, lt)
	}
}

func TestLocalTarget_ValidatorAndHostileComponents(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	n1, _ := ParseRemoteName("sub")

	// Nil validator and invalid inputs must fail closed.
	if _, err := ResolveLocalTargetWithValidator(root, nil, n1); !errors.Is(err, ErrInvalidLocalTarget) {
		t.Fatalf("nil validator err = %v, want ErrInvalidLocalTarget", err)
	}
	if _, err := ResolveLocalTargetWithValidator(root, LocalComponentValidatorFunc(nil), n1); !errors.Is(err, ErrInvalidLocalTarget) {
		t.Fatalf("nil validator func err = %v, want ErrInvalidLocalTarget", err)
	}
	if _, err := ResolveLocalTarget(root, RemoteName{}); !errors.Is(err, ErrInvalidLocalTarget) {
		t.Fatalf("zero RemoteName err = %v, want ErrInvalidLocalTarget", err)
	}
	if _, err := ResolveLocalTarget("", n1); !errors.Is(err, ErrInvalidLocalTarget) {
		t.Fatalf("empty root err = %v, want ErrInvalidLocalTarget", err)
	}
	if _, err := ResolveLocalTarget(root+"\x00", n1); !errors.Is(err, ErrInvalidLocalTarget) {
		t.Fatalf("NUL root err = %v, want ErrInvalidLocalTarget", err)
	}

	// Custom validator injection (simulating core/fsx.ValidateLocalComponent).
	sentinel := errors.New("custom validator rejected")
	called := false
	custom := LocalComponentValidatorFunc(func(name string) error {
		called = true
		if name == "blocked" {
			return sentinel
		}
		return nil
	})
	blocked, _ := ParseRemoteName("blocked")
	if _, err := ResolveLocalTargetWithValidator(root, custom, blocked); !called || !errors.Is(err, sentinel) {
		t.Fatalf("custom validator not enforced: called=%v err=%v", called, err)
	}

	// Portable hostile local filenames rejected on all OSes (incl. superscripts COM¹-LPT³).
	hostile := []string{
		"CON",
		"con.txt",
		"PRN.log",
		"AUX",
		"NUL",
		"COM1",
		"com9.dat",
		"LPT1",
		"lpt9.a.b",
		"COM\u00b9.txt",
		"COM\u00b2",
		"COM\u00b3",
		"LPT\u00b9.log",
		"LPT\u00b2",
		"LPT\u00b3",
		"CON .txt",
		"foo:bar",
		`a\..\x`,
		"trailing.",
		"trailing ",
		"bad*name",
		"bad?name",
		`bad"name`,
		"bad<name>",
		"bad|name",
	}
	for _, raw := range hostile {
		rn, err := ParseRemoteName(raw)
		if err != nil {
			t.Fatalf("expected %q to be a valid POSIX RemoteName, got %v", raw, err)
		}
		if got, err := ResolveLocalTarget(root, rn); err == nil || !errors.Is(err, ErrInvalidLocalTarget) || got.IsValid() {
			t.Errorf("ResolveLocalTarget failed to reject hostile component %q: got (%+v, %v)", raw, got, err)
		}
	}
}

func FuzzRemoteNameRoundTrip(f *testing.F) {
	for _, seed := range []string{"file.txt", ".", "..", "a/b", "", "a\x00b", "CON.txt", "COM\u00b9"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		n, err := ParseRemoteName(raw)
		if err != nil {
			if n.IsValid() {
				t.Fatalf("ParseRemoteName(%q) returned error %v with valid name", raw, err)
			}
			return
		}
		reparsed, err := ParseRemoteName(n.String())
		if err != nil || !n.Equal(reparsed) || reparsed.String() != n.String() {
			t.Fatalf("RemoteName round-trip failed for %q", raw)
		}
	})
}

func FuzzRemotePathRoundTrip(f *testing.F) {
	for _, seed := range []string{
		"/",
		".",
		"..",
		"file.txt",
		"./a/b/c",
		"/a/b/../c/",
		"../shared/data",
		"",
		"a\x00b",
		"a\nb",
	} {
		f.Add(seed)
	}
	roots := []string{".", "/", "/srv/data", "dir"}
	f.Fuzz(func(t *testing.T, raw string) {
		p, err := ParseRemotePath(raw)
		if err != nil {
			if p.IsValid() {
				t.Fatalf("ParseRemotePath(%q) returned error %v with valid path", raw, err)
			}
			return
		}
		reparsed, err := ParseRemotePath(p.String())
		if err != nil || !p.Equal(reparsed) || reparsed.String() != p.String() {
			t.Fatalf("RemotePath round-trip failed for %q -> %q", raw, p.String())
		}
		if base := p.Base(); base.IsValid() {
			if strings.ContainsRune(base.String(), '/') || base.String() == "." || base.String() == ".." {
				t.Fatalf("invalid Base() %q for %q", base, p)
			}
		}
		for _, rStr := range roots {
			r, _ := ParseRemotePath(rStr)
			segs, err := p.RelativeTo(r)
			if err != nil {
				continue
			}
			rebuilt, err := r.JoinNames(segs...)
			if err != nil || !rebuilt.Equal(p) {
				t.Fatalf("RelativeTo/JoinNames mismatch: root=%q p=%q segs=%v rebuilt=(%q, %v)", r, p, segs, rebuilt, err)
			}
		}
	})
}

func FuzzLocalTargetRoundTrip(f *testing.F) {
	for _, seed := range []string{
		"a",
		"sub/file.txt",
		"CON.txt",
		"COM\u00b9",
		"foo:bar",
		`a\..\x`,
		"dir/trailing.",
		"dir/good-name_01.tar.gz",
	} {
		f.Add(seed)
	}
	root := f.TempDir()
	f.Fuzz(func(t *testing.T, rawRel string) {
		parts := strings.Split(rawRel, "/")
		names := make([]RemoteName, 0, len(parts))
		for _, part := range parts {
			n, err := ParseRemoteName(part)
			if err != nil {
				return
			}
			names = append(names, n)
		}
		lt, err := ResolveLocalTarget(root, names...)
		if err != nil {
			if lt.IsValid() {
				t.Fatalf("ResolveLocalTarget(%v) returned error %v with valid target", names, err)
			}
			return
		}
		if err := ensureLocalDestWithinDir(lt.Root(), lt.Path(), lt.IsRoot()); err != nil {
			t.Fatalf("LocalTarget escaped root: %v", err)
		}
		// Round-trip from RelSlash() segments back through ResolveLocalTarget.
		if !lt.IsRoot() {
			relParts := strings.Split(lt.RelSlash(), "/")
			rebuiltNames := make([]RemoteName, len(relParts))
			for i, seg := range relParts {
				rn, err := ParseRemoteName(seg)
				if err != nil {
					t.Fatalf("RelSlash segment %q failed ParseRemoteName: %v", seg, err)
				}
				rebuiltNames[i] = rn
			}
			rebuilt, err := ResolveLocalTarget(lt.Root(), rebuiltNames...)
			if err != nil || !lt.Equal(rebuilt) || rebuilt.String() != lt.String() {
				t.Fatalf("LocalTarget round-trip failed: orig=%+v rebuilt=(%+v, %v)", lt, rebuilt, err)
			}
		}
	})
}
