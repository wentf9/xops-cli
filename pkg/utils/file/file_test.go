package file

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCreateFileRecursive(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "a", "b", "c", "test.txt")
	content := []byte("hello world")

	if err := CreateFileRecursive(filePath, content, 0644); err != nil {
		t.Fatalf("CreateFileRecursive failed: %v", err)
	}

	got, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read created file: %v", err)
	}
	if string(got) != "hello world" {
		t.Errorf("content = %q, want 'hello world'", string(got))
	}

	info, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("stat created file failed: %v", err)
	}
	assertRequestedFileMode(t, info, 0644)
}

func TestCreateFileRecursive_EmptyContent(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "empty.txt")

	if err := CreateFileRecursive(filePath, nil, 0600); err != nil {
		t.Fatalf("CreateFileRecursive with nil content failed: %v", err)
	}

	info, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("file not created: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("file size = %d, want 0", info.Size())
	}
}

func TestToAbsolutePath_TildeAndUserExpansion(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("UserHomeDir unavailable: %v", err)
	}
	if got := ToAbsolutePath("~"); got != home {
		t.Errorf("ToAbsolutePath(~) = %q, want %q", got, home)
	}
	wantSub := filepath.Join(home, "sub", "key")
	if got := ToAbsolutePath("~/sub/key"); got != wantSub {
		t.Errorf("ToAbsolutePath(~/sub/key) = %q, want %q", got, wantSub)
	}
	if cur, err := user.Current(); err == nil && cur != nil && cur.Username != "" && cur.HomeDir != "" {
		wantUserSub := filepath.Join(cur.HomeDir, "sub", "key")
		if got := ToAbsolutePath("~" + cur.Username + "/sub/key"); got != wantUserSub {
			t.Errorf("ToAbsolutePath(~%s/sub/key) = %q, want %q", cur.Username, got, wantUserSub)
		}
	}
	unknown := "~nonexistent_xops_user_999/key"
	if got := ToAbsolutePath(unknown); got != unknown {
		t.Errorf("ToAbsolutePath(%q) = %q, want unchanged (must not turn into <cwd>/...)", unknown, got)
	}
}

func TestCreateFileRecursive_PrivateDirModeAndStrictPerms(t *testing.T) {
	dir := t.TempDir()
	privateDir := filepath.Join(dir, "secret-parent", "nested")
	filePath := filepath.Join(privateDir, "secret.key")

	if err := CreateFileRecursive(filePath, []byte("top-secret"), 0o600); err != nil {
		t.Fatalf("CreateFileRecursive(0600) failed: %v", err)
	}

	info, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("stat secret file: %v", err)
	}
	assertRequestedFileMode(t, info, 0o600)

	if runtime.GOOS != "windows" {
		for _, p := range []string{filepath.Join(dir, "secret-parent"), privateDir} {
			dInfo, statErr := os.Stat(p)
			if statErr != nil {
				t.Fatalf("stat parent dir %q: %v", p, statErr)
			}
			if got := dInfo.Mode().Perm(); got != 0o700 {
				t.Errorf("parent dir %q perm = %o, want 700", p, got)
			}
		}
	}

	// Overwriting an existing looser-permission file must strictly enforce 0600.
	loosePath := filepath.Join(dir, "loose.txt")
	if err := os.WriteFile(loosePath, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CreateFileRecursive(loosePath, []byte("tightened"), 0o600); err != nil {
		t.Fatalf("CreateFileRecursive overwrite failed: %v", err)
	}
	looseInfo, err := os.Stat(loosePath)
	if err != nil {
		t.Fatal(err)
	}
	assertRequestedFileMode(t, looseInfo, 0o600)
	got, err := os.ReadFile(loosePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "tightened" {
		t.Errorf("overwritten content = %q, want %q", string(got), "tightened")
	}
}

func TestCreateFileRecursive_RejectsExistingDirectoryAndCleansTemp(t *testing.T) {
	dir := t.TempDir()
	existingDir := filepath.Join(dir, "subdir")
	if err := os.Mkdir(existingDir, 0o755); err != nil {
		t.Fatal(err)
	}

	err := CreateFileRecursive(existingDir, []byte("payload"), 0o600)
	if err == nil {
		t.Fatal("CreateFileRecursive on existing directory succeeded, want error")
	}
	if !strings.Contains(err.Error(), "directory") {
		t.Errorf("error = %v, want mention of directory", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".xops-tmp-") {
			t.Errorf("leftover temp file found: %s", e.Name())
		}
	}
}

func TestCreateFileRecursive_RejectsTrailingSeparatorWithoutCreatingDir(t *testing.T) {
	base := t.TempDir()
	cases := []struct {
		name     string
		target   string
		checkDir string
	}{
		{"trailing_slash", filepath.Join(base, "newdir-slash") + "/", filepath.Join(base, "newdir-slash")},
		{"trailing_os_sep", filepath.Join(base, "newdir-sep") + string(os.PathSeparator), filepath.Join(base, "newdir-sep")},
		{"trailing_backslash", filepath.Join(base, "newdir-backslash") + `\`, filepath.Join(base, "newdir-backslash")},
		{"trailing_dot", filepath.Join(base, "newdir-dot") + "/.", filepath.Join(base, "newdir-dot")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CreateFileRecursive(tc.target, []byte("payload"), 0o600)
			if err == nil {
				t.Fatalf("CreateFileRecursive(%q) succeeded, want error", tc.target)
			}
			if _, statErr := os.Lstat(tc.checkDir); !os.IsNotExist(statErr) {
				t.Fatalf("CreateFileRecursive(%q) created %q as a side effect (statErr=%v)", tc.target, tc.checkDir, statErr)
			}
		})
	}
}

func TestCreateFileRecursive_ReplacesSymlinkWithoutFollowing(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.txt")
	if err := os.WriteFile(victim, []byte("original-victim"), 0o644); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(dir, "target.txt")
	if err := os.Symlink(victim, linkPath); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks unavailable on Windows: %v", err)
		}
		t.Fatalf("os.Symlink failed: %v", err)
	}

	if err := CreateFileRecursive(linkPath, []byte("replacement"), 0o600); err != nil {
		t.Fatalf("CreateFileRecursive on symlink failed: %v", err)
	}

	linfo, err := os.Lstat(linkPath)
	if err != nil {
		t.Fatal(err)
	}
	if linfo.Mode()&os.ModeSymlink != 0 {
		t.Fatal("target path is still a symlink; expected atomic replacement with regular file")
	}
	assertRequestedFileMode(t, linfo, 0o600)

	gotTarget, err := os.ReadFile(linkPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotTarget) != "replacement" {
		t.Errorf("target content = %q, want %q", string(gotTarget), "replacement")
	}

	gotVictim, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotVictim) != "original-victim" {
		t.Errorf("symlink victim was modified: got %q, want %q", string(gotVictim), "original-victim")
	}
}
