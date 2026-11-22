package sftpshell

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/wentf9/xops-cli/core/fsx"
)

func TestP7W4a_CopyLocalFile_RefusesSymlinkDestNoTruncate(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.txt")
	if err := os.WriteFile(src, []byte("new-content"), 0o600); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(dir, "victim.txt")
	if err := os.WriteFile(victim, []byte("victim-intact"), 0o600); err != nil {
		t.Fatal(err)
	}
	dstLink := filepath.Join(dir, "dst.link")
	if err := os.Symlink(victim, dstLink); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink creation unavailable on Windows: %v", err)
		}
		t.Fatal(err)
	}

	err := copyLocalFile(src, dstLink)
	if !errors.Is(err, fsx.ErrSymlink) {
		t.Fatalf("copyLocalFile(src, symlink dst) = %v, want fsx.ErrSymlink", err)
	}
	after, readErr := os.ReadFile(victim)
	if readErr != nil || string(after) != "victim-intact" {
		t.Fatalf("victim file was truncated or modified: (%q, %v)", string(after), readErr)
	}
}

func TestP7W4a_CopyLocalFile_RegularOverwriteAndSameFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.txt")
	dst := filepath.Join(dir, "dst.txt")
	if err := os.WriteFile(src, []byte("fresh"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("longer-old-content"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := copyLocalFile(src, dst); err != nil {
		t.Fatalf("copyLocalFile overwrite failed: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil || string(got) != "fresh" {
		t.Fatalf("copied content = (%q, %v), want \"fresh\"", string(got), err)
	}

	// Copying a file onto itself must fail without truncating the source.
	if err := copyLocalFile(src, src); err == nil {
		t.Fatal("copyLocalFile(src, src) succeeded, want error")
	}
	srcAfter, err := os.ReadFile(src)
	if err != nil || string(srcAfter) != "fresh" {
		t.Fatalf("source file corrupted after same-file copy: (%q, %v)", string(srcAfter), err)
	}
}
