package sftp

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Model a filesystem that can rename files but refuses to replace an existing
// entry, including during recovery. No global filesystem hooks are modified.
func renameWithoutReplacement(source, destination string) error {
	if _, err := os.Lstat(destination); err == nil {
		return &os.LinkError{Op: "rename", Old: source, New: destination, Err: os.ErrExist}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(source, destination)
}

func writeReplacementFixture(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertReplacementContent(t *testing.T, name, want string) {
	t.Helper()
	content, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != want {
		t.Fatalf("file %q = %q, want %q", name, content, want)
	}
}

func TestReplaceLocalFile(t *testing.T) {
	for _, fallback := range []bool{false, true} {
		name := "atomic rename"
		rename := os.Rename
		if fallback {
			name = "filesystem rejects replacement"
			rename = renameWithoutReplacement
		}
		t.Run(name, func(t *testing.T) {
			for _, existing := range []bool{false, true} {
				dir := t.TempDir()
				temporary, destination := filepath.Join(dir, "temporary"), filepath.Join(dir, "destination")
				writeReplacementFixture(t, temporary, "new bytes")
				if existing {
					writeReplacementFixture(t, destination, "old bytes")
				}
				if err := replaceLocalFile(temporary, destination, rename); err != nil {
					t.Fatal(err)
				}
				assertReplacementContent(t, destination, "new bytes")
				entries, err := os.ReadDir(dir)
				if err != nil || len(entries) != 1 {
					t.Fatalf("replacement left temporary files: entries=%v, error=%v", entries, err)
				}
			}
		})
	}
}

func TestReplaceLocalFileFailurePreservesOriginal(t *testing.T) {
	for _, stage := range []string{"initial rename", "backup", "promotion", "rollback", "concurrent destination"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			temporary, destination := filepath.Join(dir, "temporary"), filepath.Join(dir, "destination")
			backup := temporary + ".backup"
			writeReplacementFixture(t, temporary, "new bytes")
			writeReplacementFixture(t, destination, "old bytes")
			fault := errors.New("injected rename failure")
			backedUp := false
			rename := func(source, target string) error {
				switch {
				case stage == "initial rename":
					return fault
				case source == destination && stage == "backup":
					return fault
				case source == temporary && backedUp:
					if stage == "concurrent destination" {
						writeReplacementFixture(t, destination, "concurrent bytes")
					}
					return fault
				case source == backup && stage == "rollback":
					return fault
				}
				err := renameWithoutReplacement(source, target)
				if err == nil && target == backup {
					backedUp = true
				}
				return err
			}
			err := replaceLocalFile(temporary, destination, rename)
			if !errors.Is(err, fault) {
				t.Fatalf("replacement error = %v, want injected failure", err)
			}
			original := destination
			if stage == "rollback" || stage == "concurrent destination" {
				original = backup
				// Diagnostics quote paths with %q, including Windows backslashes.
				if !strings.Contains(err.Error(), strconv.Quote(backup)) {
					t.Fatalf("error does not identify preserved original: %v", err)
				}
			}
			assertReplacementContent(t, original, "old bytes")
			assertReplacementContent(t, temporary, "new bytes")
			if stage == "concurrent destination" {
				assertReplacementContent(t, destination, "concurrent bytes")
			}
		})
	}
}

func TestReplaceLocalFileRejectsDirectoryAndExistingBackup(t *testing.T) {
	for _, entry := range []string{"directory", "backup"} {
		t.Run(entry, func(t *testing.T) {
			dir := t.TempDir()
			temporary, destination := filepath.Join(dir, "temporary"), filepath.Join(dir, "destination")
			writeReplacementFixture(t, temporary, "new bytes")
			protected := destination
			if entry == "directory" {
				if err := os.Mkdir(destination, 0o700); err != nil {
					t.Fatal(err)
				}
				protected = filepath.Join(destination, "child")
			} else {
				writeReplacementFixture(t, temporary+".backup", "existing backup")
			}
			writeReplacementFixture(t, protected, "old bytes")
			if err := replaceLocalFile(temporary, destination, renameWithoutReplacement); err == nil {
				t.Fatal("replacement unexpectedly succeeded")
			}
			assertReplacementContent(t, protected, "old bytes")
			assertReplacementContent(t, temporary, "new bytes")
			if entry == "backup" {
				assertReplacementContent(t, temporary+".backup", "existing backup")
			}
		})
	}
}
