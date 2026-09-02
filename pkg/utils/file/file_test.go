package file

import (
	"os"
	"path/filepath"
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
