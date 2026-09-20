package sftpshell

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestCommandHistoryLimitsAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history")
	h, err := newCommandHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"", " ls ", "ls", "get 界"} {
		if err := h.Append(line); err != nil {
			t.Fatal(err)
		}
	}
	loaded, err := newCommandHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(loaded.Lines(), "|"); got != "ls|get 界" {
		t.Fatal(got)
	}
	lines := []string{}
	for i := 0; i < 700; i++ {
		lines = appendHistoryLine(lines, fmt.Sprint(i))
	}
	if len(lines) != 500 || lines[0] != "200" {
		t.Fatal("history not bounded")
	}
	if err := writeCommandHistory(path, lines); err != nil {
		t.Fatal(err)
	}
	loaded, err = newCommandHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Lines()) != 500 {
		t.Fatal("reload not bounded")
	}
}
func TestCommandHistoryConcurrentInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history")
	const count = 12
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Go(func() {
			h, err := newCommandHistory(path)
			if err != nil {
				t.Error(err)
				return
			}
			if err := h.Append(fmt.Sprintf("command-%d", i)); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	h, err := newCommandHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Lines()) != count {
		t.Fatalf("lost commands: %v", h.Lines())
	}
}
func TestCommandHistoryWriteFailureKeepsSessionHistory(t *testing.T) {
	h, err := newCommandHistory(filepath.Join(t.TempDir(), "missing", "history"))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Append("ls"); err == nil {
		t.Fatal("expected write error")
	}
	if len(h.Lines()) != 1 {
		t.Fatal("session history lost")
	}
}
func TestHistoryReadFailure(t *testing.T) {
	dir := t.TempDir()
	if _, err := newCommandHistory(dir); err == nil {
		t.Fatal("directory history accepted")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("read created files")
	}
}

func TestCommandHistoryRetriesPendingEntries(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")
	path := filepath.Join(dir, "history")
	h, err := newCommandHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"first", "first", "second"} {
		if err := h.Append(line); err == nil {
			t.Fatal("expected write failure")
		}
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	other, err := newCommandHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Append("other-session"); err != nil {
		t.Fatal(err)
	}
	if err := h.Append("third"); err != nil {
		t.Fatal(err)
	}
	want := "other-session|first|second|third"
	if got := strings.Join(h.Lines(), "|"); got != want {
		t.Fatalf("session history=%q, want %q", got, want)
	}
	reloaded, err := newCommandHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(reloaded.Lines(), "|"); got != want {
		t.Fatalf("persisted history=%q", got)
	}
	if err := h.Append("fourth"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(h.Lines(), "|"); got != want+"|fourth" {
		t.Fatalf("pending entries were replayed twice: %q", got)
	}
}
