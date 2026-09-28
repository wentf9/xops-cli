package sftpshell

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func historyReplacementFixture(t *testing.T) (source, destination string) {
	t.Helper()
	dir := t.TempDir()
	source, destination = filepath.Join(dir, "temporary"), filepath.Join(dir, "history")
	if err := os.WriteFile(source, []byte("new history"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("old history"), 0o600); err != nil {
		t.Fatal(err)
	}
	return source, destination
}

func assertHistoryFileContent(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || string(got) != want {
		t.Fatalf("history content = %q, want %q, error: %v", got, want, err)
	}
}

func TestHistoryRenameRetriesTransientConflict(t *testing.T) {
	source, destination := historyReplacementFixture(t)
	transient := errors.New("transient file sharing conflict")
	calls := 0
	err := retryHistoryRename(t.Context(), func() error {
		calls++
		assertHistoryFileContent(t, destination, "old history")
		if calls < 3 {
			return transient
		}
		return os.Rename(source, destination)
	}, func(err error) bool { return errors.Is(err, transient) })
	if err != nil || calls != 3 {
		t.Fatalf("replacement calls=%d, error=%v", calls, err)
	}
	assertHistoryFileContent(t, destination, "new history")
}

func TestHistoryRenameFailurePreservesFiles(t *testing.T) {
	for _, scenario := range []string{"permanent error", "cancel during retry", "already cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			source, destination := historyReplacementFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if scenario == "already cancelled" {
				cancel()
			}
			failure := errors.New("injected rename error")
			calls := 0
			err := retryHistoryRename(ctx, func() error {
				calls++
				if scenario == "cancel during retry" {
					cancel()
				}
				return failure
			}, func(error) bool { return scenario != "permanent error" })
			if scenario == "already cancelled" {
				if calls != 0 || !errors.Is(err, context.Canceled) {
					t.Fatalf("cancelled replacement: calls=%d, error=%v", calls, err)
				}
			} else if calls != 1 || !errors.Is(err, failure) {
				t.Fatalf("failed replacement: calls=%d, error=%v", calls, err)
			}
			if scenario == "cancel during retry" && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation cause lost: %v", err)
			}
			assertHistoryFileContent(t, source, "new history")
			assertHistoryFileContent(t, destination, "old history")
		})
	}
}
