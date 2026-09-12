package sftpshell

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBatchListingFailureStopsCommands(t *testing.T) {
	for _, command := range []string{"lls", "lll"} {
		for _, wildcard := range []bool{false, true} {
			name := command + "/missing"
			if wildcard {
				name = command + "/wildcard"
			}
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				target := "missing-directory"
				if wildcard {
					// Glob sees the link, but Stat fails while listing it. A later
					// matching directory must not be visited after that failure.
					if err := os.Symlink(filepath.Join(dir, "missing"), filepath.Join(dir, "match-a")); err != nil {
						t.Skipf("symlink unavailable: %v", err)
					}
					if err := os.Mkdir(filepath.Join(dir, "match-z"), 0700); err != nil {
						t.Fatal(err)
					}
					target = "match-*"
				}
				var stdout, stderr bytes.Buffer
				s := &Shell{batch: true, localCwd: dir, stdout: &stdout, stderr: &stderr,
					stdin: batchInput(t, command+" "+target+"\nlmkdir after-failure\nexit\n")}
				ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
				defer cancel()
				if err := s.Run(ctx); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("expected listing not-found error, got %v", err)
				}
				if _, err := os.Stat(filepath.Join(dir, "after-failure")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("subsequent command ran: %v", err)
				}
				if wildcard && strings.Contains(stdout.String(), "match-z") {
					t.Fatal("listing continued after a failed wildcard match")
				}
			})
		}
	}
}

func TestRemoteListingPropagatesClientFailure(t *testing.T) {
	for _, command := range []string{"ls", "ll"} {
		t.Run(command, func(t *testing.T) {
			s := &Shell{cwd: "/", stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
			_, err := s.dispatchCommand(t.Context(), command, []string{"missing"})
			if err == nil || !strings.Contains(err.Error(), "/missing") {
				t.Fatalf("remote listing lost failure and path: %v", err)
			}
		})
	}
}
