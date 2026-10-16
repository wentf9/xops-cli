package cmd

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Equal size and mtime are not proof of equal contents. Exercise the actual
// directory-destination routing, with one answer available to catch re-prompts.
func TestSCPRelayExistingTarget(t *testing.T) {
	for _, metadata := range []string{"matching", "different"} {
		for _, policy := range []struct {
			name, answer, want string
			prompts            int
		}{
			{"confirm", "y", "new bytes", 1},
			{"decline", "n", "old bytes", 1},
			{"force", "", "new bytes", 0},
			{"no-clobber", "", "old bytes", 0},
			{"input-error", "", "old bytes", 1},
		} {
			for _, output := range []string{"normal", "quiet"} {
				t.Run(metadata+"/"+policy.name+"/"+output, func(t *testing.T) {
					fixture := newSCPTransferFixture(t)
					for _, directory := range []string{"source", "destination"} {
						if err := os.Mkdir(filepath.Join(fixture.home, directory), 0o700); err != nil {
							t.Fatal(err)
						}
					}
					source := filepath.Join(fixture.home, "source", "payload.txt")
					target := filepath.Join(fixture.home, "destination", "payload.txt")
					writeSCPTestFile(t, source, "new bytes")
					writeSCPTestFile(t, target, "old bytes")
					sourceTime := time.Unix(1700000000, 0)
					targetTime := sourceTime
					if metadata == "different" {
						targetTime = targetTime.Add(time.Hour)
					}
					for name, modified := range map[string]time.Time{source: sourceTime, target: targetTime} {
						if err := os.Chtimes(name, modified, modified); err != nil {
							t.Fatal(err)
						}
					}
					options := NewScpOptions()
					options.Source, options.Dest = "scp-test:./source/payload.txt", "scp-test:./destination/"
					options.Force = policy.name == "force"
					options.NoOverwrite = policy.name == "no-clobber"
					options.Quiet = output == "quiet"
					setSCPTestConfirmation(t, policy.answer)
					if policy.name == "input-error" {
						if _, err := os.Stdin.Seek(0, io.SeekEnd); err != nil {
							t.Fatal(err)
						}
					}
					var transferErr error
					captured := captureSCPOutput(t, false, func() {
						transferErr = options.runTransfer(fixture.ctx, fixture.repo, fixture.connector)
					})
					if policy.name == "input-error" {
						if !errors.Is(transferErr, io.EOF) {
							t.Fatalf("confirmation error lost: %v", transferErr)
						}
					} else if transferErr != nil {
						t.Fatal(transferErr)
					}
					if got := strings.Count(captured, "[y/N]"); got != policy.prompts {
						t.Fatalf("overwrite prompts=%d, want %d; output=%q", got, policy.prompts, captured)
					}
					assertSCPTestFile(t, target, policy.want)
					assertSCPTestFile(t, source, "new bytes")
				})
			}
		}
	}
}

func TestSCPRelaySkippedTargetHasNoProgress(t *testing.T) {
	for _, policy := range []string{"decline", "no-clobber"} {
		t.Run(policy, func(t *testing.T) {
			fixture := newSCPTransferFixture(t)
			source := filepath.Join(fixture.home, "source.txt")
			target := filepath.Join(fixture.home, "target.txt")
			writeSCPTestFile(t, source, "new bytes")
			writeSCPTestFile(t, target, "old bytes")
			modified := time.Unix(1700000000, 0)
			for _, name := range []string{source, target} {
				if err := os.Chtimes(name, modified, modified); err != nil {
					t.Fatal(err)
				}
			}
			options := NewScpOptions()
			options.Source, options.Dest = "scp-test:./source.txt", "scp-test:./target.txt"
			options.NoOverwrite = policy == "no-clobber"
			setSCPTestConfirmation(t, "n")
			var transferErr error
			captured := captureSCPOutput(t, true, func() {
				transferErr = options.runTransfer(fixture.ctx, fixture.repo, fixture.connector)
			})
			if transferErr != nil {
				t.Fatal(transferErr)
			}
			if strings.Contains(captured, "Relaying") || strings.Contains(captured, "100%") {
				t.Fatalf("skipped relay rendered transfer progress: %q", captured)
			}
			wantPrompts := 0
			if policy == "decline" {
				wantPrompts = 1
			}
			if got := strings.Count(captured, "[y/N]"); got != wantPrompts {
				t.Fatalf("overwrite prompts=%d, want %d; output=%q", got, wantPrompts, captured)
			}
			assertSCPTestFile(t, target, "old bytes")
		})
	}
}
