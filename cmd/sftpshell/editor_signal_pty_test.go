//go:build !windows

package sftpshell

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"golang.org/x/term"
)

// Keep process-wide signal delivery isolated from the test runner and its other
// prompts. Each child uses the same NotifyContext ownership as cmd.Execute.
func TestLineEditorSignalShutdown(t *testing.T) {
	const helper = "XOPS_SFTP_SIGNAL_HELPER"
	if name := os.Getenv(helper); name != "" {
		sig := syscall.SIGTERM
		if name == "SIGINT" {
			sig = syscall.SIGINT
		}
		for i := range 12 {
			t.Run(fmt.Sprint(i), func(t *testing.T) {
				h := newEditorPTY(t)
				original, err := term.GetState(int(h.slave.Fd()))
				if err != nil {
					t.Fatal(err)
				}
				ctx, stop := signal.NotifyContext(t.Context(), os.Interrupt, syscall.SIGTERM)
				defer stop()
				editor, err := newLineEditor(ctx, h.slave, h.slave, h.slave, "", &Shell{})
				if err != nil {
					t.Fatal(err)
				}
				defer closeTestResource(t, editor)
				done := make(chan error, 1)
				go func() { _, err := editor.Prompt(ctx, "SIGNAL> "); done <- err }()
				h.wait(t, "SIGNAL>")
				if err := syscall.Kill(os.Getpid(), sig); err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-done:
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("signal result: %v", err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("prompt did not shut down after signal")
				}
				closeTestResource(t, editor)
				restored, err := term.GetState(int(h.slave.Fd()))
				if err != nil {
					t.Fatal(err)
				}
				if *restored != *original {
					t.Fatal("terminal mode was not restored after signal")
				}
			})
		}
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"SIGTERM", "SIGINT"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, executable, "-test.run=^TestLineEditorSignalShutdown$", "-test.timeout=8s")
			command.Env = append(os.Environ(), helper+"="+name)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("signal helper: %v\n%s", err, output)
			}
		})
	}
}
