//go:build linux

package ssh

import (
	"bytes"
	"testing"

	corelog "github.com/wentf9/xops-cli/core/log"
	"golang.org/x/sys/unix"
)

func TestTerminalDiagnosticExitBeforeShellPolicy(t *testing.T) {
	for _, shell := range []bool{false, true} {
		t.Run(map[bool]string{false: "exec", true: "shell"}[shell], func(t *testing.T) {
			_, stdin := openPrivilegeTestPTY(t)
			before, err := unix.IoctlGetTermios(int(stdin.Fd()), unix.TCGETS)
			if err != nil {
				t.Fatal(err)
			}
			client := commandTestClient(t, &commandFixture{terminal: true, output: "remote-output", status: 23})
			recorder := &diagnosticRecorder{}
			client.diagnostics = recorder
			var stdout, stderr bytes.Buffer
			streams := InteractiveIO{Stdin: stdin, Stdout: &stdout, Stderr: &stderr}
			if shell {
				if err := client.ShellWithIO(t.Context(), streams); err != nil {
					t.Fatalf("legacy shell exit policy changed: %v", err)
				}
			} else {
				plan, err := PlanCommand("private-command", CommandOptions{})
				if err != nil {
					t.Fatal(err)
				}
				assertTerminalExit(t, client.RunInteractivePlanWithIO(t.Context(), plan, streams), 23, false, false, false)
			}
			exits := 0
			for _, event := range recorder.snapshot() {
				if event.Kind == corelog.SessionFinished {
					exits++
					if !event.HasExitCode || event.ExitCode != 23 {
						t.Fatalf("actual terminal exit lost: %+v", event)
					}
				}
			}
			if exits != 1 {
				t.Fatalf("exit reported %d times", exits)
			}
			after, err := unix.IoctlGetTermios(int(stdin.Fd()), unix.TCGETS)
			if err != nil || *before != *after {
				t.Fatalf("terminal mode changed: %v", err)
			}
		})
	}
}
