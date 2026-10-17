//go:build linux

package ssh

import (
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestInteractivePlanRegularFileRedirection(t *testing.T) {
	for _, combined := range []bool{false, true} {
		t.Run(map[bool]string{false: "separate", true: "combined"}[combined], func(t *testing.T) {
			_, stdin := openPrivilegeTestPTY(t)
			before, err := unix.IoctlGetTermios(int(stdin.Fd()), unix.TCGETS)
			if err != nil {
				t.Fatal(err)
			}
			stdout, err := os.CreateTemp(t.TempDir(), "stdout-*")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = stdout.Close() })
			stderr := stdout
			if !combined {
				stderr, err = os.CreateTemp(t.TempDir(), "stderr-*")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = stderr.Close() })
			}
			scenario := &commandFixture{terminal: true, output: "stdout 雪🙂\n", status: 7, commands: make(chan string, 1)}
			client := commandTestClient(t, scenario)
			plan, err := PlanCommand("chosen", CommandOptions{Interpreter: InterpreterSh, LaunchDialect: LaunchPOSIX})
			if err != nil {
				t.Fatal(err)
			}
			runErr := client.RunInteractivePlanWithIO(t.Context(), plan, InteractiveIO{Stdin: stdin, Stdout: stdout, Stderr: stderr})
			assertTerminalExit(t, runErr, 7, false, false, false)
			if got := <-scenario.commands; got != plan.Payload() || scenario.attempts.Load() != 1 {
				t.Fatalf("payload changed or replayed: %q", got)
			}
			out, err := os.ReadFile(stdout.Name())
			if err != nil {
				t.Fatal(err)
			}
			errOut, err := os.ReadFile(stderr.Name())
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(string(out), "stdout 雪🙂\n") != 1 || strings.Count(string(errOut), "stderr") != 1 {
				t.Fatalf("output lost: %q / %q", out, errOut)
			}
			if _, err := stdout.WriteString("caller"); err != nil {
				t.Fatalf("borrowed stdout closed: %v", err)
			}
			if _, err := stderr.WriteString("caller"); err != nil {
				t.Fatalf("borrowed stderr closed: %v", err)
			}
			after, err := unix.IoctlGetTermios(int(stdin.Fd()), unix.TCGETS)
			if err != nil || *before != *after {
				t.Fatalf("terminal not restored: %v", err)
			}
		})
	}
}

func TestInteractivePlanRegularFileWriteFailure(t *testing.T) {
	_, stdin := openPrivilegeTestPTY(t)
	before, err := unix.IoctlGetTermios(int(stdin.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/readonly.log"
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	scenario := &commandFixture{terminal: true, output: "cannot write", status: 7}
	client := commandTestClient(t, scenario)
	plan, err := PlanCommand("chosen", CommandOptions{})
	if err != nil {
		t.Fatal(err)
	}
	runErr := client.RunInteractivePlanWithIO(t.Context(), plan, InteractiveIO{Stdin: stdin, Stdout: file, Stderr: file})
	var outputErr *OutputError
	if !errors.As(runErr, &outputErr) || !outputErr.TargetsFile(file) || scenario.attempts.Load() != 1 {
		t.Fatalf("file error lost or command replayed: %v", runErr)
	}
	if _, err := file.Stat(); err != nil {
		t.Fatalf("borrowed failed file closed: %v", err)
	}
	after, err := unix.IoctlGetTermios(int(stdin.Fd()), unix.TCGETS)
	if err != nil || *before != *after {
		t.Fatalf("terminal not restored after output failure: %v", err)
	}
}
