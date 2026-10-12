package ssh

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPOSIXWorkingDirectoryGuardsWholeProgram(t *testing.T) {
	for _, interpreter := range []Interpreter{InterpreterBash, InterpreterSh, InterpreterZsh} {
		t.Run(string(interpreter), func(t *testing.T) {
			shell, err := exec.LookPath(string(interpreter))
			if err != nil {
				t.Skipf("shell unavailable: %v", err)
			}
			cwd := filepath.Join(t.TempDir(), "space and quote' dir")
			if err := os.Mkdir(cwd, 0700); err != nil {
				t.Fatal(err)
			}
			cfg := &ExecutionConfig{Interpreter: interpreter, LaunchDialect: LaunchPOSIX}
			for _, program := range []string{"printf FIRST; printf SECOND", "printf FIRST\nprintf SECOND", "printf FIRST; printf SECOND # trailing comment", "{ printf FIRST; }; printf SECOND"} {
				assertPOSIXWorkingDirectoryProgram(t, shell, cwd, program, cfg)
			}
			command, err := FormatWorkingDirCommand(cwd, "printf FIRST; exit 7", cfg)
			if err != nil {
				t.Fatal(err)
			}
			output, status := runProbeShell(t, t.Context(), shell, LaunchPOSIX, command, append(os.Environ(), "HOME="+t.TempDir(), "ZDOTDIR="+t.TempDir(), "BASH_ENV=", "ENV="))
			if status != 7 || output != "FIRST" {
				t.Fatalf("exit code changed: status=%d output=%q", status, output)
			}
		})
	}
}

func assertPOSIXWorkingDirectoryProgram(t *testing.T, shell, cwd, program string, cfg *ExecutionConfig) {
	t.Helper()
	for _, exists := range []bool{true, false} {
		target := cwd
		if !exists {
			target = filepath.Join(cwd, "missing")
		}
		command, err := FormatWorkingDirCommand(target, program, cfg)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := PlanCommand(command, cfg.CommandOptions())
		if err != nil {
			t.Fatal(err)
		}
		output, status := runProbeShell(t, t.Context(), shell, LaunchPOSIX, plan.Payload(), append(os.Environ(), "HOME="+t.TempDir(), "ZDOTDIR="+t.TempDir(), "BASH_ENV=", "ENV="))
		if exists {
			if status != 0 || output != "FIRSTSECOND" {
				t.Fatalf("compound program changed: status=%d output=%q", status, output)
			}
		} else if status == 0 || strings.Contains(output, "FIRST") || strings.Contains(output, "SECOND") {
			t.Fatalf("program ran after cd failure: status=%d output=%q", status, output)
		}
	}
}
