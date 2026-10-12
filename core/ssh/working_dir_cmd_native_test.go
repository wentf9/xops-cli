package ssh

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCMDWorkingDirectoryGuardsWholeProgram(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("requires native Windows CMD")
	}
	shell, err := exec.LookPath("cmd.exe")
	if err != nil {
		t.Skipf("CMD unavailable: %v", err)
	}
	cwd := filepath.Join(t.TempDir(), "space (and) amp&dir")
	if err := os.Mkdir(cwd, 0700); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, program, output string
		status                uint32
	}{
		{"sequence", "echo FIRST & echo SECOND", "FIRST\nSECOND", 0},
		{"and", "echo FIRST && echo SECOND", "FIRST\nSECOND", 0},
		{"or", "echo FIRST || echo SECOND", "FIRST", 0},
		{"nested group", "(echo FIRST & echo SECOND)", "FIRST\nSECOND", 0},
		{"quoted metacharacter", `echo "A&B" & echo SECOND`, `"A&B"` + "\nSECOND", 0},
		{"comment", "echo FIRST & rem trailing comment", "FIRST", 0},
		{"exit status", "echo FIRST & exit /b 7", "FIRST", 7},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assertCMDWorkingDirectoryProgram(t, shell, cwd, tt.program, tt.output, tt.status)
		})
	}
}

func assertCMDWorkingDirectoryProgram(t *testing.T, shell, cwd, program, wantOutput string, wantStatus uint32) {
	t.Helper()
	cfg := &ExecutionConfig{Interpreter: InterpreterCmd, LaunchDialect: LaunchCmd}
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
		output, status := runProbeShell(t, t.Context(), shell, LaunchCmd, plan.Payload(), nil)
		if exists {
			lines := strings.Split(strings.TrimSpace(output), "\n")
			for index := range lines {
				lines[index] = strings.TrimSpace(lines[index])
			}
			normalized := strings.Join(lines, "\n")
			if status != wantStatus || normalized != wantOutput {
				t.Fatalf("program changed: status=%d output=%q want=%d/%q", status, normalized, wantStatus, wantOutput)
			}
		} else if status == 0 || strings.Contains(output, "FIRST") || strings.Contains(output, "SECOND") || strings.Contains(output, "A&B") {
			t.Fatalf("program ran after cd failure: status=%d output=%q", status, output)
		}
	}
}
