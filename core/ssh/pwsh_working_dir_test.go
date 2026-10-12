package ssh

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPwshWorkingDirUsesNativePlatformWithoutProbe(t *testing.T) {
	shell, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skipf("native pwsh unavailable: %v", err)
	}
	for _, cwd := range []string{"/C:/cwd'quote", "/C:"} {
		command, err := FormatWorkingDirCommand(cwd, "echo unused", &ExecutionConfig{Interpreter: InterpreterPwsh, LaunchDialect: LaunchPowerShell})
		if err != nil {
			t.Fatal(err)
		}
		expression, found := strings.CutPrefix(command, "Set-Location -LiteralPath ")
		if !found {
			t.Fatalf("missing literal cwd: %q", command)
		}
		expression, _, found = strings.Cut(expression, " -ErrorAction Stop; ")
		if !found {
			t.Fatalf("missing cwd validation: %q", command)
		}
		output, status := runProbeShell(t, t.Context(), shell, LaunchPowerShell, "Write-Output ("+expression+")", nil)
		want := cwd
		if runtime.GOOS == "windows" {
			want = NormalizeWindowsSFTPWorkingDir(cwd)
		}
		if status != 0 || strings.TrimSpace(output) != want {
			t.Fatalf("native platform cwd = %q (status %d), want %q", output, status, want)
		}
	}
}

func TestPwshWindowsSFTPWorkingDirExecutesWithoutProbe(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("requires native Windows drive paths")
	}
	shell, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skipf("native pwsh unavailable: %v", err)
	}
	directory := filepath.Join(t.TempDir(), "quoted'directory")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	command, err := FormatWorkingDirCommand("/"+filepath.ToSlash(directory), "(Get-Location).ProviderPath", &ExecutionConfig{Interpreter: InterpreterPwsh, LaunchDialect: LaunchPowerShell})
	if err != nil {
		t.Fatal(err)
	}
	output, status := runProbeShell(t, t.Context(), shell, LaunchPowerShell, "$ProgressPreference = 'SilentlyContinue'; "+command, nil)
	if status != 0 || !strings.EqualFold(filepath.Clean(strings.TrimSpace(output)), filepath.Clean(directory)) {
		t.Fatalf("native Windows cwd failed: status %d, output %q", status, output)
	}
}
