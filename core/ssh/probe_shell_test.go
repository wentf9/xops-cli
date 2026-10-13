package ssh

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// Run the actual payload in installed shells; synthetic frame responses cannot
// catch overlapping shell grammars or CMD's inherited ERRORLEVEL semantics.
func TestProbeShellDialects(t *testing.T) {
	for _, tt := range []struct {
		shell   string
		dialect LaunchDialect
	}{
		{"sh", LaunchPOSIX}, {"bash", LaunchPOSIX}, {"zsh", LaunchPOSIX}, {"fish", LaunchFish},
		{"pwsh", LaunchPowerShell}, {"powershell.exe", LaunchPowerShell},
		{"cmd.exe", LaunchCmd},
	} {
		t.Run(tt.shell, func(t *testing.T) {
			if runtime.GOOS != "windows" && strings.HasSuffix(tt.shell, ".exe") {
				t.Skip("requires a native Windows executable")
			}
			shell, err := exec.LookPath(tt.shell)
			if err != nil {
				t.Skipf("shell unavailable: %v", err)
			}
			// Native grammar checks have a process watchdog, not the production SSH
			// probe budget. Each interpreter process starts cold on hosted runners.
			execute := func(ctx context.Context, payload string) (string, error) {
				output, status := runProbeShell(t, ctx, shell, tt.dialect, payload, nil)
				if t.Failed() {
					t.FailNow()
				}
				if status != 0 {
					return output, &CommandExitError{ExitCode: &status}
				}
				return output, nil
			}
			result := &ProbeResult{ServerVersion: "SSH-2.0-native-test"}
			if err := detectProbeDialect(t.Context(), result, execute); err != nil {
				t.Fatalf("native %s dialect: %v", shell, err)
			}
			if result.DetectedDialect != tt.dialect {
				t.Fatalf("native %s detected as %s, want %s", shell, result.DetectedDialect, tt.dialect)
			}
			enumeration, err := probeInterpreterCommand(result.DetectedDialect)
			if err != nil {
				t.Fatal(err)
			}
			output, err := execute(t.Context(), enumeration)
			if err != nil {
				t.Fatalf("native %s enumeration: %v", shell, err)
			}
			available, err := parseProbeInterpreters(output)
			if err != nil {
				t.Fatalf("native %s interpreter frames: %v", shell, err)
			}
			recommendation := recommendProbeExecution(result.DetectedDialect, result.RemoteShellPath, available)
			if err := recommendation.Validate(); err != nil {
				t.Fatal(err)
			}
			if recommendation.Interpreter == InterpreterServer && tt.dialect != LaunchCmd {
				t.Fatalf("native %s found no supported interpreter: %v", shell, available)
			}
		})
	}
}

func TestProbeShellCmdMissingInterpreters(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("requires native Windows CMD")
	}
	systemDir := filepath.Join(os.Getenv("SystemRoot"), "System32")
	shell := filepath.Join(systemDir, "cmd.exe")
	// Windows 10/Server 2019+ System32 may contain a native bash.exe launcher stub.
	hasBash := false
	if _, err := os.Stat(filepath.Join(systemDir, "bash.exe")); err == nil {
		hasBash = true
	}
	for _, withPowerShell := range []bool{false, true} {
		name := "CMD only"
		searchPath := systemDir
		var want []Interpreter
		if hasBash {
			want = append(want, InterpreterBash)
		}
		want = append(want, InterpreterCmd)
		if withPowerShell {
			name = "Windows PowerShell without pwsh"
			searchPath += string(os.PathListSeparator) + filepath.Join(systemDir, "WindowsPowerShell", "v1.0")
			want = nil
			if hasBash {
				want = append(want, InterpreterBash)
			}
			want = append(want, InterpreterPowerShell, InterpreterCmd)
		}
		t.Run(name, func(t *testing.T) {
			env := slices.DeleteFunc(os.Environ(), func(value string) bool {
				return strings.HasPrefix(strings.ToUpper(value), "PATH=")
			})
			env = append(env, "PATH="+searchPath)
			payload, err := probeInterpreterCommand(LaunchCmd)
			if err != nil {
				t.Fatal(err)
			}
			output, status := runProbeShell(t, t.Context(), shell, LaunchCmd, payload, env)
			if status != 0 {
				t.Fatalf("optional lookup failed enumeration: status %d, output %q", status, output)
			}
			got, err := parseProbeInterpreters(output)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("interpreters = %v, want %v, parse error %v, output %q", got, want, err, output)
			}
		})
	}
}

func runProbeShell(t *testing.T, ctx context.Context, shell string, dialect LaunchDialect, payload string, env []string) (string, uint32) {
	t.Helper()
	// Git/MSYS/WSL executables add a Windows argv conversion layer. They are
	// not native Unix remote shells; Unix grammar runs on Unix, while Windows
	// client payload fidelity is covered over SSH without CreateProcess.
	if runtime.GOOS == "windows" && (dialect == LaunchPOSIX || dialect == LaunchFish) {
		t.Skip("native Unix shell semantics require a Unix host; SSH payload bytes are tested separately")
	}
	started := time.Now()
	t.Logf("native shell: path=%s dialect=%s", shell, dialect)
	defer func() { t.Logf("native shell elapsed=%s", time.Since(started)) }()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	args := []string{"-c", payload}
	switch dialect {
	case LaunchPowerShell:
		args = []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-Command", payload}
	case LaunchCmd:
		args = []string{"/d", "/s", "/c", payload}
	}
	command := exec.CommandContext(ctx, shell, args...)
	configureProbeShellCommand(command, shell, dialect, payload)
	command.WaitDelay = time.Second
	command.Env = env
	if dialect == LaunchPowerShell {
		baseEnv := env
		if baseEnv == nil {
			baseEnv = os.Environ()
		}
		command.Env = append(slices.Clone(baseEnv),
			"POWERSHELL_TELEMETRY_OPTOUT=1",
			"POWERSHELL_UPDATECHECK=Off",
		)
	}
	// An empty directory prevents incidental local executables from satisfying
	// where.exe lookups in the Windows PATH-isolation regression cases.
	command.Dir = t.TempDir()
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Errorf("native shell timed out: %v", ctx.Err())
		return string(output), 1
	}
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() >= 0 {
			return string(output), uint32(exit.ExitCode())
		}
		t.Errorf("run native shell: %v", err)
		return string(output), 1
	}
	return string(output), 0
}
