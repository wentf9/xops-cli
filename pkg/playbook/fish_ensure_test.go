package playbook

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/pkg/models"
	cryptoSSH "golang.org/x/crypto/ssh"
)

// Run probes and user programs in actual fish; the sudo helper only forwards
// argv and never changes process credentials. Shared privilege tests cover PAM
// prompts and authentication independently of the ensure result protocol.
func nativeFishEnsureClient(t *testing.T, directory string, mode ssh.SudoMode) (*ssh.Client, *sshfixture.Server) {
	t.Helper()
	fish, err := exec.LookPath("fish")
	if err != nil {
		t.Skipf("fish unavailable: %v", err)
	}
	sudo := `#!/bin/sh
[ "$1" = -n ] && [ "$2" = -S ] && [ "$3" = -p ] && [ "$5" = -- ] || exit 93
shift 5
exec "$@"
`
	if err := os.WriteFile(filepath.Join(directory, "sudo"), []byte(sudo), 0700); err != nil {
		t.Fatal(err)
	}
	// A second exit handler must not change the check status captured by ours.
	if err := os.MkdirAll(filepath.Join(directory, "fish"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "fish", "config.fish"), []byte("function another_exit --on-event fish_exit\n true\nend\n"), 0600); err != nil {
		t.Fatal(err)
	}
	client, server := executionTestClient(t, func(payload string, channel cryptoSSH.Channel) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, fish, "-c", payload)
		command.WaitDelay = time.Second
		command.Env = append(os.Environ(), "HOME="+directory, "XDG_CONFIG_HOME="+directory, "SHELL="+fish,
			"PATH="+directory+string(os.PathListSeparator)+os.Getenv("PATH"), "XOPS_TEST_ENSURE_FILE="+filepath.Join(directory, "repaired"))
		if strings.HasPrefix(payload, "sudo ") {
			command.Stdin = channel
		}
		command.Stdout, command.Stderr = channel, channel.Stderr()
		status := uint32(0)
		if err := command.Run(); err != nil {
			var exit *exec.ExitError
			if errors.As(err, &exit) && exit.ExitCode() >= 0 {
				status = uint32(exit.ExitCode())
			} else {
				t.Errorf("run native fish ensure fixture: %v", err)
				status = 1
			}
		}
		writeLazyResult(t, channel, "", status)
	}, mode)
	return client, server
}

func TestFishEnsureDefaultProbeCheckActionAndVerify(t *testing.T) {
	for _, sudo := range []bool{false, true} {
		name, mode := "ordinary", ssh.SudoModeRoot
		if sudo {
			name, mode = "sudo", ssh.SudoModeSudoer
		}
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			client, server := nativeFishEnsureClient(t, directory, mode)
			engine := &Engine{}
			spec := &EnsureSpec{Check: `set -l required "$XOPS_TEST_ENSURE_FILE"; test -f "$required"`,
				Action: `set -l values first second; printf '%s' $values[2] > "$XOPS_TEST_ENSURE_FILE"`}
			result := engine.runEnsure(t.Context(), client, spec, nil, sudo, models.Node{})
			if result.Status != StatusChanged {
				t.Fatalf("default fish ensure failed: %+v", result)
			}
			data, err := os.ReadFile(filepath.Join(directory, "repaired"))
			if err != nil || string(data) != "second" {
				t.Fatalf("fish action semantics changed: %q, %v", data, err)
			}
			probe, cached := client.CachedExecutionProbe()
			if !cached || probe.RecommendedInterpreter != ssh.InterpreterFish || !slices.Contains(probe.AvailableInterpreters, ssh.InterpreterBash) || !slices.Contains(probe.AvailableInterpreters, ssh.InterpreterSh) {
				t.Fatalf("ensure replaced default fish or did not exercise bash/sh availability: %+v", probe)
			}
			requests := server.Executed.Load()
			result = engine.runEnsure(t.Context(), client, spec, nil, sudo, models.Node{})
			if result.Status != StatusSkipped || server.Executed.Load() != requests+1 || client.Execution() != nil {
				t.Fatalf("ensure repeated action/probe or changed connection defaults: %+v", result)
			}
		})
	}
}

func TestFishEnsureCheckExitProtocol(t *testing.T) {
	for _, tt := range []struct {
		name, check string
		want        StepStatus
		action      bool
	}{
		{"true", "true", StatusSkipped, false},
		{"explicit exit zero", "exit 0", StatusSkipped, false},
		{"exit zero after false", "false; exit 0", StatusSkipped, false},
		{"false", "false", StatusFailed, true},
		{"explicit exit seven", "true; exit 7", StatusFailed, true},
		{"command not found", "xops_missing_ensure_command", StatusFailed, false},
		{"wildcard expansion failed", `test -f "$XOPS_TEST_ENSURE_FILE"/*`, StatusFailed, false},
		{"not executable", `command "$HOME"`, StatusFailed, false},
		{"reserved invalid arguments", "exit 121", StatusFailed, false},
		{"reserved invalid command name", "exit 123", StatusFailed, false},
		{"reserved expansion failure", "exit 124", StatusFailed, false},
		{"reserved OS execution failure", "exit 125", StatusFailed, false},
		{"reserved non-executable", "exit 126", StatusFailed, false},
		{"non-reserved application status", "exit 122", StatusFailed, true},
		{"explicit exit 127", "exit 127", StatusFailed, false},
		{"parse failure", "if", StatusFailed, false},
		{"exec bypasses exit handler", "exec false", StatusFailed, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			directory := t.TempDir()
			client, _ := nativeFishEnsureClient(t, directory, ssh.SudoModeRoot)
			engine := &Engine{}
			execution := &ssh.ExecutionConfig{Interpreter: ssh.InterpreterFish, LaunchDialect: ssh.LaunchFish}
			result := engine.runEnsure(t.Context(), client, &EnsureSpec{Check: tt.check, Action: `printf action > "$XOPS_TEST_ENSURE_FILE"`}, execution, false, models.Node{})
			if result.Status != tt.want {
				t.Fatalf("status=%s want=%s result=%+v", result.Status, tt.want, result)
			}
			data, err := os.ReadFile(filepath.Join(directory, "repaired"))
			if tt.action {
				if err != nil || string(data) != "action" {
					t.Fatalf("confirmed false check did not run action: %q, %v", data, err)
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("action ran without a confirmed false check: %q, %v", data, err)
			}
			if strings.Contains(result.Output, "__XOPS_ENSURE_") {
				t.Fatalf("internal result frame leaked: %+v", result)
			}
		})
	}
}

func TestFishEnsureExecutionErrorsNeverRunElevatedAction(t *testing.T) {
	for _, check := range []string{`test -f "$XOPS_TEST_ENSURE_FILE"/*`, `command "$HOME"`} {
		t.Run(check, func(t *testing.T) {
			directory := t.TempDir()
			client, _ := nativeFishEnsureClient(t, directory, ssh.SudoModeSudoer)
			engine := &Engine{}
			cfg := &ssh.ExecutionConfig{Interpreter: ssh.InterpreterFish, LaunchDialect: ssh.LaunchFish}
			result := engine.runEnsure(t.Context(), client, &EnsureSpec{Check: check, Action: `printf ACTION_RAN > "$XOPS_TEST_ENSURE_FILE"`}, cfg, true, models.Node{})
			if result.Status != StatusFailed || result.Err == nil || !strings.Contains(result.Err.Error(), "action not executed") {
				t.Fatalf("execution failure did not stop ensure: %+v", result)
			}
			if data, err := os.ReadFile(filepath.Join(directory, "repaired")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("elevated action ran after execution failure: %q, %v", data, err)
			}
		})
	}
}
