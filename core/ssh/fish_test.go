package ssh

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestFishCommandPayloads(t *testing.T) {
	for _, dialect := range []LaunchDialect{LaunchPOSIX, LaunchFish} {
		for _, interpreter := range []Interpreter{InterpreterBash, InterpreterSh, InterpreterFish} {
			t.Run(string(dialect)+"/"+string(interpreter), func(t *testing.T) {
				shellName := "sh"
				if dialect == LaunchFish {
					shellName = "fish"
				}
				shell, err := exec.LookPath(shellName)
				if err != nil {
					t.Skipf("outer shell unavailable: %v", err)
				}
				if _, err := exec.LookPath(string(interpreter)); err != nil {
					t.Skipf("interpreter unavailable: %v", err)
				}
				// Verify bytes survive both parsing layers, including adjacent backslashes,
				// quotes, substitutions, newlines and metacharacters.
				value := "quote' and \\\\ and \\' $HOME (echo injected); & |\nnext line"
				quote := shellQuote
				if interpreter == InterpreterFish {
					quote = fishQuote
				}
				command := "printf '%s' " + quote(value)
				plan, err := PlanCommand(command, CommandOptions{Interpreter: interpreter, LaunchDialect: dialect})
				if err != nil {
					t.Fatal(err)
				}
				output, status := runProbeShell(t, t.Context(), shell, dialect, plan.Payload(), nil)
				if status != 0 || output != value {
					t.Fatalf("status = %d, output = %q, want %q", status, output, value)
				}
				exitPlan, err := PlanCommand("exit 23", CommandOptions{Interpreter: interpreter, LaunchDialect: dialect})
				if err != nil {
					t.Fatal(err)
				}
				_, status = runProbeShell(t, t.Context(), shell, dialect, exitPlan.Payload(), nil)
				if status != 23 {
					t.Fatalf("exit status = %d, want 23", status)
				}
			})
		}
	}
}

func TestFishConfigurationAndLogin(t *testing.T) {
	for _, dialect := range []LaunchDialect{LaunchPOSIX, LaunchFish} {
		for _, login := range []bool{false, true} {
			cfg := &ExecutionConfig{Interpreter: InterpreterFish, LaunchDialect: dialect, Login: &login}
			if err := cfg.Validate(); err != nil {
				t.Fatal(err)
			}
			plan, err := PlanCommand("echo ok", cfg.CommandOptions())
			if err != nil {
				t.Fatal(err)
			}
			want := "fish -c 'echo ok'"
			if login {
				want = "fish -l -c 'echo ok'"
			}
			if plan.Payload() != want || (plan.LoginMode() == LoginEnabled) != login {
				t.Fatalf("unexpected plan: %+v", plan)
			}
		}
	}
	for _, dialect := range []LaunchDialect{LaunchUnknown, LaunchCmd, LaunchPowerShell} {
		cfg := &ExecutionConfig{Interpreter: InterpreterFish, LaunchDialect: dialect}
		if !errors.Is(cfg.Validate(), ErrExecutionValidation) {
			t.Fatalf("invalid fish dialect accepted: %s", dialect)
		}
		if _, err := PlanCommand("echo ok", cfg.CommandOptions()); err == nil {
			t.Fatalf("invalid fish plan accepted: %s", dialect)
		}
	}
	cfg := &ExecutionConfig{Interpreter: InterpreterBash, LaunchDialect: LaunchFish}
	if _, err := cfg.SudoRunOptions("id"); err != nil {
		t.Fatalf("fish launch dialect rejected for sudo: %v", err)
	}
}

func TestFishWorkingDirectory(t *testing.T) {
	fish, err := exec.LookPath("fish")
	if err != nil {
		t.Skipf("fish unavailable: %v", err)
	}
	cwd := filepath.Join(t.TempDir(), "quote' slash\\\\ $HOME (echo injected)")
	if err := os.Mkdir(cwd, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := &ExecutionConfig{Interpreter: InterpreterFish, LaunchDialect: LaunchFish}
	command, err := FormatWorkingDirCommand(cwd, "pwd", cfg)
	if err != nil {
		t.Fatal(err)
	}
	output, status := runProbeShell(t, t.Context(), fish, LaunchFish, command, nil)
	if status != 0 || strings.TrimSpace(output) != cwd {
		t.Fatalf("cwd status = %d, output = %q, want %q", status, output, cwd)
	}
	command, err = FormatWorkingDirCommand(filepath.Join(cwd, "missing"), "echo USER_COMMAND_RAN", cfg)
	if err != nil {
		t.Fatal(err)
	}
	output, status = runProbeShell(t, t.Context(), fish, LaunchFish, command, nil)
	if status == 0 || strings.Contains(output, "USER_COMMAND_RAN") {
		t.Fatalf("command ran after cd failed: status %d, output %q", status, output)
	}
}

func TestFishScriptExecution(t *testing.T) {
	fish, err := exec.LookPath("fish")
	if err != nil {
		t.Skipf("fish unavailable: %v", err)
	}
	script := "#!/usr/bin/env fish\nset value 'fish script'; printf '%s' $value\n"
	shebang := ParseShebang([]byte(script))
	if !shebang.Supported || shebang.Interpreter != InterpreterFish {
		t.Fatalf("unsupported fish shebang: %+v", shebang)
	}
	cfg, err := ResolveScriptExecution(nil, nil, &ExecutionConfig{LaunchDialect: LaunchFish}, nil, []byte(script))
	if err != nil {
		t.Fatal(err)
	}
	client, _ := executionProbeClient(t, "", func(ctx context.Context, payload string, channel cryptoSSH.Channel) {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, fish, "-c", payload)
		command.WaitDelay = time.Second
		command.Stdin = channel
		output, err := command.CombinedOutput()
		status := uint32(0)
		if err != nil {
			t.Errorf("run fish script: %v", err)
			status = 1
		}
		replyExecutionProbe(t, ctx, channel, string(output), status)
	})
	output, err := client.RunScriptWithExecution(t.Context(), script, cfg)
	if err != nil || output != "fish script" {
		t.Fatalf("script output = %q, error = %v", output, err)
	}
}

func TestFishLegacyRunUsesOuterDialect(t *testing.T) {
	fish, err := exec.LookPath("fish")
	if err != nil {
		t.Skipf("fish unavailable: %v", err)
	}
	for _, interpreter := range []Interpreter{InterpreterBash, InterpreterSh, InterpreterFish} {
		t.Run(string(interpreter), func(t *testing.T) {
			if _, err := exec.LookPath(string(interpreter)); err != nil {
				t.Skipf("interpreter unavailable: %v", err)
			}
			client, _ := executionProbeClient(t, "", func(ctx context.Context, payload string, channel cryptoSSH.Channel) {
				output, status := runProbeShell(t, ctx, fish, LaunchFish, payload, nil)
				replyExecutionProbe(t, ctx, channel, output, status)
			})
			client.cfgMu.Lock()
			client.connCfg.Execution = &ExecutionConfig{Interpreter: interpreter, LaunchDialect: LaunchFish}
			client.cfgMu.Unlock()
			value := `two backslashes: \\ and quote: '`
			quote := shellQuote
			if interpreter == InterpreterFish {
				quote = fishQuote
			}
			output, err := client.Run(t.Context(), "printf '%s' "+quote(value))
			if err != nil || output != value {
				t.Fatalf("Run output = %q, want %q, error = %v", output, value, err)
			}
		})
	}
}

func TestFishProbeRejectsMalformedFrames(t *testing.T) {
	for _, frame := range []string{
		"__XOPS_DIALECT_FISH__:4.0.0\n",
		"__XOPS_DIALECT_FISH__:x.y\n__XOPS_FISH_OS__:Linux\n__XOPS_FISH_SHELL__:/usr/bin/fish\n",
		"__XOPS_DIALECT_FISH__:4.0.0\n__XOPS_FISH_OS__:Linux\n__XOPS_FISH_SHELL__:$SHELL\n",
		"__XOPS_DIALECT_FISH__:4.0.0\n__XOPS_FISH_OS__:Linux\n__XOPS_FISH_SHELL__:/usr/bin/fish\n__XOPS_FISH_OS__:Darwin\n",
	} {
		if dialect, _, _ := parseProbeDialect(frame, probeFish); dialect != LaunchUnknown {
			t.Fatalf("accepted malformed fish frame: %q", frame)
		}
	}
}

func TestFishWorkingDirectoryGuardsWholeProgram(t *testing.T) {
	fish, err := exec.LookPath("fish")
	if err != nil {
		t.Skipf("fish unavailable: %v", err)
	}
	cfg := &ExecutionConfig{Interpreter: InterpreterFish, LaunchDialect: LaunchFish}
	cwd := t.TempDir()
	for _, program := range []string{"printf FIRST; printf SECOND", "printf FIRST\nprintf SECOND", "printf FIRST; printf SECOND # trailing comment", "begin; printf FIRST; end; printf SECOND"} {
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
			output, status := runProbeShell(t, t.Context(), fish, LaunchFish, plan.Payload(), nil)
			if exists {
				if status != 0 || output != "FIRSTSECOND" {
					t.Fatalf("compound program changed: status=%d output=%q", status, output)
				}
			} else if status == 0 || strings.Contains(output, "FIRST") || strings.Contains(output, "SECOND") {
				t.Fatalf("program ran after cd failure: status=%d output=%q", status, output)
			}
		}
	}
	command, err := FormatWorkingDirCommand(cwd, "printf FIRST; exit 7", cfg)
	if err != nil {
		t.Fatal(err)
	}
	output, status := runProbeShell(t, t.Context(), fish, LaunchFish, command, nil)
	if status != 7 || output != "FIRST" {
		t.Fatalf("user exit status changed: status=%d output=%q", status, output)
	}
}
