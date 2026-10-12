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

func TestZshCommandPlanAndQuoting(t *testing.T) {
	for _, dialect := range []LaunchDialect{LaunchPOSIX, LaunchFish} {
		t.Run(string(dialect), func(t *testing.T) {
			shellName := "zsh"
			if dialect == LaunchFish {
				shellName = "fish"
			}
			shell, err := exec.LookPath(shellName)
			if err != nil {
				t.Skipf("outer shell unavailable: %v", err)
			}
			if _, err := exec.LookPath("zsh"); err != nil {
				t.Skipf("zsh unavailable: %v", err)
			}
			value := "quote' slash\\\\ $HOME (echo injected); & |\n中文"
			command := "typeset -a items; items=(first second); printf '%s:%s' ${items[2]} " + shellQuote(value)
			plan, err := PlanCommand(command, CommandOptions{Interpreter: InterpreterZsh, LaunchDialect: dialect})
			if err != nil {
				t.Fatal(err)
			}
			env := append(os.Environ(), "HOME="+t.TempDir(), "ZDOTDIR="+t.TempDir())
			output, status := runProbeShell(t, t.Context(), shell, dialect, plan.Payload(), env)
			if status != 0 || output != "second:"+value {
				t.Fatalf("zsh semantics or quoting lost: status=%d output=%q", status, output)
			}
		})
	}
}

func TestZshConfigurationAndLogin(t *testing.T) {
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skipf("zsh unavailable: %v", err)
	}
	for _, login := range []bool{false, true} {
		cfg := &ExecutionConfig{Interpreter: InterpreterZsh, LaunchDialect: LaunchPOSIX, Login: &login}
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		plan, err := PlanCommand("if [[ -o login ]]; then printf login; else printf nonlogin; fi", cfg.CommandOptions())
		if err != nil {
			t.Fatal(err)
		}
		output, status := runProbeShell(t, t.Context(), zsh, LaunchPOSIX, plan.Payload(), append(os.Environ(), "ZDOTDIR="+t.TempDir()))
		want := "nonlogin"
		if login {
			want = "login"
		}
		if status != 0 || output != want {
			t.Fatalf("login=%v: status=%d output=%q", login, status, output)
		}
		options, err := cfg.SudoRunOptions("id")
		if err != nil {
			t.Fatal(err)
		}
		run := DefaultRunConfig()
		for _, option := range options {
			option(run)
		}
		if run.Interpreter != InterpreterZsh || run.LoginShell != login || run.LaunchDialect != LaunchPOSIX {
			t.Fatalf("sudo execution lost: %+v", run)
		}
	}
	for _, dialect := range []LaunchDialect{LaunchCmd, LaunchPowerShell, LaunchUnknown} {
		cfg := &ExecutionConfig{Interpreter: InterpreterZsh, LaunchDialect: dialect}
		if !errors.Is(cfg.Validate(), ErrExecutionValidation) {
			t.Fatalf("invalid dialect accepted: %s", dialect)
		}
		if _, err := PlanCommand("echo ok", cfg.CommandOptions()); err == nil {
			t.Fatalf("invalid command plan accepted: %s", dialect)
		}
	}
}

func TestZshWorkingDirectory(t *testing.T) {
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skipf("zsh unavailable: %v", err)
	}
	cwd := filepath.Join(t.TempDir(), "quote' slash\\\\ $HOME")
	if err := os.Mkdir(cwd, 0700); err != nil {
		t.Fatal(err)
	}
	command, err := FormatWorkingDirCommand(cwd, "pwd", &ExecutionConfig{Interpreter: InterpreterZsh, LaunchDialect: LaunchPOSIX})
	if err != nil {
		t.Fatal(err)
	}
	output, status := runProbeShell(t, t.Context(), zsh, LaunchPOSIX, command, append(os.Environ(), "ZDOTDIR="+t.TempDir()))
	if status != 0 || strings.TrimSpace(output) != cwd {
		t.Fatalf("cwd changed: status=%d output=%q", status, output)
	}
}

func TestZshShebangAndScript(t *testing.T) {
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skipf("zsh unavailable: %v", err)
	}
	for _, shebang := range []string{"zsh", "/bin/zsh", "/usr/bin/zsh", "/usr/bin/env zsh"} {
		info := ParseShebang([]byte("#!" + shebang + "\n"))
		if !info.Supported || info.Interpreter != InterpreterZsh {
			t.Fatalf("zsh shebang rejected: %+v", info)
		}
	}
	script := "#!/usr/bin/env zsh\ntypeset -a items; items=(first second); print -rn -- ${items[2]}\n"
	cfg, err := ResolveScriptExecution(nil, nil, &ExecutionConfig{LaunchDialect: LaunchPOSIX}, nil, []byte(script))
	if err != nil {
		t.Fatal(err)
	}
	client, _ := executionProbeClient(t, "", func(ctx context.Context, payload string, channel cryptoSSH.Channel) {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, zsh, "-c", payload)
		command.WaitDelay = time.Second
		command.Env = append(os.Environ(), "ZDOTDIR="+t.TempDir())
		command.Stdin = channel
		output, err := command.CombinedOutput()
		status := uint32(0)
		if err != nil {
			t.Errorf("run zsh script: %v", err)
			status = 1
		}
		replyExecutionProbe(t, ctx, channel, string(output), status)
	})
	output, err := client.RunScriptWithExecution(t.Context(), script, cfg)
	if err != nil || output != "second" {
		t.Fatalf("zsh script output=%q error=%v", output, err)
	}
	if _, err := ResolveScriptExecution(nil, nil, nil, nil, []byte(script)); !errors.Is(err, ErrExecutionValidation) {
		t.Fatalf("shebang established an unknown outer dialect: %v", err)
	}
}
