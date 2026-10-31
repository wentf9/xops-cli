//go:build !windows

package ssh

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestZshPrivilegeCommandsAndScripts(t *testing.T) {
	for _, mode := range []SudoMode{SudoModeRoot, SudoModeSudoer, SudoModeSudo, SudoModeSu, SudoModeAuto} {
		t.Run(string(mode), func(t *testing.T) {
			cfg := &ExecutionConfig{Interpreter: InterpreterZsh, LaunchDialect: LaunchPOSIX}
			client := nativeUnixPrivilegeClient(t, mode, cfg, "zsh")
			value := "quote' slash\\\\ $HOME ;\n中文"
			command := "typeset -a items; items=(first second); printf '%s:%s' ${items[2]} " + shellQuote(value) + "; exit 7"
			output, err := client.RunWithSudoExecution(t.Context(), command, cfg)
			var exit *cryptoSSH.ExitError
			if !errors.As(err, &exit) || exit.ExitStatus() != 7 || output != "second:"+value {
				t.Fatalf("zsh sudo output=%q error=%v", output, err)
			}
			script := "#!/usr/bin/env zsh\ntypeset -a items; items=(first second); print -rn -- ${items[2]}\n"
			output, err = client.RunScriptWithSudoExecution(t.Context(), script, cfg)
			if err != nil || output != "second" {
				t.Fatalf("zsh privileged script output=%q error=%v", output, err)
			}
		})
	}
}

func TestZshPrivilegeLoginAndInput(t *testing.T) {
	for _, mode := range []SudoMode{SudoModeSudoer, SudoModeSudo, SudoModeSu} {
		t.Run(string(mode), func(t *testing.T) {
			cfg := &ExecutionConfig{Interpreter: InterpreterZsh, LaunchDialect: LaunchPOSIX}
			client := nativeUnixPrivilegeClient(t, mode, cfg, "zsh")
			var output, diagnostic bytes.Buffer
			if err := client.RunCommandWithIO(t.Context(), "cat", true, strings.NewReader("user-input\n"), &output, &diagnostic); err != nil || output.String() != "user-input\n" || diagnostic.Len() != 0 {
				t.Fatalf("zsh privilege stdin leaked: output=%q diagnostic=%q error=%v", output.String(), diagnostic.String(), err)
			}
			for _, login := range []bool{false, true} {
				selected := cfg.Clone()
				selected.Login = &login
				output, err := client.RunWithSudoExecution(t.Context(), "if [[ -o login ]]; then printf login; else printf nonlogin; fi", selected)
				want := "nonlogin"
				if login {
					want = "login"
				}
				if err != nil || output != want {
					t.Fatalf("login=%v output=%q error=%v", login, output, err)
				}
				script := "if [[ -o login ]]; then printf login; else printf nonlogin; fi\n"
				scriptOut, err := client.RunScriptWithSudoExecution(t.Context(), script, selected)
				if err != nil || scriptOut != want {
					t.Fatalf("script login=%v output=%q error=%v", login, scriptOut, err)
				}
			}
		})
	}
}

func TestZshPrivilegeFromFishOuterShell(t *testing.T) {
	cfg := &ExecutionConfig{Interpreter: InterpreterZsh, LaunchDialect: LaunchFish}
	client := nativeUnixPrivilegeClient(t, SudoModeSudo, cfg)
	output, err := client.RunWithSudoExecution(t.Context(), "typeset -a items; items=(first second); print -rn -- ${items[2]}", cfg)
	if err != nil || output != "second" {
		t.Fatalf("zsh under fish privilege failed: %q, %v", output, err)
	}
}

func TestZshPrivilegeRejectsWrongPassword(t *testing.T) {
	cfg := &ExecutionConfig{Interpreter: InterpreterZsh, LaunchDialect: LaunchPOSIX}
	client := nativeUnixPrivilegeClient(t, SudoModeSu, cfg, "zsh")
	client.resolver = &compatSecretResolver{suPwd: "wrong"}
	output, err := client.RunWithSudoExecution(t.Context(), "print -r -- USER_COMMAND_RAN", cfg)
	if err == nil || strings.Contains(output, "USER_COMMAND_RAN") || strings.Contains(output, "wrong") {
		t.Fatalf("zsh authentication failed to protect user code: output=%q error=%v", output, err)
	}
}

func TestZshPrivilegePinsStepExecution(t *testing.T) {
	cfg := &ExecutionConfig{Interpreter: InterpreterZsh, LaunchDialect: LaunchPOSIX}
	client := nativeUnixPrivilegeClient(t, SudoModeSu, cfg, "zsh")
	client.cfgMu.Lock()
	client.connCfg.Execution = &ExecutionConfig{Interpreter: InterpreterBash, LaunchDialect: LaunchPOSIX}
	client.cfgMu.Unlock()
	output, err := client.RunWithSudoExecution(t.Context(), "typeset -a items; items=(first second); print -rn -- ${items[2]}", cfg)
	if err != nil || output != "second" {
		t.Fatalf("step zsh was replaced: output=%q error=%v", output, err)
	}
	if client.Execution().Interpreter != InterpreterBash {
		t.Fatal("step execution changed connection defaults")
	}
}
