//go:build !windows

package ssh

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
)

// These helpers parse and execute argv without changing user IDs. They exercise
// real outer/inner shells, prompts and stdin without requiring local privileges.
const fishTestSudo = `#!/bin/sh
prompt=''
noninteractive=false
while [ "$#" -gt 0 ]; do
 case "$1" in
 -S) shift ;;
 -n) noninteractive=true; shift ;;
 -p) prompt=$2; shift 2 ;;
 --) shift; break ;;
 -*) exit 93 ;;
 *) break ;;
 esac
done
if [ "$noninteractive" = false ]; then
 printf '%s' "$prompt" >&2
 IFS= read -r password || exit 94
 if [ "$password" != fixture-password ]; then printf 'Sorry, try again.\n' >&2; exit 1; fi
 unset password
fi
exec "$@"
`

const fishTestSu = `#!/bin/sh
[ "$1" = - ] && [ "$2" = root ] && [ "$3" = -s ] && [ "$4" = /bin/sh ] && [ "$5" = -c ] || exit 93
printf 'Password: ' >&2
IFS= read -r password || exit 94
if [ "$password" != fixture-password ]; then printf 'su: Authentication failure\n' >&2; exit 1; fi
unset password
exec /bin/sh -c "$6"
`

func nativeUnixPrivilegeClient(t *testing.T, mode SudoMode, execution *ExecutionConfig, outerShell ...string) *Client {
	t.Helper()
	shellName := "sh"
	if execution.LaunchDialect == LaunchFish {
		shellName = "fish"
	}
	if len(outerShell) > 0 {
		shellName = outerShell[0]
	}
	shell, err := exec.LookPath(shellName)
	if err != nil {
		t.Skipf("outer shell unavailable: %v", err)
	}
	if _, err := exec.LookPath(string(execution.Interpreter)); err != nil {
		t.Skipf("interpreter unavailable: %v", err)
	}
	directory := t.TempDir()
	for name, script := range map[string]string{"sudo": fishTestSudo, "su": fishTestSu} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if mode == SudoModeAuto {
		if err := os.WriteFile(filepath.Join(directory, "id"), []byte("#!/bin/sh\nprintf '1000\\n'\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	client, _ := executionProbeClient(t, "", func(ctx context.Context, payload string, channel cryptoSSH.Channel) {
		work, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		command := exec.CommandContext(work, shell, "-c", payload)
		command.WaitDelay = time.Second
		command.Env = append(os.Environ(), "PATH="+directory+string(os.PathListSeparator)+os.Getenv("PATH"), "HOME="+directory, "XDG_CONFIG_HOME="+directory, "ZDOTDIR="+directory)
		command.Stdin, command.Stdout, command.Stderr = channel, channel, channel.Stderr()
		status := uint32(0)
		if err := command.Run(); err != nil {
			var exit *exec.ExitError
			if errors.As(err, &exit) && exit.ExitCode() >= 0 {
				status = uint32(exit.ExitCode())
			} else {
				status = 1
			}
		}
		replyExecutionProbe(t, ctx, channel, "", status)
	})
	client.cfgMu.Lock()
	client.connCfg.Execution = execution.Clone()
	client.connCfg.SudoMode = mode
	client.cfgMu.Unlock()
	client.resolver = &compatSecretResolver{password: "fixture-password", suPwd: "fixture-password"}
	client.promptRegex = regexp.MustCompile(`Password:\s*`)
	return client
}

func TestFishPrivilegeCommands(t *testing.T) {
	for _, mode := range []SudoMode{SudoModeRoot, SudoModeSudoer, SudoModeSudo, SudoModeSu} {
		for _, dialect := range []LaunchDialect{LaunchPOSIX, LaunchFish} {
			for _, interpreter := range []Interpreter{InterpreterBash, InterpreterSh, InterpreterFish} {
				if dialect == LaunchPOSIX && interpreter != InterpreterFish {
					continue
				}
				t.Run(string(mode)+"/"+string(dialect)+"/"+string(interpreter), func(t *testing.T) {
					cfg := &ExecutionConfig{Interpreter: interpreter, LaunchDialect: dialect}
					client := nativeUnixPrivilegeClient(t, mode, cfg)
					quote := shellQuote
					if interpreter == InterpreterFish {
						quote = fishQuote
					}
					value := "quote' slash\\\\ $HOME (echo injected);\nnext line"
					output, err := client.RunWithSudoExecution(t.Context(), "printf '%s' "+quote(value)+"; exit 7", cfg)
					var exit *cryptoSSH.ExitError
					if !errors.As(err, &exit) || exit.ExitStatus() != 7 || output != value {
						t.Fatalf("output = %q, want %q, exit error = %v", output, value, err)
					}
				})
			}
		}
	}
}

func TestFishPrivilegeScripts(t *testing.T) {
	for _, mode := range []SudoMode{SudoModeRoot, SudoModeSudoer, SudoModeSudo, SudoModeSu} {
		t.Run(string(mode), func(t *testing.T) {
			cfg := &ExecutionConfig{Interpreter: InterpreterFish, LaunchDialect: LaunchFish}
			client := nativeUnixPrivilegeClient(t, mode, cfg)
			script := "#!/usr/bin/env fish\nset value 'script payload'; printf '%s' $value\n"
			output, err := client.RunScriptWithSudoExecution(t.Context(), script, cfg)
			if err != nil || output != "script payload" {
				t.Fatalf("script output = %q, error = %v", output, err)
			}
		})
	}
}

func TestFishPrivilegeInputAndAuthentication(t *testing.T) {
	for _, mode := range []SudoMode{SudoModeSudoer, SudoModeSudo, SudoModeSu} {
		t.Run(string(mode), func(t *testing.T) {
			cfg := &ExecutionConfig{Interpreter: InterpreterFish, LaunchDialect: LaunchFish}
			client := nativeUnixPrivilegeClient(t, mode, cfg)
			var out, diagnostic bytes.Buffer
			err := client.RunCommandWithIO(t.Context(), "cat", true, strings.NewReader("user-input\n"), &out, &diagnostic)
			if err != nil || out.String() != "user-input\n" || diagnostic.Len() != 0 {
				t.Fatalf("stdin separation: output=%q diagnostics=%q error=%v", out.String(), diagnostic.String(), err)
			}
		})
	}
	t.Run("wrong password never executes user code", func(t *testing.T) {
		cfg := &ExecutionConfig{Interpreter: InterpreterFish, LaunchDialect: LaunchFish}
		client := nativeUnixPrivilegeClient(t, SudoModeSu, cfg)
		client.resolver = &compatSecretResolver{suPwd: "wrong"}
		output, err := client.RunWithSudoExecution(t.Context(), "echo USER_COMMAND_RAN", cfg)
		if err == nil || strings.Contains(output, "USER_COMMAND_RAN") || strings.Contains(output, "wrong") {
			t.Fatalf("failed authentication ran user code or leaked input: %q, %v", output, err)
		}
	})
}

func TestFishPrivilegeFrozenExecution(t *testing.T) {
	cfg := &ExecutionConfig{Interpreter: InterpreterFish, LaunchDialect: LaunchFish}
	client := nativeUnixPrivilegeClient(t, SudoModeSu, cfg)
	client.cfgMu.Lock()
	client.connCfg.Execution = &ExecutionConfig{Interpreter: InterpreterBash, LaunchDialect: LaunchPOSIX}
	client.cfgMu.Unlock()
	output, err := client.RunWithSudoExecution(t.Context(), `printf '%s' 'frozen \\ value'`, cfg)
	if err != nil || output != `frozen \ value` {
		t.Fatalf("frozen execution lost: output=%q error=%v", output, err)
	}
	output, err = client.Run(t.Context(), `printf '%s' 'ordinary \\ value'`, WithInterpreter(InterpreterFish), WithLaunchDialect(LaunchFish), WithLoginShell(false))
	if err != nil || output != `ordinary \ value` {
		t.Fatalf("explicit outer dialect lost by ordinary Run: output=%q error=%v", output, err)
	}

}

func TestFishPrivilegeHandshakeRejectsInvalidAcknowledgement(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("sh unavailable: %v", err)
	}
	exchange := newPrivilegeExchange(nil, SudoModeSudo, false, InterpreterFish)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, sh, "-c", exchange.body("fish -c 'echo USER_COMMAND_RAN'"))
	command.WaitDelay = time.Second
	command.Stdin = strings.NewReader("wrong-ack\n")
	output, err := command.CombinedOutput()
	if err == nil || string(output) != exchange.readyToken {
		t.Fatalf("user code ran before acknowledgement: %q, %v", output, err)
	}
}

// Assert the native adapter never chooses a Bash-specific handshake for fish.
func TestFishPrivilegeControlShell(t *testing.T) {
	client := NewTestClient(ConnectionConfig{Execution: &ExecutionConfig{Interpreter: InterpreterFish, LaunchDialect: LaunchFish}})
	for _, mode := range []SudoMode{SudoModeSudoer, SudoModeSudo, SudoModeSu} {
		exchange := newPrivilegeExchange(client, mode, false, InterpreterFish)
		payload := exchange.command("fish -c 'echo ok'")
		if strings.Contains(payload, "sudo -i") || strings.Contains(payload, "export LC_ALL") {
			t.Fatalf("incompatible fish outer payload: %s", payload)
		}
		if !strings.Contains(payload, "/bin/sh") {
			t.Fatalf("missing explicit control shell: %s", payload)
		}
	}
	if _, err := client.RunWithSudoExecution(t.Context(), "must not run", &ExecutionConfig{Interpreter: InterpreterServer}); !errors.Is(err, ErrExecutionValidation) {
		t.Fatalf("server sudo unexpectedly accepted: %v", err)
	}
}

func TestFishPrivilegeAutoDetection(t *testing.T) {
	cfg := &ExecutionConfig{Interpreter: InterpreterFish, LaunchDialect: LaunchFish}
	client := nativeUnixPrivilegeClient(t, SudoModeAuto, cfg)
	client.resolver = nil
	output, err := client.RunWithSudoExecution(t.Context(), "echo auto-detected", cfg)
	if err != nil || output != "auto-detected\n" || client.ConnectionConfig().SudoMode != SudoModeSudoer {
		t.Fatalf("fish sudo auto detection failed: output=%q mode=%s error=%v", output, client.ConnectionConfig().SudoMode, err)
	}
}

func TestFishPrivilegeRejectsUnknownOuterShell(t *testing.T) {
	client := NewTestClient(ConnectionConfig{Execution: &ExecutionConfig{Interpreter: InterpreterFish}, SudoMode: SudoModeSudoer})
	if _, err := client.RunWithSudo(t.Context(), "must not run"); !errors.Is(err, ErrExecutionValidation) {
		t.Fatalf("unknown outer shell accepted by buffered sudo: %v", err)
	}
	if err := client.RunCommandWithIO(t.Context(), "must not run", true, nil, &bytes.Buffer{}, &bytes.Buffer{}); !errors.Is(err, ErrExecutionValidation) {
		t.Fatalf("unknown outer shell accepted by sudo with input: %v", err)
	}
}

func TestFishPrivilegeCancellationBeforeReadiness(t *testing.T) {
	setTestHome(t)
	addr, evidence := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: SudoModeSudo, password: "valid", blockExecReply: true})
	client := exchangeTestClient(t, addr, SudoModeSudo, &recoveryTestUI{values: []string{"valid"}}, &testRecorder{})
	cfg := &ExecutionConfig{Interpreter: InterpreterFish, LaunchDialect: LaunchFish}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	_, err := client.RunWithSudoExecution(ctx, "echo MUST_NOT_RUN", cfg)
	if !errors.Is(err, context.DeadlineExceeded) || evidence.commands.Load() != 0 {
		t.Fatalf("cancellation lost or user code ran: %v", err)
	}
}

func TestFishPrivilegeLoginMode(t *testing.T) {
	for _, mode := range []SudoMode{SudoModeSudo, SudoModeSu} {
		for _, login := range []bool{false, true} {
			name := string(mode) + "/nonlogin"
			want := "nonlogin"
			if login {
				name = string(mode) + "/login"
				want = "login"
			}
			t.Run(name, func(t *testing.T) {
				cfg := &ExecutionConfig{Interpreter: InterpreterFish, LaunchDialect: LaunchFish, Login: &login}
				client := nativeUnixPrivilegeClient(t, mode, cfg)
				output, err := client.RunWithSudoExecution(t.Context(), "if status is-login; printf login; else; printf nonlogin; end", cfg)
				if err != nil || output != want {
					t.Fatalf("login selection changed: output=%q want=%q error=%v", output, want, err)
				}
			})
		}
	}
}

func TestFishOuterServerPassthroughWithInput(t *testing.T) {
	client := NewTestClient(ConnectionConfig{Execution: &ExecutionConfig{Interpreter: InterpreterServer, LaunchDialect: LaunchFish}})
	interpreter, err := client.resolveCommandIOInterpreter(false, "echo native")
	if err != nil || interpreter != InterpreterServer {
		t.Fatalf("fish outer shell rejected server passthrough: %s, %v", interpreter, err)
	}
}
