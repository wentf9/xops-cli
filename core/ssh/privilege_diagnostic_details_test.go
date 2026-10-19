package ssh

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	corelog "github.com/wentf9/xops-cli/core/log"
	cryptossh "golang.org/x/crypto/ssh"
)

func TestPrivilegeDiagnosticCommandAndPrompt(t *testing.T) {
	for _, tc := range []struct {
		name                             string
		mode                             SudoMode
		interpreter                      Interpreter
		terminal                         bool
		sudoRSPrompt, invocation, prompt string
	}{
		{"sudo", SudoModeSudo, "", false, "", "sudo -S -p '<password-prompt>' -- bash -c '<privileged payload>'", "<password-prompt>"},
		{"sudo login", SudoModeSudo, "", true, "", "sudo -i -S -p '<password-prompt>' -- bash -c '<privileged payload>'", "<password-prompt>"},
		{"sudo-rs", SudoModeSudo, "", false, "Password:", "sudo -S -p '<password-prompt>' -- bash -c '<privileged payload>'", "[sudo: <password-prompt>] Password:"},
		{"su", SudoModeSu, "", false, "", "export LC_ALL=C; su - root -c ", "Password:"},
		{"fish sudo", SudoModeSudo, InterpreterFish, false, "", "sudo -S -p '<password-prompt>' -- /bin/sh -c '<privileged payload>'", "<password-prompt>"},
		{"zsh su", SudoModeSu, InterpreterZsh, false, "", "env LC_ALL=C su - root -s /bin/sh -c '<privileged payload>'", "Password:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setTestHome(t)
			const password = "credential-value-must-not-appear"
			address, evidence := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: tc.mode, password: password, sudoRSPrompt: tc.sudoRSPrompt})
			client := exchangeTestClient(t, address, tc.mode, &recoveryTestUI{values: []string{password}}, &testRecorder{})
			setPrivilegeTestExecution(client, tc.interpreter)
			recorder := &diagnosticRecorder{}
			client.diagnostics = recorder
			var terminal *privilegeTerminal
			if tc.terminal {
				terminal = &privilegeTerminal{width: 80, height: 40, activate: func(context.Context, *cryptossh.Session) (func() error, error) {
					return func() error { return nil }, nil
				}}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if err := client.runPrivilegeOperation(ctx, tc.mode, "private-user-command ' ; echo "+password+"; echo \"$SECRET\"", nil, io.Discard, io.Discard, terminal); err != nil {
				t.Fatal(err)
			}
			var command, prompt, pattern string
			for _, event := range recorder.snapshot() {
				switch event.Outcome {
				case "command_prepared":
					command = event.PrivilegeCommand
				case "password_prompt_matched":
					prompt = event.PrivilegePrompt
				case "password_prompt_pattern":
					pattern = event.PrivilegePromptPattern
				}
			}
			if !strings.HasPrefix(command, tc.invocation) || strings.TrimSpace(prompt) != tc.prompt || pattern == "" {
				t.Fatalf("missing invocation/prompt/pattern: %q %q %q", command, prompt, pattern)
			}
			if !strings.Contains(command, "<privileged payload>") || evidence.commands.Load() != 1 || evidence.attempts.Load() != 1 {
				t.Fatal("payload redaction or execution policy changed")
			}
			text := fmt.Sprint(recorder.snapshot())
			for _, secret := range []string{password, "private-user-command", "xops-password-", "xops-ready-", "xops-continue-", "xops-terminal-"} {
				if strings.Contains(text, secret) {
					t.Fatalf("diagnostics leaked %q", secret)
				}
			}
		})
	}
}

func TestPrivilegeDiagnosticPromptFragments(t *testing.T) {
	const marker = "[xops-password-private-nonce]"
	for _, prompt := range []string{marker, "[sudo: " + marker + "] Password:"} {
		for split := -1; split <= len(prompt); split++ {
			for _, probe := range []bool{false, true} {
				recorder := &diagnosticRecorder{}
				client := &Client{diagnostics: recorder}
				var output bytes.Buffer
				var writer io.Writer
				if probe {
					writer = &privilegePromptWriter{client: client, mode: SudoModeSudo, marker: []byte(marker), target: &output}
				} else {
					exchange := newPrivilegeExchange(client, SudoModeSudo, false)
					exchange.promptToken = marker
					writer = &privilegeFrameWriter{exchange: exchange, target: &output, prompt: regexp.MustCompile(regexp.QuoteMeta(marker))}
				}
				writeSudoPromptChunks(t, writer, prompt, split)
				var matches []string
				for _, event := range recorder.snapshot() {
					if event.Kind == corelog.PrivilegeLifecycle && event.Outcome == "password_prompt_matched" {
						matches = append(matches, event.PrivilegePrompt)
					}
				}
				expected := strings.ReplaceAll(prompt, marker, "<password-prompt>")
				if len(matches) != 1 || matches[0] != expected {
					t.Fatalf("probe=%v split=%d: matches=%q expected=%q", probe, split, matches, expected)
				}
			}
		}
	}
}

func TestPrivilegeDiagnosticCommandOutputStaysOpaque(t *testing.T) {
	recorder := &diagnosticRecorder{}
	client := &Client{diagnostics: recorder}
	exchange := newPrivilegeExchange(client, SudoModeSu, false)
	exchange.readyToken = "[ready]"
	writer := &privilegeFrameWriter{exchange: exchange, target: io.Discard, prompt: regexp.MustCompile(`Password:|private-output`)}
	if _, err := writer.Write([]byte("Password:[ready]private-output")); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprint(recorder.snapshot()), "private-output") {
		t.Fatal("post-ready user output entered prompt diagnostics")
	}
}

func TestPrivilegeDiagnosticPortablePasswordlessPreview(t *testing.T) {
	exchange := newPrivilegeExchange(nil, SudoModeSudoer, false, InterpreterFish)
	exchange.launchDialect = LaunchFish
	actual := exchange.command("private command ' with $secret")
	want := "sudo -n -S -p '<password-prompt>' -- /bin/sh -c '<privileged payload>'"
	if exchange.commandPreview != want || !strings.Contains(actual, exchange.promptToken) || strings.Contains(actual, "<privileged payload>") {
		t.Fatalf("preview replaced actual command or changed wrapper: %q %q", actual, exchange.commandPreview)
	}
}

func TestPrivilegeDiagnosticPortablePasswordlessOmitsPromptRules(t *testing.T) {
	for _, interpreter := range []Interpreter{InterpreterFish, InterpreterZsh} {
		t.Run(string(interpreter), func(t *testing.T) {
			setTestHome(t)
			address, evidence := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: SudoModeSudoer, noPrompt: true})
			ui := &recoveryTestUI{}
			client := exchangeTestClient(t, address, SudoModeSudoer, ui, &testRecorder{})
			setPrivilegeTestExecution(client, interpreter)
			recorder := &diagnosticRecorder{}
			client.diagnostics = recorder
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if _, err := client.RunWithSudo(ctx, "command"); err != nil {
				t.Fatal(err)
			}
			for _, phase := range []string{"command_prepared", "elevated_shell_ready", "operation_completed"} {
				requirePrivilegePhase(t, recorder, phase, true)
			}
			for _, phase := range []string{"password_prompt_pattern", "password_prompt_fallback_pattern", "password_prompt"} {
				requirePrivilegePhase(t, recorder, phase, false)
			}
			if ui.prompts != 0 || evidence.attempts.Load() != 0 || evidence.commands.Load() != 1 {
				t.Fatal("passwordless execution prompted or changed execution count")
			}
		})
	}
}

func TestPrivilegeDiagnosticPromptBounds(t *testing.T) {
	const marker = "[xops-password-secret-nonce]"
	text := strings.Repeat("x", 1000) + marker + strings.Repeat("y", 1000)
	got := privilegePromptText(text, marker)
	if len(got) > 1024 || strings.Contains(got, "xops-password-") || !strings.HasSuffix(got, "...") {
		t.Fatalf("unbounded or unredacted prompt: %q", got)
	}
	pattern := privilegePromptText(regexp.QuoteMeta(marker), marker)
	if pattern != "<password-prompt>" {
		t.Fatalf("pattern marker not redacted: %q", pattern)
	}
}
