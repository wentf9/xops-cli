package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
)

func TestSudoPromptFallbackExplicitConfiguration(t *testing.T) {
	for _, tc := range []struct{ node, global, want string }{
		{"", "", ""}, {"Password:", "Global:", "Password:"}, {"", "Global:", "Global:"},
		{"[", "Global:", ""}, {"", "[", ""}, {"a*", "Global:", ""}, {"(?m)^", "", ""},
	} {
		client := newClient(nil, nil, &ClientConfig{PasswordPromptPattern: tc.node}, nil, tc.global)
		got := ""
		if client.sudoPromptFallback != nil {
			got = client.sudoPromptFallback.String()
		}
		if got != tc.want {
			t.Fatalf("node=%q global=%q: fallback=%q want=%q", tc.node, tc.global, got, tc.want)
		}
		if client.passwordPromptRegex() == nil {
			t.Fatal("su default regex removed")
		}
	}
}

func TestSudoPromptFallbackPriorityAndGuards(t *testing.T) {
	const marker = "[xops-password-nonce]"
	for _, tc := range []struct {
		name, text, pattern string
		mode                SudoMode
		want                string
		fallback            bool
	}{
		{"configured prompt", "Password:", `Password:`, SudoModeSudo, "Password:", true},
		{"primary first", marker + "Password:", `Password:`, SudoModeSudo, marker, false},
		{"primary preferred over banner", "Password:" + marker, `Password:`, SudoModeSudo, marker, false},
		{"partial sudo-rs envelope", "[sudo: " + marker + "] Password", `Password`, SudoModeSudo, "", false},
		{"xtrace marker followed by real prompt", "+ sudo -p '" + marker + "' command\nPassword:", `Password:`, SudoModeSudo, "Password:", true},
		{"xtrace fallback", "+ echo 'Password:'", `Password:`, SudoModeSudo, "", false},
		{"zero width", "Password:", `\b`, SudoModeSudo, "", false},
		{"passwordless", "Password:", `Password:`, SudoModeSudoer, "", false},
		{"unmatched prompt", "OTP:", `Password:`, SudoModeSudo, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &Client{sudoPromptFallback: regexp.MustCompile(tc.pattern)}
			exchange := newPrivilegeExchange(client, tc.mode, false)
			exchange.promptToken = marker
			writer := &privilegeFrameWriter{exchange: exchange, prompt: regexp.MustCompile(regexp.QuoteMeta(marker)), pending: []byte(tc.text)}
			match := writer.promptIndex()
			got := ""
			if match != nil {
				got = tc.text[match[0]:match[1]]
			}
			if got != tc.want || writer.fallbackMatched != tc.fallback {
				t.Fatalf("match=%q fallback=%v", got, writer.fallbackMatched)
			}
		})
	}
}

func TestSudoPromptFallbackFragmentsAndReadyBoundary(t *testing.T) {
	const value = "Password:[ready]Password: private command output"
	for split := -1; split <= len(value); split++ {
		recorder := &diagnosticRecorder{}
		client := &Client{diagnostics: recorder, sudoPromptFallback: regexp.MustCompile(`Password:`)}
		exchange := newPrivilegeExchange(client, SudoModeSudo, false)
		exchange.readyToken = "[ready]"
		var output bytes.Buffer
		writer := &privilegeFrameWriter{exchange: exchange, target: &output, prompt: regexp.MustCompile(regexp.QuoteMeta(exchange.promptToken))}
		writeSudoPromptChunks(t, writer, value, split)
		if err := writer.flush(); err != nil {
			t.Fatal(err)
		}
		// If ready is already buffered, it wins over a generic fallback challenge.
		if len(exchange.prompts) > 1 || !exchange.started() || !strings.HasSuffix(output.String(), "Password: private command output") {
			t.Fatalf("split=%d prompts=%d output=%q", split, len(exchange.prompts), output.String())
		}
		matches := 0
		for _, e := range recorder.snapshot() {
			if e.Outcome == "password_prompt_matched" {
				matches++
			}
		}
		if matches != len(exchange.prompts) {
			t.Fatal("post-ready output was diagnosed as a prompt")
		}
	}
}

func TestSudoPromptFallbackNeverMatchesPartialMarker(t *testing.T) {
	for _, rs := range []bool{false, true} {
		client := &Client{sudoPromptFallback: regexp.MustCompile(`(?i)password`)}
		recorder := &diagnosticRecorder{}
		client.diagnostics = recorder
		exchange := newPrivilegeExchange(client, SudoModeSudo, false)
		prompt := exchange.promptToken
		if rs {
			prompt = "[sudo: " + prompt + "] Password:"
		}
		writer := &privilegeFrameWriter{exchange: exchange, target: io.Discard, prompt: regexp.MustCompile(regexp.QuoteMeta(exchange.promptToken))}
		writeSudoPromptChunks(t, writer, prompt, -1)
		requirePrivilegePhase(t, recorder, "password_prompt_fallback", false)
		if len(exchange.prompts) != 1 {
			t.Fatalf("fragmented marker generated %d challenges", len(exchange.prompts))
		}
	}
}

func TestSudoPromptFallbackIgnoredP(t *testing.T) {
	for _, interpreter := range []Interpreter{"", InterpreterFish, InterpreterSh} {
		t.Run(string(interpreter), func(t *testing.T) {
			setTestHome(t)
			const password = "private-valid-password"
			address, evidence := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: SudoModeSudo, password: password, ignoredPrompt: "Password: ", status: 7})
			recorder := &diagnosticRecorder{}
			ui := &recoveryTestUI{values: []string{"private-wrong-password", password}}
			client := exchangeTestClient(t, address, SudoModeSudo, ui, &testRecorder{}, `(?m)^Password:[ \t]*$`)
			setPrivilegeTestExecution(client, interpreter)
			client.diagnostics = recorder
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			var terminal *privilegeTerminal
			if interpreter == InterpreterSh {
				terminal = &privilegeTerminal{width: 80, height: 40, activate: func(context.Context, *cryptossh.Session) (func() error, error) {
					return func() error { return nil }, nil
				}}
			}
			err := client.runPrivilegeOperation(ctx, SudoModeSudo, "private-user-command", strings.NewReader("only-user-input"), io.Discard, io.Discard, terminal)
			var exit *cryptossh.ExitError
			if !errors.As(err, &exit) || exit.ExitStatus() != 7 {
				t.Fatalf("user exit lost: %v", err)
			}
			if evidence.commands.Load() != 1 || evidence.attempts.Load() != 2 || <-evidence.input != "only-user-input" {
				t.Fatal("retry replayed command or changed stdin")
			}
			requirePrivilegePhase(t, recorder, "password_prompt_fallback", true)
			requirePrivilegePhase(t, recorder, "password_prompt_fallback_pattern", true)
			requirePrivilegePhase(t, recorder, "elevated_shell_ready", true)
			for _, secret := range []string{password, "private-wrong-password", "private-user-command"} {
				if strings.Contains(fmt.Sprint(recorder.snapshot()), secret) {
					t.Fatal("fallback leaked credential or user command")
				}
			}
		})
	}
}

func TestSudoPromptFallbackKeepsMarkerProtocol(t *testing.T) {
	for _, rs := range []string{"", "Password:"} {
		t.Run(rs, func(t *testing.T) {
			setTestHome(t)
			address, evidence := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: SudoModeSudo, password: "valid", sudoRSPrompt: rs})
			client := exchangeTestClient(t, address, SudoModeSudo, &recoveryTestUI{values: []string{"valid"}}, &testRecorder{}, `Password:`)
			recorder := &diagnosticRecorder{}
			client.diagnostics = recorder
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if err := client.runPrivilegeOperation(ctx, SudoModeSudo, "command", nil, io.Discard, io.Discard); err != nil {
				t.Fatal(err)
			}
			requirePrivilegePhase(t, recorder, "password_prompt_fallback", false)
			if evidence.commands.Load() != 1 || evidence.attempts.Load() != 1 {
				t.Fatal("fallback duplicated a marker prompt")
			}
		})
	}
}

func TestSudoPromptFallbackWithoutOptInDoesNotSendPassword(t *testing.T) {
	setTestHome(t)
	address, evidence := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: SudoModeSudo, password: "valid", ignoredPrompt: "Password:"})
	ui := &recoveryTestUI{values: []string{"must-not-be-read"}}
	client := exchangeTestClient(t, address, SudoModeSudo, ui, &testRecorder{})
	recorder := &diagnosticRecorder{}
	client.diagnostics = recorder
	input := bytes.NewReader([]byte("untouched"))
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	err := client.runPrivilegeOperation(ctx, SudoModeSudo, "never-start", input, io.Discard, io.Discard)
	if !errors.Is(err, context.DeadlineExceeded) || evidence.attempts.Load() != 0 || evidence.commands.Load() != 0 || ui.prompts != 0 || input.Len() != len("untouched") {
		t.Fatalf("implicit fallback used credentials/input: %v", err)
	}
	requirePrivilegePhase(t, recorder, "password_prompt_fallback", false)
}

func TestSudoPromptFallbackRejectedDoesNotConsumeInput(t *testing.T) {
	setTestHome(t)
	address, evidence := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: SudoModeSudo, password: "valid", ignoredPrompt: "Password:"})
	ui := &recoveryTestUI{values: []string{"wrong1", "wrong2", "wrong3"}}
	client := exchangeTestClient(t, address, SudoModeSudo, ui, &testRecorder{}, `Password:`)
	input := bytes.NewReader([]byte("untouched"))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	err := client.runPrivilegeOperation(ctx, SudoModeSudo, "never-start", input, io.Discard, io.Discard)
	if err == nil || evidence.attempts.Load() != 3 || evidence.commands.Load() != 0 || input.Len() != len("untouched") {
		t.Fatalf("rejection boundary changed: %v", err)
	}
}

func TestSudoPromptFallbackCancelDuringPrompt(t *testing.T) {
	setTestHome(t)
	address, evidence := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: SudoModeSudo, password: "valid", ignoredPrompt: "Password:"})
	ui := &blockingPrivilegeUI{entered: make(chan struct{})}
	client := exchangeTestClient(t, address, SudoModeSudo, ui, &testRecorder{}, `Password:`)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	input := bytes.NewReader([]byte("untouched"))
	done := make(chan error, 1)
	go func() {
		done <- client.runPrivilegeOperation(ctx, SudoModeSudo, "never-start", input, io.Discard, io.Discard)
	}()
	select {
	case <-ui.entered:
	case <-ctx.Done():
		<-done
		t.Fatal("fallback prompt not reached")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	if evidence.attempts.Load() != 0 || evidence.commands.Load() != 0 || input.Len() != len("untouched") {
		t.Fatal("cancel sent credentials or consumed user input")
	}
}
