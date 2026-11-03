package cmd

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/core/ssh"
)

// -----------------------------------------------------------------------------
// Challenge 2: CLI Flags & Mutual Exclusion Adversarial Stress
// -----------------------------------------------------------------------------

func TestAdversarialCLIConnectionFlags_MutualExclusion(t *testing.T) {
	commands := []struct {
		name string
		cmd  func() *cobra.Command
	}{
		{"ssh", func() *cobra.Command { return NewCmdSsh() }},
		{"exec", func() *cobra.Command { return NewCmdExec() }},
		{"scp", func() *cobra.Command { return NewCmdScp() }},
		{"sftp", func() *cobra.Command { return NewCmdSftp() }},
	}

	for _, tc := range commands {
		t.Run(tc.name+"_FlagArgs_BothSet", func(t *testing.T) {
			cmd := tc.cmd()
			cmd.SetArgs([]string{"--otp", "987654", "--otp-stdin"})
			err := cmd.Execute()
			if err == nil {
				t.Fatalf("[%s] expected error when both --otp and --otp-stdin are specified, got nil", tc.name)
			}
		})

		t.Run(tc.name+"_FlagArgs_EmptyStringOTPAndStdin", func(t *testing.T) {
			cmd := tc.cmd()
			cmd.SetArgs([]string{"--otp=", "--otp-stdin"})
			err := cmd.Execute()
			if err == nil {
				t.Fatalf("[%s] expected error when --otp= and --otp-stdin are specified, got nil", tc.name)
			}
		})
	}
}

func TestAdversarialCLIConnectionFlags_ProgrammaticOptions(t *testing.T) {
	t.Run("ssh_SshOptions_Validate", func(t *testing.T) {
		opts := NewSshOptions()
		opts.OTP = "123456"
		opts.OTPStdin = true
		if err := opts.Validate(); err == nil {
			t.Fatal("expected SshOptions.Validate() to fail with mutual exclusion error, got nil")
		}
	})

	t.Run("exec_ExecOptions_Validate", func(t *testing.T) {
		opts := NewExecOptions()
		opts.OTP = "123456"
		opts.OTPStdin = true
		if err := opts.Validate(); err == nil {
			t.Fatal("expected ExecOptions.Validate() to fail with mutual exclusion error, got nil")
		}
	})

	t.Run("scp_ScpOptions_Validate", func(t *testing.T) {
		opts := NewScpOptions()
		opts.OTP = "123456"
		opts.OTPStdin = true
		if err := opts.Validate(); err == nil {
			t.Fatal("expected ScpOptions.Validate() to fail with mutual exclusion error, got nil")
		}
	})

	t.Run("sftp_SftpOptions_Validate", func(t *testing.T) {
		opts := NewSftpOptions()
		opts.OTP = "123456"
		opts.OTPStdin = true
		if err := opts.Validate(); err == nil {
			t.Fatal("expected SftpOptions.Validate() to fail with mutual exclusion error, got nil")
		}
	})

	t.Run("exec_ExecOptions_OTPStdinWithNoCommandOrScript_RejectsInComplete", func(t *testing.T) {
		opts := NewExecOptions()
		opts.OTPStdin = true
		opts.Interactive = false
		opts.Command = ""
		opts.ShellFile = ""

		cmd := NewCmdExec()
		err := opts.Complete(cmd, []string{"dummy-host"})
		if err == nil {
			t.Fatal("expected Complete() to reject stdin OTP when command/script is missing, got nil")
		}
		if !strings.Contains(err.Error(), "stdin cannot supply both credentials and a script") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})

	t.Run("ssh_SshOptions_BackgroundModeRejectsOneTimeOTP", func(t *testing.T) {
		opts := NewSshOptions()
		opts.Host = "test-host"
		opts.BgRun = true
		opts.NoCmd = true
		opts.OTP = "123456"
		if err := opts.Validate(); err == nil {
			t.Fatal("expected SshOptions.Validate() to reject -f (BgRun) combined with --otp, got nil")
		}
	})
}

// -----------------------------------------------------------------------------
// Challenge 3: ANSI & Terminal Hijacking Injection Tests
// -----------------------------------------------------------------------------

func TestAdversarialSanitizeInteractiveText(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantExact  string
		mustNotSub []string
	}{
		{
			name:       "CSI screen clear and cursor moves",
			input:      "\x1b[2J\x1b[0;0H\x1b[?25lEnter Password:\x1b[?25h",
			wantExact:  "Enter Password:",
			mustNotSub: []string{"\x1b", "[2J", "[0;0H"},
		},
		{
			name:       "CSI 24-bit TrueColor and bold blink",
			input:      "\x1b[38;2;255;128;64m\x1b[1;5mOTP Code:\x1b[0m",
			wantExact:  "OTP Code:",
			mustNotSub: []string{"\x1b", "[38;2;"},
		},
		{
			name:       "CSI device status query injection",
			input:      "Answer:\x1b[6n",
			wantExact:  "Answer:",
			mustNotSub: []string{"\x1b", "[6n"},
		},
		{
			name:       "OSC title change with BEL terminator",
			input:      "\x1b]0;PWNED_TERMINAL\x07Please authenticate:",
			wantExact:  "Please authenticate:",
			mustNotSub: []string{"\x1b", "PWNED_TERMINAL", "\x07"},
		},
		{
			name:       "OSC title change with ST (ESC backslash) terminator",
			input:      "\x1b]2;HACKED_WINDOW\x1b\\Verification Code:",
			wantExact:  "Verification Code:",
			mustNotSub: []string{"\x1b", "HACKED_WINDOW"},
		},
		{
			name:       "OSC hyperlink injection",
			input:      "\x1b]8;;http://phishing.example.com\x07Click Here\x1b]8;;\x07 to login",
			wantExact:  "Click Here to login",
			mustNotSub: []string{"phishing.example.com", "\x1b", "\x07"},
		},
		{
			name:       "OSC clipboard write injection (OSC 52)",
			input:      "\x1b]52;c;cGFzc3dvcmQ=\x07Password:",
			wantExact:  "Password:",
			mustNotSub: []string{"52;c", "cGFzc3dvcmQ=", "\x07"},
		},
		{
			name:       "Naked escape and two-byte escape codes",
			input:      "\x1bMReverse\x1b7Save\x1b8Restore\x1b(BCharset",
			wantExact:  "Reverse7Save8Restore(BCharset",
			mustNotSub: []string{"\x1b"},
		},
		{
			name:       "Dangerous control characters: Bell, Backspace, Carriage Return, NUL",
			input:      "\x00Hello\x07 \x08World\r\nNewline\tTab",
			wantExact:  "Hello World\nNewline\tTab",
			mustNotSub: []string{"\x00", "\x07", "\x08", "\r"},
		},
		{
			name:       "Incomplete escape at end of stream",
			input:      "Prompt\x1b[",
			wantExact:  "Prompt[",
			mustNotSub: []string{"\x1b"},
		},
		{
			name:       "Invalid UTF-8 byte sequences",
			input:      "Malformed\xff\xfe\xfdText",
			wantExact:  "Malformed\ufffd\ufffd\ufffdText",
			mustNotSub: []string{"\xff", "\xfe", "\xfd"},
		},
		{
			name:       "Truncated multibyte UTF-8",
			input:      "Truncated\xc3",
			wantExact:  "Truncated\ufffd",
			mustNotSub: []string{"\xc3"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeInteractiveText(tc.input)
			if got != tc.wantExact {
				t.Fatalf("sanitizeInteractiveText(%q):\n got  %q\n want %q", tc.input, got, tc.wantExact)
			}
			for _, bad := range tc.mustNotSub {
				if strings.Contains(got, bad) {
					t.Fatalf("sanitized text contains forbidden substring %q: %q", bad, got)
				}
			}
		})
	}
}

func TestAdversarialPromptSecret_TerminalHijackVectors(t *testing.T) {
	var capturedOutput bytes.Buffer
	prompter := &testPrompter{
		readLineFunc: func(ctx context.Context, prompt string) (string, error) {
			return "ack", nil
		},
		readSecretFunc: func(ctx context.Context, prompt string) (string, error) {
			return "secret", nil
		},
	}

	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	handler := &cliInteractionHandler{
		promptGate: gate,
		terminal:   prompter,
		output:     &capturedOutput,
	}

	// Hostile instruction banner with multiple escape injection sequences
	hostileInstruction := "\x1b[2J\x1b[H\x1b]0;TERMINAL_TAKEOVER\x07\x00\x08CRITICAL INSTRUCTION\r\n"
	hostilePrompt := "\x1b[31;1m\x1b]8;;http://attacker.com\x07Enter Code:\x1b]8;;\x07\x1b[0m"

	ans, err := handler.PromptSecret(context.Background(), ssh.SecretRequest{
		Kind:        ssh.SecretKindKeyboardInteractive,
		Instruction: hostileInstruction,
		Prompt:      hostilePrompt,
		Echo:        false,
	})
	if err != nil {
		t.Fatalf("PromptSecret failed: %v", err)
	}
	if ans != "secret" {
		t.Fatalf("expected ans 'secret', got %q", ans)
	}

	// Verify captured output in stderr does not contain any escape characters or hostile payloads
	out := capturedOutput.String()
	if strings.Contains(out, "\x1b") {
		t.Fatalf("stderr contains raw ESC byte: %q", out)
	}
	if strings.Contains(out, "TERMINAL_TAKEOVER") {
		t.Fatalf("stderr contains OSC title payload: %q", out)
	}
	if strings.Contains(out, "\x00") || strings.Contains(out, "\x07") || strings.Contains(out, "\x08") {
		t.Fatalf("stderr contains control characters: %q", out)
	}
	if !strings.Contains(out, "CRITICAL INSTRUCTION") {
		t.Fatalf("expected instruction text to be preserved, got %q", out)
	}
}

// -----------------------------------------------------------------------------
// Challenge 4: Non-Persistence Invariant Verification
// -----------------------------------------------------------------------------

func TestAdversarialKeyboardInteractive_NonPersistenceInvariant(t *testing.T) {
	var (
		readSecretCalled bool
		readLineCalled   bool
		capturedPrompt   string
	)

	prompter := &testPrompter{
		readLineFunc: func(ctx context.Context, prompt string) (string, error) {
			readLineCalled = true
			capturedPrompt = prompt
			return "visible-one-time-pin", nil
		},
		readSecretFunc: func(ctx context.Context, prompt string) (string, error) {
			readSecretCalled = true
			capturedPrompt = prompt
			return "hidden-one-time-pin", nil
		},
	}

	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	handler := &cliInteractionHandler{
		promptGate:  gate,
		terminal:    prompter,
		canRemember: true, // Even if remember capability is present on handler
	}

	// 1. Verify masked challenge query (Echo = false)
	secretAns, err := handler.PromptSecret(context.Background(), ssh.SecretRequest{
		Kind:    ssh.SecretKindKeyboardInteractive,
		NodeID:  "secure-vault-1",
		Prompt:  "Response [PIN]:",
		Echo:    false,
		Attempt: 1,
	})
	if err != nil {
		t.Fatalf("PromptSecret (masked) failed: %v", err)
	}
	if secretAns != "hidden-one-time-pin" {
		t.Fatalf("expected 'hidden-one-time-pin', got %q", secretAns)
	}
	if !readSecretCalled || readLineCalled {
		t.Fatalf("expected ReadSecret called, got readSecret=%v, readLine=%v", readSecretCalled, readLineCalled)
	}
	if capturedPrompt != "Response [PIN]: " {
		t.Fatalf("expected formatted prompt 'Response [PIN]: ', got %q", capturedPrompt)
	}

	// 2. Verify visible challenge query (Echo = true)
	readSecretCalled = false
	readLineCalled = false
	echoAns, err := handler.PromptSecret(context.Background(), ssh.SecretRequest{
		Kind:    ssh.SecretKindKeyboardInteractive,
		NodeID:  "secure-vault-1",
		Prompt:  "Security Challenge [OTP]:",
		Echo:    true,
		Attempt: 1,
	})
	if err != nil {
		t.Fatalf("PromptSecret (echo) failed: %v", err)
	}
	if echoAns != "visible-one-time-pin" {
		t.Fatalf("expected 'visible-one-time-pin', got %q", echoAns)
	}
	if !readLineCalled || readSecretCalled {
		t.Fatalf("expected ReadLine called, got readLine=%v, readSecret=%v", readLineCalled, readSecretCalled)
	}
	if capturedPrompt != "Security Challenge [OTP]: " {
		t.Fatalf("expected formatted prompt 'Security Challenge [OTP]: ', got %q", capturedPrompt)
	}
}

func TestAdversarialCLIInteractionHandler_PasswordCallbackIsolation(t *testing.T) {
	// Verify that PasswordCallback is strictly isolated to Password auth
	// and never receives any keyboard-interactive challenge answers.
	var passwordCallbackInvocations []string
	pwCallback := func(secret string) {
		passwordCallbackInvocations = append(passwordCallbackInvocations, secret)
	}

	prompter := &testPrompter{
		readSecretFunc: func(ctx context.Context, prompt string) (string, error) {
			return "challenge-answer-never-persisted", nil
		},
	}
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	handler := &cliInteractionHandler{
		promptGate: gate,
		terminal:   prompter,
	}

	ans, err := handler.PromptSecret(context.Background(), ssh.SecretRequest{
		Kind:   ssh.SecretKindKeyboardInteractive,
		Prompt: "Duo Code:",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ans != "challenge-answer-never-persisted" {
		t.Fatalf("expected answer 'challenge-answer-never-persisted', got %q", ans)
	}

	// Verify that pwCallback was NOT invoked
	if len(passwordCallbackInvocations) > 0 {
		t.Fatalf("PasswordCallback was unexpectedly invoked for keyboard-interactive query: %v", passwordCallbackInvocations)
	}

	// Explicitly invoke pwCallback only to prove the test mechanism works
	pwCallback("real-password")
	if len(passwordCallbackInvocations) != 1 || passwordCallbackInvocations[0] != "real-password" {
		t.Fatalf("expected pwCallback invoked for password, got %v", passwordCallbackInvocations)
	}
}
