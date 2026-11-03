package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/internal/terminal"
)

type interactionFailingWriter struct {
	err error
}

func (w interactionFailingWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func TestCLIInteractionHandlerConfirmHostKey(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe: %v", err)
	}
	defer func() {
		_ = reader.Close()
	}()

	go func() {
		defer func() {
			_ = writer.Close()
		}()
		_, _ = writer.WriteString("yes\n")
	}()

	var output bytes.Buffer
	handler := newCLIInteractionHandlerWithStreams(reader, &output)
	confirmed, err := handler.ConfirmHostKey(context.Background(), ssh.HostKeyConfirmation{
		Hostname:    "host.example",
		Fingerprint: "SHA256:test",
	})
	if err != nil {
		t.Fatalf("ConfirmHostKey() error = %v", err)
	}
	if !confirmed {
		t.Fatal("ConfirmHostKey() confirmed = false, want true")
	}
	if got := output.String(); !strings.Contains(got, "host.example") || !strings.Contains(got, "SHA256:test") {
		t.Fatalf("ConfirmHostKey() output = %q, want host and fingerprint", got)
	}
}

func TestCLIInteractionHandlerConfirmHostKey_Reject(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe: %v", err)
	}
	defer func() {
		_ = reader.Close()
	}()

	go func() {
		defer func() {
			_ = writer.Close()
		}()
		_, _ = writer.WriteString("no\n")
	}()

	var output bytes.Buffer
	handler := newCLIInteractionHandlerWithStreams(reader, &output)
	confirmed, err := handler.ConfirmHostKey(context.Background(), ssh.HostKeyConfirmation{
		Hostname:    "host.example",
		Fingerprint: "SHA256:test",
	})
	if err != nil {
		t.Fatalf("ConfirmHostKey() error = %v", err)
	}
	if confirmed {
		t.Fatal("ConfirmHostKey() confirmed = true, want false")
	}
}

func TestCLIInteractionHandlerSecretKinds(t *testing.T) {
	tests := []struct {
		name       string
		req        ssh.SecretRequest
		input      string
		wantSecret string
		wantPrompt string
	}{
		{
			name: "login password with user and host",
			req: ssh.SecretRequest{
				Kind: ssh.SecretKindLoginPassword,
				User: "alice",
				Host: "192.168.1.10",
			},
			input:      "loginpass123\n",
			wantSecret: "loginpass123",
			wantPrompt: "alice@192.168.1.10",
		},
		{
			name: "private key passphrase",
			req: ssh.SecretRequest{
				Kind:    ssh.SecretKindPrivateKeyPassphrase,
				KeyPath: "/home/user/.ssh/id_ed25519",
			},
			input:      "keypassphrase456\n",
			wantSecret: "keypassphrase456",
			wantPrompt: "/home/user/.ssh/id_ed25519",
		},
		{
			name: "su password",
			req: ssh.SecretRequest{
				Kind:   ssh.SecretKindSuPassword,
				NodeID: "prod-db-1",
			},
			input:      "supassword789\n",
			wantSecret: "supassword789",
			wantPrompt: "prod-db-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatalf("create pipe: %v", err)
			}
			defer func() {
				_ = reader.Close()
			}()

			go func() {
				defer func() {
					_ = writer.Close()
				}()
				_, _ = writer.WriteString(tt.input)
			}()

			var output bytes.Buffer
			handler := newCLIInteractionHandlerWithStreams(reader, &output)
			secret, err := handler.PromptSecret(context.Background(), tt.req)
			if err != nil {
				t.Fatalf("PromptSecret() error = %v", err)
			}
			if secret != tt.wantSecret {
				t.Fatalf("PromptSecret() got %q, want %q", secret, tt.wantSecret)
			}
			if !strings.Contains(output.String(), tt.wantPrompt) {
				t.Fatalf("output %q does not contain %q", output.String(), tt.wantPrompt)
			}
		})
	}
}

func TestCLIInteractionHandlerPreCanceledContext(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe: %v", err)
	}
	defer func() {
		_ = reader.Close()
		_ = writer.Close()
	}()

	handler := newCLIInteractionHandlerWithStreams(reader, &bytes.Buffer{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = handler.PromptSecret(ctx, ssh.SecretRequest{Kind: ssh.SecretKindLoginPassword})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	_, err = handler.ConfirmHostKey(ctx, ssh.HostKeyConfirmation{Hostname: "example.com"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestCLIInteractionHandlerCancelWaitingForPromptGate(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe: %v", err)
	}
	defer func() {
		_ = reader.Close()
		_ = writer.Close()
	}()

	handler := newCLIInteractionHandlerWithStreams(reader, &bytes.Buffer{})

	// Manually acquire the gate to simulate an in-progress prompt
	release, err := handler.acquireGate(context.Background())
	if err != nil {
		t.Fatalf("acquireGate failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)

	go func() {
		_, err := handler.PromptSecret(ctx, ssh.SecretRequest{Kind: ssh.SecretKindLoginPassword})
		errCh <- err
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("PromptSecret did not return after context cancellation while waiting for gate")
	}

	release()
}

func TestCLIInteractionHandlerPromptGateSerialization(t *testing.T) {
	type mockPrompter struct {
		mu      sync.Mutex
		active  int
		maxConc int
	}

	mock := &mockPrompter{}
	customPrompter := &testPrompter{
		readLineFunc: func(ctx context.Context, prompt string) (string, error) {
			mock.mu.Lock()
			mock.active++
			if mock.active > mock.maxConc {
				mock.maxConc = mock.active
			}
			mock.mu.Unlock()

			time.Sleep(30 * time.Millisecond)

			mock.mu.Lock()
			mock.active--
			mock.mu.Unlock()
			return "yes", nil
		},
		readSecretFunc: func(ctx context.Context, prompt string) (string, error) {
			mock.mu.Lock()
			mock.active++
			if mock.active > mock.maxConc {
				mock.maxConc = mock.active
			}
			mock.mu.Unlock()

			time.Sleep(30 * time.Millisecond)

			mock.mu.Lock()
			mock.active--
			mock.mu.Unlock()
			return "secret", nil
		},
	}

	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	handler := &cliInteractionHandler{
		promptGate: gate,
		terminal:   customPrompter,
	}

	var wg sync.WaitGroup
	// Concurrently invoke PromptSecret and ConfirmHostKey
	for i := 0; i < 5; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = handler.PromptSecret(context.Background(), ssh.SecretRequest{Kind: ssh.SecretKindLoginPassword})
		}()
		go func() {
			defer wg.Done()
			_, _ = handler.ConfirmHostKey(context.Background(), ssh.HostKeyConfirmation{Hostname: "host.example"})
		}()
	}

	wg.Wait()

	if mock.maxConc > 1 {
		t.Fatalf("promptGate failed to serialize prompts, max concurrent: %d", mock.maxConc)
	}
}

func TestCLIInteractionHandlerReturnsOutputError(t *testing.T) {
	wantErr := errors.New("output unavailable")
	handler := newCLIInteractionHandlerWithStreams(os.Stdin, interactionFailingWriter{err: wantErr})
	_, err := handler.ConfirmHostKey(context.Background(), ssh.HostKeyConfirmation{Hostname: "host.example", Fingerprint: "SHA256:test"})
	if !errors.Is(err, wantErr) {
		t.Fatalf("ConfirmHostKey() error = %v, want wrapped %v", err, wantErr)
	}
}

type testPrompter struct {
	readLineFunc   func(ctx context.Context, prompt string) (string, error)
	readSecretFunc func(ctx context.Context, prompt string) (string, error)
}

func (p *testPrompter) ReadLine(ctx context.Context, prompt string) (string, error) {
	if p.readLineFunc != nil {
		return p.readLineFunc(ctx, prompt)
	}
	return "", fmt.Errorf("not implemented")
}

func (p *testPrompter) ReadSecret(ctx context.Context, prompt string) (string, error) {
	if p.readSecretFunc != nil {
		return p.readSecretFunc(ctx, prompt)
	}
	return "", fmt.Errorf("not implemented")
}

var _ terminal.Prompter = (*testPrompter)(nil)

func TestCLIInteractionHandlerPromptSecret_KeyboardInteractive(t *testing.T) {
	t.Run("EchoTrue_CallsReadLine", func(t *testing.T) {
		var readLineCalled, readSecretCalled bool
		var capturedPrompt string

		prompter := &testPrompter{
			readLineFunc: func(ctx context.Context, prompt string) (string, error) {
				readLineCalled = true
				capturedPrompt = prompt
				return "echoed-answer", nil
			},
			readSecretFunc: func(ctx context.Context, prompt string) (string, error) {
				readSecretCalled = true
				return "", nil
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
			Prompt: "Username:",
			Echo:   true,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ans != "echoed-answer" {
			t.Fatalf("expected 'echoed-answer', got %q", ans)
		}
		if !readLineCalled || readSecretCalled {
			t.Fatalf("expected ReadLine to be called, got readLine=%v, readSecret=%v", readLineCalled, readSecretCalled)
		}
		if capturedPrompt != "Username: " {
			t.Fatalf("expected prompt 'Username: ', got %q", capturedPrompt)
		}
	})

	t.Run("EchoFalse_CallsReadSecret", func(t *testing.T) {
		var readLineCalled, readSecretCalled bool
		var capturedPrompt string

		prompter := &testPrompter{
			readLineFunc: func(ctx context.Context, prompt string) (string, error) {
				readLineCalled = true
				return "", nil
			},
			readSecretFunc: func(ctx context.Context, prompt string) (string, error) {
				readSecretCalled = true
				capturedPrompt = prompt
				return "masked-secret", nil
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
			Prompt: "Passcode:",
			Echo:   false,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ans != "masked-secret" {
			t.Fatalf("expected 'masked-secret', got %q", ans)
		}
		if !readSecretCalled || readLineCalled {
			t.Fatalf("expected ReadSecret to be called, got readSecret=%v, readLine=%v", readSecretCalled, readLineCalled)
		}
		if capturedPrompt != "Passcode: " {
			t.Fatalf("expected prompt 'Passcode: ', got %q", capturedPrompt)
		}
	})

	t.Run("DisplaysSanitizedInstructionBanner", func(t *testing.T) {
		var output bytes.Buffer
		prompter := &testPrompter{
			readSecretFunc: func(ctx context.Context, prompt string) (string, error) {
				return "ans", nil
			},
		}

		gate := make(chan struct{}, 1)
		gate <- struct{}{}
		handler := &cliInteractionHandler{
			promptGate: gate,
			terminal:   prompter,
			output:     &output,
		}

		_, err := handler.PromptSecret(context.Background(), ssh.SecretRequest{
			Kind:        ssh.SecretKindKeyboardInteractive,
			Instruction: "\x1b[31;1mIMPORTANT NOTICE\x1b[0m: Gateway Auth",
			Prompt:      "Token:",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(output.String(), "IMPORTANT NOTICE: Gateway Auth") {
			t.Fatalf("expected sanitized instruction in output, got %q", output.String())
		}
		if strings.Contains(output.String(), "\x1b[") {
			t.Fatalf("output contains unescaped ANSI sequences: %q", output.String())
		}
	})

	t.Run("SanitizesPromptText", func(t *testing.T) {
		var capturedPrompt string
		prompter := &testPrompter{
			readSecretFunc: func(ctx context.Context, prompt string) (string, error) {
				capturedPrompt = prompt
				return "ans", nil
			},
		}

		gate := make(chan struct{}, 1)
		gate <- struct{}{}
		handler := &cliInteractionHandler{
			promptGate: gate,
			terminal:   prompter,
		}

		_, err := handler.PromptSecret(context.Background(), ssh.SecretRequest{
			Kind:   ssh.SecretKindKeyboardInteractive,
			Prompt: "\x1b[32mPIN Code:\x1b[0m",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if capturedPrompt != "PIN Code: " {
			t.Fatalf("expected 'PIN Code: ', got %q", capturedPrompt)
		}
	})
}

func TestCLIInteractionHandlerPromptSecret_OTP(t *testing.T) {
	t.Run("WithCustomPrompt", func(t *testing.T) {
		var capturedPrompt string
		prompter := &testPrompter{
			readSecretFunc: func(ctx context.Context, prompt string) (string, error) {
				capturedPrompt = prompt
				return "123456", nil
			},
		}
		gate := make(chan struct{}, 1)
		gate <- struct{}{}
		handler := &cliInteractionHandler{
			promptGate: gate,
			terminal:   prompter,
		}

		code, err := handler.PromptSecret(context.Background(), ssh.SecretRequest{
			Kind:   ssh.SecretKindOTP,
			Prompt: "Enter YubiKey OTP:",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if code != "123456" {
			t.Fatalf("expected '123456', got %q", code)
		}
		if capturedPrompt != "Enter YubiKey OTP: " {
			t.Fatalf("expected 'Enter YubiKey OTP: ', got %q", capturedPrompt)
		}
	})

	t.Run("WithUserAndHost", func(t *testing.T) {
		var capturedPrompt string
		prompter := &testPrompter{
			readSecretFunc: func(ctx context.Context, prompt string) (string, error) {
				capturedPrompt = prompt
				return "654321", nil
			},
		}
		gate := make(chan struct{}, 1)
		gate <- struct{}{}
		handler := &cliInteractionHandler{
			promptGate: gate,
			terminal:   prompter,
		}

		code, err := handler.PromptSecret(context.Background(), ssh.SecretRequest{
			Kind: ssh.SecretKindOTP,
			User: "admin",
			Host: "bastion.example.com",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if code != "654321" {
			t.Fatalf("expected '654321', got %q", code)
		}
		if !strings.Contains(capturedPrompt, "admin@bastion.example.com") {
			t.Fatalf("expected user@host in prompt, got %q", capturedPrompt)
		}
	})
}

func TestSanitizeInteractiveText(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "plain text",
			input: "Hello World",
			want:  "Hello World",
		},
		{
			name:  "CSI color escape sequence",
			input: "\x1b[31;1mRed Alert\x1b[0m",
			want:  "Red Alert",
		},
		{
			name:  "OSC hyperlink sequence",
			input: "\x1b]8;;http://evil.com\x07Click Here\x1b]8;;\x07",
			want:  "Click Here",
		},
		{
			name:  "control characters stripped except tab and newline",
			input: "Line 1\x00\x07\x08\tLine 2\r\n",
			want:  "Line 1\tLine 2\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeInteractiveText(tt.input)
			if got != tt.want {
				t.Fatalf("sanitizeInteractiveText(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestCLIConnectionFlags_OTPRegistration(t *testing.T) {
	commands := []struct {
		name string
		cmd  *cobra.Command
	}{
		{"ssh", NewCmdSsh()},
		{"exec", NewCmdExec()},
		{"scp", NewCmdScp()},
		{"sftp", NewCmdSftp()},
	}

	for _, tc := range commands {
		t.Run(tc.name, func(t *testing.T) {
			otpFlag := tc.cmd.Flags().Lookup("otp")
			if otpFlag == nil {
				t.Fatalf("%s missing --otp flag", tc.name)
			}
			if otpFlag.Value.Type() != "string" {
				t.Errorf("%s --otp type = %q, want string", tc.name, otpFlag.Value.Type())
			}

			otpStdin := tc.cmd.Flags().Lookup("otp-stdin")
			if otpStdin == nil {
				t.Fatalf("%s missing --otp-stdin flag", tc.name)
			}
			if otpStdin.Value.Type() != "bool" {
				t.Errorf("%s --otp-stdin type = %q, want bool", tc.name, otpStdin.Value.Type())
			}
		})
	}
}

func TestCLIConnectionFlags_OTPMutualExclusion(t *testing.T) {
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
		t.Run(tc.name, func(t *testing.T) {
			cmd := tc.cmd()
			cmd.SetArgs([]string{"--otp", "123456", "--otp-stdin"})
			err := cmd.Execute()
			if err == nil {
				t.Fatalf("%s: expected error when both --otp and --otp-stdin are specified, got nil", tc.name)
			}
		})
	}
}

func TestSshOptions_OTPStdin_SingleLineRead(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe: %v", err)
	}
	defer func() {
		_ = reader.Close()
	}()

	go func() {
		defer func() {
			_ = writer.Close()
		}()
		_, _ = writer.WriteString("998877\nsubsequent-data\n")
	}()

	oldStdin := os.Stdin
	os.Stdin = reader
	defer func() {
		os.Stdin = oldStdin
	}()

	opts := NewSshOptions()
	opts.OTPStdin = true
	opts.Host = "test-host"

	cmd := NewCmdSsh()
	if err := opts.Complete(cmd, []string{"test-host"}); err != nil {
		t.Fatalf("Complete failed: %v", err)
	}

	if opts.OTP != "998877" {
		t.Fatalf("expected OTP '998877', got %q", opts.OTP)
	}
	if opts.OTPStdin {
		t.Fatal("expected OTPStdin to be reset to false")
	}
}

func TestCLIInteractionHandler_PromptSecret_NonPersistence(t *testing.T) {
	prompter := &testPrompter{
		readSecretFunc: func(ctx context.Context, prompt string) (string, error) {
			return "interactive-one-time-pin", nil
		},
	}

	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	handler := &cliInteractionHandler{
		promptGate:  gate,
		terminal:    prompter,
		canRemember: false,
	}

	// Calling PromptSecret for KeyboardInteractive
	ans, err := handler.PromptSecret(context.Background(), ssh.SecretRequest{
		Kind:   ssh.SecretKindKeyboardInteractive,
		NodeID: "node-x",
		Prompt: "Enter Challenge Answer:",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ans != "interactive-one-time-pin" {
		t.Fatalf("expected 'interactive-one-time-pin', got %q", ans)
	}
}
