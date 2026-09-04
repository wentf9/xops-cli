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

	"github.com/wentf9/xops-cli/internal/terminal"
	"github.com/wentf9/xops-cli/pkg/ssh"
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
