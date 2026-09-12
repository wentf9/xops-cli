package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/pkg/credential"
	cryptoSSH "golang.org/x/crypto/ssh"
)

type recoveryTestUI struct {
	mu      sync.Mutex
	values  []string
	prompts int
	reports int
}

func (h *recoveryTestUI) PromptSecret(ctx context.Context, _ SecretRequest) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.prompts++
	if len(h.values) == 0 {
		return "", ErrInteractionRequired
	}
	value := h.values[0]
	h.values = h.values[1:]
	return value, nil
}
func (h *recoveryTestUI) ConfirmHostKey(context.Context, HostKeyConfirmation) (bool, error) {
	return true, nil
}
func (h *recoveryTestUI) ReportCredentialFailure(ctx context.Context, _ string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.reports++
	return nil
}

type recoveryResolverFunc func(context.Context, SecretRequest) ([]byte, error)

func (f recoveryResolverFunc) ResolveSecret(ctx context.Context, r SecretRequest) ([]byte, error) {
	return f(ctx, r)
}

type failedRecoveryRecorder struct {
	nopCredentialRecorder
	onUpdate func()
}

func (r failedRecoveryRecorder) UpdateAuth(context.Context, string, string, string, string, string) (string, error) {
	if r.onUpdate != nil {
		r.onUpdate()
	}
	return "", errors.New("backend write failed")
}

func TestRecoveryPasswordRetriesRejectedStoredValue(t *testing.T) {
	ui := &recoveryTestUI{values: []string{"valid-password"}}
	cfg := &ClientConfig{Password: "rejected-password", User: "test", AuthUpdateToken: "old"}
	c := NewConnector(nil, WithInteractionHandler(ui))
	defer func() {
		if err := c.CloseAll(); err != nil {
			t.Error(err)
		}
	}()
	method := c.recoverablePasswordAuth(t.Context(), cfg, ui, nil)
	callback := newSequentialAuthCallback([]autoAuthCandidate{{protocol: "password", method: method}}, nil, nil)
	if err := runAuthCallbackHandshake(t, callback, nil, "valid-password"); err != nil {
		t.Fatal(err)
	}
	if ui.prompts != 1 || cfg.Password != "valid-password" {
		t.Fatal("did not replace rejected value with one prompted attempt")
	}
}

func TestRecoveryReadFailureAndCancellation(t *testing.T) {
	for _, cancel := range []bool{false, true} {
		t.Run(strconv.FormatBool(cancel), func(t *testing.T) {
			ui := &recoveryTestUI{values: []string{"temporary"}}
			ctx, stop := context.WithCancel(t.Context())
			defer stop()
			if cancel {
				stop()
			}
			p := &autoSecretProvider{lifecycleCtx: ctx, prompter: ui, recoveryPrompter: ui, resolver: recoveryResolverFunc(func(context.Context, SecretRequest) ([]byte, error) {
				return nil, credential.ErrCredentialStoreUnavailable
			})}
			got, err := p.resolveOrPrompt(SecretRequest{Kind: SecretKindLoginPassword})
			if cancel {
				if err == nil || ui.prompts != 0 || ui.reports != 0 {
					t.Fatal("cancellation prompted or recovered")
				}
				return
			}
			if err != nil || got != "temporary" || ui.reports != 1 || ui.prompts != 1 {
				t.Fatalf("interactive recovery: %v", err)
			}
		})
	}
}

func TestRecoveryPrivateKeyRetriesOnlyIncorrectPassphrase(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := cryptoSSH.MarshalPrivateKeyWithPassphrase(key, "test", []byte("correct"))
	if err != nil {
		t.Fatal(err)
	}
	for _, corrupt := range []bool{false, true} {
		t.Run(strconv.FormatBool(corrupt), func(t *testing.T) {
			ui := &recoveryTestUI{values: []string{"correct"}}
			p := &autoSecretProvider{lifecycleCtx: t.Context(), prompter: ui, recoveryPrompter: ui, resolver: recoveryResolverFunc(func(context.Context, SecretRequest) ([]byte, error) { return []byte("wrong"), nil })}
			data := pem.EncodeToMemory(block)
			if corrupt {
				data = []byte("invalid key format")
			}
			signer, phrase, err := p.decryptPrivateKey(data, "test-key")
			if corrupt {
				if err == nil || ui.prompts != 0 {
					t.Fatal("corrupt key retried")
				}
				return
			}
			if err != nil || signer == nil || phrase != "correct" || ui.prompts != 1 {
				t.Fatalf("key retry: %v", err)
			}
		})
	}
}

func TestRecoverySaveFailureKeepsAuthenticatedConnection(t *testing.T) {
	for _, applied := range []bool{false, true} {
		t.Run(strconv.FormatBool(applied), func(t *testing.T) { testRecoverySaveFailureKeepsAuthenticatedConnection(t, applied) })
	}
}

func testRecoverySaveFailureKeepsAuthenticatedConnection(t *testing.T, applied bool) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	addr, _, stop := startTestAutoSSHServer(t, "valid-password")
	defer stop()
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	store := &characterizationRecordingStore{cfg: &ClientConfig{NodeID: "test", Address: host, Port: port, User: "test", AuthType: "password", Password: "valid-password", AuthUpdateToken: "auth-old", SudoUpdateToken: "sudo-old"}}
	ui := &recoveryTestUI{}
	recorder := failedRecoveryRecorder{}
	if applied {
		recorder.onUpdate = func() {
			store.mu.Lock()
			defer store.mu.Unlock()
			store.cfg.AuthUpdateToken = "applied-without-durability"
		}
	}
	c := NewConnector(store, WithInteractionHandler(ui), WithCredentialRecorder(recorder), WithHandshakeTimeout(2*time.Second))
	defer func() {
		if err := c.CloseAll(); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client, err := c.Connect(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}
	if client.connCfg.AuthUpdateToken != "" || client.connCfg.SudoUpdateToken != "" {
		t.Fatal("uncertain write retained authorization tokens")
	}
	if _, _, err := client.sshClient.SendRequest("keepalive@test", true, nil); err != nil {
		t.Fatalf("authenticated connection closed: %v", err)
	}
	ui.mu.Lock()
	defer ui.mu.Unlock()
	if ui.reports != 1 {
		t.Fatal("missing persistence warning")
	}
}

func TestRecoveryDoesNotPromptOnSnapshotMismatch(t *testing.T) {
	ui := &recoveryTestUI{values: []string{"must-not-be-read"}}
	p := &autoSecretProvider{lifecycleCtx: t.Context(), prompter: ui, recoveryPrompter: ui, resolver: recoveryResolverFunc(func(context.Context, SecretRequest) ([]byte, error) { return nil, ErrSnapshotMismatch })}
	if _, err := p.resolveOrPrompt(SecretRequest{Kind: SecretKindLoginPassword}); !errors.Is(err, ErrSnapshotMismatch) {
		t.Fatalf("snapshot mismatch lost: %v", err)
	}
	if ui.prompts != 0 || ui.reports != 0 {
		t.Fatal("snapshot mismatch recovered")
	}
}

func TestRecoveryPasswordRetriesAreBounded(t *testing.T) {
	ui := &recoveryTestUI{values: []string{"wrong-two", "wrong-three", "must-not-be-read"}}
	cfg := &ClientConfig{Password: "wrong-one", User: "test"}
	c := NewConnector(nil, WithInteractionHandler(ui))
	defer func() {
		if err := c.CloseAll(); err != nil {
			t.Error(err)
		}
	}()
	callback := newSequentialAuthCallback([]autoAuthCandidate{{protocol: "password", method: c.recoverablePasswordAuth(t.Context(), cfg, ui, nil)}}, nil, nil)
	if err := runAuthCallbackHandshake(t, callback, nil, "different-password"); err == nil {
		t.Fatal("incorrect passwords accepted")
	}
	if ui.prompts != 2 {
		t.Fatalf("prompt count %d, want two retries", ui.prompts)
	}
}

func TestRecoveryReadFailureWithoutReporterFailsClosed(t *testing.T) {
	ui := &recoveryTestUI{values: []string{"must-not-be-read"}}
	p := &autoSecretProvider{lifecycleCtx: t.Context(), prompter: ui, resolver: recoveryResolverFunc(func(context.Context, SecretRequest) ([]byte, error) { return nil, credential.ErrCredentialStoreLocked })}
	if _, err := p.resolveOrPrompt(SecretRequest{Kind: SecretKindLoginPassword}); !errors.Is(err, credential.ErrCredentialStoreLocked) {
		t.Fatalf("backend error lost: %v", err)
	}
	if ui.prompts != 0 {
		t.Fatal("non-recovering path prompted")
	}
}

func TestRecoveryFailedKeySavePreservesTargetChecks(t *testing.T) {
	for _, path := range []string{"configured-key", "discovered-key", "unrelated-key"} {
		t.Run(path, func(t *testing.T) {
			provider := &characterizationRecordingStore{cfg: &ClientConfig{Address: "host", User: "user", KeyPath: path}}
			c := NewConnector(provider)
			defer func() {
				if err := c.CloseAll(); err != nil {
					t.Error(err)
				}
			}()
			left, right := net.Pipe()
			defer func() {
				if err := left.Close(); err != nil {
					t.Error(err)
				}
				if err := right.Close(); err != nil {
					t.Error(err)
				}
			}()
			cfg := &ClientConfig{Address: "host", User: "user", KeyPath: "discovered-key"}
			err := c.syncConnectionAfterRecording("test", cfg, "", false, true, "configured-key", left)
			if path == "unrelated-key" {
				if !errors.Is(err, ErrSnapshotMismatch) {
					t.Fatalf("unrelated target accepted: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("failed-save compatible target rejected: %v", err)
			}
		})
	}
}

func (*recoveryTestUI) CredentialRecoveryAllowed() bool { return true }

func TestRecoveryRejectedPasswordsDoNotSave(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	addr, _, stop := startTestAutoSSHServer(t, "valid-password")
	defer stop()
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	store := &characterizationRecordingStore{cfg: &ClientConfig{NodeID: "test", Address: host, Port: port, User: "test", AuthType: "password", Password: "wrong-one", AuthUpdateToken: "auth-old"}}
	ui := &recoveryTestUI{values: []string{"wrong-two", "wrong-three"}}
	c := NewConnector(store, WithInteractionHandler(ui), WithHandshakeTimeout(2*time.Second))
	defer func() {
		if err := c.CloseAll(); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if _, err := c.Connect(ctx, "test"); err == nil {
		t.Fatal("invalid passwords connected")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.updateCalls != 0 || store.cfg.Password != "wrong-one" {
		t.Fatal("failed authentication updated stored credentials")
	}
}
