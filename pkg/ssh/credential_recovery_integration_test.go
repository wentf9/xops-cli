//go:build integration && (linux || windows || darwin) && (amd64 || arm64)

package ssh

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/internal/credentialfile/format"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
)

// Exercise the actual offline backend's error classification, not an injected
// generic unavailable error. Corruption must allow only temporary input.
func TestRecoveryCorruptOfflineVault(t *testing.T) {
	setTestHome(t)
	dir := t.TempDir()
	owner := config.NewEncryptedRuntime(t.Context(), filepath.Join(dir, "config.yaml"), nil)
	defer func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	}()
	registry, err := owner.Registry(config.DefaultCredentialConfig())
	if err != nil {
		t.Fatal(err)
	}
	store, err := registry.GetStore("file")
	if err != nil {
		t.Fatal(err)
	}
	ref := credential.Ref{StoreID: "file", ItemID: "existing"}
	value := credential.NewSecret([]byte("old-test-password"))
	defer value.Zero()
	if err := store.Put(t.Context(), ref, value); err != nil {
		t.Fatal(err)
	}
	if err := owner.Lock(t.Context()); err != nil {
		t.Fatal(err)
	}
	currentPath := filepath.Join(dir, "credentials", "CURRENT")
	keyPath := filepath.Join(dir, "credentials.key")
	keyBefore, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(keyBefore)
	corrupt := []byte("corrupt-publication")
	if err := os.WriteFile(currentPath, corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	resolver := recoveryResolverFunc(func(ctx context.Context, _ SecretRequest) ([]byte, error) {
		got, err := store.Get(ctx, ref)
		defer got.Zero()
		return append([]byte(nil), got.Value...), err
	})
	testCorruptVaultInputPolicies(t, resolver)
	testCorruptVaultConnection(t, resolver)
	if err := store.Put(t.Context(), ref, value); err == nil {
		t.Fatal("corrupt vault accepted a write")
	}
	after, err := os.ReadFile(currentPath)
	if err != nil || !bytes.Equal(after, corrupt) {
		t.Fatalf("corrupt publication was replaced: %v", err)
	}
	keyAfter, err := os.ReadFile(keyPath)
	defer clear(keyAfter)
	if err != nil || !bytes.Equal(keyBefore, keyAfter) {
		t.Fatalf("key was replaced: %v", err)
	}
}

func testCorruptVaultConnection(t *testing.T, resolver SecretResolver) {
	t.Helper()
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
	provider := &characterizationRecordingStore{cfg: &ClientConfig{NodeID: "test", Address: host, Port: port, User: "test", AuthType: "password", AuthUpdateToken: "auth-old", SudoUpdateToken: "sudo-old"}}
	ui := &recoveryTestUI{values: []string{"valid-password"}}
	connector := NewConnector(provider, WithInteractionHandler(ui), WithSecretResolver(resolver), WithCredentialRecorder(failedRecoveryRecorder{}), WithHandshakeTimeout(2*time.Second))
	defer func() {
		if err := connector.CloseAll(); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client, err := connector.Connect(ctx, "test")
	if err != nil {
		t.Fatalf("temporary authentication failed: %v", err)
	}
	if client.connCfg.AuthUpdateToken != "" || client.connCfg.SudoUpdateToken != "" {
		t.Fatal("failed save retained write authorization")
	}
	if _, _, err := client.sshClient.SendRequest("keepalive@test", true, nil); err != nil {
		t.Fatalf("temporary authenticated connection was closed: %v", err)
	}
}

func testCorruptVaultInputPolicies(t *testing.T, resolver SecretResolver) {
	t.Helper()
	for _, kind := range []SecretKind{SecretKindLoginPassword, SecretKindPrivateKeyPassphrase, SecretKindSudoPassword, SecretKindSuPassword} {
		ui := &recoveryTestUI{values: []string{"temporary"}}
		p := &autoSecretProvider{lifecycleCtx: t.Context(), prompter: ui, recoveryPrompter: ui, resolver: resolver}
		if got, err := p.resolveOrPrompt(SecretRequest{Kind: kind}); err != nil || got != "temporary" || ui.prompts != 1 {
			t.Fatalf("interactive corruption recovery failed for %v: %v", kind, err)
		}
	}
	for _, canceled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(t.Context())
		if canceled {
			cancel()
		}
		ui := &recoveryTestUI{values: []string{"must-not-read"}}
		p := &autoSecretProvider{lifecycleCtx: ctx, prompter: ui, resolver: resolver}
		_, err := p.resolveOrPrompt(SecretRequest{Kind: SecretKindLoginPassword})
		cancel()
		want := format.ErrCorrupt
		if canceled {
			want = context.Canceled
		}
		if !errors.Is(err, want) || ui.prompts != 0 {
			t.Fatalf("non-interactive/canceled read did not fail closed: %v", err)
		}
	}
}
