package ssh

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/pkg/logger"
	"golang.org/x/crypto/ssh"
)

func newAuthTestSigner(t *testing.T) ssh.Signer {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate test ed25519 key failed: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("create test SSH signer failed: %v", err)
	}
	return signer
}

func writeAuthTestPrivateKey(t *testing.T, path string) ssh.Signer {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate test ed25519 key failed: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(privateKey, "auth-callback-test")
	if err != nil {
		t.Fatalf("marshal test private key failed: %v", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatalf("write test private key failed: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("create test SSH signer failed: %v", err)
	}
	return signer
}

//nolint:gocyclo // Test-only SSH handshake harness intentionally centralizes transport setup, teardown, and error propagation.
func runAuthCallbackHandshake(t *testing.T, authCallback ssh.ClientAuthCallback, acceptedKey ssh.PublicKey, acceptedPassword string) (retErr error) {
	t.Helper()

	hostSigner := newAuthTestSigner(t)
	serverConfig := &ssh.ServerConfig{}
	if acceptedKey != nil {
		serverConfig.PublicKeyCallback = func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), acceptedKey.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("unauthorized public key")
		}
	}
	if acceptedPassword != "" {
		serverConfig.PasswordCallback = func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if string(password) == acceptedPassword {
				return nil, nil
			}
			return nil, errors.New("unauthorized password")
		}
	}
	serverConfig.AddHostKey(hostSigner)

	// Do not use net.Pipe here. SSH version exchange writes first on both
	// endpoints, while net.Pipe has no buffering, so both sides can block in
	// Write before either reaches Read. A loopback TCP connection matches the
	// buffering semantics of a real SSH transport and avoids that artificial
	// deadlock.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen for test SSH server failed: %w", err)
	}
	defer func() {
		if closeErr := listener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) && retErr == nil {
			retErr = fmt.Errorf("close test SSH listener failed: %w", closeErr)
		}
	}()

	deadline := time.Now().Add(5 * time.Second)
	serverErrCh := make(chan error, 1)
	go func() {
		serverSide, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErrCh <- fmt.Errorf("accept test SSH connection failed: %w", acceptErr)
			return
		}
		defer func() {
			_ = serverSide.Close()
		}()

		if setErr := serverSide.SetDeadline(deadline); setErr != nil {
			serverErrCh <- fmt.Errorf("set server test deadline failed: %w", setErr)
			return
		}

		serverConn, _, _, handshakeErr := ssh.NewServerConn(serverSide, serverConfig)
		if handshakeErr != nil {
			serverErrCh <- handshakeErr
			return
		}
		if closeErr := serverConn.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) && !errors.Is(closeErr, io.EOF) {
			serverErrCh <- fmt.Errorf("close test SSH server connection failed: %w", closeErr)
			return
		}
		serverErrCh <- nil
	}()

	clientSide, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		return fmt.Errorf("dial test SSH server failed: %w", err)
	}
	if err := clientSide.SetDeadline(deadline); err != nil {
		_ = clientSide.Close()
		return fmt.Errorf("set client test deadline failed: %w", err)
	}

	clientConfig := &ssh.ClientConfig{
		User:            "testuser",
		AuthCallback:    authCallback,
		HostKeyCallback: ssh.FixedHostKey(hostSigner.PublicKey()),
	}
	clientConn, _, _, clientErr := ssh.NewClientConn(clientSide, listener.Addr().String(), clientConfig)
	if clientErr == nil {
		if closeErr := clientConn.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) && !errors.Is(closeErr, io.EOF) {
			clientErr = fmt.Errorf("close test SSH client connection failed: %w", closeErr)
		}
	}
	if closeErr := clientSide.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) && !errors.Is(closeErr, io.EOF) && clientErr == nil {
		clientErr = fmt.Errorf("close test client transport failed: %w", closeErr)
	}

	serverErr := <-serverErrCh
	if clientErr != nil {
		return clientErr
	}
	if serverErr != nil {
		return fmt.Errorf("test SSH server handshake failed: %w", serverErr)
	}
	return nil
}

func TestSequentialAuthCallback_EmptyAgentDoesNotMaskExplicitKey(t *testing.T) {
	explicitSigner := newAuthTestSigner(t)
	candidates := []autoAuthCandidate{
		{
			protocol: autoAuthProtocolPublicKey,
			label:    "empty-agent",
			method: ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
				return nil, nil
			}),
		},
		{
			protocol: autoAuthProtocolPublicKey,
			label:    "explicit-key",
			method:   ssh.PublicKeys(explicitSigner),
		},
	}

	err := runAuthCallbackHandshake(
		t,
		newSequentialAuthCallback(candidates, nil, logger.NopLogger),
		explicitSigner.PublicKey(),
		"",
	)
	if err != nil {
		t.Fatalf("explicit key was masked by empty agent: %v", err)
	}
}

func TestSequentialAuthCallback_PublicKeyFallbacks(t *testing.T) {
	invalidSigner := newAuthTestSigner(t)
	agentSigner := newAuthTestSigner(t)
	defaultSigner := newAuthTestSigner(t)

	tests := []struct {
		name       string
		accepted   ssh.Signer
		candidates []autoAuthCandidate
	}{
		{
			name:     "invalid explicit falls back to agent",
			accepted: agentSigner,
			candidates: []autoAuthCandidate{
				{protocol: autoAuthProtocolPublicKey, label: "explicit-key", method: ssh.PublicKeys(invalidSigner)},
				{protocol: autoAuthProtocolPublicKey, label: "ssh-agent", method: ssh.PublicKeys(agentSigner)},
			},
		},
		{
			name:     "empty agent falls back to default key",
			accepted: defaultSigner,
			candidates: []autoAuthCandidate{
				{
					protocol: autoAuthProtocolPublicKey,
					label:    "ssh-agent",
					method: ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
						return nil, nil
					}),
				},
				{protocol: autoAuthProtocolPublicKey, label: "default-key", method: ssh.PublicKeys(defaultSigner)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runAuthCallbackHandshake(
				t,
				newSequentialAuthCallback(tt.candidates, nil, logger.NopLogger),
				tt.accepted.PublicKey(),
				"",
			)
			if err != nil {
				t.Fatalf("public key fallback handshake failed: %v", err)
			}
		})
	}
}

func TestSequentialAuthCallback_PublicKeysFailThenPasswordSucceeds(t *testing.T) {
	invalidSigner := newAuthTestSigner(t)
	serverOnlySigner := newAuthTestSigner(t)
	const password = "valid-password"

	candidates := []autoAuthCandidate{
		{
			protocol: autoAuthProtocolPublicKey,
			label:    "explicit-key",
			method:   ssh.PublicKeys(invalidSigner),
		},
		{
			protocol: autoAuthProtocolPublicKey,
			label:    "empty-agent",
			method: ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
				return nil, nil
			}),
		},
		{
			protocol: autoAuthProtocolPassword,
			label:    "password",
			method:   ssh.Password(password),
		},
	}

	err := runAuthCallbackHandshake(
		t,
		newSequentialAuthCallback(candidates, nil, logger.NopLogger),
		serverOnlySigner.PublicKey(),
		password,
	)
	if err != nil {
		t.Fatalf("password fallback handshake failed: %v", err)
	}
}

func TestBuildAutoAuthPlan_ExplicitKeyPrecedesEncryptedDefaultWithoutPrompt(t *testing.T) {
	home := setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatalf("create test .ssh directory failed: %v", err)
	}

	explicitPath := filepath.Join(t.TempDir(), "explicit_key")
	explicitSigner := writeAuthTestPrivateKey(t, explicitPath)

	const unrelatedPassphrase = "unrelated-default-passphrase"
	encryptedDefault, _ := generateTestEncryptedKey(t, unrelatedPassphrase)
	defaultKeyPath := filepath.Join(sshDir, "id_rsa")
	if err := os.WriteFile(defaultKeyPath, encryptedDefault, 0600); err != nil {
		t.Fatalf("write encrypted default key failed: %v", err)
	}

	ui := &mockUIForTest{passphrase: unrelatedPassphrase}
	plan := buildAutoAuthPlan(t.Context(), AutoAuthOptions{
		LifecycleCtx: t.Context(),
		User:         "testuser",
		Host:         "127.0.0.1",
		KeyPath:      explicitPath,
		Prompter:     ui,
		Logger:       logger.NopLogger,
	})
	if plan.cleanup != nil {
		t.Cleanup(plan.cleanup)
	}

	if len(plan.candidates) < 3 {
		t.Fatalf("expected explicit key, encrypted default key, and password candidates, got %d", len(plan.candidates))
	}
	if got := plan.candidates[0].label; got != "explicit key: "+explicitPath {
		t.Fatalf("first auto auth candidate = %q, want explicit key", got)
	}

	err := runAuthCallbackHandshake(t, plan.authCallback, explicitSigner.PublicKey(), "")
	if err != nil {
		t.Fatalf("explicit key handshake failed: %v", err)
	}
	if ui.called {
		t.Fatal("unrelated encrypted default key prompted for passphrase before explicit key succeeded")
	}
}
