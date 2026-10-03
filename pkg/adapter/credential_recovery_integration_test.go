//go:build integration && (linux || windows || darwin) && (amd64 || arm64)

package adapter_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	coreauth "github.com/wentf9/xops-cli/core/auth"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/internal/credentialfile/format"
	"github.com/wentf9/xops-cli/internal/sshenv"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	cryptoSSH "golang.org/x/crypto/ssh"
)

// Exercise the actual offline backend's error classification, not an injected
// generic unavailable error. Corruption must allow only temporary input.
func TestRecoveryCorruptOfflineVault(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	// Use a physical path: macOS /var is a symlink, which vaults reject.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
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
	resolver := recoveryResolverFunc(func(ctx context.Context, _ ssh.SecretRequest) ([]byte, error) {
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

func testCorruptVaultConnection(t *testing.T, resolver ssh.SecretResolver) {
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
	provider := &characterizationRecordingStore{cfg: &ssh.ClientConfig{NodeID: "test", Address: host, Port: port, User: "test", AuthType: "password", AuthUpdateToken: "auth-old", SudoUpdateToken: "sudo-old"}}
	ui := &recoveryTestUI{values: []string{"valid-password"}}
	connector := ssh.NewConnector(provider, ssh.WithEnvironment(sshenv.Discover()), ssh.WithInteractionHandler(ui), ssh.WithSecretResolver(resolver), ssh.WithCredentialRecorder(failedRecoveryRecorder{}), ssh.WithHandshakeTimeout(2*time.Second))
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
	if client.ConnectionConfig().AuthUpdateToken != "" || client.ConnectionConfig().SudoUpdateToken != "" {
		t.Fatal("failed save retained write authorization")
	}
	if _, err := client.Run(ctx, "true"); err != nil {
		t.Fatalf("temporary authenticated connection was closed: %v", err)
	}
}

// The real backend error feeds the same public classifier used by core SSH.
// Prompt/cancellation policy for every secret kind is exercised in core tests;
// the connection test above composes this backend with a real SSH handshake.
func testCorruptVaultInputPolicies(t *testing.T, resolver ssh.SecretResolver) {
	t.Helper()
	for _, kind := range []ssh.SecretKind{ssh.SecretKindLoginPassword, ssh.SecretKindPrivateKeyPassphrase, ssh.SecretKindSudoPassword, ssh.SecretKindSuPassword} {
		_, err := resolver.ResolveSecret(t.Context(), ssh.SecretRequest{Kind: kind})
		if !errors.Is(err, format.ErrCorrupt) || !coreauth.RecoverableRead(err) {
			t.Fatalf("real corrupt backend lost recoverable classification for %v: %v", kind, err)
		}
		if coreauth.RecoverableRead(errors.Join(err, context.Canceled)) {
			t.Fatal("corruption must not override cancellation")
		}
	}
}

type recoveryResolverFunc func(context.Context, ssh.SecretRequest) ([]byte, error)

func (f recoveryResolverFunc) ResolveSecret(ctx context.Context, req ssh.SecretRequest) ([]byte, error) {
	return f(ctx, req)
}

type characterizationRecordingStore struct{ cfg *ssh.ClientConfig }

func (s *characterizationRecordingStore) GetConfig(string) (*ssh.ClientConfig, error) {
	copy := *s.cfg
	return &copy, nil
}

type recoveryTestUI struct {
	values  []string
	prompts int
}

func (u *recoveryTestUI) CredentialRecoveryAllowed() bool                       { return true }
func (u *recoveryTestUI) ReportCredentialFailure(context.Context, string) error { return nil }
func (u *recoveryTestUI) ConfirmHostKey(context.Context, ssh.HostKeyConfirmation) (bool, error) {
	return true, nil
}
func (u *recoveryTestUI) PromptSecret(context.Context, ssh.SecretRequest) (string, error) {
	if u.prompts >= len(u.values) {
		return "", errors.New("unexpected credential prompt")
	}
	value := u.values[u.prompts]
	u.prompts++
	return value, nil
}

type failedRecoveryRecorder struct{}

func (failedRecoveryRecorder) UpdateAuth(context.Context, string, string, string, string, string) (string, error) {
	return "", coreauth.ErrCredentialStoreUnavailable
}
func (failedRecoveryRecorder) UpdateSudo(context.Context, string, string, ssh.SudoMode, string) (string, error) {
	return "", coreauth.ErrCredentialStoreUnavailable
}

func startTestAutoSSHServer(t *testing.T, password string) (string, <-chan struct{}, func()) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptoSSH.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &cryptoSSH.ServerConfig{PasswordCallback: func(_ cryptoSSH.ConnMetadata, supplied []byte) (*cryptoSSH.Permissions, error) {
		if string(supplied) != password {
			return nil, errors.New("wrong fixture password")
		}
		return nil, nil
	}}
	cfg.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	var mu sync.Mutex
	connections := make(map[net.Conn]struct{})
	var workers sync.WaitGroup
	done := make(chan struct{})
	workers.Add(1)
	// Listener closure ends accept; shutdown closes active transports and joins workers.
	go func() {
		defer workers.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if ctx.Err() != nil {
				mu.Unlock()
				if err := conn.Close(); err != nil {
					t.Error(err)
				}
				return
			}
			connections[conn] = struct{}{}
			mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() {
					mu.Lock()
					delete(connections, conn)
					mu.Unlock()
					if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
						t.Error(err)
					}
				}()
				if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Error(err)
					return
				}
				server, channels, requests, err := cryptoSSH.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				defer func() {
					if err := server.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
						t.Error(err)
					}
				}()
				requestsDone := make(chan struct{})
				// Closing the owning connection ends the request stream.
				go func() { cryptoSSH.DiscardRequests(requests); close(requestsDone) }()
				defer func() {
					if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
						t.Error(err)
					}
					<-requestsDone
				}()
				for incoming := range channels {
					channel, requestStream, err := incoming.Accept()
					if err != nil {
						t.Error(err)
						return
					}
					for request := range requestStream {
						if request.Type != "exec" {
							if err := request.Reply(false, nil); err != nil {
								t.Error(err)
							}
							continue
						}
						if err := request.Reply(true, nil); err != nil {
							t.Error(err)
						}
						if _, err := io.WriteString(channel, "fixture-ok"); err != nil {
							t.Error(err)
						}
						if _, err := channel.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0})); err != nil {
							t.Error(err)
						}
						break
					}
					if err := channel.Close(); err != nil && !errors.Is(err, io.EOF) {
						t.Error(err)
					}
				}
			}()
		}
	}()
	return listener.Addr().String(), done, func() {
		cancel()
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
		mu.Lock()
		for conn := range connections {
			if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				t.Error(err)
			}
		}
		mu.Unlock()
		workers.Wait()
		close(done)
	}
}
