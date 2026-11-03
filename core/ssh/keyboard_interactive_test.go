package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// keyboardInteractiveMockSSHServer sets up an in-memory test SSH server using TCP loopback.
type keyboardInteractiveMockSSHServer struct {
	listener net.Listener
	config   *ssh.ServerConfig
	signer   ssh.Signer
	addr     string
	errCh    chan error
}

func parseTestHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port %q failed: %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port %q failed: %v", portStr, err)
	}
	return host, port
}

func startKeyboardInteractiveMockSSHServer(t *testing.T, config *ssh.ServerConfig) *keyboardInteractiveMockSSHServer {
	t.Helper()

	signer := newAuthTestSigner(t)
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}

	server := &keyboardInteractiveMockSSHServer{
		listener: listener,
		config:   config,
		signer:   signer,
		addr:     listener.Addr().String(),
		errCh:    make(chan error, 1),
	}

	go func() {
		defer close(server.errCh)
		conn, err := listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				server.errCh <- fmt.Errorf("accept error: %w", err)
			}
			return
		}
		defer func() {
			_ = conn.Close()
		}()

		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		sConn, chans, reqs, err := ssh.NewServerConn(conn, config)
		if err != nil {
			server.errCh <- err
			return
		}
		defer func() {
			_ = sConn.Close()
		}()
		go ssh.DiscardRequests(reqs)
		for range chans {
		}
	}()

	t.Cleanup(func() {
		_ = listener.Close()
	})

	return server
}

type testSecretResolverFunc func(ctx context.Context, req SecretRequest) ([]byte, error)

func (f testSecretResolverFunc) ResolveSecret(ctx context.Context, req SecretRequest) ([]byte, error) {
	return f(ctx, req)
}

type testSecretPrompterFunc func(ctx context.Context, req SecretRequest) (string, error)

func (f testSecretPrompterFunc) PromptSecret(ctx context.Context, req SecretRequest) (string, error) {
	return f(ctx, req)
}

// 1. Single-factor keyboard-interactive authentication with prompt context verification
func TestKeyboardInteractive_SingleFactor_Success(t *testing.T) {
	var receivedReq atomic.Value

	serverConfig := &ssh.ServerConfig{
		KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			answers, err := client("Bastion", "Please authenticate", []string{"OTP Token: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			if len(answers) != 1 || answers[0] != "998877" {
				return nil, errors.New("unauthorized OTP")
			}
			return nil, nil
		},
	}
	server := startKeyboardInteractiveMockSSHServer(t, serverConfig)

	host, port := parseTestHostPort(t, server.addr)

	resolver := testSecretResolverFunc(func(ctx context.Context, req SecretRequest) ([]byte, error) {
		receivedReq.Store(req)
		return []byte("998877"), nil
	})

	cfg := &ClientConfig{
		NodeID:   "test-node",
		User:     "ops",
		Address:  host,
		Port:     port,
		AuthType: "keyboard-interactive",
	}

	connector := NewConnector(
		&mockConfigStore{cfg: cfg},
		WithHostKeyVerifier(&fixtureTrust{}),
		WithSecretResolver(resolver),
		WithSecretPrompter(rejectInteraction{}),
	)

	client, err := connector.Connect(t.Context(), cfg.NodeID)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	val := receivedReq.Load()
	if val == nil {
		t.Fatal("expected resolver to be called")
	}
	req := val.(SecretRequest)
	if req.Kind != SecretKindKeyboardInteractive {
		t.Errorf("expected Kind == SecretKindKeyboardInteractive, got %v", req.Kind)
	}
	if req.Prompt != "OTP Token: " {
		t.Errorf("expected Prompt == 'OTP Token: ', got %q", req.Prompt)
	}
	if req.Instruction != "Please authenticate" {
		t.Errorf("expected Instruction == 'Please authenticate', got %q", req.Instruction)
	}
	if req.Echo {
		t.Errorf("expected Echo == false, got true")
	}
	if req.Attempt != 1 {
		t.Errorf("expected Attempt == 1, got %d", req.Attempt)
	}
}

// 2. Empty challenge packet buffering (RFC 4256 len(questions) == 0)
func TestKeyboardInteractive_EmptyChallengeBuffering(t *testing.T) {
	var recordedRequests []SecretRequest
	var mu sync.Mutex

	serverConfig := &ssh.ServerConfig{
		KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			// Round 1: Empty challenge packet with banner and instruction
			emptyAns, err := client("Gateway Banner", "Notice: Maintenance Window", []string{}, []bool{})
			if err != nil {
				return nil, fmt.Errorf("empty challenge failed: %w", err)
			}
			if len(emptyAns) != 0 {
				return nil, fmt.Errorf("expected 0 answers for empty challenge, got %d", len(emptyAns))
			}

			// Round 2: Actual question packet
			answers, err := client("", "Step 2: Authenticate", []string{"Passcode: "}, []bool{true})
			if err != nil {
				return nil, err
			}
			if len(answers) != 1 || answers[0] != "554433" {
				return nil, errors.New("invalid passcode")
			}
			return nil, nil
		},
	}
	server := startKeyboardInteractiveMockSSHServer(t, serverConfig)

	host, port := parseTestHostPort(t, server.addr)

	resolver := testSecretResolverFunc(func(ctx context.Context, req SecretRequest) ([]byte, error) {
		mu.Lock()
		recordedRequests = append(recordedRequests, req)
		mu.Unlock()
		return []byte("554433"), nil
	})

	cfg := &ClientConfig{
		NodeID:   "test-node",
		User:     "ops",
		Address:  host,
		Port:     port,
		AuthType: "otp",
	}

	connector := NewConnector(
		&mockConfigStore{cfg: cfg},
		WithHostKeyVerifier(&fixtureTrust{}),
		WithSecretResolver(resolver),
		WithSecretPrompter(rejectInteraction{}),
	)

	client, err := connector.Connect(t.Context(), cfg.NodeID)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	mu.Lock()
	defer mu.Unlock()

	if len(recordedRequests) != 1 {
		t.Fatalf("expected 1 recorded request, got %d", len(recordedRequests))
	}
	req := recordedRequests[0]
	if !strings.Contains(req.Instruction, "Notice: Maintenance Window") {
		t.Errorf("expected buffered instruction from round 1 in req.Instruction, got %q", req.Instruction)
	}
	if !strings.Contains(req.Instruction, "Step 2: Authenticate") {
		t.Errorf("expected instruction from round 2 in req.Instruction, got %q", req.Instruction)
	}
	if req.Prompt != "Passcode: " {
		t.Errorf("expected Prompt == 'Passcode: ', got %q", req.Prompt)
	}
	if !req.Echo {
		t.Errorf("expected Echo == true, got false")
	}
}

// 3. Prompt and instruction sanitization (stripping ANSI escapes and control chars)
func TestKeyboardInteractive_PromptSanitization(t *testing.T) {
	var capturedReq SecretRequest
	var mu sync.Mutex

	serverConfig := &ssh.ServerConfig{
		KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			dirtyInstruction := "\x1b[1;31mWARNING:\x1b[0m Unauthorized Access Prohibited\r\n"
			dirtyPrompt := "\x1b[32mEnter Code:\x1b[0m \x07"
			answers, err := client("", dirtyInstruction, []string{dirtyPrompt}, []bool{false})
			if err != nil {
				return nil, err
			}
			if len(answers) != 1 || answers[0] != "valid-code" {
				return nil, errors.New("unauthorized")
			}
			return nil, nil
		},
	}
	server := startKeyboardInteractiveMockSSHServer(t, serverConfig)

	host, port := parseTestHostPort(t, server.addr)

	resolver := testSecretResolverFunc(func(ctx context.Context, req SecretRequest) ([]byte, error) {
		mu.Lock()
		capturedReq = req
		mu.Unlock()
		return []byte("valid-code"), nil
	})

	cfg := &ClientConfig{
		NodeID:   "test-node",
		User:     "ops",
		Address:  host,
		Port:     port,
		AuthType: "keyboard-interactive",
	}

	connector := NewConnector(
		&mockConfigStore{cfg: cfg},
		WithHostKeyVerifier(&fixtureTrust{}),
		WithSecretResolver(resolver),
		WithSecretPrompter(rejectInteraction{}),
	)

	client, err := connector.Connect(t.Context(), cfg.NodeID)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	mu.Lock()
	defer mu.Unlock()

	if strings.Contains(capturedReq.Prompt, "\x1b") || strings.Contains(capturedReq.Prompt, "\x07") {
		t.Errorf("prompt contains unescaped ANSI or control chars: %q", capturedReq.Prompt)
	}
	if capturedReq.Prompt != "Enter Code: " {
		t.Errorf("expected sanitized prompt 'Enter Code: ', got %q", capturedReq.Prompt)
	}
	if strings.Contains(capturedReq.Instruction, "\x1b") {
		t.Errorf("instruction contains unescaped ANSI chars: %q", capturedReq.Instruction)
	}
	if !strings.Contains(capturedReq.Instruction, "WARNING: Unauthorized Access Prohibited") {
		t.Errorf("expected sanitized instruction to preserve printable text, got %q", capturedReq.Instruction)
	}
}

// 4. Anti-loop prevention on Attempt > 1: falls back to interactive prompter
func TestKeyboardInteractive_LoopPrevention_FallbackToPrompter(t *testing.T) {
	var resolverAttempts int32
	var prompterAttempts int32

	serverConfig := &ssh.ServerConfig{
		KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			// Round 1: Send challenge. Client will attempt automated answer.
			ans1, err := client("", "", []string{"Verification: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			if len(ans1) != 1 || ans1[0] != "first-attempt-automated" {
				return nil, errors.New("expected automated answer")
			}

			// Server rejects automated answer and asks again (Round 2)
			ans2, err := client("", "Previous attempt failed", []string{"Verification: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			if len(ans2) != 1 || ans2[0] != "second-attempt-prompter" {
				return nil, errors.New("expected prompter answer on retry")
			}
			return nil, nil
		},
	}
	server := startKeyboardInteractiveMockSSHServer(t, serverConfig)

	host, port := parseTestHostPort(t, server.addr)

	resolver := testSecretResolverFunc(func(ctx context.Context, req SecretRequest) ([]byte, error) {
		atomic.AddInt32(&resolverAttempts, 1)
		return []byte("first-attempt-automated"), nil
	})

	prompter := testSecretPrompterFunc(func(ctx context.Context, req SecretRequest) (string, error) {
		atomic.AddInt32(&prompterAttempts, 1)
		if req.Attempt != 2 {
			t.Errorf("expected Attempt == 2 in prompter, got %d", req.Attempt)
		}
		return "second-attempt-prompter", nil
	})

	cfg := &ClientConfig{
		NodeID:   "test-node",
		User:     "ops",
		Address:  host,
		Port:     port,
		AuthType: "keyboard-interactive",
	}

	connector := NewConnector(
		&mockConfigStore{cfg: cfg},
		WithHostKeyVerifier(&fixtureTrust{}),
		WithSecretResolver(resolver),
		WithSecretPrompter(prompter),
	)

	client, err := connector.Connect(t.Context(), cfg.NodeID)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	if atomic.LoadInt32(&resolverAttempts) != 1 {
		t.Errorf("expected resolver to be called exactly once, got %d", atomic.LoadInt32(&resolverAttempts))
	}
	if atomic.LoadInt32(&prompterAttempts) != 1 {
		t.Errorf("expected prompter to be called on Attempt 2, got %d", atomic.LoadInt32(&prompterAttempts))
	}
}

// 5. Anti-loop prevention on Attempt > 1 in non-interactive mode: fails closed immediately
func TestKeyboardInteractive_LoopPrevention_NonInteractive_FailsClosed(t *testing.T) {
	var resolverAttempts int32

	serverConfig := &ssh.ServerConfig{
		KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			// Round 1: Client sends automated answer
			ans1, err := client("", "", []string{"Verification: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			if len(ans1) != 1 || ans1[0] != "rejected-secret" {
				return nil, errors.New("unexpected answer")
			}

			// Round 2: Server asks again. Client should fail closed without looping.
			_, err = client("", "", []string{"Verification: "}, []bool{false})
			return nil, err
		},
	}
	server := startKeyboardInteractiveMockSSHServer(t, serverConfig)

	host, port := parseTestHostPort(t, server.addr)

	resolver := testSecretResolverFunc(func(ctx context.Context, req SecretRequest) ([]byte, error) {
		atomic.AddInt32(&resolverAttempts, 1)
		return []byte("rejected-secret"), nil
	})

	cfg := &ClientConfig{
		NodeID:   "test-node",
		User:     "ops",
		Address:  host,
		Port:     port,
		AuthType: "keyboard-interactive",
	}

	connector := NewConnector(
		&mockConfigStore{cfg: cfg},
		WithHostKeyVerifier(&fixtureTrust{}),
		WithSecretResolver(resolver),
		WithSecretPrompter(rejectInteraction{}), // Non-interactive prompter
	)

	_, err := connector.Connect(t.Context(), cfg.NodeID)
	if err == nil {
		t.Fatal("expected connection to fail closed on rejected automated answer")
	}

	// Verify automated resolver was NOT called more than once
	if attempts := atomic.LoadInt32(&resolverAttempts); attempts != 1 {
		t.Errorf("expected resolver called exactly 1 time before failing closed, got %d", attempts)
	}
}

// 6. Multi-stage MFA: publickey -> keyboard-interactive
func TestKeyboardInteractive_MultiStage_PublicKeyThenKeyboardInteractive(t *testing.T) {
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "id_ed25519")
	clientSigner := writeAuthTestPrivateKey(t, keyPath)

	var stage1KeySeen, stage2OTPSeen bool

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(clientSigner.PublicKey().Marshal()) {
				stage1KeySeen = true
				// Stage 1 passes, but server requires keyboard-interactive
				return nil, &ssh.PartialSuccessError{
					Next: ssh.ServerAuthCallbacks{
						KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
							ans, err := client("", "Second Factor", []string{"OTP: "}, []bool{false})
							if err != nil {
								return nil, err
							}
							if len(ans) == 1 && ans[0] == "888999" {
								stage2OTPSeen = true
								return nil, nil
							}
							return nil, errors.New("unauthorized OTP")
						},
					},
				}
			}
			return nil, errors.New("unauthorized key")
		},
	}
	server := startKeyboardInteractiveMockSSHServer(t, serverConfig)

	host, port := parseTestHostPort(t, server.addr)

	resolver := testSecretResolverFunc(func(ctx context.Context, req SecretRequest) ([]byte, error) {
		if req.Kind == SecretKindKeyboardInteractive && req.Prompt == "OTP: " {
			return []byte("888999"), nil
		}
		return nil, ErrInteractionRequired
	})

	cfg := &ClientConfig{
		NodeID:   "test-node",
		User:     "ops",
		Address:  host,
		Port:     port,
		AuthType: "key",
		KeyPath:  keyPath,
	}

	// Test with AuthType: "key" (single-method auth transitioning to keyboard-interactive)
	connector := NewConnector(
		&mockConfigStore{cfg: cfg},
		WithHostKeyVerifier(&fixtureTrust{}),
		WithSecretResolver(resolver),
		WithSecretPrompter(rejectInteraction{}),
	)

	client, err := connector.Connect(t.Context(), cfg.NodeID)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	if !stage1KeySeen {
		t.Error("expected Stage 1 (publickey) to have succeeded")
	}
	if !stage2OTPSeen {
		t.Error("expected Stage 2 (keyboard-interactive) to have succeeded")
	}
}

// 7. Multi-stage MFA: password -> keyboard-interactive
func TestKeyboardInteractive_MultiStage_PasswordThenKeyboardInteractive(t *testing.T) {
	var stage1PasswordSeen, stage2OTPSeen bool

	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if string(password) == "my-login-password" {
				stage1PasswordSeen = true
				// Stage 1 passes, but server requires keyboard-interactive
				return nil, &ssh.PartialSuccessError{
					Next: ssh.ServerAuthCallbacks{
						KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
							ans, err := client("", "Second Factor", []string{"Verification Code: "}, []bool{false})
							if err != nil {
								return nil, err
							}
							if len(ans) == 1 && ans[0] == "777888" {
								stage2OTPSeen = true
								return nil, nil
							}
							return nil, errors.New("unauthorized OTP")
						},
					},
				}
			}
			return nil, errors.New("unauthorized password")
		},
	}
	server := startKeyboardInteractiveMockSSHServer(t, serverConfig)

	host, port := parseTestHostPort(t, server.addr)

	resolver := testSecretResolverFunc(func(ctx context.Context, req SecretRequest) ([]byte, error) {
		if req.Kind == SecretKindKeyboardInteractive && req.Prompt == "Verification Code: " {
			return []byte("777888"), nil
		}
		return nil, ErrInteractionRequired
	})

	cfg := &ClientConfig{
		NodeID:   "test-node",
		User:     "ops",
		Address:  host,
		Port:     port,
		AuthType: "password",
		Password: "my-login-password",
	}

	connector := NewConnector(
		&mockConfigStore{cfg: cfg},
		WithHostKeyVerifier(&fixtureTrust{}),
		WithSecretResolver(resolver),
		WithSecretPrompter(rejectInteraction{}),
	)

	client, err := connector.Connect(t.Context(), cfg.NodeID)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	if !stage1PasswordSeen {
		t.Error("expected Stage 1 (password) to have succeeded")
	}
	if !stage2OTPSeen {
		t.Error("expected Stage 2 (keyboard-interactive) to have succeeded")
	}
}

// 8. Single-method auth type ("key") with wrong key does NOT fall back to keyboard-interactive
func TestKeyboardInteractive_SingleMethod_NoPartialSuccess_DoesNotFallback(t *testing.T) {
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "id_ed25519")
	writeAuthTestPrivateKey(t, keyPath)

	var kbAttempted bool

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			// Reject key completely (no partial success)
			return nil, errors.New("unknown key")
		},
		KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			kbAttempted = true
			return nil, nil
		},
	}
	server := startKeyboardInteractiveMockSSHServer(t, serverConfig)

	host, port := parseTestHostPort(t, server.addr)

	resolver := testSecretResolverFunc(func(ctx context.Context, req SecretRequest) ([]byte, error) {
		return []byte("any-answer"), nil
	})

	cfg := &ClientConfig{
		NodeID:   "test-node",
		User:     "ops",
		Address:  host,
		Port:     port,
		AuthType: "key",
		KeyPath:  keyPath,
	}

	connector := NewConnector(
		&mockConfigStore{cfg: cfg},
		WithHostKeyVerifier(&fixtureTrust{}),
		WithSecretResolver(resolver),
		WithSecretPrompter(rejectInteraction{}),
	)

	_, err := connector.Connect(t.Context(), cfg.NodeID)
	if err == nil {
		t.Fatal("expected connection to fail when key is rejected")
	}

	if kbAttempted {
		t.Error("keyboard-interactive should NOT have been attempted when key failed without partial success")
	}
}

// 9. Bound query iterations (max 16) terminates runaway server challenge loops
func TestKeyboardInteractive_MaxQueriesBound(t *testing.T) {
	serverConfig := &ssh.ServerConfig{
		KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			for round := 1; round <= 25; round++ {
				_, err := client("", fmt.Sprintf("Round %d", round), []string{fmt.Sprintf("Question %d: ", round)}, []bool{false})
				if err != nil {
					return nil, err
				}
			}
			return nil, nil
		},
	}
	server := startKeyboardInteractiveMockSSHServer(t, serverConfig)

	host, port := parseTestHostPort(t, server.addr)

	resolver := testSecretResolverFunc(func(ctx context.Context, req SecretRequest) ([]byte, error) {
		return []byte("dummy-answer"), nil
	})

	cfg := &ClientConfig{
		NodeID:   "test-node",
		User:     "ops",
		Address:  host,
		Port:     port,
		AuthType: "keyboard-interactive",
	}

	connector := NewConnector(
		&mockConfigStore{cfg: cfg},
		WithHostKeyVerifier(&fixtureTrust{}),
		WithSecretResolver(resolver),
		WithSecretPrompter(rejectInteraction{}),
	)

	_, err := connector.Connect(t.Context(), cfg.NodeID)
	if err == nil {
		t.Fatal("expected connection to fail when server exceeds query limit")
	}

	if !strings.Contains(err.Error(), "maximum keyboard-interactive challenge limit") {
		t.Errorf("expected error mentioning maximum challenge limit, got: %v", err)
	}
}

// 10. Multi-stage MFA in auto mode: explicit key -> keyboard-interactive
func TestKeyboardInteractive_AutoMode_PublicKeyThenKeyboardInteractive(t *testing.T) {
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "id_ed25519")
	clientSigner := writeAuthTestPrivateKey(t, keyPath)

	var stage1KeySeen, stage2OTPSeen bool

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(clientSigner.PublicKey().Marshal()) {
				stage1KeySeen = true
				return nil, &ssh.PartialSuccessError{
					Next: ssh.ServerAuthCallbacks{
						KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
							ans, err := client("", "", []string{"OTP: "}, []bool{false})
							if err != nil {
								return nil, err
							}
							if len(ans) == 1 && ans[0] == "auto-otp-code" {
								stage2OTPSeen = true
								return nil, nil
							}
							return nil, errors.New("unauthorized OTP")
						},
					},
				}
			}
			return nil, errors.New("unauthorized key")
		},
	}
	server := startKeyboardInteractiveMockSSHServer(t, serverConfig)

	host, port := parseTestHostPort(t, server.addr)

	resolver := testSecretResolverFunc(func(ctx context.Context, req SecretRequest) ([]byte, error) {
		if req.Kind == SecretKindKeyboardInteractive && req.Prompt == "OTP: " {
			return []byte("auto-otp-code"), nil
		}
		return nil, ErrInteractionRequired
	})

	cfg := &ClientConfig{
		NodeID:   "test-node",
		User:     "ops",
		Address:  host,
		Port:     port,
		AuthType: "auto",
		KeyPath:  keyPath,
	}

	connector := NewConnector(
		&mockConfigStore{cfg: cfg},
		WithHostKeyVerifier(&fixtureTrust{}),
		WithSecretResolver(resolver),
		WithSecretPrompter(rejectInteraction{}),
	)

	client, err := connector.Connect(t.Context(), cfg.NodeID)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	if !stage1KeySeen || !stage2OTPSeen {
		t.Errorf("auto mode MFA failed: stage1=%v, stage2=%v", stage1KeySeen, stage2OTPSeen)
	}
}

// 11. Explicit keyboard-interactive/otp mode does NOT fall back to single-factor password when keyboard-interactive fails
func TestKeyboardInteractive_ExplicitMode_DoesNotFallbackToSingleFactorPassword(t *testing.T) {
	var passwordAttempted atomic.Bool

	serverConfig := &ssh.ServerConfig{
		KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			_, err := client("", "", []string{"OTP: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			return nil, errors.New("rejected otp")
		},
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			passwordAttempted.Store(true)
			return nil, nil
		},
	}
	server := startKeyboardInteractiveMockSSHServer(t, serverConfig)
	host, port := parseTestHostPort(t, server.addr)

	prompter := testSecretPrompterFunc(func(ctx context.Context, req SecretRequest) (string, error) {
		return "wrong-user-typed-otp", nil
	})

	cfg := &ClientConfig{
		NodeID:   "test-node",
		User:     "ops",
		Address:  host,
		Port:     port,
		AuthType: "otp",
		Password: "should-not-be-used",
	}

	connector := NewConnector(
		&mockConfigStore{cfg: cfg},
		WithHostKeyVerifier(&fixtureTrust{}),
		WithSecretPrompter(prompter),
	)

	_, err := connector.Connect(t.Context(), cfg.NodeID)
	if err == nil {
		t.Fatal("expected connection to fail when OTP is rejected")
	}
	if passwordAttempted.Load() {
		t.Fatal("explicit otp auth_type must not fall back to single-factor password after keyboard-interactive failure")
	}
}

// 12. Single-method MFA transition attempts keyboard-interactive once per partial-success stage
func TestKeyboardInteractive_SingleMethodTransition_OncePerStageOnServerReject(t *testing.T) {
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "id_ed25519")
	clientSigner := writeAuthTestPrivateKey(t, keyPath)

	var kbMethodInvocations atomic.Int32

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(clientSigner.PublicKey().Marshal()) {
				return nil, &ssh.PartialSuccessError{
					Next: ssh.ServerAuthCallbacks{
						KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
							n := kbMethodInvocations.Add(1)
							_, err := client("", "", []string{fmt.Sprintf("Dynamic Nonce [%d]: ", n)}, []bool{false})
							if err != nil {
								return nil, err
							}
							return nil, errors.New("wrong otp")
						},
					},
				}
			}
			return nil, errors.New("unauthorized key")
		},
	}
	server := startKeyboardInteractiveMockSSHServer(t, serverConfig)
	host, port := parseTestHostPort(t, server.addr)

	prompter := testSecretPrompterFunc(func(ctx context.Context, req SecretRequest) (string, error) {
		return "wrong-otp", nil
	})

	cfg := &ClientConfig{
		NodeID:   "test-node",
		User:     "ops",
		Address:  host,
		Port:     port,
		AuthType: "key",
		KeyPath:  keyPath,
	}

	connector := NewConnector(
		&mockConfigStore{cfg: cfg},
		WithHostKeyVerifier(&fixtureTrust{}),
		WithSecretPrompter(prompter),
	)

	_, err := connector.Connect(t.Context(), cfg.NodeID)
	if err == nil {
		t.Fatal("expected connection to fail when second-factor OTP is rejected")
	}
	if got := kbMethodInvocations.Load(); got != 1 {
		t.Fatalf("expected keyboard-interactive method to be invoked once for the stage, got %d", got)
	}
}

// 13. Auto mode: when password candidate is rejected without partial success and keyboard-interactive succeeds, rejected password is NOT persisted
func TestKeyboardInteractive_AutoMode_RejectedPasswordNotPersisted(t *testing.T) {
	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			return nil, errors.New("password rejected")
		},
		KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			ans, err := client("", "", []string{"OTP: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			if len(ans) == 1 && ans[0] == "valid-otp-999" {
				return nil, nil
			}
			return nil, errors.New("unauthorized otp")
		},
	}
	server := startKeyboardInteractiveMockSSHServer(t, serverConfig)
	host, port := parseTestHostPort(t, server.addr)

	store := &characterizationRecordingStore{
		cfg: &ClientConfig{
			NodeID:          "test-node",
			User:            "ops",
			Address:         host,
			Port:            port,
			AuthType:        "auto",
			AuthUpdateToken: "token-v1",
		},
	}

	prompter := testSecretPrompterFunc(func(ctx context.Context, req SecretRequest) (string, error) {
		switch req.Kind {
		case SecretKindLoginPassword:
			return "rejected-password-should-not-save", nil
		case SecretKindKeyboardInteractive:
			return "valid-otp-999", nil
		default:
			return "", ErrInteractionRequired
		}
	})

	connector := NewConnector(
		store,
		WithHostKeyVerifier(&fixtureTrust{}),
		WithSecretPrompter(prompter),
	)

	client, err := connector.Connect(t.Context(), "test-node")
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	if store.updateCalls != 0 || store.lastPassword != "" {
		t.Fatalf("rejected password was unexpectedly persisted: updateCalls=%d, lastPassword=%q", store.updateCalls, store.lastPassword)
	}
}
