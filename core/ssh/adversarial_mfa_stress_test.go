package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// concurrentAdversarialMockSSHServer supports multiple concurrent connections.
type concurrentAdversarialMockSSHServer struct {
	listener net.Listener
	config   *ssh.ServerConfig
	addr     string
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

func startConcurrentAdversarialMockSSHServer(t *testing.T, config *ssh.ServerConfig) *concurrentAdversarialMockSSHServer {
	t.Helper()

	signer := newAuthTestSigner(t)
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}

	server := &concurrentAdversarialMockSSHServer{
		listener: listener,
		config:   config,
		addr:     listener.Addr().String(),
		stopCh:   make(chan struct{}),
	}

	server.wg.Add(1)
	go func() {
		defer server.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-server.stopCh:
					return
				default:
					return
				}
			}

			server.wg.Add(1)
			go func(c net.Conn) {
				defer server.wg.Done()
				defer func() {
					_ = c.Close()
				}()

				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				sConn, chans, reqs, err := ssh.NewServerConn(c, config)
				if err != nil {
					return
				}
				defer func() {
					_ = sConn.Close()
				}()

				go ssh.DiscardRequests(reqs)
				for range chans {
				}
			}(conn)
		}
	}()

	t.Cleanup(func() {
		close(server.stopCh)
		_ = listener.Close()
		server.wg.Wait()
	})

	return server
}

// 1. Multi-Stage MFA: publickey -> password -> keyboard-interactive (3-stage MFA)
func TestAdversarial_ThreeStageMFA_AutoMode_PublicKey_Password_KeyboardInteractive(t *testing.T) {
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "id_ed25519")
	clientSigner := writeAuthTestPrivateKey(t, keyPath)

	var (
		stage1KeySeen      atomic.Bool
		stage2PasswordSeen atomic.Bool
		stage3OTPSeen      atomic.Bool
	)

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(clientSigner.PublicKey().Marshal()) {
				stage1KeySeen.Store(true)
				// Stage 1 passes -> require Stage 2 (password)
				return nil, &ssh.PartialSuccessError{
					Next: ssh.ServerAuthCallbacks{
						PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
							if string(password) == "adv-password-secret" {
								stage2PasswordSeen.Store(true)
								// Stage 2 passes -> require Stage 3 (keyboard-interactive)
								return nil, &ssh.PartialSuccessError{
									Next: ssh.ServerAuthCallbacks{
										KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
											ans, err := client("", "Factor 3", []string{"MFA Code: "}, []bool{false})
											if err != nil {
												return nil, err
											}
											if len(ans) == 1 && ans[0] == "887766" {
												stage3OTPSeen.Store(true)
												return nil, nil // Full success!
											}
											return nil, errors.New("unauthorized OTP")
										},
									},
								}
							}
							return nil, errors.New("unauthorized password")
						},
					},
				}
			}
			return nil, errors.New("unauthorized key")
		},
	}

	server := startConcurrentAdversarialMockSSHServer(t, serverConfig)
	host, port := parseTestHostPort(t, server.addr)

	resolver := testSecretResolverFunc(func(ctx context.Context, req SecretRequest) ([]byte, error) {
		switch req.Kind {
		case SecretKindLoginPassword:
			return []byte("adv-password-secret"), nil
		case SecretKindKeyboardInteractive:
			if req.Prompt == "MFA Code: " {
				return []byte("887766"), nil
			}
		}
		return nil, ErrInteractionRequired
	})

	cfg := &ClientConfig{
		NodeID:   "adv-node-3stage",
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
		t.Fatalf("3-stage Connect failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	if !stage1KeySeen.Load() {
		t.Error("Stage 1 (publickey) was not executed")
	}
	if !stage2PasswordSeen.Load() {
		t.Error("Stage 2 (password) was not executed")
	}
	if !stage3OTPSeen.Load() {
		t.Error("Stage 3 (keyboard-interactive) was not executed")
	}
}

// 2. Multi-Stage MFA: Failure at Stage 2 terminates without infinite loop
func TestAdversarial_ThreeStageMFA_PasswordFailureAtStage2(t *testing.T) {
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "id_ed25519")
	clientSigner := writeAuthTestPrivateKey(t, keyPath)

	var (
		stage1KeySeen atomic.Bool
		pwAttempts    atomic.Int32
	)

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(clientSigner.PublicKey().Marshal()) {
				stage1KeySeen.Store(true)
				return nil, &ssh.PartialSuccessError{
					Next: ssh.ServerAuthCallbacks{
						PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
							pwAttempts.Add(1)
							return nil, errors.New("wrong password at stage 2")
						},
					},
				}
			}
			return nil, errors.New("unauthorized key")
		},
	}

	server := startConcurrentAdversarialMockSSHServer(t, serverConfig)
	host, port := parseTestHostPort(t, server.addr)

	resolver := testSecretResolverFunc(func(ctx context.Context, req SecretRequest) ([]byte, error) {
		if req.Kind == SecretKindLoginPassword {
			return []byte("incorrect-password"), nil
		}
		return nil, ErrInteractionRequired
	})

	cfg := &ClientConfig{
		NodeID:   "adv-node-stage2-fail",
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

	_, err := connector.Connect(t.Context(), cfg.NodeID)
	if err == nil {
		t.Fatal("expected connection to fail when stage 2 password is rejected")
	}

	if !stage1KeySeen.Load() {
		t.Error("Stage 1 should have passed before stage 2 failure")
	}
	// PasswordCallback has retry limit of 3
	if attempts := pwAttempts.Load(); attempts < 1 || attempts > 3 {
		t.Errorf("expected between 1 and 3 password attempts, got %d", attempts)
	}
}

// 3. Multi-Stage MFA: Loop prevention on rejected automated answer at Stage 3
func TestAdversarial_ThreeStageMFA_LoopPreventionAtStage3(t *testing.T) {
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "id_ed25519")
	clientSigner := writeAuthTestPrivateKey(t, keyPath)

	var (
		stage1KeySeen atomic.Bool
		stage2PWSeen  atomic.Bool
		kbAttempts    atomic.Int32
		resCalls      atomic.Int32
	)

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(clientSigner.PublicKey().Marshal()) {
				stage1KeySeen.Store(true)
				return nil, &ssh.PartialSuccessError{
					Next: ssh.ServerAuthCallbacks{
						PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
							if string(password) == "valid-pw" {
								stage2PWSeen.Store(true)
								return nil, &ssh.PartialSuccessError{
									Next: ssh.ServerAuthCallbacks{
										KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
											kbAttempts.Add(1)
											// Challenge repeats to try to trigger infinite loop
											ans, err := client("", "Factor 3", []string{"Token: "}, []bool{false})
											if err != nil {
												return nil, err
											}
											if len(ans) == 1 && ans[0] == "correct-token" {
												return nil, nil
											}
											return nil, errors.New("bad token")
										},
									},
								}
							}
							return nil, errors.New("unauthorized password")
						},
					},
				}
			}
			return nil, errors.New("unauthorized key")
		},
	}

	server := startConcurrentAdversarialMockSSHServer(t, serverConfig)
	host, port := parseTestHostPort(t, server.addr)

	// Resolver returns valid password for stage 2, but wrong token for stage 3
	resolver := testSecretResolverFunc(func(ctx context.Context, req SecretRequest) ([]byte, error) {
		switch req.Kind {
		case SecretKindLoginPassword:
			return []byte("valid-pw"), nil
		case SecretKindKeyboardInteractive:
			resCalls.Add(1)
			return []byte("wrong-token"), nil
		}
		return nil, ErrInteractionRequired
	})

	cfg := &ClientConfig{
		NodeID:   "adv-node-stage3-loop",
		User:     "ops",
		Address:  host,
		Port:     port,
		AuthType: "auto",
		KeyPath:  keyPath,
	}

	// Non-interactive prompter (rejectInteraction) ensures fail-closed on Attempt > 1
	connector := NewConnector(
		&mockConfigStore{cfg: cfg},
		WithHostKeyVerifier(&fixtureTrust{}),
		WithSecretResolver(resolver),
		WithSecretPrompter(rejectInteraction{}),
	)

	_, err := connector.Connect(t.Context(), cfg.NodeID)
	if err == nil {
		t.Fatal("expected connection to fail on rejected stage 3 token")
	}

	if !stage1KeySeen.Load() || !stage2PWSeen.Load() {
		t.Errorf("stages 1 and 2 should have passed: s1=%v, s2=%v", stage1KeySeen.Load(), stage2PWSeen.Load())
	}

	// Automated resolver must be called at most once for keyboard-interactive due to anti-loop check
	if calls := resCalls.Load(); calls != 1 {
		t.Errorf("expected resolver called exactly 1 time for keyboard-interactive, got %d", calls)
	}
}

// 4. Candidate Reset: Multi-key MFA where earlier candidate is re-evaluated after partial success
func TestAdversarial_CandidateReset_DualPublicKeyMFA(t *testing.T) {
	tempDir := t.TempDir()
	keyPathA := filepath.Join(tempDir, "id_key_a")
	keyPathB := filepath.Join(tempDir, "id_key_b")

	signerA := writeAuthTestPrivateKey(t, keyPathA)
	signerB := writeAuthTestPrivateKey(t, keyPathB)

	var (
		stage1KeyBSeen atomic.Bool
		stage2KeyASeen atomic.Bool
	)

	// Server requires:
	// Stage 1: Key B (Key A is rejected) -> PartialSuccess
	// Stage 2: Key A (Key B is rejected) -> Success
	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			keyStr := string(key.Marshal())
			if !stage1KeyBSeen.Load() {
				// Stage 1: only accept Key B
				if keyStr == string(signerB.PublicKey().Marshal()) {
					stage1KeyBSeen.Store(true)
					return nil, &ssh.PartialSuccessError{
						Next: ssh.ServerAuthCallbacks{
							PublicKeyCallback: func(conn ssh.ConnMetadata, key2 ssh.PublicKey) (*ssh.Permissions, error) {
								// Stage 2: only accept Key A
								if string(key2.Marshal()) == string(signerA.PublicKey().Marshal()) {
									stage2KeyASeen.Store(true)
									return nil, nil
								}
								return nil, errors.New("stage 2 requires Key A")
							},
						},
					}
				}
				return nil, errors.New("stage 1 requires Key B")
			}
			return nil, errors.New("unexpected auth state")
		},
	}

	server := startConcurrentAdversarialMockSSHServer(t, serverConfig)

	// Build auto auth plan manually with candidates [Key A, Key B] to verify candidate reset
	candA, err := resolveKeyAuthMethod(keyPathA, nil, nil, nil)
	if err != nil {
		t.Fatalf("resolve key A failed: %v", err)
	}
	candB, err := resolveKeyAuthMethod(keyPathB, nil, nil, nil)
	if err != nil {
		t.Fatalf("resolve key B failed: %v", err)
	}

	candidates := []autoAuthCandidate{
		{protocol: autoAuthProtocolPublicKey, label: "key-a", method: candA},
		{protocol: autoAuthProtocolPublicKey, label: "key-b", method: candB},
	}

	authCb := newSequentialAuthCallback(candidates, nil, nil)

	sshClientConfig := &ssh.ClientConfig{
		User:            "ops",
		AuthCallback:    authCb,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	clientConn, err := net.Dial("tcp", server.addr)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer func() {
		_ = clientConn.Close()
	}()

	sConn, chans, reqs, err := ssh.NewClientConn(clientConn, server.addr, sshClientConfig)
	if err != nil {
		t.Fatalf("Dual publickey handshake failed: %v", err)
	}
	defer func() {
		_ = sConn.Close()
	}()
	go ssh.DiscardRequests(reqs)
	for range chans {
	}

	if !stage1KeyBSeen.Load() {
		t.Error("Stage 1 Key B was not accepted")
	}
	if !stage2KeyASeen.Load() {
		t.Error("Stage 2 Key A was not re-evaluated after candidate reset")
	}
}

// 5. Candidate Reset: No reset on hard failure (prevents infinite loops)
func TestAdversarial_NoResetOnHardFailure(t *testing.T) {
	tempDir := t.TempDir()
	keyPathA := filepath.Join(tempDir, "id_key_a")
	keyPathB := filepath.Join(tempDir, "id_key_b")

	_ = writeAuthTestPrivateKey(t, keyPathA)
	signerB := writeAuthTestPrivateKey(t, keyPathB)

	var keyAAttempts, keyBAttempts atomic.Int32

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(signerB.PublicKey().Marshal()) {
				keyBAttempts.Add(1)
				return nil, nil // Key B succeeds directly (no partial success)
			}
			keyAAttempts.Add(1)
			return nil, errors.New("key A rejected")
		},
	}

	server := startConcurrentAdversarialMockSSHServer(t, serverConfig)

	candA, _ := resolveKeyAuthMethod(keyPathA, nil, nil, nil)
	candB, _ := resolveKeyAuthMethod(keyPathB, nil, nil, nil)

	candidates := []autoAuthCandidate{
		{protocol: autoAuthProtocolPublicKey, label: "key-a", method: candA},
		{protocol: autoAuthProtocolPublicKey, label: "key-b", method: candB},
	}

	authCb := newSequentialAuthCallback(candidates, nil, nil)

	sshClientConfig := &ssh.ClientConfig{
		User:            "ops",
		AuthCallback:    authCb,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	clientConn, err := net.Dial("tcp", server.addr)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer func() {
		_ = clientConn.Close()
	}()

	sConn, chans, reqs, err := ssh.NewClientConn(clientConn, server.addr, sshClientConfig)
	if err != nil {
		t.Fatalf("Client connection failed: %v", err)
	}
	defer func() {
		_ = sConn.Close()
	}()
	go ssh.DiscardRequests(reqs)
	for range chans {
	}

	if a := keyAAttempts.Load(); a != 1 {
		t.Errorf("Key A should have been tried exactly once before advancing, got %d", a)
	}
	if b := keyBAttempts.Load(); b != 1 {
		t.Errorf("Key B should have succeeded on first attempt, got %d", b)
	}
}

// 6. Multi-Stage MFA: Two sequential keyboard-interactive factors
func TestAdversarial_MultiStage_TwoSequentialKeyboardInteractive(t *testing.T) {
	var (
		stage1Seen atomic.Bool
		stage2Seen atomic.Bool
	)

	serverConfig := &ssh.ServerConfig{
		KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			if !stage1Seen.Load() {
				ans, err := client("", "Step 1", []string{"Password: "}, []bool{false})
				if err != nil {
					return nil, err
				}
				if len(ans) == 1 && ans[0] == "first-secret" {
					stage1Seen.Store(true)
					return nil, &ssh.PartialSuccessError{
						Next: ssh.ServerAuthCallbacks{
							KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client2 ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
								ans2, err := client2("", "Step 2", []string{"Hardware Token: "}, []bool{false})
								if err != nil {
									return nil, err
								}
								if len(ans2) == 1 && ans2[0] == "second-token" {
									stage2Seen.Store(true)
									return nil, nil
								}
								return nil, errors.New("bad hardware token")
							},
						},
					}
				}
				return nil, errors.New("bad first secret")
			}
			return nil, errors.New("unexpected state")
		},
	}

	server := startConcurrentAdversarialMockSSHServer(t, serverConfig)
	host, port := parseTestHostPort(t, server.addr)

	resolver := testSecretResolverFunc(func(ctx context.Context, req SecretRequest) ([]byte, error) {
		if req.Prompt == "Password: " {
			return []byte("first-secret"), nil
		}
		if req.Prompt == "Hardware Token: " {
			return []byte("second-token"), nil
		}
		return nil, ErrInteractionRequired
	})

	cfg := &ClientConfig{
		NodeID:   "adv-node-dual-kb",
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
		t.Fatalf("Dual keyboard-interactive Connect failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	if !stage1Seen.Load() || !stage2Seen.Load() {
		t.Errorf("Both keyboard-interactive stages must succeed: s1=%v, s2=%v", stage1Seen.Load(), stage2Seen.Load())
	}
}

// 7. Concurrency & High Load Stress Testing: 30 concurrent multi-stage MFA connections
func TestAdversarial_Concurrency_MultiStageStress(t *testing.T) {
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "id_ed25519")
	clientSigner := writeAuthTestPrivateKey(t, keyPath)

	var successCount atomic.Int32

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(clientSigner.PublicKey().Marshal()) {
				return nil, &ssh.PartialSuccessError{
					Next: ssh.ServerAuthCallbacks{
						PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
							if string(password) == "stress-pwd" {
								return nil, &ssh.PartialSuccessError{
									Next: ssh.ServerAuthCallbacks{
										KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
											ans, err := client("", "", []string{"OTP: "}, []bool{false})
											if err != nil {
												return nil, err
											}
											if len(ans) == 1 && ans[0] == "123456" {
												return nil, nil
											}
											return nil, errors.New("bad otp")
										},
									},
								}
							}
							return nil, errors.New("bad password")
						},
					},
				}
			}
			return nil, errors.New("bad key")
		},
	}

	server := startConcurrentAdversarialMockSSHServer(t, serverConfig)
	host, port := parseTestHostPort(t, server.addr)

	resolver := testSecretResolverFunc(func(ctx context.Context, req SecretRequest) ([]byte, error) {
		switch req.Kind {
		case SecretKindLoginPassword:
			return []byte("stress-pwd"), nil
		case SecretKindKeyboardInteractive:
			if req.Prompt == "OTP: " {
				return []byte("123456"), nil
			}
		}
		return nil, ErrInteractionRequired
	})

	const numWorkers = 30
	var wg sync.WaitGroup
	errCh := make(chan error, numWorkers)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			cfg := &ClientConfig{
				NodeID:   fmt.Sprintf("stress-node-%d", id),
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
				errCh <- fmt.Errorf("worker %d failed: %w", id, err)
				return
			}
			defer func() {
				_ = client.Close()
			}()

			successCount.Add(1)
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent stress error: %v", err)
	}

	if count := successCount.Load(); count != numWorkers {
		t.Fatalf("expected %d successful connections, got %d", numWorkers, count)
	}
}

// 8. Goroutine Leak Detection across repeated handshakes
func TestAdversarial_GoroutineLeakDetection(t *testing.T) {
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "id_ed25519")
	clientSigner := writeAuthTestPrivateKey(t, keyPath)

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(clientSigner.PublicKey().Marshal()) {
				return nil, &ssh.PartialSuccessError{
					Next: ssh.ServerAuthCallbacks{
						KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
							ans, err := client("", "", []string{"Code: "}, []bool{false})
							if err != nil {
								return nil, err
							}
							if len(ans) == 1 && ans[0] == "554433" {
								return nil, nil
							}
							return nil, errors.New("bad code")
						},
					},
				}
			}
			return nil, errors.New("bad key")
		},
	}

	server := startConcurrentAdversarialMockSSHServer(t, serverConfig)
	host, port := parseTestHostPort(t, server.addr)

	resolver := testSecretResolverFunc(func(ctx context.Context, req SecretRequest) ([]byte, error) {
		if req.Kind == SecretKindKeyboardInteractive {
			return []byte("554433"), nil
		}
		return nil, ErrInteractionRequired
	})

	// Run warm-up connection
	cfg := &ClientConfig{
		NodeID:   "leak-warmup",
		User:     "ops",
		Address:  host,
		Port:     port,
		AuthType: "key",
		KeyPath:  keyPath,
	}
	conn := NewConnector(
		&mockConfigStore{cfg: cfg},
		WithHostKeyVerifier(&fixtureTrust{}),
		WithSecretResolver(resolver),
		WithSecretPrompter(rejectInteraction{}),
	)
	c, err := conn.Connect(t.Context(), cfg.NodeID)
	if err != nil {
		t.Fatalf("warmup failed: %v", err)
	}
	_ = c.Close()

	// Stabilize and record baseline goroutines
	time.Sleep(50 * time.Millisecond)
	baselineGoroutines := runtime.NumGoroutine()

	// Execute 20 sequential handshakes
	for i := 0; i < 20; i++ {
		iterCfg := &ClientConfig{
			NodeID:   fmt.Sprintf("leak-iter-%d", i),
			User:     "ops",
			Address:  host,
			Port:     port,
			AuthType: "key",
			KeyPath:  keyPath,
		}
		iterConn := NewConnector(
			&mockConfigStore{cfg: iterCfg},
			WithHostKeyVerifier(&fixtureTrust{}),
			WithSecretResolver(resolver),
			WithSecretPrompter(rejectInteraction{}),
		)
		client, connErr := iterConn.Connect(t.Context(), iterCfg.NodeID)
		if connErr != nil {
			t.Fatalf("iter %d connect failed: %v", i, connErr)
		}
		_ = client.Close()
	}

	// Give a small grace period for goroutine teardown
	time.Sleep(100 * time.Millisecond)
	finalGoroutines := runtime.NumGoroutine()

	// A leak would show ~20-40 leaked goroutines. A variance of <= 5 is normal runtime noise.
	diff := finalGoroutines - baselineGoroutines
	if diff > 5 {
		t.Errorf("Potential goroutine leak detected: baseline=%d, final=%d, diff=%d",
			baselineGoroutines, finalGoroutines, diff)
	}
}

// 9. Context cancellation during multi-stage MFA aborts promptly without hanging
func TestAdversarial_ContextCancellationDuringMultiStage(t *testing.T) {
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "id_ed25519")
	clientSigner := writeAuthTestPrivateKey(t, keyPath)

	var stage2Once sync.Once
	stage2Entered := make(chan struct{})

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(clientSigner.PublicKey().Marshal()) {
				return nil, &ssh.PartialSuccessError{
					Next: ssh.ServerAuthCallbacks{
						PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
							stage2Once.Do(func() {
								close(stage2Entered)
							})
							// Simulate stall waiting on slow backend
							time.Sleep(2 * time.Second)
							return nil, errors.New("timeout")
						},
					},
				}
			}
			return nil, errors.New("bad key")
		},
	}

	server := startConcurrentAdversarialMockSSHServer(t, serverConfig)
	host, port := parseTestHostPort(t, server.addr)

	resolver := testSecretResolverFunc(func(ctx context.Context, req SecretRequest) ([]byte, error) {
		if req.Kind == SecretKindLoginPassword {
			return []byte("some-password"), nil
		}
		return nil, ErrInteractionRequired
	})

	ctx, cancel := context.WithCancel(t.Context())

	// Cancel context as soon as stage 2 is entered
	go func() {
		<-stage2Entered
		cancel()
	}()

	cfg := &ClientConfig{
		NodeID:   "adv-node-cancel",
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

	start := time.Now()
	_, err := connector.Connect(ctx, cfg.NodeID)
	duration := time.Since(start)

	if err == nil {
		t.Fatal("expected connect to fail on canceled context")
	}

	// Should abort rapidly upon context cancellation, not wait for the 2s server stall
	if duration > 1500*time.Millisecond {
		t.Errorf("cancellation took too long (%v), expected < 1.5s", duration)
	}
}
