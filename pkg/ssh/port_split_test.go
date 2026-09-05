package ssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// standaloneConnectionProvider 仅实现 ConnectionProvider 接口
type standaloneConnectionProvider struct {
	cfg *ClientConfig
	err error
}

func (p *standaloneConnectionProvider) GetConfig(nodeID string) (*ClientConfig, error) {
	if p.err != nil {
		return nil, p.err
	}
	if p.cfg == nil {
		return nil, fmt.Errorf("node %q not found", nodeID)
	}
	cp := *p.cfg
	return &cp, nil
}

// standaloneSecretResolver 仅实现 SecretResolver 接口
type standaloneSecretResolver struct {
	mu              sync.Mutex
	secrets         map[SecretKind][]byte
	resolveCalls    int
	passphraseCalls int
	passwordCalls   int
	customErr       error
	kindErrors      map[SecretKind]error
}

func (r *standaloneSecretResolver) ResolveSecret(ctx context.Context, req SecretRequest) ([]byte, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resolveCalls++
	switch req.Kind {
	case SecretKindPrivateKeyPassphrase:
		r.passphraseCalls++
	case SecretKindLoginPassword:
		r.passwordCalls++
	}
	if err, ok := r.kindErrors[req.Kind]; ok && err != nil {
		return nil, err
	}
	if r.customErr != nil {
		return nil, r.customErr
	}
	if secret, ok := r.secrets[req.Kind]; ok && len(secret) > 0 {
		return secret, nil
	}
	return nil, ErrInteractionRequired
}

// standaloneCredentialRecorder 仅实现 CredentialRecorder 接口
type standaloneCredentialRecorder struct {
	mu          sync.Mutex
	authCalls   int
	sudoCalls   int
	lastAuthPwd string
	lastSudoPwd string
}

func (c *standaloneCredentialRecorder) UpdateAuth(ctx context.Context, nodeID, authUpdateToken, password, keyPath, passphrase string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.authCalls++
	c.lastAuthPwd = password
	return nil
}

func (c *standaloneCredentialRecorder) UpdateSudo(ctx context.Context, nodeID, sudoUpdateToken string, mode SudoMode, suPwd string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sudoCalls++
	c.lastSudoPwd = suPwd
	return nil
}

// 编译期确认独立实现没有实现不需要的接口
var (
	_ ConnectionProvider = (*standaloneConnectionProvider)(nil)
	_ SecretResolver     = (*standaloneSecretResolver)(nil)
	_ CredentialRecorder = (*standaloneCredentialRecorder)(nil)
)

func TestPortSplit_DefaultResolver_FailClosed(t *testing.T) {
	setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	provider := &standaloneConnectionProvider{
		cfg: &ClientConfig{
			NodeID:   "node-pwd-empty",
			Address:  "127.0.0.1",
			Port:     2222,
			User:     "user",
			AuthType: "password",
			// Password 为空，且未注入 SecretResolver，应触发默认 rejectSecretResolver 并失败
		},
	}

	connector := NewConnector(provider)
	t.Cleanup(func() { _ = connector.CloseAll() })

	_, err := connector.Connect(context.Background(), "node-pwd-empty")
	if err == nil {
		t.Fatal("expected error for empty password with default reject resolver, got nil")
	}
	if !errors.Is(err, ErrPasswordRequired) {
		t.Fatalf("expected ErrPasswordRequired, got: %v", err)
	}
}

func TestPortSplit_NilOptions_FallbackSafely(t *testing.T) {
	setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	provider := &standaloneConnectionProvider{
		cfg: &ClientConfig{
			NodeID:   "node-fallback",
			Address:  "127.0.0.1",
			Port:     2222,
			User:     "user",
			AuthType: "password",
		},
	}

	// 传入 nil 不应 panic，且应优雅降级为默认安全实现
	connector := NewConnector(provider,
		WithSecretResolver(nil),
		WithCredentialRecorder(nil),
		WithConnectionProvider(nil),
	)
	t.Cleanup(func() { _ = connector.CloseAll() })

	_, err := connector.Connect(context.Background(), "node-fallback")
	if err == nil {
		t.Fatal("expected connection to fail, got nil")
	}
	if !errors.Is(err, ErrPasswordRequired) {
		t.Fatalf("expected ErrPasswordRequired, got: %v", err)
	}
}

func TestPortSplit_SecretResolver_ContextCancellation(t *testing.T) {
	setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	provider := &standaloneConnectionProvider{
		cfg: &ClientConfig{
			NodeID:   "node-ctx",
			Address:  "127.0.0.1",
			Port:     2222,
			User:     "user",
			AuthType: "password",
		},
	}

	resolver := &standaloneSecretResolver{
		secrets: map[SecretKind][]byte{
			SecretKindLoginPassword: []byte("secret"),
		},
	}

	connector := NewConnector(provider, WithSecretResolver(resolver))
	t.Cleanup(func() { _ = connector.CloseAll() })

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel() // 预先取消

	_, err := connector.Connect(canceledCtx, "node-ctx")
	if err == nil {
		t.Fatal("expected context canceled error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled in error chain, got: %v", err)
	}
}

func TestPortSplit_SecretResolver_FatalErrorPropagation(t *testing.T) {
	setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	errVaultDown := errors.New("vault storage down")
	provider := &standaloneConnectionProvider{
		cfg: &ClientConfig{
			NodeID:   "node-fatal-err",
			Address:  "127.0.0.1",
			Port:     2222,
			User:     "user",
			AuthType: "password",
		},
	}

	resolver := &standaloneSecretResolver{
		customErr: errVaultDown,
	}

	connector := NewConnector(provider, WithSecretResolver(resolver))
	t.Cleanup(func() { _ = connector.CloseAll() })

	_, err := connector.Connect(context.Background(), "node-fatal-err")
	if err == nil {
		t.Fatal("expected vault down error, got nil")
	}
	if !errors.Is(err, errVaultDown) {
		t.Fatalf("expected error chain to contain errVaultDown, got: %v", err)
	}
}

func TestPortSplit_IndependentPorts_CollaborateSuccessfully(t *testing.T) {
	setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	const expectedPassword = "port-split-secret-pwd"
	addr, _, stopServer := startTestAutoSSHServer(t, expectedPassword)
	t.Cleanup(stopServer)

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port failed: %v", err)
	}
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	provider := &standaloneConnectionProvider{
		cfg: &ClientConfig{
			NodeID:          "node-independent",
			Address:         host,
			Port:            port,
			User:            "testuser",
			AuthType:        "password",
			Password:        "", // 故意留空，由 SecretResolver 提供
			SudoMode:        SudoModeSu,
			SuPwd:           "", // 故意留空，由 SecretResolver 提供
			SudoUpdateToken: "token-sudo-999",
		},
	}

	resolver := &standaloneSecretResolver{
		secrets: map[SecretKind][]byte{
			SecretKindLoginPassword: []byte(expectedPassword),
			SecretKindSuPassword:    []byte("resolved-su-pwd"),
		},
	}

	recorder := &standaloneCredentialRecorder{}

	handler := &testAutoInteractionHandler{passwordToProvide: expectedPassword}
	connector := NewConnector(provider,
		WithSecretResolver(resolver),
		WithCredentialRecorder(recorder),
		WithInteractionHandler(handler),
		WithHandshakeTimeout(2*time.Second),
	)
	t.Cleanup(func() { _ = connector.CloseAll() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := connector.Connect(ctx, "node-independent")
	if err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	if client == nil {
		t.Fatal("expected client, got nil")
	}

	// 验证 SecretResolver 确实被调用
	resolver.mu.Lock()
	calls := resolver.resolveCalls
	resolver.mu.Unlock()
	if calls < 2 {
		t.Fatalf("expected at least 2 SecretResolver calls (login + su), got: %d", calls)
	}

	// 验证 Client 内部持有了 suPwd
	if client.cfg.SuPwd != "resolved-su-pwd" {
		t.Fatalf("expected client SuPwd to be 'resolved-su-pwd', got %q", client.cfg.SuPwd)
	}
}

func TestPortSplit_ConcurrentConnectAndCloseRace(t *testing.T) {
	setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	const testPassword = "race-test-password"
	addr, _, stopServer := startTestAutoSSHServer(t, testPassword)
	t.Cleanup(stopServer)

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port failed: %v", err)
	}
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	provider := &standaloneConnectionProvider{
		cfg: &ClientConfig{
			NodeID:   "node-race",
			Address:  host,
			Port:     port,
			User:     "testuser",
			AuthType: "password",
			Password: testPassword,
		},
	}

	handler := &testAutoInteractionHandler{passwordToProvide: testPassword}
	connector := NewConnector(provider,
		WithInteractionHandler(handler),
		WithHandshakeTimeout(2*time.Second),
	)

	const goroutines = 10
	var startWG sync.WaitGroup
	var doneWG sync.WaitGroup
	startWG.Add(1)

	var successCount atomic.Int64
	var errCount atomic.Int64

	for i := 0; i < goroutines; i++ {
		doneWG.Add(1)
		go func() {
			defer doneWG.Done()
			startWG.Wait()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			client, err := connector.Connect(ctx, "node-race")
			if err != nil {
				errCount.Add(1)
				return
			}
			if client != nil {
				successCount.Add(1)
			}
		}()
	}

	startWG.Done()

	// 稍微休眠并并发执行 CloseAll
	time.Sleep(10 * time.Millisecond)
	_ = connector.CloseAll()

	doneWG.Wait()

	total := successCount.Load() + errCount.Load()
	if total != goroutines {
		t.Fatalf("expected %d total results, got %d", goroutines, total)
	}
}

type trackingPrompter struct {
	mu          sync.Mutex
	promptCalls int
	password    string
}

func (p *trackingPrompter) PromptSecret(ctx context.Context, req SecretRequest) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.promptCalls++
	if p.password != "" {
		return p.password, nil
	}
	return "", ErrInteractionRequired
}

func (p *trackingPrompter) ConfirmHostKey(ctx context.Context, req HostKeyConfirmation) (bool, error) {
	return true, nil
}

func TestPortSplit_AutoAuth_PropagatesResolverFailure(t *testing.T) {
	setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	const validPassword = "auto-test-secret"
	addr, _, stopServer := startTestAutoSSHServer(t, validPassword)
	t.Cleanup(stopServer)

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port failed: %v", err)
	}
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	provider := &standaloneConnectionProvider{
		cfg: &ClientConfig{
			NodeID:   "node-auto-fail",
			Address:  host,
			Port:     port,
			User:     "testuser",
			AuthType: "auto",
		},
	}

	errVaultStorageBroken := errors.New("vault backend unreachable")
	resolver := &standaloneSecretResolver{
		customErr: errVaultStorageBroken,
	}

	prompter := &trackingPrompter{password: validPassword}
	connector := NewConnector(provider,
		WithSecretResolver(resolver),
		WithInteractionHandler(prompter),
		WithHandshakeTimeout(2*time.Second),
	)
	t.Cleanup(func() { _ = connector.CloseAll() })

	_, connectErr := connector.Connect(context.Background(), "node-auto-fail")
	if connectErr == nil {
		t.Fatal("expected connection failure due to resolver error, got nil")
	}

	// 必须传播后端故障，且绝不能降级绕过弹密码
	if !errors.Is(connectErr, errVaultStorageBroken) {
		t.Fatalf("expected error chain to contain errVaultStorageBroken, got: %v", connectErr)
	}

	resolver.mu.Lock()
	resolverCalls := resolver.resolveCalls
	resolver.mu.Unlock()
	if resolverCalls == 0 {
		t.Fatalf("expected resolver to be called, got %d calls", resolverCalls)
	}

	prompter.mu.Lock()
	prompterCalls := pmpCalls(prompter)
	prompter.mu.Unlock()
	if prompterCalls != 0 {
		t.Fatalf("expected prompter not to be called when resolver fails, got %d calls", prompterCalls)
	}
}

func pmpCalls(p *trackingPrompter) int {
	return p.promptCalls
}

func TestPortSplit_AutoAuth_ResolverProvidesPasswordWithoutPrompt(t *testing.T) {
	setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	const validPassword = "auto-resolved-password"
	addr, _, stopServer := startTestAutoSSHServer(t, validPassword)
	t.Cleanup(stopServer)

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port failed: %v", err)
	}
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	provider := &standaloneConnectionProvider{
		cfg: &ClientConfig{
			NodeID:   "node-auto-success",
			Address:  host,
			Port:     port,
			User:     "testuser",
			AuthType: "auto",
		},
	}

	resolver := &standaloneSecretResolver{
		secrets: map[SecretKind][]byte{
			SecretKindLoginPassword: []byte(validPassword),
		},
	}

	prompter := &trackingPrompter{password: "wrong-password"}
	connector := NewConnector(provider,
		WithSecretResolver(resolver),
		WithInteractionHandler(prompter),
		WithHandshakeTimeout(2*time.Second),
	)
	t.Cleanup(func() { _ = connector.CloseAll() })

	client, err := connector.Connect(context.Background(), "node-auto-success")
	if err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	if client == nil {
		t.Fatal("expected valid client, got nil")
	}

	resolver.mu.Lock()
	resolverCalls := resolver.resolveCalls
	resolver.mu.Unlock()
	if resolverCalls == 0 {
		t.Fatalf("expected resolver to be called, got %d calls", resolverCalls)
	}

	// 密码由 resolver 提供，prompter 不应被调用
	if calls := pmpCalls(prompter); calls != 0 {
		t.Fatalf("expected 0 prompt calls, got: %d", calls)
	}
}

func TestPortSplit_AutoAuth_ResolverMissingFallsBackToPrompter(t *testing.T) {
	setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	const validPassword = "auto-prompted-password"
	addr, _, stopServer := startTestAutoSSHServer(t, validPassword)
	t.Cleanup(stopServer)

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port failed: %v", err)
	}
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	provider := &standaloneConnectionProvider{
		cfg: &ClientConfig{
			NodeID:   "node-auto-prompt",
			Address:  host,
			Port:     port,
			User:     "testuser",
			AuthType: "auto",
		},
	}

	// resolver 没有该节点秘密，返回 ErrInteractionRequired
	resolver := &standaloneSecretResolver{}

	prompter := &trackingPrompter{password: validPassword}
	connector := NewConnector(provider,
		WithSecretResolver(resolver),
		WithInteractionHandler(prompter),
		WithHandshakeTimeout(2*time.Second),
	)
	t.Cleanup(func() { _ = connector.CloseAll() })

	client, err := connector.Connect(context.Background(), "node-auto-prompt")
	if err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	if client == nil {
		t.Fatal("expected valid client, got nil")
	}

	resolver.mu.Lock()
	resolverCalls := resolver.resolveCalls
	resolver.mu.Unlock()
	if resolverCalls == 0 {
		t.Fatalf("expected resolver to be checked first, got %d calls", resolverCalls)
	}

	if calls := pmpCalls(prompter); calls == 0 {
		t.Fatal("expected prompter to be called as fallback, got 0 calls")
	}
}

type inFlightBlockingResolver struct {
	enteredCh chan struct{}
	once      sync.Once
}

func (r *inFlightBlockingResolver) ResolveSecret(ctx context.Context, req SecretRequest) ([]byte, error) {
	r.once.Do(func() {
		close(r.enteredCh)
	})
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestPortSplit_SecretResolver_InFlight_HandshakeTimeout(t *testing.T) {
	setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	provider := &standaloneConnectionProvider{
		cfg: &ClientConfig{
			NodeID:   "node-timeout",
			Address:  "127.0.0.1",
			Port:     2222,
			User:     "user",
			AuthType: "password",
		},
	}

	enteredCh := make(chan struct{})
	resolver := &inFlightBlockingResolver{enteredCh: enteredCh}

	// 握手超时设置为 50ms
	const handshakeTimeout = 50 * time.Millisecond
	connector := NewConnector(provider,
		WithSecretResolver(resolver),
		WithHandshakeTimeout(handshakeTimeout),
	)
	t.Cleanup(func() { _ = connector.CloseAll() })

	start := time.Now()
	// 调用方 context 设置为 2 秒，远大于握手超时
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		_, err := connector.Connect(ctx, "node-timeout")
		errCh <- err
	}()

	// 确保已真正进入 resolver 内部执行
	select {
	case <-enteredCh:
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for resolver to be entered")
	}

	// 等待连接返回，应当被 50ms 的握手超时终止，而不是被 2s 的调用方超时或 CloseAll 终止
	select {
	case err := <-errCh:
		elapsed := time.Since(start)
		if err == nil {
			t.Fatal("expected timeout error, got nil")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected context.DeadlineExceeded in error chain, got: %v", err)
		}
		if elapsed > 1*time.Second {
			t.Fatalf("resolver was not terminated by handshake timeout in time; elapsed: %v", elapsed)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("resolver was blocked and did not terminate within bounded handshake timeout")
	}
}

func TestPortSplit_SecretResolver_InFlight_CloseAllCancellation(t *testing.T) {
	setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	provider := &standaloneConnectionProvider{
		cfg: &ClientConfig{
			NodeID:   "node-closeall",
			Address:  "127.0.0.1",
			Port:     2222,
			User:     "user",
			AuthType: "password",
		},
	}

	enteredCh := make(chan struct{})
	resolver := &inFlightBlockingResolver{enteredCh: enteredCh}

	connector := NewConnector(provider,
		WithSecretResolver(resolver),
		WithHandshakeTimeout(10*time.Second), // 设大超时
	)

	errCh := make(chan error, 1)
	go func() {
		_, err := connector.Connect(context.Background(), "node-closeall")
		errCh <- err
	}()

	// 确保已进入 resolver 内部执行
	select {
	case <-enteredCh:
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for resolver to be entered")
	}

	// 在 resolver 执行中调用 CloseAll
	if closeErr := connector.CloseAll(); closeErr != nil {
		t.Fatalf("CloseAll failed: %v", closeErr)
	}

	// Connect 应该因 Connector 关闭而迅速返回，不会 hang 住
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected error after CloseAll, got nil")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Connect did not return after CloseAll while resolver was in-flight")
	}
}

func startTestMultiAuthSSHServer(t *testing.T, expectedPub ssh.PublicKey, expectedPassword string) (string, func()) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test rsa key failed: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("create test signer failed: %v", err)
	}

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if expectedPub != nil && bytes.Equal(key.Marshal(), expectedPub.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("unknown public key")
		},
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if string(password) == expectedPassword {
				return nil, nil
			}
			return nil, errors.New("unauthorized: wrong password")
		},
	}
	serverConfig.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp failed: %v", err)
	}

	serverCtx, serverCancel := context.WithCancel(context.Background())
	var connMu sync.Mutex
	activeConns := make(map[net.Conn]struct{})

	var serverWG sync.WaitGroup
	serverWG.Add(1)
	go func() {
		defer serverWG.Done()
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}

			connMu.Lock()
			select {
			case <-serverCtx.Done():
				connMu.Unlock()
				_ = conn.Close()
				return
			default:
				activeConns[conn] = struct{}{}
			}
			connMu.Unlock()

			serverWG.Add(1)
			go func(c net.Conn) {
				defer serverWG.Done()
				defer func() {
					connMu.Lock()
					delete(activeConns, c)
					connMu.Unlock()
					_ = c.Close()
				}()

				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				sConn, chans, reqs, srvErr := ssh.NewServerConn(c, serverConfig)
				if srvErr != nil {
					return
				}
				defer func() { _ = sConn.Close() }()

				reqWG := sync.WaitGroup{}
				reqWG.Add(1)
				go func() {
					defer reqWG.Done()
					ssh.DiscardRequests(reqs)
				}()

				for range chans {
				}
				reqWG.Wait()
			}(conn)
		}
	}()

	cleanup := func() {
		serverCancel()
		_ = listener.Close()

		connMu.Lock()
		for c := range activeConns {
			_ = c.Close()
		}
		connMu.Unlock()

		done := make(chan struct{})
		go func() {
			serverWG.Wait()
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Errorf("multi auth SSH server cleanup timed out waiting for goroutines")
		}
	}

	return listener.Addr().String(), cleanup
}

func TestPortSplit_AutoAuth_EncryptedKeyWithPub_ResolverFailureTerminatesHandshake(t *testing.T) {
	home := setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	const (
		passphrase    = "test-passphrase-with-pub"
		validPassword = "server-login-password"
	)
	pemData, sshPub := generateTestEncryptedKey(t, passphrase)

	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	keyPath := filepath.Join(sshDir, "id_rsa")
	pubPath := keyPath + ".pub"

	if err := os.WriteFile(keyPath, pemData, 0600); err != nil {
		t.Fatalf("write key failed: %v", err)
	}
	pubBytes := ssh.MarshalAuthorizedKey(sshPub)
	if err := os.WriteFile(pubPath, pubBytes, 0644); err != nil {
		t.Fatalf("write pub key failed: %v", err)
	}

	addr, stopServer := startTestMultiAuthSSHServer(t, sshPub, validPassword)
	t.Cleanup(stopServer)

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port failed: %v", err)
	}
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	provider := &standaloneConnectionProvider{
		cfg: &ClientConfig{
			NodeID:   "node-auto-key-with-pub",
			Address:  host,
			Port:     port,
			User:     "testuser",
			AuthType: "auto",
		},
	}

	errVaultStorageBroken := errors.New("vault backend unreachable")
	resolver := &standaloneSecretResolver{
		kindErrors: map[SecretKind]error{
			SecretKindPrivateKeyPassphrase: errVaultStorageBroken,
			SecretKindLoginPassword:        ErrInteractionRequired,
		},
	}

	// 注入能够提供有效登录密码的 prompter；若没有终止握手，程序会尝试密码认证并成功
	prompter := &trackingPrompter{password: validPassword}
	connector := NewConnector(provider,
		WithSecretResolver(resolver),
		WithInteractionHandler(prompter),
		WithHandshakeTimeout(2*time.Second),
	)
	t.Cleanup(func() { _ = connector.CloseAll() })

	_, connectErr := connector.Connect(context.Background(), "node-auto-key-with-pub")
	if connectErr == nil {
		t.Fatal("expected connection failure due to resolver error, got nil (bypassed by password auth!)")
	}

	// 必须终止整个认证流程，并保留原始错误链
	if !errors.Is(connectErr, errVaultStorageBroken) {
		t.Fatalf("expected error chain to contain errVaultStorageBroken, got: %v", connectErr)
	}

	// 登录密码解析次数与提示次数均必须为 0，绝对不能回退绕过
	resolver.mu.Lock()
	passphraseCalls := resolver.passphraseCalls
	passwordCalls := resolver.passwordCalls
	resolver.mu.Unlock()

	if passphraseCalls == 0 {
		t.Fatal("expected resolver to be called for passphrase")
	}
	if passwordCalls != 0 {
		t.Fatalf("expected 0 password resolve calls, got %d (password resolution was incorrectly triggered)", passwordCalls)
	}
	if calls := pmpCalls(prompter); calls != 0 {
		t.Fatalf("expected 0 prompt calls, got %d (password prompt was incorrectly triggered)", calls)
	}
}

func TestPortSplit_AutoAuth_EncryptedKeyWithoutPub_ResolverFailureTerminatesHandshake(t *testing.T) {
	home := setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	const (
		passphrase    = "test-passphrase-without-pub"
		validPassword = "server-login-password"
	)
	pemData, sshPub := generateTestEncryptedKey(t, passphrase)

	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	keyPath := filepath.Join(sshDir, "id_rsa")
	// 故意不写 .pub 文件，触发 PassphraseMissingError 回退到 PublicKeysCallback
	if err := os.WriteFile(keyPath, pemData, 0600); err != nil {
		t.Fatalf("write key failed: %v", err)
	}

	addr, stopServer := startTestMultiAuthSSHServer(t, sshPub, validPassword)
	t.Cleanup(stopServer)

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port failed: %v", err)
	}
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	provider := &standaloneConnectionProvider{
		cfg: &ClientConfig{
			NodeID:   "node-auto-key-no-pub",
			Address:  host,
			Port:     port,
			User:     "testuser",
			AuthType: "auto",
		},
	}

	errVaultStorageBroken := errors.New("vault backend unreachable")
	resolver := &standaloneSecretResolver{
		kindErrors: map[SecretKind]error{
			SecretKindPrivateKeyPassphrase: errVaultStorageBroken,
			SecretKindLoginPassword:        ErrInteractionRequired,
		},
	}

	// 注入能够提供有效登录密码的 prompter；若没有终止握手，程序会尝试密码认证并成功
	prompter := &trackingPrompter{password: validPassword}
	connector := NewConnector(provider,
		WithSecretResolver(resolver),
		WithInteractionHandler(prompter),
		WithHandshakeTimeout(2*time.Second),
	)
	t.Cleanup(func() { _ = connector.CloseAll() })

	_, connectErr := connector.Connect(context.Background(), "node-auto-key-no-pub")
	if connectErr == nil {
		t.Fatal("expected connection failure due to resolver error, got nil (bypassed by password auth!)")
	}

	// 必须终止整个认证流程，并保留原始错误链
	if !errors.Is(connectErr, errVaultStorageBroken) {
		t.Fatalf("expected error chain to contain errVaultStorageBroken, got: %v", connectErr)
	}

	// 登录密码解析次数与提示次数均必须为 0，绝对不能回退绕过
	resolver.mu.Lock()
	passphraseCalls := resolver.passphraseCalls
	passwordCalls := resolver.passwordCalls
	resolver.mu.Unlock()

	if passphraseCalls == 0 {
		t.Fatal("expected resolver to be called for passphrase")
	}
	if passwordCalls != 0 {
		t.Fatalf("expected 0 password resolve calls, got %d (password resolution was incorrectly triggered)", passwordCalls)
	}
	if calls := pmpCalls(prompter); calls != 0 {
		t.Fatalf("expected 0 prompt calls, got %d (password prompt was incorrectly triggered)", calls)
	}
}
