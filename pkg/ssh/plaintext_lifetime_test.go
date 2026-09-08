package ssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"
)

// probeSecretResolver 用于记录 SecretResolver 的解析调用时机与调用次数
type probeSecretResolver struct {
	mu              sync.Mutex
	secrets         map[SecretKind][]byte
	resolveCalls    int
	passwordCalls   int
	passphraseCalls int
	suCalls         int
	blockOnKind     SecretKind
	directReturn    bool
}

func newProbeSecretResolver() *probeSecretResolver {
	return &probeSecretResolver{
		secrets: make(map[SecretKind][]byte),
	}
}

func (r *probeSecretResolver) setSecret(kind SecretKind, val []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.secrets[kind] = val
}

func (r *probeSecretResolver) ResolveSecret(ctx context.Context, req SecretRequest) ([]byte, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}

	r.mu.Lock()
	blockKind := r.blockOnKind
	r.mu.Unlock()

	if blockKind == req.Kind {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
			return nil, errors.New("probe resolver block timeout")
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.resolveCalls++
	switch req.Kind {
	case SecretKindLoginPassword:
		r.passwordCalls++
	case SecretKindPrivateKeyPassphrase:
		r.passphraseCalls++
	case SecretKindSuPassword:
		r.suCalls++
	}

	if secret, ok := r.secrets[req.Kind]; ok && len(secret) > 0 {
		if r.directReturn {
			return secret, nil
		}
		cpy := make([]byte, len(secret))
		copy(cpy, secret)
		return cpy, nil
	}
	return nil, ErrInteractionRequired
}

type lifetimeSSHServer struct {
	host     string
	port     int
	cleanup  func()
	cmdMu    sync.Mutex
	commands []string
}

func (s *lifetimeSSHServer) getCommands() []string {
	s.cmdMu.Lock()
	defer s.cmdMu.Unlock()
	res := make([]string, len(s.commands))
	copy(res, s.commands)
	return res
}

func startLifetimeTestSSHServer(t *testing.T, expectedPassword string, expectedPub ssh.PublicKey) (string, int, func()) {
	srv := startLifetimeTestSSHServerWithRecorder(t, expectedPassword, expectedPub)
	return srv.host, srv.port, srv.cleanup
}

//nolint:gocyclo // Test helper managing mock SSH server lifecycle and channel events
func startLifetimeTestSSHServerWithRecorder(t *testing.T, expectedPassword string, expectedPub ssh.PublicKey) *lifetimeSSHServer {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key failed: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("create signer failed: %v", err)
	}

	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if expectedPassword != "" && string(password) == expectedPassword {
				return nil, nil
			}
			return nil, errors.New("wrong password")
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if expectedPub != nil && bytes.Equal(key.Marshal(), expectedPub.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("unknown public key")
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

	serverObj := &lifetimeSSHServer{}

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

				var reqWG sync.WaitGroup
				reqWG.Add(1)
				go func() {
					defer reqWG.Done()
					ssh.DiscardRequests(reqs)
				}()

				for newCh := range chans {
					if newCh.ChannelType() != "session" {
						_ = newCh.Reject(ssh.UnknownChannelType, "unsupported channel type")
						continue
					}
					ch, chReqs, chErr := newCh.Accept()
					if chErr != nil {
						continue
					}

					serverWG.Add(1)
					go func(channel ssh.Channel, requests <-chan *ssh.Request) {
						defer serverWG.Done()
						defer func() { _ = channel.Close() }()

						for req := range requests {
							switch req.Type {
							case "pty-req":
								_ = req.Reply(true, nil)
							case "exec":
								_ = req.Reply(true, nil)
								cmd := ""
								if len(req.Payload) >= 4 {
									cmdLen := int(binary.BigEndian.Uint32(req.Payload[:4]))
									if len(req.Payload) >= 4+cmdLen {
										cmd = string(req.Payload[4 : 4+cmdLen])
									}
								}

								serverObj.cmdMu.Lock()
								serverObj.commands = append(serverObj.commands, cmd)
								serverObj.cmdMu.Unlock()

								if strings.Contains(cmd, "su -") {
									_, _ = channel.Write([]byte("Password: "))
									buf := make([]byte, 128)
									_, _ = channel.Read(buf)
									_, _ = channel.Write([]byte("mock-su-success\n"))
									_, _ = channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
									_ = channel.CloseWrite()
									return
								} else if strings.Contains(cmd, "sudo -n") {
									_, _ = channel.Write([]byte("sudo: a password is required\n"))
									_, _ = channel.SendRequest("exit-status", false, []byte{0, 0, 0, 1})
									_ = channel.CloseWrite()
									return
								} else if strings.Contains(cmd, "sudo") {
									buf := make([]byte, 128)
									_, _ = channel.Read(buf)
									_, _ = channel.Write([]byte("mock-sudo-success\n"))
									_, _ = channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
									_ = channel.CloseWrite()
									return
								} else {
									_, _ = channel.Write([]byte("mock-exec-success\n"))
									_, _ = channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
									_ = channel.CloseWrite()
									return
								}
							default:
								_ = req.Reply(false, nil)
							}
						}
					}(ch, chReqs)
				}
				reqWG.Wait()
			}(conn)
		}
	}()

	host, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split host port failed: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port failed: %v", err)
	}

	serverObj.host = host
	serverObj.port = port
	serverObj.cleanup = func() {
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
			t.Errorf("lifetime SSH server cleanup timed out waiting for goroutines")
		}
	}

	return serverObj
}

// TestPlaintextLifetime_ProbeResolver_ReadOccursAtDemandPoint 验证建连仅读登录机密，提权时按命令触发独立读取
func TestPlaintextLifetime_ProbeResolver_ReadOccursAtDemandPoint(t *testing.T) {
	setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	loginPwd := "login-secret-123"
	suPwd := "su-secret-456"
	host, port, cleanup := startLifetimeTestSSHServer(t, loginPwd, nil)
	defer cleanup()

	resolver := newProbeSecretResolver()
	resolver.setSecret(SecretKindLoginPassword, []byte(loginPwd))
	resolver.setSecret(SecretKindSuPassword, []byte(suPwd))

	nodeID := "node-demand-point"
	provider := &standaloneConnectionProvider{
		cfg: &ClientConfig{
			NodeID:   nodeID,
			Address:  host,
			Port:     port,
			User:     "testuser",
			AuthType: "password",
			SudoMode: SudoModeSu,
		},
	}

	connector := NewConnector(
		provider,
		WithSecretResolver(resolver),
	)
	connector.AcceptNewHostKey.Store(true)
	defer func() { _ = connector.CloseAll() }()

	ctx := context.Background()

	// 1. 建连阶段
	client, err := connector.Connect(ctx, nodeID)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	resolver.mu.Lock()
	pwdCallsAfterConnect := resolver.passwordCalls
	suCallsAfterConnect := resolver.suCalls
	resolver.mu.Unlock()

	if pwdCallsAfterConnect != 1 {
		t.Errorf("expected 1 login password resolve call during connect, got %d", pwdCallsAfterConnect)
	}
	if suCallsAfterConnect != 0 {
		t.Errorf("expected 0 su password resolve calls during connect, got %d", suCallsAfterConnect)
	}

	// 验证 Client 不保留凭据明文快照
	if client.AuthMaterial() != nil {
		t.Errorf("expected client.AuthMaterial() to be nil, got non-nil")
	}
	if client.Config().Password != "" {
		t.Errorf("expected client.Config().Password to be empty, got %q", client.Config().Password)
	}
	if client.Config().SuPwd != "" {
		t.Errorf("expected client.Config().SuPwd to be empty, got %q", client.Config().SuPwd)
	}

	// 2. 第一次提权执行命令
	out1, err := client.RunWithSudo(ctx, "whoami")
	if err != nil {
		t.Fatalf("first RunWithSudo failed: %v", err)
	}
	if !strings.Contains(out1, "mock-su-success") {
		t.Errorf("unexpected output from first RunWithSudo: %q", out1)
	}

	resolver.mu.Lock()
	suCallsAfterFirstRun := resolver.suCalls
	resolver.mu.Unlock()

	if suCallsAfterFirstRun != 1 {
		t.Errorf("expected 1 su password resolve call after first RunWithSudo, got %d", suCallsAfterFirstRun)
	}

	// 3. 第二次提权执行命令
	out2, err := client.RunWithSudo(ctx, "id")
	if err != nil {
		t.Fatalf("second RunWithSudo failed: %v", err)
	}
	if !strings.Contains(out2, "mock-su-success") {
		t.Errorf("unexpected output from second RunWithSudo: %q", out2)
	}

	resolver.mu.Lock()
	suCallsAfterSecondRun := resolver.suCalls
	resolver.mu.Unlock()

	if suCallsAfterSecondRun != 2 {
		t.Errorf("expected 2 su password resolve calls after second RunWithSudo, got %d", suCallsAfterSecondRun)
	}
}

// TestPlaintextLifetime_ClientRetainsNoAuthMaterial 验证建连后与缓存入池后 Client 均不持久保留明文秘密
func TestPlaintextLifetime_ClientRetainsNoAuthMaterial(t *testing.T) {
	setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	expectedPwd := "persistent-pwd-999"
	host, port, cleanup := startLifetimeTestSSHServer(t, expectedPwd, nil)
	defer cleanup()

	nodeID := "node-no-retain"
	provider := &standaloneConnectionProvider{
		cfg: &ClientConfig{
			NodeID:     nodeID,
			Address:    host,
			Port:       port,
			User:       "testuser",
			AuthType:   "password",
			Password:   expectedPwd,
			Passphrase: "unexpected-passphrase",
			SuPwd:      "unexpected-supwd",
		},
	}

	connector := NewConnector(provider)
	connector.AcceptNewHostKey.Store(true)
	defer func() { _ = connector.CloseAll() }()

	ctx := context.Background()
	client, err := connector.Connect(ctx, nodeID)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	// 检查建连直接返回的 Client
	if client.AuthMaterial() != nil {
		t.Errorf("expected client.AuthMaterial() to be nil, got non-nil")
	}
	cfg := client.Config()
	if cfg.Password != "" {
		t.Errorf("expected client.Config().Password to be empty, got %q", cfg.Password)
	}
	if cfg.Passphrase != "" {
		t.Errorf("expected client.Config().Passphrase to be empty, got %q", cfg.Passphrase)
	}
	if cfg.SuPwd != "" {
		t.Errorf("expected client.Config().SuPwd to be empty, got %q", cfg.SuPwd)
	}

	// 检查 ConnectionConfig 不含敏感明文并保留标识信息
	connCfg := client.ConnectionConfig()
	if connCfg.NodeID != nodeID {
		t.Errorf("expected NodeID %q, got %q", nodeID, connCfg.NodeID)
	}
	if connCfg.Address != host {
		t.Errorf("expected Address %q, got %q", host, connCfg.Address)
	}

	// 检查从连接池重新获取的 Client
	cachedClient, err := connector.Connect(ctx, nodeID)
	if err != nil {
		t.Fatalf("Connect (cached) failed: %v", err)
	}
	if cachedClient.AuthMaterial() != nil {
		t.Errorf("expected cachedClient.AuthMaterial() to be nil, got non-nil")
	}
	cachedCfg := cachedClient.Config()
	if cachedCfg.Password != "" {
		t.Errorf("expected cachedClient.Config().Password to be empty, got %q", cachedCfg.Password)
	}
	if cachedCfg.Passphrase != "" {
		t.Errorf("expected cachedClient.Config().Passphrase to be empty, got %q", cachedCfg.Passphrase)
	}
	if cachedCfg.SuPwd != "" {
		t.Errorf("expected cachedClient.Config().SuPwd to be empty, got %q", cachedCfg.SuPwd)
	}
}

// TestPlaintextLifetime_PassphraseReleasedAfterSignerCreation 验证 Passphrase 生成 Signer 后立即清零释放
func TestPlaintextLifetime_PassphraseReleasedAfterSignerCreation(t *testing.T) {
	tempHome := setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	expectedPassphrase := "super-secure-passphrase-888"
	keyPEM, pubKey := generateTestEncryptedKey(t, expectedPassphrase)

	keyPath := filepath.Join(tempHome, "id_rsa_encrypted")
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("write key file failed: %v", err)
	}
	pubBytes := ssh.MarshalAuthorizedKey(pubKey)
	if err := os.WriteFile(keyPath+".pub", pubBytes, 0644); err != nil {
		t.Fatalf("write pub key file failed: %v", err)
	}

	host, port, cleanup := startLifetimeTestSSHServer(t, "", pubKey)
	defer cleanup()

	// 传入可追踪的底层 byte slice，验证 zeroBytes 执行后该切片全部被置零
	passphraseBytes := []byte(expectedPassphrase)

	resolver := newProbeSecretResolver()
	resolver.directReturn = true
	resolver.setSecret(SecretKindPrivateKeyPassphrase, passphraseBytes)

	nodeID := "node-key-passphrase"
	provider := &standaloneConnectionProvider{
		cfg: &ClientConfig{
			NodeID:   nodeID,
			Address:  host,
			Port:     port,
			User:     "testuser",
			AuthType: "key",
			KeyPath:  keyPath,
		},
	}

	connector := NewConnector(
		provider,
		WithSecretResolver(resolver),
	)
	connector.AcceptNewHostKey.Store(true)
	defer func() { _ = connector.CloseAll() }()

	ctx := context.Background()
	client, err := connector.Connect(ctx, nodeID)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	if client.AuthMaterial() != nil {
		t.Errorf("expected client.AuthMaterial() to be nil, got non-nil")
	}
	if client.Config().Passphrase != "" {
		t.Errorf("expected client.Config().Passphrase to be empty, got %q", client.Config().Passphrase)
	}

	resolver.mu.Lock()
	calls := resolver.passphraseCalls
	resolver.mu.Unlock()

	if calls != 1 {
		t.Errorf("expected 1 passphrase resolve call, got %d", calls)
	}

	// 验证敏感内存切片已被清零
	allZero := true
	for _, b := range passphraseBytes {
		if b != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		t.Errorf("expected passphrase slice to be wiped with zeroBytes, got: %q", string(passphraseBytes))
	}
}

func TestAutoAuth_UsesExplicitKeyPath(t *testing.T) {
	tempHome := setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	const passphrase = "explicit-key-passphrase"
	keyPEM, pubKey := generateTestEncryptedKey(t, passphrase)
	keyPath := filepath.Join(tempHome, "non-default-key")
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("write explicit key: %v", err)
	}
	host, port, cleanup := startLifetimeTestSSHServer(t, "", pubKey)
	defer cleanup()

	resolver := newProbeSecretResolver()
	resolver.setSecret(SecretKindPrivateKeyPassphrase, []byte(passphrase))
	provider := &standaloneConnectionProvider{cfg: &ClientConfig{
		NodeID: "explicit-key", Address: host, Port: port, User: "testuser", AuthType: "auto", KeyPath: keyPath,
	}}
	connector := NewConnector(provider, WithSecretResolver(resolver))
	connector.AcceptNewHostKey.Store(true)
	t.Cleanup(func() { _ = connector.CloseAll() })

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if _, err := connector.Connect(ctx, "explicit-key"); err != nil {
		t.Fatalf("connect with explicit key in auto mode: %v", err)
	}
}

func TestAutoAuth_KeySuccessDoesNotRecordUntriedPassword(t *testing.T) {
	tempHome := setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	const passphrase = "key-only-passphrase"
	keyPEM, pubKey := generateTestEncryptedKey(t, passphrase)
	keyPath := filepath.Join(tempHome, "key-only")
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("write explicit key: %v", err)
	}
	host, port, cleanup := startLifetimeTestSSHServer(t, "valid-password", pubKey)
	defer cleanup()

	store := &characterizationRecordingStore{cfg: &ClientConfig{
		NodeID: "key-only", Address: host, Port: port, User: "testuser", AuthType: "auto", KeyPath: keyPath,
		Password: "untried-password", AuthUpdateToken: "token-v1",
	}}
	resolver := newProbeSecretResolver()
	resolver.setSecret(SecretKindPrivateKeyPassphrase, []byte(passphrase))
	resolver.setSecret(SecretKindLoginPassword, []byte("untried-password"))
	connector := NewConnector(store, WithSecretResolver(resolver))
	connector.AcceptNewHostKey.Store(true)
	t.Cleanup(func() { _ = connector.CloseAll() })

	if _, err := connector.Connect(t.Context(), "key-only"); err != nil {
		t.Fatalf("connect with explicit key: %v", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.lastPassword != "" {
		t.Fatalf("recorded an untried password %q after key authentication", store.lastPassword)
	}
}

func TestAutoAuth_ExplicitKeyPrecedesEncryptedDefaultKey(t *testing.T) {
	tempHome := setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate selected key: %v", err)
	}
	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("create selected public key: %v", err)
	}
	selectedKeyPath := filepath.Join(tempHome, "selected-key")
	selectedKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	if err := os.WriteFile(selectedKeyPath, selectedKey, 0600); err != nil {
		t.Fatalf("write selected key: %v", err)
	}
	defaultKey, _ := generateTestEncryptedKey(t, "unrelated-passphrase")
	defaultKeyPath := filepath.Join(tempHome, ".ssh", "id_rsa")
	if err := os.MkdirAll(filepath.Dir(defaultKeyPath), 0700); err != nil {
		t.Fatalf("create default key directory: %v", err)
	}
	if err := os.WriteFile(defaultKeyPath, defaultKey, 0600); err != nil {
		t.Fatalf("write unrelated default key: %v", err)
	}
	host, port, cleanup := startLifetimeTestSSHServer(t, "unused-password", publicKey)
	defer cleanup()

	provider := &standaloneConnectionProvider{cfg: &ClientConfig{
		NodeID: "selected-key", Address: host, Port: port, User: "testuser", AuthType: "auto", KeyPath: selectedKeyPath,
	}}
	connector := NewConnector(provider)
	connector.AcceptNewHostKey.Store(true)
	t.Cleanup(func() { _ = connector.CloseAll() })
	if _, err := connector.Connect(t.Context(), "selected-key"); err != nil {
		t.Fatalf("explicit key was blocked by unrelated default key: %v", err)
	}
}

// TestPlaintextLifetime_SudoConcurrentExecutionRaceFree 验证 sudo 并发执行无竞态
func TestPlaintextLifetime_SudoConcurrentExecutionRaceFree(t *testing.T) {
	setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	loginPwd := "login-pwd-race"
	host, port, cleanup := startLifetimeTestSSHServer(t, loginPwd, nil)
	defer cleanup()

	resolver := newProbeSecretResolver()
	resolver.setSecret(SecretKindLoginPassword, []byte(loginPwd))

	nodeID := "node-sudo-race"
	provider := &standaloneConnectionProvider{
		cfg: &ClientConfig{
			NodeID:   nodeID,
			Address:  host,
			Port:     port,
			User:     "testuser",
			AuthType: "password",
			SudoMode: SudoModeSudo,
		},
	}

	connector := NewConnector(
		provider,
		WithSecretResolver(resolver),
	)
	connector.AcceptNewHostKey.Store(true)
	defer func() { _ = connector.CloseAll() }()

	ctx := context.Background()
	client, err := connector.Connect(ctx, nodeID)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	concurrency := 20
	var wg sync.WaitGroup
	errCh := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			cmd := fmt.Sprintf("echo job-%d", idx)
			out, runErr := client.RunWithSudo(ctx, cmd)
			if runErr != nil {
				errCh <- fmt.Errorf("concurrent RunWithSudo %d failed: %w", idx, runErr)
				return
			}
			if !strings.Contains(out, "mock-sudo-success") {
				errCh <- fmt.Errorf("concurrent RunWithSudo %d unexpected output: %s", idx, out)
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for runErr := range errCh {
		t.Errorf("concurrent error: %v", runErr)
	}
}

// TestPlaintextLifetime_CancellationExitsImmediately 验证取消时 Resolver 与命令执行立即退出
func TestPlaintextLifetime_CancellationExitsImmediately(t *testing.T) {
	setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	loginPwd := "login-cancel-pwd"
	host, port, cleanup := startLifetimeTestSSHServer(t, loginPwd, nil)
	defer cleanup()

	resolver := newProbeSecretResolver()
	resolver.setSecret(SecretKindLoginPassword, []byte(loginPwd))

	nodeID := "node-cancel-test"
	provider := &standaloneConnectionProvider{
		cfg: &ClientConfig{
			NodeID:   nodeID,
			Address:  host,
			Port:     port,
			User:     "testuser",
			AuthType: "password",
			SudoMode: SudoModeSu,
		},
	}

	connector := NewConnector(
		provider,
		WithSecretResolver(resolver),
	)
	connector.AcceptNewHostKey.Store(true)
	defer func() { _ = connector.CloseAll() }()

	client, err := connector.Connect(context.Background(), nodeID)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	// 1. 测试已取消的 Context 立即退出
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, cancelErr := client.RunWithSudo(canceledCtx, "ls")
	elapsed := time.Since(start)

	if !errors.Is(cancelErr, context.Canceled) {
		t.Errorf("expected context.Canceled error, got: %v", cancelErr)
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("expected fast cancellation exit within 100ms, took %v", elapsed)
	}

	// 2. 测试 Resolver 阻塞等待时超时快速退出
	resolver.mu.Lock()
	resolver.blockOnKind = SecretKindSuPassword
	resolver.mu.Unlock()

	timeoutCtx, cancelTimeout := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancelTimeout()

	start = time.Now()
	_, timeoutErr := client.RunWithSudo(timeoutCtx, "ls")
	elapsed = time.Since(start)

	if !errors.Is(timeoutErr, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded error, got: %v", timeoutErr)
	}
	if elapsed > 300*time.Millisecond {
		t.Errorf("expected fast timeout exit within 300ms, took %v", elapsed)
	}
}

// TestPlaintextLifetime_GoroutineLeak 验证完整重构链路无 Goroutine 泄漏
func TestPlaintextLifetime_GoroutineLeak(t *testing.T) {
	// [P2] 必须在测试创建任何资源前记录基线
	opts := []goleak.Option{goleak.IgnoreCurrent()}
	setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	loginPwd := "leak-test-pwd"
	host, port, cleanupServer := startLifetimeTestSSHServer(t, loginPwd, nil)

	resolver := newProbeSecretResolver()
	resolver.setSecret(SecretKindLoginPassword, []byte(loginPwd))
	resolver.setSecret(SecretKindSuPassword, []byte("su-pwd"))

	nodeID := "node-leak-check"
	provider := &standaloneConnectionProvider{
		cfg: &ClientConfig{
			NodeID:   nodeID,
			Address:  host,
			Port:     port,
			User:     "testuser",
			AuthType: "password",
			SudoMode: SudoModeSu,
		},
	}

	connector := NewConnector(
		provider,
		WithSecretResolver(resolver),
	)
	connector.AcceptNewHostKey.Store(true)

	ctx := context.Background()
	client, err := connector.Connect(ctx, nodeID)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	_, _ = client.RunWithSudo(ctx, "echo test")

	_ = connector.CloseAll()
	cleanupServer()

	goleak.VerifyNone(t, opts...)
}

type testRecorder struct {
	mu                 sync.Mutex
	authCalls          int
	sudoCalls          int
	lastAuthPass       string
	lastSuPass         string
	authErr            error
	sudoErr            error
	authCommittedToken string
	sudoCommittedToken string
	onUpdateAuth       func()
	onUpdateSudo       func()
}

func (m *testRecorder) UpdateAuth(ctx context.Context, nodeID, authUpdateToken, password, keyPath, passphrase string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authCalls++
	m.lastAuthPass = password
	if m.authErr != nil {
		return "", m.authErr
	}
	if m.onUpdateAuth != nil {
		m.onUpdateAuth()
	}
	if m.authCommittedToken != "" {
		return m.authCommittedToken, nil
	}
	return authUpdateToken, nil
}

func (m *testRecorder) UpdateSudo(ctx context.Context, nodeID, sudoUpdateToken string, mode SudoMode, suPwd string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sudoCalls++
	m.lastSuPass = suPwd
	if m.sudoErr != nil {
		return "", m.sudoErr
	}
	if m.onUpdateSudo != nil {
		m.onUpdateSudo()
	}
	if m.sudoCommittedToken != "" {
		return m.sudoCommittedToken, nil
	}
	return sudoUpdateToken, nil
}

func (m *testRecorder) UpdateHostKey(ctx context.Context, host string, port int, keyType, fingerprint string) error {
	return nil
}

type trackingProvider struct {
	mu       sync.Mutex
	cfg      *ClientConfig
	getCalls int
}

func (p *trackingProvider) GetConfig(nodeID string) (*ClientConfig, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.getCalls++
	copyCfg := *p.cfg
	return &copyCfg, nil
}

type probeSecretPrompter struct {
	mu           sync.Mutex
	returnSecret string
	promptCalls  int
}

func (p *probeSecretPrompter) PromptSecret(ctx context.Context, req SecretRequest) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.promptCalls++
	return p.returnSecret, nil
}

// TestPlaintextLifetime_PromptSecret_DispatchesCorrectRecorderAndUpdate 验证提示取得凭据时区分写回接口且传播失败
func TestPlaintextLifetime_PromptSecret_DispatchesCorrectRecorderAndUpdate(t *testing.T) {
	setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	expectedPwd := "prompt-pwd-123"
	host, port, cleanup := startLifetimeTestSSHServer(t, expectedPwd, nil)
	defer cleanup()

	// 1. 测试 sudo 模式提示登录密码：只调用 UpdateAuth，绝不调用 UpdateSudo
	recorder := &testRecorder{}
	provider := &trackingProvider{
		cfg: &ClientConfig{
			NodeID:          "node-prompt-sudo",
			Address:         host,
			Port:            port,
			User:            "testuser",
			AuthType:        "password",
			Password:        expectedPwd,
			SudoMode:        SudoModeSudo,
			AuthUpdateToken: "auth-tok-1",
			SudoUpdateToken: "sudo-tok-1",
		},
	}
	recorder.authCommittedToken = "auth-tok-2"
	recorder.onUpdateAuth = func() {
		provider.mu.Lock()
		provider.cfg.AuthUpdateToken = "auth-tok-2"
		provider.mu.Unlock()
	}
	prompter := &probeSecretPrompter{returnSecret: expectedPwd}

	conn := NewConnector(
		provider,
		WithSecretPrompter(prompter),
		WithCredentialRecorder(recorder),
	)
	conn.AcceptNewHostKey.Store(true)
	defer func() { _ = conn.CloseAll() }()

	ctx := context.Background()
	client, err := conn.Connect(ctx, "node-prompt-sudo")
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	// 触发 sudo 执行（需要登录密码）
	out, err := client.RunWithSudo(ctx, "whoami")
	if err != nil {
		t.Fatalf("RunWithSudo failed: %v", err)
	}
	if !strings.Contains(out, "mock-sudo-success") {
		t.Errorf("unexpected output: %s", out)
	}

	recorder.mu.Lock()
	authCalls := recorder.authCalls
	sudoCalls := recorder.sudoCalls
	lastAuthPass := recorder.lastAuthPass
	recorder.mu.Unlock()

	// 登录密码建连一次 + 提权一次，或建连已提示提权再次提示
	if authCalls == 0 {
		t.Errorf("expected UpdateAuth to be called for login password, got %d", authCalls)
	}
	if sudoCalls != 0 {
		t.Errorf("expected UpdateSudo NOT to be called for login password, got %d", sudoCalls)
	}
	if lastAuthPass != expectedPwd {
		t.Errorf("expected recorded password %q, got %q", expectedPwd, lastAuthPass)
	}

	// 2. 测试写回失败时错误正确传播，且不继续
	failRecorder := &testRecorder{
		sudoErr: errors.New("db writeback failed"),
	}
	providerSu := &trackingProvider{
		cfg: &ClientConfig{
			NodeID:          "node-prompt-su-fail",
			Address:         host,
			Port:            port,
			User:            "testuser",
			AuthType:        "password",
			Password:        expectedPwd,
			SudoMode:        SudoModeSu,
			AuthUpdateToken: "auth-tok-1",
			SudoUpdateToken: "sudo-tok-1",
		},
	}
	connSuFail := NewConnector(
		providerSu,
		WithSecretPrompter(prompter),
		WithCredentialRecorder(failRecorder),
	)
	connSuFail.AcceptNewHostKey.Store(true)
	defer func() { _ = connSuFail.CloseAll() }()

	clientSuFail, err := connSuFail.Connect(ctx, "node-prompt-su-fail")
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	_, runErr := clientSuFail.RunWithSudo(ctx, "whoami")
	if runErr == nil {
		t.Fatal("expected RunWithSudo to fail when writeback fails, got nil")
	}
	if !strings.Contains(runErr.Error(), "db writeback failed") {
		t.Errorf("expected writeback error chain preserved, got: %v", runErr)
	}
}

// TestPlaintextLifetime_BackendErrorTerminatesWithoutFallback 验证提权路径遇到后端故障立即报错不吞错误
func TestPlaintextLifetime_BackendErrorTerminatesWithoutFallback(t *testing.T) {
	setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	loginPwd := "login-backend-pwd"
	srv := startLifetimeTestSSHServerWithRecorder(t, loginPwd, nil)
	defer srv.cleanup()

	backendErr := errors.New("vault backend locked")
	errResolver := &mockErrResolver{
		err: backendErr,
	}

	nodeID := "node-backend-err"
	provider := &standaloneConnectionProvider{
		cfg: &ClientConfig{
			NodeID:   nodeID,
			Address:  srv.host,
			Port:     srv.port,
			User:     "testuser",
			AuthType: "password",
			Password: loginPwd, // 直接提供登录密码使建连通过
			SudoMode: SudoModeSu,
		},
	}

	connector := NewConnector(
		provider,
		WithSecretResolver(errResolver),
	)
	connector.AcceptNewHostKey.Store(true)
	defer func() { _ = connector.CloseAll() }()

	ctx := context.Background()
	client, err := connector.Connect(ctx, nodeID)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	// 1. runWithSuIO 提权：通过 RunCommandWithIO(..., true, ...) 验证后端错误被保留、远端命令未启动
	var stdout, stderr bytes.Buffer
	runErr := client.RunCommandWithIO(ctx, "whoami", true, bytes.NewReader(nil), &stdout, &stderr)
	if runErr == nil {
		t.Fatal("expected RunCommandWithIO to fail on resolver backend error, got nil")
	}
	if !errors.Is(runErr, backendErr) {
		t.Errorf("expected error chain to wrap backendErr, got: %v", runErr)
	}
	if stdout.Len() > 0 {
		t.Errorf("expected empty stdout when secret resolution fails, got: %q", stdout.String())
	}
	for _, cmd := range srv.getCommands() {
		if strings.Contains(cmd, "su") {
			t.Errorf("remote su command was started despite resolver error: %q", cmd)
		}
	}

	// 2. maybeDetectSudoMode 探测：遭遇后端故障绝不写回 SudoModeNone，必须返回错误
	recorder := &testRecorder{}
	providerDetect := &trackingProvider{
		cfg: &ClientConfig{
			NodeID:          "node-detect-backend-err",
			Address:         srv.host,
			Port:            srv.port,
			User:            "testuser",
			AuthType:        "password",
			Password:        loginPwd,
			SudoMode:        "", // 触发探测
			AuthUpdateToken: "auth-tok",
			SudoUpdateToken: "sudo-tok",
		},
	}
	connDetect := NewConnector(
		providerDetect,
		WithSecretResolver(errResolver),
		WithCredentialRecorder(recorder),
	)
	connDetect.AcceptNewHostKey.Store(true)
	defer func() { _ = connDetect.CloseAll() }()

	clientDetect, err := connDetect.Connect(ctx, "node-detect-backend-err")
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	detectErr := clientDetect.maybeDetectSudoMode(ctx)
	if detectErr == nil {
		t.Fatal("expected maybeDetectSudoMode to return backend error, got nil")
	}
	if !errors.Is(detectErr, backendErr) {
		t.Errorf("expected error chain to contain backendErr, got: %v", detectErr)
	}
	// 验证绝不写回 SudoModeNone
	if recorder.sudoCalls != 0 {
		t.Errorf("expected recorder.UpdateSudo NOT to be called, got %d", recorder.sudoCalls)
	}
}

type mockErrResolver struct {
	err error
}

func (m *mockErrResolver) ResolveSecret(ctx context.Context, req SecretRequest) ([]byte, error) {
	return nil, m.err
}

// TestPlaintextLifetime_PassphraseWipedOnAllErrorPaths 验证机密在所有提前返回、错误及回退出口均被清零
func TestPlaintextLifetime_PassphraseWipedOnAllErrorPaths(t *testing.T) {
	// 1. KeyPath 为空出口
	secret1 := []byte("secret-pass-1")
	cfg1 := &ClientConfig{
		KeyPath: "",
	}
	_, err1 := buildKeyAuthMethod(cfg1, secret1)
	if !errors.Is(err1, ErrKeyPathRequired) {
		t.Errorf("expected ErrKeyPathRequired, got: %v", err1)
	}
	assertSliceAllZero(t, "secret1", secret1)

	// 2. KeyPath 读文件失败出口
	secret2 := []byte("secret-pass-2")
	cfg2 := &ClientConfig{
		KeyPath: "/path/to/non-existent-key-file-12345",
	}
	_, err2 := buildKeyAuthMethod(cfg2, secret2)
	if err2 == nil {
		t.Fatal("expected error reading non-existent key file, got nil")
	}
	assertSliceAllZero(t, "secret2", secret2)

	// 3. resolvePrivilegeMaterial 中对 resolver 成功返回的原始切片清零
	rawSlice := []byte("returned-by-resolver")
	res := &sliceCheckingResolver{slice: rawSlice}
	c := &Client{
		resolver: res,
	}
	priv, err := c.resolvePrivilegeMaterial(context.Background(), SecretKindLoginPassword)
	if err != nil {
		t.Fatalf("resolvePrivilegeMaterial failed: %v", err)
	}
	defer priv.Zero()
	assertSliceAllZero(t, "rawSlice", rawSlice)

	// 4. resolvePrivilegeMaterial 中 resolver 同时返回机密和错误时，原始切片清零
	rawErrSlice := []byte("returned-with-error")
	resErr := &sliceCheckingResolver{slice: rawErrSlice, err: errors.New("backend failed")}
	cErr := &Client{
		resolver: resErr,
	}
	_, _ = cErr.resolvePrivilegeMaterial(context.Background(), SecretKindLoginPassword)
	assertSliceAllZero(t, "rawErrSlice", rawErrSlice)

	// 5. resolvePrivilegeMaterial 中 resolver 同时返回机密和 ErrInteractionRequired 回退时，原始切片清零
	rawFallbackSlice := []byte("returned-with-interaction-required")
	resFallback := &sliceCheckingResolver{slice: rawFallbackSlice, err: ErrInteractionRequired}
	cFallback := &Client{
		resolver: resFallback,
		prompter: &probeSecretPrompter{returnSecret: "prompt-fallback-pwd"},
	}
	privFallback, err := cFallback.resolvePrivilegeMaterial(context.Background(), SecretKindLoginPassword)
	if err != nil {
		t.Fatalf("resolvePrivilegeMaterial with fallback failed: %v", err)
	}
	defer privFallback.Zero()
	assertSliceAllZero(t, "rawFallbackSlice", rawFallbackSlice)

	// 6. autoSecretProvider.resolveOrPrompt 成功时清零 resolver 返回的原始切片
	autoSuccessSlice := []byte("auto-success-secret")
	resAuto := &sliceCheckingResolver{slice: autoSuccessSlice}
	autoProv := &autoSecretProvider{
		resolver: resAuto,
	}
	val, err := autoProv.resolveOrPrompt(SecretRequest{Kind: SecretKindLoginPassword})
	if err != nil || val != "auto-success-secret" {
		t.Fatalf("resolveOrPrompt unexpected result: val=%q, err=%v", val, err)
	}
	assertSliceAllZero(t, "autoSuccessSlice", autoSuccessSlice)

	// 7. autoSecretProvider.resolveOrPrompt 在 resolver 同时返回机密和错误时清零原始切片
	autoErrSlice := []byte("auto-error-secret")
	resAutoErr := &sliceCheckingResolver{slice: autoErrSlice, err: errors.New("auto backend failure")}
	autoProvErr := &autoSecretProvider{
		resolver: resAutoErr,
	}
	_, _ = autoProvErr.resolveOrPrompt(SecretRequest{Kind: SecretKindLoginPassword})
	assertSliceAllZero(t, "autoErrSlice", autoErrSlice)

	// 8. autoSecretProvider.resolveOrPrompt 在回退到 prompter 时清零原始切片
	autoFallbackSlice := []byte("auto-fallback-secret")
	resAutoFallback := &sliceCheckingResolver{slice: autoFallbackSlice, err: ErrInteractionRequired}
	autoProvFallback := &autoSecretProvider{
		resolver: resAutoFallback,
		prompter: &probeSecretPrompter{returnSecret: "prompter-val"},
	}
	pVal, pErr := autoProvFallback.resolveOrPrompt(SecretRequest{Kind: SecretKindLoginPassword})
	if pErr != nil || pVal != "prompter-val" {
		t.Fatalf("resolveOrPrompt with prompter unexpected result: val=%q, err=%v", pVal, pErr)
	}
	assertSliceAllZero(t, "autoFallbackSlice", autoFallbackSlice)
}

func assertSliceAllZero(t *testing.T, name string, s []byte) {
	t.Helper()
	for i, b := range s {
		if b != 0 {
			t.Errorf("expected %s[%d] to be 0, got %d", name, i, b)
		}
	}
}

type sliceCheckingResolver struct {
	slice []byte
	err   error
}

func (s *sliceCheckingResolver) ResolveSecret(ctx context.Context, req SecretRequest) ([]byte, error) {
	return s.slice, s.err
}

// TestPlaintextLifetime_InteractionTimeoutEnforced 验证提权交互在 WithInteractionTimeout 下施加有界超时
func TestPlaintextLifetime_InteractionTimeoutEnforced(t *testing.T) {
	setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	loginPwd := "pwd-interaction-timeout"
	host, port, cleanup := startLifetimeTestSSHServer(t, loginPwd, nil)
	defer cleanup()

	// 挂起的提示器：不理会并等待 context 结束
	hangingPrompter := &hangingSecretPrompter{}

	provider := &standaloneConnectionProvider{
		cfg: &ClientConfig{
			NodeID:   "node-interaction-timeout",
			Address:  host,
			Port:     port,
			User:     "testuser",
			AuthType: "password",
			Password: loginPwd, // 建连直接通过
			SudoMode: SudoModeSu,
		},
	}

	conn := NewConnector(
		provider,
		WithSecretPrompter(hangingPrompter),
		WithInteractionTimeout(40*time.Millisecond),
	)
	conn.AcceptNewHostKey.Store(true)
	defer func() { _ = conn.CloseAll() }()

	client, err := conn.Connect(context.Background(), "node-interaction-timeout")
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	// 传入带足够长时间的 context（2s），验证交互提示因 interactionTimeout（40ms）快速超时返回
	parentCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	_, runErr := client.RunWithSudo(parentCtx, "whoami")
	elapsed := time.Since(start)

	if runErr == nil {
		t.Fatal("expected RunWithSudo to fail due to interaction timeout, got nil")
	}
	if !errors.Is(runErr, context.DeadlineExceeded) && !strings.Contains(runErr.Error(), "context deadline exceeded") {
		t.Errorf("expected context.DeadlineExceeded error, got: %v", runErr)
	}
	if elapsed > 250*time.Millisecond {
		t.Errorf("expected fast timeout around 40ms, took %v", elapsed)
	}
}

type hangingSecretPrompter struct{}

func (h *hangingSecretPrompter) PromptSecret(ctx context.Context, req SecretRequest) (string, error) {
	if ctx != nil {
		<-ctx.Done()
		return "", ctx.Err()
	}
	time.Sleep(100 * time.Millisecond)
	return "", context.DeadlineExceeded
}

// TestTargetCompatibility_ValidatesAllTargetFields 验证连接目标各属性发生变化时均触发 ErrSnapshotMismatch
func TestTargetCompatibility_ValidatesAllTargetFields(t *testing.T) {
	base := ConnectionConfig{
		NodeID:    "node-compat",
		Address:   "10.0.0.1",
		Port:      22,
		User:      "testuser",
		KeyPath:   "/path/to/key",
		ProxyJump: "jump-node",
	}

	// 1. 完全一致
	cur := base
	matchedCfg := &ClientConfig{
		NodeID:    base.NodeID,
		Address:   base.Address,
		Port:      base.Port,
		User:      base.User,
		KeyPath:   base.KeyPath,
		ProxyJump: base.ProxyJump,
	}
	if err := validateTargetCompatibility(cur, matchedCfg); err != nil {
		t.Errorf("expected matched config to pass, got: %v", err)
	}

	// 2. nil 配置
	if err := validateTargetCompatibility(cur, nil); !errors.Is(err, ErrSnapshotMismatch) {
		t.Errorf("expected ErrSnapshotMismatch for nil config, got: %v", err)
	}

	// 3. Address 变动
	addrDiff := *matchedCfg
	addrDiff.Address = "10.0.0.2"
	if err := validateTargetCompatibility(cur, &addrDiff); !errors.Is(err, ErrSnapshotMismatch) || !strings.Contains(err.Error(), "host address changed") {
		t.Errorf("expected host address changed error, got: %v", err)
	}

	// 4. Port 变动
	portDiff := *matchedCfg
	portDiff.Port = 2222
	if err := validateTargetCompatibility(cur, &portDiff); !errors.Is(err, ErrSnapshotMismatch) || !strings.Contains(err.Error(), "host port changed") {
		t.Errorf("expected host port changed error, got: %v", err)
	}

	// 5. User 变动
	userDiff := *matchedCfg
	userDiff.User = "otheruser"
	if err := validateTargetCompatibility(cur, &userDiff); !errors.Is(err, ErrSnapshotMismatch) || !strings.Contains(err.Error(), "user changed") {
		t.Errorf("expected user changed error, got: %v", err)
	}

	// 6. KeyPath 变动
	keyDiff := *matchedCfg
	keyDiff.KeyPath = "/other/key"
	if err := validateTargetCompatibility(cur, &keyDiff); !errors.Is(err, ErrSnapshotMismatch) || !strings.Contains(err.Error(), "key path changed") {
		t.Errorf("expected key path changed error, got: %v", err)
	}

	// 7. ProxyJump 变动
	jumpDiff := *matchedCfg
	jumpDiff.ProxyJump = "other-jump"
	if err := validateTargetCompatibility(cur, &jumpDiff); !errors.Is(err, ErrSnapshotMismatch) || !strings.Contains(err.Error(), "proxy jump changed") {
		t.Errorf("expected proxy jump changed error, got: %v", err)
	}
}

// TestClient_RefreshConnectionTokens_DetectsTargetIncompatibilityAndPreservesTokens 验证 Client 刷新令牌时拒绝不兼容目标且不更新令牌
func TestClient_RefreshConnectionTokens_DetectsTargetIncompatibilityAndPreservesTokens(t *testing.T) {
	nodeID := "node-refresh-test"
	initialToken := "tok-initial-auth"
	initialSudoToken := "tok-initial-sudo"

	baseConnCfg := ConnectionConfig{
		NodeID:          nodeID,
		Address:         "192.168.1.100",
		Port:            22,
		User:            "admin",
		AuthUpdateToken: initialToken,
		SudoUpdateToken: initialSudoToken,
	}

	// 1. 目标端口被外部更新
	prov := &trackingProvider{
		cfg: &ClientConfig{
			NodeID:          nodeID,
			Address:         "192.168.1.100",
			Port:            2222, // 端口改变！
			User:            "admin",
			AuthUpdateToken: "tok-new-auth",
			SudoUpdateToken: "tok-new-sudo",
		},
	}

	c := &Client{
		connCfg:  baseConnCfg,
		provider: prov,
	}

	err := c.refreshConnectionTokens(tokenRefreshKindAuth, initialToken)
	if err == nil {
		t.Fatal("expected refreshConnectionTokens to fail when port changed, got nil")
	}
	if !errors.Is(err, ErrSnapshotMismatch) {
		t.Errorf("expected ErrSnapshotMismatch in error chain, got: %v", err)
	}

	// 验证 Client 内部令牌未被污染
	if c.connCfg.AuthUpdateToken != initialToken {
		t.Errorf("expected AuthUpdateToken to remain %q, got %q", initialToken, c.connCfg.AuthUpdateToken)
	}
	if c.connCfg.SudoUpdateToken != initialSudoToken {
		t.Errorf("expected SudoUpdateToken to remain %q, got %q", initialSudoToken, c.connCfg.SudoUpdateToken)
	}

	// 2. 幂等更新：committedToken 与 initialToken 相同，允许成功
	provSameToken := &trackingProvider{
		cfg: &ClientConfig{
			NodeID:          nodeID,
			Address:         "192.168.1.100",
			Port:            22,
			User:            "admin",
			AuthUpdateToken: initialToken, // 幂等未变！
			SudoUpdateToken: initialSudoToken,
		},
	}
	cSame := &Client{
		connCfg:  baseConnCfg,
		provider: provSameToken,
	}
	if errSame := cSame.refreshConnectionTokens(tokenRefreshKindAuth, initialToken); errSame != nil {
		t.Fatalf("expected idempotent refresh to succeed, got error: %v", errSame)
	}

	// 3. 版本不匹配：本次写回 committedToken 为 tok-committed，但刷新时取到了并发的 tok-concurrent，拒绝采纳
	provMismatch := &trackingProvider{
		cfg: &ClientConfig{
			NodeID:          nodeID,
			Address:         "192.168.1.100",
			Port:            22,
			User:            "admin",
			AuthUpdateToken: "tok-concurrent", // 第三方并发更新
			SudoUpdateToken: initialSudoToken,
		},
	}
	cMismatch := &Client{
		connCfg:  baseConnCfg,
		provider: provMismatch,
	}
	errMismatch := cMismatch.refreshConnectionTokens(tokenRefreshKindAuth, "tok-committed")
	if errMismatch == nil {
		t.Fatal("expected refreshConnectionTokens to fail when auth version mismatches committed token, got nil")
	}
	if !errors.Is(errMismatch, ErrSnapshotMismatch) {
		t.Errorf("expected ErrSnapshotMismatch when version mismatches, got: %v", errMismatch)
	}

	// 4. [P1 核心断言] 单类凭据写回刷新保留另一类凭据的原快照，绝不采纳无关版本
	// 4a. 提权写回刷新：只更新 SudoUpdateToken，严格保留 AuthUpdateToken
	provSudoRefresh := &trackingProvider{
		cfg: &ClientConfig{
			NodeID:          nodeID,
			Address:         "192.168.1.100",
			Port:            22,
			User:            "admin",
			AuthUpdateToken: "unrelated-concurrent-auth-token", // 并发变更的登录密码令牌
			SudoUpdateToken: "committed-sudo-token",
			SudoMode:        SudoModeSu,
		},
	}
	cSudo := &Client{
		connCfg:  baseConnCfg,
		provider: provSudoRefresh,
	}
	if err := cSudo.refreshConnectionTokens(tokenRefreshKindSudo, "committed-sudo-token"); err != nil {
		t.Fatalf("refreshConnectionTokens for sudo failed: %v", err)
	}
	if cSudo.connCfg.SudoUpdateToken != "committed-sudo-token" {
		t.Errorf("expected SudoUpdateToken to be %q, got %q", "committed-sudo-token", cSudo.connCfg.SudoUpdateToken)
	}
	if cSudo.connCfg.SudoMode != SudoModeSu {
		t.Errorf("expected SudoMode to be %q, got %q", SudoModeSu, cSudo.connCfg.SudoMode)
	}
	if cSudo.connCfg.AuthUpdateToken != initialToken {
		t.Errorf("expected AuthUpdateToken to remain %q, but got unrelated %q", initialToken, cSudo.connCfg.AuthUpdateToken)
	}

	// 4b. 认证写回刷新：只更新 AuthUpdateToken，严格保留 SudoUpdateToken 和 SudoMode
	provAuthRefresh := &trackingProvider{
		cfg: &ClientConfig{
			NodeID:          nodeID,
			Address:         "192.168.1.100",
			Port:            22,
			User:            "admin",
			AuthUpdateToken: "committed-auth-token",
			SudoUpdateToken: "unrelated-concurrent-sudo-token", // 并发变更的提权令牌
			SudoMode:        SudoModeNone,
		},
	}
	cAuth := &Client{
		connCfg:  baseConnCfg,
		provider: provAuthRefresh,
	}
	if err := cAuth.refreshConnectionTokens(tokenRefreshKindAuth, "committed-auth-token"); err != nil {
		t.Fatalf("refreshConnectionTokens for auth failed: %v", err)
	}
	if cAuth.connCfg.AuthUpdateToken != "committed-auth-token" {
		t.Errorf("expected AuthUpdateToken to be %q, got %q", "committed-auth-token", cAuth.connCfg.AuthUpdateToken)
	}
	if cAuth.connCfg.SudoUpdateToken != initialSudoToken {
		t.Errorf("expected SudoUpdateToken to remain %q, but got unrelated %q", initialSudoToken, cAuth.connCfg.SudoUpdateToken)
	}
	if cAuth.connCfg.SudoMode != baseConnCfg.SudoMode {
		t.Errorf("expected SudoMode to remain %q, but got unrelated %q", baseConnCfg.SudoMode, cAuth.connCfg.SudoMode)
	}
}

// TestPlaintextLifetime_CrossKind_SudoUpdate_PreservesAuthSnapshot 验证提权写回期间并发修改登录密码时，Sudo 刷新严格保留旧 Auth 快照
func TestPlaintextLifetime_CrossKind_SudoUpdate_PreservesAuthSnapshot(t *testing.T) {
	nodeID := "node-cross-sudo"
	origAuthToken := "auth-tok-orig"
	origSudoToken := "sudo-tok-orig"

	provider := &trackingProvider{
		cfg: &ClientConfig{
			NodeID:          nodeID,
			Address:         "192.168.1.100",
			Port:            22,
			User:            "testuser",
			AuthUpdateToken: origAuthToken,
			SudoUpdateToken: origSudoToken,
			SudoMode:        SudoModeAuto,
		},
	}

	recorder := &testRecorder{
		sudoCommittedToken: "sudo-tok-committed",
		onUpdateSudo: func() {
			// 模拟在 UpdateSudo 期间，外部并发更新了登录密码，导致 provider 的 AuthUpdateToken 推进
			provider.mu.Lock()
			provider.cfg.AuthUpdateToken = "concurrent-unrelated-auth-tok"
			provider.cfg.SudoUpdateToken = "sudo-tok-committed"
			provider.cfg.SudoMode = SudoModeSudo
			provider.mu.Unlock()
		},
	}

	client := newClientWithComponents(
		nil,
		nil,
		provider.cfg,
		provider,
		nil,
		nil,
		recorder,
		"",
		time.Second,
		time.Second,
		nil,
	)

	ctx := context.Background()
	if err := client.updateSudoMode(ctx, SudoModeSudo); err != nil {
		t.Fatalf("updateSudoMode failed: %v", err)
	}

	// [P1] 断言：Sudo 令牌和模式成功更新为本次写回结果，但 Auth 令牌严格保留 origAuthToken，绝不接纳 concurrent-unrelated-auth-tok
	if client.Config().SudoUpdateToken != "sudo-tok-committed" {
		t.Errorf("expected SudoUpdateToken = %q, got %q", "sudo-tok-committed", client.Config().SudoUpdateToken)
	}
	if client.Config().SudoMode != SudoModeSudo {
		t.Errorf("expected SudoMode = %q, got %q", SudoModeSudo, client.Config().SudoMode)
	}
	if client.Config().AuthUpdateToken != origAuthToken {
		t.Fatalf("expected AuthUpdateToken to remain %q, but got unrelated %q", origAuthToken, client.Config().AuthUpdateToken)
	}
}

// TestPlaintextLifetime_CrossKind_AuthUpdate_PreservesSudoSnapshot 验证登录认证写回期间并发修改提权设置时，Auth 刷新严格保留旧 Sudo 快照
func TestPlaintextLifetime_CrossKind_AuthUpdate_PreservesSudoSnapshot(t *testing.T) {
	nodeID := "node-cross-auth"
	origAuthToken := "auth-tok-orig"
	origSudoToken := "sudo-tok-orig"

	provider := &trackingProvider{
		cfg: &ClientConfig{
			NodeID:          nodeID,
			Address:         "192.168.1.100",
			Port:            22,
			User:            "testuser",
			AuthUpdateToken: origAuthToken,
			SudoUpdateToken: origSudoToken,
			SudoMode:        SudoModeSudo,
		},
	}

	recorder := &testRecorder{
		authCommittedToken: "auth-tok-committed",
		onUpdateAuth: func() {
			// 模拟在 UpdateAuth 期间，外部并发更新了提权凭据，导致 provider 的 SudoUpdateToken 推进
			provider.mu.Lock()
			provider.cfg.AuthUpdateToken = "auth-tok-committed"
			provider.cfg.SudoUpdateToken = "concurrent-unrelated-sudo-tok"
			provider.cfg.SudoMode = SudoModeSu
			provider.mu.Unlock()
		},
	}

	client := newClientWithComponents(
		nil,
		nil,
		provider.cfg,
		provider,
		nil,
		nil,
		recorder,
		"",
		time.Second,
		time.Second,
		nil,
	)

	ctx := context.Background()
	if err := client.recordPrivilegeSecret(ctx, SecretKindLoginPassword, client.connCfg, "new-pass"); err != nil {
		t.Fatalf("recordPrivilegeSecret failed: %v", err)
	}

	// [P1] 断言：Auth 令牌成功更新为本次写回结果，但 Sudo 令牌与 SudoMode 严格保留旧快照，绝不接纳并发的提权版本
	if client.Config().AuthUpdateToken != "auth-tok-committed" {
		t.Errorf("expected AuthUpdateToken = %q, got %q", "auth-tok-committed", client.Config().AuthUpdateToken)
	}
	if client.Config().SudoUpdateToken != origSudoToken {
		t.Fatalf("expected SudoUpdateToken to remain %q, but got unrelated %q", origSudoToken, client.Config().SudoUpdateToken)
	}
	if client.Config().SudoMode != SudoModeSudo {
		t.Fatalf("expected SudoMode to remain %q, but got unrelated %q", SudoModeSudo, client.Config().SudoMode)
	}
}

// TestPlaintextLifetime_CrossKind_HandshakeAuthUpdate_PreservesSudoSnapshot 验证建连握手写回期间并发修改提权设置时，握手刷新严格保留旧 Sudo 快照
func TestPlaintextLifetime_CrossKind_HandshakeAuthUpdate_PreservesSudoSnapshot(t *testing.T) {
	setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	expectedPwd := "handshake-pwd"
	host, port, cleanup := startLifetimeTestSSHServer(t, expectedPwd, nil)
	defer cleanup()

	nodeID := "node-cross-handshake"
	origAuthToken := "auth-tok-orig"
	origSudoToken := "sudo-tok-orig"

	provider := &trackingProvider{
		cfg: &ClientConfig{
			NodeID:          nodeID,
			Address:         host,
			Port:            port,
			User:            "testuser",
			AuthType:        "auto",
			Password:        "",
			AuthUpdateToken: origAuthToken,
			SudoUpdateToken: origSudoToken,
			SudoMode:        SudoModeSudo,
		},
	}

	recorder := &testRecorder{
		authCommittedToken: "auth-tok-committed",
		onUpdateAuth: func() {
			// 模拟在握手写回 UpdateAuth 期间，外部并发更新了提权凭据
			provider.mu.Lock()
			provider.cfg.AuthUpdateToken = "auth-tok-committed"
			provider.cfg.Password = expectedPwd
			provider.cfg.SudoUpdateToken = "concurrent-unrelated-sudo-tok"
			provider.cfg.SudoMode = SudoModeSu
			provider.mu.Unlock()
		},
	}

	prompter := &probeSecretPrompter{returnSecret: expectedPwd}
	connector := NewConnector(
		provider,
		WithSecretPrompter(prompter),
		WithCredentialRecorder(recorder),
	)
	connector.AcceptNewHostKey.Store(true)
	defer func() { _ = connector.CloseAll() }()

	ctx := context.Background()
	client, err := connector.Connect(ctx, nodeID)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	// [P1] 断言：建连成功后，Client 的 Auth 令牌更新为本次握手写回版本，但 Sudo 令牌与 SudoMode 严格保留建连开始时的旧快照
	if client.Config().AuthUpdateToken != "auth-tok-committed" {
		t.Errorf("expected AuthUpdateToken = %q, got %q", "auth-tok-committed", client.Config().AuthUpdateToken)
	}
	if client.Config().SudoUpdateToken != origSudoToken {
		t.Fatalf("expected SudoUpdateToken to remain %q, but got unrelated %q", origSudoToken, client.Config().SudoUpdateToken)
	}
	if client.Config().SudoMode != SudoModeSudo {
		t.Fatalf("expected SudoMode to remain %q, but got unrelated %q", SudoModeSudo, client.Config().SudoMode)
	}
}
