package ssh

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/internal/testleak"
	"golang.org/x/crypto/ssh"
)

type characterizationRecordingStore struct {
	mu           sync.Mutex
	cfg          *ClientConfig
	updateCalls  int
	lastPassword string
	lastToken    string
	updateErr    error
}

func (s *characterizationRecordingStore) GetConfig(nodeID string) (*ClientConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg == nil {
		return nil, fmt.Errorf("node %q not found", nodeID)
	}
	cp := *s.cfg
	return &cp, nil
}

func (s *characterizationRecordingStore) UpdateAuth(ctx context.Context, nodeID, authUpdateToken, password, keyPath, passphrase string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updateCalls++
	s.lastPassword = password
	s.lastToken = authUpdateToken
	if s.updateErr != nil {
		return s.updateErr
	}
	if s.cfg != nil {
		s.cfg.Password = password
		s.cfg.AuthType = "password"
	}
	return nil
}

func (s *characterizationRecordingStore) UpdateSudo(ctx context.Context, nodeID, sudoUpdateToken string, mode SudoMode, suPwd string) error {
	return nil
}

type testAutoInteractionHandler struct {
	passwordToProvide string
}

func (h *testAutoInteractionHandler) PromptSecret(ctx context.Context, req SecretRequest) (string, error) {
	return h.passwordToProvide, nil
}

func (h *testAutoInteractionHandler) ConfirmHostKey(ctx context.Context, req HostKeyConfirmation) (bool, error) {
	return true, nil
}

func startTestAutoSSHServer(t *testing.T, expectedPassword string) (string, <-chan struct{}, func()) {
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
	clientDisconnectedCh := make(chan struct{}, 4)

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
				defer func() {
					_ = sConn.Close()
				}()

				// 监控客户端断开连接（当客户端主动 rootConn.Close() 时退出）
				go func() {
					_ = sConn.Wait()
					select {
					case clientDisconnectedCh <- struct{}{}:
					default:
					}
				}()

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
			t.Errorf("test SSH server cleanup timed out waiting for goroutines")
		}
	}

	return listener.Addr().String(), clientDisconnectedCh, cleanup
}

func TestCharacterization_AutoAuth_PromptsSecret_WritesBackOnSuccess(t *testing.T) {
	// 隔离环境，防止污染宿主机 ~/.ssh/known_hosts 并避免干扰 auto 认证
	setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	const validPassword = "discovered-auto-secret"
	addr, _, stopServer := startTestAutoSSHServer(t, validPassword)
	t.Cleanup(stopServer)

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port failed: %v", err)
	}
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	store := &characterizationRecordingStore{
		cfg: &ClientConfig{
			NodeID:          "node-auto",
			Address:         host,
			Port:            port,
			User:            "testuser",
			AuthType:        "auto",
			AuthUpdateToken: "token-v1-abc",
		},
	}

	bufLogger := testleak.NewBufferLogger()
	handler := &testAutoInteractionHandler{passwordToProvide: validPassword}
	connector := NewConnector(store,
		WithInteractionHandler(handler),
		WithHandshakeTimeout(2*time.Second),
		WithLogger(bufLogger),
	)
	t.Cleanup(func() {
		if closeErr := connector.CloseAll(); closeErr != nil {
			t.Errorf("connector.CloseAll failed: %v", closeErr)
		}
	})

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	client, err := connector.Connect(ctx, "node-auto")
	if err != nil {
		t.Fatalf("connector.Connect failed: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil SSH client")
	}

	// 验证特征：UpdateAuth 被触发，且密码被写回
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.updateCalls != 1 {
		t.Fatalf("expected UpdateAuth to be called once, got %d", store.updateCalls)
	}
	if store.lastPassword != validPassword {
		t.Fatalf("UpdateAuth received password %q, want %q", store.lastPassword, validPassword)
	}
	if store.lastToken != "token-v1-abc" {
		t.Fatalf("UpdateAuth received token %q, want 'token-v1-abc'", store.lastToken)
	}
	if store.cfg.AuthType != "password" {
		t.Fatalf("cfg.AuthType = %q, want 'password'", store.cfg.AuthType)
	}

	// 捕获日志并断言秘密绝未泄漏在日志输出中
	testleak.AssertNoSecretInLogs(t, bufLogger, validPassword)
}

func TestCharacterization_AutoAuth_UpdateAuthFailure_ClosesUnpublishedClient(t *testing.T) {
	// 隔离环境，防止污染宿主机 ~/.ssh/known_hosts 并避免干扰 auto 认证
	setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	const validPassword = "discovered-auto-secret"
	addr, disconnectedCh, stopServer := startTestAutoSSHServer(t, validPassword)
	t.Cleanup(stopServer)

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port failed: %v", err)
	}
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	expectedUpdateErr := errors.New("simulated persistence failure")
	store := &characterizationRecordingStore{
		cfg: &ClientConfig{
			NodeID:          "node-auto-fail",
			Address:         host,
			Port:            port,
			User:            "testuser",
			AuthType:        "auto",
			AuthUpdateToken: "token-fail-123",
		},
		updateErr: expectedUpdateErr,
	}

	bufLogger := testleak.NewBufferLogger()
	handler := &testAutoInteractionHandler{passwordToProvide: validPassword}
	connector := NewConnector(store,
		WithInteractionHandler(handler),
		WithHandshakeTimeout(2*time.Second),
		WithLogger(bufLogger),
	)
	t.Cleanup(func() {
		_ = connector.CloseAll()
	})

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	_, err = connector.Connect(ctx, "node-auto-fail")
	if err == nil {
		t.Fatal("expected Connect to fail when UpdateAuth fails")
	}

	// 必须准确包装预期持久化错误，防止误将握手失败当成 UpdateAuth 失败通过
	if !errors.Is(err, expectedUpdateErr) {
		t.Fatalf("expected error to wrap expectedUpdateErr, got: %v", err)
	}

	// 验证 UpdateAuth 确实被调用了 1 次
	store.mu.Lock()
	calls := store.updateCalls
	store.mu.Unlock()
	if calls != 1 {
		t.Fatalf("expected UpdateAuth to be called exactly once, got %d", calls)
	}

	// 确认 client 没有被发布到池中
	_, hasClient := connector.clients.Get("node-auto-fail")
	if hasClient {
		t.Fatal("client was published despite UpdateAuth failure")
	}

	// 在服务端 cleanup 执行前，有界断言客户端主动关闭了未入池连接（杜绝连接泄漏）
	select {
	case <-disconnectedCh:
		// 验证通过：客户端在写回失败后主动断开/关闭了未入池连接
	case <-time.After(2 * time.Second):
		t.Fatal("connection leak: client did not close connection after UpdateAuth failure")
	}

	// 断言错误信息和日志中不泄露敏感密码
	testleak.AssertNoSecretInError(t, err, validPassword)
	testleak.AssertNoSecretInLogs(t, bufLogger, validPassword)
}
