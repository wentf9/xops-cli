package mcpserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/internal/testleak"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/ssh"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func isolateMCPTestEnvironment(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Setenv("SSH_AUTH_SOCK", "")
	return dir
}

func startTestSSHServerForMCP(t *testing.T) (string, cryptossh.PublicKey, func()) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test rsa key failed: %v", err)
	}
	signer, err := cryptossh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("create test signer failed: %v", err)
	}

	serverConfig := &cryptossh.ServerConfig{
		PasswordCallback: func(conn cryptossh.ConnMetadata, password []byte) (*cryptossh.Permissions, error) {
			return nil, errors.New("unauthorized: password prompt required")
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
				sConn, chans, reqs, srvErr := cryptossh.NewServerConn(c, serverConfig)
				if srvErr != nil {
					return
				}
				defer func() { _ = sConn.Close() }()

				reqWG := sync.WaitGroup{}
				reqWG.Add(1)
				go func() {
					defer reqWG.Done()
					cryptossh.DiscardRequests(reqs)
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

	return listener.Addr().String(), signer.PublicKey(), cleanup
}

func TestCharacterization_MCP_ListNodes_DoesNotLeakPlaintextCredentials(t *testing.T) {
	_ = isolateMCPTestEnvironment(t)

	const (
		sensitivePassword   = "mcp-flow-secret-login-pwd-9876"
		sensitivePassphrase = "mcp-flow-secret-passphrase-5432"
		sensitiveSuPwd      = "mcp-flow-secret-supwd-1098"
	)

	nodes := concurrent.NewMap[string, models.Node](concurrent.HashString)
	hosts := concurrent.NewMap[string, models.Host](concurrent.HashString)
	identities := concurrent.NewMap[string, models.Identity](concurrent.HashString)

	hosts.Set("host-prod", models.Host{Address: "10.0.0.8", Port: 22})
	identities.Set("id-prod", models.Identity{
		User:       "admin",
		AuthType:   "password",
		Password:   sensitivePassword,
		Passphrase: sensitivePassphrase,
	})
	nodes.Set("node-prod", models.Node{
		HostRef:     "host-prod",
		IdentityRef: "id-prod",
		SudoMode:    models.SudoModeSu,
		SuPwd:       sensitiveSuPwd,
		Tags:        []string{"prod", "database"},
	})

	cfg := &config.Configuration{
		Nodes:      nodes,
		Hosts:      hosts,
		Identities: identities,
	}
	provider := config.NewProviderWithoutOpenSSH(cfg)

	bufLogger := testleak.NewBufferLogger()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()

	conn := newMCPConnector(ctx, provider, bufLogger)
	t.Cleanup(func() {
		_ = conn.CloseAll()
	})

	mcpMu.Lock()
	oldConn := mcpConnector
	oldProvider := mcpProvider
	mcpConnector = conn
	mcpProvider = provider
	mcpMu.Unlock()

	t.Cleanup(func() {
		mcpMu.Lock()
		mcpConnector = oldConn
		mcpProvider = oldProvider
		mcpMu.Unlock()
	})

	// 调用 xops_list_nodes 工具
	_, listOut, err := listNodesHandler(ctx, nil, ListNodesInput{})
	if err != nil {
		t.Fatalf("listNodesHandler failed: %v", err)
	}

	// 序列化输出并断言明文机密（密码、密钥passphrase、提权密码）没有泄露在输出对象中
	jsonBytes, err := json.Marshal(listOut)
	if err != nil {
		t.Fatalf("marshal list output failed: %v", err)
	}
	testleak.AssertNoSecretInBytes(t, jsonBytes, sensitivePassword, sensitivePassphrase, sensitiveSuPwd)

	// 断言日志流中无敏感信息泄露
	testleak.AssertNoSecretInLogs(t, bufLogger, sensitivePassword, sensitivePassphrase, sensitiveSuPwd)
}

func TestCharacterization_MCP_FailClosedOnMissingCredential_DoesNotLeakSecrets(t *testing.T) {
	_ = isolateMCPTestEnvironment(t)

	const (
		configuredSuPwd        = "mcp-flow-configured-supwd-4444"
		clusterSensitiveSecret = "mcp-cluster-wide-secret-token-3333"
	)

	nodes := concurrent.NewMap[string, models.Node](concurrent.HashString)
	hosts := concurrent.NewMap[string, models.Host](concurrent.HashString)
	identities := concurrent.NewMap[string, models.Identity](concurrent.HashString)

	hosts.Set("host-unauth", models.Host{Address: "127.0.0.1", Port: 22})
	identities.Set("id-empty-pwd", models.Identity{
		User:     "guest",
		AuthType: "password",
		Password: "", // 空密码，触发 ErrPasswordRequired
	})
	nodes.Set("node-unauth", models.Node{
		HostRef:     "host-unauth",
		IdentityRef: "id-empty-pwd",
		SudoMode:    models.SudoModeSu,
		SuPwd:       configuredSuPwd, // 真实注入提权机密到数据流
	})

	// 注入集群其它敏感节点凭据
	identities.Set("id-cluster", models.Identity{
		User:     "root",
		AuthType: "password",
		Password: clusterSensitiveSecret,
	})

	cfg := &config.Configuration{
		Nodes:      nodes,
		Hosts:      hosts,
		Identities: identities,
	}
	provider := config.NewProviderWithoutOpenSSH(cfg)

	bufLogger := testleak.NewBufferLogger()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()

	conn := newMCPConnector(ctx, provider, bufLogger)
	t.Cleanup(func() {
		_ = conn.CloseAll()
	})

	mcpMu.Lock()
	oldConn := mcpConnector
	oldProvider := mcpProvider
	mcpConnector = conn
	mcpProvider = provider
	mcpMu.Unlock()

	t.Cleanup(func() {
		mcpMu.Lock()
		mcpConnector = oldConn
		mcpProvider = oldProvider
		mcpMu.Unlock()
	})

	// 1. 测试直接调用 connectMCPNode
	client, err := connectMCPNode(ctx, "node-unauth")
	if err == nil {
		if client != nil {
			_ = client.Close()
		}
		t.Fatal("expected connectMCPNode to fail in MCP mode without credentials, got success")
	}

	// 验证错误被 FormatMCPError 处理，且由于缺少密码返回 ErrPasswordRequired
	if !errors.Is(err, ssh.ErrPasswordRequired) {
		t.Fatalf("expected ErrPasswordRequired, got %v", err)
	}
	testleak.AssertNoSecretInError(t, err, configuredSuPwd, clusterSensitiveSecret)

	// 2. 测试通过 sshRunHandler 调用，检查命令输出与错误返回
	_, runOut, runErr := sshRunHandler(ctx, nil, SshRunInput{
		NodeID:  "node-unauth",
		Command: "whoami",
	})
	if runErr == nil {
		t.Fatal("expected sshRunHandler to fail, got success")
	}
	if !errors.Is(runErr, ssh.ErrPasswordRequired) {
		t.Fatalf("expected sshRunHandler to return ErrPasswordRequired, got %v", runErr)
	}
	if runOut.Status != "" && runOut.Status != "failed" {
		t.Fatalf("expected failed status, got %q", runOut.Status)
	}

	// 验证命令输出、命令错误以及运行时日志均不泄露数据流中的任何秘密
	testleak.AssertNoSecretInString(t, runOut.Output, configuredSuPwd, clusterSensitiveSecret)
	testleak.AssertNoSecretInString(t, runOut.Error, configuredSuPwd, clusterSensitiveSecret)
	testleak.AssertNoSecretInError(t, runErr, configuredSuPwd, clusterSensitiveSecret)
	testleak.AssertNoSecretInLogs(t, bufLogger, configuredSuPwd, clusterSensitiveSecret)
}

func TestCharacterization_MCP_FailClosedOnInteractionRequired_DoesNotLeakSecrets(t *testing.T) {
	tempHome := isolateMCPTestEnvironment(t)

	// 启动真实孤立的本地测试 SSH 服务端，并获取其公钥
	addr, serverPubKey, stopServer := startTestSSHServerForMCP(t)
	t.Cleanup(stopServer)

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port failed: %v", err)
	}
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	// 预先将测试服务器公钥写入临时 known_hosts，彻底消除主机密钥确认拦截，
	// 确保测试精准断言登录密码交互提示路径被拒绝！
	knownHostsPath := filepath.Join(tempHome, ".ssh", "known_hosts")
	if mkErr := os.MkdirAll(filepath.Dir(knownHostsPath), 0700); mkErr != nil {
		t.Fatalf("mkdir .ssh failed: %v", mkErr)
	}
	targetSpec := knownhosts.Normalize(fmt.Sprintf("%s:%d", host, port))
	knownHostsLine := knownhosts.Line([]string{targetSpec}, serverPubKey)
	if writeErr := os.WriteFile(knownHostsPath, []byte(knownHostsLine+"\n"), 0600); writeErr != nil {
		t.Fatalf("write known_hosts failed: %v", writeErr)
	}

	const (
		injectedLoginPassword    = "injected-node-flow-login-pwd-9999"
		injectedPassphraseSecret = "injected-node-flow-passphrase-7777"
		injectedSuSecret         = "injected-node-flow-supwd-8888"
	)

	nodes := concurrent.NewMap[string, models.Node](concurrent.HashString)
	hosts := concurrent.NewMap[string, models.Host](concurrent.HashString)
	identities := concurrent.NewMap[string, models.Identity](concurrent.HashString)

	// 节点 1：Pre-connect 提权交互失败场景（SudoModeSu 缺少 SuPwd）
	hosts.Set("host-su-prompt", models.Host{Address: host, Port: uint16(port)})
	identities.Set("id-su-prompt", models.Identity{
		User:       "operator",
		AuthType:   "password",
		Password:   injectedLoginPassword, // 真实注入登录密码
		Passphrase: injectedPassphraseSecret,
	})
	nodes.Set("node-su-prompt", models.Node{
		HostRef:     "host-su-prompt",
		IdentityRef: "id-su-prompt",
		SudoMode:    models.SudoModeSu,
		SuPwd:       "", // 空提权密码，握手前触发提权交互提示
	})

	// 节点 2：Handshake 认证交互失败场景（auto 模式在握手时需交互密码）
	hosts.Set("host-handshake-prompt", models.Host{Address: host, Port: uint16(port)})
	identities.Set("id-handshake-prompt", models.Identity{
		User:       "operator",
		AuthType:   "auto",
		Password:   "", // 空密码触发握手密码提示
		Passphrase: injectedPassphraseSecret,
	})
	nodes.Set("node-handshake-prompt", models.Node{
		HostRef:     "host-handshake-prompt",
		IdentityRef: "id-handshake-prompt",
		SudoMode:    models.SudoModeSu,
		SuPwd:       injectedSuSecret, // 真实注入提权密码
	})

	cfg := &config.Configuration{
		Nodes:      nodes,
		Hosts:      hosts,
		Identities: identities,
	}
	provider := config.NewProviderWithoutOpenSSH(cfg)

	bufLogger := testleak.NewBufferLogger()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	conn := newMCPConnector(ctx, provider, bufLogger)
	t.Cleanup(func() {
		_ = conn.CloseAll()
	})

	mcpMu.Lock()
	oldConn := mcpConnector
	oldProvider := mcpProvider
	mcpConnector = conn
	mcpProvider = provider
	mcpMu.Unlock()

	t.Cleanup(func() {
		mcpMu.Lock()
		mcpConnector = oldConn
		mcpProvider = oldProvider
		mcpMu.Unlock()
	})

	allSecrets := []string{injectedLoginPassword, injectedPassphraseSecret, injectedSuSecret}

	// 1. 测试 Pre-connect 阶段由于提权交互导致的 fail-closed
	_, err = connectMCPNode(ctx, "node-su-prompt")
	if err == nil {
		t.Fatal("expected interaction required error for node-su-prompt, got nil")
	}
	if !errors.Is(err, ssh.ErrInteractionRequired) {
		t.Fatalf("expected ssh.ErrInteractionRequired, got: %v", err)
	}
	if !strings.Contains(err.Error(), "prompts are disabled in MCP mode") {
		t.Fatalf("expected prompt disabled error message, got: %v", err)
	}
	testleak.AssertNoSecretInError(t, err, allSecrets...)

	// 2. 测试 Handshake 阶段由于 auto 密码交互提示导致的 fail-closed
	_, errHandshake := connectMCPNode(ctx, "node-handshake-prompt")
	if errHandshake == nil {
		t.Fatal("expected interaction required error for node-handshake-prompt, got nil")
	}
	if !errors.Is(errHandshake, ssh.ErrInteractionRequired) {
		t.Fatalf("expected ssh.ErrInteractionRequired, got: %v", errHandshake)
	}
	// 精准验证：错误明确源自密码交互提示路径（"failed to read password"），而非主机密钥确认拦截（"read response failed"）
	if !strings.Contains(errHandshake.Error(), "failed to read password") {
		t.Fatalf("expected error to originate from password prompt, got: %v", errHandshake)
	}
	if strings.Contains(errHandshake.Error(), "read response failed") {
		t.Fatalf("error unexpectedly intercepted by host key verification: %v", errHandshake)
	}
	testleak.AssertNoSecretInError(t, errHandshake, allSecrets...)

	// 3. 测试通过 sshRunHandler 调用
	_, runOut, runErr := sshRunHandler(ctx, nil, SshRunInput{
		NodeID:  "node-handshake-prompt",
		Command: "uname -a",
	})
	if runErr == nil {
		t.Fatal("expected sshRunHandler to fail on interaction required, got nil")
	}
	if !errors.Is(runErr, ssh.ErrInteractionRequired) {
		t.Fatalf("expected ErrInteractionRequired from sshRunHandler, got: %v", runErr)
	}
	if !strings.Contains(runErr.Error(), "failed to read password") {
		t.Fatalf("expected runErr to originate from password prompt, got: %v", runErr)
	}

	// 核心安全断言：流经配置和运行时的实际机密绝不在错误、命令输出、日志流中泄漏
	testleak.AssertNoSecretInError(t, runErr, allSecrets...)
	testleak.AssertNoSecretInString(t, runOut.Output, allSecrets...)
	testleak.AssertNoSecretInString(t, runOut.Error, allSecrets...)
	testleak.AssertNoSecretInLogs(t, bufLogger, allSecrets...)
}
