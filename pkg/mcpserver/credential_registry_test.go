package mcpserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/internal/testleak"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/ssh"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// registryTestMemStore 是用于单元测试的内存凭据存储，实现 credential.Store 接口
type registryTestMemStore struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func newRegistryTestMemStore() *registryTestMemStore {
	return &registryTestMemStore{data: make(map[string][]byte)}
}

func (s *registryTestMemStore) Get(_ context.Context, ref credential.Ref) (credential.Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.data[ref.ItemID]
	if !ok {
		return credential.Secret{}, credential.ErrCredentialNotFound
	}
	return credential.Secret{Value: bytes.Clone(v)}, nil
}

func (s *registryTestMemStore) Put(_ context.Context, ref credential.Ref, secret credential.Secret) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[ref.ItemID] = bytes.Clone(secret.Value)
	return nil
}

func (s *registryTestMemStore) Delete(_ context.Context, ref credential.Ref) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, ref.ItemID)
	return nil
}

// buildRegistryWithPassword 创建包含给定密码的内存注册表，返回注册表和对应 Ref。
func buildRegistryWithPassword(t *testing.T, password string) (*credential.Registry, credential.Ref) {
	t.Helper()
	store := newRegistryTestMemStore()
	ref := credential.Ref{StoreID: "mem", ItemID: "item-pwd"}
	if err := store.Put(context.Background(), ref, credential.Secret{Value: []byte(password)}); err != nil {
		t.Fatalf("buildRegistryWithPassword: store.Put failed: %v", err)
	}
	reg := credential.NewRegistry()
	if err := reg.Register("mem", store); err != nil {
		t.Fatalf("buildRegistryWithPassword: reg.Register failed: %v", err)
	}
	return reg, ref
}

// writeKnownHosts 将给定公钥写入临时 known_hosts 文件以消除主机密钥交互拦截。
func writeKnownHosts(t *testing.T, homeDir, host, portStr string, pubKey cryptossh.PublicKey) {
	t.Helper()
	knownHostsPath := filepath.Join(homeDir, ".ssh", "known_hosts")
	if err := os.MkdirAll(filepath.Dir(knownHostsPath), 0700); err != nil {
		t.Fatalf("mkdir .ssh failed: %v", err)
	}
	targetSpec := knownhosts.Normalize(net.JoinHostPort(host, portStr))
	line := knownhosts.Line([]string{targetSpec}, pubKey)
	if err := os.WriteFile(knownHostsPath, []byte(line+"\n"), 0600); err != nil {
		t.Fatalf("write known_hosts failed: %v", err)
	}
}

// TestMCPConnector_WithCredentialRegistry_ResolvesStoredPassword 验证当 WithCredentialRegistry
// 注入了包含正确密码的 Store 后，MCP 连接器能解析密码并成功建立 SSH 连接（非交互模式）。
func TestMCPConnector_WithCredentialRegistry_ResolvesStoredPassword(t *testing.T) {
	tempHome := isolateMCPTestEnvironment(t)

	// startTestSSHServerForMCP 接受密码 "injected-node-flow-login-pwd-9999"
	const storedPassword = "injected-node-flow-login-pwd-9999"
	addr, serverPubKey, stopServer := startTestSSHServerForMCP(t)
	t.Cleanup(stopServer)

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port failed: %v", err)
	}
	var port int
	if _, scanErr := fmt.Sscanf(portStr, "%d", &port); scanErr != nil {
		t.Fatalf("parse port failed: %v", scanErr)
	}

	writeKnownHosts(t, tempHome, host, portStr, serverPubKey)

	reg, ref := buildRegistryWithPassword(t, storedPassword)

	nodes := concurrent.NewMap[string, models.Node](concurrent.HashString)
	hosts := concurrent.NewMap[string, models.Host](concurrent.HashString)
	identities := concurrent.NewMap[string, models.Identity](concurrent.HashString)

	hosts.Set("host-store-pwd", models.Host{Address: host, Port: uint16(port)})
	identities.Set("id-store-pwd", models.Identity{
		User:             "operator",
		AuthType:         "password",
		Password:         "",   // 不在配置中存储明文
		LoginPasswordRef: &ref, // 从 Store 解析
	})
	nodes.Set("node-store-pwd", models.Node{
		HostRef:     "host-store-pwd",
		IdentityRef: "id-store-pwd",
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

	// 注入凭据注册表，创建 MCP 连接器
	conn := newMCPConnector(ctx, provider, bufLogger, reg)
	t.Cleanup(func() {
		_ = conn.CloseAll()
	})

	// 连接应成功（密码从 Store 解析，非交互模式仍能认证）
	client, connErr := conn.Connect(ctx, "node-store-pwd")
	if connErr != nil {
		t.Fatalf("expected successful connection with stored credential, got: %v", connErr)
	}
	if client != nil {
		_ = client.Close()
	}

	// 确认日志中无明文密码泄露
	testleak.AssertNoSecretInLogs(t, bufLogger, storedPassword)
}

// TestMCPConnector_WithoutCredentialRegistry_FailsClosed 验证当没有注入凭据注册表，
// 且配置中也没有明文密码时，MCP 连接器在非交互模式下快速 fail-closed，
// 而不是无限挂起等待用户输入。
func TestMCPConnector_WithoutCredentialRegistry_FailsClosed(t *testing.T) {
	_ = isolateMCPTestEnvironment(t)

	nodes := concurrent.NewMap[string, models.Node](concurrent.HashString)
	hosts := concurrent.NewMap[string, models.Host](concurrent.HashString)
	identities := concurrent.NewMap[string, models.Identity](concurrent.HashString)

	hosts.Set("host-no-cred", models.Host{Address: "127.0.0.1", Port: 22})
	identities.Set("id-no-cred", models.Identity{
		User:     "guest",
		AuthType: "password",
		Password: "", // 无明文密码，无 Store 引用
	})
	nodes.Set("node-no-cred", models.Node{
		HostRef:     "host-no-cred",
		IdentityRef: "id-no-cred",
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

	// 不注入凭据注册表（nil）
	conn := newMCPConnector(ctx, provider, bufLogger, nil)
	t.Cleanup(func() {
		_ = conn.CloseAll()
	})

	_, err := conn.Connect(ctx, "node-no-cred")
	if err == nil {
		t.Fatal("expected fail-closed error when no credentials available, got nil")
	}

	// 验证是密码缺失或交互被拒绝（快速失败，不挂起）
	if !errors.Is(err, ssh.ErrPasswordRequired) && !errors.Is(err, ssh.ErrInteractionRequired) {
		t.Fatalf("expected ErrPasswordRequired or ErrInteractionRequired, got: %v", err)
	}
}
