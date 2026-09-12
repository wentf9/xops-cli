package adapter

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/ssh"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
	cryptossh "golang.org/x/crypto/ssh"
)

type adapterTestStore struct{}

func (adapterTestStore) Load() (*config.Configuration, error) { return nil, nil }

func (adapterTestStore) Save(*config.Configuration) error { return nil }

type adapterCredentialStore struct {
	mu   sync.Mutex
	data map[string]credential.Secret
}

func (s *adapterCredentialStore) Get(_ context.Context, ref credential.Ref) (credential.Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, ok := s.data[ref.ItemID]
	if !ok {
		return credential.Secret{}, credential.ErrCredentialNotFound
	}
	return credential.NewSecret(secret.Value), nil
}

func (s *adapterCredentialStore) Put(_ context.Context, ref credential.Ref, secret credential.Secret) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[ref.ItemID] = credential.NewSecret(secret.Value)
	return nil
}

func (s *adapterCredentialStore) Delete(_ context.Context, ref credential.Ref) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, ref.ItemID)
	return nil
}

func setTestHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Setenv("SSH_AUTH_SOCK", "")
	return dir
}

func TestSSHAdapter_NonInteractive(t *testing.T) {
	setTestHome(t)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key failed: %v", err)
	}
	signer, err := cryptossh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("create signer failed: %v", err)
	}
	serverConfig := &cryptossh.ServerConfig{
		PasswordCallback: func(conn cryptossh.ConnMetadata, password []byte) (*cryptossh.Permissions, error) {
			if string(password) == "pwd" {
				return nil, nil
			}
			return nil, errors.New("wrong password")
		},
	}
	serverConfig.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp failed: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			c, aErr := listener.Accept()
			if aErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				sConn, chans, reqs, srvErr := cryptossh.NewServerConn(conn, serverConfig)
				if srvErr != nil {
					return
				}
				defer func() { _ = sConn.Close() }()
				go cryptossh.DiscardRequests(reqs)
				for newCh := range chans {
					_ = newCh.Reject(cryptossh.UnknownChannelType, "unsupported")
				}
			}(c)
		}
	}()

	host, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split host port failed: %v", err)
	}
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	nodeMap := concurrent.NewMap[string, models.Node](concurrent.HashString)
	hostMap := concurrent.NewMap[string, models.Host](concurrent.HashString)
	identityMap := concurrent.NewMap[string, models.Identity](concurrent.HashString)

	hostMap.Set("host-1", models.Host{Address: host, Port: uint16(port)})
	identityMap.Set("id-1", models.Identity{User: "root", AuthType: "password", Password: "pwd"})

	nodeMap.Set("node-su", models.Node{
		HostRef:     "host-1",
		IdentityRef: "id-1",
		SudoMode:    models.SudoModeSu,
	})

	cfg := &config.Configuration{
		Nodes:      nodeMap,
		Identities: identityMap,
		Hosts:      hostMap,
	}
	provider := config.NewProviderWithoutOpenSSH(cfg)

	// 创建非交互式 connector，验证默认策略在提权时返回 ErrInteractionRequired
	conn := NewConnector(provider)
	if conn == nil {
		t.Fatal("expected connector to be created, got nil")
	}
	conn.AcceptNewHostKey.Store(true)
	t.Cleanup(func() { _ = conn.CloseAll() })

	client, err := conn.Connect(context.Background(), "node-su")
	if err != nil {
		t.Fatalf("expected connect to succeed, got %v", err)
	}

	// 阶段 2：提权密码按命令执行解析，非交互模式下提权执行触发 ErrInteractionRequired
	_, runErr := client.RunWithSudo(context.Background(), "whoami")
	if runErr == nil {
		t.Fatal("expected interaction required error from RunWithSudo, got nil")
	}
	if !errors.Is(runErr, ssh.ErrInteractionRequired) {
		t.Fatalf("expected ssh.ErrInteractionRequired, got: %v", runErr)
	}
}

func TestSSHAdapterGetConfigOpenSSHVirtualNodeIsSessionLocal(t *testing.T) {
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(`
Host remote-app
    HostName 10.0.0.5
    User deploy
    Port 2200
`))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader() error = %v", err)
	}
	provider := config.NewProviderWithOpenSSHParser(&config.Configuration{}, parser)

	clientConfig, err := NewSSHAdapter(provider).GetConfig(config.OpenSSHNodePrefix + "remote-app")
	if err != nil {
		t.Fatalf("GetConfig() error = %v", err)
	}
	if clientConfig.Address != "10.0.0.5" || clientConfig.User != "deploy" {
		t.Fatalf("unexpected SSH client config: %+v", clientConfig)
	}
	if clientConfig.AuthUpdateToken != "" || clientConfig.SudoUpdateToken != "" {
		t.Fatalf("virtual OpenSSH node must not carry persistence tokens: %+v", clientConfig)
	}
}

func TestSSHAdapterSessionAuthOverrideUsesAutoAuth(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	cfg.Nodes.Set("node", models.Node{HostRef: "host", IdentityRef: "identity"})
	cfg.Hosts.Set("host", models.Host{Address: "192.0.2.1", Port: 22})
	cfg.Identities.Set("identity", models.Identity{User: "root", AuthType: "password"})

	adapter := NewSSHAdapter(config.NewProviderWithoutOpenSSH(cfg), WithSessionAuthOverride("node", SessionAuth{
		Password: "session-password",
		KeyPath:  "/tmp/session-key",
	}))
	clientCfg, err := adapter.GetConfig("node")
	if err != nil {
		t.Fatalf("GetConfig() error = %v", err)
	}
	if clientCfg.AuthType != "auto" {
		t.Fatalf("AuthType = %q, want auto so successful authentication can be recorded", clientCfg.AuthType)
	}
	if clientCfg.KeyPath != "/tmp/session-key" {
		t.Fatalf("KeyPath = %q, want session override", clientCfg.KeyPath)
	}
}

func TestSSHAdapterSessionPasswordRememberedAfterSuccessfulConnection(t *testing.T) {
	setTestHome(t)
	host, port, stopServer := startAdapterPrivilegeSSHServer(t, "session-password", "")
	t.Cleanup(stopServer)

	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Credential: &config.CredentialConfig{DefaultStore: "memory"},
	}
	cfg.Nodes.Set("node", models.Node{HostRef: "host", IdentityRef: "identity"})
	cfg.Hosts.Set("host", models.Host{Address: host, Port: uint16(port)})
	cfg.Identities.Set("identity", models.Identity{User: "root", AuthType: "auto"})
	repository, err := config.NewRepositoryWithoutOpenSSH(cfg, adapterTestStore{})
	if err != nil {
		t.Fatalf("create repository: %v", err)
	}
	store := &adapterCredentialStore{data: make(map[string]credential.Secret)}
	registry := credential.NewRegistry()
	if err := registry.Register("memory", store); err != nil {
		t.Fatalf("register store: %v", err)
	}
	journal, err := credential.NewJournalStore(t.TempDir())
	if err != nil {
		t.Fatalf("create journal store: %v", err)
	}
	service, err := credential.NewService(registry, journal, repository.AsConfigUpdater(), nil)
	if err != nil {
		t.Fatalf("create credential service: %v", err)
	}
	connector := NewConnectorWithAdapterOptions(repository, []Option{
		WithCredentialService(service),
		WithSessionAuthOverride("node", SessionAuth{Password: "session-password", Remember: true}),
	})
	connector.AcceptNewHostKey.Store(true)
	t.Cleanup(func() { _ = connector.CloseAll() })
	if _, err := connector.Connect(t.Context(), "node"); err != nil {
		t.Fatalf("connect: %v", err)
	}
	snapshot, err := repository.ResolveConnection("node")
	if err != nil {
		t.Fatalf("resolve updated node: %v", err)
	}
	if snapshot.Identity.LoginPasswordRef == nil {
		t.Fatal("successful remembered session password did not create a reference")
	}
	secret, err := store.Get(t.Context(), *snapshot.Identity.LoginPasswordRef)
	if err != nil {
		t.Fatalf("read saved password: %v", err)
	}
	defer secret.Zero()
	if string(secret.Value) != "session-password" {
		t.Fatalf("saved password = %q", secret.Value)
	}
}

func TestSSHAdapterRememberedPassphrasePersistsKeyPath(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Credential: &config.CredentialConfig{DefaultStore: "memory"},
	}
	cfg.Nodes.Set("node", models.Node{HostRef: "host", IdentityRef: "identity"})
	cfg.Hosts.Set("host", models.Host{Address: "127.0.0.1", Port: 22})
	cfg.Identities.Set("identity", models.Identity{User: "root", AuthType: "auto"})
	repository, err := config.NewRepositoryWithoutOpenSSH(cfg, adapterTestStore{})
	if err != nil {
		t.Fatalf("create repository: %v", err)
	}
	store := &adapterCredentialStore{data: make(map[string]credential.Secret)}
	registry := credential.NewRegistry()
	if err := registry.Register("memory", store); err != nil {
		t.Fatalf("register store: %v", err)
	}
	journal, err := credential.NewJournalStore(t.TempDir())
	if err != nil {
		t.Fatalf("create journal store: %v", err)
	}
	service, err := credential.NewService(registry, journal, repository.AsConfigUpdater(), nil)
	if err != nil {
		t.Fatalf("create credential service: %v", err)
	}
	adapter := NewSSHAdapter(repository, WithCredentialService(service))
	connection, err := adapter.GetConfig("node")
	if err != nil {
		t.Fatalf("get node config: %v", err)
	}
	if _, err := adapter.UpdateAuth(t.Context(), "node", connection.AuthUpdateToken, "", "/tmp/discovered-key", "passphrase"); err != nil {
		t.Fatalf("remember passphrase: %v", err)
	}
	snapshot, err := repository.ResolveConnection("node")
	if err != nil {
		t.Fatalf("resolve remembered node: %v", err)
	}
	if snapshot.Identity.KeyPath != "/tmp/discovered-key" {
		t.Fatalf("key path = %q, want discovered path", snapshot.Identity.KeyPath)
	}
	if snapshot.Identity.PassphraseRef == nil {
		t.Fatal("passphrase reference was not persisted")
	}
}

func TestSSHAdapterRejectsEmptyPersistenceToken(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	cfg.Nodes.Set("persisted", models.Node{HostRef: "host", IdentityRef: "identity", SudoMode: models.SudoModeAuto})
	cfg.Hosts.Set("host", models.Host{Address: "192.0.2.1", Port: 22})
	cfg.Identities.Set("identity", models.Identity{User: "root"})
	repository, err := config.NewRepositoryWithoutOpenSSH(cfg, adapterTestStore{})
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH() error = %v", err)
	}

	adapter := NewSSHAdapter(repository)
	if _, err := adapter.UpdateSudo(t.Context(), "persisted", "", "sudo", ""); err == nil {
		t.Fatal("UpdateSudo() error = nil for empty persistence token")
	}
	node, ok := repository.GetNode("persisted")
	if !ok {
		t.Fatal("persisted node is missing")
	}
	if node.SudoMode != models.SudoModeAuto {
		t.Fatalf("empty token changed sudo mode to %q", node.SudoMode)
	}
}

func TestSSHAdapter_ResolveSecret(t *testing.T) {
	nodeMap := concurrent.NewMap[string, models.Node](concurrent.HashString)
	hostMap := concurrent.NewMap[string, models.Host](concurrent.HashString)
	identityMap := concurrent.NewMap[string, models.Identity](concurrent.HashString)

	hostMap.Set("host-1", models.Host{Address: "127.0.0.1", Port: 22})
	identityMap.Set("id-full", models.Identity{
		User:       "root",
		AuthType:   "password",
		Password:   "login-pwd-123",
		Passphrase: "key-pass-456",
	})
	identityMap.Set("id-empty", models.Identity{
		User:     "guest",
		AuthType: "password",
	})

	nodeMap.Set("node-full", models.Node{
		HostRef:     "host-1",
		IdentityRef: "id-full",
		SudoMode:    models.SudoModeSu,
		SuPwd:       "su-pwd-789",
	})
	nodeMap.Set("node-empty", models.Node{
		HostRef:     "host-1",
		IdentityRef: "id-empty",
		SudoMode:    models.SudoModeSu,
	})

	cfg := &config.Configuration{
		Nodes:      nodeMap,
		Identities: identityMap,
		Hosts:      hostMap,
	}
	provider := config.NewProviderWithoutOpenSSH(cfg)
	adp := NewSSHAdapter(provider)

	ctx := context.Background()

	// 1. 成功解析 LoginPassword
	pwd, err := adp.ResolveSecret(ctx, ssh.SecretRequest{
		Kind:   ssh.SecretKindLoginPassword,
		NodeID: "node-full",
	})
	if err != nil || string(pwd) != "login-pwd-123" {
		t.Fatalf("ResolveSecret login password failed: err=%v, pwd=%q", err, string(pwd))
	}

	// 2. 成功解析 PrivateKeyPassphrase
	pass, err := adp.ResolveSecret(ctx, ssh.SecretRequest{
		Kind:   ssh.SecretKindPrivateKeyPassphrase,
		NodeID: "node-full",
	})
	if err != nil || string(pass) != "key-pass-456" {
		t.Fatalf("ResolveSecret passphrase failed: err=%v, pass=%q", err, string(pass))
	}

	// 3. 成功解析 SuPassword
	suPwd, err := adp.ResolveSecret(ctx, ssh.SecretRequest{
		Kind:   ssh.SecretKindSuPassword,
		NodeID: "node-full",
	})
	if err != nil || string(suPwd) != "su-pwd-789" {
		t.Fatalf("ResolveSecret su password failed: err=%v, suPwd=%q", err, string(suPwd))
	}

	// 4. 空密码返回 ErrInteractionRequired
	_, err = adp.ResolveSecret(ctx, ssh.SecretRequest{
		Kind:   ssh.SecretKindLoginPassword,
		NodeID: "node-empty",
	})
	if !errors.Is(err, ssh.ErrInteractionRequired) {
		t.Fatalf("expected ErrInteractionRequired for empty password, got: %v", err)
	}

	// 5. 空 passphrase 返回 ErrInteractionRequired
	_, err = adp.ResolveSecret(ctx, ssh.SecretRequest{
		Kind:   ssh.SecretKindPrivateKeyPassphrase,
		NodeID: "node-empty",
	})
	if !errors.Is(err, ssh.ErrInteractionRequired) {
		t.Fatalf("expected ErrInteractionRequired for empty passphrase, got: %v", err)
	}

	// 6. 空 suPwd 返回 ErrInteractionRequired
	_, err = adp.ResolveSecret(ctx, ssh.SecretRequest{
		Kind:   ssh.SecretKindSuPassword,
		NodeID: "node-empty",
	})
	if !errors.Is(err, ssh.ErrInteractionRequired) {
		t.Fatalf("expected ErrInteractionRequired for empty su password, got: %v", err)
	}

	// 7. 取消 context 立即返回 context.Canceled
	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()
	_, err = adp.ResolveSecret(canceledCtx, ssh.SecretRequest{
		Kind:   ssh.SecretKindLoginPassword,
		NodeID: "node-full",
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}

	// 8. 不支持的 Kind
	_, err = adp.ResolveSecret(ctx, ssh.SecretRequest{
		Kind:   ssh.SecretKind(99),
		NodeID: "node-full",
	})
	if err == nil {
		t.Fatal("expected error for unsupported secret kind, got nil")
	}

	// 9. Provider 为 nil
	nilAdp := &SSHAdapter{}
	_, err = nilAdp.ResolveSecret(ctx, ssh.SecretRequest{
		Kind:   ssh.SecretKindLoginPassword,
		NodeID: "node-full",
	})
	if err == nil {
		t.Fatal("expected error for nil provider, got nil")
	}

	// 10. 目标主机变动：请求旧主机，但快照主机已变更，必须拒绝
	_, err = adp.ResolveSecret(ctx, ssh.SecretRequest{
		Kind:   ssh.SecretKindLoginPassword,
		NodeID: "node-full",
		Host:   "old-host-ip", // 与 127.0.0.1 不一致
	})
	if !errors.Is(err, ssh.ErrSnapshotMismatch) {
		t.Fatalf("expected ErrSnapshotMismatch for changed host, got: %v", err)
	}

	// 11. 用户变动：请求旧用户，但快照用户已变更，必须拒绝
	_, err = adp.ResolveSecret(ctx, ssh.SecretRequest{
		Kind:   ssh.SecretKindLoginPassword,
		NodeID: "node-full",
		User:   "old-user", // 与 root 不一致
	})
	if !errors.Is(err, ssh.ErrSnapshotMismatch) {
		t.Fatalf("expected ErrSnapshotMismatch for changed user, got: %v", err)
	}
}

func TestSSHAdapter_ResolveSecret_DetectsVersionMismatchAfterUpdate(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	cfg.Nodes.Set("node-dynamic", models.Node{
		HostRef:     "host-dyn",
		IdentityRef: "id-dyn",
	})
	cfg.Hosts.Set("host-dyn", models.Host{Address: "192.0.2.10", Port: 22})
	cfg.Identities.Set("id-dyn", models.Identity{User: "admin", AuthType: "password", Password: "old-secret"})

	repository, err := config.NewRepositoryWithoutOpenSSH(cfg, adapterTestStore{})
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH() error = %v", err)
	}

	adapter := NewSSHAdapter(repository)

	// 获取初始配置快照与 token
	clientCfg, err := adapter.GetConfig("node-dynamic")
	if err != nil {
		t.Fatalf("GetConfig() error = %v", err)
	}
	oldToken := clientCfg.AuthUpdateToken
	if oldToken == "" {
		t.Fatal("expected non-empty AuthUpdateToken")
	}

	// 模拟并发更新：通过 Repository 更新了密码
	_, err = repository.UpdateAuthAtVersionContext(context.Background(), "node-dynamic", oldToken, "new-secret-456", "", "")
	if err != nil {
		t.Fatalf("UpdateAuthAtVersionContext() error = %v", err)
	}

	// 使用旧快照的 oldToken 尝试解析机密，必须被拒绝，防止将新密码注入给旧连接配置
	_, err = adapter.ResolveSecret(context.Background(), ssh.SecretRequest{
		Kind:         ssh.SecretKindLoginPassword,
		NodeID:       "node-dynamic",
		User:         clientCfg.User,
		Host:         clientCfg.Address,
		VersionToken: oldToken, // 带有旧快照版本
	})
	if !errors.Is(err, ssh.ErrSnapshotMismatch) {
		t.Fatalf("expected ErrSnapshotMismatch when version changed, got: %v", err)
	}
}

//nolint:gocyclo // Test helper managing mock SSH server lifecycle and privilege session events
func startAdapterPrivilegeSSHServer(t *testing.T, expectedLoginPwd, expectedSuPwd string) (string, int, func()) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key failed: %v", err)
	}
	signer, err := cryptossh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("create signer failed: %v", err)
	}
	serverConfig := &cryptossh.ServerConfig{
		PasswordCallback: func(conn cryptossh.ConnMetadata, password []byte) (*cryptossh.Permissions, error) {
			if string(password) == expectedLoginPwd {
				return nil, nil
			}
			return nil, errors.New("wrong password")
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
			conn, aErr := listener.Accept()
			if aErr != nil {
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

				var reqWG sync.WaitGroup
				reqWG.Add(1)
				go func() {
					defer reqWG.Done()
					cryptossh.DiscardRequests(reqs)
				}()

				for newCh := range chans {
					if newCh.ChannelType() != "session" {
						_ = newCh.Reject(cryptossh.UnknownChannelType, "unsupported")
						continue
					}
					ch, chReqs, chErr := newCh.Accept()
					if chErr != nil {
						continue
					}
					serverWG.Add(1)
					go func(channel cryptossh.Channel, requests <-chan *cryptossh.Request) {
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
								if strings.Contains(cmd, "su -") {
									_, _ = channel.Write([]byte("Password: "))
									buf := make([]byte, 128)
									n, _ := channel.Read(buf)
									inPwd := strings.TrimSpace(string(buf[:n]))
									if inPwd == expectedSuPwd {
										if !adapterPrivilegeSignal(t, channel, cmd, false) {
											return
										}
										_, _ = channel.Write([]byte("mock-su-success\n"))
										_, _ = channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
									} else {
										_, _ = channel.Write([]byte("su: Authentication failure\n"))
										_, _ = channel.SendRequest("exit-status", false, []byte{0, 0, 0, 1})
									}
									_ = channel.CloseWrite()
									return
								} else if strings.Contains(cmd, "sudo") {
									if !adapterPrivilegeSignal(t, channel, cmd, true) {
										return
									}
									buf := make([]byte, 128)
									n, _ := channel.Read(buf)
									inPwd := strings.TrimSpace(string(buf[:n]))
									if inPwd == expectedLoginPwd {
										if !adapterPrivilegeSignal(t, channel, cmd, false) {
											return
										}
										_, _ = channel.Write([]byte("mock-sudo-success\n"))
										_, _ = channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
									} else {
										_, _ = channel.Write([]byte("sudo: Authentication failure\n"))
										_, _ = channel.SendRequest("exit-status", false, []byte{0, 0, 0, 1})
									}
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
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

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
			t.Errorf("cleanup timeout")
		}
	}

	return host, port, cleanup
}

type testAdapterPrompter struct {
	mu           sync.Mutex
	returnSecret string
	calls        int
}

func (p *testAdapterPrompter) PromptSecret(ctx context.Context, req ssh.SecretRequest) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	return p.returnSecret, nil
}

// TestSSHAdapter_RealRepository_SudoUsesAuthVersionAndExecutes 验证持久化节点的 sudo 提权按 SecretKindLoginPassword 匹配 AuthVersion
func TestSSHAdapter_RealRepository_SudoUsesAuthVersionAndExecutes(t *testing.T) {
	setTestHome(t)
	loginPwd := "login-pass-sudo"
	host, port, cleanup := startAdapterPrivilegeSSHServer(t, loginPwd, "")
	defer cleanup()

	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	cfg.Hosts.Set("host-sudo", models.Host{Address: host, Port: uint16(port)})
	cfg.Identities.Set("id-sudo", models.Identity{User: "root", AuthType: "password", Password: loginPwd})
	cfg.Nodes.Set("node-sudo", models.Node{
		HostRef:     "host-sudo",
		IdentityRef: "id-sudo",
		SudoMode:    models.SudoModeSudo,
	})

	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, adapterTestStore{})
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH error = %v", err)
	}

	connector := NewConnector(repo)
	connector.AcceptNewHostKey.Store(true)
	defer func() { _ = connector.CloseAll() }()

	ctx := context.Background()
	client, err := connector.Connect(ctx, "node-sudo")
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	// 执行 sudo 提权命令：Client 内部会以 SecretKindLoginPassword 请求机密，必须使用 AuthUpdateToken（AuthVersion）
	// 若错误使用 SudoUpdateToken，Adapter 会返回 ErrSnapshotMismatch 导致执行失败
	out, err := client.RunWithSudo(ctx, "whoami")
	if err != nil {
		t.Fatalf("RunWithSudo failed: %v", err)
	}
	if !strings.Contains(out, "mock-sudo-success") {
		t.Errorf("unexpected output: %s", out)
	}
}

// TestSSHAdapter_RealRepository_SuPromptWritebackAndTokenRefresh 验证通过提示取得 su 密码后写回不覆盖登录密码，且令牌刷新使连续提权不冲突
func TestSSHAdapter_RealRepository_SuPromptWritebackAndTokenRefresh(t *testing.T) {
	setTestHome(t)
	loginPwd := "login-pwd-su"
	suPwd := "su-pwd-prompted"
	host, port, cleanup := startAdapterPrivilegeSSHServer(t, loginPwd, suPwd)
	defer cleanup()

	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	cfg.Hosts.Set("host-su", models.Host{Address: host, Port: uint16(port)})
	cfg.Identities.Set("id-su", models.Identity{User: "root", AuthType: "password", Password: loginPwd})
	cfg.Nodes.Set("node-su", models.Node{
		HostRef:     "host-su",
		IdentityRef: "id-su",
		SudoMode:    models.SudoModeSu,
		SuPwd:       "", // 初始未配置 su 密码
	})

	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, adapterTestStore{})
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH error = %v", err)
	}

	prompter := &testAdapterPrompter{returnSecret: suPwd}
	connector := NewConnector(repo, ssh.WithSecretPrompter(prompter))
	connector.AcceptNewHostKey.Store(true)
	defer func() { _ = connector.CloseAll() }()

	ctx := context.Background()
	client, err := connector.Connect(ctx, "node-su")
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	// 第一次提权执行：通过 prompter 获得 su 密码并写回
	out1, err := client.RunWithSudo(ctx, "cmd1")
	if err != nil {
		t.Fatalf("first RunWithSudo failed: %v", err)
	}
	if !strings.Contains(out1, "mock-su-success") {
		t.Errorf("unexpected output from first RunWithSudo: %s", out1)
	}

	// [P1] 校验写回结果：只写回了 SuPwd，绝对没有污染 Identity 的 Password
	snapshot, err := repo.ResolveConnection("node-su")
	if err != nil {
		t.Fatalf("ResolveConnection failed: %v", err)
	}
	if snapshot.Node.SuPwd != suPwd {
		t.Errorf("expected SuPwd to be %q, got %q", suPwd, snapshot.Node.SuPwd)
	}
	if snapshot.Identity.Password != loginPwd {
		t.Errorf("expected Identity.Password to remain %q, got %q (polluted!)", loginPwd, snapshot.Identity.Password)
	}

	// [P2] 第二次提权执行：同一个 Client 执行第二条命令，由于令牌已在第一次写回成功后刷新，绝不触发 ErrSnapshotMismatch
	out2, err := client.RunWithSudo(ctx, "cmd2")
	if err != nil {
		t.Fatalf("second RunWithSudo failed (likely snapshot mismatch token not refreshed): %v", err)
	}
	if !strings.Contains(out2, "mock-su-success") {
		t.Errorf("unexpected output from second RunWithSudo: %s", out2)
	}
}

// TestSSHAdapter_RealRepository_AutoLoginWritebackThenSudo 验证 auto 登录写回凭证后，同一个 Client 首次执行 sudo 不报 ErrSnapshotMismatch
func TestSSHAdapter_RealRepository_AutoLoginWritebackThenSudo(t *testing.T) {
	setTestHome(t)

	loginPwd := "login-pass-auto-sudo"
	host, port, cleanup := startAdapterPrivilegeSSHServer(t, loginPwd, "")
	defer cleanup()

	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	cfg.Hosts.Set("host-auto", models.Host{Address: host, Port: uint16(port)})
	cfg.Identities.Set("id-auto", models.Identity{User: "root", AuthType: "auto", Password: ""})
	cfg.Nodes.Set("node-auto", models.Node{
		HostRef:     "host-auto",
		IdentityRef: "id-auto",
		SudoMode:    models.SudoModeSudo,
	})

	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, adapterTestStore{})
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH error = %v", err)
	}

	prompter := &testAdapterPrompter{returnSecret: loginPwd}
	connector := NewConnector(repo, ssh.WithSecretPrompter(prompter))
	connector.AcceptNewHostKey.Store(true)
	defer func() { _ = connector.CloseAll() }()

	ctx := context.Background()
	// 1. auto 认证建连，提示输入登录密码并通过 recordAuthUpdate 写回 Repository
	client, err := connector.Connect(ctx, "node-auto")
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	// 2. 验证 Repository 已经更新为新的密码与认证版本
	snap, err := repo.ResolveConnection("node-auto")
	if err != nil {
		t.Fatalf("ResolveConnection failed: %v", err)
	}
	if snap.Identity.Password != loginPwd {
		t.Errorf("expected Identity.Password %q, got %q", loginPwd, snap.Identity.Password)
	}

	// 3. [P1] 同一个 client 首次执行 RunWithSudo：必须使用写回后同步的新令牌，绝不返回 ErrSnapshotMismatch
	out, err := client.RunWithSudo(ctx, "whoami")
	if err != nil {
		t.Fatalf("RunWithSudo failed after auto login writeback: %v", err)
	}
	if !strings.Contains(out, "mock-sudo-success") {
		t.Errorf("unexpected output: %s", out)
	}
}

// TestSSHAdapter_ResolveSecret_DetectsPortMismatch 验证 ResolveSecret 校验目标端口一致性，防止新端口密码注入旧端口连接
func TestSSHAdapter_ResolveSecret_DetectsPortMismatch(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	cfg.Nodes.Set("node-port-test", models.Node{
		HostRef:     "host-port-test",
		IdentityRef: "id-port-test",
	})
	cfg.Hosts.Set("host-port-test", models.Host{Address: "192.0.2.10", Port: 2222})
	cfg.Identities.Set("id-port-test", models.Identity{User: "admin", AuthType: "password", Password: "secret-pwd"})

	repository, err := config.NewRepositoryWithoutOpenSSH(cfg, adapterTestStore{})
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH() error = %v", err)
	}

	adapter := NewSSHAdapter(repository)
	clientCfg, err := adapter.GetConfig("node-port-test")
	if err != nil {
		t.Fatalf("GetConfig() error = %v", err)
	}

	// 传入不同的端口（例如旧连接的端口 22，而当前配置已是 2222），即使 VersionToken 匹配也必须拒绝
	_, err = adapter.ResolveSecret(context.Background(), ssh.SecretRequest{
		Kind:         ssh.SecretKindLoginPassword,
		NodeID:       "node-port-test",
		User:         clientCfg.User,
		Host:         clientCfg.Address,
		Port:         22, // 旧端口
		VersionToken: clientCfg.AuthUpdateToken,
	})
	if !errors.Is(err, ssh.ErrSnapshotMismatch) {
		t.Fatalf("expected ErrSnapshotMismatch when target port differs, got: %v", err)
	}
	if !strings.Contains(err.Error(), "host port changed") {
		t.Fatalf("expected 'host port changed' in error, got: %v", err)
	}
}

// TestSSHAdapter_RealRepository_ConcurrentTargetPortUpdate_BlocksTokenAdoption_ClientRefresh 验证 Client 提权写回时若端口并发变动则拒绝采纳新令牌
func TestSSHAdapter_RealRepository_ConcurrentTargetPortUpdate_BlocksTokenAdoption_ClientRefresh(t *testing.T) {
	setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	loginPwd := "login-pwd-port-conflict"
	host, port, cleanup := startAdapterPrivilegeSSHServer(t, loginPwd, "")
	defer cleanup()

	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	cfg.Hosts.Set("host-conflict", models.Host{Address: host, Port: uint16(port)})
	cfg.Identities.Set("id-conflict", models.Identity{User: "root", AuthType: "password", Password: loginPwd})
	cfg.Nodes.Set("node-conflict", models.Node{
		HostRef:     "host-conflict",
		IdentityRef: "id-conflict",
		SudoMode:    models.SudoModeSu,
		SuPwd:       "", // 触发交互提权写回
	})

	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, adapterTestStore{})
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH error = %v", err)
	}

	suPwd := "su-prompt-pwd"
	prompter := &testAdapterPrompter{returnSecret: suPwd}
	connector := NewConnector(repo, ssh.WithSecretPrompter(prompter))
	connector.AcceptNewHostKey.Store(true)
	defer func() { _ = connector.CloseAll() }()

	ctx := context.Background()
	client, err := connector.Connect(ctx, "node-conflict")
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	// 模拟并发更新同一节点的端口和密码（例如节点被重新配置到了新端口 22222 和新密码）
	newPort := uint16(22222)
	nodeRef := repo.View().NodeRefs["node-conflict"]
	curNode, curHost, curIdentity, err := repo.Resolve("node-conflict")
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	curHost.Port = newPort
	curIdentity.Password = "new-target-password"
	if err := repo.ReplaceNodeAtRefContext(ctx, nodeRef, "node-conflict", curNode, curHost, curIdentity); err != nil {
		t.Fatalf("ReplaceNodeAtRefContext failed: %v", err)
	}

	// 此时底层端口和密码已更新。在旧 Client 上执行 RunWithSudo，触发 su 密码写回并刷新令牌。
	// 刷新逻辑必须拦截目标端口不兼容，拒绝合入新端口/新密码的令牌，并返回包含 ErrSnapshotMismatch 的错误！
	_, runErr := client.RunWithSudo(ctx, "whoami")
	if runErr == nil {
		t.Fatal("expected RunWithSudo to fail due to incompatible target port update, got nil")
	}
	if !errors.Is(runErr, ssh.ErrSnapshotMismatch) {
		t.Fatalf("expected error chain to contain ErrSnapshotMismatch, got: %v", runErr)
	}
}

// TestSSHAdapter_RealRepository_ConcurrentTargetPortUpdate_BlocksTokenAdoption_ConnectorSetup 验证 Connector 建连刷新时若端口并发变动则关闭连接并拒绝采纳令牌
func TestSSHAdapter_RealRepository_ConcurrentTargetPortUpdate_BlocksTokenAdoption_ConnectorSetup(t *testing.T) {
	setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	loginPwd := "login-pwd-auto-conflict"
	host, port, cleanup := startAdapterPrivilegeSSHServer(t, loginPwd, "")
	defer cleanup()

	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	cfg.Hosts.Set("host-auto-conflict", models.Host{Address: host, Port: uint16(port)})
	cfg.Identities.Set("id-auto-conflict", models.Identity{User: "root", AuthType: "auto", Password: ""})
	cfg.Nodes.Set("node-auto-conflict", models.Node{
		HostRef:     "host-auto-conflict",
		IdentityRef: "id-auto-conflict",
		SudoMode:    models.SudoModeSudo,
	})

	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, adapterTestStore{})
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH error = %v", err)
	}

	// 包装 prompter，在用户输入密码建连并触发写回的同时，模拟并发将底层端口修改
	prompter := &concurrentTamperingPrompter{
		secretToReturn: loginPwd,
		onPrompt: func() {
			nodeRef := repo.View().NodeRefs["node-auto-conflict"]
			curNode, curHost, curIdentity, rErr := repo.Resolve("node-auto-conflict")
			if rErr == nil {
				curHost.Port = 33333
				_ = repo.ReplaceNodeAtRefContext(context.Background(), nodeRef, "node-auto-conflict", curNode, curHost, curIdentity)
			}
		},
	}

	connector := NewConnector(repo, ssh.WithSecretPrompter(prompter))
	connector.AcceptNewHostKey.Store(true)
	defer func() { _ = connector.CloseAll() }()

	ctx := context.Background()
	// Connector 建连写回后刷新配置，必须检测到端口变动不兼容，关闭未发布连接并返回 ErrSnapshotMismatch！
	_, connErr := connector.Connect(ctx, "node-auto-conflict")
	if connErr == nil {
		t.Fatal("expected Connect to fail due to concurrent target port update, got nil")
	}
	if !errors.Is(connErr, ssh.ErrSnapshotMismatch) {
		t.Fatalf("expected error chain to contain ErrSnapshotMismatch, got: %v", connErr)
	}
}

type concurrentTamperingPrompter struct {
	secretToReturn string
	onPrompt       func()
}

func (p *concurrentTamperingPrompter) PromptSecret(ctx context.Context, req ssh.SecretRequest) (string, error) {
	if p.onPrompt != nil {
		p.onPrompt()
	}
	return p.secretToReturn, nil
}

// TestSSHAdapter_RealRepository_AutoLogin_IdempotentPassword_Succeeds 验证 auto 认证使用已保存相同密码时幂等写回不报错，且后续同一 Client 顺利执行 sudo
func TestSSHAdapter_RealRepository_AutoLogin_IdempotentPassword_Succeeds(t *testing.T) {
	setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	loginPwd := "login-pass-idempotent-test"
	host, port, cleanup := startAdapterPrivilegeSSHServer(t, loginPwd, "")
	defer cleanup()

	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	cfg.Hosts.Set("host-idempotent", models.Host{Address: host, Port: uint16(port)})
	cfg.Identities.Set("id-idempotent", models.Identity{User: "root", AuthType: "auto", Password: loginPwd})
	cfg.Nodes.Set("node-idempotent", models.Node{
		HostRef:     "host-idempotent",
		IdentityRef: "id-idempotent",
		SudoMode:    models.SudoModeSudo,
	})

	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, adapterTestStore{})
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH error = %v", err)
	}

	prompter := &testAdapterPrompter{returnSecret: loginPwd}
	connector := NewConnector(repo, ssh.WithSecretPrompter(prompter))
	connector.AcceptNewHostKey.Store(true)
	defer func() { _ = connector.CloseAll() }()

	ctx := context.Background()
	// auto 登录：使用已保存的相同密码，幂等写回后哈希版本保持不变，绝不误报 "auth version not advanced"
	client, err := connector.Connect(ctx, "node-idempotent")
	if err != nil {
		t.Fatalf("Connect failed on idempotent auto login: %v", err)
	}

	// 同一个 client 首次执行 RunWithSudo：版本同步正确，不报错
	out, err := client.RunWithSudo(ctx, "whoami")
	if err != nil {
		t.Fatalf("RunWithSudo failed after idempotent auto login: %v", err)
	}
	if !strings.Contains(out, "mock-sudo-success") {
		t.Errorf("unexpected output: %s", out)
	}
}

// TestSSHAdapter_RealRepository_ConcurrentAuthUpdate_MismatchedCommittedToken_Rejected 验证写回成功但刷新前被并发修改导致令牌不属于本次提交时，拒绝采纳
func TestSSHAdapter_RealRepository_ConcurrentAuthUpdate_MismatchedCommittedToken_Rejected(t *testing.T) {
	setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	loginPwd := "login-pwd-initial"
	host, port, cleanup := startAdapterPrivilegeSSHServer(t, loginPwd, "")
	defer cleanup()

	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	cfg.Hosts.Set("host-concurrent-auth", models.Host{Address: host, Port: uint16(port)})
	cfg.Identities.Set("id-concurrent-auth", models.Identity{User: "root", AuthType: "auto", Password: ""})
	cfg.Nodes.Set("node-concurrent-auth", models.Node{
		HostRef:     "host-concurrent-auth",
		IdentityRef: "id-concurrent-auth",
		SudoMode:    models.SudoModeSudo,
	})

	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, adapterTestStore{})
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH error = %v", err)
	}

	// 构造一个包装了 Repository 的 Recorder，模拟：
	// 本次事务成功提交并返回 committedToken，但在返回给调用者后、Connector 刷新前，
	// 另一次无关更新修改了该节点的密码（使 Repository 的最新版本推进到了第三方版本）。
	adapter := NewSSHAdapter(repo)
	interceptingRecorder := &interceptingCredentialRecorder{
		base: adapter,
		onAfterUpdateAuth: func() {
			// 模拟第三方并发写更新
			snap, rErr := repo.ResolveConnection("node-concurrent-auth")
			if rErr == nil && snap.UpdateRef != nil {
				curTok := string(snap.UpdateRef.AuthVersion[:])
				_, _ = repo.UpdateAuthAtVersionContext(context.Background(), "node-concurrent-auth", curTok, "third-party-concurrent-pwd", "", "")
			}
		},
	}

	prompter := &testAdapterPrompter{returnSecret: loginPwd}
	connector := ssh.NewConnector(
		adapter,
		ssh.WithSecretResolver(adapter),
		ssh.WithSecretPrompter(prompter),
		ssh.WithCredentialRecorder(interceptingRecorder),
	)
	connector.AcceptNewHostKey.Store(true)
	defer func() { _ = connector.CloseAll() }()

	ctx := context.Background()
	_, connErr := connector.Connect(ctx, "node-concurrent-auth")
	if connErr == nil {
		t.Fatal("expected Connect to fail due to mismatched committed token, got nil")
	}
	if !errors.Is(connErr, ssh.ErrSnapshotMismatch) {
		t.Fatalf("expected error chain to contain ErrSnapshotMismatch, got: %v", connErr)
	}
	if !strings.Contains(connErr.Error(), "auth version mismatch after update") {
		t.Fatalf("expected auth version mismatch in error message, got: %v", connErr)
	}
}

type interceptingCredentialRecorder struct {
	base              ssh.CredentialRecorder
	onAfterUpdateAuth func()
	onAfterUpdateSudo func()
}

func (r *interceptingCredentialRecorder) UpdateAuth(ctx context.Context, nodeID, authUpdateToken, password, keyPath, passphrase string) (string, error) {
	tok, err := r.base.UpdateAuth(ctx, nodeID, authUpdateToken, password, keyPath, passphrase)
	if err == nil && r.onAfterUpdateAuth != nil {
		r.onAfterUpdateAuth()
	}
	return tok, err
}

func (r *interceptingCredentialRecorder) UpdateSudo(ctx context.Context, nodeID, sudoUpdateToken string, mode ssh.SudoMode, suPwd string) (string, error) {
	tok, err := r.base.UpdateSudo(ctx, nodeID, sudoUpdateToken, mode, suPwd)
	if err == nil && r.onAfterUpdateSudo != nil {
		r.onAfterUpdateSudo()
	}
	return tok, err
}

// TestSSHAdapter_RealRepository_CrossKind_HandshakeAuthUpdate_PreservesSudoSnapshot_RejectsConcurrentSudo
// 验证建连握手认证写回期间并发修改提权凭据时，返回的 Client 严格保留原 Sudo 快照，后续解析 su 密码被拦截
func TestSSHAdapter_RealRepository_CrossKind_HandshakeAuthUpdate_PreservesSudoSnapshot_RejectsConcurrentSudo(t *testing.T) {
	setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	loginPwd := "login-pass-handshake"
	origSuPwd := "su-pass-orig"
	host, port, cleanup := startAdapterPrivilegeSSHServer(t, loginPwd, origSuPwd)
	defer cleanup()

	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	cfg.Hosts.Set("host-cross-handshake", models.Host{Address: host, Port: uint16(port)})
	cfg.Identities.Set("id-cross-handshake", models.Identity{User: "root", AuthType: "auto", Password: ""})
	cfg.Nodes.Set("node-cross-handshake", models.Node{
		HostRef:     "host-cross-handshake",
		IdentityRef: "id-cross-handshake",
		SudoMode:    models.SudoModeSu,
		SuPwd:       origSuPwd,
	})

	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, adapterTestStore{})
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH error = %v", err)
	}

	adapter := NewSSHAdapter(repo)
	initialSnap, err := repo.ResolveConnection("node-cross-handshake")
	if err != nil {
		t.Fatalf("ResolveConnection failed: %v", err)
	}
	origSudoToken := string(initialSnap.UpdateRef.SudoVersion[:])

	// 在握手写回 UpdateAuth 成功后、刷新配置前，模拟外部并发修改了提权 su 密码
	interceptingRecorder := &interceptingCredentialRecorder{
		base: adapter,
		onAfterUpdateAuth: func() {
			_, uErr := repo.UpdateSudoAtVersionContext(context.Background(), "node-cross-handshake", origSudoToken, models.SudoModeSu, "new-concurrent-su-pwd")
			if uErr != nil {
				t.Logf("concurrent UpdateSudoAtVersionContext error: %v", uErr)
			}
		},
	}

	prompter := &testAdapterPrompter{returnSecret: loginPwd}
	connector := ssh.NewConnector(
		adapter,
		ssh.WithSecretResolver(adapter),
		ssh.WithSecretPrompter(prompter),
		ssh.WithCredentialRecorder(interceptingRecorder),
	)
	connector.AcceptNewHostKey.Store(true)
	defer func() { _ = connector.CloseAll() }()

	ctx := context.Background()
	client, err := connector.Connect(ctx, "node-cross-handshake")
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	// [P1] 核心断言 1：Client 的 SudoUpdateToken 必须严格保持建连时的 origSudoToken，绝不能接纳并发修改后的 SudoVersion
	if client.Config().SudoUpdateToken != origSudoToken {
		t.Fatalf("expected client SudoUpdateToken to remain %q, but got %q", origSudoToken, client.Config().SudoUpdateToken)
	}

	// [P1] 核心断言 2：旧连接后续尝试解析 su 密码时，由于带着保留的旧 Sudo 快照令牌，必须触发版本冲突拦截（ErrSnapshotMismatch）
	_, secretErr := adapter.ResolveSecret(ctx, ssh.SecretRequest{
		Kind:         ssh.SecretKindSuPassword,
		NodeID:       "node-cross-handshake",
		User:         client.Config().User,
		Host:         client.Config().Address,
		Port:         client.Config().Port,
		VersionToken: client.Config().SudoUpdateToken,
	})
	if secretErr == nil {
		t.Fatal("expected ResolveSecret for SuPassword to fail with ErrSnapshotMismatch, got nil")
	}
	if !errors.Is(secretErr, ssh.ErrSnapshotMismatch) {
		t.Fatalf("expected ErrSnapshotMismatch in error chain, got: %v", secretErr)
	}
}

// TestSSHAdapter_RealRepository_CrossKind_SudoUpdate_PreservesAuthSnapshot_RejectsConcurrentAuth
// 验证提权写回期间并发修改登录密码时，Client 刷新严格保留旧 Auth 快照，后续解析登录密码被拦截
func TestSSHAdapter_RealRepository_CrossKind_SudoUpdate_PreservesAuthSnapshot_RejectsConcurrentAuth(t *testing.T) {
	setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	loginPwd := "login-pass-orig"
	origSuPwd := "su-pass-orig"
	host, port, cleanup := startAdapterPrivilegeSSHServer(t, loginPwd, origSuPwd)
	defer cleanup()

	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	cfg.Hosts.Set("host-cross-sudo", models.Host{Address: host, Port: uint16(port)})
	cfg.Identities.Set("id-cross-sudo", models.Identity{User: "root", AuthType: "password", Password: loginPwd})
	cfg.Nodes.Set("node-cross-sudo", models.Node{
		HostRef:     "host-cross-sudo",
		IdentityRef: "id-cross-sudo",
		SudoMode:    models.SudoModeAuto,
		SuPwd:       origSuPwd,
	})

	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, adapterTestStore{})
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH error = %v", err)
	}

	adapter := NewSSHAdapter(repo)
	initialSnap, err := repo.ResolveConnection("node-cross-sudo")
	if err != nil {
		t.Fatalf("ResolveConnection failed: %v", err)
	}
	origAuthToken := string(initialSnap.UpdateRef.AuthVersion[:])
	origSudoToken := string(initialSnap.UpdateRef.SudoVersion[:])

	// 在提权写回 UpdateSudo 成功后、刷新配置前，模拟外部并发修改了登录密码
	interceptingRecorder := &interceptingCredentialRecorder{
		base: adapter,
		onAfterUpdateSudo: func() {
			_, uErr := repo.UpdateAuthAtVersionContext(context.Background(), "node-cross-sudo", origAuthToken, "new-concurrent-login-pwd", "", "")
			if uErr != nil {
				t.Logf("concurrent UpdateAuthAtVersionContext error: %v", uErr)
			}
		},
	}

	prompter := &testAdapterPrompter{returnSecret: loginPwd}
	connector := ssh.NewConnector(
		adapter,
		ssh.WithSecretResolver(adapter),
		ssh.WithSecretPrompter(prompter),
		ssh.WithCredentialRecorder(interceptingRecorder),
	)
	connector.AcceptNewHostKey.Store(true)
	defer func() { _ = connector.CloseAll() }()

	ctx := context.Background()
	client, err := connector.Connect(ctx, "node-cross-sudo")
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	// 触发探测并写回 SudoMode（SudoModeAuto -> SudoModeSudo）。
	// 在写回 SudoMode 时，onAfterUpdateSudo 并发修改了登录密码。
	// 因为更新提权模式后刷新严格保留了旧的 AuthUpdateToken，所以在随后的 sudo 执行中，
	// 当尝试解析登录密码以完成提权命令时，旧快照令牌与 Repository 当前新版本冲突，精准返回 ErrSnapshotMismatch！
	_, runErr := client.RunWithSudo(ctx, "whoami")
	if runErr == nil {
		t.Fatal("expected RunWithSudo to fail due to version mismatch on preserved old AuthUpdateToken, got nil")
	}
	if !errors.Is(runErr, ssh.ErrSnapshotMismatch) {
		t.Fatalf("expected ErrSnapshotMismatch from RunWithSudo, got: %v", runErr)
	}

	// [P1] 核心断言 1：Sudo 模式成功推进为探测结果 SudoModeSudo，且 SudoUpdateToken 推进为新版本
	if client.Config().SudoMode != ssh.SudoModeSudo {
		t.Errorf("expected client SudoMode to be %q, got %q", ssh.SudoModeSudo, client.Config().SudoMode)
	}
	if client.Config().SudoUpdateToken == origSudoToken {
		t.Errorf("expected client SudoUpdateToken to advance from %q", origSudoToken)
	}

	// [P1] 核心断言 2：Auth 令牌严格保留旧快照 origAuthToken，绝不接纳并发修改后的新版本
	if client.Config().AuthUpdateToken != origAuthToken {
		t.Fatalf("expected client AuthUpdateToken to remain %q, but got %q", origAuthToken, client.Config().AuthUpdateToken)
	}

	// [P1] 核心断言 3：旧连接后续单独解析登录密码时，由于带着保留的旧 Auth 快照令牌，必须触发冲突拦截（ErrSnapshotMismatch）
	_, secretErr := adapter.ResolveSecret(ctx, ssh.SecretRequest{
		Kind:         ssh.SecretKindLoginPassword,
		NodeID:       "node-cross-sudo",
		User:         client.Config().User,
		Host:         client.Config().Address,
		Port:         client.Config().Port,
		VersionToken: client.Config().AuthUpdateToken, // 带有旧快照令牌
	})
	if secretErr == nil {
		t.Fatal("expected ResolveSecret to fail with ErrSnapshotMismatch, got nil")
	}
	if !errors.Is(secretErr, ssh.ErrSnapshotMismatch) {
		t.Fatalf("expected ErrSnapshotMismatch in error chain, got: %v", secretErr)
	}
}

func adapterPrivilegeSignal(t *testing.T, channel cryptossh.Channel, command string, prompt bool) bool {
	t.Helper()
	if !strings.Contains(command, "[xops-ready-") {
		return true
	}
	prefix := "[xops-ready-"
	if prompt {
		prefix = "[xops-password-"
	}
	start := strings.Index(command, prefix)
	if start < 0 {
		return true
	}
	end := strings.Index(command[start:], "]")
	if end < 0 {
		t.Error("invalid protocol frame")
		return false
	}
	token := command[start : start+end+1]
	if !prompt && token == "[xops-ready-%s]" {
		nonce := regexp.MustCompile(`[A-Z2-7]{26,}`).FindString(command[start:])
		token = "[xops-ready-" + nonce + "]"
	}
	if _, err := io.WriteString(channel.Stderr(), token); err != nil {
		t.Error(err)
		return false
	}
	if !prompt {
		if _, err := io.Copy(io.Discard, channel); err != nil {
			t.Error(err)
			return false
		}
	}
	return true
}
