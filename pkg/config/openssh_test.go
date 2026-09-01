package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOpenSSHParser_NonExistentFile 验证当配置文件不存在时，返回空 Parser 且错误为 nil
func TestOpenSSHParser_NonExistentFile(t *testing.T) {
	nonExistentPath := filepath.Join(t.TempDir(), "non_existent_config")
	parser, err := NewOpenSSHParserFromPath(nonExistentPath)
	if err != nil {
		t.Fatalf("expected nil error for non-existent config, got %v", err)
	}
	if parser == nil {
		t.Fatal("expected non-nil parser")
	}

	// 查找任意 alias 应该返回虚拟节点 ID
	nodeID, ok := parser.Find("myserver")
	if !ok {
		t.Error("expected Find to return true for virtual node")
	}
	if nodeID != OpenSSHNodePrefix+"myserver" {
		t.Errorf("expected %q, got %q", OpenSSHNodePrefix+"myserver", nodeID)
	}
}

type failReader struct{}

func (failReader) Read([]byte) (int, error) {
	return 0, errors.New("simulated I/O read failure")
}

// TestOpenSSHParser_ReaderError 验证当 Reader 返回错误时，NewOpenSSHParserFromReader 正确传播错误
func TestOpenSSHParser_ReaderError(t *testing.T) {
	_, err := NewOpenSSHParserFromReader(failReader{})
	if err == nil {
		t.Fatal("expected error for failing reader, got nil")
	}
	if !strings.Contains(err.Error(), "decode ssh config") {
		t.Errorf("expected error message to contain 'decode ssh config', got: %v", err)
	}
}

// TestOpenSSHParser_PathError 验证当路径指向不可读文件时，返回具体错误
func TestOpenSSHParser_PathError(t *testing.T) {
	tmpDir := t.TempDir()
	unreadablePath := filepath.Join(tmpDir, "unreadable_config")
	if err := os.WriteFile(unreadablePath, []byte("Host test\n"), 0000); err != nil {
		t.Fatalf("write temp file failed: %v", err)
	}

	_, err := NewOpenSSHParserFromPath(unreadablePath)
	if err == nil {
		// 在 root 权限下 0000 仍可读，退化为以目录作为文件路径测试
		_, err = NewOpenSSHParserFromPath(tmpDir)
	}
	if err == nil {
		t.Fatal("expected error for invalid config path, got nil")
	}
}

// TestOpenSSHParser_ValidConfig 验证合法配置能够正确解析各字段
func TestOpenSSHParser_ValidConfig(t *testing.T) {
	configContent := `
Host web-server
    HostName 192.168.1.100
    User devops
    Port 2222
    IdentityFile ~/.ssh/id_rsa_custom
    ProxyJump jump-server

Host jump-server
    HostName 1.2.3.4
    User jumpuser
    Port 22
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(configContent))
	if err != nil {
		t.Fatalf("parse valid config failed: %v", err)
	}

	node, host, identity, err := parser.GetVirtualNode("web-server")
	if err != nil {
		t.Fatalf("GetVirtualNode failed: %v", err)
	}

	if host.Address != "192.168.1.100" {
		t.Errorf("expected address 192.168.1.100, got %s", host.Address)
	}
	if host.Port != 2222 {
		t.Errorf("expected port 2222, got %d", host.Port)
	}
	if identity.User != "devops" {
		t.Errorf("expected user devops, got %s", identity.User)
	}
	if node.ProxyJump != OpenSSHNodePrefix+"jump-server" {
		t.Errorf("expected proxy jump %q, got %q", OpenSSHNodePrefix+"jump-server", node.ProxyJump)
	}
}

// TestOpenSSHParser_InvalidPort 验证非法、零值或越界端口返回带字段上下文的明确错误
func TestOpenSSHParser_InvalidPort(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name: "zero port",
			config: `
Host bad-port
    HostName 1.2.3.4
    Port 0
`,
			wantErr: "invalid port \"0\" for \"bad-port\"",
		},
		{
			name: "out of range port",
			config: `
Host bad-port
    HostName 1.2.3.4
    Port 70000
`,
			wantErr: "invalid port \"70000\" for \"bad-port\"",
		},
		{
			name: "non-numeric port",
			config: `
Host bad-port
    HostName 1.2.3.4
    Port abc
`,
			wantErr: "invalid port \"abc\" for \"bad-port\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser, err := NewOpenSSHParserFromReader(strings.NewReader(tt.config))
			if err != nil {
				t.Fatalf("parse failed: %v", err)
			}
			_, _, _, err = parser.GetVirtualNode("bad-port")
			if err == nil {
				t.Fatal("expected error for invalid port, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

// TestOpenSSHParser_ProxyJumpAndUser 验证 ProxyJump 的 none/多跳解析以及用户名获取逻辑
func TestOpenSSHParser_ProxyJumpAndUser(t *testing.T) {
	configContent := `
Host hop-none
    HostName 10.0.0.1
    ProxyJump none

Host hop-multi
    HostName 10.0.0.2
    ProxyJump jumpuser@jump1:2201, jump2

Host custom-user
    HostName 10.0.0.3
`
	// 注入 mock 用户名，验证当配置无 User 时使用当前系统用户名
	oldUserFn := currentUserFn
	defer func() { currentUserFn = oldUserFn }()
	currentUserFn = func() (string, error) {
		return "mock_logged_user", nil
	}

	parser, err := NewOpenSSHParserFromReader(strings.NewReader(configContent))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	// 1. none ProxyJump 应为空
	node1, _, _, err := parser.GetVirtualNode("hop-none")
	if err != nil {
		t.Fatalf("get hop-none failed: %v", err)
	}
	if node1.ProxyJump != "" {
		t.Errorf("expected empty ProxyJump for none, got %q", node1.ProxyJump)
	}

	// 2. 多跳 ProxyJump
	node2, _, _, err := parser.GetVirtualNode("hop-multi")
	if err != nil {
		t.Fatalf("get hop-multi failed: %v", err)
	}
	expectedPJ := OpenSSHNodePrefix + "jumpuser@jump1:2201," + OpenSSHNodePrefix + "jump2"
	if node2.ProxyJump != expectedPJ {
		t.Errorf("expected ProxyJump %q, got %q", expectedPJ, node2.ProxyJump)
	}
	_, jumpHost, jumpIdentity, err := parser.GetVirtualNode("jumpuser@jump1:2201")
	if err != nil {
		t.Fatalf("get explicit jump spec failed: %v", err)
	}
	if jumpHost.Address != "jump1" || jumpHost.Port != 2201 || jumpIdentity.User != "jumpuser" {
		t.Fatalf("unexpected explicit jump config: host=%+v identity=%+v", jumpHost, jumpIdentity)
	}

	// 3. 用户名回退
	_, _, id3, err := parser.GetVirtualNode("custom-user")
	if err != nil {
		t.Fatalf("get custom-user failed: %v", err)
	}
	if id3.User != "mock_logged_user" {
		t.Errorf("expected user mock_logged_user, got %q", id3.User)
	}
}

// TestProvider_ResolveOpenSSHErrors 验证 Provider.Resolve 能够直接保留 OpenSSH 虚拟节点的解析错误
func TestProvider_ResolveOpenSSHErrors(t *testing.T) {
	configContent := `
Host invalid-host
    HostName 10.0.0.1
    Port 99999
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(configContent))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	cfg := &Configuration{}
	provider := NewProviderWithOpenSSHParser(cfg, parser)

	nodeID := provider.Find("invalid-host")
	_, _, _, resolveErr := provider.Resolve(nodeID)
	if resolveErr == nil {
		t.Fatal("expected resolveErr on invalid port, got nil")
	}
	if !strings.Contains(resolveErr.Error(), "invalid port \"99999\"") {
		t.Errorf("expected error containing invalid port 99999, got: %v", resolveErr)
	}
}

// TestProvider_OpenSSHVirtualNodeLookup verifies that virtual OpenSSH nodes are
// resolved through the error-returning aggregate API.
func TestProvider_OpenSSHVirtualNodeLookup(t *testing.T) {
	configContent := `
Host remote-app
    HostName 10.0.0.5
    User deploy
    Port 2200
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(configContent))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	cfg := &Configuration{}
	provider := NewProviderWithOpenSSHParser(cfg, parser)

	nodeID := provider.Find("remote-app")
	if nodeID != OpenSSHNodePrefix+"remote-app" {
		t.Fatalf("expected %q, got %q", OpenSSHNodePrefix+"remote-app", nodeID)
	}

	node, host, identity, err := provider.Resolve(nodeID)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if len(node.Alias) == 0 || node.Alias[0] != "remote-app" {
		t.Errorf("unexpected node alias: %v", node.Alias)
	}
	if host.Address != "10.0.0.5" || host.Port != 2200 {
		t.Errorf("unexpected host: %+v", host)
	}
	if identity.User != "deploy" {
		t.Errorf("unexpected identity: %+v", identity)
	}
	connection, err := provider.ResolveConnection(nodeID)
	if err != nil {
		t.Fatalf("ResolveConnection failed: %v", err)
	}
	if connection.UpdateRef != nil {
		t.Fatal("virtual OpenSSH node must not expose a persistence update reference")
	}
	if connection.Host.Address != host.Address || connection.Host.Port != host.Port || connection.Identity.User != identity.User {
		t.Fatalf("ResolveConnection returned unexpected connection: %+v", connection)
	}
	if _, ok := provider.GetNode(nodeID); ok {
		t.Error("GetNode must not parse virtual OpenSSH nodes or swallow parser errors")
	}
}

func TestRepositoryResolveConnectionOpenSSHVirtualNodeIsReadOnly(t *testing.T) {
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(`
Host remote-app
    HostName 10.0.0.5
    User deploy
    Port 2200
`))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	repository, err := NewRepositoryWithOpenSSHParser(&Configuration{}, &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser() error = %v", err)
	}

	connection, err := repository.ResolveConnection(OpenSSHNodePrefix + "remote-app")
	if err != nil {
		t.Fatalf("ResolveConnection() error = %v", err)
	}
	if connection.UpdateRef != nil {
		t.Fatal("OpenSSH virtual node must remain session-local")
	}
	if connection.Host.Address != "10.0.0.5" || connection.Identity.User != "deploy" {
		t.Fatalf("unexpected OpenSSH connection: %+v", connection)
	}
}

func TestParseOpenSSHHostSpec(t *testing.T) {
	tests := []struct {
		name     string
		spec     string
		wantHost string
		wantUser string
		wantPort uint16
		wantErr  bool
	}{
		{name: "host", spec: "jump", wantHost: "jump"},
		{name: "user and port", spec: "deploy@jump:2201", wantHost: "jump", wantUser: "deploy", wantPort: 2201},
		{name: "bracketed ipv6", spec: "root@[2001:db8::1]:2222", wantHost: "2001:db8::1", wantUser: "root", wantPort: 2222},
		{name: "unbracketed ipv6", spec: "2001:db8::1", wantHost: "2001:db8::1"},
		{name: "empty port", spec: "jump:", wantErr: true},
		{name: "empty bracketed port", spec: "[2001:db8::1]:", wantErr: true},
		{name: "out of range port", spec: "jump:65536", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, userName, port, err := parseOpenSSHHostSpec(tt.spec)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseOpenSSHHostSpec(%q) error = %v, wantErr %v", tt.spec, err, tt.wantErr)
			}
			if err == nil && (host != tt.wantHost || userName != tt.wantUser || port != tt.wantPort) {
				t.Fatalf(
					"parseOpenSSHHostSpec(%q) = (%q, %q, %d), want (%q, %q, %d)",
					tt.spec, host, userName, port, tt.wantHost, tt.wantUser, tt.wantPort,
				)
			}
		})
	}
}
