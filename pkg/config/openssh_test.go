package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
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

func TestOpenSSHParser_ControlConfig_Modes(t *testing.T) {
	configContent := `
Host srv-auto
    HostName 10.0.0.1
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h-%p
    ControlPersist 10m

Host srv-yes
    HostName 10.0.0.2
    ControlMaster yes
    ControlPath /tmp/mux-%C.sock
    ControlPersist 0

Host srv-ask
    HostName 10.0.0.3
    ControlMaster ask
    ControlPath ~/.ssh/cm-%h
    ControlPersist 1h
`

	parser, err := NewOpenSSHParserFromReader(strings.NewReader(configContent))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	node1, _, _, err := parser.GetVirtualNode("srv-auto")
	if err != nil {
		t.Fatalf("GetVirtualNode(srv-auto) failed: %v", err)
	}
	if node1.SSHOptions == nil || node1.SSHOptions.ControlMaster() != ssh.ControlMasterAuto ||
		node1.SSHOptions.ControlPath() != "~/.ssh/sockets/%r@%h-%p" ||
		node1.SSHOptions.ControlPersist() != "10m" {
		t.Fatalf("srv-auto control mismatch: %+v", node1.SSHOptions)
	}
	ctrl1, err := parser.GetControlConfig("srv-auto")
	if err != nil || !ctrl1.Equal(node1.SSHOptions.ControlConfig()) {
		t.Fatalf("GetControlConfig(srv-auto) mismatch: %v, err=%v", ctrl1, err)
	}

	node2, _, _, err := parser.GetVirtualNode("srv-yes")
	if err != nil {
		t.Fatalf("GetVirtualNode(srv-yes) failed: %v", err)
	}
	if node2.SSHOptions == nil || node2.SSHOptions.ControlMaster() != ssh.ControlMasterYes ||
		node2.SSHOptions.ControlPath() != "/tmp/mux-%C.sock" ||
		node2.SSHOptions.ControlPersist() != "0" {
		t.Fatalf("srv-yes control mismatch: %+v", node2.SSHOptions)
	}

	node3, _, _, err := parser.GetVirtualNode("srv-ask")
	if err != nil {
		t.Fatalf("GetVirtualNode(srv-ask) failed: %v", err)
	}
	if node3.SSHOptions == nil || node3.SSHOptions.ControlMaster() != ssh.ControlMasterAsk ||
		node3.SSHOptions.ControlPersist() != "1h" {
		t.Fatalf("srv-ask control mismatch: %+v", node3.SSHOptions)
	}
}

func TestOpenSSHParser_ControlConfig_NoneAndNoControl(t *testing.T) {
	configContent := `
Host srv-none
    HostName 10.0.0.4
    ControlMaster no
    ControlPath none
    ControlPersist no

Host srv-nocontrol
    HostName 10.0.0.5
`

	parser, err := NewOpenSSHParserFromReader(strings.NewReader(configContent))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	node4, _, _, err := parser.GetVirtualNode("srv-none")
	if err != nil {
		t.Fatalf("GetVirtualNode(srv-none) failed: %v", err)
	}
	if node4.SSHOptions == nil || node4.SSHOptions.ControlPath() != "none" || node4.SSHOptions.ControlMaster() != ssh.ControlMasterNo {
		t.Fatalf("srv-none control mismatch: %+v", node4.SSHOptions)
	}
	if node4.SSHOptions.ControlConfig().IsEnabled() {
		t.Fatalf("srv-none should have IsEnabled() == false")
	}

	node5, _, _, err := parser.GetVirtualNode("srv-nocontrol")
	if err != nil {
		t.Fatalf("GetVirtualNode(srv-nocontrol) failed: %v", err)
	}
	if node5.SSHOptions != nil {
		t.Fatalf("expected srv-nocontrol SSHOptions to be nil, got: %+v", node5.SSHOptions)
	}
}

func TestOpenSSHParser_ControlConfig_WildcardInheritance(t *testing.T) {
	configContent := `
Host concrete-override
    HostName 10.0.1.1
    ControlMaster no

Host concrete-disabled
    HostName 10.0.1.2
    ControlPath none

Host concrete-normal
    HostName 10.0.1.3

Host *
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h-%p
    ControlPersist 10m
`

	parser, err := NewOpenSSHParserFromReader(strings.NewReader(configContent))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	// 1. concrete-normal inherits all from Host *
	ctrlNormal, err := parser.GetControlConfig("concrete-normal")
	if err != nil {
		t.Fatalf("GetControlConfig(concrete-normal) failed: %v", err)
	}
	if ctrlNormal == nil {
		t.Fatal("expected concrete-normal to inherit control options")
	}
	if ctrlNormal.Master != ssh.ControlMasterAuto ||
		ctrlNormal.Path != "~/.ssh/sockets/%r@%h-%p" ||
		ctrlNormal.Persist != "10m" {
		t.Fatalf("inherited control mismatch: %+v", ctrlNormal)
	}

	// 2. concrete-override overrides Master to 'no', but inherits Path and Persist
	ctrlOverride, err := parser.GetControlConfig("concrete-override")
	if err != nil {
		t.Fatalf("GetControlConfig(concrete-override) failed: %v", err)
	}
	if ctrlOverride.Master != ssh.ControlMasterNo ||
		ctrlOverride.Path != "~/.ssh/sockets/%r@%h-%p" ||
		ctrlOverride.Persist != "10m" {
		t.Fatalf("overridden master mismatch: %+v", ctrlOverride)
	}

	// 3. concrete-disabled overrides Path to 'none'
	ctrlDisabled, err := parser.GetControlConfig("concrete-disabled")
	if err != nil {
		t.Fatalf("GetControlConfig(concrete-disabled) failed: %v", err)
	}
	if ctrlDisabled.Path != "none" {
		t.Fatalf("expected Path='none', got: %q", ctrlDisabled.Path)
	}
	if ctrlDisabled.IsEnabled() {
		t.Fatal("expected IsEnabled() == false for Path='none'")
	}
}

func TestOpenSSHParser_ControlConfig_Invalid(t *testing.T) {
	// 1. Invalid ControlMaster
	cfg1 := `
Host bad-master
    ControlMaster invalid_val
`
	parser1, _ := NewOpenSSHParserFromReader(strings.NewReader(cfg1))
	_, err1 := parser1.GetControlConfig("bad-master")
	if err1 == nil || !strings.Contains(err1.Error(), "invalid ControlMaster") {
		t.Fatalf("expected invalid ControlMaster error, got: %v", err1)
	}

	// 2. Invalid ControlPersist
	cfg2 := `
Host bad-persist
    ControlPersist 10x
`
	parser2, _ := NewOpenSSHParserFromReader(strings.NewReader(cfg2))
	_, err2 := parser2.GetControlConfig("bad-persist")
	if err2 == nil || !strings.Contains(err2.Error(), "invalid ControlPersist") {
		t.Fatalf("expected invalid ControlPersist error, got: %v", err2)
	}
}

// TestOpenSSHImport_NormalizesContradictoryControl verifies that a host which
// resolved to ControlMaster=no while inheriting ControlPersist from a wildcard
// still imports: the persisted schema rejects that combination outright.
func TestOpenSSHImport_NormalizesContradictoryControl(t *testing.T) {
	configContent := `
Host no-master-host
    HostName 10.0.0.7
    ControlMaster no

Host *
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h-%p
    ControlPersist 10m
`
	hosts, err := ParseOpenSSHHosts(strings.NewReader(configContent), "deploy")
	if err != nil {
		t.Fatalf("ParseOpenSSHHosts failed: %v", err)
	}
	var found *OpenSSHHost
	for i := range hosts {
		if hosts[i].Name == "no-master-host" {
			found = &hosts[i]
			break
		}
	}
	if found == nil {
		t.Fatal("no-master-host was not imported")
	}
	if found.Node.SSHOptions == nil {
		t.Fatal("expected imported ssh_options config")
	}
	if found.Node.SSHOptions.ControlMaster() != ssh.ControlMasterNo {
		t.Fatalf("expected ControlMaster=no, got %q", found.Node.SSHOptions.ControlMaster())
	}
	if found.Node.SSHOptions.ControlPersist() != "" {
		t.Fatalf("expected inherited ControlPersist to be dropped for ControlMaster=no, got %q", found.Node.SSHOptions.ControlPersist())
	}
	if err := ValidateSSHOptions(found.Node.SSHOptions); err != nil {
		t.Fatalf("imported ssh_options config is invalid: %v", err)
	}
}

// TestOpenSSHParser_ControlMasterAbsentStaysUnset verifies that an omitted
// ControlMaster is not materialized as "no"; doing so would block orthogonal
// inheritance from a lower-priority layer.
func TestOpenSSHParser_ControlMasterAbsentStaysUnset(t *testing.T) {
	configContent := `
Host path-only
    HostName 10.0.0.8
    ControlPath ~/.ssh/path-only.sock
    ControlPersist 5m
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(configContent))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	ctrl, err := parser.GetControlConfig("path-only")
	if err != nil {
		t.Fatalf("GetControlConfig failed: %v", err)
	}
	if ctrl == nil {
		t.Fatal("expected control config")
	}
	if ctrl.Master != "" {
		t.Fatalf("expected an unset ControlMaster, got %q", ctrl.Master)
	}
	if ctrl.Path != "~/.ssh/path-only.sock" || ctrl.Persist != "5m" {
		t.Fatalf("unexpected control config %+v", ctrl)
	}
}

func TestOpenSSHParser_LenientOptionsAndNeverInheritsTrust(t *testing.T) {
	configContent := `
Host *
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256
    MACs umac-128-etm@openssh.com,hmac-sha2-256
    PreferredAuthentications gssapi-with-mic,publickey,password
    PubkeyAuthentication unbound
    ChallengeResponseAuthentication yes

Host modern-host
    HostName 10.0.0.99
    User ubuntu
    KbdInteractiveAuthentication no
    ControlPath ~/.ssh/cm-%k
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(configContent))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	node, _, _, err := parser.GetVirtualNode("modern-host")
	if err != nil {
		t.Fatalf("GetVirtualNode(modern-host) failed on modern OpenSSH options: %v", err)
	}
	if node.SSHOptions == nil {
		t.Fatal("expected non-nil SSHOptions")
	}
	// H1: Trust options in ~/.ssh/config must never be inherited
	if node.SSHOptions.StrictHostKeyChecking() != "" || node.SSHOptions.UserKnownHostsFile() != "" {
		t.Fatalf("expected trust options from ~/.ssh/config to be ignored, got %+v", node.SSHOptions)
	}
	// H3: Unsupported algorithm/auth items filtered out, supported items kept
	if got := node.SSHOptions.Get(ssh.OptionKexAlgorithms); got != "curve25519-sha256" {
		t.Fatalf("expected KexAlgorithms=curve25519-sha256, got %q", got)
	}
	if got := node.SSHOptions.Get(ssh.OptionMACs); got != "hmac-sha2-256" {
		t.Fatalf("expected MACs=hmac-sha2-256, got %q", got)
	}
	if got := node.SSHOptions.Get(ssh.OptionPreferredAuthentications); got != "publickey,password" {
		t.Fatalf("expected PreferredAuthentications=publickey,password, got %q", got)
	}
	// Unsupported ControlPath token %k and PubkeyAuthentication=unbound are skipped leniently
	if node.SSHOptions.ControlPath() != "" {
		t.Fatalf("expected unsupported ControlPath %%k to be skipped, got %q", node.SSHOptions.ControlPath())
	}
	// L4: ChallengeResponseAuthentication in Host * appeared before KbdInteractiveAuthentication in Host modern-host
	if kbdEnabled, kbdSet := node.SSHOptions.KbdInteractiveAuthentication(); !kbdSet || !kbdEnabled {
		t.Fatalf("expected first-match-wins ChallengeResponseAuthentication=yes in Host * to win over later KbdInteractiveAuthentication=no")
	}
}
