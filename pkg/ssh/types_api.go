package ssh

import (
	"context"
	"errors"
	"fmt"
)

// SudoMode 定义了 SSH 连接执行命令时的提权方式
type SudoMode string

const (
	SudoModeRoot   SudoMode = "root"
	SudoModeSudo   SudoMode = "sudo"
	SudoModeSudoer SudoMode = "sudoer"
	SudoModeSu     SudoMode = "su"
	SudoModeNone   SudoMode = "none"
	SudoModeAuto   SudoMode = "auto"
)

// ClientConfig 定义建立 SSH 连接所需的各种参数，代替原有的 models.Node/Host/Identity。
type ClientConfig struct {
	NodeID     string // 逻辑标识
	Address    string
	Port       int
	User       string
	AuthType   string // "password", "key", "agent", "auto"
	Password   string
	KeyPath    string
	Passphrase string
	// AuthUpdateToken conditionally authorizes persistence of discovered
	// authentication values. An empty token makes discovery session-local.
	AuthUpdateToken string
	SudoMode        SudoMode // "root", "sudo", "sudoer", "su", "none", "auto"
	SuPwd           string
	// SudoUpdateToken conditionally authorizes persistence of discovered sudo
	// values. An empty token makes discovery session-local.
	SudoUpdateToken      string
	ProxyJump            string // 跳板机的 NodeID
	OriginalProxyJump    string // 来自 Provider 的原始 ProxyJump 配置（用于目标一致性变更检查）
	HasOriginalProxyJump bool   // 是否显式保留了配置态 ProxyJump 快照（区分显式空字符串与未设置）
	// PasswordPromptPattern 自定义密码提示正则（节点级，可选）。
	// 为空时回落到 Connector 的全局配置，再为空则使用内置的多语言默认模式。
	PasswordPromptPattern string
}

// ToConnectionConfig 将 ClientConfig 转换为仅含网络与连接参数的 ConnectionConfig，剥离所有明文密码。
func (c *ClientConfig) ToConnectionConfig() ConnectionConfig {
	if c == nil {
		return ConnectionConfig{}
	}
	origJump := c.OriginalProxyJump
	hasOriginal := c.HasOriginalProxyJump
	if !hasOriginal && origJump == "" {
		origJump = c.ProxyJump
	}
	return ConnectionConfig{
		NodeID:                c.NodeID,
		Address:               c.Address,
		Port:                  c.Port,
		User:                  c.User,
		AuthType:              c.AuthType,
		KeyPath:               c.KeyPath,
		AuthUpdateToken:       c.AuthUpdateToken,
		SudoMode:              c.SudoMode,
		SudoUpdateToken:       c.SudoUpdateToken,
		ProxyJump:             c.ProxyJump,
		OriginalProxyJump:     origJump,
		HasOriginalProxyJump:  hasOriginal,
		PasswordPromptPattern: c.PasswordPromptPattern,
	}
}

// ConnectionConfig 包含建立连接所需的目标与网络参数，不包含登录或提权明文机密。
type ConnectionConfig struct {
	NodeID                string
	Address               string
	Port                  int
	User                  string
	AuthType              string
	KeyPath               string
	AuthUpdateToken       string
	SudoMode              SudoMode
	SudoUpdateToken       string
	ProxyJump             string
	OriginalProxyJump     string
	HasOriginalProxyJump  bool
	PasswordPromptPattern string
}

// AuthMaterial 包含单次 SSH 握手所需的敏感认证材料。
type AuthMaterial struct {
	Password   []byte
	Passphrase []byte
}

// Zero 清零敏感字节切片并清空引用。
func (a *AuthMaterial) Zero() {
	if a == nil {
		return
	}
	zeroBytes(a.Password)
	zeroBytes(a.Passphrase)
	a.Password = nil
	a.Passphrase = nil
}

// PrivilegeMaterial 包含单次提权 (sudo/su) 所需的敏感机密材料。
type PrivilegeMaterial struct {
	Password []byte
}

// Zero 清零敏感字节切片并清空引用。
func (p *PrivilegeMaterial) Zero() {
	if p == nil {
		return
	}
	zeroBytes(p.Password)
	p.Password = nil
}

// zeroBytes 将切片中的所有敏感字节清零。
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ConnectionProvider 提供指定节点的底层连接配置。
type ConnectionProvider interface {
	// GetConfig 获取指定 nodeID 的连接配置
	GetConfig(nodeID string) (*ClientConfig, error)
}

// SecretResolver 解析指定节点认证或提权所需机密。
type SecretResolver interface {
	// ResolveSecret 根据机密请求解析并返回机密字节
	ResolveSecret(ctx context.Context, req SecretRequest) ([]byte, error)
}

// CredentialRecorder 负责将探测或交互获得的新凭据写回持久化存储。
type CredentialRecorder interface {
	// UpdateAuth 在探测到可用密码或私钥 passphrase 时，写回持久化存储并返回本次提交后的新认证令牌
	UpdateAuth(ctx context.Context, nodeID, authUpdateToken, password, keyPath, passphrase string) (string, error)

	// UpdateSudo 在探测到可用提权模式或接收到 su 密码时，写回持久化存储并返回本次提交后的新提权令牌
	UpdateSudo(ctx context.Context, nodeID, sudoUpdateToken string, mode SudoMode, suPwd string) (string, error)
}

// ConfigStore 聚合 ConnectionProvider 和 CredentialRecorder 接口。
// Deprecated: 请优先使用拆分后的小接口 ConnectionProvider, SecretResolver, CredentialRecorder。
type ConfigStore interface {
	ConnectionProvider
	CredentialRecorder
}

// SecretKind 标识需要交互输入的机密类型
type SecretKind uint8

const (
	SecretKindUnknown SecretKind = iota
	SecretKindLoginPassword
	SecretKindPrivateKeyPassphrase
	SecretKindSuPassword
)

// ErrSnapshotMismatch 表示连接快照与当前配置版本或目标不匹配
var ErrSnapshotMismatch = errors.New("connection snapshot mismatch")

// SecretRequest 描述向解析器或用户请求机密的上下文信息（严禁携带已有密码）
type SecretRequest struct {
	Kind         SecretKind
	NodeID       string
	User         string
	Host         string
	Port         int
	KeyPath      string
	VersionToken string
}

// HostKeyConfirmation 描述主机密钥指纹确认请求
type HostKeyConfirmation struct {
	Hostname      string
	RemoteAddress string
	Algorithm     string
	Fingerprint   string
}

// SecretPrompter 负责提示用户输入敏感凭据（如密码、私钥密码短语等）
type SecretPrompter interface {
	PromptSecret(ctx context.Context, request SecretRequest) (string, error)
}

// HostKeyConfirmer 负责提示用户确认未知的主机密钥
type HostKeyConfirmer interface {
	ConfirmHostKey(ctx context.Context, request HostKeyConfirmation) (bool, error)
}

// InteractionHandler 组合了机密提示与主机密钥确认接口
type InteractionHandler interface {
	SecretPrompter
	HostKeyConfirmer
}

type tokenRefreshKind int

const (
	tokenRefreshKindAuth tokenRefreshKind = iota
	tokenRefreshKindSudo
)

// validateTargetCompatibility 校验新配置的目标属性是否与已建立的连接快照完全一致
func validateTargetCompatibility(cur ConnectionConfig, newCfg *ClientConfig) error {
	if newCfg == nil {
		return fmt.Errorf("%w: target configuration is nil", ErrSnapshotMismatch)
	}
	if newCfg.Address != cur.Address {
		return fmt.Errorf("%w: host address changed (expected %q, got %q)",
			ErrSnapshotMismatch, cur.Address, newCfg.Address)
	}
	if newCfg.Port != cur.Port {
		return fmt.Errorf("%w: host port changed (expected %d, got %d)",
			ErrSnapshotMismatch, cur.Port, newCfg.Port)
	}
	if newCfg.User != cur.User {
		return fmt.Errorf("%w: user changed (expected %q, got %q)",
			ErrSnapshotMismatch, cur.User, newCfg.User)
	}
	if newCfg.KeyPath != cur.KeyPath {
		return fmt.Errorf("%w: key path changed (expected %q, got %q)",
			ErrSnapshotMismatch, cur.KeyPath, newCfg.KeyPath)
	}
	expectedJump := cur.ProxyJump
	if cur.HasOriginalProxyJump {
		expectedJump = cur.OriginalProxyJump
	} else if cur.OriginalProxyJump != "" {
		expectedJump = cur.OriginalProxyJump
	}
	actualJump := newCfg.ProxyJump
	if newCfg.HasOriginalProxyJump {
		actualJump = newCfg.OriginalProxyJump
	} else if newCfg.OriginalProxyJump != "" {
		actualJump = newCfg.OriginalProxyJump
	}
	if actualJump != expectedJump {
		return fmt.Errorf("%w: proxy jump changed (expected %q, got %q)",
			ErrSnapshotMismatch, expectedJump, actualJump)
	}
	return nil
}
