package ssh

import (
	"context"
	"errors"
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
	SudoUpdateToken string
	ProxyJump       string // 跳板机的 NodeID
	// PasswordPromptPattern 自定义密码提示正则（节点级，可选）。
	// 为空时回落到 Connector 的全局配置，再为空则使用内置的多语言默认模式。
	PasswordPromptPattern string
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
	// UpdateAuth 在探测到可用密码或私钥 passphrase 时，写回持久化存储
	UpdateAuth(ctx context.Context, nodeID, authUpdateToken, password, keyPath, passphrase string) error

	// UpdateSudo 在探测到可用提权模式或接收到 su 密码时，写回持久化存储
	UpdateSudo(ctx context.Context, nodeID, sudoUpdateToken string, mode SudoMode, suPwd string) error
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
