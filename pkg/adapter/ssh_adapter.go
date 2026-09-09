package adapter

import (
	"context"
	"fmt"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/ssh"
)

// SessionAuth 描述单个连接会话的临时认证机密覆盖
type SessionAuth struct {
	Password   string
	Passphrase string
	KeyPath    string
	SuPwd      string
	Remember   bool
}

// CredentialResolver 描述能够根据 Ref 解析 Secret 的契约（如 *credential.Registry）
type CredentialResolver interface {
	Resolve(ctx context.Context, ref credential.Ref) (credential.Secret, error)
}

// Option 定义 SSHAdapter 的配置选项
type Option func(*SSHAdapter)

// WithCredentialSource 注入凭据解析器（如 credential.Registry），用于解析 Ref 引用
func WithCredentialSource(source CredentialResolver) Option {
	return func(a *SSHAdapter) {
		a.credentialResolver = source
	}
}

// WithSessionAuthOverride 注入特定节点的会话级临时机密覆盖
func WithSessionAuthOverride(nodeID string, auth SessionAuth) Option {
	return func(a *SSHAdapter) {
		if a.sessionOverrides == nil {
			a.sessionOverrides = make(map[string]SessionAuth)
		}
		a.sessionOverrides[nodeID] = auth
	}
}

// WithGlobalSessionAuth 注入会话级全局默认机密覆盖（当特定节点未显式指定 override 时生效）
func WithGlobalSessionAuth(auth SessionAuth) Option {
	return func(a *SSHAdapter) {
		a.globalSessionAuth = &auth
	}
}

// WithNonInteractive 标记该适配器为非交互式环境（如批处理、MCP、Playbook）
func WithNonInteractive(nonInteractive bool) Option {
	return func(a *SSHAdapter) {
		a.nonInteractive = nonInteractive
	}
}

// WithCredentialRecording controls persistence of secrets discovered during a
// connection. Interactive UIs use false and persist only through their
// explicit credential form actions.
func WithCredentialRecording(enabled bool) Option {
	return func(a *SSHAdapter) {
		a.credentialRecording = enabled
	}
}

// SSHAdapter 实现 ssh.ConnectionProvider, ssh.SecretResolver, ssh.CredentialRecorder 接口，作为业务模型与底层 SSH 的防腐层
type SSHAdapter struct {
	cfgProvider         config.ConfigProvider
	credentialResolver  CredentialResolver
	credentialService   *credential.Service
	sessionOverrides    map[string]SessionAuth
	globalSessionAuth   *SessionAuth
	nonInteractive      bool
	credentialRecording bool
}

// WithCredentialService injects the transactional writer used when an
// interactive connection is explicitly allowed to remember a discovered
// secret.  Secrets must never be written through the legacy configuration
// fields.
func WithCredentialService(service *credential.Service) Option {
	return func(a *SSHAdapter) {
		a.credentialService = service
	}
}

var (
	_ ssh.ConnectionProvider = (*SSHAdapter)(nil)
	_ ssh.SecretResolver     = (*SSHAdapter)(nil)
	_ ssh.CredentialRecorder = (*SSHAdapter)(nil)
	_ ssh.ConfigStore        = (*SSHAdapter)(nil)
)

// NewSSHAdapter 创建 SSH 适配器
func NewSSHAdapter(cfgProvider config.ConfigProvider, opts ...Option) *SSHAdapter {
	adp := &SSHAdapter{
		cfgProvider:         cfgProvider,
		sessionOverrides:    make(map[string]SessionAuth),
		credentialRecording: true,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(adp)
		}
	}
	return adp
}

// NewNonInteractiveSSHAdapter 创建非交互式的 SSH 适配器
func NewNonInteractiveSSHAdapter(cfgProvider config.ConfigProvider, opts ...Option) *SSHAdapter {
	opts = append([]Option{WithNonInteractive(true)}, opts...)
	return NewSSHAdapter(cfgProvider, opts...)
}

// NewConnector 是一个辅助方法，快速创建组装好 Adapter 的 ssh.Connector，支持传入 Option 进行显式注入配置。
func NewConnector(cfgProvider config.ConfigProvider, opts ...ssh.Option) *ssh.Connector {
	adp := NewSSHAdapter(cfgProvider)
	return newConnector(adp, opts...)
}

// NewConnectorWithAdapterOptions 创建组装好 Adapter 选项和 SSH 选项的 Connector
func NewConnectorWithAdapterOptions(cfgProvider config.ConfigProvider, adpOpts []Option, sshOpts ...ssh.Option) *ssh.Connector {
	adp := NewSSHAdapter(cfgProvider, adpOpts...)
	return newConnector(adp, sshOpts...)
}

// NewConnectorWithInteraction creates a connector with a presentation-layer
// interaction handler supplied by the composition root.
func NewConnectorWithInteraction(cfgProvider config.ConfigProvider, interaction ssh.InteractionHandler, opts ...ssh.Option) *ssh.Connector {
	var finalOpts []ssh.Option
	if interaction != nil {
		finalOpts = append(finalOpts, ssh.WithInteractionHandler(interaction))
	}
	finalOpts = append(finalOpts, opts...)
	return NewConnector(cfgProvider, finalOpts...)
}

func newConnector(adp *SSHAdapter, opts ...ssh.Option) *ssh.Connector {
	var finalOpts []ssh.Option
	if cfg := adp.cfgProvider.Snapshot(); cfg != nil && cfg.PasswordPromptPattern != "" {
		finalOpts = append(finalOpts, ssh.WithPasswordPromptPattern(cfg.PasswordPromptPattern))
	}
	finalOpts = append(finalOpts, opts...)
	return ssh.NewConnector(adp, finalOpts...)
}

// NewNonInteractiveConnector 创建一个非交互式的 Connector，避免在批量操作中阻塞等待输入，支持传入 Option。
func NewNonInteractiveConnector(cfgProvider config.ConfigProvider, opts ...ssh.Option) *ssh.Connector {
	adp := NewNonInteractiveSSHAdapter(cfgProvider)
	return newConnector(adp, opts...)
}

func (a *SSHAdapter) getSessionOverride(nodeID string) (SessionAuth, bool) {
	if a.sessionOverrides != nil {
		if override, ok := a.sessionOverrides[nodeID]; ok {
			return override, true
		}
	}
	if a.globalSessionAuth != nil {
		return *a.globalSessionAuth, true
	}
	return SessionAuth{}, false
}

// GetConfig 获取底层 SSH 客户端需要的配置
func (a *SSHAdapter) GetConfig(nodeID string) (*ssh.ClientConfig, error) {
	if a.cfgProvider == nil {
		return nil, fmt.Errorf("configuration provider is nil")
	}
	snapshot, err := a.cfgProvider.ResolveConnection(nodeID)
	if err != nil {
		return nil, fmt.Errorf("resolve node %q failed: %w", nodeID, err)
	}
	var authUpdateToken, sudoUpdateToken string
	if snapshot.UpdateRef != nil {
		authUpdateToken = string(snapshot.UpdateRef.AuthVersion[:])
		sudoUpdateToken = string(snapshot.UpdateRef.SudoVersion[:])
	}

	cfg := &ssh.ClientConfig{
		NodeID:                nodeID,
		Address:               snapshot.Host.Address,
		Port:                  int(snapshot.Host.Port),
		User:                  snapshot.Identity.User,
		AuthType:              snapshot.Identity.AuthType,
		Password:              snapshot.Identity.Password,
		KeyPath:               snapshot.Identity.KeyPath,
		Passphrase:            snapshot.Identity.Passphrase,
		AuthUpdateToken:       authUpdateToken,
		SudoMode:              ssh.SudoMode(snapshot.Node.SudoMode),
		SuPwd:                 snapshot.Node.SuPwd,
		SudoUpdateToken:       sudoUpdateToken,
		ProxyJump:             snapshot.Node.ProxyJump,
		OriginalProxyJump:     snapshot.Node.ProxyJump,
		HasOriginalProxyJump:  true,
		PasswordPromptPattern: snapshot.Node.PasswordPromptPattern,
	}

	if override, ok := a.getSessionOverride(nodeID); ok {
		if override.Password != "" {
			cfg.Password = override.Password
		}
		if override.Passphrase != "" {
			cfg.Passphrase = override.Passphrase
		}
		if override.KeyPath != "" {
			cfg.KeyPath = override.KeyPath
		}
		// Route explicit session material through auto authentication. This lets
		// the connector record it after a successful handshake when requested,
		// while still keeping it out of the configuration before that point.
		if override.Password != "" || override.Passphrase != "" || override.KeyPath != "" {
			cfg.AuthType = "auto"
		}
		if override.SuPwd != "" {
			cfg.SuPwd = override.SuPwd
		}
	}

	return cfg, nil
}

// UpdateAuth 处理密码或私钥密码的回写并返回本次提交后的新认证令牌
func (a *SSHAdapter) UpdateAuth(ctx context.Context, nodeID, authUpdateToken, password, keyPath, passphrase string) (string, error) {
	if a.nonInteractive {
		// 非交互模式禁止写回自动发现的秘密
		return authUpdateToken, nil
	}
	if !a.credentialRecording {
		return authUpdateToken, nil
	}
	if override, ok := a.getSessionOverride(nodeID); ok && !override.Remember {
		// 显式指定 session-only 覆盖，不写回持久化配置
		return authUpdateToken, nil
	}
	if a.credentialService == nil {
		// Backward compatibility for embedders that intentionally use the
		// legacy ConfigStore API. All xops CLI composition roots inject a
		// credential service, so they never take this plaintext path.
		provider, ok := a.cfgProvider.(interface {
			UpdateAuthAtVersionContext(context.Context, string, string, string, string, string) (string, error)
		})
		if !ok {
			return "", fmt.Errorf("configuration provider does not support versioned authentication updates")
		}
		return provider.UpdateAuthAtVersionContext(ctx, nodeID, authUpdateToken, password, keyPath, passphrase)
	}
	snapshot, err := a.cfgProvider.ResolveConnection(nodeID)
	if err != nil {
		return "", fmt.Errorf("resolve node %q for remembered authentication: %w", nodeID, err)
	}
	version := authUpdateToken
	if password != "" {
		ref, nextVersion, rotateErr := a.credentialService.Rotate(ctx,
			credential.Target{NodeID: nodeID, Kind: credential.KindLoginPassword},
			version, snapshot.Identity.LoginPasswordRef, a.defaultStoreID(), credential.Secret{Value: []byte(password)})
		if rotateErr != nil {
			return "", fmt.Errorf("persist remembered login password: %w", rotateErr)
		}
		_ = ref
		version = nextVersion
	}
	if passphrase != "" {
		// The first rotation may have advanced the auth version; resolve the
		// latest snapshot before rotating the independent passphrase ref.
		snapshot, err = a.cfgProvider.ResolveConnection(nodeID)
		if err != nil {
			return "", fmt.Errorf("refresh node %q before persisting passphrase: %w", nodeID, err)
		}
		_, nextVersion, rotateErr := a.credentialService.Rotate(ctx,
			credential.Target{NodeID: nodeID, Kind: credential.KindPassphrase, KeyPath: keyPath},
			version, snapshot.Identity.PassphraseRef, a.defaultStoreID(), credential.Secret{Value: []byte(passphrase)})
		if rotateErr != nil {
			return "", fmt.Errorf("persist remembered private-key passphrase: %w", rotateErr)
		}
		version = nextVersion
	}
	return version, nil
}

func (a *SSHAdapter) defaultStoreID() string {
	if cfg := a.cfgProvider.Snapshot(); cfg != nil && cfg.Credential != nil {
		return cfg.Credential.DefaultStore
	}
	return "system"
}

// UpdateSudo 处理提权密码和模式的回写并返回本次提交后的新提权令牌
func (a *SSHAdapter) UpdateSudo(ctx context.Context, nodeID, sudoUpdateToken string, mode ssh.SudoMode, suPwd string) (string, error) {
	if a.nonInteractive {
		// 非交互模式禁止写回自动发现的秘密
		return sudoUpdateToken, nil
	}
	if !a.credentialRecording {
		return sudoUpdateToken, nil
	}
	if override, ok := a.getSessionOverride(nodeID); ok && !override.Remember {
		// 显式指定 session-only 覆盖，不写回持久化配置
		return sudoUpdateToken, nil
	}
	if a.credentialService != nil && suPwd != "" {
		snapshot, err := a.cfgProvider.ResolveConnection(nodeID)
		if err != nil {
			return "", fmt.Errorf("resolve node %q for remembered privilege password: %w", nodeID, err)
		}
		_, version, rotateErr := a.credentialService.Rotate(ctx,
			credential.Target{NodeID: nodeID, Kind: credential.KindPrivilegePassword},
			sudoUpdateToken, snapshot.Node.PrivilegePasswordRef, a.defaultStoreID(), credential.Secret{Value: []byte(suPwd)})
		if rotateErr != nil {
			return "", fmt.Errorf("persist remembered privilege password: %w", rotateErr)
		}
		return version, nil
	}
	provider, ok := a.cfgProvider.(interface {
		UpdateSudoAtVersionContext(context.Context, string, string, models.SudoMode, string) (string, error)
	})
	if !ok {
		return "", fmt.Errorf("configuration provider does not support versioned sudo updates")
	}
	return provider.UpdateSudoAtVersionContext(ctx, nodeID, sudoUpdateToken, models.SudoMode(mode), suPwd)
}

// ResolveSecret 从当前配置模型解析认证或提权所需机密，并严格校验与连接快照的一致性
func (a *SSHAdapter) ResolveSecret(ctx context.Context, req ssh.SecretRequest) ([]byte, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if a.cfgProvider == nil {
		return nil, fmt.Errorf("configuration provider is nil")
	}
	snapshot, err := a.cfgProvider.ResolveConnection(req.NodeID)
	if err != nil {
		return nil, fmt.Errorf("resolve node %q failed: %w", req.NodeID, err)
	}

	if err := validateSecretRequestSnapshot(snapshot, req); err != nil {
		return nil, err
	}

	override, hasOverride := a.getSessionOverride(req.NodeID)

	switch req.Kind {
	case ssh.SecretKindLoginPassword:
		return a.resolveLoginPassword(ctx, snapshot, hasOverride, override)
	case ssh.SecretKindPrivateKeyPassphrase:
		return a.resolvePassphrase(ctx, snapshot, hasOverride, override)
	case ssh.SecretKindSuPassword:
		return a.resolveSuPassword(ctx, snapshot, hasOverride, override)
	default:
		return nil, fmt.Errorf("unsupported secret kind: %v", req.Kind)
	}
}

func (a *SSHAdapter) resolveLoginPassword(
	ctx context.Context,
	snapshot config.ConnectionSnapshot,
	hasOverride bool,
	override SessionAuth,
) ([]byte, error) {
	if hasOverride && override.Password != "" {
		return []byte(override.Password), nil
	}
	if ref := snapshot.Identity.LoginPasswordRef; ref != nil && !ref.IsEmpty() {
		if a.credentialResolver == nil {
			return nil, fmt.Errorf("login password ref %q/%q is configured but no credential resolver is available: %w",
				ref.StoreID, ref.ItemID, credential.ErrCredentialStoreUnavailable)
		}
		sec, err := a.credentialResolver.Resolve(ctx, *ref)
		if err != nil {
			return nil, fmt.Errorf("get login password from store: %w", err)
		}
		return sec.Value, nil
	}
	if snapshot.Identity.Password != "" {
		return []byte(snapshot.Identity.Password), nil
	}
	return nil, ssh.ErrInteractionRequired
}

func (a *SSHAdapter) resolvePassphrase(
	ctx context.Context,
	snapshot config.ConnectionSnapshot,
	hasOverride bool,
	override SessionAuth,
) ([]byte, error) {
	if hasOverride && override.Passphrase != "" {
		return []byte(override.Passphrase), nil
	}
	if ref := snapshot.Identity.PassphraseRef; ref != nil && !ref.IsEmpty() {
		if a.credentialResolver == nil {
			return nil, fmt.Errorf("passphrase ref %q/%q is configured but no credential resolver is available: %w",
				ref.StoreID, ref.ItemID, credential.ErrCredentialStoreUnavailable)
		}
		sec, err := a.credentialResolver.Resolve(ctx, *ref)
		if err != nil {
			return nil, fmt.Errorf("get passphrase from store: %w", err)
		}
		return sec.Value, nil
	}
	if snapshot.Identity.Passphrase != "" {
		return []byte(snapshot.Identity.Passphrase), nil
	}
	return nil, ssh.ErrInteractionRequired
}

func (a *SSHAdapter) resolveSuPassword(
	ctx context.Context,
	snapshot config.ConnectionSnapshot,
	hasOverride bool,
	override SessionAuth,
) ([]byte, error) {
	if hasOverride && override.SuPwd != "" {
		return []byte(override.SuPwd), nil
	}
	if ref := snapshot.Node.PrivilegePasswordRef; ref != nil && !ref.IsEmpty() {
		if a.credentialResolver == nil {
			return nil, fmt.Errorf("privilege password ref %q/%q is configured but no credential resolver is available: %w",
				ref.StoreID, ref.ItemID, credential.ErrCredentialStoreUnavailable)
		}
		sec, err := a.credentialResolver.Resolve(ctx, *ref)
		if err != nil {
			return nil, fmt.Errorf("get su password from store: %w", err)
		}
		return sec.Value, nil
	}
	if snapshot.Node.SuPwd != "" {
		return []byte(snapshot.Node.SuPwd), nil
	}
	return nil, ssh.ErrInteractionRequired
}

func validateSecretRequestSnapshot(snapshot config.ConnectionSnapshot, req ssh.SecretRequest) error {
	// 1. 版本一致性校验：若请求携带了 VersionToken，必须与当前快照的版本严格匹配
	if req.VersionToken != "" {
		var currentVersion string
		if snapshot.UpdateRef != nil {
			switch req.Kind {
			case ssh.SecretKindLoginPassword, ssh.SecretKindPrivateKeyPassphrase:
				currentVersion = string(snapshot.UpdateRef.AuthVersion[:])
			case ssh.SecretKindSuPassword:
				currentVersion = string(snapshot.UpdateRef.SudoVersion[:])
			}
		}
		if currentVersion != req.VersionToken {
			return fmt.Errorf("%w: version mismatch for node %q: expected %q, got %q",
				ssh.ErrSnapshotMismatch, req.NodeID, req.VersionToken, currentVersion)
		}
	}

	// 2. 目标主机与用户一致性校验：防止节点目标地址、端口或用户名发生变动时将新机密用于旧目标
	if req.Host != "" && snapshot.Host.Address != req.Host {
		return fmt.Errorf("%w: host address changed for node %q: expected %q, got %q",
			ssh.ErrSnapshotMismatch, req.NodeID, req.Host, snapshot.Host.Address)
	}
	if req.Port != 0 && int(snapshot.Host.Port) != req.Port {
		return fmt.Errorf("%w: host port changed for node %q: expected %d, got %d",
			ssh.ErrSnapshotMismatch, req.NodeID, req.Port, snapshot.Host.Port)
	}
	if req.User != "" && snapshot.Identity.User != req.User {
		return fmt.Errorf("%w: user changed for node %q: expected %q, got %q",
			ssh.ErrSnapshotMismatch, req.NodeID, req.User, snapshot.Identity.User)
	}
	return nil
}
