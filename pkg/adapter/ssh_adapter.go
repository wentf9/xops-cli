package adapter

import (
	"context"
	"fmt"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/ssh"
)

// SSHAdapter 实现 ssh.ConnectionProvider, ssh.SecretResolver, ssh.CredentialRecorder 接口，作为业务模型与底层 SSH 的防腐层
type SSHAdapter struct {
	cfgProvider config.ConfigProvider
}

var (
	_ ssh.ConnectionProvider = (*SSHAdapter)(nil)
	_ ssh.SecretResolver     = (*SSHAdapter)(nil)
	_ ssh.CredentialRecorder = (*SSHAdapter)(nil)
	_ ssh.ConfigStore        = (*SSHAdapter)(nil)
)

// NewSSHAdapter 创建 SSH 适配器
func NewSSHAdapter(cfgProvider config.ConfigProvider) *SSHAdapter {
	return &SSHAdapter{
		cfgProvider: cfgProvider,
	}
}

// NewNonInteractiveSSHAdapter 创建非交互式的 SSH 适配器
func NewNonInteractiveSSHAdapter(cfgProvider config.ConfigProvider) *SSHAdapter {
	return NewSSHAdapter(cfgProvider)
}

// NewConnector 是一个辅助方法，快速创建组装好 Adapter 的 ssh.Connector，支持传入 Option 进行显式注入配置。
func NewConnector(cfgProvider config.ConfigProvider, opts ...ssh.Option) *ssh.Connector {
	adp := NewSSHAdapter(cfgProvider)
	return newConnector(adp, opts...)
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
	return NewConnector(cfgProvider, opts...)
}

// GetConfig 获取底层 SSH 客户端需要的配置
func (a *SSHAdapter) GetConfig(nodeID string) (*ssh.ClientConfig, error) {
	snapshot, err := a.cfgProvider.ResolveConnection(nodeID)
	if err != nil {
		return nil, fmt.Errorf("resolve node %q failed: %w", nodeID, err)
	}
	var authUpdateToken, sudoUpdateToken string
	if snapshot.UpdateRef != nil {
		authUpdateToken = string(snapshot.UpdateRef.AuthVersion[:])
		sudoUpdateToken = string(snapshot.UpdateRef.SudoVersion[:])
	}

	return &ssh.ClientConfig{
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
	}, nil
}

// UpdateAuth 处理密码或私钥密码的回写并返回本次提交后的新认证令牌
func (a *SSHAdapter) UpdateAuth(ctx context.Context, nodeID, authUpdateToken, password, keyPath, passphrase string) (string, error) {
	provider, ok := a.cfgProvider.(interface {
		UpdateAuthAtVersionContext(context.Context, string, string, string, string, string) (string, error)
	})
	if !ok {
		return "", fmt.Errorf("configuration provider does not support versioned authentication updates")
	}
	return provider.UpdateAuthAtVersionContext(ctx, nodeID, authUpdateToken, password, keyPath, passphrase)
}

// UpdateSudo 处理提权密码和模式的回写并返回本次提交后的新提权令牌
func (a *SSHAdapter) UpdateSudo(ctx context.Context, nodeID, sudoUpdateToken string, mode ssh.SudoMode, suPwd string) (string, error) {
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

	switch req.Kind {
	case ssh.SecretKindLoginPassword:
		if snapshot.Identity.Password == "" {
			return nil, ssh.ErrInteractionRequired
		}
		return []byte(snapshot.Identity.Password), nil
	case ssh.SecretKindPrivateKeyPassphrase:
		if snapshot.Identity.Passphrase == "" {
			return nil, ssh.ErrInteractionRequired
		}
		return []byte(snapshot.Identity.Passphrase), nil
	case ssh.SecretKindSuPassword:
		if snapshot.Node.SuPwd == "" {
			return nil, ssh.ErrInteractionRequired
		}
		return []byte(snapshot.Node.SuPwd), nil
	default:
		return nil, fmt.Errorf("unsupported secret kind: %v", req.Kind)
	}
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
