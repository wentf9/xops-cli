package adapter

import (
	"context"
	"fmt"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/ssh"
)

// SSHAdapter 实现 ssh.ConfigStore 接口，作为业务模型与底层 SSH 的防腐层
type SSHAdapter struct {
	cfgProvider config.ConfigProvider
}

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
		PasswordPromptPattern: snapshot.Node.PasswordPromptPattern,
	}, nil
}

// UpdateAuth 处理密码或私钥密码的回写
func (a *SSHAdapter) UpdateAuth(ctx context.Context, nodeID, authUpdateToken, password, keyPath, passphrase string) error {
	provider, ok := a.cfgProvider.(interface {
		UpdateAuthAtVersionContext(context.Context, string, string, string, string, string) error
	})
	if !ok {
		return fmt.Errorf("configuration provider does not support versioned authentication updates")
	}
	return provider.UpdateAuthAtVersionContext(ctx, nodeID, authUpdateToken, password, keyPath, passphrase)
}

// UpdateSudo 处理提权密码和模式的回写
func (a *SSHAdapter) UpdateSudo(ctx context.Context, nodeID, sudoUpdateToken string, mode ssh.SudoMode, suPwd string) error {
	provider, ok := a.cfgProvider.(interface {
		UpdateSudoAtVersionContext(context.Context, string, string, models.SudoMode, string) error
	})
	if !ok {
		return fmt.Errorf("configuration provider does not support versioned sudo updates")
	}
	return provider.UpdateSudoAtVersionContext(ctx, nodeID, sudoUpdateToken, models.SudoMode(mode), suPwd)
}
