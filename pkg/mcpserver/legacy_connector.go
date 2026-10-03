package mcpserver

import (
	"context"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/ssh"
)

func newMCPConnector(ctx context.Context, provider config.ConfigProvider, l logger.DebugLogger, credentialRegistry adapter.CredentialResolver) *ssh.Connector {
	conn := newNonInteractiveMCPConnector(provider, l, credentialRegistry)
	conn.EnableKeepAlive(ctx, ssh.DefaultKeepAliveInterval, ssh.DefaultKeepAliveTimeout)
	return conn
}

func newNonInteractiveMCPConnector(provider config.ConfigProvider, l logger.DebugLogger, credentialRegistry adapter.CredentialResolver) *ssh.Connector {
	var sshOpts []ssh.Option
	if l != nil {
		sshOpts = append(sshOpts, ssh.WithLogger(l))
	} else {
		sshOpts = append(sshOpts, ssh.WithLogger(logger.NopLogger))
	}
	if cfg := provider.Snapshot(); cfg != nil && cfg.PasswordPromptPattern != "" {
		sshOpts = append(sshOpts, ssh.WithPasswordPromptPattern(cfg.PasswordPromptPattern))
	}
	adpOpts := []adapter.Option{adapter.WithNonInteractive(true)}
	if credentialRegistry != nil {
		adpOpts = append(adpOpts, adapter.WithCredentialSource(credentialRegistry))
	}
	return adapter.NewConnectorWithAdapterOptions(provider, adpOpts, sshOpts...)
}
