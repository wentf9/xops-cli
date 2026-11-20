package mcphost

import (
	"context"

	corelog "github.com/wentf9/xops-cli/core/log"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/internal/sshenv"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
)

func newMCPEnvironment() ssh.Environment {
	env := sshenv.Discover()
	// Isolate MCP host-key verification from unversioned system-global known_hosts files.
	env.GlobalKnownHostsFiles = nil
	return env
}

func newMCPConnector(ctx context.Context, provider config.ConfigProvider, l corelog.DebugLogger, credentialRegistry adapter.CredentialResolver) *ssh.Connector {
	conn := newNonInteractiveMCPConnector(provider, l, credentialRegistry)
	conn.EnableKeepAlive(ctx, ssh.DefaultKeepAliveInterval, ssh.DefaultKeepAliveTimeout)
	return conn
}

func newNonInteractiveMCPConnector(provider config.ConfigProvider, l corelog.DebugLogger, credentialRegistry adapter.CredentialResolver) *ssh.Connector {
	sshOpts := []ssh.Option{ssh.WithEnvironment(newMCPEnvironment())}
	if l != nil {
		sshOpts = append(sshOpts, ssh.WithLogger(l))
	} else {
		sshOpts = append(sshOpts, ssh.WithLogger(corelog.NopLogger))
	}
	if cfg := provider.Snapshot(); cfg != nil && cfg.PasswordPromptPattern != "" {
		sshOpts = append(sshOpts, ssh.WithPasswordPromptPattern(cfg.PasswordPromptPattern))
	}
	adpOpts := []adapter.Option{
		adapter.WithStrictIsolation(),
	}
	if credentialRegistry != nil {
		adpOpts = append(adpOpts, adapter.WithCredentialSource(credentialRegistry))
	}
	return adapter.NewConnectorWithAdapterOptions(provider, adpOpts, sshOpts...)
}
