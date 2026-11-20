package adapter

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
)

// VerificationTimeout bounds the entire inventory connection check.
const VerificationTimeout = 15 * time.Second

// ConnectionVerification separates authentication failures from optional,
// non-fatal execution probing. No inventory or credential data is persisted.
type ConnectionVerification struct {
	Probe    *ssh.ProbeResult
	ProbeErr error
}

// probeConnectionProvider masks command execution settings only in connection
// snapshots. The embedded provider retains authentication, trust, ProxyJump,
// OpenSSH fallback and inventory data. In particular, provisional node flags
// must not inherit an incompatible global dialect before probing can fill it.
type probeConnectionProvider struct {
	config.ConfigProvider
}

func (p probeConnectionProvider) ResolveConnection(nodeID string) (config.ConnectionSnapshot, error) {
	snapshot, err := p.ConfigProvider.ResolveConnection(nodeID)
	if err != nil {
		return config.ConnectionSnapshot{}, err
	}
	snapshot.Node.Execution = &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchUnknown}
	return snapshot, nil
}

func (p probeConnectionProvider) ResolveConnectionWithOrigin(nodeID, originalHost string) (config.ConnectionSnapshot, error) {
	var (
		snapshot config.ConnectionSnapshot
		err      error
	)
	if origProvider, ok := p.ConfigProvider.(interface {
		ResolveConnectionWithOrigin(string, string) (config.ConnectionSnapshot, error)
	}); ok {
		snapshot, err = origProvider.ResolveConnectionWithOrigin(nodeID, originalHost)
	} else {
		snapshot, err = p.ConfigProvider.ResolveConnection(nodeID)
	}
	if err != nil {
		return config.ConnectionSnapshot{}, err
	}
	snapshot.Node.Execution = &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchUnknown}
	return snapshot, nil
}

func (p probeConnectionProvider) GetOpenSSHParser() *config.OpenSSHParser {
	if src, ok := p.ConfigProvider.(interface{ GetOpenSSHParser() *config.OpenSSHParser }); ok {
		return src.GetOpenSSHParser()
	}
	return nil
}

func (p probeConnectionProvider) NodeOpenSSHOrigin(nodeID string) config.OpenSSHOrigin {
	if store, ok := p.ConfigProvider.(interface {
		NodeOpenSSHOrigin(string) config.OpenSSHOrigin
	}); ok {
		return store.NodeOpenSSHOrigin(nodeID)
	}
	return config.OpenSSHOrigin{
		Alias:         p.NodeOpenSSHAlias(nodeID),
		CanonicalHost: p.NodeCanonicalHost(nodeID),
	}
}

func (p probeConnectionProvider) NodeOpenSSHAlias(nodeID string) string {
	if store, ok := p.ConfigProvider.(interface{ NodeOpenSSHAlias(string) string }); ok {
		return store.NodeOpenSSHAlias(nodeID)
	}
	return ""
}

func (p probeConnectionProvider) NodeCanonicalHost(nodeID string) string {
	if store, ok := p.ConfigProvider.(interface{ NodeCanonicalHost(string) string }); ok {
		return store.NodeCanonicalHost(nodeID)
	}
	return ""
}

// VerifyConnection authenticates an inventory preview without opening a shell
// or recording credentials. New host keys follow the existing import policy;
// changed host keys are still rejected. The caller decides whether to save.
func VerifyConnection(ctx context.Context, preview *config.Provider, nodeID string, resolver CredentialResolver) error {
	_, err := verifyConnection(ctx, preview, nodeID, resolver, false)
	return err
}

// VerifyConnectionWithProbe reuses the authenticated verification connection for
// one bounded execution probe. ProbeErr never turns successful authentication
// into a verification failure; transport cleanup failures remain fatal. The
// connection uses server/unknown independently of node/global command settings.
func VerifyConnectionWithProbe(ctx context.Context, preview *config.Provider, nodeID string, resolver CredentialResolver) (ConnectionVerification, error) {
	return verifyConnection(ctx, preview, nodeID, resolver, true)
}

func verifyConnection(ctx context.Context, preview *config.Provider, nodeID string, resolver CredentialResolver, probe bool) (result ConnectionVerification, retErr error) {
	ctx, cancel := context.WithTimeout(credential.WithoutInteraction(ctx), VerificationTimeout)
	defer cancel()
	var connectionProvider config.ConfigProvider = preview
	if probe && preview != nil {
		connectionProvider = probeConnectionProvider{ConfigProvider: preview.Frozen()}
	}
	connector := NewConnectorWithAdapterOptions(connectionProvider, []Option{
		WithStrictIsolation(), WithCredentialRecording(false), WithCredentialSource(resolver),
	}, ssh.WithHandshakeTimeout(VerificationTimeout))
	connector.AcceptNewHostKey.Store(true)
	defer func() {
		if err := connector.CloseAll(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close verification connector: %w", err))
		}
	}()
	client, err := connector.Connect(ctx, nodeID)
	if err != nil {
		return result, fmt.Errorf("verify SSH connection %q: %w", nodeID, err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close verification client: %w", err))
		}
	}()
	if probe {
		result.Probe, result.ProbeErr = client.ProbeExecutionConfig(ctx)
	}
	return result, nil
}
