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
		WithNonInteractive(true), WithCredentialRecording(false), WithCredentialSource(resolver),
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
