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

// VerifyConnection authenticates an inventory preview without opening a shell
// or recording credentials. New host keys follow the existing import policy;
// changed host keys are still rejected. The caller decides whether to save.
func VerifyConnection(ctx context.Context, preview *config.Provider, nodeID string, resolver CredentialResolver) (retErr error) {
	ctx, cancel := context.WithTimeout(credential.WithoutInteraction(ctx), VerificationTimeout)
	defer cancel()
	connector := NewConnectorWithAdapterOptions(preview, []Option{
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
		return fmt.Errorf("verify SSH connection %q: %w", nodeID, err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close verification client: %w", err))
		}
	}()
	return nil
}
