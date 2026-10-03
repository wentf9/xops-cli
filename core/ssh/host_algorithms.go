package ssh

import (
	"context"
	"errors"
	"fmt"
	"slices"

	cryptoSSH "golang.org/x/crypto/ssh"
)

func (c *Connector) getHostKeyOptions(ctx context.Context, coordinator *handshakeCoordinator, cfg *ClientConfig) (cryptoSSH.HostKeyCallback, []string, error) {
	callback, err := c.getHostKeyCallback(ctx, coordinator, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("get host key callback failed: %w", err)
	}
	algorithms, err := c.getHostKeyAlgorithms(ctx, coordinator, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("select host key algorithms failed: %w", err)
	}
	return callback, algorithms, nil
}

func (c *Connector) getHostKeyAlgorithms(ctx context.Context, coordinator *handshakeCoordinator, cfg *ClientConfig) ([]string, error) {
	source, ok := c.hostKeyVerifier.(HostKeyAlgorithmSource)
	if !ok {
		return nil, nil
	} // Existing verifiers retain the SSH library defaults.
	if coordinator != nil {
		ctx = coordinator.Context()
	}
	selection, cancel := context.WithTimeout(ctx, c.getHandshakeTimeout())
	defer cancel()
	if err := selection.Err(); err != nil {
		return nil, err
	}
	request := HostKeyRequest{NodeID: cfg.NodeID, Host: cfg.Address, Port: cfg.Port, User: cfg.User, VersionToken: cfg.TrustVersion}
	algorithms, err := source.HostKeyAlgorithms(selection, request)
	if err != nil {
		return nil, fmt.Errorf("resolve host key algorithms: %w", err)
	}
	if err := selection.Err(); err != nil {
		return nil, err
	}
	if len(algorithms) == 0 {
		return nil, errors.New("host key algorithm source returned no algorithms")
	}
	for _, algorithm := range algorithms {
		if !slices.Contains(cryptoSSH.SupportedAlgorithms().HostKeys, algorithm) {
			return nil, fmt.Errorf("host key algorithm source returned unsupported algorithm %q", algorithm)
		}
	}
	return slices.Clone(algorithms), nil
}
