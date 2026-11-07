package ssh

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"

	cryptoSSH "golang.org/x/crypto/ssh"
)

func (c *Connector) getHostKeyOptions(ctx context.Context, coordinator *handshakeCoordinator, cfg *ClientConfig, hostKeyChanged ...*atomic.Bool) (cryptoSSH.HostKeyCallback, []string, error) {
	callback, err := c.getHostKeyCallback(ctx, coordinator, cfg, hostKeyChanged...)
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
	var optionAlgos []string
	if cfg != nil && cfg.Options != nil && cfg.Options.HostKeyAlgorithms() != "" {
		algos, err := ResolveAlgorithmList(cfg.Options.HostKeyAlgorithms(), cryptoSSH.SupportedAlgorithms().HostKeys)
		if err != nil {
			return nil, fmt.Errorf("resolve HostKeyAlgorithms option: %w", err)
		}
		optionAlgos = algos
	}
	source, ok := c.hostKeyVerifier.(HostKeyAlgorithmSource)
	if !ok {
		return optionAlgos, nil
	} // Existing verifiers retain the SSH library defaults (or optionAlgos when specified).
	if coordinator != nil {
		ctx = coordinator.Context()
	}
	selection, cancel := context.WithTimeout(ctx, c.getNodeHandshakeTimeout(cfg))
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
	if len(optionAlgos) > 0 {
		var intersected []string
		for _, alg := range optionAlgos {
			if slices.Contains(algorithms, alg) {
				intersected = append(intersected, alg)
			}
		}
		if len(intersected) == 0 {
			return nil, errors.New("no host key algorithms in common between HostKeyAlgorithms option and pinned host key verifier")
		}
		return intersected, nil
	}
	return slices.Clone(algorithms), nil
}
