package ssh

import (
	"context"
	"errors"
	"fmt"
	"sync"

	cryptoSSH "golang.org/x/crypto/ssh"
)

// KeyRequest binds a signer to a target and version. Reference is opaque to
// SSH and never interpreted as a local path; Path is an explicit file hint.
type KeyRequest struct {
	NodeID       string
	Host         string
	Port         int
	User         string
	Reference    string
	Path         string
	VersionToken string
}

type KeySource interface {
	OpenKey(context.Context, KeyRequest) (KeyLease, error)
}

// KeyLease is owned by the handshake and released on every success/error path.
// Implementations honor the OpenKey context and keep Close bounded.
type KeyLease interface {
	Signer() cryptoSSH.Signer
	Close() error
}

func WithKeySource(source KeySource) Option {
	if nilCapability(source) {
		source = nil
	}
	return func(c *Connector) { c.keySource = source }
}

func (c *Connector) sourcedKeyAuth(ctx context.Context, cfg *ClientConfig) (cryptoSSH.AuthMethod, func() error, error) {
	lease, err := c.keySource.OpenKey(ctx, KeyRequest{
		NodeID: cfg.NodeID, Host: cfg.Address, Port: cfg.Port, User: cfg.User,
		Reference: cfg.KeyRef, Path: cfg.KeyPath, VersionToken: cfg.AuthUpdateToken,
	})
	var cleanup func() error
	if !nilCapability(lease) {
		cleanup = sync.OnceValue(lease.Close)
	}
	if err != nil {
		if cleanup != nil {
			err = errors.Join(err, cleanup())
		}
		return nil, nil, fmt.Errorf("resolve private key signer: %w", err)
	}
	if nilCapability(lease) {
		return nil, nil, errors.New("private key source returned no lease")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, errors.Join(err, cleanup())
	}
	signer := lease.Signer()
	if nilCapability(signer) {
		return nil, nil, errors.Join(errors.New("private key source returned no signer"), cleanup())
	}
	return cryptoSSH.PublicKeys(signer), cleanup, nil
}

// Adapt existing cleanup callbacks while key leases propagate close errors.
func legacyAuthCleanup(cleanup func()) func() error {
	if cleanup == nil {
		return nil
	}
	return func() error { cleanup(); return nil }
}

func (c *Connector) keyAuth(ctx context.Context, cfg *ClientConfig, prompter SecretPrompter, discovered func()) (cryptoSSH.AuthMethod, func() error, error) {
	if c.keySource != nil {
		return c.sourcedKeyAuth(ctx, cfg)
	}
	if credentialRecoveryPrompter(c.secretPrompter) != nil {
		method, release, err := c.recoverableKeyAuth(ctx, cfg, prompter, discovered)
		return method, legacyAuthCleanup(release), err
	}
	method, err := c.resolveKeyAuth(cfg)
	return method, nil, err
}

// Explicit referenced signers precede agent/file/password candidates. A source
// lookup failure cannot silently fall back to a different authentication source.
func (c *Connector) buildOwnedAutoAuth(ctx context.Context, cfg *ClientConfig, options AutoAuthOptions) (autoAuthPlan, func() error, error) {
	if cfg.KeyRef == "" && (c.keySource == nil || cfg.KeyPath == "") {
		plan := buildAutoAuthPlan(ctx, options)
		return plan, legacyAuthCleanup(plan.cleanup), nil
	}
	if c.keySource == nil {
		return autoAuthPlan{}, nil, errors.New("referenced SSH key requires an explicit key source")
	}
	method, release, err := c.sourcedKeyAuth(options.LifecycleCtx, cfg)
	if err != nil {
		return autoAuthPlan{}, nil, err
	}
	options.KeyPath = ""
	plan := buildAutoAuthPlan(ctx, options, method)
	return plan, func() error {
		if plan.cleanup != nil {
			plan.cleanup()
		}
		return release()
	}, nil
}
