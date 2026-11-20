package ssh

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
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

type sourcedKeyBundle struct {
	certMethods []certAuthCandidateMethod
	plainMethod cryptoSSH.AuthMethod
	pubKey      cryptoSSH.PublicKey
	release     func() error
}

func (b *sourcedKeyBundle) close() error {
	if b == nil || b.release == nil {
		return nil
	}
	return b.release()
}

func filterSourcedKeyPath(paths []string, sourcedKeyPath string, env Environment, target TargetContext, resolveKeyPath func(string) string) []string {
	if sourcedKeyPath == "" || len(paths) == 0 {
		return paths
	}
	sourcedExpanded, expErr := expandIdentityKeyPath(sourcedKeyPath, env, target, resolveKeyPath)
	if expErr != nil || sourcedExpanded == "" {
		return paths
	}
	filtered := make([]string, 0, len(paths))
	for _, p := range paths {
		if filepath.Clean(filepath.FromSlash(p)) == sourcedExpanded {
			continue
		}
		filtered = append(filtered, p)
	}
	return filtered
}

func (c *Connector) sourcedKeyMethods(ctx context.Context, cfg *ClientConfig) (*sourcedKeyBundle, error) {
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
		return nil, fmt.Errorf("resolve private key signer: %w", err)
	}
	if nilCapability(lease) {
		return nil, errors.New("private key source returned no lease")
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(err, cleanup())
	}
	signer := lease.Signer()
	if nilCapability(signer) {
		return nil, errors.Join(errors.New("private key source returned no signer"), cleanup())
	}

	l := c.getLogger()
	target := c.authTargetContext(cfg)
	explicitCerts, hasExplicitCerts := collectExplicitUserCerts(cfg.Options, c.environment, target, c.environment.ResolveKeyPath, l)
	expandedKeyPath, _ := expandIdentityKeyPath(cfg.KeyPath, c.environment, target, c.environment.ResolveKeyPath)
	matched := matchCertsForKey(expandedKeyPath, signer.PublicKey(), explicitCerts, hasExplicitCerts, l)
	var certMethods []certAuthCandidateMethod
	for _, mc := range matched {
		cs, csErr := newWrappedCertSigner(mc.cert, signer)
		if csErr != nil {
			l.Debugf("Skipping SSH certificate %q for sourced key: %v", mc.path, csErr)
			continue
		}
		certMethods = append(certMethods, certAuthCandidateMethod{
			certPath: mc.path,
			certPub:  mc.cert,
			method:   cryptoSSH.PublicKeys(cs),
		})
	}
	return &sourcedKeyBundle{
		certMethods: certMethods,
		plainMethod: cryptoSSH.PublicKeys(signer),
		pubKey:      signer.PublicKey(),
		release:     cleanup,
	}, nil
}

func (c *Connector) sourcedKeyAuth(ctx context.Context, cfg *ClientConfig) (cryptoSSH.AuthMethod, func() error, error) {
	bundle, err := c.sourcedKeyMethods(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}
	return bundle.plainMethod, bundle.release, nil
}

// Adapt existing cleanup callbacks while key leases propagate close errors.
func legacyAuthCleanup(cleanup func()) func() error {
	if cleanup == nil {
		return nil
	}
	return func() error { cleanup(); return nil }
}

// Explicit referenced signers precede agent/file/password candidates. A source
// lookup failure cannot silently fall back to a different authentication source.
func (c *Connector) buildOwnedAutoAuth(ctx context.Context, cfg *ClientConfig, options AutoAuthOptions) (autoAuthPlan, func() error, error) {
	policy := newAuthPolicy(options.SSHOptions, options.HostKeyChanged)
	if !policy.pubkeyAllowed || (cfg.KeyRef == "" && c.keySource == nil) {
		plan := buildAutoAuthPlan(ctx, options)
		return plan, legacyAuthCleanup(plan.cleanup), nil
	}
	if c.keySource == nil {
		return autoAuthPlan{}, nil, errors.New("referenced SSH key requires an explicit key source")
	}
	bundle, err := c.sourcedKeyMethods(options.LifecycleCtx, cfg)
	if err != nil {
		if cfg.KeyRef == "" && cfg.KeyPath == "" && errors.Is(err, ErrKeyNotFound) {
			plan := buildAutoAuthPlan(ctx, options)
			return plan, legacyAuthCleanup(plan.cleanup), nil
		}
		return autoAuthPlan{}, nil, err
	}
	if bundle.pubKey != nil {
		options.FirstPublicKeys = append(options.FirstPublicKeys, bundle.pubKey)
	}
	for _, cm := range bundle.certMethods {
		if cm.certPub != nil {
			options.FirstPublicKeys = append(options.FirstPublicKeys, cm.certPub)
		}
		if cm.certPath != "" {
			options.FirstCertPaths = append(options.FirstCertPaths, cm.certPath)
		}
		options.FirstCertMethods = append(options.FirstCertMethods, cm.method)
	}
	options.ExcludeKeyPath = cfg.KeyPath
	options.KeyPath = ""
	plan := buildAutoAuthPlan(ctx, options, bundle.plainMethod)
	return plan, func() error {
		if plan.cleanup != nil {
			plan.cleanup()
		}
		return bundle.close()
	}, nil
}
