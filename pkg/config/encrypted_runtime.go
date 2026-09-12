package config

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/internal/credentialfile"
	"github.com/wentf9/xops-cli/internal/credentialfile/format"
	"github.com/wentf9/xops-cli/pkg/credential"
)

// EncryptedRuntime is an explicitly owned composition-root resource. Close must
// be awaited before exit or configuration replacement. Registries borrow it.
type EncryptedRuntime struct {
	vaults     *credentialfile.Runtime
	configPath string
	mu         sync.Mutex
	stores     map[encryptedBackendKey]*encryptedBackend
}

// A comparable key preserves the exact bytes of Linux paths and StoreIDs.
// JSON encoding would collapse distinct invalid UTF-8 strings to U+FFFD.
type encryptedBackendKey struct {
	id, path, unlock, keyFile                                string
	timeout, idleTTL, cacheTTL, promptTimeout, unlockTimeout time.Duration
	readOnly, nonInteractive                                 bool
}

// NewEncryptedRuntime binds path resolution and terminal interaction for one owner.
func NewEncryptedRuntime(ctx context.Context, configPath string, prompt credentialfile.PromptProvider) *EncryptedRuntime {
	return &EncryptedRuntime{vaults: credentialfile.NewRuntime(ctx, prompt, nil), configPath: configPath, stores: make(map[encryptedBackendKey]*encryptedBackend)}
}

// Close cancels and reaps all sessions, stores and KDF children.
func (r *EncryptedRuntime) Close() error { return r.vaults.Close() }

// Vaults exposes maintenance operations on the same process-owned runtime.
func (r *EncryptedRuntime) Vaults() *credentialfile.Runtime { return r.vaults }

// Registry builds lazy sources. File stores use only Runtime's revision-aware
// cache, never the generic credential cache decorator.
func (r *EncryptedRuntime) Registry(cfg *CredentialConfig) (*credential.Registry, error) {
	if cfg == nil {
		return BuildRegistryFromConfig(cfg)
	}
	return buildRegistry(cfg, r)
}

func (r *EncryptedRuntime) backend(id string, cfg StoreConfig) (*encryptedBackend, error) {
	cfg, err := ResolveFileStore(cfg, r.configPath)
	if err != nil {
		return nil, err
	}
	key := encryptedBackendKey{
		id: id, path: cfg.Path, unlock: cfg.Unlock, keyFile: cfg.KeyFile,
		timeout: cfg.Timeout, idleTTL: cfg.UnlockIdleTTL, cacheTTL: cfg.CacheTTL,
		promptTimeout: cfg.PromptTimeout, unlockTimeout: cfg.UnlockTimeout,
		readOnly: cfg.ReadOnly, nonInteractive: cfg.NonInteractive,
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.stores[key]
	if b == nil {
		b = &encryptedBackend{owner: r, id: id, cfg: cfg, gate: make(chan struct{}, 1)}
		r.stores[key] = b
	}
	return b, nil
}

// Store opens a configured file store without unlocking it. Failed opens retry.
func (r *EncryptedRuntime) Store(ctx context.Context, id string, cfg StoreConfig) (*credentialfile.Store, error) {
	b, err := r.backend(id, cfg)
	if err != nil {
		return nil, err
	}
	return b.open(ctx)
}

type encryptedBackend struct {
	owner *EncryptedRuntime
	id    string
	cfg   StoreConfig
	gate  chan struct{}
	store *credentialfile.Store
}

func (b *encryptedBackend) open(ctx context.Context) (*credentialfile.Store, error) {
	select {
	case b.gate <- struct{}{}:
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
	defer func() { <-b.gate }()
	if b.store != nil {
		return b.store, nil
	}
	s, err := b.owner.vaults.OpenStore(ctx, b.cfg.Path, b.id, credentialfile.Options{ReadOnly: b.cfg.ReadOnly, Timeout: b.cfg.Timeout}, credentialfile.SessionOptions{
		Mode: b.cfg.Unlock, KeyFile: b.cfg.KeyFile, IdleTTL: b.cfg.UnlockIdleTTL, CacheTTL: b.cfg.CacheTTL, PromptTimeout: b.cfg.PromptTimeout, UnlockTimeout: b.cfg.UnlockTimeout, NonInteractive: b.cfg.NonInteractive,
	})
	if err != nil {
		return nil, err
	}
	b.store = s
	return s, nil
}
func (b *encryptedBackend) Get(ctx context.Context, ref credential.Ref) (credential.Secret, error) {
	s, err := b.open(ctx)
	if err != nil {
		return credential.Secret{}, err
	}
	secret, err := s.Get(ctx, ref)
	// Expose offline data failures through the backend-neutral read contract.
	// Keep the cause for diagnostics; callers may allow temporary interactive
	// input, but must not treat corruption as a missing credential or initialize
	// a replacement vault. Writes retain their original fail-closed behavior.
	if errors.Is(err, format.ErrCorrupt) {
		err = errors.Join(credential.ErrCredentialStoreUnavailable, err)
	}
	return secret, err
}
func (b *encryptedBackend) prepareWrite(ctx context.Context) error {
	// EnsureInitialized takes the native vault lock and checks CURRENT/transactions before
	// preparing a key. Existing stores must never generate replacement keys.
	// Reads, probes, and read-only stores do not enter this initialization path.
	if b.cfg.Unlock == "key-file" && !b.cfg.ReadOnly {
		_, err := b.owner.vaults.EnsureInitialized(ctx, b.cfg.Path, b.id, credentialfile.Wrapping{Mode: "key-file", KeyFile: b.cfg.KeyFile})
		if err != nil {
			return err
		}
	}
	return nil
}

func (b *encryptedBackend) Put(ctx context.Context, ref credential.Ref, secret credential.Secret) error {
	if err := b.prepareWrite(ctx); err != nil {
		return err
	}
	s, err := b.open(ctx)
	if err != nil {
		return err
	}
	return s.Put(ctx, ref, secret)
}
func (b *encryptedBackend) Delete(ctx context.Context, ref credential.Ref) error {
	s, err := b.open(ctx)
	if err != nil {
		return err
	}
	return s.Delete(ctx, ref)
}

// Lock revokes all sessions already opened by this owner. Unopened stores have no keys.
func (r *EncryptedRuntime) Lock(ctx context.Context) error {
	r.mu.Lock()
	backends := make([]*encryptedBackend, 0, len(r.stores))
	for _, b := range r.stores {
		backends = append(backends, b)
	}
	r.mu.Unlock()
	var err error
	for _, b := range backends {
		select {
		case b.gate <- struct{}{}:
		case <-ctx.Done():
			return errors.Join(err, context.Cause(ctx))
		}
		s := b.store
		<-b.gate
		if s != nil {
			err = errors.Join(err, s.Lock(ctx))
		}
	}
	return err
}
