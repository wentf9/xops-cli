package config

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	coreauth "github.com/wentf9/xops-cli/core/auth"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
	"gopkg.in/yaml.v3"
)

var ErrConfigConflict = errors.New("configuration revision conflict")

const anyRevision = ^uint64(0)

// DurabilityError reports a write which has replaced the configuration file
// but whose parent-directory sync failed. The mutation is visible now and
// must not be retried blindly.
type DurabilityError struct {
	Err error
}

func (e *DurabilityError) Error() string {
	return fmt.Sprintf("configuration update applied but durability is uncertain: %v", e.Err)
}

func (e *DurabilityError) Unwrap() error {
	return e.Err
}

// ConfigView is one immutable configuration revision. Configuration is a
// defensive copy and may safely be retained or changed by its caller.
type ConfigView struct {
	Revision      uint64
	Configuration *Configuration
	NodeRefs      map[string]NodeRef
	IdentityRefs  map[string]IdentityRef
}

// NodeRef identifies a displayed node bundle and the exact node, host, and
// identity values it contained. It is suitable for optimistic concurrency
// across independently running CLI processes.
type NodeRef struct {
	ID      string
	Version Version
}

// IdentityRef identifies the exact identity record displayed to a caller.
// It is intentionally distinct from NodeRef so a stale identity cannot be
// accidentally used as a node precondition.
type IdentityRef struct {
	ID      string
	Version Version
}

// MutationOutcome reports whether a durable configuration mutation reached
// the destination pathname and whether it is crash durable. Applied mutations
// remain authoritative even when the accompanying error is a DurabilityError.
type MutationOutcome struct {
	Applied bool
	Durable bool
}

// NodeMutation is returned by node creation even when persistence reports a
// durability failure. Ref must be used for later conditional cleanup.
type NodeMutation struct {
	Ref         NodeRef
	AuthVersion string
	Outcome     MutationOutcome
}

// ImportIssue records one OpenSSH host that could not be imported without
// making the whole batch invalid.
type ImportIssue struct {
	Name string
	Err  error
}

// ImportResult separates expected per-host skips from fatal persistence
// failures. A non-nil error from ImportOpenSSHHosts means no batch state was
// published unless it is a DurabilityError.
type ImportResult struct {
	Imported int
	Skipped  int
	Issues   []ImportIssue
}

// Repository is the sole durable mutation boundary for one process. It owns
// configuration state and serializes the complete clone-validate-persist-
// publish sequence. It intentionally does not expose its Store.
type Repository struct {
	pendingMu         sync.RWMutex
	pending           map[string]*pendingConnection
	commitMu          sync.Mutex
	provider          *Provider
	store             Store
	revision          atomic.Uint64
	hasUndurableWrite atomic.Bool
}

var _ ConfigProvider = (*Repository)(nil)

// outcomeStore is retained only for in-memory legacy test doubles while
// callers migrate to TransactionStore. Production FileStore implementations
// use TransactionStore and never reach this branch.
type outcomeStore interface {
	save(*Configuration) (PersistResult, error)
}

// NewRepository creates a durable repository with an optional local OpenSSH
// fallback. OpenSSH parse failures are retained inside OpenSSHParser and
// reported if a caller falls back to OpenSSH; local xops configuration stays usable.
func NewRepository(cfg *Configuration, store Store) (*Repository, error) {
	parser, err := NewOpenSSHParser()
	if err != nil {
		return newRepository(cfg, store, NewBrokenOpenSSHParser(fmt.Errorf("load openssh config: %w", err)))
	}
	return newRepository(cfg, store, parser)
}

// NewRepositoryWithoutOpenSSH creates a durable repository without an
// OpenSSH fallback.
func NewRepositoryWithoutOpenSSH(cfg *Configuration, store Store) (*Repository, error) {
	return newRepository(cfg, store, &OpenSSHParser{cfg: nil})
}

// NewRepositoryWithOpenSSHParser creates a durable repository with parser as
// its OpenSSH fallback. A nil parser disables the fallback.
func NewRepositoryWithOpenSSHParser(cfg *Configuration, store Store, parser *OpenSSHParser) (*Repository, error) {
	if parser == nil {
		parser = &OpenSSHParser{cfg: nil}
	}
	return newRepository(cfg, store, parser)
}

func newRepository(cfg *Configuration, store Store, parser *OpenSSHParser) (*Repository, error) {
	if store == nil {
		return nil, fmt.Errorf("configuration store is nil")
	}
	cloned, origins := cloneConfigurationExtractingMetadata(cfg)
	lookup, aliases, err := buildIndexes(cloned, true)
	if err != nil {
		return nil, wrapConfigDoctorHint(fmt.Errorf("%w: validate configuration indexes: %w", ErrSchemaValidation, err))
	}
	if err := validateRepositoryConfiguration(cloned); err != nil {
		return nil, wrapConfigDoctorHint(err)
	}
	if err := validateProxyJumpGraph(cloned, lookup, aliases); err != nil {
		return nil, wrapConfigDoctorHint(err)
	}
	return &Repository{
		provider: &Provider{
			cfg:            cloned,
			lookupIndex:    lookup,
			aliasIndex:     aliases,
			openSSH:        parser,
			openSSHOrigins: origins,
		},
		store: store,
	}, nil
}

// View returns a self-consistent, mutable copy of the current state and its
// revision for optimistic concurrency at UI boundaries.
func (r *Repository) View() ConfigView {
	if r == nil {
		return ConfigView{Configuration: cloneConfiguration(nil)}
	}
	r.commitMu.Lock()
	defer r.commitMu.Unlock()
	configuration := r.provider.Snapshot()
	return ConfigView{
		Revision:      r.revision.Load(),
		Configuration: configuration,
		NodeRefs:      nodeRefs(configuration),
		IdentityRefs:  identityRefs(configuration),
	}
}

func (r *Repository) lockCommit(ctx context.Context) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("wait for in-process configuration transaction: %w", err)
		}
	}
	if r.commitMu.TryLock() {
		return nil
	}
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if r.commitMu.TryLock() {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for in-process configuration transaction: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func nodeRefs(cfg *Configuration) map[string]NodeRef {
	refs := make(map[string]NodeRef)
	if cfg == nil || cfg.Nodes == nil {
		return refs
	}
	for _, nodeID := range cfg.Nodes.Keys() {
		version, err := nodeEntityVersion(cfg, nodeID)
		if err == nil {
			refs[nodeID] = NodeRef{ID: nodeID, Version: version}
		}
	}
	return refs
}

func identityRefs(cfg *Configuration) map[string]IdentityRef {
	refs := make(map[string]IdentityRef)
	if cfg == nil || cfg.Identities == nil {
		return refs
	}
	for _, identityID := range cfg.Identities.Keys() {
		version, err := identityEntityVersion(cfg, identityID)
		if err == nil {
			refs[identityID] = IdentityRef{ID: identityID, Version: version}
		}
	}
	return refs
}

func identityEntityVersion(cfg *Configuration, identityID string) (Version, error) {
	if cfg == nil || cfg.Identities == nil {
		return Version{}, fmt.Errorf("resolve identity %q: %w", identityID, ErrIdentityNotFound)
	}
	identity, ok := cfg.Identities.Get(identityID)
	if !ok {
		return Version{}, fmt.Errorf("resolve identity %q: %w", identityID, ErrIdentityNotFound)
	}
	data, err := yaml.Marshal(identity)
	if err != nil {
		return Version{}, fmt.Errorf("serialize identity %q version: %w", identityID, err)
	}
	return sha256.Sum256(data), nil
}

func ensureIdentityRef(cfg *Configuration, ref IdentityRef) error {
	if ref.ID == "" {
		return fmt.Errorf("identity reference ID is empty")
	}
	current, err := identityEntityVersion(cfg, ref.ID)
	if err != nil || current != ref.Version {
		return fmt.Errorf("identity %q changed or was removed since it was selected: %w", ref.ID, ErrConfigConflict)
	}
	return nil
}

func nodeAuthVersion(cfg *Configuration, nodeID string) (Version, error) {
	if cfg == nil || cfg.Nodes == nil || cfg.Identities == nil {
		return Version{}, fmt.Errorf("resolve node %q authentication version: %w", nodeID, ErrNodeNotFound)
	}
	node, ok := cfg.Nodes.Get(nodeID)
	if !ok {
		return Version{}, fmt.Errorf("resolve node %q authentication version: %w", nodeID, ErrNodeNotFound)
	}
	identity, ok := cfg.Identities.Get(node.IdentityRef)
	if !ok {
		return Version{}, fmt.Errorf("resolve identity %q authentication version: %w", node.IdentityRef, ErrIdentityNotFound)
	}
	data, err := yaml.Marshal(struct {
		IdentityRef         string                            `yaml:"identity_ref"`
		AuthType            string                            `yaml:"auth_type"`
		Password            string                            `yaml:"password"`
		KeyPath             string                            `yaml:"key_path"`
		Passphrase          string                            `yaml:"passphrase"`
		KeyFingerprint      string                            `yaml:"key_fingerprint,omitempty"`
		LoginPasswordRef    *credential.Ref                   `yaml:"login_password_ref,omitempty"`
		PassphraseRef       *credential.Ref                   `yaml:"passphrase_ref,omitempty"`
		OTP                 *models.OTPConfig                 `yaml:"otp,omitempty"`
		KeyboardInteractive *models.KeyboardInteractiveConfig `yaml:"keyboard_interactive,omitempty"`
	}{
		IdentityRef:         node.IdentityRef,
		AuthType:            identity.AuthType,
		Password:            identity.Password,
		KeyPath:             identity.KeyPath,
		Passphrase:          identity.Passphrase,
		KeyFingerprint:      identity.KeyFingerprint,
		LoginPasswordRef:    identity.LoginPasswordRef,
		PassphraseRef:       identity.PassphraseRef,
		OTP:                 identity.OTP,
		KeyboardInteractive: identity.KeyboardInteractive,
	})
	if err != nil {
		return Version{}, fmt.Errorf("serialize node %q authentication version: %w", nodeID, err)
	}
	return sha256.Sum256(data), nil
}

func nodeSudoVersion(cfg *Configuration, nodeID string) (Version, error) {
	if cfg == nil || cfg.Nodes == nil {
		return Version{}, fmt.Errorf("resolve node %q sudo version: %w", nodeID, ErrNodeNotFound)
	}
	node, ok := cfg.Nodes.Get(nodeID)
	if !ok {
		return Version{}, fmt.Errorf("resolve node %q sudo version: %w", nodeID, ErrNodeNotFound)
	}
	data, err := yaml.Marshal(struct {
		Mode                 models.SudoMode `yaml:"mode"`
		SuPwd                string          `yaml:"su_pwd"`
		PrivilegePasswordRef *credential.Ref `yaml:"privilege_password_ref,omitempty"`
	}{
		Mode:                 node.SudoMode,
		SuPwd:                node.SuPwd,
		PrivilegePasswordRef: node.PrivilegePasswordRef,
	})
	if err != nil {
		return Version{}, fmt.Errorf("serialize node %q sudo version: %w", nodeID, err)
	}
	return sha256.Sum256(data), nil
}

// ResolveConnection returns one atomic connection snapshot. Saved and prepared
// nodes receive field versions from the same copy as their values. Prepared
// versions become writable after confirmation; OpenSSH virtual nodes remain
// read-only and therefore have no UpdateRef.
func (r *Repository) ResolveConnection(nodeID string) (ConnectionSnapshot, error) {
	if r == nil {
		return ConnectionSnapshot{}, fmt.Errorf("configuration repository is nil")
	}

	provider, pendingProv := r.connectionProviderWithProvenance(nodeID)
	return resolveConnectionFromProvider(provider, pendingProv, nodeID)
}

func resolveConnectionFromProvider(provider *Provider, pendingProv NodeProvenance, nodeID string) (ConnectionSnapshot, error) {
	configuration, origin := provider.snapshotWithNodeOrigin(nodeID)
	if node, exists := configuration.Nodes.Get(nodeID); exists {
		host, hostExists := configuration.Hosts.Get(node.HostRef)
		if !hostExists {
			return ConnectionSnapshot{}, fmt.Errorf("host ref %q for node %q: %w", node.HostRef, nodeID, ErrHostNotFound)
		}
		identity, identityExists := configuration.Identities.Get(node.IdentityRef)
		if !identityExists {
			return ConnectionSnapshot{}, fmt.Errorf("identity ref %q for node %q: %w", node.IdentityRef, nodeID, ErrIdentityNotFound)
		}
		authVersion, err := nodeAuthVersion(configuration, nodeID)
		if err != nil {
			return ConnectionSnapshot{}, fmt.Errorf("resolve authentication version for node %q: %w", nodeID, err)
		}
		sudoVersion, err := nodeSudoVersion(configuration, nodeID)
		if err != nil {
			return ConnectionSnapshot{}, fmt.Errorf("resolve sudo version for node %q: %w", nodeID, err)
		}
		clonedNode := cloneNode(node)
		if clonedNode.OpenSSHAlias == "" && clonedNode.CanonicalHost == "" {
			clonedNode.OpenSSHAlias = origin.Alias
			clonedNode.CanonicalHost = origin.CanonicalHost
		}
		var updateRef *ConnectionUpdateRef
		if !IsOpenSSHNodeID(nodeID) {
			updateRef = &ConnectionUpdateRef{
				AuthVersion: authVersion,
				SudoVersion: sudoVersion,
			}
		}
		prov := pendingProv
		if prov == ProvenanceUnknown {
			prov = ProvenanceSavedManaged
		}
		return ConnectionSnapshot{
			Node:       clonedNode,
			Host:       cloneHost(host),
			Identity:   cloneIdentity(identity),
			UpdateRef:  updateRef,
			Provenance: prov,
		}, nil
	}

	return provider.ResolveConnection(nodeID)
}

// ResolveConnectionWithOrigin resolves nodeID using an explicit originalHost for
// OpenSSH virtual targets without consulting or mutating shared alias side maps.
func (r *Repository) ResolveConnectionWithOrigin(nodeID, originalHost string) (ConnectionSnapshot, error) {
	if r == nil {
		return ConnectionSnapshot{}, fmt.Errorf("configuration repository is nil")
	}
	if !IsOpenSSHNodeID(nodeID) {
		return r.ResolveConnection(nodeID)
	}
	_, prov := r.connectionProviderWithProvenance(nodeID)
	if prov != ProvenanceUnknown && prov != ProvenanceOpenSSHVirtual {
		return r.ResolveConnection(nodeID)
	}
	if r.provider == nil {
		return ConnectionSnapshot{}, fmt.Errorf("configuration provider is nil")
	}
	return r.provider.ResolveConnectionWithOrigin(nodeID, originalHost)
}

func (r *Repository) snapshotWithOrigins() (*Configuration, map[string]OpenSSHOrigin) {
	if r == nil || r.provider == nil {
		return cloneConfiguration(nil), nil
	}
	return r.provider.snapshotWithOrigins()
}

// NodeOpenSSHOrigin returns the atomic session-recorded OpenSSH origin pair for nodeID.
func (r *Repository) NodeOpenSSHOrigin(nodeID string) OpenSSHOrigin {
	if r == nil {
		return OpenSSHOrigin{}
	}
	provider, _ := r.connectionProviderWithProvenance(nodeID)
	if provider == nil {
		return OpenSSHOrigin{}
	}
	return provider.NodeOpenSSHOrigin(nodeID)
}

// SetNodeOpenSSHOrigin atomically replaces the session-recorded OpenSSH origin
// for nodeID without modifying persisted state. When nodeID is an active pending
// node, the update is isolated to pending.provider so unsaved metadata never
// leaks into r.provider.openSSHOrigins.
func (r *Repository) SetNodeOpenSSHOrigin(nodeID string, origin OpenSSHOrigin) {
	if r == nil || r.provider == nil {
		return
	}
	r.pendingMu.RLock()
	defer r.pendingMu.RUnlock()
	if pending := r.pending[nodeID]; pending != nil && pending.provider != nil {
		pending.provider.SetNodeOpenSSHOrigin(nodeID, origin)
		return
	}
	r.provider.SetNodeOpenSSHOrigin(nodeID, origin)
}

// ClearNodeOpenSSHOrigin removes the session-recorded OpenSSH origin for nodeID.
func (r *Repository) ClearNodeOpenSSHOrigin(nodeID string) {
	if r == nil || r.provider == nil {
		return
	}
	r.pendingMu.RLock()
	if pending := r.pending[nodeID]; pending != nil && pending.provider != nil {
		pending.provider.ClearNodeOpenSSHOrigin(nodeID)
	}
	r.provider.ClearNodeOpenSSHOrigin(nodeID)
	r.pendingMu.RUnlock()
}

// SetNodeOpenSSHAlias records the concrete OpenSSH Host alias from which nodeID
// was derived during the current session without modifying persisted state.
// When nodeID is an active pending node, the update is isolated to pending.provider.
func (r *Repository) SetNodeOpenSSHAlias(nodeID, alias string) {
	if r == nil || r.provider == nil {
		return
	}
	r.pendingMu.RLock()
	defer r.pendingMu.RUnlock()
	if pending := r.pending[nodeID]; pending != nil && pending.provider != nil {
		pending.provider.SetNodeOpenSSHAlias(nodeID, alias)
		return
	}
	r.provider.SetNodeOpenSSHAlias(nodeID, alias)
}

// NodeOpenSSHAlias returns the session-recorded OpenSSH Host alias for nodeID.
func (r *Repository) NodeOpenSSHAlias(nodeID string) string {
	return r.NodeOpenSSHOrigin(nodeID).Alias
}

// SetNodeCanonicalHost records the canonicalized host for nodeID without modifying
// persisted state. When nodeID is an active pending node, the update is isolated
// to pending.provider.
func (r *Repository) SetNodeCanonicalHost(nodeID, canonicalHost string) {
	if r == nil || r.provider == nil {
		return
	}
	r.pendingMu.RLock()
	defer r.pendingMu.RUnlock()
	if pending := r.pending[nodeID]; pending != nil && pending.provider != nil {
		pending.provider.SetNodeCanonicalHost(nodeID, canonicalHost)
		return
	}
	r.provider.SetNodeCanonicalHost(nodeID, canonicalHost)
}

// NodeCanonicalHost returns the session-recorded canonicalized host for nodeID.
func (r *Repository) NodeCanonicalHost(nodeID string) string {
	return r.NodeOpenSSHOrigin(nodeID).CanonicalHost
}

func versionFromString(value string) (Version, error) {
	var version Version
	if len(value) != len(version) {
		return Version{}, fmt.Errorf("configuration field version has invalid length %d", len(value))
	}
	copy(version[:], value)
	return version, nil
}

func nodeEntityVersion(cfg *Configuration, nodeID string) (Version, error) {
	if cfg == nil || cfg.Nodes == nil {
		return Version{}, fmt.Errorf("resolve node %q: %w", nodeID, ErrNodeNotFound)
	}
	node, ok := cfg.Nodes.Get(nodeID)
	if !ok {
		return Version{}, fmt.Errorf("resolve node %q: %w", nodeID, ErrNodeNotFound)
	}
	var host *models.Host
	if value, exists := cfg.Hosts.Get(node.HostRef); exists {
		cloned := cloneHost(value)
		host = &cloned
	}
	var identity *models.Identity
	if value, exists := cfg.Identities.Get(node.IdentityRef); exists {
		identity = &value
	}
	data, err := yaml.Marshal(struct {
		Node     models.Node      `yaml:"node"`
		Host     *models.Host     `yaml:"host"`
		Identity *models.Identity `yaml:"identity"`
	}{Node: node, Host: host, Identity: identity})
	if err != nil {
		return Version{}, fmt.Errorf("serialize node %q version: %w", nodeID, err)
	}
	return sha256.Sum256(data), nil
}

func ensureNodeRefs(cfg *Configuration, refs []NodeRef) error {
	seen := make(map[string]Version, len(refs))
	for _, ref := range refs {
		if ref.ID == "" {
			return fmt.Errorf("node reference ID is empty")
		}
		if existing, duplicate := seen[ref.ID]; duplicate {
			if existing != ref.Version {
				return fmt.Errorf("node reference %q has inconsistent versions: %w", ref.ID, ErrConfigConflict)
			}
			continue
		}
		current, err := nodeEntityVersion(cfg, ref.ID)
		if err != nil || current != ref.Version {
			return fmt.Errorf("node %q changed or was removed since it was selected: %w", ref.ID, ErrConfigConflict)
		}
		seen[ref.ID] = ref.Version
	}
	return nil
}

func (r *Repository) Revision() uint64 {
	if r == nil {
		return 0
	}
	return r.revision.Load()
}

func (r *Repository) commitContext(ctx context.Context, expectedRevision uint64, fn func(*Configuration) error) error {
	_, err := r.commitResultContext(ctx, expectedRevision, fn)
	return err
}

type publishAction struct {
	beforeProviderLocked func()
	applyProviderLocked  func(p *Provider, updated *Configuration)
	afterProviderLocked  func()
}

func (r *Repository) commitResultContext(ctx context.Context, expectedRevision uint64, fn func(*Configuration) error) (CommitResult, error) {
	return r.commitResultWithPublishAction(ctx, expectedRevision, fn, nil)
}

func (r *Repository) commitResultWithPublishAction(
	ctx context.Context,
	expectedRevision uint64,
	fn func(*Configuration) error,
	action *publishAction,
) (CommitResult, error) {
	if r == nil {
		return CommitResult{}, fmt.Errorf("configuration repository is nil")
	}
	if ctx == nil {
		return CommitResult{}, fmt.Errorf("configuration mutation context is nil")
	}
	if err := ctx.Err(); err != nil {
		return CommitResult{}, fmt.Errorf("configuration mutation canceled: %w", err)
	}
	if fn == nil {
		return CommitResult{}, fmt.Errorf("configuration mutation is nil")
	}

	if err := r.lockCommit(ctx); err != nil {
		return CommitResult{}, err
	}
	defer r.commitMu.Unlock()

	if expectedRevision != anyRevision && expectedRevision != r.revision.Load() {
		return CommitResult{}, fmt.Errorf("expected revision %d, current revision %d: %w", expectedRevision, r.revision.Load(), ErrConfigConflict)
	}

	if store, ok := r.store.(TransactionStore); ok {
		return r.commitTransactionResultWithPublishAction(ctx, store, fn, action)
	}

	updated, lookup, aliases, err := prepareConfiguration(r.provider.Snapshot(), fn)
	if err != nil {
		return CommitResult{}, err
	}

	result, err := r.persist(updated)
	if err != nil && !result.Applied {
		return CommitResult{}, err
	}
	if !result.Applied {
		return CommitResult{}, fmt.Errorf("configuration store reported success without applying the update")
	}

	r.publishWithAction(updated, lookup, aliases, action)
	commitResult := CommitResult{
		Snapshot: Snapshot{Configuration: cloneConfiguration(updated)},
		Applied:  true,
		Durable:  result.Durable,
	}

	if err != nil {
		r.hasUndurableWrite.Store(true)
		return commitResult, &DurabilityError{Err: err}
	}
	if !result.Durable {
		r.hasUndurableWrite.Store(true)
		return commitResult, &DurabilityError{Err: fmt.Errorf("configuration store returned an incomplete durability result")}
	}
	r.hasUndurableWrite.Store(false)
	return commitResult, nil
}

func (r *Repository) commitTransactionResultWithPublishAction(
	ctx context.Context,
	store TransactionStore,
	fn func(*Configuration) error,
	action *publishAction,
) (CommitResult, error) {
	result, err := store.Transact(ctx, func(snapshot Snapshot) (*Configuration, error) {
		updated, _, _, prepareErr := prepareConfiguration(snapshot.Configuration, fn)
		return updated, prepareErr
	})
	if err != nil && !result.Applied {
		return CommitResult{}, err
	}
	if !result.Applied {
		return CommitResult{}, fmt.Errorf("configuration transaction reported success without applying the update")
	}
	updated, lookup, aliases, prepareErr := prepareConfiguration(result.Snapshot.Configuration, func(*Configuration) error { return nil })
	if prepareErr != nil {
		return CommitResult{}, fmt.Errorf("validate applied configuration transaction result: %w", prepareErr)
	}
	r.publishWithAction(updated, lookup, aliases, action)
	result.Snapshot.Configuration = cloneConfiguration(updated)
	if err != nil {
		r.hasUndurableWrite.Store(true)
		return result, &DurabilityError{Err: err}
	}
	if !result.Durable {
		r.hasUndurableWrite.Store(true)
		return result, &DurabilityError{Err: fmt.Errorf("configuration transaction returned an incomplete durability result")}
	}
	r.hasUndurableWrite.Store(false)
	return result, nil
}

func prepareConfiguration(base *Configuration, fn func(*Configuration) error) (*Configuration, map[string][]string, map[string]string, error) {
	updated := cloneConfiguration(base)
	if err := fn(updated); err != nil {
		return nil, nil, nil, err
	}
	stripTransientNodeMetadata(updated)
	lookup, aliases, err := buildIndexes(updated, true)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: validate configuration indexes: %w", ErrSchemaValidation, err)
	}
	if err := validateRepositoryConfiguration(updated); err != nil {
		return nil, nil, nil, err
	}
	if err := validateProxyJumpGraph(updated, lookup, aliases); err != nil {
		return nil, nil, nil, err
	}
	return updated, lookup, aliases, nil
}

func (r *Repository) publish(updated *Configuration, lookup map[string][]string, aliases map[string]string) {
	r.publishWithAction(updated, lookup, aliases, nil)
}

func (r *Repository) publishWithAction(
	updated *Configuration,
	lookup map[string][]string,
	aliases map[string]string,
	action *publishAction,
) {
	stripTransientNodeMetadata(updated)

	r.pendingMu.Lock()
	defer r.pendingMu.Unlock()
	if action != nil && action.beforeProviderLocked != nil {
		action.beforeProviderLocked()
	}

	r.provider.mu.Lock()
	oldCfg := r.provider.cfg
	r.provider.cfg = updated
	r.provider.lookupIndex = lookup
	r.provider.aliasIndex = aliases
	r.provider.pruneStaleOpenSSHMetadataLocked(oldCfg, updated)
	if action != nil && action.applyProviderLocked != nil {
		action.applyProviderLocked(r.provider, updated)
	}
	r.provider.mu.Unlock()

	if action != nil && action.afterProviderLocked != nil {
		action.afterProviderLocked()
	}
	if updated != nil && updated.Nodes != nil {
		for pendingID := range r.pending {
			if _, saved := updated.Nodes.Get(pendingID); saved {
				delete(r.pending, pendingID)
			}
		}
	}
	r.revision.Add(1)
}

func (r *Repository) persist(cfg *Configuration) (PersistResult, error) {
	if store, ok := r.store.(outcomeStore); ok {
		return store.save(cfg)
	}
	if err := r.store.Save(cfg); err != nil {
		return PersistResult{}, err
	}
	return PersistResult{Applied: true, Durable: true}, nil
}

// CreateIdentityContext creates an identity only when its name is still
// absent in the transaction's freshly loaded snapshot.
func (r *Repository) CreateIdentityContext(ctx context.Context, identityID string, identity models.Identity) (MutationOutcome, error) {
	if identityID == "" {
		return MutationOutcome{}, fmt.Errorf("identity ID is empty")
	}
	result, err := r.commitResultContext(ctx, anyRevision, func(cfg *Configuration) error {
		if _, exists := cfg.Identities.Get(identityID); exists {
			return fmt.Errorf("create identity %q: %w", identityID, ErrConfigConflict)
		}
		cfg.Identities.Set(identityID, cloneIdentity(identity))
		return nil
	})
	return MutationOutcome{Applied: result.Applied, Durable: result.Durable}, err
}

// ReplaceIdentityAtRefContext updates one shared identity only when it still
// equals the value the caller displayed.
func (r *Repository) ReplaceIdentityAtRefContext(ctx context.Context, ref IdentityRef, identity models.Identity) (MutationOutcome, error) {
	result, err := r.commitResultContext(ctx, anyRevision, func(cfg *Configuration) error {
		if err := ensureIdentityRef(cfg, ref); err != nil {
			return err
		}
		cfg.Identities.Set(ref.ID, cloneIdentity(identity))
		return nil
	})
	return MutationOutcome{Applied: result.Applied, Durable: result.Durable}, err
}

// DeleteIdentityAtRefContext removes an unreferenced identity only when it
// still equals the selected value.
func (r *Repository) DeleteIdentityAtRefContext(ctx context.Context, ref IdentityRef) (MutationOutcome, error) {
	result, err := r.commitResultContext(ctx, anyRevision, func(cfg *Configuration) error {
		if err := ensureIdentityRef(cfg, ref); err != nil {
			return err
		}
		for _, nodeID := range cfg.Nodes.Keys() {
			node, ok := cfg.Nodes.Get(nodeID)
			if ok && node.IdentityRef == ref.ID {
				return fmt.Errorf("identity %q is still referenced by node %q", ref.ID, nodeID)
			}
		}
		cfg.Identities.Remove(ref.ID)
		return nil
	})
	return MutationOutcome{Applied: result.Applied, Durable: result.Durable}, err
}

// CreateNodeContext creates one complete node bundle. Existing referenced
// records may be reused only when their values are exactly equal; creation can
// therefore never overwrite another process's host or identity.
func (r *Repository) CreateNodeContext(ctx context.Context, nodeID string, node models.Node, host models.Host, identity models.Identity) (mutation NodeMutation, retErr error) {
	if nodeID == "" {
		return NodeMutation{}, fmt.Errorf("node ID is empty")
	}
	if err := ValidateNodeID(nodeID); err != nil {
		return NodeMutation{}, err
	}
	if err := ValidateNodeAliases(node.Alias); err != nil {
		return NodeMutation{}, err
	}
	if err := ValidateNodeAliases(host.Alias); err != nil {
		return NodeMutation{}, err
	}
	if err := ValidateConcreteHostAddress(host.Address); err != nil {
		return NodeMutation{}, err
	}
	initAlias := strings.TrimSpace(node.OpenSSHAlias)
	initCanon := strings.TrimSpace(node.CanonicalHost)
	var action *publishAction
	if initAlias != "" || initCanon != "" {
		action = &publishAction{
			applyProviderLocked: func(p *Provider, updated *Configuration) {
				if p == nil || updated == nil || updated.Nodes == nil {
					return
				}
				if _, exists := updated.Nodes.Get(nodeID); exists {
					p.setOpenSSHMetadataLocked(nodeID, initAlias, initCanon)
				}
			},
		}
	}
	result, err := r.commitResultWithPublishAction(ctx, anyRevision, func(cfg *Configuration) error {
		if _, exists := cfg.Nodes.Get(nodeID); exists {
			return fmt.Errorf("create node %q: %w", nodeID, ErrConfigConflict)
		}
		if existing, exists := cfg.Hosts.Get(node.HostRef); exists {
			if !reflect.DeepEqual(existing, host) {
				return fmt.Errorf("create node %q host ref %q: %w", nodeID, node.HostRef, ErrConfigConflict)
			}
		} else {
			cfg.Hosts.Set(node.HostRef, cloneHost(host))
		}
		if existing, exists := cfg.Identities.Get(node.IdentityRef); exists {
			if !reflect.DeepEqual(existing, identity) {
				return fmt.Errorf("create node %q identity ref %q: %w", nodeID, node.IdentityRef, ErrConfigConflict)
			}
		} else {
			cfg.Identities.Set(node.IdentityRef, cloneIdentity(identity))
		}
		storedNode := cloneNode(node)
		storedNode.OpenSSHAlias = ""
		storedNode.CanonicalHost = ""
		cfg.Nodes.Set(nodeID, storedNode)
		return nil
	}, action)
	mutation.Outcome = MutationOutcome{Applied: result.Applied, Durable: result.Durable}
	if !result.Applied {
		return mutation, err
	}
	version, versionErr := nodeEntityVersion(result.Snapshot.Configuration, nodeID)
	if versionErr != nil {
		return mutation, errors.Join(err, fmt.Errorf("resolve applied node %q version: %w", nodeID, versionErr))
	}
	mutation.Ref = NodeRef{ID: nodeID, Version: version}
	authVersion, authVersionErr := nodeAuthVersion(result.Snapshot.Configuration, nodeID)
	if authVersionErr != nil {
		return mutation, errors.Join(err, fmt.Errorf("resolve applied node %q authentication version: %w", nodeID, authVersionErr))
	}
	mutation.AuthVersion = string(authVersion[:])
	return mutation, err
}

func countNodeReferences(cfg *Configuration, predicate func(models.Node) bool) int {
	count := 0
	for _, nodeID := range cfg.Nodes.Keys() {
		node, ok := cfg.Nodes.Get(nodeID)
		if ok && predicate(node) {
			count++
		}
	}
	return count
}

func privateReference(inUse func(string) bool, nodeID, kind string) string {
	base := fmt.Sprintf("node:%s:%s", nodeID, kind)
	if !inUse(base) {
		return base
	}
	for suffix := 2; ; suffix++ {
		candidate := fmt.Sprintf("%s:%d", base, suffix)
		if !inUse(candidate) {
			return candidate
		}
	}
}

func privateHostReference(cfg *Configuration, nodeID string) string {
	return privateReference(func(candidate string) bool {
		_, exists := cfg.Hosts.Get(candidate)
		return exists
	}, nodeID, "host")
}

func privateIdentityReference(cfg *Configuration, nodeID string) string {
	return privateReference(func(candidate string) bool {
		_, exists := cfg.Identities.Get(candidate)
		return exists
	}, nodeID, "identity")
}

// ReplaceNodeAtRefContext replaces a node bundle only if the original bundle
// still equals the one the caller displayed.
func (r *Repository) ReplaceNodeAtRefContext(ctx context.Context, ref NodeRef, nodeID string, node models.Node, host models.Host, identity models.Identity) error {
	_, err := r.ReplaceNodeAtRefWithAuthVersionContext(ctx, ref, nodeID, node, host, identity)
	return err
}

// ReplaceNodeAtRefWithAuthVersionContext replaces a node bundle and returns
// the authentication version produced by that same committed mutation.
func (r *Repository) ReplaceNodeAtRefWithAuthVersionContext(ctx context.Context, ref NodeRef, nodeID string, node models.Node, host models.Host, identity models.Identity) (string, error) {
	_, authVersion, err := r.replaceNodeAtRefWithOutcome(ctx, ref, nodeID, node, host, identity)
	return authVersion, err
}

func (r *Repository) replaceNodeAtRefWithOutcome(ctx context.Context, ref NodeRef, nodeID string, node models.Node, host models.Host, identity models.Identity) (MutationOutcome, string, error) {
	if nodeID == "" {
		return MutationOutcome{}, "", fmt.Errorf("node ID is empty")
	}
	if ref.ID == "" {
		return MutationOutcome{}, "", fmt.Errorf("replace node %q without a versioned reference: %w", nodeID, ErrConfigConflict)
	}
	var authVersion string
	result, err := r.commitResultContext(ctx, anyRevision, func(cfg *Configuration) error {
		if err := replaceNodeAtRef(cfg, ref, nodeID, node, host, identity); err != nil {
			return err
		}
		version, versionErr := nodeAuthVersion(cfg, nodeID)
		if versionErr != nil {
			return versionErr
		}
		authVersion = string(version[:])
		return nil
	})
	return MutationOutcome{Applied: result.Applied, Durable: result.Durable}, authVersion, err
}

// replaceNodeAtRef mutates a transaction-local snapshot. Both ordinary edits
// and credential transactions use the same conflict and shared-reference rules.
func replaceNodeAtRef(cfg *Configuration, ref NodeRef, nodeID string, node models.Node, host models.Host, identity models.Identity) error {
	if err := ValidateNodeID(nodeID); err != nil {
		return err
	}
	if err := ValidateNodeAliases(node.Alias); err != nil {
		return err
	}
	if err := ValidateNodeAliases(host.Alias); err != nil {
		return err
	}
	if err := ValidateConcreteHostAddress(host.Address); err != nil {
		return err
	}
	oldNodeID := ref.ID
	var oldNode models.Node
	if oldNodeID != "" {
		if err := ensureNodeRefs(cfg, []NodeRef{ref}); err != nil {
			return err
		}
		var err error
		oldNode, err = detachSharedNodeRefs(cfg, ref, nodeID, &node, host, identity)
		if err != nil {
			return err
		}
	}
	cfg.Hosts.Set(node.HostRef, cloneHost(host))
	cfg.Identities.Set(node.IdentityRef, cloneIdentity(identity))
	cfg.Nodes.Set(nodeID, cloneNode(node))
	if oldNodeID != "" && oldNodeID != nodeID {
		removeNodeAndUnusedRefs(cfg, oldNodeID)
	} else if oldNodeID != "" {
		removeUnusedRefs(cfg, oldNode.HostRef, oldNode.IdentityRef)
	}
	return nil
}

func detachSharedNodeRefs(cfg *Configuration, ref NodeRef, nodeID string, node *models.Node, host models.Host, identity models.Identity) (models.Node, error) {
	oldNodeID := ref.ID
	oldNode, exists := cfg.Nodes.Get(oldNodeID)
	if !exists {
		return models.Node{}, fmt.Errorf("resolve node %q for replacement: %w", oldNodeID, ErrNodeNotFound)
	}
	if existingHost, ok := cfg.Hosts.Get(node.HostRef); ok && !reflect.DeepEqual(existingHost, host) {
		hostRefs := countNodeReferences(cfg, func(candidate models.Node) bool {
			return candidate.HostRef == node.HostRef
		})
		if oldNode.HostRef == node.HostRef {
			hostRefs--
		}
		if hostRefs > 0 {
			node.HostRef = privateHostReference(cfg, nodeID)
		}
	}
	if existingIdentity, ok := cfg.Identities.Get(node.IdentityRef); ok && !reflect.DeepEqual(existingIdentity, identity) {
		idRefs := countNodeReferences(cfg, func(candidate models.Node) bool {
			return candidate.IdentityRef == node.IdentityRef
		})
		if oldNode.IdentityRef == node.IdentityRef {
			idRefs--
		}
		if idRefs > 0 {
			node.IdentityRef = privateIdentityReference(cfg, nodeID)
		}
	}
	if oldNodeID != nodeID {
		if _, destExists := cfg.Nodes.Get(nodeID); destExists {
			return models.Node{}, fmt.Errorf("rename node %q to %q: destination already exists", oldNodeID, nodeID)
		}
	}
	return oldNode, nil
}

// DeleteNodeAtRefContext removes one node only if its complete bundle still
// equals the value created or displayed by the caller.
func (r *Repository) DeleteNodeAtRefContext(ctx context.Context, ref NodeRef) (MutationOutcome, error) {
	result, err := r.commitResultContext(ctx, anyRevision, func(cfg *Configuration) error {
		if err := ensureNodeRefs(cfg, []NodeRef{ref}); err != nil {
			return err
		}
		removeNodeAndUnusedRefs(cfg, ref.ID)
		return nil
	})
	return MutationOutcome{Applied: result.Applied, Durable: result.Durable}, err
}

// DeleteNodesAtRefsContext removes nodes only when every selected node bundle
// still matches its displayed version. Unrelated configuration updates may merge.
func (r *Repository) DeleteNodesAtRefsContext(ctx context.Context, refs []NodeRef) error {
	_, err := r.deleteNodesAtRefsWithOutcome(ctx, refs)
	return err
}

func (r *Repository) deleteNodesAtRefsWithOutcome(ctx context.Context, refs []NodeRef) (MutationOutcome, error) {
	if len(refs) == 0 {
		return MutationOutcome{}, nil
	}
	result, err := r.commitResultContext(ctx, anyRevision, func(cfg *Configuration) error {
		if err := ensureNodeRefs(cfg, refs); err != nil {
			return err
		}
		seen := make(map[string]struct{}, len(refs))
		for _, ref := range refs {
			if _, duplicate := seen[ref.ID]; duplicate {
				continue
			}
			seen[ref.ID] = struct{}{}
			removeNodeAndUnusedRefs(cfg, ref.ID)
		}
		return nil
	})
	return MutationOutcome{Applied: result.Applied, Durable: result.Durable}, err
}

// UpdateNodeTagsContext applies one tag operation to all nodes in a single
// durable transaction and reports how many nodes changed. It is the CLI-facing
// batch operation; callers must resolve selectors before invoking it.
func (r *Repository) UpdateNodeTagsContext(ctx context.Context, nodeIDs, tags []string, add bool) (updatedCount int, retErr error) {
	if len(nodeIDs) == 0 || len(tags) == 0 {
		return 0, nil
	}
	err := r.commitContext(ctx, anyRevision, func(cfg *Configuration) error {
		tagSet := make(map[string]struct{}, len(tags))
		orderedTags := make([]string, 0, len(tags))
		for _, tag := range tags {
			if tag == "" {
				continue
			}
			if _, exists := tagSet[tag]; exists {
				continue
			}
			tagSet[tag] = struct{}{}
			orderedTags = append(orderedTags, tag)
		}
		if len(orderedTags) == 0 {
			return nil
		}
		seen := make(map[string]struct{}, len(nodeIDs))
		for _, nodeID := range nodeIDs {
			if nodeID == "" {
				return fmt.Errorf("node ID is empty")
			}
			if _, duplicate := seen[nodeID]; duplicate {
				continue
			}
			if _, exists := cfg.Nodes.Get(nodeID); !exists {
				return fmt.Errorf("update tags for node %q: %w", nodeID, ErrNodeNotFound)
			}
			seen[nodeID] = struct{}{}
		}
		for nodeID := range seen {
			node, _ := cfg.Nodes.Get(nodeID)
			changed := false
			if add {
				existing := make(map[string]struct{}, len(node.Tags))
				for _, tag := range node.Tags {
					existing[tag] = struct{}{}
				}
				for _, tag := range orderedTags {
					if _, exists := existing[tag]; exists {
						continue
					}
					node.Tags = append(node.Tags, tag)
					existing[tag] = struct{}{}
					changed = true
				}
			} else {
				filtered := node.Tags[:0]
				for _, tag := range node.Tags {
					if _, remove := tagSet[tag]; remove {
						changed = true
						continue
					}
					filtered = append(filtered, tag)
				}
				node.Tags = filtered
			}
			if changed {
				cfg.Nodes.Set(nodeID, node)
				updatedCount++
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return updatedCount, nil
}

// ImportOpenSSHHostsContext adds all non-conflicting OpenSSH hosts in one
// durable transaction. Existing node IDs are skipped; malformed candidates
// are reported individually without suppressing their cause.
func (r *Repository) ImportOpenSSHHostsContext(ctx context.Context, hosts []OpenSSHHost) (ImportResult, error) {
	result := ImportResult{Issues: make([]ImportIssue, 0)}
	err := r.commitContext(ctx, anyRevision, func(cfg *Configuration) error {
		importedNodeIDs := make([]string, 0, len(hosts))
		_, aliases, indexErr := buildIndexes(cfg, true)
		if indexErr != nil {
			return fmt.Errorf("index existing configuration before openssh import: %w", indexErr)
		}
		for _, item := range hosts {
			if item.Name == "" {
				result.Skipped++
				result.Issues = append(result.Issues, ImportIssue{Name: item.Name, Err: fmt.Errorf("openssh host name is empty")})
				continue
			}
			if err := ValidateNodeID(item.Name); err != nil {
				result.Skipped++
				result.Issues = append(result.Issues, ImportIssue{Name: item.Name, Err: err})
				continue
			}
			if err := ValidateConcreteHostAddress(item.Host.Address); err != nil {
				result.Skipped++
				result.Issues = append(result.Issues, ImportIssue{Name: item.Name, Err: err})
				continue
			}
			if _, exists := cfg.Nodes.Get(item.Name); exists {
				result.Skipped++
				continue
			}
			sanitizedOpts, optErr := sanitizeAndValidateImportedSSHOptions(item.Node.SSHOptions, cfg.SSHOptions)
			if optErr != nil {
				result.Skipped++
				result.Issues = append(result.Issues, ImportIssue{Name: item.Name, Err: optErr})
				continue
			}
			if importErr := reserveOpenSSHAliases(aliases, item); importErr != nil {
				result.Skipped++
				result.Issues = append(result.Issues, ImportIssue{Name: item.Name, Err: importErr})
				continue
			}
			hostRef := allocateUnusedRef(func(candidate string) bool {
				_, exists := cfg.Hosts.Get(candidate)
				return exists
			}, "openssh-host:"+item.Name)
			identityRef := allocateUnusedRef(func(candidate string) bool {
				_, exists := cfg.Identities.Get(candidate)
				return exists
			}, "openssh-identity:"+item.Name)
			storedNode := cloneNode(item.Node)
			storedNode.SSHOptions = sanitizedOpts
			storedNode.HostRef = hostRef
			storedNode.IdentityRef = identityRef
			cfg.Hosts.Set(hostRef, cloneHost(item.Host))
			cfg.Identities.Set(identityRef, cloneIdentity(item.Identity))
			cfg.Nodes.Set(item.Name, storedNode)
			importedNodeIDs = append(importedNodeIDs, item.Name)
			result.Imported++
		}
		for _, nodeID := range importedNodeIDs {
			node, exists := cfg.Nodes.Get(nodeID)
			if !exists || node.ProxyJump == "" {
				continue
			}
			node.ProxyJump = resolveImportedProxyJump(cfg, node.ProxyJump)
			cfg.Nodes.Set(nodeID, node)
		}
		return nil
	})
	if err != nil {
		var durabilityErr *DurabilityError
		if errors.As(err, &durabilityErr) {
			return result, fmt.Errorf("commit openssh import: %w", err)
		}
		return ImportResult{}, fmt.Errorf("commit openssh import: %w", err)
	}
	return result, nil
}

func allocateUnusedRef(inUse func(string) bool, base string) string {
	if !inUse(base) {
		return base
	}
	for suffix := 2; ; suffix++ {
		candidate := fmt.Sprintf("%s:%d", base, suffix)
		if !inUse(candidate) {
			return candidate
		}
	}
}

func sanitizeAndValidateImportedSSHOptions(nodeOpts, globalOpts *ssh.Options) (*ssh.Options, error) {
	if nodeOpts == nil || nodeOpts.IsEmpty() {
		if globalOpts != nil {
			if err := ValidateEffectiveSSHOptions(globalOpts); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}
	cloned := nodeOpts.Clone()
	if cloned.ControlMaster() == ssh.ControlMasterNo && globalOpts != nil && !ssh.IsNoneValue(cloned.ControlPath()) {
		if gPersist, gErr := globalOpts.PersistSetting(); gErr == nil && gPersist.Enabled() {
			if nPersist, nErr := cloned.PersistSetting(); nErr != nil || !nPersist.Explicit() || nPersist.Enabled() {
				_ = cloned.Set(ssh.OptionControlPersist, "no")
			}
		}
	}
	if err := ValidateSSHOptions(cloned); err != nil {
		return nil, err
	}
	effectiveOpts, err := ssh.ResolveOptions(cloned, globalOpts)
	if err != nil {
		return nil, err
	}
	if effectiveOpts != nil {
		if err := ValidateEffectiveSSHOptions(effectiveOpts); err != nil {
			return nil, err
		}
	}
	return cloned, nil
}

func reserveOpenSSHAliases(aliases map[string]string, item OpenSSHHost) error {
	if err := ValidateNodeAliases(item.Host.Alias); err != nil {
		return err
	}
	checkList := func(list []string) error {
		for _, alias := range list {
			if alias == "" {
				continue
			}
			if err := ValidateNodeAlias(alias); err != nil {
				return err
			}
			if existingNodeID, exists := aliases[alias]; exists && existingNodeID != item.Name {
				return fmt.Errorf("alias %q is already assigned to node %q", alias, existingNodeID)
			}
		}
		return nil
	}
	if err := checkList(item.Node.Alias); err != nil {
		return err
	}
	if err := checkList(item.Host.Alias); err != nil {
		return err
	}
	for _, alias := range item.Node.Alias {
		if alias != "" {
			aliases[alias] = item.Name
		}
	}
	for _, alias := range item.Host.Alias {
		if alias != "" {
			aliases[alias] = item.Name
		}
	}
	return nil
}

func resolveImportedProxyJump(cfg *Configuration, proxyJump string) string {
	lookup, _, err := buildIndexes(cfg, true)
	if err != nil {
		return proxyJump
	}
	hops := make([]string, 0)
	for rawHop := range strings.SplitSeq(proxyJump, ",") {
		hop := strings.TrimSpace(rawHop)
		if hop == "" || strings.EqualFold(hop, "none") {
			continue
		}
		if _, exists := cfg.Nodes.Get(hop); exists {
			hops = append(hops, hop)
			continue
		}
		if candidates := lookup[hop]; len(candidates) == 1 {
			hops = append(hops, candidates[0])
			continue
		}
		if nodeID, ok := findImportedProxyByConnection(cfg, hop); ok {
			hops = append(hops, nodeID)
			continue
		}
		// Preserve an unresolved hop verbatim. This retains the source intent and
		// lets a later inventory addition make it resolvable without rewriting.
		hops = append(hops, hop)
	}
	return strings.Join(hops, ",")
}

func findImportedProxyByConnection(cfg *Configuration, hop string) (string, bool) {
	hostName, userName, port, err := parseOpenSSHHostSpec(hop)
	if err != nil {
		return "", false
	}
	targetEp, epErr := ssh.NewEndpoint(hostName, int(port))
	if epErr != nil {
		return "", false
	}
	candidates := make([]string, 0)
	for _, nodeID := range cfg.Nodes.Keys() {
		node, exists := cfg.Nodes.Get(nodeID)
		if !exists {
			continue
		}
		host, hostExists := cfg.Hosts.Get(node.HostRef)
		identity, identityExists := cfg.Identities.Get(node.IdentityRef)
		if !hostExists || !identityExists {
			continue
		}
		hostEp, hErr := ssh.NewEndpoint(host.Address, int(host.Port))
		if hErr != nil {
			continue
		}
		if port != 0 {
			if !hostEp.Equal(targetEp) {
				continue
			}
		} else if !hostEp.HostEqual(targetEp) {
			continue
		}
		if userName != "" && normalizedIdentityUser(identity.User) != userName {
			continue
		}
		candidates = append(candidates, nodeID)
	}
	if len(candidates) != 1 {
		return "", false
	}
	return candidates[0], true
}

// InitializeContext persists an otherwise empty newly created configuration.
func (r *Repository) InitializeContext(ctx context.Context) error {
	return r.commitContext(ctx, anyRevision, func(*Configuration) error {
		return nil
	})
}

// UpdateAuthAtVersionContext updates only authentication fields that still
// match the connection snapshot. A shared identity is copied for the current
// node before discovery is persisted, so runtime discovery cannot mutate a
// reusable template for unrelated nodes.
func (r *Repository) UpdateAuthAtVersionContext(ctx context.Context, nodeID, authVersion, password, keyPath, passphrase string) (string, error) {
	expected, err := versionFromString(authVersion)
	if err != nil {
		return "", fmt.Errorf("update authentication for node %q: %w", nodeID, err)
	}
	committedToken := authVersion
	err = r.commitContext(ctx, anyRevision, func(cfg *Configuration) error {
		current, err := nodeAuthVersion(cfg, nodeID)
		if err != nil || current != expected {
			return fmt.Errorf("authentication for node %q changed during connection: %w", nodeID, ErrConfigConflict)
		}
		node, ok := cfg.Nodes.Get(nodeID)
		if !ok {
			return fmt.Errorf("resolve node %q for auth update: %w", nodeID, ErrNodeNotFound)
		}
		identity, ok := cfg.Identities.Get(node.IdentityRef)
		if !ok {
			return fmt.Errorf("resolve node %q for auth update: %w", nodeID, ErrIdentityNotFound)
		}
		identity = cloneIdentity(identity)
		changed := false
		if password != "" && identity.Password != password {
			identity.Password = password
			identity.AuthType = "password"
			changed = true
		}
		if passphrase != "" && (identity.Passphrase != passphrase || identity.KeyPath != keyPath) {
			identity.Passphrase = passphrase
			identity.KeyPath = keyPath
			identity.AuthType = "key"
			changed = true
		}
		if !changed {
			committedToken = authVersion
			return nil
		}
		if countNodeReferences(cfg, func(candidate models.Node) bool {
			return candidate.IdentityRef == node.IdentityRef
		}) > 1 {
			node = cloneNode(node)
			node.IdentityRef = privateIdentityReference(cfg, nodeID)
			cfg.Nodes.Set(nodeID, node)
		}
		cfg.Identities.Set(node.IdentityRef, identity)
		newVer, err := nodeAuthVersion(cfg, nodeID)
		if err != nil {
			return err
		}
		committedToken = string(newVer[:])
		return nil
	})
	if err != nil {
		return "", err
	}
	return committedToken, nil
}

// UpdateSudoAtVersionContext updates only sudo fields that still match the
// connection snapshot. It may merge with unrelated node or identity changes.
func (r *Repository) UpdateSudoAtVersionContext(ctx context.Context, nodeID, sudoVersion string, mode models.SudoMode, suPwd string) (string, error) {
	expected, err := versionFromString(sudoVersion)
	if err != nil {
		return "", fmt.Errorf("update sudo for node %q: %w", nodeID, err)
	}
	committedToken := sudoVersion
	err = r.commitContext(ctx, anyRevision, func(cfg *Configuration) error {
		current, err := nodeSudoVersion(cfg, nodeID)
		if err != nil || current != expected {
			return fmt.Errorf("sudo settings for node %q changed during connection: %w", nodeID, ErrConfigConflict)
		}
		node, ok := cfg.Nodes.Get(nodeID)
		if !ok {
			return fmt.Errorf("resolve node %q for sudo update: %w", nodeID, ErrNodeNotFound)
		}
		node = cloneNode(node)
		changed := false
		if mode != "" && node.SudoMode != mode {
			node.SudoMode = mode
			changed = true
		}
		if suPwd != "" && node.SuPwd != suPwd {
			node.SuPwd = suPwd
			changed = true
		}
		if !changed {
			committedToken = sudoVersion
			return nil
		}
		cfg.Nodes.Set(nodeID, node)
		newVer, err := nodeSudoVersion(cfg, nodeID)
		if err != nil {
			return err
		}
		committedToken = string(newVer[:])
		return nil
	})
	if err != nil {
		return "", err
	}
	return committedToken, nil
}

func (r *Repository) Resolve(nodeID string) (models.Node, models.Host, models.Identity, error) {
	provider, _ := r.connectionProviderWithProvenance(nodeID)
	return provider.Resolve(nodeID)
}

func (r *Repository) GetNode(nodeID string) (models.Node, bool) {
	return r.provider.GetNode(nodeID)
}

func (r *Repository) GetHost(nodeID string) (models.Host, bool) {
	return r.provider.GetHost(nodeID)
}

func (r *Repository) GetIdentity(nodeID string) (models.Identity, bool) {
	return r.provider.GetIdentity(nodeID)
}

func (r *Repository) ListNodes() map[string]models.Node {
	return r.provider.ListNodes()
}

func (r *Repository) GetNodesByTag(tag string) map[string]models.Node {
	return r.provider.GetNodesByTag(tag)
}

func (r *Repository) ListIdentities() map[string]models.Identity {
	return r.provider.ListIdentities()
}

func (r *Repository) Find(input string) string {
	return r.provider.Find(input)
}

func (r *Repository) ResolveSelector(input string) (string, error) {
	if r == nil || r.provider == nil {
		return "", nil
	}
	return r.provider.ResolveSelector(input)
}

func (r *Repository) FindAlias(alias string) string {
	return r.provider.FindAlias(alias)
}

func (r *Repository) Snapshot() *Configuration {
	return r.provider.Snapshot()
}

func (r *Repository) GetOpenSSHOptions(alias string) (*ssh.Options, error) {
	if r == nil || r.provider == nil {
		return nil, nil
	}
	return r.provider.GetOpenSSHOptions(alias)
}

func (r *Repository) GetOpenSSHControl(alias string) (*ssh.ControlConfig, error) {
	if r == nil || r.provider == nil {
		return nil, nil
	}
	return r.provider.GetOpenSSHControl(alias)
}

func (r *Repository) GetOpenSSHParser() *OpenSSHParser {
	if r == nil || r.provider == nil {
		return nil
	}
	return r.provider.GetOpenSSHParser()
}

// Frozen exposes an immutable read-only view, retaining OpenSSH parser/alias
// inspection without exposing Repository's durable mutation interfaces to the caller.
func (r *Repository) Frozen() ConfigProvider {
	return &frozenRepository{ConfigProvider: r.provider.Frozen()}
}

type frozenRepository struct {
	ConfigProvider
}

func (r *frozenRepository) GetOpenSSHParser() *OpenSSHParser {
	if r == nil || r.ConfigProvider == nil {
		return nil
	}
	if src, ok := r.ConfigProvider.(openSSHParserSource); ok {
		return src.GetOpenSSHParser()
	}
	return nil
}

func (r *frozenRepository) snapshotWithOrigins() (*Configuration, map[string]OpenSSHOrigin) {
	if r == nil || r.ConfigProvider == nil {
		return cloneConfiguration(nil), nil
	}
	if src, ok := r.ConfigProvider.(interface {
		snapshotWithOrigins() (*Configuration, map[string]OpenSSHOrigin)
	}); ok {
		return src.snapshotWithOrigins()
	}
	return r.Snapshot(), nil
}

func (r *frozenRepository) NodeOpenSSHOrigin(nodeID string) OpenSSHOrigin {
	if r == nil || r.ConfigProvider == nil {
		return OpenSSHOrigin{}
	}
	if store, ok := r.ConfigProvider.(interface{ NodeOpenSSHOrigin(string) OpenSSHOrigin }); ok {
		return store.NodeOpenSSHOrigin(nodeID)
	}
	return OpenSSHOrigin{
		Alias:         r.NodeOpenSSHAlias(nodeID),
		CanonicalHost: r.NodeCanonicalHost(nodeID),
	}
}

func (r *frozenRepository) NodeOpenSSHAlias(nodeID string) string {
	if r == nil || r.ConfigProvider == nil {
		return ""
	}
	if store, ok := r.ConfigProvider.(interface{ NodeOpenSSHAlias(string) string }); ok {
		return store.NodeOpenSSHAlias(nodeID)
	}
	return ""
}

func (r *frozenRepository) ResolveConnectionWithOrigin(nodeID, originalHost string) (ConnectionSnapshot, error) {
	if r == nil || r.ConfigProvider == nil {
		return ConnectionSnapshot{}, fmt.Errorf("configuration repository is nil")
	}
	if src, ok := r.ConfigProvider.(interface {
		ResolveConnectionWithOrigin(string, string) (ConnectionSnapshot, error)
	}); ok {
		return src.ResolveConnectionWithOrigin(nodeID, originalHost)
	}
	return r.ResolveConnection(nodeID)
}

func (r *frozenRepository) NodeCanonicalHost(nodeID string) string {
	if r == nil || r.ConfigProvider == nil {
		return ""
	}
	if store, ok := r.ConfigProvider.(interface{ NodeCanonicalHost(string) string }); ok {
		return store.NodeCanonicalHost(nodeID)
	}
	return ""
}

func (r *frozenRepository) GetOpenSSHOptions(alias string) (*ssh.Options, error) {
	if r == nil || r.ConfigProvider == nil {
		return nil, nil
	}
	if src, ok := r.ConfigProvider.(interface {
		GetOpenSSHOptions(string) (*ssh.Options, error)
	}); ok {
		return src.GetOpenSSHOptions(alias)
	}
	return nil, nil
}

func (r *frozenRepository) GetOpenSSHControl(alias string) (*ssh.ControlConfig, error) {
	if r == nil || r.ConfigProvider == nil {
		return nil, nil
	}
	if src, ok := r.ConfigProvider.(interface {
		GetOpenSSHControl(string) (*ssh.ControlConfig, error)
	}); ok {
		return src.GetOpenSSHControl(alias)
	}
	return nil, nil
}

func validateRepositoryConfiguration(cfg *Configuration) error {
	if err := validateConfiguration(cfg); err != nil {
		return err
	}
	if cfg.Nodes != nil {
		nodeIDs := cfg.Nodes.Keys()
		slices.Sort(nodeIDs)
		for _, nodeID := range nodeIDs {
			node, ok := cfg.Nodes.Get(nodeID)
			if !ok {
				continue
			}
			if _, err := ssh.ResolveExecution(node.Execution, cfg.Execution); err != nil {
				return fmt.Errorf("%w: node %q effective execution invalid: %w", ErrSchemaValidation, nodeID, err)
			}
		}
	}
	return nil
}

func validateConfiguration(cfg *Configuration) error {
	if cfg == nil {
		return fmt.Errorf("%w: configuration is nil", ErrSchemaValidation)
	}
	if cfg.Execution != nil {
		if err := cfg.Execution.Validate(); err != nil {
			return fmt.Errorf("%w: global execution invalid: %w", ErrSchemaValidation, err)
		}
	}
	if cfg.SSHOptions != nil {
		if err := ValidateSSHOptions(cfg.SSHOptions); err != nil {
			return fmt.Errorf("%w: global ssh_options invalid: %w", ErrSchemaValidation, err)
		}
	}
	stores, err := validateRepositoryCredentialConfig(cfg)
	if err != nil {
		return err
	}
	if err := validateConfigurationHosts(cfg); err != nil {
		return err
	}
	if err := validateConfigurationIdentities(cfg, stores); err != nil {
		return err
	}
	return validateConfigurationNodes(cfg, stores)
}

func validateRepositoryCredentialConfig(cfg *Configuration) (map[string]StoreConfig, error) {
	if cfg.Credential == nil {
		return nil, nil
	}
	if cfg.SchemaVersion == 2 {
		if err := validateCredentialConfig(cfg.Credential); err != nil {
			return nil, err
		}
		return cfg.Credential.Stores, nil
	}
	switch cfg.Credential.RememberPrompted {
	case "", "ask", "always", "never":
	default:
		return nil, fmt.Errorf("%w: invalid remember_prompted value %q (must be ask, always, or never)",
			ErrSchemaValidation, cfg.Credential.RememberPrompted)
	}
	for storeID, storeCfg := range cfg.Credential.Stores {
		if strings.TrimSpace(storeID) == "" {
			return nil, fmt.Errorf("%w: storeID cannot be empty", ErrSchemaValidation)
		}
		if strings.ContainsAny(storeID, "/\\ \t\r\n\x00") {
			return nil, fmt.Errorf("%w: storeID %q contains invalid characters", ErrSchemaValidation, storeID)
		}
		if storeCfg.Type == StoreTypeEncryptedFile {
			if err := validateFileStoreIdentity(storeID, storeCfg); err != nil {
				return nil, err
			}
		}
		if storeCfg.Type == StoreTypeHelper && storeCfg.Command != "" {
			if strings.ContainsAny(storeCfg.Command, ";|&`$\n") {
				return nil, fmt.Errorf("%w: helper store %q command contains forbidden shell characters",
					ErrSchemaValidation, storeID)
			}
		}
		if storeCfg.Timeout < 0 {
			return nil, fmt.Errorf("%w: store %q timeout cannot be negative", ErrSchemaValidation, storeID)
		}
		if storeCfg.CacheTTL < 0 {
			return nil, fmt.Errorf("%w: store %q cache_ttl cannot be negative", ErrSchemaValidation, storeID)
		}
	}
	return cfg.Credential.Stores, nil
}

func validateConfigurationHosts(cfg *Configuration) error {
	if cfg.Hosts == nil {
		return nil
	}
	hostNames := cfg.Hosts.Keys()
	slices.Sort(hostNames)
	for _, hostName := range hostNames {
		host, ok := cfg.Hosts.Get(hostName)
		if !ok {
			continue
		}
		if err := ValidateConcreteHostAddress(host.Address); err != nil {
			return fmt.Errorf("%w: host %q address invalid: %w", ErrSchemaValidation, hostName, err)
		}
		if err := ValidateNodeAliases(host.Alias); err != nil {
			return fmt.Errorf("%w: host %q alias invalid: %w", ErrSchemaValidation, hostName, err)
		}
	}
	return nil
}

func validateConfigurationIdentities(cfg *Configuration, stores map[string]StoreConfig) error {
	if cfg.Identities == nil {
		return nil
	}
	idNames := cfg.Identities.Keys()
	slices.Sort(idNames)
	for _, idName := range idNames {
		id, ok := cfg.Identities.Get(idName)
		if !ok {
			continue
		}
		if id.LoginPasswordRef != nil {
			if err := validateConfiguredRef(*id.LoginPasswordRef, stores); err != nil {
				return fmt.Errorf("%w: identity %q login_password_ref invalid: %w", ErrSchemaValidation, idName, err)
			}
		}
		if id.PassphraseRef != nil {
			if err := validateConfiguredRef(*id.PassphraseRef, stores); err != nil {
				return fmt.Errorf("%w: identity %q passphrase_ref invalid: %w", ErrSchemaValidation, idName, err)
			}
			if id.KeyFingerprint != "" && strings.ContainsAny(id.KeyFingerprint, " \t\r\n\x00") {
				return fmt.Errorf("%w: identity %q has invalid key_fingerprint %q", ErrSchemaValidation, idName, id.KeyFingerprint)
			}
		}
		if id.OTP != nil {
			if err := validateConfigurationOTP(idName, id.OTP, stores); err != nil {
				return err
			}
		}
		if id.KeyboardInteractive != nil {
			if err := validateConfigurationKeyboardInteractive(idName, id.KeyboardInteractive, stores); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateConfigurationOTP(idName string, otp *models.OTPConfig, stores map[string]StoreConfig) error {
	hasRef := otp.TOTPSecretRef != nil && !otp.TOTPSecretRef.IsEmpty()
	hasCmd := strings.TrimSpace(otp.Command) != ""
	if hasRef && hasCmd {
		return fmt.Errorf("%w: identity %q otp cannot specify both totp_secret_ref and command (mutually exclusive)", ErrSchemaValidation, idName)
	}
	if !hasRef && !hasCmd {
		return fmt.Errorf("%w: identity %q otp must specify either totp_secret_ref or command", ErrSchemaValidation, idName)
	}
	if hasRef {
		if err := validateConfiguredRef(*otp.TOTPSecretRef, stores); err != nil {
			return fmt.Errorf("%w: identity %q otp totp_secret_ref invalid: %w", ErrSchemaValidation, idName, err)
		}
	}
	if hasCmd && strings.ContainsAny(otp.Command, ";|&`$\n") {
		return fmt.Errorf("%w: identity %q otp command contains forbidden shell characters", ErrSchemaValidation, idName)
	}
	if strings.TrimSpace(otp.PromptPattern) != "" {
		if _, err := regexp.Compile(otp.PromptPattern); err != nil {
			return fmt.Errorf("%w: identity %q otp prompt_pattern %q invalid regex: %w", ErrSchemaValidation, idName, otp.PromptPattern, err)
		}
	}
	if otp.Timeout < 0 {
		return fmt.Errorf("%w: identity %q otp timeout cannot be negative", ErrSchemaValidation, idName)
	}
	return nil
}

func validateConfigurationKeyboardInteractive(idName string, ki *models.KeyboardInteractiveConfig, stores map[string]StoreConfig) error {
	seenNames := make(map[string]int)
	for idx, rule := range ki.Rules {
		ruleDesc := fmt.Sprintf("rule %d", idx+1)
		if rule.Name != "" {
			ruleDesc = fmt.Sprintf("rule %d (%q)", idx+1, rule.Name)
			if prevIdx, exists := seenNames[rule.Name]; exists {
				return fmt.Errorf("%w: identity %q keyboard_interactive has duplicate rule name %q in rules %d and %d", ErrSchemaValidation, idName, rule.Name, prevIdx, idx+1)
			}
			seenNames[rule.Name] = idx + 1
		}
		if strings.TrimSpace(rule.PromptPattern) == "" {
			return fmt.Errorf("%w: identity %q keyboard_interactive %s prompt_pattern cannot be empty", ErrSchemaValidation, idName, ruleDesc)
		}
		if _, err := regexp.Compile(rule.PromptPattern); err != nil {
			return fmt.Errorf("%w: identity %q keyboard_interactive %s prompt_pattern %q invalid regex: %w", ErrSchemaValidation, idName, ruleDesc, rule.PromptPattern, err)
		}
		if strings.TrimSpace(rule.InstructionPattern) != "" {
			if _, err := regexp.Compile(rule.InstructionPattern); err != nil {
				return fmt.Errorf("%w: identity %q keyboard_interactive %s instruction_pattern %q invalid regex: %w", ErrSchemaValidation, idName, ruleDesc, rule.InstructionPattern, err)
			}
		}
		if rule.Timeout < 0 {
			return fmt.Errorf("%w: identity %q keyboard_interactive %s timeout cannot be negative", ErrSchemaValidation, idName, ruleDesc)
		}
		if err := validateConfigurationChallengeRuleSource(idName, ruleDesc, rule, stores); err != nil {
			return err
		}
	}
	return nil
}

func validateConfigurationChallengeRuleSource(idName, ruleDesc string, rule models.ChallengeRule, stores map[string]StoreConfig) error {
	switch rule.Source {
	case models.ChallengeSourceOTP, models.ChallengeSourceLoginPassword:
		return validateNoSecretRefOrCommand(idName, ruleDesc, string(rule.Source), rule)
	case models.ChallengeSourceSecret:
		if strings.TrimSpace(rule.Name) == "" {
			return fmt.Errorf("%w: identity %q keyboard_interactive %s with source \"secret\" must specify non-empty name", ErrSchemaValidation, idName, ruleDesc)
		}
		if rule.SecretRef == nil || rule.SecretRef.IsEmpty() {
			return fmt.Errorf("%w: identity %q keyboard_interactive %s with source \"secret\" must specify secret_ref", ErrSchemaValidation, idName, ruleDesc)
		}
		if strings.TrimSpace(rule.Command) != "" {
			return fmt.Errorf("%w: identity %q keyboard_interactive %s with source \"secret\" cannot specify command", ErrSchemaValidation, idName, ruleDesc)
		}
		if err := validateConfiguredRef(*rule.SecretRef, stores); err != nil {
			return fmt.Errorf("%w: identity %q keyboard_interactive %s secret_ref invalid: %w", ErrSchemaValidation, idName, ruleDesc, err)
		}
	case models.ChallengeSourceCommand:
		if rule.SecretRef != nil && !rule.SecretRef.IsEmpty() {
			return fmt.Errorf("%w: identity %q keyboard_interactive %s with source \"command\" cannot specify secret_ref", ErrSchemaValidation, idName, ruleDesc)
		}
		if strings.TrimSpace(rule.Command) == "" {
			return fmt.Errorf("%w: identity %q keyboard_interactive %s with source \"command\" must specify non-empty command", ErrSchemaValidation, idName, ruleDesc)
		}
		if strings.ContainsAny(rule.Command, ";|&`$\n") {
			return fmt.Errorf("%w: identity %q keyboard_interactive %s command contains forbidden shell characters", ErrSchemaValidation, idName, ruleDesc)
		}
	default:
		return fmt.Errorf("%w: identity %q keyboard_interactive %s has unknown source %q", ErrSchemaValidation, idName, ruleDesc, rule.Source)
	}
	return nil
}

func validateConfigurationNodes(cfg *Configuration, stores map[string]StoreConfig) error {
	if cfg.Nodes == nil {
		return nil
	}
	nodeIDs := cfg.Nodes.Keys()
	slices.Sort(nodeIDs)
	for _, nodeID := range nodeIDs {
		node, ok := cfg.Nodes.Get(nodeID)
		if !ok {
			continue
		}
		if err := validateConfigurationNode(cfg, stores, nodeID, node); err != nil {
			return err
		}
	}
	return nil
}

func validateConfigurationNode(cfg *Configuration, stores map[string]StoreConfig, nodeID string, node models.Node) error {
	if err := ValidateNodeID(nodeID); err != nil {
		return fmt.Errorf("%w: node %q name invalid: %w", ErrSchemaValidation, nodeID, err)
	}
	if err := ValidateNodeAliases(node.Alias); err != nil {
		return fmt.Errorf("%w: node %q alias invalid: %w", ErrSchemaValidation, nodeID, err)
	}
	if err := validateConfigurationNodeRefs(cfg, stores, nodeID, node); err != nil {
		return err
	}
	return validateConfigurationNodeOptions(cfg, nodeID, node)
}

func validateConfigurationNodeRefs(cfg *Configuration, stores map[string]StoreConfig, nodeID string, node models.Node) error {
	if strings.TrimSpace(node.HostRef) == "" {
		return fmt.Errorf("%w: node %q host_ref cannot be empty: %w", ErrSchemaValidation, nodeID, ErrHostNotFound)
	}
	if cfg.Hosts == nil {
		return fmt.Errorf("%w: node %q host ref %q: %w", ErrSchemaValidation, nodeID, node.HostRef, ErrHostNotFound)
	}
	if _, ok := cfg.Hosts.Get(node.HostRef); !ok {
		return fmt.Errorf("%w: node %q host ref %q: %w", ErrSchemaValidation, nodeID, node.HostRef, ErrHostNotFound)
	}
	if strings.TrimSpace(node.IdentityRef) == "" {
		return fmt.Errorf("%w: node %q identity_ref cannot be empty: %w", ErrSchemaValidation, nodeID, ErrIdentityNotFound)
	}
	if cfg.Identities == nil {
		return fmt.Errorf("%w: node %q identity ref %q: %w", ErrSchemaValidation, nodeID, node.IdentityRef, ErrIdentityNotFound)
	}
	if _, ok := cfg.Identities.Get(node.IdentityRef); !ok {
		return fmt.Errorf("%w: node %q identity ref %q: %w", ErrSchemaValidation, nodeID, node.IdentityRef, ErrIdentityNotFound)
	}
	if node.PrivilegePasswordRef != nil {
		if err := validateConfiguredRef(*node.PrivilegePasswordRef, stores); err != nil {
			return fmt.Errorf("%w: node %q privilege_password_ref invalid: %w", ErrSchemaValidation, nodeID, err)
		}
	}
	return nil
}

func validateConfigurationNodeOptions(cfg *Configuration, nodeID string, node models.Node) error {
	if node.Execution != nil {
		if err := node.Execution.Validate(); err != nil {
			return fmt.Errorf("%w: node %q execution invalid: %w", ErrSchemaValidation, nodeID, err)
		}
	}
	if node.SSHOptions != nil {
		if err := ValidateSSHOptions(node.SSHOptions); err != nil {
			return fmt.Errorf("%w: node %q ssh_options invalid: %w", ErrSchemaValidation, nodeID, err)
		}
	}
	if effectiveOpts, err := ssh.ResolveOptions(node.SSHOptions, cfg.SSHOptions); err != nil {
		return fmt.Errorf("%w: node %q effective ssh_options invalid: %w", ErrSchemaValidation, nodeID, err)
	} else if effectiveOpts != nil {
		if err := ValidateEffectiveSSHOptions(effectiveOpts); err != nil {
			return fmt.Errorf("%w: node %q effective ssh_options invalid: %w", ErrSchemaValidation, nodeID, err)
		}
	}
	return nil
}

// UpdateNodeCredentialRefAtVersionContext updates the specified credential reference on a node.
// If the node shares an identity with other nodes, updating authentication credentials (KindLoginPassword or KindPassphrase)
// automatically forks a private identity for the node, preserving shared templates for other nodes.
func (r *Repository) UpdateNodeCredentialRefAtVersionContext(
	ctx context.Context,
	nodeID string,
	expectedVersion string,
	kind credential.Kind,
	newRef *credential.Ref,
) (MutationOutcome, string, error) {
	return r.UpdateNodeCredentialRefWithMetadataAtVersionContext(ctx, nodeID, expectedVersion, kind, newRef, "", "", false, false, false)
}

// UpdateNodeCredentialRefWithKeyPathAtVersionContext atomically updates a
// node credential reference and, for a private-key passphrase, its non-secret
// key path. An empty keyPath leaves the existing path unchanged.
func (r *Repository) UpdateNodeCredentialRefWithKeyPathAtVersionContext(
	ctx context.Context,
	nodeID string,
	expectedVersion string,
	kind credential.Kind,
	newRef *credential.Ref,
	keyPath string,
) (MutationOutcome, string, error) {
	return r.UpdateNodeCredentialRefWithMetadataAtVersionContext(ctx, nodeID, expectedVersion, kind, newRef, keyPath, "", false, false, false)
}

// UpdateNodeCredentialRefWithMetadataAtVersionContext atomically updates a
// node credential reference with non-secret authentication metadata.
func (r *Repository) UpdateNodeCredentialRefWithMetadataAtVersionContext(
	ctx context.Context,
	nodeID string,
	expectedVersion string,
	kind credential.Kind,
	newRef *credential.Ref,
	keyPath string,
	authType string,
	clearKeyPath bool,
	clearLegacyLoginPassword bool,
	clearLegacyPassphrase bool,
) (MutationOutcome, string, error) {
	return r.updateNodeCredentialTargetAtVersion(ctx, credential.Target{NodeID: nodeID, Kind: kind, KeyPath: keyPath, AuthType: authType, ClearKeyPath: clearKeyPath, ClearLegacyLoginPassword: clearLegacyLoginPassword, ClearLegacyPassphrase: clearLegacyPassphrase}, expectedVersion, newRef)
}

func (r *Repository) updateNodeCredentialTargetAtVersion(ctx context.Context, target credential.Target, expectedVersion string, newRef *credential.Ref) (MutationOutcome, string, error) {
	nodeID, kind := target.NodeID, target.Kind

	if err := kind.Validate(); err != nil {
		return MutationOutcome{}, "", err
	}
	if newRef != nil {
		if err := newRef.Validate(); err != nil {
			return MutationOutcome{}, "", err
		}
	}

	var committedVersion string
	commitResult, err := r.commitResultContext(ctx, anyRevision, func(cfg *Configuration) error {
		switch kind {
		case credential.KindLoginPassword, credential.KindPassphrase, credential.KindTOTPSecret, credential.KindChallengeAnswer:
			ver, updateErr := updateNodeAuthCredentialTarget(cfg, target, expectedVersion, newRef)
			if updateErr != nil {
				return updateErr
			}
			committedVersion = ver
			return nil

		case credential.KindPrivilegePassword:
			ver, updateErr := updateNodeSudoCredentialRef(cfg, nodeID, expectedVersion, newRef)
			if updateErr != nil {
				return updateErr
			}
			committedVersion = ver
			return nil

		default:
			return fmt.Errorf("%w: unsupported credential kind %q", coreauth.ErrInvalidRef, kind)
		}
	})

	if err != nil {
		if commitResult.Applied {
			return MutationOutcome{Applied: true, Durable: false}, committedVersion, err
		}
		return MutationOutcome{Applied: false, Durable: false}, "", err
	}
	return MutationOutcome{Applied: true, Durable: commitResult.Durable}, committedVersion, nil
}

func updateNodeAuthCredentialRef(
	cfg *Configuration,
	nodeID string,
	expectedVersion string,
	kind credential.Kind,
	newRef *credential.Ref,
	keyPath string,
	authType string,
	clearKeyPath bool,
	clearLegacyLoginPassword bool,
	clearLegacyPassphrase bool,
	ruleName string,
) (string, error) {
	node, ok := cfg.Nodes.Get(nodeID)
	if !ok {
		return "", fmt.Errorf("resolve node %q for credential update: %w", nodeID, ErrNodeNotFound)
	}

	currentVer, verErr := nodeAuthVersion(cfg, nodeID)
	if verErr != nil {
		return "", verErr
	}
	if expectedVersion != "" {
		expected, expErr := versionFromString(expectedVersion)
		if expErr != nil {
			return "", fmt.Errorf("node %q auth expected version invalid: %w", nodeID, expErr)
		}
		if currentVer != expected {
			return "", fmt.Errorf("authentication for node %q changed: %w", nodeID, ErrConfigConflict)
		}
	}

	identity, ok := cfg.Identities.Get(node.IdentityRef)
	if !ok {
		return "", fmt.Errorf("resolve identity %q for node %q: %w", node.IdentityRef, nodeID, ErrIdentityNotFound)
	}
	identity = cloneIdentity(identity)

	// 检查是否共享：若有多个节点引用该 Identity，分裂出私有副本
	if countNodeReferences(cfg, func(candidate models.Node) bool {
		return candidate.IdentityRef == node.IdentityRef
	}) > 1 {
		node = cloneNode(node)
		node.IdentityRef = privateIdentityReference(cfg, nodeID)
		cfg.Nodes.Set(nodeID, node)
	}

	if err := applyIdentityCredentialRefKind(&identity, kind, newRef, ruleName, node.IdentityRef); err != nil {
		return "", err
	}
	applyIdentityAuthModifications(&identity, keyPath, authType, clearKeyPath, clearLegacyLoginPassword, clearLegacyPassphrase)

	cfg.Identities.Set(node.IdentityRef, identity)

	newVer, verErr := nodeAuthVersion(cfg, nodeID)
	if verErr != nil {
		return "", verErr
	}
	return string(newVer[:]), nil
}

func updateNodeSudoCredentialRef(
	cfg *Configuration,
	nodeID string,
	expectedVersion string,
	newRef *credential.Ref,
) (string, error) {
	node, ok := cfg.Nodes.Get(nodeID)
	if !ok {
		return "", fmt.Errorf("resolve node %q for credential update: %w", nodeID, ErrNodeNotFound)
	}

	currentVer, verErr := nodeSudoVersion(cfg, nodeID)
	if verErr != nil {
		return "", verErr
	}
	if expectedVersion != "" {
		expected, expErr := versionFromString(expectedVersion)
		if expErr != nil {
			return "", fmt.Errorf("node %q sudo expected version invalid: %w", nodeID, expErr)
		}
		if currentVer != expected {
			return "", fmt.Errorf("sudo settings for node %q changed: %w", nodeID, ErrConfigConflict)
		}
	}

	node = cloneNode(node)
	node.PrivilegePasswordRef = newRef.Clone()
	node.SuPwd = ""
	cfg.Nodes.Set(nodeID, node)

	newVer, verErr := nodeSudoVersion(cfg, nodeID)
	if verErr != nil {
		return "", verErr
	}
	return string(newVer[:]), nil
}

// UpdateIdentityCredentialRefAtVersionContext updates the specified credential reference directly on an identity.
func (r *Repository) UpdateIdentityCredentialRefAtVersionContext(
	ctx context.Context,
	identityID string,
	expectedVersion string,
	kind credential.Kind,
	newRef *credential.Ref,
) (MutationOutcome, string, error) {
	return r.updateIdentityCredentialRefAtVersionContext(ctx, credential.Target{IdentityID: identityID, Kind: kind}, expectedVersion, newRef)
}

func (r *Repository) updateIdentityCredentialRefAtVersionContext(ctx context.Context, target credential.Target, expectedVersion string, newRef *credential.Ref) (MutationOutcome, string, error) {
	identityID, kind := target.IdentityID, target.Kind

	if err := kind.Validate(); err != nil {
		return MutationOutcome{}, "", err
	}
	if kind != credential.KindLoginPassword && kind != credential.KindPassphrase &&
		kind != credential.KindTOTPSecret && kind != credential.KindChallengeAnswer {
		return MutationOutcome{}, "", fmt.Errorf("invalid credential kind %q for identity", kind)
	}
	if newRef != nil {
		if err := newRef.Validate(); err != nil {
			return MutationOutcome{}, "", err
		}
	}

	var committedVersion string
	commitResult, err := r.commitResultContext(ctx, anyRevision, func(cfg *Configuration) error {
		identity, ok := cfg.Identities.Get(identityID)
		if !ok {
			return fmt.Errorf("resolve identity %q for credential update: %w", identityID, ErrIdentityNotFound)
		}
		identity = cloneIdentity(identity)

		currentVer, verErr := identityEntityVersion(cfg, identityID)
		if verErr != nil {
			return verErr
		}
		if expectedVersion != "" {
			expected, expErr := versionFromString(expectedVersion)
			if expErr != nil {
				return fmt.Errorf("identity %q expected version invalid: %w", identityID, expErr)
			}
			if currentVer != expected {
				return fmt.Errorf("identity %q changed: %w", identityID, ErrConfigConflict)
			}
		}

		if err := applyIdentityCredentialRefKind(&identity, kind, newRef, target.RuleName, identityID); err != nil {
			return err
		}

		applyIdentityCredentialMetadata(&identity, target)

		cfg.Identities.Set(identityID, identity)

		newVer, verErr := identityEntityVersion(cfg, identityID)
		if verErr != nil {
			return verErr
		}
		committedVersion = string(newVer[:])
		return nil
	})

	if err != nil {
		if commitResult.Applied {
			return MutationOutcome{Applied: true, Durable: false}, committedVersion, err
		}
		return MutationOutcome{Applied: false, Durable: false}, "", err
	}
	return MutationOutcome{Applied: true, Durable: commitResult.Durable}, committedVersion, nil
}

// CheckRefUnreferenced checks whether the given credential reference is unreferenced anywhere
// in the latest active configuration snapshot.
func (r *Repository) loadDiskConfigLocked(ctx context.Context) (*Configuration, error) {
	if ts, ok := r.store.(TransactionStore); ok {
		snap, err := ts.LoadSnapshot(ctx)
		if err != nil {
			return nil, err
		}
		return snap.Configuration, nil
	}
	if r.store != nil {
		return r.store.Load()
	}
	return nil, nil
}

func (r *Repository) syncStoreLocked(ctx context.Context) error {
	hasSynced := false

	// 1. 如果底层存储支持报告耐久性状态（如共享存储或具备状态跟踪的存储）
	if dc, ok := r.store.(DurabilityChecker); ok {
		if !dc.IsDurable() {
			if syncer, ok := r.store.(Syncer); ok {
				if err := syncer.Sync(ctx); err != nil {
					return fmt.Errorf("storage durability sync failed: %w", err)
				}
				hasSynced = true
			}
			if !dc.IsDurable() {
				return fmt.Errorf("authoritative storage remains undurable")
			}
		}
	} else if dcAnon, ok := r.store.(interface{ IsDurable() bool }); ok {
		if !dcAnon.IsDurable() {
			if syncer, ok := r.store.(Syncer); ok {
				if err := syncer.Sync(ctx); err != nil {
					return fmt.Errorf("storage durability sync failed: %w", err)
				}
				hasSynced = true
			}
			if !dcAnon.IsDurable() {
				return fmt.Errorf("authoritative storage remains undurable")
			}
		}
	}

	// 2. 无论是否已检查状态，只要存储实现了 Syncer 接口且尚未同步，必须执行物理介质同步
	if !hasSynced {
		if syncer, ok := r.store.(Syncer); ok {
			if err := syncer.Sync(ctx); err != nil {
				return fmt.Errorf("storage syncer failed: %w", err)
			}
			hasSynced = true
		} else if ds, ok := r.store.(*defaultStore); ok {
			if err := ds.Sync(ctx); err != nil {
				return fmt.Errorf("default store sync failed: %w", err)
			}
			hasSynced = true
		}
	}

	// 3. 若存储层未实现任何持久化同步或耐久性检查接口，且当前实例记录了未决耐久写入，说明无法确认持久化
	if !hasSynced {
		if _, ok := r.store.(interface{ IsDurable() bool }); !ok {
			if r.hasUndurableWrite.Load() {
				return fmt.Errorf("unconfirmed durability write remains pending in current instance")
			}
		}
	}

	// 存储层已成功完成持久化同步，重置本实例未决写入标记
	r.hasUndurableWrite.Store(false)
	return nil
}

// CheckRefUnreferenced checks whether the reference is unreferenced in authoritative storage
// and confirms that this unreferenced state has been durably persisted across processes.
func (r *Repository) CheckRefUnreferenced(ctx context.Context, ref credential.Ref) (bool, error) {
	if ref.IsEmpty() {
		return true, nil
	}
	if ctx == nil {
		return false, fmt.Errorf("configuration ref check context is nil")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}

	if err := r.lockCommit(ctx); err != nil {
		return false, err
	}
	defer r.commitMu.Unlock()

	// 1. 从持久化存储重新加载最新权威配置
	diskCfg, err := r.loadDiskConfigLocked(ctx)
	if err != nil {
		return false, fmt.Errorf("reload configuration snapshot for ref check: %w", err)
	}

	// 2. 检查磁盘权威快照中是否仍然包含该引用
	if diskCfg != nil && isRefReferencedIn(diskCfg, ref) {
		return false, nil
	}

	// 3. 区分过期快照与真正未确认持久化的状态：
	// 仅当本进程处于真正未确认持久化的写入状态（Applied=true, Durable=false）时，
	// 内存快照中的引用才代表未落盘的新增引用；
	// 若本进程无未落盘写入，而磁盘权威配置已无该引用，则内存中若有该引用纯属过期快照（stale snapshot）。
	if r.hasUndurableWrite.Load() {
		memCfg := r.provider.Snapshot()
		if memCfg != nil && isRefReferencedIn(memCfg, ref) {
			return false, nil
		}
	} else if diskCfg != nil {
		memCfg := r.provider.Snapshot()
		if memCfg != nil && isRefReferencedIn(memCfg, ref) {
			// 检测到过期快照，以磁盘权威配置主动刷新内存快照
			if lookup, aliases, err := buildIndexes(diskCfg, false); err == nil {
				r.publish(diskCfg, lookup, aliases)
			}
		}
	}

	// 4. 【核心红线保障】：磁盘权威配置中虽无引用，但该状态必须在跨进程存储层确认已完成持久化同步（Durable）。
	// 若底层存储同步失败或仍处于未持久化状态，绝不能确认解绑，防止因跨 Repository 实例的未 Durable 解绑导致凭据被 GC 提前删除！
	if err := r.syncStoreLocked(ctx); err != nil {
		return false, fmt.Errorf("verify ref unreferenced durability in storage failed: %w", err)
	}

	r.hasUndurableWrite.Store(false)
	return true, nil
}

func isRefReferencedIn(cfg *Configuration, ref credential.Ref) bool {
	if cfg == nil {
		return false
	}
	if cfg.Identities != nil {
		for _, k := range cfg.Identities.Keys() {
			id, ok := cfg.Identities.Get(k)
			if ok && isRefReferencedInIdentity(id, ref) {
				return true
			}
		}
	}

	if cfg.Nodes != nil {
		for _, k := range cfg.Nodes.Keys() {
			node, ok := cfg.Nodes.Get(k)
			if ok && node.PrivilegePasswordRef != nil && *node.PrivilegePasswordRef == ref {
				return true
			}
		}
	}

	return false
}

func isRefReferencedInIdentity(id models.Identity, ref credential.Ref) bool {
	if id.LoginPasswordRef != nil && *id.LoginPasswordRef == ref {
		return true
	}
	if id.PassphraseRef != nil && *id.PassphraseRef == ref {
		return true
	}
	if id.OTP != nil && id.OTP.TOTPSecretRef != nil && *id.OTP.TOTPSecretRef == ref {
		return true
	}
	if id.KeyboardInteractive != nil {
		for _, r := range id.KeyboardInteractive.Rules {
			if r.SecretRef != nil && *r.SecretRef == ref {
				return true
			}
		}
	}
	return false
}

func applyIdentityCredentialRefKind(identity *models.Identity, kind credential.Kind, newRef *credential.Ref, ruleName, identityID string) error {
	switch kind {
	case credential.KindLoginPassword:
		identity.LoginPasswordRef = newRef.Clone()
		identity.Password = ""
		if newRef != nil && !newRef.IsEmpty() && identity.AuthType != "keyboard-interactive" && identity.AuthType != "otp" {
			identity.AuthType = "password"
		}
	case credential.KindPassphrase:
		identity.PassphraseRef = newRef.Clone()
		identity.Passphrase = ""
		if newRef != nil && !newRef.IsEmpty() && identity.AuthType != "keyboard-interactive" && identity.AuthType != "otp" {
			identity.AuthType = "key"
		}
	case credential.KindTOTPSecret:
		return applyIdentityTOTPSecretRef(identity, newRef)
	case credential.KindChallengeAnswer:
		return applyIdentityChallengeAnswerRef(identity, newRef, ruleName, identityID)
	}
	return nil
}

func applyIdentityTOTPSecretRef(identity *models.Identity, newRef *credential.Ref) error {
	if newRef == nil || newRef.IsEmpty() {
		if identity.OTP != nil {
			identity.OTP.TOTPSecretRef = nil
			if strings.TrimSpace(identity.OTP.Command) == "" {
				identity.OTP = nil
			}
		}
		return nil
	}
	if identity.OTP == nil {
		identity.OTP = &models.OTPConfig{}
	}
	identity.OTP.TOTPSecretRef = newRef.Clone()
	identity.OTP.Command = ""
	identity.OTP.Args = nil
	if identity.AuthType == "" {
		identity.AuthType = "otp"
	}
	return nil
}

func applyIdentityChallengeAnswerRef(identity *models.Identity, newRef *credential.Ref, ruleName, identityID string) error {
	if ruleName == "" {
		return fmt.Errorf("challenge_answer credential requires rule_name in target")
	}
	if identity.KeyboardInteractive == nil {
		return fmt.Errorf("challenge rule %q not found in identity %q", ruleName, identityID)
	}
	for i := range identity.KeyboardInteractive.Rules {
		if identity.KeyboardInteractive.Rules[i].Name != ruleName {
			continue
		}
		if newRef == nil || newRef.IsEmpty() {
			identity.KeyboardInteractive.Rules = slices.Delete(identity.KeyboardInteractive.Rules, i, i+1)
			if len(identity.KeyboardInteractive.Rules) == 0 {
				identity.KeyboardInteractive = nil
			}
		} else {
			identity.KeyboardInteractive.Rules[i].SecretRef = newRef.Clone()
		}
		return nil
	}
	return fmt.Errorf("challenge rule %q not found in identity %q", ruleName, identityID)
}

func applyIdentityAuthModifications(identity *models.Identity, keyPath, authType string, clearKeyPath, clearLegacyLoginPassword, clearLegacyPassphrase bool) {
	if keyPath != "" {
		identity.KeyPath = keyPath
	}
	if authType != "" {
		identity.AuthType = authType
	}
	if clearKeyPath {
		identity.KeyPath = ""
	}
	if clearLegacyLoginPassword {
		identity.Password = ""
	}
	if clearLegacyPassphrase {
		identity.Passphrase = ""
	}
}

func equalRef(actual, expected *credential.Ref) bool {
	if expected == nil {
		return actual == nil
	}
	return actual != nil && *actual == *expected
}

func confirmNodeRefDurable(diskCfg *Configuration, target credential.Target, ref *credential.Ref) bool {
	node, ok := diskCfg.Nodes.Get(target.NodeID)
	if !ok {
		return false
	}
	switch target.Kind {
	case credential.KindPrivilegePassword:
		return equalRef(node.PrivilegePasswordRef, ref)
	case credential.KindLoginPassword:
		identity, ok := diskCfg.Identities.Get(node.IdentityRef)
		if !ok {
			return false
		}
		return equalRef(identity.LoginPasswordRef, ref)
	case credential.KindPassphrase:
		identity, ok := diskCfg.Identities.Get(node.IdentityRef)
		if !ok {
			return false
		}
		return equalRef(identity.PassphraseRef, ref)
	case credential.KindTOTPSecret:
		identity, ok := diskCfg.Identities.Get(node.IdentityRef)
		if !ok {
			return false
		}
		if identity.OTP == nil {
			return ref == nil || ref.IsEmpty()
		}
		return equalRef(identity.OTP.TOTPSecretRef, ref)
	case credential.KindChallengeAnswer:
		identity, ok := diskCfg.Identities.Get(node.IdentityRef)
		if !ok {
			return false
		}
		if identity.KeyboardInteractive == nil {
			return ref == nil || ref.IsEmpty()
		}
		for _, r := range identity.KeyboardInteractive.Rules {
			if r.Name == target.RuleName {
				return equalRef(r.SecretRef, ref)
			}
		}
		return ref == nil || ref.IsEmpty()
	}
	return false
}

func confirmIdentityRefDurable(diskCfg *Configuration, target credential.Target, ref *credential.Ref) bool {
	identity, ok := diskCfg.Identities.Get(target.IdentityID)
	if !ok {
		return false
	}
	switch target.Kind {
	case credential.KindLoginPassword:
		return equalRef(identity.LoginPasswordRef, ref)
	case credential.KindPassphrase:
		return equalRef(identity.PassphraseRef, ref)
	case credential.KindTOTPSecret:
		if identity.OTP == nil {
			return ref == nil || ref.IsEmpty()
		}
		return equalRef(identity.OTP.TOTPSecretRef, ref)
	case credential.KindChallengeAnswer:
		if identity.KeyboardInteractive == nil {
			return ref == nil || ref.IsEmpty()
		}
		for _, r := range identity.KeyboardInteractive.Rules {
			if r.Name == target.RuleName {
				return equalRef(r.SecretRef, ref)
			}
		}
		return ref == nil || ref.IsEmpty()
	}
	return false
}

// ConfirmRefDurable 从底层权威持久化存储重新检查指定 target 的凭据引用是否已持久化生效（Durable）。
func (r *Repository) ConfirmRefDurable(ctx context.Context, target credential.Target, ref *credential.Ref) (bool, error) {
	if ctx == nil {
		return false, fmt.Errorf("configuration durability check context is nil")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := r.lockCommit(ctx); err != nil {
		return false, err
	}
	defer r.commitMu.Unlock()

	// 1. 先从底层权威存储读取最新配置并比对引用
	diskCfg, err := r.loadDiskConfigLocked(ctx)
	if err != nil {
		return false, fmt.Errorf("reload configuration snapshot for durability check: %w", err)
	}
	if diskCfg == nil {
		return false, fmt.Errorf("authoritative configuration unavailable")
	}

	var matched bool
	if target.NodeID != "" {
		matched = confirmNodeRefDurable(diskCfg, target, ref)
	} else if target.IdentityID != "" {
		matched = confirmIdentityRefDurable(diskCfg, target, ref)
	}
	if !matched {
		return false, nil
	}

	// 2. 引用在配置中已匹配，必须在持久化层重新完成文件/目录同步，真正确认 Durable
	if err := r.syncStoreLocked(ctx); err != nil {
		// 持久化层未能成功完成同步，不能确认 Durable，返回 false 阻止删除旧凭据
		return false, fmt.Errorf("complete storage durability sync failed: %w", err)
	}

	r.hasUndurableWrite.Store(false)
	return true, nil
}

// RepositoryConfigUpdater adapts a Repository to satisfy credential.ConfigUpdater.
type RepositoryConfigUpdater struct {
	repo *Repository
}

// NewRepositoryConfigUpdater creates a new RepositoryConfigUpdater.
func NewRepositoryConfigUpdater(repo *Repository) *RepositoryConfigUpdater {
	return &RepositoryConfigUpdater{repo: repo}
}

// ApplyCredentialRefAtVersion commits a credential reference mutation to the repository.
func (u *RepositoryConfigUpdater) ApplyCredentialRefAtVersion(
	ctx context.Context,
	target credential.Target,
	expectedVersion string,
	newRef *credential.Ref,
) (credential.MutationOutcome, string, error) {
	if target.NodeID != "" {
		outcome, newVer, err := u.repo.updateNodeCredentialTargetAtVersion(ctx, target, expectedVersion, newRef)
		return credential.MutationOutcome{Applied: outcome.Applied, Durable: outcome.Durable}, newVer, adaptConfigError(err)
	}
	if target.IdentityID != "" {
		outcome, newVer, err := u.repo.updateIdentityCredentialRefAtVersionContext(ctx, target, expectedVersion, newRef)
		return credential.MutationOutcome{Applied: outcome.Applied, Durable: outcome.Durable}, newVer, adaptConfigError(err)
	}
	return credential.MutationOutcome{}, "", fmt.Errorf("target must specify nodeID or identityID")
}

func adaptConfigError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrConfigConflict) {
		return fmt.Errorf("%w: %w", coreauth.ErrConfigConflict, err)
	}
	return err
}

// CheckRefUnreferenced checks whether the reference is unreferenced in the configuration.
func (u *RepositoryConfigUpdater) CheckRefUnreferenced(ctx context.Context, ref credential.Ref) (bool, error) {
	return u.repo.CheckRefUnreferenced(ctx, ref)
}

// ConfirmRefDurable checks whether the reference has become durable in authoritative storage.
func (u *RepositoryConfigUpdater) ConfirmRefDurable(ctx context.Context, target credential.Target, ref *credential.Ref) (bool, error) {
	return u.repo.ConfirmRefDurable(ctx, target, ref)
}

// AsConfigUpdater returns the credential.ConfigUpdater adapter for the repository.
func (r *Repository) AsConfigUpdater() credential.ConfigUpdater {
	return NewRepositoryConfigUpdater(r)
}

func applyIdentityCredentialMetadata(identity *models.Identity, target credential.Target) {
	if target.KeyFingerprint != "" {
		identity.KeyFingerprint = target.KeyFingerprint
	}
	if target.KeyPath != "" {
		identity.KeyPath = target.KeyPath
	}
	if target.AuthType != "" {
		identity.AuthType = target.AuthType
	}
	if target.ClearKeyPath {
		identity.KeyPath = ""
	}
	if target.ClearLegacyLoginPassword {
		identity.Password = ""
	}
	if target.ClearLegacyPassphrase {
		identity.Passphrase = ""
	}
}

func updateNodeAuthCredentialTarget(cfg *Configuration, target credential.Target, expectedVersion string, newRef *credential.Ref) (string, error) {
	version, err := updateNodeAuthCredentialRef(cfg, target.NodeID, expectedVersion, target.Kind, newRef, target.KeyPath, target.AuthType, target.ClearKeyPath, target.ClearLegacyLoginPassword, target.ClearLegacyPassphrase, target.RuleName)
	if err != nil || target.KeyFingerprint == "" {
		return version, err
	}
	node, _ := cfg.Nodes.Get(target.NodeID)
	identity, _ := cfg.Identities.Get(node.IdentityRef)
	identity = cloneIdentity(identity)
	identity.KeyFingerprint = target.KeyFingerprint
	cfg.Identities.Set(node.IdentityRef, identity)
	next, err := nodeAuthVersion(cfg, target.NodeID)
	return string(next[:]), err
}
