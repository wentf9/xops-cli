package config

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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
	Ref     NodeRef
	Outcome MutationOutcome
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
	commitMu   sync.Mutex
	provider   *Provider
	store      Store
	revision   atomic.Uint64
	openSSHErr error
}

var _ ConfigProvider = (*Repository)(nil)

// outcomeStore is retained only for in-memory legacy test doubles while
// callers migrate to TransactionStore. Production FileStore implementations
// use TransactionStore and never reach this branch.
type outcomeStore interface {
	save(*Configuration) (PersistResult, error)
}

// NewRepository creates a durable repository with an optional local OpenSSH
// fallback. OpenSSH parse failures are retained and reported only if a caller
// actually needs the fallback; local xops configuration stays usable.
func NewRepository(cfg *Configuration, store Store) (*Repository, error) {
	parser, err := NewOpenSSHParser()
	if err != nil {
		repository, repositoryErr := newRepository(cfg, store, &OpenSSHParser{cfg: nil})
		if repositoryErr != nil {
			return nil, repositoryErr
		}
		repository.openSSHErr = fmt.Errorf("load openssh config: %w", err)
		return repository, nil
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
	cloned := cloneConfiguration(cfg)
	lookup, aliases, err := buildIndexes(cloned, true)
	if err != nil {
		return nil, fmt.Errorf("validate configuration indexes: %w", err)
	}
	if err := validateConfiguration(cloned); err != nil {
		return nil, err
	}
	return &Repository{
		provider: &Provider{
			cfg:         cloned,
			lookupIndex: lookup,
			aliasIndex:  aliases,
			openSSH:     parser,
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
		IdentityRef string `yaml:"identity_ref"`
		AuthType    string `yaml:"auth_type"`
		Password    string `yaml:"password"`
		KeyPath     string `yaml:"key_path"`
		Passphrase  string `yaml:"passphrase"`
	}{node.IdentityRef, identity.AuthType, identity.Password, identity.KeyPath, identity.Passphrase})
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
		Mode  models.SudoMode `yaml:"mode"`
		SuPwd string          `yaml:"su_pwd"`
	}{node.SudoMode, node.SuPwd})
	if err != nil {
		return Version{}, fmt.Errorf("serialize node %q sudo version: %w", nodeID, err)
	}
	return sha256.Sum256(data), nil
}

// ResolveConnection returns one atomic connection snapshot. Persistent nodes
// receive field versions from the same configuration copy as their values;
// OpenSSH virtual nodes remain read-only and therefore have no UpdateRef.
func (r *Repository) ResolveConnection(nodeID string) (ConnectionSnapshot, error) {
	if r == nil {
		return ConnectionSnapshot{}, fmt.Errorf("configuration repository is nil")
	}

	configuration := r.provider.Snapshot()
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
		return ConnectionSnapshot{
			Node:     cloneNode(node),
			Host:     cloneHost(host),
			Identity: identity,
			UpdateRef: &ConnectionUpdateRef{
				AuthVersion: authVersion,
				SudoVersion: sudoVersion,
			},
		}, nil
	}

	node, host, identity, err := r.provider.Resolve(nodeID)
	if err != nil {
		return ConnectionSnapshot{}, err
	}
	return ConnectionSnapshot{Node: node, Host: host, Identity: identity}, nil
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

func (r *Repository) commitResultContext(ctx context.Context, expectedRevision uint64, fn func(*Configuration) error) (CommitResult, error) {
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
		return r.commitTransactionResult(ctx, store, fn)
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

	r.publish(updated, lookup, aliases)
	commitResult := CommitResult{
		Snapshot: Snapshot{Configuration: cloneConfiguration(updated)},
		Applied:  true,
		Durable:  result.Durable,
	}

	if err != nil {
		return commitResult, &DurabilityError{Err: err}
	}
	if !result.Durable {
		return commitResult, &DurabilityError{Err: fmt.Errorf("configuration store returned an incomplete durability result")}
	}
	return commitResult, nil
}

func (r *Repository) commitTransactionResult(ctx context.Context, store TransactionStore, fn func(*Configuration) error) (CommitResult, error) {
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
	r.publish(updated, lookup, aliases)
	result.Snapshot.Configuration = cloneConfiguration(updated)
	if err != nil {
		return result, &DurabilityError{Err: err}
	}
	if !result.Durable {
		return result, &DurabilityError{Err: fmt.Errorf("configuration transaction returned an incomplete durability result")}
	}
	return result, nil
}

func prepareConfiguration(base *Configuration, fn func(*Configuration) error) (*Configuration, map[string][]string, map[string]string, error) {
	updated := cloneConfiguration(base)
	if err := fn(updated); err != nil {
		return nil, nil, nil, err
	}
	lookup, aliases, err := buildIndexes(updated, true)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("validate configuration indexes: %w", err)
	}
	if err := validateConfiguration(updated); err != nil {
		return nil, nil, nil, err
	}
	return updated, lookup, aliases, nil
}

func (r *Repository) publish(updated *Configuration, lookup map[string][]string, aliases map[string]string) {
	r.provider.mu.Lock()
	r.provider.cfg = updated
	r.provider.lookupIndex = lookup
	r.provider.aliasIndex = aliases
	r.provider.mu.Unlock()
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
		cfg.Identities.Set(identityID, identity)
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
		cfg.Identities.Set(ref.ID, identity)
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
	result, err := r.commitResultContext(ctx, anyRevision, func(cfg *Configuration) error {
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
			cfg.Identities.Set(node.IdentityRef, identity)
		}
		cfg.Nodes.Set(nodeID, cloneNode(node))
		return nil
	})
	mutation.Outcome = MutationOutcome{Applied: result.Applied, Durable: result.Durable}
	if !result.Applied {
		return mutation, err
	}
	version, versionErr := nodeEntityVersion(result.Snapshot.Configuration, nodeID)
	if versionErr != nil {
		return mutation, errors.Join(err, fmt.Errorf("resolve applied node %q version: %w", nodeID, versionErr))
	}
	mutation.Ref = NodeRef{ID: nodeID, Version: version}
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
	return r.replaceNodeContext(ctx, ref, nodeID, node, host, identity)
}

func (r *Repository) replaceNodeContext(ctx context.Context, ref NodeRef, nodeID string, node models.Node, host models.Host, identity models.Identity) error {
	if nodeID == "" {
		return fmt.Errorf("node ID is empty")
	}
	if ref.ID == "" {
		return fmt.Errorf("replace node %q without a versioned reference: %w", nodeID, ErrConfigConflict)
	}
	return r.commitContext(ctx, anyRevision, func(cfg *Configuration) error {
		oldNodeID := ref.ID
		var oldNode models.Node
		if oldNodeID != "" {
			if err := ensureNodeRefs(cfg, []NodeRef{ref}); err != nil {
				return err
			}
			var exists bool
			oldNode, exists = cfg.Nodes.Get(oldNodeID)
			if !exists {
				return fmt.Errorf("resolve node %q for replacement: %w", oldNodeID, ErrNodeNotFound)
			}
			if existingHost, exists := cfg.Hosts.Get(node.HostRef); exists && !reflect.DeepEqual(existingHost, host) {
				hostReferences := countNodeReferences(cfg, func(candidate models.Node) bool {
					return candidate.HostRef == node.HostRef
				})
				if oldNode.HostRef == node.HostRef {
					hostReferences--
				}
				if hostReferences > 0 {
					node.HostRef = privateHostReference(cfg, nodeID)
				}
			}
			if existingIdentity, exists := cfg.Identities.Get(node.IdentityRef); exists && !reflect.DeepEqual(existingIdentity, identity) {
				identityReferences := countNodeReferences(cfg, func(candidate models.Node) bool {
					return candidate.IdentityRef == node.IdentityRef
				})
				if oldNode.IdentityRef == node.IdentityRef {
					identityReferences--
				}
				if identityReferences > 0 {
					node.IdentityRef = privateIdentityReference(cfg, nodeID)
				}
			}
		}
		if oldNodeID != "" && oldNodeID != nodeID {
			if _, exists := cfg.Nodes.Get(nodeID); exists {
				return fmt.Errorf("rename node %q to %q: destination already exists", oldNodeID, nodeID)
			}
		}
		cfg.Hosts.Set(node.HostRef, cloneHost(host))
		cfg.Identities.Set(node.IdentityRef, identity)
		cfg.Nodes.Set(nodeID, cloneNode(node))
		if oldNodeID != "" && oldNodeID != nodeID {
			removeNodeAndUnusedRefs(cfg, oldNodeID)
		} else if oldNodeID != "" {
			removeUnusedRefs(cfg, oldNode.HostRef, oldNode.IdentityRef)
		}
		return nil
	})
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
	if len(refs) == 0 {
		return nil
	}
	return r.commitContext(ctx, anyRevision, func(cfg *Configuration) error {
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
			if _, exists := cfg.Nodes.Get(item.Name); exists {
				result.Skipped++
				continue
			}
			if importErr := reserveOpenSSHAliases(aliases, item); importErr != nil {
				result.Skipped++
				result.Issues = append(result.Issues, ImportIssue{Name: item.Name, Err: importErr})
				continue
			}
			hostRef := "openssh-host:" + item.Name
			identityRef := "openssh-identity:" + item.Name
			item.Node.HostRef = hostRef
			item.Node.IdentityRef = identityRef
			cfg.Hosts.Set(hostRef, cloneHost(item.Host))
			cfg.Identities.Set(identityRef, item.Identity)
			cfg.Nodes.Set(item.Name, cloneNode(item.Node))
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

func reserveOpenSSHAliases(aliases map[string]string, item OpenSSHHost) error {
	for _, alias := range item.Node.Alias {
		if alias == "" {
			continue
		}
		if existingNodeID, exists := aliases[alias]; exists && existingNodeID != item.Name {
			return fmt.Errorf("alias %q is already assigned to node %q", alias, existingNodeID)
		}
	}
	for _, alias := range item.Node.Alias {
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
	candidates := make([]string, 0)
	for _, nodeID := range cfg.Nodes.Keys() {
		node, exists := cfg.Nodes.Get(nodeID)
		if !exists {
			continue
		}
		host, hostExists := cfg.Hosts.Get(node.HostRef)
		identity, identityExists := cfg.Identities.Get(node.IdentityRef)
		if !hostExists || !identityExists || host.Address != hostName {
			continue
		}
		if port != 0 && host.Port != port {
			continue
		}
		if userName != "" && identity.User != userName {
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
func (r *Repository) UpdateAuthAtVersionContext(ctx context.Context, nodeID, authVersion, password, keyPath, passphrase string) error {
	expected, err := versionFromString(authVersion)
	if err != nil {
		return fmt.Errorf("update authentication for node %q: %w", nodeID, err)
	}
	return r.commitContext(ctx, anyRevision, func(cfg *Configuration) error {
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
			return nil
		}
		if countNodeReferences(cfg, func(candidate models.Node) bool {
			return candidate.IdentityRef == node.IdentityRef
		}) > 1 {
			node.IdentityRef = privateIdentityReference(cfg, nodeID)
			cfg.Nodes.Set(nodeID, node)
		}
		cfg.Identities.Set(node.IdentityRef, identity)
		return nil
	})
}

// UpdateSudoAtVersionContext updates only sudo fields that still match the
// connection snapshot. It may merge with unrelated node or identity changes.
func (r *Repository) UpdateSudoAtVersionContext(ctx context.Context, nodeID, sudoVersion string, mode models.SudoMode, suPwd string) error {
	expected, err := versionFromString(sudoVersion)
	if err != nil {
		return fmt.Errorf("update sudo for node %q: %w", nodeID, err)
	}
	return r.commitContext(ctx, anyRevision, func(cfg *Configuration) error {
		current, err := nodeSudoVersion(cfg, nodeID)
		if err != nil || current != expected {
			return fmt.Errorf("sudo settings for node %q changed during connection: %w", nodeID, ErrConfigConflict)
		}
		node, ok := cfg.Nodes.Get(nodeID)
		if !ok {
			return fmt.Errorf("resolve node %q for sudo update: %w", nodeID, ErrNodeNotFound)
		}
		if mode != "" {
			node.SudoMode = mode
		}
		if suPwd != "" {
			node.SuPwd = suPwd
		}
		cfg.Nodes.Set(nodeID, node)
		return nil
	})
}

func (r *Repository) Resolve(nodeID string) (models.Node, models.Host, models.Identity, error) {
	return r.provider.Resolve(nodeID)
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
	nodeID, err := r.provider.ResolveSelector(input)
	if err != nil || nodeID != "" || r.openSSHErr == nil {
		return nodeID, err
	}
	return "", fmt.Errorf("resolve openssh selector %q: %w", input, r.openSSHErr)
}

func (r *Repository) FindAlias(alias string) string {
	return r.provider.FindAlias(alias)
}

func (r *Repository) Snapshot() *Configuration {
	return r.provider.Snapshot()
}

func validateConfiguration(cfg *Configuration) error {
	for _, nodeID := range cfg.Nodes.Keys() {
		node, ok := cfg.Nodes.Get(nodeID)
		if !ok {
			continue
		}
		if _, ok := cfg.Hosts.Get(node.HostRef); !ok {
			return fmt.Errorf("node %q host ref %q: %w", nodeID, node.HostRef, ErrHostNotFound)
		}
		if _, ok := cfg.Identities.Get(node.IdentityRef); !ok {
			return fmt.Errorf("node %q identity ref %q: %w", nodeID, node.IdentityRef, ErrIdentityNotFound)
		}
	}
	return nil
}
