package config

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/models"
)

// PendingLease scopes a pending node registration or staged saved-node update.
// Discard is intentionally not exported: WithPendingNode automatically discards
// any unconfirmed pending state when its callback returns (including on error,
// context cancellation, or panic).
type PendingLease interface {
	NodeID() string
	Confirm(ctx context.Context) error
}

// PendingExecutionLease is an optional extension of PendingLease implemented by
// leases that can persist an enrollment-probed ExecutionConfig atomically in
// the same confirmation transaction.
type PendingExecutionLease interface {
	PendingLease
	ConfirmWithExecution(ctx context.Context, execution *ssh.ExecutionConfig) error
}

// PendingNodeProvider supports scoped pending connection leases.
type PendingNodeProvider interface {
	WithPendingNode(ctx context.Context, req EnsureNodeOptions, fn func(PendingLease) error) error
}

type noopPendingLease struct {
	nodeID string
}

func (l noopPendingLease) NodeID() string {
	return l.nodeID
}

func (l noopPendingLease) Confirm(context.Context) error {
	return nil
}

// WithPendingNode scopes pending node preparation and automatic cleanup to fn.
// When provider implements PendingNodeProvider (such as *Repository or an
// OpenSSH -F override provider), unconfirmed pending registrations are always
// discarded on return, error, cancellation, or panic. Plain read-only providers
// resolve req.Target and invoke fn with a no-op PendingLease.
func WithPendingNode(ctx context.Context, provider ConfigProvider, req EnsureNodeOptions, fn func(PendingLease) error) error {
	if ctx == nil || provider == nil || fn == nil {
		return fmt.Errorf("with pending node requires context, provider, and callback")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("prepare connection canceled: %w", err)
	}
	if pnp, ok := provider.(PendingNodeProvider); ok {
		return pnp.WithPendingNode(ctx, req, fn)
	}
	return withReadOnlyPendingNode(provider, req, fn)
}

func withReadOnlyPendingNode(provider ConfigProvider, req EnsureNodeOptions, fn func(PendingLease) error) error {
	r, cfg := resolveTargetHelper(provider)
	if r == nil || cfg == nil {
		return fmt.Errorf("configuration snapshot is nil")
	}
	lookup, aliases, err := buildIndexes(cfg, false)
	if err != nil {
		return fmt.Errorf("build configuration indexes failed: %w", err)
	}
	defaultUser := strings.TrimSpace(req.DefaultUser)
	decision, err := r.evaluateTargetDecision(cfg, lookup, aliases, req.Target, defaultUser)
	if err != nil {
		return err
	}
	effectiveTarget := applyReadOnlyExistingUpdateJump(decision, req.ExistingUpdate)
	var resolved ResolvedTarget
	if !decision.NeedsCreation {
		resolved, err = r.buildMatchedResolvedTarget(provider, decision.MatchedNodeID, decision.BaseNodeID, decision.OpenSSHAlias, decision.CanonicalHost, effectiveTarget, defaultUser)
	} else {
		resolved, err = r.buildCreatedResolvedTargetWithUserPort(provider, cfg, decision.Canonical, decision.EffectiveUser, decision.EffectivePort, effectiveTarget)
	}
	if err != nil {
		return err
	}
	if err := validateReadOnlyPendingUpdateJump(provider, req, resolved); err != nil {
		return err
	}
	nodeID := resolved.NodeID
	if resolved.MatchedNodeID != "" {
		nodeID = resolved.MatchedNodeID
	}
	return fn(noopPendingLease{nodeID: nodeID})
}

func applyReadOnlyExistingUpdateJump(decision targetDecision, upd PendingNodeUpdate) ConnectionTarget {
	effectiveTarget := decision.NormalizedTarget
	if !decision.NeedsCreation && upd.Enabled && !IsOpenSSHNodeID(decision.MatchedNodeID) &&
		upd.JumpHost != "" && !effectiveTarget.HasProxyJump && effectiveTarget.ProxyJump == "" {
		effectiveTarget.ProxyJump = upd.JumpHost
		effectiveTarget.HasProxyJump = true
	}
	return effectiveTarget
}

func validateReadOnlyPendingUpdateJump(provider ConfigProvider, req EnsureNodeOptions, resolved ResolvedTarget) error {
	if req.ExistingUpdate.JumpHost == "" {
		return nil
	}
	resolvedJump, err := provider.ResolveProxyJumpChain(req.ExistingUpdate.JumpHost)
	if err != nil {
		return fmt.Errorf("resolve proxy jump %q failed: %w", req.ExistingUpdate.JumpHost, err)
	}
	destID := resolved.NodeID
	if resolved.MatchedNodeID != "" {
		destID = resolved.MatchedNodeID
	}
	dest := ProxyJumpTarget{
		NodeID:        destID,
		Selector:      strings.TrimSpace(req.Target.Selector),
		OpenSSHAlias:  strings.TrimSpace(resolved.OpenSSHAlias),
		CanonicalHost: strings.TrimSpace(resolved.CanonicalHost),
		Host:          strings.TrimSpace(resolved.Host),
		Port:          resolved.Port,
		User:          strings.TrimSpace(resolved.User),
		IsAdHoc:       resolved.Created && resolved.OpenSSHAlias == "",
	}
	return ValidateProxyJumpChainCycle(provider, dest, resolvedJump, req.ExistingUpdate.JumpHost)
}

func equalPersistedNode(a, b models.Node) bool {
	a.OpenSSHAlias = ""
	b.OpenSSHAlias = ""
	a.CanonicalHost = ""
	b.CanonicalHost = ""
	if !a.SSHOptions.Equal(b.SSHOptions) {
		return false
	}
	a.SSHOptions = nil
	b.SSHOptions = nil
	return reflect.DeepEqual(a, b)
}

type pendingConnection struct {
	provider   *Provider // immutable connection bundle
	provenance NodeProvenance
	gate       *contextGate
	refs       int
	isUpdate   bool
	baseRef    NodeRef
}

type repositoryPendingLease struct {
	repo      *Repository
	nodeID    string
	entry     *pendingConnection
	mu        sync.Mutex
	confirmed bool
	closed    bool
}

var (
	_ PendingLease          = (*repositoryPendingLease)(nil)
	_ PendingExecutionLease = (*repositoryPendingLease)(nil)
)

func (l *repositoryPendingLease) NodeID() string {
	if l == nil {
		return ""
	}
	return l.nodeID
}

func (l *repositoryPendingLease) Confirm(ctx context.Context) error {
	return l.confirm(ctx, nil)
}

func (l *repositoryPendingLease) ConfirmWithExecution(ctx context.Context, execution *ssh.ExecutionConfig) error {
	execution = execution.Clone()
	if err := execution.Validate(); err != nil {
		return fmt.Errorf("validate enrollment execution: %w", err)
	}
	return l.confirm(ctx, execution)
}

func (l *repositoryPendingLease) confirm(ctx context.Context, execution *ssh.ExecutionConfig) error {
	if l == nil || l.repo == nil {
		return fmt.Errorf("confirm connection requires repository")
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return fmt.Errorf("pending lease for %q is closed", l.nodeID)
	}
	if l.confirmed || l.entry == nil {
		l.mu.Unlock()
		return nil
	}
	entry := l.entry
	nodeID := l.nodeID
	l.mu.Unlock()

	if err := l.repo.confirmPendingEntry(ctx, nodeID, entry, execution); err != nil {
		return err
	}
	l.mu.Lock()
	l.confirmed = true
	l.mu.Unlock()
	return nil
}

// WithPendingNode resolves a connection without writing configuration and
// executes fn with a scoped PendingLease. New nodes and staged updates to
// existing saved nodes are visible only through Resolve and ResolveConnection
// until lease.Confirm succeeds; snapshots, selectors, and unrelated
// transactions contain saved nodes only. If fn returns (normally, with an
// error, after cancellation, or via panic) without a successful Confirm, the
// pending entry is automatically discarded.
func (r *Repository) WithPendingNode(ctx context.Context, req EnsureNodeOptions, fn func(PendingLease) error) error {
	if r == nil || ctx == nil || fn == nil {
		return fmt.Errorf("prepare connection requires repository, context, and callback")
	}
	res, entry, err := r.prepareNodeContext(ctx, req)
	if err != nil {
		return err
	}
	lease := &repositoryPendingLease{
		repo:   r,
		nodeID: res.NodeID,
		entry:  entry,
	}
	defer func() {
		lease.mu.Lock()
		wasConfirmed := lease.confirmed
		lease.closed = true
		lease.mu.Unlock()
		if !wasConfirmed && entry != nil {
			r.discardPendingEntry(res.NodeID, entry)
		}
	}()
	return fn(lease)
}

// IsPendingNode reports whether nodeID currently has an active unconfirmed
// pending connection (either a new node or a staged saved-node update).
func (r *Repository) IsPendingNode(nodeID string) bool {
	if r == nil || nodeID == "" {
		return false
	}
	r.pendingMu.RLock()
	defer r.pendingMu.RUnlock()
	return r.pending[nodeID] != nil
}

func (r *Repository) prepareNodeContext(ctx context.Context, opts EnsureNodeOptions) (EnsureNodeResult, *pendingConnection, error) {
	if r == nil || ctx == nil {
		return EnsureNodeResult{}, nil, fmt.Errorf("prepare connection requires repository and context")
	}
	if err := ctx.Err(); err != nil {
		return EnsureNodeResult{}, nil, fmt.Errorf("prepare connection canceled: %w", err)
	}
	selector := strings.TrimSpace(opts.Target.Selector)
	if selector == "" {
		return EnsureNodeResult{}, nil, fmt.Errorf("target selector is empty")
	}
	r.pendingMu.Lock()
	defer r.pendingMu.Unlock()
	defaultUser := strings.TrimSpace(opts.DefaultUser)
	snap := r.provider.Snapshot()
	if decision, err := r.findExistingNodeDecisionWithSnapshot(snap, opts.Target, defaultUser); err != nil {
		return EnsureNodeResult{}, nil, err
	} else if !decision.NeedsCreation && decision.MatchedNodeID != "" {
		return r.prepareExistingNodeLocked(snap, decision, opts)
	}
	var outcome ensureTransactionOutcome
	cfg, _, _, err := prepareConfiguration(snap, func(cfg *Configuration) error {
		return r.ensureTargetInTransaction(cfg, opts, defaultUser, &outcome)
	})
	if err != nil {
		return EnsureNodeResult{}, nil, err
	}
	nodeID := outcome.nodeID
	created := outcome.created
	if created {
		effectiveID, entry, err := r.registerPendingConnection(cfg, nodeID, outcome.openSSHAlias, outcome.canonicalHost)
		if err != nil {
			return EnsureNodeResult{}, nil, err
		}
		return EnsureNodeResult{NodeID: effectiveID, Created: true}, entry, nil
	}
	r.provider.setSavedNodeOpenSSHMetadataIfPresent(nodeID, outcome.openSSHAlias, outcome.canonicalHost)
	return EnsureNodeResult{NodeID: nodeID, Created: false}, nil, nil
}

func (r *Repository) validateExistingNodeJumpLocked(snap *Configuration, decision targetDecision, opts EnsureNodeOptions) (string, error) {
	id := decision.MatchedNodeID
	effectiveDecision := decision
	if opts.ExistingUpdate.Enabled && !IsOpenSSHNodeID(id) && opts.ExistingUpdate.JumpHost != "" &&
		!effectiveDecision.NormalizedTarget.HasProxyJump && effectiveDecision.NormalizedTarget.ProxyJump == "" {
		effectiveDecision.NormalizedTarget.ProxyJump = opts.ExistingUpdate.JumpHost
		effectiveDecision.NormalizedTarget.HasProxyJump = true
	}
	destTarget, err := r.validateMatchedDecisionJumpReturningDest(snap, effectiveDecision, opts.DefaultUser)
	if err != nil {
		return "", err
	}
	if opts.ExistingUpdate.JumpHost == "" {
		return "", nil
	}
	resolvedJump, err := r.resolveProxyJumpChain(snap, opts.ExistingUpdate.JumpHost)
	if err != nil {
		return "", fmt.Errorf("resolve proxy jump %q failed: %w", opts.ExistingUpdate.JumpHost, err)
	}
	if cErr := validateProxyJumpChainCycleWithConfig(snap, r.openSSHParserOrNil(), destTarget, resolvedJump, opts.ExistingUpdate.JumpHost); cErr != nil {
		return "", cErr
	}
	return resolvedJump, nil
}

func (r *Repository) prepareExistingNodeLocked(snap *Configuration, decision targetDecision, opts EnsureNodeOptions) (EnsureNodeResult, *pendingConnection, error) {
	id := decision.MatchedNodeID
	resolvedJump, err := r.validateExistingNodeJumpLocked(snap, decision, opts)
	if err != nil {
		return EnsureNodeResult{}, nil, err
	}
	if !opts.ExistingUpdate.Enabled || IsOpenSSHNodeID(id) {
		r.syncPreparedExistingMetadataLocked(decision)
		return EnsureNodeResult{NodeID: id}, nil, nil
	}
	ver, err := nodeEntityVersion(snap, id)
	if err != nil {
		return EnsureNodeResult{}, nil, fmt.Errorf("resolve node %q reference: %w", id, err)
	}
	baseRef := NodeRef{ID: id, Version: ver}
	node, host, identity, err := r.provider.Resolve(id)
	if err != nil {
		return EnsureNodeResult{}, nil, fmt.Errorf("resolve node %q for update failed: %w", id, err)
	}
	origNode := cloneNode(node)
	origHost := cloneHost(host)
	origIdentity := cloneIdentity(identity)
	changed, err := applyPendingNodeUpdate(r.provider, id, &node, &identity, opts.ExistingUpdate, resolvedJump)
	if err != nil {
		return EnsureNodeResult{}, nil, err
	}
	if !changed {
		r.syncPreparedExistingMetadataLocked(decision)
		return EnsureNodeResult{NodeID: id}, nil, nil
	}
	// Validate the staged update against the full configuration graph (including
	// ProxyJump cycle detection and strict alias rules) before dialing, without
	// writing anything to disk until Confirm succeeds. Capture the exact staged
	// (node, host, identity) produced by replaceNodeAtRef so any forked
	// IdentityRef/HostRef from detachSharedNodeRefs is reflected consistently in
	// pending.provider and AuthVersion computation before and after Confirm.
	stagedNode := cloneNode(node)
	stagedNode.OpenSSHAlias = ""
	stagedNode.CanonicalHost = ""
	stagedCfg, _, _, err := prepareConfiguration(snap, func(cfg *Configuration) error {
		if err := replaceNodeAtRef(cfg, baseRef, id, stagedNode, host, identity); err != nil {
			return err
		}
		return r.revalidateStagedAliasUpdateJumpLocked(cfg, id, decision, opts)
	})
	if err != nil {
		return EnsureNodeResult{}, nil, fmt.Errorf("validate staged update for node %q: %w", id, err)
	}
	stagedNode, ok := stagedCfg.Nodes.Get(id)
	if !ok {
		return EnsureNodeResult{}, nil, fmt.Errorf("resolve staged node %q: %w", id, ErrNodeNotFound)
	}
	stagedHost, ok := stagedCfg.Hosts.Get(stagedNode.HostRef)
	if !ok {
		return EnsureNodeResult{}, nil, fmt.Errorf("resolve staged host %q for node %q: %w", stagedNode.HostRef, id, ErrHostNotFound)
	}
	stagedIdentity, ok := stagedCfg.Identities.Get(stagedNode.IdentityRef)
	if !ok {
		return EnsureNodeResult{}, nil, fmt.Errorf("resolve staged identity %q for node %q: %w", stagedNode.IdentityRef, id, ErrIdentityNotFound)
	}
	routingChanged := NodeJumpRoutingChanged(id, origNode, origHost, origIdentity, id, stagedNode, stagedHost, stagedIdentity)
	if err := r.validateStagedSavedNodeJumpCycle(stagedCfg, id, stagedNode, stagedHost, stagedIdentity, decision.OpenSSHAlias, decision.CanonicalHost, decision.NormalizedTarget.Selector, routingChanged); err != nil {
		return EnsureNodeResult{}, nil, fmt.Errorf("validate staged update for node %q: %w", id, err)
	}
	entry, err := r.registerPendingUpdateLocked(id, baseRef, stagedNode, stagedHost, stagedIdentity, decision.OpenSSHAlias, decision.CanonicalHost)
	if err != nil {
		return EnsureNodeResult{}, nil, err
	}
	return EnsureNodeResult{NodeID: id}, entry, nil
}

func (r *Repository) revalidateStagedAliasUpdateJumpLocked(
	cfg *Configuration,
	id string,
	decision targetDecision,
	opts EnsureNodeOptions,
) error {
	if opts.ExistingUpdate.Alias == "" || opts.ExistingUpdate.JumpHost == "" {
		return nil
	}
	reResolved, rErr := r.resolveProxyJumpChain(cfg, opts.ExistingUpdate.JumpHost)
	if rErr != nil {
		return fmt.Errorf("resolve proxy jump %q failed: %w", opts.ExistingUpdate.JumpHost, rErr)
	}
	cur, ok := cfg.Nodes.Get(id)
	if !ok {
		return nil
	}
	if reResolved != "" {
		cur.ProxyJump = reResolved
		cfg.Nodes.Set(id, cur)
	}
	h, hOK := cfg.Hosts.Get(cur.HostRef)
	ident, iOK := cfg.Identities.Get(cur.IdentityRef)
	if !hOK || !iOK {
		return nil
	}
	return r.validateStagedSavedNodeJumpCycle(cfg, id, cur, h, ident, decision.OpenSSHAlias, decision.CanonicalHost, decision.NormalizedTarget.Selector, true)
}

func (r *Repository) validateSavedNodeJumpWithOrigin(
	cfg *Configuration,
	nodeID string,
	node models.Node,
	host models.Host,
	identity models.Identity,
	openSSHAlias, canonicalHost, selector string,
) error {
	ps, err := parseOptionalNodeProxyJump(node.ProxyJump)
	if err != nil {
		return err
	}
	targets, ok := ps.JumpTargets()
	if !ok {
		return nil
	}
	openSSH := r.openSSHParserOrNil()
	dest := buildProxyJumpTargetFromSavedNode(nodeID, openSSHAlias, canonicalHost, selector, host, identity)
	resolvedJump, rErr := resolveBaseTargetJumpWithConfig(cfg, openSSH, dest, targets)
	if rErr != nil {
		return rErr
	}
	return validateProxyJumpChainCycleWithConfig(cfg, openSSH, dest, resolvedJump, node.ProxyJump)
}

func (r *Repository) validateStagedSavedNodeJumpCycle(
	cfg *Configuration,
	nodeID string,
	node models.Node,
	host models.Host,
	identity models.Identity,
	openSSHAlias, canonicalHost, selector string,
	routingChanged bool,
) error {
	if strings.TrimSpace(node.ProxyJump) != "" {
		if err := r.validateSavedNodeJumpWithOrigin(cfg, nodeID, node, host, identity, openSSHAlias, canonicalHost, selector); err != nil {
			return err
		}
	}
	if routingChanged {
		if err := ValidateSavedNodeJumpCycleWithOpenSSH(cfg, r.openSSHParserOrNil(), nodeID); err != nil {
			return err
		}
	}
	return nil
}

func applyPendingNodeUpdate(
	provider *Provider,
	nodeID string,
	node *models.Node,
	identity *models.Identity,
	upd PendingNodeUpdate,
	resolvedJump string,
) (bool, error) {
	changed := false
	if resolvedJump != "" && resolvedJump != node.ProxyJump {
		node.ProxyJump = resolvedJump
		changed = true
	}
	if upd.Alias != "" {
		if err := ValidateNodeAlias(upd.Alias); err != nil {
			return false, err
		}
		if existing := provider.FindAlias(upd.Alias); existing == "" || existing == nodeID {
			if !slices.Contains(node.Alias, upd.Alias) {
				node.Alias = append(node.Alias, upd.Alias)
				changed = true
			}
		}
	}
	if len(upd.Tags) > 0 {
		for _, tag := range upd.Tags {
			if tag != "" && !slices.Contains(node.Tags, tag) {
				node.Tags = append(node.Tags, tag)
				changed = true
			}
		}
	}
	if upd.RememberAuth && applyPendingNodeAuthUpdate(node, identity, upd) {
		changed = true
	}
	return changed, nil
}

func applyPendingNodeAuthUpdate(node *models.Node, identity *models.Identity, upd PendingNodeUpdate) bool {
	changed := false
	if upd.HasPassword {
		if identity.AuthType != "password" {
			identity.AuthType = "password"
			changed = true
		}
	} else if absKey := NormalizePersistableIdentityPath(upd.IdentityFile); absKey != "" {
		if identity.KeyPath != absKey || identity.AuthType != "key" {
			identity.KeyPath = absKey
			identity.AuthType = "key"
			changed = true
		}
	}
	if upd.SudoMode != "" && upd.SudoMode != models.SudoModeNone && upd.SudoMode != models.SudoModeAuto && node.SudoMode != upd.SudoMode {
		node.SudoMode = upd.SudoMode
		changed = true
	}
	return changed
}

func (r *Repository) registerPendingUpdateLocked(
	nodeID string,
	baseRef NodeRef,
	node models.Node,
	host models.Host,
	identity models.Identity,
	openSSHAlias, canonicalHost string,
) (*pendingConnection, error) {
	if r.pending == nil {
		r.pending = make(map[string]*pendingConnection)
	}
	origin := normalizeOpenSSHOrigin(OpenSSHOrigin{
		Alias:         openSSHAlias,
		CanonicalHost: canonicalHost,
	})
	if origin.IsZero() && r.provider != nil {
		origin = r.provider.NodeOpenSSHOrigin(nodeID)
	}
	node.OpenSSHAlias = origin.Alias
	node.CanonicalHost = origin.CanonicalHost
	if previous := r.pending[nodeID]; previous != nil {
		if previous.isUpdate && previous.baseRef == baseRef {
			oldNode, oldHost, oldIdentity, err := previous.provider.Resolve(nodeID)
			if err == nil && equalPersistedNode(oldNode, node) && reflect.DeepEqual(oldHost, host) && reflect.DeepEqual(oldIdentity, identity) {
				previous.refs++
				return previous, nil
			}
		}
		return nil, fmt.Errorf("pending update for node %q conflicts with active pending connection: %w", nodeID, ErrConfigConflict)
	}
	pending := cloneConfiguration(nil)
	pending.Nodes.Set(nodeID, cloneNode(node))
	pending.Hosts.Set(node.HostRef, cloneHost(host))
	pending.Identities.Set(node.IdentityRef, cloneIdentity(identity))
	pendingProvider := NewProviderWithoutOpenSSH(pending)
	if !origin.IsZero() {
		pendingProvider.SetNodeOpenSSHOrigin(nodeID, origin)
	}
	entry := &pendingConnection{
		provider:   pendingProvider,
		provenance: ProvenanceSavedManaged,
		gate:       &contextGate{},
		refs:       1,
		isUpdate:   true,
		baseRef:    baseRef,
	}
	r.pending[nodeID] = entry
	return entry, nil
}

func (r *Repository) registerPendingConnection(cfg *Configuration, nodeID, openSSHAlias, canonicalHost string) (string, *pendingConnection, error) {
	// Retain only this connection's entities, never a stale copy of the
	// whole configuration that could overwrite concurrent changes.
	node, _ := cfg.Nodes.Get(nodeID)
	node.OpenSSHAlias = openSSHAlias
	node.CanonicalHost = canonicalHost
	host, _ := cfg.Hosts.Get(node.HostRef)
	identity, _ := cfg.Identities.Get(node.IdentityRef)
	if r.pending == nil {
		r.pending = make(map[string]*pendingConnection)
	}
	if previous := r.pending[nodeID]; previous != nil {
		if existingID, entry, handled, err := r.tryReuseOrDisambiguatePending(cfg, previous, nodeID, node, host, identity); handled || err != nil {
			return existingID, entry, err
		}
		nodeID = OpenSSHNodePrefix + FormatNodeID(identity.User, node.OpenSSHAlias, host.Port)
	}
	// Concurrent first connections on different ports must not reserve the
	// same identity and later share (or conflict over) remembered secrets.
	node.IdentityRef = privateIdentityReference(cfg, nodeID)
	pending := cloneConfiguration(nil)
	pending.Nodes.Set(nodeID, node)
	pending.Hosts.Set(node.HostRef, host)
	pending.Identities.Set(node.IdentityRef, identity)
	pendingProvider := NewProviderWithoutOpenSSH(pending)
	prov := ProvenanceAdHocPending
	origin := normalizeOpenSSHOrigin(OpenSSHOrigin{
		Alias:         node.OpenSSHAlias,
		CanonicalHost: node.CanonicalHost,
	})
	if !origin.IsZero() {
		pendingProvider.SetNodeOpenSSHOrigin(nodeID, origin)
		if origin.Alias != "" && node.SSHOptions == nil {
			prov = ProvenanceOpenSSHDerived
		}
	}
	entry := &pendingConnection{provider: pendingProvider, provenance: prov, gate: &contextGate{}, refs: 1}
	r.pending[nodeID] = entry
	return nodeID, entry, nil
}

func (r *Repository) tryReuseOrDisambiguatePending(
	cfg *Configuration,
	previous *pendingConnection,
	nodeID string,
	node models.Node,
	host models.Host,
	identity models.Identity,
) (string, *pendingConnection, bool, error) {
	if previous.isUpdate {
		return "", nil, false, fmt.Errorf("pending connection %q changed: %w", nodeID, ErrConfigConflict)
	}
	oldNode, oldHost, oldIdentity, err := previous.provider.Resolve(nodeID)
	if err != nil {
		return "", nil, false, fmt.Errorf("resolve pending connection %q: %w", nodeID, err)
	}
	normalizedNode := node
	normalizedNode.IdentityRef = privateIdentityReference(cfg, nodeID)
	if equalPersistedNode(oldNode, normalizedNode) && reflect.DeepEqual(oldHost, host) && reflect.DeepEqual(oldIdentity, identity) {
		if oldNode.OpenSSHAlias == node.OpenSSHAlias && oldNode.CanonicalHost == node.CanonicalHost {
			previous.refs++
			return nodeID, previous, true, nil
		}
		if upgradedID, entry, ok := r.upgradePendingAliasAndCanonical(previous, nodeID, oldNode, normalizedNode, host, identity); ok {
			return upgradedID, entry, true, nil
		}
	}
	if node.OpenSSHAlias == "" || oldNode.OpenSSHAlias == node.OpenSSHAlias {
		return "", nil, false, fmt.Errorf("pending connection %q changed: %w", nodeID, ErrConfigConflict)
	}
	altID := OpenSSHNodePrefix + FormatNodeID(identity.User, node.OpenSSHAlias, host.Port)
	altPrev := r.pending[altID]
	if altPrev == nil {
		return "", nil, false, nil
	}
	altOldNode, altOldHost, altOldIdentity, altErr := altPrev.provider.Resolve(altID)
	if altErr != nil {
		return "", nil, false, fmt.Errorf("resolve pending connection %q: %w", altID, altErr)
	}
	altNormalized := node
	altNormalized.IdentityRef = privateIdentityReference(cfg, altID)
	if !equalPersistedNode(altOldNode, altNormalized) || !reflect.DeepEqual(altOldHost, host) || !reflect.DeepEqual(altOldIdentity, identity) {
		return "", nil, false, fmt.Errorf("pending connection %q changed: %w", altID, ErrConfigConflict)
	}
	if altOldNode.OpenSSHAlias == node.OpenSSHAlias && altOldNode.CanonicalHost == node.CanonicalHost {
		altPrev.refs++
		return altID, altPrev, true, nil
	}
	if upgradedID, entry, ok := r.upgradePendingAliasAndCanonical(altPrev, altID, altOldNode, altNormalized, host, identity); ok {
		return upgradedID, entry, true, nil
	}
	return "", nil, false, fmt.Errorf("pending connection %q changed: %w", altID, ErrConfigConflict)
}

func (r *Repository) upgradePendingAliasAndCanonical(
	previous *pendingConnection,
	nodeID string,
	oldNode, normalizedNode models.Node,
	host models.Host,
	identity models.Identity,
) (string, *pendingConnection, bool) {
	aliasUpgradable := oldNode.OpenSSHAlias == normalizedNode.OpenSSHAlias || (oldNode.OpenSSHAlias == "" && normalizedNode.OpenSSHAlias != "")
	canonUpgradable := oldNode.CanonicalHost == normalizedNode.CanonicalHost || (oldNode.CanonicalHost == "" && normalizedNode.CanonicalHost != "")
	if !aliasUpgradable || !canonUpgradable {
		return "", nil, false
	}
	pending := cloneConfiguration(nil)
	pending.Nodes.Set(nodeID, normalizedNode)
	pending.Hosts.Set(normalizedNode.HostRef, host)
	pending.Identities.Set(normalizedNode.IdentityRef, identity)
	upgradedProvider := NewProviderWithoutOpenSSH(pending)
	upgradedOrigin := normalizeOpenSSHOrigin(OpenSSHOrigin{
		Alias:         normalizedNode.OpenSSHAlias,
		CanonicalHost: normalizedNode.CanonicalHost,
	})
	if !upgradedOrigin.IsZero() {
		upgradedProvider.SetNodeOpenSSHOrigin(nodeID, upgradedOrigin)
	}
	prov := previous.provenance
	if normalizedNode.SSHOptions == nil && upgradedOrigin.Alias != "" {
		prov = ProvenanceOpenSSHDerived
	}
	gate := previous.gate
	if gate == nil {
		gate = &contextGate{}
	}
	refs := previous.refs
	if refs < 1 {
		refs = 1
	}
	upgraded := &pendingConnection{provider: upgradedProvider, provenance: prov, gate: gate, refs: refs + 1}
	r.pending[nodeID] = upgraded
	return nodeID, upgraded, true
}

func (r *Repository) connectionProviderWithProvenance(nodeID string) (*Provider, NodeProvenance) {
	r.pendingMu.RLock()
	defer r.pendingMu.RUnlock()
	if pending := r.pending[nodeID]; pending != nil {
		return pending.provider, pending.provenance
	}
	return r.provider, ProvenanceUnknown
}

func (r *Repository) resolvePendingNode(nodeID string) (models.Node, models.Host, models.Identity, bool) {
	if r == nil || nodeID == "" {
		return models.Node{}, models.Host{}, models.Identity{}, false
	}
	r.pendingMu.RLock()
	pending := r.pending[nodeID]
	r.pendingMu.RUnlock()
	if pending == nil || pending.provider == nil {
		return models.Node{}, models.Host{}, models.Identity{}, false
	}
	node, host, ident, err := pending.provider.Resolve(nodeID)
	if err != nil {
		return models.Node{}, models.Host{}, models.Identity{}, false
	}
	return node, host, ident, true
}

func (r *Repository) pendingConnectionSnapshot(nodeID string) (ConnectionSnapshot, bool) {
	if r == nil || nodeID == "" {
		return ConnectionSnapshot{}, false
	}
	r.pendingMu.RLock()
	pending := r.pending[nodeID]
	var (
		provider *Provider
		prov     NodeProvenance
	)
	if pending != nil {
		provider = pending.provider
		prov = pending.provenance
	}
	r.pendingMu.RUnlock()
	if provider == nil {
		return ConnectionSnapshot{}, false
	}
	snap, err := resolveConnectionFromProvider(provider, prov, nodeID)
	if err != nil {
		return ConnectionSnapshot{}, false
	}
	return snap, true
}

// PendingNodeExecution returns a defensive execution snapshot only for a new,
// unconfirmed node. Saved nodes (including staged updates) and OpenSSH virtual
// nodes are never enrollment targets.
func (r *Repository) PendingNodeExecution(nodeID string) (*ssh.ExecutionConfig, bool) {
	if r == nil || IsOpenSSHNodeID(nodeID) {
		return nil, false
	}
	r.pendingMu.RLock()
	defer r.pendingMu.RUnlock()
	pending := r.pending[nodeID]
	if pending == nil || pending.isUpdate {
		return nil, false
	}
	node, ok := pending.provider.GetNode(nodeID)
	return node.Execution.Clone(), ok
}

func (r *Repository) buildConfirmPublishAction(pending *pendingConnection, nodeID, baseAlias, baseCanon string) *publishAction {
	mergedOrigin := normalizeOpenSSHOrigin(OpenSSHOrigin{
		Alias:         baseAlias,
		CanonicalHost: baseCanon,
	})
	return &publishAction{
		beforeProviderLocked: func() {
			current := r.pending[nodeID]
			if current == nil || current.provider == nil {
				return
			}
			mergedOrigin = current.provider.NodeOpenSSHOrigin(nodeID)
		},
		applyProviderLocked: func(p *Provider, updated *Configuration) {
			if p == nil || updated == nil || updated.Nodes == nil {
				return
			}
			if _, exists := updated.Nodes.Get(nodeID); !exists {
				return
			}
			p.setOpenSSHOriginLocked(nodeID, mergedOrigin)
		},
		afterProviderLocked: func() {
			if current := r.pending[nodeID]; current == pending || (current != nil && current.gate == pending.gate) {
				delete(r.pending, nodeID)
			}
		},
	}
}

func (r *Repository) discardPendingEntry(nodeID string, entry *pendingConnection) {
	if r == nil || nodeID == "" || entry == nil {
		return
	}
	r.pendingMu.Lock()
	defer r.pendingMu.Unlock()
	current := r.pending[nodeID]
	if current == nil {
		return
	}
	if current != entry && current.gate != entry.gate {
		return
	}
	current.refs--
	if current.refs <= 0 {
		delete(r.pending, nodeID)
	}
}

func (r *Repository) confirmPendingEntry(ctx context.Context, nodeID string, entry *pendingConnection, execution *ssh.ExecutionConfig) error {
	if r == nil || ctx == nil {
		return fmt.Errorf("confirm connection requires repository and context")
	}
	if IsOpenSSHNodeID(nodeID) {
		r.discardPendingEntry(nodeID, entry)
		return nil
	}
	pending, err := r.acquirePendingConfirmationGate(ctx, nodeID, entry)
	if err != nil || pending == nil {
		return err
	}
	defer pending.gate.release()

	node, host, identity, err := pending.provider.Resolve(nodeID)
	if err != nil {
		return fmt.Errorf("resolve pending connection %q: %w", nodeID, err)
	}
	action := r.buildConfirmPublishAction(pending, nodeID, node.OpenSSHAlias, node.CanonicalHost)
	if pending.isUpdate {
		storedNode := cloneNode(node)
		storedNode.OpenSSHAlias = ""
		storedNode.CanonicalHost = ""
		_, err = r.commitResultWithPublishAction(ctx, anyRevision, func(cfg *Configuration) error {
			routingChanged, err := replaceNodeAtRefWithRoutingCheck(cfg, pending.baseRef, nodeID, storedNode, host, identity)
			if err != nil {
				return err
			}
			if routingChanged {
				if err := ValidateSavedNodeJumpCycleWithOpenSSH(cfg, r.openSSHParserOrNil(), nodeID); err != nil {
					return err
				}
			}
			return nil
		}, action)
		if err != nil {
			return fmt.Errorf("save authenticated node update %q: %w", nodeID, err)
		}
		return nil
	}
	if execution != nil && ssh.NeedsExecutionProbe(node.Execution) {
		node.Execution = execution.Clone()
	}
	_, err = r.commitResultWithPublishAction(ctx, anyRevision, func(cfg *Configuration) error {
		if err := mergeConfirmedNodeConfig(cfg, nodeID, node, host, identity); err != nil {
			return err
		}
		return ValidateSavedNodeJumpCycleWithOpenSSH(cfg, r.openSSHParserOrNil(), nodeID)
	}, action)
	if err != nil {
		return fmt.Errorf("save authenticated connection %q: %w", nodeID, err)
	}
	return nil
}

func (r *Repository) acquirePendingConfirmationGate(ctx context.Context, nodeID string, entry *pendingConnection) (*pendingConnection, error) {
	for {
		r.pendingMu.RLock()
		pending := r.pending[nodeID]
		var prov NodeProvenance
		if pending != nil {
			prov = pending.provenance
		}
		r.pendingMu.RUnlock()
		if pending == nil || prov == ProvenanceOpenSSHVirtual {
			return nil, nil
		}
		if entry != nil && pending != entry && pending.gate != entry.gate {
			return nil, nil
		}
		// Serialize confirmation of this node without holding the pending map
		// lock across storage I/O or blocking reads of other connections.
		if err := pending.gate.acquire(ctx); err != nil {
			return nil, fmt.Errorf("lock pending connection %q: %w", nodeID, err)
		}
		r.pendingMu.RLock()
		current := r.pending[nodeID]
		var currentProv NodeProvenance
		if current != nil {
			currentProv = current.provenance
		}
		r.pendingMu.RUnlock()
		if current == pending || (current != nil && current.gate == pending.gate) {
			if currentProv == ProvenanceOpenSSHVirtual {
				pending.gate.release()
				return nil, nil
			}
			return current, nil
		}
		pending.gate.release()
		if current == nil {
			return nil, nil
		}
	}
}

func mergeConfirmedNodeConfig(cfg *Configuration, nodeID string, node models.Node, host models.Host, identity models.Identity) error {
	if err := ValidateNodeID(nodeID); err != nil {
		return fmt.Errorf("save connected node %q: %w", nodeID, err)
	}
	if err := ValidateNodeAliases(node.Alias); err != nil {
		return fmt.Errorf("save connected node %q: %w", nodeID, err)
	}
	if err := ValidateNodeAliases(host.Alias); err != nil {
		return fmt.Errorf("save connected host %q: %w", node.HostRef, err)
	}
	if err := ValidateConcreteHostAddress(host.Address); err != nil {
		return fmt.Errorf("save connected host %q: %w", node.HostRef, err)
	}
	if existing, ok := cfg.Nodes.Get(nodeID); ok && !equalPersistedNode(existing, node) {
		return fmt.Errorf("save connected node %q: %w", nodeID, ErrConfigConflict)
	}
	if existing, ok := cfg.Hosts.Get(node.HostRef); ok && !reflect.DeepEqual(existing, host) {
		return fmt.Errorf("save connected host %q: %w", node.HostRef, ErrConfigConflict)
	}
	if existing, ok := cfg.Identities.Get(node.IdentityRef); ok && !reflect.DeepEqual(existing, identity) {
		return fmt.Errorf("save connected identity %q: %w", node.IdentityRef, ErrConfigConflict)
	}
	storedNode := cloneNode(node)
	storedNode.OpenSSHAlias = ""
	storedNode.CanonicalHost = ""
	cfg.Nodes.Set(nodeID, storedNode)
	cfg.Hosts.Set(node.HostRef, cloneHost(host))
	cfg.Identities.Set(node.IdentityRef, cloneIdentity(identity))
	return nil
}
