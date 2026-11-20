package config

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/models"
)

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
}

// PrepareNodeContext resolves a connection without writing configuration. New
// nodes are visible only through Resolve and ResolveConnection until confirmed;
// snapshots, selectors and unrelated transactions contain saved nodes only.
// Explicit node creation and imports continue to use the durable mutation APIs.
func (r *Repository) PrepareNodeContext(ctx context.Context, opts EnsureNodeOptions) (EnsureNodeResult, error) {
	if r == nil || ctx == nil {
		return EnsureNodeResult{}, fmt.Errorf("prepare connection requires repository and context")
	}
	if err := ctx.Err(); err != nil {
		return EnsureNodeResult{}, fmt.Errorf("prepare connection canceled: %w", err)
	}
	selector := strings.TrimSpace(opts.Target.Selector)
	if selector == "" {
		return EnsureNodeResult{}, fmt.Errorf("target selector is empty")
	}
	r.pendingMu.Lock()
	defer r.pendingMu.Unlock()
	defaultUser := strings.TrimSpace(opts.DefaultUser)
	if decision, err := r.findExistingNodeDecision(opts.Target, defaultUser); err != nil {
		return EnsureNodeResult{}, err
	} else if !decision.NeedsCreation && decision.MatchedNodeID != "" {
		r.syncPreparedExistingMetadataLocked(decision)
		return EnsureNodeResult{NodeID: decision.MatchedNodeID}, nil
	}
	var outcome ensureTransactionOutcome
	cfg, _, _, err := prepareConfiguration(r.provider.Snapshot(), func(cfg *Configuration) error {
		return r.ensureTargetInTransaction(cfg, opts, defaultUser, &outcome)
	})
	if err != nil {
		return EnsureNodeResult{}, err
	}
	nodeID := outcome.nodeID
	created := outcome.created
	if created {
		effectiveID, err := r.registerPendingConnection(cfg, nodeID, outcome.openSSHAlias, outcome.canonicalHost)
		if err != nil {
			return EnsureNodeResult{}, err
		}
		nodeID = effectiveID
	} else {
		r.provider.setSavedNodeOpenSSHMetadataIfPresent(nodeID, outcome.openSSHAlias, outcome.canonicalHost)
	}
	return EnsureNodeResult{NodeID: nodeID, Created: created}, nil
}

func (r *Repository) registerPendingConnection(cfg *Configuration, nodeID, openSSHAlias, canonicalHost string) (string, error) {
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
		if existingID, handled, err := r.tryReuseOrDisambiguatePending(cfg, previous, nodeID, node, host, identity); handled || err != nil {
			return existingID, err
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
	r.pending[nodeID] = &pendingConnection{provider: pendingProvider, provenance: prov, gate: &contextGate{}}
	return nodeID, nil
}

func (r *Repository) tryReuseOrDisambiguatePending(
	cfg *Configuration,
	previous *pendingConnection,
	nodeID string,
	node models.Node,
	host models.Host,
	identity models.Identity,
) (string, bool, error) {
	oldNode, oldHost, oldIdentity, err := previous.provider.Resolve(nodeID)
	if err != nil {
		return "", false, fmt.Errorf("resolve pending connection %q: %w", nodeID, err)
	}
	normalizedNode := node
	normalizedNode.IdentityRef = privateIdentityReference(cfg, nodeID)
	if equalPersistedNode(oldNode, normalizedNode) && reflect.DeepEqual(oldHost, host) && reflect.DeepEqual(oldIdentity, identity) {
		if oldNode.OpenSSHAlias == node.OpenSSHAlias && oldNode.CanonicalHost == node.CanonicalHost {
			return nodeID, true, nil
		}
		if upgradedID, ok := r.upgradePendingAliasAndCanonical(previous, nodeID, oldNode, normalizedNode, host, identity); ok {
			return upgradedID, true, nil
		}
	}
	if node.OpenSSHAlias == "" || oldNode.OpenSSHAlias == node.OpenSSHAlias {
		return "", false, fmt.Errorf("pending connection %q changed: %w", nodeID, ErrConfigConflict)
	}
	altID := OpenSSHNodePrefix + FormatNodeID(identity.User, node.OpenSSHAlias, host.Port)
	altPrev := r.pending[altID]
	if altPrev == nil {
		return "", false, nil
	}
	altOldNode, altOldHost, altOldIdentity, altErr := altPrev.provider.Resolve(altID)
	if altErr != nil {
		return "", false, fmt.Errorf("resolve pending connection %q: %w", altID, altErr)
	}
	altNormalized := node
	altNormalized.IdentityRef = privateIdentityReference(cfg, altID)
	if !equalPersistedNode(altOldNode, altNormalized) || !reflect.DeepEqual(altOldHost, host) || !reflect.DeepEqual(altOldIdentity, identity) {
		return "", false, fmt.Errorf("pending connection %q changed: %w", altID, ErrConfigConflict)
	}
	if altOldNode.OpenSSHAlias == node.OpenSSHAlias && altOldNode.CanonicalHost == node.CanonicalHost {
		return altID, true, nil
	}
	if upgradedID, ok := r.upgradePendingAliasAndCanonical(altPrev, altID, altOldNode, altNormalized, host, identity); ok {
		return upgradedID, true, nil
	}
	return "", false, fmt.Errorf("pending connection %q changed: %w", altID, ErrConfigConflict)
}

func (r *Repository) upgradePendingAliasAndCanonical(
	previous *pendingConnection,
	nodeID string,
	oldNode, normalizedNode models.Node,
	host models.Host,
	identity models.Identity,
) (string, bool) {
	aliasUpgradable := oldNode.OpenSSHAlias == normalizedNode.OpenSSHAlias || (oldNode.OpenSSHAlias == "" && normalizedNode.OpenSSHAlias != "")
	canonUpgradable := oldNode.CanonicalHost == normalizedNode.CanonicalHost || (oldNode.CanonicalHost == "" && normalizedNode.CanonicalHost != "")
	if !aliasUpgradable || !canonUpgradable {
		return "", false
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
	r.pending[nodeID] = &pendingConnection{provider: upgradedProvider, provenance: prov, gate: gate}
	return nodeID, true
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

// ConfirmNodeContext saves exactly the prepared connection after SSH
// authentication succeeds. Conflicting concurrent edits are never overwritten.
// A failed save leaves the pending connection available for an explicit retry;
// an applied write is never rolled back, even if durability is uncertain.
func (r *Repository) ConfirmNodeContext(ctx context.Context, nodeID string) error {
	return r.confirmNodeContext(ctx, nodeID, nil)
}

// PendingNodeExecution returns a defensive execution snapshot only for a new,
// unconfirmed node. Saved and OpenSSH virtual nodes are never enrollment targets.
func (r *Repository) PendingNodeExecution(nodeID string) (*ssh.ExecutionConfig, bool) {
	if r == nil || strings.HasPrefix(nodeID, OpenSSHNodePrefix) {
		return nil, false
	}
	r.pendingMu.RLock()
	defer r.pendingMu.RUnlock()
	pending := r.pending[nodeID]
	if pending == nil {
		return nil, false
	}
	node, ok := pending.provider.GetNode(nodeID)
	return node.Execution.Clone(), ok
}

// ConfirmNodeWithExecutionContext includes a successful enrollment probe in the
// same node-creation transaction. Existing pending execution settings win.
func (r *Repository) ConfirmNodeWithExecutionContext(ctx context.Context, nodeID string, execution *ssh.ExecutionConfig) error {
	execution = execution.Clone()
	if err := execution.Validate(); err != nil {
		return fmt.Errorf("validate enrollment execution: %w", err)
	}
	return r.confirmNodeContext(ctx, nodeID, execution)
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
			curOrigin := current.provider.NodeOpenSSHOrigin(nodeID)
			if !curOrigin.IsZero() {
				mergedOrigin = curOrigin
			}
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

func (r *Repository) confirmNodeContext(ctx context.Context, nodeID string, execution *ssh.ExecutionConfig) error {
	if r == nil || ctx == nil {
		return fmt.Errorf("confirm connection requires repository and context")
	}
	if IsOpenSSHNodeID(nodeID) {
		return nil
	}
	pending, err := r.acquirePendingConfirmationGate(ctx, nodeID)
	if err != nil || pending == nil {
		return err
	}
	defer pending.gate.release()

	node, host, identity, err := pending.provider.Resolve(nodeID)
	if err != nil {
		return fmt.Errorf("resolve pending connection %q: %w", nodeID, err)
	}
	if execution != nil && ssh.NeedsExecutionProbe(node.Execution) {
		node.Execution = execution.Clone()
	}
	action := r.buildConfirmPublishAction(pending, nodeID, node.OpenSSHAlias, node.CanonicalHost)
	_, err = r.commitResultWithPublishAction(ctx, anyRevision, func(cfg *Configuration) error {
		return mergeConfirmedNodeConfig(cfg, nodeID, node, host, identity)
	}, action)
	if err != nil {
		return fmt.Errorf("save authenticated connection %q: %w", nodeID, err)
	}
	return nil
}

func (r *Repository) acquirePendingConfirmationGate(ctx context.Context, nodeID string) (*pendingConnection, error) {
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
	if err := ValidateNodeAlias(nodeID); err != nil {
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
	cfg.Hosts.Set(node.HostRef, host)
	cfg.Identities.Set(node.IdentityRef, identity)
	return nil
}
