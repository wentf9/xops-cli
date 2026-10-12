package config

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/wentf9/xops-cli/core/ssh"
)

type pendingConnection struct {
	provider *Provider // immutable connection bundle
	gate     contextGate
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
	if id, _, err := r.findExistingNodeFast(opts.Target, defaultUser); err != nil {
		return EnsureNodeResult{}, err
	} else if id != "" {
		return EnsureNodeResult{NodeID: id}, nil
	}
	var nodeID string
	var created bool
	cfg, _, _, err := prepareConfiguration(r.provider.Snapshot(), func(cfg *Configuration) error {
		lookup, aliases, err := buildIndexes(cfg, false)
		if err != nil {
			return fmt.Errorf("build connection indexes: %w", err)
		}
		if !opts.Target.HasUser && !opts.Target.HasPort {
			return r.ensureBareTargetInTransaction(cfg, opts, lookup, aliases, selector, defaultUser, &nodeID, &created)
		}
		return r.ensureExplicitTargetInTransaction(cfg, opts, lookup, aliases, selector, defaultUser, &nodeID, &created)
	})
	if err != nil {
		return EnsureNodeResult{}, err
	}
	if created {
		// Retain only this connection's entities, never a stale copy of the
		// whole configuration that could overwrite concurrent changes.
		node, _ := cfg.Nodes.Get(nodeID)
		host, _ := cfg.Hosts.Get(node.HostRef)
		identity, _ := cfg.Identities.Get(node.IdentityRef)
		// Concurrent first connections on different ports must not reserve the
		// same identity and later share (or conflict over) remembered secrets.
		node.IdentityRef = privateIdentityReference(cfg, nodeID)
		pending := cloneConfiguration(nil)
		pending.Nodes.Set(nodeID, node)
		pending.Hosts.Set(node.HostRef, host)
		pending.Identities.Set(node.IdentityRef, identity)
		if r.pending == nil {
			r.pending = make(map[string]*pendingConnection)
		}
		if previous := r.pending[nodeID]; previous != nil {
			oldNode, oldHost, oldIdentity, err := previous.provider.Resolve(nodeID)
			if err != nil {
				return EnsureNodeResult{}, fmt.Errorf("resolve pending connection %q: %w", nodeID, err)
			}
			if !reflect.DeepEqual(oldNode, node) || !reflect.DeepEqual(oldHost, host) || !reflect.DeepEqual(oldIdentity, identity) {
				return EnsureNodeResult{}, fmt.Errorf("pending connection %q changed: %w", nodeID, ErrConfigConflict)
			}
			return EnsureNodeResult{NodeID: nodeID, Created: true}, nil
		}
		r.pending[nodeID] = &pendingConnection{provider: NewProviderWithoutOpenSSH(pending)}
	}
	return EnsureNodeResult{NodeID: nodeID, Created: created}, nil
}

func (r *Repository) connectionProvider(nodeID string) *Provider {
	r.pendingMu.RLock()
	defer r.pendingMu.RUnlock()
	if pending := r.pending[nodeID]; pending != nil {
		return pending.provider
	}
	return r.provider
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
	if r == nil {
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

func (r *Repository) confirmNodeContext(ctx context.Context, nodeID string, execution *ssh.ExecutionConfig) error {
	if r == nil || ctx == nil {
		return fmt.Errorf("confirm connection requires repository and context")
	}
	r.pendingMu.RLock()
	pending := r.pending[nodeID]
	r.pendingMu.RUnlock()
	if pending == nil {
		return nil
	}
	// Serialize confirmation of this node without holding the pending map
	// lock across storage I/O or blocking reads of other connections.
	if err := pending.gate.acquire(ctx); err != nil {
		return fmt.Errorf("lock pending connection %q: %w", nodeID, err)
	}
	defer pending.gate.release()
	r.pendingMu.RLock()
	confirmed := r.pending[nodeID] != pending
	r.pendingMu.RUnlock()
	if confirmed {
		return nil
	}
	node, host, identity, err := pending.provider.Resolve(nodeID)
	if err != nil {
		return fmt.Errorf("resolve pending connection %q: %w", nodeID, err)
	}
	if execution != nil && ssh.NeedsExecutionProbe(node.Execution) {
		node.Execution = execution.Clone()
	}
	result, err := r.commitResultContext(ctx, anyRevision, func(cfg *Configuration) error {
		if existing, ok := cfg.Nodes.Get(nodeID); ok && !reflect.DeepEqual(existing, node) {
			return fmt.Errorf("save connected node %q: %w", nodeID, ErrConfigConflict)
		}
		if existing, ok := cfg.Hosts.Get(node.HostRef); ok && !reflect.DeepEqual(existing, host) {
			return fmt.Errorf("save connected host %q: %w", node.HostRef, ErrConfigConflict)
		}
		if existing, ok := cfg.Identities.Get(node.IdentityRef); ok && !reflect.DeepEqual(existing, identity) {
			return fmt.Errorf("save connected identity %q: %w", node.IdentityRef, ErrConfigConflict)
		}
		cfg.Nodes.Set(nodeID, node)
		cfg.Hosts.Set(node.HostRef, host)
		cfg.Identities.Set(node.IdentityRef, identity)
		return nil
	})
	if result.Applied {
		r.pendingMu.Lock()
		delete(r.pending, nodeID)
		r.pendingMu.Unlock()
	}
	if err != nil {
		return fmt.Errorf("save authenticated connection %q: %w", nodeID, err)
	}
	return nil
}
