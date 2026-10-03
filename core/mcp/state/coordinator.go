// Package state coordinates immutable inventory publication and MCP operation
// admission. Persistence belongs to the host; no network or database I/O is
// performed while the publication lock is held.
package state

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/wentf9/xops-cli/core/mcp/ports"
)

var (
	ErrUpdating           = errors.New("affected inventory is being published")
	ErrConflict           = errors.New("inventory revision conflict")
	ErrClosed             = errors.New("inventory coordinator is closed")
	ErrPersistenceUnknown = errors.New("persistence may have committed; reload before releasing admission")
	ErrUpdateState        = errors.New("inventory update state does not permit this operation")
	ErrIdentityReuse      = errors.New("deleted node identity cannot be reused")
	ErrCapacity           = errors.New("operation admission capacity exhausted")
)

type Options struct{ MaxActive int }

type Coordinator struct {
	mu        sync.RWMutex
	view      ports.OperationSnapshot
	domain    string
	closed    bool
	done      chan struct{}
	updates   chan struct{}
	pending   *Update
	active    map[*registration]struct{}
	deleted   map[string]struct{}
	maxActive int
}

type registration struct {
	permit       ports.Permit
	operationID  string
	cancel       context.CancelFunc
	dependencies map[string]struct{}
	phase        ports.Phase
	released     chan struct{}
	releaseOnce  sync.Once
}

type registrationKey struct{}

var _ ports.StateSource = (*Coordinator)(nil)
var _ ports.ExecutionGate = (*Coordinator)(nil)

func New(initial ports.OperationSnapshot, options Options) (*Coordinator, error) {
	initial = initial.Clone()
	if err := validateSnapshot(initial); err != nil {
		return nil, err
	}
	if options.MaxActive == 0 {
		options.MaxActive = 1024
	}
	if options.MaxActive < 1 {
		return nil, errors.New("admission limit must be positive")
	}
	return &Coordinator{view: initial, domain: initial.DomainID, done: make(chan struct{}), updates: make(chan struct{}, 1), active: make(map[*registration]struct{}), deleted: make(map[string]struct{}), maxActive: options.MaxActive}, nil
}

func (c *Coordinator) DomainID() string { return c.domain }

// Snapshot is an administrative view. It can include a committed publication
// whose activation is still blocked; Pending reports that distinction.
func (c *Coordinator) Snapshot() ports.OperationSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.view.Clone()
}
func (c *Coordinator) Pending() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.pending != nil }

func (c *Coordinator) List(ctx context.Context, query ports.NodeQuery) (ports.InventorySnapshot, error) {
	if err := checkContext(ctx); err != nil {
		return ports.InventorySnapshot{}, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return ports.InventorySnapshot{}, ErrClosed
	}
	if c.pending != nil {
		return ports.InventorySnapshot{}, ErrUpdating
	}
	result := ports.InventorySnapshot{DomainID: c.domain, Revision: c.view.Revision, PolicyRevision: c.view.PolicyRevision, Policy: c.view.Policy}
	for id, target := range c.view.Targets {
		if disabled(c.view, id) || query.Tag != "" && !slices.Contains(target.Info.Tags, query.Tag) {
			continue
		}
		result.Nodes = append(result.Nodes, target.Info)
	}
	slices.SortFunc(result.Nodes, func(a, b ports.NodeInfo) int { return strings.Compare(a.ID, b.ID) })
	return result.Clone(), nil
}

func (c *Coordinator) Resolve(ctx context.Context, request ports.ResolveRequest) (ports.OperationSnapshot, error) {
	if err := checkContext(ctx); err != nil {
		return ports.OperationSnapshot{}, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return ports.OperationSnapshot{}, ErrClosed
	}
	view, err := selectView(c.view, request.Selectors)
	if err != nil {
		return ports.OperationSnapshot{}, err
	}
	if c.blockedLocked(view) {
		return ports.OperationSnapshot{}, ErrUpdating
	}
	return view, nil
}

func (c *Coordinator) Enter(ctx context.Context, admission ports.Admission) (ports.Permit, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if err := admission.Binding.Validate(admission.Snapshot); err != nil {
		return nil, err
	}
	c.mu.Lock()
	permission, previous, err := c.enterLocked(ctx, admission)
	c.mu.Unlock()
	if previous != nil {
		c.release(previous)
	}
	return permission, err
}

func (c *Coordinator) enterLocked(ctx context.Context, admission ports.Admission) (ports.Permit, *registration, error) {
	if c.closed {
		return nil, nil, ErrClosed
	}
	previous, err := c.previousLocked(admission)
	if err != nil {
		return nil, nil, err
	}
	if previous == nil && len(c.active) >= c.maxActive {
		return nil, nil, ErrCapacity
	}
	current, err := selectView(c.view, selectorsFor(admission.Snapshot))
	if err != nil {
		return nil, nil, errors.Join(ports.ErrStaleBinding, err)
	}
	if c.blockedLocked(current) {
		return nil, nil, ErrUpdating
	}
	if err := admission.Binding.Validate(current); err != nil {
		return nil, nil, err
	}
	for id := range current.Targets {
		if disabled(c.view, id) {
			return nil, nil, ports.ErrNodeDisabled
		}
	}
	work, cancel := context.WithCancel(ctx)
	entry := &registration{cancel: cancel, operationID: admission.OperationID, dependencies: dependencies(current), phase: admission.Phase, released: make(chan struct{})}
	permission, err := ports.NewPermit(context.WithValue(work, registrationKey{}, entry), admission, func() error { c.release(entry); return nil })
	if err != nil {
		cancel()
		return nil, nil, err
	}
	entry.permit = permission
	if previous != nil {
		delete(c.active, previous)
	}
	c.active[entry] = struct{}{}
	// Deadline/revocation releases admission even if a caller forgets Close.
	// The callback only changes bounded in-memory state and owns no network I/O.
	context.AfterFunc(permission.Context(), func() { c.release(entry) })
	return permission, previous, nil
}

func (c *Coordinator) previousLocked(admission ports.Admission) (*registration, error) {
	previous := admission.Previous
	if previous == nil {
		return nil, nil
	}
	if ports.Nil(previous) || previous.Context() == nil || admission.Phase != ports.Commit || previous.Phase() != ports.TransferStart {
		return nil, ports.ErrPurpose
	}
	entry, ok := previous.Context().Value(registrationKey{}).(*registration)
	if !ok || entry == nil {
		return nil, ports.ErrPurpose
	}
	if _, active := c.active[entry]; !active || previous.Context() != entry.permit.Context() {
		return nil, ports.ErrPurpose
	}
	if err := entry.permit.Context().Err(); err != nil {
		return nil, err
	}
	if entry.phase != ports.TransferStart || entry.operationID != admission.OperationID || entry.permit.Binding() != admission.Binding || previous.Binding() != admission.Binding {
		return nil, ports.ErrStaleBinding
	}
	return entry, nil
}

func (c *Coordinator) release(entry *registration) {
	entry.releaseOnce.Do(func() {
		entry.cancel()
		c.mu.Lock()
		delete(c.active, entry)
		c.mu.Unlock()
		close(entry.released)
	})
}

func (c *Coordinator) blockedLocked(view ports.OperationSnapshot) bool {
	if c.pending == nil {
		return false
	}
	if c.pending.change.Policy {
		return true
	}
	for id := range dependencies(view) {
		if _, ok := c.pending.change.Affected[id]; ok {
			return true
		}
	}
	return false
}

func (c *Coordinator) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	close(c.done)
	entries := make([]*registration, 0, len(c.active))
	for entry := range c.active {
		entries = append(entries, entry)
	}
	c.mu.Unlock()
	for _, entry := range entries {
		c.release(entry)
	}
	return nil
}

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("inventory context is required")
	}
	return ctx.Err()
}

func selectorsFor(view ports.OperationSnapshot) []string {
	selectors := make([]string, 0, len(view.Selectors))
	for selector := range view.Selectors {
		selectors = append(selectors, selector)
	}
	if len(selectors) == 0 {
		for id := range view.Targets {
			selectors = append(selectors, id)
		}
	}
	return selectors
}

func selectView(source ports.OperationSnapshot, selectors []string) (ports.OperationSnapshot, error) {
	view := ports.OperationSnapshot{DomainID: source.DomainID, Revision: source.Revision, PolicyRevision: source.PolicyRevision, Policy: source.Policy, Targets: make(map[string]ports.Target), Selectors: make(map[string]string)}
	for _, selector := range selectors {
		id, target, err := source.Resolve(selector)
		if err != nil {
			return ports.OperationSnapshot{}, err
		}
		if disabled(source, id) {
			return ports.OperationSnapshot{}, fmt.Errorf("resolve %q: %w", selector, ports.ErrNodeDisabled)
		}
		view.Targets[id] = target
		view.Selectors[selector] = id
	}
	return view.Clone(), nil
}

func dependencies(view ports.OperationSnapshot) map[string]struct{} {
	set := make(map[string]struct{})
	for id, target := range view.Targets {
		set[id] = struct{}{}
		for _, hop := range target.Plan.Hops {
			set[hop.NodeID] = struct{}{}
		}
	}
	return set
}

func disabled(view ports.OperationSnapshot, id string) bool {
	target, ok := view.Targets[id]
	if !ok || target.Disabled {
		return true
	}
	for _, hop := range target.Plan.Hops {
		if dependency, ok := view.Targets[hop.NodeID]; ok && dependency.Disabled {
			return true
		}
	}
	return false
}
