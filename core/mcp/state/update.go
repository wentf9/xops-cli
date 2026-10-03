package state

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/ssh"
)

type updatePhase uint8

const (
	prepared updatePhase = iota
	persisting
	committed
	publishing
	publicationFailed
	finished
)

// Retire must stop reuse of the supplied old connection generations. It runs
// outside the publication lock while affected admission remains blocked.
// Implementations must honor ctx; retry after a failure must be idempotent.
type Retire func(context.Context, []ssh.ConnectionPlan) error

type Update struct {
	owner     *Coordinator
	next      ports.OperationSnapshot
	change    Change
	phase     updatePhase
	published bool
}

// BeginUpdate reserves the complete candidate before external persistence.
// Only one update can persist at a time; unrelated node operations continue.
func (c *Coordinator) BeginUpdate(ctx context.Context, expected string, next ports.OperationSnapshot) (*Update, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, errors.New("inventory update requires a deadline")
	}
	next = next.Clone()
	if err := validateSnapshot(next); err != nil {
		return nil, err
	}
	if next.DomainID != c.domain || next.Revision == expected {
		return nil, ErrConflict
	}
	select {
	case c.updates <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.done:
		return nil, ErrClosed
	}
	retained := false
	defer func() {
		if !retained {
			<-c.updates
		}
	}()
	c.mu.RLock()
	old := c.view.Clone()
	closed := c.closed
	c.mu.RUnlock()
	if closed {
		return nil, ErrClosed
	}
	if old.Revision != expected {
		return nil, ErrConflict
	}
	change, err := calculateChange(old, next)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := c.validateRetainedIdentities(next); err != nil {
		return nil, err
	}
	update := &Update{owner: c, next: next, change: change, phase: prepared}
	c.pending = update
	retained = true
	return update, nil
}

// Called with the publication lock. Disabled records may retain historical
// plans, but no active plan may turn a tombstoned hop back into authority.
func (c *Coordinator) validateRetainedIdentities(next ports.OperationSnapshot) error {
	for id, target := range next.Targets {
		if _, deleted := c.deleted[id]; deleted {
			return fmt.Errorf("node %q: %w", id, ErrIdentityReuse)
		}
		if target.Disabled {
			continue
		}
		for _, hop := range target.Plan.Hops {
			if _, deleted := c.deleted[hop.NodeID]; deleted {
				return fmt.Errorf("node %q uses deleted hop %q: %w", id, hop.NodeID, ErrIdentityReuse)
			}
		}
	}
	return nil
}

func (u *Update) validLocked() error {
	if u.owner.closed {
		return ErrClosed
	}
	if u.owner.pending != u || u.phase == finished {
		return ErrUpdateState
	}
	return nil
}

// BeginPersistence marks the point after which an error may mean a committed
// write. Call it before sending a database commit; Abort then fails closed.
func (u *Update) BeginPersistence() error {
	u.owner.mu.Lock()
	defer u.owner.mu.Unlock()
	if err := u.validLocked(); err != nil {
		return err
	}
	if u.phase != prepared {
		return ErrUpdateState
	}
	u.phase = persisting
	return nil
}

// ConfirmCommit records an authoritative successful transaction (or a host's
// explicit in-memory publication). It does not release admission.
func (u *Update) ConfirmCommit() error {
	u.owner.mu.Lock()
	defer u.owner.mu.Unlock()
	if err := u.validLocked(); err != nil {
		return err
	}
	if u.phase != prepared && u.phase != persisting {
		return ErrUpdateState
	}
	u.phase = committed
	return nil
}

// Abort releases a reservation only before any persistence was attempted.
func (u *Update) Abort() error {
	u.owner.mu.Lock()
	defer u.owner.mu.Unlock()
	if err := u.validLocked(); err != nil {
		return err
	}
	if u.phase != prepared {
		return ErrPersistenceUnknown
	}
	u.finishLocked()
	return nil
}

// ConfirmRollback is used only after the host has proved the write did not
// apply. It cannot undo a known commit or a partially activated publication.
func (u *Update) ConfirmRollback() error {
	u.owner.mu.Lock()
	defer u.owner.mu.Unlock()
	if err := u.validLocked(); err != nil {
		return err
	}
	if u.phase != prepared && u.phase != persisting {
		return ErrPersistenceUnknown
	}
	u.finishLocked()
	return nil
}

func (u *Update) finishLocked() {
	u.phase = finished
	u.owner.pending = nil
	<-u.owner.updates
}

// Publish activates the already committed candidate and retires old pools. If
// activation/retirement fails, the reservation remains blocked and Publish can
// be retried with a fresh deadline. Do not repeat the external transaction.
func (u *Update) Publish(ctx context.Context, retire Retire) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("publication requires a deadline")
	}
	owner := u.owner
	owner.mu.Lock()
	if err := u.validLocked(); err != nil {
		owner.mu.Unlock()
		return err
	}
	if u.phase != committed && u.phase != publicationFailed {
		owner.mu.Unlock()
		return ErrUpdateState
	}
	if len(u.change.Retired) > 0 && retire == nil {
		owner.mu.Unlock()
		return errors.New("changed connection plans require an explicit retirement callback")
	}
	u.phase = publishing
	var cancel []context.CancelFunc
	if !u.published {
		owner.view = u.next.Clone()
		for _, id := range u.change.Removed {
			owner.deleted[id] = struct{}{}
		}
		for entry := range owner.active {
			if entry.phase == ports.Commit {
				continue
			}
			if u.revokes(entry) {
				cancel = append(cancel, entry.cancel)
			}
		}
		u.published = true
	}
	plans := clonePlans(u.change.Retired)
	owner.mu.Unlock()
	for _, stop := range cancel {
		stop()
	}
	var result error
	if retire != nil {
		result = retire(ctx, plans)
	}
	if result == nil {
		result = ctx.Err()
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed {
		u.phase = publicationFailed
		return errors.Join(result, ErrClosed)
	}
	if result != nil {
		u.phase = publicationFailed
		return fmt.Errorf("activate committed inventory: %w", result)
	}
	u.finishLocked()
	return nil
}

func (u *Update) revokes(entry *registration) bool {
	if u.change.Policy {
		return true
	}
	for id := range entry.dependencies {
		if _, ok := u.change.Revoke[id]; ok {
			return true
		}
	}
	return false
}

func clonePlans(plans []ssh.ConnectionPlan) []ssh.ConnectionPlan {
	copy := slices.Clone(plans)
	for index := range copy {
		copy[index].Hops = slices.Clone(copy[index].Hops)
	}
	return copy
}
