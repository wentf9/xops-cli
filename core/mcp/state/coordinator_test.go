package state

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/ssh"
	"go.uber.org/goleak"
)

func fixtureView() ports.OperationSnapshot {
	view := ports.OperationSnapshot{DomainID: "domain", Revision: "1", PolicyRevision: "policy-1", Targets: make(map[string]ports.Target), Selectors: map[string]string{"alias": "a"}}
	for index, id := range []string{"a", "b"} {
		view.Targets[id] = ports.Target{Info: ports.NodeInfo{ID: id, Tags: []string{"fixture"}}, Version: "1", Plan: ssh.ConnectionPlan{Scope: "scope", Hops: []ssh.ConnectionConfig{{NodeID: id, Address: fmt.Sprintf("192.0.2.%d", index+1), Port: 22, User: "fixture", AuthType: "password", AuthUpdateToken: "auth-1", TrustVersion: "trust-1"}}}}
	}
	return view
}

func setup(t *testing.T) (*Coordinator, context.Context) {
	t.Helper()
	t.Cleanup(func() { goleak.VerifyNone(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	c, err := New(fixtureView(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	return c, ctx
}

func admission(t *testing.T, c *Coordinator, ctx context.Context, node string, phase ports.Phase) ports.Admission {
	t.Helper()
	view, err := c.Resolve(ctx, ports.ResolveRequest{Selectors: []string{node}})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := ports.Bind(view, "scope", "xops_ssh_run", map[string]string{"node": node, "command": "hostname"})
	if err != nil {
		t.Fatal(err)
	}
	return ports.Admission{OperationID: "operation", Phase: phase, Snapshot: view, Binding: binding}
}
func enter(t *testing.T, c *Coordinator, ctx context.Context, a ports.Admission) ports.Permit {
	t.Helper()
	p, err := c.Enter(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	})
	return p
}
func noPools(ctx context.Context, _ []ssh.ConnectionPlan) error { return ctx.Err() }
func publish(t *testing.T, c *Coordinator, ctx context.Context, next ports.OperationSnapshot) {
	t.Helper()
	u, err := c.BeginUpdate(ctx, c.Snapshot().Revision, next)
	if err != nil {
		t.Fatal(err)
	}
	if err := u.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	if err := u.Publish(ctx, noPools); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateBarrierAndAdmissionVersionAreAtomic(t *testing.T) {
	c, ctx := setup(t)
	oldA, oldB := admission(t, c, ctx, "a", ports.Execute), admission(t, c, ctx, "b", ports.Execute)
	active := enter(t, c, ctx, oldA)
	next := c.Snapshot()
	next.Revision = "2"
	target := next.Targets["a"]
	target.Plan.Hops[0].Address = "192.0.2.20"
	next.Targets["a"] = target
	u, err := c.BeginUpdate(ctx, "1", next)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Enter(ctx, oldA); !errors.Is(err, ErrUpdating) {
		t.Fatalf("affected operation crossed update barrier: %v", err)
	}
	enter(t, c, ctx, oldB)
	if err := u.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	if err := u.Publish(ctx, noPools); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Enter(ctx, oldA); !errors.Is(err, ports.ErrStaleBinding) {
		t.Fatalf("approval survived retargeting: %v", err)
	}
	if active.Context().Err() != nil {
		t.Fatal("ordinary edit cancelled admitted work")
	}
	_, captured, err := active.Snapshot().Resolve("a")
	if err != nil || captured.Plan.Hops[0].Address != "192.0.2.1" {
		t.Fatal("admitted operation changed target")
	}
	enter(t, c, ctx, admission(t, c, ctx, "a", ports.Execute))
}

func TestCommittedPublicationFailureStaysBlocked(t *testing.T) {
	c, ctx := setup(t)
	a := admission(t, c, ctx, "a", ports.Execute)
	next := c.Snapshot()
	next.Revision = "2"
	target := next.Targets["a"]
	target.Plan.Hops[0].AuthUpdateToken = "auth-2"
	next.Targets["a"] = target
	u, err := c.BeginUpdate(ctx, "1", next)
	if err != nil {
		t.Fatal(err)
	}
	if err := u.BeginPersistence(); err != nil {
		t.Fatal(err)
	}
	if err := u.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	marker := errors.New("pool retirement failed")
	if err := u.Publish(ctx, func(context.Context, []ssh.ConnectionPlan) error { return marker }); !errors.Is(err, marker) {
		t.Fatalf("publication failure lost: %v", err)
	}
	if !c.Pending() || c.Snapshot().Revision != "2" {
		t.Fatal("committed publication was rolled back or unblocked")
	}
	if err := u.Abort(); !errors.Is(err, ErrPersistenceUnknown) {
		t.Fatal("aborted an already committed write")
	}
	if _, err := c.Enter(ctx, a); !errors.Is(err, ErrUpdating) {
		t.Fatalf("failed publication admitted work: %v", err)
	}
	if err := u.Publish(ctx, noPools); err != nil {
		t.Fatal(err)
	}
	if c.Pending() {
		t.Fatal("successful recovery left admission blocked")
	}
	if _, err := c.Enter(ctx, a); !errors.Is(err, ports.ErrStaleBinding) {
		t.Fatal("old approval survived recovery")
	}
}

func TestUnknownPersistenceRequiresAnExplicitConclusion(t *testing.T) {
	c, ctx := setup(t)
	next := c.Snapshot()
	next.Revision = "2"
	target := next.Targets["a"]
	target.Version = "2"
	next.Targets["a"] = target
	u, err := c.BeginUpdate(ctx, "1", next)
	if err != nil {
		t.Fatal(err)
	}
	if err := u.BeginPersistence(); err != nil {
		t.Fatal(err)
	}
	if err := u.Abort(); !errors.Is(err, ErrPersistenceUnknown) {
		t.Fatal("ambiguous persistence released admission")
	}
	if _, err := c.Resolve(ctx, ports.ResolveRequest{Selectors: []string{"a"}}); !errors.Is(err, ErrUpdating) {
		t.Fatal("ambiguous state remained usable")
	}
	if err := u.ConfirmRollback(); err != nil {
		t.Fatal(err)
	}
	if c.Pending() || c.Snapshot().Revision != "1" {
		t.Fatal("confirmed rollback did not restore admission")
	}
}

func TestRevocationCancelsWorkButPreservesReservedCommit(t *testing.T) {
	c, ctx := setup(t)
	ordinary := enter(t, c, ctx, admission(t, c, ctx, "a", ports.TransferStart))
	commit := enter(t, c, ctx, admission(t, c, ctx, "a", ports.Commit))
	unrelated := enter(t, c, ctx, admission(t, c, ctx, "b", ports.Execute))
	next := c.Snapshot()
	next.Revision = "2"
	target := next.Targets["a"]
	target.Disabled = true
	next.Targets["a"] = target
	publish(t, c, ctx, next)
	if ordinary.Context().Err() == nil {
		t.Fatal("disabled node retained cancellable work")
	}
	if commit.Context().Err() != nil {
		t.Fatal("revocation cancelled a reserved commit")
	}
	if unrelated.Context().Err() != nil {
		t.Fatal("node revocation cancelled unrelated work")
	}
}

func TestRetirementDoesNotHoldThePublicationMutex(t *testing.T) {
	c, ctx := setup(t)
	next := c.Snapshot()
	next.Revision = "2"
	target := next.Targets["a"]
	target.Plan.Hops[0].Address = "192.0.2.20"
	next.Targets["a"] = target
	u, err := c.BeginUpdate(ctx, "1", next)
	if err != nil {
		t.Fatal(err)
	}
	if err := u.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	finished := make(chan error, 1)
	// The publication worker is released below or by the bounded test context.
	go func() {
		finished <- u.Publish(ctx, func(ctx context.Context, _ []ssh.ConnectionPlan) error {
			close(started)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("retirement never started")
	}
	enter(t, c, ctx, admission(t, c, ctx, "b", ports.Execute))
	close(release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}

func TestDisplayOnlyEditDoesNotRetireConnectionsOrApprovals(t *testing.T) {
	c, ctx := setup(t)
	a := admission(t, c, ctx, "a", ports.Execute)
	next := c.Snapshot()
	next.Revision = "2"
	target := next.Targets["a"]
	target.Info.Tags = []string{"new-display-tag"}
	next.Targets["a"] = target
	u, err := c.BeginUpdate(ctx, "1", next)
	if err != nil {
		t.Fatal(err)
	}
	if err := u.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	var retired atomic.Int32
	if err := u.Publish(ctx, func(_ context.Context, plans []ssh.ConnectionPlan) error { retired.Add(int32(len(plans))); return nil }); err != nil {
		t.Fatal(err)
	}
	if retired.Load() != 0 {
		t.Fatal("display-only edit retired execution connections")
	}
	enter(t, c, ctx, a)
}

func TestDeletedNodeIDCannotBeReused(t *testing.T) {
	c, ctx := setup(t)
	next := c.Snapshot()
	next.Revision = "2"
	delete(next.Targets, "a")
	delete(next.Selectors, "alias")
	publish(t, c, ctx, next)
	next = fixtureView()
	next.Revision = "3"
	if _, err := c.BeginUpdate(ctx, "2", next); !errors.Is(err, ErrIdentityReuse) {
		t.Fatalf("deleted ID reused: %v", err)
	}
}
