package state

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/ssh"
)

func sharedJumpView() ports.OperationSnapshot {
	view := fixtureView()
	jump := ssh.ConnectionConfig{NodeID: "jump", Address: "192.0.2.10", Port: 22, User: "jump-user", AuthType: "key", KeyRef: "shared-key", AuthUpdateToken: "jump-auth-1", TrustVersion: "jump-trust-1"}
	view.Targets["jump"] = ports.Target{Info: ports.NodeInfo{ID: "jump"}, Version: "1", Plan: ssh.ConnectionPlan{Scope: "scope", Hops: []ssh.ConnectionConfig{jump}}}
	for _, id := range []string{"a", "b"} {
		target := view.Targets[id]
		target.Plan.Hops[0].ProxyJump = "jump"
		target.Plan.Hops = append([]ssh.ConnectionConfig{jump}, target.Plan.Hops...)
		view.Targets[id] = target
	}
	return view
}

func TestSharedJumpVersionsInvalidateAllDependentNodes(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	c, err := New(sharedJumpView(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	}()
	a := enter(t, c, ctx, admission(t, c, ctx, "a", ports.Execute))
	b := enter(t, c, ctx, admission(t, c, ctx, "b", ports.Execute))
	next := c.Snapshot()
	next.Revision = "2"
	jump := next.Targets["jump"]
	jump.Plan.Hops[0].AuthUpdateToken = "jump-auth-2"
	next.Targets["jump"] = jump
	if _, err := c.BeginUpdate(ctx, "1", next); err == nil {
		t.Fatal("inconsistent shared jump snapshot was accepted")
	}
	for _, id := range []string{"a", "b"} {
		target := next.Targets[id]
		target.Plan.Hops[0].AuthUpdateToken = "jump-auth-2"
		next.Targets[id] = target
	}
	u, err := c.BeginUpdate(ctx, "1", next)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b", "jump"} {
		if _, err := c.Resolve(ctx, ports.ResolveRequest{Selectors: []string{id}}); !errors.Is(err, ErrUpdating) {
			t.Fatalf("shared dependency %q escaped barrier: %v", id, err)
		}
	}
	if err := u.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	retired := 0
	if err := u.Publish(ctx, func(_ context.Context, plans []ssh.ConnectionPlan) error { retired = len(plans); return nil }); err != nil {
		t.Fatal(err)
	}
	if retired != 3 || a.Context().Err() == nil || b.Context().Err() == nil {
		t.Fatalf("shared rotation missed dependent work: retired=%d", retired)
	}
}

func TestDisabledJumpMakesDownstreamNodesUnavailable(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	c, err := New(sharedJumpView(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	}()
	next := c.Snapshot()
	next.Revision = "2"
	jump := next.Targets["jump"]
	jump.Disabled = true
	next.Targets["jump"] = jump
	publish(t, c, ctx, next)
	if _, err := c.Resolve(ctx, ports.ResolveRequest{Selectors: []string{"a"}}); !errors.Is(err, ports.ErrNodeDisabled) {
		t.Fatalf("disabled jump remained usable: %v", err)
	}
	list, err := c.List(ctx, ports.NodeQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Nodes) != 0 {
		t.Fatal("inventory advertised nodes reachable only through a disabled jump")
	}
}

func TestAdmissionCapacityIsReleasedByCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	c, err := New(fixtureView(), Options{MaxActive: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	}()
	a := admission(t, c, ctx, "a", ports.Execute)
	first, err := c.Enter(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Enter(ctx, a); !errors.Is(err, ErrCapacity) {
		t.Fatal("capacity limit was ignored")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := c.Enter(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateReservationsRespectCallerDeadline(t *testing.T) {
	c, ctx := setup(t)
	next := c.Snapshot()
	next.Revision = "2"
	u, err := c.BeginUpdate(ctx, "1", next)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := c.BeginUpdate(cancelled, "1", next); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled update waited indefinitely: %v", err)
	}
	if err := u.Abort(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.BeginUpdate(ctx, "stale", next); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale database precondition accepted: %v", err)
	}
}

func TestCancelledPermitReleasesAdmissionWithoutExplicitClose(t *testing.T) {
	c, ctx := setup(t)
	work, cancel := context.WithCancel(ctx)
	defer cancel()
	permission, err := c.Enter(work, admission(t, c, ctx, "a", ports.Execute))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := permission.Close(); err != nil {
			t.Error(err)
		}
	}()
	c.mu.RLock()
	var released <-chan struct{}
	for entry := range c.active {
		released = entry.released
	}
	c.mu.RUnlock()
	cancel()
	select {
	case <-released:
	case <-ctx.Done():
		t.Fatal("cancellation did not release admission")
	}
	c.mu.RLock()
	count := len(c.active)
	c.mu.RUnlock()
	if count != 0 {
		t.Fatal("cancelled permit retained capacity")
	}
}

func TestAliasesCannotRedirectCanonicalIdentities(t *testing.T) {
	view := fixtureView()
	view.Selectors["a"] = "b"
	if _, err := New(view, Options{}); err == nil {
		t.Fatal("alias redirected an authoritative node ID")
	}
	view = fixtureView()
	view.Selectors["missing"] = "outside"
	if _, err := New(view, Options{}); err == nil {
		t.Fatal("alias pointed outside the published inventory")
	}
}
