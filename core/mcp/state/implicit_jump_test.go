package state

import (
	"errors"
	"testing"

	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/ssh"
)

func implicitJumpView() ports.OperationSnapshot {
	view := fixtureView()
	jump := ssh.ConnectionConfig{NodeID: "implicit-jump", Address: "192.0.2.254", Port: 22, User: "fixture", AuthType: "password", AuthUpdateToken: "auth-1", TrustVersion: "trust-1"}
	for id, target := range view.Targets {
		target.Plan.Hops = append([]ssh.ConnectionConfig{jump}, target.Plan.Hops...)
		view.Targets[id] = target
	}
	return view
}

func TestImplicitSharedJumpRejectsPartialRotation(t *testing.T) {
	c, ctx := setup(t)
	view := implicitJumpView()
	view.Revision = "2"
	publish(t, c, ctx, view)
	oldA := admission(t, c, ctx, "a", ports.Execute)
	oldB := admission(t, c, ctx, "b", ports.Execute)
	a, b := enter(t, c, ctx, oldA), enter(t, c, ctx, oldB)
	next := c.Snapshot()
	next.Revision = "3"
	next.Targets["a"].Plan.Hops[0].AuthUpdateToken = "auth-2"
	if update, err := c.BeginUpdate(ctx, "2", next); err == nil {
		if err := update.Abort(); err != nil {
			t.Error(err)
		}
		t.Fatal("inconsistent implicit jump rotation was accepted")
	}
	if c.Pending() || a.Context().Err() != nil || b.Context().Err() != nil {
		t.Fatal("rejected rotation changed existing admission")
	}
	next.Targets["b"].Plan.Hops[0].AuthUpdateToken = "auth-2"
	publish(t, c, ctx, next)
	if a.Context().Err() == nil || b.Context().Err() == nil {
		t.Fatal("full shared rotation failed to revoke every dependent permit")
	}
	if permit, err := c.Enter(ctx, oldB); !errors.Is(err, ports.ErrStaleBinding) {
		if permit != nil {
			if err := permit.Close(); err != nil {
				t.Error(err)
			}
		}
		t.Fatalf("stale dependent was readmitted: %v", err)
	}
	enter(t, c, ctx, admission(t, c, ctx, "b", ports.Execute))
}

func TestInitialImplicitSharedJumpMustBeConsistent(t *testing.T) {
	view := implicitJumpView()
	view.Targets["b"].Plan.Hops[0].TrustVersion = "other-trust"
	c, err := New(view, Options{})
	if c != nil {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	}
	if err == nil {
		t.Fatal("inconsistent implicit trust was accepted on startup")
	}
}
