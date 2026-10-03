package state

import (
	"errors"
	"testing"

	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/ssh"
)

func TestDeletedJumpCannotBeReenabledThroughRetainedPlan(t *testing.T) {
	c, ctx := setup(t)
	next := c.Snapshot()
	next.Revision = "2"
	a := next.Targets["a"]
	b := next.Targets["b"]
	a.Plan.Hops = []ssh.ConnectionConfig{b.Plan.Hops[0], a.Plan.Hops[0]}
	next.Targets["a"] = a
	publish(t, c, ctx, next)
	next = c.Snapshot()
	next.Revision = "3"
	delete(next.Targets, "b")
	a = next.Targets["a"]
	a.Disabled = true
	next.Targets["a"] = a
	publish(t, c, ctx, next)
	next = c.Snapshot()
	next.Revision = "4"
	publish(t, c, ctx, next)
	next = c.Snapshot()
	next.Revision = "5"
	a = next.Targets["a"]
	a.Disabled = false
	next.Targets["a"] = a
	if update, err := c.BeginUpdate(ctx, "4", next); !errors.Is(err, ErrIdentityReuse) {
		if update != nil {
			if err := update.Abort(); err != nil {
				t.Error(err)
			}
		}
		t.Fatalf("deleted jump accepted again: %v", err)
	}
	if _, err := c.Resolve(ctx, ports.ResolveRequest{Selectors: []string{"a"}}); !errors.Is(err, ports.ErrNodeDisabled) {
		t.Fatalf("rejected update changed admission: %v", err)
	}
	a.Plan.Hops = a.Plan.Hops[1:]
	next.Targets["a"] = a
	publish(t, c, ctx, next)
	enter(t, c, ctx, admission(t, c, ctx, "a", ports.Execute))
}
