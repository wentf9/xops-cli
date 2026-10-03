package state

import (
	"errors"
	"testing"

	"github.com/wentf9/xops-cli/core/mcp/ports"
)

type wrappedPermit struct{ ports.Permit }

func TestCommitHandoffTransfersOneSlotAndCannotBeReplayed(t *testing.T) {
	c, ctx := setup(t)
	c.maxActive = 1
	streamAdmission := admission(t, c, ctx, "a", ports.TransferStart)
	stream := enter(t, c, ctx, streamAdmission)
	commitAdmission := streamAdmission
	commitAdmission.Phase = ports.Commit
	commitAdmission.Previous = wrappedPermit{stream}
	commit := enter(t, c, ctx, commitAdmission)
	if stream.Context().Err() == nil || commit.Context().Err() != nil {
		t.Fatal("handoff did not replace the stream lifetime")
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	unrelated := admission(t, c, ctx, "b", ports.Execute)
	if permission, err := c.Enter(ctx, unrelated); !errors.Is(err, ErrCapacity) {
		if permission != nil {
			if err := permission.Close(); err != nil {
				t.Error(err)
			}
		}
		t.Fatalf("old Close released the commit slot: %v", err)
	}
	if err := commit.Close(); err != nil {
		t.Fatal(err)
	}
	if permission, err := c.Enter(ctx, commitAdmission); err == nil {
		if err := permission.Close(); err != nil {
			t.Error(err)
		}
		t.Fatal("consumed stream capability was replayed")
	}
	enter(t, c, ctx, unrelated)
}

func TestInvalidHandoffsDoNotConsumeStreamAdmission(t *testing.T) {
	for _, change := range []string{"operation", "binding", "phase", "foreign", "stale", "publishing"} {
		t.Run(change, func(t *testing.T) {
			c, ctx := setup(t)
			c.maxActive = 1
			a := admission(t, c, ctx, "a", ports.TransferStart)
			stream := enter(t, c, ctx, a)
			a.Phase, a.Previous = ports.Commit, stream
			switch change {
			case "operation":
				a.OperationID = "other"
			case "binding":
				a.Binding.Scope = "other"
			case "phase":
				a.Phase = ports.Execute
			case "foreign":
				other, _ := setup(t)
				a.Previous = enter(t, other, ctx, admission(t, other, ctx, "a", ports.TransferStart))
			case "stale", "publishing":
				next := c.Snapshot()
				next.Revision = "2"
				target := next.Targets["a"]
				target.Version = "2"
				next.Targets["a"] = target
				if change == "stale" {
					publish(t, c, ctx, next)
				} else {
					update, err := c.BeginUpdate(ctx, "1", next)
					if err != nil {
						t.Fatal(err)
					}
					defer func() {
						if err := update.Abort(); err != nil {
							t.Error(err)
						}
					}()
				}
			}
			if permission, err := c.Enter(ctx, a); err == nil {
				if err := permission.Close(); err != nil {
					t.Error(err)
				}
				t.Fatal("invalid handoff admitted")
			}
			if stream.Context().Err() != nil {
				t.Fatal("rejected handoff consumed the stream")
			}
			c.mu.RLock()
			active := len(c.active)
			c.mu.RUnlock()
			if active != 1 {
				t.Fatalf("invalid handoff changed capacity: %d", active)
			}
		})
	}
}

func TestConcurrentHandoffsConsumeTheStreamOnlyOnce(t *testing.T) {
	c, ctx := setup(t)
	c.maxActive = 1
	a := admission(t, c, ctx, "a", ports.TransferStart)
	stream := enter(t, c, ctx, a)
	a.Phase, a.Previous = ports.Commit, stream
	type result struct {
		permission ports.Permit
		err        error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for range 2 {
		go func() {
			select {
			case <-start:
			case <-ctx.Done():
				results <- result{err: ctx.Err()}
				return
			}
			permission, err := c.Enter(ctx, a)
			results <- result{permission, err}
		}()
	}
	close(start)
	winners := 0
	var winner ports.Permit
	for range 2 {
		select {
		case got := <-results:
			if got.err == nil {
				winners++
				winner = got.permission
			} else if got.permission != nil {
				if err := got.permission.Close(); err != nil {
					t.Error(err)
				}
			}
		case <-ctx.Done():
			t.Fatal("handoff contenders did not finish")
		}
	}
	if winner != nil {
		defer func() {
			if err := winner.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	if winners != 1 {
		t.Fatalf("successful handoffs=%d", winners)
	}
	c.mu.RLock()
	active := len(c.active)
	c.mu.RUnlock()
	if active != 1 {
		t.Fatalf("admission slots after concurrent handoff=%d", active)
	}
}
