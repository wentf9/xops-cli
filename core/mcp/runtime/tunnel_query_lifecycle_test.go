package runtime

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/wentf9/xops-cli/core/mcp/policy"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/mcp/tunnel"
)

type blockingTunnelFilterSource struct {
	ports.StateSource
	entered chan context.Context
	release chan struct{}
}

func (s *blockingTunnelFilterSource) Resolve(ctx context.Context, request ports.ResolveRequest) (ports.OperationSnapshot, error) {
	if len(request.Selectors) > 0 {
		s.entered <- ctx
		select {
		case <-ctx.Done():
			return ports.OperationSnapshot{}, ctx.Err()
		case <-s.release:
			if err := ctx.Err(); err != nil {
				return ports.OperationSnapshot{}, err
			}
			return ports.OperationSnapshot{}, context.Canceled
		}
	}
	return s.StateSource.Resolve(ctx, request)
}

func TestFilteredTunnelListPropagatesCallerCancellation(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "deadline"}[deadline], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				// This path only resolves a selector. Keep it in-process so virtual
				// time cannot expire the caller before the lookup worker starts.
				source := &blockingTunnelFilterSource{StateSource: runtimeTestProvider("node"), entered: make(chan context.Context, 1), release: make(chan struct{})}
				manager := tunnel.New(t.Context(), nil, nil)
				defer func() {
					if err := manager.Shutdown(t.Context()); err != nil {
						t.Errorf("stop tunnel manager: %v", err)
					}
				}()
				r := &Runtime{ctx: t.Context(), provider: source, tunnels: manager, toolTimeout: 5 * time.Minute}
				watchdog, stopWatchdog := context.WithTimeout(t.Context(), time.Second)
				defer stopWatchdog()
				ctx, cancel := context.WithCancel(t.Context())
				want := context.Canceled
				if deadline {
					cancel()
					ctx, cancel = context.WithTimeout(t.Context(), 30*time.Millisecond)
					want = context.DeadlineExceeded
				}
				defer cancel()
				done := make(chan struct{})
				var resultErr error
				// Cancellation ends the lookup; the cleanup release also joins it
				// when a regression disconnects the caller from the lookup context.
				go func() {
					defer close(done)
					_, _, resultErr = r.listTunnels(ctx, nil, ListTunnelsInput{NodeID: "node"})
				}()
				defer func() {
					close(source.release)
					cleanup, stop := context.WithTimeout(context.WithoutCancel(t.Context()), time.Second)
					defer stop()
					select {
					case <-done:
					case <-cleanup.Done():
						t.Error("lookup worker did not exit during cleanup")
					}
				}()
				var lookup context.Context
				select {
				case lookup = <-source.entered:
				case <-watchdog.Done():
					t.Fatal("filtered lookup did not start")
				}
				if deadline {
					callerDeadline, _ := ctx.Deadline()
					lookupDeadline, ok := lookup.Deadline()
					if !ok || !lookupDeadline.Equal(callerDeadline) {
						t.Errorf("lookup deadline = %v, want %v", lookupDeadline, callerDeadline)
					}
					<-ctx.Done()
				} else {
					cancel()
				}
				// Parent Done may close before cancellation reaches every child.
				// Observe the child's own completion before inspecting its error;
				// releasing the source early would manufacture context.Canceled.
				select {
				case <-lookup.Done():
				case <-watchdog.Done():
					t.Fatal("caller cancellation did not reach filtered lookup")
				}
				if !errors.Is(lookup.Err(), want) {
					t.Errorf("lookup cancellation = %v, want %v", lookup.Err(), want)
				}
				select {
				case <-done:
					if !errors.Is(resultErr, want) {
						t.Errorf("lookup cancellation lost: %v", resultErr)
					}
				case <-watchdog.Done():
					t.Fatal("lookup worker did not exit")
				}
			})
		})
	}
}

func TestFilteredTunnelListRetainsDisabledAndDeletedNodeHistory(t *testing.T) {
	for _, deleted := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "deleted"}[deleted], func(t *testing.T) {
			f := setupPublication(t, nil, false)
			created := seedTunnelListTask(t, f.runtime, "node", "history")
			stopped, err := f.runtime.tunnels.Stop(f.ctx, created.TunnelID)
			if err != nil {
				t.Fatal(err)
			}
			view := f.coordinator.Snapshot()
			if deleted {
				delete(view.Targets, "node")
				other := publicationTarget(t, f.second.Address)
				other.Info.ID = "other"
				other.Plan.Hops[0].NodeID = "other"
				view.Targets["other"] = other
				view.Selectors = map[string]string{"node": "other"}
			} else {
				target := view.Targets["node"]
				target.Disabled = true
				view.Targets["node"] = target
			}
			publishTunnelHistoryView(t, f, view)
			for _, state := range []string{"", stopped.State} {
				list := decodeTunnelList(t, callTunnelList(t, f.client, ListTunnelsInput{NodeID: "node", State: state}))
				if len(list) != 1 || list[0].TunnelID != created.TunnelID {
					t.Fatalf("history filter lost retained task: %+v", list)
				}
			}
			if list := decodeTunnelList(t, callTunnelList(t, f.client, ListTunnelsInput{NodeID: "node", State: "running"})); len(list) != 0 {
				t.Fatal("state filter ignored")
			}
			view = f.coordinator.Snapshot()
			view.Policy.Enabled = true
			view.Policy.ApprovalThreshold = "dangerous"
			view.Policy.NoElicitFallback = "deny"
			view.Policy.NodeOverrides = map[string]policy.NodeConfig{"node": {ApprovalThreshold: "safe"}}
			publishTunnelHistoryView(t, f, view)
			assertTunnelListDenied(t, callTunnelList(t, f.client, ListTunnelsInput{NodeID: "node"}), []tunnel.Status{stopped})
		})
	}
}

func publishTunnelHistoryView(t *testing.T, f *publicationFixture, view ports.OperationSnapshot) {
	t.Helper()
	previous := view.Revision
	view.Revision = "next-" + previous
	update, err := f.coordinator.BeginUpdate(f.ctx, previous, view)
	if err != nil {
		t.Fatal(err)
	}
	if err := update.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	if err := update.Publish(f.ctx, f.backend.RetirePlans); err != nil {
		t.Fatal(err)
	}
}
