package runtime

import (
	"context"
	"errors"
	"testing"
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
			f := setupPublication(t, nil, false)
			source := &blockingTunnelFilterSource{StateSource: f.coordinator, entered: make(chan context.Context, 1), release: make(chan struct{})}
			f.runtime.provider = source
			ctx, cancel := context.WithCancel(f.ctx)
			if deadline {
				cancel()
				ctx, cancel = context.WithTimeout(f.ctx, 30*time.Millisecond)
			}
			defer cancel()
			done := make(chan error, 1)
			go func() { _, _, err := f.runtime.listTunnels(ctx, nil, ListTunnelsInput{NodeID: "node"}); done <- err }()
			var lookup context.Context
			select {
			case lookup = <-source.entered:
			case <-f.ctx.Done():
				t.Fatal("filtered lookup did not start")
			}
			if deadline {
				<-ctx.Done()
			} else {
				cancel()
			}
			if !errors.Is(lookup.Err(), ctx.Err()) {
				t.Errorf("lookup did not inherit caller cancellation: caller=%v lookup=%v", ctx.Err(), lookup.Err())
			}
			close(source.release)
			select {
			case err := <-done:
				if !errors.Is(err, ctx.Err()) {
					t.Errorf("lookup cancellation lost: %v", err)
				}
			case <-f.ctx.Done():
				t.Fatal("lookup worker did not exit")
			}
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
