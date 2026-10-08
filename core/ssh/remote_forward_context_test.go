package ssh

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func newRemoteForwardClient(t *testing.T, hops int) (context.Context, *reconnectSSHServer, *Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	server, address := newReconnectSSHServer(t, ctx, hops)
	store := &mockProxyJumpStore{cfgs: make(map[string]*ClientConfig)}
	for index := 0; index <= hops; index++ {
		name := fmt.Sprintf("node-%d", index)
		cfg := &ClientConfig{
			NodeID: name, Address: "127.0.0.1", Port: address.Port,
			User: "test", AuthType: "password", AuthUpdateToken: "v1",
		}
		if index > 0 {
			cfg.ProxyJump = fmt.Sprintf("node-%d", index-1)
		}
		store.cfgs[name] = cfg
	}
	connector := newTestConnector(store, WithSecretResolver(planSecrets{}), WithHostKeyVerifier(&fixtureTrust{}))
	t.Cleanup(func() { closePlanConnector(t, connector) })
	client, err := connector.Connect(ctx, fmt.Sprintf("node-%d", hops))
	if err != nil {
		t.Fatal(err)
	}
	return ctx, server, client
}

// The monitor owns a context independent from any forwarding operation. Only
// receive progress can keep its unanswered request alive during the assertion.
func holdRemoteForwardKeepalive(t *testing.T, ctx context.Context, server *reconnectSSHServer, client *Client) *cachedProbeTraffic {
	t.Helper()
	server.stall.Store(true)
	monitorCtx, cancelMonitor := context.WithCancel(ctx)
	const idleTimeout = 150 * time.Millisecond
	done := startKeepAlive(monitorCtx, client.sshClient, 10*time.Millisecond, idleTimeout, nil, client.Interrupt)
	t.Cleanup(func() { cancelMonitor(); <-done })
	select {
	case <-server.probeSeen:
	case <-time.After(time.Second):
		t.Fatal("server did not receive the keepalive")
	}
	traffic := drainCachedProbeTraffic(t, client)
	select {
	case <-done:
		t.Fatal("keepalive ended despite ongoing receive progress")
	case <-time.After(2 * idleTimeout):
	}
	return traffic
}

type remoteForwardResult struct {
	forward *Forward
	err     error
}

func startRemoteForwardForTest(t *testing.T, client *Client, start func() (*Forward, error)) <-chan remoteForwardResult {
	t.Helper()
	results := make(chan remoteForwardResult, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		forward, err := start()
		results <- remoteForwardResult{forward, err}
	}()
	t.Cleanup(func() {
		if err := client.Interrupt(); err != nil {
			t.Error(err)
		}
		<-done
	})
	return results
}

func TestRemoteForwardContextDuringKeepalive(t *testing.T) {
	for _, hops := range []int{0, 1} {
		for _, mode := range []string{"deadline", "cancel"} {
			t.Run(fmt.Sprintf("hops=%d/%s", hops, mode), func(t *testing.T) {
				ctx, server, client := newRemoteForwardClient(t, hops)
				traffic := holdRemoteForwardKeepalive(t, ctx, server, client)
				var forwardCtx context.Context
				var cancelForward context.CancelFunc
				wantErr := context.DeadlineExceeded
				if mode == "deadline" {
					forwardCtx, cancelForward = context.WithTimeout(ctx, 150*time.Millisecond)
				} else {
					forwardCtx, cancelForward = context.WithCancel(ctx)
					wantErr = context.Canceled
				}
				defer cancelForward()
				results := startRemoteForwardForTest(t, client, func() (*Forward, error) {
					return client.RemoteForward(forwardCtx, "127.0.0.1:43210", "127.0.0.1:43211")
				})
				if mode == "cancel" {
					// Allow acquisition to enter Listen behind globalSentMu.
					select {
					case result := <-results:
						t.Fatalf("remote forward returned before cancellation: %v", result.err)
					case <-time.After(50 * time.Millisecond):
					}
					cancelForward()
				}
				select {
				case result := <-results:
					if result.forward != nil || !errors.Is(result.err, wantErr) {
						t.Fatalf("remote forward = %v, %v; want nil, %v", result.forward, result.err, wantErr)
					}
				case <-time.After(time.Second):
					t.Fatalf("remote forward ignored %s despite %d received bytes", mode, traffic.bytes.Load())
				}
			})
		}
	}
}

func TestRemoteForwardHealthyStopPreservesConnection(t *testing.T) {
	for _, hops := range []int{0, 1} {
		t.Run(fmt.Sprintf("hops=%d", hops), func(t *testing.T) {
			ctx, server, client := newRemoteForwardClient(t, hops)
			forwardCtx, cancelForward := context.WithCancel(ctx)
			defer cancelForward()
			forward, err := client.RemoteForward(forwardCtx, "127.0.0.1:43210", "127.0.0.1:43211")
			if err != nil {
				t.Fatal(err)
			}
			cancelForward()
			select {
			case <-forward.Done():
				if err := forward.Wait(); err != nil {
					t.Fatalf("stop healthy remote forward: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("healthy remote forward did not stop")
			}
			if got := server.forwards.Load(); got != 1 {
				t.Fatalf("tcpip-forward requests = %d, want 1", got)
			}
			if got := server.cancels.Load(); got != 1 {
				t.Fatalf("cancel-tcpip-forward requests = %d, want 1", got)
			}
			if err := probeWithTimeoutAndInterrupt(ctx, client.sshClient, time.Second, client.Interrupt); err != nil {
				t.Fatalf("healthy forwarding cleanup closed the shared SSH connection: %v", err)
			}
			if got := server.roots.Load(); got != 1 {
				t.Fatalf("physical connections = %d, want unchanged shared transport", got)
			}
		})
	}
}

func TestRemoteForwardStopBoundWithReceiveProgress(t *testing.T) {
	for _, hops := range []int{0, 1} {
		for _, mode := range []string{"pending-keepalive", "unanswered-cancel"} {
			t.Run(fmt.Sprintf("hops=%d/%s", hops, mode), func(t *testing.T) {
				ctx, server, client := newRemoteForwardClient(t, hops)
				forwardCtx, cancelForward := context.WithCancel(ctx)
				defer cancelForward()
				forward, err := client.remoteForward(forwardCtx, "127.0.0.1:43210", "127.0.0.1:43211", 150*time.Millisecond)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := client.Interrupt(); err != nil {
						t.Error(err)
					}
					<-forward.Done()
				})
				var traffic *cachedProbeTraffic
				if mode == "pending-keepalive" {
					traffic = holdRemoteForwardKeepalive(t, ctx, server, client)
				} else {
					server.stallCancel.Store(true)
					traffic = drainCachedProbeTraffic(t, client)
				}
				cancelForward()
				select {
				case <-forward.Done():
					if err := forward.Wait(); !errors.Is(err, context.DeadlineExceeded) {
						t.Fatalf("stop remote forward = %v, want cleanup deadline", err)
					}
				case <-time.After(time.Second):
					t.Fatalf("remote listener cancellation blocked despite %d received bytes", traffic.bytes.Load())
				}
				if got := server.cancels.Load(); mode == "unanswered-cancel" && got != 1 {
					t.Fatalf("cancel-tcpip-forward requests = %d, want 1", got)
				}
			})
		}
	}
}

func TestRemoteForwardRequestBoundWithoutCallerDeadline(t *testing.T) {
	for _, hops := range []int{0, 1} {
		t.Run(fmt.Sprintf("hops=%d", hops), func(t *testing.T) {
			ctx, server, client := newRemoteForwardClient(t, hops)
			server.stallForward.Store(true)
			traffic := drainCachedProbeTraffic(t, client)
			// The explicit request bound, rather than a caller or monitor deadline,
			// must release a peer that never answers tcpip-forward itself.
			results := startRemoteForwardForTest(t, client, func() (*Forward, error) {
				return client.remoteForward(context.WithoutCancel(ctx), "127.0.0.1:43210", "127.0.0.1:43211", 150*time.Millisecond)
			})
			select {
			case result := <-results:
				if result.forward != nil || !errors.Is(result.err, context.DeadlineExceeded) {
					t.Fatalf("remote forward = %v, %v; want nil, deadline", result.forward, result.err)
				}
			case <-time.After(time.Second):
				t.Fatalf("unanswered tcpip-forward request remained pending despite %d received bytes", traffic.bytes.Load())
			}
			if got := server.forwards.Load(); got != 1 {
				t.Fatalf("tcpip-forward requests = %d, want 1", got)
			}
		})
	}
}

func TestRemoteForwardCanceledContextPreservesConnection(t *testing.T) {
	ctx, server, client := newRemoteForwardClient(t, 1)
	forwardCtx, cancelForward := context.WithCancel(ctx)
	cancelForward()
	forward, err := client.RemoteForward(forwardCtx, "127.0.0.1:43210", "127.0.0.1:43211")
	if forward != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("remote forward = %v, %v; want nil, canceled", forward, err)
	}
	if got := server.forwards.Load(); got != 0 {
		t.Fatalf("tcpip-forward requests = %d, want 0 for an already canceled caller", got)
	}
	if err := probeWithTimeoutAndInterrupt(ctx, client.sshClient, time.Second, client.Interrupt); err != nil {
		t.Fatalf("already canceled forwarding request closed shared SSH connection: %v", err)
	}
}
