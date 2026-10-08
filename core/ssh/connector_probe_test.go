package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Keep receiving real channel data while the server deliberately withholds its
// global-request reply. The fixture's root deadline and context bound writes.
func serveCachedProbeTraffic(t *testing.T, ctx context.Context, channel ssh.Channel) {
	t.Helper()
	defer func() {
		// A deliberately interrupted peer can reset TCP while this fixture
		// still has channel traffic queued. Preserve other cleanup failures.
		if err := closeResource(channel, "cache-probe traffic channel"); err != nil && !errors.Is(err, syscall.ECONNRESET) {
			t.Error(err)
		}
	}()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := channel.Write([]byte("ongoing channel data")); err != nil {
				return // Cache-probe expiry closes the old transport.
			}
		}
	}
}

type cachedProbeTraffic struct {
	bytes atomic.Int64
	seen  chan struct{}
	once  sync.Once
}

func (c *cachedProbeTraffic) Write(p []byte) (int, error) {
	c.bytes.Add(int64(len(p)))
	c.once.Do(func() { close(c.seen) })
	return len(p), nil
}

func drainCachedProbeTraffic(t *testing.T, client *Client) *cachedProbeTraffic {
	t.Helper()
	channel, requests, err := client.sshClient.OpenChannel("cache-probe-traffic", nil)
	if err != nil {
		t.Fatal(err)
	}
	traffic := &cachedProbeTraffic{seen: make(chan struct{})}
	var workers sync.WaitGroup
	workers.Go(func() { ssh.DiscardRequests(requests) })
	workers.Go(func() {
		if _, err := io.Copy(traffic, channel); err != nil && !errors.Is(err, io.EOF) {
			t.Errorf("read cache-probe traffic: %v", err)
		}
	})
	t.Cleanup(func() {
		closeTestResource(t, client)
		closeTestResource(t, channel)
		workers.Wait()
	})
	select {
	case <-traffic.seen:
	case <-time.After(time.Second):
		t.Fatal("cached connection received no channel data")
	}
	return traffic
}

func cachedProbeAcquirer(t *testing.T, connector *Connector, store *mockProxyJumpStore, nodeID, mode string) func(context.Context) (*PlanConnection, error) {
	t.Helper()
	if mode == "Connect" {
		return func(ctx context.Context) (*PlanConnection, error) {
			client, err := connector.Connect(ctx, nodeID)
			return &PlanConnection{Client: client}, err
		}
	}
	plan, err := CapturePlan(t.Context(), store, nodeID, "cache-probe-regression")
	if err != nil {
		t.Fatal(err)
	}
	return func(ctx context.Context) (*PlanConnection, error) { return connector.ConnectPlan(ctx, plan) }
}

func cancelCachedProbeCaller(t *testing.T, ctx context.Context, acquire func(context.Context) (*PlanConnection, error), probeSeen <-chan struct{}) {
	t.Helper()
	firstCtx, cancelFirst := context.WithCancel(ctx)
	done := make(chan struct{})
	var firstErr error
	go func() {
		defer close(done)
		lease, err := acquire(firstCtx)
		if lease != nil {
			closePlanLease(t, lease)
		}
		firstErr = err
	}()
	t.Cleanup(func() { cancelFirst(); <-done })
	select {
	case <-probeSeen:
	case <-time.After(time.Second):
		t.Fatal("server did not receive the cached probe")
	}
	cancelFirst()
	select {
	case <-done:
		if !errors.Is(firstErr, context.Canceled) {
			t.Fatalf("first acquisition = %v, want caller cancellation", firstErr)
		}
	case <-time.After(time.Second):
		t.Fatal("first acquisition ignored caller cancellation")
	}
}

func TestConnectorCachedProbeBoundWithReceiveProgress(t *testing.T) {
	for _, mode := range []string{"Connect", "ConnectPlan"} {
		for _, hops := range []int{0, 1} {
			t.Run(fmt.Sprintf("%s/hops=%d", mode, hops), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
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
				// Background monitoring cannot interfere with cache validation.
				const probeTimeout = 250 * time.Millisecond
				connector.EnableKeepAlive(ctx, time.Hour, probeTimeout)
				acquire := cachedProbeAcquirer(t, connector, store, fmt.Sprintf("node-%d", hops), mode)
				initial, err := acquire(ctx)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { closePlanLease(t, initial) })
				traffic := drainCachedProbeTraffic(t, initial.Client)
				server.stall.Store(true)

				if mode == "Connect" {
					// Canceling the initiating caller must not leave the node's
					// shared work occupied by an indefinitely extended probe.
					cancelCachedProbeCaller(t, ctx, acquire, server.probeSeen)
				}

				// Validate both a later Connect caller and an in-flight
				// ConnectPlan acquisition on the same cached generation.
				nextCtx, cancelNext := context.WithTimeout(ctx, 4*probeTimeout)
				defer cancelNext()
				next, err := acquire(nextCtx)
				if err != nil {
					t.Fatalf("subsequent acquisition blocked despite %d received bytes: %v", traffic.bytes.Load(), err)
				}
				t.Cleanup(func() { closePlanLease(t, next) })
				if next.Client.rootConn == initial.Client.rootConn {
					t.Fatal("timed-out cached transport was not replaced")
				}
				if err := probeWithTimeoutAndInterrupt(nextCtx, next.Client.sshClient, probeTimeout, next.Client.Interrupt); err != nil {
					t.Fatalf("replacement connection is unusable: %v", err)
				}
				reused, err := acquire(nextCtx)
				if err != nil {
					t.Fatalf("acquisition after cache recovery: %v", err)
				}
				t.Cleanup(func() { closePlanLease(t, reused) })
				if reused.Client.sshClient != next.Client.sshClient {
					t.Fatal("healthy replacement was not reused")
				}
				if got := server.roots.Load(); got != 2 {
					t.Fatalf("physical connections = %d, want original and replacement", got)
				}
			})
		}
	}
}
