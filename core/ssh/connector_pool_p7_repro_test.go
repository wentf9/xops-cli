//go:build p7repro

package ssh

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	cryptoSSH "golang.org/x/crypto/ssh"
)

type p7BarrierTrust struct {
	onCheck func(ctx context.Context, req HostKeyRequest) error
}

func (v *p7BarrierTrust) Verify(ctx context.Context, req HostKeyRequest, _ cryptoSSH.PublicKey) error {
	if v.onCheck != nil {
		return v.onCheck(ctx, req)
	}
	return ctx.Err()
}

type p7TrackingConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *p7TrackingConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

type p7TrackingDialer struct {
	mu    sync.Mutex
	conns []*p7TrackingConn
}

func (d *p7TrackingDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *p7TrackingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	raw, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	tc := &p7TrackingConn{Conn: raw}
	d.mu.Lock()
	d.conns = append(d.conns, tc)
	d.mu.Unlock()
	return tc, nil
}

func (d *p7TrackingDialer) snapshot() []*p7TrackingConn {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]*p7TrackingConn, len(d.conns))
	copy(out, d.conns)
	return out
}

func runFixtureSessionCheck(client *Client) error {
	session, err := client.sshClient.NewSession()
	if err != nil {
		return err
	}
	defer func() { _ = session.Close() }()
	out, err := session.Output("p7-check")
	if err != nil {
		return err
	}
	if string(out) != "fixture-output" {
		return errors.New("unexpected output: " + string(out))
	}
	return nil
}

type p7ConnResult struct {
	client *Client
	err    error
}

func newP7H5FixtureEnv(t *testing.T, ctx context.Context) (
	bastionV1, bastionV2, target *sshfixture.Server,
	v2Host string, v2Port int,
	provider *mutableRouteProvider,
) {
	t.Helper()
	var v1Host, tHost string
	var v1Port, tPort int
	bastionV1, v1Host, v1Port = newP0SSHFixture(t, ctx, "bastionV1")
	bastionV2, v2Host, v2Port = newP0SSHFixture(t, ctx, "bastionV2")
	target, tHost, tPort = newP0SSHFixture(t, ctx, "target")
	provider = &mutableRouteProvider{
		cfgs: map[string]*ClientConfig{
			"jump": {
				NodeID: "jump", Address: v1Host, Port: v1Port,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
			"target": {
				NodeID: "target", Address: tHost, Port: tPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "jump",
			},
		},
	}
	return bastionV1, bastionV2, target, v2Host, v2Port, provider
}

func newP7FirstTargetBarrierTrust() (*p7BarrierTrust, <-chan struct{}, chan struct{}) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	trust := &p7BarrierTrust{
		onCheck: func(verifyCtx context.Context, req HostKeyRequest) error {
			if req.NodeID == "target" && calls.Add(1) == 1 {
				close(entered)
				select {
				case <-release:
				case <-verifyCtx.Done():
					return verifyCtx.Err()
				}
			}
			return nil
		},
	}
	return trust, entered, release
}

// TestP7Repro_H5_MultiHopSingleflightExcludesUpstreamConfig reproduces H5 part 1:
// connectPlannedNode constructs sfKey from routeKey (node names only) + targetCompatDigest(target.cfg),
// excluding upstream hop configurations. When an upstream bastion's config drifts while Caller 1 is
// mid-handshake to target, Caller 2 (resolved with bastionV2) coalesces onto Caller 1's singleflight
// (inside reuseJumpChainedTarget's target connectPlannedNode) and receives Caller 1's bastionV1
// transport without ever dialing bastionV2.
func TestP7Repro_H5_MultiHopSingleflightExcludesUpstreamConfig(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	bastionV1, bastionV2, target, v2Host, v2Port, provider := newP7H5FixtureEnv(t, ctx)
	trust, target1Entered, releaseTarget1 := newP7FirstTargetBarrierTrust()

	connector := newTestConnector(provider, WithHostKeyVerifier(trust))
	t.Cleanup(func() {
		select {
		case <-releaseTarget1:
		default:
			close(releaseTarget1)
		}
		_ = connector.CloseAll()
	})

	res1Ch := make(chan p7ConnResult, 1)
	go func() {
		c, err := connector.Connect(ctx, "target")
		res1Ch <- p7ConnResult{client: c, err: err}
	}()

	select {
	case <-target1Entered:
	case <-ctx.Done():
		t.Fatal("Caller 1 never reached target handshake")
	}

	// Switch upstream hop "jump" from bastionV1 to bastionV2 while Caller 1 is in-flight.
	provider.mu.Lock()
	provider.cfgs["jump"] = &ClientConfig{
		NodeID: "jump", Address: v2Host, Port: v2Port,
		User: "fixture", AuthType: "password", Password: sshfixture.Password,
	}
	provider.mu.Unlock()

	res2Ch := make(chan p7ConnResult, 1)
	go func() {
		c, err := connector.Connect(ctx, "target")
		res2Ch <- p7ConnResult{client: c, err: err}
	}()

	// With upstream hop config included in sfKey/route digest, Caller 2 must complete
	// independently through bastionV2 without waiting on Caller 1's bastionV1 handshake.
	var (
		res2            p7ConnResult
		caller2Finished bool
	)
	select {
	case res2 = <-res2Ch:
		caller2Finished = true
	case <-time.After(250 * time.Millisecond):
		// Caller 2 coalesced onto Caller 1's singleflight; release Caller 1 to observe the poisoned result.
	}

	close(releaseTarget1)

	res1 := <-res1Ch
	if res1.err != nil {
		t.Fatalf("Caller 1 Connect(target) failed: %v", res1.err)
	}
	if !caller2Finished {
		res2 = <-res2Ch
	}
	if res2.err != nil {
		t.Fatalf("Caller 2 Connect(target) failed: %v", res2.err)
	}

	if !caller2Finished {
		t.Errorf("H5 reproduced: Caller 2 blocked waiting on Caller 1's singleflight despite upstream hop drift (bastionV1 -> bastionV2)")
	}
	if got := bastionV2.Authenticated.Load(); got != 1 {
		t.Errorf("H5 reproduced: bastionV2 authenticated = %d, want 1 (Caller 2 bypassed bastionV2 by coalescing onto Caller 1)", got)
	}
	if got := target.Authenticated.Load(); got < 2 {
		t.Errorf("H5 reproduced: target authenticated = %d, want >= 2 (Caller 2 coalesced onto Caller 1's bastionV1 dial)", got)
	}

	// Close bastionV1; Caller 2 was resolved against bastionV2 and MUST remain functional.
	_ = bastionV1.Close()
	if err := runFixtureSessionCheck(res2.client); err != nil {
		t.Fatalf("H5 reproduced: Caller 2 failed after closing old bastionV1 (routed over bastionV1 instead of bastionV2): %v", err)
	}
}

// TestP7Repro_H5_ReuseJumpChainedTarget_StaleParentRootConn reproduces H5 part 2:
// When a slow Caller 1 publishes target riding on retired bastionV1 after jump has already
// upgraded to bastionV2, reuseJumpChainedTarget validates jump(bastionV2) and then reuses
// cached target without checking that target's RootConn matches parent jump's current RootConn.
func TestP7Repro_H5_ReuseJumpChainedTarget_StaleParentRootConn(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	bastionV1, v1Host, v1Port := newP0SSHFixture(t, ctx, "bastionV1")
	bastionV2, v2Host, v2Port := newP0SSHFixture(t, ctx, "bastionV2")
	target, tHost, tPort := newP0SSHFixture(t, ctx, "target")

	provider := &mutableRouteProvider{
		cfgs: map[string]*ClientConfig{
			"jump": {
				NodeID: "jump", Address: v1Host, Port: v1Port,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
			"target": {
				NodeID: "target", Address: tHost, Port: tPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "jump",
			},
		},
	}

	target1Entered := make(chan struct{})
	releaseTarget1 := make(chan struct{})
	var targetCalls atomic.Int32
	trust := &p7BarrierTrust{
		onCheck: func(verifyCtx context.Context, req HostKeyRequest) error {
			if req.NodeID == "target" && targetCalls.Add(1) == 1 {
				close(target1Entered)
				select {
				case <-releaseTarget1:
				case <-verifyCtx.Done():
					return verifyCtx.Err()
				}
			}
			return nil
		},
	}

	connector := newTestConnector(provider, WithHostKeyVerifier(trust))
	t.Cleanup(func() {
		select {
		case <-releaseTarget1:
		default:
			close(releaseTarget1)
		}
		_ = connector.CloseAll()
	})

	// 1. Caller 1 connects target via bastionV1 and pauses inside target's handshake.
	err1Ch := make(chan error, 1)
	go func() {
		_, err := connector.Connect(ctx, "target")
		err1Ch <- err
	}()
	select {
	case <-target1Entered:
	case <-ctx.Done():
		t.Fatal("Caller 1 never reached target handshake")
	}

	// 2. Upgrade jump to bastionV2 and connect jump synchronously so pool["jump"] is bastionV2.
	provider.mu.Lock()
	provider.cfgs["jump"] = &ClientConfig{
		NodeID: "jump", Address: v2Host, Port: v2Port,
		User: "fixture", AuthType: "password", Password: sshfixture.Password,
	}
	provider.mu.Unlock()

	if _, err := connector.Connect(ctx, "jump"); err != nil {
		t.Fatalf("Connect(jump -> bastionV2) failed: %v", err)
	}
	if got := bastionV2.Authenticated.Load(); got != 1 {
		t.Fatalf("bastionV2 authenticated = %d, want 1", got)
	}

	// 3. Release Caller 1: it finishes its stale bastionV1 dial and publishes into target's pool slot.
	close(releaseTarget1)
	if err := <-err1Ch; err != nil {
		t.Fatalf("Caller 1 Connect(target) failed: %v", err)
	}

	// 4. Caller 3 connects target while jump is bastionV2. It must NOT reuse the stale bastionV1 target.
	c3, err := connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("Caller 3 Connect(target) failed: %v", err)
	}

	if got := target.Authenticated.Load(); got < 2 {
		t.Errorf("H5 reproduced: Caller 3 reused stale-generation target (target authenticated = %d, want >= 2)", got)
	}

	// Close retired bastionV1; Caller 3 MUST ride on bastionV2 and remain functional.
	_ = bastionV1.Close()
	if err := runFixtureSessionCheck(c3); err != nil {
		t.Fatalf("H5 reproduced: Caller 3 died when retired bastionV1 closed (pool poisoned by stale parent RootConn): %v", err)
	}
}

// TestP7Repro_H6_PublishClientOverwriteLeaksDisplacedOnCloseAll reproduces H6 part 1:
// publishClient overwrites c.clients[nodeName] without retiring the displaced *PooledClient,
// so Connector.CloseAll never closes the displaced transport.
func TestP7Repro_H6_PublishClientOverwriteLeaksDisplacedOnCloseAll(t *testing.T) {
	t.Run("via_connect_overwrite", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()

		_, host, port := newP0SSHFixture(t, ctx, "node")
		provider := &mutableRouteProvider{
			cfgs: map[string]*ClientConfig{
				"node": {
					NodeID: "node", Address: host, Port: port,
					User: "fixture", AuthType: "password", Password: sshfixture.Password,
					AuthUpdateToken: "v1",
				},
			},
		}

		dial1Entered := make(chan struct{})
		releaseDial1 := make(chan struct{})
		var verifyCount atomic.Int32
		trust := &p7BarrierTrust{
			onCheck: func(verifyCtx context.Context, _ HostKeyRequest) error {
				if verifyCount.Add(1) == 1 {
					close(dial1Entered)
					select {
					case <-releaseDial1:
					case <-verifyCtx.Done():
						return verifyCtx.Err()
					}
				}
				return nil
			},
		}

		dialer := &p7TrackingDialer{}
		connector := newTestConnector(provider, WithDialer(dialer), WithHostKeyVerifier(trust))
		t.Cleanup(func() {
			select {
			case <-releaseDial1:
			default:
				close(releaseDial1)
			}
			_ = connector.CloseAll()
		})

		err1Ch := make(chan error, 1)
		go func() {
			_, err := connector.Connect(ctx, "node")
			err1Ch <- err
		}()
		select {
		case <-dial1Entered:
		case <-ctx.Done():
			t.Fatal("Caller 1 never reached handshake")
		}

		// Caller 2 connects with a distinct AuthUpdateToken (distinct sfKey) and publishes pooled2.
		provider.mu.Lock()
		provider.cfgs["node"].AuthUpdateToken = "v2"
		provider.mu.Unlock()

		if _, err := connector.Connect(ctx, "node"); err != nil {
			t.Fatalf("Caller 2 Connect(node v2) failed: %v", err)
		}

		// Roll back config to v1 so Caller 1's syncRecordedConnection succeeds and overwrites pooled2.
		provider.mu.Lock()
		provider.cfgs["node"].AuthUpdateToken = "v1"
		provider.mu.Unlock()

		close(releaseDial1)
		if err := <-err1Ch; err != nil {
			t.Fatalf("Caller 1 Connect(node v1) failed: %v", err)
		}

		conns := dialer.snapshot()
		if len(conns) != 2 {
			t.Fatalf("expected 2 dialed transports before CloseAll, got %d", len(conns))
		}

		if err := connector.CloseAll(); err != nil {
			t.Fatalf("CloseAll failed: %v", err)
		}
		for i, conn := range conns {
			if !conn.closed.Load() {
				t.Errorf("H6 reproduced: dialed transport #%d was displaced by publishClient overwrite and leaked unclosed after CloseAll", i+1)
			}
		}
	})

	t.Run("direct_publishClient_overwrite", func(t *testing.T) {
		connector := newTestConnector(&mockConfigStore{})
		conn1 := &closeResultConn{}
		conn2 := &closeResultConn{}

		if err := connector.publishClient("node-1", &PooledClient{SSHClient: &cryptoSSH.Client{Conn: conn1}}); err != nil {
			t.Fatalf("first publishClient failed: %v", err)
		}
		if err := connector.publishClient("node-1", &PooledClient{SSHClient: &cryptoSSH.Client{Conn: conn2}}); err != nil {
			t.Fatalf("second publishClient failed: %v", err)
		}
		if err := connector.CloseAll(); err != nil {
			t.Fatalf("CloseAll failed: %v", err)
		}
		if conn1.calls.Load() != 1 || conn2.calls.Load() != 1 {
			t.Fatalf("H6 reproduced: CloseAll close counts = (displaced=%d, active=%d), want (1, 1)", conn1.calls.Load(), conn2.calls.Load())
		}
	})
}

// TestP7Repro_H6_StartKeepAliveForCancelsLiveClientKeepAlive reproduces H6 part 2:
// startKeepAliveFor unconditionally pops and cancels c.keepAlives[nodeName] without verifying
// that the caller's client is still the active pool entry, so a delayed stale caller cancels
// the live pooled client's keepalive.
func TestP7Repro_H6_StartKeepAliveForCancelsLiveClientKeepAlive(t *testing.T) {
	c := newKeepAliveTestConnector(t, 40*time.Millisecond, 200*time.Millisecond)

	staleSSH := startHealthyServer(t)
	liveSSH := startHealthyServer(t)
	t.Cleanup(func() {
		_ = staleSSH.Close()
		_ = liveSSH.Close()
	})

	stalePooled := &PooledClient{SSHClient: staleSSH}
	livePooled := &PooledClient{SSHClient: liveSSH}

	// Simulate concurrent publish race: stalePooled published first, livePooled overwrote it
	// and started its keepalive before stalePooled's delayed startKeepAliveFor executes.
	if err := c.publishClient("node-1", stalePooled); err != nil {
		t.Fatalf("publish stalePooled failed: %v", err)
	}
	if err := c.publishClient("node-1", livePooled); err != nil {
		t.Fatalf("publish livePooled failed: %v", err)
	}
	c.startKeepAliveFor("node-1", livePooled)

	liveEntry, ok := c.keepAlives.Get("node-1")
	if !ok || liveEntry == nil || liveEntry.client != livePooled {
		t.Fatalf("expected livePooled keepalive registered before stale call, got ok=%v entry=%v", ok, liveEntry)
	}

	// Delayed stale caller now runs startKeepAliveFor for stalePooled.
	c.startKeepAliveFor("node-1", stalePooled)

	select {
	case <-liveEntry.done:
		t.Fatalf("H6 reproduced: delayed startKeepAliveFor(stalePooled) canceled the live pooled client's keepalive")
	case <-time.After(120 * time.Millisecond):
	}

	curEntry, ok := c.keepAlives.Get("node-1")
	if !ok || curEntry.client != livePooled {
		t.Fatalf("H6 reproduced: keepAlives[node-1] client replaced with stale client (ok=%v)", ok)
	}
}

// TestP7Repro_MED1_ControlOptionsIgnoredInCompatDigestAndValidation reproduces MED-1:
// targetCompatDigest and validateTargetCompatibility omit ControlMaster, ControlPath, and ControlPersist,
// allowing incompatible Control* updates to coalesce or reuse a mismatched cached connection.
func TestP7Repro_MED1_ControlOptionsIgnoredInCompatDigestAndValidation(t *testing.T) {
	baseCfg := func() *ClientConfig {
		return &ClientConfig{
			NodeID:   "ctrl-node",
			Address:  "10.0.0.10",
			Port:     22,
			User:     "ops",
			AuthType: "password",
			Options: MustOptions(
				OptionControlMaster, "no",
				OptionControlPath, "none",
				OptionControlPersist, "no",
			),
		}
	}

	cases := []struct {
		name  string
		key   string
		value string
	}{
		{name: "ControlMaster", key: OptionControlMaster, value: "auto"},
		{name: "ControlPath", key: OptionControlPath, value: "/tmp/xops-cm-%C"},
		{name: "ControlPersist", key: OptionControlPersist, value: "10m"},
	}

	t.Run("targetCompatDigest", func(t *testing.T) {
		orig := baseCfg()
		origDigest := targetCompatDigest(orig)
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				mut := baseCfg()
				if err := mut.Options.Set(tc.key, tc.value); err != nil {
					t.Fatalf("Options.Set(%s, %q) failed: %v", tc.key, tc.value, err)
				}
				if got := targetCompatDigest(mut); got == origDigest {
					t.Fatalf("MED-1 reproduced: targetCompatDigest ignored %s change (%q); digest unchanged (%s)", tc.name, tc.value, got)
				}
			})
		}
	})

	t.Run("validateTargetCompatibility", func(t *testing.T) {
		orig := baseCfg()
		cur := orig.ToConnectionConfig()
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				mut := baseCfg()
				if err := mut.Options.Set(tc.key, tc.value); err != nil {
					t.Fatalf("Options.Set(%s, %q) failed: %v", tc.key, tc.value, err)
				}
				if err := validateTargetCompatibility(cur, mut); !errors.Is(err, ErrSnapshotMismatch) {
					t.Fatalf("MED-1 reproduced: validateTargetCompatibility ignored %s drift (%q): got err=%v, want ErrSnapshotMismatch", tc.name, tc.value, err)
				}
			})
		}
	})

	t.Run("connector_connect_retires_on_control_option_drift", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()

		srv, host, port := newP0SSHFixture(t, ctx, "ctrl-drift")
		sockPath := filepath.Join(shortSocketDir(t), "med1.sock")

		provider := &mutableRouteProvider{
			cfgs: map[string]*ClientConfig{
				"ctrl-node": {
					NodeID: "ctrl-node", Address: host, Port: port,
					User: "fixture", AuthType: "password", Password: sshfixture.Password,
					Options: MustOptions(
						OptionControlMaster, "no",
						OptionControlPath, "none",
						OptionControlPersist, "no",
					),
				},
			},
		}

		connector := newTestConnector(provider, WithHostKeyVerifier(&fixtureTrust{}))
		t.Cleanup(func() { _ = connector.CloseAll() })

		if _, err := connector.Connect(ctx, "ctrl-node"); err != nil {
			t.Fatalf("initial Connect failed: %v", err)
		}
		if got := srv.Authenticated.Load(); got != 1 {
			t.Fatalf("initial auth count = %d, want 1", got)
		}

		// Drift Control* options in the provider.
		provider.mu.Lock()
		provider.cfgs["ctrl-node"] = &ClientConfig{
			NodeID: "ctrl-node", Address: host, Port: port,
			User: "fixture", AuthType: "password", Password: sshfixture.Password,
			Options: MustOptions(
				OptionControlMaster, "auto",
				OptionControlPath, sockPath,
				OptionControlPersist, "10m",
			),
		}
		provider.mu.Unlock()

		if _, err := connector.Connect(ctx, "ctrl-node"); err != nil {
			t.Fatalf("second Connect after Control* drift failed: %v", err)
		}
		if got := srv.Authenticated.Load(); got < 2 {
			t.Fatalf("MED-1 reproduced: Connector reused cached client despite Control* option drift (auth count = %d, want >= 2)", got)
		}
	})
}

// TestP7Repro_LOW1_BaseHostNormalizationInConfigSnapshotAndRefresh reproduces LOW-1:
//  1. Client.configSnapshot() (returned by Client.Config()) omits BaseHost altogether.
//  2. Client.refreshConnectionTokens() normalizes newCfg.Address but not newCfg.BaseHost,
//     causing ErrSnapshotMismatch when the provider stores a bracketed IPv6 BaseHost.
func TestP7Repro_LOW1_BaseHostNormalizationInConfigSnapshotAndRefresh(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	_, host, port := newP0SSHFixture(t, ctx, "low1")
	provider := &mutableRouteProvider{
		cfgs: map[string]*ClientConfig{
			"v6-node": {
				NodeID:          "v6-node",
				Address:         "[" + host + "]",
				BaseHost:        "[2001:db8::1]",
				Port:            port,
				User:            "fixture",
				AuthType:        "password",
				Password:        sshfixture.Password,
				SudoUpdateToken: "sudo-v1",
			},
		},
	}

	connector := newTestConnector(provider, WithHostKeyVerifier(&fixtureTrust{}))
	t.Cleanup(func() { _ = connector.CloseAll() })

	client, err := connector.Connect(ctx, "v6-node")
	if err != nil {
		t.Fatalf("Connect(v6-node) failed: %v", err)
	}

	t.Run("configSnapshot_preserves_normalized_BaseHost", func(t *testing.T) {
		if got := client.ConnectionConfig().BaseHost; got != "2001:db8::1" {
			t.Fatalf("precondition: ConnectionConfig().BaseHost = %q, want %q", got, "2001:db8::1")
		}
		if got := client.Config().BaseHost; got != "2001:db8::1" {
			t.Fatalf("LOW-1 reproduced: Client.Config() (configSnapshot) returned BaseHost=%q, want normalized %q", got, "2001:db8::1")
		}
	})

	t.Run("refreshConnectionTokens_normalizes_BaseHost", func(t *testing.T) {
		provider.mu.Lock()
		provider.cfgs["v6-node"].SudoUpdateToken = "sudo-v2"
		provider.mu.Unlock()

		if err := client.refreshConnectionTokens(tokenRefreshKindSudo, "sudo-v2"); err != nil {
			t.Fatalf("LOW-1 reproduced: refreshConnectionTokens failed on unchanged bracketed IPv6 BaseHost: %v", err)
		}
	})
}
