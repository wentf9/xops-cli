package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func merkleChainDigest(upstream []string, node string) HopDigest {
	parent := ZeroHopDigest
	for _, hop := range upstream {
		parent = DigestClientConfig(&ClientConfig{NodeID: hop}, parent)
	}
	return DigestClientConfig(&ClientConfig{NodeID: node}, parent)
}

func TestP0_ConnectionRouteKeyInjectiveProperty(t *testing.T) {
	t.Parallel()

	// Direct hops bind to ZeroHopDigest.
	if got := merkleChainDigest(nil, "jumpB"); got != DigestClientConfig(&ClientConfig{NodeID: "jumpB"}, ZeroHopDigest) {
		t.Fatalf("direct digest mismatch: %s", got)
	}
	if got := merkleChainDigest([]string{}, "openssh:jumpB"); got != DigestClientConfig(&ClientConfig{NodeID: "openssh:jumpB"}, ZeroHopDigest) {
		t.Fatalf("empty-slice digest mismatch: %s", got)
	}

	// Deterministic equality for identical routes.
	r1 := merkleChainDigest([]string{"jumpA", "jumpB"}, "target")
	r2 := merkleChainDigest([]string{"jumpA", "jumpB"}, "target")
	if r1 != r2 {
		t.Fatalf("non-deterministic Merkle digest: %s != %s", r1, r2)
	}

	// Distinct routes — including adversarial delimiter collisions — must all map to distinct digests.
	routes := []struct {
		upstream []string
		node     string
	}{
		{nil, "jumpB"},
		{[]string{"jumpA"}, "jumpB"},
		{[]string{"jumpX"}, "jumpB"},
		{[]string{"jumpA", "jumpB"}, "target"},
		{[]string{"jumpB", "jumpA"}, "target"},
		{[]string{"a:b"}, "c"},
		{[]string{"a"}, "b;1:c"},
		{[]string{"a;1:b"}, "c"},
		{[]string{"a", "b"}, "c"},
		{[]string{"a,b"}, "c"},
		{[]string{"a->b"}, "c"},
		{[]string{"a", "b->c"}, "d"},
		{[]string{"a->b", "c"}, "d"},
		{[]string{"openssh:first"}, "openssh:second"},
		{[]string{"openssh:first", "openssh:second"}, "target"},
	}
	seen := make(map[HopDigest]int, len(routes))
	for i, tc := range routes {
		key := merkleChainDigest(tc.upstream, tc.node)
		if prev, dup := seen[key]; dup {
			t.Fatalf("Merkle hop digest collision between case %d (%v -> %q) and case %d (%v -> %q): key=%s",
				prev, routes[prev].upstream, routes[prev].node, i, tc.upstream, tc.node, key)
		}
		seen[key] = i
	}
}

func newP0SSHFixture(t *testing.T, ctx context.Context, name string) (*sshfixture.Server, string, int) {
	t.Helper()
	srv, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatalf("%s fixture failed: %v", name, err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	host, port := fixtureEndpoint(t, srv.Address)
	return srv, host, port
}

func assertP0DirectVsChainedPoolIsolation(t *testing.T, ctx context.Context, connector *Connector, directB, targetClient *Client) {
	t.Helper()
	directPlan, err := connector.resolveConnectionPlan(ctx, "jumpB")
	if err != nil {
		t.Fatalf("resolveConnectionPlan(jumpB): %v", err)
	}
	chainedPlan, err := connector.resolveConnectionPlan(ctx, "target")
	if err != nil {
		t.Fatalf("resolveConnectionPlan(target): %v", err)
	}
	pooledDirectB, okDirect := connector.pool.Get(directPlan[0].hopDigest())
	pooledChainedB, okChained := connector.pool.Get(chainedPlan[1].hopDigest())
	if !okDirect || !okChained {
		t.Fatalf("expected both direct (%v) and chained (%v) jumpB entries in pool", okDirect, okChained)
	}
	if pooledDirectB == pooledChainedB || pooledDirectB.SSHClient == pooledChainedB.SSHClient {
		t.Fatal("direct and chained jumpB entries share the same PooledClient/SSHClient")
	}
	if directB.sshClient != pooledDirectB.SSHClient {
		t.Fatal("direct jumpB client does not match direct pool entry")
	}
	if targetClient.Config().NodeID != "target" {
		t.Fatalf("targetClient NodeID = %q, want target", targetClient.Config().NodeID)
	}
}

func TestP0_ProxyJumpRouteIsolation_DirectVsChained(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	jumpA, aHost, aPort := newP0SSHFixture(t, ctx, "jumpA")
	jumpB, bHost, bPort := newP0SSHFixture(t, ctx, "jumpB")
	target, tHost, tPort := newP0SSHFixture(t, ctx, "target")

	provider := &jumpChainProvider{
		cfgs: map[string]*ClientConfig{
			"jumpA": {
				NodeID: "jumpA", Address: aHost, Port: aPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
			"jumpB": {
				NodeID: "jumpB", Address: bHost, Port: bPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
			"target": {
				NodeID: "target", Address: tHost, Port: tPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "jumpA,jumpB",
			},
		},
	}

	connector := newTestConnector(provider, WithHostKeyVerifier(&fixtureTrust{}))
	t.Cleanup(func() {
		if closeErr := connector.CloseAll(); closeErr != nil {
			t.Errorf("CloseAll failed: %v", closeErr)
		}
	})

	// 1. Dial jumpB directly first; caches under direct route key "jumpB".
	directB, err := connector.Connect(ctx, "jumpB")
	if err != nil {
		t.Fatalf("direct Connect(jumpB) failed: %v", err)
	}
	if jumpB.Authenticated.Load() != 1 || jumpA.Authenticated.Load() != 0 {
		t.Fatalf("after direct jumpB: jumpA=%d jumpB=%d, want 0/1",
			jumpA.Authenticated.Load(), jumpB.Authenticated.Load())
	}

	// 2. Connect to target via ProxyJump "jumpA,jumpB".
	// Must NOT hit direct cached "jumpB" and bypass jumpA!
	targetClient, err := connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("chained Connect(target) failed: %v", err)
	}
	if jumpA.Authenticated.Load() != 1 || jumpB.Authenticated.Load() != 2 || target.Authenticated.Load() != 1 {
		t.Fatalf("chained connect auth counts: jumpA=%d jumpB=%d target=%d, want 1/2/1",
			jumpA.Authenticated.Load(), jumpB.Authenticated.Load(), target.Authenticated.Load())
	}

	// 3. Direct jumpB and chained jumpB must occupy distinct pool slots with distinct SSHClients.
	assertP0DirectVsChainedPoolIsolation(t, ctx, connector, directB, targetClient)

	// 4. Subsequent Connect(target) reuses the chained route without re-authenticating.
	if _, err := connector.Connect(ctx, "target"); err != nil {
		t.Fatalf("second Connect(target) failed: %v", err)
	}
	if jumpA.Authenticated.Load() != 1 || jumpB.Authenticated.Load() != 2 || target.Authenticated.Load() != 1 {
		t.Fatalf("unexpected re-authentication on reuse: jumpA=%d jumpB=%d target=%d",
			jumpA.Authenticated.Load(), jumpB.Authenticated.Load(), target.Authenticated.Load())
	}

	// 5. CloseAll cleans up every active and retired pooled client.
	if err := connector.CloseAll(); err != nil {
		t.Fatalf("CloseAll failed: %v", err)
	}
	if connector.pool.Count() != 0 || connector.pool.RetiredCount() != 0 {
		t.Fatalf("expected empty active/retired pools after CloseAll, got active=%d retired=%d",
			connector.pool.Count(), connector.pool.RetiredCount())
	}
}

type rendezvousDialer struct {
	targetAddr string
	entered    chan struct{}
	release    chan struct{}
	once       sync.Once
}

func (d *rendezvousDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *rendezvousDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if addr == d.targetAddr {
		d.once.Do(func() {
			close(d.entered)
		})
		select {
		case <-d.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
}

func TestP0_ProxyJumpRouteIsolation_ConcurrentSingleflight(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	jumpA, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatalf("jumpA fixture failed: %v", err)
	}
	defer func() { _ = jumpA.Close() }()

	jumpB, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatalf("jumpB fixture failed: %v", err)
	}
	defer func() { _ = jumpB.Close() }()

	target, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatalf("target fixture failed: %v", err)
	}
	defer func() { _ = target.Close() }()

	aHost, aPort := fixtureEndpoint(t, jumpA.Address)
	bHost, bPort := fixtureEndpoint(t, jumpB.Address)
	tHost, tPort := fixtureEndpoint(t, target.Address)

	provider := &jumpChainProvider{
		cfgs: map[string]*ClientConfig{
			"jumpA": {
				NodeID: "jumpA", Address: aHost, Port: aPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
			"jumpB": {
				NodeID: "jumpB", Address: bHost, Port: bPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
			"target": {
				NodeID: "target", Address: tHost, Port: tPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "jumpA,jumpB",
			},
		},
	}

	dialer := &rendezvousDialer{
		targetAddr: jumpB.Address,
		entered:    make(chan struct{}),
		release:    make(chan struct{}),
	}
	connector := newTestConnector(provider, WithDialer(dialer), WithHostKeyVerifier(&fixtureTrust{}))
	defer func() {
		select {
		case <-dialer.release:
		default:
			close(dialer.release)
		}
		if closeErr := connector.CloseAll(); closeErr != nil {
			t.Errorf("CloseAll failed: %v", closeErr)
		}
	}()

	// Hold direct Connect(jumpB) mid-flight inside singleflight.
	directErrCh := make(chan error, 1)
	go func() {
		_, err := connector.Connect(ctx, "jumpB")
		directErrCh <- err
	}()
	select {
	case <-dialer.entered:
	case <-ctx.Done():
		t.Fatal("direct jumpB dial never reached rendezvous")
	}

	// Concurrently connect to target via jumpA,jumpB while direct jumpB is still blocked!
	// Because singleflight is keyed by routeKey, target MUST finish without blocking on
	// direct jumpB's singleflight lane and MUST dial jumpB through jumpA.
	targetErrCh := make(chan error, 1)
	go func() {
		_, err := connector.Connect(ctx, "target")
		targetErrCh <- err
	}()

	select {
	case err := <-targetErrCh:
		if err != nil {
			t.Fatalf("chained Connect(target) failed while direct jumpB blocked: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("chained Connect(target) coalesced onto direct jumpB singleflight lane and deadlocked!")
	}

	if got := jumpA.Authenticated.Load(); got != 1 {
		t.Fatalf("jumpA authenticated = %d, want 1", got)
	}
	if got := jumpB.Authenticated.Load(); got != 1 {
		t.Fatalf("jumpB authenticated = %d while direct dial still blocked, want 1", got)
	}

	// Now unblock direct jumpB and confirm it completes independently too.
	close(dialer.release)
	select {
	case err := <-directErrCh:
		if err != nil {
			t.Fatalf("direct Connect(jumpB) failed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("direct Connect(jumpB) did not complete after release")
	}
	if got := jumpB.Authenticated.Load(); got != 2 {
		t.Fatalf("final jumpB authenticated = %d, want 2 (1 chained + 1 direct)", got)
	}
}

type mutableRouteProvider struct {
	mu   sync.RWMutex
	cfgs map[string]*ClientConfig
}

func (p *mutableRouteProvider) GetConfig(nodeID string) (*ClientConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	cfg, ok := p.cfgs[nodeID]
	if !ok {
		return nil, fmt.Errorf("unknown node %q", nodeID)
	}
	cp := *cfg
	return &cp, nil
}

func TestP0_ProxyJumpRouteIsolation_IntermediateHopRouteChange(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	jumpA, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = jumpA.Close() }()

	jumpX, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = jumpX.Close() }()

	jumpB, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = jumpB.Close() }()

	target, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = target.Close() }()

	aHost, aPort := fixtureEndpoint(t, jumpA.Address)
	xHost, xPort := fixtureEndpoint(t, jumpX.Address)
	bHost, bPort := fixtureEndpoint(t, jumpB.Address)
	tHost, tPort := fixtureEndpoint(t, target.Address)

	provider := &mutableRouteProvider{
		cfgs: map[string]*ClientConfig{
			"jumpA":  {NodeID: "jumpA", Address: aHost, Port: aPort, User: "fixture", AuthType: "password", Password: sshfixture.Password},
			"jumpX":  {NodeID: "jumpX", Address: xHost, Port: xPort, User: "fixture", AuthType: "password", Password: sshfixture.Password},
			"jumpB":  {NodeID: "jumpB", Address: bHost, Port: bPort, User: "fixture", AuthType: "password", Password: sshfixture.Password, ProxyJump: "jumpA"},
			"target": {NodeID: "target", Address: tHost, Port: tPort, User: "fixture", AuthType: "password", Password: sshfixture.Password, ProxyJump: "jumpB"},
		},
	}

	connector := newTestConnector(provider, WithHostKeyVerifier(&fixtureTrust{}))
	defer func() { _ = connector.CloseAll() }()

	if _, err := connector.Connect(ctx, "target"); err != nil {
		t.Fatalf("first Connect(target) failed: %v", err)
	}
	if jumpA.Authenticated.Load() != 1 || jumpX.Authenticated.Load() != 0 {
		t.Fatalf("unexpected initial auth counts: jumpA=%d jumpX=%d", jumpA.Authenticated.Load(), jumpX.Authenticated.Load())
	}

	// Mutate intermediate hop jumpB to route through jumpX instead of jumpA.
	// target.ProxyJump is still "jumpB", so only full-upstream route keying isolates it!
	provider.mu.Lock()
	provider.cfgs["jumpB"].ProxyJump = "jumpX"
	provider.mu.Unlock()

	if _, err := connector.Connect(ctx, "target"); err != nil {
		t.Fatalf("second Connect(target) after upstream change failed: %v", err)
	}
	if jumpX.Authenticated.Load() != 1 {
		t.Fatalf("jumpX was bypassed after jumpB's ProxyJump changed! jumpX auth=%d, want 1", jumpX.Authenticated.Load())
	}
	if target.Authenticated.Load() != 2 {
		t.Fatalf("target reused stale route! target auth=%d, want 2", target.Authenticated.Load())
	}
}

type stubCloseConn struct {
	net.Conn
	closed atomic.Bool
}

func (s *stubCloseConn) Close() error {
	s.closed.Store(true)
	return nil
}

func TestP0_ReuseJumpChainedTarget_CascadeEvictsAllDownstreamHops(t *testing.T) {
	store := &mockProxyJumpStore{cfgs: map[string]*ClientConfig{
		"jumpA":  {NodeID: "jumpA", Address: "192.0.2.1", Port: 22, User: "ops"},
		"jumpB":  {NodeID: "jumpB", Address: "192.0.2.2", Port: 22, User: "ops", ProxyJump: "jumpA"},
		"jumpC":  {NodeID: "jumpC", Address: "192.0.2.3", Port: 22, User: "ops", ProxyJump: "jumpB"},
		"target": {NodeID: "target", Address: "192.0.2.4", Port: 22, User: "ops", ProxyJump: "jumpC"},
	}}
	connector := newTestConnector(store)
	defer func() { _ = connector.CloseAll() }()

	plan, err := connector.resolveConnectionPlan(t.Context(), "target")
	if err != nil {
		t.Fatalf("resolveConnectionPlan failed: %v", err)
	}
	if len(plan) != 4 {
		t.Fatalf("len(plan) = %d, want 4", len(plan))
	}

	// plan = [target, jumpC, jumpB, jumpA]
	deadA := &coordinatedDeadConn{
		requestSeen: make(chan struct{}),
		release:     make(chan struct{}),
	}
	close(deadA.release)

	rootA := &stubCloseConn{}
	rootDirectB := &stubCloseConn{}

	keyA := plan[3].hopDigest()
	keyB := plan[2].hopDigest()
	keyC := plan[1].hopDigest()
	keyT := plan[0].hopDigest()
	keyDirectB := DigestClientConfig(NewClientConfig(*store.cfgs["jumpB"]), ZeroHopDigest)

	var kaCanceledB, kaCanceledC, kaCanceledT atomic.Bool
	pooledA := &PooledClient{SSHClient: &cryptoSSH.Client{Conn: deadA}, RootConn: rootA}
	pooledB := &PooledClient{SSHClient: &cryptoSSH.Client{}, RootConn: rootA, parentKey: keyA, kaCancel: func() { kaCanceledB.Store(true) }}
	pooledC := &PooledClient{SSHClient: &cryptoSSH.Client{}, RootConn: rootA, parentKey: keyB, kaCancel: func() { kaCanceledC.Store(true) }}
	pooledT := &PooledClient{SSHClient: &cryptoSSH.Client{}, RootConn: rootA, parentKey: keyC, kaCancel: func() { kaCanceledT.Store(true) }}
	pooledDirectB := &PooledClient{SSHClient: &cryptoSSH.Client{}, RootConn: rootDirectB}

	if _, err := connector.pool.Publish(keyA, pooledA, nil, nil); err != nil {
		t.Fatalf("publish A: %v", err)
	}
	if _, err := connector.pool.Publish(keyB, pooledB, pooledA, nil); err != nil {
		t.Fatalf("publish B: %v", err)
	}
	if _, err := connector.pool.Publish(keyC, pooledC, pooledB, nil); err != nil {
		t.Fatalf("publish C: %v", err)
	}
	if _, err := connector.pool.Publish(keyT, pooledT, pooledC, nil); err != nil {
		t.Fatalf("publish T: %v", err)
	}
	if _, err := connector.pool.Publish(keyDirectB, pooledDirectB, nil, nil); err != nil {
		t.Fatalf("publish directB: %v", err)
	}

	reused, err := connector.validateCachedChain(t.Context(), plan, connector.pool.SnapshotChain(plan))
	if !errors.Is(err, errJumpChainRequired) {
		t.Fatalf("validateCachedChain err = %v, want errJumpChainRequired", err)
	}
	if reused != nil {
		t.Fatalf("expected nil reused client after outer hop failure, got %v", reused)
	}

	// All hops in the failed chain (jumpA + downstream jumpB, jumpC, target) must be evicted!
	for name, k := range map[string]HopDigest{"jumpA": keyA, "jumpB": keyB, "jumpC": keyC, "target": keyT} {
		if _, exists := connector.pool.Get(k); exists {
			t.Errorf("hop %s (%s) remained in pool after outer hop jumpA failed", name, k)
		}
	}
	if !rootA.closed.Load() {
		t.Fatal("expected shared chain root transport to be interrupted")
	}
	if !kaCanceledB.Load() || !kaCanceledC.Load() || !kaCanceledT.Load() {
		t.Fatalf("expected all downstream keepalives canceled: B=%v C=%v T=%v",
			kaCanceledB.Load(), kaCanceledC.Load(), kaCanceledT.Load())
	}

	// Unrelated direct route to jumpB must remain untouched!
	if got, ok := connector.pool.Get(keyDirectB); !ok || got != pooledDirectB {
		t.Fatal("unrelated direct route for jumpB was evicted by chained jumpA failure")
	}
	if rootDirectB.closed.Load() {
		t.Fatal("unrelated direct route for jumpB was interrupted")
	}
	connector.pool.Clear()
}

func TestP0_ReuseJumpChainedTarget_CascadeEvictsOnlySameRootGeneration(t *testing.T) {
	store := &mockProxyJumpStore{cfgs: map[string]*ClientConfig{
		"jumpA":  {NodeID: "jumpA", Address: "192.0.2.1", Port: 22, User: "ops"},
		"jumpB":  {NodeID: "jumpB", Address: "192.0.2.2", Port: 22, User: "ops", ProxyJump: "jumpA"},
		"target": {NodeID: "target", Address: "192.0.2.3", Port: 22, User: "ops", ProxyJump: "jumpB"},
	}}
	connector := newTestConnector(store)
	defer func() { _ = connector.CloseAll() }()

	plan, err := connector.resolveConnectionPlan(t.Context(), "target")
	if err != nil {
		t.Fatalf("resolveConnectionPlan failed: %v", err)
	}
	keyA := plan[2].hopDigest()
	keyB := plan[1].hopDigest()
	keyT := plan[0].hopDigest()

	deadA := &coordinatedDeadConn{
		requestSeen: make(chan struct{}),
		release:     make(chan struct{}),
	}
	close(deadA.release)

	gen1Root := &physicalSSHConn{Conn: &stubCloseConn{}}
	gen2Root := &physicalSSHConn{Conn: &stubCloseConn{}}

	pooledA := &PooledClient{SSHClient: &cryptoSSH.Client{Conn: deadA}, RootConn: gen1Root}
	pooledBGen1 := &PooledClient{SSHClient: &cryptoSSH.Client{}, RootConn: gen1Root, parentKey: keyA}
	pooledTGen2 := &PooledClient{SSHClient: &cryptoSSH.Client{}, RootConn: gen2Root}

	if _, err := connector.pool.Publish(keyA, pooledA, nil, nil); err != nil {
		t.Fatalf("publish A: %v", err)
	}
	if _, err := connector.pool.Publish(keyB, pooledBGen1, pooledA, nil); err != nil {
		t.Fatalf("publish B: %v", err)
	}
	if _, err := connector.pool.Publish(keyT, pooledTGen2, nil, nil); err != nil {
		t.Fatalf("publish T: %v", err)
	}

	// Pure reuse decision MUST reject a chain whose parent/child RootConn generations diverge.
	if canReuseCachedChain(plan, connector.pool.SnapshotChain(plan)) {
		t.Fatal("canReuseCachedChain accepted divergent RootConn generations")
	}

	// Evicting gen1 jumpA cascade-evicts gen1 jumpB while preserving unrelated gen2Root target.
	connector.pool.Evict(keyA, pooledA, true)
	if _, exists := connector.pool.Get(keyB); exists {
		t.Fatal("stale gen1 jumpB was not cascade-evicted")
	}
	if got, exists := connector.pool.Get(keyT); !exists || got != pooledTGen2 {
		t.Fatal("fresher gen2 target was wrongly evicted by gen1 cascade")
	}
	if gen2Root.closed.Load() {
		t.Fatal("fresher gen2 transport was wrongly interrupted by gen1 cascade")
	}
	connector.pool.Clear()
}

func TestP0_MuxProxyPublishWrapsPhysicalSSHConn(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix control socket mux proxy test runs on unix")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	bastion, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatalf("bastion fixture failed: %v", err)
	}
	defer func() { _ = bastion.Close() }()

	host, port := fixtureEndpoint(t, bastion.Address)
	sockPath := filepath.Join(shortSocketDir(t), "p0-mux-phys.sock")

	provider := &jumpChainProvider{
		cfgs: map[string]*ClientConfig{
			"bastion": {
				NodeID: "bastion", Address: host, Port: port,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
		},
		ctrl: map[string]*ControlConfig{
			"bastion": {Master: ControlMasterAuto, Path: sockPath},
		},
	}

	masterConn := newTestConnector(provider, WithHostKeyVerifier(&fixtureTrust{}))
	defer func() { _ = masterConn.CloseAll() }()
	if _, err := masterConn.Connect(ctx, "bastion"); err != nil {
		t.Fatalf("master Connect(bastion) failed: %v", err)
	}
	waitForCondition(t, 5*time.Second, func() bool {
		return GetActiveMuxServer(sockPath) != nil
	}, "master mux server did not start")

	// Second connector attaches via tryDialAndPublishProxy.
	proxyConnector := newTestConnector(provider, WithHostKeyVerifier(&fixtureTrust{}))
	defer func() { _ = proxyConnector.CloseAll() }()

	client, err := proxyConnector.Connect(ctx, "bastion")
	if err != nil {
		t.Fatalf("proxy Connect(bastion) failed: %v", err)
	}
	bastionKey := DigestClientConfig(NewClientConfig(*provider.cfgs["bastion"]), ZeroHopDigest)
	pooled, ok := proxyConnector.pool.Get(bastionKey)
	if !ok || pooled == nil {
		t.Fatal("proxy client was not published to connector.pool")
	}
	phys, ok := pooled.RootConn.(*physicalSSHConn)
	if !ok || phys == nil {
		t.Fatalf("pooled.RootConn = %T, want *physicalSSHConn", pooled.RootConn)
	}
	if client.rootConn != phys {
		t.Fatalf("returned client.rootConn = %T, want same *physicalSSHConn", client.rootConn)
	}

	proxyDialer := &SSHProxyDialer{Client: client.sshClient, RootConn: client.rootConn}
	if proxyDialer.transportClosed() {
		t.Fatal("transportClosed() must be false while mux proxy transport is open")
	}
	if err := pooled.interrupt(); err != nil {
		t.Fatalf("pooled.interrupt() failed: %v", err)
	}
	if !proxyDialer.transportClosed() {
		t.Fatal("transportClosed() must be true after mux proxy transport is closed")
	}

	// connectNode must observe proxy.transportClosed() and return errProxyTransportClosed.
	downstreamCfg := NewClientConfig(ClientConfig{NodeID: "target", Address: "192.0.2.99", Port: 22, User: "fixture", ProxyJump: "bastion"})
	downstreamNode := connectionPlanNode{
		name:         "target",
		parentDigest: bastionKey,
		digest:       DigestClientConfig(downstreamCfg, bastionKey),
		cfg:          downstreamCfg,
	}
	_, nodeErr := proxyConnector.connectNode(ctx, downstreamNode, proxyDialer, pooled, false)
	if !errors.Is(nodeErr, errProxyTransportClosed) {
		t.Fatalf("connectNode with closed mux proxy dialer = %v, want errProxyTransportClosed", nodeErr)
	}
}

func TestP0_StartKeepAliveFor_OverflowSaturation(t *testing.T) {
	t.Parallel()

	// Unit tests for multiplyDurationSaturated.
	cases := []struct {
		d     time.Duration
		count int
		want  time.Duration
	}{
		{0, 3, 0},
		{-time.Second, 3, 0},
		{time.Second, 0, 0},
		{time.Second, -1, 0},
		{15 * time.Second, 3, 45 * time.Second},
		{time.Duration(math.MaxInt64 / 3), 3, time.Duration(math.MaxInt64/3) * 3},
		{time.Duration(math.MaxInt64/3) + 1, 3, time.Duration(math.MaxInt64)},
		{time.Duration(math.MaxInt64), 2, time.Duration(math.MaxInt64)},
		{time.Duration(math.MaxInt64), 1000, time.Duration(math.MaxInt64)},
		{time.Duration(math.MaxInt64 / 2), 3, time.Duration(math.MaxInt64)},
	}
	for _, tc := range cases {
		got := multiplyDurationSaturated(tc.d, tc.count)
		if got != tc.want {
			t.Errorf("multiplyDurationSaturated(%v, %d) = %v, want %v", tc.d, tc.count, got, tc.want)
		}
		if got < 0 {
			t.Errorf("multiplyDurationSaturated(%v, %d) overflowed to negative %v", tc.d, tc.count, got)
		}
	}

	// Integration with publishPooled keepalive attachment: huge ServerAliveInterval * ServerAliveCountMax
	// must saturate without negative timeout or immediate eviction.
	conn := NewConnector(nil)
	defer func() { _ = conn.CloseAll() }()

	// ServerAliveInterval=2147483647 (max int32 seconds ~68 years) * ServerAliveCountMax=100
	// overflows int64 nanoseconds without saturation!
	opts := MustOptions(
		OptionServerAliveInterval, strconv.Itoa(math.MaxInt32),
		OptionServerAliveCountMax, "100",
	)
	cfg := NewClientConfig(ClientConfig{NodeID: "overflow-node", Options: opts})
	pooled := &PooledClient{SSHClient: &cryptoSSH.Client{Conn: &coordinatedHealthyConn{
		requestSeen: make(chan struct{}),
		release:     make(chan struct{}),
	}}}
	nodeKey := DigestClientConfig(cfg, ZeroHopDigest)
	if _, err := conn.publishPooled(nodeKey, pooled, nil, cfg); err != nil {
		t.Fatalf("publishPooled failed: %v", err)
	}

	active, kaDone := pooled.keepAliveState()
	if !active || kaDone == nil {
		t.Fatal("expected keepalive to be attached on published client")
	}
	select {
	case <-kaDone:
		t.Fatal("keepalive exited immediately (possible negative timeout overflow)")
	case <-time.After(30 * time.Millisecond):
	}
	if _, stillCached := conn.pool.Get(nodeKey); !stillCached {
		t.Fatal("client was evicted immediately due to keepalive duration overflow")
	}
}

func newP0Ed25519Key(t *testing.T) cryptoSSH.PublicKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	signer, err := cryptoSSH.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return signer.PublicKey()
}

func TestP0_KnownHosts_ConcurrentOpenAndAppend_NoTruncation(t *testing.T) {
	dir := t.TempDir()
	khPath := filepath.Join(dir, ".ssh", "known_hosts")

	env := fixtureEnvironment()
	env.HomeDir = dir
	env.KnownHostsFile = khPath
	env.GlobalKnownHostsFiles = nil
	conn := NewConnector(nil, WithEnvironment(env))
	defer func() { _ = conn.CloseAll() }()

	const writers = 16
	const readers = 16
	keys := make([]cryptoSSH.PublicKey, writers)
	hosts := make([]string, writers)
	for i := range writers {
		keys[i] = newP0Ed25519Key(t)
		hosts[i] = fmt.Sprintf("host-%02d.example.com:22", i)
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	errCh := make(chan error, writers+readers*8)

	// Writers concurrently append distinct keys starting when khPath does NOT exist yet.
	for i := range writers {
		wg.Go(func() {
			<-start
			if err := appendKnownHost(khPath, hosts[i], keys[i], false); err != nil {
				errCh <- fmt.Errorf("appendKnownHost(%s): %w", hosts[i], err)
			}
		})
	}

	// Readers concurrently call openKnownHostsCallback (default path creation + strict parse).
	// Previously os.Stat + os.WriteFile(..., O_TRUNC) raced with writers and wiped pinned keys!
	for r := range readers {
		wg.Go(func() {
			<-start
			cfg := &ClientConfig{NodeID: fmt.Sprintf("r-%d", r), Address: "reader.example.com", Port: 22, User: "ops"}
			for range 8 {
				if _, _, _, err := conn.openKnownHostsCallback("", cfg); err != nil {
					errCh <- fmt.Errorf("openKnownHostsCallback: %w", err)
					return
				}
			}
		})
	}

	close(start)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent known_hosts error: %v", err)
	}

	// Verify EVERY pinned key survived intact with zero truncation or partial-line corruption.
	_, _, cb, err := conn.openKnownHostsCallback("", &ClientConfig{NodeID: "verify", Address: "verify.example.com", Port: 22, User: "ops"})
	if err != nil {
		t.Fatalf("final openKnownHostsCallback failed: %v", err)
	}
	addr := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 22}
	for i := range writers {
		if err := cb(hosts[i], addr, keys[i]); err != nil {
			t.Errorf("pinned key for %s was lost/corrupted after concurrent open+append: %v", hosts[i], err)
		}
	}
}

func TestP0_KnownHosts_AppendPreservesExistingLineWithoutTrailingNewline(t *testing.T) {
	dir := t.TempDir()
	khPath := filepath.Join(dir, "known_hosts")

	key1 := newP0Ed25519Key(t)
	key2 := newP0Ed25519Key(t)
	key3 := newP0Ed25519Key(t)

	// Write initial entry deliberately WITHOUT a trailing '\n'.
	firstLine := knownhosts.Line([]string{"first.example.com"}, key1)
	if err := os.WriteFile(khPath, []byte(firstLine), 0o600); err != nil {
		t.Fatalf("seed known_hosts failed: %v", err)
	}

	if err := appendKnownHost(khPath, "second.example.com:22", key2, false); err != nil {
		t.Fatalf("appendKnownHost(second) failed: %v", err)
	}
	if err := appendKnownHost(khPath, "third.example.com:2222", key3, true); err != nil {
		t.Fatalf("appendKnownHost(third) failed: %v", err)
	}

	raw, err := os.ReadFile(khPath)
	if err != nil {
		t.Fatalf("read known_hosts failed: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 non-merged lines in known_hosts, got %d:\n%s", len(lines), raw)
	}

	env := fixtureEnvironment()
	env.HomeDir = dir
	env.KnownHostsFile = khPath
	env.GlobalKnownHostsFiles = nil
	conn := NewConnector(nil, WithEnvironment(env))
	defer func() { _ = conn.CloseAll() }()

	_, _, cb, err := conn.openKnownHostsCallback(khPath, &ClientConfig{NodeID: "n", Address: "first.example.com", Port: 22, User: "ops"})
	if err != nil {
		t.Fatalf("openKnownHostsCallback failed on appended file: %v", err)
	}
	addr := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 22}
	if err := cb("first.example.com:22", addr, key1); err != nil {
		t.Fatalf("first.example.com key failed verification: %v", err)
	}
	if err := cb("second.example.com:22", addr, key2); err != nil {
		t.Fatalf("second.example.com key failed verification: %v", err)
	}
	if err := cb("third.example.com:2222", addr, key3); err != nil {
		t.Fatalf("third.example.com:2222 hashed key failed verification: %v", err)
	}
}

func TestP0_ValidateTargetCompatibility_BaseHost(t *testing.T) {
	t.Parallel()

	base := ClientConfig{
		NodeID:   "web",
		Address:  "override.example.com",
		BaseHost: "10.0.0.10",
		Port:     22,
		User:     "ops",
	}
	cur := base.ToConnectionConfig()

	// Exact match succeeds.
	same := base
	if err := checkTargetDigestCompatibility(cur, &same); err != nil {
		t.Fatalf("identical BaseHost unexpectedly failed: %v", err)
	}

	// Trimmed whitespace match succeeds.
	padded := base
	padded.BaseHost = "  10.0.0.10 \t"
	if err := checkTargetDigestCompatibility(cur, &padded); err != nil {
		t.Fatalf("whitespace-padded identical BaseHost unexpectedly failed: %v", err)
	}

	// Drift cases under identical override Address must fail closed with ErrSnapshotMismatch.
	drifts := []struct {
		name    string
		curBase string
		newBase string
	}{
		{"changed saved host", "10.0.0.10", "10.0.0.99"},
		{"cleared saved host", "10.0.0.10", ""},
		{"added saved host", "", "10.0.0.10"},
	}
	for _, tc := range drifts {
		t.Run(tc.name, func(t *testing.T) {
			cCfg := cur
			cCfg.BaseHost = tc.curBase
			nCfg := base
			nCfg.BaseHost = tc.newBase
			err := checkTargetDigestCompatibility(cCfg, &nCfg)
			if !errors.Is(err, ErrSnapshotMismatch) {
				t.Fatalf("checkTargetDigestCompatibility(cur=%q, new=%q) = %v, want ErrSnapshotMismatch",
					tc.curBase, tc.newBase, err)
			}
		})
	}
}
