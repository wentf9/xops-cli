package ssh

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func makeRawUnnormalizedClientConfig(addr string, port int) *ClientConfig {
	return &ClientConfig{
		KeyRef:               "key-ref-1",
		TrustVersion:         "trust-v1",
		NodeID:               "v6-ingest",
		OriginalHost:         "  web.prod  ",
		CanonicalHost:        "  web.prod.example.com  ",
		Address:              "  [" + addr + "]  ",
		BaseHost:             "  [2001:db8::20]  ",
		Port:                 port,
		User:                 "fixture",
		AuthType:             "  PaSsWoRd  ",
		Password:             sshfixture.Password,
		KeyPaths:             []string{"/tmp/id_a"},
		AuthUpdateToken:      "auth-v1",
		SudoMode:             SudoModeAuto,
		SudoUpdateToken:      "sudo-v1",
		HasOriginalProxyJump: true,
		Execution:            &ExecutionConfig{Interpreter: InterpreterSh},
		Options: MustOptions(
			OptionControlMaster, "no",
			OptionControlPath, "none",
			OptionControlPersist, "no",
		),
		EnforceAdmittedCertificates: true,
		AdmittedCertificates:        []AdmittedCertificate{{Path: "/tmp/cert.pub", SHA256: "abc", RawBytes: []byte("cert-raw")}},
		EnforceAdmittedKeyDigests:   true,
		AdmittedKeyDigests:          []AdmittedKeyDigest{{Path: "/tmp/id_a", SHA256: "def"}},
	}
}

func assertNormalizedClientConfig(t *testing.T, label string, cfg *ClientConfig, wantAddr string, wantPort int, wantDigest HopDigest) {
	t.Helper()
	if cfg == nil {
		t.Fatalf("%s: got nil ClientConfig", label)
	}
	if cfg.Address != wantAddr {
		t.Errorf("%s: Address = %q, want %q", label, cfg.Address, wantAddr)
	}
	if cfg.BaseHost != "2001:db8::20" {
		t.Errorf("%s: BaseHost = %q, want %q", label, cfg.BaseHost, "2001:db8::20")
	}
	if cfg.Port != wantPort {
		t.Errorf("%s: Port = %d, want %d", label, cfg.Port, wantPort)
	}
	if cfg.OriginalHost != "web.prod" {
		t.Errorf("%s: OriginalHost = %q, want %q", label, cfg.OriginalHost, "web.prod")
	}
	if cfg.CanonicalHost != "web.prod.example.com" {
		t.Errorf("%s: CanonicalHost = %q, want %q", label, cfg.CanonicalHost, "web.prod.example.com")
	}
	if cfg.AuthType != "password" {
		t.Errorf("%s: AuthType = %q, want %q", label, cfg.AuthType, "password")
	}
	if got := DigestClientConfig(cfg, ZeroHopDigest); !got.Equal(wantDigest) {
		t.Errorf("%s: HopDigest = %s, want %s", label, got, wantDigest)
	}
}

func assertNewClientConfigCloneAndIdempotency(t *testing.T) {
	t.Helper()
	rawZero := makeRawUnnormalizedClientConfig("2001:db8::10", 0)
	wantZeroDigest := DigestClientConfig(rawZero, ZeroHopDigest)
	norm := NewClientConfig(*rawZero)
	assertNormalizedClientConfig(t, "NewClientConfig", norm, "2001:db8::10", 22, wantZeroDigest)

	norm2 := NewClientConfig(*norm)
	if !reflect.DeepEqual(norm, norm2) {
		t.Fatalf("NewClientConfig is not idempotent:\nfirst =%+v\nsecond=%+v", norm, norm2)
	}
	rawZero.KeyPaths[0] = "/mutated"
	rawZero.AdmittedCertificates[0].RawBytes[0] = 'X'
	rawZero.AdmittedKeyDigests[0].Path = "/mutated"
	rawZero.Execution.Interpreter = InterpreterBash
	_ = rawZero.Options.Set(OptionControlMaster, "auto")
	if norm.KeyPaths[0] != "/tmp/id_a" || string(norm.AdmittedCertificates[0].RawBytes) != "cert-raw" ||
		norm.AdmittedKeyDigests[0].Path != "/tmp/id_a" || norm.Execution.Interpreter != InterpreterSh ||
		norm.Options.ControlMaster() != "no" {
		t.Fatal("NewClientConfig did not deep-clone mutable fields")
	}

	rawFresh := makeRawUnnormalizedClientConfig("2001:db8::10", 0)
	fromConn := rawFresh.ToConnectionConfig().toClientConfig()
	assertNormalizedClientConfig(t, "ToConnectionConfig/toClientConfig", fromConn, "2001:db8::10", 22, wantZeroDigest)
	if fromConn.Password != "" {
		t.Fatal("toClientConfig leaked plaintext Password")
	}

	policy := freezeDialPolicy(rawFresh)
	assertNormalizedClientConfig(t, "freezeDialPolicy.readOnlyConfig", policy.readOnlyConfig(), "2001:db8::10", 22, wantZeroDigest)
	assertNormalizedClientConfig(t, "freezeDialPolicy.toConnectionConfig", policy.toConnectionConfig().toClientConfig(), "2001:db8::10", 22, wantZeroDigest)
}

// TestClientConfig_AllIngestionPointsNormalize enumerates every ClientConfig
// ingestion boundary in core/ssh and asserts that each produces canonically
// normalized fields and an identical Merkle HopDigest.
func TestClientConfig_AllIngestionPointsNormalize(t *testing.T) {
	t.Parallel()

	assertNewClientConfigCloneAndIdempotency(t)

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	_, host, port := newP0SSHFixture(t, ctx, "ingest")
	rawLive := makeRawUnnormalizedClientConfig(host, port)
	rawLive.EnforceAdmittedCertificates = false
	rawLive.AdmittedCertificates = nil
	rawLive.EnforceAdmittedKeyDigests = false
	rawLive.AdmittedKeyDigests = nil
	wantLiveDigest := DigestClientConfig(rawLive, ZeroHopDigest)

	provider := &mutableRouteProvider{
		cfgs: map[string]*ClientConfig{
			"v6-ingest": rawLive,
		},
	}
	connector := newTestConnector(provider, WithHostKeyVerifier(&fixtureTrust{}))
	t.Cleanup(func() { _ = connector.CloseAll() })

	plan, err := connector.resolveConnectionPlan(ctx, "v6-ingest")
	if err != nil {
		t.Fatalf("resolveConnectionPlan failed: %v", err)
	}
	assertNormalizedClientConfig(t, "resolveConnectionPlan", plan[0].cfg, host, port, wantLiveDigest)
	if !plan[0].hopDigest().Equal(wantLiveDigest) {
		t.Fatalf("plan[0].hopDigest() = %s, want %s", plan[0].hopDigest(), wantLiveDigest)
	}

	reloaded, err := connector.reloadConfigAfterRecording("v6-ingest", false, &stubCloseConn{})
	if err != nil {
		t.Fatalf("reloadConfigAfterRecording failed: %v", err)
	}
	assertNormalizedClientConfig(t, "reloadConfigAfterRecording", reloaded, host, port, wantLiveDigest)

	captured, err := CapturePlan(ctx, provider, "v6-ingest", "ingest-scope")
	if err != nil {
		t.Fatalf("CapturePlan failed: %v", err)
	}
	expectedPlanCfg := NewClientConfig(*rawLive)
	expectedPlanCfg.Options.StripClasses(OptionClassMux, OptionClassForward, OptionClassSession, OptionClassLocalExec)
	if expectedPlanCfg.Options.IsEmpty() {
		expectedPlanCfg.Options = nil
	}
	fromPlan := clientConfigFromPlan(captured.Hops[0])
	assertNormalizedClientConfig(t, "CapturePlan/clientConfigFromPlan", &fromPlan, host, port, DigestClientConfig(expectedPlanCfg, ZeroHopDigest))

	client, err := connector.Connect(ctx, "v6-ingest")
	if err != nil {
		t.Fatalf("Connect(v6-ingest) failed: %v", err)
	}
	assertNormalizedClientConfig(t, "Client.Config(configSnapshot)", client.Config(), host, port, wantLiveDigest)

	provider.mu.Lock()
	provider.cfgs["v6-ingest"].SudoUpdateToken = "sudo-v2"
	provider.mu.Unlock()
	if err := client.refreshConnectionTokens(tokenRefreshKindSudo, "sudo-v2"); err != nil {
		t.Fatalf("refreshConnectionTokens failed on unnormalized provider config: %v", err)
	}
	if got := client.Config().SudoUpdateToken; got != "sudo-v2" {
		t.Fatalf("refreshed SudoUpdateToken = %q, want %q", got, "sudo-v2")
	}
	expectedRefreshed := NewClientConfig(*rawLive)
	expectedRefreshed.SudoUpdateToken = "sudo-v2"
	expectedRefreshedKey := DigestClientConfig(expectedRefreshed, ZeroHopDigest)
	if gotKey := connector.pool.DigestOf(client.pooled); gotKey != expectedRefreshedKey {
		t.Fatalf("refreshConnectionTokens did not reindex pooled client: got %s, want %s", gotKey, expectedRefreshedKey)
	}
	if err := connector.pool.CheckInvariants(false); err != nil {
		t.Fatalf("post-refreshConnectionTokens CheckInvariants failed: %v", err)
	}
}

type poolModelStormState struct {
	connector     *Connector
	provider      *mutableRouteProvider
	v1Host        string
	v1Port        int
	v2Host        string
	v2Port        int
	tHost         string
	tPort         int
	stopStorm     chan struct{}
	invErrMu      sync.Mutex
	invErr        error
	casRejections atomic.Int32
	successfulOps atomic.Int32
	reindexOps    atomic.Int32
	evictOps      atomic.Int32
	refreshOps    atomic.Int32
	kaCycleOps    atomic.Int32
	kaCheckMu     sync.RWMutex
	requireKA     bool
}

func (s *poolModelStormState) recordInvErr(err error) {
	if err == nil {
		return
	}
	s.invErrMu.Lock()
	if s.invErr == nil {
		s.invErr = err
	}
	s.invErrMu.Unlock()
}

func (s *poolModelStormState) runConnectWorker(ctx context.Context, id int) {
	for i := 0; ; i++ {
		select {
		case <-s.stopStorm:
			return
		default:
		}
		node := "target"
		if (id+i)%3 == 0 {
			node = "jump"
		}
		reqCtx, reqCancel := context.WithTimeout(ctx, 4*time.Second)
		client, err := s.connector.Connect(reqCtx, node)
		reqCancel()
		if err == nil && client != nil {
			s.successfulOps.Add(1)
			// Exercise concurrent Reindex (leaf + parent hops) and EvictByClient
			// against live Connect/Retire/keepalive transitions.
			switch (id + i) % 5 {
			case 0:
				client.SetExecution(&ExecutionConfig{Interpreter: InterpreterSh, LaunchDialect: LaunchPOSIX})
				s.reindexOps.Add(1)
			case 1:
				client.ApplyRecordedAuth("auth-storm-v2", "", nil)
				s.reindexOps.Add(1)
			case 2:
				client.ClearUpdateTokens()
				s.reindexOps.Add(1)
			case 3:
				if err := s.connector.EvictClient(client); err != nil {
					s.recordInvErr(err)
				}
				s.evictOps.Add(1)
			}
		}
	}
}

func (s *poolModelStormState) runConfigFlipper() {
	flip := false
	for {
		select {
		case <-s.stopStorm:
			return
		case <-time.After(8 * time.Millisecond):
		}
		flip = !flip
		host, port := s.v1Host, s.v1Port
		if flip {
			host, port = s.v2Host, s.v2Port
		}
		s.provider.mu.Lock()
		s.provider.cfgs["jump"] = &ClientConfig{
			NodeID: "jump", Address: host, Port: port,
			User: "fixture", AuthType: "password", Password: sshfixture.Password,
		}
		s.provider.mu.Unlock()
	}
}

func (s *poolModelStormState) runRetireAndStaleCASActor() {
	jumpV1Key := DigestClientConfig(NewClientConfig(ClientConfig{
		NodeID: "jump", Address: s.v1Host, Port: s.v1Port,
		User: "fixture", AuthType: "password", Password: sshfixture.Password,
	}), ZeroHopDigest)
	targetV1Key := DigestClientConfig(NewClientConfig(ClientConfig{
		NodeID: "target", Address: s.tHost, Port: s.tPort,
		User: "fixture", AuthType: "password", Password: sshfixture.Password,
		ProxyJump: "jump",
	}), jumpV1Key)
	for {
		select {
		case <-s.stopStorm:
			return
		case <-time.After(12 * time.Millisecond):
		}
		parent, ok := s.connector.pool.Get(jumpV1Key)
		if !ok {
			continue
		}
		s.connector.pool.Retire(jumpV1Key, parent)
		staleHop := &stubCloseConn{}
		staleChild := &PooledClient{
			SSHClient: &cryptoSSH.Client{Conn: &closeResultConn{}},
			RootConn:  parent.RootConn,
			hopConn:   staleHop,
			parentKey: jumpV1Key,
		}
		if _, err := s.connector.publishPooled(targetV1Key, staleChild, parent, nil); errors.Is(err, errStaleParentGeneration) {
			s.casRejections.Add(1)
			if !staleHop.closed.Load() {
				s.recordInvErr(errors.New("rejected stale-parent child hopConn was not closed"))
			}
			if active, _ := staleChild.keepAliveState(); active {
				s.recordInvErr(errors.New("rejected stale-parent child started a keepalive"))
			}
		}
	}
}

func (s *poolModelStormState) runInvariantChecker() {
	for {
		select {
		case <-s.stopStorm:
			return
		default:
		}
		s.kaCheckMu.RLock()
		err := s.connector.pool.CheckInvariants(s.requireKA)
		s.kaCheckMu.RUnlock()
		if err != nil {
			s.recordInvErr(err)
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (s *poolModelStormState) runTokenRefreshWorker(ctx context.Context) {
	tokens := []string{"sudo-v2", "sudo-v3", "sudo-v4", "sudo-v5"}
	for idx := 0; ; idx++ {
		select {
		case <-s.stopStorm:
			return
		default:
		}
		reqCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		cli, err := s.connector.Connect(reqCtx, "token-node")
		cancel()
		if err != nil || cli == nil {
			continue
		}
		nextTok := tokens[idx%len(tokens)]
		s.provider.mu.Lock()
		s.provider.cfgs["token-node"].SudoUpdateToken = nextTok
		s.provider.mu.Unlock()
		if err := cli.refreshConnectionTokens(tokenRefreshKindSudo, nextTok); err == nil {
			s.refreshOps.Add(1)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestModel_ConnectorPool_ConcurrentConnectFlipRetireCloseAll exercises concurrent
// multi-hop Connects, live upstream bastion config flips, retire/evict transitions,
// stale-parent CAS publish attempts, and CloseAll under -race, checking structural
// pool invariants throughout and verifying zero leaked transports or keepalives.
func TestModel_ConnectorPool_ConcurrentConnectFlipRetireCloseAll(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	_, v1Host, v1Port := newP0SSHFixture(t, ctx, "model-bastion-v1")
	_, v2Host, v2Port := newP0SSHFixture(t, ctx, "model-bastion-v2")
	_, tHost, tPort := newP0SSHFixture(t, ctx, "model-target")

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
			"token-node": {
				NodeID: "token-node", Address: tHost, Port: tPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				SudoMode: SudoModeAuto, SudoUpdateToken: "sudo-v1",
			},
		},
	}

	dialer := &p7TrackingDialer{}
	statelessTrust := &p7BarrierTrust{onCheck: func(context.Context, HostKeyRequest) error { return nil }}
	connector := newTestConnector(provider, WithDialer(dialer), WithHostKeyVerifier(statelessTrust))
	kaCtx, cancelKA := context.WithCancel(ctx)
	defer cancelKA()
	connector.EnableKeepAlive(kaCtx, 15*time.Millisecond, 500*time.Millisecond)
	t.Cleanup(func() { _ = connector.CloseAll() })

	if _, err := connector.Connect(ctx, "target"); err != nil {
		t.Fatalf("baseline Connect(target) failed: %v", err)
	}
	if err := connector.pool.CheckInvariants(true); err != nil {
		t.Fatalf("baseline pool invariant failed: %v", err)
	}

	storm := &poolModelStormState{
		connector: connector,
		provider:  provider,
		v1Host:    v1Host,
		v1Port:    v1Port,
		v2Host:    v2Host,
		v2Port:    v2Port,
		tHost:     tHost,
		tPort:     tPort,
		stopStorm: make(chan struct{}),
	}
	storm.requireKA = true

	var wg sync.WaitGroup
	for workerID := range 4 {
		wg.Go(func() { storm.runConnectWorker(ctx, workerID) })
	}
	wg.Go(storm.runConfigFlipper)
	wg.Go(storm.runRetireAndStaleCASActor)
	wg.Go(func() { storm.runTokenRefreshWorker(ctx) })
	wg.Go(storm.runInvariantChecker)

	time.Sleep(120 * time.Millisecond)
	// Also exercise StopGlobalKeepAlives concurrently with active probes, then stop storm.
	storm.kaCheckMu.Lock()
	storm.requireKA = false
	connector.pool.StopGlobalKeepAlives()
	storm.kaCheckMu.Unlock()
	storm.kaCycleOps.Add(1)
	time.Sleep(30 * time.Millisecond)
	close(storm.stopStorm)
	wg.Wait()

	storm.invErrMu.Lock()
	gotInvErr := storm.invErr
	storm.invErrMu.Unlock()
	if gotInvErr != nil {
		t.Fatalf("pool invariant violated during concurrent storm: %v", gotInvErr)
	}
	if err := connector.pool.CheckInvariants(false); err != nil {
		t.Fatalf("post-storm pool invariant failed: %v", err)
	}
	if storm.successfulOps.Load() == 0 {
		t.Fatal("expected at least one successful concurrent Connect during storm")
	}
	if storm.reindexOps.Load() == 0 {
		t.Fatal("expected at least one concurrent Reindex operation during storm")
	}
	if storm.evictOps.Load() == 0 {
		t.Fatal("expected at least one concurrent EvictClient operation during storm")
	}
	if storm.refreshOps.Load() == 0 {
		t.Fatal("expected at least one concurrent refreshConnectionTokens operation during storm")
	}

	if err := connector.CloseAll(); err != nil {
		t.Fatalf("CloseAll failed: %v", err)
	}
	if got := connector.pool.Count(); got != 0 {
		t.Fatalf("pool active count after CloseAll = %d, want 0", got)
	}
	if got := connector.pool.RetiredCount(); got != 0 {
		t.Fatalf("pool retired count after CloseAll = %d, want 0", got)
	}
	if err := connector.pool.CheckInvariants(true); err != nil {
		t.Fatalf("post-CloseAll pool invariant failed: %v", err)
	}

	conns := dialer.snapshot()
	if len(conns) == 0 {
		t.Fatal("expected tracking dialer to record at least one connection")
	}
	for i, c := range conns {
		if !c.closed.Load() {
			t.Errorf("leaked unclosed transport #%d after CloseAll (total dialed=%d, casRejections=%d)", i+1, len(conns), storm.casRejections.Load())
		}
	}
}

// TestModel_ConnectorPool_KeepAliveDeathAfterReindex verifies that when a
// pooled client is reindexed via SetExecution/ApplyRecordedAuth and its
// keepalive subsequently detects peer death, the onDead callback atomically
// evicts the client from its reindexed HopDigest key without stranding a dead,
// keepalive-less entry in the active pool.
func TestModel_ConnectorPool_KeepAliveDeathAfterReindex(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	server, host, port := newP0SSHFixture(t, ctx, "model-ka-reindex")
	provider := &mutableRouteProvider{
		cfgs: map[string]*ClientConfig{
			"node": {
				NodeID: "node", Address: host, Port: port,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				AuthUpdateToken: "v1",
			},
		},
	}

	connector := newTestConnector(provider, WithHostKeyVerifier(&fixtureTrust{}))
	kaCtx, cancelKA := context.WithCancel(ctx)
	defer cancelKA()
	connector.EnableKeepAlive(kaCtx, 25*time.Millisecond, 120*time.Millisecond)
	t.Cleanup(func() { _ = connector.CloseAll() })

	client, err := connector.Connect(ctx, "node")
	if err != nil {
		t.Fatalf("Connect(node) failed: %v", err)
	}
	oldKey := connector.pool.DigestOf(client.pooled)
	client.SetExecution(&ExecutionConfig{Interpreter: InterpreterSh, LaunchDialect: LaunchPOSIX})
	client.ApplyRecordedAuth("v2", "", nil)
	newKey := connector.pool.DigestOf(client.pooled)
	if newKey.IsZero() || newKey == oldKey {
		t.Fatalf("expected Reindex to advance digest: old=%s new=%s", oldKey, newKey)
	}
	if err := connector.pool.CheckInvariants(true); err != nil {
		t.Fatalf("post-Reindex pool invariant failed: %v", err)
	}

	// Shut down the server so the active keepalive detects transport death and
	// fires onDead against the reindexed pooled entry.
	_ = server.Close()
	deadline := time.Now().Add(3 * time.Second)
	for connector.pool.Count() != 0 && time.Now().Before(deadline) {
		time.Sleep(15 * time.Millisecond)
	}
	if got := connector.pool.Count(); got != 0 {
		t.Fatalf("reindexed client stranded in active pool after keepalive death: count=%d (CheckInvariants=%v)", got, connector.pool.CheckInvariants(true))
	}
	if err := connector.pool.CheckInvariants(true); err != nil {
		t.Fatalf("post-keepalive-death pool invariant failed: %v", err)
	}
}

func assertModelCascadeRefresh(t *testing.T, connector *Connector, provider *mutableRouteProvider, bastionClient, c2 *Client) {
	t.Helper()
	oldBastionKey := connector.pool.DigestOf(bastionClient.pooled)
	oldTarget2Key := connector.pool.DigestOf(c2.pooled)
	provider.mu.Lock()
	provider.cfgs["bastion"].SudoUpdateToken = "b-s2"
	provider.cfgs["bastion"].SudoMode = SudoModeSudo
	provider.mu.Unlock()
	if err := bastionClient.refreshConnectionTokens(tokenRefreshKindSudo, "b-s2"); err != nil {
		t.Fatalf("bastion.refreshConnectionTokens: %v", err)
	}
	if got := connector.pool.DigestOf(bastionClient.pooled); got == oldBastionKey {
		t.Fatal("bastion did not reindex on refreshConnectionTokens with active descendants")
	}
	if got := connector.pool.DigestOf(c2.pooled); got == oldTarget2Key {
		t.Fatal("active descendant target2 did not cascade-reindex with bastion")
	}
	if err := connector.pool.CheckInvariants(true); err != nil {
		t.Fatalf("post-cascade CheckInvariants(true): %v", err)
	}
}

func assertModelChildKeepAliveTimeout(t *testing.T, connector *Connector, target1Srv *keepAliveBarrierServer, bastionClient, c1, c2 *Client) {
	t.Helper()
	target1Srv.setStall(true)
	waitForCondition(t, 3*time.Second, func() bool {
		_, stillActive := connector.pool.Get(connector.pool.DigestOf(c1.pooled))
		return !stillActive && connector.pool.Count() == 2
	}, "timed-out child target1 was not evicted while keeping bastion and target2")
	if isRootConnClosed(bastionClient.rootConn) {
		t.Fatal("child-hop keepalive timeout closed shared bastion RootConn")
	}
	if err := runBarrierExecCheck(bastionClient); err != nil {
		t.Fatalf("bastion unhealthy after target1 keepalive timeout: %v", err)
	}
	if err := runBarrierExecCheck(c2); err != nil {
		t.Fatalf("sibling target2 unhealthy after target1 keepalive timeout: %v", err)
	}
	if err := connector.pool.CheckInvariants(true); err != nil {
		t.Fatalf("post-child-timeout CheckInvariants(true): %v", err)
	}
}

func assertModelPublishDisplacementInFlight(
	t *testing.T,
	connector *Connector,
	provider *mutableRouteProvider,
	target2Srv *keepAliveBarrierServer,
	bastionClient, c2 *Client,
) *PooledClient {
	t.Helper()
	target2Srv.setStall(true)
	target2Srv.waitProbeInFlight(t, 2*time.Second)
	t2Key := connector.pool.DigestOf(c2.pooled)
	_, t2DisplacedDone := c2.pooled.keepAliveState()
	replacementT2SSH := dialBarrierTestClient(t, target2Srv.addr)
	t.Cleanup(func() { _ = replacementT2SSH.Close() })
	replacementT2 := &PooledClient{
		SSHClient:    replacementT2SSH,
		RootConn:     bastionClient.rootConn,
		hopConn:      &stubCloseConn{},
		parentKey:    connector.pool.DigestOf(bastionClient.pooled),
		publishedCfg: NewClientConfig(*provider.cfgs["target2"]),
	}
	if _, err := connector.publishPooled(t2Key, replacementT2, bastionClient.pooled, nil); err != nil {
		t.Fatalf("publishPooled replacement target2: %v", err)
	}
	select {
	case <-t2DisplacedDone:
	case <-time.After(2 * time.Second):
		t.Fatal("displaced target2 keepalive did not exit on Publish displacement")
	}
	if isRootConnClosed(bastionClient.rootConn) {
		t.Fatal("Publish displacement of child target2 closed shared bastion RootConn")
	}
	if err := runBarrierExecCheck(c2); err != nil {
		t.Fatalf("displaced target2 session failed after Publish displacement: %v", err)
	}
	if err := runBarrierExecCheck(bastionClient); err != nil {
		t.Fatalf("bastion session failed after target2 Publish displacement: %v", err)
	}
	if err := connector.pool.CheckInvariants(true); err != nil {
		t.Fatalf("post-Publish-displacement CheckInvariants(true): %v", err)
	}
	return replacementT2
}

func assertModelStopGlobalAndRetireInFlight(
	t *testing.T,
	connector *Connector,
	bastionSrv, target2Srv *keepAliveBarrierServer,
	cancelKA context.CancelFunc,
	bastionClient, c2 *Client,
	replacementT2 *PooledClient,
) {
	t.Helper()
	bastionSrv.setStall(true)
	bastionSrv.waitProbeInFlight(t, 2*time.Second)
	target2Srv.waitProbeInFlight(t, 2*time.Second)

	cancelKA()
	_, bDone := bastionClient.pooled.keepAliveState()
	_, t2Done := replacementT2.keepAliveState()
	for label, ch := range map[string]<-chan struct{}{"bastion": bDone, "target2": t2Done} {
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s keepalive did not detach on StopGlobalKeepAlives", label)
		}
	}
	if isRootConnClosed(bastionClient.rootConn) {
		t.Fatal("StopGlobalKeepAlives closed live RootConn while probe was in flight")
	}
	if err := runBarrierExecCheck(bastionClient); err != nil {
		t.Fatalf("bastion session failed after StopGlobalKeepAlives during in-flight probe: %v", err)
	}
	if err := runBarrierExecCheck(c2); err != nil {
		t.Fatalf("target2 session failed after StopGlobalKeepAlives during in-flight probe: %v", err)
	}
	if err := connector.pool.CheckInvariants(false); err != nil {
		t.Fatalf("post-StopGlobalKeepAlives CheckInvariants(false): %v", err)
	}

	bastionSrv.setStall(false)
	target2Srv.setStall(false)
	connector.pool.Retire(ZeroHopDigest, bastionClient.pooled)
	if err := runBarrierExecCheck(bastionClient); err != nil {
		t.Fatalf("retired bastion session failed after Retire: %v", err)
	}
	if err := runBarrierExecCheck(c2); err != nil {
		t.Fatalf("retired target2 session failed after Retire: %v", err)
	}
	if err := connector.pool.CheckInvariants(false); err != nil {
		t.Fatalf("post-Retire CheckInvariants(false): %v", err)
	}
}

// TestModel_ConnectorPool_InFlightKeepAliveCancelAndChildTimeout verifies under
// -race that:
//  1. Concurrent in-flight keepalive probes survive Publish displacement, Retire,
//     and StopGlobalKeepAlives without closing live RootConns.
//  2. A child hop timing out over a shared bastion evicts only the timed-out
//     child while keeping the bastion and healthy sibling target live.
//  3. Parent-hop refreshConnectionTokens atomically cascades Reindex to active
//     descendants without breaking pool invariants or stranding entries.
func TestModel_ConnectorPool_InFlightKeepAliveCancelAndChildTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	bastionSrv := newKeepAliveBarrierServer(t, ctx)
	target1Srv := newKeepAliveBarrierServer(t, ctx)
	target2Srv := newKeepAliveBarrierServer(t, ctx)

	bHost, bPort := fixtureEndpoint(t, bastionSrv.addr)
	t1Host, t1Port := fixtureEndpoint(t, target1Srv.addr)
	t2Host, t2Port := fixtureEndpoint(t, target2Srv.addr)

	provider := &mutableRouteProvider{
		cfgs: map[string]*ClientConfig{
			"bastion": {
				NodeID: "bastion", Address: bHost, Port: bPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				SudoMode: SudoModeAuto, SudoUpdateToken: "b-s1",
			},
			"target1": {
				NodeID: "target1", Address: t1Host, Port: t1Port,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "bastion",
			},
			"target2": {
				NodeID: "target2", Address: t2Host, Port: t2Port,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "bastion",
			},
		},
	}

	dialer := &p7TrackingDialer{}
	statelessTrust := &p7BarrierTrust{onCheck: func(context.Context, HostKeyRequest) error { return nil }}
	connector := newTestConnector(provider, WithDialer(dialer), WithHostKeyVerifier(statelessTrust))
	kaCtx, cancelKA := context.WithCancel(ctx)
	defer cancelKA()
	connector.EnableKeepAlive(kaCtx, 15*time.Millisecond, 90*time.Millisecond)
	t.Cleanup(func() { _ = connector.CloseAll() })

	c1, err := connector.Connect(ctx, "target1")
	if err != nil {
		t.Fatalf("Connect(target1): %v", err)
	}
	c2, err := connector.Connect(ctx, "target2")
	if err != nil {
		t.Fatalf("Connect(target2): %v", err)
	}
	bastionClient, err := connector.Connect(ctx, "bastion")
	if err != nil {
		t.Fatalf("Connect(bastion): %v", err)
	}
	if c1.rootConn != c2.rootConn {
		t.Fatal("expected target1 and target2 to share bastion RootConn")
	}
	if err := connector.pool.CheckInvariants(true); err != nil {
		t.Fatalf("initial CheckInvariants(true): %v", err)
	}

	assertModelCascadeRefresh(t, connector, provider, bastionClient, c2)
	assertModelChildKeepAliveTimeout(t, connector, target1Srv, bastionClient, c1, c2)
	replacementT2 := assertModelPublishDisplacementInFlight(t, connector, provider, target2Srv, bastionClient, c2)
	assertModelStopGlobalAndRetireInFlight(t, connector, bastionSrv, target2Srv, cancelKA, bastionClient, c2, replacementT2)

	if err := connector.CloseAll(); err != nil {
		t.Fatalf("CloseAll failed: %v", err)
	}
	for i, c := range dialer.snapshot() {
		if !c.closed.Load() {
			t.Errorf("leaked unclosed transport #%d after CloseAll", i+1)
		}
	}
}

// Keep stubCloseConn compile-checked against net.Conn.
var _ net.Conn = (*stubCloseConn)(nil)
