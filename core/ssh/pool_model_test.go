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
		if err := s.connector.pool.CheckInvariants(true); err != nil {
			s.recordInvErr(err)
			return
		}
		time.Sleep(2 * time.Millisecond)
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
		},
	}

	dialer := &p7TrackingDialer{}
	statelessTrust := &p7BarrierTrust{onCheck: func(context.Context, HostKeyRequest) error { return nil }}
	connector := newTestConnector(provider, WithDialer(dialer), WithHostKeyVerifier(statelessTrust))
	kaCtx, cancelKA := context.WithCancel(ctx)
	defer cancelKA()
	connector.EnableKeepAlive(kaCtx, 40*time.Millisecond, 500*time.Millisecond)
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

	var wg sync.WaitGroup
	for workerID := range 4 {
		wg.Go(func() { storm.runConnectWorker(ctx, workerID) })
	}
	wg.Go(storm.runConfigFlipper)
	wg.Go(storm.runRetireAndStaleCASActor)
	wg.Go(storm.runInvariantChecker)

	time.Sleep(150 * time.Millisecond)
	close(storm.stopStorm)
	wg.Wait()

	storm.invErrMu.Lock()
	gotInvErr := storm.invErr
	storm.invErrMu.Unlock()
	if gotInvErr != nil {
		t.Fatalf("pool invariant violated during concurrent storm: %v", gotInvErr)
	}
	if err := connector.pool.CheckInvariants(true); err != nil {
		t.Fatalf("post-storm pool invariant failed: %v", err)
	}
	if storm.successfulOps.Load() == 0 {
		t.Fatal("expected at least one successful concurrent Connect during storm")
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

// Keep stubCloseConn compile-checked against net.Conn.
var _ net.Conn = (*stubCloseConn)(nil)
