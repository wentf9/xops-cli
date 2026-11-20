package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
)

type round5BlockingRequestChannel struct {
	stubRemoteChannel
	reqStarted chan struct{}
	closedCh   chan struct{}
	closeOnce  sync.Once
	startOnce  sync.Once
}

func (c *round5BlockingRequestChannel) SendRequest(string, bool, []byte) (bool, error) {
	c.startOnce.Do(func() {
		if c.reqStarted != nil {
			close(c.reqStarted)
		}
	})
	<-c.closedCh
	return false, errors.New("channel closed on timeout")
}

func (c *round5BlockingRequestChannel) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		close(c.closedCh)
	})
	return nil
}

func TestRound5_P2_1_ProxyChannelRequestTimeoutRetiresChannel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conn, peer := net.Pipe()
	defer func() {
		_ = conn.Close()
		_ = peer.Close()
	}()

	ps := &proxySessionState{
		server: &MuxServer{
			requestTimeout: 35 * time.Millisecond,
			serverCtx:      ctx,
			serverCancel:   cancel,
		},
		conn:   conn,
		global: newOrderedQueue[proxyGlobalRequest](),
	}
	blockCh := &round5BlockingRequestChannel{
		reqStarted: make(chan struct{}),
		closedCh:   make(chan struct{}),
	}
	pc := &proxyChan{
		remoteCh:          blockCh,
		clientCh:          11,
		serverCh:          5,
		clientWindow:      newClientFlowWindow(4096),
		clientMaxPacket:   1024,
		requests:          newOrderedQueue[proxyChannelRequest](),
		requestsDone:      make(chan struct{}),
		input:             newOrderedQueue[proxyChannelInput](),
		pendingRemoteReqs: newRemoteRequestQueue(),
	}
	ps.channels.Store(pc.serverCh, pc)

	var packetsMu sync.Mutex
	var opcodes []byte
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			pkt, err := readUnpaddedPacket(peer)
			if err != nil {
				return
			}
			if len(pkt) > 0 {
				packetsMu.Lock()
				opcodes = append(opcodes, pkt[0])
				packetsMu.Unlock()
			}
		}
	}()

	// Queue two requests: the first times out and retires the channel immediately;
	// the second must not block serveChannelRequests or leak goroutines.
	pc.requests.push(proxyChannelRequest{requestType: "exec", wantReply: true, payload: encodeStringPayload("id")})
	pc.requests.push(proxyChannelRequest{requestType: "exec", wantReply: true, payload: encodeStringPayload("uname")})

	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		ps.serveChannelRequests(pc)
	}()

	select {
	case <-blockCh.reqStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for SendRequest to start")
	}

	select {
	case <-serveDone:
	case <-time.After(2 * time.Second):
		t.Fatal("serveChannelRequests blocked instead of retiring timed-out channel")
	}
	select {
	case <-pc.requestsDone:
	case <-time.After(2 * time.Second):
		t.Fatal("pc.requestsDone did not close")
	}

	if _, loaded := ps.channels.Load(pc.serverCh); loaded {
		t.Fatal("expected timed-out proxy channel to be removed from ps.channels")
	}
	if !blockCh.closed.Load() {
		t.Fatal("expected remoteCh to be closed on request timeout")
	}

	_ = conn.Close()
	<-readDone

	packetsMu.Lock()
	defer packetsMu.Unlock()
	if !slices.Contains(opcodes, msgChannelFailure) {
		t.Fatalf("expected msgChannelFailure (%d) in packets %v", msgChannelFailure, opcodes)
	}
	if !slices.Contains(opcodes, msgChannelClose) {
		t.Fatalf("expected msgChannelClose (%d) in packets %v", msgChannelClose, opcodes)
	}
}

func encodeStringPayload(s string) []byte {
	buf := make([]byte, 4+len(s))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(s)))
	copy(buf[4:], s)
	return buf
}

type round5PlanProvider struct {
	configs map[string]*ClientConfig
}

func (p *round5PlanProvider) GetConfig(nodeID string) (*ClientConfig, error) {
	cfg, ok := p.configs[nodeID]
	if !ok {
		return nil, errors.New("not found: " + nodeID)
	}
	return cfg, nil
}

type round5FixtureSecrets struct{}

func (round5FixtureSecrets) ResolveSecret(ctx context.Context, _ SecretRequest) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return []byte(sshfixture.Password), nil
}

func TestRound5_P2_2_CanonicalHostPlanPropagationAndCompatibility(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fix, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New: %v", err)
	}
	defer func() { _ = fix.Close() }()

	host, port, err := sshfixtureSplitHostPort(fix.Address)
	if err != nil {
		t.Fatalf("split host/port: %v", err)
	}

	baseCfg := ClientConfig{
		NodeID:          "node-canon",
		Address:         host,
		Port:            port,
		User:            "fixture",
		Password:        "fixture-pass",
		AuthType:        "password",
		AuthUpdateToken: "v1",
		OriginalHost:    "short",
		CanonicalHost:   "short.corp.example.com",
		TrustVersion:    "tv1",
	}
	prov := &round5PlanProvider{configs: map[string]*ClientConfig{"node-canon": &baseCfg}}

	plan, err := CapturePlan(ctx, prov, "node-canon", "round5-canon-scope")
	if err != nil {
		t.Fatalf("CapturePlan failed: %v", err)
	}
	if len(plan.Hops) != 1 || plan.Hops[0].CanonicalHost != "short.corp.example.com" {
		t.Fatalf("CapturePlan hop CanonicalHost = %+v, want short.corp.example.com", plan.Hops)
	}

	rebuilt := clientConfigFromPlan(plan.Hops[0])
	if rebuilt.CanonicalHost != "short.corp.example.com" {
		t.Fatalf("clientConfigFromPlan CanonicalHost = %q, want short.corp.example.com", rebuilt.CanonicalHost)
	}

	connector := NewConnector(prov, WithSecretResolver(round5FixtureSecrets{}), WithHostKeyVerifier(&fixtureTrust{}))
	defer func() { _ = connector.CloseAll() }()

	lease, err := connector.ConnectPlan(ctx, plan)
	if err != nil {
		t.Fatalf("ConnectPlan failed: %v", err)
	}
	if got := lease.Client.Config().CanonicalHost; got != "short.corp.example.com" {
		_ = lease.Close()
		t.Fatalf("Client.Config().CanonicalHost = %q, want short.corp.example.com", got)
	}
	if err := lease.Close(); err != nil {
		t.Fatalf("lease.Close: %v", err)
	}

	cur := plan.Hops[0]
	sameCfg := baseCfg
	if err := validateTargetCompatibility(cur, &sameCfg); err != nil {
		t.Fatalf("validateTargetCompatibility matching CanonicalHost failed: %v", err)
	}
	driftedCfg := baseCfg
	driftedCfg.CanonicalHost = "other.corp.example.com"
	if err := validateTargetCompatibility(cur, &driftedCfg); !errors.Is(err, ErrSnapshotMismatch) {
		t.Fatalf("validateTargetCompatibility drifted CanonicalHost = %v, want ErrSnapshotMismatch", err)
	}
}

func sshfixtureSplitHostPort(addr string) (string, int, error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	var portNum int
	for _, r := range p {
		if r < '0' || r > '9' {
			return "", 0, errors.New("invalid port: " + p)
		}
		portNum = portNum*10 + int(r-'0')
	}
	return h, portNum, nil
}

func TestRound5_P2_3_And_P3_2_FilteredAgentDedupAndPairedCertSkipsAgentDial(t *testing.T) {
	t.Parallel()

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(user): %v", err)
	}
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(ca): %v", err)
	}
	caSigner, err := cryptoSSH.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatalf("NewSignerFromKey(ca): %v", err)
	}
	userSigner, err := cryptoSSH.NewSignerFromKey(privKey)
	if err != nil {
		t.Fatalf("NewSignerFromKey(user): %v", err)
	}

	cert := &cryptoSSH.Certificate{
		Key:             userSigner.PublicKey(),
		Serial:          1,
		CertType:        cryptoSSH.UserCert,
		KeyId:           "r5-cert",
		ValidPrincipals: []string{"alice"},
		ValidBefore:     cryptoSSH.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("SignCert: %v", err)
	}

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "id_ed25519")
	certPath := filepath.Join(tmpDir, "id_ed25519-cert.pub")
	block, err := cryptoSSH.MarshalPrivateKey(privKey, "")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.WriteFile(certPath, cryptoSSH.MarshalAuthorizedKey(cert), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: privKey, Certificate: cert}); err != nil {
		t.Fatalf("keyring.Add: %v", err)
	}

	// P2-3: resolveFilteredAgentAuth (IdentitiesOnly=yes) with duplicate explicit key paths
	// and explicit CertificateFile produces deduplicated cert + plain candidates in cert-first order.
	var sshOpts Options
	if err := sshOpts.Set(OptionIdentitiesOnly, "yes"); err != nil {
		t.Fatalf("Set(IdentitiesOnly): %v", err)
	}
	if err := sshOpts.Set(OptionCertificateFile, certPath); err != nil {
		t.Fatalf("Set(CertificateFile): %v", err)
	}
	if err := sshOpts.Set(OptionIdentityAgent, "/tmp/r5-agent.sock"); err != nil {
		t.Fatalf("Set(IdentityAgent): %v", err)
	}
	if err := os.WriteFile(keyPath+".pub", cryptoSSH.MarshalAuthorizedKey(userSigner.PublicKey()), 0o600); err != nil {
		t.Fatalf("write pub key: %v", err)
	}

	conn := &Connector{
		environment: Environment{
			DialAgent: func(context.Context, string) (net.Conn, error) {
				c1, c2 := net.Pipe()
				go func() {
					_ = agent.ServeAgent(keyring, c2)
					_ = c2.Close()
				}()
				return c1, nil
			},
		},
	}
	candidates, cleanup, err := conn.resolveFilteredAgentAuth(context.Background(), context.Background(), &ClientConfig{
		NodeID:  "r5-agent-dedup",
		User:    "alice",
		Address: "127.0.0.1",
		Port:    22,
		Options: &sshOpts,
	}, []string{keyPath, keyPath})
	if err != nil {
		t.Fatalf("resolveFilteredAgentAuth failed: %v", err)
	}
	defer cleanup()
	var certCandidateCount, plainCandidateCount int
	for _, c := range candidates {
		if strings.Contains(c.label, "cert") {
			certCandidateCount++
		} else {
			plainCandidateCount++
		}
	}
	if certCandidateCount != 1 || plainCandidateCount != 1 {
		t.Fatalf("resolveFilteredAgentAuth candidates = (cert=%d, plain=%d), want (1, 1)", certCandidateCount, plainCandidateCount)
	}
	if !strings.Contains(candidates[0].label, "cert") {
		t.Fatalf("expected certificate candidate first, got %q", candidates[0].label)
	}

	verifyRound5PairedCertSkipsAgentDial(t, keyring, cert, certPath)
}

func verifyRound5PairedCertSkipsAgentDial(t *testing.T, keyring agent.Agent, cert *cryptoSSH.Certificate, certPath string) {
	t.Helper()

	// P3-2: buildIdentitiesOnlyPubkeyCandidates must not dial ssh-agent when there
	// are no candidate key paths left to match and all explicit certs are already paired.
	var dialCalls atomic.Int32
	paired := map[string]struct{}{certPath: {}}
	explicitCerts := []loadedUserCert{{path: certPath, cert: cert}}
	_, pubCleanup := buildIdentitiesOnlyPubkeyCandidates(
		context.Background(),
		AutoAuthOptions{
			DialAgent: func(context.Context, string) (net.Conn, error) {
				dialCalls.Add(1)
				return nil, errors.New("unexpected agent dial")
			},
		},
		TargetContext{},
		func(context.Context, string) (net.Conn, error) {
			dialCalls.Add(1)
			return nil, errors.New("unexpected agent dial")
		},
		"/tmp/r5-agent.sock",
		false,
		nil,
		explicitCerts,
		true,
		true,
		nil,
		nil,
		paired,
		map[string]struct{}{},
		&autoSecretProvider{},
		nil,
		newOfferedPubKeyTracker(),
		nil,
	)
	if pubCleanup != nil {
		pubCleanup()
	}
	if dialCalls.Load() != 0 {
		t.Fatalf("agent dialed %d times despite zero candidate paths and zero unpaired certs", dialCalls.Load())
	}

	// Verify it DOES dial when an explicit cert remains unpaired.
	unpaired := map[string]struct{}{}
	_, dialCleanup := buildIdentitiesOnlyPubkeyCandidates(
		context.Background(),
		AutoAuthOptions{},
		TargetContext{},
		func(context.Context, string) (net.Conn, error) {
			dialCalls.Add(1)
			c1, c2 := net.Pipe()
			go func() {
				_ = agent.ServeAgent(keyring, c2)
				_ = c2.Close()
			}()
			return c1, nil
		},
		"/tmp/r5-agent.sock",
		false,
		nil,
		explicitCerts,
		true,
		true,
		nil,
		nil,
		unpaired,
		map[string]struct{}{},
		&autoSecretProvider{},
		nil,
		newOfferedPubKeyTracker(),
		nil,
	)
	if dialCleanup != nil {
		dialCleanup()
	}
	if dialCalls.Load() != 1 {
		t.Fatalf("expected 1 agent dial for unpaired explicit cert, got %d", dialCalls.Load())
	}
}

func TestRound5_P3_1_FilterSourcedKeyPathNoDoubleExpansion(t *testing.T) {
	t.Parallel()

	env := Environment{
		HomeDir: "/home/alice",
		LookupEnv: func(k string) (string, bool) {
			if k == "KEYDIR" {
				return "/var/keys", true
			}
			return "", false
		},
	}
	target := TargetContext{Host: "10.0.0.1", Port: 22, User: "alice", OriginalHost: "web"}

	// Already-expanded candidate paths containing a literal "%n" (from "%%n") must be
	// matched verbatim without undergoing a second percent/token expansion pass.
	paths := []string{"/home/alice/a%nb", "${KEYDIR}/c", "/other/id"}
	filtered := filterSourcedKeyPath(paths, "~/a%%nb", env, target, nil)
	if len(filtered) != 2 || filtered[0] != "${KEYDIR}/c" || filtered[1] != "/other/id" {
		t.Fatalf("filterSourcedKeyPath(%v) = %v, want [${KEYDIR}/c /other/id]", paths, filtered)
	}

	// Unmatched sourced expansion retains all paths cleanly.
	filtered2 := filterSourcedKeyPath([]string{"/var/keys/id_ed25519", "/fallback/id"}, "${KEYDIR}/id_ed25519", env, target, nil)
	if len(filtered2) != 1 || filtered2[0] != "/fallback/id" {
		t.Fatalf("filterSourcedKeyPath(template) = %v, want [/fallback/id]", filtered2)
	}
}

func TestRound5_P3_6_ControlCharsRejectedBeforeTrimSpace(t *testing.T) {
	t.Parallel()

	env := Environment{
		AgentSocket: "/tmp/env.sock\n",
	}
	target := TargetContext{Host: "10.0.0.1", Port: 22, User: "alice"}

	if _, _, err := ResolveIdentityAgent(" /tmp/agent.sock\n", env, target); err == nil {
		t.Fatal("expected trailing LF in IdentityAgent spec to be rejected before TrimSpace")
	}
	if _, _, err := ResolveIdentityAgent("\r/tmp/agent.sock", env, target); err == nil {
		t.Fatal("expected leading CR in IdentityAgent spec to be rejected before TrimSpace")
	}
	if _, err := expandAgentSocketPath(" \t/tmp/a\x00b ", env, target, "IdentityAgent"); err == nil {
		t.Fatal("expected NUL in expandAgentSocketPath to be rejected")
	}
	if _, _, err := resolveForwardAgentSpec("yes\n", "", env, target, false); err == nil {
		t.Fatal("expected trailing LF in ForwardAgent spec to be rejected before TrimSpace")
	}
}
