package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/fsx"
	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"gopkg.in/yaml.v3"
)

type p5UnknownPublicKey struct {
	keyType string
	blob    []byte
}

func (k p5UnknownPublicKey) Type() string    { return k.keyType }
func (k p5UnknownPublicKey) Marshal() []byte { return slices.Clone(k.blob) }
func (k p5UnknownPublicKey) Verify([]byte, *cryptoSSH.Signature) error {
	return errors.New("unsupported")
}

func p5SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func p5GenerateEd25519KeyAndCert(t *testing.T, principal string) (
	keyPEM []byte,
	userSigner cryptoSSH.Signer,
	caPub cryptoSSH.PublicKey,
	certBytes []byte,
) {
	t.Helper()
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caSigner, err := cryptoSSH.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatalf("create CA signer: %v", err)
	}
	_, userPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate user key: %v", err)
	}
	userSigner, err = cryptoSSH.NewSignerFromKey(userPriv)
	if err != nil {
		t.Fatalf("create user signer: %v", err)
	}
	block, err := cryptoSSH.MarshalPrivateKey(userPriv, "p5-test-user")
	if err != nil {
		t.Fatalf("marshal user key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(block)

	cert := &cryptoSSH.Certificate{
		Key:             userSigner.PublicKey(),
		Serial:          1,
		CertType:        cryptoSSH.UserCert,
		KeyId:           "p5-user-cert",
		ValidPrincipals: []string{principal},
		ValidAfter:      uint64(time.Now().Add(-time.Hour).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("sign user cert: %v", err)
	}
	return keyPEM, userSigner, caSigner.PublicKey(), cryptoSSH.MarshalAuthorizedKey(cert)
}

func p5StartCertOrKeySSHServer(t *testing.T, expectedCA cryptoSSH.PublicKey, expectedPlainPub cryptoSSH.PublicKey) (string, int, cryptoSSH.PublicKey, func()) {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	hostSigner, err := cryptoSSH.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("create host signer: %v", err)
	}
	checker := &cryptoSSH.CertChecker{
		IsUserAuthority: func(auth cryptoSSH.PublicKey) bool {
			return expectedCA != nil && bytes.Equal(auth.Marshal(), expectedCA.Marshal())
		},
	}
	srvCfg := &cryptoSSH.ServerConfig{
		PublicKeyCallback: func(conn cryptoSSH.ConnMetadata, key cryptoSSH.PublicKey) (*cryptoSSH.Permissions, error) {
			if cert, ok := key.(*cryptoSSH.Certificate); ok && expectedCA != nil {
				if err := checker.CheckCert(conn.User(), cert); err == nil {
					return &cryptoSSH.Permissions{}, nil
				}
			}
			if expectedPlainPub != nil && bytes.Equal(key.Marshal(), expectedPlainPub.Marshal()) {
				return &cryptoSSH.Permissions{}, nil
			}
			return nil, errors.New("unauthorized public key")
		},
	}
	srvCfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer func() { _ = c.Close() }()
				sConn, chans, reqs, err := cryptoSSH.NewServerConn(c, srvCfg)
				if err != nil {
					return
				}
				defer func() { _ = sConn.Close() }()
				go func() {
					for req := range reqs {
						if req.WantReply {
							_ = req.Reply(true, nil)
						}
					}
				}()
				for ch := range chans {
					_ = ch.Reject(cryptoSSH.Prohibited, "test server")
				}
			}(raw)
		}
	}()
	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return host, port, hostSigner.PublicKey(), func() {
		_ = ln.Close()
		wg.Wait()
	}
}

type p5StaticKeyLease struct {
	signer cryptoSSH.Signer
}

func (l *p5StaticKeyLease) Signer() cryptoSSH.Signer { return l.signer }
func (l *p5StaticKeyLease) Close() error             { return nil }

type p5StaticKeySource struct {
	signer cryptoSSH.Signer
}

func (s *p5StaticKeySource) OpenKey(context.Context, KeyRequest) (KeyLease, error) {
	return &p5StaticKeyLease{signer: s.signer}, nil
}

// --- Finding 4.3: EvaluateSSHFP cross-algorithm & unsupported key fail-closed ---

func TestP5_4_3_EvaluateSSHFP_CrossAlgorithmAndUnsupportedKeyFailClosed(t *testing.T) {
	t.Parallel()

	edKey := newPhase4HostKey(t)
	otherDigest := make([]byte, sha256.Size)
	otherDigest[0] = 0xAB
	unknownKey := p5UnknownPublicKey{keyType: "ssh-custom-unknown-v1", blob: []byte("custom-host-key")}

	cases := []struct {
		name   string
		key    cryptoSSH.PublicKey
		result SSHFPResult
		want   SSHFPVerifyStatus
	}{
		{
			name:   "authenticated other algorithm mismatches",
			key:    edKey,
			result: SSHFPResult{Authenticated: true, Records: []SSHFPRecord{{Algorithm: 1, FingerprintType: 2, Fingerprint: otherDigest}}},
			want:   SSHFPStatusMismatch,
		},
		{
			name:   "unauthenticated other algorithm yields none",
			key:    edKey,
			result: SSHFPResult{Authenticated: false, Records: []SSHFPRecord{{Algorithm: 1, FingerprintType: 2, Fingerprint: otherDigest}}},
			want:   SSHFPStatusNone,
		},
		{
			name:   "unknown key type with authenticated sha256 mismatches",
			key:    unknownKey,
			result: SSHFPResult{Authenticated: true, Records: []SSHFPRecord{{Algorithm: 4, FingerprintType: 2, Fingerprint: otherDigest}}},
			want:   SSHFPStatusMismatch,
		},
		{
			name:   "unknown key type with unauthenticated sha256 yields none",
			key:    unknownKey,
			result: SSHFPResult{Authenticated: false, Records: []SSHFPRecord{{Algorithm: 4, FingerprintType: 2, Fingerprint: otherDigest}}},
			want:   SSHFPStatusNone,
		},
		{
			name:   "algorithm zero ignored even when authenticated",
			key:    edKey,
			result: SSHFPResult{Authenticated: true, Records: []SSHFPRecord{{Algorithm: 0, FingerprintType: 2, Fingerprint: otherDigest}}},
			want:   SSHFPStatusNone,
		},
		{
			name:   "nil key yields none even with authenticated records",
			key:    nil,
			result: SSHFPResult{Authenticated: true, Records: []SSHFPRecord{{Algorithm: 4, FingerprintType: 2, Fingerprint: otherDigest}}},
			want:   SSHFPStatusNone,
		},
	}
	for _, tc := range cases {
		if got := EvaluateSSHFP(tc.result, tc.key); got != tc.want {
			t.Errorf("%s: EvaluateSSHFP = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestP5_4_3_AcceptNewRejectsWrongAlgorithmMITMKey(t *testing.T) {
	t.Parallel()

	mitmKey := newPhase4HostKey(t) // ssh-ed25519 (algo 4)
	rsaDigest := make([]byte, sha256.Size)
	rsaDigest[0] = 0x42
	dnssecRSAOnly := SSHFPResult{
		Authenticated: true,
		Records:       []SSHFPRecord{{Algorithm: 1, FingerprintType: 2, Fingerprint: rsaDigest}},
	}

	for _, batch := range []bool{true, false} {
		name := "interactive_decline"
		if batch {
			name = "batch_fail_closed"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			khFile := filepath.Join(dir, "known_hosts")
			env := fixtureEnvironment()
			env.HomeDir = dir
			env.LookupSSHFP = func(context.Context, string) (SSHFPResult, error) {
				return dnssecRSAOnly, nil
			}
			confirmer := &phase4Confirmer{accept: false}
			conn := NewConnector(nil, WithEnvironment(env), WithHostKeyConfirmer(confirmer))
			t.Cleanup(func() { _ = conn.CloseAll() })

			cfg := &ClientConfig{
				NodeID:  "mitm",
				Address: "mitm.example.com",
				Port:    22,
				User:    "alice",
				Options: MustOptions(OptionVerifyHostKeyDNS, "yes"),
			}
			err := conn.handleKnownHostsKeyError(
				t.Context(), nil, cfg, &knownhosts.KeyError{}, "accept-new", batch, false,
				khFile, "mitm.example.com:22", nil, mitmKey, nil,
			)
			if !errors.Is(err, ErrHostKeyMismatch) {
				t.Fatalf("expected ErrHostKeyMismatch for wrong-algorithm MITM key, got %v", err)
			}
			if _, statErr := os.Stat(khFile); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("MITM host key must not be persisted to known_hosts (stat err=%v)", statErr)
			}
			if !batch && (confirmer.calls.Load() != 1 || confirmer.lastStatus() != SSHFPStatusMismatch) {
				t.Fatalf("expected 1 prompt with SSHFPStatusMismatch, got calls=%d status=%q", confirmer.calls.Load(), confirmer.lastStatus())
			}
			if batch && confirmer.calls.Load() != 0 {
				t.Fatalf("batch mode must not prompt, got %d calls", confirmer.calls.Load())
			}
		})
	}
}

// --- Finding 3.1: Recursive multi-hop ProxyJump & cycle detection ---

func TestP5_3_1_RecursiveMultiHopProxyJump_PlanAndCapturePlan(t *testing.T) {
	t.Parallel()

	store := &mockProxyJumpStore{cfgs: map[string]*ClientConfig{
		"target": {NodeID: "target", Address: "10.0.0.10", Port: 22, User: "u", ProxyJump: "j1,j2"},
		"j2":     {NodeID: "j2", Address: "10.0.0.2", Port: 22, User: "u", ProxyJump: "j2-ignored"},
		"j1":     {NodeID: "j1", Address: "10.0.0.1", Port: 22, User: "u", ProxyJump: "ja,jb"},
		"jb":     {NodeID: "jb", Address: "10.0.0.12", Port: 22, User: "u", ProxyJump: "jb-ignored"},
		"ja":     {NodeID: "ja", Address: "10.0.0.11", Port: 22, User: "u", ProxyJump: "j0"},
		"j0":     {NodeID: "j0", Address: "10.0.0.0", Port: 22, User: "u"},
	}}
	conn := newTestConnector(store)
	t.Cleanup(func() { _ = conn.CloseAll() })

	resolved, err := conn.resolveConnectionPlan(t.Context(), "target")
	if err != nil {
		t.Fatalf("resolveConnectionPlan: %v", err)
	}
	wantNames := []string{"target", "j2", "j1", "jb", "ja", "j0"}
	wantActiveJump := []string{"j1,j2", "j1", "ja,jb", "ja", "j0", ""}
	wantOrigJump := []string{"j1,j2", "j2-ignored", "ja,jb", "jb-ignored", "j0", ""}
	if len(resolved) != len(wantNames) {
		t.Fatalf("len(plan) = %d, want %d", len(resolved), len(wantNames))
	}
	for i := range wantNames {
		if resolved[i].name != wantNames[i] {
			t.Fatalf("plan[%d].name = %q, want %q", i, resolved[i].name, wantNames[i])
		}
		if resolved[i].cfg.ProxyJump != wantActiveJump[i] {
			t.Fatalf("plan[%d].ProxyJump = %q, want %q", i, resolved[i].cfg.ProxyJump, wantActiveJump[i])
		}
		if resolved[i].cfg.OriginalProxyJump != wantOrigJump[i] {
			t.Fatalf("plan[%d].OriginalProxyJump = %q, want %q", i, resolved[i].cfg.OriginalProxyJump, wantOrigJump[i])
		}
	}
	for i := len(resolved) - 1; i > 0; i-- {
		parentKey := resolved[i].poolKey()
		childKey := resolved[i-1].poolKey()
		if !isDownstreamRouteKey(parentKey, childKey) {
			t.Fatalf("expected %q (%s) to be downstream of %q (%s)", resolved[i-1].name, childKey, resolved[i].name, parentKey)
		}
	}

	captured, err := CapturePlan(t.Context(), store, "target", "p5-scope")
	if err != nil {
		t.Fatalf("CapturePlan: %v", err)
	}
	wantCaptured := []string{"j0", "ja", "jb", "j1", "j2", "target"}
	if len(captured.Hops) != len(wantCaptured) {
		t.Fatalf("CapturePlan hops = %d, want %d", len(captured.Hops), len(wantCaptured))
	}
	for i, wantID := range wantCaptured {
		if captured.Hops[i].NodeID != wantID {
			t.Fatalf("captured.Hops[%d].NodeID = %q, want %q", i, captured.Hops[i].NodeID, wantID)
		}
		wantPrev := ""
		if i > 0 {
			wantPrev = wantCaptured[i-1]
		}
		if captured.Hops[i].ProxyJump != wantPrev {
			t.Fatalf("captured.Hops[%d].ProxyJump = %q, want %q", i, captured.Hops[i].ProxyJump, wantPrev)
		}
	}
}

func TestP5_3_1_RecursiveMultiHopProxyJump_CycleDetection(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cfgs map[string]*ClientConfig
	}{
		{
			name: "inner hop loops back to target",
			cfgs: map[string]*ClientConfig{
				"target": {NodeID: "target", ProxyJump: "j1,j2"},
				"j2":     {NodeID: "j2"},
				"j1":     {NodeID: "j1", ProxyJump: "target"},
			},
		},
		{
			name: "recursive hop loops back to intermediate jump",
			cfgs: map[string]*ClientConfig{
				"target": {NodeID: "target", ProxyJump: "j1,j2"},
				"j2":     {NodeID: "j2"},
				"j1":     {NodeID: "j1", ProxyJump: "j0"},
				"j0":     {NodeID: "j0", ProxyJump: "j2"},
			},
		},
		{
			name: "duplicate hop in comma list",
			cfgs: map[string]*ClientConfig{
				"target": {NodeID: "target", ProxyJump: "j1,j1"},
				"j1":     {NodeID: "j1"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := newTestConnector(&mockProxyJumpStore{cfgs: tc.cfgs})
			t.Cleanup(func() { _ = conn.CloseAll() })
			_, err := conn.resolveConnectionPlan(t.Context(), "target")
			var cycleErr *ProxyCycleError
			if !errors.As(err, &cycleErr) {
				t.Fatalf("expected ProxyCycleError, got %v", err)
			}
		})
	}
}

// --- Finding 3.2: Singleflight digest, validateTargetCompatibility, reload fail-closed, cascade eviction ---

type p5SequenceProvider struct {
	mu   sync.Mutex
	cfgs []*ClientConfig
	idx  int
}

func (p *p5SequenceProvider) GetConfig(string) (*ClientConfig, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.idx >= len(p.cfgs) {
		return p.cfgs[len(p.cfgs)-1], nil
	}
	cfg := p.cfgs[p.idx]
	p.idx++
	return cfg, nil
}

type p5GateDialer struct {
	calls        atomic.Int32
	firstEntered chan struct{}
	release      chan struct{}
}

func (d *p5GateDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *p5GateDialer) DialContext(_ context.Context, _, _ string) (net.Conn, error) {
	n := d.calls.Add(1)
	if n == 1 {
		close(d.firstEntered)
		<-d.release
	}
	return nil, errors.New("p5 synthetic dial stop")
}

func TestP5_3_2_SingleflightDoesNotCoalesceDifferingConfigs(t *testing.T) {
	t.Parallel()

	cfgV1 := &ClientConfig{NodeID: "n1", Address: "127.0.0.1", Port: 22, User: "u", AuthType: "password", Password: "p", TrustVersion: "v1"}
	cfgV2 := &ClientConfig{NodeID: "n1", Address: "127.0.0.1", Port: 22, User: "u", AuthType: "password", Password: "p", TrustVersion: "v2"}
	if targetCompatDigest(cfgV1) == targetCompatDigest(cfgV2) {
		t.Fatal("targetCompatDigest must differ across TrustVersion")
	}

	dialer := &p5GateDialer{firstEntered: make(chan struct{}), release: make(chan struct{})}
	conn := NewConnector(&p5SequenceProvider{cfgs: []*ClientConfig{cfgV1, cfgV2}}, WithDialer(dialer), WithEnvironment(fixtureEnvironment()))
	t.Cleanup(func() { _ = conn.CloseAll() })

	done1 := make(chan error, 1)
	go func() {
		_, err := conn.Connect(t.Context(), "n1")
		done1 <- err
	}()
	<-dialer.firstEntered

	done2 := make(chan error, 1)
	go func() {
		_, err := conn.Connect(t.Context(), "n1")
		done2 <- err
	}()

	select {
	case err := <-done2:
		if err == nil {
			t.Fatal("expected synthetic dial error for v2")
		}
	case <-time.After(2 * time.Second):
		close(dialer.release)
		t.Fatal("v2 caller was coalesced onto blocked v1 singleflight")
	}
	close(dialer.release)
	<-done1

	if got := dialer.calls.Load(); got != 2 {
		t.Fatalf("expected 2 independent dials for differing TrustVersion, got %d", got)
	}
}

func TestP5_3_2_ValidateTargetCompatibility_AuthAndNewOptions(t *testing.T) {
	t.Parallel()

	baseCfg := &ClientConfig{
		NodeID:          "n1",
		Address:         "10.0.0.1",
		Port:            22,
		User:            "alice",
		AuthType:        "password",
		AuthUpdateToken: "tok-1",
		Options: MustOptions(
			OptionBatchMode, "no",
			OptionServerAliveInterval, "30",
			OptionServerAliveCountMax, "3",
			OptionTCPKeepAlive, "yes",
			OptionForwardAgent, "no",
			OptionGatewayPorts, "no",
			OptionStreamLocalBindUnlink, "no",
			OptionStreamLocalBindMask, "0177",
		),
	}
	cur := baseCfg.ToConnectionConfig()
	if err := validateTargetCompatibility(cur, baseCfg); err != nil {
		t.Fatalf("identical config failed compatibility: %v", err)
	}

	// Verify auto baseline resolved to password matches auto & password, rejects key.
	autoBase := *baseCfg
	autoBase.AuthType = "auto"
	autoCur := autoBase.ToConnectionConfig()
	autoCur.AuthType = "password" // resolved during handshake
	for _, allowed := range []string{"auto", "password"} {
		cand := autoBase
		cand.AuthType = allowed
		if err := validateTargetCompatibility(autoCur, &cand); err != nil {
			t.Fatalf("auto->password snapshot should accept %q, got %v", allowed, err)
		}
	}
	autoToKey := autoBase
	autoToKey.AuthType = "key"
	if err := validateTargetCompatibility(autoCur, &autoToKey); !errors.Is(err, ErrSnapshotMismatch) {
		t.Fatalf("auto->password snapshot must reject explicit key, got %v", err)
	}

	mutations := []struct {
		name   string
		mutate func(*ClientConfig)
	}{
		{"AuthUpdateToken", func(c *ClientConfig) { c.AuthUpdateToken = "tok-2" }},
		{"AuthType password->key", func(c *ClientConfig) { c.AuthType = "key" }},
		{"AuthType password->auto", func(c *ClientConfig) { c.AuthType = "auto" }},
		{"BatchMode", func(c *ClientConfig) { _ = c.Options.Set(OptionBatchMode, "yes") }},
		{"ServerAliveInterval", func(c *ClientConfig) { _ = c.Options.Set(OptionServerAliveInterval, "60") }},
		{"ServerAliveCountMax", func(c *ClientConfig) { _ = c.Options.Set(OptionServerAliveCountMax, "5") }},
		{"TCPKeepAlive", func(c *ClientConfig) { _ = c.Options.Set(OptionTCPKeepAlive, "no") }},
		{"ForwardAgent", func(c *ClientConfig) { _ = c.Options.Set(OptionForwardAgent, "yes") }},
		{"GatewayPorts", func(c *ClientConfig) { _ = c.Options.Set(OptionGatewayPorts, "yes") }},
		{"StreamLocalBindUnlink", func(c *ClientConfig) { _ = c.Options.Set(OptionStreamLocalBindUnlink, "yes") }},
		{"StreamLocalBindMask", func(c *ClientConfig) { _ = c.Options.Set(OptionStreamLocalBindMask, "0111") }},
	}
	baseDigest := targetCompatDigest(baseCfg)
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			cand := *baseCfg
			cand.Options = baseCfg.Options.Clone()
			tc.mutate(&cand)
			if err := validateTargetCompatibility(cur, &cand); !errors.Is(err, ErrSnapshotMismatch) {
				t.Fatalf("%s: expected ErrSnapshotMismatch, got %v", tc.name, err)
			}
			if targetCompatDigest(&cand) == baseDigest {
				t.Fatalf("%s: targetCompatDigest did not change", tc.name)
			}
		})
	}
}

type p5DeleteAfterFirstGetProvider struct {
	mu    sync.Mutex
	cfg   *ClientConfig
	calls int
}

func (p *p5DeleteAfterFirstGetProvider) GetConfig(nodeID string) (*ClientConfig, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.calls == 1 {
		cp := *p.cfg
		return &cp, nil
	}
	return nil, errors.New("node deleted concurrently: " + nodeID)
}

func TestP5_3_2_ReloadConfigAfterRecording_FailClosedOnDeletedNode(t *testing.T) {
	t.Parallel()

	host, port, stop := startLifetimeTestSSHServer(t, "good-pass", nil)
	defer stop()

	env := fixtureEnvironment()
	env.HomeDir = t.TempDir()
	env.KnownHostsFile = filepath.Join(env.HomeDir, "known_hosts")

	provider := &p5DeleteAfterFirstGetProvider{
		cfg: &ClientConfig{
			NodeID:   "ephemeral",
			Address:  host,
			Port:     port,
			User:     "alice",
			AuthType: "password",
			Password: "good-pass",
		},
	}
	conn := NewConnector(provider, WithEnvironment(env))
	conn.AcceptNewHostKey.Store(true)
	t.Cleanup(func() { _ = conn.CloseAll() })

	_, err := conn.Connect(t.Context(), "ephemeral")
	if err == nil || !strings.Contains(err.Error(), "node deleted concurrently") {
		t.Fatalf("expected fail-closed error when node deleted during handshake, got %v", err)
	}
	if _, ok := conn.clients.Get("ephemeral"); ok {
		t.Fatal("deleted node client must not be published into pool")
	}
}

func TestP5_3_2_CascadeEvictionAndRetireDownstream(t *testing.T) {
	t.Parallel()

	t.Run("probe_failure_evicts_same_generation_downstream_only", func(t *testing.T) {
		store := &mockConfigStore{cfg: &ClientConfig{NodeID: "bastion", Address: "127.0.0.1", Port: 1, User: "u", AuthType: "password", Password: "p"}}
		conn := newTestConnector(store)
		t.Cleanup(func() { _ = conn.CloseAll() })

		rootOld, rootOldPeer := net.Pipe()
		rootNew, rootNewPeer := net.Pipe()
		defer func() { _ = rootOldPeer.Close(); _ = rootNewPeer.Close() }()

		deadBastionConn := &coordinatedDeadConn{requestSeen: make(chan struct{}), release: make(chan struct{})}
		close(deadBastionConn.release)
		childConn := &coordinatedHealthyConn{requestSeen: make(chan struct{}), release: make(chan struct{})}
		newGenConn := &coordinatedHealthyConn{requestSeen: make(chan struct{}), release: make(chan struct{})}
		otherConn := &coordinatedHealthyConn{requestSeen: make(chan struct{}), release: make(chan struct{})}

		bastionClient := &PooledClient{SSHClient: &cryptoSSH.Client{Conn: deadBastionConn}, RootConn: rootOld}
		childKey := connectionRouteKey([]string{"bastion"}, "target")
		newGenKey := connectionRouteKey([]string{"bastion"}, "fresh")
		conn.clients.Set("bastion", bastionClient)
		conn.clients.Set(childKey, &PooledClient{SSHClient: &cryptoSSH.Client{Conn: childConn}, RootConn: rootOld})
		conn.clients.Set(newGenKey, &PooledClient{SSHClient: &cryptoSSH.Client{Conn: newGenConn}, RootConn: rootNew})
		conn.clients.Set("unrelated", &PooledClient{SSHClient: &cryptoSSH.Client{Conn: otherConn}})

		_, err := conn.Connect(t.Context(), "bastion")
		if err == nil {
			t.Fatal("expected dead bastion reconnect to fail on port 1")
		}
		if _, ok := conn.clients.Get(childKey); ok {
			t.Fatal("downstream hop on dead RootConn was not cascade-evicted")
		}
		if childConn.closeCount.Load() == 0 {
			t.Fatal("cascade-evicted downstream hop was not interrupted")
		}
		if _, ok := conn.clients.Get(newGenKey); !ok {
			t.Fatal("downstream hop on newer RootConn generation was erroneously evicted")
		}
		if _, ok := conn.clients.Get("unrelated"); !ok {
			t.Fatal("unrelated cached route was erroneously evicted")
		}
	})

	t.Run("evictDeadClient_cascades_downstream", func(t *testing.T) {
		conn := newTestConnector(nil)
		t.Cleanup(func() { _ = conn.CloseAll() })

		root, peer := net.Pipe()
		defer func() { _ = peer.Close() }()
		deadParent := &PooledClient{SSHClient: &cryptoSSH.Client{Conn: &coordinatedDeadConn{}}, RootConn: root}
		childConn := &coordinatedHealthyConn{}
		childKey := connectionRouteKey([]string{"jump"}, "app")
		conn.clients.Set("jump", deadParent)
		conn.clients.Set(childKey, &PooledClient{SSHClient: &cryptoSSH.Client{Conn: childConn}, RootConn: root})

		entry := &keepAliveEntry{client: deadParent, cancel: func() {}}
		conn.evictDeadClient("jump", deadParent, entry)

		if _, ok := conn.clients.Get(childKey); ok {
			t.Fatal("evictDeadClient did not cascade-evict downstream hop")
		}
		if childConn.closeCount.Load() == 0 {
			t.Fatal("evictDeadClient did not interrupt downstream hop")
		}
	})

	t.Run("retireDownstreamGeneration_handles_nil_RootConn", func(t *testing.T) {
		conn := newTestConnector(nil)
		t.Cleanup(func() { _ = conn.CloseAll() })

		displaced := &PooledClient{SSHClient: &cryptoSSH.Client{}} // RootConn == nil
		childKey := connectionRouteKey([]string{"jump"}, "app")
		conn.clients.Set(childKey, &PooledClient{SSHClient: &cryptoSSH.Client{}})
		conn.clients.Set("other", &PooledClient{SSHClient: &cryptoSSH.Client{}})

		conn.retireDownstreamGeneration("jump", displaced)

		if _, ok := conn.clients.Get(childKey); ok {
			t.Fatal("retireDownstreamGeneration skipped downstream hop when displaced.RootConn == nil")
		}
		if _, ok := conn.clients.Get("other"); !ok {
			t.Fatal("retireDownstreamGeneration retired unrelated hop")
		}
	})
}

// --- Finding 4.11: Admitted cert/key binding & bounded regular-file reads ---

func TestP5_4_11_AdmittedMaterial_ConnectionKeyAndDeepClone(t *testing.T) {
	t.Parallel()

	rawA := []byte("cert-bytes-a")
	sumA := p5SHA256Hex(rawA)
	sumB := p5SHA256Hex([]byte("cert-bytes-b"))

	cfg := &ClientConfig{
		NodeID:                      "n1",
		Address:                     "10.0.0.1",
		Port:                        22,
		User:                        "alice",
		AuthType:                    "key",
		EnforceAdmittedCertificates: true,
		AdmittedCertificates:        []AdmittedCertificate{{Path: "/k/id-cert.pub", SHA256: sumA, RawBytes: slices.Clone(rawA)}},
		EnforceAdmittedKeyDigests:   true,
		AdmittedKeyDigests:          []AdmittedKeyDigest{{Path: "/k/id", SHA256: sumA}},
	}
	cc := cfg.ToConnectionConfig()
	cfg.AdmittedCertificates[0].RawBytes[0] = 'X'
	cfg.AdmittedKeyDigests[0].Path = "/mutated"
	if string(cc.AdmittedCertificates[0].RawBytes) != string(rawA) || cc.AdmittedKeyDigests[0].Path != "/k/id" {
		t.Fatal("ToConnectionConfig did not deep-clone admitted materials")
	}

	planWithRaw := ConnectionPlan{Scope: "mcp", Hops: []ConnectionConfig{cc.Clone()}}
	ccNoRaw := cc.Clone()
	ccNoRaw.AdmittedCertificates[0].RawBytes = nil
	planNoRaw := ConnectionPlan{Scope: "mcp", Hops: []ConnectionConfig{ccNoRaw}}

	kWithRaw, err := ConnectionKey(planWithRaw)
	if err != nil {
		t.Fatalf("ConnectionKey(withRaw): %v", err)
	}
	kNoRaw, err := ConnectionKey(planNoRaw)
	if err != nil {
		t.Fatalf("ConnectionKey(noRaw): %v", err)
	}
	if kWithRaw != kNoRaw {
		t.Fatalf("RawBytes (json:\"-\") must not change ConnectionKey: %q vs %q", kWithRaw, kNoRaw)
	}

	ccDiffCert := cc.Clone()
	ccDiffCert.AdmittedCertificates[0].SHA256 = sumB
	kDiffCert, err := ConnectionKey(ConnectionPlan{Scope: "mcp", Hops: []ConnectionConfig{ccDiffCert}})
	if err != nil || kDiffCert == kWithRaw {
		t.Fatalf("AdmittedCertificates SHA256 change must alter ConnectionKey (err=%v)", err)
	}

	ccDiffKey := cc.Clone()
	ccDiffKey.AdmittedKeyDigests[0].Missing = true
	kDiffKey, err := ConnectionKey(ConnectionPlan{Scope: "mcp", Hops: []ConnectionConfig{ccDiffKey}})
	if err != nil || kDiffKey == kWithRaw {
		t.Fatalf("AdmittedKeyDigests change must alter ConnectionKey (err=%v)", err)
	}

	roundTrip := clientConfigFromPlan(cc)
	cc.AdmittedCertificates[0].RawBytes[0] = 'Z'
	if string(roundTrip.AdmittedCertificates[0].RawBytes) != string(rawA) {
		t.Fatal("clientConfigFromPlan did not deep-clone AdmittedCertificates.RawBytes")
	}
}

func TestP5_4_11_ReadBoundedRegularFile_CapsAndNonRegular(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if _, err := fsx.ReadAllBounded(dir, fsx.Limits{MaxBytes: maxKeyFileBytes}, fsx.FollowSymlinks()); err == nil {
		t.Fatal("expected directory to be rejected as non-regular file")
	}

	exactCert := filepath.Join(dir, "exact.cert")
	if err := os.WriteFile(exactCert, bytes.Repeat([]byte("a"), int(maxUserCertFileBytes)), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := fsx.ReadAllBounded(exactCert, fsx.Limits{MaxBytes: maxUserCertFileBytes}, fsx.FollowSymlinks()); err != nil || int64(len(data)) != maxUserCertFileBytes {
		t.Fatalf("exact cap cert read failed: len=%d err=%v", len(data), err)
	}

	overCert := filepath.Join(dir, "over.cert")
	if err := os.WriteFile(overCert, bytes.Repeat([]byte("a"), int(maxUserCertFileBytes)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fsx.ReadAllBounded(overCert, fsx.Limits{MaxBytes: maxUserCertFileBytes}, fsx.FollowSymlinks()); err == nil {
		t.Fatal("expected oversized cert file (>256 KiB) to be rejected")
	}

	overKey := filepath.Join(dir, "over.key")
	if err := os.WriteFile(overKey, bytes.Repeat([]byte("b"), int(maxKeyFileBytes)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fsx.ReadAllBounded(overKey, fsx.Limits{MaxBytes: maxKeyFileBytes}, fsx.FollowSymlinks()); err == nil {
		t.Fatal("expected oversized key file (>1 MiB) to be rejected")
	}

	if runtime.GOOS != "windows" {
		if mkfifoBin, lookErr := exec.LookPath("mkfifo"); lookErr == nil {
			fifoPath := filepath.Join(dir, "evil.fifo")
			if err := exec.Command(mkfifoBin, fifoPath).Run(); err != nil {
				t.Fatalf("mkfifo: %v", err)
			}
			done := make(chan error, 1)
			go func() {
				_, err := fsx.ReadAllBounded(fifoPath, fsx.Limits{MaxBytes: maxUserCertFileBytes}, fsx.FollowSymlinks())
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, fsx.ErrNonRegular) {
					t.Fatalf("expected fsx.ErrNonRegular for FIFO, got %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("fsx.ReadAllBounded blocked on FIFO instead of failing closed")
			}
		}
	}
}

func TestP5_4_11_EnforceAdmittedCertificates_ZeroTOCTOUAndFailClosed(t *testing.T) {
	t.Parallel()

	keyPEM, userSigner, caPub, certBytes := p5GenerateEd25519KeyAndCert(t, "certuser")
	host, port, hostPub, stop := p5StartCertOrKeySSHServer(t, caPub, nil) // accepts ONLY CA-signed cert, NOT plain key
	defer stop()

	dir := t.TempDir()
	khFile := filepath.Join(dir, "known_hosts")
	writePhase4KnownHosts(t, khFile, net.JoinHostPort(host, strconv.Itoa(port)), hostPub)
	keyPath := filepath.Join(dir, "id_ed25519")
	explicitCertPath := filepath.Join(dir, "explicit-cert.pub")
	sidecarPath := filepath.Join(dir, "id_ed25519-cert.pub")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(explicitCertPath, certBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sidecarPath, certBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	certSum := p5SHA256Hex(certBytes)

	newPlanConnector := func(t *testing.T, ks KeySource) *Connector {
		t.Helper()
		env := fixtureEnvironment()
		env.HomeDir = dir
		env.KnownHostsFile = khFile
		opts := []Option{WithEnvironment(env)}
		if ks != nil {
			opts = append(opts, WithKeySource(ks))
		}
		c := NewConnector(nil, opts...)
		t.Cleanup(func() { _ = c.CloseAll() })
		return c
	}

	t.Run("rawbytes_zero_toctou_after_disk_tamper", func(t *testing.T) {
		tamperedCert := filepath.Join(dir, "tampered-cert.pub")
		if err := os.WriteFile(tamperedCert, []byte("corrupted-after-admission"), 0o600); err != nil {
			t.Fatal(err)
		}
		plan := ConnectionPlan{
			Scope: "p5-rawbytes",
			Hops: []ConnectionConfig{{
				NodeID:                      "n",
				Address:                     host,
				Port:                        port,
				User:                        "certuser",
				AuthType:                    "key",
				KeyPath:                     keyPath,
				Options:                     MustOptions(OptionCertificateFile, tamperedCert, OptionIdentitiesOnly, "yes"),
				EnforceAdmittedCertificates: true,
				AdmittedCertificates:        []AdmittedCertificate{{Path: tamperedCert, SHA256: certSum, RawBytes: slices.Clone(certBytes)}},
			}},
		}
		lease, err := newPlanConnector(t, nil).ConnectPlan(t.Context(), plan)
		if err != nil {
			t.Fatalf("ConnectPlan with valid admitted RawBytes failed after disk tamper: %v", err)
		}
		_ = lease.Close()
	})

	t.Run("rawbytes_sha256_mismatch_fails_closed", func(t *testing.T) {
		badRaw := slices.Clone(certBytes)
		badRaw[len(badRaw)-2] ^= 0x01
		plan := ConnectionPlan{
			Scope: "p5-rawbytes-bad",
			Hops: []ConnectionConfig{{
				NodeID:                      "n",
				Address:                     host,
				Port:                        port,
				User:                        "certuser",
				AuthType:                    "key",
				KeyPath:                     keyPath,
				Options:                     MustOptions(OptionCertificateFile, explicitCertPath, OptionIdentitiesOnly, "yes"),
				EnforceAdmittedCertificates: true,
				AdmittedCertificates:        []AdmittedCertificate{{Path: explicitCertPath, SHA256: certSum, RawBytes: badRaw}},
			}},
		}
		if lease, err := newPlanConnector(t, nil).ConnectPlan(t.Context(), plan); err == nil {
			_ = lease.Close()
			t.Fatal("expected RawBytes SHA256 mismatch to fail closed")
		}
	})

	t.Run("disk_fallback_verifies_and_rejects_mismatch", func(t *testing.T) {
		goodPlan := ConnectionPlan{
			Scope: "p5-disk-good",
			Hops: []ConnectionConfig{{
				NodeID:                      "n",
				Address:                     host,
				Port:                        port,
				User:                        "certuser",
				AuthType:                    "key",
				KeyPath:                     keyPath,
				Options:                     MustOptions(OptionCertificateFile, explicitCertPath, OptionIdentitiesOnly, "yes"),
				EnforceAdmittedCertificates: true,
				AdmittedCertificates:        []AdmittedCertificate{{Path: explicitCertPath, SHA256: certSum}},
			}},
		}
		lease, err := newPlanConnector(t, nil).ConnectPlan(t.Context(), goodPlan)
		if err != nil {
			t.Fatalf("expected matching disk cert SHA-256 to succeed: %v", err)
		}
		_ = lease.Close()

		badPlan := goodPlan
		badPlan.Scope = "p5-disk-bad"
		badPlan.Hops = slices.Clone(goodPlan.Hops)
		badPlan.Hops[0].AdmittedCertificates = []AdmittedCertificate{{Path: explicitCertPath, SHA256: p5SHA256Hex([]byte("other"))}}
		if lease, err := newPlanConnector(t, nil).ConnectPlan(t.Context(), badPlan); err == nil {
			_ = lease.Close()
			t.Fatal("expected disk cert SHA-256 mismatch to fail closed")
		}
	})

	t.Run("missing_nonregular_and_unadmitted_fail_closed", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			certs []AdmittedCertificate
		}{
			{"missing", []AdmittedCertificate{{Path: explicitCertPath, Missing: true}}},
			{"nonregular", []AdmittedCertificate{{Path: explicitCertPath, NonRegular: true}}},
			{"unadmitted", nil},
		} {
			plan := ConnectionPlan{
				Scope: "p5-cert-" + tc.name,
				Hops: []ConnectionConfig{{
					NodeID:                      "n",
					Address:                     host,
					Port:                        port,
					User:                        "certuser",
					AuthType:                    "key",
					KeyPath:                     keyPath,
					Options:                     MustOptions(OptionCertificateFile, explicitCertPath, OptionIdentitiesOnly, "yes"),
					EnforceAdmittedCertificates: true,
					AdmittedCertificates:        tc.certs,
				}},
			}
			if lease, err := newPlanConnector(t, nil).ConnectPlan(t.Context(), plan); err == nil {
				_ = lease.Close()
				t.Fatalf("%s: expected fail closed when cert is not admitted/valid", tc.name)
			}
		}
	})

	t.Run("keysource_enforces_admitted_sidecar_certs", func(t *testing.T) {
		ks := &p5StaticKeySource{signer: userSigner}
		unadmittedPlan := ConnectionPlan{
			Scope: "p5-ks-unadmitted",
			Hops: []ConnectionConfig{{
				NodeID:                      "n",
				Address:                     host,
				Port:                        port,
				User:                        "certuser",
				AuthType:                    "key",
				KeyPath:                     keyPath,
				EnforceAdmittedCertificates: true,
			}},
		}
		if lease, err := newPlanConnector(t, ks).ConnectPlan(t.Context(), unadmittedPlan); err == nil {
			_ = lease.Close()
			t.Fatal("KeySource must not load un-admitted sidecar cert when EnforceAdmittedCertificates=true")
		}

		// Delete sidecar on disk and rely solely on admitted RawBytes.
		if err := os.Remove(sidecarPath); err != nil {
			t.Fatal(err)
		}
		admittedPlan := unadmittedPlan
		admittedPlan.Scope = "p5-ks-admitted"
		admittedPlan.Hops[0].AdmittedCertificates = []AdmittedCertificate{{Path: sidecarPath, SHA256: certSum, RawBytes: slices.Clone(certBytes)}}
		lease, err := newPlanConnector(t, ks).ConnectPlan(t.Context(), admittedPlan)
		if err != nil {
			t.Fatalf("KeySource with admitted RawBytes sidecar failed: %v", err)
		}
		_ = lease.Close()
	})
}

func TestP5_4_11_EnforceAdmittedKeyDigests_FailClosed(t *testing.T) {
	t.Parallel()

	keyPEM, userSigner, _, _ := p5GenerateEd25519KeyAndCert(t, "keyuser")
	host, port, hostPub, stop := p5StartCertOrKeySSHServer(t, nil, userSigner.PublicKey())
	defer stop()

	dir := t.TempDir()
	khFile := filepath.Join(dir, "known_hosts")
	writePhase4KnownHosts(t, khFile, net.JoinHostPort(host, strconv.Itoa(port)), hostPub)
	keyPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	keySum := p5SHA256Hex(keyPEM)

	newConn := func(t *testing.T) *Connector {
		t.Helper()
		env := fixtureEnvironment()
		env.HomeDir = dir
		env.KnownHostsFile = khFile
		c := NewConnector(nil, WithEnvironment(env))
		t.Cleanup(func() { _ = c.CloseAll() })
		return c
	}

	for _, authType := range []string{"key", "auto"} {
		t.Run("matching_digest_"+authType, func(t *testing.T) {
			plan := ConnectionPlan{
				Scope: "p5-kd-ok-" + authType,
				Hops: []ConnectionConfig{{
					NodeID:                    "n",
					Address:                   host,
					Port:                      port,
					User:                      "keyuser",
					AuthType:                  authType,
					KeyPath:                   keyPath,
					Options:                   MustOptions(OptionIdentitiesOnly, "yes"),
					EnforceAdmittedKeyDigests: true,
					AdmittedKeyDigests:        []AdmittedKeyDigest{{Path: keyPath, SHA256: keySum}},
				}},
			}
			lease, err := newConn(t).ConnectPlan(t.Context(), plan)
			if err != nil {
				t.Fatalf("ConnectPlan(%s) with matching key digest failed: %v", authType, err)
			}
			_ = lease.Close()
		})
	}

	for _, tc := range []struct {
		name     string
		authType string
		digests  []AdmittedKeyDigest
	}{
		{"unadmitted_key_mode", "key", nil},
		{"unadmitted_auto_mode", "auto", nil},
		{"mutated_digest_key_mode", "key", []AdmittedKeyDigest{{Path: keyPath, SHA256: p5SHA256Hex([]byte("mutated"))}}},
		{"mutated_digest_auto_mode", "auto", []AdmittedKeyDigest{{Path: keyPath, SHA256: p5SHA256Hex([]byte("mutated"))}}},
		{"newly_appeared_missing_key", "key", []AdmittedKeyDigest{{Path: keyPath, Missing: true}}},
		{"newly_appeared_missing_auto", "auto", []AdmittedKeyDigest{{Path: keyPath, Missing: true}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := ConnectionPlan{
				Scope: "p5-kd-" + tc.name,
				Hops: []ConnectionConfig{{
					NodeID:                    "n",
					Address:                   host,
					Port:                      port,
					User:                      "keyuser",
					AuthType:                  tc.authType,
					KeyPath:                   keyPath,
					Options:                   MustOptions(OptionIdentitiesOnly, "yes"),
					EnforceAdmittedKeyDigests: true,
					AdmittedKeyDigests:        tc.digests,
				}},
			}
			lease, err := newConn(t).ConnectPlan(t.Context(), plan)
			if err == nil {
				_ = lease.Close()
				t.Fatalf("%s: expected ErrSnapshotMismatch, got nil", tc.name)
			}
			if !errors.Is(err, ErrSnapshotMismatch) {
				t.Fatalf("%s: expected ErrSnapshotMismatch, got %v", tc.name, err)
			}
		})
	}

	t.Run("admitted_missing_still_absent_falls_through_to_second_admitted_key", func(t *testing.T) {
		absentPath := filepath.Join(dir, "id_absent")
		plan := ConnectionPlan{
			Scope: "p5-kd-absent-ok",
			Hops: []ConnectionConfig{{
				NodeID:                    "n",
				Address:                   host,
				Port:                      port,
				User:                      "keyuser",
				AuthType:                  "key",
				KeyPaths:                  []string{absentPath, keyPath},
				Options:                   MustOptions(OptionIdentitiesOnly, "yes"),
				EnforceAdmittedKeyDigests: true,
				AdmittedKeyDigests: []AdmittedKeyDigest{
					{Path: absentPath, Missing: true},
					{Path: keyPath, SHA256: keySum},
				},
			}},
		}
		lease, err := newConn(t).ConnectPlan(t.Context(), plan)
		if err != nil {
			t.Fatalf("expected absent-admitted key to skip cleanly to valid second key, got %v", err)
		}
		_ = lease.Close()
	})
}

// --- Finding 4.2: IdentityFile=none / CertificateFile=none break & single-layer truncation ---

func TestP5_4_2_NoneTerminationSingleLayerAndCollectors(t *testing.T) {
	t.Parallel()

	t.Run("Options_Append_truncates_and_preserves_none_sentinel", func(t *testing.T) {
		for _, optKey := range []string{OptionIdentityFile, OptionCertificateFile} {
			layer := &Options{}
			if err := layer.Append(optKey, "/tmp/first"); err != nil {
				t.Fatal(err)
			}
			if err := layer.Append(optKey, "NONE"); err != nil {
				t.Fatal(err)
			}
			if err := layer.Append(optKey, "/tmp/after_none"); err != nil {
				t.Fatal(err)
			}
			if got := layer.GetAll(optKey); !slices.Equal(got, []string{"/tmp/first", "none"}) {
				t.Fatalf("%s Append = %v, want [/tmp/first none]", optKey, got)
			}
			// Syntax validation still runs even after none.
			if err := layer.Append(optKey, "/tmp/bad_%k"); !errors.Is(err, ErrSSHOptionsValidation) {
				t.Fatalf("%s Append invalid after none: err=%v, want ErrSSHOptionsValidation", optKey, err)
			}
			// Merging over a lower layer must still truncate lower layer entries.
			lower := MustOptions(optKey, "/tmp/lower_secret")
			merged := MergeOptionLayers(layer, lower)
			if got := merged.GetAll(optKey); !slices.Equal(got, []string{"/tmp/first"}) {
				t.Fatalf("%s MergeOptionLayers = %v, want [/tmp/first]", optKey, got)
			}
		}
	})

	t.Run("UnmarshalYAML_and_UnmarshalJSON_truncate_at_first_none", func(t *testing.T) {
		var fromYAML Options
		if err := yaml.Unmarshal([]byte("identity_file:\n  - /tmp/k1\n  - none\n  - /tmp/k2\ncertificate_file:\n  - NONE\n  - /tmp/c2\n"), &fromYAML); err != nil {
			t.Fatalf("yaml.Unmarshal: %v", err)
		}
		if got := fromYAML.IdentityFiles(); !slices.Equal(got, []string{"/tmp/k1", "none"}) {
			t.Fatalf("YAML IdentityFiles = %v, want [/tmp/k1 none]", got)
		}
		if got := fromYAML.CertificateFiles(); !slices.Equal(got, []string{"none"}) {
			t.Fatalf("YAML CertificateFiles = %v, want [none]", got)
		}

		var fromJSON Options
		if err := json.Unmarshal([]byte(`{"identity_file":["/tmp/k1","none","/tmp/k2"],"certificate_file":["none","/tmp/c2"]}`), &fromJSON); err != nil {
			t.Fatalf("json.Unmarshal: %v", err)
		}
		if got := fromJSON.IdentityFiles(); !slices.Equal(got, []string{"/tmp/k1", "none"}) {
			t.Fatalf("JSON IdentityFiles = %v, want [/tmp/k1 none]", got)
		}
		if got := fromJSON.CertificateFiles(); !slices.Equal(got, []string{"none"}) {
			t.Fatalf("JSON CertificateFiles = %v, want [none]", got)
		}
	})
}

func TestP5_4_2_CollectorsBreakOnNone(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, _, _, certBytes := p5GenerateEd25519KeyAndCert(t, "u")
	c1 := filepath.Join(dir, "c1-cert.pub")
	c2 := filepath.Join(dir, "c2-cert.pub")
	if err := os.WriteFile(c1, certBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c2, certBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	env := fixtureEnvironment()
	target := TargetContext{Host: "h", Port: 22, User: "u"}

	keys, hasExplicit := collectExplicitKeyCandidates(
		[]string{filepath.Join(dir, "k1"), "none", filepath.Join(dir, "k2")},
		"", nil, env, target, nil, nil,
	)
	if !hasExplicit || !slices.Equal(keys, []string{filepath.Join(dir, "k1")}) {
		t.Fatalf("collectExplicitKeyCandidates = (%v, %v), want ([k1], true)", keys, hasExplicit)
	}

	// Direct raw map bypassing Set/Append to verify collector itself breaks at "none".
	rawOpts := &Options{values: map[string]string{
		OptionCertificateFile: c1 + "\nnone\n" + c2,
	}}
	certs, hasCerts := collectExplicitUserCerts(rawOpts, env, target, nil, nil)
	if !hasCerts || len(certs) != 1 || certs[0].path != c1 {
		t.Fatalf("collectExplicitUserCerts = (%+v, %v), want only %q", certs, hasCerts, c1)
	}
}

// --- Finding 2.2: ControlPath=none same-layer vs cross-layer validation ---

func TestP5_2_2_ControlPathNone_SameLayerRejectedCrossLayerAllowed(t *testing.T) {
	t.Parallel()

	sameLayerCases := []struct {
		name string
		opts *Options
	}{
		{"path_none_and_master_yes", MustOptions(OptionControlPath, "none", OptionControlMaster, "yes")},
		{"path_none_and_master_auto", MustOptions(OptionControlPath, "none", OptionControlMaster, "auto")},
		{"path_none_and_persist_10m", MustOptions(OptionControlPath, "none", OptionControlPersist, "10m")},
		{"path_none_and_persist_yes", MustOptions(OptionControlPath, "none", OptionControlPersist, "yes")},
	}
	for _, tc := range sameLayerCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.opts.Validate(); !errors.Is(err, ErrSSHOptionsValidation) {
				t.Fatalf("Validate(): err=%v, want ErrSSHOptionsValidation", err)
			}
			if _, err := tc.opts.ValidatedControlConfig(); !errors.Is(err, ErrSSHOptionsValidation) {
				t.Fatalf("ValidatedControlConfig(): err=%v, want ErrSSHOptionsValidation", err)
			}
			if _, err := MergeEffectiveOptions(tc.opts); !errors.Is(err, ErrSSHOptionsValidation) {
				t.Fatalf("MergeEffectiveOptions(single): err=%v, want ErrSSHOptionsValidation", err)
			}
		})
	}

	// Cross-layer: Tier-1 ControlPath=none cleanly overrides valid lower-tier mux config.
	tier1 := MustOptions(OptionControlPath, "none")
	tier2 := MustOptions(OptionControlMaster, "auto", OptionControlPath, "~/.ssh/cm-%C", OptionControlPersist, "10m")
	eff, err := MergeEffectiveOptions(tier1, tier2)
	if err != nil {
		t.Fatalf("cross-layer ControlPath=none override failed: %v", err)
	}
	if eff.ControlPath() != "none" || eff.ControlMaster() != ControlMasterNo || eff.ControlPersist() != "" {
		t.Fatalf("unexpected effective cross-layer mux: path=%q master=%q persist=%q", eff.ControlPath(), eff.ControlMaster(), eff.ControlPersist())
	}

	// Multi-block Tier-4 OpenSSH (ImplicitTier4=true): Host foo ControlPath=none + Host * Master/Persist succeeds,
	// while broken Tier-4 (Master=yes with no ControlPath) still fails closed.
	t4Disable := MustOptions(OptionControlPath, "none", OptionControlMaster, "auto", OptionControlPersist, "10m")
	t4Disable.ImplicitTier4 = true
	if eff4, err := MergeEffectiveOptions(nil, t4Disable); err != nil || eff4.ControlMaster() != ControlMasterNo {
		t.Fatalf("ImplicitTier4 multi-block ControlPath=none failed: eff=%+v err=%v", eff4, err)
	}
	t4Broken := MustOptions(OptionControlMaster, "yes")
	t4Broken.ImplicitTier4 = true
	if _, err := MergeEffectiveOptions(nil, t4Broken); !errors.Is(err, ErrSSHOptionsValidation) {
		t.Fatalf("ImplicitTier4 Master=yes without ControlPath must fail closed, got %v", err)
	}
}

// --- Finding R2: ExpandRemoteCommand token safety ---

func TestP5_R2_ExpandRemoteCommand_TokenSafety(t *testing.T) {
	t.Parallel()

	baseEnv := Environment{
		HomeDir:   "/home/alice",
		LocalUser: "alice",
		LocalHost: "workstation.corp.local",
		LocalUID:  "1000",
	}
	baseTarget := TargetContext{
		Host:         "app.example.com",
		Port:         2222,
		User:         "deploy",
		OriginalHost: "app-alias",
	}

	got, err := ExpandRemoteCommand("tmux attach -t %n-%h-%p-%r-%u-%l-%L-%i-%d", baseEnv, baseTarget)
	if err != nil {
		t.Fatalf("valid ExpandRemoteCommand failed: %v", err)
	}
	if !strings.Contains(got, "/home/alice") || !strings.Contains(got, "app.example.com") {
		t.Fatalf("unexpected expansion %q", got)
	}

	// Spaces and backslashes in home dirs (macOS/Windows) remain allowed when free of shell metachars/controls.
	for _, home := range []string{"/Users/Jane Doe", `C:\Users\John Doe`} {
		env := baseEnv
		env.HomeDir = home
		if out, err := ExpandRemoteCommand("cd %d && exec bash", env, baseTarget); err != nil || !strings.Contains(out, home) {
			t.Fatalf("expected valid home %q to expand cleanly, got (%q, %v)", home, out, err)
		}
	}

	badTokens := []struct {
		name    string
		pattern string
		mutate  func(*Environment, *TargetContext)
	}{
		{"host_semicolon", "echo %h", func(_ *Environment, tc *TargetContext) { tc.Host = "a;id" }},
		{"host_subshell", "echo %h", func(_ *Environment, tc *TargetContext) { tc.Host = "$(id)" }},
		{"user_pipe", "echo %r", func(_ *Environment, tc *TargetContext) { tc.User = "alice|sh" }},
		{"orig_host_backtick", "echo %n", func(_ *Environment, tc *TargetContext) { tc.OriginalHost = "`id`" }},
		{"local_user_quote", "echo %u", func(e *Environment, _ *TargetContext) { e.LocalUser = "a'b" }},
		{"local_host_amp", "echo %l", func(e *Environment, _ *TargetContext) { e.LocalHost = "h&id" }},
		{"short_host_ctrl", "echo %L", func(e *Environment, _ *TargetContext) { e.LocalHost = "h\x1b[31m.local" }},
		{"uid_space", "echo %i", func(e *Environment, _ *TargetContext) { e.LocalUID = "1000;id" }},
		{"home_semicolon", "echo %d", func(e *Environment, _ *TargetContext) { e.HomeDir = "/home/a;id" }},
		{"home_subshell", "echo %d", func(e *Environment, _ *TargetContext) { e.HomeDir = "/home/$(id)" }},
		{"home_backtick", "echo %d", func(e *Environment, _ *TargetContext) { e.HomeDir = "/home/`id`" }},
		{"home_tab_ctrl", "echo %d", func(e *Environment, _ *TargetContext) { e.HomeDir = "/home/a\tb" }},
		{"home_linesep_ctrl", "echo %d", func(e *Environment, _ *TargetContext) { e.HomeDir = "/home/a\u2028b" }},
		{"home_leading_dash", "echo %d", func(e *Environment, _ *TargetContext) { e.HomeDir = "-rf" }},
	}
	for _, tc := range badTokens {
		t.Run(tc.name, func(t *testing.T) {
			env := baseEnv
			target := baseTarget
			tc.mutate(&env, &target)
			if out, err := ExpandRemoteCommand(tc.pattern, env, target); !errors.Is(err, ErrUnsafeExecToken) {
				t.Fatalf("%s: expected ErrUnsafeExecToken, got (%q, %v)", tc.name, out, err)
			}
		})
	}
}

// --- Finding R5: MatchesMasterTarget fail-closed ---

func TestP5_R5_MatchesMasterTarget_FailClosed(t *testing.T) {
	t.Parallel()

	target := TargetContext{Host: "app.example.com", Port: 2222, User: "alice", JumpHost: "bastion"}
	validID := target.CanonicalTargetIdentity()
	if !target.MatchesMasterTarget(validID) {
		t.Fatalf("expected valid canonical identity %q to match", validID)
	}
	// Legacy OpenSSH master interop: empty masterIdentity means extension absent.
	if !target.MatchesMasterTarget("") {
		t.Fatal("empty masterIdentity must return true for legacy OpenSSH master interop")
	}

	badIdentities := []string{
		" ",
		"garbage",
		"port=2222;user=alice;jump=bastion",
		"host=;port=2222;user=alice;jump=bastion",
		"host=[];port=2222;user=alice;jump=bastion",
		"host=app.example.com;port=0;user=alice;jump=bastion",
		"host=app.example.com;port=-1;user=alice;jump=bastion",
		"host=app.example.com;port=abc;user=alice;jump=bastion",
		"host=app.example.com;port=70000;user=alice;jump=bastion",
		"host=app.example.com;port=2222;malformed",
		"host=app.example.com;port=2222;",
		"host=app.example.com;host=app.example.com;port=2222;user=alice;jump=bastion",
		"host=app.example.com;port=2222;port=2222;user=alice;jump=bastion",
	}
	for _, bad := range badIdentities {
		if target.MatchesMasterTarget(bad) {
			t.Errorf("MatchesMasterTarget(%q) = true, want false (fail closed)", bad)
		}
	}

	emptyLocal := TargetContext{Port: 2222, User: "alice", JumpHost: "bastion"}
	if emptyLocal.MatchesMasterTarget(validID) {
		t.Fatal("empty local target host must fail closed against non-empty master identity")
	}

	conn := newTestConnector(nil)
	t.Cleanup(func() { _ = conn.CloseAll() })
	legacyMux := &MuxClient{extensions: map[string]string{}}
	if err := conn.verifyMuxMasterTarget(legacyMux, "/tmp/cm.sock", target); err != nil {
		t.Fatalf("legacy master without target@xops extension failed: %v", err)
	}
	emptyExtMux := &MuxClient{extensions: map[string]string{muxTargetExtensionName: ""}}
	if err := conn.verifyMuxMasterTarget(emptyExtMux, "/tmp/cm.sock", target); !errors.Is(err, ErrControlTargetMismatch) {
		t.Fatalf("empty target@xops extension must fail closed with ErrControlTargetMismatch, got %v", err)
	}
}
