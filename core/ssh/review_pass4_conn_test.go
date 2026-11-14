package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestPass4Conn_M1_RelativeHostKeyAlgorithmsPreserveKnownHostsOrdering(t *testing.T) {
	t.Run("dual_key_server_ed25519_pinned_with_plus_ssh_rsa", func(t *testing.T) {
		assertPass4DualKeyPinnedEd25519WithPlusRSA(t)
	})
	t.Run("plain_key_pinned_without_cert_authority_keeps_plain_ahead_of_certs", func(t *testing.T) {
		assertPass4PlainPinnedBeforeCertsUnderRelativeModifiers(t)
	})
	t.Run("cert_authority_in_known_hosts_keeps_certs_first_with_excluded_removed", func(t *testing.T) {
		assertPass4CertAuthorityKeepsCertsFirstUnderRelativeModifiers(t)
	})
	t.Run("custom_verifier_and_explicit_list_never_read_known_hosts", func(t *testing.T) {
		assertPass4CustomVerifierAndExplicitListIsolation(t)
	})
}

func assertPass4DualKeyPinnedEd25519WithPlusRSA(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaSigner, err := cryptoSSH.NewSignerFromKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edSigner, err := cryptoSSH.NewSignerFromKey(edPriv)
	if err != nil {
		t.Fatal(err)
	}

	peer, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		HostKeys: []cryptoSSH.Signer{rsaSigner, edSigner},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })

	host, portStr, err := net.SplitHostPort(peer.Address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	userKH := filepath.Join(dir, "known_hosts")
	khHost := net.JoinHostPort(host, portStr)
	if err := appendKnownHost(userKH, khHost, edSigner.PublicKey(), false); err != nil {
		t.Fatal(err)
	}

	env := fixtureEnvironment()
	env.HomeDir = dir
	env.KnownHostsFile = userKH
	env.GlobalKnownHostsFiles = nil

	cfg := &ClientConfig{
		NodeID:   "dual-key-server",
		Address:  host,
		Port:     port,
		User:     "fixture",
		AuthType: "password",
		Password: sshfixture.Password,
		Options: MustOptions(
			OptionHostKeyAlgorithms, "+ssh-rsa",
			OptionStrictHostKeyChecking, "yes",
			OptionUserKnownHostsFile, userKH,
			OptionGlobalKnownHostsFile, "none",
		),
	}
	provider := &mapConfigProvider{configs: map[string]*ClientConfig{"dual-key-server": cfg}}
	conn := NewConnector(provider, WithEnvironment(env))
	t.Cleanup(func() { _ = conn.CloseAll() })

	algs, err := conn.getHostKeyAlgorithms(ctx, nil, cfg)
	if err != nil {
		t.Fatalf("getHostKeyAlgorithms(+ssh-rsa) failed: %v", err)
	}
	edIdx := slices.Index(algs, cryptoSSH.KeyAlgoED25519)
	rsa256Idx := slices.Index(algs, cryptoSSH.KeyAlgoRSASHA256)
	rsaLegacyIdx := slices.Index(algs, cryptoSSH.KeyAlgoRSA)
	if edIdx != 0 || rsa256Idx <= edIdx || rsaLegacyIdx <= rsa256Idx {
		t.Fatalf("expected ssh-ed25519 ahead of rsa-sha2-256 and ssh-rsa, got %v", algs)
	}

	client, err := conn.Connect(ctx, "dual-key-server")
	if err != nil {
		t.Fatalf("Connect to dual-key server with pinned ed25519 and +ssh-rsa failed: %v", err)
	}
	if _, err := client.Run(ctx, "hostname"); err != nil {
		t.Fatalf("client.Run after dual-key handshake failed: %v", err)
	}
}

func assertPass4PlainPinnedBeforeCertsUnderRelativeModifiers(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	untrustedCA := newPhase3CertFixture(t)
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edSigner, err := cryptoSSH.NewSignerFromKey(edPriv)
	if err != nil {
		t.Fatal(err)
	}
	untrustedCert := signTestCertificate(t, untrustedCA.caSigner, edSigner.PublicKey(), "127.0.0.1", cryptoSSH.HostCert, 9401)
	untrustedCertSigner, err := cryptoSSH.NewCertSigner(untrustedCert, edSigner)
	if err != nil {
		t.Fatal(err)
	}

	peer, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		HostKeys: []cryptoSSH.Signer{untrustedCertSigner, edSigner},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })

	host, portStr, err := net.SplitHostPort(peer.Address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	userKH := filepath.Join(dir, "known_hosts")
	if err := appendKnownHost(userKH, net.JoinHostPort(host, portStr), edSigner.PublicKey(), false); err != nil {
		t.Fatal(err)
	}

	env := fixtureEnvironment()
	env.HomeDir = dir
	env.KnownHostsFile = userKH
	env.GlobalKnownHostsFiles = nil

	for _, spec := range []string{"+ssh-rsa", "-ecdsa-sha2-nistp521", "^rsa-sha2-512"} {
		nodeID := "plain-pinned-" + spec
		cfg := &ClientConfig{
			NodeID:   nodeID,
			Address:  host,
			Port:     port,
			User:     "fixture",
			AuthType: "password",
			Password: sshfixture.Password,
			Options: MustOptions(
				OptionHostKeyAlgorithms, spec,
				OptionStrictHostKeyChecking, "yes",
				OptionUserKnownHostsFile, userKH,
				OptionGlobalKnownHostsFile, "none",
			),
		}
		conn := NewConnector(&mapConfigProvider{configs: map[string]*ClientConfig{nodeID: cfg}}, WithEnvironment(env))
		algs, err := conn.getHostKeyAlgorithms(ctx, nil, cfg)
		if err != nil {
			_ = conn.CloseAll()
			t.Fatalf("getHostKeyAlgorithms(%q) failed: %v", spec, err)
		}
		assertAllPlainBeforeCertAlgorithms(t, spec, algs)
		if spec == "-ecdsa-sha2-nistp521" && slices.Contains(algs, cryptoSSH.KeyAlgoECDSA521) {
			_ = conn.CloseAll()
			t.Fatalf("expected ecdsa-sha2-nistp521 removed for %q, got %v", spec, algs)
		}
		client, err := conn.Connect(ctx, nodeID)
		if err != nil {
			_ = conn.CloseAll()
			t.Fatalf("Connect(%q) with untrusted cert + pinned plain key failed: %v", spec, err)
		}
		if _, err := client.Run(ctx, "hostname"); err != nil {
			_ = conn.CloseAll()
			t.Fatalf("client.Run(%q) failed: %v", spec, err)
		}
		_ = conn.CloseAll()
	}
}

func assertAllPlainBeforeCertAlgorithms(t *testing.T, spec string, algs []string) {
	t.Helper()
	seenCert := false
	for _, alg := range algs {
		isCert := strings.HasSuffix(alg, "-cert-v01@openssh.com")
		if isCert {
			seenCert = true
			continue
		}
		// Appended "+ssh-rsa" comes at the tail of defaults; all base plain algorithms must precede certs.
		if seenCert && alg != cryptoSSH.KeyAlgoRSA {
			t.Fatalf("spec %q placed cert algorithm ahead of base plain algorithm %q: %v", spec, alg, algs)
		}
	}
}

func assertPass4CertAuthorityKeepsCertsFirstUnderRelativeModifiers(t *testing.T) {
	t.Helper()
	fix := newPhase3CertFixture(t)
	dir := t.TempDir()
	userKH := filepath.Join(dir, "known_hosts")
	caLine := "@cert-authority *.corp.example " + strings.TrimSpace(string(cryptoSSH.MarshalAuthorizedKey(fix.caSigner.PublicKey()))) + "\n"
	if err := os.WriteFile(userKH, []byte(caLine), 0o600); err != nil {
		t.Fatal(err)
	}

	env := fixtureEnvironment()
	env.HomeDir = dir
	env.KnownHostsFile = userKH
	env.GlobalKnownHostsFiles = nil

	conn := NewConnector(nil, WithEnvironment(env))
	t.Cleanup(func() { _ = conn.CloseAll() })

	cfg := &ClientConfig{
		NodeID:  "ca-minus-ecdsa",
		Address: "app.corp.example",
		Port:    22,
		User:    "alice",
		Options: MustOptions(
			OptionHostKeyAlgorithms, "-ecdsa-sha2-nistp521",
			OptionUserKnownHostsFile, userKH,
			OptionGlobalKnownHostsFile, "none",
		),
	}
	algs, err := conn.getHostKeyAlgorithms(t.Context(), nil, cfg)
	if err != nil {
		t.Fatalf("getHostKeyAlgorithms(-ecdsa-sha2-nistp521) failed: %v", err)
	}
	if slices.Contains(algs, cryptoSSH.KeyAlgoECDSA521) {
		t.Fatalf("expected ecdsa-sha2-nistp521 excluded, got %v", algs)
	}

	var wantCerts []string
	for _, alg := range cryptoSSH.SupportedAlgorithms().HostKeys {
		if strings.HasSuffix(alg, "-cert-v01@openssh.com") {
			wantCerts = append(wantCerts, alg)
		}
	}
	if len(algs) < len(wantCerts) || !slices.Equal(algs[:len(wantCerts)], wantCerts) {
		t.Fatalf("expected -cert-v01@openssh.com first when @cert-authority matches, got %v (want prefix %v)", algs, wantCerts)
	}
}

func assertPass4CustomVerifierAndExplicitListIsolation(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	userKH := filepath.Join(dir, "known_hosts")
	fix := newPhase3CertFixture(t)
	caLine := "@cert-authority *.corp.example " + strings.TrimSpace(string(cryptoSSH.MarshalAuthorizedKey(fix.caSigner.PublicKey()))) + "\n"
	if err := os.WriteFile(userKH, []byte(caLine), 0o600); err != nil {
		t.Fatal(err)
	}

	env := fixtureEnvironment()
	env.HomeDir = dir
	env.KnownHostsFile = userKH

	verifier := stubAlgorithmVerifier{
		algs: []string{cryptoSSH.KeyAlgoED25519, cryptoSSH.KeyAlgoECDSA256},
	}
	connVerifier := NewConnector(nil, WithEnvironment(env), WithHostKeyVerifier(verifier))
	t.Cleanup(func() { _ = connVerifier.CloseAll() })

	// Relative "+ssh-rsa" with HostKeyAlgorithmSource preserves source order, never widens trust,
	// and cleans bracketed IPv6 Host in HostKeyRequest.
	var capturedAlgHost, capturedVerifyHost string
	capturingVerifier := algorithmSourceWithHostCapture{
		algs:        []string{cryptoSSH.KeyAlgoED25519, cryptoSSH.KeyAlgoECDSA256},
		onAlgReq:    func(req HostKeyRequest) { capturedAlgHost = req.Host },
		onVerifyReq: func(req HostKeyRequest) { capturedVerifyHost = req.Host },
	}
	connCapturing := NewConnector(nil, WithEnvironment(env), WithHostKeyVerifier(capturingVerifier))
	t.Cleanup(func() { _ = connCapturing.CloseAll() })

	cfgPlus := &ClientConfig{
		Address: "[2001:db8::1]",
		Port:    22,
		Options: MustOptions(OptionHostKeyAlgorithms, "+ssh-rsa"),
	}
	gotPlus, err := connCapturing.getHostKeyAlgorithms(t.Context(), nil, cfgPlus)
	if err != nil {
		t.Fatalf("getHostKeyAlgorithms(verifier +ssh-rsa) failed: %v", err)
	}
	wantSource := []string{cryptoSSH.KeyAlgoED25519, cryptoSSH.KeyAlgoECDSA256}
	if !slices.Equal(gotPlus, wantSource) {
		t.Fatalf("verifier +ssh-rsa = %v, want %v", gotPlus, wantSource)
	}
	cbVerify, err := connCapturing.getHostKeyCallbackWithState(t.Context(), nil, cfgPlus, nil, nil)
	if err != nil {
		t.Fatalf("getHostKeyCallbackWithState(verifier) failed: %v", err)
	}
	_ = cbVerify("[2001:db8::1]:22", &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 22}, fix.hostSigner.PublicKey())
	if capturedAlgHost != "2001:db8::1" || capturedVerifyHost != "2001:db8::1" {
		t.Fatalf("HostKeyRequest.Host = alg:%q verify:%q, want 2001:db8::1", capturedAlgHost, capturedVerifyHost)
	}

	// Relative "-ecdsa-sha2-nistp256" narrows verifier source cleanly.
	cfgMinus := &ClientConfig{
		Address: "app.corp.example",
		Port:    22,
		Options: MustOptions(OptionHostKeyAlgorithms, "-ecdsa-sha2-nistp256"),
	}
	gotMinus, err := connVerifier.getHostKeyAlgorithms(t.Context(), nil, cfgMinus)
	if err != nil || !slices.Equal(gotMinus, []string{cryptoSSH.KeyAlgoED25519}) {
		t.Fatalf("verifier -ecdsa-sha2-nistp256 = %v, %v; want [ssh-ed25519]", gotMinus, err)
	}

	// Explicit replacement list without verifier resolves directly without adding cert algorithms.
	connKH := NewConnector(nil, WithEnvironment(env))
	t.Cleanup(func() { _ = connKH.CloseAll() })
	cfgExplicit := &ClientConfig{
		Address: "app.corp.example",
		Port:    22,
		Options: MustOptions(OptionHostKeyAlgorithms, "ssh-ed25519,rsa-sha2-512"),
	}
	gotExplicit, err := connKH.getHostKeyAlgorithms(t.Context(), nil, cfgExplicit)
	if err != nil || !slices.Equal(gotExplicit, []string{cryptoSSH.KeyAlgoED25519, cryptoSSH.KeyAlgoRSASHA512}) {
		t.Fatalf("explicit HostKeyAlgorithms = %v, %v; want [ssh-ed25519 rsa-sha2-512]", gotExplicit, err)
	}
}

type algorithmSourceWithHostCapture struct {
	algs        []string
	onAlgReq    func(HostKeyRequest)
	onVerifyReq func(HostKeyRequest)
}

func (a algorithmSourceWithHostCapture) HostKeyAlgorithms(_ context.Context, req HostKeyRequest) ([]string, error) {
	if a.onAlgReq != nil {
		a.onAlgReq(req)
	}
	return a.algs, nil
}

func (a algorithmSourceWithHostCapture) Verify(_ context.Context, req HostKeyRequest, _ cryptoSSH.PublicKey) error {
	if a.onVerifyReq != nil {
		a.onVerifyReq(req)
	}
	return nil
}

type dialCountingRedirectDialer struct {
	targetAddr string
	dials      atomic.Int32
}

func (d *dialCountingRedirectDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *dialCountingRedirectDialer) DialContext(ctx context.Context, _ string, _ string) (net.Conn, error) {
	d.dials.Add(1)
	var nd net.Dialer
	return nd.DialContext(ctx, "tcp", d.targetAddr)
}

func TestPass4Conn_L1_CleanHostLiteralUnifiedAcrossPlanTokensAndMux(t *testing.T) {
	t.Run("connection_key_connect_plan_and_retire_plan_ipv6_parity", func(t *testing.T) {
		assertPass4PlanIPv6BracketParityAndRetirement(t)
	})
	t.Run("token_expansion_and_mux_target_identity_ipv6_parity", func(t *testing.T) {
		assertPass4TokenExpansionAndMuxTargetParity(t)
	})
	t.Run("unbalanced_brackets_not_silently_stripped", func(t *testing.T) {
		assertPass4UnbalancedBracketsPreserved(t)
	})
}

func assertPass4PlanIPv6BracketParityAndRetirement(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	peer, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })

	planBracketed := ConnectionPlan{
		Scope: "pass4-ipv6",
		Hops: []ConnectionConfig{{
			NodeID:          "ipv6-node",
			Address:         "[2001:db8::1]",
			Port:            2222,
			User:            "fixture",
			AuthType:        "password",
			AuthUpdateToken: "v1",
			TrustVersion:    "t1",
		}},
	}
	planBare := ConnectionPlan{
		Scope: "pass4-ipv6",
		Hops: []ConnectionConfig{{
			NodeID:          "ipv6-node",
			Address:         "2001:db8::1",
			Port:            2222,
			User:            "fixture",
			AuthType:        "password",
			AuthUpdateToken: "v1",
			TrustVersion:    "t1",
		}},
	}

	keyBracketed, err := ConnectionKey(planBracketed)
	if err != nil {
		t.Fatalf("ConnectionKey(bracketed) failed: %v", err)
	}
	keyBare, err := ConnectionKey(planBare)
	if err != nil {
		t.Fatalf("ConnectionKey(bare) failed: %v", err)
	}
	if keyBracketed != keyBare {
		t.Fatalf("ConnectionKey mismatch: bracketed=%s vs bare=%s", keyBracketed, keyBare)
	}

	// Zone-ID IPv6 literal parity in ConnectionKey as well.
	zoneBracketed := planBracketed
	zoneBracketed.Hops = slices.Clone(planBracketed.Hops)
	zoneBracketed.Hops[0].Address = "[fe80::1%eth0]"
	zoneBare := planBare
	zoneBare.Hops = slices.Clone(planBare.Hops)
	zoneBare.Hops[0].Address = "fe80::1%eth0"
	kZone1, err1 := ConnectionKey(zoneBracketed)
	kZone2, err2 := ConnectionKey(zoneBare)
	if err1 != nil || err2 != nil || kZone1 != kZone2 {
		t.Fatalf("Zone IPv6 ConnectionKey mismatch: %q (%v) vs %q (%v)", kZone1, err1, kZone2, err2)
	}

	// Empty "[]" address must fail closed in normalizePlan.
	emptyBrackets := planBare
	emptyBrackets.Hops = slices.Clone(planBare.Hops)
	emptyBrackets.Hops[0].Address = "[]"
	if _, err := ConnectionKey(emptyBrackets); err == nil {
		t.Fatal("expected ConnectionKey with Address=\"[]\" to fail closed")
	}

	dialer := &dialCountingRedirectDialer{targetAddr: peer.Address}
	verifier := &pinnedAlgorithmVerifier{key: peer.HostKey}
	// Bind verifier NodeID/User/TrustVersion to match pinnedAlgorithmVerifier expectations.
	planBracketed.Hops[0].NodeID = "pinned"
	planBracketed.Hops[0].TrustVersion = "trust-v1"
	planBare.Hops[0].NodeID = "pinned"
	planBare.Hops[0].TrustVersion = "trust-v1"

	conn := NewConnector(
		nil,
		WithDialer(dialer),
		WithSecretResolver(fixturePassword{}),
		WithHostKeyVerifier(verifier),
	)
	t.Cleanup(func() { _ = conn.CloseAll() })

	lease1, err := conn.ConnectPlan(ctx, planBracketed)
	if err != nil {
		t.Fatalf("ConnectPlan(bracketed) failed: %v", err)
	}
	if gotAddr := lease1.Client.ConnectionConfig().Address; gotAddr != "2001:db8::1" {
		_ = lease1.Close()
		t.Fatalf("connected client Address = %q, want %q", gotAddr, "2001:db8::1")
	}

	// Connecting with bare "2001:db8::1" reuses the cached transport (dials == 1).
	lease2, err := conn.ConnectPlan(ctx, planBare)
	if err != nil {
		_ = lease1.Close()
		t.Fatalf("ConnectPlan(bare) failed: %v", err)
	}
	if dialer.dials.Load() != 1 {
		_ = lease2.Close()
		_ = lease1.Close()
		t.Fatalf("expected cached transport reuse across [2001:db8::1] and 2001:db8::1, got %d dials", dialer.dials.Load())
	}
	_ = lease2.Close()
	_ = lease1.Close()

	// Retiring via bare "2001:db8::1" must retire the plan originally cached via "[2001:db8::1]".
	if err := conn.RetirePlan(planBare); err != nil {
		t.Fatalf("RetirePlan(bare) failed: %v", err)
	}
	lease3, err := conn.ConnectPlan(ctx, planBracketed)
	if err != nil {
		t.Fatalf("ConnectPlan after RetirePlan failed: %v", err)
	}
	_ = lease3.Close()
	if dialer.dials.Load() != 2 {
		t.Fatalf("expected RetirePlan(bare) to evict cached [2001:db8::1] transport and force redial, got %d dials", dialer.dials.Load())
	}
}

func assertPass4TokenExpansionAndMuxTargetParity(t *testing.T) {
	t.Helper()
	env := Environment{
		HomeDir:   "/home/alice",
		LocalUser: "alice",
		LocalHost: "workstation.corp.example",
		LocalUID:  "1000",
	}

	for _, pair := range [][2]string{
		{"[2001:db8::1]", "2001:db8::1"},
		{"[fe80::1%eth0]", "fe80::1%eth0"},
	} {
		assertPass4SingleIPv6PairParity(t, env, pair[0], pair[1])
	}

	// Verify Connector target helpers (authTargetContext, knownHostsTarget, buildTargetContext).
	conn := NewConnector(nil, WithEnvironment(env))
	t.Cleanup(func() { _ = conn.CloseAll() })
	cfg := &ClientConfig{
		NodeID:  "v6-node",
		Address: " [2001:db8::1] ",
		Port:    2222,
		User:    "alice",
	}
	if got := conn.authTargetContext(cfg).Host; got != "2001:db8::1" {
		t.Fatalf("authTargetContext.Host = %q, want 2001:db8::1", got)
	}
	if got := knownHostsTarget(cfg).Host; got != "2001:db8::1" {
		t.Fatalf("knownHostsTarget.Host = %q, want 2001:db8::1", got)
	}
	if got := conn.buildTargetContext(connectionPlanNode{name: "v6-node", cfg: cfg}).Host; got != "2001:db8::1" {
		t.Fatalf("buildTargetContext.Host = %q, want 2001:db8::1", got)
	}
}

func assertPass4SingleIPv6PairParity(t *testing.T, env Environment, bracketed, bare string) {
	t.Helper()
	tBracket := TargetContext{Host: bracketed, Port: 2222, User: "alice"}
	tBare := TargetContext{Host: bare, Port: 2222, User: "alice"}

	cpBracket, err := ExpandControlPath("%h %n %C", env, tBracket)
	if err != nil {
		t.Fatalf("ExpandControlPath(%q) failed: %v", bracketed, err)
	}
	cpBare, err := ExpandControlPath("%h %n %C", env, tBare)
	if err != nil {
		t.Fatalf("ExpandControlPath(%q) failed: %v", bare, err)
	}
	rcBracket, err := ExpandRemoteCommand("%h %n %C", env, tBracket)
	if err != nil {
		t.Fatalf("ExpandRemoteCommand(%q) failed: %v", bracketed, err)
	}
	rcBare, err := ExpandRemoteCommand("%h %n %C", env, tBare)
	if err != nil {
		t.Fatalf("ExpandRemoteCommand(%q) failed: %v", bare, err)
	}
	lcBracket, err := ExpandLocalCommand("%h %n %C", env, tBracket)
	if err != nil {
		t.Fatalf("ExpandLocalCommand(%q) failed: %v", bracketed, err)
	}
	lcBare, err := ExpandLocalCommand("%h %n %C", env, tBare)
	if err != nil {
		t.Fatalf("ExpandLocalCommand(%q) failed: %v", bare, err)
	}

	if cpBracket != cpBare || cpBracket != rcBracket || rcBracket != rcBare || lcBracket != lcBare || cpBracket != lcBare {
		t.Fatalf("token expansion mismatch for [%s, %s]:\n  ControlPath: %q vs %q\n  RemoteCmd:   %q vs %q\n  LocalCmd:    %q vs %q",
			bracketed, bare, cpBracket, cpBare, rcBracket, rcBare, lcBracket, lcBare)
	}
	if strings.ContainsAny(cpBracket, "[]") {
		t.Fatalf("expanded tokens still contain brackets: %q", cpBracket)
	}

	idBracket := tBracket.CanonicalTargetIdentity()
	idBare := tBare.CanonicalTargetIdentity()
	if idBracket != idBare || strings.ContainsAny(idBracket, "[]") {
		t.Fatalf("CanonicalTargetIdentity mismatch: %q vs %q", idBracket, idBare)
	}
	if !tBracket.MatchesMasterTarget(idBare) || !tBare.MatchesMasterTarget(idBracket) {
		t.Fatalf("MatchesMasterTarget failed across %q and %q", idBracket, idBare)
	}
	legacyMasterID := "host=" + bracketed + ";port=2222;user=alice;jump="
	if !tBare.MatchesMasterTarget(legacyMasterID) {
		t.Fatalf("MatchesMasterTarget rejected legacy bracketed master identity %q", legacyMasterID)
	}
}

func assertPass4UnbalancedBracketsPreserved(t *testing.T) {
	t.Helper()
	cases := []struct {
		in   string
		want string
	}{
		{"[bad", "[bad"},
		{"bad]", "bad]"},
		{" [bad ", "[bad"},
		{" bad] ", "bad]"},
		{"[", "["},
		{"]", "]"},
		{"[2001:db8::1]", "2001:db8::1"},
	}
	for _, tc := range cases {
		if got := normalizeHostAddress(tc.in); got != tc.want {
			t.Fatalf("normalizeHostAddress(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if got := cleanHostLiteral(tc.in); got != tc.want {
			t.Fatalf("cleanHostLiteral(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	env := Environment{
		HomeDir:   "/home/alice",
		LocalUser: "alice",
		LocalHost: "workstation",
		LocalUID:  "1000",
	}
	for _, bad := range []string{"[bad", "bad]", "[127.0.0.1]", "[[2001:db8::1]]"} {
		if _, err := ExpandProxyCommand("nc %h %p", env, TargetContext{Host: bad, Port: 22, User: "alice"}); !errors.Is(err, ErrUnsafeExecToken) {
			t.Fatalf("ExpandProxyCommand(%q) = %v, want ErrUnsafeExecToken", bad, err)
		}
		if _, err := ExpandLocalCommand("echo %h", env, TargetContext{Host: bad, Port: 22, User: "alice"}); !errors.Is(err, ErrUnsafeExecToken) {
			t.Fatalf("ExpandLocalCommand(%q) = %v, want ErrUnsafeExecToken", bad, err)
		}
	}
}
