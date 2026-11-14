package ssh

import (
	"context"
	"crypto/dsa" //nolint:staticcheck // regression test for opt-in legacy ssh-dss compatibility
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
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

func TestPass5Conn_H1_RelativeHostKeyAlgorithmsKnownHostsOrdering(t *testing.T) {
	t.Run("pinned_ssh_rsa_on_multi_key_legacy_server_succeeds_with_plus_ssh_rsa", func(t *testing.T) {
		assertPass5PinnedLegacyRSAWithPlusRSA(t)
	})
	t.Run("pinned_ssh_dss_on_multi_key_legacy_server_succeeds_with_plus_ssh_dss", func(t *testing.T) {
		assertPass5PinnedLegacyDSSWithPlusDSS(t)
	})
	t.Run("untrusted_cert_plus_plain_ssh_rsa_without_ca_succeeds_with_plus_ssh_rsa", func(t *testing.T) {
		assertPass5UntrustedCertPlusLegacyRSAWithoutCA(t)
	})
	t.Run("cert_authority_match_with_plus_legacy_cert_keeps_cert_in_cert_block", func(t *testing.T) {
		assertPass5CertAuthorityWithPlusLegacyCert(t)
	})
	t.Run("caret_head_override_stays_at_index_zero_with_known_hosts_order_behind", func(t *testing.T) {
		assertPass5CaretHeadOverridePreservesKnownHostsTail(t)
	})
}

func newLegacyOnlyRSASigner(t *testing.T) cryptoSSH.Signer {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rawSigner, err := cryptoSSH.NewSignerFromKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	algoSigner, ok := rawSigner.(cryptoSSH.AlgorithmSigner)
	if !ok {
		t.Fatalf("RSA signer %T does not implement AlgorithmSigner", rawSigner)
	}
	legacySigner, err := cryptoSSH.NewSignerWithAlgorithms(algoSigner, []string{cryptoSSH.KeyAlgoRSA})
	if err != nil {
		t.Fatal(err)
	}
	return legacySigner
}

func newLegacyDSSSigner(t *testing.T) cryptoSSH.Signer {
	t.Helper()
	var params dsa.Parameters
	if err := dsa.GenerateParameters(&params, rand.Reader, dsa.L1024N160); err != nil {
		t.Fatal(err)
	}
	priv := &dsa.PrivateKey{PublicKey: dsa.PublicKey{Parameters: params}}
	if err := dsa.GenerateKey(priv, rand.Reader); err != nil {
		t.Fatal(err)
	}
	signer, err := cryptoSSH.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func newECDSAP256Signer(t *testing.T) cryptoSSH.Signer {
	t.Helper()
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptoSSH.NewSignerFromKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func assertPass5PinnedLegacyRSAWithPlusRSA(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	unpinnedECDSA := newECDSAP256Signer(t)
	pinnedLegacyRSA := newLegacyOnlyRSASigner(t)

	peer, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		HostKeys: []cryptoSSH.Signer{unpinnedECDSA, pinnedLegacyRSA},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })

	host, portStr, port := splitFixtureHostPort(t, peer.Address)
	dir := t.TempDir()
	userKH := filepath.Join(dir, "known_hosts")
	if err := appendKnownHost(userKH, net.JoinHostPort(host, portStr), pinnedLegacyRSA.PublicKey(), false); err != nil {
		t.Fatal(err)
	}

	env := isolatedPass5Env(dir, userKH)

	// Without +ssh-rsa, SHA-1 ssh-rsa must remain strictly disabled even when pinned in known_hosts.
	defaultCfg := &ClientConfig{
		NodeID:   "legacy-rsa-default",
		Address:  host,
		Port:     port,
		User:     "fixture",
		AuthType: "password",
		Password: sshfixture.Password,
		Options: MustOptions(
			OptionStrictHostKeyChecking, "yes",
			OptionUserKnownHostsFile, userKH,
			OptionGlobalKnownHostsFile, "none",
		),
	}
	connDefault := NewConnector(&mapConfigProvider{configs: map[string]*ClientConfig{"legacy-rsa-default": defaultCfg}}, WithEnvironment(env))
	t.Cleanup(func() { _ = connDefault.CloseAll() })
	defaultAlgs, err := connDefault.getHostKeyAlgorithms(ctx, nil, defaultCfg)
	if err != nil {
		t.Fatalf("getHostKeyAlgorithms(default) failed: %v", err)
	}
	if slices.Contains(defaultAlgs, cryptoSSH.KeyAlgoRSA) {
		t.Fatalf("expected ssh-rsa disabled by default, got %v", defaultAlgs)
	}

	// With +ssh-rsa, pinned ssh-rsa must be promoted right behind rsa-sha2-512/256 and ahead of unpinned ecdsa.
	plusCfg := &ClientConfig{
		NodeID:   "legacy-rsa-plus",
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
	connPlus := NewConnector(&mapConfigProvider{configs: map[string]*ClientConfig{"legacy-rsa-plus": plusCfg}}, WithEnvironment(env))
	t.Cleanup(func() { _ = connPlus.CloseAll() })

	algs, err := connPlus.getHostKeyAlgorithms(ctx, nil, plusCfg)
	if err != nil {
		t.Fatalf("getHostKeyAlgorithms(+ssh-rsa) failed: %v", err)
	}
	wantPrefix := []string{cryptoSSH.KeyAlgoRSASHA512, cryptoSSH.KeyAlgoRSASHA256, cryptoSSH.KeyAlgoRSA}
	if len(algs) < 3 || !slices.Equal(algs[:3], wantPrefix) {
		t.Fatalf("expected prefix %v for pinned ssh-rsa + +ssh-rsa, got %v", wantPrefix, algs)
	}
	assertAllPlainBeforeCertAlgorithms(t, "+ssh-rsa", algs)

	client, err := connPlus.Connect(ctx, "legacy-rsa-plus")
	if err != nil {
		t.Fatalf("Connect with pinned ssh-rsa and +ssh-rsa failed: %v", err)
	}
	if _, err := client.Run(ctx, "hostname"); err != nil {
		t.Fatalf("client.Run failed: %v", err)
	}
}

func assertPass5PinnedLegacyDSSWithPlusDSS(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	unpinnedECDSA := newECDSAP256Signer(t)
	pinnedDSS := newLegacyDSSSigner(t)

	peer, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		HostKeys: []cryptoSSH.Signer{unpinnedECDSA, pinnedDSS},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })

	host, portStr, port := splitFixtureHostPort(t, peer.Address)
	dir := t.TempDir()
	userKH := filepath.Join(dir, "known_hosts")
	if err := appendKnownHost(userKH, net.JoinHostPort(host, portStr), pinnedDSS.PublicKey(), false); err != nil {
		t.Fatal(err)
	}

	env := isolatedPass5Env(dir, userKH)
	cfg := &ClientConfig{
		NodeID:   "legacy-dss-plus",
		Address:  host,
		Port:     port,
		User:     "fixture",
		AuthType: "password",
		Password: sshfixture.Password,
		Options: MustOptions(
			OptionHostKeyAlgorithms, "+ssh-dss",
			OptionStrictHostKeyChecking, "yes",
			OptionUserKnownHostsFile, userKH,
			OptionGlobalKnownHostsFile, "none",
		),
	}
	conn := NewConnector(&mapConfigProvider{configs: map[string]*ClientConfig{"legacy-dss-plus": cfg}}, WithEnvironment(env))
	t.Cleanup(func() { _ = conn.CloseAll() })

	algs, err := conn.getHostKeyAlgorithms(ctx, nil, cfg)
	if err != nil {
		t.Fatalf("getHostKeyAlgorithms(+ssh-dss) failed: %v", err)
	}
	if len(algs) == 0 || algs[0] != "ssh-dss" {
		t.Fatalf("expected pinned ssh-dss at index 0 with +ssh-dss, got %v", algs)
	}
	assertAllPlainBeforeCertAlgorithms(t, "+ssh-dss", algs)

	client, err := conn.Connect(ctx, "legacy-dss-plus")
	if err != nil {
		t.Fatalf("Connect with pinned ssh-dss and +ssh-dss failed: %v", err)
	}
	if _, err := client.Run(ctx, "hostname"); err != nil {
		t.Fatalf("client.Run failed: %v", err)
	}
}

func assertPass5UntrustedCertPlusLegacyRSAWithoutCA(t *testing.T) {
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
	untrustedCert := signTestCertificate(t, untrustedCA.caSigner, edSigner.PublicKey(), "127.0.0.1", cryptoSSH.HostCert, 9501)
	untrustedCertSigner, err := cryptoSSH.NewCertSigner(untrustedCert, edSigner)
	if err != nil {
		t.Fatal(err)
	}
	plainLegacyRSA := newLegacyOnlyRSASigner(t)

	// Server offers untrusted ed25519 certificate + plain legacy ssh-rsa (without RFC 8332).
	peer, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		HostKeys: []cryptoSSH.Signer{untrustedCertSigner, plainLegacyRSA},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })

	host, _, port := splitFixtureHostPort(t, peer.Address)
	dir := t.TempDir()
	userKH := filepath.Join(dir, "known_hosts")
	// Only an unrelated domain has @cert-authority; target host has NO @cert-authority match.
	otherCALine := "@cert-authority *.other.invalid " + strings.TrimSpace(string(cryptoSSH.MarshalAuthorizedKey(untrustedCA.caSigner.PublicKey()))) + "\n"
	if err := os.WriteFile(userKH, []byte(otherCALine), 0o600); err != nil {
		t.Fatal(err)
	}

	env := isolatedPass5Env(dir, userKH)
	cfg := &ClientConfig{
		NodeID:   "untrusted-cert-legacy-rsa",
		Address:  host,
		Port:     port,
		User:     "fixture",
		AuthType: "password",
		Password: sshfixture.Password,
		Options: MustOptions(
			OptionHostKeyAlgorithms, "+ssh-rsa",
			OptionStrictHostKeyChecking, "accept-new",
			OptionUserKnownHostsFile, userKH,
			OptionGlobalKnownHostsFile, "none",
		),
	}
	conn := NewConnector(&mapConfigProvider{configs: map[string]*ClientConfig{"untrusted-cert-legacy-rsa": cfg}}, WithEnvironment(env))
	t.Cleanup(func() { _ = conn.CloseAll() })

	algs, err := conn.getHostKeyAlgorithms(ctx, nil, cfg)
	if err != nil {
		t.Fatalf("getHostKeyAlgorithms(+ssh-rsa) failed: %v", err)
	}
	assertAllPlainBeforeCertAlgorithms(t, "+ssh-rsa", algs)

	client, err := conn.Connect(ctx, "untrusted-cert-legacy-rsa")
	if err != nil {
		t.Fatalf("Connect with untrusted cert + plain ssh-rsa (+ssh-rsa, accept-new) failed: %v", err)
	}
	if _, err := client.Run(ctx, "hostname"); err != nil {
		t.Fatalf("client.Run failed: %v", err)
	}
}

type nonAlgoSigner struct {
	signer cryptoSSH.Signer
}

func (s nonAlgoSigner) PublicKey() cryptoSSH.PublicKey {
	return s.signer.PublicKey()
}

func (s nonAlgoSigner) Sign(rand io.Reader, data []byte) (*cryptoSSH.Signature, error) {
	return s.signer.Sign(rand, data)
}

func assertPass5CertAuthorityWithPlusLegacyCert(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	caFix := newPhase3CertFixture(t)
	legacyRSASigner := newLegacyOnlyRSASigner(t)
	rsaHostCert := signTestCertificate(t, caFix.caSigner, legacyRSASigner.PublicKey(), "127.0.0.1", cryptoSSH.HostCert, 9502)
	// Wrapping in nonAlgoSigner makes NewCertSigner advertise only ssh-rsa-cert-v01@openssh.com
	// (without rsa-sha2-256-cert-v01@openssh.com or rsa-sha2-512-cert-v01@openssh.com).
	legacyCertOnlySigner, err := cryptoSSH.NewCertSigner(rsaHostCert, nonAlgoSigner{signer: legacyRSASigner})
	if err != nil {
		t.Fatal(err)
	}
	unpinnedECDSA := newECDSAP256Signer(t)

	peer, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		HostKeys: []cryptoSSH.Signer{unpinnedECDSA, legacyCertOnlySigner},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })

	host, portStr, port := splitFixtureHostPort(t, peer.Address)
	dir := t.TempDir()
	userKH := filepath.Join(dir, "known_hosts")
	caLine := "@cert-authority " + net.JoinHostPort(host, portStr) + " " + strings.TrimSpace(string(cryptoSSH.MarshalAuthorizedKey(caFix.caSigner.PublicKey()))) + "\n"
	if err := os.WriteFile(userKH, []byte(caLine), 0o600); err != nil {
		t.Fatal(err)
	}

	env := isolatedPass5Env(dir, userKH)
	cfg := &ClientConfig{
		NodeID:   "ca-legacy-rsa-cert",
		Address:  host,
		Port:     port,
		User:     "fixture",
		AuthType: "password",
		Password: sshfixture.Password,
		Options: MustOptions(
			OptionHostKeyAlgorithms, "+ssh-rsa-cert-v01@openssh.com",
			OptionStrictHostKeyChecking, "yes",
			OptionUserKnownHostsFile, userKH,
			OptionGlobalKnownHostsFile, "none",
		),
	}
	conn := NewConnector(&mapConfigProvider{configs: map[string]*ClientConfig{"ca-legacy-rsa-cert": cfg}}, WithEnvironment(env))
	t.Cleanup(func() { _ = conn.CloseAll() })

	algs, err := conn.getHostKeyAlgorithms(ctx, nil, cfg)
	if err != nil {
		t.Fatalf("getHostKeyAlgorithms(+ssh-rsa-cert-v01@openssh.com) failed: %v", err)
	}
	seenPlain := false
	for _, alg := range algs {
		if strings.HasSuffix(alg, "-cert-v01@openssh.com") {
			if seenPlain {
				t.Fatalf("expected %q inside leading cert block before plain algorithms: %v", alg, algs)
			}
			continue
		}
		seenPlain = true
	}
	if !slices.Contains(algs, cryptoSSH.CertAlgoRSAv01) {
		t.Fatalf("expected %q in %v", cryptoSSH.CertAlgoRSAv01, algs)
	}

	client, err := conn.Connect(ctx, "ca-legacy-rsa-cert")
	if err != nil {
		t.Fatalf("Connect with @cert-authority and +ssh-rsa-cert-v01@openssh.com failed: %v", err)
	}
	if _, err := client.Run(ctx, "hostname"); err != nil {
		t.Fatalf("client.Run failed: %v", err)
	}
}

func assertPass5CaretHeadOverridePreservesKnownHostsTail(t *testing.T) {
	t.Helper()
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edSigner, err := cryptoSSH.NewSignerFromKey(edPriv)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	userKH := filepath.Join(dir, "known_hosts")
	if err := appendKnownHost(userKH, "[127.0.0.1]:2222", edSigner.PublicKey(), false); err != nil {
		t.Fatal(err)
	}
	env := isolatedPass5Env(dir, userKH)
	conn := NewConnector(nil, WithEnvironment(env))
	t.Cleanup(func() { _ = conn.CloseAll() })

	for _, headAlg := range []string{cryptoSSH.KeyAlgoECDSA384, cryptoSSH.KeyAlgoRSA} {
		spec := "^" + headAlg
		cfg := &ClientConfig{
			NodeID:  "caret-" + headAlg,
			Address: "127.0.0.1",
			Port:    2222,
			User:    "alice",
			Options: MustOptions(
				OptionHostKeyAlgorithms, spec,
				OptionUserKnownHostsFile, userKH,
				OptionGlobalKnownHostsFile, "none",
			),
		}
		algs, err := conn.getHostKeyAlgorithms(t.Context(), nil, cfg)
		if err != nil {
			t.Fatalf("getHostKeyAlgorithms(%q) failed: %v", spec, err)
		}
		if len(algs) < 2 || algs[0] != headAlg || algs[1] != cryptoSSH.KeyAlgoED25519 {
			t.Fatalf("expected [%s, ssh-ed25519, ...] for %q, got %v", headAlg, spec, algs)
		}
		assertAllPlainBeforeCertAlgorithms(t, spec, algs)
	}
}

func TestPass5Conn_H2_CleanHostLiteralIdempotencyAndFailClosed(t *testing.T) {
	t.Run("clean_host_literal_strictly_idempotent_across_inputs", func(t *testing.T) {
		assertPass5CleanHostLiteralIdempotency(t)
	})
	t.Run("connect_with_nested_brackets_and_proxy_command_fails_closed", func(t *testing.T) {
		assertPass5ConnectNestedBracketsProxyCommandFailsClosed(t)
	})
	t.Run("connect_with_nested_brackets_and_local_command_fails_closed", func(t *testing.T) {
		assertPass5ConnectNestedBracketsLocalCommandFailsClosed(t)
	})
	t.Run("connect_plan_and_connection_key_do_not_peel_nested_brackets", func(t *testing.T) {
		assertPass5ConnectPlanNestedBracketsConsistency(t)
	})
}

func assertPass5CleanHostLiteralIdempotency(t *testing.T) {
	t.Helper()
	cases := []struct {
		in   string
		want string
	}{
		{"[[2001:db8::1]]", "[[2001:db8::1]]"},
		{"[2001:db8::1],[2001:db8::2]", "[2001:db8::1],[2001:db8::2]"},
		{"[]", "[]"},
		{" [ ] ", "[ ]"},
		{"[ 2001:db8::1 ]", "[ 2001:db8::1 ]"},
		{"[bad]]", "[bad]]"},
		{"[[bad]", "[[bad]"},
		{"[2001:db8::1]", "2001:db8::1"},
		{" [fe80::1%eth0] ", "fe80::1%eth0"},
	}
	for _, tc := range cases {
		once := cleanHostLiteral(tc.in)
		twice := cleanHostLiteral(once)
		thrice := normalizeHostAddress(twice)
		if once != tc.want || twice != tc.want || thrice != tc.want {
			t.Fatalf("cleanHostLiteral(%q) pipeline = (%q, %q, %q), want idempotent %q", tc.in, once, twice, thrice, tc.want)
		}
	}

	// Literal "[]" must NOT collapse to "" and match arbitrary ControlMaster targets.
	emptyBracketTarget := TargetContext{Host: "[]", Port: 22, User: "guest"}
	if emptyBracketTarget.MatchesMasterTarget("host=prod.corp;port=22;user=root;jump=") {
		t.Fatal("TargetContext{Host: \"[]\"} unexpectedly matched active ControlMaster target")
	}
}

func assertPass5ConnectNestedBracketsProxyCommandFailsClosed(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	dir := t.TempDir()
	userKH := filepath.Join(dir, "known_hosts")
	var proxySpawns atomic.Int32
	env := isolatedPass5Env(dir, userKH)
	env.DialProxyCommand = func(_ context.Context, cmd string) (net.Conn, error) {
		proxySpawns.Add(1)
		return nil, errors.New("unexpected ProxyCommand execution: " + cmd)
	}

	for _, proxyCmd := range []string{"nc %h %p", "nc 127.0.0.1 22"} {
		nodeID := "nested-proxy-" + proxyCmd
		cfg := &ClientConfig{
			NodeID:   nodeID,
			Address:  "[[2001:db8::1]]",
			Port:     2222,
			User:     "alice",
			AuthType: "password",
			Password: "secret",
			Options: MustOptions(
				OptionProxyCommand, proxyCmd,
				OptionStrictHostKeyChecking, "no",
				OptionUserKnownHostsFile, "none",
				OptionGlobalKnownHostsFile, "none",
			),
		}
		conn := NewConnector(&mapConfigProvider{configs: map[string]*ClientConfig{nodeID: cfg}}, WithEnvironment(env))
		_, err := conn.Connect(ctx, nodeID)
		_ = conn.CloseAll()
		if !errors.Is(err, ErrUnsafeExecToken) {
			t.Fatalf("Connect(Address=[[2001:db8::1]], ProxyCommand=%q) = %v, want ErrUnsafeExecToken", proxyCmd, err)
		}
		if proxySpawns.Load() != 0 {
			t.Fatalf("ProxyCommand %q spawned %d times on unsafe nested-bracket host", proxyCmd, proxySpawns.Load())
		}
	}
}

func assertPass5ConnectNestedBracketsLocalCommandFailsClosed(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	peer, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })

	dir := t.TempDir()
	userKH := filepath.Join(dir, "known_hosts")
	var localSpawns atomic.Int32
	env := isolatedPass5Env(dir, userKH)
	env.RunLocalCommand = func(_ context.Context, cmd string) error {
		localSpawns.Add(1)
		return errors.New("unexpected LocalCommand execution: " + cmd)
	}

	dialer := &dialCountingRedirectDialer{targetAddr: peer.Address}
	verifier := stubHostKeyVerifier{acceptKey: peer.HostKey}

	for _, localCmd := range []string{"echo %h", "echo connected"} {
		nodeID := "nested-local-" + localCmd
		cfg := &ClientConfig{
			NodeID:   nodeID,
			Address:  "[[2001:db8::1]]",
			Port:     2222,
			User:     "fixture",
			AuthType: "password",
			Password: sshfixture.Password,
			Options: MustOptions(
				OptionPermitLocalCommand, "yes",
				OptionLocalCommand, localCmd,
			),
		}
		conn := NewConnector(
			&mapConfigProvider{configs: map[string]*ClientConfig{nodeID: cfg}},
			WithEnvironment(env),
			WithDialer(dialer),
			WithHostKeyVerifier(verifier),
		)
		client, err := conn.Connect(ctx, nodeID)
		if err != nil {
			_ = conn.CloseAll()
			t.Fatalf("Connect setup for LocalCommand test failed: %v", err)
		}
		if gotAddr := client.ConnectionConfig().Address; gotAddr != "[[2001:db8::1]]" {
			_ = conn.CloseAll()
			t.Fatalf("ConnectionConfig().Address = %q, want [[2001:db8::1]]", gotAddr)
		}
		err = client.RunPostAuthLocalCommand(ctx)
		_ = conn.CloseAll()
		if !errors.Is(err, ErrUnsafeExecToken) {
			t.Fatalf("RunPostAuthLocalCommand(%q) = %v, want ErrUnsafeExecToken", localCmd, err)
		}
		if localSpawns.Load() != 0 {
			t.Fatalf("LocalCommand %q executed %d times on unsafe nested-bracket host", localCmd, localSpawns.Load())
		}
	}
}

func assertPass5ConnectPlanNestedBracketsConsistency(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	peer, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })

	planNested := ConnectionPlan{
		Scope: "pass5-nested",
		Hops: []ConnectionConfig{{
			NodeID:       "pinned",
			Address:      "[[2001:db8::1]]",
			Port:         2222,
			User:         "fixture",
			AuthType:     "password",
			TrustVersion: "trust-v1",
		}},
	}
	planSingle := ConnectionPlan{
		Scope: "pass5-nested",
		Hops: []ConnectionConfig{{
			NodeID:       "pinned",
			Address:      "[2001:db8::1]",
			Port:         2222,
			User:         "fixture",
			AuthType:     "password",
			TrustVersion: "trust-v1",
		}},
	}

	keyNested, err := ConnectionKey(planNested)
	if err != nil {
		t.Fatalf("ConnectionKey(nested) failed: %v", err)
	}
	keySingle, err := ConnectionKey(planSingle)
	if err != nil {
		t.Fatalf("ConnectionKey(single) failed: %v", err)
	}
	if keyNested == keySingle {
		t.Fatalf("expected nested-bracket ConnectionKey to stay distinct from valid IPv6 literal, both got %s", keyNested)
	}

	var lastDialAddr atomic.Value
	dialer := dialFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		lastDialAddr.Store(addr)
		var nd net.Dialer
		return nd.DialContext(ctx, "tcp", peer.Address)
	})
	conn := NewConnector(
		nil,
		WithDialer(dialer),
		WithSecretResolver(fixturePassword{}),
		WithHostKeyVerifier(&pinnedAlgorithmVerifier{key: peer.HostKey}),
	)
	t.Cleanup(func() { _ = conn.CloseAll() })

	lease, err := conn.ConnectPlan(ctx, planNested)
	if err != nil {
		t.Fatalf("ConnectPlan(nested) failed: %v", err)
	}
	defer func() { _ = lease.Close() }()

	if gotAddr := lease.Client.ConnectionConfig().Address; gotAddr != "[[2001:db8::1]]" {
		t.Fatalf("ConnectPlan client Address = %q, want [[2001:db8::1]] (must not peel second bracket layer)", gotAddr)
	}
	if dialed, _ := lastDialAddr.Load().(string); dialed == "[2001:db8::1]:2222" {
		t.Fatalf("ConnectPlan dialed %q as if [[2001:db8::1]] were valid [2001:db8::1]", dialed)
	}
}

func TestPass5Conn_M1_MuxDisablesEmptyHostTarget(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	peer, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })

	host, portStr, port := splitFixtureHostPort(t, peer.Address)
	sockDir := shortSocketDir(t)
	sharedSock := filepath.Join(sockDir, "shared.sock")

	khDir := t.TempDir()
	userKH := filepath.Join(khDir, "known_hosts")
	if err := appendKnownHost(userKH, net.JoinHostPort(host, portStr), peer.HostKey, false); err != nil {
		t.Fatal(err)
	}
	env := isolatedPass5Env(khDir, userKH)

	// 1. Start an active ControlMaster bound to peer on static shared.sock.
	masterCfg := &ClientConfig{
		NodeID:   "real-master",
		Address:  host,
		Port:     port,
		User:     "fixture",
		AuthType: "password",
		Password: sshfixture.Password,
		Options: MustOptions(
			OptionStrictHostKeyChecking, "yes",
			OptionUserKnownHostsFile, userKH,
			OptionGlobalKnownHostsFile, "none",
		),
	}
	masterConn := NewConnector(
		&testMuxProvider{
			cfg:  masterCfg,
			ctrl: &ControlConfig{Master: ControlMasterYes, Path: sharedSock},
		},
		WithEnvironment(env),
	)
	t.Cleanup(func() { _ = masterConn.CloseAll() })

	masterClient, err := masterConn.Connect(ctx, "real-master")
	if err != nil {
		t.Fatalf("Connect(real-master) failed: %v", err)
	}
	if _, err := masterClient.Run(ctx, "hostname"); err != nil {
		t.Fatalf("masterClient.Run failed: %v", err)
	}
	if _, err := os.Lstat(sharedSock); err != nil {
		t.Fatalf("expected active ControlMaster socket %q: %v", sharedSock, err)
	}

	// 2. Connector.Connect with empty or whitespace Address on static sharedSock must NOT attach.
	errRefusedBlankDial := errors.New("refused dial for blank host")
	var directDialCount atomic.Int32
	rejectBlankDialer := dialFunc(func(_ context.Context, _, addr string) (net.Conn, error) {
		directDialCount.Add(1)
		return nil, errRefusedBlankDial
	})

	for _, blankAddr := range []string{"", "   "} {
		for _, mode := range []ControlMasterMode{ControlMasterNo, ControlMasterAuto} {
			slaveCfg := &ClientConfig{
				NodeID:   "blank-slave",
				Address:  blankAddr,
				Port:     22,
				User:     "guest",
				AuthType: "password",
				Password: "wrong",
			}
			slaveConn := NewConnector(
				&testMuxProvider{
					cfg:  slaveCfg,
					ctrl: &ControlConfig{Master: mode, Path: sharedSock},
				},
				WithEnvironment(env),
				WithDialer(rejectBlankDialer),
			)
			before := directDialCount.Load()
			_, err := slaveConn.Connect(ctx, "blank-slave")
			_ = slaveConn.CloseAll()
			if !errors.Is(err, errRefusedBlankDial) {
				t.Fatalf("Connect(Address=%q, mode=%s) = %v, want fallback dial error %v (must not attach to %q)", blankAddr, mode, err, errRefusedBlankDial, sharedSock)
			}
			if directDialCount.Load() != before+1 {
				t.Fatalf("expected direct dial attempt after skipping mux for Address=%q mode=%s", blankAddr, mode)
			}
		}
	}

	// 3. maybeStartMasterListener must also skip creating a master socket when Address is blank.
	emptyMasterSock := filepath.Join(sockDir, "empty-master.sock")
	blankMasterCfg := &ClientConfig{
		NodeID:   "blank-master",
		Address:  "   ",
		Port:     port,
		User:     "fixture",
		AuthType: "password",
		Password: sshfixture.Password,
	}
	blankMasterConn := NewConnector(
		&testMuxProvider{
			cfg:  blankMasterCfg,
			ctrl: &ControlConfig{Master: ControlMasterYes, Path: emptyMasterSock},
		},
		WithEnvironment(env),
		WithDialer(&dialCountingRedirectDialer{targetAddr: peer.Address}),
		WithHostKeyVerifier(stubHostKeyVerifier{acceptKey: peer.HostKey}),
	)
	t.Cleanup(func() { _ = blankMasterConn.CloseAll() })

	if _, err := blankMasterConn.Connect(ctx, "blank-master"); err != nil {
		t.Fatalf("Connect(blank-master) via redirect dialer failed: %v", err)
	}
	if _, err := os.Lstat(emptyMasterSock); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected maybeStartMasterListener not to bind %q for blank Address, Lstat err=%v", emptyMasterSock, err)
	}
}

type stubHostKeyVerifier struct {
	acceptKey cryptoSSH.PublicKey
}

func (v stubHostKeyVerifier) Verify(_ context.Context, _ HostKeyRequest, key cryptoSSH.PublicKey) error {
	if v.acceptKey != nil && !slices.Equal(v.acceptKey.Marshal(), key.Marshal()) {
		return ErrHostKeyMismatch
	}
	return nil
}

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

func (f dialFunc) Dial(network, addr string) (net.Conn, error) {
	return f(context.Background(), network, addr)
}

func (f dialFunc) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return f(ctx, network, addr)
}

func splitFixtureHostPort(t *testing.T, addr string) (string, string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return host, portStr, port
}

func isolatedPass5Env(homeDir, userKH string) Environment {
	env := fixtureEnvironment()
	env.HomeDir = homeDir
	env.KnownHostsFile = userKH
	env.GlobalKnownHostsFiles = nil
	return env
}
