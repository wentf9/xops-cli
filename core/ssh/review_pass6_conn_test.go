package ssh

import (
	"bytes"
	"context"
	"crypto/dsa" //nolint:staticcheck // regression test for legacy ssh-dss certificate normalization
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	logger "github.com/wentf9/xops-cli/core/log"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

type rawBlobCertPubKey struct {
	keyType string
	blob    []byte
}

func (k rawBlobCertPubKey) Type() string    { return k.keyType }
func (k rawBlobCertPubKey) Marshal() []byte { return slices.Clone(k.blob) }
func (k rawBlobCertPubKey) Verify(data []byte, sig *cryptoSSH.Signature) error {
	parsed, err := cryptoSSH.ParsePublicKey(k.blob)
	if err != nil {
		return err
	}
	return parsed.Verify(data, sig)
}

type pass6PKCS8Key struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

func newMLDSASignerAndRawKey(t *testing.T, keyAlgo string) (cryptoSSH.Signer, any) {
	t.Helper()
	var oid asn1.ObjectIdentifier
	switch keyAlgo {
	case cryptoSSH.KeyAlgoMLDSA44:
		oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	case cryptoSSH.KeyAlgoMLDSA65:
		oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	case cryptoSSH.KeyAlgoMLDSA87:
		oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
	default:
		t.Fatalf("unsupported ML-DSA algorithm %q", keyAlgo)
	}
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(pass6PKCS8Key{
		Version:    0,
		Algo:       pkix.AlgorithmIdentifier{Algorithm: oid},
		PrivateKey: append([]byte{0x80, 32}, seed[:]...),
	})
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	rawKey, err := cryptoSSH.ParseRawPrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("ParseRawPrivateKey(%s) failed: %v", keyAlgo, err)
	}
	signer, err := cryptoSSH.ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("ParsePrivateKey(%s) failed: %v", keyAlgo, err)
	}
	return signer, rawKey
}

func mldsaRuntimeAvailable() bool {
	return slices.Contains(cryptoSSH.SupportedAlgorithms().HostKeys, cryptoSSH.CertAlgoMLDSA65v01Go)
}

func signTestCert(
	t *testing.T,
	pub cryptoSSH.PublicKey,
	ca cryptoSSH.Signer,
	certType uint32,
	principals []string,
) *cryptoSSH.Certificate {
	t.Helper()
	cert := &cryptoSSH.Certificate{
		Key:             pub,
		Serial:          42,
		CertType:        certType,
		KeyId:           "pass6-cert",
		ValidPrincipals: principals,
		ValidAfter:      uint64(time.Now().Add(-time.Hour).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatalf("SignCert failed: %v", err)
	}
	return cert
}

func TestPass6Conn_H1_MLDSAAndDSACertificateAlgorithms(t *testing.T) {
	t.Run("predicate_and_normalization_tables", func(t *testing.T) {
		assertPass6CertPredicateAndNormalization(t)
	})
	t.Run("extract_and_wrapped_signers_for_mldsa_and_dsa", func(t *testing.T) {
		assertPass6ExtractAndWrappedCertSigners(t)
	})
	t.Run("known_hosts_ordering_and_handshake_with_mldsa_and_dsa_certs", func(t *testing.T) {
		assertPass6MLDSAHostAndAgentUserCertEndToEnd(t)
	})
}

func assertPass6CertPredicateAndNormalization(t *testing.T) {
	t.Helper()
	certAlgos := []struct {
		certAlg string
		wantKey string
	}{
		{cryptoSSH.CertAlgoRSAv01, cryptoSSH.KeyAlgoRSA},
		{cryptoSSH.CertAlgoRSASHA256v01, cryptoSSH.KeyAlgoRSASHA256},
		{cryptoSSH.CertAlgoRSASHA512v01, cryptoSSH.KeyAlgoRSASHA512},
		{"ssh-dss-cert-v01@openssh.com", "ssh-dss"},
		{cryptoSSH.CertAlgoECDSA256v01, cryptoSSH.KeyAlgoECDSA256},
		{cryptoSSH.CertAlgoECDSA384v01, cryptoSSH.KeyAlgoECDSA384},
		{cryptoSSH.CertAlgoECDSA521v01, cryptoSSH.KeyAlgoECDSA521},
		{cryptoSSH.CertAlgoSKECDSA256v01, cryptoSSH.KeyAlgoSKECDSA256},
		{cryptoSSH.CertAlgoED25519v01, cryptoSSH.KeyAlgoED25519},
		{cryptoSSH.CertAlgoSKED25519v01, cryptoSSH.KeyAlgoSKED25519},
		{cryptoSSH.CertAlgoMLDSA44v01Go, cryptoSSH.KeyAlgoMLDSA44},
		{cryptoSSH.CertAlgoMLDSA65v01Go, cryptoSSH.KeyAlgoMLDSA65},
		{cryptoSSH.CertAlgoMLDSA87v01Go, cryptoSSH.KeyAlgoMLDSA87},
	}
	for _, tc := range certAlgos {
		if !isCertAlgorithm(tc.certAlg) {
			t.Fatalf("isCertAlgorithm(%q) = false, want true", tc.certAlg)
		}
		if got := normalizeCertSignAlgorithm(tc.certAlg); got != tc.wantKey {
			t.Fatalf("normalizeCertSignAlgorithm(%q) = %q, want %q", tc.certAlg, got, tc.wantKey)
		}
	}

	if !isCertAlgorithm("custom-pq-cert-v01@openssh.com") || !isCertAlgorithm("custom-pq-cert-v01@golang.org") {
		t.Fatal("expected custom *-cert-v01@openssh.com and *-cert-v01@golang.org suffixes to match isCertAlgorithm")
	}

	nonCertAlgos := []string{
		"",
		"-cert-v01@openssh.com",
		"-cert-v01@golang.org",
		cryptoSSH.KeyAlgoRSA,
		cryptoSSH.KeyAlgoRSASHA256,
		cryptoSSH.KeyAlgoRSASHA512,
		"ssh-dss",
		cryptoSSH.KeyAlgoECDSA256,
		cryptoSSH.KeyAlgoSKECDSA256,
		cryptoSSH.KeyAlgoED25519,
		cryptoSSH.KeyAlgoSKED25519,
		cryptoSSH.KeyAlgoMLDSA44,
		cryptoSSH.KeyAlgoMLDSA65,
		cryptoSSH.KeyAlgoMLDSA87,
	}
	for _, plain := range nonCertAlgos {
		if isCertAlgorithm(plain) {
			t.Fatalf("isCertAlgorithm(%q) = true, want false", plain)
		}
		if got := normalizeCertSignAlgorithm(plain); got != plain {
			t.Fatalf("normalizeCertSignAlgorithm(%q) = %q, want unchanged", plain, got)
		}
	}
}

type recordingAlgoCertSigner struct {
	pub     cryptoSSH.PublicKey
	gotAlgo string
}

func (s *recordingAlgoCertSigner) PublicKey() cryptoSSH.PublicKey { return s.pub }
func (s *recordingAlgoCertSigner) Sign(_ io.Reader, _ []byte) (*cryptoSSH.Signature, error) {
	s.gotAlgo = "<default>"
	return &cryptoSSH.Signature{Format: s.pub.Type()}, nil
}
func (s *recordingAlgoCertSigner) SignWithAlgorithm(_ io.Reader, _ []byte, algorithm string) (*cryptoSSH.Signature, error) {
	s.gotAlgo = algorithm
	return &cryptoSSH.Signature{Format: algorithm}, nil
}

func assertPass6ExtractAndWrappedCertSigners(t *testing.T) {
	t.Helper()
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caSigner, err := cryptoSSH.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatal(err)
	}

	// Verify signCertWithNormalizedAlgorithm dispatches normalized ML-DSA & DSA key algorithms
	// regardless of Go runtime build tags.
	for _, pair := range [][2]string{
		{cryptoSSH.CertAlgoMLDSA44v01Go, cryptoSSH.KeyAlgoMLDSA44},
		{cryptoSSH.CertAlgoMLDSA65v01Go, cryptoSSH.KeyAlgoMLDSA65},
		{cryptoSSH.CertAlgoMLDSA87v01Go, cryptoSSH.KeyAlgoMLDSA87},
		{"ssh-dss-cert-v01@openssh.com", "ssh-dss"},
	} {
		rec := &recordingAlgoCertSigner{pub: caSigner.PublicKey()}
		if _, err := signCertWithNormalizedAlgorithm(nil, rec, rand.Reader, []byte("x"), pair[0]); err != nil {
			t.Fatalf("signCertWithNormalizedAlgorithm(%q) failed: %v", pair[0], err)
		}
		if rec.gotAlgo != pair[1] {
			t.Fatalf("signCertWithNormalizedAlgorithm(%q) passed %q, want %q", pair[0], rec.gotAlgo, pair[1])
		}
	}

	type certCase struct {
		name    string
		signer  cryptoSSH.Signer
		certAlg string
	}
	cases := []certCase{
		{"dsa", newLegacyDSSSignerForPass6(t), "ssh-dss-cert-v01@openssh.com"},
	}
	if mldsaRuntimeAvailable() {
		s44, _ := newMLDSASignerAndRawKey(t, cryptoSSH.KeyAlgoMLDSA44)
		s65, _ := newMLDSASignerAndRawKey(t, cryptoSSH.KeyAlgoMLDSA65)
		s87, _ := newMLDSASignerAndRawKey(t, cryptoSSH.KeyAlgoMLDSA87)
		cases = append(cases,
			certCase{"mldsa44", s44, cryptoSSH.CertAlgoMLDSA44v01Go},
			certCase{"mldsa65", s65, cryptoSSH.CertAlgoMLDSA65v01Go},
			certCase{"mldsa87", s87, cryptoSSH.CertAlgoMLDSA87v01Go},
		)
	}

	for _, tc := range cases {
		userCert := signTestCert(t, tc.signer.PublicKey(), caSigner, cryptoSSH.UserCert, []string{"fixture"})
		opaquePub := rawBlobCertPubKey{keyType: userCert.Type(), blob: userCert.Marshal()}
		extracted, ok := extractCertFromPublicKey(opaquePub)
		if !ok || !bytes.Equal(extracted.Marshal(), userCert.Marshal()) {
			t.Fatalf("%s: extractCertFromPublicKey(%q) failed: ok=%v", tc.name, opaquePub.Type(), ok)
		}

		agentCertSigner, err := cryptoSSH.NewCertSigner(userCert, tc.signer)
		if err != nil {
			t.Fatalf("%s: NewCertSigner: %v", tc.name, err)
		}
		opaqueBase := &plainKeyOverrideSigner{inner: agentCertSigner, pub: opaquePub}
		wrapped, err := newWrappedCertSigner(userCert, opaqueBase)
		if err != nil {
			t.Fatalf("%s: newWrappedCertSigner over cert-backed signer failed: %v", tc.name, err)
		}
		algoSigner, ok := wrapped.(cryptoSSH.AlgorithmSigner)
		if !ok {
			t.Fatalf("%s: wrapped signer does not implement AlgorithmSigner", tc.name)
		}
		msg := []byte("pass6-challenge-" + tc.name)
		sig, err := algoSigner.SignWithAlgorithm(rand.Reader, msg, tc.certAlg)
		if err != nil {
			t.Fatalf("%s: SignWithAlgorithm(%q) failed: %v", tc.name, tc.certAlg, err)
		}
		if err := userCert.Verify(msg, sig); err != nil {
			t.Fatalf("%s: userCert.Verify failed: %v", tc.name, err)
		}
	}
}

func newLegacyDSSSignerForPass6(t *testing.T) cryptoSSH.Signer {
	t.Helper()
	var params dsa.Parameters
	if err := dsa.GenerateParameters(&params, rand.Reader, dsa.L1024N160); err != nil {
		t.Fatal(err)
	}
	var priv dsa.PrivateKey
	priv.Parameters = params
	if err := dsa.GenerateKey(&priv, rand.Reader); err != nil {
		t.Fatal(err)
	}
	signer, err := cryptoSSH.NewSignerFromKey(&priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func assertPass6MLDSAHostAndAgentUserCertEndToEnd(t *testing.T) {
	t.Helper()
	// Always verify orderKnownHostsHostKeyAlgorithms directly on an explicit pool containing
	// CertAlgoMLDSA{44,65,87}v01Go and ssh-dss-cert-v01@openssh.com (even on Go < 1.27).
	assertPass6ExplicitPoolCertOrdering(t)

	if !mldsaRuntimeAvailable() {
		return
	}

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	caSigner, _ := newMLDSASignerAndRawKey(t, cryptoSSH.KeyAlgoMLDSA65)
	hostBaseSigner, _ := newMLDSASignerAndRawKey(t, cryptoSSH.KeyAlgoMLDSA65)
	hostCert := signTestCert(t, hostBaseSigner.PublicKey(), caSigner, cryptoSSH.HostCert, []string{"127.0.0.1", "localhost"})
	hostCertSigner, err := cryptoSSH.NewCertSigner(hostCert, hostBaseSigner)
	if err != nil {
		t.Fatal(err)
	}

	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edHostSigner, err := cryptoSSH.NewSignerFromKey(edPriv)
	if err != nil {
		t.Fatal(err)
	}

	userSigner, userPriv := newMLDSASignerAndRawKey(t, cryptoSSH.KeyAlgoMLDSA65)
	userCert := signTestCert(t, userSigner.PublicKey(), caSigner, cryptoSSH.UserCert, []string{"fixture"})

	// 1. Without @cert-authority, ML-DSA cert algorithms must stay in the trailing cert block
	// after all plain algorithms.
	peerDual, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		HostKeys: []cryptoSSH.Signer{hostCertSigner, edHostSigner},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peerDual.Close() })

	dualHost, dualPortStr, dualPort := splitFixtureHostPort(t, peerDual.Address)
	dir := t.TempDir()
	noCAKH := filepath.Join(dir, "no_ca_known_hosts")
	if err := appendKnownHost(noCAKH, net.JoinHostPort(dualHost, dualPortStr), edHostSigner.PublicKey(), false); err != nil {
		t.Fatal(err)
	}
	envNoCA := isolatedPass5Env(dir, noCAKH)
	cfgNoCA := &ClientConfig{
		NodeID:   "dual-mldsa-no-ca",
		Address:  dualHost,
		Port:     dualPort,
		User:     "fixture",
		AuthType: "password",
		Password: sshfixture.Password,
		Options: MustOptions(
			OptionStrictHostKeyChecking, "yes",
			OptionUserKnownHostsFile, noCAKH,
			OptionGlobalKnownHostsFile, "none",
		),
	}
	connNoCA := NewConnector(&mapConfigProvider{configs: map[string]*ClientConfig{"dual-mldsa-no-ca": cfgNoCA}}, WithEnvironment(envNoCA))
	t.Cleanup(func() { _ = connNoCA.CloseAll() })
	algsNoCA, err := connNoCA.getHostKeyAlgorithms(ctx, nil, cfgNoCA)
	if err != nil {
		t.Fatalf("getHostKeyAlgorithms(no CA) failed: %v", err)
	}
	assertAllPlainBeforeCertAlgorithms(t, "default-no-ca", algsNoCA)
	if !slices.Contains(algsNoCA, cryptoSSH.CertAlgoMLDSA65v01Go) {
		t.Fatalf("expected %q in HostKeyAlgorithms, got %v", cryptoSSH.CertAlgoMLDSA65v01Go, algsNoCA)
	}
	if cli, err := connNoCA.Connect(ctx, "dual-mldsa-no-ca"); err != nil {
		t.Fatalf("Connect(dual-mldsa-no-ca) failed: %v", err)
	} else if _, err := cli.Run(ctx, "hostname"); err != nil {
		t.Fatalf("cli.Run(dual-mldsa-no-ca) failed: %v", err)
	}

	// 2. With @cert-authority, ML-DSA cert algorithms and +ssh-dss-cert-v01@openssh.com must lead,
	// and an SSH agent serving an ML-DSA-65 user certificate must authenticate end-to-end.
	assertPass6MLDSACertAuthorityAndAgentAuth(t, ctx, caSigner, hostCertSigner, edHostSigner, userPriv, userCert)
}

func assertPass6ExplicitPoolCertOrdering(t *testing.T) {
	t.Helper()
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edSigner, err := cryptoSSH.NewSignerFromKey(edPriv)
	if err != nil {
		t.Fatal(err)
	}

	pool := []string{
		cryptoSSH.CertAlgoMLDSA65v01Go,
		cryptoSSH.KeyAlgoMLDSA65,
		cryptoSSH.CertAlgoED25519v01,
		cryptoSSH.KeyAlgoED25519,
		"ssh-dss-cert-v01@openssh.com",
		"ssh-dss",
	}

	dir := t.TempDir()
	noCAKH := filepath.Join(dir, "no_ca")
	if err := appendKnownHost(noCAKH, "host.corp:22", edSigner.PublicKey(), false); err != nil {
		t.Fatal(err)
	}
	connNoCA := NewConnector(nil, WithEnvironment(isolatedPass5Env(dir, noCAKH)))
	t.Cleanup(func() { _ = connNoCA.CloseAll() })
	gotNoCA := connNoCA.orderKnownHostsHostKeyAlgorithms(&ClientConfig{Address: "host.corp", Port: 22}, pool)
	wantNoCA := []string{
		cryptoSSH.KeyAlgoED25519,
		cryptoSSH.KeyAlgoMLDSA65,
		"ssh-dss",
		cryptoSSH.CertAlgoMLDSA65v01Go,
		cryptoSSH.CertAlgoED25519v01,
		"ssh-dss-cert-v01@openssh.com",
	}
	if !slices.Equal(gotNoCA, wantNoCA) {
		t.Fatalf("orderKnownHostsHostKeyAlgorithms(no CA) = %v, want %v", gotNoCA, wantNoCA)
	}

	caKH := filepath.Join(dir, "with_ca")
	caLine := "@cert-authority *.corp " + strings.TrimSpace(string(cryptoSSH.MarshalAuthorizedKey(edSigner.PublicKey()))) + "\n"
	if err := os.WriteFile(caKH, []byte(caLine), 0o600); err != nil {
		t.Fatal(err)
	}
	connCA := NewConnector(nil, WithEnvironment(isolatedPass5Env(dir, caKH)))
	t.Cleanup(func() { _ = connCA.CloseAll() })
	gotCA := connCA.orderKnownHostsHostKeyAlgorithms(&ClientConfig{Address: "host.corp", Port: 22}, pool)
	wantCA := []string{
		cryptoSSH.CertAlgoMLDSA65v01Go,
		cryptoSSH.CertAlgoED25519v01,
		"ssh-dss-cert-v01@openssh.com",
		cryptoSSH.KeyAlgoMLDSA65,
		cryptoSSH.KeyAlgoED25519,
		"ssh-dss",
	}
	if !slices.Equal(gotCA, wantCA) {
		t.Fatalf("orderKnownHostsHostKeyAlgorithms(with CA) = %v, want %v", gotCA, wantCA)
	}
}

func assertPass6MLDSACertAuthorityAndAgentAuth(
	t *testing.T,
	ctx context.Context,
	caSigner cryptoSSH.Signer,
	hostCertSigner cryptoSSH.Signer,
	edHostSigner cryptoSSH.Signer,
	userPriv any,
	userCert *cryptoSSH.Certificate,
) {
	t.Helper()
	peerCA, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		HostKeys:   []cryptoSSH.Signer{edHostSigner, hostCertSigner},
		PublicKeys: []cryptoSSH.PublicKey{userCert},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peerCA.Close() })

	host, portStr, port := splitFixtureHostPort(t, peerCA.Address)
	dir := t.TempDir()
	caKH := filepath.Join(dir, "ca_known_hosts")
	caLine := "@cert-authority " + knownhosts.Normalize(net.JoinHostPort(host, portStr)) + " " + strings.TrimSpace(string(cryptoSSH.MarshalAuthorizedKey(caSigner.PublicKey()))) + "\n"
	if err := os.WriteFile(caKH, []byte(caLine), 0o600); err != nil {
		t.Fatal(err)
	}

	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: userPriv, Certificate: userCert}); err != nil {
		t.Fatalf("keyring.Add(mldsa cert) failed: %v", err)
	}
	agentSock := filepath.Join(shortSocketDir(t), "mldsa-agent.sock")
	ln, err := net.Listen("unix", agentSock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				_ = agent.ServeAgent(keyring, conn)
			}(c)
		}
	}()

	env := isolatedPass5Env(dir, caKH)
	env.AgentSocket = agentSock
	env.DialAgent = func(dialCtx context.Context, path string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(dialCtx, "unix", path)
	}

	cfg := &ClientConfig{
		NodeID:   "mldsa-ca-agent",
		Address:  host,
		Port:     port,
		User:     "fixture",
		AuthType: "auto",
		Options: MustOptions(
			OptionHostKeyAlgorithms, "+ssh-dss-cert-v01@openssh.com",
			OptionStrictHostKeyChecking, "yes",
			OptionUserKnownHostsFile, caKH,
			OptionGlobalKnownHostsFile, "none",
		),
	}
	conn := NewConnector(&mapConfigProvider{configs: map[string]*ClientConfig{"mldsa-ca-agent": cfg}}, WithEnvironment(env))
	t.Cleanup(func() { _ = conn.CloseAll() })

	algs, err := conn.getHostKeyAlgorithms(ctx, nil, cfg)
	if err != nil {
		t.Fatalf("getHostKeyAlgorithms(mldsa CA) failed: %v", err)
	}
	seenPlain := false
	for _, alg := range algs {
		if isCertAlgorithm(alg) {
			if seenPlain {
				t.Fatalf("cert algorithm %q placed after plain algorithm: %v", alg, algs)
			}
			continue
		}
		seenPlain = true
	}
	if !slices.Contains(algs, cryptoSSH.CertAlgoMLDSA65v01Go) || !slices.Contains(algs, "ssh-dss-cert-v01@openssh.com") {
		t.Fatalf("expected ML-DSA and DSA cert algorithms in %v", algs)
	}

	cli, err := conn.Connect(ctx, "mldsa-ca-agent")
	if err != nil {
		t.Fatalf("Connect(mldsa-ca-agent) failed: %v", err)
	}
	if _, err := cli.Run(ctx, "hostname"); err != nil {
		t.Fatalf("cli.Run(mldsa-ca-agent) failed: %v", err)
	}
}

func TestPass6Conn_M1_ExtractLocalExecHostSpecValidatesBeforeUnbracketing(t *testing.T) {
	t.Run("unit_valid_and_malformed_bracket_host_specs", func(t *testing.T) {
		assertPass6ExtractLocalExecHostSpecUnit(t)
	})
	t.Run("end_to_end_proxy_and_local_command_percent_n", func(t *testing.T) {
		assertPass6LocalExecPercentNEndToEnd(t)
	})
}

func assertPass6ExtractLocalExecHostSpecUnit(t *testing.T) {
	t.Helper()
	valid := []struct {
		in   string
		want string
	}{
		{"[::1]", "::1"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"[fe80::1%eth0]", "fe80::1%eth0"},
		{"[::1]:22", "::1"},
		{"[2001:db8::1]:2222", "2001:db8::1"},
		{"[fe80::1%eth0]:2222", "fe80::1%eth0"},
		{"::1", "::1"},
		{"2001:db8::1", "2001:db8::1"},
		{"fe80::1%eth0", "fe80::1%eth0"},
		{"10.0.0.5:22", "10.0.0.5"},
		{"web-prod.corp:2222", "web-prod.corp"},
		{"web-prod", "web-prod"},
	}
	for _, tc := range valid {
		got, err := extractLocalExecHostSpec(tc.in)
		if err != nil || got != tc.want {
			t.Fatalf("extractLocalExecHostSpec(%q) = (%q, %v), want (%q, nil)", tc.in, got, err, tc.want)
		}
	}

	unsafe := []string{
		"",
		"[]",
		"[ ]",
		"[127.0.0.1]",
		"[127.0.0.1]:22",
		"[example.com]",
		"[example.com]:2222",
		"[[::1]]",
		"[[2001:db8::1]]",
		"[[2001:db8::1]]:2222",
		"[ 2001:db8::1 ]",
		"[ 2001:db8::1 ]:22",
		"[-oProxyCommand=sh]",
		"[-oProxyCommand=sh]:22",
		"[::1];id",
		"[::1]:22;id",
		"[::1",
		"::1]",
		"host]:22",
		"[::1]:0",
		"[::1]:99999",
	}
	for _, bad := range unsafe {
		if got, err := extractLocalExecHostSpec(bad); !errors.Is(err, ErrUnsafeExecToken) {
			t.Fatalf("extractLocalExecHostSpec(%q) = (%q, %v), want ErrUnsafeExecToken", bad, got, err)
		}
	}
}

func assertPass6LocalExecPercentNEndToEnd(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	peer, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })

	// Valid bracketed IPv6 NodeIDs expand %n cleanly without brackets.
	for _, nodeID := range []string{"openssh:[::1]", "fixture@[::1]:2222"} {
		var gotProxy, gotLocal string
		env := isolatedPass5Env(t.TempDir(), filepath.Join(t.TempDir(), "kh"))
		env.DialProxyCommand = func(dialCtx context.Context, cmd string) (net.Conn, error) {
			gotProxy = cmd
			var d net.Dialer
			return d.DialContext(dialCtx, "tcp", peer.Address)
		}
		env.RunLocalCommand = func(_ context.Context, cmd string) error {
			gotLocal = cmd
			return nil
		}
		cfg := &ClientConfig{
			NodeID:   nodeID,
			Address:  "[::1]",
			Port:     2222,
			User:     "fixture",
			AuthType: "password",
			Password: sshfixture.Password,
			Options: MustOptions(
				OptionProxyCommand, "ssh -W [%h]:%p [%n]",
				OptionPermitLocalCommand, "yes",
				OptionLocalCommand, "echo [%n] [%h]:%p",
			),
		}
		conn := NewConnector(
			&mapConfigProvider{configs: map[string]*ClientConfig{nodeID: cfg}},
			WithEnvironment(env),
			WithHostKeyVerifier(stubHostKeyVerifier{acceptKey: peer.HostKey}),
		)
		cli, err := conn.Connect(ctx, nodeID)
		if err != nil {
			_ = conn.CloseAll()
			t.Fatalf("Connect(%q) failed: %v", nodeID, err)
		}
		if err := cli.RunPostAuthLocalCommand(ctx); err != nil {
			_ = conn.CloseAll()
			t.Fatalf("RunPostAuthLocalCommand(%q) failed: %v", nodeID, err)
		}
		_ = conn.CloseAll()
		if gotProxy != "ssh -W [::1]:2222 [::1]" {
			t.Fatalf("ProxyCommand(%q) = %q, want %q", nodeID, gotProxy, "ssh -W [::1]:2222 [::1]")
		}
		if gotLocal != "echo [::1] [::1]:2222" {
			t.Fatalf("LocalCommand(%q) = %q, want %q", nodeID, gotLocal, "echo [::1] [::1]:2222")
		}
	}

	// Bracket-masked non-IPv6 or nested-bracket NodeIDs fail closed before spawning any command.
	for _, badNodeID := range []string{
		"openssh:[127.0.0.1]",
		"openssh:[example.com]",
		"openssh:[[2001:db8::1]]",
		"fixture@[127.0.0.1]:2222",
		"fixture@[example.com]:2222",
		"fixture@[[2001:db8::1]]:2222",
	} {
		var spawns atomic.Int32
		env := isolatedPass5Env(t.TempDir(), filepath.Join(t.TempDir(), "kh"))
		env.DialProxyCommand = func(_ context.Context, cmd string) (net.Conn, error) {
			spawns.Add(1)
			return nil, errors.New("unexpected ProxyCommand: " + cmd)
		}
		env.RunLocalCommand = func(_ context.Context, cmd string) error {
			spawns.Add(1)
			return errors.New("unexpected LocalCommand: " + cmd)
		}
		cfg := &ClientConfig{
			NodeID:   badNodeID,
			Address:  "127.0.0.1",
			Port:     2222,
			User:     "fixture",
			AuthType: "password",
			Password: sshfixture.Password,
			Options: MustOptions(
				OptionProxyCommand, "nc %n %p",
				OptionPermitLocalCommand, "yes",
				OptionLocalCommand, "echo %n",
			),
		}
		conn := NewConnector(
			&mapConfigProvider{configs: map[string]*ClientConfig{badNodeID: cfg}},
			WithEnvironment(env),
			WithHostKeyVerifier(stubHostKeyVerifier{acceptKey: peer.HostKey}),
		)
		_, err := conn.Connect(ctx, badNodeID)
		_ = conn.CloseAll()
		if !errors.Is(err, ErrUnsafeExecToken) {
			t.Fatalf("Connect(%q) = %v, want ErrUnsafeExecToken", badNodeID, err)
		}
		rawCli := &Client{environment: env, connCfg: cfg.ToConnectionConfig()}
		if err := rawCli.RunPostAuthLocalCommand(ctx); !errors.Is(err, ErrUnsafeExecToken) {
			t.Fatalf("RunPostAuthLocalCommand(%q) = %v, want ErrUnsafeExecToken", badNodeID, err)
		}
		if spawns.Load() != 0 {
			t.Fatalf("spawns for %q = %d, want 0", badNodeID, spawns.Load())
		}
	}
}

type deadlineTrackingConn struct {
	net.Conn
	mu           sync.Mutex
	deadlines    []time.Time
	unboundAfter bool
	latePastSeen bool
}

func (c *deadlineTrackingConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadlines = append(c.deadlines, t)
	if c.unboundAfter && !t.IsZero() {
		c.latePastSeen = true
	}
	c.mu.Unlock()
	return c.Conn.SetDeadline(t)
}

func (c *deadlineTrackingConn) markUnboundComplete() {
	c.mu.Lock()
	c.unboundAfter = true
	c.mu.Unlock()
}

func (c *deadlineTrackingConn) sawLateDeadline() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.latePastSeen
}

func TestPass6Conn_M2_BindConnContextRaceAndPostHandshakeCancel(t *testing.T) {
	t.Run("bind_conn_context_mutex_prevents_late_afterfunc_poisoning", func(t *testing.T) {
		assertPass6BindConnContextSynchronization(t)
	})
	t.Run("mux_dials_surface_ctx_err_and_survive_post_handshake_cancel_race", func(t *testing.T) {
		assertPass6MuxDialCancelRaceAndSurvival(t)
	})
}

func assertPass6BindConnContextSynchronization(t *testing.T) {
	t.Helper()
	for range 200 {
		a, b := net.Pipe()
		tracked := &deadlineTrackingConn{Conn: a}
		ctx, cancel := context.WithCancel(context.Background())

		unbind := bindConnContext(ctx, tracked, DefaultMuxHandshakeTimeout)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			cancel()
		}()

		unbind()
		// Once unbind() returns when ctx was not yet canceled before unbind cleared deadline,
		// or even when racing, NO SetDeadline(!IsZero) may occur AFTER unbind() returns!
		tracked.markUnboundComplete()
		unbind() // idempotent repeat call must never touch SetDeadline again
		wg.Wait()
		time.Sleep(100 * time.Microsecond)

		if tracked.sawLateDeadline() {
			_ = a.Close()
			_ = b.Close()
			t.Fatal("AfterFunc called SetDeadline with non-zero deadline AFTER unbind() completed")
		}
		_ = a.Close()
		_ = b.Close()
	}
}

func assertPass6MuxDialCancelRaceAndSurvival(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	peer, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })

	host, _, port := splitFixtureHostPort(t, peer.Address)
	sockPath := filepath.Join(shortSocketDir(t), "pass6-m2.sock")
	masterCfg := &ClientConfig{
		NodeID:   "m2-master",
		Address:  host,
		Port:     port,
		User:     "fixture",
		AuthType: "password",
		Password: sshfixture.Password,
	}
	masterConn := NewConnector(
		&testMuxProvider{
			cfg:  masterCfg,
			ctrl: &ControlConfig{Master: ControlMasterYes, Path: sockPath},
		},
		WithEnvironment(isolatedPass5Env(t.TempDir(), filepath.Join(t.TempDir(), "kh"))),
		WithHostKeyVerifier(stubHostKeyVerifier{acceptKey: peer.HostKey}),
	)
	t.Cleanup(func() { _ = masterConn.CloseAll() })

	if _, err := masterConn.Connect(ctx, "m2-master"); err != nil {
		t.Fatalf("Connect(m2-master) failed: %v", err)
	}
	target := TargetContext{Host: host, Port: port, User: "fixture"}

	assertPass6DeterministicCancelDuringMuxHandshake(t, target)
	assertPass6PostHandshakeCancelStress(t, ctx, sockPath, target)
}

func assertPass6DeterministicCancelDuringMuxHandshake(t *testing.T, target TargetContext) {
	t.Helper()
	sockPath := filepath.Join(shortSocketDir(t), "stall.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	release := make(chan struct{})
	defer close(release)
	accepted := make(chan struct{}, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			go func(conn net.Conn) {
				<-release
				_ = conn.Close()
			}(c)
		}
	}()

	type dialFn struct {
		name string
		run  func(context.Context) error
	}
	cases := []dialFn{
		{"DialMuxClient", func(dCtx context.Context) error {
			_, err := DialMuxClient(dCtx, sockPath)
			return err
		}},
		{"DialMuxProxyStream", func(dCtx context.Context) error {
			_, err := DialMuxProxyStream(dCtx, sockPath)
			return err
		}},
		{"DialControlProxy", func(dCtx context.Context) error {
			_, _, err := DialControlProxy(dCtx, sockPath, target)
			return err
		}},
		{"DialControlProxyClient", func(dCtx context.Context) error {
			_, err := DialControlProxyClient(dCtx, sockPath, target, Environment{}, nil, logger.NopLogger)
			return err
		}},
	}

	for _, tc := range cases {
		dCtx, dCancel := context.WithCancel(context.Background())
		errCh := make(chan error, 1)
		go func() { errCh <- tc.run(dCtx) }()
		<-accepted
		dCancel()
		gotErr := <-errCh
		if !errors.Is(gotErr, context.Canceled) {
			t.Fatalf("%s on mid-handshake cancel returned %v, want errors.Is(context.Canceled)", tc.name, gotErr)
		}
	}
}

func assertPass6PostHandshakeCancelStress(t *testing.T, liveCtx context.Context, sockPath string, target TargetContext) {
	t.Helper()
	for iter := range 30 {
		// 1. DialMuxClient: cancel dialCtx immediately on return (and race on odd iterations);
		// returned client must remain healthy for AliveCheck(liveCtx).
		dCtx1, dCancel1 := context.WithCancel(liveCtx)
		if iter%2 == 1 {
			go func() {
				time.Sleep(time.Duration(iter%5) * 50 * time.Microsecond)
				dCancel1()
			}()
		}
		mc, err := DialMuxClient(dCtx1, sockPath)
		dCancel1()
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("iter %d: DialMuxClient race error = %v, want context.Canceled", iter, err)
			}
		} else {
			time.Sleep(200 * time.Microsecond)
			if pid, aliveErr := mc.AliveCheck(liveCtx); aliveErr != nil || pid == 0 {
				_ = mc.Close()
				t.Fatalf("iter %d: MuxClient poisoned by post-handshake dialCtx cancel: pid=%d err=%v", iter, pid, aliveErr)
			}
			_ = mc.Close()
		}

		// 2. DialControlProxyClient (which exercises DialControlProxy): cancel dialCtx on/during return;
		// returned *Client must still run commands cleanly on liveCtx.
		dCtx2, dCancel2 := context.WithCancel(liveCtx)
		if iter%2 == 1 {
			go func() {
				time.Sleep(time.Duration(iter%5) * 50 * time.Microsecond)
				dCancel2()
			}()
		}
		cli, err := DialControlProxyClient(dCtx2, sockPath, target, Environment{}, nil, logger.NopLogger)
		dCancel2()
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("iter %d: DialControlProxyClient race error = %v, want context.Canceled", iter, err)
			}
		} else {
			time.Sleep(200 * time.Microsecond)
			if _, runErr := cli.Run(liveCtx, "hostname"); runErr != nil {
				_ = cli.Close()
				t.Fatalf("iter %d: ControlProxy Client poisoned by post-handshake dialCtx cancel: %v", iter, runErr)
			}
			_ = cli.Close()
		}
	}
}

func TestPass6Conn_M6_ConnectorTracksLogicalMasterNodeID(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	bastionPeer, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bastionPeer.Close() })

	targetPeer, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = targetPeer.Close() })

	bHost, _, bPort := splitFixtureHostPort(t, bastionPeer.Address)
	tHost, _, tPort := splitFixtureHostPort(t, targetPeer.Address)
	sockDir := shortSocketDir(t)
	bastionSock := filepath.Join(sockDir, "bastion.sock")
	targetSock := filepath.Join(sockDir, "target.sock")

	// Simulate CanonicalizeHostname having overwritten OriginalHost to the canonical FQDN,
	// while Connector was invoked with logical OpenSSH/saved node selectors.
	provider := &multiNodeMuxProvider{
		cfgs: map[string]*ClientConfig{
			"openssh:bastion-alias": {
				NodeID:       "openssh:bastion-alias",
				OriginalHost: "bastion.Canonical.Corp.Example",
				Address:      bHost,
				Port:         bPort,
				User:         "fixture",
				AuthType:     "password",
				Password:     sshfixture.Password,
			},
			"openssh:app-alias": {
				NodeID:       "openssh:app-alias",
				OriginalHost: "app.Canonical.Corp.Example",
				Address:      tHost,
				Port:         tPort,
				User:         "fixture",
				AuthType:     "password",
				Password:     sshfixture.Password,
				ProxyJump:    "openssh:bastion-alias",
			},
		},
		ctrls: map[string]*ControlConfig{
			"openssh:bastion-alias": {Master: ControlMasterAuto, Path: bastionSock, Persist: "30s"},
			"openssh:app-alias":     {Master: ControlMasterAuto, Path: targetSock, Persist: "30s"},
		},
	}

	conn := NewConnector(
		provider,
		WithEnvironment(isolatedPass5Env(t.TempDir(), filepath.Join(t.TempDir(), "kh"))),
		WithHostKeyVerifier(acceptMultipleHostKeys{keys: []cryptoSSH.PublicKey{bastionPeer.HostKey, targetPeer.HostKey}}),
	)
	t.Cleanup(func() { _ = conn.CloseAll() })

	var nilConn *Connector
	if got := nilConn.MasterNodeID(&MuxServer{}); got != "" {
		t.Fatalf("nilConn.MasterNodeID = %q, want empty", got)
	}
	if got := conn.MasterNodeID(nil); got != "" {
		t.Fatalf("conn.MasterNodeID(nil) = %q, want empty", got)
	}
	if got := conn.MasterNodeID(&MuxServer{}); got != "" {
		t.Fatalf("conn.MasterNodeID(unowned) = %q, want empty", got)
	}

	cli, err := conn.Connect(ctx, "openssh:app-alias")
	if err != nil {
		t.Fatalf("Connect(openssh:app-alias) failed: %v", err)
	}
	if _, err := cli.Run(ctx, "hostname"); err != nil {
		t.Fatalf("cli.Run failed: %v", err)
	}

	masters := conn.Masters()
	if len(masters) != 2 {
		t.Fatalf("len(Masters()) = %d, want 2", len(masters))
	}
	if masters[0].Target().OriginalHost != "bastion.Canonical.Corp.Example" ||
		masters[1].Target().OriginalHost != "app.Canonical.Corp.Example" {
		t.Fatalf("unexpected canonical Target().OriginalHost: %q, %q", masters[0].Target().OriginalHost, masters[1].Target().OriginalHost)
	}
	if got := conn.MasterNodeID(masters[0]); got != "openssh:bastion-alias" {
		t.Fatalf("MasterNodeID(masters[0]) = %q, want openssh:bastion-alias", got)
	}
	if got := conn.MasterNodeID(masters[1]); got != "openssh:app-alias" {
		t.Fatalf("MasterNodeID(masters[1]) = %q, want openssh:app-alias", got)
	}

	// Concurrent -race exercise across MasterNodeID, ReleaseMaster, and AcquireMaster.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 50 {
			_ = conn.ReleaseMaster(masters[1])
			_ = conn.AcquireMaster(masters[1])
		}
	}()
	go func() {
		defer wg.Done()
		for range 50 {
			if got := conn.MasterNodeID(masters[1]); got != "openssh:app-alias" {
				t.Errorf("concurrent MasterNodeID = %q, want openssh:app-alias", got)
				return
			}
		}
	}()
	wg.Wait()

	if err := conn.CloseAll(); err != nil {
		t.Fatalf("CloseAll failed: %v", err)
	}
	if got := conn.MasterNodeID(masters[1]); got != "" {
		t.Fatalf("MasterNodeID after CloseAll = %q, want empty", got)
	}
}

type acceptMultipleHostKeys struct {
	keys []cryptoSSH.PublicKey
}

func (v acceptMultipleHostKeys) Verify(_ context.Context, _ HostKeyRequest, key cryptoSSH.PublicKey) error {
	for _, k := range v.keys {
		if bytes.Equal(k.Marshal(), key.Marshal()) {
			return nil
		}
	}
	return ErrHostKeyMismatch
}
