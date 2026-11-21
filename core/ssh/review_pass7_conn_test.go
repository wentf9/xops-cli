package ssh

import (
	"bytes"
	"context"
	"crypto/dsa" //nolint:staticcheck // regression test for legacy ssh-dss CA signature rejection
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	cryptoSSH "golang.org/x/crypto/ssh"
)

type forcedAlgoCertCASigner struct {
	algSigner cryptoSSH.AlgorithmSigner
	algo      string
}

func (s forcedAlgoCertCASigner) PublicKey() cryptoSSH.PublicKey {
	return s.algSigner.PublicKey()
}

func (s forcedAlgoCertCASigner) Sign(randReader io.Reader, data []byte) (*cryptoSSH.Signature, error) {
	return s.algSigner.SignWithAlgorithm(randReader, data, s.algo)
}

func newPass7DSASigner(t *testing.T) cryptoSSH.Signer {
	t.Helper()
	var params dsa.Parameters
	if err := dsa.GenerateParameters(&params, rand.Reader, dsa.L1024N160); err != nil {
		t.Fatalf("dsa.GenerateParameters failed: %v", err)
	}
	priv := &dsa.PrivateKey{PublicKey: dsa.PublicKey{Parameters: params}}
	if err := dsa.GenerateKey(priv, rand.Reader); err != nil {
		t.Fatalf("dsa.GenerateKey failed: %v", err)
	}
	signer, err := cryptoSSH.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey(DSA) failed: %v", err)
	}
	return signer
}

func newPass7RSASigner(t *testing.T) (cryptoSSH.Signer, cryptoSSH.AlgorithmSigner) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}
	signer, err := cryptoSSH.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey(RSA) failed: %v", err)
	}
	algSigner, ok := signer.(cryptoSSH.AlgorithmSigner)
	if !ok {
		t.Fatalf("RSA signer %T does not implement AlgorithmSigner", signer)
	}
	return signer, algSigner
}

func newPass7Ed25519Signer(t *testing.T) cryptoSSH.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey failed: %v", err)
	}
	signer, err := cryptoSSH.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey(ed25519) failed: %v", err)
	}
	return signer
}

func formatKnownHostsCALine(pattern string, pub cryptoSSH.PublicKey) string {
	return "@cert-authority " + pattern + " " + strings.TrimSpace(string(cryptoSSH.MarshalAuthorizedKey(pub))) + "\n"
}

func TestPass7Conn_H1_HostCertCASignatureAlgorithmEnforcement(t *testing.T) {
	t.Run("unit_callback_rejects_weak_and_malformed_ca_signatures", func(t *testing.T) {
		assertPass7HostCertCASignatureCallback(t)
	})
	t.Run("connector_handshake_rejects_sha1_rsa_ca_and_accepts_sha2_rsa_ca", func(t *testing.T) {
		assertPass7ConnectorHandshakeCASignature(t)
	})
}

func assertPass7HostCertCASignatureCallback(t *testing.T) {
	t.Helper()
	_, rsaCAAlg := newPass7RSASigner(t)
	dsaCA := newPass7DSASigner(t)
	edCA := newPass7Ed25519Signer(t)
	hostSigner := newPass7Ed25519Signer(t)

	khText := formatKnownHostsCALine("*", rsaCAAlg.PublicKey()) +
		formatKnownHostsCALine("*", dsaCA.PublicKey()) +
		formatKnownHostsCALine("*", edCA.PublicKey())
	db := newKnownHostsDB()
	if err := db.readLines(strings.NewReader(khText), "known_hosts", nil); err != nil {
		t.Fatalf("readLines failed: %v", err)
	}
	cb := db.hostKeyCallback()
	remote := proxyEndpointAddr("127.0.0.1:22")

	// 1. RSA CA signing host cert with SHA-1 ("ssh-rsa") must be rejected.
	sha1Cert := signTestCert(t, hostSigner.PublicKey(), forcedAlgoCertCASigner{
		algSigner: rsaCAAlg,
		algo:      cryptoSSH.KeyAlgoRSA,
	}, cryptoSSH.HostCert, []string{"app.corp.example"})
	if sha1Cert.Signature.Format != cryptoSSH.KeyAlgoRSA {
		t.Fatalf("sha1Cert signature format = %q, want %q", sha1Cert.Signature.Format, cryptoSSH.KeyAlgoRSA)
	}
	if err := cb("app.corp.example:22", remote, sha1Cert); !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("SHA-1 RSA CA host cert = %v, want ErrHostKeyMismatch", err)
	}

	// 2. DSA CA ("ssh-dss") must be rejected.
	dssCert := signTestCert(t, hostSigner.PublicKey(), dsaCA, cryptoSSH.HostCert, []string{"app.corp.example"})
	if err := cb("app.corp.example:22", remote, dssCert); !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("DSA CA host cert = %v, want ErrHostKeyMismatch", err)
	}

	// 3. Missing CA signature and nested *-cert-v01* signature format must be rejected.
	nilSigCert := *signTestCert(t, hostSigner.PublicKey(), edCA, cryptoSSH.HostCert, []string{"app.corp.example"})
	nilSigCert.Signature = nil
	if err := cb("app.corp.example:22", remote, &nilSigCert); !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("nil-signature host cert = %v, want ErrHostKeyMismatch", err)
	}
	nestedFmtCert := *signTestCert(t, hostSigner.PublicKey(), edCA, cryptoSSH.HostCert, []string{"app.corp.example"})
	nestedSig := *nestedFmtCert.Signature
	nestedSig.Format = cryptoSSH.CertAlgoED25519v01
	nestedFmtCert.Signature = &nestedSig
	if err := cb("app.corp.example:22", remote, &nestedFmtCert); !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("nested cert format signature = %v, want ErrHostKeyMismatch", err)
	}

	// 4. Strong RSA SHA-2 (256 & 512) and Ed25519 CA signatures succeed on port 22 and 2222.
	for _, algo := range []string{cryptoSSH.KeyAlgoRSASHA256, cryptoSSH.KeyAlgoRSASHA512} {
		goodRSACert := signTestCert(t, hostSigner.PublicKey(), forcedAlgoCertCASigner{
			algSigner: rsaCAAlg,
			algo:      algo,
		}, cryptoSSH.HostCert, []string{"app.corp.example"})
		if err := cb("app.corp.example:22", remote, goodRSACert); err != nil {
			t.Fatalf("strong %s CA cert on port 22 failed: %v", algo, err)
		}
		if err := cb("[app.corp.example]:2222", proxyEndpointAddr("127.0.0.1:2222"), goodRSACert); err != nil {
			t.Fatalf("strong %s CA cert on port 2222 failed: %v", algo, err)
		}
	}
	goodEdCert := signTestCert(t, hostSigner.PublicKey(), edCA, cryptoSSH.HostCert, []string{"app.corp.example"})
	if err := cb("app.corp.example:22", remote, goodEdCert); err != nil {
		t.Fatalf("Ed25519 CA cert failed: %v", err)
	}
}

func assertPass7ConnectorHandshakeCASignature(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	_, rsaCAAlg := newPass7RSASigner(t)
	hostSigner := newPass7Ed25519Signer(t)

	weakCert := signTestCert(t, hostSigner.PublicKey(), forcedAlgoCertCASigner{
		algSigner: rsaCAAlg,
		algo:      cryptoSSH.KeyAlgoRSA,
	}, cryptoSSH.HostCert, []string{"127.0.0.1"})
	weakCertSigner, err := cryptoSSH.NewCertSigner(weakCert, hostSigner)
	if err != nil {
		t.Fatalf("NewCertSigner(weak) failed: %v", err)
	}
	weakPeer, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{HostKeys: []cryptoSSH.Signer{weakCertSigner}})
	if err != nil {
		t.Fatalf("sshfixture(weak) failed: %v", err)
	}
	t.Cleanup(func() { _ = weakPeer.Close() })

	strongCert := signTestCert(t, hostSigner.PublicKey(), forcedAlgoCertCASigner{
		algSigner: rsaCAAlg,
		algo:      cryptoSSH.KeyAlgoRSASHA512,
	}, cryptoSSH.HostCert, []string{"127.0.0.1"})
	strongCertSigner, err := cryptoSSH.NewCertSigner(strongCert, hostSigner)
	if err != nil {
		t.Fatalf("NewCertSigner(strong) failed: %v", err)
	}
	strongPeer, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{HostKeys: []cryptoSSH.Signer{strongCertSigner}})
	if err != nil {
		t.Fatalf("sshfixture(strong) failed: %v", err)
	}
	t.Cleanup(func() { _ = strongPeer.Close() })

	dir := t.TempDir()
	userKH := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(userKH, []byte(formatKnownHostsCALine("*", rsaCAAlg.PublicKey())), 0o600); err != nil {
		t.Fatal(err)
	}
	env := isolatedPass5Env(dir, userKH)

	wHost, _, wPort := splitFixtureHostPort(t, weakPeer.Address)
	for _, strict := range []string{"yes", "no"} {
		cfg := &ClientConfig{
			NodeID:   "weak-" + strict,
			Address:  wHost,
			Port:     wPort,
			User:     "fixture",
			AuthType: "password",
			Password: sshfixture.Password,
			Options: MustOptions(
				OptionStrictHostKeyChecking, strict,
				OptionUserKnownHostsFile, userKH,
				OptionGlobalKnownHostsFile, "none",
			),
		}
		conn := NewConnector(&mapConfigProvider{configs: map[string]*ClientConfig{cfg.NodeID: cfg}}, WithEnvironment(env))
		_, connErr := conn.Connect(ctx, cfg.NodeID)
		_ = conn.CloseAll()
		if !errors.Is(connErr, ErrHostKeyMismatch) {
			t.Fatalf("Connect(strict=%s) with SHA-1 RSA CA cert = %v, want ErrHostKeyMismatch", strict, connErr)
		}
	}

	sHost, _, sPort := splitFixtureHostPort(t, strongPeer.Address)
	strongCfg := &ClientConfig{
		NodeID:   "strong-ca",
		Address:  sHost,
		Port:     sPort,
		User:     "fixture",
		AuthType: "password",
		Password: sshfixture.Password,
		Options: MustOptions(
			OptionStrictHostKeyChecking, "yes",
			OptionUserKnownHostsFile, userKH,
			OptionGlobalKnownHostsFile, "none",
		),
	}
	conn := NewConnector(&mapConfigProvider{configs: map[string]*ClientConfig{"strong-ca": strongCfg}}, WithEnvironment(env))
	t.Cleanup(func() { _ = conn.CloseAll() })
	cli, err := conn.Connect(ctx, "strong-ca")
	if err != nil {
		t.Fatalf("Connect with rsa-sha2-512 CA cert failed: %v", err)
	}
	if _, err := cli.Run(ctx, "hostname"); err != nil {
		t.Fatalf("cli.Run failed: %v", err)
	}
}

func TestPass7Conn_H2_KnownHostsWildcardPortMatching(t *testing.T) {
	t.Run("openssh_put_host_port_and_negation_matrix", func(t *testing.T) {
		assertPass7KnownHostsPatternMatrix(t)
	})
	t.Run("cert_authority_wildcard_on_non22_port_orders_certs_and_blocks_tofu", func(t *testing.T) {
		assertPass7CertAuthorityWildcardNon22Port(t)
	})
}

func assertPass7KnownHostsPatternMatrix(t *testing.T) {
	t.Helper()
	cases := []struct {
		pattern string
		addr    khAddr
		want    bool
	}{
		{"*", khAddr{host: "app.corp.example.com", port: "22"}, true},
		{"*", khAddr{host: "app.corp.example.com", port: "2222"}, true},
		{"*", khAddr{host: "::1", port: "2222"}, true},
		{"*corp.example.com*", khAddr{host: "App.Corp.Example.Com", port: "2222"}, true},
		{"!*bad*", khAddr{host: "api.bad.example.com", port: "22"}, false},
		{"!*bad*", khAddr{host: "api.bad.example.com", port: "2222"}, false},
		{"*,!*", khAddr{host: "app.corp.example.com", port: "22"}, false},
		{"*,!*", khAddr{host: "app.corp.example.com", port: "2222"}, false},
		{"*,!*bad.corp*", khAddr{host: "good.corp", port: "2222"}, true},
		{"*,!*bad.corp*", khAddr{host: "evil.bad.corp", port: "22"}, false},
		{"*,!*bad.corp*", khAddr{host: "evil.bad.corp", port: "2222"}, false},
		{"*,!*.corp,![*.corp]:*", khAddr{host: "api.corp", port: "22"}, false},
		{"*,!*.corp,![*.corp]:*", khAddr{host: "api.corp", port: "2222"}, false},
		{"corp.example.com", khAddr{host: "corp.example.com", port: "22"}, true},
		{"corp.example.com", khAddr{host: "corp.example.com", port: "2222"}, false},
		{"[*.corp.example.com]:2222", khAddr{host: "api.corp.example.com", port: "2222"}, true},
		{"[*.corp.example.com]:2222", khAddr{host: "api.corp.example.com", port: "22"}, false},
	}
	for _, tc := range cases {
		m, err := newKHHostnameMatcher(tc.pattern)
		if err != nil {
			t.Fatalf("newKHHostnameMatcher(%q) failed: %v", tc.pattern, err)
		}
		if got := m.match(tc.addr); got != tc.want {
			t.Fatalf("pattern %q match(%+v) = %v, want %v", tc.pattern, tc.addr, got, tc.want)
		}
	}
}

func assertPass7CertAuthorityWildcardNon22Port(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	edCA := newPass7Ed25519Signer(t)
	hostSigner := newPass7Ed25519Signer(t)
	hostCert := signTestCert(t, hostSigner.PublicKey(), edCA, cryptoSSH.HostCert, []string{"127.0.0.1"})
	certSigner, err := cryptoSSH.NewCertSigner(hostCert, hostSigner)
	if err != nil {
		t.Fatal(err)
	}
	unpinnedPlain := newECDSAP256Signer(t)

	dualPeer, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		HostKeys: []cryptoSSH.Signer{unpinnedPlain, certSigner},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dualPeer.Close() })

	plainOnlyPeer, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		HostKeys: []cryptoSSH.Signer{unpinnedPlain},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = plainOnlyPeer.Close() })

	dir := t.TempDir()
	userKH := filepath.Join(dir, "known_hosts")
	initialKH := formatKnownHostsCALine("*", edCA.PublicKey())
	if err := os.WriteFile(userKH, []byte(initialKH), 0o600); err != nil {
		t.Fatal(err)
	}
	env := isolatedPass5Env(dir, userKH)

	dHost, _, dPort := splitFixtureHostPort(t, dualPeer.Address)
	if dPort == 22 {
		t.Fatalf("expected non-22 ephemeral port from sshfixture, got %d", dPort)
	}
	dualCfg := &ClientConfig{
		NodeID:   "dual-non22",
		Address:  dHost,
		Port:     dPort,
		User:     "fixture",
		AuthType: "password",
		Password: sshfixture.Password,
		Options: MustOptions(
			OptionStrictHostKeyChecking, "accept-new",
			OptionUserKnownHostsFile, userKH,
			OptionGlobalKnownHostsFile, "none",
		),
	}
	conn := NewConnector(&mapConfigProvider{configs: map[string]*ClientConfig{"dual-non22": dualCfg}}, WithEnvironment(env))
	t.Cleanup(func() { _ = conn.CloseAll() })

	algs, err := conn.getHostKeyAlgorithms(ctx, nil, dualCfg)
	if err != nil {
		t.Fatalf("getHostKeyAlgorithms failed: %v", err)
	}
	if len(algs) == 0 || !isCertAlgorithm(algs[0]) {
		t.Fatalf("expected cert algorithms promoted first for @cert-authority * on port %d, got %v", dPort, algs)
	}

	cli, err := conn.Connect(ctx, "dual-non22")
	if err != nil {
		t.Fatalf("Connect(dual-non22) with @cert-authority * failed: %v", err)
	}
	if _, err := cli.Run(ctx, "hostname"); err != nil {
		t.Fatalf("cli.Run(dual-non22) failed: %v", err)
	}

	// Plain-only peer on non-22 port must NOT bypass @cert-authority * via accept-new TOFU.
	pHost, _, pPort := splitFixtureHostPort(t, plainOnlyPeer.Address)
	plainCfg := &ClientConfig{
		NodeID:   "plain-non22",
		Address:  pHost,
		Port:     pPort,
		User:     "fixture",
		AuthType: "password",
		Password: sshfixture.Password,
		Options: MustOptions(
			OptionStrictHostKeyChecking, "accept-new",
			OptionUserKnownHostsFile, userKH,
			OptionGlobalKnownHostsFile, "none",
		),
	}
	plainConn := NewConnector(&mapConfigProvider{configs: map[string]*ClientConfig{"plain-non22": plainCfg}}, WithEnvironment(env))
	_, plainErr := plainConn.Connect(ctx, "plain-non22")
	_ = plainConn.CloseAll()
	if !errors.Is(plainErr, ErrHostKeyMismatch) {
		t.Fatalf("Connect(plain-non22) under accept-new + @cert-authority * = %v, want ErrHostKeyMismatch", plainErr)
	}
	afterKH, err := os.ReadFile(userKH)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterKH) != initialKH {
		t.Fatalf("known_hosts was unexpectedly modified:\ngot:  %q\nwant: %q", string(afterKH), initialKH)
	}
}

func countStuckCryptoSSHLoopGoroutines() int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			stacks := string(buf[:n])
			count := 0
			for block := range strings.SplitSeq(stacks, "\n\n") {
				if strings.Contains(block, "golang.org/x/crypto/ssh.(*mux).loop") ||
					strings.Contains(block, "golang.org/x/crypto/ssh.(*handshakeTransport).readLoop") ||
					strings.Contains(block, "golang.org/x/crypto/ssh.(*handshakeTransport).kexLoop") {
					count++
				}
			}
			return count
		}
		buf = make([]byte, len(buf)*2)
	}
}

func assertNoCryptoSSHLoopGoroutineLeak(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		cur := countStuckCryptoSSHLoopGoroutines()
		if cur <= baseline {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("leaked x/crypto/ssh mux/transport goroutines: baseline=%d, current=%d", baseline, cur)
		}
		time.Sleep(15 * time.Millisecond)
	}
}

func encodeRawControlProxyFrame(payload []byte) []byte {
	// x/crypto/ssh controlProxyTransport framing: [uint32 length][0x00 paddingLen][payload]
	pkt := make([]byte, 4+1+len(payload))
	binary.BigEndian.PutUint32(pkt[0:4], uint32(1+len(payload)))
	pkt[4] = 0
	copy(pkt[5:], payload)
	return pkt
}

func buildPipelinedControlProxyBurst(count int) []byte {
	// SSH_MSG_GLOBAL_REQUEST (80): byte(80) + string("keepalive@openssh.com") + bool(true)
	reqWriter := newMuxWriter()
	reqWriter.buf = append(reqWriter.buf, 80)
	reqWriter.WriteString("keepalive@openssh.com")
	reqWriter.WriteBool(true)
	globalFrame := encodeRawControlProxyFrame(reqWriter.Bytes())

	// SSH_MSG_CHANNEL_OPEN (90): byte(90) + string("forwarded-tcpip") + uint32(senderID) + uint32(win) + uint32(maxPkt)
	var out bytes.Buffer
	for i := range count {
		out.Write(globalFrame)
		chWriter := newMuxWriter()
		chWriter.buf = append(chWriter.buf, 90)
		chWriter.WriteString("forwarded-tcpip")
		chWriter.WriteUint32(uint32(i + 1))
		chWriter.WriteUint32(65536)
		chWriter.WriteUint32(32768)
		out.Write(encodeRawControlProxyFrame(chWriter.Bytes()))
	}
	return out.Bytes()
}

func TestPass7Conn_M1_AbortedSSHConnDrainsPipelinedFramesWithoutLeak(t *testing.T) {
	t.Run("dial_control_proxy_mismatch_and_cancel_drain_pipelined_frames", func(t *testing.T) {
		assertPass7DialControlProxyAbortNoLeak(t)
	})
	t.Run("connector_dial_and_handshake_abort_drains_pipelined_frames", func(t *testing.T) {
		assertPass7ConnectorHandshakeAbortNoLeak(t)
	})
}

func assertPass7DialControlProxyAbortNoLeak(t *testing.T) {
	t.Helper()
	baseline := countStuckCryptoSSHLoopGoroutines()
	burst := buildPipelinedControlProxyBurst(24) // 24 global + 24 channel-open frames (> 16 buffer)

	// Subcase 1: Direct deterministic 17th-frame mux.loop saturation on NewControlClientConn + abortUnclaimedSSHConn.
	sockRaw, lnRaw := createTestUnixSocket(t)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := lnRaw.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _, _ = ReadMuxPacket(c)
		_ = WriteMuxPacket(c, MUX_MSG_HELLO, EncodeMuxHello(MuxProtoVersion, nil))
		pktType, payload, err := ReadMuxPacket(c)
		if err != nil || pktType != MUX_C_PROXY {
			return
		}
		reqID, _ := DecodeMuxRequestID(payload)
		var combined bytes.Buffer
		_ = WriteMuxPacket(&combined, MUX_S_PROXY, EncodeMuxClientRequestID(reqID))
		combined.Write(burst)
		_, _ = c.Write(combined.Bytes())
	}()
	clientRaw, err := net.Dial("unix", sockRaw)
	if err != nil {
		t.Fatalf("net.Dial(unix) failed: %v", err)
	}
	sshConn, chans, reqs, err := cryptoSSH.NewControlClientConn(clientRaw)
	if err != nil {
		_ = clientRaw.Close()
		t.Fatalf("NewControlClientConn failed: %v", err)
	}
	time.Sleep(30 * time.Millisecond) // allow mux.loop to block on the 17th incoming frame
	_ = abortUnclaimedSSHConn(sshConn, chans, reqs)
	_ = clientRaw.Close()
	wg.Wait()

	// Subcase 2: Target mismatch via muxTargetExtensionName in HELLO + 24 pipelined frames.
	sockExtMismatch, lnExtMismatch := createTestUnixSocket(t)
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, acceptErr := lnExtMismatch.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _, _ = ReadMuxPacket(c)
		otherTarget := (TargetContext{Host: "other.example", Port: 22, User: "evil"}).CanonicalTargetIdentity()
		exts := []MuxExtension{{Name: muxTargetExtensionName, Value: otherTarget}}
		_ = WriteMuxPacket(c, MUX_MSG_HELLO, EncodeMuxHello(MuxProtoVersion, exts))
		_, payload, readErr := ReadMuxPacket(c)
		if readErr != nil {
			return
		}
		reqID, _ := DecodeMuxRequestID(payload)
		var combined bytes.Buffer
		_ = WriteMuxPacket(&combined, MUX_S_PROXY, EncodeMuxClientRequestID(reqID))
		combined.Write(burst)
		_, _ = c.Write(combined.Bytes())
	}()

	_, _, err = DialControlProxy(t.Context(), sockExtMismatch, TargetContext{Host: "expected.example", Port: 22, User: "ops"})
	if !errors.Is(err, ErrControlTargetMismatch) {
		t.Fatalf("DialControlProxy mismatch err = %v, want ErrControlTargetMismatch", err)
	}
	wg.Wait()

	// Subcase 3: Context canceled right as MUX_S_PROXY + 24 pipelined frames arrive.
	sockCancel, lnCancel := createTestUnixSocket(t)
	ctx, cancel := context.WithCancel(t.Context())
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, acceptErr := lnCancel.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _, _ = ReadMuxPacket(c)
		_ = WriteMuxPacket(c, MUX_MSG_HELLO, EncodeMuxHello(MuxProtoVersion, nil))
		_, payload, readErr := ReadMuxPacket(c)
		if readErr != nil {
			return
		}
		reqID, _ := DecodeMuxRequestID(payload)
		var combined bytes.Buffer
		_ = WriteMuxPacket(&combined, MUX_S_PROXY, EncodeMuxClientRequestID(reqID))
		combined.Write(burst)
		_, _ = c.Write(combined.Bytes())
		cancel()
	}()
	if cli, proxyConn, dialErr := DialControlProxy(ctx, sockCancel, TargetContext{}); dialErr == nil {
		_ = cli.Close()
		_ = proxyConn.Close()
	}
	wg.Wait()

	assertNoCryptoSSHLoopGoroutineLeak(t, baseline)
}

type postHandshakeHookConn struct {
	net.Conn
	onClearDeadline func() error
}

func (c *postHandshakeHookConn) SetDeadline(t time.Time) error {
	if t.IsZero() && c.onClearDeadline != nil {
		if err := c.onClearDeadline(); err != nil {
			return err
		}
	}
	return c.Conn.SetDeadline(t)
}

type funcDialer func(ctx context.Context, network, addr string) (net.Conn, error)

func (f funcDialer) Dial(network, addr string) (net.Conn, error) {
	return f(context.Background(), network, addr)
}

func (f funcDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return f(ctx, network, addr)
}

func startBurstingSSHServer(t *testing.T, hostKey cryptoSSH.Signer) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	srvCfg := &cryptoSSH.ServerConfig{
		PasswordCallback: func(_ cryptoSSH.ConnMetadata, pwd []byte) (*cryptoSSH.Permissions, error) {
			if string(pwd) == sshfixture.Password {
				return &cryptoSSH.Permissions{}, nil
			}
			return nil, errors.New("bad password")
		},
	}
	srvCfg.AddHostKey(hostKey)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			raw, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			wg.Add(1)
			go func(nc net.Conn) {
				defer wg.Done()
				defer func() { _ = nc.Close() }()
				sc, chans, reqs, hsErr := cryptoSSH.NewServerConn(nc, srvCfg)
				if hsErr != nil {
					return
				}
				defer func() { _ = sc.Close() }()
				go cryptoSSH.DiscardRequests(reqs)
				go func() {
					for ch := range chans {
						_ = ch.Reject(cryptoSSH.Prohibited, "test")
					}
				}()
				// Pipeline > 17 global requests and channel opens immediately on auth completion.
				var burstWG sync.WaitGroup
				for range 24 {
					burstWG.Add(2)
					go func() {
						defer burstWG.Done()
						_, _, _ = sc.SendRequest("keepalive@openssh.com", true, nil)
					}()
					go func() {
						defer burstWG.Done()
						ch, chReqs, openErr := sc.OpenChannel("forwarded-tcpip", make([]byte, 16))
						if openErr == nil {
							go cryptoSSH.DiscardRequests(chReqs)
							_ = ch.Close()
						}
					}()
				}
				burstWG.Wait()
			}(raw)
		}
	}()

	cleanup := func() {
		_ = ln.Close()
		wg.Wait()
	}
	return ln.Addr().String(), cleanup
}

func assertPass7ConnectorHandshakeAbortNoLeak(t *testing.T) {
	t.Helper()
	baseline := countStuckCryptoSSHLoopGoroutines()
	hostSigner := newPass7Ed25519Signer(t)
	addr, stopSrv := startBurstingSSHServer(t, hostSigner)
	defer stopSrv()

	host, _, port := splitFixtureHostPort(t, addr)
	cfg := &ClientConfig{
		NodeID:   "burst-node",
		Address:  host,
		Port:     port,
		User:     "fixture",
		AuthType: "password",
		Password: sshfixture.Password,
	}

	// Path A: Clear-deadline failure right after ssh.NewClientConn succeeds + peer pipelines 48 frames.
	injectedErr := errors.New("injected clear-deadline failure")
	dialerClearErr := funcDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		nc, err := d.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &postHandshakeHookConn{
			Conn: nc,
			onClearDeadline: func() error {
				time.Sleep(30 * time.Millisecond) // allow server burst to fill chans/reqs
				return injectedErr
			},
		}, nil
	})
	connA := NewConnector(
		&mapConfigProvider{configs: map[string]*ClientConfig{"burst-node": cfg}},
		WithDialer(dialerClearErr),
		WithHostKeyVerifier(stubHostKeyVerifier{acceptKey: hostSigner.PublicKey()}),
		WithEnvironment(isolatedPass5Env(t.TempDir(), filepath.Join(t.TempDir(), "kh"))),
	)
	_, errA := connA.Connect(t.Context(), "burst-node")
	_ = connA.CloseAll()
	if !errors.Is(errA, injectedErr) {
		t.Fatalf("clear-deadline abort err = %v, want %v", errA, injectedErr)
	}

	// Path B: Coordinator/connector context canceled right after ssh.NewClientConn succeeds.
	var connB *Connector
	dialerCancel := funcDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		nc, err := d.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &postHandshakeHookConn{
			Conn: nc,
			onClearDeadline: func() error {
				time.Sleep(30 * time.Millisecond)
				// Trigger coordinator context cancellation via CloseAll mid-post-handshake.
				go func() { _ = connB.CloseAll() }()
				time.Sleep(20 * time.Millisecond)
				return nil
			},
		}, nil
	})
	connB = NewConnector(
		&mapConfigProvider{configs: map[string]*ClientConfig{"burst-node": cfg}},
		WithDialer(dialerCancel),
		WithHostKeyVerifier(stubHostKeyVerifier{acceptKey: hostSigner.PublicKey()}),
		WithEnvironment(isolatedPass5Env(t.TempDir(), filepath.Join(t.TempDir(), "kh"))),
	)
	_, _ = connB.Connect(t.Context(), "burst-node")
	_ = connB.CloseAll()

	assertNoCryptoSSHLoopGoroutineLeak(t, baseline)
}

type muxRPCCase struct {
	name      string
	call      func(ctx context.Context, c *MuxClient) error
	badReply  func(reqID uint32) (uint32, []byte)
	goodReply func(reqID uint32) (uint32, []byte)
}

func pass7MuxRPCCases() []muxRPCCase {
	fwd := ForwardRequest{
		Type:        ForwardRemote,
		ListenHost:  "127.0.0.1",
		ListenPort:  0,
		ConnectHost: "127.0.0.1",
		ConnectPort: 8080,
	}
	return []muxRPCCase{
		{
			name:      "AliveCheck",
			call:      func(ctx context.Context, c *MuxClient) error { _, err := c.AliveCheck(ctx); return err },
			badReply:  func(reqID uint32) (uint32, []byte) { return MUX_S_ALIVE, EncodeMuxAlive(reqID+77, 1234) },
			goodReply: func(reqID uint32) (uint32, []byte) { return MUX_S_ALIVE, EncodeMuxAlive(reqID, 1234) },
		},
		{
			name:      "Terminate",
			call:      func(ctx context.Context, c *MuxClient) error { return c.Terminate(ctx) },
			badReply:  func(reqID uint32) (uint32, []byte) { return MUX_S_OK, EncodeMuxClientRequestID(reqID + 77) },
			goodReply: func(reqID uint32) (uint32, []byte) { return MUX_S_OK, EncodeMuxClientRequestID(reqID) },
		},
		{
			name:      "StopListening",
			call:      func(ctx context.Context, c *MuxClient) error { return c.StopListening(ctx) },
			badReply:  func(reqID uint32) (uint32, []byte) { return MUX_S_OK, EncodeMuxClientRequestID(reqID + 77) },
			goodReply: func(reqID uint32) (uint32, []byte) { return MUX_S_OK, EncodeMuxClientRequestID(reqID) },
		},
		{
			name: "OpenForward",
			call: func(ctx context.Context, c *MuxClient) error { _, err := c.OpenForward(ctx, fwd); return err },
			badReply: func(reqID uint32) (uint32, []byte) {
				return MUX_S_REMOTE_PORT, EncodeMuxRemotePort(reqID+77, 45678)
			},
			goodReply: func(reqID uint32) (uint32, []byte) {
				return MUX_S_REMOTE_PORT, EncodeMuxRemotePort(reqID, 45678)
			},
		},
		{
			name:      "CloseForward",
			call:      func(ctx context.Context, c *MuxClient) error { return c.CloseForward(ctx, fwd) },
			badReply:  func(reqID uint32) (uint32, []byte) { return MUX_S_OK, EncodeMuxClientRequestID(reqID + 77) },
			goodReply: func(reqID uint32) (uint32, []byte) { return MUX_S_OK, EncodeMuxClientRequestID(reqID) },
		},
		{
			name: "RequestInfo",
			call: func(ctx context.Context, c *MuxClient) error { _, err := c.RequestInfo(ctx, "connection"); return err },
			badReply: func(reqID uint32) (uint32, []byte) {
				return MUX_S_EXT_INFO, EncodeMuxExtInfoResponse(reqID+77, 1, "ok")
			},
			goodReply: func(reqID uint32) (uint32, []byte) {
				return MUX_S_EXT_INFO, EncodeMuxExtInfoResponse(reqID, 1, "ok")
			},
		},
	}
}

func dialSocketMuxClientForTest(t *testing.T, withInfoExt bool) (*MuxClient, net.Conn) {
	t.Helper()
	sockPath, ln := createTestUnixSocket(t)
	srvCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(srvCh)
			return
		}
		srvCh <- c
	}()
	clientConn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("net.Dial(unix) failed: %v", err)
	}
	serverConn := <-srvCh
	if serverConn == nil {
		_ = clientConn.Close()
		t.Fatal("failed to accept test unix connection")
	}
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})
	exts := map[string]string{}
	if withInfoExt {
		exts["info"] = "1"
	}
	mc := &MuxClient{
		socketPath: sockPath,
		conn:       clientConn,
		serverVer:  MuxProtoVersion,
		extensions: exts,
	}
	return mc, serverConn
}

func extractMuxReqIDFromPayload(payload []byte) uint32 {
	if len(payload) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32(payload[:4])
}

func TestPass7Conn_M2_MuxClientUnifiedRPCHelper(t *testing.T) {
	t.Run("all_six_rpcs_wrap_ctx_err_and_close_conn_on_cancel_or_deadline", func(t *testing.T) {
		assertPass7MuxRPCCancelAndDeadline(t)
	})
	t.Run("all_six_rpcs_check_resp_id_and_poison_conn_on_protocol_errors", func(t *testing.T) {
		assertPass7MuxRPCRespIDMismatchAndPoison(t)
	})
	t.Run("clean_server_rejections_preserve_conn_for_subsequent_rpcs", func(t *testing.T) {
		assertPass7MuxRPCCleanRejectionKeepsConnAlive(t)
	})
}

func assertPass7MuxRPCCancelAndDeadline(t *testing.T) {
	t.Helper()
	for _, tc := range pass7MuxRPCCases() {
		// 1. Mid-RPC context cancellation wraps context.Canceled and closes m.conn.
		mcCancel, srvCancel := dialSocketMuxClientForTest(t, true)
		ctxCancel, cancel := context.WithCancel(t.Context())
		go func(srv net.Conn) {
			_, _, err := ReadMuxPacket(srv)
			if err == nil {
				cancel()
			}
		}(srvCancel)
		err := tc.call(ctxCancel, mcCancel)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("%s mid-RPC cancel err = %v, want context.Canceled", tc.name, err)
		}
		if !mcCancel.closed.Load() {
			t.Fatalf("%s did not close MuxClient on I/O cancel failure", tc.name)
		}
		if _, afterErr := mcCancel.AliveCheck(t.Context()); !errors.Is(afterErr, net.ErrClosed) {
			t.Fatalf("%s subsequent AliveCheck after poisoned conn = %v, want net.ErrClosed", tc.name, afterErr)
		}

		// 2. Mid-RPC deadline expiration wraps context.DeadlineExceeded and closes m.conn.
		mcDeadline, srvDeadline := dialSocketMuxClientForTest(t, true)
		go func(srv net.Conn) {
			_, _, _ = ReadMuxPacket(srv)
		}(srvDeadline)
		ctxDeadline, cancelDeadline := context.WithTimeout(t.Context(), 35*time.Millisecond)
		errDeadline := tc.call(ctxDeadline, mcDeadline)
		cancelDeadline()
		if !errors.Is(errDeadline, context.DeadlineExceeded) {
			t.Fatalf("%s deadline err = %v, want context.DeadlineExceeded", tc.name, errDeadline)
		}
		if !mcDeadline.closed.Load() {
			t.Fatalf("%s did not close MuxClient on deadline timeout", tc.name)
		}
	}
}

func assertPass7MuxRPCRespIDMismatchAndPoison(t *testing.T) {
	t.Helper()
	for _, tc := range pass7MuxRPCCases() {
		// 1. Mismatched respID in positive reply closes m.conn.
		mcBadOK, srvBadOK := dialSocketMuxClientForTest(t, true)
		go func(srv net.Conn, replyFn func(uint32) (uint32, []byte)) {
			_, payload, err := ReadMuxPacket(srv)
			if err != nil {
				return
			}
			msgType, resp := replyFn(extractMuxReqIDFromPayload(payload))
			_ = WriteMuxPacket(srv, msgType, resp)
		}(srvBadOK, tc.badReply)

		err := tc.call(t.Context(), mcBadOK)
		if err == nil || !strings.Contains(err.Error(), "request id mismatch") {
			t.Fatalf("%s bad respID err = %v, want request id mismatch", tc.name, err)
		}
		if !mcBadOK.closed.Load() {
			t.Fatalf("%s did not close MuxClient on respID mismatch", tc.name)
		}

		// 2. Mismatched respID in MUX_S_FAILURE reply ALSO closes m.conn.
		mcBadErr, srvBadErr := dialSocketMuxClientForTest(t, true)
		go func(srv net.Conn) {
			_, payload, readErr := ReadMuxPacket(srv)
			if readErr != nil {
				return
			}
			reqID := extractMuxReqIDFromPayload(payload)
			_ = WriteMuxPacket(srv, MUX_S_FAILURE, EncodeMuxError(reqID+99, "stale failure"))
		}(srvBadErr)

		errRej := tc.call(t.Context(), mcBadErr)
		if errRej == nil || !strings.Contains(errRej.Error(), "request id mismatch") {
			t.Fatalf("%s MUX_S_FAILURE bad respID err = %v, want request id mismatch", tc.name, errRej)
		}
		if !mcBadErr.closed.Load() {
			t.Fatalf("%s did not close MuxClient on MUX_S_FAILURE respID mismatch", tc.name)
		}

		// 3. Unexpected opcode closes m.conn.
		mcUnexpected, srvUnexpected := dialSocketMuxClientForTest(t, true)
		go func(srv net.Conn) {
			_, _, readErr := ReadMuxPacket(srv)
			if readErr != nil {
				return
			}
			_ = WriteMuxPacket(srv, 0xdeadbeef, []byte{0, 0, 0, 1})
		}(srvUnexpected)
		if unexpErr := tc.call(t.Context(), mcUnexpected); unexpErr == nil || !mcUnexpected.closed.Load() {
			t.Fatalf("%s unexpected opcode err=%v closed=%v, want non-nil and closed=true", tc.name, unexpErr, mcUnexpected.closed.Load())
		}
	}
}

func assertPass7MuxRPCCleanRejectionKeepsConnAlive(t *testing.T) {
	t.Helper()
	mc, srv := dialSocketMuxClientForTest(t, true)
	cases := pass7MuxRPCCases()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range cases {
			_, payload, err := ReadMuxPacket(srv)
			if err != nil {
				return
			}
			reqID := extractMuxReqIDFromPayload(payload)
			errType := MUX_S_FAILURE
			if i%2 == 1 {
				errType = MUX_S_PERMISSION_DENIED
			}
			_ = WriteMuxPacket(srv, errType, EncodeMuxError(reqID, "denied cleanly"))
		}
		// RequestInfo status=0 clean application error:
		_, payload, err := ReadMuxPacket(srv)
		if err != nil {
			return
		}
		reqID := extractMuxReqIDFromPayload(payload)
		_ = WriteMuxPacket(srv, MUX_S_EXT_INFO, EncodeMuxExtInfoResponse(reqID, 0, "unknown topic"))

		// Final AliveCheck succeeds on the exact same connection!
		_, payload, err = ReadMuxPacket(srv)
		if err != nil {
			return
		}
		reqID = extractMuxReqIDFromPayload(payload)
		_ = WriteMuxPacket(srv, MUX_S_ALIVE, EncodeMuxAlive(reqID, 4242))
	}()

	for _, tc := range cases {
		err := tc.call(t.Context(), mc)
		if err == nil || !strings.Contains(err.Error(), "denied cleanly") {
			t.Fatalf("%s clean rejection err = %v, want 'denied cleanly'", tc.name, err)
		}
		if mc.closed.Load() {
			t.Fatalf("%s closed MuxClient on clean server rejection", tc.name)
		}
	}
	if _, err := mc.RequestInfo(t.Context(), "unknown"); err == nil || mc.closed.Load() {
		t.Fatalf("RequestInfo(status=0) err=%v closed=%v, want error with closed=false", err, mc.closed.Load())
	}
	pid, err := mc.AliveCheck(t.Context())
	if err != nil || pid != 4242 {
		t.Fatalf("AliveCheck after clean rejections = (%d, %v), want (4242, nil)", pid, err)
	}
	wg.Wait()
}

func TestPass7Conn_M3_ConnectorPrunesClosedMuxServers(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	peer, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })

	host, _, port := splitFixtureHostPort(t, peer.Address)
	sockPath := filepath.Join(shortSocketDir(t), "m3-prune.sock")
	provider := &multiNodeMuxProvider{
		cfgs: map[string]*ClientConfig{
			"openssh:app": {
				NodeID:       "openssh:app",
				OriginalHost: "app.canonical.example",
				Address:      host,
				Port:         port,
				User:         "fixture",
				AuthType:     "password",
				Password:     sshfixture.Password,
			},
		},
		ctrls: map[string]*ControlConfig{
			"openssh:app": {Master: ControlMasterAuto, Path: sockPath, Persist: "30s"},
		},
	}

	conn := NewConnector(
		provider,
		WithEnvironment(isolatedPass5Env(t.TempDir(), filepath.Join(t.TempDir(), "kh"))),
		WithHostKeyVerifier(stubHostKeyVerifier{acceptKey: peer.HostKey}),
	)
	t.Cleanup(func() { _ = conn.CloseAll() })

	cli1, err := conn.Connect(ctx, "openssh:app")
	if err != nil {
		t.Fatalf("first Connect failed: %v", err)
	}
	masters1 := conn.Masters()
	if len(masters1) != 1 {
		t.Fatalf("len(Masters()) after first Connect = %d, want 1", len(masters1))
	}
	server1 := masters1[0]
	if !conn.OwnsMaster(server1) || !conn.HasMasterSession(server1) || conn.MasterNodeID(server1) != "openssh:app" {
		t.Fatalf("unexpected server1 ownership before Shutdown: owns=%v session=%v nodeID=%q",
			conn.OwnsMaster(server1), conn.HasMasterSession(server1), conn.MasterNodeID(server1))
	}

	if err := server1.Shutdown(); err != nil {
		t.Fatalf("server1.Shutdown() failed: %v", err)
	}
	_ = cli1.Close()

	if got := conn.Masters(); len(got) != 0 {
		t.Fatalf("len(Masters()) after server1.Shutdown() = %d, want 0", len(got))
	}
	if conn.OwnsMaster(server1) {
		t.Fatal("OwnsMaster(server1) = true after Shutdown, want false")
	}
	if conn.HasMasterSession(server1) {
		t.Fatal("HasMasterSession(server1) = true after Shutdown, want false")
	}
	if got := conn.MasterNodeID(server1); got != "" {
		t.Fatalf("MasterNodeID(server1) after Shutdown = %q, want empty", got)
	}
	if conn.ReleaseMaster(server1) || conn.AcquireMaster(server1) {
		t.Fatal("ReleaseMaster/AcquireMaster succeeded on shut-down server1")
	}

	// Reconnect on the same Connector: server2 must be the sole entry in Masters() at index 0.
	cli2, err := conn.Connect(ctx, "openssh:app")
	if err != nil {
		t.Fatalf("second Connect failed: %v", err)
	}
	if _, err := cli2.Run(ctx, "hostname"); err != nil {
		t.Fatalf("cli2.Run failed: %v", err)
	}
	masters2 := conn.Masters()
	if len(masters2) != 1 {
		t.Fatalf("len(Masters()) after reconnect = %d, want 1", len(masters2))
	}
	server2 := masters2[0]
	if server2 == server1 {
		t.Fatal("expected fresh MuxServer instance on reconnect")
	}
	if !conn.OwnsMaster(server2) || conn.MasterNodeID(server2) != "openssh:app" {
		t.Fatalf("unexpected server2 ownership: owns=%v nodeID=%q", conn.OwnsMaster(server2), conn.MasterNodeID(server2))
	}
}

type syncedConfigStore struct {
	mu   sync.Mutex
	cfgs map[string]*ClientConfig
}

func (s *syncedConfigStore) GetConfig(nodeID string) (*ClientConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, ok := s.cfgs[nodeID]
	if !ok || cfg == nil {
		return nil, nil
	}
	cp := *cfg
	return &cp, nil
}

func TestPass7Conn_L1_MultiHopFirstHopProxyCommandSnapshotValidation(t *testing.T) {
	store := &syncedConfigStore{
		cfgs: map[string]*ClientConfig{
			"openssh:first": {
				NodeID:               "openssh:first",
				Address:              "192.0.2.1",
				Port:                 22,
				User:                 "jump1",
				ProxyJump:            "",
				OriginalProxyJump:    "ignored-upstream",
				HasOriginalProxyJump: true,
				Options:              MustOptions(OptionProxyCommand, "nc %h %p"),
			},
			"openssh:second": {
				NodeID:  "openssh:second",
				Address: "192.0.2.2",
				Port:    22,
				User:    "jump2",
			},
			"target": {
				NodeID:    "target",
				Address:   "192.0.2.3",
				Port:      22,
				User:      "app",
				ProxyJump: "openssh:first, openssh:second",
			},
		},
	}

	connector := newTestConnector(store)
	t.Cleanup(func() { _ = connector.CloseAll() })

	plan, err := connector.resolveConnectionPlan(t.Context(), "target")
	if err != nil {
		t.Fatalf("resolveConnectionPlan failed: %v", err)
	}
	firstHop := plan[2].cfg
	if firstHop.ProxyJump != "" || firstHop.OriginalProxyJump != "ignored-upstream" {
		t.Fatalf("unexpected firstHop jump fields: ProxyJump=%q OriginalProxyJump=%q", firstHop.ProxyJump, firstHop.OriginalProxyJump)
	}
	cur := firstHop.ToConnectionConfig()

	// 1. Unchanged raw provider config (ProxyJump="ignored-upstream") and planned config (ProxyJump="") both pass.
	rawUnchanged, _ := store.GetConfig("openssh:first")
	if err := checkTargetDigestCompatibility(cur, rawUnchanged); err != nil {
		t.Fatalf("unchanged raw provider config failed compatibility check: %v", err)
	}
	plannedUnchanged := *firstHop
	if err := checkTargetDigestCompatibility(cur, &plannedUnchanged); err != nil {
		t.Fatalf("unchanged planned config failed compatibility check: %v", err)
	}

	// 2. Drifted ProxyCommand on raw provider config AND planned config must fail with ErrSnapshotMismatch.
	rawDrifted := *rawUnchanged
	rawDrifted.Options = MustOptions(OptionProxyCommand, "evil-proxy %h %p")
	if err := checkTargetDigestCompatibility(cur, &rawDrifted); !errors.Is(err, ErrSnapshotMismatch) {
		t.Fatalf("drifted ProxyCommand on raw provider config = %v, want ErrSnapshotMismatch", err)
	}

	plannedDrifted := *firstHop
	plannedDrifted.Options = MustOptions(OptionProxyCommand, "evil-proxy %h %p")
	if err := checkTargetDigestCompatibility(cur, &plannedDrifted); !errors.Is(err, ErrSnapshotMismatch) {
		t.Fatalf("drifted ProxyCommand on planned config = %v, want ErrSnapshotMismatch", err)
	}

	// 3. End-to-end Connector.Connect detects mid-handshake ProxyCommand drift on multi-hop first hop.
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	firstPeer, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = firstPeer.Close() })

	fHost, _, fPort := splitFixtureHostPort(t, firstPeer.Address)
	liveStore := &syncedConfigStore{
		cfgs: map[string]*ClientConfig{
			"openssh:first": {
				NodeID:               "openssh:first",
				Address:              fHost,
				Port:                 fPort,
				User:                 "fixture",
				AuthType:             "password",
				Password:             sshfixture.Password,
				ProxyJump:            "",
				OriginalProxyJump:    "ignored-upstream",
				HasOriginalProxyJump: true,
				Options:              MustOptions(OptionProxyCommand, "nc %h %p"),
			},
			"openssh:second": {
				NodeID:  "openssh:second",
				Address: "127.0.0.1",
				Port:    22,
				User:    "fixture",
			},
			"target": {
				NodeID:    "target",
				Address:   "127.0.0.1",
				Port:      22,
				User:      "fixture",
				ProxyJump: "openssh:first, openssh:second",
			},
		},
	}

	env := isolatedPass5Env(t.TempDir(), filepath.Join(t.TempDir(), "kh"))
	env.DialProxyCommand = func(dialCtx context.Context, _ string) (net.Conn, error) {
		// Mutate openssh:first's ProxyCommand in the store while first hop handshake is in flight.
		liveStore.mu.Lock()
		drifted := *liveStore.cfgs["openssh:first"]
		drifted.Options = MustOptions(OptionProxyCommand, "tampered-cmd %h %p")
		liveStore.cfgs["openssh:first"] = &drifted
		liveStore.mu.Unlock()
		var d net.Dialer
		return d.DialContext(dialCtx, "tcp", firstPeer.Address)
	}

	liveConn := NewConnector(
		liveStore,
		WithEnvironment(env),
		WithHostKeyVerifier(stubHostKeyVerifier{acceptKey: firstPeer.HostKey}),
	)
	t.Cleanup(func() { _ = liveConn.CloseAll() })

	_, connectErr := liveConn.Connect(ctx, "target")
	if !errors.Is(connectErr, ErrSnapshotMismatch) {
		t.Fatalf("Connect(target) with mid-handshake first-hop ProxyCommand drift = %v, want ErrSnapshotMismatch", connectErr)
	}
}
