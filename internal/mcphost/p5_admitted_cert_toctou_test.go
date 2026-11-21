package mcphost

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	corepolicy "github.com/wentf9/xops-cli/core/mcp/policy"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/mcp/transfer"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type p5AuthObserver struct {
	mu          sync.Mutex
	certSerials []uint64
	plainKeyFPs []string
	authedKeys  []string
}

func (o *p5AuthObserver) recordAttempt(key cryptoSSH.PublicKey) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if cert, ok := key.(*cryptoSSH.Certificate); ok {
		o.certSerials = append(o.certSerials, cert.Serial)
		return
	}
	o.plainKeyFPs = append(o.plainKeyFPs, cryptoSSH.FingerprintSHA256(key))
}

func (o *p5AuthObserver) recordAuth(key cryptoSSH.PublicKey) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if cert, ok := key.(*cryptoSSH.Certificate); ok {
		o.authedKeys = append(o.authedKeys, fmt.Sprintf("cert:%d", cert.Serial))
		return
	}
	o.authedKeys = append(o.authedKeys, "key:"+cryptoSSH.FingerprintSHA256(key))
}

func (o *p5AuthObserver) snapshot() (serials []uint64, plainFPs []string, authed []string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]uint64(nil), o.certSerials...),
		append([]string(nil), o.plainKeyFPs...),
		append([]string(nil), o.authedKeys...)
}

func p5NewEd25519KeyPair(t *testing.T, comment string) (keyPEM []byte, signer cryptoSSH.Signer) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	signer, err = cryptoSSH.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("cryptoSSH.NewSignerFromKey: %v", err)
	}
	block, err := cryptoSSH.MarshalPrivateKey(priv, comment)
	if err != nil {
		t.Fatalf("cryptoSSH.MarshalPrivateKey: %v", err)
	}
	return pem.EncodeToMemory(block), signer
}

func p5SignUserCert(t *testing.T, userPub cryptoSSH.PublicKey, principal string, serial uint64) (caPub cryptoSSH.PublicKey, certBytes []byte) {
	t.Helper()
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caSigner, err := cryptoSSH.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatalf("CA signer: %v", err)
	}
	cert := &cryptoSSH.Certificate{
		Key:             userPub,
		Serial:          serial,
		CertType:        cryptoSSH.UserCert,
		KeyId:           fmt.Sprintf("p5-cert-%d", serial),
		ValidPrincipals: []string{principal},
		ValidAfter:      uint64(time.Now().Add(-time.Hour).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	return caSigner.PublicKey(), cryptoSSH.MarshalAuthorizedKey(cert)
}

func p5BuildTestServerConfig(
	t *testing.T,
	acceptedCAs []cryptoSSH.PublicKey,
	acceptedPlainKeys []cryptoSSH.PublicKey,
	observer *p5AuthObserver,
) (*cryptoSSH.ServerConfig, cryptoSSH.PublicKey) {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	hostSigner, err := cryptoSSH.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	checker := &cryptoSSH.CertChecker{
		IsUserAuthority: func(auth cryptoSSH.PublicKey) bool {
			return p5ContainsKey(acceptedCAs, auth)
		},
	}
	srvCfg := &cryptoSSH.ServerConfig{
		PublicKeyCallback: func(conn cryptoSSH.ConnMetadata, key cryptoSSH.PublicKey) (*cryptoSSH.Permissions, error) {
			return p5VerifyTestPublicKey(conn.User(), key, acceptedCAs, acceptedPlainKeys, checker, observer)
		},
	}
	srvCfg.AddHostKey(hostSigner)
	return srvCfg, hostSigner.PublicKey()
}

func p5ContainsKey(keys []cryptoSSH.PublicKey, target cryptoSSH.PublicKey) bool {
	if target == nil {
		return false
	}
	want := target.Marshal()
	for _, k := range keys {
		if k != nil && bytes.Equal(k.Marshal(), want) {
			return true
		}
	}
	return false
}

func p5VerifyTestPublicKey(
	user string,
	key cryptoSSH.PublicKey,
	acceptedCAs []cryptoSSH.PublicKey,
	acceptedPlainKeys []cryptoSSH.PublicKey,
	checker *cryptoSSH.CertChecker,
	observer *p5AuthObserver,
) (*cryptoSSH.Permissions, error) {
	if observer != nil {
		observer.recordAttempt(key)
	}
	if cert, ok := key.(*cryptoSSH.Certificate); ok && len(acceptedCAs) > 0 {
		if checker.IsUserAuthority(cert.SignatureKey) {
			if err := checker.CheckCert(user, cert); err == nil {
				if observer != nil {
					observer.recordAuth(key)
				}
				return &cryptoSSH.Permissions{}, nil
			}
		}
	}
	if p5ContainsKey(acceptedPlainKeys, key) {
		if observer != nil {
			observer.recordAuth(key)
		}
		return &cryptoSSH.Permissions{}, nil
	}
	return nil, errors.New("unauthorized public key")
}

func p5StartTestSSHServer(
	t *testing.T,
	acceptedCAs []cryptoSSH.PublicKey,
	acceptedPlainKeys []cryptoSSH.PublicKey,
	observer *p5AuthObserver,
) (host string, port uint16, hostPub cryptoSSH.PublicKey) {
	t.Helper()
	srvCfg, hostPub := p5BuildTestServerConfig(t, acceptedCAs, acceptedPlainKeys, observer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
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
			go func(c net.Conn) {
				defer wg.Done()
				p5ServeTestSSHConn(c, srvCfg)
			}(raw)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	h, pStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	pInt, err := strconv.Atoi(pStr)
	if err != nil {
		t.Fatalf("Atoi port: %v", err)
	}
	return h, uint16(pInt), hostPub
}

func p5ServeTestSSHConn(c net.Conn, srvCfg *cryptoSSH.ServerConfig) {
	defer func() { _ = c.Close() }()
	sConn, chans, reqs, hsErr := cryptoSSH.NewServerConn(c, srvCfg)
	if hsErr != nil {
		return
	}
	defer func() { _ = sConn.Close() }()
	go cryptoSSH.DiscardRequests(reqs)
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(cryptoSSH.UnknownChannelType, "unsupported")
			continue
		}
		ch, chReqs, chErr := newCh.Accept()
		if chErr != nil {
			continue
		}
		go p5HandleExecSession(ch, chReqs)
	}
}

func p5HandleExecSession(ch cryptoSSH.Channel, reqs <-chan *cryptoSSH.Request) {
	defer func() { _ = ch.Close() }()
	for req := range reqs {
		switch req.Type {
		case "exec":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			_, _ = ch.Write([]byte("p5-ok\n"))
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
			return
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func p5WriteKnownHost(t *testing.T, home, host string, port uint16, hostPub cryptoSSH.PublicKey) {
	t.Helper()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("MkdirAll .ssh: %v", err)
	}
	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	line := knownhosts.Line([]string{knownhosts.Normalize(addr)}, hostPub) + "\n"
	if err := os.WriteFile(filepath.Join(sshDir, "known_hosts"), []byte(line), 0o600); err != nil {
		t.Fatalf("WriteFile known_hosts: %v", err)
	}
}

func p5WriteFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
}

func p5NewHostConfig(hostAddr string, port uint16, user, authType, keyPath string, opts *ssh.Options) *config.Configuration {
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Guardrail = &corepolicy.Config{Enabled: false}
	cfg.Hosts.Set("h", models.Host{Address: hostAddr, Port: port})
	cfg.Identities.Set("id", models.Identity{
		User:     user,
		AuthType: authType,
		KeyPath:  keyPath,
	})
	cfg.Nodes.Set("node", models.Node{
		HostRef:     "h",
		IdentityRef: "id",
		SSHOptions:  opts,
	})
	return cfg
}

func p5NewHostAndBackend(t *testing.T, ctx context.Context, cfg *config.Configuration) (*host, ports.Backend) {
	t.Helper()
	h := newHost(Config{Provider: config.NewProviderWithoutOpenSSH(cfg)})
	b, err := h.dependencies().NewBackend(ctx)
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	t.Cleanup(func() { _ = b.Shutdown(context.Background()) })
	return h, b
}

func p5ResolveBindEnter(t *testing.T, ctx context.Context, h *host) (ports.OperationSnapshot, ports.Binding, ports.Permit) {
	t.Helper()
	view, err := h.Resolve(ctx, ports.ResolveRequest{Selectors: []string{"node"}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	binding, err := ports.Bind(view, "p5-toctou-scope", "terminal", struct{}{})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	permit, err := h.Enter(ctx, ports.Admission{
		OperationID: "op-p5",
		Phase:       ports.Execute,
		Snapshot:    view,
		Binding:     binding,
	})
	if err != nil {
		t.Fatalf("Enter: %v", err)
	}
	t.Cleanup(func() { _ = permit.Close() })
	return view, binding, permit
}

func p5AssertNoSerial(t *testing.T, serials []uint64, forbidden uint64) {
	t.Helper()
	for _, s := range serials {
		if s == forbidden {
			t.Fatalf("handshake presented forbidden swapped cert serial %d (observed=%v)", forbidden, serials)
		}
	}
}

func TestP5_4_11_AdmittedCertTOCTOU_ExplicitAndSidecarAndDigestOnly(t *testing.T) {
	t.Run("explicit_cert_swap_uses_admitted_in_memory_rawbytes_only", testP5ExplicitCertSwapUsesRawBytes)
	t.Run("sidecar_cert_swap_uses_admitted_rawbytes_and_blocks_newly_planted_sidecar", testP5SidecarCertSwapAndPlant)
	t.Run("digest_only_plan_without_rawbytes_rejects_swapped_disk_cert_fail_closed", testP5DigestOnlyCertSwapFailsClosed)
}

func testP5ExplicitCertSwapUsesRawBytes(t *testing.T) {
	home := isolateMCPTestEnvironment(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	keyPEM, userSigner := p5NewEd25519KeyPair(t, "p5-explicit-cert")
	ca1Pub, cert1Bytes := p5SignUserCert(t, userSigner.PublicKey(), "certuser", 101)
	ca2Pub, cert2Bytes := p5SignUserCert(t, userSigner.PublicKey(), "certuser", 202)

	// Server accepts ONLY CA1 (serial 101), rejects CA2 (serial 202) and plain keys.
	obs := &p5AuthObserver{}
	srvHost, srvPort, hostPub := p5StartTestSSHServer(t, []cryptoSSH.PublicKey{ca1Pub}, nil, obs)
	p5WriteKnownHost(t, home, srvHost, srvPort, hostPub)

	keyDir := t.TempDir()
	keyPath := filepath.Join(keyDir, "id_ed25519")
	certPath := filepath.Join(keyDir, "explicit-cert.pub")
	p5WriteFile(t, keyPath, keyPEM)
	p5WriteFile(t, certPath, cert1Bytes)

	cfg := p5NewHostConfig(srvHost, srvPort, "certuser", "key", keyPath,
		ssh.MustOptions(ssh.OptionCertificateFile, certPath, ssh.OptionIdentitiesOnly, "yes"))
	h, b := p5NewHostAndBackend(t, ctx, cfg)

	view, _, permit := p5ResolveBindEnter(t, ctx, h)
	hop := view.Targets["node"].Plan.Hops[0]
	if !hop.EnforceAdmittedCertificates || len(hop.AdmittedCertificates) != 1 || len(hop.AdmittedCertificates[0].RawBytes) == 0 {
		t.Fatalf("expected EnforceAdmittedCertificates=true with populated RawBytes, got enforce=%v certs=%+v",
			hop.EnforceAdmittedCertificates, hop.AdmittedCertificates)
	}
	if !hop.EnforceAdmittedKeyDigests || len(hop.AdmittedKeyDigests) == 0 {
		t.Fatalf("expected EnforceAdmittedKeyDigests=true with bound key digests, got enforce=%v digests=%+v",
			hop.EnforceAdmittedKeyDigests, hop.AdmittedKeyDigests)
	}

	// Swap CertificateFile on disk AFTER Enter() and BEFORE handshake!
	p5WriteFile(t, certPath, cert2Bytes)

	res, runErr := b.Run(ctx, permit, "node", ports.Command{Text: "echo ok"})
	if runErr != nil {
		t.Fatalf("Run with admitted in-memory RawBytes failed after disk cert swap: %v", runErr)
	}
	if strings.TrimSpace(res.Output) != "p5-ok" {
		t.Fatalf("unexpected Run output %q", res.Output)
	}
	serials, _, authed := obs.snapshot()
	p5AssertNoSerial(t, serials, 202)
	if len(authed) != 1 || authed[0] != "cert:101" {
		t.Fatalf("expected authentication via admitted cert:101, got %v", authed)
	}

	// Reverse check: server accepting ONLY CA2 (swapped disk cert) MUST reject the admitted permit.
	obsCA2 := &p5AuthObserver{}
	srv2Host, srv2Port, host2Pub := p5StartTestSSHServer(t, []cryptoSSH.PublicKey{ca2Pub}, nil, obsCA2)
	p5WriteKnownHost(t, home, srv2Host, srv2Port, host2Pub)
	p5WriteFile(t, certPath, cert1Bytes)

	cfg2 := p5NewHostConfig(srv2Host, srv2Port, "certuser", "key", keyPath,
		ssh.MustOptions(ssh.OptionCertificateFile, certPath, ssh.OptionIdentitiesOnly, "yes"))
	h2, b2 := p5NewHostAndBackend(t, ctx, cfg2)
	_, _, permit2 := p5ResolveBindEnter(t, ctx, h2)

	// Swap cert1 -> cert2 (accepted by srv2) AFTER Enter().
	p5WriteFile(t, certPath, cert2Bytes)
	if _, err := b2.Run(ctx, permit2, "node", ports.Command{Text: "echo ok"}); err == nil {
		t.Fatal("handshake unexpectedly authenticated using swapped disk cert (CA2) after admission")
	}
	serials2, _, _ := obsCA2.snapshot()
	p5AssertNoSerial(t, serials2, 202)
}

func testP5SidecarCertSwapAndPlant(t *testing.T) {
	home := isolateMCPTestEnvironment(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	keyPEM, userSigner := p5NewEd25519KeyPair(t, "p5-sidecar-cert")
	ca1Pub, cert1Bytes := p5SignUserCert(t, userSigner.PublicKey(), "certuser", 301)
	_, cert2Bytes := p5SignUserCert(t, userSigner.PublicKey(), "certuser", 302)

	obs := &p5AuthObserver{}
	srvHost, srvPort, hostPub := p5StartTestSSHServer(t, []cryptoSSH.PublicKey{ca1Pub}, nil, obs)
	p5WriteKnownHost(t, home, srvHost, srvPort, hostPub)

	keyDir := t.TempDir()
	keyPath := filepath.Join(keyDir, "id_ed25519")
	sidecarPath := keyPath + "-cert.pub"
	p5WriteFile(t, keyPath, keyPEM)
	p5WriteFile(t, sidecarPath, cert1Bytes)

	cfg := p5NewHostConfig(srvHost, srvPort, "certuser", "key", keyPath,
		ssh.MustOptions(ssh.OptionIdentitiesOnly, "yes"))
	h, b := p5NewHostAndBackend(t, ctx, cfg)

	_, _, permit := p5ResolveBindEnter(t, ctx, h)

	// Swap sidecar cert on disk AFTER Enter() and BEFORE handshake.
	p5WriteFile(t, sidecarPath, cert2Bytes)
	if _, err := b.Run(ctx, permit, "node", ports.Command{Text: "echo ok"}); err != nil {
		t.Fatalf("Run failed after sidecar cert swap despite admitted RawBytes: %v", err)
	}
	serials, _, authed := obs.snapshot()
	p5AssertNoSerial(t, serials, 302)
	if len(authed) != 1 || authed[0] != "cert:301" {
		t.Fatalf("expected authentication via admitted sidecar cert:301, got %v", authed)
	}

	// Remove sidecar before admission, then plant valid CA1 sidecar AFTER Enter().
	// Handshake MUST refuse the un-admitted newly-planted sidecar cert fail-closed.
	if err := os.Remove(sidecarPath); err != nil {
		t.Fatal(err)
	}
	_, _, noCertPermit := p5ResolveBindEnter(t, ctx, h)
	p5WriteFile(t, sidecarPath, cert1Bytes)
	if _, err := b.Run(ctx, noCertPermit, "node", ports.Command{Text: "echo ok"}); err == nil {
		t.Fatal("handshake unexpectedly accepted newly-planted sidecar cert after admission")
	}
}

func testP5DigestOnlyCertSwapFailsClosed(t *testing.T) {
	home := isolateMCPTestEnvironment(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	keyPEM, userSigner := p5NewEd25519KeyPair(t, "p5-digest-only")
	ca1Pub, cert1Bytes := p5SignUserCert(t, userSigner.PublicKey(), "certuser", 401)
	ca2Pub, cert2Bytes := p5SignUserCert(t, userSigner.PublicKey(), "certuser", 402)

	// Server accepts BOTH CA1 and CA2 so only client-side fail-closed enforcement blocks cert2.
	obs := &p5AuthObserver{}
	srvHost, srvPort, hostPub := p5StartTestSSHServer(t, []cryptoSSH.PublicKey{ca1Pub, ca2Pub}, nil, obs)
	p5WriteKnownHost(t, home, srvHost, srvPort, hostPub)

	keyDir := t.TempDir()
	keyPath := filepath.Join(keyDir, "id_ed25519")
	certPath := filepath.Join(keyDir, "explicit-cert.pub")
	p5WriteFile(t, keyPath, keyPEM)
	p5WriteFile(t, certPath, cert1Bytes)

	cfg := p5NewHostConfig(srvHost, srvPort, "certuser", "key", keyPath,
		ssh.MustOptions(ssh.OptionCertificateFile, certPath, ssh.OptionIdentitiesOnly, "yes"))
	h, b := p5NewHostAndBackend(t, ctx, cfg)

	view, err := h.Resolve(ctx, ports.ResolveRequest{Selectors: []string{"node"}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	binding, err := ports.Bind(view, "p5-digest-only-scope", "terminal", struct{}{})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	// JSON round-trip strips RawBytes (json:"-") while keeping SHA256 digest (persisted recovery path).
	rawJSON, err := json.Marshal(transfer.Authorization{Snapshot: view, Binding: binding})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var restored transfer.Authorization
	if err := json.Unmarshal(rawJSON, &restored); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	restoredCerts := restored.Snapshot.Targets["node"].Plan.Hops[0].AdmittedCertificates
	if len(restoredCerts) != 1 || restoredCerts[0].SHA256 == "" || len(restoredCerts[0].RawBytes) != 0 {
		t.Fatalf("expected digest-only restored cert (SHA256 set, RawBytes empty), got %+v", restoredCerts)
	}

	// Enter BEFORE disk swap succeeds (ConnectionKey ignores RawBytes).
	permit, err := h.Enter(ctx, ports.Admission{
		OperationID: "op-digest-only",
		Phase:       ports.Execute,
		Snapshot:    restored.Snapshot,
		Binding:     restored.Binding,
	})
	if err != nil {
		t.Fatalf("Enter(digest-only): %v", err)
	}
	t.Cleanup(func() { _ = permit.Close() })

	// Swap cert1 -> cert2 on disk AFTER Enter() and BEFORE handshake.
	p5WriteFile(t, certPath, cert2Bytes)
	if _, err := b.Run(ctx, permit, "node", ports.Command{Text: "echo ok"}); err == nil {
		t.Fatal("digest-only plan unexpectedly accepted swapped disk cert")
	}
	serials, _, authed := obs.snapshot()
	if len(serials) != 0 || len(authed) != 0 {
		t.Fatalf("swapped disk cert must never be presented or authenticated, got serials=%v authed=%v", serials, authed)
	}
}

func TestP5_4_11_AdmittedKeyDigestTOCTOU_SwapAndPlantFailClosed(t *testing.T) {
	t.Run("swapping_explicit_private_key_after_enter_fails_closed_with_ErrSnapshotMismatch", testP5SwapExplicitKeyFailsClosed)
	t.Run("planting_missing_explicit_key_after_enter_fails_closed_with_ErrSnapshotMismatch", testP5PlantMissingExplicitKeyFailsClosed)
	t.Run("planting_default_key_after_enter_in_auto_mode_fails_closed_with_ErrSnapshotMismatch", testP5PlantDefaultKeyFailsClosed)
}

func testP5SwapExplicitKeyFailsClosed(t *testing.T) {
	home := isolateMCPTestEnvironment(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	key1PEM, signer1 := p5NewEd25519KeyPair(t, "p5-key-1")
	key2PEM, signer2 := p5NewEd25519KeyPair(t, "p5-key-2")

	// Server accepts BOTH key1 and key2 so only digest verification stops swapped key2.
	obs := &p5AuthObserver{}
	srvHost, srvPort, hostPub := p5StartTestSSHServer(t, nil, []cryptoSSH.PublicKey{signer1.PublicKey(), signer2.PublicKey()}, obs)
	p5WriteKnownHost(t, home, srvHost, srvPort, hostPub)

	keyDir := t.TempDir()
	keyPath := filepath.Join(keyDir, "id_ed25519")
	p5WriteFile(t, keyPath, key1PEM)

	cfg := p5NewHostConfig(srvHost, srvPort, "keyuser", "key", keyPath,
		ssh.MustOptions(ssh.OptionIdentitiesOnly, "yes"))
	h, b := p5NewHostAndBackend(t, ctx, cfg)

	view, _, permit := p5ResolveBindEnter(t, ctx, h)
	// Private key material must NEVER appear in the ConnectionPlan or serialized snapshot.
	snapJSON, err := json.Marshal(view)
	if err != nil {
		t.Fatalf("json.Marshal(view): %v", err)
	}
	if bytes.Contains(snapJSON, []byte("OPENSSH PRIVATE KEY")) || bytes.Contains(snapJSON, key1PEM[:32]) {
		t.Fatal("private key bytes leaked into serialized OperationSnapshot / ConnectionPlan")
	}

	// Swap private key on disk AFTER Enter() and BEFORE handshake!
	p5WriteFile(t, keyPath, key2PEM)

	_, runErr := b.Run(ctx, permit, "node", ports.Command{Text: "echo ok"})
	if !errors.Is(runErr, ssh.ErrSnapshotMismatch) {
		t.Fatalf("expected ssh.ErrSnapshotMismatch after key swap, got %v", runErr)
	}
	_, plainFPs, authed := obs.snapshot()
	if len(plainFPs) != 0 || len(authed) != 0 {
		t.Fatalf("swapped private key must never be offered to SSH server, got offered=%v authed=%v", plainFPs, authed)
	}
}

func testP5PlantMissingExplicitKeyFailsClosed(t *testing.T) {
	home := isolateMCPTestEnvironment(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	key1PEM, signer1 := p5NewEd25519KeyPair(t, "p5-key-existing")
	key2PEM, signer2 := p5NewEd25519KeyPair(t, "p5-key-planted")

	obs := &p5AuthObserver{}
	srvHost, srvPort, hostPub := p5StartTestSSHServer(t, nil, []cryptoSSH.PublicKey{signer1.PublicKey(), signer2.PublicKey()}, obs)
	p5WriteKnownHost(t, home, srvHost, srvPort, hostPub)

	keyDir := t.TempDir()
	missingFirstKey := filepath.Join(keyDir, "id_first_missing")
	existingSecondKey := filepath.Join(keyDir, "id_second_ok")
	p5WriteFile(t, existingSecondKey, key1PEM)

	opts := &ssh.Options{}
	if err := opts.Append(ssh.OptionIdentityFile, missingFirstKey); err != nil {
		t.Fatal(err)
	}
	if err := opts.Append(ssh.OptionIdentityFile, existingSecondKey); err != nil {
		t.Fatal(err)
	}
	if err := opts.Set(ssh.OptionIdentitiesOnly, "yes"); err != nil {
		t.Fatal(err)
	}
	cfg := p5NewHostConfig(srvHost, srvPort, "keyuser", "key", "", opts)
	h, b := p5NewHostAndBackend(t, ctx, cfg)

	_, _, permit := p5ResolveBindEnter(t, ctx, h)

	// Plant key2 at the previously-missing explicit path AFTER Enter().
	p5WriteFile(t, missingFirstKey, key2PEM)
	_, runErr := b.Run(ctx, permit, "node", ports.Command{Text: "echo ok"})
	if !errors.Is(runErr, ssh.ErrSnapshotMismatch) {
		t.Fatalf("expected ssh.ErrSnapshotMismatch after planting missing explicit key, got %v", runErr)
	}
	_, _, authed := obs.snapshot()
	if len(authed) != 0 {
		t.Fatalf("newly-planted key must never authenticate, got %v", authed)
	}
}

func testP5PlantDefaultKeyFailsClosed(t *testing.T) {
	home := isolateMCPTestEnvironment(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	plantedPEM, plantedSigner := p5NewEd25519KeyPair(t, "p5-default-planted")
	obs := &p5AuthObserver{}
	srvHost, srvPort, hostPub := p5StartTestSSHServer(t, nil, []cryptoSSH.PublicKey{plantedSigner.PublicKey()}, obs)
	p5WriteKnownHost(t, home, srvHost, srvPort, hostPub)

	cfg := p5NewHostConfig(srvHost, srvPort, "keyuser", "auto", "", nil)
	h, b := p5NewHostAndBackend(t, ctx, cfg)

	_, _, permit := p5ResolveBindEnter(t, ctx, h)

	// Plant default ~/.ssh/id_ed25519 AFTER Enter() and BEFORE handshake.
	defaultKeyPath := filepath.Join(home, ".ssh", "id_ed25519")
	p5WriteFile(t, defaultKeyPath, plantedPEM)
	_, runErr := b.Run(ctx, permit, "node", ports.Command{Text: "echo ok"})
	if !errors.Is(runErr, ssh.ErrSnapshotMismatch) {
		t.Fatalf("expected ssh.ErrSnapshotMismatch after planting default key, got %v", runErr)
	}
	_, _, authed := obs.snapshot()
	if len(authed) != 0 {
		t.Fatalf("newly-planted default key must never authenticate, got %v", authed)
	}
}

func TestP5_4_11_PrivateKeyMutationInvalidatesCredentialVersionAndEnter(t *testing.T) {
	home := isolateMCPTestEnvironment(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	key1PEM, _ := p5NewEd25519KeyPair(t, "p5-version-1")
	key2PEM, _ := p5NewEd25519KeyPair(t, "p5-version-2")

	keyDir := t.TempDir()
	explicitKeyPath := filepath.Join(keyDir, "id_ed25519")
	p5WriteFile(t, explicitKeyPath, key1PEM)

	cfg := p5NewHostConfig("192.0.2.1", 22, "keyuser", "key", explicitKeyPath,
		ssh.MustOptions(ssh.OptionIdentitiesOnly, "yes"))
	provider := config.NewProviderWithoutOpenSSH(cfg)
	h := newHost(Config{Provider: provider})

	view, err := h.Resolve(ctx, ports.ResolveRequest{Selectors: []string{"node"}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	binding, err := ports.Bind(view, "p5-key-version-scope", "terminal", struct{}{})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	admission := ports.Admission{
		OperationID: "op-key-mutate",
		Phase:       ports.Execute,
		Snapshot:    view,
		Binding:     binding,
	}

	// Unchanged key file passes Enter().
	permit, err := h.Enter(ctx, admission)
	if err != nil {
		t.Fatalf("Enter before key mutation failed: %v", err)
	}
	if err := permit.Close(); err != nil {
		t.Fatalf("permit.Close: %v", err)
	}

	vBefore, err := credentialVersion(provider, view.Targets["node"].Plan)
	if err != nil {
		t.Fatalf("credentialVersion(before): %v", err)
	}

	// Mutate private key file on disk -> credentialVersion changes and Enter() rejects stale plan!
	p5WriteFile(t, explicitKeyPath, key2PEM)
	vAfter, err := credentialVersion(provider, view.Targets["node"].Plan)
	if err != nil {
		t.Fatalf("credentialVersion(after): %v", err)
	}
	if vAfter == vBefore {
		t.Fatal("mutating private key file on disk must change credentialVersion")
	}
	if stalePermit, enterErr := h.Enter(ctx, admission); !errors.Is(enterErr, ports.ErrStaleBinding) {
		if stalePermit != nil {
			_ = stalePermit.Close()
		}
		t.Fatalf("Enter after private key mutation = %v, want ports.ErrStaleBinding", enterErr)
	}

	// Also verify default key planting invalidates credentialVersion and Enter() when !IdentitiesOnly.
	cfgAuto := p5NewHostConfig("192.0.2.1", 22, "keyuser", "auto", "", nil)
	hAuto := newHost(Config{Provider: config.NewProviderWithoutOpenSSH(cfgAuto)})
	viewAuto, err := hAuto.Resolve(ctx, ports.ResolveRequest{Selectors: []string{"node"}})
	if err != nil {
		t.Fatalf("Resolve(auto): %v", err)
	}
	bindingAuto, err := ports.Bind(viewAuto, "p5-default-key-scope", "terminal", struct{}{})
	if err != nil {
		t.Fatalf("Bind(auto): %v", err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	p5WriteFile(t, filepath.Join(home, ".ssh", "id_ed25519"), key1PEM)
	if stalePermit, enterErr := hAuto.Enter(ctx, ports.Admission{
		OperationID: "op-default-key-plant",
		Phase:       ports.Execute,
		Snapshot:    viewAuto,
		Binding:     bindingAuto,
	}); !errors.Is(enterErr, ports.ErrStaleBinding) {
		if stalePermit != nil {
			_ = stalePermit.Close()
		}
		t.Fatalf("Enter after planting default key = %v, want ports.ErrStaleBinding", enterErr)
	}
}
