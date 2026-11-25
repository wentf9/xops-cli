package dial_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/internal/sshnet/hostkey"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
)

type testSignerPort struct {
	signer ssh.Signer
	pub    ports.PublicKeyInfo
}

func (p *testSignerPort) DialAgent(context.Context, algebraic.Option[inventory.AgentSpec]) (net.Conn, error) {
	return nil, ports.ErrUnsupported
}

func (p *testSignerPort) ListAgentKeys(context.Context, algebraic.Option[inventory.AgentSpec]) ([]ports.PublicKeyInfo, error) {
	return []ports.PublicKeyInfo{p.pub}, nil
}

func (p *testSignerPort) SignWithAgent(_ context.Context, _ algebraic.Option[inventory.AgentSpec], fp inventory.KeyFingerprint, algo string, data []byte) (ports.Signature, error) {
	return p.sign(fp, algo, data)
}

func (p *testSignerPort) ListPublicKeys(context.Context, inventory.AuthMethod) ([]ports.PublicKeyInfo, error) {
	return []ports.PublicKeyInfo{p.pub}, nil
}

func (p *testSignerPort) Sign(_ context.Context, fp inventory.KeyFingerprint, algo string, data []byte) (ports.Signature, error) {
	return p.sign(fp, algo, data)
}

func (p *testSignerPort) InspectPrivateKeyFingerprint(context.Context, inventory.KeyPathSpec, algebraic.Option[secret.Ref]) (inventory.KeyFingerprint, error) {
	return p.pub.Fingerprint(), nil
}

func (p *testSignerPort) sign(fp inventory.KeyFingerprint, algo string, data []byte) (ports.Signature, error) {
	if !fp.Equal(p.pub.Fingerprint()) {
		var zero ports.Signature
		return zero, ports.ErrNotFound
	}
	var (
		sig *ssh.Signature
		err error
	)
	if algSigner, ok := p.signer.(ssh.AlgorithmSigner); ok && algo != "" {
		sig, err = algSigner.SignWithAlgorithm(rand.Reader, data, algo)
	} else {
		sig, err = p.signer.Sign(rand.Reader, data)
	}
	if err != nil {
		var zero ports.Signature
		return zero, err
	}
	return ports.NewSignature(sig.Format, sig.Blob)
}

type testInteractionPort struct {
	canInteract bool
	confirmOK   bool
	textReply   string
	secretReply string
	confirmCnt  atomic.Int32
}

func (p *testInteractionPort) CanInteract() bool { return p.canInteract }

func (p *testInteractionPort) Confirm(context.Context, ports.ConfirmRequest) (security.Verdict, error) {
	p.confirmCnt.Add(1)
	if p.confirmOK {
		return security.VerdictAllow, nil
	}
	return security.VerdictDeny, nil
}

func (p *testInteractionPort) PromptApproval(context.Context, security.ApprovalEnvelope) (ports.ApprovalDecisionResponse, error) {
	var zero ports.ApprovalDecisionResponse
	return zero, ports.ErrUnsupported
}

func (p *testInteractionPort) PromptText(context.Context, ports.TextPromptRequest) (string, error) {
	return p.textReply, nil
}

// PromptSecret 实现 ports.InteractionPort 同步借用契约，便于单测验证键盘交互质询回退。
//
//xops:syncclosure
//xops:borrowed
func (p *testInteractionPort) PromptSecret(_ context.Context, _ ports.SecretPromptRequest, fn func(box *secret.SecretBox) error) error {
	return secret.WithBytes([]byte(p.secretReply), func(box *secret.SecretBox) error { return fn(box) })
}

func newRealKnownHostsDB(t *testing.T) (*hostkey.KnownHostsDB, pathalg.LocalDir) {
	t.Helper()
	base, err := pathalg.ParseLocalDir(t.TempDir())
	if err != nil {
		t.Fatalf("ParseLocalDir: %v", err)
	}
	dir, err := base.JoinComponent("ssh")
	if err != nil {
		t.Fatalf("JoinComponent(ssh): %v", err)
	}
	rootFS := osfs.NewScopedRootFS()
	if err := rootFS.EnsureRoot(dir, 0o700); err != nil {
		t.Fatalf("EnsureRoot: %v", err)
	}
	db, err := hostkey.NewKnownHostsDB(hostkey.Config{
		RootFS:     rootFS,
		DefaultDir: dir,
	})
	if err != nil {
		t.Fatalf("NewKnownHostsDB: %v", err)
	}
	return db, dir
}

func mustSingleHopPlan(t *testing.T, ep netaddr.Endpoint, auth inventory.AuthMethod, layer option.OptionLayer) (plan.HopSpec, plan.HopDigest) {
	t.Helper()
	user, err := option.ParseUsername("ops")
	if err != nil {
		t.Fatalf("ParseUsername: %v", err)
	}
	unset := option.UnsetOptionLayer()
	eff, err := option.ResolveEffectivePolicy(option.OriginManaged, ep, layer, unset, unset, unset)
	if err != nil {
		t.Fatalf("ResolveEffectivePolicy: %v", err)
	}
	hop, err := plan.NewHopSpecFromAuth(0, "test-node", user, auth, eff)
	if err != nil {
		t.Fatalf("NewHopSpecFromAuth: %v", err)
	}
	cp, err := plan.SealConnectionPlan(hop)
	if err != nil {
		t.Fatalf("SealConnectionPlan: %v", err)
	}
	dig, ok := cp.HopDigestAt(0)
	if !ok {
		t.Fatal("missing hop digest")
	}
	return hop, dig
}

func mustAgentAuth(t *testing.T) inventory.AuthMethod {
	t.Helper()
	a, err := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	if err != nil {
		t.Fatalf("NewAuthAgent: %v", err)
	}
	return a
}

func mustPasswordAuth(t *testing.T, ref secret.Ref) inventory.AuthMethod {
	t.Helper()
	a, err := inventory.NewAuthPassword(ref)
	if err != nil {
		t.Fatalf("NewAuthPassword: %v", err)
	}
	return a
}

func mustPrivateKeyAuth(t *testing.T, keyPath, certPath string, pass algebraic.Option[inventory.KeyPassphraseBinding]) inventory.AuthMethod {
	t.Helper()
	kp, err := inventory.ParseKeyPathSpec(keyPath)
	if err != nil {
		t.Fatalf("ParseKeyPathSpec: %v", err)
	}
	var certs []inventory.CertPathSpec
	if certPath != "" {
		cp, cErr := inventory.ParseCertPathSpec(certPath)
		if cErr != nil {
			t.Fatalf("ParseCertPathSpec: %v", cErr)
		}
		certs = []inventory.CertPathSpec{cp}
	}
	a, err := inventory.NewAuthPrivateKey(algebraic.NewNonEmpty(kp), pass, certs)
	if err != nil {
		t.Fatalf("NewAuthPrivateKey: %v", err)
	}
	return a
}

func mustSignTestUserCert(t *testing.T, ca ssh.Signer, userPub ssh.PublicKey, principal string) []byte {
	t.Helper()
	cert := &ssh.Certificate{
		Key:             userPub,
		CertType:        ssh.UserCert,
		KeyId:           "test-cert",
		ValidPrincipals: []string{principal},
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	return ssh.MarshalAuthorizedKey(cert)
}

func putSimSecret(t *testing.T, ctx context.Context, v *sim.SimVault, ref secret.Ref, val string) {
	t.Helper()
	if err := secret.WithBytes([]byte(val), func(box *secret.SecretBox) error {
		return v.PutAndVerify(ctx, ref, box)
	}); err != nil {
		t.Fatalf("vault.PutAndVerify(%s): %v", ref, err)
	}
}

func writeScopedFile(t *testing.T, dir pathalg.LocalDir, name string, data []byte) {
	t.Helper()
	dest, err := pathalg.ParseLocalRootedDest(name)
	if err != nil {
		t.Fatalf("ParseLocalRootedDest(%s): %v", name, err)
	}
	if err := osfs.NewScopedRootFS().WithRoot(dir, func(root ports.RootHandle) error {
		return root.AtomicReplace(dest, 0o600, func(w io.Writer) error {
			_, wErr := w.Write(data)
			return wErr
		})
	}); err != nil {
		t.Fatalf("AtomicReplace(%s): %v", name, err)
	}
}

func assertDialSucceeds(t *testing.T, ctx context.Context, d ports.DialerPort, ep netaddr.Endpoint, auth inventory.AuthMethod, layer option.OptionLayer) {
	t.Helper()
	hop, dig := mustSingleHopPlan(t, ep, auth, layer)
	conn, err := d.DialHop(ctx, hop, dig, nil)
	if err != nil {
		t.Fatalf("DialHop(%s) 失败: %v", ep, err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close(%s) 失败: %v", ep, err)
	}
}

func generateTestEd25519Key(t *testing.T, passphrase string) (ssh.Signer, []byte, []byte, ports.PublicKeyInfo) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	plainBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	plainPEM := pem.EncodeToMemory(plainBlock)
	var encPEM []byte
	if passphrase != "" {
		encBlock, eErr := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
		if eErr != nil {
			t.Fatalf("MarshalPrivateKeyWithPassphrase: %v", eErr)
		}
		encPEM = pem.EncodeToMemory(encBlock)
	}
	blob := signer.PublicKey().Marshal()
	fp := inventory.KeyFingerprintFromSHA256(sha256.Sum256(blob))
	pubInfo, err := ports.NewPublicKeyInfo(ports.PublicKeyInfoSpec{
		Algorithm:   signer.PublicKey().Type(),
		Fingerprint: fp,
		WireBlob:    blob,
	})
	if err != nil {
		t.Fatalf("NewPublicKeyInfo: %v", err)
	}
	return signer, plainPEM, encPEM, pubInfo
}

// syncCloseConn 在客户端 Close 时先关闭底层 TCP 套接字，再等待回环服务端协程完整退出。
type syncCloseConn struct {
	net.Conn
	done      <-chan struct{}
	nursery   *conc.Nursery
	closeOnce sync.Once
	closeErr  error
}

func (c *syncCloseConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.Conn.Close()
		<-c.done
		_ = c.nursery.Close()
	})
	return c.closeErr
}
