package dial_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial"
	"github.com/wentf9/xops-cli/core/internal/sshnet/hostkey"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
)

// TestDialer_HostCertificatesEndToEnd 验证真实 SSH 握手下 @cert-authority 放行、未验签/过期证书零 TOFU、
// 与 @revoked 底层主机密钥在含 No 在内的全模式下均严格拒绝。
func TestDialer_HostCertificatesEndToEnd(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	now := time.Date(2026, time.August, 1, 12, 0, 0, 0, time.UTC)
	clk := sim.NewSimClock(now)
	db, dir := newRealKnownHostsDBWithClock(t, clk)

	caSigner, _, _, _ := generateTestEd25519Key(t, "")
	untrustedCA, _, _, _ := generateTestEd25519Key(t, "")
	hostSigner, _, _, _ := generateTestEd25519Key(t, "")
	revokedSigner, _, _, _ := generateTestEd25519Key(t, "")
	clientSigner, _, _, clientPub := generateTestEd25519Key(t, "")

	caLine := fmt.Sprintf("@cert-authority *.cert.test %s", string(ssh.MarshalAuthorizedKey(caSigner.PublicKey())))
	revLine := fmt.Sprintf("@revoked app.cert.test %s", string(ssh.MarshalAuthorizedKey(revokedSigner.PublicKey())))
	writeScopedFile(t, dir, "known_hosts", []byte(caLine+revLine))

	after := uint64(now.Add(-time.Hour).Unix())
	before := uint64(now.Add(time.Hour).Unix())
	ep := tck.MustEndpoint(t, "app.cert.test", 22)

	// 1. 合法 @cert-authority 主机证书在 StrictHostKeyChecking=yes + BatchMode 下成功建连。
	validCertSigner := mustMakeHostCertSigner(t, caSigner, hostSigner, ssh.HostCert, []string{"app.cert.test"}, after, before)
	dValid := newCertTestDialer(t, db, clientSigner, clientPub, validCertSigner)
	layerYesBatch := option.UnsetOptionLayer().WithStrictHostKeyChecking(option.StrictHostKeyCheckingYes).WithBatchMode(true)
	assertDialSucceeds(t, ctx, dValid, ep, mustAgentAuth(t), layerYesBatch)

	// 2. 自签/非信任 CA 证书即使在 StrictHostKeyChecking=no 或 accept-new 下也严格拒绝，绝不 TOFU 落盘。
	untrustedSigner := mustMakeHostCertSigner(t, untrustedCA, hostSigner, ssh.HostCert, []string{"app.cert.test"}, after, before)
	dUntrusted := newCertTestDialer(t, db, clientSigner, clientPub, untrustedSigner)
	for _, mode := range []option.StrictHostKeyCheckingMode{option.StrictHostKeyCheckingAcceptNew, option.StrictHostKeyCheckingNo} {
		hop, dig := mustSingleHopPlan(t, ep, mustAgentAuth(t), option.UnsetOptionLayer().WithStrictHostKeyChecking(mode))
		if _, err := dUntrusted.DialHop(ctx, hop, dig, nil); !errors.Is(err, ports.ErrHostKeyMismatch) {
			t.Fatalf("mode=%s 非信任 CA 证书须返回 ErrHostKeyMismatch，实际 %v", mode, err)
		}
	}

	// 3. 受信 CA 签发但已过期的证书在 StrictHostKeyChecking=no 下也必须拒绝（禁止降级放行）。
	expiredSigner := mustMakeHostCertSigner(t, caSigner, hostSigner, ssh.HostCert, []string{"app.cert.test"}, uint64(now.Add(-2*time.Hour).Unix()), uint64(now.Add(-time.Minute).Unix()))
	dExpired := newCertTestDialer(t, db, clientSigner, clientPub, expiredSigner)
	hopExp, digExp := mustSingleHopPlan(t, ep, mustAgentAuth(t), option.UnsetOptionLayer().WithStrictHostKeyChecking(option.StrictHostKeyCheckingNo))
	if _, err := dExpired.DialHop(ctx, hopExp, digExp, nil); !errors.Is(err, ports.ErrHostKeyMismatch) {
		t.Fatalf("过期主机证书须返回 ErrHostKeyMismatch，实际 %v", err)
	}

	// 4. @revoked 底层主机私钥被包装为自签证书时，即使 mode=no 也必须返回 ErrHostKeyRevoked。
	revWrappedSigner := mustMakeHostCertSigner(t, untrustedCA, revokedSigner, ssh.HostCert, []string{"app.cert.test"}, after, before)
	dRevoked := newCertTestDialer(t, db, clientSigner, clientPub, revWrappedSigner)
	hopRev, digRev := mustSingleHopPlan(t, ep, mustAgentAuth(t), option.UnsetOptionLayer().WithStrictHostKeyChecking(option.StrictHostKeyCheckingNo))
	if _, err := dRevoked.DialHop(ctx, hopRev, digRev, nil); !errors.Is(err, ports.ErrHostKeyRevoked) {
		t.Fatalf("@revoked 底层私钥包装证书须返回 ErrHostKeyRevoked，实际 %v", err)
	}
}

func newRealKnownHostsDBWithClock(t *testing.T, clk ports.Clock) (*hostkey.KnownHostsDB, pathalg.LocalDir) {
	t.Helper()
	_, dir := newRealKnownHostsDB(t)
	db2, err := hostkey.NewKnownHostsDB(hostkey.Config{
		RootFS:     osfs.NewScopedRootFS(),
		DefaultDir: dir,
		Clock:      clk,
	})
	if err != nil {
		t.Fatalf("NewKnownHostsDB(clock): %v", err)
	}
	return db2, dir
}

func mustMakeHostCertSigner(t *testing.T, ca, host ssh.Signer, certType uint32, principals []string, after, before uint64) ssh.Signer {
	t.Helper()
	cert := &ssh.Certificate{
		Key:             host.PublicKey(),
		CertType:        certType,
		KeyId:           "e2e-host-cert",
		ValidPrincipals: principals,
		ValidAfter:      after,
		ValidBefore:     before,
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	s, err := ssh.NewCertSigner(cert, host)
	if err != nil {
		t.Fatalf("NewCertSigner: %v", err)
	}
	return s
}

func newCertTestDialer(t *testing.T, db *hostkey.KnownHostsDB, cli ssh.Signer, cliPub ports.PublicKeyInfo, hostCertSigner ssh.Signer) ports.DialerPort {
	t.Helper()
	srv, _ := newLoopbackSSHSpec(t)
	srv.hostSigner = hostCertSigner
	srv.authorizedPubs = []ssh.PublicKey{cli.PublicKey()}
	d, err := dial.NewDialer(dial.Config{
		HostTrust:   db,
		Agent:       &testSignerPort{signer: cli, pub: cliPub},
		DialContext: srv.dialFunc(),
	})
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	return d
}

// TestDialer_ProxyCommandQuotesProxyJumpGuardAndAuthFallbacks 验证引号感知 ProxyCommand 分词、
// 缺 parent 的 ProxyJump Fail-Closed、AuthComposite/多私钥回退、~/ 主目录展开与填充 TOTP/空提示兜底。
func TestDialer_ProxyCommandQuotesProxyJumpGuardAndAuthFallbacks(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	signer, plainPEM, _, pub := generateTestEd25519Key(t, "")
	srv, srvPub := newLoopbackSSHSpec(t)
	srv.authorizedPubs = []ssh.PublicKey{signer.PublicKey()}

	db, dir := newRealKnownHostsDB(t)
	ep := tck.MustEndpoint(t, "proxyq.example.test", 22)
	_ = db.RecordHostKey(ctx, ep, srvPub, option.UnsetKnownHostsList())
	writeScopedFile(t, dir, "id_ops", plainPEM)

	// 1. ProxyCommand 含空格引号 Windows 路径与单/双引号参数正确拆解，未闭合引号失败关闭。
	proc := &capturingProxyProcessPort{srv: srv}
	idInfo, err := ports.NewLocalIdentityInfo(ports.LocalIdentityInfoSpec{
		LocalHost: "workstation", LocalUser: "alice", HomeDir: dir.String() + "/",
	})
	if err != nil {
		t.Fatalf("NewLocalIdentityInfo: %v", err)
	}
	envPort := sim.NewSimEnvPort(nil, idInfo)
	d, err := dial.NewDialer(dial.Config{
		HostTrust: db,
		KeySigner: emptyKeySignerPort{},
		ReadFS:    osfs.NewOperatorReadFS(),
		Env:       envPort,
		Process:   proc,
	})
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	pcQuoted, err := option.ParseProxyCommand(`"C:\Program Files\OpenSSH\ssh.exe" -o "BatchMode=yes" -i '/my keys/id' -W %h:%p jump`)
	if err != nil {
		t.Fatalf("ParseProxyCommand(quoted): %v", err)
	}
	// 同时验证 AuthComposite([无 Agent, KeySigner空->回退ReadFS([不存在私钥, ~/id_ops])]) 全链路回退与主目录展开。
	missingKP, err := inventory.ParseKeyPathSpec(dir.String() + "/nonexistent_key")
	if err != nil {
		t.Fatalf("ParseKeyPathSpec(missing): %v", err)
	}
	homeKP, err := inventory.ParseKeyPathSpec("~/id_ops")
	if err != nil {
		t.Fatalf("ParseKeyPathSpec(~/id_ops): %v", err)
	}
	pkAuth, err := inventory.NewAuthPrivateKey(algebraic.NewNonEmpty(missingKP, homeKP), algebraic.None[inventory.KeyPassphraseBinding](), nil)
	if err != nil {
		t.Fatalf("NewAuthPrivateKey: %v", err)
	}
	compAuth, err := inventory.NewAuthComposite(algebraic.NewNonEmpty[inventory.AuthMethod](mustAgentAuth(t), pkAuth))
	if err != nil {
		t.Fatalf("NewAuthComposite: %v", err)
	}

	hopQ, digQ := mustSingleHopPlan(t, ep, compAuth, option.UnsetOptionLayer().WithProxyRoute(pcQuoted))
	connQ, err := d.DialHop(ctx, hopQ, digQ, nil)
	if err != nil {
		t.Fatalf("DialHop(quoted ProxyCommand + composite fallback): %v", err)
	}
	_ = connQ.Close()
	wantArgs := []string{"-o", "BatchMode=yes", "-i", "/my keys/id", "-W", "proxyq.example.test:22", "jump"}
	if proc.lastSpec.Command() != `C:\Program Files\OpenSSH\ssh.exe` || !slices.Equal(proc.lastSpec.Args(), wantArgs) {
		t.Fatalf("引号分词不符: cmd=%q args=%q", proc.lastSpec.Command(), proc.lastSpec.Args())
	}

	// 2. 未闭合引号 ProxyCommand 失败关闭。
	pcBad, _ := option.ParseProxyCommand(`nc "unclosed %h %p`)
	hopBad, digBad := mustSingleHopPlan(t, ep, compAuth, option.UnsetOptionLayer().WithProxyRoute(pcBad))
	if _, err := d.DialHop(ctx, hopBad, digBad, nil); !errors.Is(err, ports.ErrDialFailed) {
		t.Fatalf("未闭合引号 ProxyCommand 须返回 ErrDialFailed，实际 %v", err)
	}

	// 3. ProxyJump 缺失 parent 及 HopIndex>0 缺失 parent 均严禁退化直连（返回 ErrInvalidArgument）。
	pj, _ := option.ParseProxyJump("bastion.example.test")
	hopPJ, digPJ := mustSingleHopPlan(t, ep, compAuth, option.UnsetOptionLayer().WithProxyRoute(pj))
	if _, err := d.DialHop(ctx, hopPJ, digPJ, nil); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("ProxyJump 缺失 parent 须返回 ErrInvalidArgument，实际 %v", err)
	}
	_, multiPlan := tck.MustHopAndPlan(t)
	hop1, _ := multiPlan.HopAt(1)
	dig1, _ := multiPlan.HopDigestAt(1)
	if _, err := d.DialHop(ctx, hop1, dig1, nil); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("HopIndex>0 缺失 parent 须返回 ErrInvalidArgument，实际 %v", err)
	}

	// 4. 带空格与 '=' 填充的 TOTP Base32 密钥及空白远端质询提示兜底。
	assertPaddedTOTPAndBlankPrompt(t, ctx, db)
	_ = pub
}

func assertPaddedTOTPAndBlankPrompt(t *testing.T, ctx context.Context, db *hostkey.KnownHostsDB) {
	t.Helper()
	clk := sim.NewSimClock(time.Unix(1700000010, 0).UTC())
	vault := sim.NewSimVault(sim.NewSeededRand(99))
	refTOTP := tck.MustRef(t, "sim", "totp-padded")
	putSimSecret(t, ctx, vault, refTOTP, "jbsw y3dp ehpk 3pxp====")
	wantCode := computeExpectedTOTP("JBSWY3DPEHPK3PXP", clk.Now())

	srv, srvPub := newLoopbackSSHSpec(t)
	srv.kiQuestions = []string{"OTP:", "   "}
	srv.kiEchos = []bool{false, false}
	srv.kiExpected = []string{wantCode, "blank-reply"}
	epKI := tck.MustEndpoint(t, "totp-pad.example.test", 22)
	_ = db.RecordHostKey(ctx, epKI, srvPub, option.UnsetKnownHostsList())

	rOTP, _ := inventory.NewRuleTOTP(inventory.ChallengeRuleMeta{PromptPattern: "OTP"}, refTOTP)
	kiAuth, _ := inventory.NewAuthKeyboardInteractive(algebraic.NewNonEmpty[inventory.ChallengeRule](rOTP))
	d, _ := dial.NewDialer(dial.Config{
		HostTrust:   db,
		Vault:       vault,
		Clock:       clk,
		Interaction: &testInteractionPort{canInteract: true, secretReply: "blank-reply"},
		DialContext: srv.dialFunc(),
	})
	assertDialSucceeds(t, ctx, d, epKI, kiAuth, option.UnsetOptionLayer())
}

type emptyKeySignerPort struct{}

func (emptyKeySignerPort) ListPublicKeys(context.Context, inventory.AuthMethod) ([]ports.PublicKeyInfo, error) {
	return nil, nil
}
func (emptyKeySignerPort) Sign(context.Context, inventory.KeyFingerprint, string, []byte) (ports.Signature, error) {
	var zero ports.Signature
	return zero, ports.ErrNotFound
}
func (emptyKeySignerPort) InspectPrivateKeyFingerprint(context.Context, inventory.KeyPathSpec, algebraic.Option[secret.Ref]) (inventory.KeyFingerprint, error) {
	var zero inventory.KeyFingerprint
	return zero, ports.ErrNotFound
}

type capturingProxyProcessPort struct {
	srv      *loopbackSSHSpec
	lastSpec ports.ProcessSpec
}

func (p *capturingProxyProcessPort) Run(context.Context, ports.ProcessSpec, io.Reader) (ports.ProcessResult, error) {
	var zero ports.ProcessResult
	return zero, ports.ErrUnsupported
}

func (p *capturingProxyProcessPort) DialStdio(ctx context.Context, spec ports.ProcessSpec) (net.Conn, error) {
	p.lastSpec = spec
	return p.srv.dialOnDemandLoopback(ctx)
}
