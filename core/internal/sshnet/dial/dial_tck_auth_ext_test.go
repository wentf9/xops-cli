package dial_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"testing"
	"time"

	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
)

// TestDialer_TCKSuite_SingleAndMultiHop 使用真实回环双跳 SSH 服务端 + KnownHostsDB 运行完整 TCK 契约套件。
func TestDialer_TCKSuite_SingleAndMultiHop(t *testing.T) {
	tck.RunDialerSuite(t, tck.DialerFixture{
		NewDialer: func(st *testing.T) ports.DialerPort {
			clientSigner, _, _, clientPub := generateTestEd25519Key(st, "")
			bastion, bastionPub := newLoopbackSSHSpec(st)
			target, targetPub := newLoopbackSSHSpec(st)
			bastion.authorizedPubs = []ssh.PublicKey{clientSigner.PublicKey()}
			target.authorizedPubs = []ssh.PublicKey{clientSigner.PublicKey()}
			bastion.forwardTargets["198.51.100.2:2222"] = target

			db, _ := newRealKnownHostsDB(st)
			ctx := context.Background()
			ep0 := tck.MustEndpoint(st, "198.51.100.1", 22)
			ep1 := tck.MustEndpoint(st, "198.51.100.2", 2222)
			if err := db.RecordHostKey(ctx, ep0, bastionPub, option.UnsetKnownHostsList()); err != nil {
				st.Fatalf("RecordHostKey(hop0): %v", err)
			}
			if err := db.RecordHostKey(ctx, ep1, targetPub, option.UnsetKnownHostsList()); err != nil {
				st.Fatalf("RecordHostKey(hop1): %v", err)
			}
			d, err := dial.NewDialer(dial.Config{
				HostTrust:   db,
				Agent:       &testSignerPort{signer: clientSigner, pub: clientPub},
				DialContext: bastion.dialFunc(),
			})
			if err != nil {
				st.Fatalf("NewDialer: %v", err)
			}
			return d
		},
		CheckMultiHop:         true,
		CheckTunnelExtensions: true,
	})
}

func TestDialer_AuthPasswordPrivateKeyAndCert(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	vault := sim.NewSimVault(sim.NewSeededRand(11))
	passRef := tck.MustRef(t, "sim", "pass-login")
	putSimSecret(t, ctx, vault, passRef, "correct-horse-battery")
	badPassRef := tck.MustRef(t, "sim", "pass-wrong")
	putSimSecret(t, ctx, vault, badPassRef, "wrong-pass")

	keySigner, plainPEM, encPEM, keyPub := generateTestEd25519Key(t, "key-passphrase")
	caSigner, _, _, _ := generateTestEd25519Key(t, "")
	certAuthorized := mustSignTestUserCert(t, caSigner, keySigner.PublicKey(), "ops")

	keyPassRef := tck.MustRef(t, "sim", "key-pass")
	putSimSecret(t, ctx, vault, keyPassRef, "key-passphrase")

	srv, srvPub := newLoopbackSSHSpec(t)
	srv.password = "correct-horse-battery"
	srv.authorizedPubs = []ssh.PublicKey{keySigner.PublicKey()}
	srv.trustedUserCA = caSigner.PublicKey()

	db, dir := newRealKnownHostsDB(t)
	ep := tck.MustEndpoint(t, "auth.example.test", 22)
	if err := db.RecordHostKey(ctx, ep, srvPub, option.UnsetKnownHostsList()); err != nil {
		t.Fatalf("RecordHostKey: %v", err)
	}
	writeScopedFile(t, dir, "id_plain", plainPEM)
	writeScopedFile(t, dir, "id_enc", encPEM)
	writeScopedFile(t, dir, "id_cert-cert.pub", certAuthorized)

	d, err := dial.NewDialer(dial.Config{
		HostTrust:   db,
		Vault:       vault,
		ReadFS:      osfs.NewOperatorReadFS(),
		DialContext: srv.dialFunc(),
	})
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	layer := option.UnsetOptionLayer()

	// 1. 密码认证成功与错误密码失败。
	assertDialSucceeds(t, ctx, d, ep, mustPasswordAuth(t, passRef), layer)
	hopBad, digBad := mustSingleHopPlan(t, ep, mustPasswordAuth(t, badPassRef), layer)
	if _, dErr := d.DialHop(ctx, hopBad, digBad, nil); !errors.Is(dErr, ports.ErrAuthFailed) {
		t.Fatalf("错误密码须返回 ErrAuthFailed，实际 %v", dErr)
	}

	// 2. OperatorReadFS 读取未加密私钥 + 匹配用户证书认证成功。
	plainKeyPath := dir.String() + "/id_plain"
	certPath := dir.String() + "/id_cert-cert.pub"
	assertDialSucceeds(t, ctx, d, ep, mustPrivateKeyAuth(t, plainKeyPath, certPath, algebraic.None[inventory.KeyPassphraseBinding]()), layer)

	// 3. 口令保护私钥：INV-F1 匹配指纹成功，失配指纹严格失败关闭。
	encKeyPath := dir.String() + "/id_enc"
	goodBind, err := inventory.NewKeyPassphraseBinding(keyPassRef, keyPub.Fingerprint())
	if err != nil {
		t.Fatalf("NewKeyPassphraseBinding(good): %v", err)
	}
	assertDialSucceeds(t, ctx, d, ep, mustPrivateKeyAuth(t, encKeyPath, "", algebraic.Some(goodBind)), layer)
	wrongFP, _ := inventory.ParseKeyFingerprint(tck.TestFingerprintA)
	badBind, err := inventory.NewKeyPassphraseBinding(keyPassRef, wrongFP)
	if err != nil {
		t.Fatalf("NewKeyPassphraseBinding(bad): %v", err)
	}
	hopBadFP, digBadFP := mustSingleHopPlan(t, ep, mustPrivateKeyAuth(t, encKeyPath, "", algebraic.Some(badBind)), layer)
	if _, dErr := d.DialHop(ctx, hopBadFP, digBadFP, nil); !errors.Is(dErr, ports.ErrAuthFailed) {
		t.Fatalf("INV-F1 指纹失配须返回 ErrAuthFailed，实际 %v", dErr)
	}

	// 4. KeySignerPort 外部签名器认证成功。
	dKeyPort, _ := dial.NewDialer(dial.Config{
		HostTrust:   db,
		KeySigner:   &testSignerPort{signer: keySigner, pub: keyPub},
		DialContext: srv.dialFunc(),
	})
	assertDialSucceeds(t, ctx, dKeyPort, ep, mustPrivateKeyAuth(t, plainKeyPath, "", algebraic.None[inventory.KeyPassphraseBinding]()), layer)
}

func TestDialer_AuthKeyboardInteractiveAllRulesAndBatchMode(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	clk := sim.NewSimClock(time.Unix(1700000010, 0).UTC())
	vault := sim.NewSimVault(sim.NewSeededRand(21))
	totpSecret := "JBSWY3DPEHPK3PXP"
	expectedTOTP := computeExpectedTOTP(totpSecret, clk.Now())

	refLogin := tck.MustRef(t, "sim", "ki-login")
	refPin := tck.MustRef(t, "sim", "ki-pin")
	refTOTP := tck.MustRef(t, "sim", "ki-totp")
	putSimSecret(t, ctx, vault, refLogin, "login-secret-val")
	putSimSecret(t, ctx, vault, refPin, "pin-9876")
	putSimSecret(t, ctx, vault, refTOTP, totpSecret)

	proc := sim.NewSimProcessPort()
	proc.RegisterCommand("token-cmd", func(context.Context, ports.ProcessSpec, []byte) (ports.ProcessResult, error) {
		return ports.NewProcessResult(ports.ProcessResultSpec{
			ExitStatus: execution.NewExitCode(0),
			Stdout:     []byte("cmd-token-ok\n"),
		})
	})

	srv, srvPub := newLoopbackSSHSpec(t)
	srv.kiInstruction = "MFA Required"
	srv.kiQuestions = []string{"Login Password:", "PIN:", "OTP:", "CmdToken:", "Reason:", "Hidden:"}
	srv.kiEchos = []bool{false, false, false, false, true, false}
	srv.kiExpected = []string{"login-secret-val", "pin-9876", expectedTOTP, "cmd-token-ok", "deploy", "interactive-secret"}

	db, _ := newRealKnownHostsDB(t)
	ep := tck.MustEndpoint(t, "mfa.example.test", 22)
	if err := db.RecordHostKey(ctx, ep, srvPub, option.UnsetKnownHostsList()); err != nil {
		t.Fatalf("RecordHostKey: %v", err)
	}

	kiAuth := mustCompositeKIAuth(t, refLogin, refPin, refTOTP)
	inter := &testInteractionPort{canInteract: true, textReply: "deploy", secretReply: "interactive-secret"}
	d, err := dial.NewDialer(dial.Config{
		HostTrust:   db,
		Vault:       vault,
		Process:     proc,
		Interaction: inter,
		Clock:       clk,
		DialContext: srv.dialFunc(),
	})
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}

	// 非批处理模式下全 6 项质询（LoginPassword + SecretRef + TOTP + Command + EchoText + HiddenSecret）全部通过。
	assertDialSucceeds(t, ctx, d, ep, kiAuth, option.UnsetOptionLayer())

	// BatchMode 下未命中规则的交互质询必须失败关闭。
	layerBatch := option.UnsetOptionLayer().WithBatchMode(true)
	hopBatch, digBatch := mustSingleHopPlan(t, ep, kiAuth, layerBatch)
	if _, dErr := d.DialHop(ctx, hopBatch, digBatch, nil); !errors.Is(dErr, ports.ErrAuthFailed) {
		t.Fatalf("BatchMode 下未命中规则质询须失败关闭，实际 %v", dErr)
	}
}

func TestDialer_HostKeyPoliciesAndRealKnownHostsDB(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	vault := sim.NewSimVault(sim.NewSeededRand(31))
	passRef := tck.MustRef(t, "sim", "hk-pass")
	putSimSecret(t, ctx, vault, passRef, "pw")
	keySigner, _, _, keyPub := generateTestEd25519Key(t, "")

	srvA, _ := newLoopbackSSHSpec(t)
	srvA.password = "pw"
	srvA.authorizedPubs = []ssh.PublicKey{keySigner.PublicKey()}
	srvB, _ := newLoopbackSSHSpec(t)
	srvB.password = "pw"
	srvB.authorizedPubs = []ssh.PublicKey{keySigner.PublicKey()}

	db, dir := newRealKnownHostsDB(t)
	ep := tck.MustEndpoint(t, "hk.example.test", 22)
	inter := &testInteractionPort{canInteract: true, confirmOK: true}
	dA, _ := dial.NewDialer(dial.Config{
		HostTrust: db, Vault: vault, Agent: &testSignerPort{signer: keySigner, pub: keyPub},
		Interaction: inter, DialContext: srvA.dialFunc(),
	})
	dB, _ := dial.NewDialer(dial.Config{
		HostTrust: db, Vault: vault, Agent: &testSignerPort{signer: keySigner, pub: keyPub},
		Interaction: inter, DialContext: srvB.dialFunc(),
	})

	agentAuth := mustAgentAuth(t)
	passAuth := mustPasswordAuth(t, passRef)

	// 1. Yes 模式拒绝未知密钥。
	layerYes := option.UnsetOptionLayer().WithStrictHostKeyChecking(option.StrictHostKeyCheckingYes)
	hopY, digY := mustSingleHopPlan(t, ep, agentAuth, layerYes)
	if _, err := dA.DialHop(ctx, hopY, digY, nil); !errors.Is(err, ports.ErrHostKeyUnknown) {
		t.Fatalf("Yes 模式未知密钥须返回 ErrHostKeyUnknown，实际 %v", err)
	}

	// 2. Ask 模式：BatchMode 拒绝；拒绝确认返回 ErrHostKeyUnknown；同意确认记录并放行。
	layerAskBatch := option.UnsetOptionLayer().WithStrictHostKeyChecking(option.StrictHostKeyCheckingAsk).WithBatchMode(true)
	hopAB, digAB := mustSingleHopPlan(t, ep, agentAuth, layerAskBatch)
	if _, err := dA.DialHop(ctx, hopAB, digAB, nil); !errors.Is(err, ports.ErrHostKeyUnknown) {
		t.Fatalf("Ask+BatchMode 须拒绝未知密钥，实际 %v", err)
	}
	inter.confirmOK = false
	layerAsk := option.UnsetOptionLayer().WithStrictHostKeyChecking(option.StrictHostKeyCheckingAsk)
	hopA, digA := mustSingleHopPlan(t, ep, agentAuth, layerAsk)
	if _, err := dA.DialHop(ctx, hopA, digA, nil); !errors.Is(err, ports.ErrHostKeyUnknown) {
		t.Fatalf("Ask 拒绝后须返回 ErrHostKeyUnknown，实际 %v", err)
	}
	inter.confirmOK = true
	assertDialSucceeds(t, ctx, dA, ep, agentAuth, layerAsk)
	assertDialSucceeds(t, ctx, dA, ep, agentAuth, layerYes)

	// 3. Mismatch：AcceptNew 拒绝；No 在密码认证下仍拦截防 MITM，仅纯公钥/Agent 放行。
	layerAcceptNew := option.UnsetOptionLayer().WithStrictHostKeyChecking(option.StrictHostKeyCheckingAcceptNew)
	hopM1, digM1 := mustSingleHopPlan(t, ep, agentAuth, layerAcceptNew)
	if _, err := dB.DialHop(ctx, hopM1, digM1, nil); !errors.Is(err, ports.ErrHostKeyMismatch) {
		t.Fatalf("AcceptNew 密钥变更须返回 ErrHostKeyMismatch，实际 %v", err)
	}
	layerNo := option.UnsetOptionLayer().WithStrictHostKeyChecking(option.StrictHostKeyCheckingNo)
	hopM2, digM2 := mustSingleHopPlan(t, ep, passAuth, layerNo)
	if _, err := dB.DialHop(ctx, hopM2, digM2, nil); !errors.Is(err, ports.ErrHostKeyMismatch) {
		t.Fatalf("No+Password 在 Mismatch 下须拦截防凭据泄露，实际 %v", err)
	}
	assertDialSucceeds(t, ctx, dB, ep, agentAuth, layerNo)

	// 4. @revoked 在包括 No 在内的所有模式下均无条件拦截。
	writeScopedFile(t, dir, "known_hosts", []byte(fmt.Sprintf("@revoked %s %s\n", ep.KnownHostsKey(), string(ssh.MarshalAuthorizedKey(srvB.hostSigner.PublicKey())))))
	hopRev, digRev := mustSingleHopPlan(t, ep, agentAuth, layerNo)
	if _, err := dB.DialHop(ctx, hopRev, digRev, nil); !errors.Is(err, ports.ErrHostKeyRevoked) {
		t.Fatalf("@revoked 密钥在 No 模式下也须返回 ErrHostKeyRevoked，实际 %v", err)
	}
}

func mustCompositeKIAuth(t *testing.T, refLogin, refPin, refTOTP secret.Ref) inventory.AuthMethod {
	t.Helper()
	rLogin, err := inventory.NewRuleLoginPassword(inventory.ChallengeRuleMeta{PromptPattern: "Login Password"})
	if err != nil {
		t.Fatalf("NewRuleLoginPassword: %v", err)
	}
	rPin, err := inventory.NewRuleSecretRef(inventory.ChallengeRuleMeta{Name: "pin-rule", PromptPattern: "PIN"}, refPin)
	if err != nil {
		t.Fatalf("NewRuleSecretRef: %v", err)
	}
	rOTP, err := inventory.NewRuleTOTP(inventory.ChallengeRuleMeta{PromptPattern: "OTP"}, refTOTP)
	if err != nil {
		t.Fatalf("NewRuleTOTP: %v", err)
	}
	rCmd, err := inventory.NewRuleCommand(inventory.ChallengeRuleMeta{PromptPattern: "CmdToken"}, "token-cmd", nil, algebraic.None[algebraic.Duration]())
	if err != nil {
		t.Fatalf("NewRuleCommand: %v", err)
	}
	ki, err := inventory.NewAuthKeyboardInteractive(algebraic.NewNonEmpty[inventory.ChallengeRule](rLogin, rPin, rOTP, rCmd))
	if err != nil {
		t.Fatalf("NewAuthKeyboardInteractive: %v", err)
	}
	// 通过 AuthComposite 携带关联登录密码引用以验证 RuleLoginPassword。
	comp, err := inventory.NewAuthComposite(algebraic.NewNonEmpty[inventory.AuthMethod](ki, mustPasswordAuth(t, refLogin)))
	if err != nil {
		t.Fatalf("NewAuthComposite: %v", err)
	}
	return comp
}

func computeExpectedTOTP(base32Secret string, now time.Time) string {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(base32Secret)
	mac := hmac.New(sha1.New, key)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(now.Unix()/30))
	_, _ = mac.Write(buf[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off]&0x7f) << 24) | (uint32(sum[off+1]) << 16) | (uint32(sum[off+2]) << 8) | uint32(sum[off+3])
	return fmt.Sprintf("%06d", bin%uint32(math.Pow10(6)))
}
