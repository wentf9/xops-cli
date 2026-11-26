package dial_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
)

type spyVault struct {
	ports.SecretVault
	withSecretCalls atomic.Int32
}

//xops:syncclosure
//xops:borrowed
func (v *spyVault) WithSecret(ctx context.Context, ref secret.Ref, fn func(*secret.SecretBox) error) error {
	v.withSecretCalls.Add(1)
	return v.SecretVault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
		return fn(box)
	})
}

type cancelAgent struct{}

func (*cancelAgent) DialAgent(context.Context, algebraic.Option[inventory.AgentSpec]) (net.Conn, error) {
	return nil, context.Canceled
}
func (*cancelAgent) ListAgentKeys(ctx context.Context, _ algebraic.Option[inventory.AgentSpec]) ([]ports.PublicKeyInfo, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return nil, context.Canceled
}
func (*cancelAgent) SignWithAgent(context.Context, algebraic.Option[inventory.AgentSpec], inventory.KeyFingerprint, string, []byte) (ports.Signature, error) {
	var zero ports.Signature
	return zero, context.Canceled
}

type spyInteraction struct {
	canInteract bool
	reply       string
	seenPrompts []string
}

func (s *spyInteraction) CanInteract() bool { return s.canInteract }
func (*spyInteraction) Confirm(context.Context, ports.ConfirmRequest) (security.Verdict, error) {
	return security.VerdictDeny, ports.ErrUnsupported
}

//xops:syncclosure
//xops:borrowed
func (s *spyInteraction) PromptSecret(_ context.Context, req ports.SecretPromptRequest, fn func(*secret.SecretBox) error) error {
	s.seenPrompts = append(s.seenPrompts, req.Prompt())
	return secret.WithBytes([]byte(s.reply), func(box *secret.SecretBox) error {
		return fn(box)
	})
}
func (s *spyInteraction) PromptText(_ context.Context, req ports.TextPromptRequest) (string, error) {
	s.seenPrompts = append(s.seenPrompts, req.Prompt())
	return s.reply, nil
}
func (*spyInteraction) PromptApproval(context.Context, security.ApprovalEnvelope) (ports.ApprovalDecisionResponse, error) {
	var zero ports.ApprovalDecisionResponse
	return zero, ports.ErrUnsupported
}

type truncatedProcessStub struct{}

func (*truncatedProcessStub) Run(context.Context, ports.ProcessSpec, io.Reader) (ports.ProcessResult, error) {
	return ports.NewProcessResult(ports.ProcessResultSpec{
		ExitStatus: execution.NewExitCode(0),
		Stdout:     []byte("truncated-ans"),
		Truncated:  true,
	})
}
func (*truncatedProcessStub) DialStdio(context.Context, ports.ProcessSpec) (net.Conn, error) {
	return nil, ports.ErrUnsupported
}

// TestDialer_INVF1CompositeSwapEarlyCheckAndHopTokens 回归评审 #25 M1 / Minor #5 / Nit #4 与 #31 M1：
//   - AuthComposite([AuthPrivateKey(INV-F1 失配), AuthPassword]) 使用真实 KeySigner 时必须失败关闭，绝不跳过回退密码；
//   - 将配置了 KeyPassphraseBinding 的加密私钥替换为未加密伪造私钥时，KeySigner 与 ReadFS 路径均须返回 ErrAuthFailed；
//   - OpenSSH 加密私钥指纹失配时须在访问 Vault 前完成预校验（0 次 Vault.WithSecret 调用）；
//   - KeySigner 与 ReadFS 同注时，带跳板级 %h 令牌的私钥路径须正确展开；
//   - buildAgentAuth 在 ctx 已取消时透传 ctx.Err() 而非包装为 ErrSignerUnavailable。
func TestDialer_INVF1CompositeSwapEarlyCheckAndHopTokens(t *testing.T) {
	defer goleak.VerifyNone(t)
	t.Run("CompositeINVF1FailClosedAndVaultPrecheck", testCompositeINVF1AndPrecheck)
	t.Run("UnencryptedSwapHopTokensAndAgentCancel", testUnencryptedSwapHopTokensAndAgentCancel)
}

func writeTempKeyFile(t *testing.T, dir pathalg.LocalDir, name string, data []byte) string {
	t.Helper()
	writeScopedFile(t, dir, name, data)
	return dir.String() + "/" + name
}

func testCompositeINVF1AndPrecheck(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	_, encPEM, _, _ := generateTestEd25519Key(t, "real-pass")
	dir, _ := pathalg.ParseLocalDir(t.TempDir())
	encPath := writeTempKeyFile(t, dir, "id_enc", encPEM)
	kpEnc, _ := inventory.ParseKeyPathSpec(encPath)

	baseVault := sim.NewSimVault(sim.NewSeededRand(201))
	passRef := tck.MustRef(t, "sim", "enc-pass")
	loginRef := tck.MustRef(t, "sim", "login-pass")
	putSimSecret(t, ctx, baseVault, passRef, "real-pass")
	putSimSecret(t, ctx, baseVault, loginRef, "fallback-pass")
	sv := &spyVault{SecretVault: baseVault}

	ks, err := dial.NewKeySigner(dial.KeySignerConfig{ReadFS: osfs.NewOperatorReadFS(), Vault: sv})
	if err != nil {
		t.Fatalf("NewKeySigner: %v", err)
	}
	srv, srvPub := newLoopbackSSHSpec(t)
	srv.password = "fallback-pass"
	db, _ := newRealKnownHostsDB(t)
	ep := tck.MustEndpoint(t, "invf1-comp.example.test", 22)
	_ = db.RecordHostKey(ctx, ep, srvPub, option.UnsetKnownHostsList())

	wrongFP, _ := inventory.ParseKeyFingerprint(tck.TestFingerprintA)
	badBind, _ := inventory.NewKeyPassphraseBinding(passRef, wrongFP)
	authKey, _ := inventory.NewAuthPrivateKey(algebraic.NewNonEmpty(kpEnc), algebraic.Some(badBind), nil)
	authPass, _ := inventory.NewAuthPassword(loginRef)
	compAuth, _ := inventory.NewAuthComposite(algebraic.NewNonEmpty[inventory.AuthMethod](authKey, authPass))

	// 仅注入 KeySigner（无 ReadFS）：AuthComposite 遇到 INV-F1 硬错误绝不可吞掉并回退到 AuthPassword。
	d, err := dial.NewDialer(dial.Config{HostTrust: db, Vault: sv, KeySigner: ks, DialContext: srv.dialFunc()})
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	hop, dig := mustSingleHopPlan(t, ep, compAuth, option.UnsetOptionLayer())
	if _, err := d.DialHop(ctx, hop, dig, nil); !errors.Is(err, ports.ErrAuthFailed) {
		t.Fatalf("AuthComposite 遇 KeySigner INV-F1 失配须立即失败关闭，实际 %v", err)
	}
	if calls := sv.withSecretCalls.Load(); calls != 0 {
		t.Fatalf("OpenSSH 加密私钥 INV-F1 预校验应在访问 Vault 前拦截，实际 WithSecret 调用 %d 次", calls)
	}
}

func testUnencryptedSwapHopTokensAndAgentCancel(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	rogueSigner, roguePEM, _, _ := generateTestEd25519Key(t, "")
	goodSigner, goodPEM, _, _ := generateTestEd25519Key(t, "")
	dir, _ := pathalg.ParseLocalDir(t.TempDir())
	roguePath := writeTempKeyFile(t, dir, "id_swapped", roguePEM)
	kpRogue, _ := inventory.ParseKeyPathSpec(roguePath)

	vault := sim.NewSimVault(sim.NewSeededRand(202))
	passRef := tck.MustRef(t, "sim", "bind-pass")
	putSimSecret(t, ctx, vault, passRef, "unused-pass")
	wrongFP, _ := inventory.ParseKeyFingerprint(tck.TestFingerprintB)
	bind, _ := inventory.NewKeyPassphraseBinding(passRef, wrongFP)
	authSwapped, _ := inventory.NewAuthPrivateKey(algebraic.NewNonEmpty(kpRogue), algebraic.Some(bind), nil)

	ks, _ := dial.NewKeySigner(dial.KeySignerConfig{ReadFS: osfs.NewOperatorReadFS(), Vault: vault})
	if _, err := ks.ListPublicKeys(ctx, authSwapped); !errors.Is(err, ports.ErrAuthFailed) {
		t.Fatalf("KeySigner 未加密私钥掉包须被 INV-F1 拦截，实际 %v", err)
	}
	srv, srvPub := newLoopbackSSHSpec(t)
	srv.authorizedPubs = []ssh.PublicKey{rogueSigner.PublicKey(), goodSigner.PublicKey()}
	db, _ := newRealKnownHostsDB(t)
	ep := tck.MustEndpoint(t, "hop-token.example.test", 22)
	_ = db.RecordHostKey(ctx, ep, srvPub, option.UnsetKnownHostsList())

	dReadFS, _ := dial.NewDialer(dial.Config{HostTrust: db, Vault: vault, ReadFS: osfs.NewOperatorReadFS(), DialContext: srv.dialFunc()})
	hopSwap, digSwap := mustSingleHopPlan(t, ep, authSwapped, option.UnsetOptionLayer())
	if _, err := dReadFS.DialHop(ctx, hopSwap, digSwap, nil); !errors.Is(err, ports.ErrAuthFailed) {
		t.Fatalf("Dialer ReadFS 未加密私钥掉包须被 INV-F1 拦截，实际 %v", err)
	}

	// 同注 KeySigner 与 ReadFS 时，KeySigner 成功返回后不得重复回退读取 Dialer.ReadFS。
	goodPath := writeTempKeyFile(t, dir, "id_good", goodPEM)
	kpGood, err := inventory.ParseKeyPathSpec(goodPath)
	if err != nil {
		t.Fatalf("ParseKeyPathSpec(good): %v", err)
	}
	authGood, _ := inventory.NewAuthPrivateKey(algebraic.NewNonEmpty(kpGood), algebraic.None[inventory.KeyPassphraseBinding](), nil)
	dBoth, _ := dial.NewDialer(dial.Config{
		HostTrust: db, Vault: vault, KeySigner: ks, ReadFS: osfs.NewOperatorReadFS(), DialContext: srv.dialFunc(),
	})
	assertDialSucceeds(t, ctx, dBoth, ep, authGood, option.UnsetOptionLayer())

	// buildAgentAuth 遇 ctx 取消须透传 context.Canceled 而非 ErrSignerUnavailable。
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	dAg, _ := dial.NewDialer(dial.Config{HostTrust: db, Agent: &cancelAgent{}, DialContext: srv.dialFunc()})
	hopAg, digAg := mustSingleHopPlan(t, ep, mustAgentAuth(t), option.UnsetOptionLayer())
	_, agErr := dAg.DialHop(cancelCtx, hopAg, digAg, nil)
	if !errors.Is(agErr, context.Canceled) || errors.Is(agErr, ports.ErrSignerUnavailable) {
		t.Fatalf("Agent ctx 取消应直接透传 context.Canceled，实际 %v", agErr)
	}
}

// TestDialer_KI_BannerAttemptFallbackTruncatedCmdAndOTPUnescape 回归评审 #31 M2 与 #25 Minor #4：
//   - RFC 4256 空问横幅轮保留并合入下一轮 InstructionPattern 与交互提示；
//   - 同一问题第 2 次重问（attempt > 1）跳过自动规则：交互模式回退 InteractionPort，BatchMode 失败关闭；
//   - RuleCommand 返回 res.Truncated()==true 失败关闭；
//   - otpauth://totp 支持 + / %XX 查询反转义与 #fragment 剥离，拒绝非法 %zz 与重复 secret=。
func TestDialer_KI_BannerAttemptFallbackTruncatedCmdAndOTPUnescape(t *testing.T) {
	defer goleak.VerifyNone(t)
	t.Run("BannerPreservedAndAttempt2Fallback", testKIBannerAndAttemptFallback)
	t.Run("TruncatedRuleCommandAndOTPQueryUnescape", testTruncatedCmdAndOTPUnescape)
}

func testKIBannerAndAttemptFallback(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	vault := sim.NewSimVault(sim.NewSeededRand(203))
	secRef := tck.MustRef(t, "sim", "ki-sec")
	putSimSecret(t, ctx, vault, secRef, "auto-once")

	db, _ := newRealKnownHostsDB(t)
	ep := tck.MustEndpoint(t, "ki-retry.example.test", 22)

	// 1. 空问横幅轮（Corp MFA Banner）合入第 2 轮，第 2 轮命中的自动答案被模拟拒绝后第 3 轮同题重问，
	//    须跳过自动规则回退至 InteractionPort 并携带横幅与说明文本。
	srv, srvPub := newLoopbackSSHSpec(t)
	srv.kiRounds = []kiRoundSpec{
		{instruction: "Corp MFA Banner"},
		{instruction: "", questions: []string{"Verification code:"}, echos: []bool{false}, expected: []string{"auto-once"}},
		{instruction: "Retry needed", questions: []string{"Verification code:"}, echos: []bool{false}, expected: []string{"human-override"}},
	}
	_ = db.RecordHostKey(ctx, ep, srvPub, option.UnsetKnownHostsList())

	rule, err := inventory.NewRuleSecretRef(inventory.ChallengeRuleMeta{
		Name:               "mfa-banner-rule",
		InstructionPattern: "Corp MFA Banner",
		PromptPattern:      "Verification code",
	}, secRef)
	if err != nil {
		t.Fatalf("NewRuleSecretRef: %v", err)
	}
	kiAuth, _ := inventory.NewAuthKeyboardInteractive(algebraic.NewNonEmpty[inventory.ChallengeRule](rule))

	inter := &spyInteraction{canInteract: true, reply: "human-override"}
	d, _ := dial.NewDialer(dial.Config{HostTrust: db, Vault: vault, Interaction: inter, DialContext: srv.dialFunc()})
	assertDialSucceeds(t, ctx, d, ep, kiAuth, option.UnsetOptionLayer())
	if len(inter.seenPrompts) != 1 || !strings.Contains(inter.seenPrompts[0], "Retry needed") {
		t.Fatalf("attempt>1 回退交互提示应携带 instruction，实际 %q", inter.seenPrompts)
	}

	// 2. BatchMode 下第 2 次同题重问必须立即失败关闭，绝不重复提交自动凭据。
	batchLayer := option.UnsetOptionLayer().WithBatchMode(true)
	hopBatch, digBatch := mustSingleHopPlan(t, ep, kiAuth, batchLayer)
	if _, err := d.DialHop(ctx, hopBatch, digBatch, nil); !errors.Is(err, ports.ErrAuthFailed) {
		t.Fatalf("BatchMode 下 attempt>1 须失败关闭返回 ErrAuthFailed，实际 %v", err)
	}

	// 3. 超长（>512B 含多字节 UTF-8）MFA 横幅回退至交互提示时，须安全截断至 <=512B UTF-8 且保留问题正文（评审 #42 Minor #1）。
	longBanner := strings.Repeat("安全横幅Notice-", 80) // > 1.5 KiB 多字节 UTF-8
	srvLong, longPub := newLoopbackSSHSpec(t)
	srvLong.kiRounds = []kiRoundSpec{
		{instruction: longBanner},
		{instruction: "", questions: []string{"Manual OTP:", "Echo Note:"}, echos: []bool{false, true}, expected: []string{"ok-long", "ok-long"}},
	}
	epLong := tck.MustEndpoint(t, "ki-long-banner.example.test", 22)
	_ = db.RecordHostKey(ctx, epLong, longPub, option.UnsetKnownHostsList())
	interLong := &spyInteraction{canInteract: true, reply: "ok-long"}
	dLong, _ := dial.NewDialer(dial.Config{HostTrust: db, Vault: vault, Interaction: interLong, DialContext: srvLong.dialFunc()})
	assertDialSucceeds(t, ctx, dLong, epLong, kiAuth, option.UnsetOptionLayer())
	if len(interLong.seenPrompts) != 2 {
		t.Fatalf("期望触发 2 次交互提示，实际 %d", len(interLong.seenPrompts))
	}
	for i, wantQ := range []string{"Manual OTP:", "Echo Note:"} {
		got := interLong.seenPrompts[i]
		if len(got) > 512 || !utf8.ValidString(got) || !strings.Contains(got, wantQ) {
			t.Fatalf("超长横幅交互提示 #%d 异常: len=%d validUTF8=%v prompt=%q", i, len(got), utf8.ValidString(got), got)
		}
	}
}

func testTruncatedCmdAndOTPUnescape(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	clk := sim.NewSimClock(time.Unix(1700000180, 0).UTC())
	vault := sim.NewSimVault(sim.NewSeededRand(204))
	db, _ := newRealKnownHostsDB(t)

	// 1. otpauth://totp 含 + / %20 / %3d 与 #fragment 正常计算。
	refOK := tck.MustRef(t, "sim", "otp-unescape-ok")
	refBadEsc := tck.MustRef(t, "sim", "otp-bad-esc")
	refDup := tck.MustRef(t, "sim", "otp-dup-secret")
	putSimSecret(t, ctx, vault, refOK, "otpauth://totp/XOps:ops?secret=JBSW+Y3DP%20EHPK%2d3PXP%3d&algorithm=SHA256&digits=6&period=30#frag-ignored")
	putSimSecret(t, ctx, vault, refBadEsc, "otpauth://totp/XOps:ops?secret=JBSW%zzEHPK3PXP")
	putSimSecret(t, ctx, vault, refDup, "otpauth://totp/XOps:ops?secret=JBSWY3DPEHPK3PXP&secret=AAAA")

	wantCode := computeExpectedTOTPWith(t, "JBSWY3DPEHPK3PXP", sha256.New, 6, 30, clk.Now())
	srv, srvPub := newLoopbackSSHSpec(t)
	srv.kiRounds = []kiRoundSpec{
		{questions: []string{"OTP:"}, echos: []bool{false}, expected: []string{wantCode}},
	}
	ep := tck.MustEndpoint(t, "otp-unescape.example.test", 22)
	_ = db.RecordHostKey(ctx, ep, srvPub, option.UnsetKnownHostsList())

	d, _ := dial.NewDialer(dial.Config{
		HostTrust: db, Vault: vault, Clock: clk, Process: &truncatedProcessStub{}, DialContext: srv.dialFunc(),
	})
	rOK, _ := inventory.NewRuleTOTP(inventory.ChallengeRuleMeta{PromptPattern: "OTP:"}, refOK)
	authOK, _ := inventory.NewAuthKeyboardInteractive(algebraic.NewNonEmpty[inventory.ChallengeRule](rOK))
	assertDialSucceeds(t, ctx, d, ep, authOK, option.UnsetOptionLayer())

	// 2. 非法 %zz 转义与重复 secret= 均须失败关闭。
	for _, badRef := range []secret.Ref{refBadEsc, refDup} {
		rBad, _ := inventory.NewRuleTOTP(inventory.ChallengeRuleMeta{PromptPattern: "OTP:"}, badRef)
		authBad, _ := inventory.NewAuthKeyboardInteractive(algebraic.NewNonEmpty[inventory.ChallengeRule](rBad))
		hop, dig := mustSingleHopPlan(t, ep, authBad, option.UnsetOptionLayer())
		if _, err := d.DialHop(ctx, hop, dig, nil); !errors.Is(err, ports.ErrAuthFailed) {
			t.Fatalf("非法 otpauth 参数 (%s) 须返回 ErrAuthFailed，实际 %v", badRef, err)
		}
	}

	// 3. RuleCommand 输出被截断（res.Truncated() == true）须失败关闭。
	rCmd, _ := inventory.NewRuleCommand(inventory.ChallengeRuleMeta{PromptPattern: "OTP:"}, "otp-helper", nil, algebraic.None[algebraic.Duration]())
	authCmd, _ := inventory.NewAuthKeyboardInteractive(algebraic.NewNonEmpty[inventory.ChallengeRule](rCmd))
	hopCmd, digCmd := mustSingleHopPlan(t, ep, authCmd, option.UnsetOptionLayer())
	if _, err := d.DialHop(ctx, hopCmd, digCmd, nil); !errors.Is(err, ports.ErrAuthFailed) {
		t.Fatalf("截断的 RuleCommand 输出须返回 ErrAuthFailed，实际 %v", err)
	}
}
