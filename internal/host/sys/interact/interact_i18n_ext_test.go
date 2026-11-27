package interact_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"testing/fstest"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
	"github.com/wentf9/xops-cli/internal/host/sys/interact"
	"github.com/wentf9/xops-cli/internal/i18n"
	"go.uber.org/goleak"
)

func loadTestLocalizers(t *testing.T) (*i18n.Localizer, *i18n.Localizer) {
	t.Helper()
	cat, err := i18n.LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog 失败: %v", err)
	}
	return cat.For(domi18n.LocaleEn), cat.For(domi18n.LocaleZh)
}

func newTestStreamUI(t *testing.T, input string, loc *i18n.Localizer) (*interact.Interaction, *bytes.Buffer) {
	t.Helper()
	var out bytes.Buffer
	ui, err := interact.NewStreamInteraction(interact.StreamSpec{
		In:          strings.NewReader(input),
		Out:         &out,
		Interactive: true,
		Localizer:   loc,
	})
	if err != nil {
		t.Fatalf("NewStreamInteraction 失败: %v", err)
	}
	return ui, &out
}

// TestInteractionBilingualConfirmAndSanitization 验证 Confirm 在构造期严格拒绝含控制字符的结构化 BodyMessage，
// 并在英文/简体中文下正确渲染结构化提示、风险等级本地化以及 ASCII [y/N]: 确认契约（中文非 ASCII 确认词严格拒绝）。
func TestInteractionBilingualConfirmAndSanitization(t *testing.T) {
	defer goleak.VerifyNone(t)
	enLoc, zhLoc := loadTestLocalizers(t)
	ctx := context.Background()

	titleMsg := domi18n.NewMessage(domi18n.KeyInteractHostKeyTitle)
	// 构造期防线：BodyMessage 参数含 ESC 转义或 CRLF 控制字符时，ports.NewConfirmRequest 必须严格拒绝。
	dirtyBodyMsg := domi18n.NewMessage(
		domi18n.KeyInteractHostKeyBody,
		domi18n.BoundStr("algorithm", "ssh-ed25519"),
		domi18n.BoundStr("fingerprint", "SHA256:abc123\x1b[31m"),
		domi18n.BoundStr("endpoint", "10.0.0.1:22\r\nFAKE"),
	)
	if _, err := ports.NewConfirmRequest(ports.ConfirmRequestSpec{
		Title:        titleMsg.Canonical(),
		Message:      dirtyBodyMsg.Canonical(),
		Subject:      "10.0.0.1:22",
		Risk:         security.RiskModerate,
		TitleMessage: algebraic.Some(titleMsg),
		BodyMessage:  algebraic.Some(dirtyBodyMsg),
	}); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("含控制字符的 BodyMessage 应被 NewConfirmRequest 拒绝返回 ErrInvalidArgument，实际: %v", err)
	}

	bodyMsg := domi18n.NewMessage(
		domi18n.KeyInteractHostKeyBody,
		domi18n.BoundStr("algorithm", "ssh-ed25519"),
		domi18n.BoundStr("fingerprint", "SHA256:abc123"),
		domi18n.BoundStr("endpoint", "10.0.0.1:22"),
	)
	req, err := ports.NewConfirmRequest(ports.ConfirmRequestSpec{
		Title:        titleMsg.Canonical(),
		Message:      bodyMsg.Canonical(),
		Subject:      "10.0.0.1:22",
		Risk:         security.RiskModerate,
		TitleMessage: algebraic.Some(titleMsg),
		BodyMessage:  algebraic.Some(bodyMsg),
	})
	if err != nil {
		t.Fatalf("NewConfirmRequest 失败: %v", err)
	}

	assertConfirmRender(t, ctx, enLoc, req, "yes\n", security.VerdictAllow,
		`[moderate] SSH Host Key Verification: (10.0.0.1:22) Trust unknown SSH host key ssh-ed25519 (SHA256:abc123) for 10.0.0.1:22? [y/N]: `)
	assertConfirmRender(t, ctx, zhLoc, req, "y\n", security.VerdictAllow,
		`[中等风险] SSH 主机密钥验证: (10.0.0.1:22) 是否信任 10.0.0.1:22 的未知 SSH 主机密钥 ssh-ed25519（SHA256:abc123）？ [y/N]: `)
	// 中文 "是" 必须严格失败关闭，仅接受 ASCII y/yes。
	assertConfirmRender(t, ctx, zhLoc, req, "是\n", security.VerdictDeny,
		`[中等风险] SSH 主机密钥验证: (10.0.0.1:22) 是否信任 10.0.0.1:22 的未知 SSH 主机密钥 ssh-ed25519（SHA256:abc123）？ [y/N]: `)

	assertRiskLevelLabels(t, ctx, enLoc, zhLoc)
}

// TestInteractionRenderSideSanitizationAndByteBounds 验证渲染端纵深防御：
// 即使外部词库模板注入控制/Bidi 字符或展开超过 128B(标题)/512B(正文)，
// Confirm、PromptText 与 PromptSecret 输出仍恒为合法 UTF-8、无原始控制字符且按完整 rune 边界截断。
func TestInteractionRenderSideSanitizationAndByteBounds(t *testing.T) {
	defer goleak.VerifyNone(t)
	advLoc := buildAdversarialLocalizer(t)
	ctx := context.Background()

	cTitle := domi18n.NewMessage(domi18n.KeyInteractHostKeyTitle)
	cBody := domi18n.NewMessage(
		domi18n.KeyInteractHostKeyBody,
		domi18n.BoundStr("algorithm", "ssh-ed25519"),
		domi18n.BoundStr("fingerprint", "SHA256:ok"),
		domi18n.BoundStr("endpoint", "10.0.0.1:22"),
	)
	cReq, err := ports.NewConfirmRequest(ports.ConfirmRequestSpec{
		Title: cTitle.Canonical(), Message: cBody.Canonical(), Subject: "10.0.0.1:22",
		Risk: security.RiskModerate, TitleMessage: algebraic.Some(cTitle), BodyMessage: algebraic.Some(cBody),
	})
	if err != nil {
		t.Fatalf("NewConfirmRequest 失败: %v", err)
	}
	cUI, cOut := newTestStreamUI(t, "n\n", advLoc)
	if _, err := cUI.Confirm(ctx, cReq); err != nil {
		t.Fatalf("adversarial Confirm 失败: %v", err)
	}
	assertBoundedSanitizedPrompt(t, "Confirm", cOut.String(), "[moderate] ", ": (10.0.0.1:22) ", " [y/N]: ")

	tTitle := domi18n.NewMessage(domi18n.KeyInteractSSHChallengeTitle)
	tBody := domi18n.NewMessage(domi18n.KeyInteractChallengeResponse)
	tReq, err := ports.NewTextPromptRequest(ports.TextPromptRequestSpec{
		Title: tTitle.Canonical(), Prompt: tBody.Canonical(), Subject: "node-1",
		TitleMessage: algebraic.Some(tTitle), BodyMessage: algebraic.Some(tBody),
	})
	if err != nil {
		t.Fatalf("NewTextPromptRequest 失败: %v", err)
	}
	tUI, tOut := newTestStreamUI(t, "ok\n", advLoc)
	if _, err := tUI.PromptText(ctx, tReq); err != nil {
		t.Fatalf("adversarial PromptText 失败: %v", err)
	}
	assertBoundedSanitizedPrompt(t, "PromptText", tOut.String(), "", ": (node-1) ", " ")

	sReq, err := ports.NewSecretPromptRequest(ports.SecretPromptRequestSpec{
		Title: tTitle.Canonical(), Prompt: tBody.Canonical(), Subject: "node-1",
		TitleMessage: algebraic.Some(tTitle), BodyMessage: algebraic.Some(tBody),
	})
	if err != nil {
		t.Fatalf("NewSecretPromptRequest 失败: %v", err)
	}
	sUI, sOut := newTestStreamUI(t, tck.TestSecretTokenA+"\n", advLoc)
	if err := sUI.PromptSecret(ctx, sReq, func(*secret.SecretBox) error { return nil }); err != nil {
		t.Fatalf("adversarial PromptSecret 失败: %v", err)
	}
	assertBoundedSanitizedPrompt(t, "PromptSecret", sOut.String(), "", ": (node-1) ", " ")
}

func buildAdversarialLocalizer(t *testing.T) *i18n.Localizer {
	t.Helper()
	dirtyTitle := `\u001b[31m\r\n\u202e` + strings.Repeat("汉", 60)
	dirtyBody := `\u001b]52;c;abc\u0007\r\n` + strings.Repeat("中", 200) + ` {algorithm} {fingerprint} {endpoint}`
	dirtyResp := `\u001b[33m\r\n` + strings.Repeat("答", 200)
	fsys := fstest.MapFS{
		"locales/en/interact.yaml": &fstest.MapFile{Data: []byte(
			"interact.hostkey.title: \"SSH Host Key Verification\"\n" +
				"interact.hostkey.body: \"Trust {algorithm} {fingerprint} {endpoint}\"\n" +
				"interact.ssh_challenge.title: \"SSH Challenge\"\n" +
				"interact.ssh_challenge.response: \"Response:\"\n",
		)},
		"locales/zh/interact.yaml": &fstest.MapFile{Data: []byte(
			"interact.hostkey.title: \"" + dirtyTitle + "\"\n" +
				"interact.hostkey.body: \"" + dirtyBody + "\"\n" +
				"interact.ssh_challenge.title: \"" + dirtyTitle + "\"\n" +
				"interact.ssh_challenge.response: \"" + dirtyResp + "\"\n",
		)},
	}
	cat, err := i18n.LoadCatalogFromFS(fsys)
	if err != nil {
		t.Fatalf("LoadCatalogFromFS 失败: %v", err)
	}
	return cat.For(domi18n.LocaleZh)
}

func assertBoundedSanitizedPrompt(t *testing.T, name, got, prefix, mid, suffix string) {
	t.Helper()
	if !utf8.ValidString(got) {
		t.Fatalf("%s 渲染输出包含非法 UTF-8: %q", name, got)
	}
	if strings.ContainsAny(got, "\x1b\r\n\x07\u202e") {
		t.Fatalf("%s 渲染输出残留未脱敏控制或 Bidi 字符: %q", name, got)
	}
	rest, ok := strings.CutPrefix(got, prefix)
	if !ok {
		t.Fatalf("%s 缺少预期前缀 %q: %q", name, prefix, got)
	}
	rest, ok = strings.CutSuffix(rest, suffix)
	if !ok {
		t.Fatalf("%s 缺少预期后缀 %q: %q", name, suffix, got)
	}
	title, body, ok := strings.Cut(rest, mid)
	if !ok {
		t.Fatalf("%s 缺少主体分隔段 %q: %q", name, mid, got)
	}
	if len(title) > 128 || len(title) < 120 || !utf8.ValidString(title) {
		t.Fatalf("%s 标题段字节界限异常: len=%d validUTF8=%v", name, len(title), utf8.ValidString(title))
	}
	if len(body) > 512 || len(body) < 500 || !utf8.ValidString(body) {
		t.Fatalf("%s 正文段字节界限异常: len=%d validUTF8=%v", name, len(body), utf8.ValidString(body))
	}
}

func assertConfirmRender(
	t *testing.T,
	ctx context.Context,
	loc *i18n.Localizer,
	req ports.ConfirmRequest,
	input string,
	wantVerdict security.Verdict,
	wantPrompt string,
) {
	t.Helper()
	ui, out := newTestStreamUI(t, input, loc)
	verdict, err := ui.Confirm(ctx, req)
	if err != nil || verdict != wantVerdict {
		t.Fatalf("Confirm(%q) = (%v, %v), 期望 (%v, nil)", input, verdict, err, wantVerdict)
	}
	got := out.String()
	if strings.ContainsAny(got, "\x1b\r\n") {
		t.Fatalf("渲染后的确认提示包含未脱敏控制字符: %q", got)
	}
	if got != wantPrompt {
		t.Fatalf("Confirm 提示不匹配:\n got: %q\nwant: %q", got, wantPrompt)
	}
}

func assertRiskLevelLabels(t *testing.T, ctx context.Context, enLoc, zhLoc *i18n.Localizer) {
	t.Helper()
	cases := []struct {
		risk   security.RiskLevel
		wantEn string
		wantZh string
	}{
		{security.RiskSafe, "[safe] ", "[安全] "},
		{security.RiskModerate, "[moderate] ", "[中等风险] "},
		{security.RiskDangerous, "[dangerous] ", "[高风险] "},
	}
	for _, tc := range cases {
		req, err := ports.NewConfirmRequest(ports.ConfirmRequestSpec{Message: "Proceed?", Risk: tc.risk})
		if err != nil {
			t.Fatalf("NewConfirmRequest(%v) 失败: %v", tc.risk, err)
		}
		enUI, enOut := newTestStreamUI(t, "n\n", enLoc)
		if _, err := enUI.Confirm(ctx, req); err != nil {
			t.Fatalf("en Confirm(%v) 失败: %v", tc.risk, err)
		}
		if !strings.HasPrefix(enOut.String(), tc.wantEn) || !strings.HasSuffix(enOut.String(), " [y/N]: ") {
			t.Fatalf("en 风险标签渲染异常: %q", enOut.String())
		}
		zhUI, zhOut := newTestStreamUI(t, "n\n", zhLoc)
		if _, err := zhUI.Confirm(ctx, req); err != nil {
			t.Fatalf("zh Confirm(%v) 失败: %v", tc.risk, err)
		}
		if !strings.HasPrefix(zhOut.String(), tc.wantZh) || !strings.HasSuffix(zhOut.String(), " [y/N]: ") {
			t.Fatalf("zh 风险标签渲染异常: %q", zhOut.String())
		}
	}
}

// TestInteractionBilingualApprovalInvariant 验证 PromptApproval 在中英文下均本地化外框与摘要标签，
// 严格保持 ApprovalEnvelope.ScopeSummary() 与 Digest() 原样输出（INV-E5）并强制 ASCII [approve/N]: 确认词。
func TestInteractionBilingualApprovalInvariant(t *testing.T) {
	defer goleak.VerifyNone(t)
	enLoc, zhLoc := loadTestLocalizers(t)
	ctx := context.Background()

	env := tck.MustApprovalEnvelope(t, tck.NewDeterministicEntropy(99))
	dig, err := env.Digest()
	if err != nil {
		t.Fatalf("ApprovalEnvelope.Digest 失败: %v", err)
	}

	wantEn := "[APPROVAL " + env.Risk().String() + "] " + env.ScopeSummary() + " (digest=" + dig.String() + ") [approve/N]: "
	assertApprovalRender(t, ctx, enLoc, env, dig, "approve\n", security.VerdictAllow, wantEn)

	zhRisk := map[security.RiskLevel]string{
		security.RiskSafe:      "安全",
		security.RiskModerate:  "中等风险",
		security.RiskDangerous: "高风险",
	}[env.Risk()]
	wantZh := "[审批确认 " + zhRisk + "] " + env.ScopeSummary() + " (摘要=" + dig.String() + ") [approve/N]: "
	assertApprovalRender(t, ctx, zhLoc, env, dig, "approve\n", security.VerdictAllow, wantZh)
	// 中文“批准”不得放行审批，必须失败关闭为 VerdictDeny 且仍绑定原摘要。
	assertApprovalRender(t, ctx, zhLoc, env, dig, "批准\n", security.VerdictDeny, wantZh)
}

func assertApprovalRender(
	t *testing.T,
	ctx context.Context,
	loc *i18n.Localizer,
	env security.ApprovalEnvelope,
	wantDig security.Digest,
	input string,
	wantVerdict security.Verdict,
	wantPrompt string,
) {
	t.Helper()
	ui, out := newTestStreamUI(t, input, loc)
	resp, err := ui.PromptApproval(ctx, env)
	if err != nil {
		t.Fatalf("PromptApproval 失败: %v", err)
	}
	if !resp.IsValid() || resp.Verdict() != wantVerdict || !resp.EnvelopeDigest().Equal(wantDig) {
		t.Fatalf("PromptApproval 响应异常: verdict=%v digestMatch=%v", resp.Verdict(), resp.EnvelopeDigest().Equal(wantDig))
	}
	if got := out.String(); got != wantPrompt {
		t.Fatalf("PromptApproval 提示不匹配:\n got: %q\nwant: %q", got, wantPrompt)
	}
}

// TestInteractionBilingualTextAndSecretPrompts 验证 PromptText 与 PromptSecret 的双语渲染，
// 以及远端 SSH PAM 质询在 BodyMessage=None 时原样保留远端提示文本的安全契约。
func TestInteractionBilingualTextAndSecretPrompts(t *testing.T) {
	defer goleak.VerifyNone(t)
	enLoc, zhLoc := loadTestLocalizers(t)
	ctx := context.Background()

	assertBilingualTextPrompts(t, ctx, enLoc, zhLoc)
	assertBilingualSecretPrompts(t, ctx, enLoc, zhLoc)
}

func assertBilingualTextPrompts(t *testing.T, ctx context.Context, enLoc, zhLoc *i18n.Localizer) {
	t.Helper()
	tTitle := domi18n.NewMessage(domi18n.KeyInteractSSHChallengeTitle)
	tBody := domi18n.NewMessage(domi18n.KeyInteractChallengeResponse)

	// 结构化默认应答正文随语种本地化。
	localReq, err := ports.NewTextPromptRequest(ports.TextPromptRequestSpec{
		Title:        tTitle.Canonical(),
		Prompt:       tBody.Canonical(),
		Subject:      "node-1",
		TitleMessage: algebraic.Some(tTitle),
		BodyMessage:  algebraic.Some(tBody),
	})
	if err != nil {
		t.Fatalf("NewTextPromptRequest 失败: %v", err)
	}
	assertTextPromptRender(t, ctx, enLoc, localReq, "123456", "SSH Challenge: (node-1) Response: ")
	assertTextPromptRender(t, ctx, zhLoc, localReq, "123456", "SSH 身份验证质询: (node-1) 请输入应答： ")

	// 携带远端横幅的空问题质询（KeyInteractChallengeBannerResponse）在 EN/ZH 下均保留横幅并本地化应答尾缀。
	bannerBody := domi18n.NewMessage(domi18n.KeyInteractChallengeBannerResponse, domi18n.BoundStr("banner", "PAM MFA Notice"))
	bannerReq, err := ports.NewTextPromptRequest(ports.TextPromptRequestSpec{
		Title:        tTitle.Canonical(),
		Prompt:       bannerBody.Canonical(),
		Subject:      "node-1",
		TitleMessage: algebraic.Some(tTitle),
		BodyMessage:  algebraic.Some(bannerBody),
	})
	if err != nil {
		t.Fatalf("NewTextPromptRequest(banner) 失败: %v", err)
	}
	assertTextPromptRender(t, ctx, enLoc, bannerReq, "111222", "SSH Challenge: (node-1) PAM MFA Notice | Response: ")
	assertTextPromptRender(t, ctx, zhLoc, bannerReq, "111222", "SSH 身份验证质询: (node-1) PAM MFA Notice | 请输入应答： ")

	// 远端 SSH PAM 质询（BodyMessage=None）仅本地化标题，远端提示原文脱敏透传。
	remoteReq, err := ports.NewTextPromptRequest(ports.TextPromptRequestSpec{
		Title:        tTitle.Canonical(),
		Prompt:       "OTP verification code:",
		Subject:      "bastion",
		TitleMessage: algebraic.Some(tTitle),
		BodyMessage:  algebraic.None[domi18n.Message](),
	})
	if err != nil {
		t.Fatalf("NewTextPromptRequest(remote PAM) 失败: %v", err)
	}
	assertTextPromptRender(t, ctx, zhLoc, remoteReq, "654321", "SSH 身份验证质询: (bastion) OTP verification code: ")
}

func assertTextPromptRender(
	t *testing.T,
	ctx context.Context,
	loc *i18n.Localizer,
	req ports.TextPromptRequest,
	wantVal string,
	wantPrompt string,
) {
	t.Helper()
	ui, out := newTestStreamUI(t, wantVal+"\n", loc)
	if got, err := ui.PromptText(ctx, req); err != nil || got != wantVal {
		t.Fatalf("PromptText = (%q, %v), 期望 (%q, nil)", got, err, wantVal)
	}
	if out.String() != wantPrompt {
		t.Fatalf("PromptText 提示不匹配:\n got: %q\nwant: %q", out.String(), wantPrompt)
	}
}

func assertBilingualSecretPrompts(t *testing.T, ctx context.Context, enLoc, zhLoc *i18n.Localizer) {
	t.Helper()
	privTitle := domi18n.NewMessage(domi18n.KeyInteractPrivilegeTitle)
	privBody := domi18n.NewMessage(
		domi18n.KeyInteractPrivilegeBody,
		domi18n.BoundStr("method", "sudo"),
		domi18n.BoundStr("node", "db-01"),
	)
	privReq, err := ports.NewSecretPromptRequest(ports.SecretPromptRequestSpec{
		Title:        privTitle.Canonical(),
		Prompt:       privBody.Canonical(),
		Subject:      "db-01",
		TitleMessage: algebraic.Some(privTitle),
		BodyMessage:  algebraic.Some(privBody),
	})
	if err != nil {
		t.Fatalf("NewSecretPromptRequest(privilege) 失败: %v", err)
	}
	assertSecretPromptRender(t, ctx, enLoc, privReq, tck.TestSecretTokenA, "Privilege Escalation: (db-01) Enter sudo password for db-01 ")
	assertSecretPromptRender(t, ctx, zhLoc, privReq, tck.TestSecretTokenA, "权限提升认证: (db-01) 请输入节点 db-01 的 sudo 提权密码 ")

	// 无回显横幅质询（KeyInteractChallengeBannerResponse）在 EN/ZH 下均保留横幅并本地化应答尾缀。
	pamTitle := domi18n.NewMessage(domi18n.KeyInteractSSHChallengeTitle)
	bannerBody := domi18n.NewMessage(domi18n.KeyInteractChallengeBannerResponse, domi18n.BoundStr("banner", "PAM MFA Notice"))
	bannerSecReq, err := ports.NewSecretPromptRequest(ports.SecretPromptRequestSpec{
		Title:        pamTitle.Canonical(),
		Prompt:       bannerBody.Canonical(),
		Subject:      "prod-edge",
		TitleMessage: algebraic.Some(pamTitle),
		BodyMessage:  algebraic.Some(bannerBody),
	})
	if err != nil {
		t.Fatalf("NewSecretPromptRequest(banner) 失败: %v", err)
	}
	assertSecretPromptRender(t, ctx, enLoc, bannerSecReq, tck.TestSecretTokenA, "SSH Challenge: (prod-edge) PAM MFA Notice | Response: ")
	assertSecretPromptRender(t, ctx, zhLoc, bannerSecReq, tck.TestSecretTokenA, "SSH 身份验证质询: (prod-edge) PAM MFA Notice | 请输入应答： ")

	// 远端无回显 SSH PAM 质询（BodyMessage=None）在中文模式下须保持远端 PAM 原文不变。
	pamReq, err := ports.NewSecretPromptRequest(ports.SecretPromptRequestSpec{
		Title:        pamTitle.Canonical(),
		Prompt:       "Duo Push or Passcode:",
		Subject:      "prod-edge",
		TitleMessage: algebraic.Some(pamTitle),
		BodyMessage:  algebraic.None[domi18n.Message](),
	})
	if err != nil {
		t.Fatalf("NewSecretPromptRequest(remote PAM) 失败: %v", err)
	}
	assertSecretPromptRender(t, ctx, zhLoc, pamReq, tck.TestSecretTokenA, "SSH 身份验证质询: (prod-edge) Duo Push or Passcode: ")
}

func assertSecretPromptRender(
	t *testing.T,
	ctx context.Context,
	loc *i18n.Localizer,
	req ports.SecretPromptRequest,
	token string,
	wantPrompt string,
) {
	t.Helper()
	ui, out := newTestStreamUI(t, token+"\n", loc)
	var matched bool
	err := secret.WithBytes([]byte(token), func(expected *secret.SecretBox) error {
		return ui.PromptSecret(ctx, req, func(got *secret.SecretBox) error {
			matched = got.IsValid() && got.Len() == expected.Len() && got.Equal(expected)
			return nil
		})
	})
	if err != nil || !matched {
		t.Fatalf("PromptSecret 失败或 SecretBox 不匹配: err=%v matched=%v", err, matched)
	}
	if got := out.String(); got != wantPrompt {
		t.Fatalf("PromptSecret 提示不匹配:\n got: %q\nwant: %q", got, wantPrompt)
	}
}

// TestInteractionSetLocalizerHotSwapAndFallback 验证 SetLocalizer 运行期动态热切换、
// nil/无效 Localizer 回退英文以及空/零值接收者安全无 panic 行为与并发竞态安全。
func TestInteractionSetLocalizerHotSwapAndFallback(t *testing.T) {
	defer goleak.VerifyNone(t)
	enLoc, zhLoc := loadTestLocalizers(t)
	ctx := context.Background()

	// nil 与零值接收者调用 SetLocalizer 不得 panic，且零值恒保持不可交互。
	var nilUI *interact.Interaction
	nilUI.SetLocalizer(zhLoc)
	var zeroUI interact.Interaction
	zeroUI.SetLocalizer(zhLoc)
	if zeroUI.CanInteract() {
		t.Fatal("零值 Interaction 调用 SetLocalizer 后仍必须保持 CanInteract()==false")
	}

	titleMsg := domi18n.NewMessage(domi18n.KeyInteractMuxConfirmTitle)
	bodyMsg := domi18n.NewMessage(domi18n.KeyInteractMuxStartBody)
	req, err := ports.NewConfirmRequest(ports.ConfirmRequestSpec{
		Title:        titleMsg.Canonical(),
		Message:      bodyMsg.Canonical(),
		Risk:         security.RiskModerate,
		TitleMessage: algebraic.Some(titleMsg),
		BodyMessage:  algebraic.Some(bodyMsg),
	})
	if err != nil {
		t.Fatalf("NewConfirmRequest 失败: %v", err)
	}

	// StreamSpec.Localizer == nil 时自动回退英文；随后依次热切至中文、nil、再次切中文再传无效零值 Localizer 验证失败关闭回退。
	var invalidLoc i18n.Localizer
	ui, out := newTestStreamUI(t, "n\nn\nn\nn\nn\n", nil)
	steps := []struct {
		name string
		set  func()
		want string
	}{
		{"initial-nil-default-en", func() {}, "[moderate] ControlMaster Confirmation: Start ControlMaster listener [y/N]: "},
		{"hotswap-zh", func() { ui.SetLocalizer(zhLoc) }, "[中等风险] ControlMaster 确认: 是否启动 ControlMaster 监听器 [y/N]: "},
		{"reset-nil-en", func() { ui.SetLocalizer(nil) }, "[moderate] ControlMaster Confirmation: Start ControlMaster listener [y/N]: "},
		{"hotswap-zh-before-invalid", func() { ui.SetLocalizer(zhLoc) }, "[中等风险] ControlMaster 确认: 是否启动 ControlMaster 监听器 [y/N]: "},
		{"reset-invalid-en", func() { ui.SetLocalizer(&invalidLoc) }, "[moderate] ControlMaster Confirmation: Start ControlMaster listener [y/N]: "},
	}
	for _, st := range steps {
		out.Reset()
		st.set()
		if _, err := ui.Confirm(ctx, req); err != nil {
			t.Fatalf("步骤 %s Confirm 失败: %v", st.name, err)
		}
		if got := out.String(); got != st.want {
			t.Fatalf("步骤 %s 提示不匹配:\n got: %q\nwant: %q", st.name, got, st.want)
		}
	}

	// 并发 SetLocalizer 热切换 + Confirm 读取在 -race 下必须零数据竞态且零协程泄漏。
	assertConcurrentSetLocalizerRaceFree(t, ctx, enLoc, zhLoc, req)
}

func assertConcurrentSetLocalizerRaceFree(t *testing.T, ctx context.Context, enLoc, zhLoc *i18n.Localizer, req ports.ConfirmRequest) {
	t.Helper()
	concUI, _ := newTestStreamUI(t, strings.Repeat("n\n", 40), enLoc)
	err := conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			toggleLocalizerLoop(concUI, enLoc, zhLoc, 40)
			return nil
		}); gErr != nil {
			return gErr
		}
		return n.Go(func(runCtx context.Context) error {
			return confirmLoop(runCtx, concUI, req, 40)
		})
	})
	if err != nil {
		t.Fatalf("并发 SetLocalizer + Confirm 失败: %v", err)
	}
}

func toggleLocalizerLoop(ui *interact.Interaction, enLoc, zhLoc *i18n.Localizer, count int) {
	for idx := range count {
		if idx%2 == 0 {
			ui.SetLocalizer(zhLoc)
			continue
		}
		ui.SetLocalizer(enLoc)
	}
}

func confirmLoop(ctx context.Context, ui *interact.Interaction, req ports.ConfirmRequest, count int) error {
	for range count {
		if _, err := ui.Confirm(ctx, req); err != nil {
			return err
		}
	}
	return nil
}

// TestInteractionStructuredErrorsBilingual 验证 interact 包全部结构化错误均保留原哨兵契约、
// 携带有效 MessageID，并在英文等价性（enLoc.RenderError == err.Error()）与中文渲染下均无占位符残留。
func TestInteractionStructuredErrorsBilingual(t *testing.T) {
	defer goleak.VerifyNone(t)
	enLoc, zhLoc := loadTestLocalizers(t)
	ctx := context.Background()

	_, errNilFiles := interact.NewFileInteraction(nil, nil)
	_, errNilStream := interact.NewStreamInteraction(interact.StreamSpec{})
	var invalidLoc i18n.Localizer
	_, errInvalidLoc := interact.NewStreamInteraction(interact.StreamSpec{
		In:        strings.NewReader(""),
		Out:       &bytes.Buffer{},
		Localizer: &invalidLoc,
	})

	var zeroConfirm ports.ConfirmRequest
	var zeroApproval security.ApprovalEnvelope
	var zeroText ports.TextPromptRequest
	var zeroSecret ports.SecretPromptRequest

	ui, _ := newTestStreamUI(t, "\n\n"+strings.Repeat("x", 4100)+"\n", zhLoc)
	_, errZeroConfirm := ui.Confirm(ctx, zeroConfirm)
	_, errZeroApproval := ui.PromptApproval(ctx, zeroApproval)
	_, errZeroText := ui.PromptText(ctx, zeroText)
	errZeroSecret := ui.PromptSecret(ctx, zeroSecret, func(*secret.SecretBox) error { return nil })

	tReq, _ := ports.NewTextPromptRequest(ports.TextPromptRequestSpec{Prompt: "Tag:"})
	_, errEmptyText := ui.PromptText(ctx, tReq)
	sReq, _ := ports.NewSecretPromptRequest(ports.SecretPromptRequestSpec{Prompt: "Pass:"})
	errEmptySecret := ui.PromptSecret(ctx, sReq, func(*secret.SecretBox) error { return nil })
	_, errTooLong := ui.PromptText(ctx, tReq)

	cases := []struct {
		name     string
		err      error
		sentinel error
		wantID   domi18n.MessageID
	}{
		{"nil_files", errNilFiles, ports.ErrInvalidArgument, i18n.KeyInteractNilFileHandles},
		{"nil_stream", errNilStream, ports.ErrInvalidArgument, i18n.KeyInteractNilStreamHandles},
		{"invalid_localizer", errInvalidLoc, ports.ErrInvalidArgument, i18n.KeyInteractInvalidRequest},
		{"zero_confirm", errZeroConfirm, ports.ErrInvalidArgument, i18n.KeyInteractInvalidRequest},
		{"zero_approval", errZeroApproval, ports.ErrInvalidArgument, i18n.KeyInteractInvalidRequest},
		{"zero_text", errZeroText, ports.ErrInvalidArgument, i18n.KeyInteractInvalidRequest},
		{"zero_secret", errZeroSecret, ports.ErrInvalidArgument, i18n.KeyInteractInvalidRequest},
		{"empty_text", errEmptyText, ports.ErrInvalidArgument, i18n.KeyInteractEmptyText},
		{"empty_secret", errEmptySecret, ports.ErrInvalidArgument, i18n.KeyInteractEmptySecret},
		{"line_too_long", errTooLong, ports.ErrLimitExceeded, i18n.KeyInteractLineTooLong},
	}
	for _, tc := range cases {
		if !errors.Is(tc.err, tc.sentinel) {
			t.Errorf("[%s] errors.Is(%v, %v) = false", tc.name, tc.err, tc.sentinel)
		}
		if id, ok := domi18n.ErrorID(tc.err); !ok || id != tc.wantID {
			t.Errorf("[%s] ErrorID = (%q, %v), 期望 %q", tc.name, id, ok, tc.wantID)
		}
		if gotEn := enLoc.RenderError(tc.err); gotEn != tc.err.Error() {
			t.Errorf("[%s] en RenderError=%q != err.Error()=%q", tc.name, gotEn, tc.err.Error())
		}
		if gotZh := zhLoc.RenderError(tc.err); gotZh == "" || strings.ContainsAny(gotZh, "{}") {
			t.Errorf("[%s] zh RenderError 异常或存在占位符残留: %q", tc.name, gotZh)
		}
	}
}
