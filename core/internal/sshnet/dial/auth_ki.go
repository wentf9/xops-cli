package dial

import (
	"context"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/ports"
)

const maxInteractivePromptBytes = 512

type kiQuestionAction uint8

const (
	kiActionLiteral kiQuestionAction = iota
	kiActionVaultSecret
	kiActionPromptSecret
)

type kiQuestionPlan struct {
	action    kiQuestionAction
	answer    string
	secretRef secret.Ref
	promptReq ports.SecretPromptRequest
}

// buildKeyboardInteractiveAuth 适配 RFC 4256 多轮质询应答循环（严格遵循 secrettaint/sinks_narrow.go
// P4-T1 窄消费模式，限定轮次与单轮问题上限、保留空问横幅、按问题统计尝试次数防止自动应答死循环、检查 ctx 取消，零 nolint 豁免）。
func (d *Dialer) buildKeyboardInteractiveAuth(ctx context.Context, hop plan.HopSpec, ki *inventory.AuthKeyboardInteractive, loginPassRef algebraic.Option[secret.Ref]) ssh.AuthMethod {
	rules := ki.Rules()
	rounds := 0
	var pendingBanner string
	promptAttempts := make(map[string]int)
	return ssh.KeyboardInteractive(func(name string, instruction string, questions []string, echos []bool) ([]string, error) {
		rounds++
		if err := checkKIRoundLimit(ctx, rounds, len(questions)); err != nil {
			return nil, err
		}
		roundBanner := joinKIBanner(name, instruction)
		if len(questions) == 0 {
			pendingBanner = appendBoundedBanner(pendingBanner, roundBanner)
			return nil, nil
		}
		effectiveInstr := joinKIBanner(pendingBanner, roundBanner)
		pendingBanner = ""

		answers := make([]string, len(questions))
		for i, q := range questions {
			promptKey := strings.TrimSpace(q)
			promptAttempts[promptKey]++
			qp, err := d.planKIQuestion(ctx, hop, rules, loginPassRef, effectiveInstr, q, echoAt(echos, i), promptAttempts[promptKey])
			if err != nil {
				return nil, err
			}
			var fillErr error
			switch qp.action {
			case kiActionLiteral:
				answers[i] = qp.answer
			case kiActionVaultSecret:
				fillErr = d.vault.WithSecret(ctx, qp.secretRef, func(box *secret.SecretBox) error {
					return box.Use(func(plain []byte) error {
						answers[i] = string(plain)
						return nil
					})
				})
			case kiActionPromptSecret:
				fillErr = d.interaction.PromptSecret(ctx, qp.promptReq, func(box *secret.SecretBox) error {
					return box.Use(func(plain []byte) error {
						answers[i] = string(plain)
						return nil
					})
				})
			}
			if fillErr != nil {
				return nil, fillErr
			}
		}
		return answers, nil
	})
}

func joinKIBanner(a, b string) string {
	ta := strings.TrimSpace(a)
	tb := strings.TrimSpace(b)
	switch {
	case ta == "":
		return tb
	case tb == "" || tb == ta:
		return ta
	default:
		return ta + "\n" + tb
	}
}

func appendBoundedBanner(prev, next string) string {
	combined := joinKIBanner(prev, next)
	if len(combined) > maxKIBannerBytes {
		return combined[:maxKIBannerBytes]
	}
	return combined
}

func checkKIRoundLimit(ctx context.Context, rounds, questionCount int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if rounds > maxKIChallengeRounds || questionCount > maxKIQuestionsPerRound {
		return domi18n.EF(ports.ErrAuthFailed, domi18n.KeyCommonLimitExceeded)
	}
	return nil
}

func echoAt(echos []bool, idx int) bool {
	return idx >= 0 && idx < len(echos) && echos[idx]
}

func (d *Dialer) planKIQuestion(
	ctx context.Context,
	hop plan.HopSpec,
	rules []inventory.ChallengeRule,
	loginPassRef algebraic.Option[secret.Ref],
	instruction, prompt string,
	echo bool,
	attempt int,
) (kiQuestionPlan, error) {
	// 同一问题在第 1 次自动应答被远端拒绝并再次下发（attempt > 1）时，禁止重复提交同一自动凭据
	// （防止触发 PAM pam_faillock 锁定），立即回退至交互提示（非交互模式下失败关闭）。
	if attempt > 1 {
		return d.planInteractiveKIQuestion(ctx, hop, instruction, prompt, echo)
	}
	rule, matched := matchChallengeRule(rules, instruction, prompt)
	if !matched {
		return d.planInteractiveKIQuestion(ctx, hop, instruction, prompt, echo)
	}
	return d.planMatchedRuleKIQuestion(ctx, rule, loginPassRef)
}

func (d *Dialer) planInteractiveKIQuestion(ctx context.Context, hop plan.HopSpec, instruction, prompt string, echo bool) (kiQuestionPlan, error) {
	if hop.Transport().BatchMode() || d.interaction == nil || !d.interaction.CanInteract() {
		return kiQuestionPlan{}, domi18n.EF(ports.ErrAuthFailed, domi18n.KeyDialChallengeUnmatched, domi18n.BoundStr("prompt", prompt))
	}
	if !echo {
		req, err := newChallengeSecretPrompt(hop.Endpoint().String(), instruction, prompt)
		if err != nil {
			return kiQuestionPlan{}, err
		}
		return kiQuestionPlan{action: kiActionPromptSecret, promptReq: req}, nil
	}
	reply, err := d.promptInteractiveText(ctx, hop.Endpoint().String(), instruction, prompt)
	if err != nil {
		return kiQuestionPlan{}, err
	}
	return kiQuestionPlan{action: kiActionLiteral, answer: reply}, nil
}

// buildEmptyPromptChallengeBody 为远端 PAM 空提示构造结构化应答消息：
//   - 横幅同为空时返回 KeyInteractChallengeResponse；
//   - 横幅非空时返回携带脱敏有界 banner 参数的 KeyInteractChallengeBannerResponse，
//     在非英文环境下保留远端横幅并本地化应答尾缀。
func buildEmptyPromptChallengeBody(cleanInstr string) domi18n.Message {
	if cleanInstr == "" {
		return domi18n.NewMessage(domi18n.KeyInteractChallengeResponse)
	}
	budget := maxInteractivePromptBytes - len(domi18n.KeyInteractChallengeBannerResponse) - len(domi18n.CanonicalFallback(domi18n.KeyInteractChallengeBannerResponse))
	banner := strings.TrimSpace(truncateUTF8Bytes(cleanInstr, budget))
	if banner == "" {
		return domi18n.NewMessage(domi18n.KeyInteractChallengeResponse)
	}
	return domi18n.NewMessage(domi18n.KeyInteractChallengeBannerResponse, domi18n.BoundStr("banner", banner))
}

// formatNonEmptyKIPrompt 构造携带非空远端 PAM 问题的脱敏展示文本：
// 规则匹配仍保留完整 4 KiB pendingBanner，交互回退展示时先经 security.SanitizePromptText 脱敏，
// 再按 UTF-8 字符边界截断至 <= 512 字节（优先完整保留问题正文），防止超长 MFA 横幅触发 ports.ErrInvalidArgument。
func formatNonEmptyKIPrompt(cleanInstr, cleanPrompt string) string {
	cleanPrompt = strings.TrimSpace(truncateUTF8Bytes(cleanPrompt, maxInteractivePromptBytes))
	if cleanInstr == "" {
		return cleanPrompt
	}
	const sep = " | "
	budget := maxInteractivePromptBytes - len(cleanPrompt) - len(sep)
	if budget <= 0 {
		return cleanPrompt
	}
	cleanInstr = strings.TrimSpace(truncateUTF8Bytes(cleanInstr, budget))
	if cleanInstr == "" {
		return cleanPrompt
	}
	return cleanInstr + sep + cleanPrompt
}

func truncateUTF8Bytes(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	if maxBytes <= 0 {
		return ""
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func (d *Dialer) planMatchedRuleKIQuestion(ctx context.Context, rule inventory.ChallengeRule, loginPassRef algebraic.Option[secret.Ref]) (kiQuestionPlan, error) {
	switch r := rule.(type) {
	case *inventory.RuleTOTP:
		code, err := d.computeTOTPFromVault(ctx, r.TOTPSecretRef())
		if err != nil {
			return kiQuestionPlan{}, err
		}
		return kiQuestionPlan{action: kiActionLiteral, answer: code}, nil
	case *inventory.RuleSecretRef:
		if d.vault == nil {
			return kiQuestionPlan{}, domi18n.EF(ports.ErrAuthFailed, domi18n.KeyCommonMissingDep, domi18n.Str("component", "SecretVault"))
		}
		return kiQuestionPlan{action: kiActionVaultSecret, secretRef: r.SecretRef()}, nil
	case *inventory.RuleLoginPassword:
		ref, hasRef := loginPassRef.Get()
		if !hasRef || d.vault == nil {
			return kiQuestionPlan{}, domi18n.EF(ports.ErrAuthFailed, domi18n.KeyCommonMissingDep, domi18n.Str("component", "login password secret or SecretVault"))
		}
		return kiQuestionPlan{action: kiActionVaultSecret, secretRef: ref}, nil
	case *inventory.RuleCommand:
		ans, err := d.runChallengeCommand(ctx, r)
		if err != nil {
			return kiQuestionPlan{}, err
		}
		return kiQuestionPlan{action: kiActionLiteral, answer: ans}, nil
	default:
		return kiQuestionPlan{}, domi18n.EF(ports.ErrAuthFailed, domi18n.KeyCommonNotSupported, domi18n.Str("feature", "challenge rule"))
	}
}

// buildChallengePromptParts 构造质询提示标题、清洗后正文与可选结构化消息：
// 仅当远端 prompt 为空时附带 BodyMessage（无横幅用 KeyInteractChallengeResponse，有横幅用
// KeyInteractChallengeBannerResponse）；远端 prompt 非空时保持 BodyMessage=None 原样透传远端 PAM 提示。
func buildChallengePromptParts(instruction, prompt string) (string, domi18n.Message, string, algebraic.Option[domi18n.Message]) {
	titleMsg := domi18n.NewMessage(domi18n.KeyInteractSSHChallengeTitle)
	cleanPrompt := strings.TrimSpace(security.SanitizePromptText(prompt))
	cleanInstr := strings.TrimSpace(security.SanitizePromptText(instruction))
	if cleanPrompt == "" {
		bodyMsg := buildEmptyPromptChallengeBody(cleanInstr)
		return titleMsg.Canonical(), titleMsg, bodyMsg.Canonical(), algebraic.Some(bodyMsg)
	}
	return titleMsg.Canonical(), titleMsg, formatNonEmptyKIPrompt(cleanInstr, cleanPrompt), algebraic.None[domi18n.Message]()
}

func newChallengeSecretPrompt(subject, instruction, prompt string) (ports.SecretPromptRequest, error) {
	title, titleMsg, body, bodyMsg := buildChallengePromptParts(instruction, prompt)
	return ports.NewSecretPromptRequest(ports.SecretPromptRequestSpec{
		Title:        title,
		Prompt:       body,
		Subject:      subject,
		AllowEmpty:   true,
		TitleMessage: algebraic.Some(titleMsg),
		BodyMessage:  bodyMsg,
	})
}

func (d *Dialer) promptInteractiveText(ctx context.Context, subject, instruction, prompt string) (string, error) {
	title, titleMsg, body, bodyMsg := buildChallengePromptParts(instruction, prompt)
	req, err := ports.NewTextPromptRequest(ports.TextPromptRequestSpec{
		Title:        title,
		Prompt:       body,
		Subject:      subject,
		AllowEmpty:   true,
		TitleMessage: algebraic.Some(titleMsg),
		BodyMessage:  bodyMsg,
	})
	if err != nil {
		return "", err
	}
	return d.interaction.PromptText(ctx, req)
}

func (d *Dialer) runChallengeCommand(ctx context.Context, rule *inventory.RuleCommand) (string, error) {
	if d.process == nil {
		return "", domi18n.EF(ports.ErrAuthFailed, domi18n.KeyCommonMissingDep, domi18n.Str("component", "ProcessPort"))
	}
	spec, err := ports.NewProcessSpec(ports.ProcessSpecInput{
		Command: rule.Command(),
		Args:    rule.Args(),
		Timeout: rule.Timeout(),
	})
	if err != nil {
		return "", err
	}
	res, err := d.process.Run(ctx, spec, nil)
	if err != nil {
		return "", domi18n.WrapS(ports.ErrAuthFailed, err, domi18n.KeyDialChallengeCmdFailed)
	}
	if !res.Succeeded() {
		return "", domi18n.EF(ports.ErrAuthFailed, domi18n.KeyDialChallengeCmdFailed)
	}
	if res.Truncated() {
		return "", domi18n.EF(ports.ErrAuthFailed, domi18n.KeyDialChallengeCmdFailed)
	}
	return strings.TrimRight(string(res.Stdout()), "\r\n"), nil
}

func matchChallengeRule(rules []inventory.ChallengeRule, instruction, prompt string) (inventory.ChallengeRule, bool) {
	for _, r := range rules {
		if r != nil && r.IsValid() && r.Matches(instruction, prompt) {
			return r, true
		}
	}
	return nil, false
}

func findLoginPasswordRef(m inventory.AuthMethod) algebraic.Option[secret.Ref] {
	if m == nil || !m.IsValid() {
		return algebraic.None[secret.Ref]()
	}
	switch v := m.(type) {
	case *inventory.AuthPassword:
		return algebraic.Some(v.PasswordRef())
	case *inventory.AuthComposite:
		for _, sub := range v.Methods() {
			if ref := findLoginPasswordRef(sub); ref.IsSome() {
				return ref
			}
		}
		return algebraic.None[secret.Ref]()
	case *inventory.AuthPrivateKey, *inventory.AuthAgent, *inventory.AuthKeyboardInteractive:
		return algebraic.None[secret.Ref]()
	default:
		return algebraic.None[secret.Ref]()
	}
}
