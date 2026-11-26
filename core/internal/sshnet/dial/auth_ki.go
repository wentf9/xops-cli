package dial

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
)

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
		return fmt.Errorf("%w: Keyboard-Interactive 质询轮次或问题数超过安全上限", ports.ErrAuthFailed)
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
		return kiQuestionPlan{}, fmt.Errorf("%w: 质询 %q 未命中可用自动规则且不可交互", ports.ErrAuthFailed, prompt)
	}
	displayPrompt := formatInteractiveKIPrompt(instruction, prompt)
	if !echo {
		req, err := newChallengeSecretPrompt(hop.Endpoint().String(), displayPrompt)
		if err != nil {
			return kiQuestionPlan{}, err
		}
		return kiQuestionPlan{action: kiActionPromptSecret, promptReq: req}, nil
	}
	reply, err := d.promptInteractiveText(ctx, hop.Endpoint().String(), displayPrompt)
	if err != nil {
		return kiQuestionPlan{}, err
	}
	return kiQuestionPlan{action: kiActionLiteral, answer: reply}, nil
}

func formatInteractiveKIPrompt(instruction, prompt string) string {
	p := normalizeChallengePrompt(prompt)
	instr := strings.TrimSpace(instruction)
	if instr == "" {
		return p
	}
	return instr + "\n" + p
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
			return kiQuestionPlan{}, fmt.Errorf("%w: 质询凭据消费需要注入 SecretVault", ports.ErrAuthFailed)
		}
		return kiQuestionPlan{action: kiActionVaultSecret, secretRef: r.SecretRef()}, nil
	case *inventory.RuleLoginPassword:
		ref, hasRef := loginPassRef.Get()
		if !hasRef || d.vault == nil {
			return kiQuestionPlan{}, fmt.Errorf("%w: RuleLoginPassword 缺少关联登录密码凭据引用或 SecretVault", ports.ErrAuthFailed)
		}
		return kiQuestionPlan{action: kiActionVaultSecret, secretRef: ref}, nil
	case *inventory.RuleCommand:
		ans, err := d.runChallengeCommand(ctx, r)
		if err != nil {
			return kiQuestionPlan{}, err
		}
		return kiQuestionPlan{action: kiActionLiteral, answer: ans}, nil
	default:
		return kiQuestionPlan{}, fmt.Errorf("%w: 未知质询规则 %T", ports.ErrAuthFailed, rule)
	}
}

func newChallengeSecretPrompt(subject, prompt string) (ports.SecretPromptRequest, error) {
	return ports.NewSecretPromptRequest(ports.SecretPromptRequestSpec{
		Title:      "SSH Challenge",
		Prompt:     normalizeChallengePrompt(prompt),
		Subject:    subject,
		AllowEmpty: true,
	})
}

func (d *Dialer) promptInteractiveText(ctx context.Context, subject, prompt string) (string, error) {
	req, err := ports.NewTextPromptRequest(ports.TextPromptRequestSpec{
		Title: "SSH Challenge", Prompt: normalizeChallengePrompt(prompt), Subject: subject, AllowEmpty: true,
	})
	if err != nil {
		return "", err
	}
	return d.interaction.PromptText(ctx, req)
}

func normalizeChallengePrompt(prompt string) string {
	if strings.TrimSpace(prompt) == "" {
		return "Response:"
	}
	return prompt
}

func (d *Dialer) runChallengeCommand(ctx context.Context, rule *inventory.RuleCommand) (string, error) {
	if d.process == nil {
		return "", fmt.Errorf("%w: RuleCommand 需要注入 ProcessPort", ports.ErrAuthFailed)
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
		return "", fmt.Errorf("%w: 执行质询命令失败: %w", ports.ErrAuthFailed, err)
	}
	if !res.Succeeded() {
		return "", fmt.Errorf("%w: 质询命令返回非零退出状态", ports.ErrAuthFailed)
	}
	if res.Truncated() {
		return "", fmt.Errorf("%w: 质询命令输出被截断", ports.ErrAuthFailed)
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
