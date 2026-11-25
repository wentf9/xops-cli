package dial

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"

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

// buildKeyboardInteractiveAuth 适配 RFC 4256 质询应答（遵循 secrettaint/sinks_narrow.go P4-T1 窄消费模式，零 nolint 豁免）。
func (d *Dialer) buildKeyboardInteractiveAuth(ctx context.Context, hop plan.HopSpec, ki *inventory.AuthKeyboardInteractive, loginPassRef algebraic.Option[secret.Ref]) ssh.AuthMethod {
	rules := ki.Rules()
	return ssh.KeyboardInteractive(func(_ string, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		for i, q := range questions {
			qp, err := d.planKIQuestion(ctx, hop, rules, loginPassRef, instruction, q, echoAt(echos, i))
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
) (kiQuestionPlan, error) {
	rule, matched := matchChallengeRule(rules, instruction, prompt)
	if !matched {
		return d.planInteractiveKIQuestion(ctx, hop, prompt, echo)
	}
	return d.planMatchedRuleKIQuestion(ctx, rule, loginPassRef)
}

func (d *Dialer) planInteractiveKIQuestion(ctx context.Context, hop plan.HopSpec, prompt string, echo bool) (kiQuestionPlan, error) {
	if hop.Transport().BatchMode() || d.interaction == nil || !d.interaction.CanInteract() {
		return kiQuestionPlan{}, fmt.Errorf("%w: 质询 %q 未命中任何规则且不可交互", ports.ErrAuthFailed, prompt)
	}
	if !echo {
		req, err := newChallengeSecretPrompt(hop.Endpoint().String(), prompt)
		if err != nil {
			return kiQuestionPlan{}, err
		}
		return kiQuestionPlan{action: kiActionPromptSecret, promptReq: req}, nil
	}
	reply, err := d.promptInteractiveText(ctx, hop.Endpoint().String(), prompt)
	if err != nil {
		return kiQuestionPlan{}, err
	}
	return kiQuestionPlan{action: kiActionLiteral, answer: reply}, nil
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

// computeTOTPFromVault 在同步明文闭包内按 RFC 6238 计算 6 位 HMAC-SHA1 动态口令（不向外部泄露原始密钥）。
func (d *Dialer) computeTOTPFromVault(ctx context.Context, ref secret.Ref) (string, error) {
	if d.vault == nil {
		return "", fmt.Errorf("%w: TOTP 质询需要注入 SecretVault", ports.ErrAuthFailed)
	}
	now := time.Now()
	if d.clock != nil {
		now = d.clock.Now()
	}
	counter := uint64(max(now.Unix()/defaultTOTPPeriodSecond, 0))
	var code string
	err := d.vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
		return box.Use(func(plain []byte) error {
			cleaned := strings.TrimRight(strings.ToUpper(strings.Join(strings.Fields(string(plain)), "")), "=")
			key, decErr := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(cleaned)
			if decErr != nil {
				return fmt.Errorf("%w: TOTP Base32 密钥解码失败: %w", ports.ErrAuthFailed, decErr)
			}
			defer clear(key)
			mac := hmac.New(sha1.New, key)
			var buf [8]byte
			binary.BigEndian.PutUint64(buf[:], counter)
			_, _ = mac.Write(buf[:])
			sum := mac.Sum(nil)
			offset := sum[len(sum)-1] & 0x0f
			binCode := (uint32(sum[offset]&0x7f) << 24) |
				(uint32(sum[offset+1]) << 16) |
				(uint32(sum[offset+2]) << 8) |
				uint32(sum[offset+3])
			mod := uint32(math.Pow10(defaultTOTPDigits))
			code = fmt.Sprintf("%0*d", defaultTOTPDigits, binCode%mod)
			return nil
		})
	})
	return code, err
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
