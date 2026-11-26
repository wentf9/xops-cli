package dial

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"strconv"
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

type totpAlgorithm uint8

const (
	totpAlgoInvalid totpAlgorithm = iota
	totpAlgoSHA1
	totpAlgoSHA256
	totpAlgoSHA512
)

// buildKeyboardInteractiveAuth 适配 RFC 4256 多轮质询应答循环（严格遵循 secrettaint/sinks_narrow.go
// P4-T1 窄消费模式，限定轮次与单轮问题上限、检查 ctx 取消，零 nolint 豁免）。
func (d *Dialer) buildKeyboardInteractiveAuth(ctx context.Context, hop plan.HopSpec, ki *inventory.AuthKeyboardInteractive, loginPassRef algebraic.Option[secret.Ref]) ssh.AuthMethod {
	rules := ki.Rules()
	rounds := 0
	return ssh.KeyboardInteractive(func(_ string, instruction string, questions []string, echos []bool) ([]string, error) {
		rounds++
		if err := checkKIRoundLimit(ctx, rounds, len(questions)); err != nil {
			return nil, err
		}
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

// computeTOTPFromVault 在同步明文闭包内按 RFC 6238 / RFC 4226 计算动态口令：
// 支持原始 Base32（容忍空格、连字符、小写与可选 '=' 填充）及标准 otpauth://totp/... URI
// （支持 algorithm=SHA1|SHA256|SHA512、digits=6..10、period>0），绝不向外部或错误消息泄露种子明文。
func (d *Dialer) computeTOTPFromVault(ctx context.Context, ref secret.Ref) (string, error) {
	if d.vault == nil {
		return "", fmt.Errorf("%w: TOTP 质询需要注入 SecretVault", ports.ErrAuthFailed)
	}
	now := time.Now()
	if d.clock != nil {
		now = d.clock.Now()
	}
	unixSec := now.Unix()
	if unixSec < 0 {
		return "", fmt.Errorf("%w: TOTP 时钟早于 Unix 纪元", ports.ErrAuthFailed)
	}
	var code string
	err := d.vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
		return box.Use(func(plain []byte) error {
			generated, tErr := computeTOTPFromPlainBytes(plain, unixSec)
			if tErr != nil {
				return tErr
			}
			code = generated
			return nil
		})
	})
	return code, err
}

// computeTOTPFromPlainBytes 在同步明文作用域内完成 otpauth:// 或 Base32 解码与 RFC 6238 HMAC 动态截断，
// 仅返回净化后的数字口令与不含任何明文的静态错误（零 nolint）。
//
//xops:secretuse
func computeTOTPFromPlainBytes(plain []byte, unixSec int64) (string, error) {
	raw := strings.TrimSpace(string(plain))
	if raw == "" {
		return "", fmt.Errorf("%w: TOTP 种子为空", ports.ErrAuthFailed)
	}
	if strings.HasPrefix(strings.ToLower(raw), "otpauth://") {
		return computeOTPAuthTOTP(raw, unixSec)
	}
	return decodeAndComputeTOTP(raw, totpAlgoSHA1, defaultTOTPDigits, defaultTOTPPeriodSecond, unixSec)
}

// computeOTPAuthTOTP 解析标准 otpauth://totp URI 参数并在同作用域内完成 RFC 6238 口令计算。
//
//xops:secretuse
func computeOTPAuthTOTP(raw string, unixSec int64) (string, error) {
	rest := raw[len("otpauth://"):]
	hostAndPath, query, hasQuery := strings.Cut(rest, "?")
	otpType, _, _ := strings.Cut(hostAndPath, "/")
	if !strings.EqualFold(otpType, "totp") || !hasQuery {
		return "", fmt.Errorf("%w: 仅支持包含查询参数的 otpauth://totp URI", ports.ErrAuthFailed)
	}
	algo := totpAlgoSHA1
	digits := defaultTOTPDigits
	period := defaultTOTPPeriodSecond
	var b32Source string
	for pair := range strings.SplitSeq(query, "&") {
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(k) {
		case "secret":
			b32Source = strings.ReplaceAll(strings.ReplaceAll(v, "%3D", "="), "%3d", "=")
		case "algorithm":
			algo = classifyTOTPAlgorithm(v)
		case "digits":
			digits = classifyTOTPDigits(v)
		case "period":
			p, pErr := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if pErr != nil || p <= 0 {
				return "", fmt.Errorf("%w: TOTP period 参数须为正整数", ports.ErrAuthFailed)
			}
			period = p
		}
	}
	if b32Source == "" || algo == totpAlgoInvalid || digits == 0 {
		return "", fmt.Errorf("%w: otpauth URI 缺少有效 secret/algorithm/digits 参数", ports.ErrAuthFailed)
	}
	return decodeAndComputeTOTP(b32Source, algo, digits, period, unixSec)
}

// decodeAndComputeTOTP 清洗 Base32 种子、立即清零解码密钥并经标准库 HMAC 净化输出动态口令。
//
//xops:secretuse
func decodeAndComputeTOTP(b32Source string, algo totpAlgorithm, digits int, period, unixSec int64) (string, error) {
	cleaned := strings.TrimRight(strings.ToUpper(strings.ReplaceAll(strings.Join(strings.Fields(b32Source), ""), "-", "")), "=")
	if cleaned == "" {
		return "", fmt.Errorf("%w: TOTP Base32 种子为空", ports.ErrAuthFailed)
	}
	key, decErr := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(cleaned)
	if decErr != nil || len(key) == 0 {
		clear(key)
		return "", fmt.Errorf("%w: TOTP Base32 密钥解码失败", ports.ErrAuthFailed)
	}
	defer clear(key)

	var hashCtor func() hash.Hash
	switch algo {
	case totpAlgoSHA256:
		hashCtor = sha256.New
	case totpAlgoSHA512:
		hashCtor = sha512.New
	default:
		hashCtor = sha1.New
	}
	mac := hmac.New(hashCtor, key)
	counter := uint64(unixSec / period)
	buf := [8]byte{
		byte(counter >> 56), byte(counter >> 48), byte(counter >> 40), byte(counter >> 32),
		byte(counter >> 24), byte(counter >> 16), byte(counter >> 8), byte(counter),
	}
	_, _ = mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	binCode := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return formatTOTPDigits(binCode, digits), nil
}

// classifyTOTPAlgorithm 将算法参数映射为编译期常量枚举（零明文回传）。
//
//xops:secretuse
func classifyTOTPAlgorithm(raw string) totpAlgorithm {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "", "SHA1":
		return totpAlgoSHA1
	case "SHA256":
		return totpAlgoSHA256
	case "SHA512":
		return totpAlgoSHA512
	default:
		return totpAlgoInvalid
	}
}

// classifyTOTPDigits 将位数参数映射为编译期常量 6..10（非法值返回 0，零明文回传）。
//
//xops:secretuse
func classifyTOTPDigits(raw string) int {
	switch strings.TrimSpace(raw) {
	case "", "6":
		return 6
	case "7":
		return 7
	case "8":
		return 8
	case "9":
		return 9
	case "10":
		return 10
	default:
		return 0
	}
}

func formatTOTPDigits(binCode uint32, digits int) string {
	switch digits {
	case 7:
		return fmt.Sprintf("%07d", uint64(binCode)%10_000_000)
	case 8:
		return fmt.Sprintf("%08d", uint64(binCode)%100_000_000)
	case 9:
		return fmt.Sprintf("%09d", uint64(binCode)%1_000_000_000)
	case 10:
		return fmt.Sprintf("%010d", uint64(binCode)%10_000_000_000)
	default:
		return fmt.Sprintf("%06d", uint64(binCode)%1_000_000)
	}
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
