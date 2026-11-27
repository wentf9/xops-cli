package inventory

import (
	"regexp"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/secret"
)

const forbiddenCmdShellMeta = ";|&$`\r\n"

// ChallengeRuleKind 标识 keyboard-interactive 质询应答规则类别；零值 ChallengeRuleKindInvalid 失败关闭。
//
//xops:opaque
//xops:failclosed
type ChallengeRuleKind uint8

const (
	ChallengeRuleKindInvalid       ChallengeRuleKind = iota // 无效规则类别（零值失败关闭）
	ChallengeRuleKindTOTP                                   // 托管 TOTP 种子引用规则
	ChallengeRuleKindSecretRef                              // 静态机密凭据引用规则
	ChallengeRuleKindCommand                                // 外部可执行命令提供者规则
	ChallengeRuleKindLoginPassword                          // 复用身份登录密码规则
)

// ParseChallengeRuleKind 严格解析质询规则类别文本（totp/secret_ref/command/login_password）。
func ParseChallengeRuleKind(raw string) (ChallengeRuleKind, error) {
	return parseEnumByName(raw, ChallengeRuleKindTOTP, ChallengeRuleKindLoginPassword, ChallengeRuleKindInvalid, ChallengeRuleKind.String, ErrInvalidChallengeRule)
}
func (k ChallengeRuleKind) IsValid() bool {
	return k >= ChallengeRuleKindTOTP && k <= ChallengeRuleKindLoginPassword
}
func (k ChallengeRuleKind) IsZero() bool { return k == ChallengeRuleKindInvalid }
func (k ChallengeRuleKind) String() string {
	return enumName(uint8(k), "invalid", "invalid", "totp", "secret_ref", "command", "login_password")
}
func (k ChallengeRuleKind) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, k.IsValid(), k.String(), ErrInvalidChallengeRule)
}
func (k ChallengeRuleKind) MarshalText() ([]byte, error) { return k.AppendText(nil) }
func (k *ChallengeRuleKind) UnmarshalText(b []byte) error {
	return unmarshalText(k, b, ParseChallengeRuleKind)
}

// ChallengeRule 是 keyboard-interactive 质询应答规则的封闭和类型（RFC §3.6）：
// *RuleTOTP | *RuleSecretRef | *RuleCommand | *RuleLoginPassword。
//
//xops:failclosed
type ChallengeRule interface {
	sealedChallengeRule()
	Kind() ChallengeRuleKind
	Name() string
	PromptPattern() string
	InstructionPattern() string
	Matches(instruction, prompt string) bool
	IsValid() bool
}

// ChallengeRuleMeta 承载全部质询规则共用的命名与正则匹配元数据。
type ChallengeRuleMeta struct{ Name, PromptPattern, InstructionPattern string }

type ruleMeta struct {
	name, promptPattern, instrPattern string
	promptRegex, instrRegex           *regexp.Regexp
}

func compileRuleMeta(meta ChallengeRuleMeta, requireName bool) (ruleMeta, error) {
	name := strings.TrimSpace(meta.Name)
	if (requireName && name == "") || (name != "" && validateAssetIdent(name, false) != nil) {
		return ruleMeta{}, domi18n.EF(ErrInvalidChallengeRule, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "name"), domi18n.BoundStr("value", meta.Name))
	}
	pr, err := compileBoundedRegex(meta.PromptPattern, true)
	if err != nil {
		return ruleMeta{}, err
	}
	ir, err := compileBoundedRegex(meta.InstructionPattern, false)
	if err != nil {
		return ruleMeta{}, err
	}
	return ruleMeta{name, meta.PromptPattern, meta.InstructionPattern, pr, ir}, nil
}
func compileBoundedRegex(pat string, required bool) (*regexp.Regexp, error) {
	if pat == "" {
		return nil, pickIf[error](required, domi18n.EF(ErrInvalidChallengeRule, domi18n.KeyCommonFieldEmpty, domi18n.Str("field", "pattern")), nil)
	}
	if len(pat) > maxPatternBytes || hasForbiddenText(pat) {
		return nil, domi18n.EF(ErrInvalidChallengeRule, domi18n.KeyCommonInvalidTextChars, domi18n.Str("field", "pattern"))
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		return nil, domi18n.WrapS(ErrInvalidChallengeRule, err, domi18n.KeyInventoryRegexCompileFailed)
	}
	return re, nil
}
func (m ruleMeta) matches(inst, prompt string) bool {
	return m.promptRegex != nil && m.promptRegex.MatchString(prompt) && (m.instrRegex == nil || m.instrRegex.MatchString(inst))
}
func (m ruleMeta) equal(o ruleMeta) bool {
	return m.name == o.name && m.promptPattern == o.promptPattern && m.instrPattern == o.instrPattern
}

// RuleTOTP、RuleSecretRef、RuleCommand 与 RuleLoginPassword 为 ChallengeRule 全部封闭不可变变体。
//
//xops:opaque
//xops:failclosed
type RuleTOTP struct {
	meta          ruleMeta
	totpSecretRef secret.Ref
	valid         bool
}

//xops:opaque
//xops:failclosed
type RuleSecretRef struct {
	meta      ruleMeta
	secretRef secret.Ref
	valid     bool
}

//xops:opaque
//xops:failclosed
type RuleCommand struct {
	meta    ruleMeta
	command string
	args    []string
	timeout algebraic.Option[algebraic.Duration]
	valid   bool
}

//xops:opaque
//xops:failclosed
type RuleLoginPassword struct {
	meta  ruleMeta
	valid bool
}

// NewRuleTOTP、NewRuleSecretRef、NewRuleCommand 与 NewRuleLoginPassword 校验并构造质询规则。
func compileSecretRule(meta ChallengeRuleMeta, requireName bool, ref secret.Ref) (ruleMeta, error) {
	cm, err := compileRuleMeta(meta, requireName)
	if err != nil || !ref.IsValid() {
		return ruleMeta{}, domi18n.EF(ErrInvalidChallengeRule, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "challenge_rule"))
	}
	return cm, nil
}
func NewRuleTOTP(meta ChallengeRuleMeta, ref secret.Ref) (*RuleTOTP, error) {
	cm, err := compileSecretRule(meta, false, ref)
	return pickIf(err == nil, &RuleTOTP{cm, ref, true}, nil), err
}
func NewRuleSecretRef(meta ChallengeRuleMeta, ref secret.Ref) (*RuleSecretRef, error) {
	cm, err := compileSecretRule(meta, true, ref)
	return pickIf(err == nil, &RuleSecretRef{cm, ref, true}, nil), err
}
func NewRuleCommand(meta ChallengeRuleMeta, command string, args []string, timeout algebraic.Option[algebraic.Duration]) (*RuleCommand, error) {
	cm, err := compileRuleMeta(meta, false)
	if err != nil {
		return nil, err
	}
	cmd := strings.TrimSpace(command)
	if cmd == "" || len(cmd) > maxCommandBytes || hasForbiddenText(command) || strings.ContainsAny(cmd, forbiddenCmdShellMeta) || len(args) > maxCommandArgs ||
		slices.ContainsFunc(args, func(a string) bool { return len(a) > maxCommandBytes || hasForbiddenText(a) }) {
		return nil, domi18n.EF(ErrInvalidChallengeRule, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "command/args"))
	}
	if d, ok := timeout.Get(); ok && !d.IsPositive() {
		return nil, domi18n.EF(ErrInvalidChallengeRule, domi18n.KeyCommonFieldPositive, domi18n.Str("field", "timeout"))
	}
	return &RuleCommand{cm, cmd, slices.Clone(args), timeout, true}, nil
}
func NewRuleLoginPassword(meta ChallengeRuleMeta) (*RuleLoginPassword, error) {
	cm, err := compileRuleMeta(meta, false)
	return pickIf(err == nil, &RuleLoginPassword{cm, true}, nil), err
}

func (*RuleTOTP) sealedChallengeRule()          {}
func (*RuleSecretRef) sealedChallengeRule()     {}
func (*RuleCommand) sealedChallengeRule()       {}
func (*RuleLoginPassword) sealedChallengeRule() {}

// 四类质询规则的零值与 nil 安全只读访问器与正则匹配方法。
func (r *RuleTOTP) rm() ruleMeta               { return getValid(r, func(v *RuleTOTP) ruleMeta { return v.meta }) }
func (r *RuleTOTP) IsValid() bool              { return r != nil && r.valid && r.totpSecretRef.IsValid() }
func (r *RuleTOTP) Kind() ChallengeRuleKind    { return kindIf(r.IsValid(), ChallengeRuleKindTOTP) }
func (r *RuleTOTP) Name() string               { return r.rm().name }
func (r *RuleTOTP) PromptPattern() string      { return r.rm().promptPattern }
func (r *RuleTOTP) InstructionPattern() string { return r.rm().instrPattern }
func (r *RuleTOTP) TOTPSecretRef() secret.Ref {
	return getValid(r, func(v *RuleTOTP) secret.Ref { return v.totpSecretRef })
}
func (r *RuleTOTP) Matches(inst, p string) bool { return r.rm().matches(inst, p) }
func (r *RuleSecretRef) rm() ruleMeta {
	return getValid(r, func(v *RuleSecretRef) ruleMeta { return v.meta })
}
func (r *RuleSecretRef) IsValid() bool { return r != nil && r.valid && r.secretRef.IsValid() }
func (r *RuleSecretRef) Kind() ChallengeRuleKind {
	return kindIf(r.IsValid(), ChallengeRuleKindSecretRef)
}
func (r *RuleSecretRef) Name() string               { return r.rm().name }
func (r *RuleSecretRef) PromptPattern() string      { return r.rm().promptPattern }
func (r *RuleSecretRef) InstructionPattern() string { return r.rm().instrPattern }
func (r *RuleSecretRef) SecretRef() secret.Ref {
	return getValid(r, func(v *RuleSecretRef) secret.Ref { return v.secretRef })
}
func (r *RuleSecretRef) Matches(inst, p string) bool { return r.rm().matches(inst, p) }
func (r *RuleCommand) rm() ruleMeta {
	return getValid(r, func(v *RuleCommand) ruleMeta { return v.meta })
}
func (r *RuleCommand) IsValid() bool              { return r != nil && r.valid && r.command != "" }
func (r *RuleCommand) Kind() ChallengeRuleKind    { return kindIf(r.IsValid(), ChallengeRuleKindCommand) }
func (r *RuleCommand) Name() string               { return r.rm().name }
func (r *RuleCommand) PromptPattern() string      { return r.rm().promptPattern }
func (r *RuleCommand) InstructionPattern() string { return r.rm().instrPattern }
func (r *RuleCommand) Command() string {
	return getValid(r, func(v *RuleCommand) string { return v.command })
}
func (r *RuleCommand) Args() []string {
	return getValid(r, func(v *RuleCommand) []string { return slices.Clone(v.args) })
}
func (r *RuleCommand) Timeout() algebraic.Option[algebraic.Duration] {
	return getValid(r, func(v *RuleCommand) algebraic.Option[algebraic.Duration] { return v.timeout })
}
func (r *RuleCommand) Matches(inst, p string) bool { return r.rm().matches(inst, p) }
func (r *RuleLoginPassword) rm() ruleMeta {
	return getValid(r, func(v *RuleLoginPassword) ruleMeta { return v.meta })
}
func (r *RuleLoginPassword) IsValid() bool { return r != nil && r.valid }
func (r *RuleLoginPassword) Kind() ChallengeRuleKind {
	return kindIf(r.IsValid(), ChallengeRuleKindLoginPassword)
}
func (r *RuleLoginPassword) Name() string                { return r.rm().name }
func (r *RuleLoginPassword) PromptPattern() string       { return r.rm().promptPattern }
func (r *RuleLoginPassword) InstructionPattern() string  { return r.rm().instrPattern }
func (r *RuleLoginPassword) Matches(inst, p string) bool { return r.rm().matches(inst, p) }

// EqualChallengeRule 严格比对两条 ChallengeRule 是否均有效且语义一致。
func EqualChallengeRule(a, b ChallengeRule) bool {
	if a == nil || b == nil || !a.IsValid() || !b.IsValid() {
		return false
	}
	switch va := a.(type) {
	case *RuleTOTP:
		vb, ok := b.(*RuleTOTP)
		return ok && vb.IsValid() && va.meta.equal(vb.meta) && va.totpSecretRef.Equal(vb.totpSecretRef)
	case *RuleSecretRef:
		vb, ok := b.(*RuleSecretRef)
		return ok && vb.IsValid() && va.meta.equal(vb.meta) && va.secretRef.Equal(vb.secretRef)
	case *RuleCommand:
		vb, ok := b.(*RuleCommand)
		return ok && vb.IsValid() && va.meta.equal(vb.meta) && va.command == vb.command &&
			slices.Equal(va.args, vb.args) && equalOptionFunc(va.timeout, vb.timeout, algebraic.Duration.Equal)
	case *RuleLoginPassword:
		vb, ok := b.(*RuleLoginPassword)
		return ok && vb.IsValid() && va.meta.equal(vb.meta)
	default:
		return false
	}
}

func writeChallengeRuleCanonical(enc *canonicalEncoder, r ChallengeRule) error {
	if r == nil || !r.IsValid() {
		return ErrInvalidChallengeRule
	}
	enc.writeUint8(uint8(r.Kind()))
	enc.writeString(r.Name())
	enc.writeString(r.PromptPattern())
	enc.writeString(r.InstructionPattern())
	switch v := r.(type) {
	case *RuleTOTP:
		enc.writeString(v.totpSecretRef.String())
	case *RuleSecretRef:
		enc.writeString(v.secretRef.String())
	case *RuleCommand:
		enc.writeString(v.command)
		enc.writeUint64(uint64(len(v.args)))
		for _, a := range v.args {
			enc.writeString(a)
		}
		d, ok := v.timeout.Get()
		enc.writeUint8(pickIf[uint8](ok, 1, 0))
		if ok {
			enc.writeUint64(uint64(d.Std()))
		}
	case *RuleLoginPassword:
	default:
		return ErrInvalidChallengeRule
	}
	return enc.err
}
