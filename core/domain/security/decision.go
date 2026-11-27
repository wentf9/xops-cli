package security

import (
	"cmp"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

// DecisionKind 表示 GuardrailDecision 的三态判别枚举，零值恒为 DecisionKindDeny（限制支配吸收元）。
//
//xops:opaque
//xops:failclosed
type DecisionKind uint8

const (
	DecisionKindDeny         DecisionKind = iota // 零值失败关闭判定类别（最严，吸收 NeedApproval 与 Allow）
	DecisionKindNeedApproval                     // 需用户显式审批挑战（次严，吸收 Allow）
	DecisionKindAllow                            // 策略显式允许执行（最宽，限制支配并半格单位元）
)

// ParseDecisionKind 严格解析规范小写决策类别（"deny"、"need_approval"、"allow"）。
func ParseDecisionKind(raw string) (DecisionKind, error) {
	return parseEnumByName(raw, DecisionKindDeny, DecisionKindAllow, DecisionKindDeny, DecisionKind.String, ErrInvalidDecision)
}

// IsValid 报告 k 是否为合法的 DecisionKind。
func (k DecisionKind) IsValid() bool { return k <= DecisionKindAllow }

// IsZero 报告 k 是否处于零值拒绝态（DecisionKindDeny）。
func (k DecisionKind) IsZero() bool { return k == DecisionKindDeny }

// StrictnessRank 返回决策限制严苛度全序秩（Allow=1 < NeedApproval=2 < Deny/非法=3）。
func (k DecisionKind) StrictnessRank() uint8 { return pickIf(k.IsValid(), 3-uint8(k), 3) }

// CompareStrictness 按限制严苛度顺序比较两个 DecisionKind。
func (k DecisionKind) CompareStrictness(other DecisionKind) int {
	return cmp.Compare(k.StrictnessRank(), other.StrictnessRank())
}

// Join 按限制支配规则合并两个 DecisionKind（Deny 吸收 NeedApproval 吸收 Allow；非法值折叠为 Deny）。
func (k DecisionKind) Join(other DecisionKind) DecisionKind {
	return pickIf(k.IsValid() && other.IsValid(), min(k, other), DecisionKindDeny)
}

// ToVerdict 将 DecisionKind 投影到二值 Verdict：仅显式 DecisionKindAllow 映射为 VerdictAllow。
func (k DecisionKind) ToVerdict() Verdict {
	return pickIf(k == DecisionKindAllow, VerdictAllow, VerdictDeny)
}

// String 返回规范小写文本；非法值返回 "deny(invalid)"。
func (k DecisionKind) String() string {
	return enumName(uint8(k), "deny(invalid)", "deny", "need_approval", "allow")
}

// AppendText 实现 encoding.TextAppender（值接收者）；对非法越界值失败关闭。
func (k DecisionKind) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, k.IsValid(), k.String(), ErrInvalidDecision, uint8(k))
}

// MarshalText 实现 encoding.TextMarshaler（值接收者）。
func (k DecisionKind) MarshalText() ([]byte, error) { return k.AppendText(nil) }

// UnmarshalText 实现 encoding.TextUnmarshaler；失败时重置为 DecisionKindDeny 并失败关闭。
func (k *DecisionKind) UnmarshalText(text []byte) error {
	return unmarshalTextWithReset(k, DecisionKindDeny, text, ParseDecisionKind)
}

// GuardrailDecision 是护栏策略判定的封闭代数和类型（RFC §3.6），仅含三个不可变具体变体：
// *DecisionDeny、*DecisionNeedApproval 与 *DecisionAllow；由 xopsvet/sumexhaust 强制穷尽与 fail-closed default。
//
//xops:failclosed
type GuardrailDecision interface {
	sealedGuardrailDecision()
	Kind() DecisionKind
	Reason() string
	IsValid() bool
	ToVerdict() Verdict
}

// DecisionDeny 表示无条件拒绝执行该操作（限制支配格吸收顶元；零值语义仍为拒绝）。
//
//xops:opaque
//xops:failclosed
type DecisionDeny struct{ code, reason string }

// NewDecisionDeny 构造携带脱敏原因文本的不可变拒绝决策。
func NewDecisionDeny(reason string) *DecisionDeny {
	return &DecisionDeny{reason: SanitizePromptText(reason)}
}

// NewDecisionDenyWithCode 构造携带机器可读拒绝码与原因文本的不可变拒绝决策。
func NewDecisionDenyWithCode(code, reason string) *DecisionDeny {
	return &DecisionDeny{code: SanitizePromptText(code), reason: SanitizePromptText(reason)}
}

func (*DecisionDeny) sealedGuardrailDecision() {}

// Kind 恒返回 DecisionKindDeny。
func (*DecisionDeny) Kind() DecisionKind { return DecisionKindDeny }

// Code 返回拒绝原因代码；nil 接收者返回空串。
func (d *DecisionDeny) Code() string {
	if d == nil {
		return ""
	}
	return d.code
}

// Reason 返回脱敏拒绝原因；nil 接收者返回空串。
func (d *DecisionDeny) Reason() string {
	if d == nil {
		return ""
	}
	return d.reason
}

// IsValid 报告拒绝决策实例是否非 nil。
func (d *DecisionDeny) IsValid() bool { return d != nil }

// ToVerdict 恒返回 VerdictDeny。
func (*DecisionDeny) ToVerdict() Verdict { return VerdictDeny }

// MarshalJSONTo 实现 encoding/json/v2.MarshalerTo（值接收者），输出规范拒绝变体对象。
func (d DecisionDeny) MarshalJSONTo(enc *jsontext.Encoder) error { return MarshalDecisionTo(enc, &d) }

// DecisionNeedApproval 表示操作必须经用户显式审批挑战方可放行；
// 内置正向门控 valid bool，未初始化零值与 typed-nil 均失败关闭为 DecisionDeny。
//
//xops:opaque
//xops:failclosed
type DecisionNeedApproval struct {
	risk   RiskLevel
	reason string
	valid  bool
}

// NewDecisionNeedApproval 校验风险等级并构造不可变需审批决策。
func NewDecisionNeedApproval(risk RiskLevel, reason string) (*DecisionNeedApproval, error) {
	if !risk.IsValid() {
		return nil, domi18n.EF(ErrInvalidRiskLevel, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "risk"))
	}
	return &DecisionNeedApproval{risk: risk, reason: SanitizePromptText(reason), valid: true}, nil
}

func (*DecisionNeedApproval) sealedGuardrailDecision() {}

// IsValid 报告审批决策是否有效且携带合法风险等级。
func (d *DecisionNeedApproval) IsValid() bool { return d != nil && d.valid && d.risk.IsValid() }

// Kind 有效时返回 DecisionKindNeedApproval，无效时失败关闭返回 DecisionKindDeny。
func (d *DecisionNeedApproval) Kind() DecisionKind {
	return pickIf(d.IsValid(), DecisionKindNeedApproval, DecisionKindDeny)
}

// Risk 返回触发审批的风险等级；无效时返回 RiskUnknown。
func (d *DecisionNeedApproval) Risk() RiskLevel {
	if d.IsValid() {
		return d.risk
	}
	return RiskUnknown
}

// Reason 返回脱敏审批提示原因；无效时返回空串。
func (d *DecisionNeedApproval) Reason() string {
	if d.IsValid() {
		return d.reason
	}
	return ""
}

// ToVerdict 恒返回 VerdictDeny（获批前严禁放行）。
func (*DecisionNeedApproval) ToVerdict() Verdict { return VerdictDeny }

// MarshalJSONTo 实现 encoding/json/v2.MarshalerTo（值接收者）；对零值/无效实例失败关闭。
func (d DecisionNeedApproval) MarshalJSONTo(enc *jsontext.Encoder) error {
	return MarshalDecisionTo(enc, &d)
}

// DecisionAllow 表示策略在当前上下文下显式允许执行；
// 内置正向门控 valid bool，未初始化零值与 typed-nil 均失败关闭为拒绝。
//
//xops:opaque
//xops:failclosed
type DecisionAllow struct {
	reason string
	valid  bool
}

// NewDecisionAllow 构造经显式策略核准的不可变放行决策。
func NewDecisionAllow(reason string) *DecisionAllow {
	return &DecisionAllow{reason: SanitizePromptText(reason), valid: true}
}

func (*DecisionAllow) sealedGuardrailDecision() {}

// IsValid 报告放行决策是否非 nil 且经合法构造器签发。
func (d *DecisionAllow) IsValid() bool { return d != nil && d.valid }

// Kind 有效时返回 DecisionKindAllow；无效时失败关闭返回 DecisionKindDeny。
func (d *DecisionAllow) Kind() DecisionKind {
	return pickIf(d.IsValid(), DecisionKindAllow, DecisionKindDeny)
}

// Reason 返回脱敏放行说明；无效时返回空串。
func (d *DecisionAllow) Reason() string {
	if d.IsValid() {
		return d.reason
	}
	return ""
}

// ToVerdict 有效时返回 VerdictAllow；无效时失败关闭返回 VerdictDeny。
func (d *DecisionAllow) ToVerdict() Verdict { return pickIf(d.IsValid(), VerdictAllow, VerdictDeny) }

// MarshalJSONTo 实现 encoding/json/v2.MarshalerTo（值接收者）；对零值/无效实例失败关闭。
func (d DecisionAllow) MarshalJSONTo(enc *jsontext.Encoder) error { return MarshalDecisionTo(enc, &d) }

func invalidDecisionDeny() *DecisionDeny {
	return &DecisionDeny{code: "invalid_decision", reason: "nil or uninitialized guardrail decision"}
}

// NormalizeDecision 将任意 GuardrailDecision 归一化为有效不可变副本；nil/无效零值失败关闭为 *DecisionDeny。
func NormalizeDecision(d GuardrailDecision) GuardrailDecision {
	switch v := d.(type) {
	case *DecisionDeny:
		if v.IsValid() {
			return &DecisionDeny{code: v.code, reason: v.reason}
		}
	case *DecisionNeedApproval:
		if v.IsValid() {
			return &DecisionNeedApproval{risk: v.risk, reason: v.reason, valid: true}
		}
	case *DecisionAllow:
		if v.IsValid() {
			return &DecisionAllow{reason: v.reason, valid: true}
		}
	default:
		return invalidDecisionDeny()
	}
	return invalidDecisionDeny()
}

// JoinDecisions 按限制支配有界格合并两个护栏决策（Deny 吸收 NeedApproval 吸收 Allow）。
// 同类别 *DecisionNeedApproval 按 (SeverityRank DESC, reason ASC) 全序选取，确保高风险原因绝不被低风险原因遮蔽，
// 同时完整满足交换律、结合律、幂等律与单调律。
func JoinDecisions(a, b GuardrailDecision) GuardrailDecision {
	na, nb := NormalizeDecision(a), NormalizeDecision(b)
	if c := na.Kind().CompareStrictness(nb.Kind()); c > 0 {
		return na
	} else if c < 0 {
		return nb
	}
	return joinSameKindDecisions(na, nb)
}

func joinSameKindDecisions(a, b GuardrailDecision) GuardrailDecision {
	switch va := a.(type) {
	case *DecisionDeny:
		if vb, ok := b.(*DecisionDeny); ok && vb.IsValid() {
			code, reason := pickCanonicalDenyMeta(va.code, va.reason, vb.code, vb.reason)
			return &DecisionDeny{code: code, reason: reason}
		}
	case *DecisionNeedApproval:
		if vb, ok := b.(*DecisionNeedApproval); ok && vb.IsValid() {
			return joinNeedApproval(va, vb)
		}
	case *DecisionAllow:
		if vb, ok := b.(*DecisionAllow); ok && vb.IsValid() {
			return &DecisionAllow{reason: pickCanonicalText(va.reason, vb.reason), valid: true}
		}
	default:
		return invalidDecisionDeny()
	}
	return invalidDecisionDeny()
}

func joinNeedApproval(va, vb *DecisionNeedApproval) *DecisionNeedApproval {
	if c := va.risk.CompareSeverity(vb.risk); c != 0 {
		win := pickIf(c > 0, va, vb)
		return &DecisionNeedApproval{risk: win.risk, reason: win.reason, valid: true}
	}
	return &DecisionNeedApproval{risk: va.risk, reason: pickCanonicalText(va.reason, vb.reason), valid: true}
}

// FoldDecisions 对一组护栏决策执行顺序无关的限制支配并半格折叠；空输入严格失败关闭返回 *DecisionDeny。
func FoldDecisions(decisions ...GuardrailDecision) GuardrailDecision {
	if len(decisions) == 0 {
		return NewDecisionDenyWithCode("empty_decisions", "no guardrail decision evaluated")
	}
	acc := NormalizeDecision(decisions[0])
	for _, item := range decisions[1:] {
		acc = JoinDecisions(acc, item)
	}
	return acc
}

// EqualDecision 按值严格比较两个 GuardrailDecision 是否均有效且完全一致（nil 或无效零值恒返回 false）。
func EqualDecision(a, b GuardrailDecision) bool {
	if a == nil || b == nil || !a.IsValid() || !b.IsValid() {
		return false
	}
	switch va := a.(type) {
	case *DecisionDeny:
		vb, ok := b.(*DecisionDeny)
		return ok && vb.IsValid() && va.code == vb.code && va.reason == vb.reason
	case *DecisionNeedApproval:
		vb, ok := b.(*DecisionNeedApproval)
		return ok && vb.IsValid() && va.risk == vb.risk && va.reason == vb.reason
	case *DecisionAllow:
		vb, ok := b.(*DecisionAllow)
		return ok && vb.IsValid() && va.reason == vb.reason
	default:
		return false
	}
}

func pickCanonicalText(a, b string) string { return pickIf(compareNonEmptyFirst(a, b) <= 0, a, b) }

func pickCanonicalDenyMeta(cA, rA, cB, rB string) (string, string) {
	if c := compareNonEmptyFirst(cA, cB); c > 0 || (c == 0 && compareNonEmptyFirst(rA, rB) > 0) {
		return cB, rB
	}
	return cA, rA
}

func compareNonEmptyFirst(a, b string) int {
	if a == b {
		return 0
	}
	return pickIf(a == "", 1, pickIf(b == "", -1, cmp.Compare(a, b)))
}

type decisionWire struct {
	Kind   algebraic.Option[DecisionKind] `json:"kind"`
	Code   string                         `json:"code,omitzero"`
	Risk   algebraic.Option[RiskLevel]    `json:"risk,omitzero"`
	Reason string                         `json:"reason,omitzero"`
}

// MarshalDecisionTo 将任意有效 GuardrailDecision 编码至 Go 1.27 JSON/v2 流；
// 对 nil、typed-nil 或未初始化零值变体一律失败关闭返回 ErrInvalidDecision。
func MarshalDecisionTo(enc *jsontext.Encoder, d GuardrailDecision) error {
	if enc == nil {
		return ErrNilWriter
	}
	w, err := encodeDecisionWire(d)
	if err != nil {
		return err
	}
	return jsonv2.MarshalEncode(enc, w)
}

// UnmarshalDecisionFrom 从 Go 1.27 JSON/v2 流严格解码多态 GuardrailDecision；
// 对 JSON null、缺失 kind、非法变体字段组合均严格失败关闭返回 ErrInvalidDecision。
func UnmarshalDecisionFrom(dec *jsontext.Decoder) (GuardrailDecision, error) {
	if dec == nil {
		return nil, ErrNilReceiver
	}
	var out GuardrailDecision
	err := unmarshalJSONWithNullReject(&out, dec, ErrInvalidDecision, decodeDecisionWire)
	return out, err
}

func encodeDecisionWire(d GuardrailDecision) (decisionWire, error) {
	if d == nil || !d.IsValid() {
		return decisionWire{}, ErrInvalidDecision
	}
	switch v := d.(type) {
	case *DecisionDeny:
		return decisionWire{Kind: algebraic.Some(DecisionKindDeny), Code: v.code, Reason: v.reason}, nil
	case *DecisionNeedApproval:
		return decisionWire{Kind: algebraic.Some(DecisionKindNeedApproval), Risk: algebraic.Some(v.risk), Reason: v.reason}, nil
	case *DecisionAllow:
		return decisionWire{Kind: algebraic.Some(DecisionKindAllow), Reason: v.reason}, nil
	default:
		return decisionWire{}, ErrInvalidDecision
	}
}

func decodeDecisionWire(w decisionWire) (GuardrailDecision, error) {
	kind, ok := w.Kind.Get()
	if !ok {
		return nil, domi18n.EF(ErrInvalidDecision, domi18n.KeyCommonJSONMissingField, domi18n.Str("field", "decision.kind"))
	}
	switch kind {
	case DecisionKindDeny:
		if w.Risk.IsSome() {
			return nil, domi18n.EF(ErrInvalidDecision, domi18n.KeyCommonJSONVariantInvalid, domi18n.Str("variant", "deny"))
		}
		return NewDecisionDenyWithCode(w.Code, w.Reason), nil
	case DecisionKindNeedApproval:
		risk, hasRisk := w.Risk.Get()
		if w.Code != "" || !hasRisk {
			return nil, domi18n.EF(ErrInvalidDecision, domi18n.KeyCommonJSONVariantInvalid, domi18n.Str("variant", "need_approval"))
		}
		return NewDecisionNeedApproval(risk, w.Reason)
	case DecisionKindAllow:
		if w.Code != "" || w.Risk.IsSome() {
			return nil, domi18n.EF(ErrInvalidDecision, domi18n.KeyCommonJSONVariantInvalid, domi18n.Str("variant", "allow"))
		}
		return NewDecisionAllow(w.Reason), nil
	default:
		return nil, domi18n.EF(ErrInvalidDecision, domi18n.KeyCommonUnknownValue, domi18n.Str("kind", "decision.kind"), domi18n.Uint64("value", uint64(kind)))
	}
}
