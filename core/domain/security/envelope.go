package security

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
)

const (
	approvalEnvelopeDomainTag = "xops.security.approval_envelope.v1"
	approvalNonceBytes        = 16
	approvalNonceHexLen       = approvalNonceBytes * 2
)

// ApprovalEnvelopeSpec 是构造不可变 ApprovalEnvelope 的显式入参规格；
// IssuedAt 与 IssuedAt+TTL 均须落在 RFC 3339 合法年份 [1, 9999] 且无溢出，TTL 统一使用 algebraic.Duration，
// Nonce 须非全零 16 字节，且当 Decision 为 *DecisionNeedApproval 时 spec.Risk 必须与审批决策风险严格一致。
type ApprovalEnvelopeSpec struct {
	OperationID  OperationID
	Binding      OperationBinding
	Risk         RiskLevel
	Decision     GuardrailDecision
	ScopeSummary string
	IssuedAt     time.Time
	TTL          algebraic.Duration
	Nonce        [approvalNonceBytes]byte
	PolicyDigest algebraic.Option[Digest]
}

// ApprovalEnvelope 是密码学锚定操作标识、规范绑定、风险等级、护栏决策、作用域摘要、签发时刻、
// 有效期与防重放 Nonce 的不可变审批挑战信封（INV-E5 / RFC §3.5–3.6）；
// 零值恒无效，且经 //xops:canonicalhash 由 xopsvet/digestcover 校验 WriteCanonical 全字段覆盖（零 reflect）。
//
//xops:opaque
//xops:failclosed
//xops:canonicalhash
type ApprovalEnvelope struct {
	operationID  OperationID
	binding      OperationBinding
	risk         RiskLevel
	decision     GuardrailDecision
	scopeSummary string
	issuedAt     time.Time
	ttl          algebraic.Duration
	nonce        [approvalNonceBytes]byte
	policyDigest algebraic.Option[Digest]
	valid        bool
}

// NewApprovalNonceFrom 从显式注入熵源读取 16 字节非全零审批防重放 Nonce（零隐式 crypto/rand）。
func NewApprovalNonceFrom(entropy io.Reader) ([approvalNonceBytes]byte, error) {
	raw, err := readExact16Bytes(entropy)
	if err != nil {
		return [approvalNonceBytes]byte{}, fmt.Errorf("%w: %w", ErrInvalidApprovalEnvelope, err)
	}
	if isAllZero16(raw) {
		return [approvalNonceBytes]byte{}, fmt.Errorf("%w: 审批 Nonce 不能为全零", ErrInvalidApprovalEnvelope)
	}
	return raw, nil
}

// NewApprovalEnvelope 校验全部安全字段、RFC 3339 时间窗口与决策风险一致性并构造不可变 ApprovalEnvelope。
func NewApprovalEnvelope(spec ApprovalEnvelopeSpec) (ApprovalEnvelope, error) {
	if err := validateApprovalSpec(spec); err != nil {
		return ApprovalEnvelope{}, err
	}
	return ApprovalEnvelope{
		operationID: spec.OperationID, binding: spec.Binding, risk: spec.Risk,
		decision: NormalizeDecision(spec.Decision), scopeSummary: SanitizePromptText(spec.ScopeSummary),
		issuedAt: spec.IssuedAt.UTC().Round(0), ttl: spec.TTL, nonce: spec.Nonce,
		policyDigest: spec.PolicyDigest, valid: true,
	}, nil
}

func validateApprovalSpec(spec ApprovalEnvelopeSpec) error {
	switch {
	case !spec.OperationID.IsValid():
		return fmt.Errorf("%w: %w", ErrInvalidApprovalEnvelope, ErrInvalidOperationID)
	case !spec.Binding.IsValid():
		return fmt.Errorf("%w: %w", ErrInvalidApprovalEnvelope, ErrInvalidOperationBinding)
	case !spec.Risk.IsValid():
		return fmt.Errorf("%w: %w", ErrInvalidApprovalEnvelope, ErrInvalidRiskLevel)
	case spec.Decision == nil || !spec.Decision.IsValid():
		return fmt.Errorf("%w: %w", ErrInvalidApprovalEnvelope, ErrInvalidDecision)
	case !decisionMatchesEnvelopeRisk(spec.Decision, spec.Risk):
		return fmt.Errorf("%w: 信封风险与审批决策风险不一致", ErrInvalidApprovalEnvelope)
	case !hasVisibleSummary(spec.ScopeSummary):
		return fmt.Errorf("%w: scope_summary 必须包含有效可见 UTF-8 内容", ErrInvalidApprovalEnvelope)
	case !isValidApprovalWindow(spec.IssuedAt.UTC().Round(0), spec.TTL) || isAllZero16(spec.Nonce):
		return fmt.Errorf("%w: issued_at/ttl 越界溢出或 nonce 全零", ErrInvalidApprovalEnvelope)
	case optInvalid(spec.PolicyDigest):
		return fmt.Errorf("%w: policy_digest 不可为无效零值", ErrInvalidApprovalEnvelope)
	}
	return nil
}

func decisionMatchesEnvelopeRisk(d GuardrailDecision, risk RiskLevel) bool {
	na, ok := d.(*DecisionNeedApproval)
	return !ok || na.Risk() == risk
}

func isValidRFC3339Time(t time.Time) bool {
	return !t.IsZero() && t.UTC().Year() >= 1 && t.UTC().Year() <= 9999
}

func isValidApprovalWindow(issuedUTC time.Time, ttl algebraic.Duration) bool {
	if !isValidRFC3339Time(issuedUTC) || !ttl.IsPositive() {
		return false
	}
	exp := issuedUTC.Add(ttl.Std())
	return exp.After(issuedUTC) && isValidRFC3339Time(exp)
}

func hasVisibleSummary(raw string) bool {
	return utf8.ValidString(raw) && strings.ContainsFunc(raw, func(r rune) bool {
		return !unicode.IsSpace(r) && !isForbiddenFormatOrControl(r)
	})
}

// IsValid 报告审批信封是否经构造器完整校验且所有不变量成立。
func (e ApprovalEnvelope) IsValid() bool {
	return e.valid && e.operationID.IsValid() && e.binding.IsValid() && e.risk.IsValid() &&
		e.decision != nil && e.decision.IsValid() && decisionMatchesEnvelopeRisk(e.decision, e.risk) &&
		e.scopeSummary != "" && isValidApprovalWindow(e.issuedAt, e.ttl) && !isAllZero16(e.nonce)
}

// IsZero 报告审批信封是否为无效零值。
func (e ApprovalEnvelope) IsZero() bool { return !e.IsValid() }

// OperationID 返回信封绑定的操作唯一标识。
func (e ApprovalEnvelope) OperationID() OperationID { return e.operationID }

// Binding 返回信封绑定的不可变操作绑定快照。
func (e ApprovalEnvelope) Binding() OperationBinding { return e.binding }

// Risk 返回信封锁定的操作风险等级；无效零值返回 RiskUnknown。
func (e ApprovalEnvelope) Risk() RiskLevel { return pickIf(e.IsValid(), e.risk, RiskUnknown) }

// Decision 返回信封锁定的护栏决策副本；无效零值失败关闭返回 *DecisionDeny。
func (e ApprovalEnvelope) Decision() GuardrailDecision {
	if e.IsValid() {
		return NormalizeDecision(e.decision)
	}
	return invalidDecisionDeny()
}

// ScopeSummary 返回已脱敏的审批范围摘要文本。
func (e ApprovalEnvelope) ScopeSummary() string { return e.scopeSummary }

// IssuedAt 返回规范化的 UTC 签发时刻。
func (e ApprovalEnvelope) IssuedAt() time.Time { return e.issuedAt }

// TTL 返回信封有效期（algebraic.Duration）。
func (e ApprovalEnvelope) TTL() algebraic.Duration { return e.ttl }

// ExpiresAt 返回信封到期 UTC 时刻（issuedAt + ttl）与有效性标志。
func (e ApprovalEnvelope) ExpiresAt() (time.Time, bool) {
	if !e.IsValid() {
		return time.Time{}, false
	}
	return e.issuedAt.Add(e.ttl.Std()), true
}

// Nonce 返回 16 字节防重放 Nonce 副本与有效性标志。
func (e ApprovalEnvelope) Nonce() ([approvalNonceBytes]byte, bool) {
	return pickIf(e.IsValid(), e.nonce, [approvalNonceBytes]byte{}), e.IsValid()
}

// NonceHex 返回 32 位小写十六进制防重放 Nonce；无效零值返回空串。
func (e ApprovalEnvelope) NonceHex() string {
	if !e.IsValid() {
		return ""
	}
	return hex.EncodeToString(e.nonce[:])
}

// PolicyDigest 返回可选活跃策略快照摘要。
func (e ApprovalEnvelope) PolicyDigest() algebraic.Option[Digest] { return e.policyDigest }

// CanApprove 报告该信封是否代表可进入用户确认流程的待审批挑战（仅 DecisionNeedApproval 返回 true）。
func (e ApprovalEnvelope) CanApprove() bool {
	return e.IsValid() && e.decision.Kind() == DecisionKindNeedApproval
}

// IsExpiredAt 在显式观测时刻 now 判断信封是否已过期（零 time.Now）；无效或零时刻失败关闭返回 true。
func (e ApprovalEnvelope) IsExpiredAt(now time.Time) bool {
	exp, ok := e.ExpiresAt()
	return !ok || now.IsZero() || !now.UTC().Before(exp)
}

// IsActiveAt 报告信封在显式观测时刻 now 是否处于有效窗口 [issuedAt, issuedAt+ttl) 内。
func (e ApprovalEnvelope) IsActiveAt(now time.Time) bool {
	exp, ok := e.ExpiresAt()
	return ok && !now.IsZero() && !now.UTC().Before(e.issuedAt) && now.UTC().Before(exp)
}

// MatchesBinding 校验给定 OperationBinding 是否与信封锁定绑定完全一致（无效零值恒返回 false）。
func (e ApprovalEnvelope) MatchesBinding(binding OperationBinding) bool {
	return e.IsValid() && binding.IsValid() && e.binding.Equal(binding)
}

// MatchesDigest 计算本信封的规范 SHA-256 摘要并以常量时间与 expected 比对。
func (e ApprovalEnvelope) MatchesDigest(expected Digest) (bool, error) {
	if !expected.IsValid() {
		return false, ErrInvalidDigest
	}
	actual, err := e.Digest()
	if err != nil {
		return false, err
	}
	return actual.Equal(expected), nil
}

// WriteCanonical 以零反射、长度前缀与域分离方式将 ApprovalEnvelope 全部字段写入 w（受 digestcover 校验）。
func (e ApprovalEnvelope) WriteCanonical(w io.Writer) error {
	if w == nil {
		return ErrNilWriter
	}
	if !e.valid || !e.IsValid() {
		return ErrInvalidApprovalEnvelope
	}
	enc := &canonicalEncoder{w: w}
	enc.writeString(approvalEnvelopeDomainTag)
	enc.writeString(e.operationID.String())
	if enc.err == nil {
		enc.fail(e.binding.WriteCanonical(w))
	}
	enc.writeUint8(uint8(e.risk))
	enc.fail(enc.writeDecision(e.decision))
	enc.writeString(e.scopeSummary)
	utc := e.issuedAt.UTC()
	enc.writeInt64(utc.Unix())
	enc.writeInt64(int64(utc.Nanosecond()))
	enc.writeInt64(int64(e.ttl.Std()))
	enc.writeBytes(e.nonce[:])
	enc.writeOptDigest(e.policyDigest)
	return enc.err
}

// Digest 计算并返回 ApprovalEnvelope 的确定性 SHA-256 规范摘要。
func (e ApprovalEnvelope) Digest() (Digest, error) { return digestCanonical(e.WriteCanonical) }

// CanonicalJSON 使用 Go 1.27 encoding/json/v2 的 Deterministic(true) 编码确定性 JSON 字节流。
func (e ApprovalEnvelope) CanonicalJSON() ([]byte, error) {
	if !e.IsValid() {
		return nil, ErrInvalidApprovalEnvelope
	}
	return jsonv2.Marshal(e, jsonv2.Deterministic(true))
}

// Equal 严格比对两个 ApprovalEnvelope 是否均有效且全部字段一致（Nonce 采用常量时间比对）。
func (e ApprovalEnvelope) Equal(other ApprovalEnvelope) bool {
	return e.IsValid() && other.IsValid() && e.operationID.Equal(other.operationID) &&
		e.binding.Equal(other.binding) && e.risk == other.risk && EqualDecision(e.decision, other.decision) &&
		e.scopeSummary == other.scopeSummary && e.issuedAt.Equal(other.issuedAt) && e.ttl.Equal(other.ttl) &&
		subtle.ConstantTimeCompare(e.nonce[:], other.nonce[:]) == 1 && equalOpt(e.policyDigest, other.policyDigest)
}

type approvalEnvelopeWire struct {
	OperationID  algebraic.Option[OperationID]        `json:"operation_id"`
	Binding      algebraic.Option[OperationBinding]   `json:"binding"`
	Risk         algebraic.Option[RiskLevel]          `json:"risk"`
	Decision     algebraic.Option[decisionWire]       `json:"decision"`
	ScopeSummary algebraic.Option[string]             `json:"scope_summary"`
	IssuedAt     algebraic.Option[time.Time]          `json:"issued_at"`
	TTL          algebraic.Option[algebraic.Duration] `json:"ttl"`
	Nonce        algebraic.Option[string]             `json:"nonce"`
	PolicyDigest algebraic.Option[Digest]             `json:"policy_digest,omitzero"`
}

// MarshalJSONTo 实现 encoding/json/v2.MarshalerTo（值接收者）；对零值信封失败关闭。
func (e ApprovalEnvelope) MarshalJSONTo(enc *jsontext.Encoder) error {
	if !e.IsValid() {
		return ErrInvalidApprovalEnvelope
	}
	dw, err := encodeDecisionWire(e.decision)
	if err != nil {
		return err
	}
	return jsonv2.MarshalEncode(enc, approvalEnvelopeWire{
		OperationID: algebraic.Some(e.operationID), Binding: algebraic.Some(e.binding),
		Risk: algebraic.Some(e.risk), Decision: algebraic.Some(dw),
		ScopeSummary: algebraic.Some(e.scopeSummary), IssuedAt: algebraic.Some(e.issuedAt.UTC()),
		TTL: algebraic.Some(e.ttl), Nonce: algebraic.Some(hex.EncodeToString(e.nonce[:])),
		PolicyDigest: e.policyDigest,
	})
}

// UnmarshalJSONFrom 实现 encoding/json/v2.UnmarshalerFrom；对 JSON null、缺失必需字段或篡改值失败关闭并重置零值。
func (e *ApprovalEnvelope) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(e, dec, ErrInvalidApprovalEnvelope, func(w approvalEnvelopeWire) (ApprovalEnvelope, error) {
		spec, err := decodeApprovalEnvelopeWire(w)
		if err != nil {
			return ApprovalEnvelope{}, err
		}
		return NewApprovalEnvelope(spec)
	})
}

func decodeApprovalEnvelopeWire(w approvalEnvelopeWire) (ApprovalEnvelopeSpec, error) {
	opID, okID := w.OperationID.Get()
	binding, okB := w.Binding.Get()
	risk, okR := w.Risk.Get()
	dw, okD := w.Decision.Get()
	summary, okS := w.ScopeSummary.Get()
	issuedAt, okI := w.IssuedAt.Get()
	ttl, okT := w.TTL.Get()
	nonceHex, okN := w.Nonce.Get()
	if !okID || !okB || !okR || !okD || !okS || !okI || !okT || !okN {
		return ApprovalEnvelopeSpec{}, fmt.Errorf("%w: 缺少必需的审批信封字段", ErrInvalidApprovalEnvelope)
	}
	decision, err := decodeDecisionWire(dw)
	if err != nil {
		return ApprovalEnvelopeSpec{}, fmt.Errorf("%w: %w", ErrInvalidApprovalEnvelope, err)
	}
	nonce, err := parseApprovalNonceHex(nonceHex)
	if err != nil {
		return ApprovalEnvelopeSpec{}, err
	}
	return ApprovalEnvelopeSpec{opID, binding, risk, decision, summary, issuedAt, ttl, nonce, w.PolicyDigest}, nil
}

func parseApprovalNonceHex(raw string) ([approvalNonceBytes]byte, error) {
	var out [approvalNonceBytes]byte
	if len(raw) != approvalNonceHexLen || !isLowerHexString(raw) {
		return out, fmt.Errorf("%w: 非法 nonce 编码 %q", ErrInvalidApprovalEnvelope, raw)
	}
	_, err := hex.Decode(out[:], []byte(raw))
	return out, err
}

func isAllZero16(b [16]byte) bool { return b == ([16]byte{}) }
