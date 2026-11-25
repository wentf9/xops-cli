package ports

import (
	"context"
	"fmt"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
)

type promptCore struct {
	title, prompt, subject string
	allowEmpty, valid      bool
}

func buildPromptCore(rawTitle, rawBody, rawSubject string, allowEmpty bool) (promptCore, error) {
	body, e1 := sanitizeBoundedText(security.SanitizePromptText(rawBody), maxPortDetailBytes, false, ErrInvalidArgument)
	title, e2 := sanitizeBoundedText(security.SanitizePromptText(rawTitle), maxPortTokenLen, true, ErrInvalidArgument)
	subj, e3 := sanitizeBoundedText(security.SanitizePromptText(rawSubject), maxPortTokenLen, true, ErrInvalidArgument)
	err := firstErr(e1, e2, e3)
	return pickIf(err == nil, promptCore{title, body, subj, allowEmpty, true}, promptCore{}), err
}
func (c promptCore) ok() bool             { return c.valid && c.prompt != "" }
func (c promptCore) eq(o promptCore) bool { return c.ok() && o.ok() && c == o }

// SecretPromptRequestSpec 是构造不可变 SecretPromptRequest 的显式入参规格（严禁包含 SecretBox）。
type SecretPromptRequestSpec struct {
	Title      string `json:"title,omitzero"`
	Prompt     string `json:"prompt"`
	Subject    string `json:"subject,omitzero"`
	AllowEmpty bool   `json:"allow_empty,omitzero"`
}

// SecretPromptRequest 描述面向 InteractionPort.PromptSecret 的脱敏机密输入提示请求；零值恒无效。
//
//xops:opaque
//xops:failclosed
type SecretPromptRequest struct{ core promptCore }

// NewSecretPromptRequest 校验并脱敏提示文案后构造不可变 SecretPromptRequest。
func NewSecretPromptRequest(spec SecretPromptRequestSpec) (SecretPromptRequest, error) {
	c, err := buildPromptCore(spec.Title, spec.Prompt, spec.Subject, spec.AllowEmpty)
	return SecretPromptRequest{core: c}, err
}
func (r SecretPromptRequest) IsValid() bool                    { return r.core.ok() }
func (r SecretPromptRequest) IsZero() bool                     { return !r.IsValid() }
func (r SecretPromptRequest) Title() string                    { return r.core.title }
func (r SecretPromptRequest) Prompt() string                   { return r.core.prompt }
func (r SecretPromptRequest) Subject() string                  { return r.core.subject }
func (r SecretPromptRequest) AllowEmpty() bool                 { return r.IsValid() && r.core.allowEmpty }
func (r SecretPromptRequest) Equal(o SecretPromptRequest) bool { return r.core.eq(o.core) }

// ConfirmRequestSpec 是构造不可变 ConfirmRequest 的显式入参规格。
type ConfirmRequestSpec struct {
	Title   string             `json:"title,omitzero"`
	Message string             `json:"message"`
	Subject string             `json:"subject,omitzero"`
	Risk    security.RiskLevel `json:"risk"`
}

// ConfirmRequest 描述面向 InteractionPort.Confirm 的失败关闭二值确认请求（默认拒绝）；零值恒无效。
//
//xops:opaque
//xops:failclosed
type ConfirmRequest struct {
	core promptCore
	risk security.RiskLevel
}

// NewConfirmRequest 校验消息与风险等级并构造不可变 ConfirmRequest。
func NewConfirmRequest(spec ConfirmRequestSpec) (ConfirmRequest, error) {
	if !spec.Risk.IsValid() {
		return ConfirmRequest{}, fmt.Errorf("%w: ConfirmRequest 需要有效 RiskLevel", ErrInvalidArgument)
	}
	c, err := buildPromptCore(spec.Title, spec.Message, spec.Subject, false)
	return ConfirmRequest{core: c, risk: spec.Risk}, err
}
func (r ConfirmRequest) IsValid() bool            { return r.core.ok() && r.risk.IsValid() }
func (r ConfirmRequest) IsZero() bool             { return !r.IsValid() }
func (r ConfirmRequest) Title() string            { return r.core.title }
func (r ConfirmRequest) Message() string          { return r.core.prompt }
func (r ConfirmRequest) Subject() string          { return r.core.subject }
func (r ConfirmRequest) Risk() security.RiskLevel { return orZero(r.IsValid(), r.risk) }
func (r ConfirmRequest) Equal(o ConfirmRequest) bool {
	return r.IsValid() && o.IsValid() && r.core.eq(o.core) && r.risk == o.risk
}

// TextPromptRequestSpec 是构造不可变 TextPromptRequest 的显式入参规格。
type TextPromptRequestSpec struct {
	Title      string `json:"title,omitzero"`
	Prompt     string `json:"prompt"`
	Subject    string `json:"subject,omitzero"`
	AllowEmpty bool   `json:"allow_empty,omitzero"`
}

// TextPromptRequest 描述非敏感文本质询提示请求；零值恒无效。
//
//xops:opaque
//xops:failclosed
type TextPromptRequest struct{ core promptCore }

// NewTextPromptRequest 校验并脱敏提示文案后构造不可变 TextPromptRequest。
func NewTextPromptRequest(spec TextPromptRequestSpec) (TextPromptRequest, error) {
	c, err := buildPromptCore(spec.Title, spec.Prompt, spec.Subject, spec.AllowEmpty)
	return TextPromptRequest{core: c}, err
}
func (r TextPromptRequest) IsValid() bool                  { return r.core.ok() }
func (r TextPromptRequest) IsZero() bool                   { return !r.IsValid() }
func (r TextPromptRequest) Title() string                  { return r.core.title }
func (r TextPromptRequest) Prompt() string                 { return r.core.prompt }
func (r TextPromptRequest) Subject() string                { return r.core.subject }
func (r TextPromptRequest) AllowEmpty() bool               { return r.IsValid() && r.core.allowEmpty }
func (r TextPromptRequest) Equal(o TextPromptRequest) bool { return r.core.eq(o.core) }

// ApprovalDecisionResponse 表示用户对不可变 ApprovalEnvelope 的显式审批回执（INV-E5）；零值恒拒绝。
//
//xops:opaque
//xops:failclosed
type ApprovalDecisionResponse struct {
	verdict        security.Verdict
	envelopeDigest security.Digest
	comment        string
	valid          bool
}

// NewApprovalDecisionResponse 校验判定值与信封摘要并构造不可变 ApprovalDecisionResponse。
func NewApprovalDecisionResponse(verdict security.Verdict, envelopeDigest security.Digest, comment string) (ApprovalDecisionResponse, error) {
	if !verdict.IsValid() || !envelopeDigest.IsValid() {
		return ApprovalDecisionResponse{}, fmt.Errorf("%w: ApprovalDecisionResponse 需要有效 Verdict 与 EnvelopeDigest", ErrInvalidArgument)
	}
	clean, err := sanitizeBoundedText(security.SanitizePromptText(comment), maxPortDetailBytes, true, ErrInvalidArgument)
	return ApprovalDecisionResponse{verdict: verdict, envelopeDigest: envelopeDigest, comment: clean, valid: err == nil}, err
}
func (r ApprovalDecisionResponse) IsValid() bool {
	return r.valid && r.verdict.IsValid() && r.envelopeDigest.IsValid()
}
func (r ApprovalDecisionResponse) IsZero() bool                    { return !r.IsValid() }
func (r ApprovalDecisionResponse) Verdict() security.Verdict       { return orZero(r.IsValid(), r.verdict) }
func (r ApprovalDecisionResponse) Approved() bool                  { return r.IsValid() && r.verdict.Allowed() }
func (r ApprovalDecisionResponse) EnvelopeDigest() security.Digest { return r.envelopeDigest }
func (r ApprovalDecisionResponse) Comment() string                 { return r.comment }
func (r ApprovalDecisionResponse) Equal(o ApprovalDecisionResponse) bool {
	return r.IsValid() && o.IsValid() && r.verdict == o.verdict && r.envelopeDigest.Equal(o.envelopeDigest) && r.comment == o.comment
}

// InteractionPort 定义人工确认、审批挑战、非敏感文本与全作用域闭包机密输入出站端口。
type InteractionPort interface {
	CanInteract() bool
	Confirm(ctx context.Context, req ConfirmRequest) (security.Verdict, error)
	PromptApproval(ctx context.Context, envelope security.ApprovalEnvelope) (ApprovalDecisionResponse, error)
	PromptText(ctx context.Context, req TextPromptRequest) (string, error)
	// PromptSecret 以无回显方式采集用户机密输入并在同步闭包内借出 *secret.SecretBox。
	//xops:syncclosure
	//xops:borrowed
	PromptSecret(ctx context.Context, req SecretPromptRequest, fn func(box *secret.SecretBox) error) error
}
