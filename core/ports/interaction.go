package ports

import (
	"context"
	"fmt"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
)

func sanitizePromptMeta(rawTitle, rawBody, rawSubject string) (title, body, subject string, err error) {
	body, err = sanitizeBoundedText(security.SanitizePromptText(rawBody), maxPortDetailBytes, false, ErrInvalidArgument)
	if err != nil {
		return "", "", "", fmt.Errorf("%w: 提示正文非法", err)
	}
	title, err = sanitizeBoundedText(security.SanitizePromptText(rawTitle), maxPortTokenLen, true, ErrInvalidArgument)
	if err != nil {
		return "", "", "", err
	}
	subject, err = sanitizeBoundedText(security.SanitizePromptText(rawSubject), maxPortTokenLen, true, ErrInvalidArgument)
	if err != nil {
		return "", "", "", err
	}
	return title, body, subject, nil
}

// SecretPromptRequestSpec 是构造不可变 SecretPromptRequest 的显式入参规格（严禁包含 SecretBox）。
type SecretPromptRequestSpec struct {
	Title      string
	Prompt     string
	Subject    string
	AllowEmpty bool
}

// SecretPromptRequest 描述面向 InteractionPort.PromptSecret 的脱敏机密输入提示请求；零值恒无效。
//
//xops:opaque
//xops:failclosed
type SecretPromptRequest struct {
	title      string
	prompt     string
	subject    string
	allowEmpty bool
	valid      bool
}

// NewSecretPromptRequest 校验并脱敏提示文案后构造不可变 SecretPromptRequest。
func NewSecretPromptRequest(spec SecretPromptRequestSpec) (SecretPromptRequest, error) {
	title, prompt, subj, err := sanitizePromptMeta(spec.Title, spec.Prompt, spec.Subject)
	if err != nil {
		return SecretPromptRequest{}, err
	}
	return SecretPromptRequest{title: title, prompt: prompt, subject: subj, allowEmpty: spec.AllowEmpty, valid: true}, nil
}

// SecretPromptRequest 只读访问器与等价比对。
func (r SecretPromptRequest) IsValid() bool    { return r.valid && r.prompt != "" }
func (r SecretPromptRequest) IsZero() bool     { return !r.IsValid() }
func (r SecretPromptRequest) Title() string    { return r.title }
func (r SecretPromptRequest) Prompt() string   { return r.prompt }
func (r SecretPromptRequest) Subject() string  { return r.subject }
func (r SecretPromptRequest) AllowEmpty() bool { return r.IsValid() && r.allowEmpty }
func (r SecretPromptRequest) Equal(o SecretPromptRequest) bool {
	return r.IsValid() && o.IsValid() && r.title == o.title && r.prompt == o.prompt && r.subject == o.subject && r.allowEmpty == o.allowEmpty
}

// ConfirmRequestSpec 是构造不可变 ConfirmRequest 的显式入参规格。
type ConfirmRequestSpec struct {
	Title   string
	Message string
	Subject string
	Risk    security.RiskLevel
}

// ConfirmRequest 描述面向 InteractionPort.Confirm 的失败关闭二值确认请求（默认拒绝）；零值恒无效。
//
//xops:opaque
//xops:failclosed
type ConfirmRequest struct {
	title   string
	message string
	subject string
	risk    security.RiskLevel
	valid   bool
}

// NewConfirmRequest 校验消息与风险等级并构造不可变 ConfirmRequest。
func NewConfirmRequest(spec ConfirmRequestSpec) (ConfirmRequest, error) {
	if !spec.Risk.IsValid() {
		return ConfirmRequest{}, fmt.Errorf("%w: ConfirmRequest 需要有效 RiskLevel", ErrInvalidArgument)
	}
	title, msg, subj, err := sanitizePromptMeta(spec.Title, spec.Message, spec.Subject)
	if err != nil {
		return ConfirmRequest{}, err
	}
	return ConfirmRequest{title: title, message: msg, subject: subj, risk: spec.Risk, valid: true}, nil
}

// ConfirmRequest 只读访问器与等价比对。
func (r ConfirmRequest) IsValid() bool   { return r.valid && r.message != "" && r.risk.IsValid() }
func (r ConfirmRequest) IsZero() bool    { return !r.IsValid() }
func (r ConfirmRequest) Title() string   { return r.title }
func (r ConfirmRequest) Message() string { return r.message }
func (r ConfirmRequest) Subject() string { return r.subject }
func (r ConfirmRequest) Risk() security.RiskLevel {
	return pickIf(r.IsValid(), r.risk, security.RiskUnknown)
}
func (r ConfirmRequest) Equal(o ConfirmRequest) bool {
	return r.IsValid() && o.IsValid() && r.title == o.title && r.message == o.message && r.subject == o.subject && r.risk == o.risk
}

// TextPromptRequestSpec 是构造不可变 TextPromptRequest 的显式入参规格。
type TextPromptRequestSpec struct {
	Title      string
	Prompt     string
	Subject    string
	AllowEmpty bool
}

// TextPromptRequest 描述非敏感文本质询提示请求（如用户名、非回显关闭的 OTP 提示等）；零值恒无效。
//
//xops:opaque
//xops:failclosed
type TextPromptRequest struct {
	title      string
	prompt     string
	subject    string
	allowEmpty bool
	valid      bool
}

// NewTextPromptRequest 校验并脱敏提示文案后构造不可变 TextPromptRequest。
func NewTextPromptRequest(spec TextPromptRequestSpec) (TextPromptRequest, error) {
	title, prompt, subj, err := sanitizePromptMeta(spec.Title, spec.Prompt, spec.Subject)
	if err != nil {
		return TextPromptRequest{}, err
	}
	return TextPromptRequest{title: title, prompt: prompt, subject: subj, allowEmpty: spec.AllowEmpty, valid: true}, nil
}

// TextPromptRequest 只读访问器与等价比对。
func (r TextPromptRequest) IsValid() bool    { return r.valid && r.prompt != "" }
func (r TextPromptRequest) IsZero() bool     { return !r.IsValid() }
func (r TextPromptRequest) Title() string    { return r.title }
func (r TextPromptRequest) Prompt() string   { return r.prompt }
func (r TextPromptRequest) Subject() string  { return r.subject }
func (r TextPromptRequest) AllowEmpty() bool { return r.IsValid() && r.allowEmpty }
func (r TextPromptRequest) Equal(o TextPromptRequest) bool {
	return r.IsValid() && o.IsValid() && r.title == o.title && r.prompt == o.prompt && r.subject == o.subject && r.allowEmpty == o.allowEmpty
}

// ApprovalDecisionResponse 表示用户对不可变 ApprovalEnvelope 的显式审批回执（INV-E5）；
// 零值恒无效且 Verdict 为 VerdictDeny（失败关闭），并强制锚定被审批信封的 SHA-256 摘要防止跨操作重放。
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
	if err != nil {
		return ApprovalDecisionResponse{}, err
	}
	return ApprovalDecisionResponse{verdict: verdict, envelopeDigest: envelopeDigest, comment: clean, valid: true}, nil
}

// ApprovalDecisionResponse 只读访问器与等价比对。
func (r ApprovalDecisionResponse) IsValid() bool {
	return r.valid && r.verdict.IsValid() && r.envelopeDigest.IsValid()
}
func (r ApprovalDecisionResponse) IsZero() bool { return !r.IsValid() }
func (r ApprovalDecisionResponse) Verdict() security.Verdict {
	return pickIf(r.IsValid(), r.verdict, security.VerdictDeny)
}
func (r ApprovalDecisionResponse) Approved() bool                  { return r.IsValid() && r.verdict.Allowed() }
func (r ApprovalDecisionResponse) EnvelopeDigest() security.Digest { return r.envelopeDigest }
func (r ApprovalDecisionResponse) Comment() string                 { return r.comment }
func (r ApprovalDecisionResponse) Equal(o ApprovalDecisionResponse) bool {
	return r.IsValid() && o.IsValid() && r.verdict == o.verdict &&
		r.envelopeDigest.Equal(o.envelopeDigest) && r.comment == o.comment
}

// InteractionPort 定义人工确认、审批挑战、非敏感文本与全作用域闭包机密输入出站端口（Plan §4.6）。
// 非交互环境或 BatchMode 下实现方必须返回 ErrInteractionUnavailable，严禁静默放行。
type InteractionPort interface {
	// CanInteract 报告当前宿主入口是否具备与用户交互的能力。
	CanInteract() bool
	// Confirm 发起二值确认并返回失败关闭 security.Verdict（任何错误或取消均须返回 VerdictDeny）。
	Confirm(ctx context.Context, req ConfirmRequest) (security.Verdict, error)
	// PromptApproval 向用户展示经密码学锚定的 ApprovalEnvelope 并返回绑定信封摘要的审批回执。
	PromptApproval(ctx context.Context, envelope security.ApprovalEnvelope) (ApprovalDecisionResponse, error)
	// PromptText 向用户请求单行非敏感文本输入。
	PromptText(ctx context.Context, req TextPromptRequest) (string, error)
	// PromptSecret 以无回显方式采集用户机密输入，内部经 secret.WithBytes 封装为 *secret.SecretBox
	// 并在同步作用域闭包 fn 内借出；回调退出（含 panic）前无条件清零底层字节缓冲。
	//
	//xops:syncclosure
	//xops:borrowed
	PromptSecret(ctx context.Context, req SecretPromptRequest, fn func(box *secret.SecretBox) error) error
}
