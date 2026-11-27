package clikit

import (
	"bytes"
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"

	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/i18n"
)

// ReferenceConflictView 是引用冲突错误的规范 JSON/v2 视图（零明文、零裸 time.Duration）。
type ReferenceConflictView struct {
	AssetKind        string                      `json:"asset_kind"`
	Subject          string                      `json:"subject"`
	AssetReferences  []inventory.AssetReference  `json:"asset_references,omitzero"`
	SecretReferences []inventory.SecretReference `json:"secret_references,omitzero"`
}

// ApprovalChallengeView 是两步审批挑战信封的规范 JSON/v2 视图。
type ApprovalChallengeView struct {
	Digest    security.Digest           `json:"digest"`
	Escalated bool                      `json:"escalated"`
	Reason    string                    `json:"reason,omitzero"`
	Envelope  security.ApprovalEnvelope `json:"envelope"`
}

// ErrorEnvelope 是 CLI `--json` 模式下统一输出的结构化错误载荷。
type ErrorEnvelope struct {
	OK        bool                   `json:"ok"`
	ExitCode  int                    `json:"exit_code"`
	ErrorCode string                 `json:"error_code"`
	Error     string                 `json:"error"`
	Conflict  *ReferenceConflictView `json:"reference_conflict,omitzero"`
	Challenge *ApprovalChallengeView `json:"approval_challenge,omitzero"`
}

// WriteJSON 使用 Go 1.27 encoding/json/v2 Deterministic(true) 将任意 DTO 规范编码并附换行写入 w。
func WriteJSON(w io.Writer, v any) error {
	raw, err := jsonv2.Marshal(v, jsonv2.Deterministic(true))
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.Grow(len(raw) + 1)
	_, _ = buf.Write(raw)
	_ = buf.WriteByte('\n')
	_, err = w.Write(buf.Bytes())
	return err
}

// WriteJSONError 以规范英文构造 ErrorEnvelope 并以确定性 JSON/v2 写入输出流。
func WriteJSONError(w io.Writer, exitCode int, err error) {
	WriteJSONErrorLocalized(w, nil, exitCode, err)
}

// WriteJSONErrorLocalized 使用指定 Localizer 渲染 ErrorEnvelope.Error，同时保持 ErrorCode 与全部 JSON 字段名为规范英文常量。
func WriteJSONErrorLocalized(w io.Writer, loc *i18n.Localizer, exitCode int, err error) {
	effLoc := EnsureLocalizer(loc)
	msg := effLoc.T(i18n.KeyCLICommandFailed)
	if err != nil {
		msg = effLoc.RenderError(err)
	}
	env := ErrorEnvelope{
		OK:        false,
		ExitCode:  exitCode,
		ErrorCode: ClassifyErrorCode(err),
		Error:     msg,
	}
	if rc, ok := engine.ExtractReferenceConflict(err); ok && rc.IsValid() {
		env.Conflict = &ReferenceConflictView{
			AssetKind:        rc.AssetKind(),
			Subject:          rc.Subject(),
			AssetReferences:  rc.AssetReferences(),
			SecretReferences: rc.SecretReferences(),
		}
	}
	if ch, ok := engine.ExtractApprovalChallenge(err); ok && ch.IsValid() {
		env.Challenge = &ApprovalChallengeView{
			Digest:    ch.EnvelopeDigest(),
			Escalated: ch.Escalated(),
			Reason:    ch.Reason(),
			Envelope:  ch.Envelope(),
		}
	}
	if mErr := WriteJSON(w, env); mErr != nil {
		_, _ = fmt.Fprintf(w, "{\"error\":%q,\"error_code\":\"json_marshal_error\",\"exit_code\":%d,\"ok\":false}\n", msg, exitCode)
	}
}

type errCodeRule struct {
	target error
	code   string
}

func errorCodeRules() []errCodeRule {
	return []errCodeRule{
		{ErrUsage, "usage_error"},
		{ErrNotConfigured, "not_configured"},
		{ErrUnsupportedRunner, "unsupported_runner"},
		{engine.ErrEngineHalted, "engine_halted"},
		{engine.ErrApprovalRequired, "approval_required"},
		{engine.ErrApprovalRejected, "approval_rejected"},
		{engine.ErrAuthorizationDenied, "authorization_denied"},
		{engine.ErrScopeEscalated, "scope_escalated"},
		{engine.ErrNotFound, "not_found"},
		{engine.ErrAlreadyExists, "already_exists"},
		{engine.ErrRevisionConflict, "revision_conflict"},
		{engine.ErrStillReferenced, "still_referenced"},
		{engine.ErrImportConflict, "import_conflict"},
		{engine.ErrUncertainDurability, "uncertain_durability"},
		{engine.ErrOutcomeUnknown, "outcome_unknown"},
		{engine.ErrVaultUnavailable, "vault_unavailable"},
		{engine.ErrVaultLocked, "vault_locked"},
		{engine.ErrSecretNotFound, "secret_not_found"},
		{engine.ErrAuthFailed, "auth_failed"},
		{engine.ErrHostKeyUnknown, "host_key_unknown"},
		{engine.ErrHostKeyMismatch, "host_key_mismatch"},
		{engine.ErrHostKeyRevoked, "host_key_revoked"},
		{engine.ErrDialFailed, "dial_failed"},
		{engine.ErrControlMasterDisabled, "control_master_disabled"},
		{engine.ErrMuxUnavailable, "mux_unavailable"},
		{engine.ErrInteractionUnavailable, "interaction_unavailable"},
		{engine.ErrInteractionCanceled, "interaction_canceled"},
		{engine.ErrRemoteAnchorMismatch, "remote_anchor_mismatch"},
		{engine.ErrPatchConflict, "patch_conflict"},
		{engine.ErrDigestMismatch, "digest_mismatch"},
		{engine.ErrSymlinkRejected, "symlink_rejected"},
		{engine.ErrLimitExceeded, "limit_exceeded"},
		{engine.ErrUnsupported, "unsupported"},
		{engine.ErrInvalidRequest, "invalid_request"},
		{context.Canceled, "canceled"},
		{context.DeadlineExceeded, "timeout"},
	}
}

// ClassifyErrorCode 将错误链稳定归类为机器可读小写错误码，供 `--json` 错误信封消费。
func ClassifyErrorCode(err error) string {
	if err == nil {
		return "ok"
	}
	for _, rule := range errorCodeRules() {
		if errors.Is(err, rule.target) {
			return rule.code
		}
	}
	return "runtime_error"
}
