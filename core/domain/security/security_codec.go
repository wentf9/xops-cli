package security

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"slices"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
)

type (
	scopedPathWire struct {
		Path           algebraic.Option[string] `json:"path"`
		Recursive      bool                     `json:"recursive,omitzero"`
		ProtectedZones []string                 `json:"protected_zones,omitzero"`
	}
	scopeSnapshotWire struct {
		Capability algebraic.Option[CapabilityKind]   `json:"capability"`
		TargetNode string                             `json:"target_node,omitzero"`
		Endpoint   algebraic.Option[netaddr.Endpoint] `json:"endpoint,omitzero"`
		Verdict    algebraic.Option[Verdict]          `json:"verdict"`
		Risk       algebraic.Option[RiskLevel]        `json:"risk"`
		Decision   algebraic.Option[decisionWire]     `json:"decision"`
		Paths      []ScopedPath                       `json:"paths,omitzero"`
	}
	scopeEscalationResultWire struct {
		Escalated           algebraic.Option[bool] `json:"escalated"`
		Reasons             []EscalationReason     `json:"reasons,omitzero"`
		AddedProtectedPaths []string               `json:"added_protected_paths,omitzero"`
	}
)

// MarshalJSONTo 与 UnmarshalJSONFrom 实现 ScopedPath、ScopeSnapshot 与 ScopeEscalationResult 的严格 json/v2 编解码（拒绝零值、null、未知字段与缺失必需字段）。
func (p ScopedPath) MarshalJSONTo(enc *jsontext.Encoder) error {
	if !p.IsValid() {
		return ErrInvalidScopeSnapshot
	}
	return jsonv2.MarshalEncode(enc, scopedPathWire{algebraic.Some(p.path), p.recursive, p.protectedZones})
}
func (p *ScopedPath) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(p, dec, ErrInvalidScopeSnapshot, func(w scopedPathWire) (ScopedPath, error) {
		path, ok := w.Path.Get()
		if !ok {
			return ScopedPath{}, domi18n.EF(ErrInvalidScopeSnapshot, domi18n.KeyCommonJSONMissingField, domi18n.Str("field", "path"))
		}
		return NewScopedPath(path, w.Recursive, w.ProtectedZones...)
	})
}
func (s ScopeSnapshot) MarshalJSONTo(enc *jsontext.Encoder) error {
	if !s.IsValid() {
		return ErrInvalidScopeSnapshot
	}
	dw, err := encodeDecisionWire(s.decision)
	if err != nil {
		return err
	}
	return jsonv2.MarshalEncode(enc, scopeSnapshotWire{
		algebraic.Some(s.capability), s.targetNode, s.endpoint,
		algebraic.Some(s.verdict), algebraic.Some(s.risk), algebraic.Some(dw), s.paths,
	})
}
func (s *ScopeSnapshot) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(s, dec, ErrInvalidScopeSnapshot, decodeScopeSnapshotWire)
}
func (r ScopeEscalationResult) MarshalJSONTo(enc *jsontext.Encoder) error {
	if !r.valid {
		return ErrInvalidScopeSnapshot
	}
	return jsonv2.MarshalEncode(enc, scopeEscalationResultWire{algebraic.Some(r.escalated), r.reasons, r.addedProtectedPaths})
}
func (r *ScopeEscalationResult) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(r, dec, ErrInvalidScopeSnapshot, decodeScopeEscalationWire)
}

func decodeScopeSnapshotWire(w scopeSnapshotWire) (ScopeSnapshot, error) {
	capKind, okC := w.Capability.Get()
	verdict, okV := w.Verdict.Get()
	risk, okR := w.Risk.Get()
	dw, okD := w.Decision.Get()
	if !okC || !okV || !okR || !okD {
		return ScopeSnapshot{}, domi18n.EF(ErrInvalidScopeSnapshot, domi18n.KeyCommonJSONMissingField, domi18n.Str("field", "capability/verdict/risk/decision"))
	}
	decision, err := decodeDecisionWire(dw)
	if err != nil {
		return ScopeSnapshot{}, domi18n.WrapSentinel(ErrInvalidScopeSnapshot, err)
	}
	return NewScopeSnapshot(ScopeSnapshotSpec{capKind, w.TargetNode, w.Endpoint, verdict, risk, decision, w.Paths})
}

func decodeScopeEscalationWire(w scopeEscalationResultWire) (ScopeEscalationResult, error) {
	escalated, ok := w.Escalated.Get()
	if !ok {
		return ScopeEscalationResult{}, domi18n.EF(ErrInvalidScopeSnapshot, domi18n.KeyCommonJSONMissingField, domi18n.Str("field", "escalated"))
	}
	if !escalated {
		if len(w.Reasons) > 0 || len(w.AddedProtectedPaths) > 0 {
			return ScopeEscalationResult{}, domi18n.EF(ErrInvalidScopeSnapshot, domi18n.KeySecurityEscalationReasons)
		}
		return ScopeEscalationResult{valid: true}, nil
	}
	if len(w.Reasons) == 0 {
		return ScopeEscalationResult{}, domi18n.EF(ErrInvalidScopeSnapshot, domi18n.KeySecurityEscalationReasons)
	}
	reasons := make([]EscalationReason, 0, len(w.Reasons))
	for _, reason := range w.Reasons {
		if !reason.IsValid() || slices.Contains(reasons, reason) {
			return ScopeEscalationResult{}, domi18n.EF(ErrInvalidScopeSnapshot, domi18n.KeySecurityEscalationReasons)
		}
		reasons = append(reasons, reason)
	}
	added, err := canonicalizeUniqueStrings(w.AddedProtectedPaths, "added_protected_paths", ErrInvalidScopeSnapshot)
	if err != nil {
		return ScopeEscalationResult{}, err
	}
	return ScopeEscalationResult{escalated: true, reasons: reasons, addedProtectedPaths: added, valid: true}, nil
}
