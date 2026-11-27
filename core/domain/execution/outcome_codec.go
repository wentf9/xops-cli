package execution

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

type exitStatusWire struct {
	Kind       algebraic.Option[ExitStatusKind] `json:"kind"`
	Code       algebraic.Option[int32]          `json:"code,omitzero"`
	Signal     string                           `json:"signal,omitzero"`
	CoreDumped bool                             `json:"core_dumped,omitzero"`
	Message    string                           `json:"message,omitzero"`
	Reason     string                           `json:"reason,omitzero"`
}

// MarshalExitStatusTo 将任意有效 ExitStatus 编码至 Go 1.27 JSON/v2 流；nil 或无效零值失败关闭。
func MarshalExitStatusTo(enc *jsontext.Encoder, status ExitStatus) error {
	if enc == nil {
		return ErrNilWriter
	}
	w, err := encodeExitStatusWire(status)
	if err != nil {
		return err
	}
	return jsonv2.MarshalEncode(enc, w)
}

// UnmarshalExitStatusFrom 从 Go 1.27 JSON/v2 流严格解码多态 ExitStatus；null/缺失字段/串用字段均失败关闭。
func UnmarshalExitStatusFrom(dec *jsontext.Decoder) (ExitStatus, error) {
	if dec == nil {
		return nil, ErrNilReceiver
	}
	var out ExitStatus
	err := unmarshalJSONWithNullReject(&out, dec, ErrInvalidExitStatus, decodeExitStatusWire)
	return out, err
}

// MarshalJSONTo 为 ExitCode、ExitSignal、ExitUnknown 提供值接收者 json/v2 编码（零值失败关闭）。
func (e ExitCode) MarshalJSONTo(enc *jsontext.Encoder) error    { return MarshalExitStatusTo(enc, &e) }
func (e ExitSignal) MarshalJSONTo(enc *jsontext.Encoder) error  { return MarshalExitStatusTo(enc, &e) }
func (e ExitUnknown) MarshalJSONTo(enc *jsontext.Encoder) error { return MarshalExitStatusTo(enc, &e) }

func encodeExitStatusWire(s ExitStatus) (exitStatusWire, error) {
	if s == nil || !s.IsValid() {
		return exitStatusWire{}, ErrInvalidExitStatus
	}
	switch v := s.(type) {
	case *ExitCode:
		return exitStatusWire{Kind: algebraic.Some(ExitStatusKindCode), Code: algebraic.Some(v.code)}, nil
	case *ExitSignal:
		return exitStatusWire{
			Kind: algebraic.Some(ExitStatusKindSignal), Signal: v.signal,
			CoreDumped: v.coreDumped, Message: v.message,
		}, nil
	case *ExitUnknown:
		return exitStatusWire{Kind: algebraic.Some(ExitStatusKindUnknown), Reason: v.reason}, nil
	default:
		return exitStatusWire{}, ErrInvalidExitStatus
	}
}

func decodeExitStatusWire(w exitStatusWire) (ExitStatus, error) {
	kind, ok := w.Kind.Get()
	if !ok {
		return nil, domi18n.EF(ErrInvalidExitStatus, domi18n.KeyCommonJSONMissingField, domi18n.Str("field", "exit_status.kind"))
	}
	switch kind {
	case ExitStatusKindCode:
		code, hasCode := w.Code.Get()
		if !hasCode || w.Signal != "" || w.CoreDumped || w.Message != "" || w.Reason != "" {
			return nil, domi18n.EF(ErrInvalidExitStatus, domi18n.KeyCommonJSONVariantInvalid, domi18n.Str("variant", "code"))
		}
		return NewExitCode(code), nil
	case ExitStatusKindSignal:
		if w.Code.IsSome() || w.Reason != "" || w.Signal == "" {
			return nil, domi18n.EF(ErrInvalidExitStatus, domi18n.KeyCommonJSONVariantInvalid, domi18n.Str("variant", "signal"))
		}
		return NewExitSignal(w.Signal, w.CoreDumped, w.Message)
	case ExitStatusKindUnknown:
		if w.Code.IsSome() || w.Signal != "" || w.CoreDumped || w.Message != "" {
			return nil, domi18n.EF(ErrInvalidExitStatus, domi18n.KeyCommonJSONVariantInvalid, domi18n.Str("variant", "unknown"))
		}
		return NewExitUnknown(w.Reason), nil
	default:
		return nil, domi18n.EF(ErrInvalidExitStatus, domi18n.KeyCommonUnknownValue, domi18n.Str("kind", "exit_status.kind"), domi18n.Uint64("value", uint64(kind)))
	}
}

type outcomeWire struct {
	Kind       algebraic.Option[OutcomeKind]    `json:"kind"`
	StartPhase algebraic.Option[StartPhase]     `json:"start_phase,omitzero"`
	ExecPhase  algebraic.Option[ExecPhase]      `json:"exec_phase,omitzero"`
	Code       string                           `json:"code,omitzero"`
	Reason     string                           `json:"reason,omitzero"`
	ExitStatus algebraic.Option[exitStatusWire] `json:"exit_status,omitzero"`
	Truncated  bool                             `json:"truncated,omitzero"`
}

// MarshalOutcomeTo 将任意有效 ExecutionOutcome 编码至 Go 1.27 JSON/v2 流；nil 或无效零值失败关闭。
func MarshalOutcomeTo(enc *jsontext.Encoder, outcome ExecutionOutcome) error {
	if enc == nil {
		return ErrNilWriter
	}
	w, err := encodeOutcomeWire(outcome)
	if err != nil {
		return err
	}
	return jsonv2.MarshalEncode(enc, w)
}

// UnmarshalOutcomeFrom 从 Go 1.27 JSON/v2 流严格解码多态 ExecutionOutcome；
// 对 JSON null、缺失必需字段或跨变体混用字段一律失败关闭。
func UnmarshalOutcomeFrom(dec *jsontext.Decoder) (ExecutionOutcome, error) {
	if dec == nil {
		return nil, ErrNilReceiver
	}
	var out ExecutionOutcome
	err := unmarshalJSONWithNullReject(&out, dec, ErrInvalidExecutionOutcome, decodeOutcomeWire)
	return out, err
}

// MarshalJSONTo 为 OutcomeNotStarted、OutcomeCompleted、OutcomeUnknown 提供值接收者 json/v2 编码（零值失败关闭）。
func (o OutcomeNotStarted) MarshalJSONTo(enc *jsontext.Encoder) error {
	return MarshalOutcomeTo(enc, &o)
}
func (o OutcomeCompleted) MarshalJSONTo(enc *jsontext.Encoder) error {
	return MarshalOutcomeTo(enc, &o)
}
func (o OutcomeUnknown) MarshalJSONTo(enc *jsontext.Encoder) error {
	return MarshalOutcomeTo(enc, &o)
}

func encodeOutcomeWire(o ExecutionOutcome) (outcomeWire, error) {
	if o == nil || !o.IsValid() {
		return outcomeWire{}, ErrInvalidExecutionOutcome
	}
	switch v := o.(type) {
	case *OutcomeNotStarted:
		return outcomeWire{
			Kind: algebraic.Some(OutcomeKindNotStarted), StartPhase: algebraic.Some(v.phase),
			Code: v.code, Reason: v.reason,
		}, nil
	case *OutcomeCompleted:
		ew, err := encodeExitStatusWire(v.status)
		if err != nil {
			return outcomeWire{}, err
		}
		return outcomeWire{
			Kind: algebraic.Some(OutcomeKindCompleted), ExitStatus: algebraic.Some(ew),
			Truncated: v.truncated,
		}, nil
	case *OutcomeUnknown:
		return outcomeWire{
			Kind: algebraic.Some(OutcomeKindUnknown), ExecPhase: algebraic.Some(v.phase),
			Code: v.code, Reason: v.reason,
		}, nil
	default:
		return outcomeWire{}, ErrInvalidExecutionOutcome
	}
}

func decodeOutcomeWire(w outcomeWire) (ExecutionOutcome, error) {
	kind, ok := w.Kind.Get()
	if !ok {
		return nil, domi18n.EF(ErrInvalidExecutionOutcome, domi18n.KeyCommonJSONMissingField, domi18n.Str("field", "outcome.kind"))
	}
	switch kind {
	case OutcomeKindNotStarted:
		return decodeNotStartedWire(w)
	case OutcomeKindCompleted:
		return decodeCompletedWire(w)
	case OutcomeKindUnknown:
		return decodeUnknownWire(w)
	default:
		return nil, domi18n.EF(ErrInvalidExecutionOutcome, domi18n.KeyCommonUnknownValue, domi18n.Str("kind", "outcome.kind"), domi18n.Uint64("value", uint64(kind)))
	}
}

func decodeNotStartedWire(w outcomeWire) (ExecutionOutcome, error) {
	phase, ok := w.StartPhase.Get()
	if !ok || w.ExecPhase.IsSome() || w.ExitStatus.IsSome() || w.Truncated {
		return nil, domi18n.EF(ErrInvalidExecutionOutcome, domi18n.KeyCommonJSONVariantInvalid, domi18n.Str("variant", "not_started"))
	}
	return NewOutcomeNotStarted(phase, w.Code, w.Reason)
}

func decodeCompletedWire(w outcomeWire) (ExecutionOutcome, error) {
	ew, ok := w.ExitStatus.Get()
	if !ok || w.StartPhase.IsSome() || w.ExecPhase.IsSome() || w.Code != "" || w.Reason != "" {
		return nil, domi18n.EF(ErrInvalidExecutionOutcome, domi18n.KeyCommonJSONVariantInvalid, domi18n.Str("variant", "completed"))
	}
	st, err := decodeExitStatusWire(ew)
	if err != nil {
		return nil, domi18n.WrapSentinel(ErrInvalidExecutionOutcome, err)
	}
	return NewOutcomeCompleted(st, w.Truncated)
}

func decodeUnknownWire(w outcomeWire) (ExecutionOutcome, error) {
	phase, ok := w.ExecPhase.Get()
	if !ok || w.StartPhase.IsSome() || w.ExitStatus.IsSome() || w.Truncated {
		return nil, domi18n.EF(ErrInvalidExecutionOutcome, domi18n.KeyCommonJSONVariantInvalid, domi18n.Str("variant", "unknown"))
	}
	return NewOutcomeUnknown(phase, w.Code, w.Reason)
}
