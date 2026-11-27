package i18n

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"

	"github.com/wentf9/xops-cli/core/domain/i18n/internal/textalg"
)

type messageWire struct {
	ID       MessageID `json:"id"`
	Fallback string    `json:"fallback,omitzero"`
	Count    *int64    `json:"count,omitzero"`
	Params   []Param   `json:"params,omitzero"`
}

// AppendText 实现 Locale 的 encoding.TextAppender（值接收者）；对非法零值严格失败关闭。
func (l Locale) AppendText(b []byte) ([]byte, error) {
	if !l.IsValid() {
		return nil, ErrInvalidLocale
	}
	return append(b, l.String()...), nil
}

// MarshalText 实现 Locale 的 encoding.TextMarshaler（值接收者）。
func (l Locale) MarshalText() ([]byte, error) {
	return l.AppendText(nil)
}

// UnmarshalText 实现 Locale 的 encoding.TextUnmarshaler；失败时重置为 LocaleInvalid 并返回错误。
func (l *Locale) UnmarshalText(text []byte) error {
	if l == nil {
		return ErrNilReceiver
	}
	parsed, err := ParseLocale(string(text))
	if err != nil {
		*l = LocaleInvalid
		return err
	}
	*l = parsed
	return nil
}

// MarshalJSONTo 实现 Param 的 encoding/json/v2.MarshalerTo（值接收者，确定性字段序，拒绝无效零值）。
func (p Param) MarshalJSONTo(enc *jsontext.Encoder) error {
	if !p.IsValid() {
		return ErrInvalidParam
	}
	return jsonv2.MarshalEncode(enc, encodeParamWire(p))
}

// UnmarshalJSONFrom 实现 Param 的 encoding/json/v2.UnmarshalerFrom：
// 失败时重置为零值，拒绝 JSON null、显式 null 旁路载荷键、未知字段、冲突字段、NaN/±Inf、超长字符串与超深嵌套。
func (p *Param) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	if p == nil {
		return ErrNilReceiver
	}
	*p = Param{}
	var wire textalg.ParamWire[Message]
	if err := textalg.UnmarshalCheckedObject(dec, &wire, ErrInvalidParam); err != nil {
		return err
	}
	parsed, err := decodeParamWire(wire)
	if err != nil {
		return err
	}
	*p = parsed
	return nil
}

// MarshalJSONTo 实现 Message 的 encoding/json/v2.MarshalerTo（值接收者，确定性字段序，拒绝无效零值）。
func (m Message) MarshalJSONTo(enc *jsontext.Encoder) error {
	if !m.IsValid() {
		return ErrInvalidMessage
	}
	wire := messageWire{ID: m.id, Fallback: m.fallback, Params: m.params}
	if m.hasCount {
		c := m.count
		wire.Count = &c
	}
	return jsonv2.MarshalEncode(enc, wire)
}

// UnmarshalJSONFrom 实现 Message 的 encoding/json/v2.UnmarshalerFrom：
// 失败时重置为零值，拒绝 JSON null、显式 null 成员键、未知字段、非法 MessageID、参数超限/重复与嵌套超深。
func (m *Message) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	if m == nil {
		return ErrNilReceiver
	}
	*m = Message{}
	var wire messageWire
	if err := textalg.UnmarshalCheckedObject(dec, &wire, ErrInvalidMessage); err != nil {
		return err
	}
	parsed, err := decodeMessageWire(wire)
	if err != nil {
		return err
	}
	*m = parsed
	return nil
}

func encodeParamWire(p Param) textalg.ParamWire[Message] {
	w := textalg.ParamWire[Message]{Key: p.key, Kind: p.kind.String()}
	switch p.kind {
	case ParamKindString:
		v := p.strVal
		w.Str = &v
	case ParamKindInt64:
		v := p.intVal
		w.Int64 = &v
	case ParamKindUint64:
		v := p.uintVal
		w.Uint64 = &v
	case ParamKindFloat64:
		fv, pv := p.floatVal, p.floatPrec
		w.Float64, w.Prec = &fv, &pv
	case ParamKindBool:
		v := p.boolVal
		w.Bool = &v
	case ParamKindDuration:
		v := textalg.FormatDurationNanos(p.durNanos)
		w.Duration = &v
	case ParamKindMessage:
		mc := p.msgVal.clone()
		w.Message = &mc
	}
	return w
}

func decodeParamWire(w textalg.ParamWire[Message]) (Param, error) {
	if !textalg.IsValidParamKey(w.Key) {
		return Param{}, EF(ErrInvalidParam, KeyParamInvalidKey, Str("key", BoundDisplayText(w.Key, MaxParamKeyBytes)))
	}
	if !textalg.HasValidParamWireShape(w) {
		return Param{}, EF(ErrInvalidParam, KeyParamInvalidValue, Str("key", w.Key))
	}
	return buildDecodedParam(w)
}

func buildDecodedParam(w textalg.ParamWire[Message]) (Param, error) {
	switch w.Kind {
	case "string":
		return validateDecodedParam(w.Key, w.Str != nil, func() Param { return Str(w.Key, *w.Str) })
	case "int64":
		return validateDecodedParam(w.Key, w.Int64 != nil, func() Param { return Int64(w.Key, *w.Int64) })
	case "uint64":
		return validateDecodedParam(w.Key, w.Uint64 != nil, func() Param { return Uint64(w.Key, *w.Uint64) })
	case "float64":
		return decodeFloatParam(w)
	case "bool":
		return validateDecodedParam(w.Key, w.Bool != nil, func() Param { return Bool(w.Key, *w.Bool) })
	case "duration":
		return decodeDurationParam(w)
	case "message":
		return decodeNestedMessageParam(w)
	default:
		return Param{}, EF(ErrInvalidParam, KeyParamInvalidKind, Str("kind", BoundDisplayText(w.Kind, MaxParamKeyBytes)))
	}
}

func validateDecodedParam(key string, present bool, makeParam func() Param) (Param, error) {
	if !present {
		return Param{}, EF(ErrInvalidParam, KeyParamInvalidValue, Str("key", key))
	}
	if p := makeParam(); p.IsValid() {
		return p, nil
	}
	return Param{}, EF(ErrInvalidParam, KeyParamInvalidValue, Str("key", key))
}

func decodeFloatParam(w textalg.ParamWire[Message]) (Param, error) {
	prec := -1
	if w.Prec != nil {
		prec = *w.Prec
	}
	return validateDecodedParam(w.Key, w.Float64 != nil, func() Param { return Float(w.Key, *w.Float64, prec) })
}

func decodeDurationParam(w textalg.ParamWire[Message]) (Param, error) {
	if w.Duration == nil || *w.Duration == "" {
		return Param{}, EF(ErrInvalidParam, KeyParamInvalidValue, Str("key", w.Key))
	}
	nanos, err := textalg.ParseDurationNanos(*w.Duration)
	if err != nil {
		return Param{}, WrapS(ErrInvalidParam, err, KeyParamInvalidValue, Str("key", w.Key))
	}
	return validateDecodedParam(w.Key, true, func() Param { return DurNanos(w.Key, nanos) })
}

func decodeNestedMessageParam(w textalg.ParamWire[Message]) (Param, error) {
	if w.Message == nil || !w.Message.IsValid() {
		return Param{}, EF(ErrInvalidParam, KeyParamInvalidValue, Str("key", w.Key))
	}
	if w.Message.depth >= MaxMessageDepth {
		return Param{}, EF(ErrInvalidParam, KeyParamDepthExceeded, Int("max", int(MaxMessageDepth)))
	}
	return validateDecodedParam(w.Key, true, func() Param { return Msg(w.Key, *w.Message) })
}

func decodeMessageWire(w messageWire) (Message, error) {
	if !w.ID.IsValid() {
		return Message{}, EF(ErrInvalidMessage, KeyMessageInvalid)
	}
	if len(w.Params) > MaxMessageParams {
		return Message{}, EF(ErrInvalidMessage, KeyMessageTooManyParams, Int("max", MaxMessageParams))
	}
	if dupKey, ok := textalg.FindDuplicateKey(w.Params, func(p Param) (string, bool) { return p.key, p.IsValid() }); ok {
		return Message{}, EF(ErrInvalidMessage, KeyMessageDuplicateParam, Str("key", dupKey))
	}
	var parsed Message
	if w.Count != nil {
		parsed = NewPluralMessageWithFallback(w.ID, w.Fallback, *w.Count, w.Params...)
	} else {
		parsed = NewMessageWithFallback(w.ID, w.Fallback, w.Params...)
	}
	if !parsed.IsValid() {
		return Message{}, EF(ErrInvalidMessage, KeyMessageInvalid)
	}
	return parsed, nil
}
