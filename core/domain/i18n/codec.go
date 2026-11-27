package i18n

import (
	"bytes"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"time"
)

type paramWire struct {
	Key      string   `json:"key"`
	Kind     string   `json:"kind"`
	Str      *string  `json:"str,omitzero"`
	Int64    *int64   `json:"int64,omitzero"`
	Uint64   *uint64  `json:"uint64,omitzero"`
	Float64  *float64 `json:"float64,omitzero"`
	Prec     *int     `json:"prec,omitzero"`
	Bool     *bool    `json:"bool,omitzero"`
	Duration *string  `json:"duration,omitzero"`
	Message  *Message `json:"message,omitzero"`
}

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
	raw, err := readCheckedObjectValue(dec, ErrInvalidParam)
	if err != nil {
		return err
	}
	var wire paramWire
	if err := jsonv2.Unmarshal(raw, &wire, jsonv2.RejectUnknownMembers(true)); err != nil {
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
	wire := messageWire{
		ID:       m.id,
		Fallback: m.fallback,
		Params:   m.params,
	}
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
	raw, err := readCheckedObjectValue(dec, ErrInvalidMessage)
	if err != nil {
		return err
	}
	var wire messageWire
	if err := jsonv2.Unmarshal(raw, &wire, jsonv2.RejectUnknownMembers(true)); err != nil {
		return err
	}
	parsed, err := decodeMessageWire(wire)
	if err != nil {
		return err
	}
	*m = parsed
	return nil
}

func encodeParamWire(p Param) paramWire {
	w := paramWire{Key: p.key, Kind: p.kind.String()}
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
		v := time.Duration(p.durNanos).String()
		w.Duration = &v
	case ParamKindMessage:
		mc := p.msgVal.clone()
		w.Message = &mc
	}
	return w
}

func decodeParamWire(w paramWire) (Param, error) {
	if !isValidParamKey(w.Key) {
		return Param{}, EF(ErrInvalidParam, KeyParamInvalidKey, Str("key", BoundDisplayText(w.Key, MaxParamKeyBytes)))
	}
	if countParamPayloadFields(w) != 1 || (w.Kind != "float64" && w.Prec != nil) {
		return Param{}, EF(ErrInvalidParam, KeyParamInvalidValue, Str("key", w.Key))
	}
	return buildDecodedParam(w)
}

func buildDecodedParam(w paramWire) (Param, error) {
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
	p := makeParam()
	if !p.IsValid() {
		return Param{}, EF(ErrInvalidParam, KeyParamInvalidValue, Str("key", key))
	}
	return p, nil
}

func decodeFloatParam(w paramWire) (Param, error) {
	if w.Float64 == nil {
		return Param{}, EF(ErrInvalidParam, KeyParamInvalidValue, Str("key", w.Key))
	}
	prec := -1
	if w.Prec != nil {
		prec = *w.Prec
	}
	p := Float(w.Key, *w.Float64, prec)
	if !p.IsValid() {
		return Param{}, EF(ErrInvalidParam, KeyParamInvalidValue, Str("key", w.Key))
	}
	return p, nil
}

func decodeDurationParam(w paramWire) (Param, error) {
	if w.Duration == nil || *w.Duration == "" {
		return Param{}, EF(ErrInvalidParam, KeyParamInvalidValue, Str("key", w.Key))
	}
	d, err := time.ParseDuration(*w.Duration)
	if err != nil {
		return Param{}, WrapS(ErrInvalidParam, err, KeyParamInvalidValue, Str("key", w.Key))
	}
	p := Dur(w.Key, d)
	if !p.IsValid() {
		return Param{}, EF(ErrInvalidParam, KeyParamInvalidValue, Str("key", w.Key))
	}
	return p, nil
}

func decodeNestedMessageParam(w paramWire) (Param, error) {
	if w.Message == nil || !w.Message.IsValid() {
		return Param{}, EF(ErrInvalidParam, KeyParamInvalidValue, Str("key", w.Key))
	}
	if w.Message.depth >= MaxMessageDepth {
		return Param{}, EF(ErrInvalidParam, KeyParamDepthExceeded, Int("max", int(MaxMessageDepth)))
	}
	p := Msg(w.Key, *w.Message)
	if !p.IsValid() {
		return Param{}, EF(ErrInvalidParam, KeyParamInvalidValue, Str("key", w.Key))
	}
	return p, nil
}

func countParamPayloadFields(w paramWire) int {
	n := 0
	for _, set := range []bool{
		w.Str != nil, w.Int64 != nil, w.Uint64 != nil,
		w.Float64 != nil, w.Bool != nil, w.Duration != nil, w.Message != nil,
	} {
		if set {
			n++
		}
	}
	return n
}

func decodeMessageWire(w messageWire) (Message, error) {
	if !w.ID.IsValid() {
		return Message{}, EF(ErrInvalidMessage, KeyMessageInvalid)
	}
	if len(w.Params) > MaxMessageParams {
		return Message{}, EF(ErrInvalidMessage, KeyMessageTooManyParams, Int("max", MaxMessageParams))
	}
	if dupKey, ok := findDuplicateParamKey(w.Params); ok {
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

func findDuplicateParamKey(params []Param) (string, bool) {
	for i := range params {
		if !params[i].IsValid() {
			continue
		}
		for j := range i {
			if params[j].IsValid() && params[j].key == params[i].key {
				return params[i].key, true
			}
		}
	}
	return "", false
}

// readCheckedObjectValue 读取完整 JSON 值并拒绝顶层 null 以及对象内任意显式 null 成员值，
// 防止类似 {"key":"k","kind":"string","str":"ok","int64":null} 的旁路载荷绕过指针非空校验。
func readCheckedObjectValue(dec *jsontext.Decoder, baseErr error) (jsontext.Value, error) {
	raw, err := dec.ReadValue()
	if err != nil {
		return nil, err
	}
	if err := rejectNullObjectMembers(raw, baseErr); err != nil {
		return nil, err
	}
	return raw, nil
}

func rejectNullObjectMembers(raw jsontext.Value, baseErr error) error {
	d := jsontext.NewDecoder(bytes.NewReader(raw))
	if d.PeekKind() == 'n' {
		return baseErr
	}
	if d.PeekKind() != '{' {
		return nil
	}
	if _, err := d.ReadToken(); err != nil {
		return err
	}
	for d.PeekKind() != '}' {
		if _, err := d.ReadToken(); err != nil {
			return err
		}
		if d.PeekKind() == 'n' {
			return baseErr
		}
		if err := d.SkipValue(); err != nil {
			return err
		}
	}
	return nil
}
