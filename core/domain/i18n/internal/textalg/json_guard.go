package textalg

import (
	"bytes"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"time"
)

// ParamWire 是强类型消息参数 Param 的 JSON/v2 确定性线协议表示（泛型载荷 M 避免对父包类型形成循环依赖）。
type ParamWire[M any] struct {
	Key      string   `json:"key"`
	Kind     string   `json:"kind"`
	Str      *string  `json:"str,omitzero"`
	Int64    *int64   `json:"int64,omitzero"`
	Uint64   *uint64  `json:"uint64,omitzero"`
	Float64  *float64 `json:"float64,omitzero"`
	Prec     *int     `json:"prec,omitzero"`
	Bool     *bool    `json:"bool,omitzero"`
	Duration *string  `json:"duration,omitzero"`
	Message  *M       `json:"message,omitzero"`
}

// UnmarshalCheckedObject 读取完整 JSON 对象值、拒绝顶层 null 与对象内任意显式 null 成员键，
// 随后以 RejectUnknownMembers(true) 严格反序列化至 dst。
func UnmarshalCheckedObject[T any](dec *jsontext.Decoder, dst *T, baseErr error) error {
	raw, err := ReadCheckedObjectValue(dec, baseErr)
	if err != nil {
		return err
	}
	return jsonv2.Unmarshal(raw, dst, jsonv2.RejectUnknownMembers(true))
}

// ReadCheckedObjectValue 读取完整 JSON 值并拒绝顶层 null 以及对象内任意显式 null 成员值，
// 防止类似 {"key":"k","kind":"string","str":"ok","int64":null} 的旁路载荷绕过指针非空校验。
func ReadCheckedObjectValue(dec *jsontext.Decoder, baseErr error) (jsontext.Value, error) {
	raw, err := dec.ReadValue()
	if err != nil {
		return nil, err
	}
	if err := RejectNullObjectMembers(raw, baseErr); err != nil {
		return nil, err
	}
	return raw, nil
}

// RejectNullObjectMembers 扫描原始 JSON 文本，拒绝顶层 null 以及对象内任意显式 null 成员值。
func RejectNullObjectMembers(raw jsontext.Value, baseErr error) error {
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

// HasValidParamWireShape 校验 ParamWire 恰含 1 个非空变体载荷字段，且非 float64 变体不携带 prec。
func HasValidParamWireShape[M any](w ParamWire[M]) bool {
	return countParamPayloadFields(w) == 1 && (w.Kind == "float64" || w.Prec == nil)
}

func countParamPayloadFields[M any](w ParamWire[M]) int {
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

// FormatDurationNanos 将纳秒整数确定性格式化为标准 Go 时长文本。
func FormatDurationNanos(nanos int64) string {
	return time.Duration(nanos).String()
}

// ParseDurationNanos 解析标准 Go 时长文本并返回纳秒整数。
func ParseDurationNanos(raw string) (int64, error) {
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, err
	}
	return int64(d), nil
}

// FindDuplicateKey 在元素序列中按 keyOf 提取有效键名并检测首个重复键（小切片零堆分配）。
func FindDuplicateKey[T any](items []T, keyOf func(T) (string, bool)) (string, bool) {
	for i := range items {
		ki, ok := keyOf(items[i])
		if !ok {
			continue
		}
		for j := range i {
			if kj, okj := keyOf(items[j]); okj && kj == ki {
				return ki, true
			}
		}
	}
	return "", false
}
