package algebraic

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
)

var (
	_ jsonv2.MarshalerTo     = Option[int]{}
	_ jsonv2.UnmarshalerFrom = (*Option[int])(nil)
)

// Option 表示结构体中的可选值字段，用于精确区分“未设置（None）”与“显式设置了类型零值（Some(zero)）”。
//
// 约束（ADR-014）：仅限结构体可选字段使用，不替代函数返回值的 (T, error) 或 (T, bool) 习惯；
// 零值代表未设置（None），配合 Go 1.27 encoding/json/v2 的 omitzero 标签可自动省略未设置字段并保留显式零值。
//
//xops:opaque
//xops:failclosed
type Option[T any] struct {
	value T
	valid bool
}

// Some 构造一个包含显式值 value 的 Option[T]（即使 value 为类型 T 的零值，IsSome() 仍为 true）。
func Some[T any](value T) Option[T] {
	return Option[T]{
		value: value,
		valid: true,
	}
}

// None 返回表示未设置的零值 Option[T]。
func None[T any]() Option[T] {
	return Option[T]{}
}

// OptionFromPtr 将可选指针转换为不可变值语义的 Option[T]：p == nil 返回 None，否则复制 *p 返回 Some。
func OptionFromPtr[T any](p *T) Option[T] {
	if p == nil {
		return None[T]()
	}
	return Some(*p)
}

// IsSome 报告当前 Option 是否显式持有值。
func (o Option[T]) IsSome() bool {
	return o.valid
}

// IsNone 报告当前 Option 是否处于未设置状态。
func (o Option[T]) IsNone() bool {
	return !o.valid
}

// IsZero 报告当前 Option 是否为零值（未设置状态）。
// 当且仅当为 None 时返回 true，使 encoding/json/v2 的 omitzero 不会误省略 Some(0) 或 Some("")。
func (o Option[T]) IsZero() bool {
	return !o.valid
}

// Get 提取 Option 中持有的值；若为 None 则返回类型零值与 false。
func (o Option[T]) Get() (T, bool) {
	if !o.valid {
		var zero T
		return zero, false
	}
	return o.value, true
}

// OrElse 在持有值时返回内部值，否则返回显式指定的回退值 fallback。
func (o Option[T]) OrElse(fallback T) T {
	if !o.valid {
		return fallback
	}
	return o.value
}

// Or 按左优先规则合并两个 Option：若当前为 Some 则返回自身，否则返回 other。
// 该运算与 None 共同构成结合律幺半群（左优先语义，与 FirstWins 一致）。
func (o Option[T]) Or(other Option[T]) Option[T] {
	if o.valid {
		return o
	}
	return other
}

// EqualOption 判断两个可比较元素类型的 Option 是否语义相等（同为 None 或同为 Some 且内部值相等）。
func EqualOption[T comparable](a, b Option[T]) bool {
	if a.valid != b.valid {
		return false
	}
	if !a.valid {
		return true
	}
	return a.value == b.value
}

// MarshalJSONTo 实现 encoding/json/v2.MarshalerTo（值接收者）：
// None 编码为 JSON null；Some 委托 json/v2.MarshalEncode 透传外层编码选项（含 Deterministic(true)）。
func (o Option[T]) MarshalJSONTo(enc *jsontext.Encoder) error {
	if !o.valid {
		return enc.WriteToken(jsontext.Null)
	}
	return jsonv2.MarshalEncode(enc, o.value)
}

// UnmarshalJSONFrom 实现 encoding/json/v2.UnmarshalerFrom：
// JSON null 解码为 None；其余 JSON 值解码为 Some(v)；若解码失败则重置为 None 并失败关闭。
func (o *Option[T]) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	if o == nil {
		return ErrNilReceiver
	}
	if dec.PeekKind() == 'n' {
		if _, err := dec.ReadToken(); err != nil {
			*o = None[T]()
			return err
		}
		*o = None[T]()
		return nil
	}
	var v T
	if err := jsonv2.UnmarshalDecode(dec, &v); err != nil {
		*o = None[T]()
		return err
	}
	*o = Some(v)
	return nil
}
