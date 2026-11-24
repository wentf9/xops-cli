package algebraic

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
)

var (
	_ jsonv2.MarshalerTo     = FirstWins[int]{}
	_ jsonv2.UnmarshalerFrom = (*FirstWins[int])(nil)
)

// FirstWins 表示 OpenSSH “首次匹配生效（First-Match-Wins）”策略求解所用的左优先幺半群：
//   - 单位元（Identity）：零值 Unset（IsSet() == false）；
//   - 二元运算 Combine：若左操作数已设置则左吸收胜出，否则采用右操作数；
//   - 代数律：严格满足结合律、左右单位元律、幂等律与已设置左吸收律。
//
//xops:opaque
//xops:failclosed
type FirstWins[T any] struct {
	value T
	valid bool
}

// NewFirstWins 构造一个已设置显式值 value 的 FirstWins[T]。
func NewFirstWins[T any](value T) FirstWins[T] {
	return FirstWins[T]{
		value: value,
		valid: true,
	}
}

// UnsetFirstWins 返回 FirstWins[T] 幺半群的单位元（未设置零值）。
func UnsetFirstWins[T any]() FirstWins[T] {
	return FirstWins[T]{}
}

// FirstWinsFromOption 将可选字段 Option[T] 提升为参与幺半群求解的 FirstWins[T]。
func FirstWinsFromOption[T any](opt Option[T]) FirstWins[T] {
	v, ok := opt.Get()
	if !ok {
		return UnsetFirstWins[T]()
	}
	return NewFirstWins(v)
}

// FoldFirstWins 按从高优先级到低优先级的顺序左折叠多个 FirstWins[T]（空序列返回单位元 Unset）。
func FoldFirstWins[T any](layers ...FirstWins[T]) FirstWins[T] {
	acc := UnsetFirstWins[T]()
	for _, layer := range layers {
		acc = acc.Combine(layer)
	}
	return acc
}

// IsSet 报告当前 FirstWins 是否已设置值。
func (f FirstWins[T]) IsSet() bool {
	return f.valid
}

// IsUnset 报告当前 FirstWins 是否为单位元（未设置）。
func (f FirstWins[T]) IsUnset() bool {
	return !f.valid
}

// IsZero 报告当前 FirstWins 是否为零值未设置状态（配合 encoding/json/v2 omitzero）。
func (f FirstWins[T]) IsZero() bool {
	return !f.valid
}

// Get 提取当前值；若未设置则返回类型零值与 false。
func (f FirstWins[T]) Get() (T, bool) {
	if !f.valid {
		var zero T
		return zero, false
	}
	return f.value, true
}

// OrElse 在已设置时返回内部值，否则返回显式指定的默认值 fallback。
func (f FirstWins[T]) OrElse(fallback T) T {
	if !f.valid {
		return fallback
	}
	return f.value
}

// Combine 执行左优先幺半群二元运算：左操作数已设置时保持不变，否则回退为 other。
func (f FirstWins[T]) Combine(other FirstWins[T]) FirstWins[T] {
	if f.valid {
		return f
	}
	return other
}

// ToOption 将 FirstWins[T] 投影为等价的 Option[T]。
func (f FirstWins[T]) ToOption() Option[T] {
	if !f.valid {
		return None[T]()
	}
	return Some(f.value)
}

// EqualFirstWins 判断两个可比较元素类型的 FirstWins 是否语义相等。
func EqualFirstWins[T comparable](a, b FirstWins[T]) bool {
	if a.valid != b.valid {
		return false
	}
	if !a.valid {
		return true
	}
	return a.value == b.value
}

// MarshalJSONTo 实现 encoding/json/v2.MarshalerTo（值接收者）：
// 未设置编码为 JSON null；已设置委托 json/v2.MarshalEncode 透传外层编码选项。
func (f FirstWins[T]) MarshalJSONTo(enc *jsontext.Encoder) error {
	if !f.valid {
		return enc.WriteToken(jsontext.Null)
	}
	return jsonv2.MarshalEncode(enc, f.value)
}

// UnmarshalJSONFrom 实现 encoding/json/v2.UnmarshalerFrom：
// JSON null 解码为未设置单位元；其余值解码为已设置值；失败时重置为零值并失败关闭。
func (f *FirstWins[T]) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	if f == nil {
		return ErrNilReceiver
	}
	if dec.PeekKind() == 'n' {
		if _, err := dec.ReadToken(); err != nil {
			*f = UnsetFirstWins[T]()
			return err
		}
		*f = UnsetFirstWins[T]()
		return nil
	}
	var v T
	if err := jsonv2.UnmarshalDecode(dec, &v); err != nil {
		*f = UnsetFirstWins[T]()
		return err
	}
	*f = NewFirstWins(v)
	return nil
}
