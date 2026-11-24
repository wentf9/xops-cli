package algebraic

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"iter"
	"slices"
)

var (
	_ jsonv2.MarshalerTo     = NonEmpty[int]{}
	_ jsonv2.UnmarshalerFrom = (*NonEmpty[int])(nil)
)

// NonEmpty 表示类型级证明至少包含一个元素的不可变非空切片（len >= 1）。
//
// 所有构造器与切片导出方法均执行防御性拷贝，阻止调用方通过共享底层数组破坏不可变性；
// 零值代表无效状态（IsValid() == false、IsZero() == true），在序列化、连接与追加时严格失败关闭。
//
//xops:opaque
//xops:failclosed
type NonEmpty[T any] struct {
	items []T
}

// NewNonEmpty 以编译期强制非空的方式构造 NonEmpty[T]（必含首元素 head 及可选后续元素 tail）。
func NewNonEmpty[T any](head T, tail ...T) NonEmpty[T] {
	items := make([]T, 1+len(tail))
	items[0] = head
	copy(items[1:], tail)
	return NonEmpty[T]{items: items}
}

// NonEmptyFromSlice 校验 items 非空并执行防御性拷贝以构造 NonEmpty[T]；空切片返回 ErrEmptySlice。
func NonEmptyFromSlice[T any](items []T) (NonEmpty[T], error) {
	if len(items) == 0 {
		return NonEmpty[T]{}, ErrEmptySlice
	}
	return NonEmpty[T]{items: slices.Clone(items)}, nil
}

// IsValid 报告当前 NonEmpty 是否满足至少含有一个元素的不变量。
func (n NonEmpty[T]) IsValid() bool {
	return len(n.items) > 0
}

// IsZero 报告当前 NonEmpty 是否处于无效零值状态（配合 encoding/json/v2 omitzero）。
func (n NonEmpty[T]) IsZero() bool {
	return len(n.items) == 0
}

// Len 返回包含的元素个数；无效零值返回 0。
func (n NonEmpty[T]) Len() int {
	return len(n.items)
}

// Head 返回首个元素；若当前为无效零值则失败关闭返回类型零值与 false。
func (n NonEmpty[T]) Head() (T, bool) {
	if len(n.items) == 0 {
		var zero T
		return zero, false
	}
	return n.items[0], true
}

// Tail 返回除首元素外的剩余元素防御性副本；若仅有一个元素或为无效零值则返回 nil。
func (n NonEmpty[T]) Tail() []T {
	if len(n.items) <= 1 {
		return nil
	}
	return slices.Clone(n.items[1:])
}

// At 按索引安全读取第 index 个元素；若越界或当前为无效零值则返回类型零值与 false。
func (n NonEmpty[T]) At(index int) (T, bool) {
	if index < 0 || index >= len(n.items) {
		var zero T
		return zero, false
	}
	return n.items[index], true
}

// Slice 返回全部元素的防御性副本，修改返回切片不会影响原 NonEmpty；无效零值返回 nil。
func (n NonEmpty[T]) Slice() []T {
	if len(n.items) == 0 {
		return nil
	}
	return slices.Clone(n.items)
}

// All 返回按序遍历全部元素的只读迭代器（零额外切片分配）；无效零值不产生任何元素。
// 注意：由于 All 返回自定义 iter.Seq[T]（非标准库 slices/maps 迭代器），在 //xops:borrowed 借用作用域或
// SecretBox.Use 明文作用域内捕获借用/机密变量时，请改用标注 //xops:syncclosure 的 ForEach、Slice() 或 At()。
func (n NonEmpty[T]) All() iter.Seq[T] {
	return func(yield func(T) bool) {
		for _, item := range n.items {
			if !yield(item) {
				return
			}
		}
	}
}

// ForEach 在同步作用域内零分配按序对每个元素调用 fn（遇错立即短路返回）。
// 本方法显式标注 //xops:syncclosure，支持在 //xops:borrowed 借用闭包与 SecretBox.Use 明文闭包内安全捕获外层句柄；
// 失败关闭：若当前 NonEmpty 为无效零值返回 ErrEmptySlice，若 fn 为 nil 返回 ErrNilCallback。
//
//xops:syncclosure
func (n NonEmpty[T]) ForEach(fn func(T) error) error {
	if len(n.items) == 0 {
		return ErrEmptySlice
	}
	if fn == nil {
		return ErrNilCallback
	}
	for _, item := range n.items {
		if err := fn(item); err != nil {
			return err
		}
	}
	return nil
}

// Append 在不修改原实例的前提下返回追加 elems 后的新 NonEmpty[T]；
// 若当前为无效零值则严格失败关闭，返回无效零值。
func (n NonEmpty[T]) Append(elems ...T) NonEmpty[T] {
	if len(n.items) == 0 {
		return NonEmpty[T]{}
	}
	out := make([]T, len(n.items)+len(elems))
	copy(out, n.items)
	copy(out[len(n.items):], elems)
	return NonEmpty[T]{items: out}
}

// Concat 执行半群连接运算，按顺序拼接 n 与 other 的元素并返回新 NonEmpty[T]。
// 为保证严格失败关闭与全域结合律，无效零值作为吸收元：任一操作数无效时结果恒为无效零值。
func (n NonEmpty[T]) Concat(other NonEmpty[T]) NonEmpty[T] {
	if len(n.items) == 0 || len(other.items) == 0 {
		return NonEmpty[T]{}
	}
	out := make([]T, len(n.items)+len(other.items))
	copy(out, n.items)
	copy(out[len(n.items):], other.items)
	return NonEmpty[T]{items: out}
}

// EqualNonEmpty 比较两个可比较元素类型的 NonEmpty 是否均有效且逐元素完全相等。
// 遵循失败关闭原则：无效零值与任意值（包括另一无效零值）均不相等。
func EqualNonEmpty[T comparable](a, b NonEmpty[T]) bool {
	if len(a.items) == 0 || len(b.items) == 0 {
		return false
	}
	return slices.Equal(a.items, b.items)
}

// MarshalJSONTo 实现 encoding/json/v2.MarshalerTo（值接收者）：
// 有效实例编码为 JSON 数组并继承外层编码选项；无效零值严格失败关闭并返回 ErrEmptySlice。
func (n NonEmpty[T]) MarshalJSONTo(enc *jsontext.Encoder) error {
	if len(n.items) == 0 {
		return ErrEmptySlice
	}
	return jsonv2.MarshalEncode(enc, n.items)
}

// UnmarshalJSONFrom 实现 encoding/json/v2.UnmarshalerFrom：
// 拒绝 JSON null 与空数组 [] 并重置为零值，仅当至少解码出一个元素时才写入目标。
func (n *NonEmpty[T]) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	if n == nil {
		return ErrNilReceiver
	}
	if dec.PeekKind() == 'n' {
		*n = NonEmpty[T]{}
		if _, err := dec.ReadToken(); err != nil {
			return err
		}
		return ErrEmptySlice
	}
	var items []T
	if err := jsonv2.UnmarshalDecode(dec, &items); err != nil {
		*n = NonEmpty[T]{}
		return err
	}
	if len(items) == 0 {
		*n = NonEmpty[T]{}
		return ErrEmptySlice
	}
	*n = NonEmpty[T]{items: items}
	return nil
}
