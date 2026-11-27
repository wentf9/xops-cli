// Package algebraic 提供 XOps v2 纯函数领域核使用的基础代数原语与 Go 1.27 序列化安全时长类型。
//
// 本包恪守 100% 纯数学与零副作用铁律（零 sync/atomic、零 context、零 I/O、零反射），提供四类核心原语：
//   - Option[T]：仅用于结构体可选值字段，精确区分“未设置（None）”与“显式设置为零值（Some(zero)）”；
//   - NonEmpty[T]：类型级非空切片证明（len >= 1），构造与导出均执行防御性拷贝以保证不可变性；
//   - FirstWins[T]：左优先幺半群（(FirstWins[T], Combine, Unset)），供四层 OpenSSH 选项策略统一求解；
//   - Duration：封装 time.Duration 并以值接收者实现 TextAppender/TextMarshaler/TextUnmarshaler，
//     彻底解决 Go 1.27 encoding/json/v2 对裸 time.Duration 触发 SemanticError 的问题并兼容 YAML。
//
// 依据 ADR-014，本包故意不提供泛化 Result[T]，失败路径统一回归地道 Go 的 (T, error) 契约。
package algebraic

import domi18n "github.com/wentf9/xops-cli/core/domain/i18n"

// ErrEmptySlice 表示构造或反序列化 NonEmpty[T] 时收到空切片、JSON 空数组或 JSON null。
var ErrEmptySlice = domi18n.Sentinel(domi18n.KeyAlgebraicEmptySlice)

// ErrInvalidDuration 表示解析 Duration 时遇到空串、非法时长语法或非预期输入。
var ErrInvalidDuration = domi18n.Sentinel(domi18n.KeyAlgebraicInvalidDuration)

// ErrDurationOverflow 表示两个 Duration 相加超出 int64 纳秒可表示范围。
var ErrDurationOverflow = domi18n.Sentinel(domi18n.KeyAlgebraicDurationOverflow)

// ErrNilReceiver 表示在 nil 指针接收者上调用反序列化方法。
var ErrNilReceiver = domi18n.Sentinel(domi18n.KeyAlgebraicNilReceiver)

// ErrNilCallback 表示传入同步迭代回调方法（如 NonEmpty.ForEach）的函数为 nil。
var ErrNilCallback = domi18n.Sentinel(domi18n.KeyAlgebraicNilCallback)
