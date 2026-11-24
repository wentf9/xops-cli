// Package trace 提供 XOps v2 只读请求追踪标识（TraceID/OpID）与连接租约防重入上下文标记（LeaseScope）。
//
// 本包是全仓唯一允许调用 context.WithValue 与 ctx.Value 的特权白名单包，
// 所有上下文键均为未导出零大小结构体，所有导出值对象均采用私有字段与零值无效（fail-closed）设计。
package trace

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	randomIDBytes = 16
	maxTokenLen   = 128
)

// ErrInvalidTraceID 表示 TraceID 为零值、空串或包含非法字符/超长。
var ErrInvalidTraceID = errors.New("trace: TraceID 无效")

// ErrInvalidOpID 表示 OpID 为零值、空串或包含非法字符/超长。
var ErrInvalidOpID = errors.New("trace: OpID 无效")

// ErrInvalidLeaseScope 表示 LeaseScope 的域或租约标识无效。
var ErrInvalidLeaseScope = errors.New("trace: LeaseScope 无效")

// ErrNilContext 表示传入的 context.Context 为 nil（拒绝隐式回退到 Background）。
var ErrNilContext = errors.New("trace: context 不能为 nil")

// ErrReentrantLease 表示当前上下文已处于全局活跃连接租约作用域内，禁止任何同池或跨池嵌套重入申请租约。
var ErrReentrantLease = errors.New("trace: 当前上下文已处于活跃连接租约作用域，禁止重入申请租约")

type traceCtxKey struct{}

type traceRecord struct {
	traceID TraceID
	opID    OpID
}

// TraceID 是不可变的请求链路追踪标识值对象。
// 零值代表无效未设置状态（IsValid() == false），且序列化时严格失败关闭。
//
//xops:opaque
//xops:failclosed
type TraceID struct {
	value string
}

// OpID 是不可变的单次操作执行标识值对象。
// 零值代表无效未设置状态（IsValid() == false），且序列化时严格失败关闭。
//
//xops:opaque
//xops:failclosed
type OpID struct {
	value string
}

// NewTraceID 使用密码学安全随机数生成 128-bit（32 位十六进制字符）的 TraceID。
func NewTraceID() (TraceID, error) {
	raw, err := newRandomHexID()
	if err != nil {
		return TraceID{}, fmt.Errorf("trace: 生成 TraceID 失败: %w", err)
	}
	return TraceID{value: raw}, nil
}

// ParseTraceID 校验并构造 TraceID；仅允许长度 1..128 的可打印非空白 ASCII（0x21..0x7E）。
func ParseTraceID(raw string) (TraceID, error) {
	if !isValidToken(raw) {
		return TraceID{}, ErrInvalidTraceID
	}
	return TraceID{value: raw}, nil
}

// IsValid 返回 TraceID 是否为有效的非零标识。
func (id TraceID) IsValid() bool {
	return id.value != ""
}

// String 返回 TraceID 的字符串表示；零值返回空串。
func (id TraceID) String() string {
	return id.value
}

// Equal 比较两个 TraceID 是否完全相等。
func (id TraceID) Equal(other TraceID) bool {
	return id.value == other.value
}

// AppendText 实现 encoding.TextAppender，将有效的 TraceID 追加到 b；对零值失败关闭。
func (id TraceID) AppendText(b []byte) ([]byte, error) {
	if !id.IsValid() {
		return nil, ErrInvalidTraceID
	}
	return append(b, id.value...), nil
}

// MarshalText 实现 encoding.TextMarshaler，对零值失败关闭。
func (id TraceID) MarshalText() ([]byte, error) {
	if !id.IsValid() {
		return nil, ErrInvalidTraceID
	}
	return []byte(id.value), nil
}

// NewOpID 使用密码学安全随机数生成 128-bit（32 位十六进制字符）的 OpID。
func NewOpID() (OpID, error) {
	raw, err := newRandomHexID()
	if err != nil {
		return OpID{}, fmt.Errorf("trace: 生成 OpID 失败: %w", err)
	}
	return OpID{value: raw}, nil
}

// ParseOpID 校验并构造 OpID；仅允许长度 1..128 的可打印非空白 ASCII（0x21..0x7E）。
func ParseOpID(raw string) (OpID, error) {
	if !isValidToken(raw) {
		return OpID{}, ErrInvalidOpID
	}
	return OpID{value: raw}, nil
}

// IsValid 返回 OpID 是否为有效的非零标识。
func (id OpID) IsValid() bool {
	return id.value != ""
}

// String 返回 OpID 的字符串表示；零值返回空串。
func (id OpID) String() string {
	return id.value
}

// Equal 比较两个 OpID 是否完全相等。
func (id OpID) Equal(other OpID) bool {
	return id.value == other.value
}

// AppendText 实现 encoding.TextAppender，将有效的 OpID 追加到 b；对零值失败关闭。
func (id OpID) AppendText(b []byte) ([]byte, error) {
	if !id.IsValid() {
		return nil, ErrInvalidOpID
	}
	return append(b, id.value...), nil
}

// MarshalText 实现 encoding.TextMarshaler，对零值失败关闭。
func (id OpID) MarshalText() ([]byte, error) {
	if !id.IsValid() {
		return nil, ErrInvalidOpID
	}
	return []byte(id.value), nil
}

// WithTrace 将只读的 TraceID 与 OpID 写入派生上下文。
// 若传入的 traceID 为零值但父上下文已携带有效 TraceID，则自动继承父级 TraceID；
// 若 ctx 为 nil 或继承后 TraceID 与 OpID 均无效，则失败关闭返回错误。
func WithTrace(ctx context.Context, traceID TraceID, opID OpID) (context.Context, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	effectiveTraceID := traceID
	if !effectiveTraceID.IsValid() {
		if parentTID, ok := TraceIDFromContext(ctx); ok {
			effectiveTraceID = parentTID
		}
	}
	if !effectiveTraceID.IsValid() && !opID.IsValid() {
		return nil, ErrInvalidTraceID
	}
	return context.WithValue(ctx, traceCtxKey{}, traceRecord{
		traceID: effectiveTraceID,
		opID:    opID,
	}), nil
}

// TraceFromContext 从上下文只读提取 TraceID 与 OpID。
// 若 ctx 为 nil 或未携带任何有效追踪标识，则返回零值与 false。
func TraceFromContext(ctx context.Context) (TraceID, OpID, bool) {
	if ctx == nil {
		return TraceID{}, OpID{}, false
	}
	rec, ok := ctx.Value(traceCtxKey{}).(traceRecord)
	if !ok || (!rec.traceID.IsValid() && !rec.opID.IsValid()) {
		return TraceID{}, OpID{}, false
	}
	return rec.traceID, rec.opID, true
}

// TraceIDFromContext 从上下文只读提取有效的 TraceID。
func TraceIDFromContext(ctx context.Context) (TraceID, bool) {
	tid, _, ok := TraceFromContext(ctx)
	if !ok || !tid.IsValid() {
		return TraceID{}, false
	}
	return tid, true
}

// OpIDFromContext 从上下文只读提取有效的 OpID。
func OpIDFromContext(ctx context.Context) (OpID, bool) {
	_, oid, ok := TraceFromContext(ctx)
	if !ok || !oid.IsValid() {
		return OpID{}, false
	}
	return oid, true
}

func newRandomHexID() (string, error) {
	var buf [randomIDBytes]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}

func isValidToken(raw string) bool {
	if len(raw) == 0 || len(raw) > maxTokenLen {
		return false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x21 || raw[i] > 0x7E {
			return false
		}
	}
	return true
}
