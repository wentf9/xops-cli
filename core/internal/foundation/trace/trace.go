// Package trace 提供 XOps v2 只读请求追踪标识（TraceID/OpID）与连接租约防重入上下文标记（LeaseScope）。
//
// 本包是全仓唯一允许调用 context.WithValue 与 ctx.Value 的特权白名单包，同时严守 100% 纯内存非 I/O 约束
// （零 crypto/rand 隐式系统调用，通过显式字节或 io.Reader 注入熵源以保障单种子 DST 确定性），
// 所有上下文键均为未导出零大小结构体。TraceID 与 OpID 直接类型别名复用 core/domain/security.{TraceID, OperationID}，
// 消除跨包转换摩擦并确保全仓零值失败关闭与序列化契约完全统一。
package trace

import (
	"context"
	"errors"
	"io"

	"github.com/wentf9/xops-cli/core/domain/security"
)

const (
	randomIDBytes = 16
	maxTokenLen   = 128
)

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

// TraceID 是不可变的请求链路追踪标识值对象，直接类型别名复用 security.TraceID（零拷贝互通，零值失败关闭）。
type TraceID = security.TraceID

// OpID 是不可变的单次操作执行标识值对象，直接类型别名复用 security.OperationID（零拷贝互通，零值失败关闭）。
type OpID = security.OperationID

// TraceIDFromBytes 以纯函数方式将 16 字节原始熵编码为 32 位小写十六进制 TraceID。
func TraceIDFromBytes(raw [16]byte) TraceID { return security.TraceIDFromBytes(raw) }

// NewTraceIDFrom 从调用方显式注入的熵源 entropy 读取 16 字节并生成 32 位十六进制 TraceID。
// 生产路径由组合根注入基于 crypto/rand.Reader 的 ports.Entropy，DST 仿真路径注入确定性 SeededRand；
// 若 entropy 为 nil 或读取不足 16 字节，则严格失败关闭并返回包装 security.ErrInvalidTraceID 的错误。
func NewTraceIDFrom(entropy io.Reader) (TraceID, error) { return security.NewTraceIDFrom(entropy) }

// ParseTraceID 校验并构造 TraceID；仅允许长度 1..128 的可打印非空白 ASCII（0x21..0x7E）。
func ParseTraceID(raw string) (TraceID, error) { return security.ParseTraceID(raw) }

// OpIDFromBytes 以纯函数方式将 16 字节原始熵编码为 32 位小写十六进制 OpID。
func OpIDFromBytes(raw [16]byte) OpID { return security.OperationIDFromBytes(raw) }

// NewOpIDFrom 从调用方显式注入的熵源 entropy 读取 16 字节并生成 32 位十六进制 OpID。
// 若 entropy 为 nil 或读取不足 16 字节，则严格失败关闭并返回包装 security.ErrInvalidOperationID 的错误。
func NewOpIDFrom(entropy io.Reader) (OpID, error) { return security.NewOperationIDFrom(entropy) }

// ParseOpID 校验并构造 OpID；仅允许长度 1..128 的可打印非空白 ASCII（0x21..0x7E）。
func ParseOpID(raw string) (OpID, error) { return security.ParseOperationID(raw) }

// WithTrace 将只读的 TraceID 与 OpID 写入派生上下文。
// 若传入的 traceID 为零值但父上下文已携带有效 TraceID，则自动继承父级 TraceID；
// 若 ctx 为 nil（ErrNilContext）或继承后 TraceID 与 OpID 均无效（security.ErrInvalidTraceID），则失败关闭返回错误。
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
		return nil, security.ErrInvalidTraceID
	}
	return context.WithValue(ctx, traceCtxKey{}, traceRecord{
		traceID: effectiveTraceID,
		opID:    opID,
	}), nil
}

// TraceFromContext 从上下文只读提取 TraceID 与 OpID。
// 若 ctx 为 nil 或未携带任何有效追踪标识，则返回零值与 false。
func TraceFromContext(ctx context.Context) (tid TraceID, oid OpID, ok bool) {
	if ctx == nil {
		return tid, oid, false
	}
	rec, found := ctx.Value(traceCtxKey{}).(traceRecord)
	if !found || (!rec.traceID.IsValid() && !rec.opID.IsValid()) {
		return tid, oid, false
	}
	return rec.traceID, rec.opID, true
}

// TraceIDFromContext 从上下文只读提取有效的 TraceID。
func TraceIDFromContext(ctx context.Context) (tid TraceID, ok bool) {
	got, _, found := TraceFromContext(ctx)
	if !found || !got.IsValid() {
		return tid, false
	}
	return got, true
}

// OpIDFromContext 从上下文只读提取有效的 OpID。
func OpIDFromContext(ctx context.Context) (oid OpID, ok bool) {
	_, got, found := TraceFromContext(ctx)
	if !found || !got.IsValid() {
		return oid, false
	}
	return got, true
}

func isValidToken(raw string) bool {
	if len(raw) == 0 || len(raw) > maxTokenLen {
		return false
	}
	for i := range len(raw) {
		if raw[i] < 0x21 || raw[i] > 0x7E {
			return false
		}
	}
	return true
}
