// Package events 提供 XOps v2 作用域化双层事件流与封闭事件代数和类型（ADR-010 / RFC §3.5–§4.1）。
//
// 本包遵循严格的六边形物理隔离边界（由 Go 模块与 xopsvet/archbound 双重强制）：
//   - 生产代码仅依赖 core/domain/** 与纯内存非 I/O 标准库，物理禁止导入 core/ports、core/osfs、
//     core/conc、core/internal/** 以及 os/net/syscall/unsafe 等宿主原语；
//   - 全包 0 裸 go 语句、0 裸 time.Duration 序列化字段、0 secret.SecretBox 字段与明文泄密路径；
//   - 核心组件分为三层正交契约：
//     1. 封闭事件和类型 Event（12 个不可变指针变体）与严格失败关闭的 Go 1.27 encoding/json/v2 编解码（Deterministic(true)）；
//     2. 单次操作隔离流 OperationStream（确定性 EOF、按事件类差异化 BlockWithContext / CoalesceLatest 背压与纯函数 Fold）；
//     3. 同步失败关闭审计分发抽象 AuditDispatcher（与 core/ports.AuditSink 零耦合，支持 Halted 不可逆熔断）
//     及有界非阻塞诊断总线 SystemBus（DropAndCount 丢弃计数与确定性关闭）。
package events

import (
	"context"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"iter"
	"maps"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/security"
)

const (
	maxCodeBytes           = 128
	maxLabelKeyBytes       = 64
	maxLabelValBytes       = 512
	maxMapEntries          = 32
	maxTextBytes           = 4096
	maxOutputChunkBytes    = 1 << 20
	defaultMaxCoalesceKeys = 256
)

// 本包导出的不可变哨兵错误集合，均由失败关闭路径返回以便上层通过 errors.Is 精确识别。
var (
	ErrNilContext                    = errors.New("events: context 不能为 nil")
	ErrNilReceiver                   = errors.New("events: 反序列化目标接收者不能为 nil")
	ErrNilWriter                     = errors.New("events: 编码输出目标不能为 nil")
	ErrInvalidEvent                  = errors.New("events: 无效的事件实例或变体字段")
	ErrInvalidEventMeta              = errors.New("events: 无效的 EventMeta 元数据")
	ErrInvalidEventKind              = errors.New("events: 无效的 EventKind")
	ErrInvalidEventClass             = errors.New("events: 无效的 EventClass")
	ErrInvalidBackpressure           = errors.New("events: 无效的 BackpressurePolicy")
	ErrInvalidSeverity               = errors.New("events: 无效的 Severity")
	ErrInvalidOutputStream           = errors.New("events: 无效的 OutputStreamKind")
	ErrInvalidAuditStage             = errors.New("events: 无效的 AuditStage")
	ErrInvalidPoolAction             = errors.New("events: 无效的 PoolEventAction")
	ErrInvalidDiagnosticScope        = errors.New("events: 无效的 DiagnosticScope")
	ErrInvalidFSMMachine             = errors.New("events: 无效的 FSMMachineKind")
	ErrUnsupportedEventClass         = errors.New("events: 当前通道不支持该事件类别")
	ErrOperationMismatch             = errors.New("events: 事件 TraceID 或 OperationID 与操作流绑定不一致")
	ErrInvalidStreamConfig           = errors.New("events: 无效的 OperationStream 配置")
	ErrStreamNotInitialized          = errors.New("events: OperationStream 未初始化")
	ErrStreamClosed                  = errors.New("events: OperationStream 已关闭")
	ErrInvalidFoldFunc               = errors.New("events: Fold 归约函数不能为 nil")
	ErrInvalidAuditConfig            = errors.New("events: 无效的 AuditDispatcher 配置")
	ErrNilAuditWriter                = errors.New("events: AuditWriter 不能为 nil")
	ErrAuditDispatcherNotInitialized = errors.New("events: AuditDispatcher 未初始化")
	ErrAuditHalted                   = errors.New("events: AuditDispatcher 已进入 Halted 熔断态")
	ErrAuditDispatchFailed           = errors.New("events: 同步审计分发失败")
	ErrInvalidBusConfig              = errors.New("events: 无效的 SystemBus 配置")
	ErrBusNotInitialized             = errors.New("events: SystemBus 未初始化")
	ErrBusClosed                     = errors.New("events: SystemBus 已关闭")
	ErrBusSubscriberLimit            = errors.New("events: SystemBus 订阅者数量已达上限")
	ErrSubscriptionNotInitialized    = errors.New("events: SystemSubscription 未初始化")
)

func pickIf[T any](ok bool, yes, no T) T {
	if ok {
		return yes
	}
	return no
}

func zeroVal[T any]() (z T) { return z }

// isValidASCIIToken 校验机器可读标识符（代码、指标名、标签键、进程实例 ID）：仅接受 1..maxLen 的可打印非空白 ASCII。
func isValidASCIIToken(raw string, maxLen int) bool {
	if len(raw) == 0 || len(raw) > maxLen {
		return false
	}
	for i := range len(raw) {
		if raw[i] < 0x21 || raw[i] > 0x7E {
			return false
		}
	}
	return true
}

// sanitizeText 转义控制字符、Bidi 覆盖与非法 UTF-8，并沿 UTF-8 符文边界截断至 maxBytes。
func sanitizeText(raw string, maxBytes int) string {
	return truncateUTF8(security.SanitizePromptText(raw), maxBytes)
}

func truncateUTF8(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// canonicalizeKVMap 校验并深拷贝只读诊断/指标键值表，防止调用方持有引用后外部篡改。
func canonicalizeKVMap(raw map[string]string, baseErr error) (map[string]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > maxMapEntries {
		return nil, fmt.Errorf("%w: 键值数量 %d 超出上限 %d", baseErr, len(raw), maxMapEntries)
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		if !isValidASCIIToken(k, maxLabelKeyBytes) {
			return nil, fmt.Errorf("%w: 非法标签键 %q", baseErr, k)
		}
		out[k] = sanitizeText(v, maxLabelValBytes)
	}
	return out, nil
}

func cloneStringMap(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	return maps.Clone(m)
}

func equalOptComparable[T interface{ Equal(T) bool }](a, b algebraic.Option[T]) bool {
	va, oka := a.Get()
	vb, okb := b.Get()
	return oka == okb && (!oka || va.Equal(vb))
}

func equalOptVal[T comparable](a, b algebraic.Option[T]) bool {
	va, oka := a.Get()
	vb, okb := b.Get()
	return oka == okb && (!oka || va == vb)
}

func rejectJSONNull(dec *jsontext.Decoder, baseErr error) (bool, error) {
	if dec.PeekKind() != 'n' {
		return false, nil
	}
	if _, err := dec.ReadToken(); err != nil {
		return true, err
	}
	return true, fmt.Errorf("%w: JSON null 不是有效值", baseErr)
}

func unmarshalJSONWithNullReject[T, W any](dst *T, dec *jsontext.Decoder, baseErr error, build func(W) (T, error)) error {
	if dst == nil || dec == nil {
		return ErrNilReceiver
	}
	*dst = zeroVal[T]()
	if isNull, err := rejectJSONNull(dec, baseErr); isNull {
		return err
	}
	var wire W
	if err := jsonv2.UnmarshalDecode(dec, &wire, jsonv2.RejectUnknownMembers(true)); err != nil {
		return err
	}
	parsed, err := build(wire)
	if err == nil {
		*dst = parsed
	}
	return err
}

// iterNextStream 将顺序拉取函数包装为延迟求值的 iter.Seq2 迭代器（不标注 syncclosure）。
func iterNextStream(ctx context.Context, next func(context.Context) (Event, bool, error)) iter.Seq2[Event, error] {
	return func(yield func(Event, error) bool) {
		for {
			ev, ok, err := next(ctx)
			if err != nil {
				yield(nil, err)
				return
			}
			if !ok || !yield(ev, nil) {
				return
			}
		}
	}
}
