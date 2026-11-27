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
	"iter"
	"maps"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
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
	ErrNilContext                    = domi18n.Sentinel(domi18n.KeyEventsNilContext)
	ErrNilReceiver                   = domi18n.Sentinel(domi18n.KeyEventsNilReceiver)
	ErrNilWriter                     = domi18n.Sentinel(domi18n.KeyEventsNilWriter)
	ErrInvalidEvent                  = domi18n.Sentinel(domi18n.KeyEventsInvalidEvent)
	ErrInvalidEventMeta              = domi18n.Sentinel(domi18n.KeyEventsInvalidEventMeta)
	ErrInvalidEventKind              = domi18n.Sentinel(domi18n.KeyEventsInvalidEventKind)
	ErrInvalidEventClass             = domi18n.Sentinel(domi18n.KeyEventsInvalidEventClass)
	ErrInvalidBackpressure           = domi18n.Sentinel(domi18n.KeyEventsInvalidBackpressure)
	ErrInvalidSeverity               = domi18n.Sentinel(domi18n.KeyEventsInvalidSeverity)
	ErrInvalidOutputStream           = domi18n.Sentinel(domi18n.KeyEventsInvalidOutputStream)
	ErrInvalidAuditStage             = domi18n.Sentinel(domi18n.KeyEventsInvalidAuditStage)
	ErrInvalidPoolAction             = domi18n.Sentinel(domi18n.KeyEventsInvalidPoolAction)
	ErrInvalidDiagnosticScope        = domi18n.Sentinel(domi18n.KeyEventsInvalidDiagScope)
	ErrInvalidFSMMachine             = domi18n.Sentinel(domi18n.KeyEventsInvalidFSMMachine)
	ErrUnsupportedEventClass         = domi18n.Sentinel(domi18n.KeyEventsUnsupportedClass)
	ErrOperationMismatch             = domi18n.Sentinel(domi18n.KeyEventsOperationMismatch)
	ErrInvalidStreamConfig           = domi18n.Sentinel(domi18n.KeyEventsInvalidStreamConfig)
	ErrStreamNotInitialized          = domi18n.Sentinel(domi18n.KeyEventsStreamNotInit)
	ErrStreamClosed                  = domi18n.Sentinel(domi18n.KeyEventsStreamClosed)
	ErrInvalidFoldFunc               = domi18n.Sentinel(domi18n.KeyEventsInvalidFoldFunc)
	ErrInvalidAuditConfig            = domi18n.Sentinel(domi18n.KeyEventsInvalidAuditConfig)
	ErrNilAuditWriter                = domi18n.Sentinel(domi18n.KeyEventsNilAuditWriter)
	ErrAuditDispatcherNotInitialized = domi18n.Sentinel(domi18n.KeyEventsAuditDispNotInit)
	ErrAuditHalted                   = domi18n.Sentinel(domi18n.KeyEventsAuditHalted)
	ErrAuditDispatchFailed           = domi18n.Sentinel(domi18n.KeyEventsAuditDispatchFailed)
	ErrInvalidBusConfig              = domi18n.Sentinel(domi18n.KeyEventsInvalidBusConfig)
	ErrBusNotInitialized             = domi18n.Sentinel(domi18n.KeyEventsBusNotInit)
	ErrBusClosed                     = domi18n.Sentinel(domi18n.KeyEventsBusClosed)
	ErrBusSubscriberLimit            = domi18n.Sentinel(domi18n.KeyEventsBusSubscriberLimit)
	ErrSubscriptionNotInitialized    = domi18n.Sentinel(domi18n.KeyEventsSubNotInit)
)

func fieldErr(sentinel error, field string) error {
	return domi18n.EF(sentinel, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", field))
}
func missingFieldErr(sentinel error, field string) error {
	return domi18n.EF(sentinel, domi18n.KeyCommonJSONMissingField, domi18n.Str("field", field))
}

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
		return nil, domi18n.EF(baseErr, domi18n.KeyCommonCountLimit, domi18n.Str("kind", "labels"), domi18n.Int("count", len(raw)), domi18n.Int("limit", maxMapEntries))
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		if !isValidASCIIToken(k, maxLabelKeyBytes) {
			return nil, domi18n.EF(baseErr, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "label_key"), domi18n.BoundStr("value", k))
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
	return true, domi18n.EF(baseErr, domi18n.KeyCommonJSONNullForbidden)
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
