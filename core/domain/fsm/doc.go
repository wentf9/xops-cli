// Package fsm 提供 XOps v2 纯函数领域核的五大高风险多步协议纯 Mealy 状态机（RFC §3.6）：
//   - VaultSagaFSM：凭据写入、基于 ports.SecretVault.PutAndVerify + SecretBox.Equal 的回读校验、
//     配置 CAS 提交、5 位置零引用核验与旧凭据 GC，对 Applied && !Durable 进入零重试零删凭据停机态 UncertainDurability；
//   - ApprovalFSM：词法预检、远端规范化、作用域升级判定（含 Protected-A -> Protected-B）、挑战签发与
//     显式时刻常量时间令牌核验，对 Round-2 探测失败、挑战后升级或已绑定信封的任意路径漂移立即作废待决/已签发令牌；
//   - TransferFSM：面向上传（pathalg.RemotePath）与下载（pathalg.LocalRootedDest）双方向、最高 10 GiB 分片流、
//     可选预期摘要、双版本（V1/V2）双代 Journal、原子交接与崩溃恢复；
//   - EnsureFSM：Playbook ensure 幂等收敛状态机，在任意阶段遇 execution.OutcomeUnknown 严禁自动重试；
//   - PendingEnrollFSM：首连「先验证后入库」作用域租约状态机，未验节点绝不入库且全程钉住暂存凭据防 GC。
//
// 本包恪守 100% 纯数学与零副作用铁律（零 time.Now、零 crypto/rand、零 I/O、零 sync/sync/atomic、零反射），
// 全部状态转换遵循确定性 Mealy 签名 Transition(state, input) (nextState, []Effect, []Event, error)，
// 对零值、nil 或非法 (state, input) 严格失败关闭且绝不破坏原状态。
package fsm

import (
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/security"
)

// 五大状态机的单次边界上限常量。
const (
	MaxTransferBytes      uint64 = 10 << 30 // TransferFSM 单次流式传输总字节数上限（精确 10 GiB）
	MaxTransferChunkBytes uint64 = 64 << 20 // 单次流式分片最大字节数（64 MiB）
	MaxJournalRecords            = 1 << 20  // 崩溃恢复单次扫描最大 Journal 记录数
	MaxEnsureRetries      uint8  = 10       // EnsureFSM 对 OutcomeNotStarted 的最大重试预算
	MaxPendingSecretRefs         = 64       // 单次首连暂存租约最多钉住的凭据引用数
	maxReasonBytes               = 512
	maxLabelLen                  = 128
)

// 本包导出的规范哨兵错误，所有零值状态、非法输入、越界转换与 Journal 损坏均严格失败关闭。
var (
	ErrInvalidState            = domi18n.Sentinel(domi18n.KeyFSMInvalidState)
	ErrInvalidInput            = domi18n.Sentinel(domi18n.KeyFSMInvalidInput)
	ErrIllegalTransition       = domi18n.Sentinel(domi18n.KeyFSMIllegalTransition)
	ErrInvalidContext          = domi18n.Sentinel(domi18n.KeyFSMInvalidContext)
	ErrInvalidDurability       = domi18n.Sentinel(domi18n.KeyFSMInvalidDurability)
	ErrInvalidOutcome          = domi18n.Sentinel(domi18n.KeyFSMInvalidOutcome)
	ErrInvalidJournal          = domi18n.Sentinel(domi18n.KeyFSMInvalidJournal)
	ErrCorruptJournal          = domi18n.Sentinel(domi18n.KeyFSMCorruptJournal)
	ErrTransferSizeExceeded    = domi18n.Sentinel(domi18n.KeyFSMTransferSizeExceeded)
	ErrInvalidChunkOffset      = domi18n.Sentinel(domi18n.KeyFSMInvalidChunkOffset)
	ErrInvalidApprovalEnvelope = domi18n.Sentinel(domi18n.KeyFSMInvalidApprovalEnvelope)
	ErrInvalidEnsureStep       = domi18n.Sentinel(domi18n.KeyFSMInvalidEnsureStep)
	ErrInvalidEnrollLease      = domi18n.Sentinel(domi18n.KeyFSMInvalidEnrollLease)
	ErrNilWriter               = domi18n.Sentinel(domi18n.KeyFSMNilWriter)
	ErrNilReceiver             = domi18n.Sentinel(domi18n.KeyFSMNilReceiver)
)

// DurabilityStatus 与 SideEffectOutcome 为持久化提交与单步副作用的失败关闭结果枚举。
type (
	//xops:opaque
	//xops:failclosed
	DurabilityStatus uint8
	//xops:opaque
	//xops:failclosed
	SideEffectOutcome uint8
)

const (
	DurabilityUnknown           DurabilityStatus = iota // 未初始化零值（失败关闭）
	DurabilityNotApplied                                // 确认未生效，可安全补偿
	DurabilityCommitted                                 // Applied && Durable，已持久生效
	DurabilityAppliedNotDurable                         // Applied && !Durable，零重试零删凭据停机
	DurabilityOutcomeUnknown                            // 结果完全未知（禁自动重试）
)
const (
	SideEffectInvalid          SideEffectOutcome = iota // 无效零值（失败关闭）
	SideEffectSucceeded                                 // 副作用确认成功
	SideEffectFailedNotApplied                          // 副作用确认未生效而失败
	SideEffectOutcomeUnknown                            // 副作用结果未知（严禁自动重试）
)

// ClassifyDurability 根据 (applied, durable, outcomeKnown) 映射为 DurabilityStatus；矛盾组合 (!applied && durable) 失败关闭。
func ClassifyDurability(applied, durable, outcomeKnown bool) DurabilityStatus {
	if !outcomeKnown {
		return DurabilityOutcomeUnknown
	}
	if applied {
		return pickIf(durable, DurabilityCommitted, DurabilityAppliedNotDurable)
	}
	return pickIf(!durable, DurabilityNotApplied, DurabilityUnknown)
}
func (d DurabilityStatus) IsZero() bool { return d == DurabilityUnknown }
func (d DurabilityStatus) Applied() bool {
	return d == DurabilityCommitted || d == DurabilityAppliedNotDurable
}
func (d DurabilityStatus) Durable() bool { return d == DurabilityCommitted }
func (o SideEffectOutcome) IsZero() bool { return o == SideEffectInvalid }

type validKind interface {
	~uint8
	IsValid() bool
	encoding.TextAppender
	encoding.TextMarshaler
}

// Event 表示状态机发出的不可变脱敏领域事件；零值恒无效并失败关闭，支持 json/v2 严格编解码。
//
//xops:opaque
//xops:failclosed
type Event[K validKind] struct {
	kind   K
	detail string
	valid  bool
}

func (e Event[K]) IsValid() bool  { return e.valid && e.kind.IsValid() }
func (e Event[K]) IsZero() bool   { return !e.IsValid() }
func (e Event[K]) Kind() K        { return e.kind }
func (e Event[K]) Detail() string { return e.detail }
func (e Event[K]) Equal(o Event[K]) bool {
	return e.IsValid() && o.IsValid() && e.kind == o.kind && e.detail == o.detail
}
func newEvent[K validKind](k K, d string) Event[K] { return Event[K]{k, sanitizeReason(d), true} }
func zeroVal[T any]() (z T)                        { return z }
func pickIf[T any](ok bool, yes, no T) T {
	if ok {
		return yes
	}
	return no
}
func hasForbiddenStrictText(s string) bool {
	return !utf8.ValidString(s) || strings.ContainsFunc(s, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029'
	})
}
func sanitizeReason(raw string) string {
	return truncateUTF8(security.SanitizePromptText(raw), maxReasonBytes)
}

// truncateUTF8 在不超过 maxBytes 字节的前提下沿合法 UTF-8 字符边界截断字符串，避免切碎多字节符文。
func truncateUTF8(s string, maxBytes int) string {
	if maxBytes <= 0 || len(s) <= maxBytes {
		return pickIf(maxBytes <= 0, "", s)
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
func isValidRFC3339Time(t time.Time) bool {
	return !t.IsZero() && t.UTC().Year() >= 1 && t.UTC().Year() <= 9999
}
func isValidTimeWindow(startUTC time.Time, ttl algebraic.Duration) bool {
	end := startUTC.Add(ttl.Std())
	return isValidRFC3339Time(startUTC) && ttl.IsPositive() && end.After(startUTC) && isValidRFC3339Time(end)
}
func equalOptionFunc[T any](a, b algebraic.Option[T], eq func(T, T) bool) bool {
	va, oka := a.Get()
	vb, okb := b.Get()
	return oka == okb && (!oka || eq(va, vb))
}

type canonicalEncoder struct {
	w   io.Writer
	err error
}

func digestCanonical(writeFn func(io.Writer) error) (security.Digest, error) {
	h := sha256.New()
	if err := writeFn(h); err != nil {
		return zeroVal[security.Digest](), err
	}
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return security.DigestFromSHA256(sum), nil
}
func (e *canonicalEncoder) writeRaw(p []byte) {
	if e.err == nil && len(p) > 0 {
		_, e.err = e.w.Write(p)
	}
}
func (e *canonicalEncoder) writeUint8(v uint8) { e.writeRaw([]byte{v}) }
func (e *canonicalEncoder) writeUint64(v uint64) {
	var buf [8]byte
	e.writeRaw(binary.BigEndian.AppendUint64(buf[:0], v))
}
func (e *canonicalEncoder) writeBytes(p []byte)  { e.writeUint64(uint64(len(p))); e.writeRaw(p) }
func (e *canonicalEncoder) writeString(s string) { e.writeBytes([]byte(s)) }
