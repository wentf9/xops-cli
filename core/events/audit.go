package events

import (
	"context"
	"sync"
	"sync/atomic"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

// AuditWriter 定义 core/events 侧同步失败关闭审计写入抽象（零缓冲、零后台协程，物理隔离 core/ports）。
type AuditWriter interface {
	WriteAudit(ctx context.Context, ev *AuditRecordEvent) error
}

// AuditWriterFunc 允许通过普通函数适配 AuditWriter 接口，便于上层零样板桥接 core/ports.AuditSink。
type AuditWriterFunc func(ctx context.Context, ev *AuditRecordEvent) error

func (f AuditWriterFunc) WriteAudit(ctx context.Context, ev *AuditRecordEvent) error {
	if f == nil {
		return ErrNilAuditWriter
	}
	return f(ctx, ev)
}

// OnAuditHaltFunc 为 AuditDispatcher 首次进入不可逆 Halted 熔断态时在锁外触发至多一次的通知回调（ADR-008）。
// 并发调用 Halt 的调用方均线性化阻塞至 OnHalt 完成，回调内可安全读取 IsHalted/Stats，但不得重入调用 Halt。
type OnAuditHaltFunc func(reason string, cause error)

// AuditDispatcherConfig 定义同步审计分发器 AuditDispatcher 的初始化参数。
type AuditDispatcherConfig struct {
	Writer           AuditWriter     // 必填底层同步持久化写入器
	HaltOnWriteError bool            // true 时任意同步写失败立即触发不可逆 Halted 熔断
	OnHalt           OnAuditHaltFunc // 可选熔断回调，首次熔断时于锁外同步触发一次
	DiagnosticBus    *SystemBus      // 可选非阻塞诊断总线，仅在写失败时做脱敏旁路镜像
}

// AuditDispatcherStats 提供 AuditDispatcher 当前的不可变运行统计快照。
type AuditDispatcherStats struct {
	Dispatched, Failed uint64
	Halted             bool
}

// AuditDispatcher 是面向安全审计事件流（*AuditRecordEvent）的可选同步 Fail-Closed 分发器（ADR-008 / ADR-010）：
// 零缓冲、零丢弃、零后台协程，绝不持锁调用外部 ctx.Err()/AuditWriter/OnHalt，熔断状态不可逆。
//
// 单一熔断所有权边界（ADR-008）：在 core/engine 生产装配中，core/internal/gate.Gate 是唯一权威的审计落盘与
// Halted 熔断状态机所有者（直接写入 ports.AuditSink 并经 OnHaltFunc 驱动 pool.GateHalted）；
// 本类型仅作事件投影旁路或独立测试组件使用，严禁与 gate.Gate 并行装配为第二套独立熔断状态机。
//
//xops:opaque
//xops:failclosed
type AuditDispatcher struct {
	writer            AuditWriter
	haltOnWriteError  bool
	onHalt            OnAuditHaltFunc
	diagBus           *SystemBus
	mu                sync.Mutex
	initialized       bool
	halted            bool
	haltReason        string
	haltCause         error
	haltOnce          sync.Once
	dispatched, fails atomic.Uint64
}

// NewAuditDispatcher 校验写入器非空（含拒绝 typed-nil AuditWriterFunc(nil)）与可选诊断总线已初始化，构造同步失败关闭的 AuditDispatcher。
func NewAuditDispatcher(cfg AuditDispatcherConfig) (*AuditDispatcher, error) {
	if cfg.Writer == nil {
		return nil, domi18n.WrapSentinel(ErrInvalidAuditConfig, ErrNilAuditWriter)
	}
	if fn, ok := cfg.Writer.(AuditWriterFunc); ok && fn == nil {
		return nil, domi18n.WrapSentinel(ErrInvalidAuditConfig, ErrNilAuditWriter)
	}
	if cfg.DiagnosticBus != nil && !cfg.DiagnosticBus.initialized {
		return nil, domi18n.EF(ErrInvalidAuditConfig, domi18n.KeyCommonComponentClosed, domi18n.Str("component", "diagnostic_bus"))
	}
	return &AuditDispatcher{
		writer: cfg.Writer, haltOnWriteError: cfg.HaltOnWriteError,
		onHalt: cfg.OnHalt, diagBus: cfg.DiagnosticBus, initialized: true,
	}, nil
}

// Dispatch 同步向底层 AuditWriter 分发有效 *AuditRecordEvent；未初始化、已熔断、ctx 取消或落盘失败均失败关闭。
func (d *AuditDispatcher) Dispatch(ctx context.Context, ev *AuditRecordEvent) error {
	if d == nil || !d.initialized {
		return ErrAuditDispatcherNotInitialized
	}
	if ctx == nil {
		return ErrNilContext
	}
	if ev == nil || !ev.IsValid() {
		return ErrInvalidEvent
	}
	if err := d.haltedErr(); err != nil {
		d.fails.Add(1)
		return err
	}
	if err := ctx.Err(); err != nil {
		d.fails.Add(1)
		return err
	}
	if err := d.writer.WriteAudit(ctx, ev); err != nil {
		d.fails.Add(1)
		if d.haltOnWriteError {
			d.Halt("audit_write_failed", err)
		}
		d.mirrorFailureDiag(ev, err)
		return domi18n.WrapSentinel(ErrAuditDispatchFailed, err)
	}
	d.dispatched.Add(1)
	return nil
}

// DispatchEvent 经由穷尽 Event type switch 仅放行 *AuditRecordEvent，其余变体一律失败关闭拒绝。
func (d *AuditDispatcher) DispatchEvent(ctx context.Context, ev Event) error {
	if d == nil || !d.initialized {
		return ErrAuditDispatcherNotInitialized
	}
	if ev == nil || !ev.IsValid() {
		return ErrInvalidEvent
	}
	switch v := ev.(type) {
	case *AuditRecordEvent:
		return d.Dispatch(ctx, v)
	case *OperationStartedEvent, *OperationCompletedEvent, *OutputChunkEvent, *StepEvent,
		*FSMTransitionEvent, *ApprovalChallengeEvent, *TransferProgressEvent, *MetricSampleEvent,
		*PoolStateEvent, *DiagnosticEvent, *BusDroppedEvent:
		return domi18n.EF(ErrUnsupportedEventClass, domi18n.KeyEventsClassMismatch, domi18n.Str("expected", EventKindAuditRecord.String()), domi18n.Str("actual", v.Kind().String()))
	default:
		return ErrInvalidEvent
	}
}

// Halt 将分发器不可逆切换至 Halted 熔断态，并在锁外经 haltOnce 线性化至多触发一次 OnHalt 回调。
func (d *AuditDispatcher) Halt(reason string, cause error) {
	if d == nil || !d.initialized {
		return
	}
	clean := sanitizeText(reason, maxCodeBytes)
	if clean == "" {
		clean = "audit_halted"
	}
	d.mu.Lock()
	if !d.halted {
		d.halted, d.haltReason, d.haltCause = true, clean, cause
	}
	winReason, winCause := d.haltReason, d.haltCause
	d.mu.Unlock()
	if d.onHalt != nil {
		d.haltOnce.Do(func() { d.onHalt(winReason, winCause) })
	}
}

// IsHalted、HaltReason 与 Stats 返回分发器熔断状态与并发安全统计快照（零值恒返回 Halted=true）。
func (d *AuditDispatcher) IsHalted() bool {
	if d == nil || !d.initialized {
		return true
	}
	d.mu.Lock()
	halted := d.halted
	d.mu.Unlock()
	return halted
}
func (d *AuditDispatcher) HaltReason() string {
	if d == nil || !d.initialized {
		return ""
	}
	d.mu.Lock()
	reason := d.haltReason
	d.mu.Unlock()
	return reason
}
func (d *AuditDispatcher) Stats() AuditDispatcherStats {
	if d == nil || !d.initialized {
		return AuditDispatcherStats{Halted: true}
	}
	return AuditDispatcherStats{d.dispatched.Load(), d.fails.Load(), d.IsHalted()}
}

func (d *AuditDispatcher) haltedErr() error {
	d.mu.Lock()
	halted, reason, cause := d.halted, d.haltReason, d.haltCause
	d.mu.Unlock()
	if !halted {
		return nil
	}
	switch reason {
	case "audit_write_failed":
		return domi18n.WrapS(ErrAuditHalted, cause, domi18n.KeyEventsAuditHaltWriteFailed)
	case "", "audit_halted":
		return pickIf[error](cause != nil, domi18n.WrapSentinel(ErrAuditHalted, cause), ErrAuditHalted)
	default:
		return domi18n.WrapS(ErrAuditHalted, cause, domi18n.KeyEventsAuditHaltReason, domi18n.BoundStr("reason", reason))
	}
}

func (d *AuditDispatcher) mirrorFailureDiag(ev *AuditRecordEvent, writeErr error) {
	if d.diagBus == nil || d.diagBus.IsClosed() {
		return
	}
	diag, err := NewDiagnosticEvent(DiagnosticSpec{
		Meta: ev.Meta(), Scope: DiagnosticScopeGate, Severity: SeverityError,
		Code: "audit_dispatch_failed", Message: "synchronous audit dispatch failed: " + writeErr.Error(),
		Attrs: map[string]string{"stage": ev.Stage().String(), "halted": pickIf(d.IsHalted(), "true", "false")},
	})
	if err == nil {
		_ = d.diagBus.Publish(diag)
	}
}
