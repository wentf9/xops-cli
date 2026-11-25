package gate

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/ports"
)

// HaltInfo 描述 Gate 首次进入不可逆 Halted 熔断态时的只读诊断快照（ADR-008）；零值恒无效。
//
//xops:opaque
//xops:failclosed
type HaltInfo struct {
	processID   ports.ProcessInstanceID
	operationID algebraic.Option[security.OperationID]
	reason      string
	cause       error
	haltedAt    time.Time
	valid       bool
}

// HaltInfo 只读诊断访问器（零值恒无效并失败关闭）。
func (h HaltInfo) IsValid() bool {
	return h.valid && h.processID.IsValid() && h.reason != "" && isValidRFC3339Time(h.haltedAt)
}
func (h HaltInfo) IsZero() bool                                        { return !h.IsValid() }
func (h HaltInfo) ProcessID() ports.ProcessInstanceID                  { return h.processID }
func (h HaltInfo) OperationID() algebraic.Option[security.OperationID] { return h.operationID }
func (h HaltInfo) Reason() string                                      { return h.reason }
func (h HaltInfo) Cause() error                                        { return h.cause }
func (h HaltInfo) HaltedAt() time.Time                                 { return h.haltedAt }

// OnHaltFunc 是 Gate 首次进入不可逆 Halted 熔断态时在锁外经 sync.Once 线性化触发至多一次的出站回调（ADR-008）。
// 由 core/engine 将其接线至连接池控制通道（如 pool.GateHalted），彻底保持 gate 与 pool 零依赖隔离。
// 回调内可安全读取 Gate.IsHalted()/HaltInfo()/Stats()，但严禁重入调用 Gate.Halt。
type OnHaltFunc func(info HaltInfo)

// GateStats 提供 Gate 当前的不可变运行统计快照（零值或未初始化实例恒报告 Halted=true）。
type GateStats struct {
	Authorized        uint64
	Denied            uint64
	Finalized         uint64
	PostWriteErrors   uint64
	ActiveHandles     int
	PendingChallenges int
	Halted            bool
}

// GateConfig 定义能力门控运行时 Gate 的全显式依赖注入配置（零逃生口：Profile/Policy/AuditSink/Clock/Entropy 均必填）。
type GateConfig struct {
	Profile     PolicyProfileKind     // 必填：运行策略配置档（DirectOperator / StrictOperator / StrictAgent）
	Policy      GuardrailPolicy       // 必填：不可变护栏策略（严禁零值或跳过求值）
	AuditSink   ports.AuditSink       // 必填：同步 Fail-Closed 审计写入与只追加操作登记端口
	Reconciler  ports.AuditReconciler // 可选：启动期 O(1) 跨进程崩溃审计对账端口（显式注入，零隐式接口嗅探）
	Interaction ports.InteractionPort // 可选：人工审批交互端口（nil 时按 Policy.NoElicitFallback 失败关闭）
	Clock       ports.Clock           // 必填：确定性时钟端口（零隐式 time.Now）
	Entropy     ports.Entropy         // 必填：显式密码学/确定性熵源（零隐式 crypto/rand）
	OnHalt      OnHaltFunc            // 可选：Halted 熔断出站回调（锁外线性化触发一次）
	SystemBus   *events.SystemBus     // 可选：非阻塞诊断事件总线（仅发布脱敏熔断与崩溃对账诊断）
}

// Gate 是 XOps v2 的核心安全能力门控运行时（ADR-008 / ADR-009 / Plan P2-T4），实现封闭接口 Authorizer。
//
// 单一权威所有权与并发故障安全不变量：
//   - Gate 是全引擎唯一的权威审计落盘与 Halted 熔断状态机所有者（直接驱动 ports.AuditSink 与 OnHaltFunc ->
//     pool.GateHalted），严禁在 core/engine 中另行装配 events.AuditDispatcher 作为第二套独立熔断源；
//   - 严禁持 g.mu 调用外部 AuditSink、InteractionPort、Canonicalize、Clock、OnHaltFunc 或 ctx.Err()；
//   - StrictAgentProfile 下终态审计落盘失败（*ports.AuditPostWriteError）立即不可逆进入 Halted 态、
//     吊销全部活跃 Authorized[C] 句柄、保持未闭合操作留在 .lock 供崩溃恢复，并在锁外线性化通知 OnHaltFunc；
//   - 零值 Gate{} 与 typed-nil (*Gate)(nil) 在全部导出与内部方法上均严格失败关闭、零 panic。
//
//xops:opaque
//xops:failclosed
type Gate struct {
	profile     PolicyProfileKind
	policy      GuardrailPolicy
	sink        ports.AuditSink
	reconciler  ports.AuditReconciler
	interaction ports.InteractionPort
	clock       ports.Clock
	entropy     ports.Entropy
	onHalt      OnHaltFunc
	bus         *events.SystemBus
	procID      ports.ProcessInstanceID

	mu                  sync.Mutex
	initialized         bool // 正向有效门控（满足 xopsvet/failclosed 对 halted 否定字段检查）
	halted              bool
	haltInfo            HaltInfo
	haltOnce            sync.Once
	haltDiagOnce        sync.Once
	nextHandleSeq       uint64
	activeHandles       map[uint64]*atomic.Bool
	pending             map[security.Digest]*pendingChallenge
	consumedDig         map[security.Digest]consumedRecord
	consumedNonce       map[[16]byte]time.Time
	consumedOrder       []consumedEntry
	consumedHead        int
	earliestConsumedExp time.Time

	authorizedCount     atomic.Uint64
	deniedCount         atomic.Uint64
	finalizedCount      atomic.Uint64
	postWriteErrorCount atomic.Uint64
}

// NewGate 严格校验全部必填依赖（拒绝 nil AuditSink/Clock/Entropy、零值 Policy、非法 Profile
// 与未初始化或已关闭 SystemBus），构造并初始化不可绕过的 Gate 实例。
func NewGate(cfg GateConfig) (*Gate, error) {
	if !cfg.Profile.IsValid() {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, ErrInvalidProfile)
	}
	if !cfg.Policy.IsValid() {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, ErrInvalidPolicy)
	}
	if cfg.AuditSink == nil {
		return nil, fmt.Errorf("%w: AuditSink 不能为 nil", ErrInvalidConfig)
	}
	procID := cfg.AuditSink.ProcessInstanceID()
	if !procID.IsValid() {
		return nil, fmt.Errorf("%w: AuditSink.ProcessInstanceID 无效", ErrInvalidConfig)
	}
	if cfg.Clock == nil {
		return nil, fmt.Errorf("%w: Clock 不能为 nil", ErrInvalidConfig)
	}
	if cfg.Entropy == nil {
		return nil, fmt.Errorf("%w: Entropy 不能为 nil", ErrInvalidConfig)
	}
	if cfg.SystemBus != nil && cfg.SystemBus.IsClosed() {
		return nil, fmt.Errorf("%w: SystemBus 未初始化或已关闭", ErrInvalidConfig)
	}
	return &Gate{
		profile:       cfg.Profile,
		policy:        cfg.Policy,
		sink:          cfg.AuditSink,
		reconciler:    cfg.Reconciler,
		interaction:   cfg.Interaction,
		clock:         cfg.Clock,
		entropy:       cfg.Entropy,
		onHalt:        cfg.OnHalt,
		bus:           cfg.SystemBus,
		procID:        procID,
		initialized:   true,
		activeHandles: make(map[uint64]*atomic.Bool),
		pending:       make(map[security.Digest]*pendingChallenge),
		consumedDig:   make(map[security.Digest]consumedRecord),
		consumedNonce: make(map[[16]byte]time.Time),
	}, nil
}

// IsHalted 报告门控是否处于不可逆 Halted 熔断态；nil 或未初始化零值失败关闭返回 true。
func (g *Gate) IsHalted() bool { return g.isHalted() }

func (g *Gate) isHalted() bool {
	if g == nil || !g.initialized {
		return true
	}
	g.mu.Lock()
	halted := g.halted
	g.mu.Unlock()
	return halted
}

// Profile 返回当前门控绑定的策略配置档；nil 或未初始化零值返回 PolicyProfileInvalid。
func (g *Gate) Profile() PolicyProfileKind {
	if g == nil || !g.initialized {
		return PolicyProfileInvalid
	}
	return g.profile
}

// Policy 返回当前门控绑定的不可变护栏策略副本；nil 或未初始化零值返回无效零值。
func (g *Gate) Policy() GuardrailPolicy {
	if g == nil || !g.initialized {
		return GuardrailPolicy{}
	}
	return g.policy
}

// ProcessInstanceID 返回底层 AuditSink 绑定的进程实例标识；nil 或未初始化零值返回零值。
func (g *Gate) ProcessInstanceID() ports.ProcessInstanceID {
	if g == nil || !g.initialized {
		return zeroVal[ports.ProcessInstanceID]()
	}
	return g.procID
}

// HaltInfo 返回进入熔断态时的只读诊断快照；尚未熔断、nil 或未初始化时返回 (零值, false)。
func (g *Gate) HaltInfo() (HaltInfo, bool) {
	if g == nil || !g.initialized {
		return HaltInfo{}, false
	}
	g.mu.Lock()
	halted, info := g.halted, g.haltInfo
	g.mu.Unlock()
	return info, halted && info.IsValid()
}

// Stats 返回 Gate 当前并发安全的运行期指标快照；nil 或未初始化零值返回 Halted=true。
func (g *Gate) Stats() GateStats {
	if g == nil || !g.initialized {
		return GateStats{Halted: true}
	}
	g.mu.Lock()
	active, pending, halted := len(g.activeHandles), len(g.pending), g.halted
	g.mu.Unlock()
	return GateStats{
		Authorized:        g.authorizedCount.Load(),
		Denied:            g.deniedCount.Load(),
		Finalized:         g.finalizedCount.Load(),
		PostWriteErrors:   g.postWriteErrorCount.Load(),
		ActiveHandles:     active,
		PendingChallenges: pending,
		Halted:            halted,
	}
}

// Halt 显式将 Gate 不可逆切换至 Halted 熔断态、立即吊销全部活跃 Authorized[C] 句柄，
// 并在锁外通过 sync.Once 线性化至多触发一次 OnHaltFunc（幂等且并发安全）。
func (g *Gate) Halt(reason string, cause error) {
	g.triggerHalt(algebraic.None[security.OperationID](), reason, cause)
}

func (g *Gate) triggerHalt(opID algebraic.Option[security.OperationID], reason string, cause error) {
	if g == nil || !g.initialized {
		return
	}
	now := g.clock.Now().UTC().Round(0)
	cleanReason := sanitizeReason(reason, "gate_halted")

	g.mu.Lock()
	if !g.halted {
		g.halted = true
		g.haltInfo = HaltInfo{
			processID:   g.procID,
			operationID: opID,
			reason:      cleanReason,
			cause:       cause,
			haltedAt:    now,
			valid:       true,
		}
	}
	for _, flag := range g.activeHandles {
		flag.Store(true)
	}
	clear(g.pending)
	info := g.haltInfo
	g.mu.Unlock()

	if g.onHalt != nil {
		g.haltOnce.Do(func() {
			g.onHalt(info)
		})
	}
	g.haltDiagOnce.Do(func() {
		g.emitDiagnostic(info.operationID, events.SeverityError, "gate_halted", info.reason, map[string]string{
			"profile": g.profile.String(),
			"halted":  "true",
		})
	})
}

// ReconcileCrashedAudits 执行启动期 O(1) 跨进程崩溃审计对账（ADR-008 / RFC §3.4 / Plan §4.4）：
// 委托显式注入的 ports.AuditReconciler 扫描 ~/.xops/run/*.lock，无死亡锁时零读取 audit.jsonl；
// 若抢占到死亡进程锁并补写 AbortedByCrash，则向可选 SystemBus 发射脱敏告警诊断事件。
func (g *Gate) ReconcileCrashedAudits(ctx context.Context) (ports.CrashReconcileReport, error) {
	zRep := zeroVal[ports.CrashReconcileReport]()
	if g == nil || !g.initialized {
		return zRep, ErrGateNotInitialized
	}
	if ctx == nil {
		return zRep, ErrNilContext
	}
	if err := g.haltedErr(); err != nil {
		return zRep, err
	}
	if err := ctx.Err(); err != nil {
		return zRep, err
	}
	if g.reconciler == nil {
		return zRep, ErrReconcilerUnavailable
	}
	now := g.clock.Now().UTC().Round(0)
	if !isValidRFC3339Time(now) {
		return zRep, fmt.Errorf("%w: 时钟返回无效对账时刻", ErrInvalidConfig)
	}
	report, err := g.reconciler.ReconcileCrashedAudits(ctx, now)
	if err != nil {
		g.emitDiagnostic(algebraic.None[security.OperationID](), events.SeverityError, "audit_reconcile_failed", err.Error(), nil)
		return zRep, err
	}
	if !report.IsValid() {
		return zRep, fmt.Errorf("%w: AuditReconciler 返回无效 CrashReconcileReport", ErrInvalidConfig)
	}
	g.emitReconcileDiagnostic(report)
	return report, nil
}

func (g *Gate) haltedErr() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.haltedErrLocked()
}

func (g *Gate) haltedErrLocked() error {
	if !g.halted {
		return nil
	}
	if g.haltInfo.cause != nil {
		return fmt.Errorf("%w (%s): %w", ErrGateHalted, g.haltInfo.reason, g.haltInfo.cause)
	}
	return fmt.Errorf("%w: %s", ErrGateHalted, g.haltInfo.reason)
}

func (g *Gate) emitReconcileDiagnostic(report ports.CrashReconcileReport) {
	aborted := report.AbortedOperations()
	attrs := map[string]string{
		"scanned_locks":      strconv.Itoa(report.ScannedLocks()),
		"live_locks_skipped": strconv.Itoa(report.LiveLocksSkipped()),
		"dead_locks_claimed": strconv.Itoa(report.DeadLocksClaimed()),
		"aborted_count":      strconv.Itoa(len(aborted)),
	}
	if report.DeadLocksClaimed() > 0 || len(aborted) > 0 {
		attrs["mode"] = "slow_path"
		g.emitDiagnostic(algebraic.None[security.OperationID](), events.SeverityWarn, "audit_crash_reconciled",
			fmt.Sprintf("reconciled %d dead lock(s) and finalized %d crashed operation(s)", report.DeadLocksClaimed(), len(aborted)), attrs)
		return
	}
	attrs["mode"] = "fast_path_o1"
	g.emitDiagnostic(algebraic.None[security.OperationID](), events.SeverityInfo, "audit_reconcile_clean",
		"startup crash reconciliation clean (O(1) fast path)", attrs)
}

func (g *Gate) emitDiagnostic(
	opID algebraic.Option[security.OperationID],
	sev events.Severity,
	code, msg string,
	attrs map[string]string,
) {
	if g.bus == nil || g.bus.IsClosed() {
		return
	}
	tid, err := security.ParseTraceID("gate-" + g.procID.String())
	if err != nil {
		return
	}
	meta, err := events.NewEventMeta(events.EventMetaSpec{
		TraceID:     tid,
		OperationID: opID,
		OccurredAt:  g.clock.Now().UTC().Round(0),
	})
	if err != nil {
		return
	}
	ev, err := events.NewDiagnosticEvent(events.DiagnosticSpec{
		Meta:     meta,
		Scope:    events.DiagnosticScopeGate,
		Severity: sev,
		Code:     code,
		Message:  msg,
		Attrs:    attrs,
	})
	if err == nil {
		_ = g.bus.Publish(ev)
	}
}
