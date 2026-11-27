package pool

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/foundation/actor"
	"github.com/wentf9/xops-cli/core/internal/foundation/trace"
	"github.com/wentf9/xops-cli/core/ports"
)

// errFastPathMiss 为包内不可变哨兵，用于指示整链快路径未命中并回退至逐跳多跳解析。
var errFastPathMiss = domi18n.Sentinel(domi18n.KeyPoolFastPathMiss)

// Pool 是完全解耦于具体 SSH 实现的双通道纯内存 Actor Merkle 连接池（ADR-009 / Plan P2-T5）。
//
// 零值恒未初始化且所有方法均严格失败关闭；通过 NewPool 创建后，由 workNursery 监督 DualActor
// 主循环、在途拨号与保活任务，由独立 teardownNursery 执行 90ms 有界拆断，确保调用 Close 时
// 按严格顺序收敛所有后台协程并满足 goleak 0 泄漏。
//
//xops:opaque
//xops:failclosed
type Pool struct {
	initialized              bool // 非指针正向有效门控（满足 xopsvet/failclosed 零值最严约束）
	halted, closed           atomic.Bool
	haltMu                   sync.Mutex
	haltErr                  error
	haltCtx                  context.Context
	haltCancel               context.CancelCauseFunc
	dialer                   ports.DialerPort
	clock                    ports.Clock
	entropy                  ports.Entropy
	bus                      *events.SystemBus
	domain                   string
	poolTraceID              security.TraceID
	maxConns                 int
	teardownGrace            time.Duration
	idleTTL                  time.Duration
	defaultKeepaliveInterval time.Duration
	workNursery              *conc.Nursery
	teardownNursery          *conc.Nursery
	actor                    *actor.DualActor[acquireMsg, controlMsg]
	slots                    *slotMap
	// 以下映射与世代计数器仅在 DualActor 单线程循环（及 actorDone 后的停机清理）内访问。
	active    map[plan.HopDigest]*hopInstance
	byPlan    map[plan.PlanDigest]plan.HopDigest
	dialing   map[plan.HopDigest]*dialInflight
	nextEpoch uint64
	// 以下原子计数器供无锁 Stats() 与租约/事件序列使用。
	activeConns, dialingConns, activeLeases                      atomic.Int64
	totalDials, dialErrors, cacheHits, parentCASRejects          atomic.Uint64
	teardownCompleted, teardownEscalated, nextLeaseSeq, eventSeq atomic.Uint64
	tdMu                                                         sync.Mutex
	tdPending                                                    int64
	tdIdleCh                                                     chan struct{}
	finalCleanupOnce, closeOnce                                  sync.Once
	closeErr                                                     error
}

// NewPool 校验配置与出站依赖端口，初始化 DualActor、双 Nursery 与世代 SlotMap，并启动 Actor 主循环。
// 调用方须在生命周期结束时配对调用 Close() 以优雅排空所有后台协程与底层传输连接。
func NewPool(ctx context.Context, cfg PoolConfig) (*Pool, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	norm, err := normalizePoolConfig(cfg)
	if err != nil {
		return nil, err
	}
	poolTID, err := trace.NewTraceIDFrom(norm.Entropy)
	if err != nil {
		return nil, domi18n.WrapS(ErrInvalidPoolConfig, err, domi18n.KeyCommonIDGenFailed, domi18n.Str("kind", "TraceID"))
	}
	return buildAndStartPool(ctx, norm, poolTID)
}
func normalizePoolConfig(cfg PoolConfig) (PoolConfig, error) {
	if err := validatePoolPorts(cfg); err != nil {
		return PoolConfig{}, err
	}
	if err := validatePoolLimits(cfg); err != nil {
		return PoolConfig{}, err
	}
	if cfg.Domain == "" {
		cfg.Domain = DefaultDomain
	}
	if _, err := trace.NewLeaseScope(cfg.Domain, "init"); err != nil {
		return PoolConfig{}, domi18n.WrapS(ErrInvalidPoolConfig, err, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "Domain"))
	}
	if cfg.AcquireBuffer == 0 {
		cfg.AcquireBuffer = DefaultAcquireBuffer
	}
	if cfg.TeardownGrace == 0 {
		cfg.TeardownGrace = DefaultTeardownGrace
	}
	return cfg, nil
}
func validatePoolPorts(cfg PoolConfig) error {
	switch {
	case cfg.Dialer == nil:
		return domi18n.EF(ErrInvalidPoolConfig, domi18n.KeyCommonFieldNil, domi18n.Str("field", "Dialer"))
	case cfg.Clock == nil:
		return domi18n.EF(ErrInvalidPoolConfig, domi18n.KeyCommonFieldNil, domi18n.Str("field", "Clock"))
	case cfg.Entropy == nil:
		return domi18n.EF(ErrInvalidPoolConfig, domi18n.KeyCommonFieldNil, domi18n.Str("field", "Entropy"))
	case cfg.Bus != nil && cfg.Bus.IsClosed():
		return domi18n.EF(ErrInvalidPoolConfig, domi18n.KeyCommonComponentClosed, domi18n.Str("component", "SystemBus"))
	default:
		return nil
	}
}
func validatePoolLimits(cfg PoolConfig) error {
	if cfg.AcquireBuffer < 0 || cfg.MaxConns < 0 || cfg.MaxHandles < 0 ||
		cfg.TeardownGrace < 0 || cfg.IdleTTL < 0 || cfg.DefaultKeepaliveInterval < 0 {
		return domi18n.EF(ErrInvalidPoolConfig, domi18n.KeyCommonFieldNegative, domi18n.Str("field", "pool_limit"))
	}
	return nil
}
func buildAndStartPool(ctx context.Context, cfg PoolConfig, poolTID security.TraceID) (*Pool, error) {
	workNursery, err := conc.NewNursery(ctx)
	if err != nil {
		return nil, err
	}
	teardownNursery, err := conc.NewNursery(context.Background())
	if err != nil {
		_ = workNursery.Close()
		return nil, err
	}
	haltCtx, haltCancel := context.WithCancelCause(workNursery.Context())
	idleCh := make(chan struct{})
	close(idleCh)
	p := &Pool{
		initialized: true, haltCtx: haltCtx, haltCancel: haltCancel,
		dialer: cfg.Dialer, clock: cfg.Clock, entropy: cfg.Entropy, bus: cfg.Bus,
		domain: cfg.Domain, poolTraceID: poolTID, maxConns: cfg.MaxConns,
		teardownGrace: cfg.TeardownGrace, idleTTL: cfg.IdleTTL,
		defaultKeepaliveInterval: cfg.DefaultKeepaliveInterval,
		workNursery:              workNursery, teardownNursery: teardownNursery,
		slots:   newSlotMap(cfg.MaxHandles),
		active:  make(map[plan.HopDigest]*hopInstance),
		byPlan:  make(map[plan.PlanDigest]plan.HopDigest),
		dialing: make(map[plan.HopDigest]*dialInflight), tdIdleCh: idleCh,
	}
	da, err := actor.NewDualActor(actor.DualActorConfig[acquireMsg, controlMsg]{
		AcquireBuffer:  cfg.AcquireBuffer,
		OnRequest:      p.handleAcquireReq,
		OnControl:      p.handleControlMsg,
		OnDrainRequest: p.handleDrainAcquireReq,
	})
	if err != nil {
		haltCancel(nil)
		_ = workNursery.Close()
		_ = teardownNursery.Close()
		return nil, err
	}
	p.actor = da
	if err := p.startBackgroundLoops(); err != nil {
		haltCancel(nil)
		_ = workNursery.Close()
		_ = teardownNursery.Close()
		return nil, err
	}
	return p, nil
}
func (p *Pool) startBackgroundLoops() error {
	if err := p.workNursery.Go(p.runActor); err != nil {
		return err
	}
	if p.idleTTL > 0 {
		if err := p.workNursery.Go(p.runIdleSweeper); err != nil {
			p.actor.Stop()
			return err
		}
	}
	return nil
}
func (p *Pool) nextLeaseID() string { return "lease-" + strconv.FormatUint(p.nextLeaseSeq.Add(1), 10) }
func (p *Pool) terminalStateError() error {
	if p.halted.Load() {
		return p.haltCause()
	}
	return ErrPoolClosed
}

// GateHalted 响应能力门控触发的 Halted 熔断（可直接接线至 gate.OnHaltFunc，ADR-008 / ADR-009）：
// 原子置位熔断态、取消 haltCtx 并吊销全部活跃托管句柄、经控制通道同步摘除全部连接并有界拆断。
func (p *Pool) GateHalted(reason error) {
	if p == nil || !p.initialized {
		return
	}
	cause := p.recordHaltReason(reason)
	p.haltCancel(cause)
	p.revokeAllSlots(events.PoolActionGateHalted, cause)
	doneCh := make(chan struct{})
	if p.actor.SendControl(controlMsg{kind: ctrlGateHalted, err: cause, doneCh: doneCh}) {
		select {
		case <-doneCh:
		case <-p.actor.Done():
		}
	}
}
func (p *Pool) recordHaltReason(reason error) error {
	p.haltMu.Lock()
	defer p.haltMu.Unlock()
	if p.haltErr != nil {
		return p.haltErr
	}
	switch {
	case reason == nil:
		p.haltErr = ErrGateHalted
	case errors.Is(reason, ErrGateHalted):
		p.haltErr = reason
	default:
		p.haltErr = domi18n.WrapSentinel(ErrGateHalted, reason)
	}
	p.halted.Store(true)
	return p.haltErr
}
func (p *Pool) haltCause() error {
	p.haltMu.Lock()
	err := p.haltErr
	p.haltMu.Unlock()
	return pickIf[error](err != nil, err, ErrGateHalted)
}

// RetireHop 主动退役指定 HopDigest 的当前活跃连接及其全部下游子跳，取消关联租约并在 90ms 宽限内拆断。
func (p *Pool) RetireHop(digest plan.HopDigest) error {
	return p.sendSyncControl(digest.IsValid(), controlMsg{kind: ctrlRetireHop, hopDigest: digest})
}

// RetirePlan 主动退役指定顶层 PlanDigest 对应的末跳连接（不误伤健康共享的上游堡垒机跳板）。
func (p *Pool) RetirePlan(planDigest plan.PlanDigest) error {
	return p.sendSyncControl(planDigest.IsValid(), controlMsg{kind: ctrlRetirePlan, planDigest: planDigest})
}
func (p *Pool) sendSyncControl(validArg bool, msg controlMsg) error {
	if p == nil || !p.initialized {
		return ErrPoolNotInitialized
	}
	if !validArg {
		return ErrInvalidPlan
	}
	msg.doneCh = make(chan struct{})
	if !p.actor.SendControl(msg) {
		return p.terminalStateError()
	}
	select {
	case <-msg.doneCh:
		return nil
	case <-p.actor.Done():
		return p.terminalStateError()
	}
}

// EvictIdle 立即驱逐池内所有无活跃租约、无钉选托管句柄且无活跃子跳的空闲连接（自底向上级联驱逐），返回驱逐数量。
func (p *Pool) EvictIdle() int {
	if p == nil || !p.initialized {
		return 0
	}
	countCh := make(chan int, 1)
	if !p.actor.SendControl(controlMsg{kind: ctrlEvictIdle, cutoff: p.clock.Now(), forceIdle: true, countCh: countCh}) {
		return 0
	}
	select {
	case n := <-countCh:
		return n
	case <-p.actor.Done():
		return 0
	}
}

// WaitPendingTeardowns 阻塞等待当前已派发的有界拆断协调任务全部结束（或 ctx 取消），供测试零 time.Sleep 同步。
func (p *Pool) WaitPendingTeardowns(ctx context.Context) error {
	if p == nil || !p.initialized {
		return ErrPoolNotInitialized
	}
	if ctx == nil {
		return ErrNilContext
	}
	p.tdMu.Lock()
	ch := p.tdIdleCh
	p.tdMu.Unlock()
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// IsHalted / IsClosed 报告连接池熔断或关闭状态（nil 或未初始化零值失败关闭返回 true）。
func (p *Pool) IsHalted() bool { return p == nil || !p.initialized || p.halted.Load() }
func (p *Pool) IsClosed() bool { return p == nil || !p.initialized || p.closed.Load() }

// Stats 返回连接池当前的无锁并发安全运行期统计快照。
func (p *Pool) Stats() PoolStats {
	if p == nil || !p.initialized {
		return PoolStats{Closed: true}
	}
	return PoolStats{
		ActiveConns: int(p.activeConns.Load()), DialingConns: int(p.dialingConns.Load()),
		ActiveLeases: p.activeLeases.Load(), ActiveHandles: p.slots.len(),
		TotalDials: p.totalDials.Load(), DialErrors: p.dialErrors.Load(),
		CacheHits: p.cacheHits.Load(), ParentCASRejections: p.parentCASRejects.Load(),
		TeardownCompleted: p.teardownCompleted.Load(), TeardownEscalations: p.teardownEscalated.Load(),
		Halted: p.halted.Load(), Closed: p.closed.Load(),
	}
}

// Close 幂等关闭连接池：吊销全部托管句柄、停止 DualActor 并排空所有请求与工作协程、
// 对残余连接执行 90ms 有界拆断并等待全部拆断协程退出，保证零连接与零协程泄漏。
func (p *Pool) Close() error {
	if p == nil || !p.initialized {
		return ErrPoolNotInitialized
	}
	p.closeOnce.Do(func() {
		p.closed.Store(true)
		p.haltCancel(ErrPoolClosed)
		p.revokeAllSlots(events.PoolActionRetired, ErrPoolClosed)
		p.actor.Stop()
		<-p.actor.Done()
		workErr := p.workNursery.Close()
		p.cleanupAfterActorExit()
		_ = p.WaitPendingTeardowns(context.Background())
		tdErr := p.teardownNursery.Wait()
		p.closeErr = errors.Join(workErr, tdErr)
	})
	return p.closeErr
}
