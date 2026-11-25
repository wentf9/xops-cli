package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/foundation/trace"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	ucinv "github.com/wentf9/xops-cli/core/internal/usecase/inventory"
	ucsess "github.com/wentf9/xops-cli/core/internal/usecase/session"
	"github.com/wentf9/xops-cli/core/ports"
)

// Engine 是 XOps v2 六边形核心的唯一公开业务编排与运行期门面（ADR-001 / ADR-008 / ADR-009）；
// 零值恒未初始化且所有方法均严格失败关闭。
//
// 生命周期与停机次序：
//   - 由组合根（cmd/xops）通过 New(cfg) 显式装配，严禁全局单例或 init() 隐式构造；
//   - Close(ctx) 按确定性逆序执行：拒绝新入站操作并取消在途 UseCase 上下文等待排空 ->
//     关闭连接池 Pool（同步收敛全部 DualActor 与拆断协程）-> 关闭 Engine 自建的 SystemBus；
//   - 外部注入的 AuditSink、ScopedRootFS、OperatorReadFS、Vault、SystemBus 由组合根在 Engine.Close 之后逆序关闭。
//
//xops:opaque
//xops:failclosed
type Engine struct {
	initialized bool // 非指针正向有效门控（满足 xopsvet/failclosed 零值最严约束）

	clock   ports.Clock
	entropy ports.Entropy
	bus     *events.SystemBus
	ownsBus bool

	pool      *pool.Pool
	gate      *gate.Gate
	inventory *ucinv.Service
	session   *ucsess.Service

	opCtx    context.Context
	opCancel context.CancelCauseFunc

	opMu     sync.Mutex
	closing  bool
	inflight int
	drainCh  chan struct{}

	closeOnce sync.Once
	closeErr  error
}

// New 校验配置与出站依赖，装配真实主机信任库（sshnet/hostkey）、真实 SSH 拨号器（sshnet/dial）、
// 连接池（pool）、安全门控（gate，接线 OnHaltFunc -> pool.GateHalted）及目标解析/会话用例服务。
// 任意装配步骤失败时均同步回滚已创建的后台资源，保证零 goroutine 泄漏。
func New(cfg Config) (*Engine, error) {
	profile, policy, err := validateBaseConfig(cfg)
	if err != nil {
		return nil, err
	}
	hostTrust, err := buildHostTrustPort(cfg)
	if err != nil {
		return nil, err
	}
	realDialer, err := buildRealDialer(cfg, hostTrust)
	if err != nil {
		return nil, err
	}
	bus, ownsBus, err := resolveSystemBus(cfg)
	if err != nil {
		return nil, err
	}
	rollbackBus := func() {
		if ownsBus && bus != nil {
			bus.Close()
		}
	}
	pCfg, err := buildPoolConfig(cfg, realDialer, bus)
	if err != nil {
		rollbackBus()
		return nil, err
	}
	p, err := pool.NewPool(context.Background(), pCfg)
	if err != nil {
		rollbackBus()
		return nil, fmt.Errorf("%w: 初始化连接池失败: %w", ErrInvalidConfig, err)
	}
	rollbackAll := func() {
		_ = p.Close()
		rollbackBus()
	}
	g, err := buildEngineGate(cfg, profile, policy, bus, p)
	if err != nil {
		rollbackAll()
		return nil, err
	}
	invSvc, sessSvc, err := buildEngineServices(cfg, g, p)
	if err != nil {
		rollbackAll()
		return nil, err
	}
	opCtx, opCancel := context.WithCancelCause(context.Background())
	return &Engine{
		initialized: true,
		clock:       cfg.Clock,
		entropy:     cfg.Entropy,
		bus:         bus,
		ownsBus:     ownsBus,
		pool:        p,
		gate:        g,
		inventory:   invSvc,
		session:     sessSvc,
		opCtx:       opCtx,
		opCancel:    opCancel,
	}, nil
}

const (
	defaultSystemBusBuffer       = 64
	defaultOperationStreamBuffer = 64
)

func resolveSystemBus(cfg Config) (*events.SystemBus, bool, error) {
	if cfg.SystemBus != nil {
		return cfg.SystemBus, false, nil
	}
	buf := cfg.SystemBusBuffer
	if buf == 0 {
		buf = defaultSystemBusBuffer
	}
	bus, err := events.NewSystemBus(events.SystemBusConfig{
		DefaultSubscriberBuffer: buf,
	})
	if err != nil {
		return nil, false, fmt.Errorf("%w: 创建默认 SystemBus 失败: %w", ErrInvalidConfig, err)
	}
	return bus, true, nil
}

func buildEngineGate(
	cfg Config,
	profile gate.PolicyProfileKind,
	policy gate.GuardrailPolicy,
	bus *events.SystemBus,
	p *pool.Pool,
) (*gate.Gate, error) {
	userOnHalt := cfg.OnHalt
	g, err := gate.NewGate(gate.GateConfig{
		Profile:     profile,
		Policy:      policy,
		AuditSink:   cfg.AuditSink,
		Reconciler:  cfg.Reconciler,
		Interaction: cfg.Interaction,
		Clock:       cfg.Clock,
		Entropy:     cfg.Entropy,
		SystemBus:   bus,
		// 严格遵循 ADR-008/ADR-009：Gate 进入不可逆 Halted 后第一时间通知连接池吊销全部句柄，
		// 再触发可选外部 OnHalt 通知。
		OnHalt: func(info gate.HaltInfo) {
			p.GateHalted(info.Cause())
			if userOnHalt != nil {
				userOnHalt(haltInfoFromGate(info))
			}
		},
	})
	if err != nil {
		return nil, fmt.Errorf("%w: 初始化安全门控失败: %w", ErrInvalidConfig, err)
	}
	return g, nil
}

func buildEngineServices(
	cfg Config,
	g *gate.Gate,
	p *pool.Pool,
) (*ucinv.Service, *ucsess.Service, error) {
	invSvc, err := ucinv.NewService(ucinv.ServiceConfig{
		OpenSSH:       cfg.OpenSSH,
		Env:           cfg.Env,
		GlobalOptions: cfg.GlobalOptions,
		MaxJumpDepth:  cfg.MaxJumpDepth,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("%w: 初始化目标解析服务失败: %w", ErrInvalidConfig, err)
	}
	sessSvc, err := ucsess.NewService(ucsess.ServiceConfig{
		Gate:     g,
		Pool:     p,
		Clock:    cfg.Clock,
		Env:      cfg.Env,
		Terminal: cfg.Terminal,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("%w: 初始化会话执行服务失败: %w", ErrInvalidConfig, err)
	}
	return invSvc, sessSvc, nil
}

// ReconcileCrashedAudits 执行启动期 O(1) 跨进程崩溃审计对账（ADR-008 / RFC §3.4），
// 委托内部 gate.ReconcileCrashedAudits 扫描死亡锁并补写 AbortedByCrash，使 cmd/xops 无需导入 core/internal/gate。
func (e *Engine) ReconcileCrashedAudits(ctx context.Context) (ReconcileReport, error) {
	runCtx, cleanup, err := e.beginOp(ctx)
	if err != nil {
		return ReconcileReport{}, err
	}
	defer cleanup()

	raw, err := e.gate.ReconcileCrashedAudits(runCtx)
	if err != nil {
		return ReconcileReport{}, mapGateError(err)
	}
	return ReconcileReport{raw: raw, valid: true}, nil
}

// NewOperationStream 从 Engine 显式熵源分配全局唯一 TraceID 与 OperationID，
// 构造供单次操作绑定的隔离 events.OperationStream（确定性 EOF；buffer==0 取默认 64，负值失败关闭）。
func (e *Engine) NewOperationStream(ctx context.Context, buffer int) (*events.OperationStream, error) {
	if e == nil || !e.initialized {
		return nil, ErrEngineNotInitialized
	}
	if ctx == nil {
		return nil, ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if e.IsClosed() {
		return nil, ErrEngineClosed
	}
	if buffer < 0 {
		return nil, fmt.Errorf("%w: OperationStream 缓冲容量不能为负", ErrInvalidRequest)
	}
	if buffer == 0 {
		buffer = defaultOperationStreamBuffer
	}
	tid, err := trace.NewTraceIDFrom(e.entropy)
	if err != nil {
		return nil, fmt.Errorf("engine: 分配 TraceID 失败: %w", err)
	}
	oid, err := trace.NewOpIDFrom(e.entropy)
	if err != nil {
		return nil, fmt.Errorf("engine: 分配 OperationID 失败: %w", err)
	}
	return events.NewOperationStream(events.OperationStreamConfig{
		TraceID:         tid,
		OperationID:     oid,
		OperationBuffer: buffer,
	})
}

// SystemBus 返回 Engine 绑定的只读诊断事件总线（未初始化零值返回 nil）。
func (e *Engine) SystemBus() *events.SystemBus {
	if e == nil || !e.initialized {
		return nil
	}
	return e.bus
}

// IsHalted 报告安全门控是否已进入不可逆 Halted 熔断态；nil 或未初始化零值失败关闭返回 true。
func (e *Engine) IsHalted() bool {
	if e == nil || !e.initialized {
		return true
	}
	return e.gate.IsHalted()
}

// HaltInfo 返回进入不可逆 Halted 熔断态时的只读诊断快照；尚未熔断或未初始化返回 (零值, false)。
func (e *Engine) HaltInfo() (HaltInfo, bool) {
	if e == nil || !e.initialized {
		return HaltInfo{}, false
	}
	info, ok := e.gate.HaltInfo()
	if !ok {
		return HaltInfo{}, false
	}
	return haltInfoFromGate(info), true
}

// IsClosed 报告 Engine 是否已进入关闭或已完成关闭；nil 或未初始化零值失败关闭返回 true。
func (e *Engine) IsClosed() bool {
	if e == nil || !e.initialized {
		return true
	}
	e.opMu.Lock()
	closed := e.closing
	e.opMu.Unlock()
	return closed
}

// Close 按确定性逆序优雅关闭 Engine（幂等且并发安全）：
//  1. 拒绝新入站请求、取消在途 UseCase 上下文并等待在途操作排空（受 ctx.Done 有界约束）；
//  2. 关闭连接池 Pool（同步回收全部 DualActor、保活及拆断协程）；
//  3. 若 SystemBus 由 Engine 自建则关闭之（绝不关闭外部注入的 SystemBus 或 AuditSink/ScopedFS）。
func (e *Engine) Close(ctx context.Context) error {
	if e == nil || !e.initialized {
		return ErrEngineNotInitialized
	}
	if ctx == nil {
		return ErrNilContext
	}
	e.closeOnce.Do(func() {
		e.closeErr = e.shutdownReverseOrder(ctx)
	})
	return e.closeErr
}

func (e *Engine) shutdownReverseOrder(ctx context.Context) error {
	// 阶段 1（UseCases）：进入关闭态并取消在途操作上下文，等待在途调用收敛。
	e.opMu.Lock()
	e.closing = true
	var waitCh chan struct{}
	if e.inflight > 0 {
		if e.drainCh == nil {
			e.drainCh = make(chan struct{})
		}
		waitCh = e.drainCh
	}
	e.opMu.Unlock()

	e.opCancel(ErrEngineClosed)

	var drainErr error
	if waitCh != nil {
		select {
		case <-waitCh:
		case <-ctx.Done():
			drainErr = ctx.Err()
		}
	}

	// 阶段 2（Pool）：即使排空超时也必须关闭连接池以消除后台协程与连接泄漏。
	poolErr := e.pool.Close()

	// 阶段 3（Events）：仅关闭 Engine 自有 SystemBus。
	if e.ownsBus && e.bus != nil {
		e.bus.Close()
	}
	return errors.Join(drainErr, poolErr)
}

func (e *Engine) beginOp(ctx context.Context) (context.Context, func(), error) {
	if e == nil || !e.initialized {
		return nil, nil, ErrEngineNotInitialized
	}
	if ctx == nil {
		return nil, nil, ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	e.opMu.Lock()
	if e.closing {
		e.opMu.Unlock()
		return nil, nil, ErrEngineClosed
	}
	e.inflight++
	e.opMu.Unlock()

	runCtx, cancelRun := context.WithCancelCause(ctx)
	bridgeDone := make(chan struct{})
	stopBridge := context.AfterFunc(e.opCtx, func() {
		defer close(bridgeDone)
		cancelRun(context.Cause(e.opCtx))
	})
	cleanup := func() {
		if !stopBridge() {
			<-bridgeDone
		}
		cancelRun(nil)
		e.endOp()
	}
	return runCtx, cleanup, nil
}

func (e *Engine) endOp() {
	e.opMu.Lock()
	e.inflight--
	if e.closing && e.inflight == 0 && e.drainCh != nil {
		close(e.drainCh)
		e.drainCh = nil
	}
	e.opMu.Unlock()
}

func mapGateError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, gate.ErrGateHalted) {
		return fmt.Errorf("%w: %w", ErrEngineHalted, err)
	}
	if errors.Is(err, gate.ErrReconcilerUnavailable) {
		return fmt.Errorf("%w: %w", ErrReconcilerUnavailable, err)
	}
	return err
}
