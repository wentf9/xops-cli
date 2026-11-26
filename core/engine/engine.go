package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/foundation/trace"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	ucauto "github.com/wentf9/xops-cli/core/internal/usecase/automation"
	uccred "github.com/wentf9/xops-cli/core/internal/usecase/credential"
	ucinv "github.com/wentf9/xops-cli/core/internal/usecase/inventory"
	ucobs "github.com/wentf9/xops-cli/core/internal/usecase/observability"
	ucsess "github.com/wentf9/xops-cli/core/internal/usecase/session"
	uctrans "github.com/wentf9/xops-cli/core/internal/usecase/transfer"
	"github.com/wentf9/xops-cli/core/ports"
)

const (
	defaultSystemBusBuffer       = 64
	defaultOperationStreamBuffer = 64
)

// Engine 是 XOps v2 六边形核心的唯一公开业务编排与运行期门面（ADR-001 / ADR-008 / ADR-009）；
// 零值恒未初始化且所有方法均严格失败关闭。
// Close(ctx) 按确定性逆序关闭：派生 MCPServer & Projection -> 在途 UseCase 排空 -> 连接池 Pool -> 自建 SystemBus。
//
//xops:opaque
//xops:failclosed
type Engine struct {
	initialized, ownsBus, closing bool // initialized 为非指针正向有效门控（满足 xopsvet/failclosed 零值最严约束）
	clock                         ports.Clock
	entropy                       ports.Entropy
	scopedFS                      ports.ScopedRootFS
	bus                           *events.SystemBus
	hostTrustObs                  *hostTrustObserver
	pool                          *pool.Pool
	gate                          *gate.Gate
	inventory                     *ucinv.Service
	credential                    *uccred.Service
	session                       *ucsess.Service
	transfer, mcpTransfer         *uctrans.Service // mcpTransfer 共享活跃句柄表且物理 0 OperatorReadFS
	automation, mcpAutomation     *ucauto.Service  // mcpAutomation 物理 0 OperatorReadFS
	observability                 *ucobs.Service
	opCtx                         context.Context
	opCancel                      context.CancelCauseFunc
	opMu                          sync.Mutex
	inflight                      int
	drainCh                       chan struct{}
	mcpServers                    map[*MCPServer]struct{}
	projections                   map[*Projection]struct{}
	closeOnce                     sync.Once
	closeErr                      error
}

type pendingRefBridge struct{ inv atomic.Pointer[ucinv.Service] }

func (b *pendingRefBridge) ActivePendingSecretRefs() []inventory.PendingSecretRef {
	if inv := b.inv.Load(); inv != nil {
		return inv.ActivePendingSecretRefs()
	}
	return nil
}
func wrapCfgErr(msg string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %s: %w", ErrInvalidConfig, msg, err)
}
func rollbackNew(opCancel context.CancelCauseFunc, p *pool.Pool, ownsBus bool, bus *events.SystemBus, cause error) {
	if opCancel != nil {
		opCancel(cause)
	}
	if p != nil {
		_ = p.Close()
	}
	if ownsBus && bus != nil {
		bus.Close()
	}
}

// New 校验配置与出站依赖，装配拨号器（含透明 ControlMaster 复用与主机信任观测器）、连接池、安全门控与全部 6 大用例服务。
// 任意步骤失败均同步回滚已建后台资源，保证零 goroutine 泄漏。
func New(cfg Config) (eng *Engine, err error) {
	profile, policy, err := validateBaseConfig(cfg)
	if err != nil {
		return nil, err
	}
	dialer, hostTrustObs, err := buildDialerPort(cfg)
	if err != nil {
		return nil, err
	}
	bus, ownsBus, err := resolveSystemBus(cfg)
	if err != nil {
		return nil, err
	}
	var p *pool.Pool
	var g *gate.Gate
	var opCancel context.CancelCauseFunc
	defer func() {
		if err != nil {
			rollbackNew(opCancel, p, ownsBus, bus, err)
		}
	}()
	if pCfg, pErr := buildPoolConfig(cfg, dialer, bus); pErr != nil {
		return nil, pErr
	} else if p, err = pool.NewPool(context.Background(), pCfg); err != nil {
		return nil, wrapCfgErr("初始化连接池失败", err)
	}
	if g, err = buildEngineGate(cfg, profile, policy, bus, p); err != nil {
		return nil, err
	}
	var opCtx context.Context
	opCtx, opCancel = context.WithCancelCause(context.Background())
	eng = &Engine{
		initialized: true, ownsBus: ownsBus, clock: cfg.Clock, entropy: cfg.Entropy, scopedFS: cfg.ScopedFS,
		bus: bus, hostTrustObs: hostTrustObs, pool: p, gate: g, opCtx: opCtx, opCancel: opCancel,
		mcpServers: map[*MCPServer]struct{}{}, projections: map[*Projection]struct{}{},
	}
	return eng, eng.initServices(cfg)
}
func resolveSystemBus(cfg Config) (*events.SystemBus, bool, error) {
	if cfg.SystemBus != nil {
		return cfg.SystemBus, false, nil
	}
	if cfg.SystemBusBuffer == 0 {
		cfg.SystemBusBuffer = defaultSystemBusBuffer
	}
	bus, err := events.NewSystemBus(events.SystemBusConfig{DefaultSubscriberBuffer: cfg.SystemBusBuffer})
	return bus, err == nil, wrapCfgErr("创建默认 SystemBus 失败", err)
}
func buildEngineGate(cfg Config, profile gate.PolicyProfileKind, policy gate.GuardrailPolicy, bus *events.SystemBus, p *pool.Pool) (*gate.Gate, error) {
	userOnHalt := cfg.OnHalt
	g, err := gate.NewGate(gate.GateConfig{
		Profile: profile, Policy: policy, AuditSink: cfg.AuditSink, Reconciler: cfg.Reconciler,
		Interaction: cfg.Interaction, Clock: cfg.Clock, Entropy: cfg.Entropy, SystemBus: bus,
		// ADR-008/ADR-009：Gate 进入不可逆 Halted 后第一时间通知连接池吊销全部句柄，再触发外部回调。
		OnHalt: func(info gate.HaltInfo) {
			p.GateHalted(info.Cause())
			if userOnHalt != nil {
				userOnHalt(haltInfoFromGate(info))
			}
		},
	})
	return g, wrapCfgErr("初始化安全门控失败", err)
}
func (e *Engine) initServices(cfg Config) (err error) {
	bridge := &pendingRefBridge{}
	if cfg.Vault != nil {
		if e.credential, err = uccred.NewService(uccred.ServiceConfig{
			Gate: e.gate, Vault: cfg.Vault, VaultControl: cfg.VaultControl, Store: cfg.InventoryStore,
			Interaction: cfg.Interaction, Clock: cfg.Clock, Entropy: cfg.Entropy, PendingRefs: bridge,
		}); err != nil {
			return wrapCfgErr("初始化凭据服务失败", err)
		}
	}
	if e.inventory, err = ucinv.NewService(ucinv.ServiceConfig{
		OpenSSH: cfg.OpenSSH, Env: cfg.Env, GlobalOptions: cfg.GlobalOptions, MaxJumpDepth: cfg.MaxJumpDepth,
		Store: cfg.InventoryStore, Gate: e.gate, Vault: cfg.Vault, VaultControl: cfg.VaultControl,
		KeySigner: cfg.KeySigner, Interaction: cfg.Interaction, Credential: e.credential,
		Clock: cfg.Clock, Entropy: cfg.Entropy, Importers: cfg.Importers, KnownStores: cfg.KnownStores,
		DefaultEnrollTTL: cfg.DefaultEnrollTTL.OrElse(zeroVal[algebraic.Duration]()),
	}); err != nil {
		return wrapCfgErr("初始化资产服务失败", err)
	}
	bridge.inv.Store(e.inventory)
	if e.session, err = ucsess.NewService(ucsess.ServiceConfig{
		Gate: e.gate, Pool: e.pool, Clock: cfg.Clock, Env: cfg.Env, Terminal: cfg.Terminal,
		Escalator: cfg.PrivilegeEscalation, Vault: cfg.Vault, Interaction: cfg.Interaction,
		ShellProbe: cfg.ShellProbe, Forwarder: cfg.Forwarder, TUNDevice: cfg.TUNDevice, MuxSocket: cfg.MuxSocket,
	}); err != nil {
		return wrapCfgErr("初始化会话服务失败", err)
	}
	return e.initTransferAutoObsServices(cfg)
}
func (e *Engine) initTransferAutoObsServices(cfg Config) (err error) {
	if e.transfer, err = uctrans.NewService(uctrans.ServiceConfig{
		Gate: e.gate, Pool: e.pool, Clock: cfg.Clock, Entropy: cfg.Entropy, ScopedFS: cfg.ScopedFS,
		OperatorReadFS: cfg.OperatorReadFS, Journals: cfg.JournalStore, SystemBus: e.bus,
		DefaultChunkSize: cfg.TransferDefaultChunkSize, DefaultMaxReadBytes: cfg.TransferDefaultMaxReadBytes, DefaultConcurrency: cfg.TransferDefaultConcurrency,
	}); err != nil {
		return wrapCfgErr("初始化传输服务失败", err)
	}
	// 派生共享活跃句柄表但物理 0 OperatorReadFS 的 MCP 沙箱传输视图，消除同进程 InspectTransfer 视角分裂。
	e.mcpTransfer = e.transfer.WithoutOperatorReadFS()
	aCfg := ucauto.ServiceConfig{
		Gate: e.gate, Pool: e.pool, Clock: cfg.Clock, Entropy: cfg.Entropy, Env: cfg.Env, ScopedFS: cfg.ScopedFS,
		OperatorReadFS: cfg.OperatorReadFS, Inventory: e.inventory, SystemBus: e.bus, DefaultConcurrency: cfg.AutomationDefaultConcurrency,
		MaxScriptBytes: cfg.AutomationMaxScriptBytes, MaxTemplateBytes: cfg.AutomationMaxTemplateBytes, MaxCopyBytes: cfg.AutomationMaxCopyBytes,
	}
	if e.automation, err = ucauto.NewService(aCfg); err != nil {
		return wrapCfgErr("初始化自动化服务失败", err)
	}
	e.mcpAutomation = e.automation
	if cfg.OperatorReadFS != nil {
		aCfg.OperatorReadFS = nil
		if e.mcpAutomation, err = ucauto.NewService(aCfg); err != nil {
			return wrapCfgErr("初始化 MCP 沙箱自动化服务失败", err)
		}
	}
	e.observability, err = ucobs.NewService(ucobs.ServiceConfig{
		Gate: e.gate, Pool: e.pool, Clock: cfg.Clock, Entropy: cfg.Entropy, Env: cfg.Env,
		ScopedFS: cfg.ScopedFS, Forwarder: cfg.Forwarder, ShellProbe: cfg.ShellProbe, SystemBus: e.bus,
	})
	return wrapCfgErr("初始化可观测性与 GUI 服务失败", err)
}

// ReconcileCrashedAudits 执行启动期 O(1) 跨进程崩溃审计对账（ADR-008 / RFC §3.4）。
func (e *Engine) ReconcileCrashedAudits(ctx context.Context) (ReconcileReport, error) {
	return runOp(e, ctx, func(c context.Context) (ReconcileReport, error) { return e.gate.ReconcileCrashedAudits(c) })
}

// NewOperationStream 从显式熵源分配唯一 TraceID/OperationID，构造单次操作隔离事件流（确定性 EOF）。
func (e *Engine) NewOperationStream(ctx context.Context, buffer int) (*events.OperationStream, error) {
	return runOp(e, ctx, func(context.Context) (*events.OperationStream, error) {
		if buffer < 0 {
			return nil, fmt.Errorf("%w: OperationStream 缓冲容量不能为负", ErrInvalidRequest)
		}
		if buffer == 0 {
			buffer = defaultOperationStreamBuffer
		}
		tid, e1 := trace.NewTraceIDFrom(e.entropy)
		oid, e2 := trace.NewOpIDFrom(e.entropy)
		if err := errors.Join(e1, e2); err != nil {
			return nil, fmt.Errorf("engine: 分配 TraceID/OperationID 失败: %w", err)
		}
		return events.NewOperationStream(events.OperationStreamConfig{TraceID: tid, OperationID: oid, OperationBuffer: buffer})
	})
}

// SystemBus / IsHalted / HaltInfo / IsClosed 提供 Engine 运行态只读查询（未初始化零值严格失败关闭）。
func (e *Engine) SystemBus() *events.SystemBus {
	if e == nil || !e.initialized {
		return nil
	}
	return e.bus
}
func (e *Engine) IsHalted() bool { return e == nil || !e.initialized || e.gate.IsHalted() }
func (e *Engine) HaltInfo() (HaltInfo, bool) {
	if e != nil && e.initialized {
		if info, ok := e.gate.HaltInfo(); ok {
			return haltInfoFromGate(info), true
		}
	}
	return HaltInfo{}, false
}
func (e *Engine) IsClosed() bool {
	if e == nil || !e.initialized {
		return true
	}
	e.opMu.Lock()
	defer e.opMu.Unlock()
	return e.closing
}

// Close 按确定性逆序优雅关闭 Engine（幂等并发安全）：MCPServer & Projection -> UseCases 排空 -> Pool -> 自建 SystemBus。
func (e *Engine) Close(ctx context.Context) error {
	switch {
	case e == nil || !e.initialized:
		return ErrEngineNotInitialized
	case ctx == nil:
		return ErrNilContext
	}
	e.closeOnce.Do(func() { e.closeErr = e.shutdownReverseOrder(ctx) })
	return e.closeErr
}
func takeMapKeys[K comparable](m map[K]struct{}) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	clear(m)
	return out
}
func (e *Engine) shutdownReverseOrder(ctx context.Context) error {
	e.opMu.Lock()
	e.closing = true
	servers, projs := takeMapKeys(e.mcpServers), takeMapKeys(e.projections)
	var waitCh chan struct{}
	if e.inflight > 0 {
		if e.drainCh == nil {
			e.drainCh = make(chan struct{})
		}
		waitCh = e.drainCh
	}
	e.opMu.Unlock()
	var errs []error
	for _, srv := range servers {
		errs = append(errs, srv.Close(ctx))
	}
	for _, proj := range projs {
		errs = append(errs, proj.Close())
	}
	e.opCancel(ErrEngineClosed)
	if waitCh != nil {
		select {
		case <-waitCh:
		case <-ctx.Done():
			errs = append(errs, ctx.Err())
		}
	}
	errs = append(errs, e.pool.Close())
	if e.ownsBus && e.bus != nil {
		e.bus.Close()
	}
	return errors.Join(errs...)
}
func closeStreamIfNonNil(s *events.OperationStream) {
	if s != nil {
		s.Close()
	}
}
func closeOpStreams(main *events.OperationStream, extras map[inventory.NodeID]*events.OperationStream) {
	closeStreamIfNonNil(main)
	for _, s := range extras {
		closeStreamIfNonNil(s)
	}
}

//xops:syncclosure
func runOpStream[T any](e *Engine, ctx context.Context, stream *events.OperationStream, fn func(context.Context) (T, error)) (T, error) {
	defer closeStreamIfNonNil(stream)
	runCtx, cleanup, err := e.beginOp(ctx)
	if err != nil {
		return zeroVal[T](), err
	}
	defer cleanup()
	return mapRes(fn(runCtx))
}

//xops:syncclosure
func runOp[T any](e *Engine, ctx context.Context, fn func(context.Context) (T, error)) (T, error) {
	return runOpStream(e, ctx, nil, fn)
}

//xops:syncclosure
func runOpErr(e *Engine, ctx context.Context, fn func(context.Context) error) error {
	_, err := runOpStream(e, ctx, nil, func(c context.Context) (struct{}, error) { return struct{}{}, fn(c) })
	return err
}

//xops:syncclosure
func runTargetOp[T any](e *Engine, ctx context.Context, rc RemoteCall, fn func(context.Context, ResolvedTarget) (T, error)) (T, error) {
	return runOpStream(e, ctx, rc.OperationStream, func(c context.Context) (T, error) {
		resolved, err := e.resolveTargetRef(c, rc.Target, rc.TargetSpec, rc.CLIOptions)
		if err != nil {
			return zeroVal[T](), err
		}
		return fn(c, resolved)
	})
}
func (e *Engine) beginOp(ctx context.Context) (context.Context, func(), error) {
	switch {
	case e == nil || !e.initialized:
		return nil, nil, ErrEngineNotInitialized
	case ctx == nil:
		return nil, nil, ErrNilContext
	case ctx.Err() != nil:
		return nil, nil, ctx.Err()
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
	stopBridge := context.AfterFunc(e.opCtx, func() { defer close(bridgeDone); cancelRun(context.Cause(e.opCtx)) })
	return runCtx, func() {
		if !stopBridge() {
			<-bridgeDone
		}
		cancelRun(nil)
		e.opMu.Lock()
		e.inflight--
		if e.closing && e.inflight == 0 && e.drainCh != nil {
			close(e.drainCh)
			e.drainCh = nil
		}
		e.opMu.Unlock()
	}, nil
}
func (e *Engine) resolveTargetRef(ctx context.Context, pre ResolvedTarget, spec string, cliOpts option.OptionLayer) (ResolvedTarget, error) {
	return e.resolveTargetForSession(ctx, pre, spec, cliOpts, algebraic.None[option.OriginKind](), nil)
}
