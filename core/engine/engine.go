package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"

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
// Close(ctx) 按确定性逆序关闭：派生 MCPServer -> 在途 UseCase 排空 -> 连接池 Pool -> 自建 SystemBus。
//
//xops:opaque
//xops:failclosed
type Engine struct {
	initialized bool // 非指针正向有效门控（满足 xopsvet/failclosed 零值最严约束）

	clock    ports.Clock
	entropy  ports.Entropy
	scopedFS ports.ScopedRootFS
	bus      *events.SystemBus
	ownsBus  bool

	pool          *pool.Pool
	gate          *gate.Gate
	inventory     *ucinv.Service
	credential    *uccred.Service
	session       *ucsess.Service
	transfer      *uctrans.Service
	mcpTransfer   *uctrans.Service // 物理 0 OperatorReadFS，专供 MCP 运行时
	automation    *ucauto.Service
	mcpAutomation *ucauto.Service // 物理 0 OperatorReadFS，专供 MCP 运行时
	observability *ucobs.Service

	opCtx      context.Context
	opCancel   context.CancelCauseFunc
	opMu       sync.Mutex
	closing    bool
	inflight   int
	drainCh    chan struct{}
	mcpServers map[*MCPServer]struct{}
	closeOnce  sync.Once
	closeErr   error
}

type engineServices struct {
	inventory     *ucinv.Service
	credential    *uccred.Service
	session       *ucsess.Service
	transfer      *uctrans.Service
	mcpTransfer   *uctrans.Service
	automation    *ucauto.Service
	mcpAutomation *ucauto.Service
	observability *ucobs.Service
}

type pendingRefBridge struct {
	mu  sync.Mutex
	inv *ucinv.Service
}

func (b *pendingRefBridge) ActivePendingSecretRefs() []inventory.PendingSecretRef {
	b.mu.Lock()
	inv := b.inv
	b.mu.Unlock()
	if inv == nil {
		return nil
	}
	return inv.ActivePendingSecretRefs()
}

// New 校验配置与出站依赖，装配拨号器、连接池、安全门控（OnHalt -> pool.GateHalted）及全部 6 大用例服务与 MCP 沙箱服务。
// 任意步骤失败均同步回滚已建后台资源，保证零 goroutine 泄漏。
func New(cfg Config) (*Engine, error) {
	profile, policy, err := validateBaseConfig(cfg)
	if err != nil {
		return nil, err
	}
	dialer, err := buildDialerPort(cfg)
	if err != nil {
		return nil, err
	}
	bus, ownsBus, err := resolveSystemBus(cfg)
	if err != nil {
		return nil, err
	}
	rollback := func(p *pool.Pool) {
		if p != nil {
			_ = p.Close()
		}
		if ownsBus && bus != nil {
			bus.Close()
		}
	}
	pCfg, err := buildPoolConfig(cfg, dialer, bus)
	if err != nil {
		rollback(nil)
		return nil, err
	}
	p, err := pool.NewPool(context.Background(), pCfg)
	if err != nil {
		rollback(nil)
		return nil, fmt.Errorf("%w: 初始化连接池失败: %w", ErrInvalidConfig, err)
	}
	g, err := buildEngineGate(cfg, profile, policy, bus, p)
	if err != nil {
		rollback(p)
		return nil, err
	}
	svcs, err := buildEngineServices(cfg, g, p, bus)
	if err != nil {
		rollback(p)
		return nil, err
	}
	opCtx, opCancel := context.WithCancelCause(context.Background())
	return &Engine{
		initialized: true, clock: cfg.Clock, entropy: cfg.Entropy, scopedFS: cfg.ScopedFS,
		bus: bus, ownsBus: ownsBus, pool: p, gate: g,
		inventory: svcs.inventory, credential: svcs.credential, session: svcs.session,
		transfer: svcs.transfer, mcpTransfer: svcs.mcpTransfer,
		automation: svcs.automation, mcpAutomation: svcs.mcpAutomation, observability: svcs.observability,
		opCtx: opCtx, opCancel: opCancel, mcpServers: make(map[*MCPServer]struct{}),
	}, nil
}

func resolveSystemBus(cfg Config) (*events.SystemBus, bool, error) {
	if cfg.SystemBus != nil {
		return cfg.SystemBus, false, nil
	}
	buf := cfg.SystemBusBuffer
	if buf == 0 {
		buf = defaultSystemBusBuffer
	}
	bus, err := events.NewSystemBus(events.SystemBusConfig{DefaultSubscriberBuffer: buf})
	if err != nil {
		return nil, false, fmt.Errorf("%w: 创建默认 SystemBus 失败: %w", ErrInvalidConfig, err)
	}
	return bus, true, nil
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
	if err != nil {
		return nil, fmt.Errorf("%w: 初始化安全门控失败: %w", ErrInvalidConfig, err)
	}
	return g, nil
}

func buildEngineServices(cfg Config, g *gate.Gate, p *pool.Pool, bus *events.SystemBus) (engineServices, error) {
	var out engineServices
	bridge := &pendingRefBridge{}
	if cfg.Vault != nil {
		credSvc, err := uccred.NewService(uccred.ServiceConfig{
			Gate: g, Vault: cfg.Vault, VaultControl: cfg.VaultControl, Store: cfg.InventoryStore,
			Interaction: cfg.Interaction, Clock: cfg.Clock, Entropy: cfg.Entropy, PendingRefs: bridge,
		})
		if err != nil {
			return out, fmt.Errorf("%w: 初始化凭据服务失败: %w", ErrInvalidConfig, err)
		}
		out.credential = credSvc
	}
	invSvc, err := ucinv.NewService(ucinv.ServiceConfig{
		OpenSSH: cfg.OpenSSH, Env: cfg.Env, GlobalOptions: cfg.GlobalOptions, MaxJumpDepth: cfg.MaxJumpDepth,
		Store: cfg.InventoryStore, Gate: g, Vault: cfg.Vault, VaultControl: cfg.VaultControl,
		KeySigner: cfg.KeySigner, Interaction: cfg.Interaction, Credential: out.credential,
		Clock: cfg.Clock, Entropy: cfg.Entropy, Importers: cfg.Importers, KnownStores: cfg.KnownStores,
		DefaultEnrollTTL: cfg.DefaultEnrollTTL.OrElse(zeroVal[algebraic.Duration]()),
	})
	if err != nil {
		return out, fmt.Errorf("%w: 初始化资产服务失败: %w", ErrInvalidConfig, err)
	}
	bridge.mu.Lock()
	bridge.inv = invSvc
	bridge.mu.Unlock()
	out.inventory = invSvc

	if out.session, err = ucsess.NewService(ucsess.ServiceConfig{
		Gate: g, Pool: p, Clock: cfg.Clock, Env: cfg.Env, Terminal: cfg.Terminal,
		Escalator: cfg.PrivilegeEscalation, Vault: cfg.Vault, Interaction: cfg.Interaction,
		ShellProbe: cfg.ShellProbe, Forwarder: cfg.Forwarder, TUNDevice: cfg.TUNDevice, MuxSocket: cfg.MuxSocket,
	}); err != nil {
		return out, fmt.Errorf("%w: 初始化会话服务失败: %w", ErrInvalidConfig, err)
	}
	if err = buildTransferAutoObsServices(cfg, g, p, bus, invSvc, &out); err != nil {
		return out, err
	}
	return out, nil
}

func buildTransferAutoObsServices(
	cfg Config, g *gate.Gate, p *pool.Pool, bus *events.SystemBus, invSvc *ucinv.Service, out *engineServices,
) error {
	tCfg := uctrans.ServiceConfig{
		Gate: g, Pool: p, Clock: cfg.Clock, Entropy: cfg.Entropy, ScopedFS: cfg.ScopedFS,
		OperatorReadFS: cfg.OperatorReadFS, Journals: cfg.JournalStore, SystemBus: bus,
		DefaultChunkSize: cfg.TransferDefaultChunkSize, DefaultMaxReadBytes: cfg.TransferDefaultMaxReadBytes, DefaultConcurrency: cfg.TransferDefaultConcurrency,
	}
	var err error
	if out.transfer, err = uctrans.NewService(tCfg); err != nil {
		return fmt.Errorf("%w: 初始化传输服务失败: %w", ErrInvalidConfig, err)
	}
	out.mcpTransfer = out.transfer
	if cfg.OperatorReadFS != nil {
		tCfg.OperatorReadFS = nil
		if out.mcpTransfer, err = uctrans.NewService(tCfg); err != nil {
			return fmt.Errorf("%w: 初始化 MCP 沙箱传输服务失败: %w", ErrInvalidConfig, err)
		}
	}
	aCfg := ucauto.ServiceConfig{
		Gate: g, Pool: p, Clock: cfg.Clock, Entropy: cfg.Entropy, Env: cfg.Env, ScopedFS: cfg.ScopedFS,
		OperatorReadFS: cfg.OperatorReadFS, Inventory: invSvc, SystemBus: bus, DefaultConcurrency: cfg.AutomationDefaultConcurrency,
		MaxScriptBytes: cfg.AutomationMaxScriptBytes, MaxTemplateBytes: cfg.AutomationMaxTemplateBytes, MaxCopyBytes: cfg.AutomationMaxCopyBytes,
	}
	if out.automation, err = ucauto.NewService(aCfg); err != nil {
		return fmt.Errorf("%w: 初始化自动化服务失败: %w", ErrInvalidConfig, err)
	}
	out.mcpAutomation = out.automation
	if cfg.OperatorReadFS != nil {
		aCfg.OperatorReadFS = nil
		if out.mcpAutomation, err = ucauto.NewService(aCfg); err != nil {
			return fmt.Errorf("%w: 初始化 MCP 沙箱自动化服务失败: %w", ErrInvalidConfig, err)
		}
	}
	if out.observability, err = ucobs.NewService(ucobs.ServiceConfig{
		Gate: g, Pool: p, Clock: cfg.Clock, Entropy: cfg.Entropy, Env: cfg.Env,
		ScopedFS: cfg.ScopedFS, Forwarder: cfg.Forwarder, ShellProbe: cfg.ShellProbe, SystemBus: bus,
	}); err != nil {
		return fmt.Errorf("%w: 初始化可观测性与 GUI 服务失败: %w", ErrInvalidConfig, err)
	}
	return nil
}

// ReconcileCrashedAudits 执行启动期 O(1) 跨进程崩溃审计对账（ADR-008 / RFC §3.4）。
func (e *Engine) ReconcileCrashedAudits(ctx context.Context) (ReconcileReport, error) {
	return runOp(e, ctx, func(runCtx context.Context) (ReconcileReport, error) {
		raw, err := e.gate.ReconcileCrashedAudits(runCtx)
		if err != nil {
			return ReconcileReport{}, err
		}
		return ReconcileReport{raw: raw, valid: true}, nil
	})
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
		tid, err := trace.NewTraceIDFrom(e.entropy)
		if err != nil {
			return nil, fmt.Errorf("engine: 分配 TraceID 失败: %w", err)
		}
		oid, err := trace.NewOpIDFrom(e.entropy)
		if err != nil {
			return nil, fmt.Errorf("engine: 分配 OperationID 失败: %w", err)
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
	closed := e.closing
	e.opMu.Unlock()
	return closed
}

// Close 按确定性逆序优雅关闭 Engine（幂等并发安全）：MCPServer -> UseCases 排空 -> Pool -> 自建 SystemBus。
func (e *Engine) Close(ctx context.Context) error {
	if e == nil || !e.initialized {
		return ErrEngineNotInitialized
	}
	if ctx == nil {
		return ErrNilContext
	}
	e.closeOnce.Do(func() { e.closeErr = e.shutdownReverseOrder(ctx) })
	return e.closeErr
}

func (e *Engine) shutdownReverseOrder(ctx context.Context) error {
	e.opMu.Lock()
	e.closing = true
	var servers []*MCPServer
	for srv := range e.mcpServers {
		servers = append(servers, srv)
	}
	clear(e.mcpServers)
	var waitCh chan struct{}
	if e.inflight > 0 {
		if e.drainCh == nil {
			e.drainCh = make(chan struct{})
		}
		waitCh = e.drainCh
	}
	e.opMu.Unlock()

	var mcpErrs []error
	for _, srv := range servers {
		mcpErrs = append(mcpErrs, srv.Close(ctx))
	}
	e.opCancel(ErrEngineClosed)

	var drainErr error
	if waitCh != nil {
		select {
		case <-waitCh:
		case <-ctx.Done():
			drainErr = ctx.Err()
		}
	}
	poolErr := e.pool.Close()
	if e.ownsBus && e.bus != nil {
		e.bus.Close()
	}
	return errors.Join(append(mcpErrs, drainErr, poolErr)...)
}

//xops:syncclosure
func runOp[T any](e *Engine, ctx context.Context, fn func(context.Context) (T, error)) (T, error) {
	runCtx, cleanup, err := e.beginOp(ctx)
	if err != nil {
		return zeroVal[T](), err
	}
	defer cleanup()
	out, err := fn(runCtx)
	return out, mapGateError(err)
}

//xops:syncclosure
func runOpErr(e *Engine, ctx context.Context, fn func(context.Context) error) error {
	_, err := runOp(e, ctx, func(c context.Context) (struct{}, error) { return struct{}{}, fn(c) })
	return err
}

//xops:syncclosure
func runTargetOp[T any](e *Engine, ctx context.Context, target TargetInput, fn func(context.Context, ResolvedTarget) (T, error)) (T, error) {
	return runOp(e, ctx, func(c context.Context) (T, error) {
		resolved, err := e.resolveTargetRef(c, target.Target, target.TargetSpec, target.CLIOptions)
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
	stopBridge := context.AfterFunc(e.opCtx, func() {
		defer close(bridgeDone)
		cancelRun(context.Cause(e.opCtx))
	})
	cleanup := func() {
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
	}
	return runCtx, cleanup, nil
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
	if _, isCh := errors.AsType[*gate.ApprovalChallengeError](err); isCh || errors.Is(err, gate.ErrApprovalRequired) {
		return fmt.Errorf("%w: %w", ErrApprovalRequired, err)
	}
	return err
}

func (e *Engine) resolveTargetRef(ctx context.Context, pre ResolvedTarget, spec string, cliOpts option.OptionLayer) (ResolvedTarget, error) {
	return e.resolveTargetForSession(ctx, pre, spec, cliOpts, algebraic.None[option.OriginKind](), nil)
}
