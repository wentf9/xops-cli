package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/ports"
)

// ControlMasterRequest 描述启动或附着 ControlMaster（-M / ControlPersist）的强类型输入（P3-T2）。
// 所有多路复用门控严格从 Plan 末跳的 ControlPolicy.EffectiveMaster() / EffectivePersist() 投影求值。
type ControlMasterRequest struct {
	Plan            plan.SealedConnectionPlan
	NodeID          string
	Risk            algebraic.Option[security.RiskLevel]
	Approval        algebraic.Option[gate.ApprovalSubmission]
	OperationStream *events.OperationStream
}

// ControlMasterInfo 封装 ControlMaster 启动或复用已有主进程的不可变结果；零值恒无效并失败关闭。
//
//xops:opaque
//xops:failclosed
type ControlMasterInfo struct {
	handle                algebraic.Option[plan.ManagedHandle[plan.KindMux]]
	socketPath            pathalg.LocalSourcePath
	reusedExisting, valid bool
	masterPID             uint32
	effectiveMaster       option.ControlMasterMode
	effectivePersist      option.ControlPersistSpec
}

// ControlMasterInfo 零值安全只读访问器。
func (i ControlMasterInfo) IsValid() bool {
	if !i.valid || !i.socketPath.IsValid() || !i.effectiveMaster.IsSet() {
		return false
	}
	if i.reusedExisting {
		return i.handle.IsNone() && i.masterPID > 0
	}
	h, ok := i.handle.Get()
	return ok && h.IsValid()
}
func (i ControlMasterInfo) IsZero() bool { return !i.IsValid() }
func (i ControlMasterInfo) Handle() algebraic.Option[plan.ManagedHandle[plan.KindMux]] {
	return i.handle
}
func (i ControlMasterInfo) SocketPath() pathalg.LocalSourcePath         { return i.socketPath }
func (i ControlMasterInfo) ReusedExisting() bool                        { return i.IsValid() && i.reusedExisting }
func (i ControlMasterInfo) MasterPID() uint32                           { return i.masterPID }
func (i ControlMasterInfo) EffectiveMaster() option.ControlMasterMode   { return i.effectiveMaster }
func (i ControlMasterInfo) EffectivePersist() option.ControlPersistSpec { return i.effectivePersist }

// ControlMasterStatus 表示受管 ControlMaster 句柄的不可变只读状态快照；零值恒无效并失败关闭。
//
//xops:opaque
//xops:failclosed
type ControlMasterStatus struct {
	handleStatus     pool.HandleStatus
	socketPath       pathalg.LocalSourcePath
	effectiveMaster  option.ControlMasterMode
	effectivePersist option.ControlPersistSpec
	active, valid    bool
	err              error
}

func (st ControlMasterStatus) IsValid() bool {
	return st.valid && st.handleStatus.IsValid() && st.socketPath.IsValid()
}
func (st ControlMasterStatus) IsZero() bool                              { return !st.IsValid() }
func (st ControlMasterStatus) HandleStatus() pool.HandleStatus           { return st.handleStatus }
func (st ControlMasterStatus) SocketPath() pathalg.LocalSourcePath       { return st.socketPath }
func (st ControlMasterStatus) EffectiveMaster() option.ControlMasterMode { return st.effectiveMaster }
func (st ControlMasterStatus) EffectivePersist() option.ControlPersistSpec {
	return st.effectivePersist
}
func (st ControlMasterStatus) Active() bool { return st.IsValid() && st.active }
func (st ControlMasterStatus) Err() error   { return st.err }

type muxResource interface {
	pool.ManagedResource
	touch(ctx context.Context)
}

// managedMuxMaster 实现 muxResource、snapshotResource[ControlMasterStatus] 与 pool.ComparableManagedResource，
// 在 core/conc.Nursery 监督下驱动 MuxSocketPort.WithListener + Serve 与确定性 ControlPersist 驻留计时器（0 裸 go、0 ln 逃逸）。
//
//xops:opaque
//xops:failclosed
type managedMuxMaster struct {
	valid, shouldRelease bool
	socketPath           pathalg.LocalSourcePath
	effectiveMaster      option.ControlMasterMode
	effectivePersist     option.ControlPersistSpec
	conn                 ports.TransportConn
	nursery              *conc.Nursery
	activityCh           chan chan struct{}
	doneCh               chan struct{}
	closed               atomic.Bool
	closeOnce            sync.Once
	serveErr             firstErr
	relMu                sync.Mutex
	releaseFn            func()
}

func (s *Service) startManagedMuxMaster(
	leaseCtx, revokeCtx context.Context, conn ports.TransportConn, sockPath pathalg.LocalSourcePath,
	effMaster option.ControlMasterMode, effPersist option.ControlPersistSpec,
) (*managedMuxMaster, error) {
	if err := leaseCtx.Err(); err != nil {
		return nil, err
	}
	n, err := conc.NewNursery(revokeCtx)
	if err != nil {
		return nil, err
	}
	mm := &managedMuxMaster{
		valid: true, socketPath: sockPath, effectiveMaster: effMaster, effectivePersist: effPersist,
		conn: conn, nursery: n, activityCh: make(chan chan struct{}, 1), doneCh: make(chan struct{}),
	}
	readyCh, startErrCh := make(chan struct{}), make(chan error, 1)
	if err := mm.launchMuxWorkers(s.cfg.MuxSocket, s.cfg.Forwarder, s.cfg.Clock, readyCh, startErrCh); err != nil {
		_ = mm.Close()
		return nil, err
	}
	var failErr error
	select {
	case <-readyCh:
		return mm, nil
	case failErr = <-startErrCh:
	case <-leaseCtx.Done():
		failErr = leaseCtx.Err()
	case <-revokeCtx.Done():
		failErr = context.Cause(revokeCtx)
	}
	_ = mm.Close()
	return nil, failErr
}

func (m *managedMuxMaster) launchMuxWorkers(muxPort ports.MuxSocketPort, forwarder ports.ForwarderPort, clk ports.Clock, readyCh chan struct{}, startErrCh chan error) error {
	if err := m.nursery.Go(func(serveCtx context.Context) error {
		defer close(m.doneCh)
		bound := false
		err := muxPort.WithListener(serveCtx, m.socketPath, func(ln net.Listener) error {
			bound = true
			close(readyCh)
			return muxPort.Serve(serveCtx, ln, m.conn, forwarder)
		})
		if !bound {
			select {
			case startErrCh <- firstNonNilErr(err, ErrMuxMasterUnavailable):
			default:
			}
			return err
		}
		if err != nil && !errors.Is(err, context.Canceled) {
			m.serveErr.record(err)
		}
		m.closed.Store(true)
		m.setAutoRelease(nil, true)
		return nil
	}); err != nil {
		return err
	}
	if timeout, ok := m.effectivePersist.Timeout(); ok {
		return m.nursery.Go(func(pCtx context.Context) error { return m.runPersistTimer(pCtx, clk, timeout.Std()) })
	}
	return nil
}

func (m *managedMuxMaster) runPersistTimer(ctx context.Context, clk ports.Clock, idle time.Duration) error {
	tm := clk.NewTimer(idle)
	defer tm.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-m.doneCh:
			return nil
		case ack := <-m.activityCh:
			tm.Reset(idle)
			close(ack)
		case <-tm.C():
			m.serveErr.record(ErrMuxPersistExpired)
			m.nursery.Cancel(ErrMuxPersistExpired)
			m.setAutoRelease(nil, true)
			return nil
		}
	}
}
func (m *managedMuxMaster) touch(ctx context.Context) {
	if _, hasTimeout := m.effectivePersist.Timeout(); !hasTimeout || m == nil || !m.valid || m.closed.Load() {
		return
	}
	ack := make(chan struct{})
	select {
	case m.activityCh <- ack:
	case <-m.doneCh:
		return
	case <-ctx.Done():
		return
	}
	select {
	case <-ack:
	case <-m.doneCh:
	case <-ctx.Done():
	}
}
func (m *managedMuxMaster) setAutoRelease(fn func(), fire bool) {
	m.relMu.Lock()
	var call func()
	if fire {
		call, m.shouldRelease, m.releaseFn = m.releaseFn, true, nil
	} else if m.shouldRelease {
		call = fn
	} else {
		m.releaseFn = fn
	}
	m.relMu.Unlock()
	if call != nil {
		call()
	}
}
func (m *managedMuxMaster) IsValid() bool {
	return m != nil && m.valid && !m.closed.Load() && m.conn != nil && m.conn.IsAlive()
}
func (m *managedMuxMaster) snapshot(hs pool.HandleStatus) ControlMasterStatus {
	return ControlMasterStatus{
		handleStatus: hs, socketPath: m.socketPath, effectiveMaster: m.effectiveMaster,
		effectivePersist: m.effectivePersist, active: hs.Active() && m.IsValid(), err: m.serveErr.get(), valid: true,
	}
}
func (m *managedMuxMaster) Close() error {
	if m == nil || !m.valid {
		return nil
	}
	m.closeOnce.Do(func() {
		m.closed.Store(true)
		m.relMu.Lock()
		m.releaseFn = nil
		m.relMu.Unlock()
		m.nursery.Cancel(ports.ErrClosed)
		m.serveErr.record(errors.Join(m.nursery.Close(), m.conn.Close()))
	})
	return m.serveErr.get()
}

// StartControlMaster 启动受管 ControlMaster（-M / ControlPersist）或在 auto/autoask 模式下复用活跃主进程：
// 严格消费 ControlPolicy.EffectiveMaster() 与 EffectivePersist() 失败关闭投影，绝不绕过 Path 禁用校验。
func (s *Service) StartControlMaster(ctx context.Context, req ControlMasterRequest) (ControlMasterInfo, error) {
	defer closeStream(req.OperationStream)
	if err := s.validateMuxBaseCall(ctx, req.Plan, req.Risk); err != nil {
		return ControlMasterInfo{}, err
	}
	targetHop, nodeID, err := resolvePlanTargetAndNode(req.Plan, req.NodeID)
	if err != nil {
		return ControlMasterInfo{}, err
	}
	cp := targetHop.Transport().ControlPolicy()
	effMaster, effPersist := cp.EffectiveMaster(), cp.EffectivePersist()
	if effMaster == option.ControlMasterNo || effMaster == option.ControlMasterUnset {
		return ControlMasterInfo{}, fmt.Errorf("%w: EffectiveMaster=%s（确认 ControlPath 已启用且 ControlMaster 非 no）", ErrControlMasterDisabled, effMaster)
	}
	sockPath, err := expandControlPath(req.Plan, targetHop, cp.Path(), s.cfg.Env)
	if err != nil {
		return ControlMasterInfo{}, err
	}
	gateReq, err := buildMuxGateReq[security.CapTunnel](req.Plan, targetHop, nodeID, "mux_master_start", sockPath, req.Risk.OrElse(security.RiskModerate), nil, req.Approval, req.OperationStream)
	if err != nil {
		return ControlMasterInfo{}, err
	}
	var info ControlMasterInfo
	_, _, gateErr := runAuthorized[security.CapTunnel](ctx, s, req.Plan.PlanDigest(), nodeID, "mux_master_start", gateReq, req.OperationStream, false,
		func(authCtx context.Context, binding security.OperationBinding, _ *operationEmitter) (execution.ExecutionOutcome, error) {
			return nil, s.execStartControlMaster(authCtx, req.Plan, nodeID, binding, sockPath, effMaster, effPersist, &info)
		})
	if gateErr != nil {
		if h, ok := info.handle.Get(); ok && h.IsValid() {
			_ = pool.ReleaseHandle[plan.KindMux](s.cfg.Pool, h)
		}
		return ControlMasterInfo{}, gateErr
	}
	return info, nil
}

func (s *Service) execStartControlMaster(
	authCtx context.Context, connPlan plan.SealedConnectionPlan, nodeID string, binding security.OperationBinding,
	sockPath pathalg.LocalSourcePath, effMaster option.ControlMasterMode, effPersist option.ControlPersistSpec, outInfo *ControlMasterInfo,
) error {
	if reused, rInfo, rErr := s.tryReuseControlMaster(authCtx, nodeID, sockPath, effMaster, effPersist); rErr != nil || reused {
		*outInfo = rInfo
		return rErr
	}
	if effMaster == option.ControlMasterAsk || effMaster == option.ControlMasterAutoAsk {
		if err := s.confirmMuxMaster(authCtx, nodeID, "Start ControlMaster listener"); err != nil {
			return err
		}
	}
	return s.cfg.Pool.WithLease(authCtx, connPlan, func(leaseCtx context.Context, lease *pool.Lease) error {
		var master *managedMuxMaster
		h, err := pool.RegisterLeaseHandleWith[plan.KindMux](s.cfg.Pool, lease, binding, func(revokeCtx context.Context, conn ports.TransportConn) (*managedMuxMaster, error) {
			mm, mErr := s.startManagedMuxMaster(leaseCtx, revokeCtx, conn, sockPath, effMaster, effPersist)
			master = mm
			return mm, mErr
		})
		if err != nil {
			return err
		}
		if master != nil {
			master.setAutoRelease(func() { _ = pool.ReleaseHandle[plan.KindMux](s.cfg.Pool, h) }, false)
		}
		*outInfo = ControlMasterInfo{handle: algebraic.Some(h), socketPath: sockPath, effectiveMaster: effMaster, effectivePersist: effPersist, valid: true}
		return nil
	})
}

func (s *Service) tryReuseControlMaster(ctx context.Context, nodeID string, sockPath pathalg.LocalSourcePath, effMaster option.ControlMasterMode, effPersist option.ControlPersistSpec) (bool, ControlMasterInfo, error) {
	if effMaster != option.ControlMasterAuto && effMaster != option.ControlMasterAutoAsk {
		return false, ControlMasterInfo{}, nil
	}
	resp, err := s.cfg.MuxSocket.Probe(ctx, sockPath)
	if errors.Is(err, ports.ErrMuxUnavailable) || errors.Is(err, ports.ErrNotFound) || (err == nil && (!resp.IsValid() || !resp.Alive())) {
		return false, ControlMasterInfo{}, nil
	}
	if err != nil {
		return false, ControlMasterInfo{}, err
	}
	if effMaster == option.ControlMasterAutoAsk {
		if err := s.confirmMuxMaster(ctx, nodeID, "Reuse active ControlMaster connection"); err != nil {
			return false, ControlMasterInfo{}, err
		}
	}
	return true, ControlMasterInfo{socketPath: sockPath, reusedExisting: true, masterPID: resp.MasterPID(), effectiveMaster: effMaster, effectivePersist: effPersist, valid: true}, nil
}

func (s *Service) confirmMuxMaster(ctx context.Context, nodeID, message string) error {
	if s.cfg.Interaction == nil || !s.cfg.Interaction.CanInteract() {
		return fmt.Errorf("%w: %w: ControlMaster ask/autoask 需要可交互终端", ErrMuxMasterUnavailable, ports.ErrInteractionUnavailable)
	}
	cReq, err := ports.NewConfirmRequest(ports.ConfirmRequestSpec{Title: "ControlMaster Confirmation", Message: message, Subject: nodeID, Risk: security.RiskModerate})
	if err != nil {
		return err
	}
	if verdict, err := s.cfg.Interaction.Confirm(ctx, cReq); err != nil {
		return fmt.Errorf("%w: %w", ErrMuxMasterUnavailable, err)
	} else if !verdict.Allowed() {
		return fmt.Errorf("%w: 操作员拒绝共享或启动 ControlMaster", ErrMuxMasterUnavailable)
	}
	return nil
}

// InspectControlMaster 返回指定世代 ControlMaster 句柄的只读状态快照。
func (s *Service) InspectControlMaster(ctx context.Context, handle plan.ManagedHandle[plan.KindMux]) (ControlMasterStatus, error) {
	return inspectManagedHandle[plan.KindMux, ControlMasterStatus](ctx, s, handle)
}

// TouchControlMaster 刷新处于 ControlPersist 限时驻留模式的 ControlMaster 空闲计时器。
func (s *Service) TouchControlMaster(ctx context.Context, handle plan.ManagedHandle[plan.KindMux]) error {
	if err := s.validateActiveHandleOp(ctx, handle.IsValid()); err != nil {
		return err
	}
	return pool.WithManagedHandle[plan.KindMux, muxResource](ctx, s.cfg.Pool, handle, func(hCtx context.Context, mm muxResource) error { mm.touch(hCtx); return nil })
}

// StopControlMaster 释放 ControlMaster 句柄、解钉底层跳板并触发监听套接字与服务端有序停机。
func (s *Service) StopControlMaster(ctx context.Context, handle plan.ManagedHandle[plan.KindMux]) error {
	return releaseManagedHandle[plan.KindMux](ctx, s, handle)
}

func expandControlPath(connPlan plan.SealedConnectionPlan, targetHop plan.HopSpec, spec option.ControlPathSpec, env ports.EnvPort) (pathalg.LocalSourcePath, error) {
	if !spec.IsEnabled() {
		return zeroVal[pathalg.LocalSourcePath](), fmt.Errorf("%w: ControlPath 未启用", ErrControlMasterDisabled)
	}
	raw := spec.String()
	if !spec.IsLiteral() {
		tokCtx := option.TokenContext{
			TargetHost: targetHop.Endpoint().Host().String(), Port: targetHop.Endpoint().Port(),
			RemoteUser: targetHop.Username().String(), OriginalHost: targetHop.OriginalHost().String(),
			JumpHost: extractJumpHostForPercentJ(connPlan, targetHop),
		}
		if env != nil {
			if id, err := env.LookupLocalIdentity(); err == nil && id.IsValid() {
				tokCtx = id.ApplyToTokenContext(tokCtx)
			}
		}
		expanded, err := option.ExpandPathTokens(raw, tokCtx)
		if err != nil {
			return zeroVal[pathalg.LocalSourcePath](), fmt.Errorf("%w: 展开 ControlPath 模板失败: %w", ErrInvalidRequest, err)
		}
		if strings.HasPrefix(expanded, "~/") && tokCtx.HomeDir != "" {
			expanded = strings.TrimRight(tokCtx.HomeDir, "/") + expanded[1:]
		}
		raw = expanded
	}
	p, err := pathalg.ParseLocalSourcePath(raw)
	if err != nil {
		return zeroVal[pathalg.LocalSourcePath](), fmt.Errorf("%w: 非法控制套接字路径 %q: %w", ErrInvalidRequest, raw, err)
	}
	return p, nil
}

func extractJumpHostForPercentJ(connPlan plan.SealedConnectionPlan, targetHop plan.HopSpec) string {
	switch route := targetHop.Transport().ProxyRoute().(type) {
	case *option.ProxyJumpChain:
		if route.IsValid() {
			hops := route.Hops().Slice()
			return hops[len(hops)-1].Host()
		}
	case *option.ProxyUnset, *option.ProxyDisabled, *option.ProxyCommandSpec:
		if connPlan.Len() >= 2 {
			if prev, ok := connPlan.HopAt(connPlan.Len() - 2); ok {
				return prev.Endpoint().Host().String()
			}
		}
	default:
		return ""
	}
	return ""
}
