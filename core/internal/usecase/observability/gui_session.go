package observability

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/ports"
)

// OpenGUISession 在 CapTunnel 门控与 pool.RegisterLeaseHandleWith 监督下建立受管 X11/VNC 隧道会话，
// 强制端口与套接字路径强校验、默认仅绑定本机回环并支持 Gate Halted 即时吊销（0 goroutine 泄漏）。
func (s *Service) OpenGUISession(ctx context.Context, req OpenGUISessionRequest) (GUISessionInfo, error) {
	defer closeStream(req.OperationStream)
	targetHop, fwdSpec, bindHost, remoteDesc, nonLoopback, err := s.validateOpenGUISession(ctx, req)
	if err != nil {
		return GUISessionInfo{}, err
	}
	nodeID := resolveNodeID(targetHop, req.NodeID)
	gateReq, err := buildGUISessionGateRequest(req, targetHop, nodeID, bindHost, fwdSpec.BindAddr(), remoteDesc, nonLoopback)
	if err != nil {
		return GUISessionInfo{}, err
	}
	var handle plan.ManagedHandle[plan.KindTunnel]
	var boundAddr string
	_, gateErr := runAuthorized[security.CapTunnel](ctx, s, req.Plan.PlanDigest(), nodeID, "gui_session_open", gateReq, req.OperationStream,
		func(authCtx context.Context, authBind security.OperationBinding, _ *obsEmitter) (execution.ExecutionOutcome, error) {
			err := s.pool.WithLease(authCtx, req.Plan, func(leaseCtx context.Context, lease *pool.Lease) error {
				var rErr error
				handle, rErr = pool.RegisterLeaseHandleWith[plan.KindTunnel](s.pool, lease, authBind, func(revokeCtx context.Context, conn ports.TransportConn) (*managedGUITunnel, error) {
					mt, sErr := startManagedGUITunnel(leaseCtx, revokeCtx, s.forwarder, conn, fwdSpec, req.Spec.Kind, req.Spec.DisplayNum, remoteDesc)
					if sErr == nil {
						boundAddr = mt.boundAddr
					}
					return mt, sErr
				})
				return rErr
			})
			return nil, err
		})
	if gateErr != nil {
		if handle.IsValid() {
			_ = pool.ReleaseHandle[plan.KindTunnel](s.pool, handle)
		}
		return GUISessionInfo{}, gateErr
	}
	return GUISessionInfo{handle: handle, kind: req.Spec.Kind, display: req.Spec.DisplayNum, boundAddr: boundAddr, remoteEnd: remoteDesc, valid: true}, nil
}

func buildGUISessionGateRequest(req OpenGUISessionRequest, hop plan.HopSpec, nodeID, bindHost, bindAddr, remoteDesc string, nonLoopback bool) (gate.GateRequest[security.CapTunnel], error) {
	defaultRisk := pickIf(nonLoopback, security.RiskDangerous, security.RiskModerate)
	binding, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityTunnel, Tool: toolObservability, Action: "gui_session_open",
		NodeID: nodeID, Endpoint: algebraic.Some(hop.Endpoint()),
		PlanDigest: algebraic.Some(req.Plan.PlanDigest().SecurityDigest()),
		Parameters: map[string]string{
			"kind": req.Spec.Kind.String(), "display": strconv.Itoa(req.Spec.DisplayNum),
			"bind_host": bindHost, "remote": remoteDesc, "non_loopback": strconv.FormatBool(nonLoopback),
		},
	})
	if err != nil {
		return zeroVal[gate.GateRequest[security.CapTunnel]](), err
	}
	return gate.NewGateRequest[security.CapTunnel](gate.GateRequestSpec[security.CapTunnel]{
		Binding: binding, Risk: req.Risk.OrElse(defaultRisk),
		ScopeSummary: fmt.Sprintf("open %s GUI session :%d on %s (%s -> %s)", req.Spec.Kind, req.Spec.DisplayNum, nodeID, bindAddr, remoteDesc),
		Approval:     req.Approval, OperationStream: req.OperationStream,
	})
}

type guiTunnelSnapshotter interface {
	pool.ManagedResource
	snapshot(hs pool.HandleStatus) GUISessionStatus
}

// InspectGUISession 查询受管 GUI 会话句柄的不可变状态快照；Gate Halted 态立即拒绝。
func (s *Service) InspectGUISession(ctx context.Context, handle plan.ManagedHandle[plan.KindTunnel]) (GUISessionStatus, error) {
	if err := s.checkReady(ctx); err != nil {
		return GUISessionStatus{}, err
	}
	if !handle.IsValid() {
		return GUISessionStatus{}, pool.ErrInvalidHandle
	}
	hs, err := pool.InspectHandle[plan.KindTunnel](s.pool, handle)
	if err != nil {
		return GUISessionStatus{}, err
	}
	var status GUISessionStatus
	err = pool.WithManagedHandle[plan.KindTunnel, guiTunnelSnapshotter](ctx, s.pool, handle, func(_ context.Context, mt guiTunnelSnapshotter) error {
		status = mt.snapshot(hs)
		return nil
	})
	return status, err
}

// CloseGUISession 显式释放受管 GUI 会话句柄并有界关闭底层转发与守护协程。
func (s *Service) CloseGUISession(ctx context.Context, handle plan.ManagedHandle[plan.KindTunnel]) error {
	if s == nil || !s.valid {
		return ErrServiceNotInitialized
	}
	if ctx == nil {
		return ErrNilContext
	}
	if !handle.IsValid() {
		return pool.ErrInvalidHandle
	}
	return pool.ReleaseHandle[plan.KindTunnel](s.pool, handle)
}

func (s *Service) validateOpenGUISession(ctx context.Context, req OpenGUISessionRequest) (plan.HopSpec, ports.ForwardSpec, string, string, bool, error) {
	hop, err := s.validatePlanCall(ctx, req.Plan, req.Risk)
	if err != nil {
		return zeroVal[plan.HopSpec](), zeroVal[ports.ForwardSpec](), "", "", false, err
	}
	if s.forwarder == nil {
		return zeroVal[plan.HopSpec](), zeroVal[ports.ForwardSpec](), "", "", false, ErrForwarderUnavailable
	}
	if !req.Spec.Kind.IsValid() || req.Spec.DisplayNum < 0 || req.Spec.DisplayNum > maxGUIDisplayNum {
		return zeroVal[plan.HopSpec](), zeroVal[ports.ForwardSpec](), "", "", false, fmt.Errorf("%w: GUI 会话协议或显示编号越界 [0,%d]", ErrInvalidGUIInput, maxGUIDisplayNum)
	}
	bindHost := pickIf(req.Spec.LocalBindHost == "", "127.0.0.1", req.Spec.LocalBindHost)
	addr, pErr := netip.ParseAddr(bindHost)
	if pErr != nil {
		return zeroVal[plan.HopSpec](), zeroVal[ports.ForwardSpec](), "", "", false, fmt.Errorf("%w: LocalBindHost 必须为合法 IP 字面量", ErrInvalidGUIInput)
	}
	nonLoopback := !addr.IsLoopback()
	if nonLoopback && !req.Spec.AllowNonLoopbackBind {
		return zeroVal[plan.HopSpec](), zeroVal[ports.ForwardSpec](), "", "", false, fmt.Errorf("%w: 默认禁止非回环地址 %s 绑定", ErrInvalidGUIInput, bindHost)
	}
	bindAddr := netip.AddrPortFrom(addr, req.Spec.LocalBindPort).String()
	fwdSpec, remoteDesc, err := buildGUISessionForwardSpec(req.Spec, bindAddr)
	return hop, fwdSpec, bindHost, remoteDesc, nonLoopback, err
}

func buildGUISessionForwardSpec(spec GUISessionSpec, bindAddr string) (ports.ForwardSpec, string, error) {
	if spec.Kind == GUISessionX11 && spec.UseUnixSocket {
		sockPath := fmt.Sprintf("/tmp/.X11-unix/X%d", spec.DisplayNum)
		fs, err := ports.NewTypedForwardSpec(ports.ForwardLocal, ports.ForwardEndpointTCP, bindAddr, ports.ForwardEndpointUnix, sockPath)
		return fs, sockPath, err
	}
	basePort := pickIf(spec.Kind == GUISessionX11, 6000, 5900)
	remote := fmt.Sprintf("127.0.0.1:%d", basePort+spec.DisplayNum)
	fs, err := ports.NewTypedForwardSpec(ports.ForwardLocal, ports.ForwardEndpointTCP, bindAddr, ports.ForwardEndpointTCP, remote)
	return fs, remote, err
}

// managedGUITunnel 包装受管 ForwardHandle 与池钉选连接，并在 conc.Nursery 监督下响应吊销即时关闭。
//
//xops:opaque
//xops:failclosed
type managedGUITunnel struct {
	valid                 bool
	kind                  GUISessionKind
	display               int
	boundAddr, remoteDesc string
	handle                ports.ForwardHandle
	conn                  ports.TransportConn
	nursery               *conc.Nursery
	closed                atomic.Bool
	closeOnce, resOnce    sync.Once
	errMu                 sync.Mutex
	err                   error
}

func startManagedGUITunnel(leaseCtx, revokeCtx context.Context, fwd ports.ForwarderPort, conn ports.TransportConn, spec ports.ForwardSpec, kind GUISessionKind, display int, remoteDesc string) (*managedGUITunnel, error) {
	if err := leaseCtx.Err(); err != nil {
		return nil, err
	}
	fh, err := fwd.StartForward(revokeCtx, conn, spec)
	if err != nil {
		return nil, err
	}
	if fh == nil || !fh.IsValid() || fh.BoundAddr() == "" {
		if fh != nil {
			_ = fh.Close()
		}
		return nil, fmt.Errorf("%w: ForwarderPort 返回无效 ForwardHandle", ErrInvalidRequest)
	}
	n, err := conc.NewNursery(revokeCtx)
	if err != nil {
		_ = fh.Close()
		return nil, err
	}
	mt := &managedGUITunnel{valid: true, kind: kind, display: display, boundAddr: fh.BoundAddr(), remoteDesc: remoteDesc, handle: fh, conn: conn, nursery: n}
	if err := n.Go(func(wCtx context.Context) error {
		defer mt.closeResources()
		select {
		case <-wCtx.Done():
		case <-fh.Done():
		}
		return nil
	}); err != nil {
		_ = mt.Close()
		return nil, err
	}
	return mt, nil
}

func (m *managedGUITunnel) IsValid() bool { return m != nil && m.valid }
func (m *managedGUITunnel) recordErr(err error) {
	if err != nil {
		m.errMu.Lock()
		if m.err == nil {
			m.err = err
		}
		m.errMu.Unlock()
	}
}
func (m *managedGUITunnel) snapshot(hs pool.HandleStatus) GUISessionStatus {
	m.errMu.Lock()
	err := firstErr(m.handle.Err(), m.err)
	m.errMu.Unlock()
	return GUISessionStatus{
		handleStatus: hs, kind: m.kind, display: m.display, boundAddr: m.boundAddr,
		remoteEnd: m.remoteDesc, active: hs.Active() && !m.closed.Load() && m.handle.IsValid(), err: err, valid: true,
	}
}
func (m *managedGUITunnel) closeResources() {
	m.resOnce.Do(func() {
		m.closed.Store(true)
		m.recordErr(errors.Join(m.handle.Close(), m.conn.Close()))
	})
}
func (m *managedGUITunnel) Close() error {
	if m == nil || !m.valid {
		return nil
	}
	m.closeOnce.Do(func() {
		m.nursery.Cancel(ports.ErrClosed)
		m.closeResources()
		m.recordErr(m.nursery.Close())
	})
	m.errMu.Lock()
	defer m.errMu.Unlock()
	return m.err
}
