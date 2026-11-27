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
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/ports"
)

// OpenGUISession 在 CapTunnel 门控与 pool.RegisterLeaseHandleWith 监督下建立受管 X11/VNC 隧道会话，
// 强制端口与套接字路径强校验、默认仅绑定本机回环并支持 Gate Halted 即时吊销（0 goroutine 泄漏）。
type guiSessionPrepared struct {
	hop                  plan.HopSpec
	fwdSpec              ports.ForwardSpec
	bindHost, remoteDesc string
	nonLoopback          bool
}

func (s *Service) OpenGUISession(ctx context.Context, req OpenGUISessionRequest) (GUISessionInfo, error) {
	defer closeStream(req.OperationStream)
	prep, err := s.validateOpenGUISession(ctx, req)
	if err != nil {
		return GUISessionInfo{}, err
	}
	nodeID := resolveNodeID(prep.hop, req.NodeID)
	gateReq, err := buildGUISessionGateRequest(req, prep.hop, nodeID, prep.bindHost, prep.fwdSpec.BindAddr(), prep.remoteDesc, prep.nonLoopback)
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
					mt, sErr := startManagedGUITunnel(leaseCtx, revokeCtx, s.forwarder, conn, prep.fwdSpec, req.Spec.Kind, req.Spec.DisplayNum, prep.remoteDesc)
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
	return GUISessionInfo{handle: handle, kind: req.Spec.Kind, display: req.Spec.DisplayNum, boundAddr: boundAddr, remoteEnd: prep.remoteDesc, valid: true}, nil
}

func buildGUISessionGateRequest(req OpenGUISessionRequest, hop plan.HopSpec, nodeID, bindHost, bindAddr, remoteDesc string, nonLoopback bool) (gate.GateRequest[security.CapTunnel], error) {
	return newObsGateReq[security.CapTunnel](security.OperationBindingSpec{
		Capability: security.CapabilityTunnel, Tool: toolObservability, Action: "gui_session_open",
		NodeID: nodeID, Endpoint: algebraic.Some(hop.Endpoint()), PlanDigest: algebraic.Some(req.Plan.PlanDigest().SecurityDigest()),
		Parameters: map[string]string{
			"kind": req.Spec.Kind.String(), "display": strconv.Itoa(req.Spec.DisplayNum),
			"bind_host": bindHost, "bind_port": strconv.FormatUint(uint64(req.Spec.LocalBindPort), 10),
			"bind_addr": bindAddr, "use_unix_socket": strconv.FormatBool(req.Spec.UseUnixSocket),
			"remote": remoteDesc, "non_loopback": strconv.FormatBool(nonLoopback),
		},
	}, req.Risk.OrElse(pickIf(nonLoopback, security.RiskDangerous, security.RiskModerate)),
		fmt.Sprintf("open %s GUI session :%d on %s (%s -> %s)", req.Spec.Kind, req.Spec.DisplayNum, nodeID, bindAddr, remoteDesc),
		nil, nil, req.Approval, req.OperationStream)
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
	switch {
	case s == nil || !s.valid:
		return ErrServiceNotInitialized
	case ctx == nil:
		return ErrNilContext
	case !handle.IsValid():
		return pool.ErrInvalidHandle
	default:
		return pool.ReleaseHandle[plan.KindTunnel](s.pool, handle)
	}
}
func (s *Service) validateOpenGUISession(ctx context.Context, req OpenGUISessionRequest) (guiSessionPrepared, error) {
	hop, err := s.validatePlanCall(ctx, req.Plan, req.Risk)
	if err != nil {
		return guiSessionPrepared{}, err
	}
	if s.forwarder == nil {
		return guiSessionPrepared{}, ErrForwarderUnavailable
	}
	if !req.Spec.Kind.IsValid() || req.Spec.DisplayNum < 0 || req.Spec.DisplayNum > maxGUIDisplayNum {
		return guiSessionPrepared{}, domi18n.EF(ErrInvalidGUIInput, domi18n.KeyCommonFieldRange, domi18n.Str("field", "display_num"), domi18n.Int("value", req.Spec.DisplayNum), domi18n.Int("min", 0), domi18n.Int("max", maxGUIDisplayNum))
	}
	bindHost := pickIf(req.Spec.LocalBindHost == "", "127.0.0.1", req.Spec.LocalBindHost)
	addr, pErr := netip.ParseAddr(bindHost)
	if pErr != nil {
		return guiSessionPrepared{}, domi18n.EF(ErrInvalidGUIInput, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "LocalBindHost"), domi18n.BoundStr("value", bindHost))
	}
	nonLoopback := !addr.IsLoopback()
	if nonLoopback && !req.Spec.AllowNonLoopbackBind {
		return guiSessionPrepared{}, domi18n.EF(ErrInvalidGUIInput, domi18n.KeyUCObsNonLoopback, domi18n.BoundStr("addr", bindHost))
	}
	fwdSpec, remoteDesc, err := buildGUISessionForwardSpec(req.Spec, netip.AddrPortFrom(addr, req.Spec.LocalBindPort).String())
	if err != nil {
		return guiSessionPrepared{}, err
	}
	return guiSessionPrepared{hop: hop, fwdSpec: fwdSpec, bindHost: bindHost, remoteDesc: remoteDesc, nonLoopback: nonLoopback}, nil
}
func buildGUISessionForwardSpec(spec GUISessionSpec, bindAddr string) (ports.ForwardSpec, string, error) {
	if spec.UseUnixSocket {
		if spec.Kind != GUISessionX11 {
			return zeroVal[ports.ForwardSpec](), "", domi18n.EF(ErrInvalidGUIInput, domi18n.KeyUCObsVNCUnixSocketUnsup)
		}
		sockPath := fmt.Sprintf("/tmp/.X11-unix/X%d", spec.DisplayNum)
		fs, err := ports.NewTypedForwardSpec(ports.ForwardLocal, ports.ForwardEndpointTCP, bindAddr, ports.ForwardEndpointUnix, sockPath)
		return fs, sockPath, err
	}
	remote := fmt.Sprintf("127.0.0.1:%d", pickIf(spec.Kind == GUISessionX11, 6000, 5900)+spec.DisplayNum)
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
		return nil, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "ForwardHandle"))
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
	if err == nil {
		return
	}
	m.errMu.Lock()
	if m.err == nil {
		m.err = err
	}
	m.errMu.Unlock()
}
func (m *managedGUITunnel) snapshot(hs pool.HandleStatus) GUISessionStatus {
	m.errMu.Lock()
	err := firstErr(m.handle.Err(), m.err)
	m.errMu.Unlock()
	return GUISessionStatus{handleStatus: hs, kind: m.kind, display: m.display, boundAddr: m.boundAddr, remoteEnd: m.remoteDesc, active: hs.Active() && !m.closed.Load() && m.handle.IsValid(), err: err, valid: true}
}
func (m *managedGUITunnel) closeResources() {
	m.resOnce.Do(func() { m.closed.Store(true); m.recordErr(errors.Join(m.handle.Close(), m.conn.Close())) })
}
func (m *managedGUITunnel) Close() error {
	if !m.IsValid() {
		return nil
	}
	m.closeOnce.Do(func() { m.nursery.Cancel(ports.ErrClosed); m.closeResources(); m.recordErr(m.nursery.Close()) })
	m.errMu.Lock()
	defer m.errMu.Unlock()
	return m.err
}
