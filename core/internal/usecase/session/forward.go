package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/ports"
)

// StartForwardRequest 描述启动 SSH 端口转发（-L/-R/-D）、StreamLocal（TCP↔Unix 双向/混合）或 TUN 隧道的强类型输入（P3-T2）。
type StartForwardRequest struct {
	Plan            plan.SealedConnectionPlan
	Spec            ports.ForwardSpec
	NodeID          string
	Risk            algebraic.Option[security.RiskLevel]
	Approval        algebraic.Option[gate.ApprovalSubmission]
	OperationStream *events.OperationStream
}

// ForwardInfo 封装成功启动的受管长驻转发句柄与绑定地址元信息；零值恒无效并失败关闭。
//
//xops:opaque
//xops:failclosed
type ForwardInfo struct {
	handle    plan.ManagedHandle[plan.KindTunnel]
	spec      ports.ForwardSpec
	boundAddr string
	valid     bool
}

func (i ForwardInfo) IsValid() bool {
	return i.valid && i.handle.IsValid() && i.spec.IsValid() && i.boundAddr != ""
}
func (i ForwardInfo) IsZero() bool            { return !i.IsValid() }
func (i ForwardInfo) Spec() ports.ForwardSpec { return i.spec }
func (i ForwardInfo) BoundAddr() string       { return i.boundAddr }
func (i ForwardInfo) Handle() plan.ManagedHandle[plan.KindTunnel] {
	if !i.IsValid() {
		return zeroVal[plan.ManagedHandle[plan.KindTunnel]]()
	}
	return i.handle
}

// ForwardStatus 表示受管隧道转发句柄的不可变只读状态快照；零值恒无效并失败关闭。
//
//xops:opaque
//xops:failclosed
type ForwardStatus struct {
	handleStatus pool.HandleStatus
	spec         ports.ForwardSpec
	boundAddr    string
	active, val  bool
	err          error
}

func (st ForwardStatus) IsValid() bool {
	return st.val && st.handleStatus.IsValid() && st.spec.IsValid()
}
func (st ForwardStatus) IsZero() bool                    { return !st.IsValid() }
func (st ForwardStatus) HandleStatus() pool.HandleStatus { return st.handleStatus }
func (st ForwardStatus) Spec() ports.ForwardSpec         { return st.spec }
func (st ForwardStatus) BoundAddr() string               { return st.boundAddr }
func (st ForwardStatus) Active() bool                    { return st.IsValid() && st.active }
func (st ForwardStatus) Err() error                      { return st.err }

type forwardResource interface {
	pool.ManagedResource
	view() ports.ForwardHandle
}

// managedForward 实现 forwardResource、snapshotResource[ForwardStatus] 与 ports.ForwardHandle，
// 持留池钉选可撤销 TransportConn，确保 WithLease 返回后可持续建链且吊销时即时终止、0 泄漏。
//
//xops:opaque
//xops:failclosed
type managedForward struct {
	valid                   bool
	spec                    ports.ForwardSpec
	boundAddr               string
	handle                  ports.ForwardHandle
	conn                    ports.TransportConn
	localTUN, remoteTUN     io.ReadWriteCloser
	nursery                 *conc.Nursery
	doneCh                  chan struct{}
	closed                  atomic.Bool
	resCloseOnce, closeOnce sync.Once
	err                     firstErr
}

func (s *Service) startManagedForward(leaseCtx, revokeCtx context.Context, conn ports.TransportConn, spec ports.ForwardSpec) (*managedForward, error) {
	if err := leaseCtx.Err(); err != nil {
		return nil, err
	}
	if spec.Direction() == ports.ForwardTUN && s.cfg.TUNDevice != nil {
		return startDirectTUNBridge(revokeCtx, conn, s.cfg.TUNDevice, spec)
	}
	fh, err := s.cfg.Forwarder.StartForward(revokeCtx, conn, spec)
	if err != nil {
		return nil, err
	}
	if fh == nil || !fh.IsValid() || fh.BoundAddr() == "" {
		_ = closeClosers(fh)
		return nil, fmt.Errorf("%w: ForwarderPort 返回无效 ForwardHandle", ErrInvalidRequest)
	}
	return finishManagedForward(revokeCtx, &managedForward{valid: true, spec: spec, boundAddr: fh.BoundAddr(), handle: fh, conn: conn, doneCh: make(chan struct{})},
		func(wCtx context.Context) error {
			select {
			case <-wCtx.Done():
			case <-fh.Done():
			}
			return nil
		})
}

func startDirectTUNBridge(revokeCtx context.Context, conn ports.TransportConn, tunPort ports.TUNDevicePort, spec ports.ForwardSpec) (*managedForward, error) {
	tunSpec, ok := spec.TUN().Get()
	if !ok || !tunSpec.IsValid() {
		return nil, fmt.Errorf("%w: ForwardTUN 缺少有效 TUNSpec", ErrInvalidRequest)
	}
	localDev, ifaceName, err := tunPort.OpenLocalTUN(revokeCtx, tunSpec)
	if err != nil {
		return nil, err
	}
	if localDev == nil || ifaceName == "" {
		_ = closeClosers(localDev)
		return nil, fmt.Errorf("%w: TUNDevicePort 返回无效设备句柄或空接口名", ErrInvalidRequest)
	}
	remoteTUN, err := conn.OpenTUN(revokeCtx, tunSpec)
	if err != nil {
		_ = localDev.Close()
		return nil, err
	}
	mf := &managedForward{valid: true, spec: spec, boundAddr: ifaceName, conn: conn, localTUN: localDev, remoteTUN: remoteTUN, doneCh: make(chan struct{})}
	pump := func(dst io.Writer, src io.Reader) func(context.Context) error {
		return func(context.Context) error {
			if _, err := io.Copy(dst, src); err != nil && !isRemotePipeClosedErr(err) {
				mf.err.record(err)
				_ = mf.closeResources()
			}
			return nil
		}
	}
	return finishManagedForward(revokeCtx, mf, pump(remoteTUN, localDev), pump(localDev, remoteTUN), func(wCtx context.Context) error { <-wCtx.Done(); return nil })
}

func finishManagedForward(revokeCtx context.Context, mf *managedForward, workers ...func(context.Context) error) (*managedForward, error) {
	n, err := conc.NewNursery(revokeCtx)
	if err != nil {
		_ = mf.closeResources()
		return nil, err
	}
	mf.nursery = n
	for i, w := range workers {
		isWatchdog := i == len(workers)-1
		if err := n.Go(func(wCtx context.Context) error {
			err := w(wCtx)
			if isWatchdog {
				_ = mf.closeResources()
			}
			return err
		}); err != nil {
			_ = mf.Close()
			return nil, err
		}
	}
	return mf, nil
}

func (f *managedForward) IsValid() bool {
	if f == nil || !f.valid || f.closed.Load() {
		return false
	}
	if f.handle != nil {
		return f.handle.IsValid()
	}
	return f.conn != nil && f.conn.IsAlive()
}
func (f *managedForward) Spec() ports.ForwardSpec { return f.spec }
func (f *managedForward) BoundAddr() string       { return f.boundAddr }
func (f *managedForward) Done() <-chan struct{}   { return f.doneCh }
func (f *managedForward) Err() error {
	if f == nil || !f.valid {
		return ports.ErrClosed
	}
	if f.handle != nil {
		if hErr := f.handle.Err(); hErr != nil {
			return hErr
		}
	}
	return f.err.get()
}
func (f *managedForward) snapshot(hs pool.HandleStatus) ForwardStatus {
	return ForwardStatus{handleStatus: hs, spec: f.spec, boundAddr: f.boundAddr, active: hs.Active() && f.IsValid(), err: f.Err(), val: true}
}
func (f *managedForward) view() ports.ForwardHandle {
	if f.handle != nil {
		return f.handle
	}
	return f
}
func (f *managedForward) closeResources() error {
	var err error
	f.resCloseOnce.Do(func() {
		f.closed.Store(true)
		err = closeClosers(f.handle, f.localTUN, f.remoteTUN, f.conn)
		f.err.record(err)
		close(f.doneCh)
	})
	return err
}
func (f *managedForward) Close() error {
	if f == nil || !f.valid {
		return nil
	}
	f.closeOnce.Do(func() {
		f.nursery.Cancel(ports.ErrClosed)
		f.err.record(errors.Join(f.closeResources(), f.nursery.Close()))
	})
	return f.Err()
}

// StartForward 启动一条受管长驻 SSH 转发（支持 -L/-R/-D、TCP↔Unix StreamLocal 双向/混合与 TUN）：
// 严格遵循 gate.WithAuthorized[security.CapTunnel] 包裹 pool.WithLease 与 pool.RegisterLeaseHandleWith。
func (s *Service) StartForward(ctx context.Context, req StartForwardRequest) (ForwardInfo, error) {
	defer closeStream(req.OperationStream)
	if err := s.validateStartForwardCall(ctx, req); err != nil {
		return ForwardInfo{}, err
	}
	targetHop, nodeID, err := resolvePlanTargetAndNode(req.Plan, req.NodeID)
	if err != nil {
		return ForwardInfo{}, err
	}
	gateReq, err := buildGateReq[security.CapTunnel](gateReqInput{
		plan: req.Plan, targetHop: targetHop, nodeID: nodeID, action: "forward_start",
		summary: fmt.Sprintf("forward %s %s -> %s on %s", req.Spec.Direction(), req.Spec.BindAddr(), req.Spec.TargetAddr(), nodeID),
		risk:    req.Risk.OrElse(defaultForwardRisk(req.Spec)), params: buildForwardBindingParams(req.Spec, targetHop),
		approval: req.Approval, stream: req.OperationStream,
	})
	if err != nil {
		return ForwardInfo{}, err
	}
	var bound string
	h, err := registerAuthorizedHandle[security.CapTunnel, plan.KindTunnel](ctx, s, req.Plan, nodeID, "forward_start", gateReq, req.OperationStream,
		func(leaseCtx, revokeCtx context.Context, conn ports.TransportConn) (*managedForward, error) {
			mf, sErr := s.startManagedForward(leaseCtx, revokeCtx, conn, req.Spec)
			if sErr == nil {
				bound = mf.BoundAddr()
			}
			return mf, sErr
		})
	if err != nil {
		return ForwardInfo{}, err
	}
	return ForwardInfo{handle: h, spec: req.Spec, boundAddr: bound, valid: true}, nil
}

func (s *Service) validateStartForwardCall(ctx context.Context, req StartForwardRequest) error {
	if err := s.validateBaseCall(ctx, req.Plan, RequestTTYUnset, req.Risk); err != nil {
		return err
	}
	if !req.Spec.IsValid() {
		return fmt.Errorf("%w: ForwardSpec 无效", ErrInvalidRequest)
	}
	if req.Spec.Direction() == ports.ForwardTUN {
		if s.cfg.TUNDevice == nil && s.cfg.Forwarder == nil {
			return fmt.Errorf("%w: ForwardTUN 需要配置 TUNDevicePort 或 ForwarderPort", ErrPortUnavailable)
		}
	} else if s.cfg.Forwarder == nil {
		return fmt.Errorf("%w: ForwarderPort 未配置", ErrPortUnavailable)
	}
	return nil
}

func buildForwardBindingParams(spec ports.ForwardSpec, targetHop plan.HopSpec) map[string]string {
	params := map[string]string{"user": targetHop.Username().String(), "direction": spec.Direction().String(), "bind_addr": spec.BindAddr()}
	for k, v := range map[string]string{"bind_kind": spec.BindKind().String(), "target_kind": spec.TargetKind().String(), "target_addr": spec.TargetAddr()} {
		if v != "" && v != "unset" {
			params[k] = v
		}
	}
	if ts, ok := spec.TUN().Get(); ok && ts.IsValid() {
		params["tun_mode"], params["local_unit"], params["remote_unit"] = ts.Mode().String(), strconv.FormatUint(uint64(ts.LocalUnit()), 10), strconv.FormatUint(uint64(ts.RemoteUnit()), 10)
	}
	return params
}

func defaultForwardRisk(spec ports.ForwardSpec) security.RiskLevel {
	if spec.Direction() == ports.ForwardLocal {
		return security.RiskModerate
	}
	return security.RiskDangerous
}

// InspectForward 返回指定世代隧道句柄的不可变运行期状态快照（含绑定地址与活跃状态）。
func (s *Service) InspectForward(ctx context.Context, handle plan.ManagedHandle[plan.KindTunnel]) (ForwardStatus, error) {
	return inspectManagedHandle[plan.KindTunnel, ForwardStatus](ctx, s, handle)
}

// WithForwardHandle 在同步作用域闭包内借出受管隧道句柄的只读/演练视图（零逃逸、吊销即取消上下文）。
//
//xops:syncclosure
//xops:borrowed
func (s *Service) WithForwardHandle(ctx context.Context, handle plan.ManagedHandle[plan.KindTunnel], fn func(ctx context.Context, fh ports.ForwardHandle) error) error {
	if err := s.validateActiveHandleOp(ctx, handle.IsValid()); err != nil {
		return err
	}
	if fn == nil {
		return ports.ErrNilCallback
	}
	return pool.WithManagedHandle[plan.KindTunnel, forwardResource](ctx, s.cfg.Pool, handle, func(hCtx context.Context, mf forwardResource) error { return fn(hCtx, mf.view()) })
}

// StopForward 显式释放隧道转发句柄、解钉底层跳板并有界关闭底层监听与传输视图。
func (s *Service) StopForward(ctx context.Context, handle plan.ManagedHandle[plan.KindTunnel]) error {
	return releaseManagedHandle[plan.KindTunnel](ctx, s, handle)
}
