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
	doneCh    <-chan struct{}
	waitErr   func() error
	valid     bool
}

// ForwardInfo 零值安全只读访问器与响应式停机等待方法（供 entry/cli -N 前台隧道零轮询阻塞等待）。
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

// Done 返回只读完成信号通道：受管转发终止并释放本地监听/资源后关闭；零值/无效返回 nil。
func (i ForwardInfo) Done() <-chan struct{} {
	if !i.IsValid() {
		return nil
	}
	return i.doneCh
}

// Wait 阻塞等待受管转发终止或 ctx 取消，并在终止后返回终态传输错误（正常 StopForward 停止返回 nil，零值严格失败关闭）。
func (i ForwardInfo) Wait(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: %w", ErrNilContext, ports.ErrNilContext)
	}
	if !i.IsValid() || i.doneCh == nil {
		return fmt.Errorf("%w: %w: ForwardInfo 无效", ErrInvalidRequest, ports.ErrInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-i.doneCh:
		if i.waitErr != nil {
			return i.waitErr()
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
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
	valid                            bool
	spec                             ports.ForwardSpec
	boundAddr                        string
	handle                           ports.ForwardHandle
	conn                             ports.TransportConn
	localTUN, remoteTUN              io.ReadWriteCloser
	nursery                          *conc.Nursery
	doneCh                           chan struct{}
	closed                           atomic.Bool
	remaining                        atomic.Int32
	ioCloseOnce, doneOnce, closeOnce sync.Once
	err                              firstErr
}

func (s *Service) startManagedForward(leaseCtx, revokeCtx context.Context, conn ports.TransportConn, spec ports.ForwardSpec) (*managedForward, error) {
	if err := leaseCtx.Err(); err != nil {
		return nil, err
	}
	if spec.Direction() == ports.ForwardTUN && s.cfg.TUNDevice != nil {
		return startDirectTUNBridge(leaseCtx, revokeCtx, conn, s.cfg.TUNDevice, spec)
	}
	fh, err := s.cfg.Forwarder.StartForward(revokeCtx, conn, spec)
	if err != nil {
		return nil, err
	}
	if leaseCtx.Err() != nil || fh == nil || !fh.IsValid() || fh.BoundAddr() == "" {
		_ = closeClosers(fh)
		return nil, firstNonNilErr(leaseCtx.Err(), fmt.Errorf("%w: ForwarderPort 返回无效 ForwardHandle", ErrInvalidRequest))
	}
	mf := &managedForward{valid: true, spec: spec, boundAddr: fh.BoundAddr(), handle: fh, conn: conn, doneCh: make(chan struct{})}
	return finishManagedForward(revokeCtx, mf, func(wCtx context.Context) error {
		return mf.watchHandle(wCtx, fh)
	})
}
func (f *managedForward) watchHandle(wCtx context.Context, fh ports.ForwardHandle) error {
	defer func() { _ = f.closeIO() }()
	if wCtx.Err() != nil {
		return nil
	}
	select {
	case <-wCtx.Done():
	case <-fh.Done():
		// 仅在非主动撤销/关闭路径下记录底层转发故障或上游断连，避免与 StopForward 竞争误报 ErrClosed。
		if wCtx.Err() == nil && !f.closed.Load() {
			if fErr := fh.Err(); fErr != nil {
				f.err.record(fErr)
			} else if !f.conn.IsAlive() {
				f.err.record(ports.ErrClosed)
			}
		}
	}
	return nil
}
func startDirectTUNBridge(leaseCtx, revokeCtx context.Context, conn ports.TransportConn, tunPort ports.TUNDevicePort, spec ports.ForwardSpec) (*managedForward, error) {
	tunSpec, ok := spec.TUN().Get()
	if !ok || !tunSpec.IsValid() {
		return nil, fmt.Errorf("%w: ForwardTUN 缺少有效 TUNSpec", ErrInvalidRequest)
	}
	hsCtx, cleanupHS := deriveHandshakeContext(leaseCtx, revokeCtx)
	defer cleanupHS()
	localDev, ifaceName, err := tunPort.OpenLocalTUN(hsCtx, tunSpec)
	if err != nil {
		return nil, err
	}
	if localDev == nil || ifaceName == "" {
		_ = closeClosers(localDev)
		return nil, fmt.Errorf("%w: TUNDevicePort 返回无效设备句柄或空接口名", ErrInvalidRequest)
	}
	remoteTUN, err := conn.OpenTUN(hsCtx, tunSpec)
	if err != nil {
		_ = localDev.Close()
		return nil, err
	}
	mf := &managedForward{valid: true, spec: spec, boundAddr: ifaceName, conn: conn, localTUN: localDev, remoteTUN: remoteTUN, doneCh: make(chan struct{})}
	pump := func(dst io.Writer, src io.Reader) func(context.Context) error {
		return func(wCtx context.Context) error {
			// 任一方向流终止（含正常 EOF 或关闭错）即代表隧道结束，立即关闭双端并取消看门狗避免僵尸隧道。
			defer func() { _ = mf.closeIO(); mf.nursery.Cancel(ports.ErrClosed) }()
			if _, err := io.Copy(dst, src); err != nil && !isRemotePipeClosedErr(err) && wCtx.Err() == nil && !mf.closed.Load() {
				mf.err.record(err)
			}
			return nil
		}
	}
	return finishManagedForward(revokeCtx, mf, pump(remoteTUN, localDev), pump(localDev, remoteTUN), func(wCtx context.Context) error { <-wCtx.Done(); _ = mf.closeIO(); return nil })
}
func finishManagedForward(revokeCtx context.Context, mf *managedForward, workers ...func(context.Context) error) (*managedForward, error) {
	n, err := conc.NewNursery(revokeCtx)
	if err != nil {
		_ = mf.closeIO()
		mf.markDone()
		return nil, err
	}
	mf.nursery = n
	// 仅在全部受监督协程退出且 I/O 已关闭后关闭 doneCh，建立所有 mf.err.record -> <-info.Done() 的严格 happens-before 边。
	mf.remaining.Store(int32(len(workers)))
	for _, w := range workers {
		worker := w
		if err := n.Go(func(wCtx context.Context) error {
			defer func() {
				if mf.remaining.Add(-1) == 0 {
					_ = mf.closeIO()
					mf.markDone()
				}
			}()
			return worker(wCtx)
		}); err != nil {
			_ = mf.Close()
			return nil, err
		}
	}
	return mf, nil
}

// IsValid 仅校验托管槽位资源已正确构造，确保对端 EOF 关闭隧道后 InspectForward 仍能返回 Active()==false 快照。
func (f *managedForward) IsValid() bool { return f != nil && f.valid }
func (f *managedForward) isActive() bool {
	if f == nil || !f.valid || f.closed.Load() {
		return false
	}
	if f.handle != nil {
		return f.handle.IsValid()
	}
	return f.conn != nil && f.conn.IsAlive()
}
func (f *managedForward) Err() error {
	if f == nil || !f.valid {
		return ports.ErrClosed
	}
	if f.handle != nil {
		return firstNonNilErr(f.handle.Err(), f.err.get())
	}
	return f.err.get()
}
func (f *managedForward) snapshot(hs pool.HandleStatus) ForwardStatus {
	return ForwardStatus{handleStatus: hs, spec: f.spec, boundAddr: f.boundAddr, active: hs.Active() && f.isActive(), err: f.Err(), val: true}
}
func (f *managedForward) view() ports.ForwardHandle {
	if f.handle != nil {
		return f.handle
	}
	return directTUNHandle{f: f}
}

type directTUNHandle struct{ f *managedForward }

func (h directTUNHandle) IsValid() bool           { return h.f.isActive() }
func (h directTUNHandle) Spec() ports.ForwardSpec { return h.f.spec }
func (h directTUNHandle) BoundAddr() string       { return h.f.boundAddr }
func (h directTUNHandle) Done() <-chan struct{}   { return h.f.doneCh }
func (h directTUNHandle) Err() error              { return h.f.Err() }
func (h directTUNHandle) Close() error            { return h.f.Close() }
func (f *managedForward) closeIO() error {
	var err error
	f.ioCloseOnce.Do(func() {
		f.closed.Store(true)
		err = closeClosers(f.handle, f.localTUN, f.remoteTUN, f.conn)
		f.err.record(err)
	})
	return err
}
func (f *managedForward) markDone() {
	f.doneOnce.Do(func() { close(f.doneCh) })
}
func (f *managedForward) Close() error {
	if f == nil || !f.valid {
		return nil
	}
	f.closeOnce.Do(func() {
		f.closed.Store(true)
		f.nursery.Cancel(ports.ErrClosed)
		f.err.record(errors.Join(f.closeIO(), f.nursery.Close()))
		f.markDone()
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
	var mfRef *managedForward
	h, err := registerAuthorizedHandle[security.CapTunnel, plan.KindTunnel](ctx, s, req.Plan, nodeID, "forward_start", gateReq, req.OperationStream,
		func(leaseCtx, revokeCtx context.Context, conn ports.TransportConn) (*managedForward, error) {
			mf, sErr := s.startManagedForward(leaseCtx, revokeCtx, conn, req.Spec)
			if sErr == nil {
				mfRef = mf
			}
			return mf, sErr
		})
	if err != nil {
		return ForwardInfo{}, err
	}
	return ForwardInfo{handle: h, spec: req.Spec, boundAddr: mfRef.boundAddr, doneCh: mfRef.doneCh, waitErr: mfRef.Err, valid: true}, nil
}
func (s *Service) validateStartForwardCall(ctx context.Context, req StartForwardRequest) error {
	if err := s.validateBaseCall(ctx, req.Plan, RequestTTYUnset, req.Risk); err != nil {
		return err
	}
	if !req.Spec.IsValid() {
		return fmt.Errorf("%w: ForwardSpec 无效", ErrInvalidRequest)
	}
	if req.Spec.Direction() == ports.ForwardTUN && s.cfg.TUNDevice != nil {
		return nil
	}
	if s.cfg.Forwarder == nil {
		return fmt.Errorf("%w: ForwarderPort 未配置（ForwardTUN 亦可配置 TUNDevicePort）", ErrPortUnavailable)
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

// InspectForward / WithForwardHandle / StopForward 提供受管隧道句柄的状态查询、同步借用与显式释放。
func (s *Service) InspectForward(ctx context.Context, handle plan.ManagedHandle[plan.KindTunnel]) (ForwardStatus, error) {
	return inspectManagedHandle[plan.KindTunnel, ForwardStatus](ctx, s, handle)
}

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
func (s *Service) StopForward(ctx context.Context, handle plan.ManagedHandle[plan.KindTunnel]) error {
	return releaseManagedHandle[plan.KindTunnel](ctx, s, handle)
}
