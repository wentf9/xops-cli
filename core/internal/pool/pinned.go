package pool

import (
	"context"
	"fmt"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/ports"
	"io"
	"net"
	"sync/atomic"
)

var _ ports.TransportConn = (*pinnedTransportConn)(nil)

type (
	subsystemStreamOpener interface {
		OpenSubsystemStream(ctx context.Context, subsystem string) (io.ReadWriteCloser, error)
	}
	waitDoneProvider interface {
		WaitDone() <-chan struct{}
	}
)

func extractLeasePinMeta[K plan.HandleKind](p *Pool, lease *Lease, binding security.OperationBinding) (plan.HopDigest, uint64, plan.PlanDigest, error) {
	var zeroHop plan.HopDigest
	var zeroPlan plan.PlanDigest
	if err := checkPoolAvailable(p); err != nil {
		return zeroHop, 0, zeroPlan, err
	}
	if lease == nil || !lease.valid || lease.pool != p {
		return zeroHop, 0, zeroPlan, ErrLeaseInvalid
	}
	if !lease.active.Load() {
		return zeroHop, 0, zeroPlan, ErrLeaseExpired
	}
	hopDig, hopEpoch, planDig := lease.HopDigest(), lease.Epoch(), lease.PlanDigest()
	if !hopDig.IsValid() || hopEpoch == 0 || !planDig.IsValid() {
		return zeroHop, 0, zeroPlan, ErrLeaseRevoked
	}
	if err := validateHandleBinding[K](planDig, binding); err != nil {
		return zeroHop, 0, zeroPlan, err
	}
	return hopDig, hopEpoch, planDig, nil
}
func validateHandleBinding[K plan.HandleKind](planDigest plan.PlanDigest, binding security.OperationBinding) error {
	if !plan.HandleKindOf[K]().IsValid() || !planDigest.IsValid() || !binding.IsValid() {
		return ErrInvalidHandle
	}
	if bpd, ok := binding.PlanDigest().Get(); !ok || !bpd.Equal(planDigest.SecurityDigest()) {
		return ErrHandleBindingMismatch
	}
	return nil
}
func checkValidManagedResource[R ComparableManagedResource](resource R) error {
	var zeroRes R
	var iface ManagedResource = resource
	if resource == zeroRes || iface == nil || !iface.IsValid() {
		return ErrInvalidResource
	}
	return nil
}

// pinnedTransportConn 是面向长生命周期托管句柄（如 ForwardHandle、ControlMaster Serve）的
// 池钉选可撤销传输视图（ADR-009）：受熔断/关闭、槽位活跃哨兵与底层跳板精确世代门控，
// 不受短命 *Lease 作用域失效影响；Close 仅关闭本视图，绝不关闭池内共享底层 TransportConn。
//
//xops:opaque
//xops:failclosed
type pinnedTransportConn struct {
	pool       *Pool
	inst       *hopInstance
	epoch      uint64
	hopDigest  plan.HopDigest
	endpoint   netaddr.Endpoint
	slotActive *atomic.Bool
	open       atomic.Bool
	valid      bool
}

func newPinnedTransportConn(p *Pool, inst *hopInstance, epoch uint64, slotActive *atomic.Bool) *pinnedTransportConn {
	c := &pinnedTransportConn{
		pool: p, inst: inst, epoch: epoch, hopDigest: inst.digest,
		endpoint: inst.hopSpec.Endpoint(), slotActive: slotActive, valid: true,
	}
	c.open.Store(true)
	return c
}
func (t *pinnedTransportConn) checkDataPlane(ctx context.Context) error {
	if t == nil || !t.valid || t.pool == nil || t.inst == nil || t.slotActive == nil {
		return ErrInvalidTransportConn
	}
	if ctx == nil {
		return ErrNilContext
	}
	switch {
	case t.pool.halted.Load():
		return ErrGateHalted
	case t.pool.closed.Load():
		return ErrPoolClosed
	case !t.open.Load():
		return ports.ErrClosed
	case !t.slotActive.Load():
		return ErrHandleRevoked
	case !t.inst.isValidEpoch(t.epoch):
		return ErrLeaseRevoked
	default:
		return ctx.Err()
	}
}
func (t *pinnedTransportConn) HopDigest() plan.HopDigest {
	if t == nil || !t.valid {
		return zeroVal[plan.HopDigest]()
	}
	return t.hopDigest
}
func (t *pinnedTransportConn) Endpoint() netaddr.Endpoint {
	if t == nil || !t.valid {
		return zeroVal[netaddr.Endpoint]()
	}
	return t.endpoint
}
func (t *pinnedTransportConn) IsAlive() bool {
	return t != nil && t.valid && t.pool != nil && t.inst != nil && t.slotActive != nil &&
		t.open.Load() && t.slotActive.Load() && !t.pool.halted.Load() && !t.pool.closed.Load() &&
		t.inst.isValidEpoch(t.epoch) && t.inst.conn.IsAlive()
}
func (t *pinnedTransportConn) Close() error {
	if t != nil {
		t.open.Store(false)
	}
	return nil
}
func (t *pinnedTransportConn) SendKeepalive(ctx context.Context) error {
	if err := t.checkDataPlane(ctx); err != nil {
		return err
	}
	return t.inst.conn.SendKeepalive(ctx)
}
func (t *pinnedTransportConn) OpenSession(ctx context.Context) (ports.RemoteSession, error) {
	return dpCall(t.checkDataPlane(ctx), func() (ports.RemoteSession, error) { return t.inst.conn.OpenSession(ctx) })
}
func (t *pinnedTransportConn) DialTCP(ctx context.Context, target netaddr.HostPort) (net.Conn, error) {
	return dpCall(t.checkDataPlane(ctx), func() (net.Conn, error) { return t.inst.conn.DialTCP(ctx, target) })
}
func (t *pinnedTransportConn) ListenTCP(ctx context.Context, bindAddr string) (net.Listener, error) {
	return dpCall(t.checkDataPlane(ctx), func() (net.Listener, error) { return t.inst.conn.ListenTCP(ctx, bindAddr) })
}
func (t *pinnedTransportConn) DialStreamLocal(ctx context.Context, remoteSocket pathalg.RemotePath) (net.Conn, error) {
	return dpCall(t.checkDataPlane(ctx), func() (net.Conn, error) { return t.inst.conn.DialStreamLocal(ctx, remoteSocket) })
}
func (t *pinnedTransportConn) ListenStreamLocal(ctx context.Context, remoteSocket pathalg.RemotePath) (net.Listener, error) {
	return dpCall(t.checkDataPlane(ctx), func() (net.Listener, error) { return t.inst.conn.ListenStreamLocal(ctx, remoteSocket) })
}
func (t *pinnedTransportConn) OpenTUN(ctx context.Context, spec ports.TUNSpec) (io.ReadWriteCloser, error) {
	return dpCall(t.checkDataPlane(ctx), func() (io.ReadWriteCloser, error) { return t.inst.conn.OpenTUN(ctx, spec) })
}
func (t *pinnedTransportConn) OpenRemoteFS(ctx context.Context) (ports.RemoteFSPort, error) {
	return dpCall(t.checkDataPlane(ctx), func() (ports.RemoteFSPort, error) { return t.inst.conn.OpenRemoteFS(ctx) })
}

// WaitDone 透传底层连接的断连通知通道（供 ForwardHandle 与 ControlMaster 在上游断连时即时收敛）；
// 若视图已失效则立即返回已关闭通道，若底层实现未暴露 WaitDone 则返回 nil。
func (t *pinnedTransportConn) WaitDone() <-chan struct{} {
	if !t.IsAlive() {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	if wp, ok := t.inst.conn.(waitDoneProvider); ok {
		return wp.WaitDone()
	}
	return nil
}

// OpenSubsystemStream 经池世代与熔断门控校验后透传底层连接的命名子系统原始流（支撑 ControlMaster 复用 SFTP）。
func (t *pinnedTransportConn) OpenSubsystemStream(ctx context.Context, subsystem string) (io.ReadWriteCloser, error) {
	return dpCall(t.checkDataPlane(ctx), func() (io.ReadWriteCloser, error) {
		opener, ok := t.inst.conn.(subsystemStreamOpener)
		if !ok {
			return nil, ports.ErrUnsupported
		}
		return opener.OpenSubsystemStream(ctx, subsystem)
	})
}

//xops:syncclosure
func dpCall[T any](checkErr error, fn func() (T, error)) (T, error) {
	if checkErr != nil {
		return zeroVal[T](), checkErr
	}
	return fn()
}

// RegisterLeaseHandleWith 在当前有效租约 lease 锁定的底层跳板世代上先钉选跳板并预分配世代槽位，
// 再同步调用 start(revokeCtx, conn) 构造长生命周期托管资源 R：
//   - 传入的 conn 为池钉选可撤销 ports.TransportConn（严禁标注 //xops:borrowed），租约退出后仍持续有效；
//   - 在 ReleaseHandle、RetireHop/RetirePlan、GateHalted 或 Pool.Close 后，conn 立即拒绝后续数据面打开；
//   - 若 start 失败、返回无效资源、发生 panic 或期间被并发吊销，均原子回滚槽位与跳板钉选并有界关闭资源。
//
//xops:syncclosure
func RegisterLeaseHandleWith[K plan.HandleKind, R ComparableManagedResource](p *Pool, lease *Lease, binding security.OperationBinding, start func(revokeCtx context.Context, conn ports.TransportConn) (R, error)) (plan.ManagedHandle[K], error) {
	var zero plan.ManagedHandle[K]
	if start == nil {
		return zero, ErrNilCallback
	}
	hopDig, hopEpoch, planDig, err := extractLeasePinMeta[K](p, lease, binding)
	if err != nil {
		return zero, err
	}
	id, err := plan.NewHandleIDFrom(p.entropy)
	if err != nil {
		return zero, fmt.Errorf("%w: 生成 HandleID 失败: %w", ErrInvalidHandle, err)
	}
	meta, err := p.slots.allocateHandle(p, id, planDig, binding, nil, plan.HandleKindOf[K]())
	if err != nil {
		return zero, err
	}
	typed, err := plan.NewManagedHandle[K](meta.id, meta.gen, planDig, binding)
	if err != nil {
		p.rollbackSlot(meta.id)
		return zero, err
	}
	inst, pinErr := p.pinHandleOnActor(meta.id, meta.gen, planDig, hopDig, hopEpoch, true)
	if pinErr != nil || inst == nil {
		p.rollbackSlot(meta.id)
		if pinErr != nil {
			return zero, pinErr
		}
		return zero, ErrLeaseRevoked
	}
	pinnedConn := newPinnedTransportConn(p, inst, hopEpoch, meta.active)
	committed := false
	defer func() {
		if !committed {
			_ = pinnedConn.Close()
			p.rollbackSlot(meta.id)
			p.sendUnpinIfBound(hopDig, hopEpoch, meta.id, meta.gen)
		}
	}()
	res, err := start(meta.revokeCtx, pinnedConn)
	if err != nil {
		return zero, err
	}
	if err := checkValidManagedResource(res); err != nil {
		return zero, err
	}
	if err := p.slots.attachResource(p, meta.id, meta.gen, res); err != nil {
		_ = pinnedConn.Close()
		p.scheduleResourceClose(res)
		return zero, err
	}
	committed = true
	p.emitHandleEvent(events.PoolActionMuxHandover, typed.Kind(), typed.ID(), planDig, typed.Generation(), "managed handle registered with pinned transport")
	return typed, nil
}
