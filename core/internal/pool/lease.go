package pool

import (
	"context"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/ports"
	"io"
	"net"
	"strings"
	"sync/atomic"
)

// 编译期契约断言：*Lease 天然满足最小会话打开器与全量隧道数据面窄接口，且不暴露 Close/SendKeepalive。
var (
	_ ports.SessionOpener   = (*Lease)(nil)
	_ ports.TunnelTransport = (*Lease)(nil)
)

// Lease 表示由 Pool.WithLease 或 Pool.WithMultiLease 在同步作用域闭包内借出的连接租约（ADR-009 / ADR-011）。
// 零值恒无效；回调退出即置 active=false；全部数据面方法仅做无锁原子 Epoch 校验，绝不触碰 DualActor 循环。
//
//xops:opaque
//xops:failclosed
type Lease struct {
	pool       *Pool
	inst       *hopInstance
	planDigest plan.PlanDigest
	epoch      uint64
	leaseID    string
	valid      bool
	active     atomic.Bool
}

func newLease(p *Pool, inst *hopInstance, pd plan.PlanDigest, leaseID string) *Lease {
	l := &Lease{pool: p, inst: inst, planDigest: pd, epoch: inst.epoch, leaseID: leaseID, valid: true}
	l.active.Store(true)
	return l
}
func (l *Lease) invalidate() {
	if l != nil {
		l.active.Store(false)
	}
}

// checkDataPlane 在数据面热路径上执行纯无锁原子门控检查（零互斥锁、零 Actor 通信）。
func (l *Lease) checkDataPlane(ctx context.Context) error {
	if l == nil || !l.valid || l.pool == nil || l.inst == nil {
		return ErrLeaseInvalid
	}
	if ctx == nil {
		return ErrNilContext
	}
	if l.pool.halted.Load() {
		return ErrGateHalted
	}
	if !l.active.Load() {
		return ErrLeaseExpired
	}
	if l.pool.closed.Load() {
		return ErrPoolClosed
	}
	if !l.inst.isValidEpoch(l.epoch) {
		return ErrLeaseRevoked
	}
	return ctx.Err()
}

// IsValid 报告租约当前是否处于有效作用域内且底层连接世代未被吊销或熔断。
func (l *Lease) IsValid() bool {
	return l != nil && l.valid && l.pool != nil && l.inst != nil &&
		l.active.Load() && !l.pool.halted.Load() && !l.pool.closed.Load() && l.inst.isValidEpoch(l.epoch)
}
func (l *Lease) IsZero() bool  { return !l.IsValid() }
func (l *Lease) IsAlive() bool { return l.IsValid() && l.inst.conn.IsAlive() }

func (l *Lease) PlanDigest() plan.PlanDigest {
	if !l.IsValid() {
		return zeroVal[plan.PlanDigest]()
	}
	if sum, ok := l.planDigest.Bytes(); ok {
		return plan.PlanDigestFromSHA256(sum)
	}
	return zeroVal[plan.PlanDigest]()
}
func (l *Lease) HopDigest() plan.HopDigest {
	if !l.IsValid() {
		return zeroVal[plan.HopDigest]()
	}
	if sum, ok := l.inst.digest.Bytes(); ok {
		return plan.HopDigestFromSHA256(sum)
	}
	return zeroVal[plan.HopDigest]()
}
func (l *Lease) Endpoint() netaddr.Endpoint {
	if !l.IsValid() {
		return zeroVal[netaddr.Endpoint]()
	}
	return l.inst.hopSpec.Endpoint()
}
func (l *Lease) Epoch() uint64 {
	if !l.IsValid() {
		return 0
	}
	return l.inst.epochAtom.Load()
}
func (l *Lease) LeaseID() string {
	if !l.IsValid() {
		return ""
	}
	return strings.Clone(l.leaseID)
}

// 以下方法在无锁数据面路径上直接委派底层 ports.TransportConn 执行会话、SFTP 与各类隧道转发。
func (l *Lease) OpenSession(ctx context.Context) (ports.RemoteSession, error) {
	return dpCall(l.checkDataPlane(ctx), func() (ports.RemoteSession, error) { return l.inst.conn.OpenSession(ctx) })
}
func (l *Lease) DialTCP(ctx context.Context, target netaddr.HostPort) (net.Conn, error) {
	return dpCall(l.checkDataPlane(ctx), func() (net.Conn, error) { return l.inst.conn.DialTCP(ctx, target) })
}
func (l *Lease) ListenTCP(ctx context.Context, bindAddr string) (net.Listener, error) {
	return dpCall(l.checkDataPlane(ctx), func() (net.Listener, error) { return l.inst.conn.ListenTCP(ctx, bindAddr) })
}
func (l *Lease) DialStreamLocal(ctx context.Context, remoteSocket pathalg.RemotePath) (net.Conn, error) {
	return dpCall(l.checkDataPlane(ctx), func() (net.Conn, error) { return l.inst.conn.DialStreamLocal(ctx, remoteSocket) })
}
func (l *Lease) ListenStreamLocal(ctx context.Context, remoteSocket pathalg.RemotePath) (net.Listener, error) {
	return dpCall(l.checkDataPlane(ctx), func() (net.Listener, error) { return l.inst.conn.ListenStreamLocal(ctx, remoteSocket) })
}
func (l *Lease) OpenTUN(ctx context.Context, spec ports.TUNSpec) (io.ReadWriteCloser, error) {
	return dpCall(l.checkDataPlane(ctx), func() (io.ReadWriteCloser, error) { return l.inst.conn.OpenTUN(ctx, spec) })
}
func (l *Lease) OpenRemoteFS(ctx context.Context) (ports.RemoteFSPort, error) {
	return dpCall(l.checkDataPlane(ctx), func() (ports.RemoteFSPort, error) { return l.inst.conn.OpenRemoteFS(ctx) })
}

// Retire 通知连接池退役本租约绑定的精确世代连接实例（带世代防 ABA，绝不误杀已重连的新世代）。
func (l *Lease) Retire() {
	if l == nil || !l.valid || l.pool == nil || l.inst == nil {
		return
	}
	l.pool.actor.SendControl(controlMsg{kind: ctrlRetireInstance, inst: l.inst})
}

// deriveRevocableContext 组合调用方 parent 与吊销 revokeCtx；cleanup 同步回收 AfterFunc 保证 0 协程泄漏。
func deriveRevocableContext(parent, revokeCtx context.Context) (context.Context, func()) {
	derived, cancel := context.WithCancelCause(parent)
	if revokeCtx == nil {
		return derived, func() { cancel(nil) }
	}
	if revokeCtx.Err() != nil {
		cancel(context.Cause(revokeCtx))
		return derived, func() { cancel(nil) }
	}
	done := make(chan struct{})
	stop := context.AfterFunc(revokeCtx, func() {
		defer close(done)
		cancel(context.Cause(revokeCtx))
	})
	return derived, func() {
		if !stop() {
			<-done
		}
		cancel(nil)
	}
}
