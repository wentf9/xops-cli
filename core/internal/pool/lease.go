package pool

import (
	"context"
	"net"
	"strings"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/ports"
)

// Lease 表示由 Pool.WithLease 或 Pool.WithMultiLease 在同步作用域闭包内借出的连接租约。
//
// 安全与并发不变量（ADR-009 / ADR-011）：
//   - 零值恒无效并失败关闭（由非指针正向门控 valid bool 保证）；
//   - 作用域回调退出时立即通过 active 原子哨兵置为失效，后续任何残留引用的数据面调用均返回 ErrLeaseExpired；
//   - 控制面与数据面彻底分离：所有数据面操作仅做无锁原子状态与世代 Epoch 校验，直接委托底层
//     ports.TransportConn 并发执行，绝不触碰 DualActor 循环；
//   - 故意不暴露 Close 与 SendKeepalive：底层连接生命周期与协议保活归连接池独占托管（INV-C2）。
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
	l := &Lease{
		pool:       p,
		inst:       inst,
		planDigest: pd,
		epoch:      inst.epoch,
		leaseID:    leaseID,
		valid:      true,
	}
	l.active.Store(true)
	return l
}

// invalidate 将租约的运行时借用失效哨兵原子置为 false（幂等，在作用域回调退出时无条件调用）。
func (l *Lease) invalidate() {
	if l == nil {
		return
	}
	l.active.Store(false)
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

// IsValid 报告租约当前是否仍处于有效作用域内且底层连接世代未被吊销或熔断。
func (l *Lease) IsValid() bool {
	if l == nil || !l.valid || l.pool == nil || l.inst == nil {
		return false
	}
	if !l.active.Load() || l.pool.halted.Load() || l.pool.closed.Load() {
		return false
	}
	return l.inst.isValidEpoch(l.epoch)
}

// IsZero 报告租约是否为无效零值或已失效。
func (l *Lease) IsZero() bool { return !l.IsValid() }

// PlanDigest 返回租约绑定的顶层连接计划 Merkle 摘要（无效或失效时返回零值）。
func (l *Lease) PlanDigest() plan.PlanDigest {
	if !l.IsValid() {
		return zeroVal[plan.PlanDigest]()
	}
	if sum, ok := l.planDigest.Bytes(); ok {
		return plan.PlanDigestFromSHA256(sum)
	}
	return zeroVal[plan.PlanDigest]()
}

// HopDigest 返回租约对应末跳传输连接的 Merkle 单跳摘要（无效或失效时返回零值）。
func (l *Lease) HopDigest() plan.HopDigest {
	if !l.IsValid() {
		return zeroVal[plan.HopDigest]()
	}
	if sum, ok := l.inst.digest.Bytes(); ok {
		return plan.HopDigestFromSHA256(sum)
	}
	return zeroVal[plan.HopDigest]()
}

// Endpoint 返回租约对应末跳连接的规范化目标端点（无效或失效时返回零值）。
func (l *Lease) Endpoint() netaddr.Endpoint {
	if !l.IsValid() {
		return zeroVal[netaddr.Endpoint]()
	}
	return l.inst.hopSpec.Endpoint()
}

// Epoch 返回租约锁定的连接世代号（经原子 Epoch 视图读取，无效或失效时返回 0）。
func (l *Lease) Epoch() uint64 {
	if !l.IsValid() {
		return 0
	}
	return l.inst.epochAtom.Load()
}

// LeaseID 返回本次作用域租约的诊断实例标识（与 trace.LeaseScope.LeaseID 一致；无效时返回空串）。
func (l *Lease) LeaseID() string {
	if !l.IsValid() {
		return ""
	}
	return strings.Clone(l.leaseID)
}

// IsAlive 无锁检查租约有效且底层传输连接仍处于活跃可用状态。
func (l *Lease) IsAlive() bool {
	return l.IsValid() && l.inst.conn.IsAlive()
}

// OpenSession 在无锁数据面路径上打开一条隔离的远端命令/Shell 会话通道。
func (l *Lease) OpenSession(ctx context.Context) (ports.RemoteSession, error) {
	if err := l.checkDataPlane(ctx); err != nil {
		return nil, err
	}
	return l.inst.conn.OpenSession(ctx)
}

// DialTCP 在无锁数据面路径上经当前传输连接发起 direct-tcpip 隧道连接（供 -L/-D 转发）。
func (l *Lease) DialTCP(ctx context.Context, target netaddr.HostPort) (net.Conn, error) {
	if err := l.checkDataPlane(ctx); err != nil {
		return nil, err
	}
	return l.inst.conn.DialTCP(ctx, target)
}

// ListenTCP 在无锁数据面路径上于远端请求 tcpip-forward 监听（供 -R 远端转发）。
func (l *Lease) ListenTCP(ctx context.Context, bindAddr string) (net.Listener, error) {
	if err := l.checkDataPlane(ctx); err != nil {
		return nil, err
	}
	return l.inst.conn.ListenTCP(ctx, bindAddr)
}

// OpenRemoteFS 在无锁数据面路径上打开受保护的 SFTP 子系统出站端口。
func (l *Lease) OpenRemoteFS(ctx context.Context) (ports.RemoteFSPort, error) {
	if err := l.checkDataPlane(ctx); err != nil {
		return nil, err
	}
	return l.inst.conn.OpenRemoteFS(ctx)
}

// Retire 通知连接池退役本租约绑定的精确世代连接实例（带世代防 ABA，绝不误杀已重连的新世代）。
// 该操作经 DualActor 永不阻塞控制通道异步投递并监听 actorDone，绝不阻塞数据面调用方。
func (l *Lease) Retire() {
	if l == nil || !l.valid || l.pool == nil || l.inst == nil {
		return
	}
	l.pool.actor.SendControl(controlMsg{
		kind: ctrlRetireInstance,
		inst: l.inst,
	})
}

// deriveRevocableContext 将调用方上下文 parent 与连接/句柄吊销上下文 revokeCtx 组合为单一派生上下文：
// 任一方取消都会立即传播至派生上下文；cleanup 保证在回调退出时同步回收 AfterFunc 注册，
// 若回调协程已被触发则等待其完成关闭 done，数学上保证 goleak 0 泄漏。
func deriveRevocableContext(parent context.Context, revokeCtx context.Context) (context.Context, func()) {
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
