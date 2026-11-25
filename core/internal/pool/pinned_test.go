package pool

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/ports"
)

// pinnedTransportRes 模拟持留池钉选 TransportConn 的长生命周期转发器或 ControlMaster 托管资源。
type pinnedTransportRes struct {
	conn       ports.TransportConn
	revokeCtx  context.Context
	closeCount atomic.Int64
	valid      bool
}

func (r *pinnedTransportRes) IsValid() bool { return r != nil && r.valid && r.conn != nil }
func (r *pinnedTransportRes) Close() error {
	if r == nil {
		return nil
	}
	r.closeCount.Add(1)
	if r.conn != nil {
		return r.conn.Close()
	}
	return nil
}

// TestRegisterLeaseHandleWithPostLeaseDataPlaneAndRevocations 验证池钉选可撤销传输视图（ADR-009）：
//  1. WithLease 返回且租约归还后，持留的 pinnedTransportConn 仍可成功打开 DialTCP / DialStreamLocal / OpenSession；
//  2. ReleaseHandle、RetireHop、GateHalted 与 Pool.Close 四类撤销路径触发后立即拒绝新通道并取消 revokeCtx；
//  3. ReleaseHandle 关闭 pinnedTransportConn 视图时绝不误关共享底层跳板连接。
func TestRegisterLeaseHandleWithPostLeaseDataPlaneAndRevocations(t *testing.T) {
	defer goleak.VerifyNone(t)
	hp, err := netaddr.ParseHostPort("10.0.0.8:8080")
	requireNoErr(t, err, "ParseHostPort")
	rp, err := pathalg.ParseAbsRemotePath("/run/app.sock")
	requireNoErr(t, err, "ParseAbsRemotePath")

	cases := []struct {
		name    string
		wantErr error
		trigger func(t *testing.T, p *Pool, pl plan.SealedConnectionPlan, h plan.ManagedHandle[plan.KindTunnel])
	}{
		{
			name:    "ReleaseHandle",
			wantErr: ports.ErrClosed,
			trigger: func(t *testing.T, p *Pool, _ plan.SealedConnectionPlan, h plan.ManagedHandle[plan.KindTunnel]) {
				requireNoErr(t, ReleaseHandle[plan.KindTunnel](p, h), "ReleaseHandle")
				requireNoErr(t, p.WaitPendingTeardowns(context.Background()), "WaitPendingTeardowns")
			},
		},
		{
			name:    "RetireHop",
			wantErr: ErrHandleRevoked,
			trigger: func(t *testing.T, p *Pool, pl plan.SealedConnectionPlan, _ plan.ManagedHandle[plan.KindTunnel]) {
				leafDig, _ := pl.HopDigestAt(1)
				requireNoErr(t, p.RetireHop(leafDig), "RetireHop")
				requireNoErr(t, p.WaitPendingTeardowns(context.Background()), "WaitPendingTeardowns")
			},
		},
		{
			name:    "GateHalted",
			wantErr: ErrGateHalted,
			trigger: func(t *testing.T, p *Pool, _ plan.SealedConnectionPlan, _ plan.ManagedHandle[plan.KindTunnel]) {
				p.GateHalted(errors.New("audit post-write halt"))
				requireNoErr(t, p.WaitPendingTeardowns(context.Background()), "WaitPendingTeardowns")
			},
		},
		{
			name:    "PoolClose",
			wantErr: ErrPoolClosed,
			trigger: func(t *testing.T, p *Pool, _ plan.SealedConnectionPlan, _ plan.ManagedHandle[plan.KindTunnel]) {
				requireNoErr(t, p.Close(), "Pool.Close")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, _, _ := newTestPool(t, PoolConfig{})
			defer func() { _ = p.Close() }()

			ctx := context.Background()
			pl := mustPlan(t,
				mustHop(t, 0, "bastion-p", "198.51.100.180", 22, 0, 0),
				mustHop(t, 1, "app-p", "198.51.100.181", 22, 0, 0),
			)
			binding := mustBindingForPlan(t, pl.PlanDigest(), "forward", "pinned")

			var res *pinnedTransportRes
			var h plan.ManagedHandle[plan.KindTunnel]
			var epochBefore uint64
			err := p.WithLease(ctx, pl, func(_ context.Context, lease *Lease) error {
				epochBefore = lease.Epoch()
				var rErr error
				h, rErr = RegisterLeaseHandleWith[plan.KindTunnel](p, lease, binding, func(revokeCtx context.Context, conn ports.TransportConn) (*pinnedTransportRes, error) {
					res = &pinnedTransportRes{conn: conn, revokeCtx: revokeCtx, valid: true}
					return res, nil
				})
				return rErr
			})
			requireNoErr(t, err, "WithLease+RegisterLeaseHandleWith")
			requireTrue(t, p.Stats().ActiveLeases == 0 && p.Stats().ActiveHandles == 1, "租约归还后句柄应保持活跃")
			requireTrue(t, p.EvictIdle() == 0, "钉选句柄存活期间绝不能被空闲驱逐")

			// 关键断言：WithLease 退出后，池钉选 TransportConn 仍可稳定打开 TCP / StreamLocal / Session 通道。
			requireTrue(t, res.conn.IsAlive() && res.conn.HopDigest().IsValid() && res.conn.Endpoint().IsValid(), "租约退出后 pinnedConn 仍应活跃")
			tcpConn, err := res.conn.DialTCP(ctx, hp)
			requireNoErr(t, err, "post-lease DialTCP")
			_ = tcpConn.Close()
			unixConn, err := res.conn.DialStreamLocal(ctx, rp)
			requireNoErr(t, err, "post-lease DialStreamLocal")
			_ = unixConn.Close()
			sess, err := res.conn.OpenSession(ctx)
			requireNoErr(t, err, "post-lease OpenSession")
			_ = sess.Close()

			// 触发撤销并验证 revokeCtx 取消 + 新通道立即被拒。
			tc.trigger(t, p, pl, h)
			requireTrue(t, res.revokeCtx.Err() != nil, "撤销后 revokeCtx 必须已取消")
			requireTrue(t, !res.conn.IsAlive(), "撤销后 pinnedConn.IsAlive 必须为 false")
			_, dialErr := res.conn.DialTCP(ctx, hp)
			requireTrue(t, errors.Is(dialErr, tc.wantErr) || errors.Is(dialErr, ErrHandleRevoked) || errors.Is(dialErr, ports.ErrClosed), "撤销后 DialTCP 必须立即拒绝")
			_, slErr := res.conn.DialStreamLocal(ctx, rp)
			requireTrue(t, slErr != nil, "撤销后 DialStreamLocal 必须立即拒绝")

			// ReleaseHandle 仅关闭视图，共享底层连接须继续保持相同世代可复用。
			if tc.name == "ReleaseHandle" {
				var epochAfter uint64
				requireNoErr(t, p.WithLease(ctx, pl, func(_ context.Context, lease *Lease) error {
					epochAfter = lease.Epoch()
					return nil
				}), "ReleaseHandle 后复用共享底层连接")
				requireTrue(t, epochAfter == epochBefore, "ReleaseHandle 绝不能关闭底层共享跳板连接")
			}
		})
	}
}

// TestRegisterLeaseHandleWithRollbackAndConcurrentRevocation 验证构造失败、无效资源返回与并发跳板退役的原子回滚与零泄漏。
func TestRegisterLeaseHandleWithRollbackAndConcurrentRevocation(t *testing.T) {
	defer goleak.VerifyNone(t)
	p, _, _ := newTestPool(t, PoolConfig{})
	defer func() { requireNoErr(t, p.Close(), "Pool.Close") }()

	ctx := context.Background()
	pl := mustPlan(t, mustHop(t, 0, "rb-node", "198.51.100.190", 22, 0, 0))
	hopDig, _ := pl.HopDigestAt(0)
	binding := mustBindingForPlan(t, pl.PlanDigest(), "forward", "rollback")
	wantBoom := errors.New("start forward failed")

	// 1. nil start 回调、start 报错与返回无效零值资源均原子回滚槽位与跳板钉选。
	requireNoErr(t, p.WithLease(ctx, pl, func(_ context.Context, lease *Lease) error {
		_, err := RegisterLeaseHandleWith[plan.KindTunnel, *pinnedTransportRes](p, lease, binding, nil)
		requireErrIs(t, err, ErrNilCallback, "nil start")

		_, err = RegisterLeaseHandleWith[plan.KindTunnel](p, lease, binding, func(context.Context, ports.TransportConn) (*pinnedTransportRes, error) {
			return nil, wantBoom
		})
		requireErrIs(t, err, wantBoom, "start error")

		_, err = RegisterLeaseHandleWith[plan.KindTunnel](p, lease, binding, func(context.Context, ports.TransportConn) (*pinnedTransportRes, error) {
			return &pinnedTransportRes{}, nil
		})
		requireErrIs(t, err, ErrInvalidResource, "invalid resource")
		return nil
	}), "WithLease(rollback)")
	requireTrue(t, p.Stats().ActiveHandles == 0, "回滚后 ActiveHandles 必须归零")
	requireTrue(t, p.EvictIdle() == 1, "回滚解钉后空闲跳板须立即可驱逐")
	requireNoErr(t, p.WaitPendingTeardowns(ctx), "WaitPendingTeardowns(rollback)")

	// 2. start 执行期间发生并发 RetireHop：立即取消 revokeCtx 并在 start 返回资源后自动有界关闭，零槽位/资源泄漏。
	inStart := make(chan struct{})
	releaseStart := make(chan struct{})
	var lateRes *pinnedTransportRes
	var regErr error
	runErr := conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(c context.Context) error {
			return p.WithLease(c, pl, func(_ context.Context, lease *Lease) error {
				_, regErr = RegisterLeaseHandleWith[plan.KindTunnel](p, lease, binding, func(revokeCtx context.Context, conn ports.TransportConn) (*pinnedTransportRes, error) {
					close(inStart)
					<-releaseStart
					<-revokeCtx.Done()
					lateRes = &pinnedTransportRes{conn: conn, revokeCtx: revokeCtx, valid: true}
					return lateRes, nil
				})
				return nil
			})
		}); gErr != nil {
			return gErr
		}
		return n.Go(func(context.Context) error {
			<-inStart
			requireNoErr(t, p.RetireHop(hopDig), "concurrent RetireHop")
			close(releaseStart)
			return nil
		})
	})
	requireNoErr(t, runErr, "conc.RunWait(concurrent revoke)")
	requireErrIs(t, regErr, ErrHandleRevoked, "并发退役期间注册须返回 ErrHandleRevoked")
	requireNoErr(t, p.WaitPendingTeardowns(ctx), "WaitPendingTeardowns(concurrent)")
	requireTrue(t, p.Stats().ActiveHandles == 0, "并发退役后绝不能泄漏槽位")
	requireTrue(t, lateRes != nil && lateRes.closeCount.Load() == 1, "并发退役后延迟返回的资源须被有界关闭")
}
