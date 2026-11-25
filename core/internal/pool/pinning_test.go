package pool

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
)

// TestManagedHandlePinsHopAgainstIdleLRUAndTTLEviction 验证活跃托管句柄钉选底层跳板后：
//  1. 即使 ActiveLeases==0，EvictIdle、IdleTTL 后台扫描与 MaxConns LRU 均不得驱逐该跳板或其祖先跳板；
//  2. ReleaseHandle / RevokeHandlesByPlan 非阻塞解钉后，EvictIdle 可立即驱逐并回收底层连接。
func TestManagedHandlePinsHopAgainstIdleLRUAndTTLEviction(t *testing.T) {
	defer goleak.VerifyNone(t)
	clk := newSimClock()
	p, _, _ := newTestPool(t, PoolConfig{Clock: clk, MaxConns: 2, IdleTTL: 40 * time.Millisecond})
	defer func() { requireNoErr(t, p.Close(), "Pool.Close") }()

	clk.WaitTimerArmed(t, 1)
	ctx := context.Background()
	hop0 := mustHop(t, 0, "bastion-pin", "198.51.100.140", 22, 0, 0)
	hop1 := mustHop(t, 1, "app-pin", "198.51.100.141", 22, 0, 0)
	plA := mustPlan(t, hop0, hop1)
	plB := mustPlan(t, mustHop(t, 0, "other-pin", "198.51.100.142", 22, 0, 0))
	bindingA := mustBindingForPlan(t, plA.PlanDigest(), "forward", "start")

	res1 := &mockManagedRes{label: "fwd-1"}
	var h1 plan.ManagedHandle[plan.KindTunnel]
	err := p.WithLease(ctx, plA, func(_ context.Context, lease *Lease) error {
		var rErr error
		h1, rErr = RegisterLeaseHandle[plan.KindTunnel](p, lease, bindingA, res1)
		return rErr
	})
	requireNoErr(t, err, "WithLease+RegisterLeaseHandle")
	requireTrue(t, p.Stats().ActiveLeases == 0 && p.Stats().ActiveConns == 2 && p.Stats().ActiveHandles == 1, "租约归还后连接与句柄应保持活跃")

	// 1. 显式 EvictIdle 不得驱逐被钉选的末跳及其父跳板。
	requireTrue(t, p.EvictIdle() == 0, "存在钉选句柄时 EvictIdle 必须为 0")

	// 2. 推进虚拟时钟超过 IdleTTL，后台扫描器同样不得驱逐被钉选跳板。
	clk.Advance(100 * time.Millisecond)
	clk.WaitTimerArmed(t, 2)
	requireTrue(t, p.Stats().ActiveConns == 2, "IdleTTL 扫描不得驱逐钉选跳板")

	// 3. 容量上限 MaxConns=2 已满且末跳被钉选，LRU 不得驱逐钉选跳板，新计划须返回容量超限。
	err = p.WithLease(ctx, plB, func(context.Context, *Lease) error { return nil })
	requireErrIs(t, err, ErrPoolCapacityExceeded, "LRU 驱逐不得误杀钉选跳板")

	// 4. 再以 RegisterHandle（按 PlanDigest 自动钉选）叠加第 2 个句柄，验证多句柄引用计数与 RevokeHandlesByPlan 解钉。
	res2 := &mockManagedRes{label: "fwd-2"}
	h2, err := RegisterHandle[plan.KindTunnel](p, plA.PlanDigest(), bindingA, res2)
	requireNoErr(t, err, "RegisterHandle(auto-pin)")
	requireNoErr(t, ReleaseHandle[plan.KindTunnel](p, h1), "ReleaseHandle(h1)")
	requireNoErr(t, p.WaitPendingTeardowns(ctx), "WaitPendingTeardowns(h1)")
	requireTrue(t, res1.closeCount.Load() == 1, "h1 释放后底层资源应关闭")
	requireTrue(t, p.EvictIdle() == 0, "h2 仍钉选时 EvictIdle 必须继续为 0")

	// 5. RevokeHandlesByPlan 吊销 h2 并发送非阻塞解钉，随后 EvictIdle 可立刻级联清理两跳连接。
	requireTrue(t, p.RevokeHandlesByPlan(plA.PlanDigest()) == 1, "RevokeHandlesByPlan 应吊销剩余 1 个句柄")
	_, err = InspectHandle[plan.KindTunnel](p, h2)
	requireErrIs(t, err, ErrHandleNotFound, "h2 已被吊销")
	requireNoErr(t, p.WaitPendingTeardowns(ctx), "WaitPendingTeardowns(h2)")
	requireTrue(t, res2.closeCount.Load() == 1, "h2 吊销后底层资源应关闭")
	requireTrue(t, p.EvictIdle() == 2, "全部解钉后 EvictIdle 须立即驱逐末跳与父跳板")
	requireNoErr(t, p.WaitPendingTeardowns(ctx), "WaitPendingTeardowns(evict)")
	requireTrue(t, p.Stats().ActiveConns == 0, "驱逐后活跃连接应归零")
}

// TestManagedHandleReverseRevocationOnHopDetach 验证底层跳板经五类路径摘除时均同步吊销绑定句柄并关闭资源：
// RetireHop(末跳)、RetireHop(父跳级联)、RetirePlan、Lease.Retire 与保活失败。
func TestManagedHandleReverseRevocationOnHopDetach(t *testing.T) {
	defer goleak.VerifyNone(t)
	cases := []struct {
		name      string
		keepalive time.Duration
		trigger   func(t *testing.T, p *Pool, clk *simClock, dialer *mockDialer, pl plan.SealedConnectionPlan, leaseRef *Lease)
	}{
		{
			name: "RetireHopLeaf",
			trigger: func(t *testing.T, p *Pool, _ *simClock, _ *mockDialer, pl plan.SealedConnectionPlan, _ *Lease) {
				leafDig, _ := pl.HopDigestAt(1)
				requireNoErr(t, p.RetireHop(leafDig), "RetireHop(leaf)")
			},
		},
		{
			name: "RetireHopParentCascade",
			trigger: func(t *testing.T, p *Pool, _ *simClock, _ *mockDialer, pl plan.SealedConnectionPlan, _ *Lease) {
				parentDig, _ := pl.HopDigestAt(0)
				requireNoErr(t, p.RetireHop(parentDig), "RetireHop(parent)")
			},
		},
		{
			name: "RetirePlan",
			trigger: func(t *testing.T, p *Pool, _ *simClock, _ *mockDialer, pl plan.SealedConnectionPlan, _ *Lease) {
				requireNoErr(t, p.RetirePlan(pl.PlanDigest()), "RetirePlan")
			},
		},
		{
			name: "LeaseRetire",
			trigger: func(_ *testing.T, _ *Pool, _ *simClock, _ *mockDialer, _ plan.SealedConnectionPlan, leaseRef *Lease) {
				leaseRef.Retire()
			},
		},
		{
			name:      "KeepaliveFailed",
			keepalive: 20 * time.Millisecond,
			trigger: func(t *testing.T, _ *Pool, clk *simClock, dialer *mockDialer, _ plan.SealedConnectionPlan, _ *Lease) {
				leafConn := dialer.lastConn()
				leafConn.kaHook = func(context.Context) error { return errors.New("ka timeout") }
				clk.WaitTimerArmed(t, 1)
				clk.Advance(25 * time.Millisecond)
				waitConnClosedCh(t, leafConn, "保活失败拆断末跳")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clk := newSimClock()
			p, dialer, _ := newTestPool(t, PoolConfig{Clock: clk})
			defer func() { requireNoErr(t, p.Close(), "Pool.Close") }()

			ctx := context.Background()
			hop0 := mustHop(t, 0, "bastion-rev", "198.51.100.150", 22, 0, 0)
			hop1 := mustHop(t, 1, "app-rev", "198.51.100.151", 22, tc.keepalive, 1)
			pl := mustPlan(t, hop0, hop1)
			binding := mustBindingForPlan(t, pl.PlanDigest(), "pty", "attach")

			// 使用白盒 acquirePlan 仅在 LeaseRetire 子用例保留可调用 Retire 的租约句柄，其余场景走正常 WithLease。
			res := &mockManagedRes{label: tc.name}
			var h plan.ManagedHandle[plan.KindSession]
			var leaseRef *Lease
			if tc.name == "LeaseRetire" {
				inst, err := p.acquirePlan(ctx, pl)
				requireNoErr(t, err, "acquirePlan")
				leaseRef = newLease(p, inst, pl.PlanDigest(), "lease-retire-test")
				h, err = RegisterLeaseHandle[plan.KindSession](p, leaseRef, binding, res)
				requireNoErr(t, err, "RegisterLeaseHandle")
				p.releaseHopLease(inst)
			} else {
				err := p.WithLease(ctx, pl, func(_ context.Context, lease *Lease) error {
					var rErr error
					h, rErr = RegisterLeaseHandle[plan.KindSession](p, lease, binding, res)
					return rErr
				})
				requireNoErr(t, err, "WithLease+RegisterLeaseHandle")
			}

			// 并发进入 WithManagedHandle 等待 revokeCtx 取消，验证跳板摘除立刻中断活跃句柄借用。
			inCallback := make(chan struct{})
			runErr := conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
				if err := n.Go(func(c context.Context) error {
					return WithManagedHandle[plan.KindSession, *mockManagedRes](c, p, h, func(scopedCtx context.Context, _ *mockManagedRes) error {
						close(inCallback)
						<-scopedCtx.Done()
						return nil
					})
				}); err != nil {
					return err
				}
				return n.Go(func(context.Context) error {
					<-inCallback
					tc.trigger(t, p, clk, dialer, pl, leaseRef)
					return nil
				})
			})
			requireNoErr(t, runErr, "conc.RunWait(reverse revoke)")

			_, err := InspectHandle[plan.KindSession](p, h)
			requireErrIs(t, err, ErrHandleNotFound, "跳板摘除后句柄须已同步撤销")
			requireNoErr(t, p.WaitPendingTeardowns(ctx), "WaitPendingTeardowns")
			requireTrue(t, res.closeCount.Load() == 1, "跳板摘除后托管资源必须已被关闭")
		})
	}
}

// TestRegisterLeaseHandleFailClosedValidation 验证 RegisterLeaseHandle 对 nil/零值/过期/已退役/熔断租约严格失败关闭且零槽位泄漏。
func TestRegisterLeaseHandleFailClosedValidation(t *testing.T) {
	defer goleak.VerifyNone(t)
	p, _, _ := newTestPool(t, PoolConfig{})
	defer func() { requireNoErr(t, p.Close(), "Pool.Close") }()

	ctx := context.Background()
	pl := mustPlan(t, mustHop(t, 0, "val-pin", "198.51.100.160", 22, 0, 0))
	binding := mustBindingForPlan(t, pl.PlanDigest(), "forward", "start")

	var zeroLease Lease
	_, err := RegisterLeaseHandle[plan.KindTunnel](p, nil, binding, &mockManagedRes{label: "nil"})
	requireErrIs(t, err, ErrLeaseInvalid, "nil lease")
	_, err = RegisterLeaseHandle[plan.KindTunnel](p, &zeroLease, binding, &mockManagedRes{label: "zero"})
	requireErrIs(t, err, ErrLeaseInvalid, "zero lease")

	inst, err := p.acquirePlan(ctx, pl)
	requireNoErr(t, err, "acquirePlan")
	l := newLease(p, inst, pl.PlanDigest(), "lease-val")
	l.invalidate()
	_, err = RegisterLeaseHandle[plan.KindTunnel](p, l, binding, &mockManagedRes{label: "expired"})
	requireErrIs(t, err, ErrLeaseExpired, "expired lease")

	// 重新构造活跃哨兵但先退役底层跳板：Actor 严格校验 hopEpoch 失败并返回 ErrLeaseRevoked 且回滚槽位。
	l2 := newLease(p, inst, pl.PlanDigest(), "lease-revoked")
	p.releaseHopLease(inst)
	hopDig, _ := pl.HopDigestAt(0)
	requireNoErr(t, p.RetireHop(hopDig), "RetireHop")
	_, err = RegisterLeaseHandle[plan.KindTunnel](p, l2, binding, &mockManagedRes{label: "revoked"})
	requireErrIs(t, err, ErrLeaseRevoked, "revoked hop")
	requireTrue(t, p.Stats().ActiveHandles == 0, "失败注册绝不能泄漏槽位")

	// 熔断后注册同样必须返回 ErrGateHalted。
	p.GateHalted(errors.New("audit halt"))
	_, err = RegisterLeaseHandle[plan.KindTunnel](p, l2, binding, &mockManagedRes{label: "halted"})
	requireErrIs(t, err, ErrGateHalted, "halted pool")
}

// TestManagedHandlePinUnpinDetachConcurrentRace 并发压测句柄钉选/解钉/借用/退役/空闲驱逐竞态，验证零竞态与零协程泄漏。
func TestManagedHandlePinUnpinDetachConcurrentRace(t *testing.T) {
	defer goleak.VerifyNone(t)
	p, _, _ := newTestPool(t, PoolConfig{MaxConns: 8})
	defer func() { requireNoErr(t, p.Close(), "Pool.Close") }()

	ctx := context.Background()
	pl := mustPlan(t,
		mustHop(t, 0, "race-b", "198.51.100.170", 22, 0, 0),
		mustHop(t, 1, "race-a", "198.51.100.171", 22, 0, 0),
	)
	binding := mustBindingForPlan(t, pl.PlanDigest(), "forward", "race")
	leafDig, _ := pl.HopDigestAt(1)
	var registered atomic.Int64

	err := conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		for w := range 6 {
			workerID := w
			if err := n.Go(func(c context.Context) error {
				return runPinRaceWorker(c, p, pl, binding, leafDig, workerID, &registered)
			}); err != nil {
				return err
			}
		}
		return nil
	})
	requireNoErr(t, err, "concurrent race")
	requireTrue(t, registered.Load() > 0, "并发压测至少应完成若干次成功句柄注册")
	requireNoErr(t, p.WaitPendingTeardowns(ctx), "WaitPendingTeardowns")
}

func runPinRaceWorker(c context.Context, p *Pool, pl plan.SealedConnectionPlan, binding security.OperationBinding, leafDig plan.HopDigest, workerID int, registered *atomic.Int64) error {
	for range 25 {
		switch workerID % 3 {
		case 0:
			var h plan.ManagedHandle[plan.KindTunnel]
			if lErr := p.WithLease(c, pl, func(_ context.Context, lease *Lease) error {
				var rErr error
				h, rErr = RegisterLeaseHandle[plan.KindTunnel](p, lease, binding, &mockManagedRes{label: "race"})
				return rErr
			}); lErr == nil {
				registered.Add(1)
				_ = WithManagedHandle[plan.KindTunnel, *mockManagedRes](c, p, h, func(context.Context, *mockManagedRes) error { return nil })
				_ = ReleaseHandle[plan.KindTunnel](p, h)
			}
		case 1:
			_ = p.EvictIdle()
			_ = p.RevokeHandlesByPlan(pl.PlanDigest())
		default:
			_ = p.RetireHop(leafDig)
		}
	}
	return nil
}
