package pool

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/ports"
)

// TestKeepaliveRootEscalationConcurrentWithPoolClose 回归验证：
// 当启用保活的根跳板下存在卡死子跳触发 90ms 升级拆断、同时并发调用 Pool.Close() 时，
// 依托不可变 inst.revokeCtx 取消保活，在 -race 下零数据竞态、零 nil-func panic、零协程泄漏。
func TestKeepaliveRootEscalationConcurrentWithPoolClose(t *testing.T) {
	defer goleak.VerifyNone(t)
	clk := newSimClock()
	hop0 := mustHop(t, 0, "ka-root", "198.51.100.150", 22, 0, 3)
	hop1 := mustHop(t, 1, "ka-stuck-child", "198.51.100.151", 22, 0, 3)
	pl := mustPlan(t, hop0, hop1)
	dig0, _ := pl.HopDigestAt(0)
	dig1, _ := pl.HopDigestAt(1)

	bastionClosed := make(chan struct{})
	dialer := &mockDialer{
		hook: func(_ context.Context, hop plan.HopSpec, dig plan.HopDigest, _ ports.TransportConn) (ports.TransportConn, error) {
			mc := newMockConn(dig, hop.Endpoint())
			if dig.Equal(dig0) {
				mc.closeHook = func() error {
					close(bastionClosed)
					return nil
				}
			} else {
				mc.closeHook = func() error {
					<-bastionClosed
					return nil
				}
			}
			return mc, nil
		},
	}
	p, _, _ := newTestPool(t, PoolConfig{
		Dialer:                   dialer,
		Clock:                    clk,
		TeardownGrace:            90 * time.Millisecond,
		DefaultKeepaliveInterval: 500 * time.Millisecond,
	})

	ctx := context.Background()
	requireNoErr(t, p.WithLease(ctx, pl, func(context.Context, *Lease) error { return nil }), "dial 2-hop with keepalive")
	// 2 条连接各自装弹 1 个保活定时器（累计 2 个）。
	clk.WaitTimerCreated(t, 2)

	requireNoErr(t, p.RetireHop(dig1), "RetireHop(child)")
	// 子跳拆断再注册 1 个 90ms 定时器（累计 3 个）。
	clk.WaitTimerCreated(t, 3)

	// 并发触发 90ms 升级拆断与 Pool.Close()，验证零竞态收敛。
	err := conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			clk.Advance(90 * time.Millisecond)
			return nil
		}); gErr != nil {
			return gErr
		}
		return n.Go(func(context.Context) error {
			return p.Close()
		})
	})
	requireNoErr(t, err, "并发 90ms 升级与 Pool.Close")
	requireTrue(t, p.IsClosed() && p.Stats().ActiveLeases == 0 && p.Stats().ActiveConns == 0, "关闭后所有状态须归零")
}

// TestKeepaliveBlackholeTimeoutAndExplicitCountMaxZero 回归验证：
//  1. 黑洞 TCP（SendKeepalive 阻塞直至 <-ctx.Done()）由注入 ports.Clock 看门狗按 interval 确定性超时；
//  2. 显式配置 ServerAliveCountMax=0 时绝不静默放宽为 3，首次探活超时即刻退役并关闭连接。
func TestKeepaliveBlackholeTimeoutAndExplicitCountMaxZero(t *testing.T) {
	defer goleak.VerifyNone(t)
	clk := newSimClock()
	probeStarted := make(chan struct{}, 4)
	dialer := &mockDialer{
		hook: func(_ context.Context, hop plan.HopSpec, dig plan.HopDigest, _ ports.TransportConn) (ports.TransportConn, error) {
			mc := newMockConn(dig, hop.Endpoint())
			mc.kaHook = func(ctx context.Context) error {
				select {
				case probeStarted <- struct{}{}:
				default:
				}
				<-ctx.Done()
				return ctx.Err()
			}
			return mc, nil
		},
	}
	p, _, _ := newTestPool(t, PoolConfig{
		Dialer:                   dialer,
		Clock:                    clk,
		DefaultKeepaliveInterval: 20 * time.Millisecond,
	})
	defer func() { requireNoErr(t, p.Close(), "Pool.Close") }()

	// 显式指定 ServerAliveCountMax=0：首次黑洞超时即应触发退役。
	hop0 := mustHopWithCountMax(t, 0, "blackhole-host", "198.51.100.152", 22, 0, algebraic.Some(uint32(0)))
	pl := mustPlan(t, hop0)
	ctx := context.Background()
	requireNoErr(t, p.WithLease(ctx, pl, func(context.Context, *Lease) error { return nil }), "dial blackhole-host")
	conn := dialer.lastConn()

	// 等待保活主定时器注册（第 1 个），推进 20ms 触发首次黑洞探活。
	clk.WaitTimerCreated(t, 1)
	clk.Advance(20 * time.Millisecond)
	<-probeStarted

	// 等待单次探活有界超时看门狗注册定时器（第 2 个），再推进 20ms 使探活超时。
	clk.WaitTimerCreated(t, 2)
	clk.Advance(20 * time.Millisecond)

	// ServerAliveCountMax=0（min 1 次失败阈值）必须在第 1 次超时后立即退役并关闭连接。
	waitConnClosedCh(t, conn, "黑洞保活首次超时即退役")
	requireNoErr(t, p.WaitPendingTeardowns(ctx), "WaitPendingTeardowns(blackhole)")
	requireTrue(t, conn.kaCount.Load() == 1 && p.Stats().ActiveConns == 0, "显式 ServerAliveCountMax=0 必须在首次超时后立即退役")
}

// TestPoolCloseInflightMultiHopDialConservesActiveLeases 回归验证：
// 当多跳拨号阻塞在第 2 跳（已持有父跳临时固定计数）时执行 Pool.Close()，
// cleanupAfterActorExit 与 releaseHopLease 协同保证 ActiveLeases 严格守恒归零。
func TestPoolCloseInflightMultiHopDialConservesActiveLeases(t *testing.T) {
	defer goleak.VerifyNone(t)
	hop0 := mustHop(t, 0, "mh-root", "198.51.100.153", 22, 0, 0)
	hop1 := mustHop(t, 1, "mh-leaf", "198.51.100.154", 22, 0, 0)
	pl := mustPlan(t, hop0, hop1)
	dig1, _ := pl.HopDigestAt(1)

	hop1Entered := make(chan struct{}, 1)
	dialer := &mockDialer{
		hook: func(ctx context.Context, hop plan.HopSpec, dig plan.HopDigest, _ ports.TransportConn) (ports.TransportConn, error) {
			if dig.Equal(dig1) {
				select {
				case hop1Entered <- struct{}{}:
				default:
				}
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return newMockConn(dig, hop.Endpoint()), nil
		},
	}
	p, _, _ := newTestPool(t, PoolConfig{Dialer: dialer})

	var leaseErr error
	err := conc.RunWait(context.Background(), func(ctx context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			<-hop1Entered
			return p.Close()
		}); gErr != nil {
			return gErr
		}
		leaseErr = p.WithLease(ctx, pl, func(context.Context, *Lease) error { return nil })
		return nil
	})
	requireNoErr(t, err, "多跳在途拨号并发关闭驱动")
	requireErrIs(t, leaseErr, ErrPoolClosed, "关闭中断在途多跳拨号须返回 ErrPoolClosed")
	st := p.Stats()
	requireTrue(t, st.Closed && st.ActiveLeases == 0 && st.ActiveConns == 0 && st.DialingConns == 0, "多跳在途拨号被关闭后所有计数须严格归零")
}

// TestRetirePlanCancelsInflightDial 回归验证：
// 在针对某 PlanDigest 的拨号尚在途中时调用 RetirePlan(planDigest)，
// Actor 必须立即取消对应在途单飞拨号（返回 ErrHopRetired），并回收竞态返回的孤儿连接而不入池。
func TestRetirePlanCancelsInflightDial(t *testing.T) {
	defer goleak.VerifyNone(t)
	pl := mustPlan(t, mustHop(t, 0, "rp-host", "198.51.100.155", 22, 0, 0))
	dialEntered := make(chan struct{}, 1)
	releaseDial := make(chan struct{})
	orphanCh := make(chan *mockConn, 1)

	dialer := &mockDialer{
		hook: func(_ context.Context, hop plan.HopSpec, dig plan.HopDigest, _ ports.TransportConn) (ports.TransportConn, error) {
			select {
			case dialEntered <- struct{}{}:
			default:
			}
			<-releaseDial
			mc := newMockConn(dig, hop.Endpoint())
			orphanCh <- mc
			return mc, nil
		},
	}
	p, _, _ := newTestPool(t, PoolConfig{Dialer: dialer})
	defer func() { requireNoErr(t, p.Close(), "Pool.Close") }()

	var leaseErr error
	err := conc.RunWait(context.Background(), func(ctx context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			<-dialEntered
			if rErr := p.RetirePlan(pl.PlanDigest()); rErr != nil {
				return rErr
			}
			close(releaseDial)
			return nil
		}); gErr != nil {
			return gErr
		}
		leaseErr = p.WithLease(ctx, pl, func(context.Context, *Lease) error { return nil })
		return nil
	})
	requireNoErr(t, err, "RetirePlan 取消在途拨号驱动")
	requireErrIs(t, leaseErr, ErrHopRetired, "RetirePlan 取消在途拨号须返回 ErrHopRetired")
	waitMockConnFromCh(t, orphanCh, "RetirePlan 竞态返回孤儿连接关闭")
	requireNoErr(t, p.WaitPendingTeardowns(context.Background()), "WaitPendingTeardowns(retirePlan)")
	requireTrue(t, p.Stats().ActiveConns == 0 && p.Stats().DialingConns == 0, "已退役计划的在途拨号绝不可发布入池")
}

// TestGracefulCloseEmitsRetiredNotGateHaltedOnSystemBus 回归验证：
// 正常 Pool.Close() 回收活跃托管句柄时，SystemBus 必须发布 PoolActionRetired 而非误报 PoolActionGateHalted。
func TestGracefulCloseEmitsRetiredNotGateHaltedOnSystemBus(t *testing.T) {
	defer goleak.VerifyNone(t)
	bus, err := events.NewSystemBus(events.SystemBusConfig{DefaultSubscriberBuffer: 32})
	requireNoErr(t, err, "NewSystemBus")
	defer bus.Close()
	sub, err := bus.Subscribe()
	requireNoErr(t, err, "Subscribe")
	defer sub.Close()

	p, _, _ := newTestPool(t, PoolConfig{Bus: bus})
	pl := mustPlan(t, mustHop(t, 0, "ev-host", "198.51.100.156", 22, 0, 0))
	res := &mockManagedRes{label: "pty-close"}
	_, err = RegisterHandle[plan.KindPTY](p, pl.PlanDigest(), mustBindingForPlan(t, pl.PlanDigest(), "pty", "open"), res)
	requireNoErr(t, err, "RegisterHandle")

	requireNoErr(t, p.Close(), "Pool.Close")
	bus.Close()

	var sawRetired, sawGateHalted bool
	for {
		ev, ok, nErr := sub.Next(context.Background())
		if !ok || nErr != nil {
			break
		}
		if ps, isPS := ev.(*events.PoolStateEvent); isPS {
			if ps.Action() == events.PoolActionRetired && ps.HandleID().IsSome() {
				sawRetired = true
			}
			if ps.Action() == events.PoolActionGateHalted {
				sawGateHalted = true
			}
		}
	}
	requireTrue(t, sawRetired && !sawGateHalted, "正常 Pool.Close() 必须对句柄发布 PoolActionRetired 且严禁误报 PoolActionGateHalted")
}

// selfReleaseManagedRes 模拟在独立 reaperNursery 中自发调用 ReleaseHandle、且 Close() 无条件等待
// reaperNursery.Close() 的托管资源（如 managedMuxMaster），验证 ReleaseHandle 与 Pool.Close() 并发竞态下
// 永不落入 teardownNursery 已关闭的同步 Close 回退自死锁且零协程泄漏。
type selfReleaseManagedRes struct {
	reaper   *conc.Nursery
	trigger  chan struct{}
	closed   atomic.Bool
	once     sync.Once
	release  func()
	relReady chan struct{}
}

func (r *selfReleaseManagedRes) IsValid() bool { return r != nil && !r.closed.Load() }
func (r *selfReleaseManagedRes) Close() error {
	r.once.Do(func() {
		r.closed.Store(true)
		r.reaper.Cancel(ErrHandleRevoked)
		_ = r.reaper.Close()
	})
	return nil
}

// TestReleaseHandleConcurrentWithPoolCloseLinearizedNoSyncSelfWait 回归验证：
// ReleaseHandle 在持 slots.mu 期间预增 tdPending 与 Pool.Close() 严格线性化，
// 并发竞态下既不会在调用方自身协程同步重入 res.Close() 导致自死锁，也保证 100% 确定性排空与零泄漏。
func TestReleaseHandleConcurrentWithPoolCloseLinearizedNoSyncSelfWait(t *testing.T) {
	defer goleak.VerifyNone(t)
	pl := mustPlan(t, mustHop(t, 0, "lin-host", "198.51.100.161", 22, 0, 0))
	binding := mustBindingForPlan(t, pl.PlanDigest(), "mux", "start")
	for range 40 {
		p, _, _ := newTestPool(t, PoolConfig{})
		reaper, err := conc.NewNursery(context.Background())
		requireNoErr(t, err, "NewNursery")
		res := &selfReleaseManagedRes{reaper: reaper, trigger: make(chan struct{}), relReady: make(chan struct{})}
		requireNoErr(t, reaper.Go(func(rCtx context.Context) error {
			select {
			case <-rCtx.Done():
				return nil
			case <-res.trigger:
			}
			select {
			case <-rCtx.Done():
				return nil
			case <-res.relReady:
			}
			res.release()
			return nil
		}), "reaper.Go")
		h, err := RegisterHandle[plan.KindMux](p, pl.PlanDigest(), binding, res)
		requireNoErr(t, err, "RegisterHandle")
		res.release = func() { _ = ReleaseHandle[plan.KindMux](p, h) }
		close(res.relReady)

		requireNoErr(t, conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
			start := make(chan struct{})
			if gErr := n.Go(func(context.Context) error { <-start; close(res.trigger); return nil }); gErr != nil {
				return gErr
			}
			if gErr := n.Go(func(context.Context) error { <-start; _ = p.Close(); return nil }); gErr != nil {
				return gErr
			}
			close(start)
			return nil
		}), "RunWait concurrent ReleaseHandle vs Pool.Close")
		requireTrue(t, res.closed.Load(), "资源必须已确定性关闭")
		requireNoErr(t, p.WaitPendingTeardowns(context.Background()), "WaitPendingTeardowns")
	}
}
