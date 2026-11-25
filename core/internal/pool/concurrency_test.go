package pool

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/ports"
)

func TestFullMailboxReleaseNeverDeadlocks(t *testing.T) {
	defer goleak.VerifyNone(t)
	blockDial := make(chan struct{})
	dialEntered := make(chan struct{}, 1)
	slowPlan := mustPlan(t, mustHop(t, 0, "slow-host", "198.51.100.70", 22, 0, 0))
	fastPlan := mustPlan(t, mustHop(t, 0, "fast-host", "198.51.100.71", 22, 0, 0))
	slowDig, _ := slowPlan.HopDigestAt(0)

	dialer := &mockDialer{
		hook: func(ctx context.Context, hop plan.HopSpec, dig plan.HopDigest, _ ports.TransportConn) (ports.TransportConn, error) {
			if dig.Equal(slowDig) {
				select {
				case dialEntered <- struct{}{}:
				default:
				}
				select {
				case <-blockDial:
					return newMockConn(dig, hop.Endpoint()), nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return newMockConn(dig, hop.Endpoint()), nil
		},
	}
	p, _, _ := newTestPool(t, PoolConfig{Dialer: dialer, AcquireBuffer: 1})
	defer func() {
		close(blockDial)
		requireNoErr(t, p.Close(), "Pool.Close")
	}()

	ctx := context.Background()
	// 预热 fastPlan 以便在满邮箱高压下反复申请与归还租约。
	requireNoErr(t, p.WithLease(ctx, fastPlan, func(context.Context, *Lease) error { return nil }), "warmup fastPlan")

	// 在 AcquireBuffer=1 下用 20 个并发慢请求洪泛请求邮箱，同时快速租约持续申请与归还，绝不死锁。
	floodCtx, cancelFlood := context.WithCancel(ctx)
	defer cancelFlood()
	err := conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		if fErr := spawnLeaseFlood(n, p, floodCtx, slowPlan, 20); fErr != nil {
			return fErr
		}
		<-dialEntered
		if rErr := runFastLeaseCycles(ctx, p, fastPlan, 40); rErr != nil {
			return rErr
		}
		cancelFlood()
		return nil
	})
	requireNoErr(t, err, "满邮箱高并发归还压测")
	requireTrue(t, p.Stats().ActiveLeases == 0, "满邮箱压测结束后活跃租约必须归零")
}

func spawnLeaseFlood(n *conc.Nursery, p *Pool, floodCtx context.Context, pl plan.SealedConnectionPlan, count int) error {
	for range count {
		if err := n.Go(func(context.Context) error {
			_ = p.WithLease(floodCtx, pl, func(context.Context, *Lease) error { return nil })
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

func runFastLeaseCycles(ctx context.Context, p *Pool, pl plan.SealedConnectionPlan, cycles int) error {
	for range cycles {
		err := p.WithLease(ctx, pl, func(sCtx context.Context, l *Lease) error {
			sess, sErr := l.OpenSession(sCtx)
			if sErr != nil {
				return sErr
			}
			return sess.Close()
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func TestPoolCloseReleaseNeverHangs(t *testing.T) {
	defer goleak.VerifyNone(t)
	p, _, _ := newTestPool(t, PoolConfig{})
	pl := mustPlan(t, mustHop(t, 0, "close-host", "198.51.100.72", 22, 0, 0))

	entered := make(chan struct{})
	closedDone := make(chan struct{})
	err := conc.RunWait(context.Background(), func(ctx context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			<-entered
			if cErr := p.Close(); cErr != nil {
				return cErr
			}
			close(closedDone)
			return nil
		}); gErr != nil {
			return gErr
		}
		return p.WithLease(ctx, pl, func(scopedCtx context.Context, l *Lease) error {
			close(entered)
			<-closedDone
			<-scopedCtx.Done()
			_, sErr := l.OpenSession(context.Background())
			if !errors.Is(sErr, ErrPoolClosed) && !errors.Is(sErr, ErrLeaseRevoked) {
				return errors.New("池关闭后数据面必须失败关闭")
			}
			// 返回后 defer 中的 ReleaseLease 必须监听 actorDone 且绝不挂起。
			return nil
		})
	})
	requireNoErr(t, err, "池关闭期间归还租约不得挂起")
	requireTrue(t, p.IsClosed() && p.Stats().ActiveLeases == 0, "池关闭且租约归还后 ActiveLeases 必须严格守恒为 0")
}

func TestParentEpochCASInvalidation(t *testing.T) {
	defer goleak.VerifyNone(t)
	hop0 := mustHop(t, 0, "bastion", "198.51.100.80", 22, 0, 0)
	hop1 := mustHop(t, 1, "app", "198.51.100.81", 22, 0, 0)
	pl := mustPlan(t, hop0, hop1)
	dig0, _ := pl.HopDigestAt(0)
	dig1, _ := pl.HopDigestAt(1)

	hop1Started := make(chan struct{}, 1)
	releaseHop1 := make(chan struct{})
	staleConnCh := make(chan *mockConn, 1)
	var hop1Attempt atomic.Int32

	dialer := &mockDialer{
		hook: func(ctx context.Context, hop plan.HopSpec, dig plan.HopDigest, _ ports.TransportConn) (ports.TransportConn, error) {
			if dig.Equal(dig1) && hop1Attempt.Add(1) == 1 {
				select {
				case hop1Started <- struct{}{}:
				default:
				}
				// 故意忽略 ctx 取消并在放行后返回一条绑定旧父代的连接，检验 onDialDone 侧孤儿回收与父代 CAS。
				<-releaseHop1
				mc := newMockConn(dig, hop.Endpoint())
				staleConnCh <- mc
				return mc, nil
			}
			return newMockConn(dig, hop.Endpoint()), nil
		},
	}
	p, _, _ := newTestPool(t, PoolConfig{Dialer: dialer})
	defer func() { requireNoErr(t, p.Close(), "Pool.Close") }()

	ctx := context.Background()
	var leaseErr error
	err := conc.RunWait(ctx, func(c context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			<-hop1Started
			if rErr := p.RetireHop(dig0); rErr != nil {
				return rErr
			}
			close(releaseHop1)
			return nil
		}); gErr != nil {
			return gErr
		}
		leaseErr = p.WithLease(c, pl, func(context.Context, *Lease) error { return nil })
		return nil
	})
	requireNoErr(t, err, "父代 CAS 并发驱动")
	requireErrIs(t, leaseErr, ErrParentEpochChanged, "上游父跳退役必须触发 ErrParentEpochChanged")
	requireTrue(t, p.Stats().ParentCASRejections >= 1, "ParentCASRejections 计数应递增")

	// 确保陈旧 hop1 连接被立即关闭且池未被毒化（直接等待 closedCh，零 CPU 自旋）。
	waitMockConnFromCh(t, staleConnCh, "陈旧子跳连接关闭")
	requireNoErr(t, p.WaitPendingTeardowns(ctx), "WaitPendingTeardowns")
	requireNoErr(t, p.WithLease(ctx, pl, func(_ context.Context, l *Lease) error {
		requireTrue(t, l.IsAlive(), "重拨后新连接必须存活")
		return nil
	}), "重拨干净链路")
}

func waitMockConnFromCh(t *testing.T, ch <-chan *mockConn, label string) {
	t.Helper()
	var mc *mockConn
	select {
	case mc = <-ch:
	case <-time.After(3 * time.Second):
		t.Fatalf("%s 超时：未收到连接实例", label)
	}
	waitConnClosedCh(t, mc, label)
}

func TestBoundedTeardown90msFastAndEscalation(t *testing.T) {
	t.Run("FastChildClosePreservesBastion", func(t *testing.T) {
		defer goleak.VerifyNone(t)
		clk := newSimClock()
		dialer := &mockDialer{}
		p, _, _ := newTestPool(t, PoolConfig{Dialer: dialer, Clock: clk, TeardownGrace: 90 * time.Millisecond})
		defer func() { requireNoErr(t, p.Close(), "Pool.Close") }()

		hop0 := mustHop(t, 0, "bastion", "198.51.100.90", 22, 0, 0)
		hop1 := mustHop(t, 1, "app", "198.51.100.91", 22, 0, 0)
		pl := mustPlan(t, hop0, hop1)
		dig1, _ := pl.HopDigestAt(1)
		ctx := context.Background()

		requireNoErr(t, p.WithLease(ctx, pl, func(context.Context, *Lease) error { return nil }), "dial 2-hop")
		dialer.mu.Lock()
		bastionConn, appConn := dialer.conns[0], dialer.conns[1]
		dialer.mu.Unlock()

		requireNoErr(t, p.RetireHop(dig1), "RetireHop(app)")
		requireNoErr(t, p.WaitPendingTeardowns(ctx), "WaitPendingTeardowns(fast)")
		requireTrue(t, appConn.closeCount.Load() == 1, "子跳连接应已优雅关闭")
		requireTrue(t, bastionConn.closeCount.Load() == 0 && bastionConn.IsAlive(), "90ms 内关闭子跳不得误伤健康父跳板")
		requireTrue(t, p.Stats().TeardownEscalations == 0 && p.Stats().ActiveConns == 1, "不应触发升级拆断")
	})

	t.Run("StuckChildEscalatesToAbortRootAt90ms", func(t *testing.T) {
		defer goleak.VerifyNone(t)
		clk := newSimClock()
		hop0 := mustHop(t, 0, "bastion", "198.51.100.92", 22, 0, 0)
		hop1 := mustHop(t, 1, "app-stuck", "198.51.100.93", 22, 0, 0)
		pl := mustPlan(t, hop0, hop1)
		dig0, _ := pl.HopDigestAt(0)
		dig1, _ := pl.HopDigestAt(1)

		var bastionConn, appConn *mockConn
		bastionAborted := make(chan struct{})
		dialer := &mockDialer{
			hook: func(_ context.Context, hop plan.HopSpec, dig plan.HopDigest, _ ports.TransportConn) (ports.TransportConn, error) {
				mc := newMockConn(dig, hop.Endpoint())
				if dig.Equal(dig0) {
					mc.closeHook = func() error {
						close(bastionAborted)
						return nil
					}
					bastionConn = mc
				} else {
					// 模拟多跳信道关闭卡死，直至父跳板被 90ms 升级拆断后才解除阻塞（INV-C3）。
					mc.closeHook = func() error {
						<-bastionAborted
						return nil
					}
					appConn = mc
				}
				return mc, nil
			},
		}
		p, _, _ := newTestPool(t, PoolConfig{Dialer: dialer, Clock: clk, TeardownGrace: 90 * time.Millisecond})
		defer func() { requireNoErr(t, p.Close(), "Pool.Close") }()
		ctx := context.Background()

		requireNoErr(t, p.WithLease(ctx, pl, func(context.Context, *Lease) error { return nil }), "dial stuck 2-hop")
		requireNoErr(t, p.RetireHop(dig1), "RetireHop(app-stuck)")
		clk.WaitTimerCreated(t, 1)

		// 推进 50ms（未满 90ms）：父跳板必须依然存活且未升级。
		clk.Advance(50 * time.Millisecond)
		requireTrue(t, bastionConn.closeCount.Load() == 0 && p.Stats().TeardownEscalations == 0, "未达 90ms 宽限时不得提前拆断父跳板")

		// 再推进 40ms（累计满 90ms）：触发升级拆断父跳板，进而解除子跳阻塞。
		clk.Advance(40 * time.Millisecond)
		requireNoErr(t, p.WaitPendingTeardowns(ctx), "WaitPendingTeardowns(escalated)")
		<-appConn.closedCh
		requireTrue(t, bastionConn.closeCount.Load() == 1 && appConn.closeCount.Load() == 1, "90ms 升级后父子连接均须完成关闭")
		requireTrue(t, p.Stats().TeardownEscalations == 1 && p.Stats().ActiveConns == 0, "须记录 1 次升级拆断并清空活跃连接")
	})

	t.Run("StuckRootCloseBoundedAt90ms", func(t *testing.T) {
		defer goleak.VerifyNone(t)
		clk := newSimClock()
		unblockRoot := make(chan struct{})
		dialer := &mockDialer{
			hook: func(_ context.Context, hop plan.HopSpec, dig plan.HopDigest, _ ports.TransportConn) (ports.TransportConn, error) {
				mc := newMockConn(dig, hop.Endpoint())
				mc.closeHook = func() error {
					<-unblockRoot
					return nil
				}
				return mc, nil
			},
		}
		p, _, _ := newTestPool(t, PoolConfig{Dialer: dialer, Clock: clk, TeardownGrace: 90 * time.Millisecond})
		pl := mustPlan(t, mustHop(t, 0, "slow-root", "198.51.100.94", 22, 0, 0))
		dig0, _ := pl.HopDigestAt(0)
		ctx := context.Background()

		requireNoErr(t, p.WithLease(ctx, pl, func(context.Context, *Lease) error { return nil }), "dial slow-root")
		requireNoErr(t, p.RetireHop(dig0), "RetireHop(slow-root)")
		clk.WaitTimerCreated(t, 1)
		clk.Advance(90 * time.Millisecond)

		// 即使底层根连接 Close 尚未解除阻塞，90ms 有界拆断等待也必须立刻收敛返回。
		requireNoErr(t, p.WaitPendingTeardowns(ctx), "90ms 有界拆断必须在宽限点返回")
		requireTrue(t, p.Stats().TeardownEscalations == 1, "根连接超时拆断应累加 TeardownEscalations")

		close(unblockRoot)
		requireNoErr(t, p.Close(), "Pool.Close")
	})
}

func TestSingleFlightCoalescingAndWaiterCancel(t *testing.T) {
	defer goleak.VerifyNone(t)
	releaseDial := make(chan struct{})
	dialStarted := make(chan struct{}, 1)
	dialer := &mockDialer{
		hook: func(ctx context.Context, hop plan.HopSpec, dig plan.HopDigest, _ ports.TransportConn) (ports.TransportConn, error) {
			select {
			case dialStarted <- struct{}{}:
			default:
			}
			select {
			case <-releaseDial:
				return newMockConn(dig, hop.Endpoint()), nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
	}
	p, _, _ := newTestPool(t, PoolConfig{Dialer: dialer})
	defer func() { requireNoErr(t, p.Close(), "Pool.Close") }()

	pl := mustPlan(t, mustHop(t, 0, "sf-host", "198.51.100.95", 22, 0, 0))
	ctx := context.Background()
	canceledCtx, cancelFirst := context.WithCancel(ctx)

	var succeeded atomic.Int32
	err := conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			wErr := p.WithLease(canceledCtx, pl, func(context.Context, *Lease) error { return nil })
			if !errors.Is(wErr, context.Canceled) {
				return errors.New("被取消等待者须返回 context.Canceled")
			}
			return nil
		}); gErr != nil {
			return gErr
		}
		for range 7 {
			if gErr := n.Go(func(c context.Context) error {
				return p.WithLease(c, pl, func(context.Context, *Lease) error {
					succeeded.Add(1)
					return nil
				})
			}); gErr != nil {
				return gErr
			}
		}
		<-dialStarted
		// 等其余等待者汇入单飞后再取消第 1 个等待者，确保不会误杀仍在等待的其余 7 个调用方。
		cancelFirst()
		close(releaseDial)
		return nil
	})
	requireNoErr(t, err, "单飞合并与部分取消测试")
	requireTrue(t, dialer.dialCount.Load() == 1 && succeeded.Load() == 7, "8 并发请求应仅触发 1 次拨号且其余 7 者全部成功")
	requireTrue(t, p.Stats().ActiveLeases == 0, "全部归还后 ActiveLeases 必须归零")
}

func TestWithMultiLeaseOppositeOrderDeadlockFree(t *testing.T) {
	defer goleak.VerifyNone(t)
	p, _, _ := newTestPool(t, PoolConfig{AcquireBuffer: 2})
	defer func() { requireNoErr(t, p.Close(), "Pool.Close") }()

	plA := mustPlan(t, mustHop(t, 0, "m-a", "198.51.100.101", 22, 0, 0))
	plB := mustPlan(t, mustHop(t, 0, "m-b", "198.51.100.102", 22, 0, 0))
	plC := mustPlan(t, mustHop(t, 0, "m-c", "198.51.100.103", 22, 0, 0))
	fwd := []plan.SealedConnectionPlan{plA, plB, plC}
	rev := []plan.SealedConnectionPlan{plC, plB, plA}

	err := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		for i := range 16 {
			order := fwd
			if i%2 == 1 {
				order = rev
			}
			if gErr := n.Go(func(c context.Context) error {
				return runMultiLeaseWorker(c, p, order, 25)
			}); gErr != nil {
				return gErr
			}
		}
		return nil
	})
	requireNoErr(t, err, "WithMultiLease 反序并发无死锁压测")
	requireTrue(t, p.Stats().ActiveLeases == 0 && p.Stats().ActiveConns == 3, "压测结束后活跃租约应为 0 且连接数应为 3")
}

func runMultiLeaseWorker(ctx context.Context, p *Pool, order []plan.SealedConnectionPlan, rounds int) error {
	for range rounds {
		err := p.WithMultiLease(ctx, order, func(sCtx context.Context, ls []*Lease) error {
			return verifyMultiLeaseSlice(sCtx, order, ls)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func verifyMultiLeaseSlice(ctx context.Context, order []plan.SealedConnectionPlan, ls []*Lease) error {
	for j, l := range ls {
		if !l.PlanDigest().Equal(order[j].PlanDigest()) || !l.IsAlive() {
			return errors.New("WithMultiLease 顺序或存活状态校验失败")
		}
		sess, err := l.OpenSession(ctx)
		if err != nil {
			return err
		}
		if err := sess.Close(); err != nil {
			return err
		}
	}
	return nil
}

func TestGateHaltedRevokesAllHandlesLeasesAndInflightDials(t *testing.T) {
	defer goleak.VerifyNone(t)
	dialEntered := make(chan struct{}, 1)
	plLive := mustPlan(t, mustHop(t, 0, "live", "198.51.100.110", 22, 0, 0))
	plDial := mustPlan(t, mustHop(t, 0, "dialing", "198.51.100.111", 22, 0, 0))
	dialDig, _ := plDial.HopDigestAt(0)

	dialer := &mockDialer{
		hook: func(ctx context.Context, hop plan.HopSpec, dig plan.HopDigest, _ ports.TransportConn) (ports.TransportConn, error) {
			if dig.Equal(dialDig) {
				select {
				case dialEntered <- struct{}{}:
				default:
				}
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return newMockConn(dig, hop.Endpoint()), nil
		},
	}
	p, _, _ := newTestPool(t, PoolConfig{Dialer: dialer})
	defer func() { requireNoErr(t, p.Close(), "Pool.Close") }()
	ctx := context.Background()

	// 预先登记 2 个不同类别的 ManagedHandle（PTY + Tunnel）。
	resPTY := &mockManagedRes{label: "pty-1"}
	resTun := &mockManagedRes{label: "tun-1"}
	hPTY, err := RegisterHandle[plan.KindPTY](p, plLive.PlanDigest(), mustBindingForPlan(t, plLive.PlanDigest(), "term", "open"), resPTY)
	requireNoErr(t, err, "RegisterHandle(PTY)")
	hTun, err := RegisterHandle[plan.KindTunnel](p, plLive.PlanDigest(), mustBindingForPlan(t, plLive.PlanDigest(), "tunnel", "open"), resTun)
	requireNoErr(t, err, "RegisterHandle(Tunnel)")

	leaseActive := make(chan struct{})
	var dialFailErr error
	haltCause := errors.New("audit enospc")

	err = conc.RunWait(ctx, func(c context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(gc context.Context) error {
			dialFailErr = p.WithLease(gc, plDial, func(context.Context, *Lease) error { return nil })
			return nil
		}); gErr != nil {
			return gErr
		}
		if gErr := n.Go(func(context.Context) error {
			<-leaseActive
			<-dialEntered
			// 并发幂等调用 GateHalted（直接匹配 gate.OnHaltFunc 语义）。
			p.GateHalted(haltCause)
			p.GateHalted(errors.New("second ignored halt"))
			return nil
		}); gErr != nil {
			return gErr
		}
		return p.WithLease(c, plLive, func(scopedCtx context.Context, l *Lease) error {
			close(leaseActive)
			<-scopedCtx.Done()
			_, sErr := l.OpenSession(context.Background())
			if !errors.Is(sErr, ErrGateHalted) {
				return errors.New("GateHalted 后数据面必须立即返回 ErrGateHalted")
			}
			return nil
		})
	})
	requireNoErr(t, err, "GateHalted 联动吊销测试")
	requireErrIs(t, dialFailErr, ErrGateHalted, "在途拨号必须因 GateHalted 失败")
	requireNoErr(t, p.WaitPendingTeardowns(ctx), "WaitPendingTeardowns(halted)")

	requireTrue(t, p.IsHalted() && p.Stats().Halted, "池必须处于 Halted 态")
	requireTrue(t, p.Stats().ActiveConns == 0 && p.Stats().ActiveHandles == 0 && p.Stats().ActiveLeases == 0, "所有连接、句柄与租约必须清零")
	requireTrue(t, resPTY.closeCount.Load() == 1 && resTun.closeCount.Load() == 1, "所有托管资源必须被关闭一次")

	// 熔断后一切后续申请与句柄操作均须失败关闭返回 ErrGateHalted。
	requireErrIs(t, p.WithLease(ctx, plLive, func(context.Context, *Lease) error { return nil }), ErrGateHalted, "post-halt WithLease")
	requireErrIs(t, p.WithMultiLease(ctx, []plan.SealedConnectionPlan{plLive}, func(context.Context, []*Lease) error { return nil }), ErrGateHalted, "post-halt WithMultiLease")
	requireErrIs(t, WithManagedHandle[plan.KindPTY, *mockManagedRes](ctx, p, hPTY, func(context.Context, *mockManagedRes) error { return nil }), ErrGateHalted, "post-halt WithManagedHandle")
	_, err = InspectHandle[plan.KindTunnel](p, hTun)
	requireErrIs(t, err, ErrGateHalted, "post-halt InspectHandle")
	_, err = RegisterHandle[plan.KindPTY](p, plLive.PlanDigest(), mustBindingForPlan(t, plLive.PlanDigest(), "term", "new"), &mockManagedRes{})
	requireErrIs(t, err, ErrGateHalted, "post-halt RegisterHandle")
}

func TestGenerationalSlotMapLifecycleAndSafety(t *testing.T) {
	defer goleak.VerifyNone(t)
	p, _, _ := newTestPool(t, PoolConfig{MaxHandles: 2})
	defer func() { requireNoErr(t, p.Close(), "Pool.Close") }()

	ctx := context.Background()
	pl1 := mustPlan(t, mustHop(t, 0, "s1", "198.51.100.120", 22, 0, 0))
	pl2 := mustPlan(t, mustHop(t, 0, "s2", "198.51.100.121", 22, 0, 0))
	b1 := mustBindingForPlan(t, pl1.PlanDigest(), "pty", "open")
	b2 := mustBindingForPlan(t, pl2.PlanDigest(), "pty", "open")

	// 绑定 PlanDigest 不一致、typed-nil 指针、零值与无效状态资源均须失败关闭拒绝。
	_, err := RegisterHandle[plan.KindPTY](p, pl1.PlanDigest(), b2, &mockManagedRes{label: "bad"})
	requireErrIs(t, err, ErrHandleBindingMismatch, "binding 与 planDigest 不匹配须拒绝")
	var typedNil *mockManagedRes
	_, err = RegisterHandle[plan.KindPTY](p, pl1.PlanDigest(), b1, typedNil)
	requireErrIs(t, err, ErrInvalidResource, "typed-nil 托管资源须被拒绝")
	_, err = RegisterHandle[plan.KindPTY](p, pl1.PlanDigest(), b1, mockValueRes{})
	requireErrIs(t, err, ErrInvalidResource, "零值结构体托管资源须被拒绝")
	_, err = RegisterHandle[plan.KindPTY](p, pl1.PlanDigest(), b1, mockValueRes{label: "uninit", valid: false})
	requireErrIs(t, err, ErrInvalidResource, "IsValid()==false 结构体托管资源须被拒绝")
	invalidPtr := &mockManagedRes{label: "closed"}
	invalidPtr.invalid.Store(true)
	_, err = RegisterHandle[plan.KindPTY](p, pl1.PlanDigest(), b1, invalidPtr)
	requireErrIs(t, err, ErrInvalidResource, "IsValid()==false 指针托管资源须被拒绝")

	// 正常登记并检查 Inspect / WithManagedHandle。
	r1 := &mockManagedRes{label: "pty-a"}
	h1, err := RegisterHandle[plan.KindPTY](p, pl1.PlanDigest(), b1, r1)
	requireNoErr(t, err, "RegisterHandle(h1)")
	st, err := InspectHandle[plan.KindPTY](p, h1)
	requireNoErr(t, err, "InspectHandle(h1)")
	requireTrue(t, st.IsValid() && st.Active() && st.Generation() == h1.Generation() && st.ID().Equal(h1.ID()), "HandleStatus 字段须一致")

	var matched bool
	err = WithManagedHandle[plan.KindPTY, *mockManagedRes](ctx, p, h1, func(_ context.Context, res *mockManagedRes) error {
		matched = res.label == "pty-a"
		return nil
	})
	requireNoErr(t, err, "WithManagedHandle(h1)")
	requireTrue(t, matched, "借用资源标签须匹配")

	// 若托管资源在进入回调前变为无效，WithManagedHandle 须拦截且绝不调用 fn。
	r1.invalid.Store(true)
	invoked := false
	err = WithManagedHandle[plan.KindPTY, *mockManagedRes](ctx, p, h1, func(context.Context, *mockManagedRes) error {
		invoked = true
		return nil
	})
	requireErrIs(t, err, ErrInvalidResource, "无效托管资源进入回调前须拦截")
	requireTrue(t, !invoked, "前置门控拒绝时绝不可调用用户回调 fn")
	r1.invalid.Store(false)

	// 伪造过旧/错误世代的同 ID 句柄必须返回 ErrHandleGenerationMismatch。
	forgedGen, err := plan.NewManagedHandle[plan.KindPTY](h1.ID(), h1.Generation()+99, pl1.PlanDigest(), b1)
	requireNoErr(t, err, "NewManagedHandle(forged)")
	err = WithManagedHandle[plan.KindPTY, *mockManagedRes](ctx, p, forgedGen, func(context.Context, *mockManagedRes) error { return nil })
	requireErrIs(t, err, ErrHandleGenerationMismatch, "伪造世代句柄必须被拒绝")

	// 达到 MaxHandles=2 后拒绝第 3 个登记。
	r2 := &mockManagedRes{label: "pty-b"}
	h2, err := RegisterHandle[plan.KindPTY](p, pl2.PlanDigest(), b2, r2)
	requireNoErr(t, err, "RegisterHandle(h2)")
	_, err = RegisterHandle[plan.KindPTY](p, pl2.PlanDigest(), b2, &mockManagedRes{label: "overflow"})
	requireErrIs(t, err, ErrHandleLimitExceeded, "超出 MaxHandles 须失败关闭")

	// 释放 h1 后槽位可复用且世代号严格递增；再次使用旧 h1 失败关闭。
	requireNoErr(t, ReleaseHandle[plan.KindPTY](p, h1), "ReleaseHandle(h1)")
	requireNoErr(t, p.WaitPendingTeardowns(ctx), "WaitPendingTeardowns(h1)")
	requireTrue(t, r1.closeCount.Load() == 1, "释放后底层资源须被关闭")
	err = WithManagedHandle[plan.KindPTY, *mockManagedRes](ctx, p, h1, func(context.Context, *mockManagedRes) error { return nil })
	requireErrIs(t, err, ErrHandleNotFound, "已释放旧句柄不可再次借用")

	r3 := &mockManagedRes{label: "pty-c"}
	h3, err := RegisterHandle[plan.KindPTY](p, pl1.PlanDigest(), b1, r3)
	requireNoErr(t, err, "RegisterHandle(h3 reuse slot)")
	requireTrue(t, h3.Generation() > h2.Generation(), "复用槽位后世代号必须单调递增")

	// RevokeHandlesByPlan 仅吊销绑定 pl2 的句柄 h2，不影响 pl1 的 h3。
	requireTrue(t, p.RevokeHandlesByPlan(pl2.PlanDigest()) == 1, "RevokeHandlesByPlan(pl2) 应回收 1 个句柄")
	requireNoErr(t, p.WaitPendingTeardowns(ctx), "WaitPendingTeardowns(pl2)")
	requireTrue(t, r2.closeCount.Load() == 1 && r3.closeCount.Load() == 0, "按计划回收不得误伤其他计划句柄")
	st3, err := InspectHandle[plan.KindPTY](p, h3)
	requireNoErr(t, err, "InspectHandle(h3)")
	requireTrue(t, st3.Active(), "h3 必须仍处于活跃态")
}

func TestKeepaliveProbesAndMissRetirement(t *testing.T) {
	defer goleak.VerifyNone(t)
	clk := newSimClock()
	var failKA atomic.Bool
	kaProbed := make(chan struct{}, 16)
	dialer := &mockDialer{
		hook: func(_ context.Context, hop plan.HopSpec, dig plan.HopDigest, _ ports.TransportConn) (ports.TransportConn, error) {
			mc := newMockConn(dig, hop.Endpoint())
			mc.kaHook = func(context.Context) error {
				select {
				case kaProbed <- struct{}{}:
				default:
				}
				if failKA.Load() {
					return errors.New("keepalive timeout")
				}
				return nil
			}
			return mc, nil
		},
	}
	p, _, _ := newTestPool(t, PoolConfig{
		Dialer:                   dialer,
		Clock:                    clk,
		DefaultKeepaliveInterval: 10 * time.Millisecond,
	})
	defer func() { requireNoErr(t, p.Close(), "Pool.Close") }()

	pl := mustPlan(t, mustHop(t, 0, "ka-host", "198.51.100.130", 22, 0, 2))
	ctx := context.Background()
	requireNoErr(t, p.WithLease(ctx, pl, func(context.Context, *Lease) error { return nil }), "dial ka-host")
	kaConn := dialer.lastConn()
	clk.WaitTimerCreated(t, 1)

	// 第 1 次探活成功：每次探活还会创建一个有界看门狗定时器，故下一轮间隔重置时 armedCount 至少增 2。
	clk.Advance(10 * time.Millisecond)
	<-kaProbed
	clk.WaitTimerArmed(t, 3)
	requireTrue(t, p.Stats().ActiveConns == 1, "保活成功后连接须保持活跃")

	// 连续 2 次保活失败达到 HopSpec.ServerAliveCountMax=2 阈值：连接自动退役并关闭（等待 closedCh，零忙等）。
	failKA.Store(true)
	clk.Advance(10 * time.Millisecond)
	<-kaProbed
	clk.WaitTimerArmed(t, 5)
	clk.Advance(10 * time.Millisecond)
	<-kaProbed
	waitConnClosedCh(t, kaConn, "保活连续失败退役关闭")
	requireNoErr(t, p.WaitPendingTeardowns(ctx), "WaitPendingTeardowns(ka)")
	requireTrue(t, p.Stats().ActiveConns == 0 && kaConn.closeCount.Load() == 1, "保活失败退役连接须关闭且活跃数归零")
}

func TestAllWaitersCanceledClosesOrphanAndParentCtxShutdown(t *testing.T) {
	t.Run("AllWaitersCanceledOrphanConnClosed", func(t *testing.T) {
		defer goleak.VerifyNone(t)
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

		pl := mustPlan(t, mustHop(t, 0, "orphan-h", "198.51.100.135", 22, 0, 0))
		wCtx, cancelW := context.WithCancel(context.Background())
		var leaseErr error
		err := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
			if gErr := n.Go(func(context.Context) error {
				<-dialEntered
				cancelW()
				return nil
			}); gErr != nil {
				return gErr
			}
			leaseErr = p.WithLease(wCtx, pl, func(context.Context, *Lease) error { return nil })
			return nil
		})
		requireNoErr(t, err, "全部等待者取消驱动")
		requireErrIs(t, leaseErr, context.Canceled, "等待者取消须返回 context.Canceled")
		close(releaseDial)
		waitMockConnFromCh(t, orphanCh, "全部等待者取消后孤儿连接关闭")
		requireNoErr(t, p.WaitPendingTeardowns(context.Background()), "WaitPendingTeardowns(orphan)")
	})

	t.Run("ParentCtxCancelCleansUpPoolAndSlots", func(t *testing.T) {
		defer goleak.VerifyNone(t)
		parentCtx, cancelParent := context.WithCancel(context.Background())
		dialer := &mockDialer{}
		p, err := NewPool(parentCtx, PoolConfig{
			Dialer:  dialer,
			Clock:   newSimClock(),
			Entropy: newSeqEntropy(31),
		})
		requireNoErr(t, err, "NewPool(parentCtx)")
		pl := mustPlan(t, mustHop(t, 0, "parent-h", "198.51.100.136", 22, 0, 0))
		requireNoErr(t, p.WithLease(context.Background(), pl, func(context.Context, *Lease) error { return nil }), "dial")
		res := &mockManagedRes{label: "parent-res"}
		_, err = RegisterHandle[plan.KindTransfer](p, pl.PlanDigest(), mustBindingForPlan(t, pl.PlanDigest(), "transfer", "put"), res)
		requireNoErr(t, err, "RegisterHandle")

		cancelParent()
		requireNoErr(t, p.Close(), "Pool.Close(after parent cancel)")
		requireTrue(t, res.closeCount.Load() == 1 && dialer.lastConn().closeCount.Load() == 1, "父上下文取消后连接与托管资源均须清理")
	})

	t.Run("WithManagedHandleConcurrentReleaseCancelsScopedCtx", func(t *testing.T) {
		defer goleak.VerifyNone(t)
		p, _, _ := newTestPool(t, PoolConfig{})
		defer func() { requireNoErr(t, p.Close(), "Pool.Close") }()

		pl := mustPlan(t, mustHop(t, 0, "slot-h", "198.51.100.137", 22, 0, 0))
		res := &mockManagedRes{label: "live-res"}
		h, err := RegisterHandle[plan.KindMux](p, pl.PlanDigest(), mustBindingForPlan(t, pl.PlanDigest(), "mux", "hold"), res)
		requireNoErr(t, err, "RegisterHandle(KindMux)")

		entered := make(chan struct{})
		err = conc.RunWait(context.Background(), func(ctx context.Context, n *conc.Nursery) error {
			if gErr := n.Go(func(context.Context) error {
				<-entered
				return ReleaseHandle[plan.KindMux](p, h)
			}); gErr != nil {
				return gErr
			}
			return WithManagedHandle[plan.KindMux, *mockManagedRes](ctx, p, h, func(scopedCtx context.Context, _ *mockManagedRes) error {
				close(entered)
				<-scopedCtx.Done()
				return nil
			})
		})
		requireNoErr(t, err, "并发 ReleaseHandle 须立即取消 WithManagedHandle 上下文")
		requireNoErr(t, p.WaitPendingTeardowns(context.Background()), "WaitPendingTeardowns")
		requireTrue(t, res.closeCount.Load() == 1, "并发释放后资源必须关闭")
	})
}

func TestConcurrentChaosRetireAcquireAndGateHalted(t *testing.T) {
	defer goleak.VerifyNone(t)
	p, _, _ := newTestPool(t, PoolConfig{AcquireBuffer: 4, MaxConns: 4})
	defer func() { requireNoErr(t, p.Close(), "Pool.Close") }()

	hop0 := mustHop(t, 0, "chaos-b", "198.51.100.140", 22, 0, 0)
	plans := []plan.SealedConnectionPlan{
		mustPlan(t, hop0, mustHop(t, 1, "c1", "198.51.100.141", 22, 0, 0)),
		mustPlan(t, hop0, mustHop(t, 1, "c2", "198.51.100.142", 22, 0, 0)),
		mustPlan(t, mustHop(t, 0, "c3", "198.51.100.143", 22, 0, 0)),
	}
	dig0, _ := plans[0].HopDigestAt(0)

	err := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		for w := range 8 {
			pl := plans[w%len(plans)]
			if gErr := n.Go(func(c context.Context) error {
				runChaosAcquireWorker(c, p, pl, 20)
				return nil
			}); gErr != nil {
				return gErr
			}
		}
		return n.Go(func(context.Context) error {
			runChaosDisruptor(p, dig0)
			return nil
		})
	})
	requireNoErr(t, err, "并发混沌压测")
	requireNoErr(t, p.WaitPendingTeardowns(context.Background()), "WaitPendingTeardowns(chaos)")
	requireTrue(t, p.IsHalted() && p.Stats().ActiveLeases == 0 && p.Stats().ActiveConns == 0, "混沌压测后熔断池须清零全部活跃资源")
}

func runChaosAcquireWorker(ctx context.Context, p *Pool, pl plan.SealedConnectionPlan, rounds int) {
	for range rounds {
		_ = p.WithLease(ctx, pl, func(sCtx context.Context, l *Lease) error {
			if sess, err := l.OpenSession(sCtx); err == nil {
				_ = sess.Close()
			}
			return nil
		})
	}
}

func runChaosDisruptor(p *Pool, dig plan.HopDigest) {
	for i := range 10 {
		_ = p.RetireHop(dig)
		_ = p.EvictIdle()
		if i == 7 {
			p.GateHalted(errors.New("chaos halt"))
		}
	}
}

// BenchmarkPoolDataPlaneConcurrent 验证控制面与数据面彻底分离：多协程高并发执行 Lease 数据面操作零 Actor 争用。
func BenchmarkPoolDataPlaneConcurrent(b *testing.B) {
	dialer := &mockDialer{}
	clk := newSimClock()
	p, err := NewPool(context.Background(), PoolConfig{
		Dialer:  dialer,
		Clock:   clk,
		Entropy: newSeqEntropy(7),
	})
	if err != nil {
		b.Fatalf("NewPool: %v", err)
	}
	defer func() { _ = p.Close() }()

	ch, err := netaddr.ParseCanonicalHost("198.51.100.200")
	if err != nil {
		b.Fatal(err)
	}
	ep, err := netaddr.NewEndpoint(ch, 22)
	if err != nil {
		b.Fatal(err)
	}
	user, err := option.ParseUsername("bench")
	if err != nil {
		b.Fatal(err)
	}
	auth, err := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	if err != nil {
		b.Fatal(err)
	}
	unset := option.UnsetOptionLayer()
	eff, err := option.ResolveEffectivePolicy(option.OriginManaged, ep, unset, unset, unset, unset)
	if err != nil {
		b.Fatal(err)
	}
	hop, err := plan.NewHopSpecFromAuth(0, "bench-node", user, auth, eff)
	if err != nil {
		b.Fatal(err)
	}
	pl, err := plan.SealConnectionPlan(hop)
	if err != nil {
		b.Fatal(err)
	}

	// 预热缓存后测量数据面高并发 OpenSession 吞吐（纯无锁原子检查 + 直通 TransportConn）。
	ctx := context.Background()
	inst, err := p.acquirePlan(ctx, pl)
	if err != nil {
		b.Fatal(err)
	}
	lease := newLease(p, inst, pl.PlanDigest(), "bench-lease")
	defer func() {
		lease.invalidate()
		p.releaseHopLease(inst)
	}()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			sess, sErr := lease.OpenSession(ctx)
			if sErr != nil {
				b.Errorf("OpenSession: %v", sErr)
				return
			}
			_ = sess.Close()
		}
	})
}
