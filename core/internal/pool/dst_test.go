package pool_test

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"sync"
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
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/foundation/trace"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/ports"
)

const (
	defaultPoolDSTSeeds = 64
	poolDSTWorkers      = 4
)

func resolvePoolDSTSeeds(t *testing.T, offset uint64) []uint64 {
	t.Helper()
	if raw := os.Getenv("XOPS_DST_SEED"); raw != "" {
		v, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			t.Fatalf("无效的 XOPS_DST_SEED=%q: %v", raw, err)
		}
		return []uint64{v}
	}
	n := defaultPoolDSTSeeds
	if raw := os.Getenv("XOPS_DST_SEEDS"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v <= 0 {
			t.Fatalf("无效的 XOPS_DST_SEEDS=%q: %v", raw, err)
		}
		n = v
	}
	seeds := make([]uint64, n)
	for i := range n {
		seeds[i] = offset + uint64(i) + 1
	}
	return seeds
}

func runPoolSeedsParallel(t *testing.T, seeds []uint64, fn func(seed uint64) error) {
	t.Helper()
	var next atomic.Uint64
	workers := min(poolDSTWorkers, len(seeds))
	err := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		for range workers {
			if gErr := n.Go(func(c context.Context) error {
				return drainPoolSeedQueue(c, seeds, &next, fn)
			}); gErr != nil {
				return gErr
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func drainPoolSeedQueue(ctx context.Context, seeds []uint64, next *atomic.Uint64, fn func(seed uint64) error) error {
	for ctx.Err() == nil {
		idx := int(next.Add(1) - 1)
		if idx >= len(seeds) {
			return nil
		}
		if err := fn(seeds[idx]); err != nil {
			return fmt.Errorf("seed=%d: %w", seeds[idx], err)
		}
	}
	return ctx.Err()
}

type poolDSTPlans struct {
	direct    plan.SealedConnectionPlan
	twoHopA   plan.SealedConnectionPlan
	twoHopB   plan.SealedConnectionPlan
	threeHopC plan.SealedConnectionPlan
	all       []plan.SealedConnectionPlan
	bindings  map[plan.PlanDigest]security.OperationBinding
}

func mustDSTHop(t *testing.T, idx uint32, nodeID, host string) plan.HopSpec {
	t.Helper()
	ch, err := netaddr.ParseCanonicalHost(host)
	if err != nil {
		t.Fatalf("ParseCanonicalHost(%q): %v", host, err)
	}
	ep, err := netaddr.NewEndpoint(ch, 22)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	u, err := option.ParseUsername("dst")
	if err != nil {
		t.Fatalf("ParseUsername: %v", err)
	}
	auth, err := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	if err != nil {
		t.Fatalf("NewAuthAgent: %v", err)
	}
	unset := option.UnsetOptionLayer()
	eff, err := option.ResolveEffectivePolicy(option.OriginManaged, ep, unset, unset, unset, unset)
	if err != nil {
		t.Fatalf("ResolveEffectivePolicy: %v", err)
	}
	hop, err := plan.NewHopSpecFromAuth(idx, nodeID, u, auth, eff)
	if err != nil {
		t.Fatalf("NewHopSpecFromAuth: %v", err)
	}
	return hop
}

func mustSealPlan(t *testing.T, hops ...plan.HopSpec) plan.SealedConnectionPlan {
	t.Helper()
	pl, err := plan.SealConnectionPlan(hops...)
	if err != nil {
		t.Fatalf("SealConnectionPlan: %v", err)
	}
	return pl
}

func mustPoolDSTPlans(t *testing.T) poolDSTPlans {
	t.Helper()
	bastion := mustDSTHop(t, 0, "bastion-1", "198.51.100.1")
	mid := mustDSTHop(t, 1, "mid-1", "198.51.100.2")
	direct := mustSealPlan(t, mustDSTHop(t, 0, "direct-d", "198.51.100.10"))
	twoA := mustSealPlan(t, bastion, mustDSTHop(t, 1, "app-a", "198.51.100.20"))
	twoB := mustSealPlan(t, bastion, mustDSTHop(t, 1, "app-b", "198.51.100.21"))
	threeC := mustSealPlan(t, bastion, mid, mustDSTHop(t, 2, "db-c", "198.51.100.30"))
	all := []plan.SealedConnectionPlan{direct, twoA, twoB, threeC}
	bindings := make(map[plan.PlanDigest]security.OperationBinding, len(all))
	for _, pl := range all {
		bind, err := security.NewOperationBinding(security.OperationBindingSpec{
			Capability: security.CapabilityExecute,
			Tool:       "session",
			Action:     "open",
			PlanDigest: algebraic.Some(pl.PlanDigest().SecurityDigest()),
		})
		if err != nil {
			t.Fatalf("NewOperationBinding: %v", err)
		}
		bindings[pl.PlanDigest()] = bind
	}
	return poolDSTPlans{
		direct: direct, twoHopA: twoA, twoHopB: twoB, threeHopC: threeC,
		all:      all,
		bindings: bindings,
	}
}

type dstManagedRes struct {
	closed atomic.Bool
}

func (r *dstManagedRes) IsValid() bool { return r != nil && !r.closed.Load() }
func (r *dstManagedRes) Close() error {
	r.closed.Store(true)
	return nil
}

// leaseScopeAssertDialer 包装 SimDialer，编译与运行时双重断言任何池内多跳 DialHop 绝不携带 trace.LeaseScope（ADR-009）。
type leaseScopeAssertDialer struct {
	inner      *sim.SimDialer
	violations atomic.Int64
}

func (d *leaseScopeAssertDialer) DialHop(ctx context.Context, hop plan.HopSpec, dig plan.HopDigest, parent ports.TransportConn) (ports.TransportConn, error) {
	if trace.InLeaseScope(ctx) {
		d.violations.Add(1)
		return nil, errors.New("dst: DialHop 不得携带 trace.LeaseScope")
	}
	return d.inner.DialHop(ctx, hop, dig, parent)
}

func isExpectedPoolChaosErr(err error) bool {
	if err == nil {
		return true
	}
	for _, target := range []error{
		sim.ErrFaultInjected,
		ports.ErrDialFailed,
		ports.ErrClosed,
		pool.ErrGateHalted,
		pool.ErrPoolClosed,
		pool.ErrPoolCapacityExceeded,
		pool.ErrParentEpochChanged,
		pool.ErrInvalidTransportConn, // 并发 Drop 在 DialHop 返回与 validateDialPublish 之间断开连接时按契约拒发
		pool.ErrHopRetired,
		pool.ErrLeaseRevoked,
		pool.ErrHandleLimitExceeded,
		pool.ErrHandleNotFound,
		pool.ErrHandleRevoked,
		pool.ErrHandleGenerationMismatch,
		context.Canceled,
	} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// TestDST_PoolRandomizedConcurrencyAndFaults 在有界满邮箱压测、多跳虚拟延迟与单飞合并、随机 Drop 断连、
// WithMultiLease 反序/重复计划、并发 Retire/EvictIdle/SlotMap 句柄操作、非重入租约守卫与
// 随机 GateHalted 熔断下验证零死锁、零未预期错误、零定时器/连接/句柄泄漏。
func TestDST_PoolRandomizedConcurrencyAndFaults(t *testing.T) {
	defer goleak.VerifyNone(t)
	fx := mustPoolDSTPlans(t)
	seeds := resolvePoolDSTSeeds(t, 0x30000)
	runPoolSeedsParallel(t, seeds, func(seed uint64) error {
		return runPoolChaosSeed(fx, seed)
	})
}

func runPoolChaosSeed(fx poolDSTPlans, seed uint64) error {
	rng := sim.NewSeededRand(seed)
	clk := sim.NewSimClock(sim.DefaultBaseTime())
	dialer := sim.NewSimDialer(clk, rng.Fork())
	scopeDialer := &leaseScopeAssertDialer{inner: dialer}
	if rng.Bool() {
		dialer.Faults().SetRate("dial.hop", 1, 6, sim.ErrFaultInjected)
	}
	useLatency := rng.Bool()
	if useLatency {
		dialer.SetHopIndexProfile(1, sim.HopFaultProfile{DialLatency: 2 * time.Millisecond})
	}
	bus, err := events.NewSystemBus(events.SystemBusConfig{DefaultSubscriberBuffer: 8})
	if err != nil {
		return err
	}
	defer bus.Close()

	p, err := pool.NewPool(context.Background(), pool.PoolConfig{
		Dialer:        scopeDialer,
		Clock:         clk,
		Entropy:       rng.Fork(),
		Bus:           bus,
		AcquireBuffer: 1 + rng.IntN(4), // 极小有界队列制造满邮箱背压
		MaxConns:      2 + rng.IntN(5),
		MaxHandles:    2 + rng.IntN(4),
		TeardownGrace: pool.DefaultTeardownGrace,
	})
	if err != nil {
		return err
	}

	var mu sync.Mutex
	var handles []plan.ManagedHandle[plan.KindSession]
	var resources []*dstManagedRes
	triggerHalt := rng.IntN(4) == 0

	runErr := runPoolChaosWorkload(fx, p, dialer, clk, rng, useLatency, triggerHalt, &mu, &handles, &resources)
	closeErr := p.Close()
	if runErr != nil {
		return runErr
	}
	if closeErr != nil {
		return fmt.Errorf("Pool.Close 失败: %w", closeErr)
	}
	return verifyPoolPostClose(p, dialer, scopeDialer, clk, resources, triggerHalt)
}

func runPoolChaosWorkload(
	fx poolDSTPlans,
	p *pool.Pool,
	dialer *sim.SimDialer,
	clk *sim.SimClock,
	rng *sim.SeededRand,
	useLatency, triggerHalt bool,
	mu *sync.Mutex,
	handles *[]plan.ManagedHandle[plan.KindSession],
	resources *[]*dstManagedRes,
) error {
	return conc.RunScoped(context.Background(), func(sCtx context.Context, bg *conc.Nursery) error {
		if useLatency {
			if gErr := bg.Go(func(c context.Context) error { return drivePoolSimClock(c, clk) }); gErr != nil {
				return gErr
			}
		}
		return conc.RunWait(sCtx, func(_ context.Context, n *conc.Nursery) error {
			for w := range 4 {
				wRng := rng.Fork()
				doHalt := triggerHalt && w == 3
				if gErr := n.Go(func(wCtx context.Context) error {
					return runPoolWorkerSteps(wCtx, fx, p, dialer, wRng, mu, handles, resources, doHalt)
				}); gErr != nil {
					return gErr
				}
			}
			return nil
		})
	})
}

func drivePoolSimClock(ctx context.Context, clk *sim.SimClock) error {
	for ctx.Err() == nil {
		if clk.PendingTimers() > 0 {
			clk.Advance(2 * time.Millisecond)
		}
		runtime.Gosched()
	}
	return nil
}

func runPoolWorkerSteps(
	ctx context.Context,
	fx poolDSTPlans,
	p *pool.Pool,
	dialer *sim.SimDialer,
	rng *sim.SeededRand,
	mu *sync.Mutex,
	handles *[]plan.ManagedHandle[plan.KindSession],
	resources *[]*dstManagedRes,
	doHalt bool,
) error {
	steps := 5 + rng.IntN(4)
	haltAt := steps / 2
	for s := range steps {
		if doHalt && s == haltAt {
			p.GateHalted(sim.ErrSimulatedENOSPC)
			continue
		}
		if err := execSinglePoolAction(ctx, fx, p, dialer, rng, mu, handles, resources); err != nil {
			return err
		}
	}
	return nil
}

func execSinglePoolAction(
	ctx context.Context,
	fx poolDSTPlans,
	p *pool.Pool,
	dialer *sim.SimDialer,
	rng *sim.SeededRand,
	mu *sync.Mutex,
	handles *[]plan.ManagedHandle[plan.KindSession],
	resources *[]*dstManagedRes,
) error {
	pl := fx.all[rng.IntN(len(fx.all))]
	switch rng.IntN(8) {
	case 0, 1:
		return execPoolLeaseStep(ctx, fx, p, pl, rng)
	case 2:
		return execPoolMultiLeaseStep(ctx, fx, p, rng)
	case 3:
		return checkPoolChaosErr("RetirePlan", p.RetirePlan(pl.PlanDigest()))
	case 4:
		if dig, ok := pl.HopDigestAt(0); ok {
			return checkPoolChaosErr("RetireHop", p.RetireHop(dig))
		}
	case 5:
		_ = p.EvictIdle()
	case 6:
		if conns := dialer.ConnsSnapshot(); len(conns) > 0 {
			conns[rng.IntN(len(conns))].Drop()
		}
	default:
		return execPoolHandleStep(ctx, fx, p, pl, rng, mu, handles, resources)
	}
	return nil
}

func checkPoolChaosErr(op string, err error) error {
	if !isExpectedPoolChaosErr(err) {
		return fmt.Errorf("%s 返回未预期错误: %w", op, err)
	}
	return nil
}

func execPoolLeaseStep(ctx context.Context, fx poolDSTPlans, p *pool.Pool, pl plan.SealedConnectionPlan, rng *sim.SeededRand) error {
	checkReenter := rng.IntN(4) == 0
	retireSelf := rng.IntN(5) == 0
	var innerErr error
	err := p.WithLease(ctx, pl, func(scopedCtx context.Context, l *pool.Lease) error {
		if !trace.InLeaseScope(scopedCtx) {
			innerErr = errors.New("WithLease 回调内必须处于 trace.LeaseScope")
			return innerErr
		}
		if checkReenter {
			reErr := p.WithLease(scopedCtx, fx.direct, func(context.Context, *pool.Lease) error {
				return errors.New("重入 WithLease 不得进入回调")
			})
			if !errors.Is(reErr, trace.ErrReentrantLease) && !errors.Is(reErr, pool.ErrGateHalted) && !errors.Is(reErr, pool.ErrPoolClosed) {
				innerErr = fmt.Errorf("重入 WithLease 期望 ErrReentrantLease，实际=%w", reErr)
				return innerErr
			}
		}
		if retireSelf {
			l.Retire()
		}
		return nil
	})
	if innerErr != nil {
		return innerErr
	}
	return checkPoolChaosErr("WithLease", err)
}

func execPoolMultiLeaseStep(ctx context.Context, fx poolDSTPlans, p *pool.Pool, rng *sim.SeededRand) error {
	perm := rng.Perm(len(fx.all))
	reqPlans := []plan.SealedConnectionPlan{fx.all[perm[0]], fx.all[perm[1]]}
	if rng.Bool() {
		reqPlans = append(reqPlans, fx.all[perm[0]]) // 含重复计划验证顺序对齐
	}
	var orderErr error
	err := p.WithMultiLease(ctx, reqPlans, func(scopedCtx context.Context, leases []*pool.Lease) error {
		if !trace.InLeaseScope(scopedCtx) || len(leases) != len(reqPlans) {
			orderErr = fmt.Errorf("WithMultiLease 租约数量或作用域异常: got=%d want=%d", len(leases), len(reqPlans))
			return orderErr
		}
		for i, l := range leases {
			// 若租约在回调期间被并发 Retire/GateHalted 吊销，PlanDigest() 按契约返回零值；有效期内必须严格对齐输入顺序。
			if pd := l.PlanDigest(); pd.IsValid() && !pd.Equal(reqPlans[i].PlanDigest()) {
				orderErr = fmt.Errorf("WithMultiLease 第 %d 个租约与输入顺序不匹配", i)
				return orderErr
			}
		}
		return nil
	})
	if orderErr != nil {
		return orderErr
	}
	return checkPoolChaosErr("WithMultiLease", err)
}

func execPoolHandleStep(
	ctx context.Context,
	fx poolDSTPlans,
	p *pool.Pool,
	pl plan.SealedConnectionPlan,
	rng *sim.SeededRand,
	mu *sync.Mutex,
	handles *[]plan.ManagedHandle[plan.KindSession],
	resources *[]*dstManagedRes,
) error {
	if rng.Bool() {
		res := &dstManagedRes{}
		h, err := pool.RegisterHandle[plan.KindSession](p, pl.PlanDigest(), fx.bindings[pl.PlanDigest()], res)
		if err == nil {
			mu.Lock()
			*handles = append(*handles, h)
			*resources = append(*resources, res)
			mu.Unlock()
			return nil
		}
		return checkPoolChaosErr("RegisterHandle", err)
	}
	mu.Lock()
	var h plan.ManagedHandle[plan.KindSession]
	if len(*handles) > 0 {
		h = (*handles)[rng.IntN(len(*handles))]
	}
	mu.Unlock()
	if !h.IsValid() {
		return nil
	}
	switch rng.IntN(3) {
	case 0:
		return checkPoolChaosErr("WithManagedHandle", pool.WithManagedHandle[plan.KindSession, *dstManagedRes](ctx, p, h, func(context.Context, *dstManagedRes) error { return nil }))
	case 1:
		return checkPoolChaosErr("ReleaseHandle", pool.ReleaseHandle[plan.KindSession](p, h))
	default:
		_ = p.RevokeHandlesByPlan(pl.PlanDigest())
		return nil
	}
}

func verifyPoolPostClose(p *pool.Pool, dialer *sim.SimDialer, scopeDialer *leaseScopeAssertDialer, clk *sim.SimClock, resources []*dstManagedRes, triggerHalt bool) error {
	st := p.Stats()
	if !st.Closed || st.ActiveConns != 0 || st.DialingConns != 0 || st.ActiveLeases != 0 || st.ActiveHandles != 0 {
		return fmt.Errorf("Close 后连接池状态未归零: %+v", st)
	}
	if triggerHalt && !st.Halted {
		return fmt.Errorf("触发 GateHalted 后 Halted 标志必须保持不可逆 true")
	}
	if dialer.OpenConns() != 0 {
		return fmt.Errorf("Close 后底层 SimDialer 残留未关闭连接: open=%d", dialer.OpenConns())
	}
	if scopeDialer.violations.Load() != 0 {
		return fmt.Errorf("检测到出站 DialHop 携带 trace.LeaseScope: count=%d", scopeDialer.violations.Load())
	}
	if clk.PendingTimers() != 0 {
		return fmt.Errorf("Close 后 SimClock 残留未释放定时器: pending=%d", clk.PendingTimers())
	}
	for i, res := range resources {
		if !res.closed.Load() {
			return fmt.Errorf("Close 后第 %d 个托管资源未被关闭", i)
		}
	}
	return nil
}

// TestDST_PoolMultiHop90msTeardown 在 2 跳与 3 跳子跳卡死 Close 场景下基于虚拟 SimClock 验证：
// 1. 推进 <90ms 绝不提前升级拆断；
// 2. 跨过 90ms 宽限阈值即刻升级拆断根跳板、父代 Epoch 失效、自动解阻卡死子跳且零泄漏。
func TestDST_PoolMultiHop90msTeardown(t *testing.T) {
	defer goleak.VerifyNone(t)
	fx := mustPoolDSTPlans(t)
	seeds := resolvePoolDSTSeeds(t, 0x40000)
	runPoolSeedsParallel(t, seeds, func(seed uint64) error {
		return runPool90msTeardownSeed(fx, seed)
	})
}

func runPool90msTeardownSeed(fx poolDSTPlans, seed uint64) error {
	rng := sim.NewSeededRand(seed)
	clk := sim.NewSimClock(sim.DefaultBaseTime())
	dialer := sim.NewSimDialer(clk, rng.Fork())
	scopeDialer := &leaseScopeAssertDialer{inner: dialer}
	ctx := context.Background()

	targetPlan := fx.twoHopA
	leafIdx := uint32(1)
	if rng.Bool() {
		targetPlan = fx.threeHopC
		leafIdx = 2
	}
	dialer.SetHopIndexProfile(leafIdx, sim.HopFaultProfile{StuckClose: true})

	p, err := pool.NewPool(ctx, pool.PoolConfig{
		Dialer:        scopeDialer,
		Clock:         clk,
		Entropy:       rng.Fork(),
		TeardownGrace: pool.DefaultTeardownGrace,
	})
	if err != nil {
		return err
	}
	defer func() {
		dialer.UnblockAll()
		_ = p.Close()
	}()

	var epochBefore uint64
	if err := p.WithLease(ctx, targetPlan, func(_ context.Context, l *pool.Lease) error {
		epochBefore = l.Epoch()
		return nil
	}); err != nil {
		return fmt.Errorf("首次 WithLease 失败: %w", err)
	}
	if err := p.RetirePlan(targetPlan.PlanDigest()); err != nil {
		return fmt.Errorf("RetirePlan 失败: %w", err)
	}

	// 零 time.Sleep 等待拆断 90ms 定时器挂上 SimClock。
	if err := clk.WaitPending(ctx, 1); err != nil {
		return fmt.Errorf("WaitPending(1) 失败: %w", err)
	}
	subGrace := time.Duration(1+rng.IntN(89)) * time.Millisecond
	clk.Advance(subGrace)
	if p.Stats().TeardownEscalations != 0 {
		return fmt.Errorf("推进 %v (<90ms) 不得提前升级拆断: esc=%d", subGrace, p.Stats().TeardownEscalations)
	}

	// 跨过 90ms 边界触发根跳板升级拆断，根连接关闭后自动解阻卡死的子跳 Close()。
	clk.Advance(pool.DefaultTeardownGrace - subGrace + time.Millisecond)
	if err := p.WaitPendingTeardowns(ctx); err != nil {
		return fmt.Errorf("WaitPendingTeardowns 失败: %w", err)
	}
	st := p.Stats()
	conns := dialer.ConnsSnapshot()
	if st.TeardownEscalations == 0 || st.ActiveConns != 0 || len(conns) == 0 || !conns[0].IsClosed() {
		return fmt.Errorf("90ms 升级拆断未生效: esc=%d active=%d rootClosed=%v", st.TeardownEscalations, st.ActiveConns, len(conns) > 0 && conns[0].IsClosed())
	}

	// 验证父跳板与子跳均已重连到全新 Epoch（旧世代彻底失效），且 Close 后零底层连接与定时器残留。
	dialer.SetHopIndexProfile(leafIdx, sim.HopFaultProfile{})
	var epochAfter uint64
	if err := p.WithLease(ctx, targetPlan, func(_ context.Context, l *pool.Lease) error {
		epochAfter = l.Epoch()
		return nil
	}); err != nil {
		return fmt.Errorf("升级拆断后重连失败: %w", err)
	}
	if epochAfter <= epochBefore {
		return fmt.Errorf("升级拆断后必须分配新世代: before=%d after=%d", epochBefore, epochAfter)
	}
	if err := p.Close(); err != nil {
		return fmt.Errorf("90ms 场景 Pool.Close 失败: %w", err)
	}
	if dialer.OpenConns() != 0 || scopeDialer.violations.Load() != 0 || clk.PendingTimers() != 0 {
		return fmt.Errorf("90ms Close 后残留状态: open=%d scopeViol=%d timers=%d", dialer.OpenConns(), scopeDialer.violations.Load(), clk.PendingTimers())
	}
	return nil
}

// TestDST_PoolDeterministicReplay 验证全量种子连接池确定性回放两遍产出完全一致的统计与操作摘要。
func TestDST_PoolDeterministicReplay(t *testing.T) {
	defer goleak.VerifyNone(t)
	fx := mustPoolDSTPlans(t)
	seeds := resolvePoolDSTSeeds(t, 0x48000)
	runPoolSeedsParallel(t, seeds, func(seed uint64) error {
		d1, err := runDeterministicPoolTranscript(fx, seed)
		if err != nil {
			return fmt.Errorf("run1: %w", err)
		}
		d2, err := runDeterministicPoolTranscript(fx, seed)
		if err != nil {
			return fmt.Errorf("run2: %w", err)
		}
		if d1 != d2 {
			return fmt.Errorf("确定性复现失配: %x != %x", d1, d2)
		}
		return nil
	})
}

func runDeterministicPoolTranscript(fx poolDSTPlans, seed uint64) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	rng := sim.NewSeededRand(seed)
	clk := sim.NewSimClock(sim.DefaultBaseTime())
	dialer := sim.NewSimDialer(clk, rng.Fork())
	scopeDialer := &leaseScopeAssertDialer{inner: dialer}
	dialer.Faults().SetRate("dial.hop", 1, 5, sim.ErrFaultInjected)
	ctx := context.Background()

	p, err := pool.NewPool(ctx, pool.PoolConfig{
		Dialer:        scopeDialer,
		Clock:         clk,
		Entropy:       rng.Fork(),
		AcquireBuffer: 2,
		MaxConns:      3,
		MaxHandles:    3,
	})
	if err != nil {
		return zero, err
	}

	h := sha256.New()
	var buf [8]byte
	var handles []plan.ManagedHandle[plan.KindSession]
	for step := range 8 {
		pl := fx.all[rng.IntN(len(fx.all))]
		code := runDeterministicPoolStep(ctx, fx, p, pl, rng, &handles, step)
		binary.LittleEndian.PutUint64(buf[:], code)
		_, _ = h.Write(buf[:])
		clk.Advance(5 * time.Millisecond)
	}
	if err := p.Close(); err != nil {
		return zero, err
	}
	if dialer.OpenConns() != 0 || scopeDialer.violations.Load() != 0 || clk.PendingTimers() != 0 {
		return zero, fmt.Errorf("replay Close 后残留状态: open=%d scopeViol=%d timers=%d", dialer.OpenConns(), scopeDialer.violations.Load(), clk.PendingTimers())
	}
	st := p.Stats()
	for _, v := range []uint64{st.TotalDials, st.DialErrors, st.CacheHits, st.TeardownCompleted, st.TeardownEscalations} {
		binary.LittleEndian.PutUint64(buf[:], v)
		_, _ = h.Write(buf[:])
	}
	var out [sha256.Size]byte
	h.Sum(out[:0])
	return out, nil
}

func runDeterministicPoolStep(
	ctx context.Context,
	fx poolDSTPlans,
	p *pool.Pool,
	pl plan.SealedConnectionPlan,
	rng *sim.SeededRand,
	handles *[]plan.ManagedHandle[plan.KindSession],
	step int,
) uint64 {
	if step == 6 && rng.Bool() {
		p.GateHalted(sim.ErrSimulatedENOSPC)
		return 99
	}
	switch rng.IntN(6) {
	case 0, 1:
		var ep uint64
		err := p.WithLease(ctx, pl, func(_ context.Context, l *pool.Lease) error {
			ep = l.Epoch()
			return nil
		})
		if err != nil {
			return 100
		}
		return ep
	case 2:
		if err := p.WithMultiLease(ctx, []plan.SealedConnectionPlan{fx.twoHopB, fx.twoHopA}, func(context.Context, []*pool.Lease) error { return nil }); err != nil {
			return 200
		}
		return 201
	case 3:
		_ = p.RetirePlan(pl.PlanDigest())
		return 300
	case 4:
		return uint64(400 + p.EvictIdle())
	default:
		res := &dstManagedRes{}
		if hd, err := pool.RegisterHandle[plan.KindSession](p, pl.PlanDigest(), fx.bindings[pl.PlanDigest()], res); err == nil {
			*handles = append(*handles, hd)
			return 500 + hd.Generation()
		}
		if len(*handles) > 0 {
			_ = pool.ReleaseHandle[plan.KindSession](p, (*handles)[0])
			*handles = (*handles)[1:]
		}
		return 550
	}
}
