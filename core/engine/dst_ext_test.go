package engine_test

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/foundation/trace"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/ports"
)

const (
	defaultEngineDSTSeeds = 64
	engineDSTWorkers      = 4
)

func resolveEngineDSTSeeds(t *testing.T, offset uint64) []uint64 {
	t.Helper()
	if raw := os.Getenv("XOPS_DST_SEED"); raw != "" {
		v, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			t.Fatalf("无效的 XOPS_DST_SEED=%q: %v", raw, err)
		}
		return []uint64{v}
	}
	n := defaultEngineDSTSeeds
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

func runEngineSeedsParallel(t *testing.T, seeds []uint64, fn func(seed uint64) error) {
	t.Helper()
	var next atomic.Uint64
	workers := min(engineDSTWorkers, len(seeds))
	err := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		for range workers {
			if gErr := n.Go(func(c context.Context) error {
				return drainEngineSeedQueue(c, seeds, &next, fn)
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

func drainEngineSeedQueue(ctx context.Context, seeds []uint64, next *atomic.Uint64, fn func(seed uint64) error) error {
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

type engineDSTFixture struct {
	policy     gate.GuardrailPolicy
	bindExec   security.OperationBinding
	bindHandle security.OperationBinding
	direct     plan.SealedConnectionPlan
	twoHopA    plan.SealedConnectionPlan
	twoHopB    plan.SealedConnectionPlan
	allPlans   []plan.SealedConnectionPlan
	allowReq   gate.GateRequest[security.CapExecute]
	deniedReq  gate.GateRequest[security.CapExecute]
}

func mustEngineHop(t *testing.T, idx uint32, nodeID, host string) plan.HopSpec {
	t.Helper()
	ch, err := netaddr.ParseCanonicalHost(host)
	if err != nil {
		t.Fatalf("ParseCanonicalHost: %v", err)
	}
	ep, err := netaddr.NewEndpoint(ch, 22)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	u, err := option.ParseUsername("eng")
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

func mustEngineDSTFixture(t *testing.T) engineDSTFixture {
	t.Helper()
	policy, err := gate.NewGuardrailPolicy(gate.GuardrailPolicySpec{
		ApprovalThreshold: security.RiskModerate,
		NoElicitFallback:  gate.NoElicitFallbackDeny,
	})
	if err != nil {
		t.Fatalf("NewGuardrailPolicy: %v", err)
	}
	bindExec, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityExecute,
		Tool:       "exec",
		Action:     "run",
	})
	if err != nil {
		t.Fatalf("NewOperationBinding: %v", err)
	}
	bastion := mustEngineHop(t, 0, "bastion", "198.51.100.51")
	direct, err := plan.SealConnectionPlan(mustEngineHop(t, 0, "direct", "198.51.100.52"))
	if err != nil {
		t.Fatalf("SealConnectionPlan(direct): %v", err)
	}
	twoA, err := plan.SealConnectionPlan(bastion, mustEngineHop(t, 1, "app-a", "198.51.100.53"))
	if err != nil {
		t.Fatalf("SealConnectionPlan(twoA): %v", err)
	}
	twoB, err := plan.SealConnectionPlan(bastion, mustEngineHop(t, 1, "app-b", "198.51.100.54"))
	if err != nil {
		t.Fatalf("SealConnectionPlan(twoB): %v", err)
	}
	allowReq, err := gate.NewGateRequest[security.CapExecute](gate.GateRequestSpec[security.CapExecute]{
		Binding: bindExec,
		Risk:    security.RiskSafe,
	})
	if err != nil {
		t.Fatalf("NewGateRequest(allow): %v", err)
	}
	deniedReq, err := gate.NewGateRequest[security.CapExecute](gate.GateRequestSpec[security.CapExecute]{
		Binding: bindExec,
		Risk:    security.RiskSafe,
		Verdict: algebraic.Some(security.VerdictDeny),
	})
	if err != nil {
		t.Fatalf("NewGateRequest(deny): %v", err)
	}
	bindHandle, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityExecute,
		Tool:       "session",
		Action:     "open",
		PlanDigest: algebraic.Some(twoA.PlanDigest().SecurityDigest()),
	})
	if err != nil {
		t.Fatalf("NewOperationBinding(handle): %v", err)
	}
	return engineDSTFixture{
		policy: policy, bindExec: bindExec, bindHandle: bindHandle,
		direct: direct, twoHopA: twoA, twoHopB: twoB,
		allPlans:  []plan.SealedConnectionPlan{direct, twoA, twoB},
		allowReq:  allowReq,
		deniedReq: deniedReq,
	}
}

type engineManagedSession struct {
	closed atomic.Bool
}

func (s *engineManagedSession) IsValid() bool { return s != nil && !s.closed.Load() }
func (s *engineManagedSession) Close() error {
	s.closed.Store(true)
	return nil
}

// engineLeaseScopeAssertDialer 包装 SimDialer，断言跨包真实装配下的所有出站 DialHop 绝不携带 trace.LeaseScope（ADR-009）。
type engineLeaseScopeAssertDialer struct {
	inner      *sim.SimDialer
	violations atomic.Int64
}

func (d *engineLeaseScopeAssertDialer) DialHop(ctx context.Context, hop plan.HopSpec, dig plan.HopDigest, parent ports.TransportConn) (ports.TransportConn, error) {
	if trace.InLeaseScope(ctx) {
		d.violations.Add(1)
		return nil, errors.New("dst: DialHop 不得携带 trace.LeaseScope")
	}
	return d.inner.DialHop(ctx, hop, dig, parent)
}

// TestDST_EngineGatePoolCircuitBreaker 在真实跨包装配（gate.Gate + pool.Pool + sim）下验证 ADR-008/ADR-009
// 五大全局不变量：gate.WithAuthorized 严格包裹 pool.WithLease/WithMultiLease、AcquireBuffer=1 邮箱饱和且
// 慢拨号在途时命中 ENOSPC -> gate.OnHalt -> pool.GateHalted 零自死锁熔断、活跃能力/租约/托管句柄即刻吊销、
// 事后 O(1) 崩溃对账零孤儿零重复终态与全量定时器/连接/协程零泄漏。
func TestDST_EngineGatePoolCircuitBreaker(t *testing.T) {
	defer goleak.VerifyNone(t)
	fx := mustEngineDSTFixture(t)
	seeds := resolveEngineDSTSeeds(t, 0x50000)
	runEngineSeedsParallel(t, seeds, func(seed uint64) error {
		return runEngineGatePoolSeed(fx, seed)
	})
}

func runEngineGatePoolSeed(fx engineDSTFixture, seed uint64) error {
	rng := sim.NewSeededRand(seed)
	clk := sim.NewSimClock(sim.DefaultBaseTime())
	cluster := sim.NewSimAuditCluster()
	sink, err := cluster.NewSinkFromEntropy(rng)
	if err != nil {
		return err
	}
	dialer := sim.NewSimDialer(clk, rng.Fork())
	scopeDialer := &engineLeaseScopeAssertDialer{inner: dialer}
	// 为 twoHopB 末跳配置虚拟拨号延迟，用于制造 AcquireBuffer=1 邮箱饱和时的真实在途拨号等待。
	dialer.SetDigestProfile(fx.twoHopB.HopDigests()[1], sim.HopFaultProfile{DialLatency: 50 * time.Millisecond})

	bus, err := events.NewSystemBus(events.SystemBusConfig{DefaultSubscriberBuffer: 8})
	if err != nil {
		return err
	}
	defer bus.Close()

	ctx := context.Background()
	p, err := pool.NewPool(ctx, pool.PoolConfig{
		Dialer:        scopeDialer,
		Clock:         clk,
		Entropy:       rng.Fork(),
		Bus:           bus,
		AcquireBuffer: 1, // 严格单槽有界邮箱，制造真实背压
		MaxConns:      4 + rng.IntN(3),
		MaxHandles:    4,
		TeardownGrace: pool.DefaultTeardownGrace,
	})
	if err != nil {
		return err
	}

	var haltCalls atomic.Int32
	g, err := gate.NewGate(gate.GateConfig{
		Profile:    gate.PolicyProfileStrictAgent,
		Policy:     fx.policy,
		AuditSink:  sink,
		Reconciler: cluster,
		Clock:      clk,
		Entropy:    rng.Fork(),
		SystemBus:  bus,
		OnHalt: func(info gate.HaltInfo) {
			haltCalls.Add(1)
			p.GateHalted(info.Cause())
		},
	})
	if err != nil {
		_ = p.Close()
		return err
	}

	// 注册长生命周期 ManagedHandle，验证 ENOSPC 熔断时同步吊销其借用上下文并关闭资源。
	res := &engineManagedSession{}
	handle, err := pool.RegisterHandle[plan.KindSession](p, fx.twoHopA.PlanDigest(), fx.bindHandle, res)
	if err != nil {
		_ = p.Close()
		return err
	}

	obs, runErr := runEngineConcurrentFaultBurst(ctx, fx, g, p, cluster, dialer, clk, handle, rng)
	closeErr := p.Close()
	if runErr != nil {
		return runErr
	}
	if closeErr != nil {
		return fmt.Errorf("Pool.Close 失败: %w", closeErr)
	}
	return verifyEnginePostHaltInvariants(ctx, fx, g, p, sink, cluster, dialer, scopeDialer, clk, res, haltCalls.Load(), obs)
}

type engineBurstObs struct {
	bystanderAuthRevoked  atomic.Bool
	bystanderLeaseRevoked atomic.Bool
	handleCtxCanceled     atomic.Bool
	scopeErr              atomic.Pointer[error]
}

func runEngineConcurrentFaultBurst(
	ctx context.Context,
	fx engineDSTFixture,
	g *gate.Gate,
	p *pool.Pool,
	cluster *sim.SimAuditCluster,
	dialer *sim.SimDialer,
	clk *sim.SimClock,
	handle plan.ManagedHandle[plan.KindSession],
	rng *sim.SeededRand,
) (*engineBurstObs, error) {
	obs := &engineBurstObs{}
	bystanderReady := make(chan struct{})
	handleReady := make(chan struct{})
	haltTriggered := make(chan struct{})
	enableDialFaults := rng.IntN(3) == 0

	err := conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		// 协程 1-2：旁观者（持活跃 Authorized+Lease）与长会话 ManagedHandle 持有者。
		if gErr := n.Go(func(wCtx context.Context) error {
			return runEngineBystanderWorker(wCtx, fx, g, p, bystanderReady, haltTriggered, obs)
		}); gErr != nil {
			return gErr
		}
		if gErr := n.Go(func(wCtx context.Context) error {
			return runEngineHandleHolder(wCtx, p, handle, handleReady, obs)
		}); gErr != nil {
			return gErr
		}
		// 协程 3-6：旁观者就位后并发饱和 AcquireBuffer=1 慢拨号队列与背景噪声。
		if gErr := spawnEngineWaitersAndNoise(n, fx, g, p, bystanderReady, rng.Fork()); gErr != nil {
			return gErr
		}
		// 协程 7：待旁观者、托管句柄与慢拨号定时器均就位后，拉高 ENOSPC 触发 StrictAgent -> OnHalt -> p.GateHalted。
		tRng := rng.Fork()
		return n.Go(func(wCtx context.Context) error {
			return waitAndTriggerEngineHalt(wCtx, fx, g, p, cluster, dialer, clk, bystanderReady, handleReady, haltTriggered, enableDialFaults, tRng)
		})
	})
	if obsErr := obs.scopeErr.Load(); obsErr != nil {
		return obs, *obsErr
	}
	return obs, err
}

func spawnEngineWaitersAndNoise(
	n *conc.Nursery,
	fx engineDSTFixture,
	g *gate.Gate,
	p *pool.Pool,
	bystanderReady <-chan struct{},
	wRng *sim.SeededRand,
) error {
	for range 3 {
		if gErr := n.Go(func(wCtx context.Context) error {
			<-bystanderReady
			_ = gate.WithAuthorized(wCtx, g, fx.allowReq, func(aCtx context.Context, _ gate.Authorized[security.CapExecute]) error {
				return p.WithLease(aCtx, fx.twoHopB, func(context.Context, *pool.Lease) error { return nil })
			})
			return nil
		}); gErr != nil {
			return gErr
		}
	}
	return n.Go(func(wCtx context.Context) error {
		<-bystanderReady
		runEngineNoiseWorker(wCtx, fx, g, p, wRng)
		return nil
	})
}

func waitAndTriggerEngineHalt(
	wCtx context.Context,
	fx engineDSTFixture,
	g *gate.Gate,
	p *pool.Pool,
	cluster *sim.SimAuditCluster,
	dialer *sim.SimDialer,
	clk *sim.SimClock,
	bystanderReady, handleReady <-chan struct{},
	haltTriggered chan<- struct{},
	enableDialFaults bool,
	tRng *sim.SeededRand,
) error {
	<-bystanderReady
	<-handleReady
	if wErr := clk.WaitPending(wCtx, 1); wErr != nil {
		return wErr
	}
	if enableDialFaults {
		dialer.Faults().SetRate("dial.hop", 1, 7, sim.ErrFaultInjected)
	}
	defer close(haltTriggered)
	runEngineENOSPCTrigger(wCtx, fx, g, p, cluster, tRng)
	return nil
}

func runEngineBystanderWorker(
	ctx context.Context,
	fx engineDSTFixture,
	g *gate.Gate,
	p *pool.Pool,
	ready chan<- struct{},
	haltTriggered <-chan struct{},
	obs *engineBurstObs,
) error {
	_ = gate.WithAuthorized(ctx, g, fx.allowReq, func(authCtx context.Context, auth gate.Authorized[security.CapExecute]) error {
		if trace.InLeaseScope(authCtx) {
			e := errors.New("gate.WithAuthorized 严禁在进入 pool.WithLease 前提前注入 trace.LeaseScope")
			obs.scopeErr.CompareAndSwap(nil, &e)
		}
		readyClosed := false
		lErr := p.WithLease(authCtx, fx.direct, func(leaseCtx context.Context, lease *pool.Lease) error {
			if !trace.InLeaseScope(leaseCtx) {
				e := errors.New("pool.WithLease 回调内必须处于 trace.LeaseScope")
				obs.scopeErr.CompareAndSwap(nil, &e)
			}
			close(ready)
			readyClosed = true
			<-haltTriggered
			<-leaseCtx.Done()
			obs.bystanderAuthRevoked.Store(auth.IsRevoked() && !auth.IsValid())
			obs.bystanderLeaseRevoked.Store(leaseCtx.Err() != nil && !lease.IsValid())
			return nil
		})
		if !readyClosed {
			close(ready)
			e := fmt.Errorf("旁观者在故障开启前未能获取确定性租约: %w", lErr)
			obs.scopeErr.CompareAndSwap(nil, &e)
		}
		return lErr
	})
	return nil
}

func runEngineHandleHolder(
	ctx context.Context,
	p *pool.Pool,
	handle plan.ManagedHandle[plan.KindSession],
	ready chan<- struct{},
	obs *engineBurstObs,
) error {
	entered := false
	_ = pool.WithManagedHandle[plan.KindSession, *engineManagedSession](ctx, p, handle, func(hCtx context.Context, _ *engineManagedSession) error {
		entered = true
		close(ready)
		<-hCtx.Done()
		obs.handleCtxCanceled.Store(true)
		return nil
	})
	if !entered {
		close(ready)
	}
	return nil
}

func runEngineNoiseWorker(ctx context.Context, fx engineDSTFixture, g *gate.Gate, p *pool.Pool, rng *sim.SeededRand) {
	fastPlans := []plan.SealedConnectionPlan{fx.direct, fx.twoHopA}
	for range 4 {
		pl := fastPlans[rng.IntN(len(fastPlans))]
		switch rng.IntN(4) {
		case 0:
			_ = gate.WithAuthorized(ctx, g, fx.allowReq, func(aCtx context.Context, _ gate.Authorized[security.CapExecute]) error {
				return p.WithLease(aCtx, pl, func(context.Context, *pool.Lease) error { return nil })
			})
		case 1:
			_ = gate.WithAuthorized(ctx, g, fx.allowReq, func(aCtx context.Context, _ gate.Authorized[security.CapExecute]) error {
				return p.WithMultiLease(aCtx, []plan.SealedConnectionPlan{fx.direct, fx.twoHopA}, func(context.Context, []*pool.Lease) error { return nil })
			})
		case 2:
			_ = gate.WithAuthorized(ctx, g, fx.deniedReq, func(context.Context, gate.Authorized[security.CapExecute]) error { return nil })
		default:
			_ = p.RetirePlan(pl.PlanDigest())
		}
	}
}

func runEngineENOSPCTrigger(
	ctx context.Context,
	fx engineDSTFixture,
	g *gate.Gate,
	p *pool.Pool,
	cluster *sim.SimAuditCluster,
	rng *sim.SeededRand,
) {
	pl := fx.direct
	if rng.Bool() {
		pl = fx.twoHopA
	}
	_ = gate.WithAuthorized(ctx, g, fx.allowReq, func(aCtx context.Context, auth gate.Authorized[security.CapExecute]) error {
		_ = p.WithLease(aCtx, pl, func(_ context.Context, _ *pool.Lease) error {
			if rng.Bool() {
				if unk, err := execution.NewOutcomeUnknown(execution.ExecPhaseRunning, "sim_io", "io interrupted"); err == nil {
					_ = auth.ReportOutcome(unk)
				}
			}
			return nil
		})
		// 在退出 WithAuthorized 即将写 Audit(Finalized) 前拉高 ENOSPC，触发 StrictAgent -> OnHalt -> pool.GateHalted。
		cluster.SetENOSPC(true)
		return nil
	})
}

func verifyEnginePostHaltInvariants(
	ctx context.Context,
	fx engineDSTFixture,
	g *gate.Gate,
	p *pool.Pool,
	sink *sim.SimAuditSink,
	cluster *sim.SimAuditCluster,
	dialer *sim.SimDialer,
	scopeDialer *engineLeaseScopeAssertDialer,
	clk *sim.SimClock,
	res *engineManagedSession,
	haltCalls int32,
	obs *engineBurstObs,
) error {
	if !g.IsHalted() || !p.IsHalted() || haltCalls != 1 {
		return fmt.Errorf("熔断状态不一致: gateHalted=%v poolHalted=%v haltCalls=%d", g.IsHalted(), p.IsHalted(), haltCalls)
	}
	if !obs.bystanderAuthRevoked.Load() || !obs.bystanderLeaseRevoked.Load() || !obs.handleCtxCanceled.Load() || !res.closed.Load() {
		return fmt.Errorf("熔断吊销不完整: authRevoked=%v leaseRevoked=%v handleCanceled=%v resClosed=%v",
			obs.bystanderAuthRevoked.Load(), obs.bystanderLeaseRevoked.Load(), obs.handleCtxCanceled.Load(), res.closed.Load())
	}
	if err := gate.WithAuthorized(ctx, g, fx.allowReq, func(context.Context, gate.Authorized[security.CapExecute]) error {
		return errors.New("Halted Gate 不得放行")
	}); !errors.Is(err, gate.ErrGateHalted) {
		return fmt.Errorf("Halted Gate 新请求期望 ErrGateHalted，实际=%w", err)
	}
	if err := p.WithLease(ctx, fx.direct, func(context.Context, *pool.Lease) error {
		return errors.New("Halted Pool 不得放行")
	}); !errors.Is(err, pool.ErrGateHalted) && !errors.Is(err, pool.ErrPoolClosed) {
		return fmt.Errorf("Halted Pool 新请求期望 ErrGateHalted/ErrPoolClosed，实际=%w", err)
	}
	st := p.Stats()
	if !st.Closed || st.ActiveConns != 0 || st.DialingConns != 0 || st.ActiveLeases != 0 || st.ActiveHandles != 0 ||
		dialer.OpenConns() != 0 || scopeDialer.violations.Load() != 0 || clk.PendingTimers() != 0 {
		return fmt.Errorf("Pool 关闭后残留资源: stats=%+v openConns=%d scopeViol=%d timers=%d",
			st, dialer.OpenConns(), scopeDialer.violations.Load(), clk.PendingTimers())
	}

	// 清除 ENOSPC，模拟熔断进程重启并执行两次崩溃对账，验证零孤儿、零重复终态与二次 O(1) 零扫描。
	cluster.SetENOSPC(false)
	sink.SimulateSIGKILL()
	clk.Advance(time.Second)
	if _, err := cluster.ReconcileCrashedAudits(ctx, clk.Now()); err != nil {
		return fmt.Errorf("首次崩溃对账失败: %w", err)
	}
	scansAfterFirst := cluster.AuditLogScans()
	clk.Advance(time.Second)
	rep2, err := cluster.ReconcileCrashedAudits(ctx, clk.Now())
	if err != nil || rep2.DeadLocksClaimed() != 0 || cluster.AuditLogScans() != scansAfterFirst {
		return fmt.Errorf("二次崩溃对账违背 O(1) 零扫描: err=%w rep2=%+v scans=%d->%d", err, rep2, scansAfterFirst, cluster.AuditLogScans())
	}
	return verifyEngineAuditPairs(cluster.Entries())
}

func verifyEngineAuditPairs(entries []ports.AuditEntry) error {
	authCount := make(map[security.OperationID]int)
	finCount := make(map[security.OperationID]int)
	for _, e := range entries {
		switch e.Phase() {
		case ports.AuditPhaseAuthorized:
			authCount[e.OperationID()]++
		case ports.AuditPhaseFinalized:
			if authCount[e.OperationID()] == 0 {
				return fmt.Errorf("无头 Finalized 记录: %s", e.OperationID())
			}
			finCount[e.OperationID()]++
		case ports.AuditPhaseDenied:
		default:
			return fmt.Errorf("未知审计阶段: %v", e.Phase())
		}
	}
	for opID, n := range authCount {
		if n != 1 || finCount[opID] != 1 {
			return fmt.Errorf("操作 %s 审计闭环失配: auth=%d fin=%d", opID, n, finCount[opID])
		}
	}
	return nil
}

// TestDST_EngineDeterministicReplay 验证全量种子端到端 Gate+Pool+Sim 重复执行两遍产出逐位完全一致的审计与状态摘要。
func TestDST_EngineDeterministicReplay(t *testing.T) {
	defer goleak.VerifyNone(t)
	fx := mustEngineDSTFixture(t)
	seeds := resolveEngineDSTSeeds(t, 0x58000)
	runEngineSeedsParallel(t, seeds, func(seed uint64) error {
		d1, err := runDeterministicEngineTranscript(fx, seed)
		if err != nil {
			return fmt.Errorf("run1: %w", err)
		}
		d2, err := runDeterministicEngineTranscript(fx, seed)
		if err != nil {
			return fmt.Errorf("run2: %w", err)
		}
		if d1 != d2 {
			return fmt.Errorf("确定性复现失配: %x != %x", d1, d2)
		}
		return nil
	})
}

func runDeterministicEngineTranscript(fx engineDSTFixture, seed uint64) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	rng := sim.NewSeededRand(seed)
	clk := sim.NewSimClock(sim.DefaultBaseTime())
	cluster := sim.NewSimAuditCluster()
	sink, err := cluster.NewSinkFromEntropy(rng)
	if err != nil {
		return zero, err
	}
	dialer := sim.NewSimDialer(clk, rng.Fork())
	scopeDialer := &engineLeaseScopeAssertDialer{inner: dialer}
	ctx := context.Background()

	p, err := pool.NewPool(ctx, pool.PoolConfig{
		Dialer: scopeDialer, Clock: clk, Entropy: rng.Fork(), AcquireBuffer: 2, MaxConns: 4, MaxHandles: 3,
	})
	if err != nil {
		return zero, err
	}
	g, err := gate.NewGate(gate.GateConfig{
		Profile: gate.PolicyProfileStrictAgent, Policy: fx.policy,
		AuditSink: sink, Reconciler: cluster, Clock: clk, Entropy: rng.Fork(),
		OnHalt: func(info gate.HaltInfo) { p.GateHalted(info.Cause()) },
	})
	if err != nil {
		_ = p.Close()
		return zero, err
	}

	for step := range 7 {
		clk.Advance(10 * time.Millisecond)
		runDeterministicEngineStep(ctx, fx, g, p, cluster, rng, step)
	}
	if err := p.Close(); err != nil {
		return zero, err
	}
	if dialer.OpenConns() != 0 || scopeDialer.violations.Load() != 0 || clk.PendingTimers() != 0 {
		return zero, fmt.Errorf("replay Close 后残留状态: open=%d scopeViol=%d timers=%d", dialer.OpenConns(), scopeDialer.violations.Load(), clk.PendingTimers())
	}
	cluster.SetENOSPC(false)
	sink.SimulateSIGKILL()
	clk.Advance(time.Second)
	if _, err := cluster.ReconcileCrashedAudits(ctx, clk.Now()); err != nil {
		return zero, err
	}
	if err := verifyEngineAuditPairs(cluster.Entries()); err != nil {
		return zero, err
	}
	return hashEngineState(cluster, g.Stats(), p.Stats())
}

func runDeterministicEngineStep(
	ctx context.Context,
	fx engineDSTFixture,
	g *gate.Gate,
	p *pool.Pool,
	cluster *sim.SimAuditCluster,
	rng *sim.SeededRand,
	step int,
) {
	pl := fx.allPlans[rng.IntN(len(fx.allPlans))]
	if step == 5 {
		_ = gate.WithAuthorized(ctx, g, fx.allowReq, func(aCtx context.Context, _ gate.Authorized[security.CapExecute]) error {
			_ = p.WithLease(aCtx, pl, func(context.Context, *pool.Lease) error { return nil })
			cluster.SetENOSPC(true)
			return nil
		})
		return
	}
	switch rng.IntN(3) {
	case 0:
		_ = gate.WithAuthorized(ctx, g, fx.allowReq, func(aCtx context.Context, _ gate.Authorized[security.CapExecute]) error {
			return p.WithLease(aCtx, pl, func(context.Context, *pool.Lease) error { return nil })
		})
	case 1:
		_ = gate.WithAuthorized(ctx, g, fx.allowReq, func(aCtx context.Context, _ gate.Authorized[security.CapExecute]) error {
			return p.WithMultiLease(aCtx, []plan.SealedConnectionPlan{fx.twoHopA, fx.twoHopB}, func(context.Context, []*pool.Lease) error { return nil })
		})
	default:
		_ = gate.WithAuthorized(ctx, g, fx.deniedReq, func(context.Context, gate.Authorized[security.CapExecute]) error { return nil })
	}
}

func hashEngineState(cluster *sim.SimAuditCluster, gs gate.GateStats, ps pool.PoolStats) ([sha256.Size]byte, error) {
	var out [sha256.Size]byte
	auditSum, err := cluster.Digest()
	if err != nil {
		return out, err
	}
	h := sha256.New()
	_, _ = h.Write(auditSum[:])
	var buf [8]byte
	for _, v := range []uint64{gs.Authorized, gs.Denied, gs.Finalized, gs.PostWriteErrors, ps.TotalDials, ps.CacheHits, ps.TeardownCompleted} {
		binary.LittleEndian.PutUint64(buf[:], v)
		_, _ = h.Write(buf[:])
	}
	h.Sum(out[:0])
	return out, nil
}
