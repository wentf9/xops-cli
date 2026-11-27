package gate

import (
	"context"
	"errors"
	"runtime"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/foundation/trace"
	"github.com/wentf9/xops-cli/core/ports"
)

func TestWithAuthorizedExactOrderAndZeroOrphanPaths(t *testing.T) {
	clk, ent := newFakeClock(baseTestTime()), newFakeEntropy(11)
	sink := newFakeAuditSink(t, "gate-order-01")
	g := mustGate(t, GateConfig{
		Profile:   PolicyProfileStrictAgent,
		Policy:    mustPolicy(t, security.RiskDangerous, NoElicitFallbackDeny),
		AuditSink: sink, Clock: clk, Entropy: ent,
	})
	req := mustNewRequest(t, GateRequestSpec[security.CapInspect]{
		Binding: mustBinding(t, security.CapabilityInspect, "nodes", "list", "web-01"),
		Risk:    security.RiskSafe,
	})

	var observedOpID security.OperationID
	var flag *atomic.Bool
	err := WithAuthorized(context.Background(), g, req, func(opCtx context.Context, auth Authorized[security.CapInspect]) error {
		requireTrue(t, auth.IsValid() && !auth.IsRevoked() && !auth.IsZero(), "回调期内 Authorized 必须有效且未吊销")
		requireNoErr(t, auth.Validate(), "Validate")
		tid, oid, ok := trace.TraceFromContext(opCtx)
		requireTrue(t, ok && tid.IsValid() && oid.IsValid(), "opCtx 必须携带有效追踪标识")
		requireTrue(t, !trace.InLeaseScope(opCtx), "ADR-009 违规：gate 严禁注入 trace.LeaseScope")
		observedOpID = oid
		flag = peekSingleActiveHandleFlag(t, g)
		requireTrue(t, !flag.Load(), "执行期间句柄不得提前吊销")
		clk.Advance(150 * time.Millisecond)
		sink.recordEvent("run:" + observedOpID.String())
		return nil
	})
	requireNoErr(t, err, "WithAuthorized")
	requireTrue(t, flag != nil && flag.Load(), "退出回调后必须立即吊销借用句柄 revoked=true")

	wantTrace := []string{
		"stage:" + observedOpID.String(),
		"record:authorized:" + observedOpID.String(),
		"run:" + observedOpID.String(),
		"record:finalized:" + observedOpID.String(),
		"unstage:" + observedOpID.String(),
	}
	requireTrue(t, slices.Equal(sink.snapshotTrace(), wantTrace), "审计与只追加登记顺序必须严格为 Stage->Authorized->run->Finalized->Unstage")
	assertNoOrphanAudit(t, g, sink)
}

func TestWithAuthorizedZeroOrphanOnErrorCancelPanicAndGoexit(t *testing.T) {
	defer verifyNoGoroutineLeak(t)
	clk, ent := newFakeClock(baseTestTime()), newFakeEntropy(22)
	sink := newFakeAuditSink(t, "gate-zero-orphan-01")
	g := mustGate(t, GateConfig{
		Profile:   PolicyProfileStrictAgent,
		Policy:    mustPolicy(t, security.RiskDangerous, NoElicitFallbackDeny),
		AuditSink: sink, Clock: clk, Entropy: ent,
	})
	req := mustNewRequest(t, GateRequestSpec[security.CapExecute]{
		Binding: mustBinding(t, security.CapabilityExecute, "terminal_exec", "run", "app-01"),
		Risk:    security.RiskModerate,
	})

	bizErr := errors.New("remote command exit 1")
	requireErrIs(t, WithAuthorized(context.Background(), g, req, func(context.Context, Authorized[security.CapExecute]) error {
		clk.Advance(10 * time.Millisecond)
		return bizErr
	}), bizErr, "业务错误透传")

	cancelCtx, cancel := context.WithCancel(context.Background())
	requireErrIs(t, WithAuthorized(cancelCtx, g, req, func(opCtx context.Context, _ Authorized[security.CapExecute]) error {
		cancel()
		return opCtx.Err()
	}), context.Canceled, "取消路径")

	var panicFlag *atomic.Bool
	recovered := invokeAndRecoverPanic(func() {
		_ = WithAuthorized(context.Background(), g, req, func(context.Context, Authorized[security.CapExecute]) error {
			panicFlag = peekSingleActiveHandleFlag(t, g)
			panic("boom-inside-authorized")
		})
	})
	requireTrue(t, recovered == "boom-inside-authorized", "期望重抛原始 panic")
	requireTrue(t, panicFlag != nil && panicFlag.Load(), "panic 退场后句柄必须立即吊销")

	var goexitFlag *atomic.Bool
	requireNoErr(t, conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		return n.Go(func(c context.Context) error {
			return WithAuthorized(c, g, req, func(context.Context, Authorized[security.CapExecute]) error {
				goexitFlag = peekSingleActiveHandleFlag(t, g)
				runtime.Goexit()
				return nil
			})
		})
	}), "RunWait(Goexit)")
	requireTrue(t, goexitFlag != nil && goexitFlag.Load(), "Goexit 退场后句柄必须立即吊销")

	assertNoOrphanAudit(t, g, sink)
	assertFinalizedOutcomes(t, sink, []ports.AuditOutcome{
		ports.AuditOutcomeFailed,
		ports.AuditOutcomeCanceled,
		ports.AuditOutcomeFailed,
		ports.AuditOutcomeCanceled,
	})
}

func TestWithAuthorizedPreWriteAndUnstageFailures(t *testing.T) {
	clk, ent := newFakeClock(baseTestTime()), newFakeEntropy(33)
	sink := newFakeAuditSink(t, "gate-prewrite-01")
	g := mustGate(t, GateConfig{
		Profile:   PolicyProfileStrictAgent,
		Policy:    mustPolicy(t, security.RiskDangerous, NoElicitFallbackDeny),
		AuditSink: sink, Clock: clk, Entropy: ent,
	})
	req := mustNewRequest(t, GateRequestSpec[security.CapInspect]{
		Binding: mustBinding(t, security.CapabilityInspect, "nodes", "list", "web-01"),
		Risk:    security.RiskSafe,
	})

	sink.stageErr = errors.New("lock append failed")
	runCalled := false
	err := WithAuthorized(context.Background(), g, req, func(context.Context, Authorized[security.CapInspect]) error {
		runCalled = true
		return nil
	})
	requireErrIs(t, err, ErrAuditStageFailed, "Stage 失败必须返回 ErrAuditStageFailed")
	requireTrue(t, !runCalled, "Stage 失败不得调用 run")
	sink.stageErr = nil

	sink.authWriteErr = errSimulatedENOSPC
	err = WithAuthorized(context.Background(), g, req, func(context.Context, Authorized[security.CapInspect]) error {
		runCalled = true
		return nil
	})
	requireErrIs(t, err, ErrAuditPreWriteFailed, "前置审计失败必须返回 ErrAuditPreWriteFailed")
	requireTrue(t, !runCalled && sink.stagedCount() == 0, "前置审计失败必须注销 staged 且拦截 run")
	sink.authWriteErr = nil

	sink.unstageErr = errors.New("unstage io error")
	err = WithAuthorized(context.Background(), g, req, func(context.Context, Authorized[security.CapInspect]) error {
		return nil
	})
	requireErrIs(t, err, ErrAuditUnstageFailed, "Unstage 失败必须向上暴露 ErrAuditUnstageFailed")
}

func TestStrictAgentProfileENOSPCImmediateHaltAndOnHaltLinearization(t *testing.T) {
	defer verifyNoGoroutineLeak(t)
	clk, ent := newFakeClock(baseTestTime()), newFakeEntropy(44)
	sink := newFakeAuditSink(t, "gate-enospc-01")
	bus := mustSystemBus(t)
	defer bus.Close()
	sub, err := bus.Subscribe()
	requireNoErr(t, err, "Subscribe")
	defer sub.Close()

	var haltCalls atomic.Int32
	var capturedInfo HaltInfo
	var gateRef atomic.Pointer[Gate]
	g := mustGate(t, GateConfig{
		Profile:   PolicyProfileStrictAgent,
		Policy:    mustPolicy(t, security.RiskDangerous, NoElicitFallbackDeny),
		AuditSink: sink, Clock: clk, Entropy: ent, SystemBus: bus,
		OnHalt: func(info HaltInfo) {
			haltCalls.Add(1)
			capturedInfo = info
			cur := gateRef.Load()
			requireTrue(t, cur.IsHalted(), "OnHalt 内 IsHalted 必须为 true")
			_, ok := cur.HaltInfo()
			requireTrue(t, ok, "OnHalt 内必须可读到有效 HaltInfo")
			_ = cur.Stats()
		},
	})
	gateRef.Store(g)

	req := mustNewRequest(t, GateRequestSpec[security.CapExecute]{
		Binding: mustBinding(t, security.CapabilityExecute, "terminal_exec", "run", "prod-01"),
		Risk:    security.RiskModerate,
	})
	runConcurrentENOSPCHalt(t, g, sink, req)

	requireTrue(t, g.IsHalted() && haltCalls.Load() == 1 && capturedInfo.IsValid(), "期望不可逆 Halted 且 OnHalt 恰好触发 1 次")
	requireTrue(t, sink.stagedCount() == 1, "终态落盘失败的 B 必须保留在 .lock 中供崩溃对账")

	calledAfterHalt := false
	err = WithAuthorized(context.Background(), g, req, func(context.Context, Authorized[security.CapExecute]) error {
		calledAfterHalt = true
		return nil
	})
	requireErrIs(t, err, ErrGateHalted, "熔断后新请求必须返回 ErrGateHalted")
	requireTrue(t, !calledAfterHalt, "熔断后不得执行 run")

	ev, ok, nErr := sub.Next(context.Background())
	requireNoErr(t, nErr, "sub.Next")
	diag, isDiag := ev.(*events.DiagnosticEvent)
	requireTrue(t, ok && isDiag && diag.Scope() == events.DiagnosticScopeGate && diag.Code() == "gate_halted", "期望收到 gate_halted 诊断事件")
}

func runConcurrentENOSPCHalt(t *testing.T, g *Gate, sink *fakeAuditSink, req GateRequest[security.CapExecute]) {
	t.Helper()
	aEntered, bDone := make(chan struct{}), make(chan struct{})
	var aRevoked atomic.Bool
	sink.finalWriteErr = errSimulatedENOSPC
	sink.finalFailOnCall = 1

	err := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(c context.Context) error {
			return WithAuthorized(c, g, req, func(_ context.Context, auth Authorized[security.CapExecute]) error {
				close(aEntered)
				<-bDone
				aRevoked.Store(auth.IsRevoked() && !auth.IsValid() && errors.Is(auth.Validate(), ErrPermitRevoked))
				return nil
			})
		}); gErr != nil {
			return gErr
		}
		return n.Go(func(c context.Context) error {
			<-aEntered
			defer close(bDone)
			bErr := WithAuthorized(c, g, req, func(context.Context, Authorized[security.CapExecute]) error { return nil })
			requireErrIs(t, bErr, ports.ErrAuditPostWrite, "B ErrAuditPostWrite")
			requireErrIs(t, bErr, errSimulatedENOSPC, "B ENOSPC")
			pw, ok := errors.AsType[*ports.AuditPostWriteError](bErr)
			requireTrue(t, ok && pw.IsValid(), "B 必须返回有效 *ports.AuditPostWriteError")
			return nil
		})
	})
	requireNoErr(t, err, "runConcurrentENOSPCHalt")
	requireTrue(t, aRevoked.Load(), "并发熔断必须立即吊销在途操作 A 持有的 Authorized 句柄")
}

func TestHaltBetweenAuthorizedRecordAndRegisterZeroOrphan(t *testing.T) {
	clk, ent := newFakeClock(baseTestTime()), newFakeEntropy(48)
	sink := newFakeAuditSink(t, "gate-halt-window-01")
	var g *Gate
	sink.onRecord = func(entry ports.AuditEntry) {
		if entry.Phase() == ports.AuditPhaseAuthorized {
			// 在 Authorized 落盘完成瞬间并发触发 Halt，验证 registerIssuedPermit 跳过 run 并自动闭合终态零孤儿。
			g.Halt("mid_authorize_halt", errSimulatedENOSPC)
		}
	}
	g = mustGate(t, GateConfig{
		Profile:   PolicyProfileStrictAgent,
		Policy:    mustPolicy(t, security.RiskDangerous, NoElicitFallbackDeny),
		AuditSink: sink, Clock: clk, Entropy: ent,
	})
	req := mustNewRequest(t, GateRequestSpec[security.CapInspect]{
		Binding: mustBinding(t, security.CapabilityInspect, "nodes", "list", "web-01"),
		Risk:    security.RiskSafe,
	})
	runCalled := false
	err := WithAuthorized(context.Background(), g, req, func(context.Context, Authorized[security.CapInspect]) error {
		runCalled = true
		return nil
	})
	requireErrIs(t, err, ErrGateHalted, "授权竞态窗口遇 Halt 必须返回 ErrGateHalted")
	requireTrue(t, !runCalled, "竞态窗口遇 Halt 绝不得进入 run")
	assertNoOrphanAudit(t, g, sink)
	assertFinalizedOutcomes(t, sink, []ports.AuditOutcome{ports.AuditOutcomeCanceled})
}

func TestDirectOperatorProfileAuditAndExplicitDeny(t *testing.T) {
	clk, ent := newFakeClock(baseTestTime()), newFakeEntropy(55)
	sink := newFakeAuditSink(t, "gate-direct-01")
	sink.finalWriteErr = errSimulatedENOSPC
	sink.finalFailOnCall = 1

	var haltCalls atomic.Int32
	g := mustGate(t, GateConfig{
		Profile:   PolicyProfileDirectOperator,
		Policy:    mustPolicy(t, security.RiskSafe, NoElicitFallbackDeny, "/etc/**"),
		AuditSink: sink, Clock: clk, Entropy: ent,
		OnHalt: func(HaltInfo) { haltCalls.Add(1) },
	})
	req := mustNewRequest(t, GateRequestSpec[security.CapFileMut]{
		Binding: mustBinding(t, security.CapabilityFileMut, "file", "write", "web-01", "/etc/hosts"),
		Risk:    security.RiskDangerous,
	})

	requireErrIs(t, WithAuthorized(context.Background(), g, req, func(context.Context, Authorized[security.CapFileMut]) error {
		return nil
	}), ports.ErrAuditPostWrite, "DirectOperator 仍须返回 *AuditPostWriteError")
	requireTrue(t, !g.IsHalted() && haltCalls.Load() == 0, "DirectOperatorProfile 不应因单次后置写错误进入永久 Halted")

	requireNoErr(t, WithAuthorized(context.Background(), g, req, func(context.Context, Authorized[security.CapFileMut]) error {
		return nil
	}), "DirectOperator 后续请求放行")

	// DirectOperatorProfile 下显式 VerdictDeny 仍须严格拒绝。
	denyReq := mustNewRequest(t, GateRequestSpec[security.CapFileMut]{
		Binding: mustBinding(t, security.CapabilityFileMut, "file", "write", "web-01", "/etc/hosts"),
		Risk:    security.RiskSafe,
		Verdict: algebraic.Some(security.VerdictDeny),
	})
	requireErrIs(t, WithAuthorized(context.Background(), g, denyReq, func(context.Context, Authorized[security.CapFileMut]) error {
		t.Fatal("VerdictDeny 不得放行")
		return nil
	}), ErrAuthorizationDenied, "DirectOperator VerdictDeny")
}

func TestOutcomeUnknownPreservedNeverDowngraded(t *testing.T) {
	clk, ent := newFakeClock(baseTestTime()), newFakeEntropy(66)
	sink := newFakeAuditSink(t, "gate-unknown-01")
	g := mustGate(t, GateConfig{
		Profile:   PolicyProfileStrictAgent,
		Policy:    mustPolicy(t, security.RiskDangerous, NoElicitFallbackDeny),
		AuditSink: sink, Clock: clk, Entropy: ent,
	})
	req := mustNewRequest(t, GateRequestSpec[security.CapExecute]{
		Binding: mustBinding(t, security.CapabilityExecute, "terminal_exec", "run", "db-01"),
		Risk:    security.RiskModerate,
	})
	unk, err := execution.NewOutcomeUnknown(execution.ExecPhaseTransportLost, "ssh_eof", "transport dropped")
	requireNoErr(t, err, "NewOutcomeUnknown")
	completedOK, err := execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	requireNoErr(t, err, "NewOutcomeCompleted")

	// 1. 通过 WrapOutcomeError 经错误链携带 OutcomeUnknown。
	wrapped, err := WrapOutcomeError(unk, errors.New("eof during wait"))
	requireNoErr(t, err, "WrapOutcomeError")
	requireErrIs(t, WithAuthorized(context.Background(), g, req, func(context.Context, Authorized[security.CapExecute]) error {
		return wrapped
	}), wrapped, "场景 1 WrapOutcomeError")

	// 2. 通过 auth.ReportOutcome(OutcomeUnknown)，后续尝试写入 Completed 不可降级。
	requireNoErr(t, WithAuthorized(context.Background(), g, req, func(_ context.Context, auth Authorized[security.CapExecute]) error {
		requireNoErr(t, auth.ReportOutcome(unk), "ReportOutcome(unk)")
		requireNoErr(t, auth.ReportOutcome(completedOK), "ReportOutcome(completedOK)")
		return nil
	}), "场景 2 ReportOutcome")

	// 3. ReportOutcome(OutcomeUnknown) + 上下文超时。
	requireErrIs(t, WithAuthorized(context.Background(), g, req, func(_ context.Context, auth Authorized[security.CapExecute]) error {
		_ = auth.ReportOutcome(unk)
		return context.DeadlineExceeded
	}), context.DeadlineExceeded, "场景 3 超时")

	// 4. ReportOutcome(OutcomeUnknown) + panic。
	_ = invokeAndRecoverPanic(func() {
		_ = WithAuthorized(context.Background(), g, req, func(_ context.Context, auth Authorized[security.CapExecute]) error {
			_ = auth.ReportOutcome(unk)
			panic("post-send panic")
		})
	})

	assertFinalizedOutcomes(t, sink, []ports.AuditOutcome{
		ports.AuditOutcomeUnknown,
		ports.AuditOutcomeUnknown,
		ports.AuditOutcomeUnknown,
		ports.AuditOutcomeUnknown,
	})
}

func TestReconcileCrashedAuditsFastAndSlowPaths(t *testing.T) {
	clk, ent := newFakeClock(baseTestTime()), newFakeEntropy(77)
	sink := newFakeAuditSink(t, "gate-reconcile-01")
	rec := &fakeReconciler{scannedLocks: 2, liveLocks: 2}
	bus := mustSystemBus(t)
	defer bus.Close()
	sub, err := bus.Subscribe()
	requireNoErr(t, err, "Subscribe")
	defer sub.Close()

	noRecGate := mustGate(t, GateConfig{
		Profile:   PolicyProfileStrictAgent,
		Policy:    mustPolicy(t, security.RiskModerate, NoElicitFallbackDeny),
		AuditSink: sink, Clock: clk, Entropy: ent,
	})
	_, err = noRecGate.ReconcileCrashedAudits(context.Background())
	requireErrIs(t, err, ErrReconcilerUnavailable, "未配置 reconciler")

	g := mustGate(t, GateConfig{
		Profile:   PolicyProfileStrictAgent,
		Policy:    mustPolicy(t, security.RiskModerate, NoElicitFallbackDeny),
		AuditSink: sink, Reconciler: rec, Clock: clk, Entropy: ent, SystemBus: bus,
	})

	// 干净启动 O(1) 快路径：零读取 audit.jsonl。
	rep, err := g.ReconcileCrashedAudits(context.Background())
	requireNoErr(t, err, "Reconcile(clean)")
	requireTrue(t, rep.IsValid() && rep.DeadLocksClaimed() == 0 && rec.auditScanCount == 0, "干净启动快路径不得扫描 audit.jsonl")
	assertDiagCode(t, sub, "audit_reconcile_clean")

	// 崩溃恢复慢路径 + 二次幂等回落快路径。
	crashedOp, err := security.NewOperationIDFrom(ent)
	requireNoErr(t, err, "NewOperationIDFrom")
	rec.scannedLocks, rec.liveLocks, rec.deadLocks = 3, 2, 1
	rec.crashedOps = []security.OperationID{crashedOp}

	rep2, err := g.ReconcileCrashedAudits(context.Background())
	requireNoErr(t, err, "Reconcile(crash)")
	requireTrue(t, rep2.DeadLocksClaimed() == 1 && slices.ContainsFunc(rep2.AbortedOperations(), crashedOp.Equal) && rec.auditScanCount == 1, "崩溃慢路径报告异常")
	assertDiagCode(t, sub, "audit_crash_reconciled")

	rep3, err := g.ReconcileCrashedAudits(context.Background())
	requireNoErr(t, err, "Reconcile(idempotent)")
	requireTrue(t, rep3.DeadLocksClaimed() == 0 && len(rep3.AbortedOperations()) == 0 && rec.auditScanCount == 1, "二次对账必须幂等零扫描")
}

func TestConcurrentWithAuthorizedAndHaltStress(t *testing.T) {
	defer verifyNoGoroutineLeak(t)
	clk, ent := newFakeClock(baseTestTime()), newFakeEntropy(88)
	sink := newFakeAuditSink(t, "gate-stress-01")

	var haltCalls atomic.Int32
	g := mustGate(t, GateConfig{
		Profile:   PolicyProfileStrictAgent,
		Policy:    mustPolicy(t, security.RiskDangerous, NoElicitFallbackDeny),
		AuditSink: sink, Clock: clk, Entropy: ent,
		OnHalt: func(HaltInfo) { haltCalls.Add(1) },
	})
	req := mustNewRequest(t, GateRequestSpec[security.CapInspect]{
		Binding: mustBinding(t, security.CapabilityInspect, "nodes", "inspect", "web-01"),
		Risk:    security.RiskSafe,
	})

	err := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if wErr := spawnStressWorkers(n, g, req); wErr != nil {
			return wErr
		}
		return spawnStressHalters(n, g)
	})
	requireNoErr(t, err, "并发压测")
	requireTrue(t, g.IsHalted() && haltCalls.Load() == 1, "期望 Halted 且 OnHalt 恰好触发 1 次")
	assertNoOrphanAudit(t, g, sink)
}

func spawnStressWorkers(n *conc.Nursery, g *Gate, req GateRequest[security.CapInspect]) error {
	for i := range 16 {
		idx := i
		if err := n.Go(func(c context.Context) error { return runStressWorkerLoop(c, g, req, idx) }); err != nil {
			return err
		}
	}
	return nil
}

func runStressWorkerLoop(ctx context.Context, g *Gate, req GateRequest[security.CapInspect], idx int) error {
	for range 6 {
		wErr := WithAuthorized(ctx, g, req, func(_ context.Context, auth Authorized[security.CapInspect]) error {
			_ = auth.IsValid()
			_ = auth.Capability()
			if idx == 3 {
				g.Halt("concurrent_stress_halt", errSimulatedENOSPC)
			}
			return nil
		})
		if wErr != nil && !errors.Is(wErr, ErrGateHalted) {
			return wErr
		}
	}
	return nil
}

func spawnStressHalters(n *conc.Nursery, g *Gate) error {
	for range 4 {
		if err := n.Go(func(context.Context) error {
			g.Halt("concurrent_stress_halt", errSimulatedENOSPC)
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

func assertNoOrphanAudit(t *testing.T, g *Gate, sink *fakeAuditSink) {
	t.Helper()
	if sink.stagedCount() != 0 || len(sink.orphanOpIDs()) != 0 || g.Stats().ActiveHandles != 0 {
		t.Fatalf("不得存在残留 staged、活跃句柄或孤儿审计: staged=%d orphans=%v active=%d",
			sink.stagedCount(), sink.orphanOpIDs(), g.Stats().ActiveHandles)
	}
}

func assertFinalizedOutcomes(t *testing.T, sink *fakeAuditSink, want []ports.AuditOutcome) {
	t.Helper()
	entries := sink.snapshotEntries()
	if len(entries) != len(want)*2 {
		t.Fatalf("期望 %d 条配对审计记录，实际=%d", len(want)*2, len(entries))
	}
	for i, w := range want {
		fin := entries[i*2+1]
		if fin.Phase() != ports.AuditPhaseFinalized || fin.Outcome() != w {
			t.Fatalf("第 %d 次终态记录不符: phase=%s outcome=%s want=%s", i, fin.Phase(), fin.Outcome(), w)
		}
	}
}

func assertDiagCode(t *testing.T, sub *events.SystemSubscription, wantCode string) {
	t.Helper()
	ev, ok, err := sub.Next(context.Background())
	requireNoErr(t, err, "sub.Next")
	diag, isDiag := ev.(*events.DiagnosticEvent)
	if !ok || !isDiag || diag.Code() != wantCode {
		t.Fatalf("期望诊断码 %q，实际=%#v", wantCode, ev)
	}
}

func invokeAndRecoverPanic(fn func()) (recovered any) {
	defer func() {
		recovered = recover()
	}()
	fn()
	return nil
}

func TestOperationPanicErrorLocalizableNode(t *testing.T) {
	pe := newOperationPanicError("boom\x00detail", []byte("stack"))
	requireErrIs(t, pe, ErrOperationPanicked, "OperationPanicError Unwrap")
	view, ok := domi18n.InspectNode(pe)
	requireTrue(t, ok && view.Message.ID() == domi18n.KeyGateOpPanickedDetail && errors.Is(view.Sentinel, ErrOperationPanicked), "OperationPanicError LocalizableView 异常")
	requireTrue(t, pe.Error() == domi18n.CanonicalError(pe) && pe.Error() != "", "OperationPanicError CanonicalError 异常")
}
