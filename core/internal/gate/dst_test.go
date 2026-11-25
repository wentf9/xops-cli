package gate_test

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
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/ports"
)

const (
	defaultGateDSTSeeds = 64
	gateDSTWorkers      = 4
)

func resolveGateDSTSeeds(t *testing.T, offset uint64) []uint64 {
	t.Helper()
	if raw := os.Getenv("XOPS_DST_SEED"); raw != "" {
		v, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			t.Fatalf("无效的 XOPS_DST_SEED=%q: %v", raw, err)
		}
		return []uint64{v}
	}
	n := defaultGateDSTSeeds
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

func runSeedsParallel(t *testing.T, seeds []uint64, fn func(seed uint64) error) {
	t.Helper()
	var next atomic.Uint64
	workers := min(gateDSTWorkers, len(seeds))
	err := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		for range workers {
			if gErr := n.Go(func(c context.Context) error {
				return drainGateSeedQueue(c, seeds, &next, fn)
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

func drainGateSeedQueue(ctx context.Context, seeds []uint64, next *atomic.Uint64, fn func(seed uint64) error) error {
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

type gateDSTFixture struct {
	policy        gate.GuardrailPolicy
	bindExec      security.OperationBinding
	bindWrite     security.OperationBinding
	bindEscalateA security.OperationBinding
	bindEscalateB security.OperationBinding
}

func mustGateDSTFixture(t *testing.T) gateDSTFixture {
	t.Helper()
	ruleA, err := pathalg.NewProtectedRule("/etc/**", "sys_etc")
	if err != nil {
		t.Fatalf("NewProtectedRule(A): %v", err)
	}
	ruleB, err := pathalg.NewProtectedRule("/var/lib/**", "state_var")
	if err != nil {
		t.Fatalf("NewProtectedRule(B): %v", err)
	}
	policy, err := gate.NewGuardrailPolicy(gate.GuardrailPolicySpec{
		ApprovalThreshold: security.RiskModerate,
		NoElicitFallback:  gate.NoElicitFallbackChallenge,
		ProtectedRules:    []pathalg.ProtectedRule{ruleA, ruleB},
	})
	if err != nil {
		t.Fatalf("NewGuardrailPolicy: %v", err)
	}
	return gateDSTFixture{
		policy:        policy,
		bindExec:      mustBinding(t, security.CapabilityExecute, "exec", "run", nil),
		bindWrite:     mustBinding(t, security.CapabilityFileMut, "sftp", "put", []string{"/tmp/upload.bin"}),
		bindEscalateA: mustBinding(t, security.CapabilityFileMut, "sftp", "put", []string{"/etc/app.conf"}),
		bindEscalateB: mustBinding(t, security.CapabilityFileMut, "sftp", "put", []string{"/var/lib/secret.db"}),
	}
}

func mustBinding(t *testing.T, capKind security.CapabilityKind, tool, action string, paths []string) security.OperationBinding {
	t.Helper()
	b, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability:     capKind,
		Tool:           tool,
		Action:         action,
		CanonicalPaths: paths,
	})
	if err != nil {
		t.Fatalf("NewOperationBinding: %v", err)
	}
	return b
}

// TestDST_GateCrashReconciliation 在随机多进程、全部 4 类审计边界 SIGKILL 注入、审批重放、
// Protected-A->B 升级、OutcomeUnknown 与 panic 场景下验证零孤儿、零重复终态与 O(1) 崩溃对账不变量。
func TestDST_GateCrashReconciliation(t *testing.T) {
	defer goleak.VerifyNone(t)
	fx := mustGateDSTFixture(t)
	seeds := resolveGateDSTSeeds(t, 0x10000)
	runSeedsParallel(t, seeds, func(seed uint64) error {
		return runGateCrashSeed(fx, seed)
	})
}

func runGateCrashSeed(fx gateDSTFixture, seed uint64) error {
	rng := sim.NewSeededRand(seed)
	clk := sim.NewSimClock(sim.DefaultBaseTime())
	cluster := sim.NewSimAuditCluster()
	ctx := context.Background()

	// 活跃对等进程持有效锁且存在 1 个在途操作：崩溃对账必须跳过该活跃锁且不得补写 AbortedByCrash。
	liveSink, err := cluster.NewSinkFromEntropy(rng)
	if err != nil {
		return err
	}
	defer func() { _ = liveSink.Close() }()
	liveOp, err := stageLiveOperation(ctx, liveSink, rng, fx.bindExec)
	if err != nil {
		return err
	}

	unknownOps := make(map[security.OperationID]bool)
	crashedCount := 1 + rng.IntN(2)
	for range crashedCount {
		if err := runCrashedProcessWorkload(ctx, fx, cluster, clk, rng, unknownOps); err != nil {
			return err
		}
	}

	recSink, err := cluster.NewSinkFromEntropy(rng)
	if err != nil {
		return err
	}
	defer func() { _ = recSink.Close() }()
	recGate, err := gate.NewGate(gate.GateConfig{
		Profile:    gate.PolicyProfileStrictOperator,
		Policy:     fx.policy,
		AuditSink:  recSink,
		Reconciler: cluster,
		Clock:      clk,
		Entropy:    rng,
	})
	if err != nil {
		return err
	}

	clk.Advance(time.Second)
	rep1, err := recGate.ReconcileCrashedAudits(ctx)
	if err != nil {
		return fmt.Errorf("首次 ReconcileCrashedAudits 失败: %w", err)
	}
	if rep1.DeadLocksClaimed() != crashedCount || rep1.LiveLocksSkipped() < 2 {
		return fmt.Errorf("首次对账统计异常: claimed=%d(want %d) liveSkipped=%d", rep1.DeadLocksClaimed(), crashedCount, rep1.LiveLocksSkipped())
	}

	scansBefore := cluster.AuditLogScans()
	clk.Advance(time.Second)
	rep2, err := recGate.ReconcileCrashedAudits(ctx)
	if err != nil {
		return fmt.Errorf("二次 ReconcileCrashedAudits 失败: %w", err)
	}
	if rep2.DeadLocksClaimed() != 0 || len(rep2.AbortedOperations()) != 0 || cluster.AuditLogScans() != scansBefore {
		return fmt.Errorf("二次对账违背 O(1)/幂等不变量: rep=%+v scans=%d->%d", rep2, scansBefore, cluster.AuditLogScans())
	}
	return verifyAuditInvariants(cluster.Entries(), liveOp, unknownOps)
}

func stageLiveOperation(ctx context.Context, sink *sim.SimAuditSink, rng *sim.SeededRand, b security.OperationBinding) (opID security.OperationID, err error) {
	traceID, err := security.NewTraceIDFrom(rng)
	if err != nil {
		return opID, err
	}
	opID, err = security.NewOperationIDFrom(rng)
	if err != nil {
		return opID, err
	}
	if err := sink.StageOperation(ctx, opID); err != nil {
		return opID, err
	}
	ent, err := ports.NewAuditEntry(ports.AuditEntrySpec{
		ProcessID: sink.ProcessInstanceID(), TraceID: traceID, OperationID: opID,
		Phase: ports.AuditPhaseAuthorized, Outcome: ports.AuditOutcomePending,
		Risk: security.RiskSafe, Decision: security.DecisionKindAllow, Binding: b,
		Timestamp: sim.DefaultBaseTime(), Reason: "live peer op",
	})
	if err != nil {
		return opID, err
	}
	return opID, sink.Record(ctx, ent)
}

func runCrashedProcessWorkload(
	ctx context.Context,
	fx gateDSTFixture,
	cluster *sim.SimAuditCluster,
	clk *sim.SimClock,
	rng *sim.SeededRand,
	unknownOps map[security.OperationID]bool,
) error {
	sink, err := cluster.NewSinkFromEntropy(rng)
	if err != nil {
		return err
	}
	g, err := gate.NewGate(gate.GateConfig{
		Profile:   gate.PolicyProfileStrictOperator,
		Policy:    fx.policy,
		AuditSink: sink,
		Clock:     clk,
		Entropy:   rng,
	})
	if err != nil {
		return err
	}
	opCount := 2 + rng.IntN(3)
	crashStep := rng.IntN(opCount)
	crashKind := rng.IntN(5) // 0..3 对应 4 类 AuditBoundary，4 对应 run 回调中途崩溃
	for i := range opCount {
		clk.Advance(10 * time.Millisecond)
		if i == crashStep && crashKind < 4 {
			target := sim.AuditBoundary(crashKind + 1)
			sink.SetBoundaryHook(func(b sim.AuditBoundary, _ security.OperationID) {
				if b == target {
					sink.SimulateSIGKILL()
				}
			})
		}
		midCrash := i == crashStep && crashKind == 4
		if err := execRandomizedGateOp(ctx, fx, g, sink, rng, midCrash, unknownOps); err != nil {
			return err
		}
		if i == crashStep {
			sink.SimulateSIGKILL()
			break
		}
	}
	return nil
}

func execRandomizedGateOp(
	ctx context.Context,
	fx gateDSTFixture,
	g *gate.Gate,
	sink *sim.SimAuditSink,
	rng *sim.SeededRand,
	midCrash bool,
	unknownOps map[security.OperationID]bool,
) error {
	switch rng.IntN(6) {
	case 0:
		return execAllowOrUnknownOp(ctx, fx, g, sink, rng, midCrash, unknownOps)
	case 1:
		return execDeniedOp(ctx, fx, g)
	case 2:
		return execTwoStepApprovalAndReplay(ctx, fx, g, sink, midCrash)
	case 3:
		return execRound2Escalation(ctx, fx, g)
	case 4:
		return execPanicOp(ctx, fx, g)
	default:
		return execCanceledOp(ctx, fx, g, sink, midCrash)
	}
}

func execAllowOrUnknownOp(
	ctx context.Context,
	fx gateDSTFixture,
	g *gate.Gate,
	sink *sim.SimAuditSink,
	rng *sim.SeededRand,
	midCrash bool,
	unknownOps map[security.OperationID]bool,
) error {
	req, err := gate.NewGateRequest[security.CapExecute](gate.GateRequestSpec[security.CapExecute]{
		Binding: fx.bindExec,
		Risk:    security.RiskSafe,
	})
	if err != nil {
		return err
	}
	reportUnknown := !midCrash && rng.Bool()
	var capturedOp security.OperationID
	runErr := gate.WithAuthorized(ctx, g, req, func(_ context.Context, auth gate.Authorized[security.CapExecute]) error {
		if !auth.IsValid() || auth.IsRevoked() {
			return errors.New("回调内 Authorized 必须有效且未吊销")
		}
		capturedOp = auth.OperationID()
		if midCrash {
			sink.SimulateSIGKILL()
			return sim.ErrSimulatedCrash
		}
		if reportUnknown {
			unk, uErr := execution.NewOutcomeUnknown(execution.ExecPhaseTransportLost, "sim_drop", "network dropped mid-flight")
			if uErr != nil {
				return uErr
			}
			_ = auth.ReportOutcome(unk)
			return sim.ErrFaultInjected
		}
		return nil
	})
	if reportUnknown && capturedOp.IsValid() && errors.Is(runErr, sim.ErrFaultInjected) && !errors.Is(runErr, ports.ErrAuditPostWrite) {
		unknownOps[capturedOp] = true
	}
	return nil
}

func execDeniedOp(ctx context.Context, fx gateDSTFixture, g *gate.Gate) error {
	req, err := gate.NewGateRequest[security.CapExecute](gate.GateRequestSpec[security.CapExecute]{
		Binding: fx.bindExec,
		Risk:    security.RiskSafe,
		Verdict: algebraic.Some(security.VerdictDeny),
	})
	if err != nil {
		return err
	}
	executed := false
	err = gate.WithAuthorized(ctx, g, req, func(context.Context, gate.Authorized[security.CapExecute]) error {
		executed = true
		return nil
	})
	if executed || err == nil {
		return fmt.Errorf("拒绝策略不得执行回调: executed=%v err=%w", executed, err)
	}
	return nil
}

func execTwoStepApprovalAndReplay(ctx context.Context, fx gateDSTFixture, g *gate.Gate, sink *sim.SimAuditSink, midCrash bool) error {
	req1, err := gate.NewGateRequest[security.CapFileMut](gate.GateRequestSpec[security.CapFileMut]{
		Binding: fx.bindWrite,
		Risk:    security.RiskDangerous,
	})
	if err != nil {
		return err
	}
	ranUnapproved := false
	err1 := gate.WithAuthorized(ctx, g, req1, func(context.Context, gate.Authorized[security.CapFileMut]) error {
		ranUnapproved = true
		return errors.New("未审批不得执行")
	})
	chErr, ok := errors.AsType[*gate.ApprovalChallengeError](err1)
	if ranUnapproved || !ok {
		return fmt.Errorf("未审批高危操作必须返回 ApprovalChallengeError: ran=%v err=%w", ranUnapproved, err1)
	}
	resp, err := ports.NewApprovalDecisionResponse(security.VerdictAllow, chErr.EnvelopeDigest(), "dst approve")
	if err != nil {
		return err
	}
	sub, err := gate.NewApprovalSubmission(gate.ApprovalSubmissionSpec{
		Envelope: algebraic.Some(chErr.Envelope()),
		Response: resp,
	})
	if err != nil {
		return err
	}
	req2, err := gate.NewGateRequest[security.CapFileMut](gate.GateRequestSpec[security.CapFileMut]{
		OperationID: algebraic.Some(chErr.Envelope().OperationID()),
		Binding:     fx.bindWrite,
		Risk:        security.RiskDangerous,
		Approval:    algebraic.Some(sub),
	})
	if err != nil {
		return err
	}
	_ = gate.WithAuthorized(ctx, g, req2, func(_ context.Context, _ gate.Authorized[security.CapFileMut]) error {
		if midCrash {
			sink.SimulateSIGKILL()
			return sim.ErrSimulatedCrash
		}
		return nil
	})
	if !midCrash {
		replayed := false
		rErr := gate.WithAuthorized(ctx, g, req2, func(context.Context, gate.Authorized[security.CapFileMut]) error {
			replayed = true
			return nil
		})
		if replayed || rErr == nil || (!errors.Is(rErr, gate.ErrApprovalReplayed) && !errors.Is(rErr, ports.ErrClosed)) {
			return fmt.Errorf("审批重放必须失败关闭且返回 ErrApprovalReplayed/ErrClosed: replayed=%v err=%w", replayed, rErr)
		}
	}
	return nil
}

func execRound2Escalation(ctx context.Context, fx gateDSTFixture, g *gate.Gate) error {
	// 场景 1：首次申请在规范化阶段发生 Protected-A -> Protected-B 重定向，必须返回绑定到 B 的审批挑战。
	req, err := gate.NewGateRequest[security.CapFileMut](gate.GateRequestSpec[security.CapFileMut]{
		Binding: fx.bindEscalateA,
		Risk:    security.RiskSafe,
		Canonicalize: func(context.Context) (gate.CanonicalizeResult, error) {
			return gate.CanonicalizeResult{Binding: fx.bindEscalateB}, nil
		},
	})
	if err != nil {
		return err
	}
	executed := false
	err = gate.WithAuthorized(ctx, g, req, func(context.Context, gate.Authorized[security.CapFileMut]) error {
		executed = true
		return nil
	})
	chErr, ok := errors.AsType[*gate.ApprovalChallengeError](err)
	if executed || !ok || !chErr.Envelope().Binding().Equal(fx.bindEscalateB) {
		return fmt.Errorf("首次规范化升级必须返回绑定目标 B 的 ApprovalChallengeError: executed=%v ok=%v err=%w", executed, ok, err)
	}
	return execPostApprovalEscalation(ctx, fx, g)
}

func execPostApprovalEscalation(ctx context.Context, fx gateDSTFixture, g *gate.Gate) error {
	// 场景 2：为 Protected-A（含 Round-1 规范化）签发合法审批后，二次提交 Round-2 重定向至 Protected-B，
	// 必须作废挑战令牌并返回 ErrScopeEscalated（ADR-016 / INV-E5）。
	reqA, err := gate.NewGateRequest[security.CapFileMut](gate.GateRequestSpec[security.CapFileMut]{
		Binding: fx.bindEscalateA,
		Risk:    security.RiskSafe,
		Canonicalize: func(context.Context) (gate.CanonicalizeResult, error) {
			return gate.CanonicalizeResult{Binding: fx.bindEscalateA}, nil
		},
	})
	if err != nil {
		return err
	}
	errA := gate.WithAuthorized(ctx, g, reqA, func(context.Context, gate.Authorized[security.CapFileMut]) error {
		return errors.New("Protected-A 未审批不得执行")
	})
	chA, ok := errors.AsType[*gate.ApprovalChallengeError](errA)
	if !ok {
		return fmt.Errorf("Protected-A 必须触发审批挑战: err=%w", errA)
	}
	resp, err := ports.NewApprovalDecisionResponse(security.VerdictAllow, chA.EnvelopeDigest(), "dst approve A")
	if err != nil {
		return err
	}
	sub, err := gate.NewApprovalSubmission(gate.ApprovalSubmissionSpec{
		Envelope: algebraic.Some(chA.Envelope()),
		Response: resp,
	})
	if err != nil {
		return err
	}
	reqEsc, err := gate.NewGateRequest[security.CapFileMut](gate.GateRequestSpec[security.CapFileMut]{
		OperationID: algebraic.Some(chA.Envelope().OperationID()),
		Binding:     fx.bindEscalateA,
		Risk:        security.RiskSafe,
		Approval:    algebraic.Some(sub),
		Canonicalize: func(context.Context) (gate.CanonicalizeResult, error) {
			return gate.CanonicalizeResult{Binding: fx.bindEscalateB}, nil
		},
	})
	if err != nil {
		return err
	}
	executed := false
	errEsc := gate.WithAuthorized(ctx, g, reqEsc, func(context.Context, gate.Authorized[security.CapFileMut]) error {
		executed = true
		return nil
	})
	if executed || !errors.Is(errEsc, gate.ErrScopeEscalated) {
		return fmt.Errorf("批后 Round-2 Protected-A->B 升级必须返回 ErrScopeEscalated: executed=%v err=%w", executed, errEsc)
	}
	return nil
}

func execPanicOp(ctx context.Context, fx gateDSTFixture, g *gate.Gate) error {
	req, err := gate.NewGateRequest[security.CapExecute](gate.GateRequestSpec[security.CapExecute]{
		Binding: fx.bindExec,
		Risk:    security.RiskSafe,
	})
	if err != nil {
		return err
	}
	defer func() { _ = recover() }()
	_ = gate.WithAuthorized(ctx, g, req, func(context.Context, gate.Authorized[security.CapExecute]) error {
		panic("dst-simulated-panic")
	})
	return nil
}

func execCanceledOp(ctx context.Context, fx gateDSTFixture, g *gate.Gate, sink *sim.SimAuditSink, midCrash bool) error {
	opCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, err := gate.NewGateRequest[security.CapExecute](gate.GateRequestSpec[security.CapExecute]{
		Binding: fx.bindExec,
		Risk:    security.RiskSafe,
	})
	if err != nil {
		return err
	}
	_ = gate.WithAuthorized(opCtx, g, req, func(_ context.Context, _ gate.Authorized[security.CapExecute]) error {
		cancel()
		if midCrash {
			sink.SimulateSIGKILL()
		}
		return context.Canceled
	})
	return nil
}

func verifyAuditInvariants(entries []ports.AuditEntry, liveOp security.OperationID, unknownOps map[security.OperationID]bool) error {
	authCount := make(map[security.OperationID]int)
	finCount := make(map[security.OperationID]int)
	finOutcome := make(map[security.OperationID]ports.AuditOutcome)
	// 仅对纯拒绝操作（未进入审批挑战或已获批准后重放）校验无 Authorized/Finalized；
	// 两步审批合法共用同一 OperationID：Challenge(Denied) -> Approved(Authorized+Finalized) -> Replay(Denied)。
	pureDeniedOps := make(map[security.OperationID]bool)
	for _, e := range entries {
		opID := e.OperationID()
		switch e.Phase() {
		case ports.AuditPhaseAuthorized:
			authCount[opID]++
		case ports.AuditPhaseFinalized:
			if authCount[opID] == 0 {
				return fmt.Errorf("检测到无头 Finalized 审计记录: op=%s", opID)
			}
			finCount[opID]++
			finOutcome[opID] = e.Outcome()
		case ports.AuditPhaseDenied:
			if e.Decision() == security.DecisionKindDeny && e.ErrorCode() == "policy_denied" {
				pureDeniedOps[opID] = true
			}
		default:
			return fmt.Errorf("检测到无效审计阶段: %v", e.Phase())
		}
	}
	return checkAuditMaps(authCount, finCount, finOutcome, pureDeniedOps, liveOp, unknownOps)
}

func checkAuditMaps(
	authCount, finCount map[security.OperationID]int,
	finOutcome map[security.OperationID]ports.AuditOutcome,
	deniedOps map[security.OperationID]bool,
	liveOp security.OperationID,
	unknownOps map[security.OperationID]bool,
) error {
	for opID, n := range authCount {
		if err := checkSingleAuthOp(opID, n, finCount[opID], finOutcome[opID], liveOp, unknownOps[opID]); err != nil {
			return err
		}
	}
	for opID := range deniedOps {
		if authCount[opID] != 0 || finCount[opID] != 0 {
			return fmt.Errorf("被拒操作 %s 不得出现 Authorized/Finalized 记录", opID)
		}
	}
	return nil
}

func checkSingleAuthOp(
	opID security.OperationID,
	authN, finN int,
	outcome ports.AuditOutcome,
	liveOp security.OperationID,
	isUnknown bool,
) error {
	if authN != 1 {
		return fmt.Errorf("操作 %s 存在重复 Authorized 记录: count=%d", opID, authN)
	}
	if opID.Equal(liveOp) {
		if finN != 0 {
			return fmt.Errorf("活跃对等进程操作 %s 被错误补写终态", opID)
		}
		return nil
	}
	if finN != 1 {
		return fmt.Errorf("操作 %s 终态计数违背零孤儿/零重复不变量: finCount=%d", opID, finN)
	}
	if isUnknown && outcome != ports.AuditOutcomeUnknown {
		return fmt.Errorf("OutcomeUnknown 操作 %s 被非法降级为 %s", opID, outcome)
	}
	return nil
}

// TestDST_GateStrictAgentCircuitBreaker 在并发在途授权与随机 ENOSPC 注入下验证 StrictAgentProfile
// 不可逆 Halted 熔断、OnHaltFunc 线性化单次触发、在途 Authorized 立即吊销与事后崩溃对账闭合。
func TestDST_GateStrictAgentCircuitBreaker(t *testing.T) {
	defer goleak.VerifyNone(t)
	fx := mustGateDSTFixture(t)
	seeds := resolveGateDSTSeeds(t, 0x20000)
	runSeedsParallel(t, seeds, func(seed uint64) error {
		return runGateCircuitBreakerSeed(fx, seed)
	})
}

func runGateCircuitBreakerSeed(fx gateDSTFixture, seed uint64) error {
	rng := sim.NewSeededRand(seed)
	clk := sim.NewSimClock(sim.DefaultBaseTime())
	cluster := sim.NewSimAuditCluster()
	sink, err := cluster.NewSinkFromEntropy(rng)
	if err != nil {
		return err
	}
	strictAgent := rng.IntN(4) != 0
	profile := gate.PolicyProfileStrictOperator
	if strictAgent {
		profile = gate.PolicyProfileStrictAgent
	}

	var haltCalls atomic.Int32
	g, err := gate.NewGate(gate.GateConfig{
		Profile:    profile,
		Policy:     fx.policy,
		AuditSink:  sink,
		Reconciler: cluster,
		Clock:      clk,
		Entropy:    rng,
		OnHalt: func(info gate.HaltInfo) {
			haltCalls.Add(1)
			_ = info.IsValid()
		},
	})
	if err != nil {
		return err
	}
	req, err := gate.NewGateRequest[security.CapExecute](gate.GateRequestSpec[security.CapExecute]{
		Binding: fx.bindExec,
		Risk:    security.RiskSafe,
	})
	if err != nil {
		return err
	}

	ctx := context.Background()
	peerEntered := make(chan struct{})
	triggerDone := make(chan struct{})
	var peerSawRevoked atomic.Bool

	_ = conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(wCtx context.Context) error {
			return gate.WithAuthorized(wCtx, g, req, func(_ context.Context, auth gate.Authorized[security.CapExecute]) error {
				close(peerEntered)
				<-triggerDone
				peerSawRevoked.Store(auth.IsRevoked() && !auth.IsValid())
				return nil
			})
		}); gErr != nil {
			return gErr
		}
		return n.Go(func(wCtx context.Context) error {
			<-peerEntered
			defer close(triggerDone)
			_ = gate.WithAuthorized(wCtx, g, req, func(_ context.Context, _ gate.Authorized[security.CapExecute]) error {
				cluster.SetENOSPC(true)
				return nil
			})
			return nil
		})
	})

	return verifyCircuitBreakerPostState(ctx, fx, g, sink, cluster, clk, strictAgent, haltCalls.Load(), peerSawRevoked.Load())
}

func verifyCircuitBreakerPostState(
	ctx context.Context,
	fx gateDSTFixture,
	g *gate.Gate,
	sink *sim.SimAuditSink,
	cluster *sim.SimAuditCluster,
	clk *sim.SimClock,
	strictAgent bool,
	haltCalls int32,
	peerSawRevoked bool,
) error {
	req, err := gate.NewGateRequest[security.CapExecute](gate.GateRequestSpec[security.CapExecute]{
		Binding: fx.bindExec,
		Risk:    security.RiskSafe,
	})
	if err != nil {
		return err
	}
	cluster.SetENOSPC(false)

	if strictAgent {
		if !g.IsHalted() || haltCalls != 1 || !peerSawRevoked {
			return fmt.Errorf("StrictAgent 熔断不变量违背: halted=%v haltCalls=%d peerRevoked=%v", g.IsHalted(), haltCalls, peerSawRevoked)
		}
		if nextErr := gate.WithAuthorized(ctx, g, req, func(context.Context, gate.Authorized[security.CapExecute]) error {
			return errors.New("Halted 态不得执行新请求")
		}); !errors.Is(nextErr, gate.ErrGateHalted) {
			return fmt.Errorf("Halted 后新请求期望 ErrGateHalted，实际=%w", nextErr)
		}
	} else {
		if g.IsHalted() || haltCalls != 0 {
			return fmt.Errorf("StrictOperator 不得因单次终态写失败永久熔断: halted=%v calls=%d", g.IsHalted(), haltCalls)
		}
		if nextErr := gate.WithAuthorized(ctx, g, req, func(context.Context, gate.Authorized[security.CapExecute]) error { return nil }); nextErr != nil {
			return fmt.Errorf("StrictOperator ENOSPC 恢复后新请求应恢复成功: %w", nextErr)
		}
	}

	sink.SimulateSIGKILL()
	clk.Advance(time.Second)
	if _, rErr := cluster.ReconcileCrashedAudits(ctx, clk.Now()); rErr != nil {
		return rErr
	}
	var noLiveOp security.OperationID
	return verifyAuditInvariants(cluster.Entries(), noLiveOp, nil)
}

// TestDST_GateDeterministicReplay 验证全量种子重复执行两遍产出逐位完全一致的审计摘要与统计快照。
func TestDST_GateDeterministicReplay(t *testing.T) {
	defer goleak.VerifyNone(t)
	fx := mustGateDSTFixture(t)
	seeds := resolveGateDSTSeeds(t, 0x18000)
	runSeedsParallel(t, seeds, func(seed uint64) error {
		d1, err := runDeterministicGateTranscript(fx, seed)
		if err != nil {
			return fmt.Errorf("run1: %w", err)
		}
		d2, err := runDeterministicGateTranscript(fx, seed)
		if err != nil {
			return fmt.Errorf("run2: %w", err)
		}
		if d1 != d2 {
			return fmt.Errorf("确定性复现失配: %x != %x", d1, d2)
		}
		return nil
	})
}

func runDeterministicGateTranscript(fx gateDSTFixture, seed uint64) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	rng := sim.NewSeededRand(seed)
	clk := sim.NewSimClock(sim.DefaultBaseTime())
	cluster := sim.NewSimAuditCluster()
	ctx := context.Background()

	unknownOps := make(map[security.OperationID]bool)
	if err := runCrashedProcessWorkload(ctx, fx, cluster, clk, rng, unknownOps); err != nil {
		return zero, err
	}
	clk.Advance(time.Second)
	rep, err := cluster.ReconcileCrashedAudits(ctx, clk.Now())
	if err != nil {
		return zero, err
	}
	var noLiveOp security.OperationID
	if err := verifyAuditInvariants(cluster.Entries(), noLiveOp, unknownOps); err != nil {
		return zero, err
	}
	auditDigest, err := cluster.Digest()
	if err != nil {
		return zero, err
	}
	h := sha256.New()
	_, _ = h.Write(auditDigest[:])
	var buf [16]byte
	binary.LittleEndian.PutUint64(buf[0:8], uint64(rep.DeadLocksClaimed()))
	binary.LittleEndian.PutUint64(buf[8:16], uint64(len(rep.AbortedOperations())))
	_, _ = h.Write(buf[:])
	var out [sha256.Size]byte
	h.Sum(out[:0])
	return out, nil
}
