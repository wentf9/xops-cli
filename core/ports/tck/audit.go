package tck

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/ports"
)

// AuditFixture 描述 AuditSink 与 AuditReconciler 契约测试夹具（ADR-008 / RFC §3.4）。
type AuditFixture struct {
	// NewAudit 返回共享同一底层审计日志与 ~/.xops/run 锁目录的 AuditSink 与 AuditReconciler。
	NewAudit func(t *testing.T) (ports.AuditSink, ports.AuditReconciler)
	// SimulateCrash 在不调用 Close/UnstageOperation 的前提下模拟另一已死亡进程残留 .lock 与未闭合操作，
	// 返回遗留未闭合的 OperationID（可选；提供时验证死亡锁抢占、补写 AbortedByCrash 与幂等性）。
	SimulateCrash func(t *testing.T) security.OperationID
	// SimulatePostDrainCrash 模拟「首次登记->闭合排空（触发 Truncate(0)+Seek(0,SeekStart)）->再次登记->突发崩溃」
	// 场景并返回第二次未闭合的 OperationID，用于专门回归验证锁文件截断归零偏移不变量（可选）。
	SimulatePostDrainCrash func(t *testing.T) security.OperationID
}

// RunAuditSuite 验证 AuditSink 只追加登记/闭合、无效入参拦截、O(1) 崩溃对账与并发登记契约。
func RunAuditSuite(t *testing.T, fx AuditFixture) {
	t.Helper()
	requireTrue(t, fx.NewAudit != nil, "AuditFixture.NewAudit 不能为 nil")

	t.Run("ValidationAndCleanLifecycle", func(t *testing.T) {
		ctx := context.Background()
		sink, rec := fx.NewAudit(t)
		procID := sink.ProcessInstanceID()
		requireTrue(t, procID.IsValid(), "ProcessInstanceID 必须有效")

		var nilCtx context.Context
		var zeroOp security.OperationID
		var zeroEntry ports.AuditEntry

		requireErrIs(t, sink.StageOperation(nilCtx, zeroOp), ports.ErrNilContext, "StageOperation(nil ctx)")
		requireErr(t, sink.StageOperation(ctx, zeroOp), "StageOperation(zero opID)")
		requireErrIs(t, sink.UnstageOperation(nilCtx, zeroOp), ports.ErrNilContext, "UnstageOperation(nil ctx)")
		requireErr(t, sink.UnstageOperation(ctx, zeroOp), "UnstageOperation(zero opID)")
		requireErrIs(t, sink.Record(nilCtx, zeroEntry), ports.ErrNilContext, "Record(nil ctx)")
		requireErr(t, sink.Record(ctx, zeroEntry), "Record(zero entry)")

		ent := NewDeterministicEntropy(33)
		traceID, err := security.NewTraceIDFrom(ent)
		requireNoErr(t, err, "NewTraceIDFrom")
		opID, err := security.NewOperationIDFrom(ent)
		requireNoErr(t, err, "NewOperationIDFrom")

		requireNoErr(t, sink.StageOperation(ctx, opID), "StageOperation")
		requireNoErr(t, sink.Record(ctx, MustAuditEntry(t, procID, traceID, opID, ports.AuditPhaseAuthorized, ports.AuditOutcomePending)), "Record(Authorized)")

		// 活跃进程持锁且存在在途操作期间执行对账，必须跳过活跃锁且零误判崩溃（ADR-008 / RFC §3.4）。
		if rec != nil {
			liveRep, lErr := rec.ReconcileCrashedAudits(ctx, BaseTime().Add(30*time.Second))
			requireNoErr(t, lErr, "Reconcile(while live)")
			requireTrue(t, liveRep.IsValid() && liveRep.LiveLocksSkipped() >= 1 && liveRep.DeadLocksClaimed() == 0 && len(liveRep.AbortedOperations()) == 0, "活跃锁对账必须跳过活跃进程且零补写")
		}

		requireNoErr(t, sink.Record(ctx, MustAuditEntry(t, procID, traceID, opID, ports.AuditPhaseFinalized, ports.AuditOutcomeSucceeded)), "Record(Finalized)")
		requireNoErr(t, sink.UnstageOperation(ctx, opID), "UnstageOperation")

		// 验证排空归零（Truncate(0)+Seek(0)）后的二次登记与闭合不会受损。
		opID2, err := security.NewOperationIDFrom(ent)
		requireNoErr(t, err, "NewOperationIDFrom(op2)")
		requireNoErr(t, sink.StageOperation(ctx, opID2), "StageOperation(post-drain)")
		requireNoErr(t, sink.Record(ctx, MustAuditEntry(t, procID, traceID, opID2, ports.AuditPhaseAuthorized, ports.AuditOutcomePending)), "Record(post-drain Authorized)")
		requireNoErr(t, sink.Record(ctx, MustAuditEntry(t, procID, traceID, opID2, ports.AuditPhaseFinalized, ports.AuditOutcomeSucceeded)), "Record(post-drain Finalized)")
		requireNoErr(t, sink.UnstageOperation(ctx, opID2), "UnstageOperation(post-drain)")

		requireNoErr(t, sink.Close(), "AuditSink.Close(1)")
		requireNoErr(t, sink.Close(), "AuditSink.Close(2, idempotent)")

		// 关闭后禁止再登记或落盘审计记录。
		requireErrIs(t, sink.StageOperation(ctx, opID), ports.ErrClosed, "Close 后 StageOperation 须返回 ErrClosed")
		requireErrIs(t, sink.Record(ctx, MustAuditEntry(t, procID, traceID, opID, ports.AuditPhaseFinalized, ports.AuditOutcomeUnknown)), ports.ErrClosed, "Close 后 Record 须返回 ErrClosed")

		if rec != nil {
			_, rErr := rec.ReconcileCrashedAudits(nilCtx, BaseTime())
			requireErrIs(t, rErr, ports.ErrNilContext, "Reconcile(nil ctx)")
			_, rErr = rec.ReconcileCrashedAudits(ctx, time.Time{})
			requireErr(t, rErr, "Reconcile(zero now)")

			report, rErr := rec.ReconcileCrashedAudits(ctx, BaseTime().Add(time.Minute))
			requireNoErr(t, rErr, "Reconcile(clean)")
			requireTrue(t, report.IsValid() && report.DeadLocksClaimed() == 0 && len(report.AbortedOperations()) == 0, "干净关闭后对账不得报告崩溃遗留操作")
		}
	})

	t.Run("ConcurrentStageUnstage", func(t *testing.T) {
		verifyConcurrentAuditStage(t, fx.NewAudit)
	})

	if fx.SimulateCrash != nil {
		t.Run("CrashReconcileAndIdempotency", func(t *testing.T) {
			verifyCrashReconcileIdempotent(t, fx.NewAudit, fx.SimulateCrash)
		})
	}
	if fx.SimulatePostDrainCrash != nil {
		t.Run("PostDrainRestageCrashReconcile", func(t *testing.T) {
			verifyCrashReconcileIdempotent(t, fx.NewAudit, fx.SimulatePostDrainCrash)
		})
	}
}

func verifyConcurrentAuditStage(t *testing.T, newAudit func(t *testing.T) (ports.AuditSink, ports.AuditReconciler)) {
	t.Helper()
	defer VerifyNoLeaks(t)
	ctx := context.Background()
	sink, _ := newAudit(t)
	defer func() { _ = sink.Close() }()

	ent := NewDeterministicEntropy(55)
	ops := make([]security.OperationID, 8)
	for i := range ops {
		var err error
		ops[i], err = security.NewOperationIDFrom(ent)
		requireNoErr(t, err, "NewOperationIDFrom")
	}

	err := conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		for _, op := range ops {
			if gErr := n.Go(func(c context.Context) error {
				if sErr := sink.StageOperation(c, op); sErr != nil {
					return sErr
				}
				return sink.UnstageOperation(c, op)
			}); gErr != nil {
				return gErr
			}
		}
		return nil
	})
	requireNoErr(t, err, "并发 Stage/Unstage")
}

func verifyCrashReconcileIdempotent(t *testing.T, newAudit func(t *testing.T) (ports.AuditSink, ports.AuditReconciler), simulate func(t *testing.T) security.OperationID) {
	t.Helper()
	ctx := context.Background()
	sink, rec := newAudit(t)
	requireTrue(t, rec != nil, "提供崩溃模拟钩子时 NewAudit 必须返回非 nil AuditReconciler")
	defer func() { _ = sink.Close() }()

	abortedOp := simulate(t)
	requireTrue(t, abortedOp.IsValid(), "崩溃模拟必须返回有效 OperationID")

	first, err := rec.ReconcileCrashedAudits(ctx, BaseTime().Add(2*time.Minute))
	requireNoErr(t, err, "Reconcile(first)")
	requireTrue(t, first.IsValid() && first.DeadLocksClaimed() >= 1, "首次对账必须抢占至少 1 个死亡进程锁")
	requireTrue(t, slices.ContainsFunc(first.AbortedOperations(), abortedOp.Equal), "首次对账报告必须包含崩溃遗留 OperationID")

	second, err := rec.ReconcileCrashedAudits(ctx, BaseTime().Add(3*time.Minute))
	requireNoErr(t, err, "Reconcile(second, idempotent)")
	requireTrue(t, second.IsValid() && second.DeadLocksClaimed() == 0 && len(second.AbortedOperations()) == 0, "二次对账必须幂等且零重复补写")
}
