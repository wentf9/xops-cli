package audit_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
	"github.com/wentf9/xops-cli/internal/host/audit"
	"go.uber.org/goleak"
)

// TestDrainThenCompactUnderOverlappingConcurrency 验证长驻进程只追加行数达到 MaxLockLogLines 时：
//   - 在仍有在途操作期间绝不执行 Truncate(0)，新 StageOperation 暂停等待排空且响应 ctx 取消；
//   - 全部既有在途操作 Unstage 归零瞬间精确执行一次 Truncate(0)+Seek(0)，并自动唤醒等待的新准入操作。
func TestDrainThenCompactUnderOverlappingConcurrency(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	_, rootDir := newPrivateAuditRoot(t)
	fsPort := osfs.NewScopedRootFS()
	ent := tck.NewDeterministicEntropy(123)
	procID, _ := ports.NewProcessInstanceIDFrom(ent)

	sink, err := audit.NewFileSink(audit.SinkSpec{
		ScopedFS:        fsPort,
		RootDir:         rootDir,
		ProcessID:       procID,
		MaxLockLogLines: 4,
	})
	if err != nil {
		t.Fatalf("NewFileSink(MaxLockLogLines=4) 失败: %v", err)
	}
	defer func() { _ = sink.Close() }()

	op1, _ := security.NewOperationIDFrom(ent)
	op2, _ := security.NewOperationIDFrom(ent)
	op3, _ := security.NewOperationIDFrom(ent)
	op4, _ := security.NewOperationIDFrom(ent)
	opCanceled, _ := security.NewOperationIDFrom(ent)

	// 制造 4 条只追加记录 (+op1, +op2, -op1, +op3)，活跃集为 {op2, op3} 且未归零。
	for _, fn := range []func() error{
		func() error { return sink.StageOperation(ctx, op1) },
		func() error { return sink.StageOperation(ctx, op2) },
		func() error { return sink.UnstageOperation(ctx, op1) },
		func() error { return sink.StageOperation(ctx, op3) },
	} {
		if stepErr := fn(); stepErr != nil {
			t.Fatalf("准备重叠操作失败: %v", stepErr)
		}
	}
	if sink.LockTruncations() != 0 {
		t.Fatalf("活跃集非空时严禁 Truncate(0): truncations=%d", sink.LockTruncations())
	}

	// 在排空门控下发起 op4（将被暂停直至 op2/op3 排空），同时验证带取消 ctx 的准入立即返回错误。
	if err := runOverlappingDrainPhase(ctx, sink, op2, op3, op4, opCanceled); err != nil {
		t.Fatalf("排空压缩并发校验失败: %v", err)
	}
	if sink.LockTruncations() != 2 {
		t.Fatalf("期望排空触发第 1 次截断、op4 闭合触发第 2 次截断，实际=%d", sink.LockTruncations())
	}
}

func runOverlappingDrainPhase(
	ctx context.Context, sink *audit.FileSink,
	op2, op3, op4, opCanceled security.OperationID,
) error {
	op4Entered := make(chan struct{})
	op4Done := make(chan error, 1)
	return conc.RunWait(ctx, func(runCtx context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(c context.Context) error {
			close(op4Entered)
			op4Done <- sink.StageOperation(c, op4)
			return nil
		}); gErr != nil {
			return gErr
		}
		<-op4Entered
		if err := assertDrainCancelAndUnstage(runCtx, sink, op2, op3, opCanceled); err != nil {
			return err
		}
		if err4 := <-op4Done; err4 != nil {
			return err4
		}
		return sink.UnstageOperation(runCtx, op4)
	})
}

func assertDrainCancelAndUnstage(
	runCtx context.Context, sink *audit.FileSink,
	op2, op3, opCanceled security.OperationID,
) error {
	// 带超时取消的准入须触发排空暂停并在取消时立即返回 DeadlineExceeded，绝不挂起。
	cancelCtx, cancel := context.WithTimeout(runCtx, 20*time.Millisecond)
	defer cancel()
	if cErr := sink.StageOperation(cancelCtx, opCanceled); !errors.Is(cErr, context.DeadlineExceeded) {
		return errors.New("排空期间超时准入未返回 DeadlineExceeded")
	}
	if sink.LockTruncations() != 0 {
		return errors.New("op2/op3 未排空前意外触发了 Truncate")
	}
	if uErr := sink.UnstageOperation(runCtx, op2); uErr != nil {
		return uErr
	}
	if sink.LockTruncations() != 0 {
		return errors.New("op3 仍在途时意外触发了 Truncate")
	}
	return sink.UnstageOperation(runCtx, op3)
}

// TestCrashBoundaryPrecisionAndCorruptAuditFailClosed 验证：
//   - 在 Stage 之后、Record(Authorized) 之前崩溃：零无头 AbortedByCrash；
//   - 在 Record(Finalized) 之后、Unstage 之前崩溃：零重复 AbortedByCrash；
//   - audit.jsonl 含损坏 JSON 行时慢路径严格失败关闭返回 ErrCorruptAuditLog；
//   - 存在未对账非空 .lock 时拒绝复用同一 ProcessInstanceID 静默截断。
func TestCrashBoundaryPrecisionAndCorruptAuditFailClosed(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	dir, rootDir := newPrivateAuditRoot(t)
	fsPort := osfs.NewScopedRootFS()
	ent := tck.NewDeterministicEntropy(151)

	setupHeadlessAndFinalizedCrashLocks(t, ctx, fsPort, rootDir, ent)
	rec, err := audit.NewFileReconciler(audit.ReconcilerSpec{ScopedFS: fsPort, RootDir: rootDir})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := rec.ReconcileCrashedAudits(ctx, tck.BaseTime().Add(time.Minute))
	if err != nil {
		t.Fatalf("ReconcileCrashedAudits 失败: %v", err)
	}
	if rep.DeadLocksClaimed() != 2 || len(rep.AbortedOperations()) != 0 {
		t.Fatalf("边界崩溃对账期望 dead=2, aborted=0，实际 dead=%d aborted=%v", rep.DeadLocksClaimed(), rep.AbortedOperations())
	}
	verifyCorruptAuditLogFailClosed(t, ctx, dir, fsPort, rootDir, ent, rec)
}

func setupHeadlessAndFinalizedCrashLocks(t *testing.T, ctx context.Context, fsPort ports.ScopedRootFS, rootDir pathalg.LocalDir, ent *tck.DeterministicEntropy) {
	t.Helper()
	// 1. Stage 后未写 Authorized 即脏关闭 -> 对账应认领死锁但零补写无头 AbortedByCrash。
	procHeadless, _ := ports.NewProcessInstanceIDFrom(ent)
	opHeadless, _ := security.NewOperationIDFrom(ent)
	mustStageAndDirtyClose(t, ctx, fsPort, rootDir, procHeadless, opHeadless)

	// 验证未对账的非空 .lock 禁止被同 ProcessInstanceID 静默截断覆写。
	if _, err := audit.NewFileSink(audit.SinkSpec{ScopedFS: fsPort, RootDir: rootDir, ProcessID: procHeadless}); !errors.Is(err, ports.ErrAlreadyExists) {
		t.Fatalf("复用未对账非空 .lock 期望返回 ErrAlreadyExists, 实际=%v", err)
	}

	// 2. 已写 Authorized + Finalized 但未 Unstage 即脏关闭 -> 对账零重复补写。
	procFinalized, _ := ports.NewProcessInstanceIDFrom(ent)
	traceID, _ := security.NewTraceIDFrom(ent)
	opFinalized, _ := security.NewOperationIDFrom(ent)
	sink2, err := audit.NewFileSink(audit.SinkSpec{ScopedFS: fsPort, RootDir: rootDir, ProcessID: procFinalized})
	if err != nil {
		t.Fatal(err)
	}
	if err := sink2.StageOperation(ctx, opFinalized); err != nil {
		t.Fatal(err)
	}
	if err := sink2.Record(ctx, tck.MustAuditEntry(t, procFinalized, traceID, opFinalized, ports.AuditPhaseAuthorized, ports.AuditOutcomePending)); err != nil {
		t.Fatal(err)
	}
	if err := sink2.Record(ctx, tck.MustAuditEntry(t, procFinalized, traceID, opFinalized, ports.AuditPhaseFinalized, ports.AuditOutcomeSucceeded)); err != nil {
		t.Fatal(err)
	}
	if err := sink2.Close(); err != nil {
		t.Fatal(err)
	}
}

func mustStageAndDirtyClose(t *testing.T, ctx context.Context, fsPort ports.ScopedRootFS, rootDir pathalg.LocalDir, pid ports.ProcessInstanceID, op security.OperationID) {
	t.Helper()
	s, err := audit.NewFileSink(audit.SinkSpec{ScopedFS: fsPort, RootDir: rootDir, ProcessID: pid})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.StageOperation(ctx, op); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func verifyCorruptAuditLogFailClosed(t *testing.T, ctx context.Context, dir string, fsPort ports.ScopedRootFS, rootDir pathalg.LocalDir, ent *tck.DeterministicEntropy, rec *audit.FileReconciler) {
	t.Helper()
	procCorrupt, _ := ports.NewProcessInstanceIDFrom(ent)
	opCorrupt, _ := security.NewOperationIDFrom(ent)
	mustStageAndDirtyClose(t, ctx, fsPort, rootDir, procCorrupt, opCorrupt)
	auditPath := filepath.Join(dir, "audit.jsonl")
	rawAudit, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(auditPath, append(rawAudit, []byte("{corrupt-json-line\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := rec.ReconcileCrashedAudits(ctx, tck.BaseTime().Add(2*time.Minute)); !errors.Is(err, audit.ErrCorruptAuditLog) {
		t.Fatalf("损坏 audit.jsonl 对账返回 %v, 期望 ErrCorruptAuditLog", err)
	}
}

// TestMultiTerminalConcurrentReconciliationStress 验证多终端并发场景：
// 2 个真实活跃子进程锁 + 3 个真实已崩溃子进程锁，由 3 个并发 FileReconciler 同时对账，
// 确保所有活跃锁被跳过且 3 条崩溃操作恰好各补写 1 次 AbortedByCrash、所有死锁文件完全清理。
func TestMultiTerminalConcurrentReconciliationStress(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	dir, rootDir := newPrivateAuditRoot(t)
	fsPort := osfs.NewScopedRootFS()
	ent := tck.NewDeterministicEntropy(181)

	livePID1, _ := ports.NewProcessInstanceIDFrom(ent)
	liveOp1, _ := security.NewOperationIDFrom(ent)
	stop1 := startLiveHolderChild(t, dir, livePID1, liveOp1)
	defer stop1()

	livePID2, _ := ports.NewProcessInstanceIDFrom(ent)
	liveOp2, _ := security.NewOperationIDFrom(ent)
	stop2 := startLiveHolderChild(t, dir, livePID2, liveOp2)
	defer stop2()

	type deadCase struct {
		pid ports.ProcessInstanceID
		op  security.OperationID
	}
	var deadCases [3]deadCase
	var zeroOp security.OperationID
	for i := range deadCases {
		deadCases[i].pid, _ = ports.NewProcessInstanceIDFrom(ent)
		deadCases[i].op, _ = security.NewOperationIDFrom(ent)
		spawnCrashChild(t, dir, "crash", deadCases[i].pid, deadCases[i].op, zeroOp)
	}

	reps := runConcurrentReconcilers(t, ctx, fsPort, rootDir, 3)
	var allAborted []security.OperationID
	for _, r := range reps {
		if r.LiveLocksSkipped() < 2 {
			t.Fatalf("每个对账实例均须跳过 2 个活跃终端锁，实际 skipped=%d", r.LiveLocksSkipped())
		}
		allAborted = append(allAborted, r.AbortedOperations()...)
	}
	if len(allAborted) != len(deadCases) {
		t.Fatalf("总补写操作数 = %d, 期望恰好 %d: %v", len(allAborted), len(deadCases), allAborted)
	}
	for _, dc := range deadCases {
		if !slices.ContainsFunc(allAborted, dc.op.Equal) {
			t.Fatalf("缺失崩溃操作 %s 的补写记录", dc.op)
		}
		verifyAbortedLineCount(t, filepath.Join(dir, "audit.jsonl"), dc.pid, dc.op, 1)
		deadLock := filepath.Join(dir, "run", dc.pid.String()+".lock")
		if _, statErr := os.Stat(deadLock); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("死亡锁文件 %s 未清理: statErr=%v", deadLock, statErr)
		}
	}
}

func runConcurrentReconcilers(t *testing.T, ctx context.Context, fsPort ports.ScopedRootFS, rootDir pathalg.LocalDir, count int) []ports.CrashReconcileReport {
	t.Helper()
	reps := make([]ports.CrashReconcileReport, count)
	err := conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		for idx := range reps {
			rec, rErr := audit.NewFileReconciler(audit.ReconcilerSpec{ScopedFS: fsPort, RootDir: rootDir})
			if rErr != nil {
				return rErr
			}
			if gErr := n.Go(func(c context.Context) error {
				var err error
				reps[idx], err = rec.ReconcileCrashedAudits(c, tck.BaseTime().Add(3*time.Minute))
				return err
			}); gErr != nil {
				return gErr
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("多终端并发对账失败: %v", err)
	}
	return reps
}
