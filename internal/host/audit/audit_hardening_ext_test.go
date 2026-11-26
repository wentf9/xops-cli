package audit_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
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

// TestPartialLockWriteRollbackAndNestedAuditFile 验证 #35 Major #5、#34 Minor #4 与 #51 Major #1 / Minor #1：
//   - .lock 部分写入或刷盘失败时按 confirmedOffset 回滚，或回滚失败后以 Seek(0, io.SeekEnd) 重锚偏移；
//   - 三步回归：op1 写/刷盘失败且回滚失败 -> op2 成功并 Authorized -> op3 失败且回滚成功 -> 脏关闭对账完整恢复 op2；
//   - 排空压缩 Truncate(0) 成功后 Seek(0) 失败绝不将文件零扩展回旧偏移；
//   - 嵌套自定义 AuditFile（logs/nested/audit.jsonl）自动建父目录，且多段 RunDir / AuditFile 悬空符号链接祖先失败关闭。
func TestPartialLockWriteRollbackAndNestedAuditFile(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	t.Run("PartialWriteRollbackRestoresFrameBoundary", func(t *testing.T) {
		verifyPartialLockWriteRecovery(t, ctx, false)
	})
	t.Run("ThreeStepReanchorAfterPartialWriteRollbackFailure", func(t *testing.T) {
		verifyThreeStepLockReanchorRecovery(t, ctx, false)
	})
	t.Run("ThreeStepReanchorAfterSyncAndRollbackFailure", func(t *testing.T) {
		verifyThreeStepLockReanchorRecovery(t, ctx, true)
	})
	t.Run("DrainCompactSeekFailureNeverZeroExtends", func(t *testing.T) {
		verifyDrainCompactSeekFailureNeverZeroExtends(t, ctx)
	})
	t.Run("CustomNestedAuditFileCreatesParentDir", func(t *testing.T) {
		verifyCustomNestedAuditFile(t, ctx)
	})
	t.Run("NestedAuditAndRunDirAncestorSymlinkFailsClosed", func(t *testing.T) {
		verifyNestedAncestorSymlinkFailsClosed(t, ctx)
	})
}

func verifyPartialLockWriteRecovery(t *testing.T, ctx context.Context, failRollback bool) {
	t.Helper()
	_, rootDir := newPrivateAuditRoot(t)
	ent := tck.NewDeterministicEntropy(201)
	procID, _ := ports.NewProcessInstanceIDFrom(ent)
	traceID, _ := security.NewTraceIDFrom(ent)
	op1, _ := security.NewOperationIDFrom(ent)
	op2, _ := security.NewOperationIDFrom(ent)

	memFS := newPartialFaultAuditFS(failRollback)
	sink, err := audit.NewFileSink(audit.SinkSpec{ScopedFS: memFS, RootDir: rootDir, ProcessID: procID})
	if err != nil {
		t.Fatalf("NewFileSink 失败: %v", err)
	}
	if err := sink.StageOperation(ctx, op1); !errors.Is(err, ports.ErrAuditWriteFailed) {
		t.Fatalf("半行写入故障期望 ErrAuditWriteFailed, 实际=%v", err)
	}
	if err := sink.StageOperation(ctx, op2); err != nil {
		t.Fatalf("故障恢复后 op2 StageOperation 失败: %v", err)
	}
	if err := sink.Record(ctx, tck.MustAuditEntry(t, procID, traceID, op2, ports.AuditPhaseAuthorized, ports.AuditOutcomePending)); err != nil {
		t.Fatalf("op2 Record(Authorized) 失败: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("脏 Close 失败: %v", err)
	}
	assertReconciledSingleOp(t, ctx, memFS, rootDir, op2)
}

func verifyThreeStepLockReanchorRecovery(t *testing.T, ctx context.Context, failViaSync bool) {
	t.Helper()
	_, rootDir := newPrivateAuditRoot(t)
	ent := tck.NewDeterministicEntropy(205)
	procID, _ := ports.NewProcessInstanceIDFrom(ent)
	traceID, _ := security.NewTraceIDFrom(ent)
	op1, _ := security.NewOperationIDFrom(ent)
	op2, _ := security.NewOperationIDFrom(ent)
	op3, _ := security.NewOperationIDFrom(ent)

	memFS := newPartialFaultAuditFS(false)
	memFS.armOp1Fault(failViaSync)
	sink, err := audit.NewFileSink(audit.SinkSpec{ScopedFS: memFS, RootDir: rootDir, ProcessID: procID})
	if err != nil {
		t.Fatalf("NewFileSink 失败: %v", err)
	}
	// Step 1: op1 写入/刷盘失败且回滚 Truncate 失败（磁盘留有半行或未刷盘完整行，offsetKnown=false）。
	if err := sink.StageOperation(ctx, op1); !errors.Is(err, ports.ErrAuditWriteFailed) {
		t.Fatalf("Step 1 op1 期望 ErrAuditWriteFailed, 实际=%v", err)
	}
	// Step 2: op2 成功重锚真实 EOF 并落盘 +<op2>\n，随后写入 Authorized 审计记录。
	if err := sink.StageOperation(ctx, op2); err != nil {
		t.Fatalf("Step 2 op2 StageOperation 失败: %v", err)
	}
	if err := sink.Record(ctx, tck.MustAuditEntry(t, procID, traceID, op2, ports.AuditPhaseAuthorized, ports.AuditOutcomePending)); err != nil {
		t.Fatalf("Step 2 op2 Record(Authorized) 失败: %v", err)
	}
	// Step 3: op3 半行写入失败且回滚 Truncate 成功——必须仅截断 op3 残留，绝不截断已确认的 op2！
	memFS.armNextWriteFail()
	if err := sink.StageOperation(ctx, op3); !errors.Is(err, ports.ErrAuditWriteFailed) {
		t.Fatalf("Step 3 op3 期望 ErrAuditWriteFailed, 实际=%v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("脏 Close 失败: %v", err)
	}
	assertReconciledSingleOp(t, ctx, memFS, rootDir, op2)
}

func verifyDrainCompactSeekFailureNeverZeroExtends(t *testing.T, ctx context.Context) {
	t.Helper()
	_, rootDir := newPrivateAuditRoot(t)
	ent := tck.NewDeterministicEntropy(207)
	procID, _ := ports.NewProcessInstanceIDFrom(ent)
	traceID, _ := security.NewTraceIDFrom(ent)
	op1, _ := security.NewOperationIDFrom(ent)
	op2, _ := security.NewOperationIDFrom(ent)

	memFS := newPartialFaultAuditFS(false)
	memFS.clearFaults()
	sink, err := audit.NewFileSink(audit.SinkSpec{ScopedFS: memFS, RootDir: rootDir, ProcessID: procID})
	if err != nil {
		t.Fatalf("NewFileSink 失败: %v", err)
	}
	if err := sink.StageOperation(ctx, op1); err != nil {
		t.Fatalf("op1 Stage 失败: %v", err)
	}
	// 在 Unstage 触发排空截断时，让 Truncate(0) 成功但随后的 Seek(0) 失败。
	memFS.armNextSeekStartFail()
	if err := sink.UnstageOperation(ctx, op1); !errors.Is(err, ports.ErrAuditWriteFailed) {
		t.Fatalf("排空 Seek(0) 失败期望 ErrAuditWriteFailed, 实际=%v", err)
	}
	lockKey := "run/" + procID.String() + ".lock"
	if gotLen := memFS.fileLen(lockKey); gotLen != 0 {
		t.Fatalf("Truncate(0) 成功后 Seek(0) 失败不得零扩展锁文件: gotLen=%d", gotLen)
	}
	// 后续 op2 应通过 Seek(0, io.SeekEnd) 锚定到 0 并正常落盘 +<op2>\n。
	if err := sink.StageOperation(ctx, op2); err != nil {
		t.Fatalf("排空故障恢复后 op2 Stage 失败: %v", err)
	}
	if err := sink.Record(ctx, tck.MustAuditEntry(t, procID, traceID, op2, ports.AuditPhaseAuthorized, ports.AuditOutcomePending)); err != nil {
		t.Fatalf("op2 Record(Authorized) 失败: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("脏 Close 失败: %v", err)
	}
	assertReconciledSingleOp(t, ctx, memFS, rootDir, op2)
}

func assertReconciledSingleOp(t *testing.T, ctx context.Context, fsPort ports.ScopedRootFS, rootDir pathalg.LocalDir, want security.OperationID) {
	t.Helper()
	rec, err := audit.NewFileReconciler(audit.ReconcilerSpec{ScopedFS: fsPort, RootDir: rootDir})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := rec.ReconcileCrashedAudits(ctx, tck.BaseTime().Add(time.Minute))
	if err != nil {
		t.Fatalf("ReconcileCrashedAudits 失败: %v", err)
	}
	if rep.DeadLocksClaimed() != 1 || len(rep.AbortedOperations()) != 1 || !rep.AbortedOperations()[0].Equal(want) {
		t.Fatalf("对账结果异常: dead=%d aborted=%v want=%s", rep.DeadLocksClaimed(), rep.AbortedOperations(), want)
	}
}

func verifyNestedAncestorSymlinkFailsClosed(t *testing.T, ctx context.Context) {
	t.Helper()
	dir, rootDir := newPrivateAuditRoot(t)
	fsPort := osfs.NewScopedRootFS()
	if err := fsPort.EnsureRoot(rootDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing_logs_target", filepath.Join(dir, "logs")); err != nil {
		t.Skipf("环境不支持创建符号链接: %v", err)
	}
	// 先写入一个死亡进程锁，触发慢路径检查 logs/nested/audit.jsonl 的祖先目录链。
	ent := tck.NewDeterministicEntropy(223)
	procID, _ := ports.NewProcessInstanceIDFrom(ent)
	opID, _ := security.NewOperationIDFrom(ent)
	if err := os.MkdirAll(filepath.Join(dir, "run"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run", procID.String()+".lock"), []byte("+"+opID.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	nestedAudit, err := pathalg.ParseLocalRootedDest("logs/nested/audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := audit.NewFileReconciler(audit.ReconcilerSpec{
		ScopedFS:  fsPort,
		RootDir:   rootDir,
		AuditFile: algebraic.Some(nestedAudit),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rec.ReconcileCrashedAudits(ctx, tck.BaseTime().Add(time.Minute)); !errors.Is(err, ports.ErrSymlinkRejected) {
		t.Fatalf("多段 AuditFile 悬空符号链接祖先期望 ErrSymlinkRejected, 实际=%v", err)
	}
	// 同时校验多段 RunDir（var/run）的悬空符号链接祖先亦失败关闭。
	if err := os.Symlink("missing_var_target", filepath.Join(dir, "var")); err != nil {
		t.Fatal(err)
	}
	nestedRun, err := pathalg.ParseLocalRootedDest("var/run")
	if err != nil {
		t.Fatal(err)
	}
	recRun, err := audit.NewFileReconciler(audit.ReconcilerSpec{
		ScopedFS: fsPort,
		RootDir:  rootDir,
		RunDir:   algebraic.Some(nestedRun),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recRun.ReconcileCrashedAudits(ctx, tck.BaseTime().Add(time.Minute)); !errors.Is(err, ports.ErrSymlinkRejected) {
		t.Fatalf("多段 RunDir 悬空符号链接祖先期望 ErrSymlinkRejected, 实际=%v", err)
	}
}

func verifyCustomNestedAuditFile(t *testing.T, ctx context.Context) {
	t.Helper()
	_, rootDir := newPrivateAuditRoot(t)
	fsPort := osfs.NewScopedRootFS()
	nestedAudit, err := pathalg.ParseLocalRootedDest("logs/nested/audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	ent := tck.NewDeterministicEntropy(219)
	procID, _ := ports.NewProcessInstanceIDFrom(ent)
	traceID, _ := security.NewTraceIDFrom(ent)
	opID, _ := security.NewOperationIDFrom(ent)

	sink, err := audit.NewFileSink(audit.SinkSpec{
		ScopedFS:  fsPort,
		RootDir:   rootDir,
		AuditFile: algebraic.Some(nestedAudit),
		ProcessID: procID,
	})
	if err != nil {
		t.Fatalf("嵌套 AuditFile NewFileSink 失败: %v", err)
	}
	if err := sink.StageOperation(ctx, opID); err != nil {
		t.Fatal(err)
	}
	if err := sink.Record(ctx, tck.MustAuditEntry(t, procID, traceID, opID, ports.AuditPhaseAuthorized, ports.AuditOutcomePending)); err != nil {
		t.Fatalf("嵌套 AuditFile Record 失败: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	rec, err := audit.NewFileReconciler(audit.ReconcilerSpec{
		ScopedFS:  fsPort,
		RootDir:   rootDir,
		AuditFile: algebraic.Some(nestedAudit),
	})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := rec.ReconcileCrashedAudits(ctx, tck.BaseTime().Add(time.Minute))
	if err != nil || len(rep.AbortedOperations()) != 1 || !rep.AbortedOperations()[0].Equal(opID) {
		t.Fatalf("嵌套 AuditFile 对账异常: rep=%v err=%v", rep, err)
	}
}

// partialFaultAuditFS 是测试专用的纯内存 ScopedRootFS，用于确定性注入 .lock 半行写/刷盘/回滚/Seek 故障。
type partialFaultAuditFS struct {
	mu                sync.Mutex
	files             map[string][]byte
	failNextWrite     bool
	failNextSync      bool
	failNextTruncate  bool
	failNextSeekStart bool
}

func newPartialFaultAuditFS(failRollback bool) *partialFaultAuditFS {
	return &partialFaultAuditFS{
		files:            make(map[string][]byte),
		failNextWrite:    true,
		failNextTruncate: failRollback,
	}
}

func (f *partialFaultAuditFS) clearFaults() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failNextWrite = false
	f.failNextSync = false
	f.failNextTruncate = false
	f.failNextSeekStart = false
}

func (f *partialFaultAuditFS) armOp1Fault(failViaSync bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failNextWrite = !failViaSync
	f.failNextSync = failViaSync
	f.failNextTruncate = true
	f.failNextSeekStart = false
}

func (f *partialFaultAuditFS) armNextWriteFail() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failNextWrite = true
}

func (f *partialFaultAuditFS) armNextSeekStartFail() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failNextSeekStart = true
}

func (f *partialFaultAuditFS) fileLen(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.files[key])
}

func (f *partialFaultAuditFS) EnsureRoot(pathalg.LocalDir, fs.FileMode) error { return nil }

//xops:syncclosure
//xops:borrowed
func (f *partialFaultAuditFS) WithRoot(_ pathalg.LocalDir, fn func(root ports.RootHandle) error) error {
	return fn(&partialFaultRoot{fs: f})
}

type partialFaultRoot struct{ fs *partialFaultAuditFS }

func (r *partialFaultRoot) ReadAllBounded(dest pathalg.LocalRootedDest, _ ports.ReadLimits) ([]byte, error) {
	r.fs.mu.Lock()
	defer r.fs.mu.Unlock()
	b, ok := r.fs.files[dest.String()]
	if !ok {
		return nil, ports.ErrNotFound
	}
	return bytes.Clone(b), nil
}

//xops:syncclosure
//xops:borrowed
func (r *partialFaultRoot) WithReadRegular(pathalg.LocalRootedDest, ports.ReadLimits, func(ports.BoundedReadHandle, int64) error) error {
	return ports.ErrUnsupported
}

//xops:syncclosure
//xops:borrowed
func (r *partialFaultRoot) CreateExclusive(pathalg.LocalRootedDest, fs.FileMode, func(io.Writer) error) error {
	return ports.ErrUnsupported
}

//xops:syncclosure
//xops:borrowed
func (r *partialFaultRoot) AtomicReplace(pathalg.LocalRootedDest, fs.FileMode, func(io.Writer) error) error {
	return ports.ErrUnsupported
}

func (r *partialFaultRoot) WriteChunk(pathalg.LocalRootedDest, int64, io.Reader, int64, fs.FileMode) (int64, error) {
	return 0, ports.ErrUnsupported
}
func (r *partialFaultRoot) Rename(pathalg.LocalRootedDest, pathalg.LocalRootedDest) error {
	return ports.ErrUnsupported
}

func (r *partialFaultRoot) openLockedFile(dest pathalg.LocalRootedDest, create bool) (*partialFaultLockedFile, bool, error) {
	r.fs.mu.Lock()
	defer r.fs.mu.Unlock()
	key := dest.String()
	if _, ok := r.fs.files[key]; !ok {
		if !create {
			return nil, false, ports.ErrNotFound
		}
		r.fs.files[key] = nil
	}
	return &partialFaultLockedFile{fs: r.fs, key: key}, true, nil
}

//xops:syncclosure
//xops:borrowed
func (r *partialFaultRoot) WithLockedFile(_ context.Context, dest pathalg.LocalRootedDest, _ ports.LockMode, create bool, _ fs.FileMode, fn func(ports.LockedFile) error) error {
	lf, _, err := r.openLockedFile(dest, create)
	if err != nil {
		return err
	}
	return fn(lf)
}

//xops:syncclosure
//xops:borrowed
func (r *partialFaultRoot) TryWithLockedFile(dest pathalg.LocalRootedDest, _ ports.LockMode, create bool, _ fs.FileMode, fn func(ports.LockedFile) error) (bool, error) {
	lf, ok, err := r.openLockedFile(dest, create)
	if err != nil {
		return ok, err
	}
	return true, fn(lf)
}

func (r *partialFaultRoot) AppendLine(dest pathalg.LocalRootedDest, _ fs.FileMode, line []byte) error {
	r.fs.mu.Lock()
	defer r.fs.mu.Unlock()
	r.fs.files[dest.String()] = append(append(r.fs.files[dest.String()], line...), '\n')
	return nil
}

func (r *partialFaultRoot) Stat(dest pathalg.LocalRootedDest) (ports.LocalFileInfo, error) {
	return r.Lstat(dest)
}

func (r *partialFaultRoot) Lstat(dest pathalg.LocalRootedDest) (ports.LocalFileInfo, error) {
	r.fs.mu.Lock()
	defer r.fs.mu.Unlock()
	key := dest.String()
	if b, ok := r.fs.files[key]; ok {
		return ports.NewLocalFileInfo(ports.LocalFileInfoSpec{Name: dest.Base(), Size: int64(len(b)), Mode: 0o600})
	}
	prefix := key + "/"
	for k := range r.fs.files {
		if strings.HasPrefix(k, prefix) {
			return ports.NewLocalFileInfo(ports.LocalFileInfoSpec{Name: dest.Base(), Mode: fs.ModeDir | 0o700})
		}
	}
	var zero ports.LocalFileInfo
	return zero, ports.ErrNotFound
}

func (r *partialFaultRoot) ReadDir(dir algebraic.Option[pathalg.LocalRootedDest]) ([]ports.LocalDirEntry, error) {
	r.fs.mu.Lock()
	defer r.fs.mu.Unlock()
	prefix := ""
	if d, ok := dir.Get(); ok {
		prefix = d.String() + "/"
	}
	var out []ports.LocalDirEntry
	for k, b := range r.fs.files {
		if rest, ok := strings.CutPrefix(k, prefix); ok && rest != "" && !strings.Contains(rest, "/") {
			e, err := ports.NewLocalDirEntry(rest, 0o600, int64(len(b)))
			if err == nil {
				out = append(out, e)
			}
		}
	}
	return out, nil
}

func (r *partialFaultRoot) MkdirAll(pathalg.LocalRootedDest, fs.FileMode) error { return nil }
func (r *partialFaultRoot) CreateSymlink(pathalg.LocalRootedDest, string) error {
	return ports.ErrUnsupported
}
func (r *partialFaultRoot) Chtimes(pathalg.LocalRootedDest, time.Time, time.Time) error {
	return ports.ErrUnsupported
}
func (r *partialFaultRoot) Remove(dest pathalg.LocalRootedDest) error {
	r.fs.mu.Lock()
	defer r.fs.mu.Unlock()
	if _, ok := r.fs.files[dest.String()]; !ok {
		return ports.ErrNotFound
	}
	delete(r.fs.files, dest.String())
	return nil
}

type partialFaultLockedFile struct {
	fs     *partialFaultAuditFS
	key    string
	offset int64
}

func (f *partialFaultLockedFile) Read(p []byte) (int, error) {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	b := f.fs.files[f.key]
	if f.offset >= int64(len(b)) {
		return 0, io.EOF
	}
	n := copy(p, b[f.offset:])
	f.offset += int64(n)
	return n, nil
}

func (f *partialFaultLockedFile) Write(p []byte) (int, error) {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	if f.fs.failNextWrite && len(p) > 6 {
		f.fs.failNextWrite = false
		f.writeAtLocked(p[:6])
		return 6, errors.New("simulated transient ENOSPC mid-line")
	}
	f.writeAtLocked(p)
	return len(p), nil
}

func (f *partialFaultLockedFile) writeAtLocked(p []byte) {
	b := f.fs.files[f.key]
	end := int(f.offset) + len(p)
	if end > len(b) {
		grown := make([]byte, end)
		copy(grown, b)
		b = grown
	}
	copy(b[f.offset:], p)
	f.fs.files[f.key] = b
	f.offset = int64(end)
}

func (f *partialFaultLockedFile) Seek(offset int64, whence int) (int64, error) {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	if whence == io.SeekStart && f.fs.failNextSeekStart {
		f.fs.failNextSeekStart = false
		return f.offset, errors.New("simulated seek failure after truncate")
	}
	var next int64
	switch whence {
	case io.SeekStart:
		next = offset
	case io.SeekCurrent:
		next = f.offset + offset
	case io.SeekEnd:
		next = int64(len(f.fs.files[f.key])) + offset
	default:
		return 0, ports.ErrInvalidArgument
	}
	f.offset = next
	return next, nil
}

func (f *partialFaultLockedFile) Truncate(size int64) error {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	// 仅对正在写入的锁回滚（非初始空文件打开阶段）注入截断故障。
	if f.fs.failNextTruncate && !f.fs.failNextWrite && !f.fs.failNextSync && len(f.fs.files[f.key]) > 0 {
		f.fs.failNextTruncate = false
		return errors.New("simulated truncate failure during rollback")
	}
	b := f.fs.files[f.key]
	switch {
	case size < int64(len(b)):
		f.fs.files[f.key] = bytes.Clone(b[:size])
	case size > int64(len(b)):
		// 忠实模拟真实 OS ftruncate 零扩展语义，确保排空截断回归能被测试捕获。
		grown := make([]byte, size)
		copy(grown, b)
		f.fs.files[f.key] = grown
	}
	return nil
}

func (f *partialFaultLockedFile) Sync() error {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	if f.fs.failNextSync && len(f.fs.files[f.key]) > 0 {
		f.fs.failNextSync = false
		return errors.New("simulated EIO on fsync")
	}
	return nil
}

func (f *partialFaultLockedFile) Stat() (ports.LocalFileInfo, error) {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	b := f.fs.files[f.key]
	return ports.NewLocalFileInfo(ports.LocalFileInfoSpec{Name: "lock", Size: int64(len(b)), Mode: 0o600})
}
