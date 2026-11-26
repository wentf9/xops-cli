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

// TestPartialLockWriteRollbackAndNestedAuditFile 验证 #35 Major #5 与 #34 Minor #4：
//   - .lock 部分写入失败时按 confirmedOffset 回滚 Truncate+Seek，或回滚失败时前置 '\n' 兜底，
//     确保下一条 +<op2>\n 仍位于独立行首并可被崩溃对账完整恢复；
//   - 嵌套自定义 AuditFile（如 logs/nested/audit.jsonl）自动创建父目录并完成写入与崩溃对账。
func TestPartialLockWriteRollbackAndNestedAuditFile(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	t.Run("PartialWriteRollbackRestoresFrameBoundary", func(t *testing.T) {
		verifyPartialLockWriteRecovery(t, ctx, false)
	})
	t.Run("PartialWriteFailedRollbackPrependsNewline", func(t *testing.T) {
		verifyPartialLockWriteRecovery(t, ctx, true)
	})
	t.Run("CustomNestedAuditFileCreatesParentDir", func(t *testing.T) {
		verifyCustomNestedAuditFile(t, ctx)
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
	// 1. op1 触发半行写入失败（仅落盘前 6 字节，无换行符）-> 须返回 ErrAuditWriteFailed。
	if err := sink.StageOperation(ctx, op1); !errors.Is(err, ports.ErrAuditWriteFailed) {
		t.Fatalf("半行写入故障期望 ErrAuditWriteFailed, 实际=%v", err)
	}
	// 2. 故障恢复后 op2 正常 Stage + Record(Authorized) + 脏 Close（模拟随后崩溃）。
	if err := sink.StageOperation(ctx, op2); err != nil {
		t.Fatalf("故障恢复后 op2 StageOperation 失败: %v", err)
	}
	if err := sink.Record(ctx, tck.MustAuditEntry(t, procID, traceID, op2, ports.AuditPhaseAuthorized, ports.AuditOutcomePending)); err != nil {
		t.Fatalf("op2 Record(Authorized) 失败: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("脏 Close 失败: %v", err)
	}
	// 3. 对账必须完整找回 op2 并补写唯一 AbortedByCrash，绝不因 op1 半行残留丢失 op2。
	rec, err := audit.NewFileReconciler(audit.ReconcilerSpec{ScopedFS: memFS, RootDir: rootDir})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := rec.ReconcileCrashedAudits(ctx, tck.BaseTime().Add(time.Minute))
	if err != nil {
		t.Fatalf("ReconcileCrashedAudits 失败: %v", err)
	}
	if rep.DeadLocksClaimed() != 1 || len(rep.AbortedOperations()) != 1 || !rep.AbortedOperations()[0].Equal(op2) {
		t.Fatalf("半行写故障恢复后对账丢失 op2: dead=%d aborted=%v", rep.DeadLocksClaimed(), rep.AbortedOperations())
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

// partialFaultAuditFS 是测试专用的纯内存 ScopedRootFS，用于确定性注入 .lock 半行写故障与回滚失败。
type partialFaultAuditFS struct {
	mu           sync.Mutex
	files        map[string][]byte
	failNext     bool
	failRollback bool
}

func newPartialFaultAuditFS(failRollback bool) *partialFaultAuditFS {
	return &partialFaultAuditFS{files: make(map[string][]byte), failNext: true, failRollback: failRollback}
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
	b, ok := r.fs.files[dest.String()]
	if !ok {
		var zero ports.LocalFileInfo
		return zero, ports.ErrNotFound
	}
	return ports.NewLocalFileInfo(ports.LocalFileInfoSpec{Name: dest.Base(), Size: int64(len(b)), Mode: 0o600})
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
	if f.fs.failNext && len(p) > 6 {
		f.fs.failNext = false
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
	if f.fs.failRollback && !f.fs.failNext {
		f.fs.failRollback = false
		return errors.New("simulated truncate failure during rollback")
	}
	b := f.fs.files[f.key]
	if size < int64(len(b)) {
		f.fs.files[f.key] = bytes.Clone(b[:size])
	}
	return nil
}

func (f *partialFaultLockedFile) Sync() error { return nil }

func (f *partialFaultLockedFile) Stat() (ports.LocalFileInfo, error) {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	b := f.fs.files[f.key]
	return ports.NewLocalFileInfo(ports.LocalFileInfoSpec{Name: "lock", Size: int64(len(b)), Mode: 0o600})
}
