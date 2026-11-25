package audit_test

import (
	"bufio"
	"bytes"
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
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

// 编译期接口契约断言（ADR-008）。
var (
	_ ports.AuditSink       = (*audit.FileSink)(nil)
	_ ports.AuditReconciler = (*audit.FileReconciler)(nil)
)

const (
	crashHelperModeKey   = "XOPS_AUDIT_CRASH_HELPER_MODE"
	crashHelperRootKey   = "XOPS_AUDIT_CRASH_HELPER_ROOT"
	crashHelperProcIDKey = "XOPS_AUDIT_CRASH_HELPER_PROC_ID"
	crashHelperOpIDKey   = "XOPS_AUDIT_CRASH_HELPER_OP_ID"
	crashHelperOpID1Key  = "XOPS_AUDIT_CRASH_HELPER_OP_ID_1"
)

// TestAuditCrashHelper 在独立操作系统子进程内执行真实内核文件锁登记，并通过 os.Exit 模拟无清理 SIGKILL 崩溃
// 或在收到 stdin EOF 前长期持有真实跨进程活跃锁（完全跨平台兼容 Linux / FreeBSD / macOS / Windows）。
func TestAuditCrashHelper(t *testing.T) {
	mode := os.Getenv(crashHelperModeKey)
	if mode == "" {
		return
	}
	sink, procID, opID := openHelperSink(t)
	ctx := context.Background()
	traceID, _ := security.NewTraceIDFrom(tck.NewDeterministicEntropy(91))

	if mode == "post-drain-crash" {
		runHelperDrainCycle(t, ctx, sink, procID, traceID)
	}
	mustHelperStep(t, "Stage(op)", sink.StageOperation(ctx, opID))
	mustHelperStep(t, "Record(auth)", sink.Record(ctx, tck.MustAuditEntry(t, procID, traceID, opID, ports.AuditPhaseAuthorized, ports.AuditOutcomePending)))

	if mode == "hold-live" {
		runHelperHoldLive(t, ctx, sink, procID, traceID, opID)
	}

	// 故意跳过 Close() 与 UnstageOperation() 直接 os.Exit(0)：由 OS 内核释放文件锁并遗留真实 .lock 文件。
	os.Exit(0)
}

func openHelperSink(t *testing.T) (*audit.FileSink, ports.ProcessInstanceID, security.OperationID) {
	t.Helper()
	rootDir := mustLocalDir(t, os.Getenv(crashHelperRootKey))
	procID, err := ports.ParseProcessInstanceID(os.Getenv(crashHelperProcIDKey))
	mustHelperStep(t, "ParseProcessInstanceID", err)
	opID, err := security.ParseOperationID(os.Getenv(crashHelperOpIDKey))
	mustHelperStep(t, "ParseOperationID", err)
	sink, err := audit.NewFileSink(audit.SinkSpec{
		ScopedFS:  osfs.NewScopedRootFS(),
		RootDir:   rootDir,
		ProcessID: procID,
	})
	mustHelperStep(t, "NewFileSink", err)
	return sink, procID, opID
}

func runHelperDrainCycle(t *testing.T, ctx context.Context, sink *audit.FileSink, procID ports.ProcessInstanceID, traceID security.TraceID) {
	t.Helper()
	op1, err := security.ParseOperationID(os.Getenv(crashHelperOpID1Key))
	mustHelperStep(t, "ParseOperationID(op1)", err)
	mustHelperStep(t, "Stage(op1)", sink.StageOperation(ctx, op1))
	mustHelperStep(t, "Record(op1 auth)", sink.Record(ctx, tck.MustAuditEntry(t, procID, traceID, op1, ports.AuditPhaseAuthorized, ports.AuditOutcomePending)))
	mustHelperStep(t, "Record(op1 fin)", sink.Record(ctx, tck.MustAuditEntry(t, procID, traceID, op1, ports.AuditPhaseFinalized, ports.AuditOutcomeSucceeded)))
	mustHelperStep(t, "Unstage(op1)", sink.UnstageOperation(ctx, op1))
}

func runHelperHoldLive(t *testing.T, ctx context.Context, sink *audit.FileSink, procID ports.ProcessInstanceID, traceID security.TraceID, opID security.OperationID) {
	t.Helper()
	_, _ = io.WriteString(os.Stdout, "READY\n")
	_, _ = io.ReadAll(os.Stdin)
	_ = sink.Record(ctx, tck.MustAuditEntry(t, procID, traceID, opID, ports.AuditPhaseFinalized, ports.AuditOutcomeSucceeded))
	_ = sink.UnstageOperation(ctx, opID)
	_ = sink.Close()
	os.Exit(0)
}

func mustHelperStep(t *testing.T, label string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("helper %s 失败: %v", label, err)
	}
}

func mustLocalDir(t *testing.T, raw string) pathalg.LocalDir {
	t.Helper()
	d, err := pathalg.ParseLocalDir(raw)
	if err != nil {
		t.Fatalf("ParseLocalDir(%q) 失败: %v", raw, err)
	}
	return d
}

// newPrivateAuditRoot 在 t.TempDir() 下返回尚未预创建的私有子目录路径，
// 使 ScopedRootFS.EnsureRoot(0o700) 按 INV-A4 在 Windows 上以受保护 Owner-Only DACL 创建该根目录
// （避免直接将继承宽泛 DACL 的 Go t.TempDir() 传入 osfs 触发安全拒绝）。
func newPrivateAuditRoot(t *testing.T) (string, pathalg.LocalDir) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "xops-root")
	return dir, mustLocalDir(t, dir)
}

func spawnCrashChild(t *testing.T, rootDir, mode string, procID ports.ProcessInstanceID, opID, op1 security.OperationID) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable 失败: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestAuditCrashHelper$")
	cmd.WaitDelay = 2 * time.Second
	cmd.Env = append(os.Environ(),
		crashHelperModeKey+"="+mode,
		crashHelperRootKey+"="+rootDir,
		crashHelperProcIDKey+"="+procID.String(),
		crashHelperOpIDKey+"="+opID.String(),
		crashHelperOpID1Key+"="+op1.String(),
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("崩溃辅助子进程 (%s) 失败: %v\n%s", mode, err, string(out))
	}
}

// TestTCKAuditSuiteWithRealChildCrash 验证 FileSink 与 FileReconciler 完整通过 core/ports/tck，
// 包含真实跨进程 SIGKILL 崩溃恢复与排空归零（Truncate(0)+Seek(0)）后再崩溃恢复。
func TestTCKAuditSuiteWithRealChildCrash(t *testing.T) {
	defer goleak.VerifyNone(t)
	ent := tck.NewDeterministicEntropy(17)
	var mu sync.Mutex
	var curDir string

	tck.RunAuditSuite(t, tck.AuditFixture{
		NewAudit: func(t *testing.T) (ports.AuditSink, ports.AuditReconciler) {
			dir, rootDir := newPrivateAuditRoot(t)
			mu.Lock()
			curDir = dir
			mu.Unlock()
			fsPort := osfs.NewScopedRootFS()
			sink, err := audit.NewFileSinkFromEntropy(fsPort, rootDir, ent)
			if err != nil {
				t.Fatalf("NewFileSinkFromEntropy 失败: %v", err)
			}
			rec, err := audit.NewFileReconciler(audit.ReconcilerSpec{ScopedFS: fsPort, RootDir: rootDir})
			if err != nil {
				t.Fatalf("NewFileReconciler 失败: %v", err)
			}
			return sink, rec
		},
		SimulateCrash: func(t *testing.T) security.OperationID {
			mu.Lock()
			dir := curDir
			mu.Unlock()
			deadPID, _ := ports.NewProcessInstanceIDFrom(ent)
			opID, _ := security.NewOperationIDFrom(ent)
			var zeroOp security.OperationID
			spawnCrashChild(t, dir, "crash", deadPID, opID, zeroOp)
			return opID
		},
		SimulatePostDrainCrash: func(t *testing.T) security.OperationID {
			mu.Lock()
			dir := curDir
			mu.Unlock()
			deadPID, _ := ports.NewProcessInstanceIDFrom(ent)
			op1, _ := security.NewOperationIDFrom(ent)
			op2, _ := security.NewOperationIDFrom(ent)
			spawnCrashChild(t, dir, "post-drain-crash", deadPID, op2, op1)
			// 核验排空后二次写入的真实 .lock 文件绝不含前导稀疏 NUL 字节（§4 #4）。
			lockBytes, err := os.ReadFile(filepath.Join(dir, "run", deadPID.String()+".lock"))
			if err != nil {
				t.Fatalf("读取排空后崩溃锁文件失败: %v", err)
			}
			if bytes.ContainsRune(lockBytes, 0) || !strings.HasPrefix(string(lockBytes), "+"+op2.String()) {
				t.Fatalf("排空归零后 .lock 文件含稀疏 NUL 或偏移错位: %q", string(lockBytes))
			}
			return op2
		},
	})
}

// TestO1CleanStartupZeroScanAndMultiTerminalConcurrency 验证：
//   - 干净启动与仅存在跨进程活跃终端锁时，AuditLogScans 恒为 0（O(1) 零扫描 audit.jsonl）；
//   - 多终端并发场景：活跃子进程锁被跳过、死亡子进程锁被抢占补写唯一 AbortedByCrash 并彻底删除；
//   - 多个在途操作未归零前绝不 Truncate(0)，归零瞬间精确触发 Truncate(0)+Seek(0)。
func TestO1CleanStartupZeroScanAndMultiTerminalConcurrency(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	dir, rootDir := newPrivateAuditRoot(t)
	fsPort := osfs.NewScopedRootFS()
	ent := tck.NewDeterministicEntropy(63)

	rec, err := audit.NewFileReconciler(audit.ReconcilerSpec{ScopedFS: fsPort, RootDir: rootDir})
	if err != nil {
		t.Fatalf("NewFileReconciler 失败: %v", err)
	}

	// 1. 空白启动 O(1) 零扫描。
	rep0, err := rec.ReconcileCrashedAudits(ctx, tck.BaseTime())
	if err != nil || rep0.ScannedLocks() != 0 || rec.AuditLogScans() != 0 {
		t.Fatalf("空白启动期望 O(1) 零扫描: rep=%v err=%v scans=%d", rep0, err, rec.AuditLogScans())
	}

	// 2. 启动一个真实活跃子进程终端持锁，同时制造一个死亡子进程锁。
	livePID, _ := ports.NewProcessInstanceIDFrom(ent)
	liveOp, _ := security.NewOperationIDFrom(ent)
	stopLive := startLiveHolderChild(t, dir, livePID, liveOp)
	defer stopLive()

	// 仅存在活跃进程锁时，对账仍必须 O(1) 零扫描 audit.jsonl。
	repLive, err := rec.ReconcileCrashedAudits(ctx, tck.BaseTime().Add(time.Minute))
	if err != nil || repLive.LiveLocksSkipped() != 1 || repLive.DeadLocksClaimed() != 0 || rec.AuditLogScans() != 0 {
		t.Fatalf("仅活跃终端对账期望 O(1) 零扫描: rep=%v err=%v scans=%d", repLive, err, rec.AuditLogScans())
	}

	// 制造死亡进程崩溃遗留操作，同时并发跑两个 Reconciler 抢占验证仅补写一次且无冲突。
	deadPID, _ := ports.NewProcessInstanceIDFrom(ent)
	deadOp, _ := security.NewOperationIDFrom(ent)
	var zeroOp security.OperationID
	spawnCrashChild(t, dir, "crash", deadPID, deadOp, zeroOp)

	rec2, err := audit.NewFileReconciler(audit.ReconcilerSpec{ScopedFS: fsPort, RootDir: rootDir})
	if err != nil {
		t.Fatalf("NewFileReconciler(2) 失败: %v", err)
	}
	var reps [2]ports.CrashReconcileReport
	err = conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		for idx, r := range []*audit.FileReconciler{rec, rec2} {
			if gErr := n.Go(func(c context.Context) error {
				var rErr error
				reps[idx], rErr = r.ReconcileCrashedAudits(c, tck.BaseTime().Add(2*time.Minute))
				return rErr
			}); gErr != nil {
				return gErr
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("并发崩溃对账失败: %v", err)
	}
	totalAborted := append(reps[0].AbortedOperations(), reps[1].AbortedOperations()...)
	if len(totalAborted) != 1 || !totalAborted[0].Equal(deadOp) {
		t.Fatalf("并发对账必须恰好补写 1 次 deadOp，实际=%v", totalAborted)
	}
	verifyAbortedLineCount(t, filepath.Join(dir, "audit.jsonl"), deadPID, deadOp, 1)

	// 核验多操作并发活跃时仅归零后截断。
	verifyTruncateOnlyWhenActiveReachesZero(t, fsPort, rootDir, ent)
}

func startLiveHolderChild(t *testing.T, rootDir string, procID ports.ProcessInstanceID, opID security.OperationID) func() {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable 失败: %v", err)
	}
	cmd := exec.Command(exe, "-test.run=^TestAuditCrashHelper$")
	cmd.WaitDelay = 2 * time.Second
	cmd.Env = append(os.Environ(),
		crashHelperModeKey+"=hold-live",
		crashHelperRootKey+"="+rootDir,
		crashHelperProcIDKey+"="+procID.String(),
		crashHelperOpIDKey+"="+opID.String(),
	)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe 失败: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe 失败: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("启动活跃持锁子进程失败: %v", err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "READY" {
		_ = stdin.Close()
		_ = cmd.Wait()
		t.Fatalf("等待活跃持锁子进程 READY 失败: line=%q err=%v", line, err)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			_ = stdin.Close()
			if wErr := cmd.Wait(); wErr != nil {
				t.Errorf("关闭活跃持锁子进程失败: %v", wErr)
			}
		})
	}
}

func verifyAbortedLineCount(t *testing.T, auditPath string, procID ports.ProcessInstanceID, opID security.OperationID, want int) {
	t.Helper()
	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", auditPath, err)
	}
	got := 0
	for line := range bytes.SplitSeq(raw, []byte{'\n'}) {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		var entry ports.AuditEntry
		if err := jsonv2.Unmarshal(trimmed, &entry); err != nil {
			t.Fatalf("audit.jsonl 反序列化失败: %v", err)
		}
		if entry.ProcessID().Equal(procID) && entry.OperationID().Equal(opID) && entry.Outcome() == ports.AuditOutcomeAbortedByCrash {
			got++
		}
	}
	if got != want {
		t.Fatalf("audit.jsonl 中 AbortedByCrash 条数 = %d, 期望 %d", got, want)
	}
}

func verifyTruncateOnlyWhenActiveReachesZero(t *testing.T, fsPort ports.ScopedRootFS, rootDir pathalg.LocalDir, ent io.Reader) {
	t.Helper()
	ctx := context.Background()
	sink, err := audit.NewFileSinkFromEntropy(fsPort, rootDir, ent)
	if err != nil {
		t.Fatalf("NewFileSinkFromEntropy 失败: %v", err)
	}
	defer func() { _ = sink.Close() }()

	opA, _ := security.NewOperationIDFrom(ent)
	opB, _ := security.NewOperationIDFrom(ent)
	if err := sink.StageOperation(ctx, opA); err != nil {
		t.Fatalf("Stage(opA): %v", err)
	}
	if err := sink.StageOperation(ctx, opB); err != nil {
		t.Fatalf("Stage(opB): %v", err)
	}
	if err := sink.UnstageOperation(ctx, opA); err != nil {
		t.Fatalf("Unstage(opA): %v", err)
	}
	if sink.LockTruncations() != 0 {
		t.Fatalf("opB 仍在途时禁止 Truncate(0): truncations=%d", sink.LockTruncations())
	}
	if err := sink.UnstageOperation(ctx, opB); err != nil {
		t.Fatalf("Unstage(opB): %v", err)
	}
	if sink.LockTruncations() != 1 {
		t.Fatalf("活跃集合归零时必须精确触发 1 次 Truncate(0)+Seek(0): truncations=%d", sink.LockTruncations())
	}
}

// TestZeroValuesAndPostWriteErrorContract 验证零值失败关闭与 Finalized 写入故障包装为 *ports.AuditPostWriteError。
func TestZeroValuesAndPostWriteErrorContract(t *testing.T) {
	defer goleak.VerifyNone(t)
	var zeroSink audit.FileSink
	if zeroSink.ProcessInstanceID().IsValid() || !errors.Is(zeroSink.Close(), ports.ErrInvalidArgument) {
		t.Fatal("零值 FileSink 必须失败关闭")
	}
	var zeroRec audit.FileReconciler
	if _, err := zeroRec.ReconcileCrashedAudits(context.Background(), tck.BaseTime()); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("零值 FileReconciler = %v, 期望 ErrInvalidArgument", err)
	}

	// 先通过 EnsureRoot(0o700) 按 INV-A4 安全引导 Owner-Only 根目录，再将 audit.jsonl 预先占为目录，
	// 迫使 Finalized Record 落盘失败，验证返回 *ports.AuditPostWriteError。
	_, rootDir := newPrivateAuditRoot(t)
	fsPort := osfs.NewScopedRootFS()
	if err := fsPort.EnsureRoot(rootDir, 0o700); err != nil {
		t.Fatalf("EnsureRoot 失败: %v", err)
	}
	auditDirDest, err := pathalg.ParseLocalRootedDest("audit.jsonl")
	if err != nil {
		t.Fatalf("ParseLocalRootedDest 失败: %v", err)
	}
	if err := fsPort.WithRoot(rootDir, func(root ports.RootHandle) error {
		return root.MkdirAll(auditDirDest, 0o700)
	}); err != nil {
		t.Fatalf("构造故障目录失败: %v", err)
	}
	ent := tck.NewDeterministicEntropy(81)
	sink, err := audit.NewFileSinkFromEntropy(fsPort, rootDir, ent)
	if err != nil {
		t.Fatalf("NewFileSinkFromEntropy 失败: %v", err)
	}
	defer func() { _ = sink.Close() }()

	traceID, _ := security.NewTraceIDFrom(ent)
	opID, _ := security.NewOperationIDFrom(ent)
	fin := tck.MustAuditEntry(t, sink.ProcessInstanceID(), traceID, opID, ports.AuditPhaseFinalized, ports.AuditOutcomeSucceeded)
	recErr := sink.Record(context.Background(), fin)
	if !errors.Is(recErr, ports.ErrAuditPostWrite) {
		t.Fatalf("Finalized 写入失败 = %v, 期望匹配 ErrAuditPostWrite", recErr)
	}
	if pw, ok := errors.AsType[*ports.AuditPostWriteError](recErr); !ok || !pw.OperationID().Equal(opID) {
		t.Fatalf("期望 *ports.AuditPostWriteError 携带 opID=%s, 实际=%T (%v)", opID, recErr, recErr)
	}

	// 顺带验证 Authorized 写入失败包装为 ErrAuditWriteFailed。
	auth := tck.MustAuditEntry(t, sink.ProcessInstanceID(), traceID, opID, ports.AuditPhaseAuthorized, ports.AuditOutcomePending)
	if !errors.Is(sink.Record(context.Background(), auth), ports.ErrAuditWriteFailed) {
		t.Fatal("Authorized 写入失败期望匹配 ErrAuditWriteFailed")
	}
}

// TestReconcileRejectsNonRegularLockEntry 验证 run/ 目录存在同名非常规 .lock 对象（如目录/符号链接）时
// FileReconciler 必须严格失败关闭返回 ports.ErrNotRegularFile，绝不静默跳过。
func TestReconcileRejectsNonRegularLockEntry(t *testing.T) {
	defer goleak.VerifyNone(t)
	_, rootDir := newPrivateAuditRoot(t)
	fsPort := osfs.NewScopedRootFS()
	if err := fsPort.EnsureRoot(rootDir, 0o700); err != nil {
		t.Fatalf("EnsureRoot 失败: %v", err)
	}
	badLockDir, err := pathalg.ParseLocalRootedDest("run/fake-proc.lock")
	if err != nil {
		t.Fatalf("ParseLocalRootedDest 失败: %v", err)
	}
	if err := fsPort.WithRoot(rootDir, func(root ports.RootHandle) error {
		return root.MkdirAll(badLockDir, 0o700)
	}); err != nil {
		t.Fatalf("创建伪造目录锁失败: %v", err)
	}
	rec, err := audit.NewFileReconciler(audit.ReconcilerSpec{ScopedFS: fsPort, RootDir: rootDir})
	if err != nil {
		t.Fatalf("NewFileReconciler 失败: %v", err)
	}
	if _, err := rec.ReconcileCrashedAudits(context.Background(), tck.BaseTime()); !errors.Is(err, ports.ErrNotRegularFile) {
		t.Fatalf("非常规 .lock 对象对账 = %v, 期望 ErrNotRegularFile", err)
	}
}

// TestCloseWithUnclosedOpsPreservesLockAndReconciles 验证存在未闭合操作时 Close() 不得截断或删除 .lock，
// 确保 Halted 熔断关闭后下次启动 FileReconciler 能够抢占该残留锁并补写 AbortedByCrash（ADR-008）。
func TestCloseWithUnclosedOpsPreservesLockAndReconciles(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	dir, rootDir := newPrivateAuditRoot(t)
	fsPort := osfs.NewScopedRootFS()
	ent := tck.NewDeterministicEntropy(97)

	sink, err := audit.NewFileSinkFromEntropy(fsPort, rootDir, ent)
	if err != nil {
		t.Fatalf("NewFileSinkFromEntropy 失败: %v", err)
	}
	procID := sink.ProcessInstanceID()
	traceID, _ := security.NewTraceIDFrom(ent)
	opID, _ := security.NewOperationIDFrom(ent)
	if err := sink.StageOperation(ctx, opID); err != nil {
		t.Fatalf("StageOperation 失败: %v", err)
	}
	if err := sink.Record(ctx, tck.MustAuditEntry(t, procID, traceID, opID, ports.AuditPhaseAuthorized, ports.AuditOutcomePending)); err != nil {
		t.Fatalf("Record(Authorized) 失败: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("存在未闭合操作时 Close 失败: %v", err)
	}

	lockPath := filepath.Join(dir, "run", procID.String()+".lock")
	lockBytes, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("未闭合操作 Close 后 .lock 必须保留在磁盘: %v", err)
	}
	if !strings.Contains(string(lockBytes), "+"+opID.String()) {
		t.Fatalf("保留的 .lock 内容缺少未闭合 opID: %q", string(lockBytes))
	}

	rec, err := audit.NewFileReconciler(audit.ReconcilerSpec{ScopedFS: fsPort, RootDir: rootDir})
	if err != nil {
		t.Fatalf("NewFileReconciler 失败: %v", err)
	}
	rep, err := rec.ReconcileCrashedAudits(ctx, tck.BaseTime().Add(time.Minute))
	if err != nil {
		t.Fatalf("ReconcileCrashedAudits 失败: %v", err)
	}
	if rep.DeadLocksClaimed() != 1 || len(rep.AbortedOperations()) != 1 || !rep.AbortedOperations()[0].Equal(opID) {
		t.Fatalf("崩溃对账报告不符: dead=%d aborted=%v", rep.DeadLocksClaimed(), rep.AbortedOperations())
	}
	verifyAbortedLineCount(t, filepath.Join(dir, "audit.jsonl"), procID, opID, 1)
	if _, statErr := os.Stat(lockPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("对账完成后残留 .lock 应已清理，实际 statErr=%v", statErr)
	}
}
