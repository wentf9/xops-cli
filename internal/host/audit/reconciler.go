package audit

import (
	"bytes"
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/i18n"
)

// FileReconciler 实现 ports.AuditReconciler，在启动期提供 O(1) 零扫描快路径与多终端安全的崩溃恢复慢路径（ADR-008）。
//
//xops:opaque
//xops:failclosed
type FileReconciler struct {
	fs            ports.ScopedRootFS
	rootDir       pathalg.LocalDir
	auditFile     pathalg.LocalRootedDest
	runDir        pathalg.LocalRootedDest
	maxAuditBytes int64
	maxLockBytes  int64
	auditScans    atomic.Uint64
	valid         bool
}

// NewFileReconciler 校验沙箱端口、目录路径与字节读取上限后构造 FileReconciler。
func NewFileReconciler(spec ReconcilerSpec) (*FileReconciler, error) {
	if spec.ScopedFS == nil || !spec.RootDir.IsValid() {
		return nil, i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostInvalidField, i18n.Str("field", "ScopedFS/RootDir"))
	}
	auditDest, runDest, err := resolveAuditPaths(spec.AuditFile, spec.RunDir)
	if err != nil {
		return nil, err
	}
	maxAudit, maxLock, err := normalizeReconcilerLimits(spec)
	if err != nil {
		return nil, err
	}
	return &FileReconciler{
		fs:            spec.ScopedFS,
		rootDir:       spec.RootDir,
		auditFile:     auditDest,
		runDir:        runDest,
		maxAuditBytes: maxAudit,
		maxLockBytes:  maxLock,
		valid:         true,
	}, nil
}

func normalizeReconcilerLimits(spec ReconcilerSpec) (maxAudit, maxLock int64, err error) {
	maxAudit = spec.MaxAuditBytes
	if maxAudit == 0 {
		maxAudit = defaultMaxAuditReadBytes
	}
	if maxAudit < 0 || maxAudit > maxAllowedAuditReadBytes {
		return 0, 0, i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostLimitOutOfRange, i18n.Str("field", "MaxAuditBytes"), i18n.Int64("value", spec.MaxAuditBytes), i18n.Int64("max", maxAllowedAuditReadBytes))
	}
	maxLock = spec.MaxLockBytes
	if maxLock == 0 {
		maxLock = defaultMaxLockReadBytes
	}
	if maxLock < 0 || maxLock > maxAllowedLockReadBytes {
		return 0, 0, i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostLimitOutOfRange, i18n.Str("field", "MaxLockBytes"), i18n.Int64("value", spec.MaxLockBytes), i18n.Int64("max", maxAllowedLockReadBytes))
	}
	return maxAudit, maxLock, nil
}

// AuditLogScans 返回触发崩溃恢复慢路径并实际扫描 audit.jsonl 的累计次数（干净启动恒保持 0）。
func (r *FileReconciler) AuditLogScans() uint64 {
	if r == nil || !r.valid {
		return 0
	}
	return r.auditScans.Load()
}

// ReconcileCrashedAudits 扫描 ~/.xops/run/*.lock：
//   - 若目录不存在或全部锁仍被活跃进程持有，直接 O(1) 返回且零读取 audit.jsonl；
//   - 对可被非阻塞独占 TryLock 抢占的死亡进程锁，重放 +/- 差集、核验 audit.jsonl 并在跨进程旁路锁下
//     为已写 Authorized 但缺失 Finalized 的操作补写唯一 AbortedByCrash，随后经 osfs.RemoveLockedFileSafely 删除死锁。
func (r *FileReconciler) ReconcileCrashedAudits(ctx context.Context, now time.Time) (ports.CrashReconcileReport, error) {
	if err := r.checkArgs(ctx, now); err != nil {
		return zeroVal[ports.CrashReconcileReport](), err
	}
	var report ports.CrashReconcileReport
	err := r.fs.WithRoot(r.rootDir, func(root ports.RootHandle) error {
		var rErr error
		report, rErr = r.reconcileInRoot(ctx, root, now.UTC().Round(0))
		return rErr
	})
	if errors.Is(err, ports.ErrNotFound) {
		return ports.NewCrashReconcileReport(ports.CrashReconcileReportSpec{})
	}
	return report, err
}

func (r *FileReconciler) checkArgs(ctx context.Context, now time.Time) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if r == nil || !r.valid {
		return i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostNotInitialized, i18n.Str("component", "FileReconciler"))
	}
	if now.IsZero() || now.UTC().Year() < 1 || now.UTC().Year() > 9999 {
		return i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostInvalidField, i18n.Str("field", "now"))
	}
	return nil
}

func (r *FileReconciler) readRunDirEntries(root ports.RootHandle) ([]ports.LocalDirEntry, bool, error) {
	runExists, err := checkLstatDirChain(root, r.runDir)
	if err != nil || !runExists {
		return nil, false, err
	}
	entries, err := root.ReadDir(algebraic.Some(r.runDir))
	if errors.Is(err, ports.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return entries, true, nil
}

func (r *FileReconciler) reconcileInRoot(ctx context.Context, root ports.RootHandle, now time.Time) (ports.CrashReconcileReport, error) {
	entries, exists, err := r.readRunDirEntries(root)
	if err != nil {
		return zeroVal[ports.CrashReconcileReport](), err
	}
	if !exists {
		return ports.NewCrashReconcileReport(ports.CrashReconcileReportSpec{})
	}
	var scanned, liveSkipped, deadClaimed int
	var abortedOps []security.OperationID
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return zeroVal[ports.CrashReconcileReport](), err
		}
		procID, lockDest, ok, pErr := r.parseLockCandidate(entry)
		if errors.Is(pErr, ports.ErrNotRegularFile) {
			return zeroVal[ports.CrashReconcileReport](), pErr
		}
		if pErr != nil || !ok {
			continue
		}
		scanned++
		status, ops, cErr := r.claimOneLock(ctx, root, procID, lockDest, now)
		if cErr != nil {
			return zeroVal[ports.CrashReconcileReport](), cErr
		}
		switch status {
		case lockClaimLive:
			liveSkipped++
		case lockClaimDead:
			deadClaimed++
			abortedOps = append(abortedOps, ops...)
		case lockClaimVanished:
		}
	}
	return ports.NewCrashReconcileReport(ports.CrashReconcileReportSpec{
		ScannedLocks:      scanned,
		LiveLocksSkipped:  liveSkipped,
		DeadLocksClaimed:  deadClaimed,
		AbortedOperations: abortedOps,
	})
}

type lockClaimStatus uint8

const (
	lockClaimVanished lockClaimStatus = iota
	lockClaimLive
	lockClaimDead
)

func (r *FileReconciler) parseLockCandidate(entry ports.LocalDirEntry) (ports.ProcessInstanceID, pathalg.LocalRootedDest, bool, error) {
	rawID, ok := strings.CutSuffix(entry.Name(), ".lock")
	if !ok || rawID == "" {
		return zeroVal[ports.ProcessInstanceID](), zeroVal[pathalg.LocalRootedDest](), false, nil
	}
	// 先校验 .lock 后缀再判定对象类型，防止 run/ 目录中被植入同名目录或符号链接时静默跳过。
	if !entry.IsRegular() {
		return zeroVal[ports.ProcessInstanceID](), zeroVal[pathalg.LocalRootedDest](), false, i18n.EF(ports.ErrNotRegularFile, i18n.KeyHostPathNotRegular, i18n.BoundStr("path", entry.Name()))
	}
	procID, err := ports.ParseProcessInstanceID(rawID)
	if err != nil {
		return zeroVal[ports.ProcessInstanceID](), zeroVal[pathalg.LocalRootedDest](), false, err
	}
	lockDest, err := r.runDir.JoinComponent(entry.Name())
	if err != nil {
		return zeroVal[ports.ProcessInstanceID](), zeroVal[pathalg.LocalRootedDest](), false, err
	}
	return procID, lockDest, true, nil
}

func (r *FileReconciler) claimOneLock(ctx context.Context, root ports.RootHandle, procID ports.ProcessInstanceID, lockDest pathalg.LocalRootedDest, now time.Time) (lockClaimStatus, []security.OperationID, error) {
	var aborted []security.OperationID
	acquired, err := root.TryWithLockedFile(lockDest, ports.LockExclusive, false, 0, func(lf ports.LockedFile) error {
		pending, rErr := r.readLockPendingOps(lf)
		if rErr != nil {
			return rErr
		}
		if len(pending) > 0 {
			ops, sErr := r.reconcileSlowPath(ctx, root, procID, pending, now)
			if sErr != nil {
				return sErr
			}
			aborted = ops
		}
		// 仍在持独占锁态截断并归零偏移，防止并发竞态者重复补写 AbortedByCrash。
		return truncateAndRewind(lf)
	})
	if errors.Is(err, ports.ErrNotFound) {
		return lockClaimVanished, nil, nil
	}
	if err != nil {
		return lockClaimVanished, nil, err
	}
	if !acquired {
		return lockClaimLive, nil, nil
	}
	// 严格经 osfs.RemoveLockedFileSafely 完成三平台（含 Windows）安全删锁，忽略并发删除导致的 ErrNotFound。
	if _, rmErr := osfs.RemoveLockedFileSafely(root, lockDest); rmErr != nil {
		return lockClaimVanished, nil, rmErr
	}
	return lockClaimDead, aborted, nil
}

func (r *FileReconciler) readLockPendingOps(lf ports.LockedFile) ([]security.OperationID, error) {
	if _, err := lf.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(lf, r.maxLockBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > r.maxLockBytes {
		return nil, i18n.EF(ports.ErrLimitExceeded, i18n.KeyHostSizeExceedsLimit, i18n.Int64("max", r.maxLockBytes))
	}
	return replayLockLog(raw), nil
}

func (r *FileReconciler) reconcileSlowPath(ctx context.Context, root ports.RootHandle, procID ports.ProcessInstanceID, pending []security.OperationID, now time.Time) ([]security.OperationID, error) {
	limits, err := ports.NewReadLimits(r.maxAuditBytes)
	if err != nil {
		return nil, err
	}
	parentExists, err := checkAuditParentDir(root, r.auditFile)
	if err != nil || !parentExists {
		return nil, err
	}
	var aborted []security.OperationID
	err = osfs.WithSidecarLock(ctx, root, r.auditFile, ports.LockExclusive, auditFilePerm, func(ports.LockedFile) error {
		r.auditScans.Add(1)
		rawAudit, rErr := root.ReadAllBounded(r.auditFile, limits)
		if errors.Is(rErr, ports.ErrNotFound) {
			return nil
		}
		if rErr != nil {
			return rErr
		}
		authByOp, finalized, pErr := parseAuditEntriesForProcess(rawAudit, procID)
		if pErr != nil {
			return pErr
		}
		var wErr error
		aborted, wErr = appendAbortedEntries(root, r.auditFile, procID, pending, authByOp, finalized, now)
		return wErr
	})
	return aborted, err
}

func checkAuditParentDir(root ports.RootHandle, auditFile pathalg.LocalRootedDest) (bool, error) {
	parent, ok := auditFile.Parent()
	if !ok {
		return true, nil
	}
	return checkLstatDirChain(root, parent)
}

// checkLstatDirChain 自顶向下逐级以 Lstat 校验目录链的每个分量，确保多段自定义 RunDir 或 AuditFile
// 父路径中任一祖先为悬空/存活符号链接时严格失败关闭返回 ports.ErrSymlinkRejected。
func checkLstatDirChain(root ports.RootHandle, dir pathalg.LocalRootedDest) (bool, error) {
	parts := strings.Split(dir.String(), "/")
	cur, err := pathalg.ParseLocalRootedDest(parts[0])
	if err != nil {
		return false, err
	}
	for i := range parts {
		if i > 0 {
			cur, err = cur.JoinComponent(parts[i])
			if err != nil {
				return false, err
			}
		}
		exists, cErr := checkSingleLstatDir(root, cur)
		if cErr != nil || !exists {
			return false, cErr
		}
	}
	return true, nil
}

func checkSingleLstatDir(root ports.RootHandle, dir pathalg.LocalRootedDest) (bool, error) {
	info, err := root.Lstat(dir)
	if errors.Is(err, ports.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.IsSymlink() {
		return false, i18n.EF(ports.ErrSymlinkRejected, i18n.KeyHostPathIsSymlink, i18n.BoundStr("path", dir.String()))
	}
	if !info.IsDir() {
		return false, i18n.EF(ports.ErrNotRegularFile, i18n.KeyHostPathNotDir, i18n.BoundStr("path", dir.String()))
	}
	return true, nil
}

func parseAuditEntriesForProcess(raw []byte, procID ports.ProcessInstanceID) (map[security.OperationID]ports.AuditEntry, map[security.OperationID]bool, error) {
	authByOp := make(map[security.OperationID]ports.AuditEntry)
	finalized := make(map[security.OperationID]bool)
	lineNo := 0
	for line := range bytes.SplitSeq(raw, []byte{'\n'}) {
		lineNo++
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		var entry ports.AuditEntry
		if err := jsonv2.Unmarshal(trimmed, &entry); err != nil {
			return nil, nil, i18n.WrapS(ErrCorruptAuditLog, err, i18n.KeyHostAuditLineUnmarshalFailed, i18n.Int("line", lineNo))
		}
		if !entry.ProcessID().Equal(procID) {
			continue
		}
		if entry.Phase() == ports.AuditPhaseAuthorized {
			authByOp[entry.OperationID()] = entry
		} else if entry.Phase() == ports.AuditPhaseFinalized {
			finalized[entry.OperationID()] = true
		}
	}
	return authByOp, finalized, nil
}

func appendAbortedEntries(
	root ports.RootHandle,
	auditDest pathalg.LocalRootedDest,
	procID ports.ProcessInstanceID,
	pending []security.OperationID,
	authByOp map[security.OperationID]ports.AuditEntry,
	finalized map[security.OperationID]bool,
	now time.Time,
) ([]security.OperationID, error) {
	var aborted []security.OperationID
	for _, opID := range pending {
		auth, ok := authByOp[opID]
		if !ok || finalized[opID] {
			continue
		}
		entry, err := ports.NewAuditEntry(ports.AuditEntrySpec{
			ProcessID:   procID,
			TraceID:     auth.TraceID(),
			OperationID: opID,
			Phase:       ports.AuditPhaseFinalized,
			Outcome:     ports.AuditOutcomeAbortedByCrash,
			Risk:        auth.Risk(),
			Decision:    auth.Decision(),
			Binding:     auth.Binding(),
			Timestamp:   now,
			ErrorCode:   "aborted_by_crash",
			Reason:      "reconciled crashed process lock",
		})
		if err != nil {
			return nil, err
		}
		rawJSON, err := entry.CanonicalJSON()
		if err != nil {
			return nil, err
		}
		if err := root.AppendLine(auditDest, auditFilePerm, rawJSON); err != nil {
			return nil, i18n.WrapS(ports.ErrAuditWriteFailed, err, i18n.KeyHostAuditAppendAbortedFailed)
		}
		aborted = append(aborted, opID)
	}
	return aborted, nil
}
