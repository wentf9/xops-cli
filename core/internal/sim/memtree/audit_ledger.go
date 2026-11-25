package memtree

import (
	"crypto/sha256"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/ports"
)

// ProcLock 表示纯内存审计集群中单个进程实例的活跃锁与未闭合操作集合。
type ProcLock struct {
	Live   bool
	Active map[security.OperationID]bool
}

// AuditLedger 封装 SimAuditCluster 的纯内存审计条目、进程锁状态与崩溃对账算法（ADR-008）。
// 全部方法要求调用方持有外层互斥锁。
type AuditLedger struct {
	Entries []ports.AuditEntry
	Locks   map[ports.ProcessInstanceID]*ProcLock
}

// NewAuditLedger 创建空白审计账本。
func NewAuditLedger() *AuditLedger {
	return &AuditLedger{Locks: make(map[ports.ProcessInstanceID]*ProcLock)}
}

// AcquireLockLocked 为 procID 登记活跃进程锁，已被活跃进程占用时返回 ports.ErrLockBusy。
func (l *AuditLedger) AcquireLockLocked(procID ports.ProcessInstanceID) error {
	if ex := l.Locks[procID]; ex != nil && ex.Live {
		return ports.ErrLockBusy
	}
	l.Locks[procID] = &ProcLock{Live: true, Active: make(map[security.OperationID]bool)}
	return nil
}

// MutateLockLocked 登记或注销活跃操作，并在活跃集合由非空归零时返回 true（触发截断计数）。
func (l *AuditLedger) MutateLockLocked(lk *ProcLock, opID security.OperationID, stage bool) bool {
	if stage {
		lk.Active[opID] = true
		return false
	}
	if lk.Active[opID] {
		delete(lk.Active, opID)
		return len(lk.Active) == 0
	}
	return false
}

// TerminateLockLocked 标记进程锁为非活跃；仅当非崩溃且活跃未闭合集合为空时才删除锁记录。
// 若存在未闭合操作（如 Halted 熔断后关闭），保留锁记录供启动期 ReconcileCrashedAudits 补写 AbortedByCrash。
func (l *AuditLedger) TerminateLockLocked(procID ports.ProcessInstanceID, closed, crash bool) {
	if lk := l.Locks[procID]; lk != nil && (crash || (!closed && lk.Live)) {
		lk.Live = false
		if !crash && len(lk.Active) == 0 {
			delete(l.Locks, procID)
		}
	}
}

// ReconcileLocked 执行 O(1) 崩溃对账；无死亡锁时零扫描，存在死亡未闭合操作时通过 onLogScan 计数并补写 AbortedByCrash。
func (l *AuditLedger) ReconcileLocked(now time.Time, enospc bool, enospcErr error, onLogScan func()) (out ports.CrashReconcileReport, err error) {
	pids := slices.Collect(maps.Keys(l.Locks))
	slices.SortFunc(pids, ports.ProcessInstanceID.Compare)
	dead := slices.DeleteFunc(slices.Clone(pids), func(pid ports.ProcessInstanceID) bool { return l.Locks[pid].Live })
	if len(dead) == 0 {
		return ports.NewCrashReconcileReport(ports.CrashReconcileReportSpec{ScannedLocks: len(pids), LiveLocksSkipped: len(pids)})
	}
	var aborted []security.OperationID
	var writes []ports.AuditEntry
	scannedLog := false
	nowUTC := now.UTC().Round(0)
	for _, pid := range dead {
		staged := slices.Collect(maps.Keys(l.Locks[pid].Active))
		if len(staged) == 0 {
			continue
		}
		slices.SortFunc(staged, security.OperationID.Compare)
		if !scannedLog {
			if onLogScan != nil {
				onLogScan()
			}
			scannedLog = true
		}
		ents, ops, bErr := l.buildAbortedLocked(pid, staged, nowUTC)
		if bErr != nil {
			return out, bErr
		}
		writes, aborted = append(writes, ents...), append(aborted, ops...)
	}
	if len(writes) > 0 && enospc {
		return out, fmt.Errorf("%w: %w", ports.ErrAuditWriteFailed, enospcErr)
	}
	l.Entries = append(l.Entries, writes...)
	for _, pid := range dead {
		delete(l.Locks, pid)
	}
	return ports.NewCrashReconcileReport(ports.CrashReconcileReportSpec{
		ScannedLocks: len(pids), LiveLocksSkipped: len(pids) - len(dead), DeadLocksClaimed: len(dead), AbortedOperations: aborted,
	})
}

func (l *AuditLedger) buildAbortedLocked(pid ports.ProcessInstanceID, staged []security.OperationID, now time.Time) (outE []ports.AuditEntry, outOps []security.OperationID, err error) {
	authByOp, finalized := make(map[security.OperationID]ports.AuditEntry), make(map[security.OperationID]bool)
	for _, e := range l.Entries {
		if e.ProcessID().Equal(pid) && e.Phase() == ports.AuditPhaseAuthorized {
			authByOp[e.OperationID()] = e
		} else if e.ProcessID().Equal(pid) && e.Phase() == ports.AuditPhaseFinalized {
			finalized[e.OperationID()] = true
		}
	}
	for _, opID := range staged {
		auth, ok := authByOp[opID]
		if !ok || finalized[opID] {
			continue
		}
		e, eErr := ports.NewAuditEntry(ports.AuditEntrySpec{
			ProcessID: pid, TraceID: auth.TraceID(), OperationID: opID, Phase: ports.AuditPhaseFinalized, Outcome: ports.AuditOutcomeAbortedByCrash,
			Risk: auth.Risk(), Decision: auth.Decision(), Binding: auth.Binding(), Timestamp: now, ErrorCode: "aborted_by_crash", Reason: "reconciled crashed process lock",
		})
		if eErr != nil {
			return nil, nil, eErr
		}
		outE, outOps = append(outE, e), append(outOps, opID)
	}
	return outE, outOps, nil
}

// DigestAuditEntries 计算规范 JSONL 序列的确定性 SHA-256 摘要。
func DigestAuditEntries(entries []ports.AuditEntry) (sum [sha256.Size]byte, err error) {
	h := sha256.New()
	for _, e := range entries {
		raw, rErr := e.CanonicalJSON()
		if rErr != nil {
			return sum, rErr
		}
		_, _ = h.Write(append(raw, '\n'))
	}
	h.Sum(sum[:0])
	return sum, nil
}
