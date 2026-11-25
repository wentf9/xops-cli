package sim

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"maps"
	"slices"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/ports"
)

// AuditBoundary 标识可供 DST 精确触发 SIGKILL 崩溃注入的审计生命周期边界。
type AuditBoundary uint8

const (
	// AuditBoundaryAfterStage 表示完成 StageOperation(+opID) 后的崩溃注入点。
	AuditBoundaryAfterStage AuditBoundary = iota + 1
	// AuditBoundaryAfterAuthorized 表示前置 Audit(Authorized) 落盘后的崩溃注入点。
	AuditBoundaryAfterAuthorized
	// AuditBoundaryAfterFinalized 表示终态 Audit(Finalized) 落盘后的崩溃注入点。
	AuditBoundaryAfterFinalized
	// AuditBoundaryAfterUnstage 表示完成 UnstageOperation(-opID) 后的崩溃注入点。
	AuditBoundaryAfterUnstage
)

type simProcLock struct {
	live   bool
	active map[security.OperationID]bool
}

// SimAuditCluster 模拟多进程共享的 audit.jsonl 与 run/<ProcessInstanceID>.lock 目录（ADR-008 / RFC §3.4），
// 实现 ports.AuditReconciler：无死亡锁 O(1) 零读取 audit.jsonl，遇死亡锁按活跃差集补写唯一 AbortedByCrash。
//
//xops:opaque
//xops:failclosed
type SimAuditCluster struct {
	simBase
	enospc                     atomic.Bool
	entries                    []ports.AuditEntry
	locks                      map[ports.ProcessInstanceID]*simProcLock
	auditLogScans, truncations atomic.Uint64
}

// NewSimAuditCluster 创建空白的共享审计集群仿真器。
func NewSimAuditCluster() *SimAuditCluster {
	return &SimAuditCluster{simBase: newSimBase(nil), locks: make(map[ports.ProcessInstanceID]*simProcLock)}
}

// SetENOSPC / AuditLogScans / LockTruncations / Entries / Digest 提供故障控制与 O(1) 观测。
func (c *SimAuditCluster) SetENOSPC(en bool) {
	if c.ok() {
		c.enospc.Store(en)
	}
}
func (c *SimAuditCluster) AuditLogScans() uint64   { return c.auditLogScans.Load() }
func (c *SimAuditCluster) LockTruncations() uint64 { return c.truncations.Load() }
func (c *SimAuditCluster) Entries() []ports.AuditEntry {
	return withLockRet(&c.simBase, nil, func() []ports.AuditEntry { return slices.Clone(c.entries) })
}
func (c *SimAuditCluster) Digest() (sum [sha256.Size]byte, err error) {
	if !c.ok() {
		return sum, ErrSimNotInitialized
	}
	h := sha256.New()
	for _, e := range c.Entries() {
		raw, rErr := e.CanonicalJSON()
		if rErr != nil {
			return sum, rErr
		}
		_, _ = h.Write(append(raw, '\n'))
	}
	h.Sum(sum[:0])
	return sum, nil
}

// NewSink 与 NewSinkFromEntropy 为指定进程签发持实时进程锁的 SimAuditSink。
func (c *SimAuditCluster) NewSink(procID ports.ProcessInstanceID) (*SimAuditSink, error) {
	if !c.ok() {
		return nil, ErrSimNotInitialized
	}
	if !procID.IsValid() {
		return nil, ports.ErrInvalidProcessInstanceID
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if ex := c.locks[procID]; ex != nil && ex.live {
		return nil, ports.ErrLockBusy
	}
	c.locks[procID] = &simProcLock{live: true, active: make(map[security.OperationID]bool)}
	return &SimAuditSink{cluster: c, procID: procID, initialized: true}, nil
}
func (c *SimAuditCluster) NewSinkFromEntropy(entropy io.Reader) (*SimAuditSink, error) {
	pid, err := ports.NewProcessInstanceIDFrom(entropy)
	if err != nil {
		return nil, err
	}
	return c.NewSink(pid)
}

// ReconcileCrashedAudits 实现 ports.AuditReconciler：无死亡锁 O(1) 零扫描，发现死亡锁补写 AbortedByCrash 并删锁。
func (c *SimAuditCluster) ReconcileCrashedAudits(ctx context.Context, now time.Time) (out ports.CrashReconcileReport, err error) {
	if err = c.check(ctx, "audit.reconcile", !now.IsZero()); err != nil {
		return out, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	pids := slices.Collect(maps.Keys(c.locks))
	slices.SortFunc(pids, ports.ProcessInstanceID.Compare)
	dead := slices.DeleteFunc(slices.Clone(pids), func(pid ports.ProcessInstanceID) bool { return c.locks[pid].live })
	if len(dead) == 0 {
		return ports.NewCrashReconcileReport(ports.CrashReconcileReportSpec{ScannedLocks: len(pids), LiveLocksSkipped: len(pids)})
	}
	return c.reconcileDeadLocked(len(pids), len(pids)-len(dead), dead, now.UTC().Round(0))
}
func (c *SimAuditCluster) reconcileDeadLocked(scanned, liveSkipped int, dead []ports.ProcessInstanceID, now time.Time) (out ports.CrashReconcileReport, err error) {
	var aborted []security.OperationID
	var writes []ports.AuditEntry
	scannedLog := false
	for _, pid := range dead {
		staged := slices.Collect(maps.Keys(c.locks[pid].active))
		if len(staged) == 0 {
			continue
		}
		slices.SortFunc(staged, security.OperationID.Compare)
		if !scannedLog {
			c.auditLogScans.Add(1)
			scannedLog = true
		}
		ents, ops, bErr := c.buildAbortedLocked(pid, staged, now)
		if bErr != nil {
			return out, bErr
		}
		writes, aborted = append(writes, ents...), append(aborted, ops...)
	}
	if len(writes) > 0 && c.enospc.Load() {
		return out, fmt.Errorf("%w: %w", ports.ErrAuditWriteFailed, ErrSimulatedENOSPC)
	}
	c.entries = append(c.entries, writes...)
	for _, pid := range dead {
		delete(c.locks, pid)
	}
	return ports.NewCrashReconcileReport(ports.CrashReconcileReportSpec{ScannedLocks: scanned, LiveLocksSkipped: liveSkipped, DeadLocksClaimed: len(dead), AbortedOperations: aborted})
}
func (c *SimAuditCluster) buildAbortedLocked(pid ports.ProcessInstanceID, staged []security.OperationID, now time.Time) (outE []ports.AuditEntry, outOps []security.OperationID, err error) {
	authByOp, finalized := make(map[security.OperationID]ports.AuditEntry), make(map[security.OperationID]bool)
	for _, e := range c.entries {
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

// SimAuditSink 表示单个进程持有的只追加审计接收器，实现 ports.AuditSink，支持 SIGKILL 与边界钩子。
//
//xops:opaque
//xops:failclosed
type SimAuditSink struct {
	cluster             *SimAuditCluster
	procID              ports.ProcessInstanceID
	initialized, closed bool
	onBoundary          func(b AuditBoundary, opID security.OperationID)
}

// SetBoundaryHook / ProcessInstanceID / StageOperation / UnstageOperation / Record / Close / SimulateSIGKILL。
func (s *SimAuditSink) SetBoundaryHook(fn func(b AuditBoundary, opID security.OperationID)) {
	if s != nil && s.initialized {
		s.cluster.withLock(func() { s.onBoundary = fn })
	}
}
func (s *SimAuditSink) ProcessInstanceID() (out ports.ProcessInstanceID) {
	if s != nil && s.initialized {
		return s.procID
	}
	return out
}
func (s *SimAuditSink) StageOperation(ctx context.Context, opID security.OperationID) error {
	return s.mutateLock(ctx, opID, true)
}
func (s *SimAuditSink) UnstageOperation(ctx context.Context, opID security.OperationID) error {
	return s.mutateLock(ctx, opID, false)
}
func (s *SimAuditSink) Close() error     { return s.terminate(false) }
func (s *SimAuditSink) SimulateSIGKILL() { _ = s.terminate(true) }

func (s *SimAuditSink) mutateLock(ctx context.Context, opID security.OperationID, stage bool) error {
	opName, bnd := "audit.unstage", AuditBoundaryAfterUnstage
	if stage {
		opName, bnd = "audit.stage", AuditBoundaryAfterStage
	}
	hook, err := s.applyLocked(ctx, opID.IsValid(), ports.ErrInvalidArgument, func() error {
		if fErr := s.checkWriteFault(opName); fErr != nil {
			return fmt.Errorf("%w: %w", ports.ErrAuditWriteFailed, fErr)
		}
		return nil
	}, func(lk *simProcLock) {
		if stage {
			lk.active[opID] = true
		} else if lk.active[opID] {
			delete(lk.active, opID)
			if len(lk.active) == 0 {
				s.cluster.truncations.Add(1)
			}
		}
	})
	if err == nil && hook != nil {
		hook(bnd, opID)
	}
	return err
}
func (s *SimAuditSink) Record(ctx context.Context, entry ports.AuditEntry) error {
	hook, err := s.applyLocked(ctx, entry.IsValid(), ports.ErrInvalidAuditEntry, func() error { return s.checkRecordFault(entry) }, func(*simProcLock) { s.cluster.entries = append(s.cluster.entries, entry) })
	if err == nil && hook != nil {
		if entry.Phase() == ports.AuditPhaseAuthorized {
			hook(AuditBoundaryAfterAuthorized, entry.OperationID())
		} else if entry.Phase() == ports.AuditPhaseFinalized {
			hook(AuditBoundaryAfterFinalized, entry.OperationID())
		}
	}
	return err
}
func (s *SimAuditSink) applyLocked(ctx context.Context, argOK bool, argErr error, faultFn func() error, mutateFn func(*simProcLock)) (func(AuditBoundary, security.OperationID), error) {
	if s == nil || !s.initialized {
		return nil, ErrSimNotInitialized
	}
	if err := checkCtx(ctx); err != nil || !argOK {
		return nil, firstErr(err, argErr)
	}
	c := s.cluster
	c.mu.Lock()
	defer c.mu.Unlock()
	lk := c.locks[s.procID]
	if s.closed || lk == nil || !lk.live {
		return nil, ports.ErrClosed
	}
	if err := faultFn(); err != nil {
		return nil, err
	}
	mutateFn(lk)
	return s.onBoundary, nil
}
func (s *SimAuditSink) terminate(crash bool) error {
	if s == nil || !s.initialized {
		return ErrSimNotInitialized
	}
	s.cluster.withLock(func() {
		if lk := s.cluster.locks[s.procID]; lk != nil && (crash || (!s.closed && lk.live)) {
			lk.live = false
			if !crash {
				delete(s.cluster.locks, s.procID)
			}
		}
		s.closed = true
	})
	return nil
}
func (s *SimAuditSink) checkWriteFault(op string) error {
	if s.cluster.enospc.Load() {
		return ErrSimulatedENOSPC
	}
	return s.cluster.faults.Check(op)
}
func (s *SimAuditSink) checkRecordFault(entry ports.AuditEntry) error {
	err := firstErr(s.checkWriteFault("audit.record."+entry.Phase().String()), s.cluster.faults.Check("audit.record"))
	if err == nil {
		return nil
	}
	if entry.Phase() == ports.AuditPhaseFinalized {
		if pw, pwErr := ports.NewAuditPostWriteError(entry.OperationID(), err); pwErr == nil {
			return pw
		}
		return fmt.Errorf("%w: %w", ports.ErrAuditPostWrite, err)
	}
	return fmt.Errorf("%w: %w", ports.ErrAuditWriteFailed, err)
}
