package sim

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/sim/memtree"
	"github.com/wentf9/xops-cli/core/ports"
	"io"
	"slices"
	"sync/atomic"
	"time"
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

// SimAuditCluster 模拟多进程共享的 audit.jsonl 与 run/<ProcessInstanceID>.lock 目录（ADR-008 / RFC §3.4），
// 实现 ports.AuditReconciler：无死亡锁 O(1) 零读取 audit.jsonl，遇死亡锁按活跃差集补写唯一 AbortedByCrash。
//
//xops:opaque
//xops:failclosed
type SimAuditCluster struct {
	simBase
	enospc                     atomic.Bool
	ledger                     *memtree.AuditLedger
	auditLogScans, truncations atomic.Uint64
}

// NewSimAuditCluster 创建空白的共享审计集群仿真器。
func NewSimAuditCluster() *SimAuditCluster {
	return &SimAuditCluster{simBase: newSimBase(nil), ledger: memtree.NewAuditLedger()}
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
	return withLockRet(&c.simBase, nil, func() []ports.AuditEntry { return slices.Clone(c.ledger.Entries) })
}
func (c *SimAuditCluster) Digest() (sum [sha256.Size]byte, err error) {
	if !c.ok() {
		return sum, ErrSimNotInitialized
	}
	return memtree.DigestAuditEntries(c.Entries())
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
	err := c.ledger.AcquireLockLocked(procID)
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
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
	return c.ledger.ReconcileLocked(now, c.enospc.Load(), ErrSimulatedENOSPC, func() { c.auditLogScans.Add(1) })
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
	}, func(lk *memtree.ProcLock) {
		if s.cluster.ledger.MutateLockLocked(lk, opID, stage) {
			s.cluster.truncations.Add(1)
		}
	})
	if err == nil && hook != nil {
		hook(bnd, opID)
	}
	return err
}
func (s *SimAuditSink) Record(ctx context.Context, entry ports.AuditEntry) error {
	hook, err := s.applyLocked(ctx, entry.IsValid(), ports.ErrInvalidAuditEntry, func() error { return s.checkRecordFault(entry) }, func(*memtree.ProcLock) { s.cluster.ledger.Entries = append(s.cluster.ledger.Entries, entry) })
	if err == nil && hook != nil {
		if entry.Phase() == ports.AuditPhaseAuthorized {
			hook(AuditBoundaryAfterAuthorized, entry.OperationID())
		} else if entry.Phase() == ports.AuditPhaseFinalized {
			hook(AuditBoundaryAfterFinalized, entry.OperationID())
		}
	}
	return err
}
func (s *SimAuditSink) applyLocked(ctx context.Context, argOK bool, argErr error, faultFn func() error, mutateFn func(*memtree.ProcLock)) (func(AuditBoundary, security.OperationID), error) {
	if s == nil || !s.initialized {
		return nil, ErrSimNotInitialized
	}
	if err := checkCtx(ctx); err != nil || !argOK {
		return nil, firstErr(err, argErr)
	}
	c := s.cluster
	c.mu.Lock()
	defer c.mu.Unlock()
	lk := c.ledger.Locks[s.procID]
	if s.closed || lk == nil || !lk.Live {
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
		s.cluster.ledger.TerminateLockLocked(s.procID, s.closed, crash)
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
