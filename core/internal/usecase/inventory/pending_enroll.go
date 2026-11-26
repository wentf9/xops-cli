package inventory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/ports"
)

// PendingProbeFunc、PendingEnrollmentRequest、PendingEnrollmentResult 与 PendingEnrollmentLease 定义首连暂存租约契约。
type (
	PendingProbeFunc         func(ctx context.Context) (inventory.KeyFingerprint, error)
	PendingEnrollmentRequest struct {
		Host             algebraic.Option[inventory.Host]
		Identity         algebraic.Option[inventory.Identity]
		Node             inventory.Node
		PinnedRefs       []secret.Ref
		ExtraPending     []inventory.PendingSecretRef
		ExpectedRevision algebraic.Option[ports.Revision]
		TTL              algebraic.Duration
		ScopeSummary     string
		Risk             algebraic.Option[security.RiskLevel]
		Approval         algebraic.Option[gate.ApprovalSubmission]
		OperationStream  *events.OperationStream
	}
	//xops:opaque
	//xops:failclosed
	PendingEnrollmentResult struct {
		phase      fsm.PendingEnrollPhase
		leaseID    security.OperationID
		targetNode inventory.NodeID
		hostKeyFP  algebraic.Option[inventory.KeyFingerprint]
		revision   algebraic.Option[ports.Revision]
		durability algebraic.Option[ports.DurabilityOutcome]
		events     []fsm.PendingEnrollEvent
		reason     string
		valid      bool
	}
	//xops:opaque
	//xops:failclosed
	PendingEnrollmentLease struct {
		mu                      sync.Mutex
		svc                     *Service
		req                     PendingEnrollmentRequest
		state                   fsm.PendingEnrollState
		emitter                 *invOpEmitter
		revision                algebraic.Option[ports.Revision]
		durability              algebraic.Option[ports.DurabilityOutcome]
		events                  []fsm.PendingEnrollEvent
		unknownCode, unknownMsg string
		expired, valid          bool
	}
)

// PendingEnrollmentResult 与 PendingEnrollmentLease 零值安全只读访问器。
func (r PendingEnrollmentResult) IsValid() bool {
	return r.valid && r.phase.IsValid() && r.leaseID.IsValid() && r.targetNode.IsValid()
}
func (r PendingEnrollmentResult) IsZero() bool                  { return !r.IsValid() }
func (r PendingEnrollmentResult) Phase() fsm.PendingEnrollPhase { return r.phase }
func (r PendingEnrollmentResult) LeaseID() security.OperationID { return r.leaseID }
func (r PendingEnrollmentResult) TargetNode() inventory.NodeID  { return r.targetNode }
func (r PendingEnrollmentResult) HostKeyFingerprint() algebraic.Option[inventory.KeyFingerprint] {
	return r.hostKeyFP
}
func (r PendingEnrollmentResult) Revision() algebraic.Option[ports.Revision] { return r.revision }
func (r PendingEnrollmentResult) Durability() algebraic.Option[ports.DurabilityOutcome] {
	return r.durability
}
func (r PendingEnrollmentResult) Events() []fsm.PendingEnrollEvent { return slices.Clone(r.events) }
func (r PendingEnrollmentResult) Reason() string                   { return r.reason }
func leaseRead[T any](l *PendingEnrollmentLease, fn func(*PendingEnrollmentLease) T) T {
	if l == nil {
		return zeroVal[T]()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return fn(l)
}
func (l *PendingEnrollmentLease) IsValid() bool {
	return leaseRead(l, func(x *PendingEnrollmentLease) bool { return x.valid && !x.expired && x.state.IsValid() })
}
func (l *PendingEnrollmentLease) Phase() fsm.PendingEnrollPhase {
	return leaseRead(l, func(x *PendingEnrollmentLease) fsm.PendingEnrollPhase { return x.state.Phase() })
}
func (l *PendingEnrollmentLease) LeaseID() security.OperationID {
	return leaseRead(l, func(x *PendingEnrollmentLease) security.OperationID { return x.state.Context().LeaseID() })
}
func (l *PendingEnrollmentLease) TargetNode() inventory.NodeID {
	return leaseRead(l, func(x *PendingEnrollmentLease) inventory.NodeID { return x.state.Context().TargetNode() })
}
func (l *PendingEnrollmentLease) PinnedRefs() []secret.Ref {
	return leaseRead(l, func(x *PendingEnrollmentLease) []secret.Ref { return x.state.Context().PinnedRefs() })
}

// WithPendingEnrollment 在同步闭包内严格驱动 fsm.PendingEnrollFSM 完成「先验证后入库」首连登记：
// 暂存凭据全程钉住防 GC；跳过 Probe 直接 Commit 被 FSM 物理拒绝；未提交退出/失败/过期/panic 自动清理无引用暂存凭据；
// 遇 AppliedNotDurable 或 OutcomeUnknown 停机于 PendingEnrollPhaseUncertain 且保留钉住绝不误删。
//
//xops:syncclosure
//xops:borrowed
func (s *Service) WithPendingEnrollment(ctx context.Context, req PendingEnrollmentRequest, fn func(ctx context.Context, lease *PendingEnrollmentLease) error) (PendingEnrollmentResult, error) {
	if err := s.validatePendingEnrollRequest(ctx, req, fn); err != nil {
		closeIfNonNil(req.OperationStream)
		return PendingEnrollmentResult{}, err
	}
	summary := pickIf(req.ScopeSummary != "", req.ScopeSummary, "pending enrollment "+req.Node.ID().String())
	return runMutate(ctx, s, "pending_enrollment", req.Node.ID().String(), summary, req.Risk, req.Approval, req.OperationStream, func(authCtx context.Context, traceID security.TraceID, leaseID security.OperationID) (PendingEnrollmentResult, string, string, error) {
		return s.runPendingEnrollmentScope(authCtx, traceID, leaseID, req, summary, fn)
	})
}

func (s *Service) validatePendingEnrollRequest(ctx context.Context, req PendingEnrollmentRequest, fn func(context.Context, *PendingEnrollmentLease) error) error {
	if err := s.requireStoreAndGate(ctx, req.Risk); err != nil {
		return err
	}
	h, hasH := req.Host.Get()
	id, hasI := req.Identity.Get()
	rev, hasR := req.ExpectedRevision.Get()
	switch {
	case s.clock == nil:
		return ErrClockUnavailable
	case fn == nil:
		return ErrNilCallback
	case len(req.PinnedRefs) > 0 && s.vault == nil:
		return ErrVaultUnavailable
	case !req.Node.IsValid() || req.TTL.IsNegative() || (hasH && !h.IsValid()) || (hasI && !id.IsValid()) || (hasR && !rev.IsValid()):
		return fmt.Errorf("%w: 首连暂存登记请求参数无效", ErrInvalidRequest)
	}
	_, err := s.mergePendingRefsExcluding(zeroVal[security.OperationID](), req.ExtraPending)
	return err
}

func (s *Service) runPendingEnrollmentScope(
	ctx context.Context, traceID security.TraceID, leaseID security.OperationID,
	req PendingEnrollmentRequest, summary string, fn func(context.Context, *PendingEnrollmentLease) error,
) (res PendingEnrollmentResult, unkCode, unkDetail string, finalErr error) {
	enrollCtx, err := fsm.NewPendingEnrollContext(fsm.PendingEnrollContextSpec{
		LeaseID: leaseID, TargetNode: req.Node.ID(), PinnedRefs: req.PinnedRefs,
		StagedAt: s.clock.Now().UTC().Round(0), TTL: pickIf(req.TTL.IsZero(), s.defaultEnrollTTL, req.TTL),
	})
	if err != nil {
		return PendingEnrollmentResult{}, "", "", fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	emitter, startedAt := newInvOpEmitter(req.OperationStream, s.clock, traceID, leaseID, req.Node.ID()), s.clock.Now()
	emitter.emitLifecycle(ctx, "pending_enrollment", summary, algebraic.None[time.Time](), nil)
	lease := &PendingEnrollmentLease{svc: s, req: req, state: fsm.NewPendingEnrollState(), emitter: emitter, valid: true}
	stageIn, err := fsm.EnrollInputStage(enrollCtx)
	if err == nil {
		err = lease.stepAndHandleEffectsLocked(ctx, stageIn)
	}
	if err != nil {
		emitter.emitLifecycle(ctx, "pending_enrollment", summary, algebraic.Some(startedAt), err)
		return PendingEnrollmentResult{}, "", "", err
	}
	returnedNormally := false
	defer func() {
		lease.mu.Lock()
		lease.expired = true
		if !lease.state.IsTerminal() {
			reason := pickIf(finalErr != nil, fmt.Sprint(finalErr), pickIf(returnedNormally, "scope exited without commit", "scope panicked"))
			if cleanErr := lease.abortUnfinishedLocked(context.WithoutCancel(ctx), reason); finalErr == nil && cleanErr != nil {
				finalErr = cleanErr
			}
		}
		res, unkCode, unkDetail = lease.snapshotResultLocked(), lease.unknownCode, lease.unknownMsg
		lease.mu.Unlock()
		emitter.emitLifecycle(ctx, "pending_enrollment", summary, algebraic.Some(startedAt), finalErr)
	}()
	finalErr = fn(ctx, lease)
	returnedNormally = true
	return PendingEnrollmentResult{}, "", "", finalErr
}

// Probe 驱动 Staged -> Probing -> Verified（失败或过期自动清理回滚至 Aborted/Uncertain）。
func (l *PendingEnrollmentLease) Probe(ctx context.Context, probeFn PendingProbeFunc) (inventory.KeyFingerprint, error) {
	if probeFn == nil {
		return zeroVal[inventory.KeyFingerprint](), ErrNilCallback
	}
	unlock, err := l.lockAndEnterPhase(ctx, fsm.EnrollInputStartProbe, fsm.PendingEnrollPhaseProbing)
	if err != nil {
		return zeroVal[inventory.KeyFingerprint](), err
	}
	defer unlock()
	fp, probeErr := probeFn(ctx)
	ok := probeErr == nil && fp.IsValid()
	resIn, err := fsm.EnrollInputProbeResult(ok, fp, l.svc.clock.Now(), pickIf(ok, "", pickIf(probeErr != nil, fmt.Sprint(probeErr), "probe returned invalid host key fingerprint")))
	if err == nil {
		err = l.stepAndHandleEffectsLocked(ctx, resIn)
	}
	if err != nil {
		return zeroVal[inventory.KeyFingerprint](), err
	}
	if l.state.Phase() != fsm.PendingEnrollPhaseVerified {
		return zeroVal[inventory.KeyFingerprint](), l.terminalErrorLocked(probeErr)
	}
	return fp, nil
}

// Commit 驱动 Verified -> Committing -> Enrolled（跳过 Probe 直接提交由 FSM 返回 fsm.ErrIllegalTransition）。
func (l *PendingEnrollmentLease) Commit(ctx context.Context) (ports.Revision, error) {
	unlock, err := l.lockAndEnterPhase(ctx, fsm.EnrollInputCommit, fsm.PendingEnrollPhaseCommitting)
	if err != nil {
		return zeroVal[ports.Revision](), err
	}
	defer unlock()
	durStatus, newRev, durOut, causeErr := l.executeCommitCASLocked(ctx)
	if newRev.IsValid() {
		l.revision = algebraic.Some(newRev)
	}
	if durOut.IsValid() {
		l.durability = algebraic.Some(durOut)
	}
	resIn, err := fsm.EnrollInputCommitResult(durStatus, pickIf(causeErr != nil, fmt.Sprint(causeErr), ""))
	if err == nil {
		err = l.stepAndHandleEffectsLocked(ctx, resIn)
	}
	if err != nil {
		return zeroVal[ports.Revision](), err
	}
	if l.state.Phase() != fsm.PendingEnrollPhaseEnrolled {
		return zeroVal[ports.Revision](), l.terminalErrorLocked(causeErr)
	}
	return newRev, nil
}

// Cancel 显式中止尚未终结的首连暂存租约并自动清理无引用暂存凭据与钉住。
func (l *PendingEnrollmentLease) Cancel(ctx context.Context, reason string) error {
	unlock, err := l.lockActive(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	return l.stepAndHandleEffectsLocked(ctx, fsm.EnrollInputCancel(reason))
}

func (l *PendingEnrollmentLease) lockAndEnterPhase(ctx context.Context, makeIn func(time.Time) (fsm.PendingEnrollInput, error), want fsm.PendingEnrollPhase) (func(), error) {
	unlock, err := l.lockActive(ctx)
	if err != nil {
		return nil, err
	}
	in, err := makeIn(l.svc.clock.Now())
	if err == nil {
		err = l.stepAndHandleEffectsLocked(ctx, in)
	}
	if err != nil || l.state.Phase() != want {
		tErr := pickIf(err != nil, err, l.terminalErrorLocked(nil))
		unlock()
		return nil, tErr
	}
	return unlock, nil
}
func (l *PendingEnrollmentLease) lockActive(ctx context.Context) (func(), error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if l == nil {
		return nil, ErrLeaseExpired
	}
	l.mu.Lock()
	if !l.valid || l.expired {
		l.mu.Unlock()
		return nil, ErrLeaseExpired
	}
	return l.mu.Unlock, nil
}
func (l *PendingEnrollmentLease) abortUnfinishedLocked(ctx context.Context, reason string) error {
	if now := l.svc.clock.Now(); l.state.Context().IsExpiredAt(now) {
		if expIn, err := fsm.EnrollInputExpire(now); err == nil && l.stepAndHandleEffectsLocked(ctx, expIn) == nil {
			return nil
		}
	}
	return l.stepAndHandleEffectsLocked(ctx, fsm.EnrollInputCancel(reason))
}
func (l *PendingEnrollmentLease) stepAndHandleEffectsLocked(ctx context.Context, in fsm.PendingEnrollInput) error {
	from := l.state.Phase()
	next, effs, evs, err := fsm.TransitionPendingEnroll(l.state, in)
	if err != nil {
		return err
	}
	l.state, l.events = next, append(l.events, evs...)
	for _, fev := range evs {
		l.emitter.emit(ctx, func(m events.EventMeta) (events.Event, error) {
			return events.NewPendingEnrollTransitionEvent(m, from, next.Phase(), fev, next.IsTerminal())
		})
	}
	for _, eff := range effs {
		switch eff.Kind() {
		case fsm.EnrollEffectPinSecrets:
			l.svc.updatePendingPins(next.Context().LeaseID(), next.Context().PendingSecretRefs())
		case fsm.EnrollEffectReleasePins:
			l.svc.updatePendingPins(next.Context().LeaseID(), nil)
		case fsm.EnrollEffectCleanupPendingSecrets:
			outcome, cleanErr := l.cleanupPendingSecretsLocked(ctx, eff.Refs())
			cIn, cErr := fsm.EnrollInputCleanupResult(outcome, pickIf(cleanErr != nil, fmt.Sprint(cleanErr), ""))
			if cErr != nil {
				return cErr
			}
			if tErr := l.stepAndHandleEffectsLocked(ctx, cIn); tErr != nil {
				return tErr
			}
		}
	}
	return nil
}
func (l *PendingEnrollmentLease) executeCommitCASLocked(ctx context.Context) (st fsm.DurabilityStatus, newRev ports.Revision, out ports.DurabilityOutcome, err error) {
	snap, err := l.svc.loadSnapshotAt(ctx, l.req.ExpectedRevision)
	if err != nil {
		return fsm.DurabilityNotApplied, newRev, out, err
	}
	nextGraph, err := l.buildEnrollmentGraphLocked(ctx, snap.Graph())
	if err != nil {
		return fsm.DurabilityNotApplied, newRev, out, err
	}
	newRev, out, unkCode, err := l.svc.commitGraphCAS(ctx, snap.Revision(), nextGraph, "enroll_commit_missing_revision")
	if err == nil {
		return fsm.DurabilityCommitted, newRev, out, nil
	}
	l.recordUnknownLocked(unkCode, err)
	st = pickIf(errors.Is(err, ErrUncertainDurability), fsm.DurabilityAppliedNotDurable,
		pickIf(errors.Is(err, ErrCommitOutcomeUnknown), fsm.DurabilityOutcomeUnknown, fsm.DurabilityNotApplied))
	return st, newRev, out, err
}
func (l *PendingEnrollmentLease) buildEnrollmentGraphLocked(ctx context.Context, g inventory.Graph) (inventory.Graph, error) {
	hosts, err := mergeStagedAsset(g.Hosts(), l.req.Host, "host", func(a, b inventory.Host) bool { return a.ID().Equal(b.ID()) }, inventory.Host.Equal, func(h inventory.Host) string { return h.ID().String() })
	var idents []inventory.Identity
	if err == nil {
		idents, err = mergeStagedAsset(g.Identities(), l.req.Identity, "identity", func(a, b inventory.Identity) bool { return a.ID().Equal(b.ID()) }, inventory.Identity.Equal, func(i inventory.Identity) string { return i.ID().String() })
	}
	var nodes []inventory.Node
	if err == nil {
		nodes, _, err = upsertAsset(g.Nodes(), l.req.Node, false, "node", l.req.Node.ID().String(), func(n inventory.Node) bool { return n.ID().Equal(l.req.Node.ID()) })
	}
	next, _, bErr := l.svc.finishGraph(ctx, g, hosts, idents, nodes, nil, err)
	return next, bErr
}
func mergeStagedAsset[T any](items []T, staged algebraic.Option[T], kind string, sameID, equal func(T, T) bool, idStr func(T) string) ([]T, error) {
	val, ok := staged.Get()
	if !ok {
		return items, nil
	}
	if idx := slices.IndexFunc(items, func(x T) bool { return sameID(x, val) }); idx < 0 {
		return append(items, val), nil
	} else if !equal(items[idx], val) {
		return nil, fmt.Errorf("%w: %s %q", ErrAssetAlreadyExists, kind, idStr(val))
	}
	return items, nil
}
func (l *PendingEnrollmentLease) cleanupPendingSecretsLocked(ctx context.Context, refs []secret.Ref) (fsm.SideEffectOutcome, error) {
	if len(refs) == 0 {
		return fsm.SideEffectSucceeded, nil
	}
	snap, err := l.svc.store.Load(ctx)
	if err != nil {
		l.recordUnknownLocked("enroll_cleanup_load_failed", err)
		return fsm.SideEffectFailedNotApplied, err
	}
	otherPending, err := l.svc.mergePendingRefsExcluding(l.state.Context().LeaseID(), l.req.ExtraPending)
	if err != nil {
		return fsm.SideEffectFailedNotApplied, err
	}
	for _, ref := range deduplicateRefs(refs) {
		if canGC, _ := snap.Graph().CanGCSecret(ref, otherPending...); !canGC {
			continue
		}
		if delErr := l.svc.vault.Delete(ctx, ref); delErr != nil && !errors.Is(delErr, ports.ErrSecretNotFound) {
			l.recordUnknownLocked("enroll_cleanup_delete_failed", delErr)
			return fsm.SideEffectOutcomeUnknown, delErr
		}
	}
	return fsm.SideEffectSucceeded, nil
}
func (l *PendingEnrollmentLease) recordUnknownLocked(code string, err error) {
	if code != "" && l.unknownCode == "" && err != nil {
		l.unknownCode, l.unknownMsg = code, err.Error()
	}
}
func (l *PendingEnrollmentLease) terminalErrorLocked(cause error) error {
	base := pickIf(l.state.Phase() == fsm.PendingEnrollPhaseUncertain, ErrEnrollmentUncertain, ErrEnrollmentAborted)
	return wrapCommitError(base, l.state.Reason(), cause)
}
func (l *PendingEnrollmentLease) snapshotResultLocked() PendingEnrollmentResult {
	return PendingEnrollmentResult{l.state.Phase(), l.state.Context().LeaseID(), l.state.Context().TargetNode(), l.state.HostKeyFingerprint(), l.revision, l.durability, slices.Clone(l.events), l.state.Reason(), true}
}
func (s *Service) updatePendingPins(leaseID security.OperationID, pins []inventory.PendingSecretRef) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	if len(pins) == 0 {
		delete(s.activePins, leaseID)
	} else {
		s.activePins[leaseID] = slices.Clone(pins)
	}
}
