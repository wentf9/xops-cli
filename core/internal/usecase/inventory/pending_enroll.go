package inventory

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/usecase/credential"
	"github.com/wentf9/xops-cli/core/ports"
)

// 首连暂存登记契约类型定义（PendingProbeFunc、PendingEnrollmentRequest、PendingEnrollmentResult 与 PendingEnrollmentLease）。
type (
	// PendingProbeFunc 定义首连暂存阶段执行远端主机公钥探测与认证验证的回调函数。
	PendingProbeFunc func(ctx context.Context) (inventory.KeyFingerprint, error)
	// PendingEnrollmentRequest 描述「先验证后入库」首连暂存租约的授权请求参数。
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
	// PendingEnrollmentResult 封装首连暂存租约终结后的不可变结果快照；零值恒无效。
	//
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
	// PendingEnrollmentLease 是仅限 WithPendingEnrollment 同步闭包内借用的首连暂存租约句柄。
	// 锁不变式：mu 仅保护纯内存 FSM 字段，严禁在持锁态调用 probeFn、存储/Vault I/O、s.pendingMu 或 OperationStream.Emit。
	//
	//xops:opaque
	//xops:failclosed
	PendingEnrollmentLease struct {
		mu                      sync.Mutex
		svc                     *Service
		req                     PendingEnrollmentRequest
		state                   fsm.PendingEnrollState
		emitter                 *credential.OpEmitter
		revision                algebraic.Option[ports.Revision]
		durability              algebraic.Option[ports.DurabilityOutcome]
		events                  []fsm.PendingEnrollEvent
		unknownCode, unknownMsg string
		expired, valid          bool
	}
	pendingStepSnapshot struct {
		from, to fsm.PendingEnrollPhase
		terminal bool
		leaseID  security.OperationID
		pins     []inventory.PendingSecretRef
		effs     []fsm.PendingEnrollEffect
		evs      []fsm.PendingEnrollEvent
	}
)

// PendingEnrollmentResult 只读访问器（零值恒无效）。
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

func leaseRead[T any](l *PendingEnrollmentLease, fn func(*PendingEnrollmentLease) T) (z T) {
	if l == nil {
		return z
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return fn(l)
}

// PendingEnrollmentLease 并发安全只读访问器（Probe/Commit 期间无锁，可无阻塞实时观测租约状态）。
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
// 暂存凭据全程钉住防 GC；跳过 Probe 直接 Commit 被 FSM 物理拒绝；未提交退出、Cancel、失败、过期或 panic
// 均在有界非取消上下文中自动清理独占暂存凭据并严格失败关闭返回非空错误；遇 Uncertain 保留钉住并上报 AuditOutcomeUnknown。
//
//xops:syncclosure
//xops:borrowed
func (s *Service) WithPendingEnrollment(ctx context.Context, req PendingEnrollmentRequest, fn func(ctx context.Context, lease *PendingEnrollmentLease) error) (res PendingEnrollmentResult, gateErr error) {
	defer closeIfNonNil(req.OperationStream)
	if err := s.validatePendingEnrollRequest(ctx, req, fn); err != nil {
		return res, err
	}
	summary := pickIf(req.ScopeSummary != "", req.ScopeSummary, "pending enrollment "+req.Node.ID().String())
	gateReq, err := credential.BuildGateRequest[security.CapMutate](security.CapabilityMutate, toolInventory, "pending_enrollment", req.Node.ID().String(), nil, req.Risk.OrElse(security.RiskModerate), summary, req.Approval, req.OperationStream)
	if err != nil {
		return res, domi18n.WrapSentinel(ErrInvalidRequest, err)
	}
	var (
		emitter    *credential.OpEmitter
		startedAt  time.Time
		outcomeOpt algebraic.Option[execution.ExecutionOutcome]
	)
	returnedNormally := false
	// 终态 OperationCompletedEvent 置于 gate.WithAuthorized 外层 defer，捕获真实 gateErr（含 AuditPostWriteError）、OutcomeUnknown 及 panic。
	defer func() {
		emitter.EmitFinal(ctx, security.CapabilityMutate, startedAt, outcomeOpt, returnedNormally, "pending enrollment panicked", gateErr)
	}()
	gateErr = gate.WithAuthorized[security.CapMutate](ctx, s.gate, gateReq, func(c context.Context, auth gate.Authorized[security.CapMutate]) (runErr error) {
		startedAt = s.clock.Now().UTC().Round(0)
		emitter = credential.NewOpEmitter(req.OperationStream, s.clock, toolInventory, auth.TraceID(), auth.OperationID(), req.Node.ID().String())
		emitter.EmitStarted(c, security.CapabilityMutate, "pending_enrollment", summary)
		var unkCode, unkDetail string
		// 在 defer 中向 Gate 上报 OutcomeUnknown，确保 CommitCAS 期间 panic 展开时仍向审计账本写入 AuditOutcomeUnknown。
		defer func() { outcomeOpt = credential.ReportOutcomeUnknown(auth, unkCode, unkDetail) }()
		res, runErr = s.runPendingEnrollmentScope(c, auth.OperationID(), req, emitter, &unkCode, &unkDetail, fn)
		return runErr
	})
	returnedNormally = true
	return res, gateErr
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
		return domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "PendingEnrollmentRequest"))
	default:
		return validateExtraPending(req.ExtraPending)
	}
}
func (s *Service) runPendingEnrollmentScope(ctx context.Context, leaseID security.OperationID, req PendingEnrollmentRequest, emitter *credential.OpEmitter, unkCode, unkDetail *string, fn func(context.Context, *PendingEnrollmentLease) error) (res PendingEnrollmentResult, finalErr error) {
	enrollCtx, err := fsm.NewPendingEnrollContext(fsm.PendingEnrollContextSpec{
		LeaseID: leaseID, TargetNode: req.Node.ID(), PinnedRefs: req.PinnedRefs,
		StagedAt: s.clock.Now().UTC().Round(0), TTL: pickIf(req.TTL.IsZero(), s.defaultEnrollTTL, req.TTL),
	})
	if err != nil {
		return res, domi18n.WrapSentinel(ErrInvalidRequest, err)
	}
	lease := &PendingEnrollmentLease{svc: s, req: req, state: fsm.NewPendingEnrollState(), emitter: emitter, valid: true}
	if err = lease.driveNew(ctx, false, func() (fsm.PendingEnrollInput, error) { return fsm.EnrollInputStage(enrollCtx) }); err != nil {
		return res, err
	}
	returnedNormally := false
	defer func() {
		lease.finishScopeDefer(ctx, returnedNormally, &finalErr)
		res, *unkCode, *unkDetail = lease.snapshotFinal()
		if returnedNormally && finalErr == nil && res.Phase() != fsm.PendingEnrollPhaseEnrolled {
			finalErr = lease.terminalError(nil) // 未达 Enrolled 终态时必须失败关闭，严禁伪造成功审计与事件
		}
	}()
	finalErr = fn(ctx, lease)
	returnedNormally = true
	return res, finalErr
}

// Probe 驱动 Staged -> Probing -> Verified：仅在纯内存跃迁期持锁，probeFn 在无锁态同步执行；
// 探测失败、取消或超时均在有界非取消上下文中自动清理独占暂存凭据并进入 Aborted（仅本地清理故障进 Uncertain）。
//
//xops:syncclosure
func (l *PendingEnrollmentLease) Probe(ctx context.Context, probeFn PendingProbeFunc) (z inventory.KeyFingerprint, err error) {
	if probeFn == nil {
		return z, ErrNilCallback
	}
	if err = l.enterPhase(ctx, fsm.EnrollInputStartProbe, fsm.PendingEnrollPhaseProbing); err != nil {
		return z, err
	}
	fp, probeErr := probeFn(ctx) // 锁外调用外部探针回调，允许观测租约状态零自死锁
	ok := probeErr == nil && fp.IsValid()
	reason := pickIf(ok, "", pickIf(probeErr != nil, errMsg(probeErr), "probe returned invalid host key fingerprint"))
	if err = l.finishPhase(ctx, func() (fsm.PendingEnrollInput, error) {
		return fsm.EnrollInputProbeResult(ok, fp, l.svc.clock.Now(), reason)
	}, fsm.PendingEnrollPhaseVerified, probeErr); err != nil {
		return z, err
	}
	return fp, nil
}

// Commit 驱动 Verified -> Committing -> Enrolled（跳过 Probe 直接提交由 FSM 物理拒绝返回 fsm.ErrIllegalTransition）；
// 存储 CAS I/O 全程在无锁态执行，避免阻塞租约状态观测。
func (l *PendingEnrollmentLease) Commit(ctx context.Context) (z ports.Revision, err error) {
	if err = l.enterPhase(ctx, fsm.EnrollInputCommit, fsm.PendingEnrollPhaseCommitting); err != nil {
		return z, err
	}
	durStatus, newRev, durOut, unkCode, causeErr := l.executeCommitCAS(ctx)
	l.recordCommitMeta(newRev, durOut, unkCode, causeErr)
	if err = l.finishPhase(ctx, func() (fsm.PendingEnrollInput, error) {
		return fsm.EnrollInputCommitResult(durStatus, errMsg(causeErr))
	}, fsm.PendingEnrollPhaseEnrolled, causeErr); err != nil {
		return z, err
	}
	return newRev, nil
}

// Cancel 显式中止尚未终结的首连暂存租约并执行有界非取消清理；若清理失败转入 Uncertain 则严格返回 ErrEnrollmentUncertain。
func (l *PendingEnrollmentLease) Cancel(ctx context.Context, reason string) error {
	if ctx == nil {
		return ErrNilContext
	}
	if err := l.driveStep(ctx, fsm.EnrollInputCancel(reason), false); err != nil {
		return err
	}
	return pickIf[error](l.Phase() == fsm.PendingEnrollPhaseUncertain, l.terminalError(nil), nil)
}
func (l *PendingEnrollmentLease) enterPhase(ctx context.Context, makeIn func(time.Time) (fsm.PendingEnrollInput, error), want fsm.PendingEnrollPhase) error {
	if ctx == nil || !l.IsValid() {
		return pickIf(ctx == nil, ErrNilContext, ErrLeaseExpired)
	}
	return l.finishPhase(ctx, func() (fsm.PendingEnrollInput, error) { return makeIn(l.svc.clock.Now()) }, want, nil)
}
func (l *PendingEnrollmentLease) finishPhase(ctx context.Context, makeIn func() (fsm.PendingEnrollInput, error), want fsm.PendingEnrollPhase, causeErr error) error {
	if err := l.driveNew(ctx, false, makeIn); err != nil {
		return err
	}
	if l.Phase() != want {
		return l.terminalError(causeErr)
	}
	return nil
}
func (l *PendingEnrollmentLease) driveNew(ctx context.Context, allowExpired bool, makeIn func() (fsm.PendingEnrollInput, error)) error {
	in, err := makeIn()
	if err != nil {
		return err
	}
	return l.driveStep(ctx, in, allowExpired)
}
func (l *PendingEnrollmentLease) finishScopeDefer(ctx context.Context, returnedNormally bool, finalErr *error) {
	l.mu.Lock()
	l.expired = true
	phase, isTerm := l.state.Phase(), l.state.IsTerminal()
	l.mu.Unlock()
	if isTerm {
		return
	}
	reason := pickIf(*finalErr != nil, errMsg(*finalErr), pickIf(returnedNormally, "scope exited without commit", "scope panicked"))
	if cleanErr := l.convergeUnfinished(ctx, phase, reason); *finalErr == nil && cleanErr != nil {
		*finalErr = cleanErr
	}
}
func (l *PendingEnrollmentLease) convergeUnfinished(ctx context.Context, phase fsm.PendingEnrollPhase, reason string) error {
	switch phase {
	case fsm.PendingEnrollPhaseCommitting:
		// CommitCAS 期间 panic 绝不可投递 Cancel（FSM 拒绝），须按结果未知转入 Uncertain 并保留钉住。
		l.recordCommitMeta(zeroVal[ports.Revision](), zeroVal[ports.DurabilityOutcome](), "enroll_commit_panic", domi18n.E(domi18n.KeyCommonDetail, domi18n.BoundStr("detail", reason)))
		return l.driveNew(ctx, true, func() (fsm.PendingEnrollInput, error) {
			return fsm.EnrollInputCommitResult(fsm.DurabilityOutcomeUnknown, reason)
		})
	case fsm.PendingEnrollPhaseCleaningUp:
		l.recordCommitMeta(zeroVal[ports.Revision](), zeroVal[ports.DurabilityOutcome](), "enroll_cleanup_interrupted", domi18n.E(domi18n.KeyCommonDetail, domi18n.BoundStr("detail", reason)))
		return l.driveNew(ctx, true, func() (fsm.PendingEnrollInput, error) {
			return fsm.EnrollInputCleanupResult(fsm.SideEffectOutcomeUnknown, reason)
		})
	default:
		now := l.svc.clock.Now()
		if leaseRead(l, func(x *PendingEnrollmentLease) bool { return x.state.Context().IsExpiredAt(now) }) && l.driveNew(ctx, true, func() (fsm.PendingEnrollInput, error) { return fsm.EnrollInputExpire(now) }) == nil {
			return nil
		}
		return l.driveStep(ctx, fsm.EnrollInputCancel(reason), true)
	}
}
func (l *PendingEnrollmentLease) stepLocked(in fsm.PendingEnrollInput, allowExpired bool) (pendingStepSnapshot, error) {
	if l == nil {
		return pendingStepSnapshot{}, ErrLeaseExpired
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.valid || (!allowExpired && l.expired) {
		return pendingStepSnapshot{}, ErrLeaseExpired
	}
	from := l.state.Phase()
	next, effs, evs, err := fsm.TransitionPendingEnroll(l.state, in)
	if err != nil {
		return pendingStepSnapshot{}, err
	}
	l.state, l.events = next, append(l.events, evs...)
	return pendingStepSnapshot{
		from: from, to: next.Phase(), terminal: next.IsTerminal(),
		leaseID: next.Context().LeaseID(), pins: next.Context().PendingSecretRefs(), effs: effs, evs: evs,
	}, nil
}

// driveStep 在锁外依次执行事件发射、钉住表维护与有界非取消暂存凭据清理，彻底杜绝持锁重入或 I/O 死锁。
func (l *PendingEnrollmentLease) driveStep(ctx context.Context, in fsm.PendingEnrollInput, allowExpired bool) error {
	curIn, curAllow := in, allowExpired
	for range 4 {
		snap, err := l.stepLocked(curIn, curAllow)
		if err != nil {
			return err
		}
		for _, fev := range snap.evs {
			l.emitter.Emit(ctx, func(m events.EventMeta) (events.Event, error) {
				return events.NewPendingEnrollTransitionEvent(m, snap.from, snap.to, fev, snap.terminal)
			})
		}
		nextIn, hasNext, effErr := l.runStepEffects(ctx, snap)
		if effErr != nil || !hasNext {
			return effErr
		}
		curIn, curAllow = nextIn, true
	}
	return ErrEnrollmentUncertain
}
func (l *PendingEnrollmentLease) runStepEffects(ctx context.Context, snap pendingStepSnapshot) (z fsm.PendingEnrollInput, hasNext bool, err error) {
	for _, eff := range snap.effs {
		switch eff.Kind() {
		case fsm.EnrollEffectPinSecrets:
			l.svc.updatePendingPins(snap.leaseID, snap.pins)
		case fsm.EnrollEffectReleasePins:
			l.svc.updatePendingPins(snap.leaseID, nil)
		case fsm.EnrollEffectCleanupPendingSecrets:
			outcome, cleanErr := l.cleanupPendingSecrets(ctx, snap.leaseID, eff.Refs())
			cIn, cErr := fsm.EnrollInputCleanupResult(outcome, errMsg(cleanErr))
			return cIn, cErr == nil, cErr
		}
	}
	return z, false, nil
}
func (l *PendingEnrollmentLease) executeCommitCAS(ctx context.Context) (st fsm.DurabilityStatus, newRev ports.Revision, out ports.DurabilityOutcome, unkCode string, err error) {
	snap, err := l.svc.loadSnapshotAt(ctx, l.req.ExpectedRevision)
	var nextGraph inventory.Graph
	if err == nil {
		nextGraph, err = l.buildEnrollmentGraph(ctx, snap.Graph())
	}
	if err != nil {
		return fsm.DurabilityNotApplied, newRev, out, "", err
	}
	return l.svc.commitGraphCAS(ctx, snap.Revision(), nextGraph, "enroll_commit_missing_revision")
}
func (l *PendingEnrollmentLease) buildEnrollmentGraph(ctx context.Context, g inventory.Graph) (inventory.Graph, error) {
	hosts, err := mergeStagedAsset(g.Hosts(), l.req.Host, "host", func(a, b inventory.Host) bool { return a.ID().Equal(b.ID()) }, inventory.Host.Equal, func(h inventory.Host) string { return h.ID().String() })
	var idents []inventory.Identity
	if err == nil {
		idents, err = mergeStagedAsset(g.Identities(), l.req.Identity, "identity", func(a, b inventory.Identity) bool { return a.ID().Equal(b.ID()) }, inventory.Identity.Equal, func(i inventory.Identity) string { return i.ID().String() })
	}
	var nodes []inventory.Node
	if err == nil {
		nodes, _, err = upsertAsset(g.Nodes(), l.req.Node, false, "node", l.req.Node.ID().String(), func(n inventory.Node) bool { return n.ID().Equal(l.req.Node.ID()) })
	}
	if err != nil {
		return zeroVal[inventory.Graph](), err
	}
	return l.svc.buildValidatedGraph(ctx, g, hosts, idents, nodes)
}
func mergeStagedAsset[T any](items []T, staged algebraic.Option[T], kind string, sameID, equal func(T, T) bool, idStr func(T) string) ([]T, error) {
	val, ok := staged.Get()
	if !ok {
		return items, nil
	}
	if idx := slices.IndexFunc(items, func(x T) bool { return sameID(x, val) }); idx < 0 {
		return append(items, val), nil
	} else if !equal(items[idx], val) {
		return nil, domi18n.EF(ErrAssetAlreadyExists, domi18n.KeyCommonDuplicateItem, domi18n.Str("kind", kind), domi18n.BoundStr("value", idStr(val)))
	}
	return items, nil
}
func (l *PendingEnrollmentLease) cleanupPendingSecrets(ctx context.Context, leaseID security.OperationID, refs []secret.Ref) (fsm.SideEffectOutcome, error) {
	if len(refs) == 0 {
		return fsm.SideEffectSucceeded, nil
	}
	_, loadFailed, err := l.svc.gcSecretsDetached(ctx, leaseID, refs, l.req.ExtraPending)
	if err == nil {
		return fsm.SideEffectSucceeded, nil
	}
	l.recordCommitMeta(zeroVal[ports.Revision](), zeroVal[ports.DurabilityOutcome](), pickIf(loadFailed, "enroll_cleanup_load_failed", "enroll_cleanup_delete_failed"), err)
	return pickIf(loadFailed, fsm.SideEffectFailedNotApplied, fsm.SideEffectOutcomeUnknown), err
}
func (l *PendingEnrollmentLease) recordCommitMeta(newRev ports.Revision, durOut ports.DurabilityOutcome, unkCode string, causeErr error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if newRev.IsValid() {
		l.revision = algebraic.Some(newRev)
	}
	if durOut.IsValid() {
		l.durability = algebraic.Some(durOut)
	}
	if unkCode != "" && l.unknownCode == "" && causeErr != nil {
		l.unknownCode, l.unknownMsg = unkCode, causeErr.Error()
	}
}
func (l *PendingEnrollmentLease) terminalError(cause error) error {
	l.mu.Lock()
	phase, reason := l.state.Phase(), l.state.Reason()
	l.mu.Unlock()
	return wrapCommitError(pickIf(phase == fsm.PendingEnrollPhaseUncertain, ErrEnrollmentUncertain, ErrEnrollmentAborted), reason, cause)
}
func (l *PendingEnrollmentLease) snapshotFinal() (PendingEnrollmentResult, string, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	res := PendingEnrollmentResult{
		phase: l.state.Phase(), leaseID: l.state.Context().LeaseID(), targetNode: l.state.Context().TargetNode(),
		hostKeyFP: l.state.HostKeyFingerprint(), revision: l.revision, durability: l.durability,
		events: slices.Clone(l.events), reason: l.state.Reason(), valid: true,
	}
	unkCode, unkMsg := l.unknownCode, l.unknownMsg
	if res.phase == fsm.PendingEnrollPhaseUncertain && unkCode == "" {
		unkCode, unkMsg = "enroll_uncertain", pickIf(res.reason != "", res.reason, "pending enrollment ended uncertain")
	}
	return res, unkCode, unkMsg
}
func (s *Service) updatePendingPins(leaseID security.OperationID, pins []inventory.PendingSecretRef) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	if len(pins) == 0 {
		delete(s.activePins, leaseID)
		return
	}
	s.activePins[leaseID] = slices.Clone(pins)
}
