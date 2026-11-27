package gate

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/foundation/trace"
	"github.com/wentf9/xops-cli/core/ports"
)

// evaluateAndAudit 执行前置鉴权、审批核验、只追加 StageOperation(+opID) 与 Audit(Authorized) 落盘，
// 全部成功后登记活跃句柄并签发 issuedPermit（Plan §4.4）。
func (g *Gate) evaluateAndAudit(ctx context.Context, req rawGateRequest) (issuedPermit, error) {
	if g == nil || !g.initialized {
		return issuedPermit{}, ErrGateNotInitialized
	}
	if err := g.haltedErr(); err != nil {
		return issuedPermit{}, err
	}
	if err := ctx.Err(); err != nil {
		return issuedPermit{}, err
	}
	traceID, err := g.resolveTraceID(ctx, req.traceID)
	if err != nil {
		return issuedPermit{}, err
	}
	approved, rej := g.evaluatePolicyAndApproval(ctx, traceID, req)
	if rej != nil {
		return issuedPermit{}, g.recordDeniedAudit(ctx, traceID, rej)
	}
	// 审批交互可能耗时，签发前再次复核熔断态与上下文取消状态。
	if err := g.haltedErr(); err != nil {
		return issuedPermit{}, err
	}
	if err := ctx.Err(); err != nil {
		return issuedPermit{}, err
	}
	return g.stageAndAuthorize(ctx, traceID, req, approved)
}

func (g *Gate) stageAndAuthorize(
	ctx context.Context,
	traceID security.TraceID,
	req rawGateRequest,
	approved approvalOutcome,
) (issuedPermit, error) {
	startedAt := g.clock.Now().UTC().Round(0)
	if !isValidRFC3339Time(startedAt) {
		return issuedPermit{}, domi18n.EF(ErrInvalidConfig, domi18n.KeyGateInvalidClockTime)
	}
	// 严格顺序第 1 步：只追加登记 +<opID>\n 至当前进程 .lock。
	if err := g.sink.StageOperation(ctx, approved.opID); err != nil {
		return issuedPermit{}, domi18n.WrapSentinel(ErrAuditStageFailed, err)
	}
	decision := approvalDecisionKind(approved.approvedViaChg)
	authEntry, err := ports.NewAuditEntry(ports.AuditEntrySpec{
		ProcessID:   g.procID,
		TraceID:     traceID,
		OperationID: approved.opID,
		Phase:       ports.AuditPhaseAuthorized,
		Outcome:     ports.AuditOutcomePending,
		Risk:        approved.risk,
		Decision:    decision,
		Binding:     approved.binding,
		Timestamp:   startedAt,
		Reason:      approved.reason,
	})
	if err != nil {
		_ = g.sink.UnstageOperation(context.WithoutCancel(ctx), approved.opID)
		return issuedPermit{}, domi18n.WrapSentinel(ErrAuditPreWriteFailed, err)
	}
	// 严格顺序第 2 步：同步落盘 Audit(Authorized)，失败时尽力注销 +opID 且绝不执行回调。
	if err := g.sink.Record(ctx, authEntry); err != nil {
		unstageErr := g.sink.UnstageOperation(context.WithoutCancel(ctx), approved.opID)
		preErr := domi18n.WrapSentinel(ErrAuditPreWriteFailed, err)
		if unstageErr != nil {
			return issuedPermit{}, errors.Join(preErr, domi18n.WrapSentinel(ErrAuditUnstageFailed, unstageErr))
		}
		return issuedPermit{}, preErr
	}
	g.authorizedCount.Add(1)
	return g.registerIssuedPermit(ctx, traceID, req, approved, decision, startedAt)
}

func approvalDecisionKind(viaChallenge bool) security.DecisionKind {
	if viaChallenge {
		return security.DecisionKindNeedApproval
	}
	return security.DecisionKindAllow
}

func (g *Gate) registerIssuedPermit(
	ctx context.Context,
	traceID security.TraceID,
	req rawGateRequest,
	approved approvalOutcome,
	decision security.DecisionKind,
	startedAt time.Time,
) (issuedPermit, error) {
	revoked := &atomic.Bool{}
	permit := issuedPermit{
		traceID:   traceID,
		opID:      approved.opID,
		binding:   approved.binding,
		profile:   g.profile,
		risk:      approved.risk,
		decision:  decision,
		startedAt: startedAt,
		revoked:   revoked,
		recorder:  &outcomeRecorder{},
		opStream:  req.opStream,
		valid:     true,
	}

	g.mu.Lock()
	if g.halted {
		haltErr := g.haltedErrLocked()
		g.mu.Unlock()
		revoked.Store(true)
		// Authorized 已落盘但并发熔断抢先发生：跳过 run 回调并立即闭合终态审计，维持零孤儿。
		return issuedPermit{}, g.finalizeAudit(ctx, permit, haltErr)
	}
	g.nextHandleSeq++
	permit.handleSeq = g.nextHandleSeq
	g.activeHandles[permit.handleSeq] = revoked
	g.mu.Unlock()
	return permit, nil
}

// finalizeAudit 在受权回调退出后注销活跃句柄，并严格按 Audit(Finalized) -> Unstage(-opID) 闭合审计。
// 使用 context.WithoutCancel 确保即使调用方上下文已取消仍完整落盘终态，维持进程内零孤儿；
// StrictAgentProfile 下终态落盘失败立即触发不可逆 Halted 熔断且保留 +opID 于 .lock 中。
func (g *Gate) finalizeAudit(ctx context.Context, permit issuedPermit, runErr error) error {
	if g == nil || !g.initialized {
		return ErrGateNotInitialized
	}
	permit.revoke()
	if permit.handleSeq != 0 {
		g.mu.Lock()
		delete(g.activeHandles, permit.handleSeq)
		g.mu.Unlock()
	}
	if !permit.valid {
		return ErrInvalidPermit
	}

	auditCtx := context.WithoutCancel(ctx)
	finalEntry, buildErr := g.buildFinalizedAuditEntry(permit, runErr)
	if buildErr != nil {
		return g.handlePostWriteFailure(permit.opID, runErr, buildErr)
	}
	if writeErr := g.sink.Record(auditCtx, finalEntry); writeErr != nil {
		return g.handlePostWriteFailure(permit.opID, runErr, writeErr)
	}
	g.finalizedCount.Add(1)

	if unstageErr := g.sink.UnstageOperation(auditCtx, permit.opID); unstageErr != nil {
		g.emitDiagnostic(algebraic.Some(permit.opID), events.SeverityWarn, "audit_unstage_failed", unstageErr.Error(), nil)
		if errors.Is(unstageErr, ports.ErrAuditPostWrite) && g.profile.HaltsOnAuditPostWriteError() {
			g.triggerHalt(algebraic.Some(permit.opID), "audit_unstage_post_write_failed", unstageErr)
		}
		return joinRunAndAuditErr(runErr, domi18n.WrapSentinel(ErrAuditUnstageFailed, unstageErr))
	}
	return runErr
}

func (g *Gate) buildFinalizedAuditEntry(permit issuedPermit, runErr error) (ports.AuditEntry, error) {
	now := g.clock.Now().UTC().Round(0)
	if !isValidRFC3339Time(now) {
		return zeroVal[ports.AuditEntry](), domi18n.EF(ErrInvalidConfig, domi18n.KeyGateInvalidClockTime)
	}
	elapsed := g.clock.Since(permit.startedAt)
	if elapsed < 0 {
		elapsed = 0
	}
	effOutcome := selectEffectiveOutcome(permit.recorder.load(), extractErrorOutcome(runErr))
	auditOutcome, errCode, reason := classifyFinalAuditOutcome(effOutcome, runErr)
	return ports.NewAuditEntry(ports.AuditEntrySpec{
		ProcessID:   g.procID,
		TraceID:     permit.traceID,
		OperationID: permit.opID,
		Phase:       ports.AuditPhaseFinalized,
		Outcome:     auditOutcome,
		Risk:        permit.risk,
		Decision:    permit.decision,
		Binding:     permit.binding,
		Timestamp:   now,
		Duration:    algebraic.Some(algebraic.FromStdDuration(elapsed)),
		ErrorCode:   errCode,
		Reason:      reason,
	})
}

func (g *Gate) handlePostWriteFailure(opID security.OperationID, runErr, writeErr error) error {
	g.postWriteErrorCount.Add(1)
	postErr := ensureAuditPostWriteError(opID, writeErr)
	if g.profile.HaltsOnAuditPostWriteError() {
		g.triggerHalt(algebraic.Some(opID), "audit_post_write_failed", postErr)
	} else {
		g.emitDiagnostic(algebraic.Some(opID), events.SeverityError, "audit_post_write_failed", postErr.Error(), map[string]string{
			"profile": g.profile.String(),
			"halted":  "false",
		})
	}
	return joinRunAndAuditErr(runErr, postErr)
}

func ensureAuditPostWriteError(opID security.OperationID, writeErr error) error {
	if pw, ok := errors.AsType[*ports.AuditPostWriteError](writeErr); ok && pw.IsValid() {
		return writeErr
	}
	pw, err := ports.NewAuditPostWriteError(opID, writeErr)
	if err != nil {
		return domi18n.WrapSentinel(ports.ErrAuditPostWrite, writeErr)
	}
	return pw
}

func (g *Gate) recordDeniedAudit(ctx context.Context, traceID security.TraceID, rej *policyRejection) error {
	g.deniedCount.Add(1)
	opID := rej.opID
	if !opID.IsValid() {
		genID, err := security.NewOperationIDFrom(g.entropy)
		if err != nil {
			return errors.Join(rej.err, domi18n.WrapSentinel(ErrAuditPreWriteFailed, err))
		}
		opID = genID
	}
	now := g.clock.Now().UTC().Round(0)
	if !isValidRFC3339Time(now) || !rej.binding.IsValid() || !rej.risk.IsValid() {
		return errors.Join(rej.err, domi18n.EF(ErrAuditPreWriteFailed, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "denied audit metadata")))
	}
	entry, err := ports.NewAuditEntry(ports.AuditEntrySpec{
		ProcessID:   g.procID,
		TraceID:     traceID,
		OperationID: opID,
		Phase:       ports.AuditPhaseDenied,
		Outcome:     ports.AuditOutcomeDenied,
		Risk:        rej.risk,
		Decision:    rej.decision,
		Binding:     rej.binding,
		Timestamp:   now,
		ErrorCode:   normalizeAuditErrorCode(rej.errorCode, "authorization_denied"),
		Reason:      sanitizeReason(rej.reason, "authorization denied"),
	})
	if err != nil {
		return errors.Join(rej.err, domi18n.WrapSentinel(ErrAuditPreWriteFailed, err))
	}
	if writeErr := g.sink.Record(context.WithoutCancel(ctx), entry); writeErr != nil {
		if errors.Is(writeErr, ports.ErrAuditPostWrite) && g.profile.HaltsOnAuditPostWriteError() {
			g.triggerHalt(algebraic.Some(opID), "audit_denied_post_write_failed", writeErr)
		}
		return errors.Join(rej.err, domi18n.WrapSentinel(ErrAuditPreWriteFailed, writeErr))
	}
	return rej.err
}

func (g *Gate) resolveTraceID(ctx context.Context, explicit algebraic.Option[security.TraceID]) (security.TraceID, error) {
	if tid, ok := explicit.Get(); ok {
		return tid, nil
	}
	if tid, ok := trace.TraceIDFromContext(ctx); ok {
		return tid, nil
	}
	return trace.NewTraceIDFrom(g.entropy)
}

func (g *Gate) resolveFreshOperationID(explicit algebraic.Option[security.OperationID]) (security.OperationID, error) {
	if opID, ok := explicit.Get(); ok {
		return opID, nil
	}
	return trace.NewOpIDFrom(g.entropy)
}

func (g *Gate) fallbackOpID(explicit algebraic.Option[security.OperationID]) security.OperationID {
	if opID, ok := explicit.Get(); ok {
		return opID
	}
	return zeroVal[security.OperationID]()
}

func extractErrorOutcome(err error) execution.ExecutionOutcome {
	if err == nil {
		return nil
	}
	if carrier, ok := errors.AsType[OutcomeCarrier](err); ok && carrier != nil {
		return carrier.ExecutionOutcome()
	}
	return nil
}

// selectEffectiveOutcome 合并回调上报结果与错误链携带结果，保证 OutcomeUnknown 拥有最高不可逆优先级。
func selectEffectiveOutcome(recorded, fromErr execution.ExecutionOutcome) execution.ExecutionOutcome {
	if fromErr != nil && fromErr.IsValid() && fromErr.Kind() == execution.OutcomeKindUnknown {
		return fromErr
	}
	if recorded != nil && recorded.IsValid() && recorded.Kind() == execution.OutcomeKindUnknown {
		return recorded
	}
	if fromErr != nil && fromErr.IsValid() {
		return fromErr
	}
	if recorded != nil && recorded.IsValid() {
		return recorded
	}
	return nil
}

// classifyFinalAuditOutcome 通过穷尽 ExecutionOutcome 封闭和类型映射终态审计结果，
// 严禁将 *execution.OutcomeUnknown 降级为 AuditOutcomeFailed（INV-C6 / ADR-016）。
func classifyFinalAuditOutcome(out execution.ExecutionOutcome, runErr error) (ports.AuditOutcome, string, string) {
	if out != nil {
		return classifyTypedOutcome(out, runErr)
	}
	if runErr == nil {
		return ports.AuditOutcomeSucceeded, "", "operation succeeded"
	}
	switch {
	case errors.Is(runErr, ErrOperationPanicked):
		return ports.AuditOutcomeFailed, "operation_panicked", sanitizeReason(runErr.Error(), "operation panicked")
	case errors.Is(runErr, ErrOperationAborted):
		return ports.AuditOutcomeCanceled, "operation_aborted", sanitizeReason(runErr.Error(), "operation aborted")
	case errors.Is(runErr, ErrGateHalted):
		return ports.AuditOutcomeCanceled, "gate_halted", sanitizeReason(runErr.Error(), "gate halted")
	case errors.Is(runErr, ErrScopeEscalated):
		return ports.AuditOutcomeEscalated, "scope_escalated", sanitizeReason(runErr.Error(), "scope escalated")
	case errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded):
		return ports.AuditOutcomeCanceled, "context_canceled", sanitizeReason(runErr.Error(), "context canceled")
	default:
		return ports.AuditOutcomeFailed, "operation_failed", sanitizeReason(runErr.Error(), "operation failed")
	}
}

func classifyTypedOutcome(out execution.ExecutionOutcome, runErr error) (ports.AuditOutcome, string, string) {
	switch v := out.(type) {
	case *execution.OutcomeUnknown:
		return classifyUnknownOutcome(v)
	case *execution.OutcomeCompleted:
		return classifyCompletedOutcome(v, runErr)
	case *execution.OutcomeNotStarted:
		return classifyNotStartedOutcome(v, runErr)
	default:
		return ports.AuditOutcomeFailed, "invalid_outcome", "unexpected execution outcome variant"
	}
}

func classifyUnknownOutcome(v *execution.OutcomeUnknown) (ports.AuditOutcome, string, string) {
	code := normalizeAuditErrorCode(v.Code(), "outcome_unknown")
	return ports.AuditOutcomeUnknown, code, sanitizeReason(v.Reason(), "execution outcome unknown")
}

func classifyCompletedOutcome(v *execution.OutcomeCompleted, runErr error) (ports.AuditOutcome, string, string) {
	if v.Succeeded() && runErr == nil {
		return ports.AuditOutcomeSucceeded, "", "operation completed"
	}
	if isContextCancelErr(runErr) {
		return ports.AuditOutcomeCanceled, "context_canceled", sanitizeReason(runErr.Error(), "context canceled")
	}
	if runErr != nil {
		return ports.AuditOutcomeFailed, "operation_failed", sanitizeReason(runErr.Error(), "operation failed")
	}
	return ports.AuditOutcomeFailed, "non_zero_exit", "operation completed with non-zero status"
}

func classifyNotStartedOutcome(v *execution.OutcomeNotStarted, runErr error) (ports.AuditOutcome, string, string) {
	code := normalizeAuditErrorCode(v.Code(), "not_started")
	if isContextCancelErr(runErr) {
		return ports.AuditOutcomeCanceled, code, sanitizeReason(v.Reason(), "operation not started (canceled)")
	}
	return ports.AuditOutcomeFailed, code, sanitizeReason(v.Reason(), "operation not started")
}

func isContextCancelErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func joinRunAndAuditErr(runErr, auditErr error) error {
	if runErr == nil {
		return auditErr
	}
	if auditErr == nil {
		return runErr
	}
	return errors.Join(runErr, auditErr)
}
