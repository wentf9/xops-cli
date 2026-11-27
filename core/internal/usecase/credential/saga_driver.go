package credential

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/foundation/trace"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/ports"
)

type sagaRunState struct {
	cur        fsm.VaultSagaState
	events     []fsm.VaultSagaEvent
	revision   algebraic.Option[ports.Revision]
	durability algebraic.Option[ports.DurabilityOutcome]
	causeErr   error
}

func (s *Service) executeSagaAuthorized(
	ctx context.Context,
	req VaultSagaRequest,
	promptOpt algebraic.Option[ports.SecretPromptRequest],
	//xops:borrowed
	newSecret *secret.SecretBox,
) (result SagaResult, gateErr error) {
	action := sanitizeASCIICode(req.Action, "vault_saga")
	targetLabel := pickIf(req.NewRef.IsValid(), req.NewRef.String(), req.TargetStore)
	summary := pickIf(req.ScopeSummary != "", req.ScopeSummary, action+" "+targetLabel)
	params := buildSagaGateParams(req)
	gateReq, err := buildMutateGateRequest(action, req.NodeID, params, req.Risk.OrElse(security.RiskModerate), summary, req.Approval, req.OperationStream)
	if err != nil {
		return SagaResult{}, domi18n.WrapSentinel(ErrInvalidRequest, err)
	}

	var outcomeOpt algebraic.Option[execution.ExecutionOutcome]
	var emitter *OpEmitter
	var startedAt time.Time
	returnedNormally := false
	defer func() {
		emitter.EmitFinal(ctx, security.CapabilityMutate, startedAt, outcomeOpt, returnedNormally, "vault saga panicked", gateErr)
	}()

	gateErr = gate.WithAuthorized[security.CapMutate](ctx, s.gate, gateReq, func(authCtx context.Context, auth gate.Authorized[security.CapMutate]) error {
		startedAt = s.clock.Now().UTC().Round(0)
		emitter = NewOpEmitter(req.OperationStream, s.clock, toolCredential, auth.TraceID(), auth.OperationID(), req.NodeID)
		emitter.EmitStarted(authCtx, security.CapabilityMutate, action, summary)

		res, runErr := s.runAuthorizedSagaBody(authCtx, auth, req, promptOpt, newSecret, emitter)
		result = res
		if isUncertainSagaOutcome(res, runErr) {
			detail := pickIf(runErr != nil, fmt.Sprint(runErr), "vault saga uncertain")
			if unk := ReportOutcomeUnknown(auth, classifyOpErrorCode(toolCredential, runErr), detail); unk.IsSome() {
				outcomeOpt = unk
			}
		}
		return runErr
	})
	returnedNormally = true
	return result, gateErr
}

func buildSagaGateParams(req VaultSagaRequest) map[string]string {
	params := make(map[string]string, 2)
	if req.NewRef.IsValid() {
		params["new_ref"] = req.NewRef.String()
	} else {
		params["target_store"] = req.TargetStore
	}
	if old, ok := req.OldRef.Get(); ok {
		params["old_ref"] = old.String()
	}
	return params
}

func isUncertainSagaOutcome(res SagaResult, runErr error) bool {
	return res.IsUncertainDurability() || res.IsFailedUncertain() ||
		errors.Is(runErr, ErrUncertainDurability) || errors.Is(runErr, ErrSagaUncertain)
}

func (s *Service) runAuthorizedSagaBody(
	authCtx context.Context,
	auth gate.Authorized[security.CapMutate],
	req VaultSagaRequest,
	promptOpt algebraic.Option[ports.SecretPromptRequest],
	//xops:borrowed
	newSecret *secret.SecretBox,
	emitter *OpEmitter,
) (SagaResult, error) {
	newRef, err := s.resolveSagaNewRef(req)
	if err != nil {
		return SagaResult{}, err
	}
	oldRef, extraOldRefs, err := resolveSagaOldRefs(authCtx, req)
	if err != nil {
		return SagaResult{}, err
	}
	var res SagaResult
	if prompt, isInteractive := promptOpt.Get(); isInteractive {
		err = s.interaction.PromptSecret(authCtx, prompt, func(box *secret.SecretBox) error {
			var dErr error
			res, dErr = s.driveVaultSaga(authCtx, auth, req, newRef, oldRef, box, emitter)
			return dErr
		})
	} else {
		res, err = s.driveVaultSaga(authCtx, auth, req, newRef, oldRef, newSecret, emitter)
	}
	if err != nil || len(extraOldRefs) == 0 || res.StateKind() != fsm.VaultSagaKindCompleted {
		return res, err
	}
	if gcErr := s.gcExtraOldRefsAfterCommit(authCtx, extraOldRefs, req.ExtraPending); gcErr != nil {
		return res, domi18n.WrapS(ErrSagaUncertain, gcErr, domi18n.KeyCommonOpFailed, domi18n.Str("op", "post-commit extra old secret gc"))
	}
	return res, nil
}

func resolveSagaOldRefs(ctx context.Context, req VaultSagaRequest) (algebraic.Option[secret.Ref], []secret.Ref, error) {
	if req.ResolveOldRefs == nil {
		return req.OldRef, nil, nil
	}
	primary, extra, err := req.ResolveOldRefs(ctx)
	if err != nil {
		return algebraic.None[secret.Ref](), nil, err
	}
	if p, ok := primary.Get(); ok && !p.IsValid() {
		return algebraic.None[secret.Ref](), nil, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "ResolveOldRefs primary ref"))
	}
	uniqExtra, err := canonicalizeSecretRefs(extra)
	if err != nil {
		return algebraic.None[secret.Ref](), nil, err
	}
	return primary, uniqExtra, nil
}

func (s *Service) gcExtraOldRefsAfterCommit(ctx context.Context, extraOldRefs []secret.Ref, extraPending []inventory.PendingSecretRef) error {
	cleanCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupEffectTimeout)
	defer cancel()
	_, _, err := s.gcCandidatesAuthorized(cleanCtx, extraOldRefs, extraPending)
	return err
}

func (s *Service) driveVaultSaga(
	ctx context.Context,
	auth gate.Authorized[security.CapMutate],
	req VaultSagaRequest,
	newRef secret.Ref,
	oldRef algebraic.Option[secret.Ref],
	//xops:borrowed
	newSecret *secret.SecretBox,
	emitter *OpEmitter,
) (SagaResult, error) {
	sagaID := auth.OperationID()
	if !sagaID.IsValid() {
		var err error
		if sagaID, err = trace.NewOpIDFrom(s.entropy); err != nil {
			return SagaResult{}, err
		}
	}
	sagaCtx, err := fsm.NewVaultSagaContext(fsm.VaultSagaContextSpec{
		SagaID:             sagaID,
		NewRef:             newRef,
		OldRef:             oldRef,
		ExpectedCASVersion: req.ExpectedCASVersion,
	})
	if err != nil {
		return SagaResult{}, domi18n.WrapSentinel(ErrInvalidRequest, err)
	}
	initSt, err := fsm.NewVaultSagaState(sagaCtx)
	if err != nil {
		return SagaResult{}, domi18n.WrapSentinel(ErrInvalidRequest, err)
	}

	rs := &sagaRunState{cur: initSt}
	nextIn := fsm.VaultInputStart()
	for range maxVaultSagaSteps {
		effs, stepErr := rs.applyTransition(ctx, nextIn, emitter)
		if stepErr != nil {
			return SagaResult{}, stepErr
		}
		if rs.cur.IsTerminal() {
			return rs.finalize(newRef, oldRef)
		}
		if len(effs) != 1 {
			return SagaResult{}, domi18n.EF(ErrSagaUncertain, domi18n.KeyCommonMismatch, domi18n.Str("field", "saga effect count for "+rs.cur.Kind().String()), domi18n.Int("expected", 1), domi18n.Int("actual", len(effs)))
		}
		nextIn, err = s.execSagaEffect(ctx, effs[0], req, newSecret, rs)
		if err != nil {
			return SagaResult{}, err
		}
	}
	return SagaResult{}, domi18n.EF(ErrSagaUncertain, domi18n.KeyUCCredSagaStepLimit, domi18n.Int("max", maxVaultSagaSteps))
}

func (rs *sagaRunState) applyTransition(ctx context.Context, in fsm.VaultSagaInput, emitter *OpEmitter) ([]fsm.VaultSagaEffect, error) {
	fromKind := rs.cur.Kind()
	next, effs, evs, err := fsm.TransitionVaultSaga(rs.cur, in)
	if err != nil {
		return nil, err
	}
	rs.cur = next
	rs.events = append(rs.events, evs...)
	emitter.EmitVaultSagaEvents(ctx, fromKind, next.Kind(), evs, next.IsTerminal())
	return effs, nil
}

func (rs *sagaRunState) finalize(newRef secret.Ref, oldRef algebraic.Option[secret.Ref]) (SagaResult, error) {
	res := SagaResult{
		state:      rs.cur,
		newRef:     newRef,
		oldRef:     oldRef,
		revision:   rs.revision,
		durability: rs.durability,
		events:     slices.Clone(rs.events),
		valid:      true,
	}
	switch st := rs.cur.(type) {
	case *fsm.VaultSagaCompleted:
		return res, nil
	case *fsm.VaultSagaRolledBack:
		return res, wrapSagaTerminalError(ErrSagaRolledBack, st.Reason(), rs.causeErr)
	case *fsm.VaultSagaUncertainDurability:
		return res, wrapSagaTerminalError(ErrUncertainDurability, st.Reason(), rs.causeErr)
	case *fsm.VaultSagaFailedUncertain:
		return res, wrapSagaTerminalError(ErrSagaUncertain, st.Reason(), rs.causeErr)
	case *fsm.VaultSagaInit, *fsm.VaultSagaWritingNew, *fsm.VaultSagaVerifyingReadback,
		*fsm.VaultSagaCommittingConfig, *fsm.VaultSagaCheckingOldRefs,
		*fsm.VaultSagaDeletingOld, *fsm.VaultSagaCompensating:
		return SagaResult{}, domi18n.EF(ErrSagaUncertain, domi18n.KeyCommonStateForbidden, domi18n.Str("action", "finalize"), domi18n.Str("state", st.Kind().String()))
	default:
		return SagaResult{}, domi18n.EF(ErrSagaUncertain, domi18n.KeyCommonUnknownValue, domi18n.Str("kind", "VaultSagaState"), domi18n.BoundStr("value", fmt.Sprintf("%T", rs.cur)))
	}
}

func wrapSagaTerminalError(sentinel error, reason string, cause error) error {
	if cause != nil {
		if reason != "" && !strings.Contains(cause.Error(), reason) {
			return domi18n.WrapSentinel(sentinel, domi18n.Wrap(cause, domi18n.KeyCommonDetail, domi18n.BoundStr("detail", reason)))
		}
		return domi18n.WrapSentinel(sentinel, cause)
	}
	if reason != "" {
		return domi18n.WrapSentinel(sentinel, domi18n.E(domi18n.KeyCommonDetail, domi18n.BoundStr("detail", reason)))
	}
	return sentinel
}

func (s *Service) execSagaEffect(
	ctx context.Context,
	eff fsm.VaultSagaEffect,
	req VaultSagaRequest,
	//xops:borrowed
	newSecret *secret.SecretBox,
	rs *sagaRunState,
) (fsm.VaultSagaInput, error) {
	switch eff.Kind() {
	case fsm.VaultEffectWriteNew:
		return s.runEffectWriteNew(ctx, eff.Ref(), newSecret, rs)
	case fsm.VaultEffectVerifyReadback:
		return s.runEffectVerifyReadback(ctx, eff.Ref(), newSecret, req.VerifyNewRef, rs)
	case fsm.VaultEffectCommitConfigCAS:
		return s.runEffectCommitConfigCAS(ctx, eff.Ref(), req, rs)
	case fsm.VaultEffectCheckOldRefs:
		// CheckOldRefs 仅在 CommitConfigCAS 持久提交后执行，须与外部取消隔离以保证正常收尾回收。
		cleanCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupEffectTimeout)
		defer cancel()
		return s.runEffectCheckOldRefs(cleanCtx, eff.Ref(), req.ExtraPending, rs)
	case fsm.VaultEffectDeleteOld:
		cleanCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupEffectTimeout)
		defer cancel()
		return s.runEffectDeleteVaultSecret(cleanCtx, eff.Ref(), fsm.VaultInputDeleteOldResult, rs)
	case fsm.VaultEffectCompensateDeleteNew:
		// 回滚补偿清理新写凭据必须使用有界 WithoutCancel 上下文，杜绝因外层取消/超时遗留孤儿凭据。
		cleanCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupEffectTimeout)
		defer cancel()
		return s.runEffectDeleteVaultSecret(cleanCtx, eff.Ref(), fsm.VaultInputCompensateResult, rs)
	default:
		return zeroVal[fsm.VaultSagaInput](), domi18n.EF(ErrSagaUncertain, domi18n.KeyCommonUnknownValue, domi18n.Str("kind", "VaultSagaEffectKind"), domi18n.BoundStr("value", eff.Kind().String()))
	}
}

func (s *Service) runEffectWriteNew(
	ctx context.Context,
	ref secret.Ref,
	//xops:borrowed
	newSecret *secret.SecretBox,
	rs *sagaRunState,
) (fsm.VaultSagaInput, error) {
	err := s.vault.PutAndVerify(ctx, ref, newSecret)
	if err == nil {
		return fsm.VaultInputWriteNewResult(fsm.SideEffectSucceeded, "")
	}
	rs.causeErr = err
	return fsm.VaultInputWriteNewResult(classifyVaultWriteError(err), err.Error())
}

func (s *Service) runEffectVerifyReadback(
	ctx context.Context,
	ref secret.Ref,
	//xops:borrowed
	expected *secret.SecretBox,
	verifyNewRef NewSecretVerifier,
	rs *sagaRunState,
) (fsm.VaultSagaInput, error) {
	matched := false
	err := s.vault.WithSecret(ctx, ref, func(got *secret.SecretBox) error {
		matched = got.IsValid() && got.Equal(expected)
		return nil
	})
	if err != nil {
		rs.causeErr = err
		return fsm.VaultInputReadbackResult(classifyReadbackError(err), false, err.Error())
	}
	if !matched {
		rs.causeErr = ports.ErrSecretVerifyFailed
		return fsm.VaultInputReadbackResult(fsm.SideEffectSucceeded, false, "readback secret mismatch")
	}
	if verifyNewRef != nil {
		if vErr := verifyNewRef(ctx, ref); vErr != nil {
			rs.causeErr = vErr
			return fsm.VaultInputReadbackResult(classifyVerifyHookError(vErr), false, vErr.Error())
		}
	}
	return fsm.VaultInputReadbackResult(fsm.SideEffectSucceeded, true, "")
}

// CommitGraphCAS 执行 InventoryStore.CommitCAS 并按失败关闭法则规范分类持久化状态（供 credential 与 inventory 统一复用）：
// DurabilityCommitted 若伴随非空错误或缺少有效 Revision，强制降级为 DurabilityOutcomeUnknown，杜绝误判成功或误删旧凭据。
func CommitGraphCAS(
	ctx context.Context,
	store ports.InventoryStore,
	baseRev ports.Revision,
	nextGraph inventory.Graph,
) (status fsm.DurabilityStatus, newRev ports.Revision, out ports.DurabilityOutcome, reason string, err error) {
	out, commitErr := store.CommitCAS(ctx, baseRev, nextGraph)
	if out.IsValid() {
		if rev, ok := out.Revision().Get(); ok && rev.IsValid() {
			newRev = rev
		}
		reason = out.Detail()
		if reason == "" && commitErr != nil {
			reason = commitErr.Error()
		}
		if out.Status() == fsm.DurabilityCommitted && (commitErr != nil || !newRev.IsValid()) {
			if reason == "" {
				reason = "committed durability missing valid revision"
			}
			return fsm.DurabilityOutcomeUnknown, newRev, out, reason, commitErr
		}
		return out.Status(), newRev, out, reason, commitErr
	}
	if commitErr == nil {
		return fsm.DurabilityOutcomeUnknown, newRev, zeroVal[ports.DurabilityOutcome](), "store returned invalid DurabilityOutcome", nil
	}
	return classifyCommitCASError(commitErr), newRev, zeroVal[ports.DurabilityOutcome](), commitErr.Error(), commitErr
}

func (s *Service) runEffectCommitConfigCAS(
	ctx context.Context,
	newRef secret.Ref,
	req VaultSagaRequest,
	rs *sagaRunState,
) (fsm.VaultSagaInput, error) {
	snap, err := s.store.Load(ctx)
	if err != nil {
		rs.causeErr = err
		return fsm.VaultInputCommitCASResult(fsm.DurabilityNotApplied, "load snapshot failed: "+err.Error())
	}
	if expRev, hasExp := req.ExpectedRevision.Get(); hasExp && !snap.Revision().Equal(expRev) {
		rs.causeErr = ports.ErrRevisionConflict
		return fsm.VaultInputCommitCASResult(fsm.DurabilityNotApplied, "expected revision mismatch")
	}
	nextGraph, err := req.MutateGraph(ctx, snap, newRef)
	if err != nil {
		rs.causeErr = err
		return fsm.VaultInputCommitCASResult(fsm.DurabilityNotApplied, err.Error())
	}
	status, rev, out, reason, commitErr := CommitGraphCAS(ctx, s.store, snap.Revision(), nextGraph)
	if out.IsValid() {
		rs.durability = algebraic.Some(out)
	}
	if rev.IsValid() {
		rs.revision = algebraic.Some(rev)
	}
	if commitErr != nil {
		rs.causeErr = commitErr
	}
	return fsm.VaultInputCommitCASResult(status, reason)
}

func (s *Service) runEffectCheckOldRefs(
	ctx context.Context,
	oldRef secret.Ref,
	extraPending []inventory.PendingSecretRef,
	rs *sagaRunState,
) (fsm.VaultSagaInput, error) {
	snap, err := s.store.Load(ctx)
	if err != nil {
		rs.causeErr = err
		return fsm.VaultInputOldRefsResult(false, 0, err.Error())
	}
	pending, err := s.collectPendingRefs(extraPending)
	if err != nil {
		rs.causeErr = err
		return fsm.VaultInputOldRefsResult(false, 0, err.Error())
	}
	refs := snap.Graph().FindSecretReferences(oldRef, pending...)
	return fsm.VaultInputOldRefsResult(true, len(refs), "")
}

func (s *Service) runEffectDeleteVaultSecret(
	ctx context.Context,
	ref secret.Ref,
	build func(fsm.SideEffectOutcome, string) (fsm.VaultSagaInput, error),
	rs *sagaRunState,
) (fsm.VaultSagaInput, error) {
	err := s.vault.Delete(ctx, ref)
	// Saga 补偿删新凭据与后置删旧凭据的后置条件均为「目标条目不存在」：ErrSecretNotFound 幂等视为已满足。
	if err == nil || errors.Is(err, ports.ErrSecretNotFound) {
		return build(fsm.SideEffectSucceeded, "")
	}
	if rs.causeErr == nil {
		rs.causeErr = err
	} else {
		rs.causeErr = errors.Join(rs.causeErr, err)
	}
	return build(classifyVaultDeleteError(err), err.Error())
}

func classifyVaultWriteError(err error) fsm.SideEffectOutcome {
	switch {
	case errors.Is(err, ports.ErrVaultLocked), errors.Is(err, ports.ErrInvalidArgument), errors.Is(err, ports.ErrPermissionDenied),
		errors.Is(err, ports.ErrAlreadyExists), errors.Is(err, ports.ErrLimitExceeded), errors.Is(err, ports.ErrSecretVerifyFailed):
		return fsm.SideEffectFailedNotApplied
	default:
		return fsm.SideEffectOutcomeUnknown
	}
}
func classifyReadbackError(err error) fsm.SideEffectOutcome {
	if errors.Is(err, ports.ErrSecretNotFound) || errors.Is(err, ports.ErrSecretVerifyFailed) || errors.Is(err, ports.ErrCorruptData) {
		return fsm.SideEffectFailedNotApplied
	}
	return fsm.SideEffectOutcomeUnknown
}

// classifyVerifyHookError 将 CommitConfigCAS 之前只读 VerifyNewRef 的一切失败（含取消与超时）
// 统一归类为 SideEffectFailedNotApplied，确保状态机立即执行有界非取消补偿删除新写凭据。
func classifyVerifyHookError(_ error) fsm.SideEffectOutcome { return fsm.SideEffectFailedNotApplied }
func classifyCommitCASError(err error) fsm.DurabilityStatus {
	switch {
	case errors.Is(err, ports.ErrRevisionConflict), errors.Is(err, ports.ErrInvalidArgument), errors.Is(err, ports.ErrInvalidRevision),
		errors.Is(err, ports.ErrPermissionDenied), errors.Is(err, ports.ErrLimitExceeded), errors.Is(err, ports.ErrNotFound), errors.Is(err, ports.ErrAlreadyExists):
		return fsm.DurabilityNotApplied
	default:
		return fsm.DurabilityOutcomeUnknown
	}
}
func classifyVaultDeleteError(err error) fsm.SideEffectOutcome {
	if errors.Is(err, ports.ErrVaultLocked) || errors.Is(err, ports.ErrInvalidArgument) || errors.Is(err, ports.ErrPermissionDenied) {
		return fsm.SideEffectFailedNotApplied
	}
	return fsm.SideEffectOutcomeUnknown
}
