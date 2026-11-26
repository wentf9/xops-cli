package credential

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/fsm"
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
	newRef secret.Ref,
	//xops:borrowed
	newSecret *secret.SecretBox,
) (SagaResult, error) {
	action := sanitizeASCIICode(req.Action, "vault_saga")
	summary := pickIf(req.ScopeSummary != "", req.ScopeSummary, action+" "+newRef.String())
	params := map[string]string{"new_ref": newRef.String()}
	if old, ok := req.OldRef.Get(); ok {
		params["old_ref"] = old.String()
	}
	gateReq, err := buildMutateGateRequest(action, req.NodeID, params, req.Risk.OrElse(security.RiskModerate), summary, req.Approval, req.OperationStream)
	if err != nil {
		return SagaResult{}, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}

	var result SagaResult
	var outcomeOpt algebraic.Option[execution.ExecutionOutcome]
	var emitter *opEmitter
	var startedAt time.Time
	gateErr := gate.WithAuthorized[security.CapMutate](ctx, s.gate, gateReq, func(authCtx context.Context, auth gate.Authorized[security.CapMutate]) error {
		startedAt = s.clock.Now().UTC().Round(0)
		emitter = newOpEmitter(req.OperationStream, s.clock, auth.TraceID(), auth.OperationID(), req.NodeID)
		emitter.emitStarted(authCtx, security.CapabilityMutate, action, summary)

		res, runErr := s.driveVaultSaga(authCtx, auth, req, newRef, newSecret, emitter)
		result = res
		if res.IsUncertainDurability() || res.IsFailedUncertain() {
			unk, uErr := execution.NewOutcomeUnknown(execution.ExecPhaseRunning, classifyCredentialErrorCode(runErr), runErr.Error())
			if uErr == nil {
				outcomeOpt = algebraic.Some[execution.ExecutionOutcome](unk)
				_ = auth.ReportOutcome(unk)
			}
		}
		return runErr
	})
	if emitter != nil {
		emitter.emitCompleted(ctx, security.CapabilityMutate, startedAt, outcomeOpt, gateErr)
	}
	return result, gateErr
}

func (s *Service) driveVaultSaga(
	ctx context.Context,
	auth gate.Authorized[security.CapMutate],
	req VaultSagaRequest,
	newRef secret.Ref,
	//xops:borrowed
	newSecret *secret.SecretBox,
	emitter *opEmitter,
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
		OldRef:             req.OldRef,
		ExpectedCASVersion: req.ExpectedCASVersion,
	})
	if err != nil {
		return SagaResult{}, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	initSt, err := fsm.NewVaultSagaState(sagaCtx)
	if err != nil {
		return SagaResult{}, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}

	rs := &sagaRunState{cur: initSt}
	nextIn := fsm.VaultInputStart()
	for range maxVaultSagaSteps {
		effs, stepErr := rs.applyTransition(ctx, nextIn, emitter)
		if stepErr != nil {
			return SagaResult{}, stepErr
		}
		if rs.cur.IsTerminal() {
			return rs.finalize(newRef, req.OldRef)
		}
		if len(effs) != 1 {
			return SagaResult{}, fmt.Errorf("%w: 非终态状态 %s 产生异常副作用数 %d", ErrSagaUncertain, rs.cur.Kind(), len(effs))
		}
		nextIn, err = s.execSagaEffect(ctx, effs[0], req, newSecret, rs)
		if err != nil {
			return SagaResult{}, err
		}
	}
	return SagaResult{}, fmt.Errorf("%w: 超过最大状态转移步数 %d", ErrSagaUncertain, maxVaultSagaSteps)
}

func (rs *sagaRunState) applyTransition(ctx context.Context, in fsm.VaultSagaInput, emitter *opEmitter) ([]fsm.VaultSagaEffect, error) {
	fromKind := rs.cur.Kind()
	next, effs, evs, err := fsm.TransitionVaultSaga(rs.cur, in)
	if err != nil {
		return nil, err
	}
	rs.cur = next
	rs.events = append(rs.events, evs...)
	emitter.emitVaultSagaEvents(ctx, fromKind, next.Kind(), evs, next.IsTerminal())
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
		return SagaResult{}, fmt.Errorf("%w: 非终态 %s 提前结束", ErrSagaUncertain, st.Kind())
	default:
		return SagaResult{}, fmt.Errorf("%w: 未知 VaultSagaState 变体 %T", ErrSagaUncertain, rs.cur)
	}
}

func wrapSagaTerminalError(sentinel error, reason string, cause error) error {
	if cause != nil {
		return fmt.Errorf("%w: %w", sentinel, cause)
	}
	if reason != "" {
		return fmt.Errorf("%w: %s", sentinel, reason)
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
		return s.runEffectCheckOldRefs(ctx, eff.Ref(), req.ExtraPending, rs)
	case fsm.VaultEffectDeleteOld:
		return s.runEffectDeleteVaultSecret(ctx, eff.Ref(), fsm.VaultInputDeleteOldResult, rs)
	case fsm.VaultEffectCompensateDeleteNew:
		return s.runEffectDeleteVaultSecret(ctx, eff.Ref(), fsm.VaultInputCompensateResult, rs)
	default:
		return zeroVal[fsm.VaultSagaInput](), fmt.Errorf("%w: 未知 VaultSagaEffectKind=%s", ErrSagaUncertain, eff.Kind())
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
	out, commitErr := s.store.CommitCAS(ctx, snap.Revision(), nextGraph)
	if out.IsValid() {
		rs.durability = algebraic.Some(out)
		if rev, ok := out.Revision().Get(); ok {
			rs.revision = algebraic.Some(rev)
		}
		if commitErr != nil {
			rs.causeErr = commitErr
		}
		reason := out.Detail()
		if reason == "" && commitErr != nil {
			reason = commitErr.Error()
		}
		return fsm.VaultInputCommitCASResult(out.Status(), reason)
	}
	if commitErr == nil {
		return fsm.VaultInputCommitCASResult(fsm.DurabilityOutcomeUnknown, "store returned invalid DurabilityOutcome")
	}
	rs.causeErr = commitErr
	return fsm.VaultInputCommitCASResult(classifyCommitCASError(commitErr), commitErr.Error())
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
	if err == nil {
		return build(fsm.SideEffectSucceeded, "")
	}
	if rs.causeErr == nil {
		rs.causeErr = err
	}
	return build(classifyVaultDeleteError(err), err.Error())
}

func classifyVaultWriteError(err error) fsm.SideEffectOutcome {
	if errors.Is(err, ports.ErrVaultLocked) ||
		errors.Is(err, ports.ErrInvalidArgument) ||
		errors.Is(err, ports.ErrPermissionDenied) ||
		errors.Is(err, ports.ErrAlreadyExists) ||
		errors.Is(err, ports.ErrLimitExceeded) ||
		errors.Is(err, ports.ErrSecretVerifyFailed) {
		return fsm.SideEffectFailedNotApplied
	}
	return fsm.SideEffectOutcomeUnknown
}

func classifyReadbackError(err error) fsm.SideEffectOutcome {
	if errors.Is(err, ports.ErrSecretNotFound) ||
		errors.Is(err, ports.ErrSecretVerifyFailed) ||
		errors.Is(err, ports.ErrCorruptData) {
		return fsm.SideEffectFailedNotApplied
	}
	return fsm.SideEffectOutcomeUnknown
}

func classifyVerifyHookError(err error) fsm.SideEffectOutcome {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fsm.SideEffectOutcomeUnknown
	}
	return fsm.SideEffectFailedNotApplied
}

func classifyCommitCASError(err error) fsm.DurabilityStatus {
	if errors.Is(err, ports.ErrRevisionConflict) ||
		errors.Is(err, ports.ErrInvalidArgument) ||
		errors.Is(err, ports.ErrInvalidRevision) ||
		errors.Is(err, ports.ErrPermissionDenied) ||
		errors.Is(err, ports.ErrLimitExceeded) ||
		errors.Is(err, ports.ErrNotFound) ||
		errors.Is(err, ports.ErrAlreadyExists) {
		return fsm.DurabilityNotApplied
	}
	return fsm.DurabilityOutcomeUnknown
}

func classifyVaultDeleteError(err error) fsm.SideEffectOutcome {
	if errors.Is(err, ports.ErrVaultLocked) ||
		errors.Is(err, ports.ErrSecretNotFound) ||
		errors.Is(err, ports.ErrInvalidArgument) ||
		errors.Is(err, ports.ErrPermissionDenied) {
		return fsm.SideEffectFailedNotApplied
	}
	return fsm.SideEffectOutcomeUnknown
}
