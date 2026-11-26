package credential

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/ports"
)

//xops:syncclosure
func (s *Service) runVaultControlMutation(
	ctx context.Context,
	action string,
	req VaultControlRequest,
	run func(authCtx context.Context) error,
) error {
	summary := pickIf(req.ScopeSummary != "", req.ScopeSummary, action)
	gateReq, err := buildMutateGateRequest(action, "", nil, req.Risk.OrElse(security.RiskModerate), summary, req.Approval, req.OperationStream)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	var emitter *opEmitter
	var startedAt time.Time
	gateErr := gate.WithAuthorized[security.CapMutate](ctx, s.gate, gateReq, func(authCtx context.Context, auth gate.Authorized[security.CapMutate]) error {
		startedAt = s.clock.Now().UTC().Round(0)
		emitter = newOpEmitter(req.OperationStream, s.clock, auth.TraceID(), auth.OperationID(), "")
		emitter.emitStarted(authCtx, security.CapabilityMutate, action, summary)
		return run(authCtx)
	})
	if emitter != nil {
		emitter.emitCompleted(ctx, security.CapabilityMutate, startedAt, algebraic.None[execution.ExecutionOutcome](), gateErr)
	}
	return gateErr
}

func (s *Service) validateBaseCall(ctx context.Context, risk algebraic.Option[security.RiskLevel]) error {
	if s == nil || !s.valid {
		return ErrServiceNotInitialized
	}
	if ctx == nil {
		return ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if r, ok := risk.Get(); ok && !r.IsValid() {
		return fmt.Errorf("%w: RiskLevel 无效", ErrInvalidRequest)
	}
	return nil
}

func (s *Service) validateControlCall(ctx context.Context, risk algebraic.Option[security.RiskLevel]) error {
	if err := s.validateBaseCall(ctx, risk); err != nil {
		return err
	}
	if s.vaultControl == nil {
		return ErrVaultControlUnavailable
	}
	return nil
}

func (s *Service) validateInteractionCall(ctx context.Context, prompt ports.SecretPromptRequest) error {
	if s == nil || !s.valid {
		return ErrServiceNotInitialized
	}
	if ctx == nil {
		return ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !prompt.IsValid() {
		return fmt.Errorf("%w: SecretPromptRequest 无效", ErrInvalidRequest)
	}
	if s.interaction == nil || !s.interaction.CanInteract() {
		return fmt.Errorf("%w: %w", ErrInteractionUnavailable, ports.ErrInteractionUnavailable)
	}
	return nil
}

func (s *Service) validateInteractiveControlCall(ctx context.Context, req InteractiveVaultControlRequest) error {
	if err := s.validateControlCall(ctx, req.Risk); err != nil {
		return err
	}
	if !req.Prompt.IsValid() {
		return fmt.Errorf("%w: Prompt 无效", ErrInvalidRequest)
	}
	if cp, ok := req.ConfirmPrompt.Get(); ok && !cp.IsValid() {
		return fmt.Errorf("%w: ConfirmPrompt 无效", ErrInvalidRequest)
	}
	if s.interaction == nil || !s.interaction.CanInteract() {
		return fmt.Errorf("%w: %w", ErrInteractionUnavailable, ports.ErrInteractionUnavailable)
	}
	return nil
}

func buildInspectGateRequest(
	action, nodeID string,
	params map[string]string,
	risk security.RiskLevel,
	summary string,
	approval algebraic.Option[gate.ApprovalSubmission],
	stream *events.OperationStream,
) (gate.GateRequest[security.CapInspect], error) {
	binding, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityInspect,
		Tool:       toolCredential,
		Action:     action,
		NodeID:     nodeID,
		Parameters: params,
	})
	if err != nil {
		return zeroVal[gate.GateRequest[security.CapInspect]](), err
	}
	return gate.NewGateRequest[security.CapInspect](gate.GateRequestSpec[security.CapInspect]{
		Binding:         binding,
		Risk:            risk,
		ScopeSummary:    summary,
		Approval:        approval,
		OperationStream: stream,
	})
}

func buildMutateGateRequest(
	action, nodeID string,
	params map[string]string,
	risk security.RiskLevel,
	summary string,
	approval algebraic.Option[gate.ApprovalSubmission],
	stream *events.OperationStream,
) (gate.GateRequest[security.CapMutate], error) {
	binding, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityMutate,
		Tool:       toolCredential,
		Action:     action,
		NodeID:     nodeID,
		Parameters: params,
	})
	if err != nil {
		return zeroVal[gate.GateRequest[security.CapMutate]](), err
	}
	return gate.NewGateRequest[security.CapMutate](gate.GateRequestSpec[security.CapMutate]{
		Binding:         binding,
		Risk:            risk,
		ScopeSummary:    summary,
		Approval:        approval,
		OperationStream: stream,
	})
}

// opEmitter 封装单次凭据操作向可选 OperationStream 发射生命周期与 VaultSagaFSM 转移事件的辅助逻辑。
type opEmitter struct {
	stream  *events.OperationStream
	clock   ports.Clock
	traceID security.TraceID
	opID    security.OperationID
	nodeID  algebraic.Option[inventory.NodeID]
	seq     atomic.Uint64
}

func newOpEmitter(
	stream *events.OperationStream,
	clock ports.Clock,
	traceID security.TraceID,
	opID security.OperationID,
	nodeLabel string,
) *opEmitter {
	if stream == nil {
		return nil
	}
	var nodeOpt algebraic.Option[inventory.NodeID]
	if nid, err := inventory.ParseNodeID(nodeLabel); err == nil {
		nodeOpt = algebraic.Some(nid)
	}
	return &opEmitter{stream: stream, clock: clock, traceID: traceID, opID: opID, nodeID: nodeOpt}
}

func (e *opEmitter) active() bool { return e != nil && e.stream != nil && !e.stream.IsClosed() }

func (e *opEmitter) nextMeta() (events.EventMeta, error) {
	return events.NewEventMeta(events.EventMetaSpec{
		TraceID:     e.traceID,
		OperationID: algebraic.Some(e.opID),
		OccurredAt:  e.clock.Now().UTC().Round(0),
		Seq:         e.seq.Add(1),
		NodeID:      e.nodeID,
	})
}

func (e *opEmitter) emitStarted(ctx context.Context, capKind security.CapabilityKind, action, summary string) {
	if !e.active() {
		return
	}
	meta, err := e.nextMeta()
	if err != nil {
		return
	}
	ev, err := events.NewOperationStartedEvent(events.OperationStartedSpec{
		Meta: meta, Capability: capKind, Tool: toolCredential, Action: action, Summary: summary,
	})
	if err == nil {
		_ = e.stream.Emit(ctx, ev)
	}
}

func (e *opEmitter) emitVaultSagaEvents(ctx context.Context, from, to fsm.VaultSagaStateKind, evs []fsm.VaultSagaEvent, terminal bool) {
	if !e.active() {
		return
	}
	for _, fev := range evs {
		meta, err := e.nextMeta()
		if err != nil {
			return
		}
		ev, err := events.NewVaultSagaTransitionEvent(meta, from, to, fev, terminal)
		if err == nil {
			_ = e.stream.Emit(ctx, ev)
		}
	}
}

func (e *opEmitter) emitCompleted(
	ctx context.Context,
	capKind security.CapabilityKind,
	startedAt time.Time,
	outcome algebraic.Option[execution.ExecutionOutcome],
	finalErr error,
) {
	if !e.active() {
		return
	}
	meta, err := e.nextMeta()
	if err != nil {
		return
	}
	elapsed := max(e.clock.Since(startedAt), 0)
	succeeded := finalErr == nil
	code, msg := "", "completed"
	if finalErr != nil {
		code, msg = classifyCredentialErrorCode(finalErr), finalErr.Error()
	}
	ev, err := events.NewOperationCompletedEvent(events.OperationCompletedSpec{
		Meta:       meta,
		Capability: capKind,
		Duration:   algebraic.FromStdDuration(elapsed),
		Outcome:    outcome,
		Succeeded:  succeeded,
		Code:       code,
		Message:    msg,
	})
	if err != nil {
		return
	}
	emitCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), terminalEventEmitTimeout)
	defer cancel()
	_ = e.stream.Emit(emitCtx, ev)
}

func classifyCredentialErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrUncertainDurability):
		return "uncertain_durability"
	case errors.Is(err, ErrSagaUncertain):
		return "saga_uncertain"
	case errors.Is(err, ErrSagaRolledBack):
		return "saga_rolled_back"
	case errors.Is(err, ErrSecretStillReferenced):
		return "secret_still_referenced"
	case errors.Is(err, ports.ErrAuditPostWrite):
		return "audit_post_write_failed"
	case errors.Is(err, gate.ErrGateHalted):
		return "gate_halted"
	default:
		return "credential_error"
	}
}
