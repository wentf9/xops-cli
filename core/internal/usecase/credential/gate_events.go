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
) (gateErr error) {
	summary := pickIf(req.ScopeSummary != "", req.ScopeSummary, action)
	gateReq, err := buildMutateGateRequest(action, "", nil, req.Risk.OrElse(security.RiskModerate), summary, req.Approval, req.OperationStream)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	var emitter *OpEmitter
	var startedAt time.Time
	returnedNormally := false
	defer func() {
		emitter.EmitFinal(ctx, security.CapabilityMutate, startedAt, algebraic.None[execution.ExecutionOutcome](), returnedNormally, "vault control panicked", gateErr)
	}()
	gateErr = gate.WithAuthorized[security.CapMutate](ctx, s.gate, gateReq, func(authCtx context.Context, auth gate.Authorized[security.CapMutate]) error {
		startedAt = s.clock.Now().UTC().Round(0)
		emitter = NewOpEmitter(req.OperationStream, s.clock, toolCredential, auth.TraceID(), auth.OperationID(), "")
		emitter.EmitStarted(authCtx, security.CapabilityMutate, action, summary)
		return run(authCtx)
	})
	returnedNormally = true
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

func (s *Service) validateInteractiveControlCall(ctx context.Context, req InteractiveVaultControlRequest, allowConfirm bool) error {
	if err := s.validateControlCall(ctx, req.Risk); err != nil {
		return err
	}
	if !req.Prompt.IsValid() {
		return fmt.Errorf("%w: Prompt 无效", ErrInvalidRequest)
	}
	if cp, ok := req.ConfirmPrompt.Get(); ok {
		if !allowConfirm {
			return fmt.Errorf("%w: 当前交互操作不支持 ConfirmPrompt", ErrInvalidRequest)
		}
		if !cp.IsValid() {
			return fmt.Errorf("%w: ConfirmPrompt 无效", ErrInvalidRequest)
		}
	}
	if s.interaction == nil || !s.interaction.CanInteract() {
		return fmt.Errorf("%w: %w", ErrInteractionUnavailable, ports.ErrInteractionUnavailable)
	}
	return nil
}

// BuildGateRequest 构造强类型 GateRequest[C]，供 credential 与 inventory 用例共享统一能力绑定与门控装配。
func BuildGateRequest[C security.Capability](
	capKind security.CapabilityKind,
	tool, action, nodeID string,
	params map[string]string,
	risk security.RiskLevel,
	summary string,
	approval algebraic.Option[gate.ApprovalSubmission],
	stream *events.OperationStream,
) (gate.GateRequest[C], error) {
	binding, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: capKind,
		Tool:       tool,
		Action:     action,
		NodeID:     nodeID,
		Parameters: params,
	})
	if err != nil {
		return zeroVal[gate.GateRequest[C]](), err
	}
	return gate.NewGateRequest[C](gate.GateRequestSpec[C]{
		Binding:         binding,
		Risk:            risk,
		ScopeSummary:    summary,
		Approval:        approval,
		OperationStream: stream,
	})
}

// ReportOutcomeUnknown 在写路径结果未知或半提交时向 Gate 上报 execution.OutcomeUnknown 并返回对应的 Option 供终态事件复用。
func ReportOutcomeUnknown(auth gate.Authorized[security.CapMutate], code, detail string) algebraic.Option[execution.ExecutionOutcome] {
	if code == "" || !auth.IsValid() {
		return algebraic.None[execution.ExecutionOutcome]()
	}
	if unk, err := execution.NewOutcomeUnknown(execution.ExecPhaseRunning, code, detail); err == nil {
		_ = auth.ReportOutcome(unk)
		return algebraic.Some[execution.ExecutionOutcome](unk)
	}
	return algebraic.None[execution.ExecutionOutcome]()
}

func buildInspectGateRequest(
	action, nodeID string,
	params map[string]string,
	risk security.RiskLevel,
	summary string,
	approval algebraic.Option[gate.ApprovalSubmission],
	stream *events.OperationStream,
) (gate.GateRequest[security.CapInspect], error) {
	return BuildGateRequest[security.CapInspect](security.CapabilityInspect, toolCredential, action, nodeID, params, risk, summary, approval, stream)
}

func buildMutateGateRequest(
	action, nodeID string,
	params map[string]string,
	risk security.RiskLevel,
	summary string,
	approval algebraic.Option[gate.ApprovalSubmission],
	stream *events.OperationStream,
) (gate.GateRequest[security.CapMutate], error) {
	return BuildGateRequest[security.CapMutate](security.CapabilityMutate, toolCredential, action, nodeID, params, risk, summary, approval, stream)
}

// OpEmitter 封装单次用例操作向可选 OperationStream 发射生命周期与状态机转移事件的共享辅助器（供 credential 与 inventory 复用）。
type OpEmitter struct {
	stream  *events.OperationStream
	clock   ports.Clock
	tool    string
	traceID security.TraceID
	opID    security.OperationID
	nodeID  algebraic.Option[inventory.NodeID]
	seq     atomic.Uint64
}

// NewOpEmitter 构造绑定单次操作标识的 OpEmitter；若 stream 或 clock 为 nil 则返回 nil（全部方法安全空操作）。
func NewOpEmitter(
	stream *events.OperationStream,
	clock ports.Clock,
	tool string,
	traceID security.TraceID,
	opID security.OperationID,
	nodeLabel string,
) *OpEmitter {
	if stream == nil || clock == nil {
		return nil
	}
	var nodeOpt algebraic.Option[inventory.NodeID]
	if nid, err := inventory.ParseNodeID(nodeLabel); err == nil {
		nodeOpt = algebraic.Some(nid)
	}
	return &OpEmitter{
		stream:  stream,
		clock:   clock,
		tool:    pickIf(tool != "", tool, toolCredential),
		traceID: traceID,
		opID:    opID,
		nodeID:  nodeOpt,
	}
}

func (e *OpEmitter) active() bool { return e != nil && e.stream != nil && !e.stream.IsClosed() }

// Emit 在事件流未关闭时生成单调递增序号的 EventMeta，调用 build 构造事件并发送至 OperationStream。
func (e *OpEmitter) Emit(ctx context.Context, build func(events.EventMeta) (events.Event, error)) {
	if !e.active() {
		return
	}
	meta, err := events.NewEventMeta(events.EventMetaSpec{
		TraceID:     e.traceID,
		OperationID: algebraic.Some(e.opID),
		OccurredAt:  e.clock.Now().UTC().Round(0),
		Seq:         e.seq.Add(1),
		NodeID:      e.nodeID,
	})
	if err != nil {
		return
	}
	if ev, evErr := build(meta); evErr == nil {
		_ = e.stream.Emit(ctx, ev)
	}
}

// EmitStarted 发射操作启动事件 *events.OperationStartedEvent。
func (e *OpEmitter) EmitStarted(ctx context.Context, capKind security.CapabilityKind, action, summary string) {
	e.Emit(ctx, func(meta events.EventMeta) (events.Event, error) {
		return events.NewOperationStartedEvent(events.OperationStartedSpec{
			Meta: meta, Capability: capKind, Tool: e.tool, Action: action, Summary: summary,
		})
	})
}

// EmitVaultSagaEvents 逐条发射 VaultSagaFSM 领域转移事件。
func (e *OpEmitter) EmitVaultSagaEvents(ctx context.Context, from, to fsm.VaultSagaStateKind, evs []fsm.VaultSagaEvent, terminal bool) {
	for _, fev := range evs {
		e.Emit(ctx, func(meta events.EventMeta) (events.Event, error) {
			return events.NewVaultSagaTransitionEvent(meta, from, to, fev, terminal)
		})
	}
}

// EmitCompleted 在有界非取消上下文中发射终态 *events.OperationCompletedEvent（携带可选 OutcomeUnknown）。
func (e *OpEmitter) EmitCompleted(
	ctx context.Context,
	capKind security.CapabilityKind,
	startedAt time.Time,
	outcome algebraic.Option[execution.ExecutionOutcome],
	finalErr error,
) {
	code, msg := "", "completed"
	if finalErr != nil {
		code, msg = classifyOpErrorCode(e.tool, finalErr), finalErr.Error()
	}
	e.emitTerminal(ctx, capKind, startedAt, outcome, finalErr == nil, code, msg)
}

// EmitFinal 统一在 defer 中按 returnedNormally 发射正常完成或 panic 失败终态事件（nil emitter 安全空操作）。
func (e *OpEmitter) EmitFinal(
	ctx context.Context,
	capKind security.CapabilityKind,
	startedAt time.Time,
	outcome algebraic.Option[execution.ExecutionOutcome],
	returnedNormally bool,
	panicMsg string,
	finalErr error,
) {
	if e == nil {
		return
	}
	if !returnedNormally {
		e.EmitPanicked(ctx, capKind, startedAt, outcome, panicMsg)
		return
	}
	e.EmitCompleted(ctx, capKind, startedAt, outcome, finalErr)
}

// EmitPanicked 在回调发生 panic 尚未正常返回时发射失败终态事件（Succeeded=false, Code="panic"），避免误发成功事件。
func (e *OpEmitter) EmitPanicked(
	ctx context.Context,
	capKind security.CapabilityKind,
	startedAt time.Time,
	outcome algebraic.Option[execution.ExecutionOutcome],
	msg string,
) {
	e.emitTerminal(ctx, capKind, startedAt, outcome, false, "panic", pickIf(msg != "", msg, "operation panicked"))
}

func (e *OpEmitter) emitTerminal(
	ctx context.Context,
	capKind security.CapabilityKind,
	startedAt time.Time,
	outcome algebraic.Option[execution.ExecutionOutcome],
	succeeded bool,
	code, msg string,
) {
	if !e.active() {
		return
	}
	emitCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), terminalEventEmitTimeout)
	defer cancel()
	e.Emit(emitCtx, func(meta events.EventMeta) (events.Event, error) {
		return events.NewOperationCompletedEvent(events.OperationCompletedSpec{
			Meta:       meta,
			Capability: capKind,
			Duration:   algebraic.FromStdDuration(max(e.clock.Since(startedAt), 0)),
			Outcome:    outcome,
			Succeeded:  succeeded,
			Code:       code,
			Message:    msg,
		})
	})
}

func classifyOpErrorCode(tool string, err error) string {
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
		return tool + "_error"
	}
}
