package automation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/playbook"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/ports"
)

func closeStream(st *events.OperationStream) {
	if st != nil {
		st.Close()
	}
}

func closeAllStreams(batchStream *events.OperationStream, nodeStreams map[inventory.NodeID]*events.OperationStream) {
	closeStream(batchStream)
	for _, st := range nodeStreams {
		closeStream(st)
	}
}

// streamEmitter 封装向隔离 OperationStream 发射强类型事件与有界终态事件的并发安全辅助器。
type streamEmitter struct {
	stream                    *events.OperationStream
	clock                     ports.Clock
	traceID                   security.TraceID
	opID                      security.OperationID
	nodeID                    algebraic.Option[inventory.NodeID]
	capability                security.CapabilityKind
	seq, stdoutSeq, stderrSeq atomic.Uint64
}

func newStreamEmitter(stream *events.OperationStream, clock ports.Clock, traceID security.TraceID, opID security.OperationID, nodeID algebraic.Option[inventory.NodeID], capKind security.CapabilityKind) *streamEmitter {
	if stream == nil || clock == nil {
		return nil
	}
	// 当流自身已绑定独立 TraceID/OperationID 时以流绑定标识为准，避免跨流 ID 失配导致静默丢弃。
	if stream.TraceID().IsValid() && stream.OperationID().IsValid() {
		traceID, opID = stream.TraceID(), stream.OperationID()
	}
	return &streamEmitter{stream: stream, clock: clock, traceID: traceID, opID: opID, nodeID: nodeID, capability: capKind}
}

func (e *streamEmitter) active() bool { return e != nil && e.stream != nil && !e.stream.IsClosed() }

func (e *streamEmitter) nextMeta(nodeOpt algebraic.Option[inventory.NodeID]) (events.EventMeta, error) {
	if !e.active() {
		return zeroVal[events.EventMeta](), ports.ErrClosed
	}
	return events.NewEventMeta(events.EventMetaSpec{
		TraceID: e.traceID, OperationID: algebraic.Some(e.opID),
		OccurredAt: e.clock.Now().UTC().Round(0), Seq: e.seq.Add(1), NodeID: nodeOpt,
	})
}

func (e *streamEmitter) emitStarted(ctx context.Context, action string, planDigest algebraic.Option[plan.PlanDigest], summary string) {
	if !e.active() {
		return
	}
	meta, err := e.nextMeta(e.nodeID)
	if err != nil {
		return
	}
	ev, err := events.NewOperationStartedEvent(events.OperationStartedSpec{
		Meta: meta, Capability: e.capability, Tool: toolAutomation,
		Action: action, PlanDigest: planDigest, Summary: summary,
	})
	if err == nil {
		_ = e.stream.Emit(ctx, ev)
	}
}

func (e *streamEmitter) emitChunk(ctx context.Context, kind events.OutputStreamKind, data []byte) {
	if len(data) == 0 || !e.active() {
		return
	}
	counter := pickIf(kind == events.OutputStreamStderr, &e.stderrSeq, &e.stdoutSeq)
	for off := 0; off < len(data); off += outputChunkMaxSize {
		meta, err := e.nextMeta(e.nodeID)
		if err != nil {
			return
		}
		ev, err := events.NewOutputChunkEvent(events.OutputChunkSpec{
			Meta: meta, Stream: kind, ChunkIndex: counter.Add(1) - 1,
			Data: data[off:min(off+outputChunkMaxSize, len(data))],
		})
		if err != nil || e.stream.Emit(ctx, ev) != nil {
			return
		}
	}
}

func (e *streamEmitter) emitStep(ctx context.Context, pbID playbook.PlaybookID, rec playbook.StepExecutionRecord) {
	if !e.active() || !rec.IsValid() {
		return
	}
	meta, err := e.nextMeta(algebraic.Some(rec.NodeID()))
	if err != nil {
		return
	}
	ev, err := events.NewStepEvent(events.StepEventSpec{
		Meta: meta, PlaybookID: algebraic.Some(pbID), StepID: rec.StepID(),
		Status: rec.Status(), Duration: rec.Duration(), Outcome: rec.Outcome(), Message: rec.Message(),
	})
	if err == nil {
		_ = e.stream.Emit(ctx, ev)
	}
}

func (e *streamEmitter) emitEnsureTransition(ctx context.Context, nodeID inventory.NodeID, from, to fsm.EnsurePhase, evs []fsm.EnsureEvent, terminal bool) {
	if !e.active() || len(evs) == 0 {
		return
	}
	for _, fev := range evs {
		meta, err := e.nextMeta(algebraic.Some(nodeID))
		if err != nil {
			return
		}
		if trEv, tErr := events.NewEnsureTransitionEvent(meta, from, to, fev, terminal); tErr == nil {
			_ = e.stream.Emit(ctx, trEv)
		}
	}
}

func (e *streamEmitter) emitCompleted(ctx context.Context, startedAt time.Time, outcome execution.ExecutionOutcome, succeeded bool, code, msg string) {
	if !e.active() {
		return
	}
	meta, err := e.nextMeta(e.nodeID)
	if err != nil {
		return
	}
	outOpt, finalOK, finalCode := normalizeCompletedFields(outcome, succeeded, code)
	ev, err := events.NewOperationCompletedEvent(events.OperationCompletedSpec{
		Meta: meta, Capability: e.capability,
		Duration: algebraic.FromStdDuration(max(e.clock.Since(startedAt), 0)),
		Outcome:  outOpt, Succeeded: finalOK, Code: finalCode, Message: msg,
	})
	if err != nil {
		return
	}
	emitCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), terminalEventTimeout)
	defer cancel()
	_ = e.stream.Emit(emitCtx, ev)
}

func normalizeCompletedFields(outcome execution.ExecutionOutcome, succeeded bool, code string) (algebraic.Option[execution.ExecutionOutcome], bool, string) {
	if outcome == nil || !outcome.IsValid() {
		return algebraic.None[execution.ExecutionOutcome](), succeeded, sanitizeEventCode(code)
	}
	switch v := outcome.(type) {
	case *execution.OutcomeUnknown:
		return algebraic.Some(outcome), false, sanitizeEventCode(pickIf(code != "", code, v.Code()))
	case *execution.OutcomeNotStarted:
		return algebraic.Some(outcome), false, sanitizeEventCode(pickIf(code != "", code, v.Code()))
	case *execution.OutcomeCompleted:
		if v.Succeeded() && !succeeded {
			// 远端退出 0 但存在后置故障（如审计/落盘错）：剥离 outcome 以严格维持 completedOutcomeConsistent。
			return algebraic.None[execution.ExecutionOutcome](), false, sanitizeEventCode(code)
		}
		return algebraic.Some(outcome), v.Succeeded(), sanitizeEventCode(code)
	default:
		return algebraic.None[execution.ExecutionOutcome](), false, "invalid_outcome"
	}
}

func sanitizeEventCode(raw string) string {
	if raw == "" || len(raw) > 64 {
		return ""
	}
	for i := range len(raw) {
		if raw[i] < 0x21 || raw[i] > 0x7E {
			return ""
		}
	}
	return raw
}

// boundedCaptureWriter 在限流字节上限内同时捕获输出并向隔离 OperationStream 实时流式推送 OutputChunkEvent。
type boundedCaptureWriter struct {
	ctx       context.Context
	emitter   *streamEmitter
	kind      events.OutputStreamKind
	limit     uint64
	mu        sync.Mutex
	buf       bytes.Buffer
	total     uint64
	truncated bool
}

func newBoundedCaptureWriter(ctx context.Context, emitter *streamEmitter, kind events.OutputStreamKind, limit uint64) *boundedCaptureWriter {
	return &boundedCaptureWriter{ctx: ctx, emitter: emitter, kind: kind, limit: limit}
}

func (w *boundedCaptureWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	w.mu.Lock()
	var toEmit []byte
	if w.total < w.limit {
		take := min(uint64(len(p)), w.limit-w.total)
		_, _ = w.buf.Write(p[:take])
		w.total += take
		toEmit = bytes.Clone(p[:take])
		if take < uint64(len(p)) {
			w.truncated = true
		}
	} else {
		w.truncated = true
	}
	w.mu.Unlock()
	if len(toEmit) > 0 {
		w.emitter.emitChunk(w.ctx, w.kind, toEmit)
	}
	return len(p), nil
}

func (w *boundedCaptureWriter) snapshot() ([]byte, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return bytes.Clone(w.buf.Bytes()), w.truncated
}

func makeNotStartedOutcome(phase execution.StartPhase, code string, err error) execution.ExecutionOutcome {
	out, _ := execution.NewOutcomeNotStarted(phase, code, errString(err, ""))
	return out
}

func classifyPostStartOutcome(ctx context.Context, out execution.ExecutionOutcome, waitErr error) execution.ExecutionOutcome {
	if out != nil && out.IsValid() {
		return out
	}
	phase, code := execution.ExecPhaseTransportLost, "transport_lost"
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(waitErr, context.DeadlineExceeded) {
		phase, code = execution.ExecPhaseTimedOut, "timed_out"
	} else if ctx.Err() != nil || errors.Is(waitErr, context.Canceled) {
		phase, code = execution.ExecPhaseCanceled, "canceled"
	}
	unk, _ := execution.NewOutcomeUnknown(phase, code, errString(waitErr, "remote session ended without terminal outcome"))
	return unk
}

func outcomeTruncated(out execution.ExecutionOutcome) bool {
	c, ok := out.(*execution.OutcomeCompleted)
	return ok && c.Truncated()
}

func applyOptionalTimeout(ctx context.Context, durOpt algebraic.Option[algebraic.Duration]) (context.Context, context.CancelFunc) {
	if d, ok := durOpt.Get(); ok && d.IsPositive() {
		return context.WithTimeout(ctx, d.Std())
	}
	return ctx, func() {}
}

func fillMissingBatchResults(targets []TargetNode, results []BatchNodeResult, ctx context.Context, runErr error, halted bool) {
	fallbackErr := firstErr(runErr, context.Cause(ctx), ctx.Err(), ErrBatchFailed)
	if halted && !errors.Is(fallbackErr, gate.ErrGateHalted) {
		fallbackErr = gate.ErrGateHalted
	}
	phase := pickIf(halted, execution.StartPhaseAuthorize, execution.StartPhaseValidate)
	code := pickIf(halted, "gate_halted", "batch_aborted")
	for i, target := range targets {
		if !results[i].IsValid() {
			results[i] = makeNotStartedBatchResult(target.nodeID, phase, code, fallbackErr, 0)
		}
	}
}

func foldBatchExecReport(results []BatchNodeResult, dur algebraic.Duration) BatchExecReport {
	var okCnt, failCnt, unkCnt, notStartedCnt int
	for _, r := range results {
		switch {
		case r.IsOutcomeUnknown():
			unkCnt++
		case r.Succeeded():
			okCnt++
		case r.IsNotStarted():
			notStartedCnt++
			failCnt++
		default:
			failCnt++
		}
	}
	return BatchExecReport{
		results: results, succeededCount: okCnt, failedCount: failCnt,
		unknownCount: unkCnt, notStartedCount: notStartedCnt,
		hasUnknownOutcome: unkCnt > 0, duration: dur, valid: len(results) > 0,
	}
}

func findFirstUnknownBatchOutcome(results []BatchNodeResult) execution.ExecutionOutcome {
	for _, r := range results {
		if r.IsOutcomeUnknown() {
			return r.outcome
		}
	}
	return nil
}

func classifyBatchRunError(report BatchExecReport, firstUnknown execution.ExecutionOutcome, runErr error, halted bool) error {
	if firstUnknown != nil {
		cause := ErrUncertainOutcome
		if halted {
			cause = fmt.Errorf("%w: %w", ErrUncertainOutcome, gate.ErrGateHalted)
		} else if runErr != nil && !errors.Is(runErr, ErrUncertainOutcome) {
			cause = fmt.Errorf("%w: %w", ErrUncertainOutcome, runErr)
		}
		if wrapped, err := gate.WrapOutcomeError(firstUnknown, cause); err == nil {
			return wrapped
		}
		return cause
	}
	if halted && !errors.Is(runErr, gate.ErrGateHalted) {
		return pickIf[error](runErr != nil, fmt.Errorf("%w: %w", gate.ErrGateHalted, runErr), gate.ErrGateHalted)
	}
	if runErr != nil {
		return runErr
	}
	if report.failedCount > 0 {
		return fmt.Errorf("%w: succeeded=%d failed=%d", ErrBatchFailed, report.succeededCount, report.failedCount)
	}
	return nil
}

func batchCompletedFields(report BatchExecReport, firstUnknown execution.ExecutionOutcome, gateErr error, panicked bool) (execution.ExecutionOutcome, bool, string, string) {
	if panicked {
		return nil, false, "operation_panicked", "batch exec panicked"
	}
	if firstUnknown != nil {
		return firstUnknown, false, "outcome_unknown", "batch exec has unknown node outcome"
	}
	if gateErr != nil {
		return nil, false, pickIf(errors.Is(gateErr, gate.ErrGateHalted), "gate_halted", "batch_failed"), gateErr.Error()
	}
	return nil, report.failedCount == 0, "", "completed"
}

func classifyNodeCompletedMeta(res BatchNodeResult) (string, string) {
	if !res.IsValid() {
		return "invalid_result", "node result invalid"
	}
	if res.Succeeded() {
		return "", "completed"
	}
	if res.IsOutcomeUnknown() {
		return "outcome_unknown", pickIf(res.errMsg != "", res.errMsg, "execution outcome unknown")
	}
	return "node_failed", pickIf(res.errMsg != "", res.errMsg, "node execution failed")
}

func makeNotStartedBatchResult(nodeID inventory.NodeID, phase execution.StartPhase, code string, err error, elapsed time.Duration) BatchNodeResult {
	return BatchNodeResult{
		nodeID: nodeID, outcome: makeNotStartedOutcome(phase, code, err),
		duration: algebraic.FromStdDuration(max(elapsed, 0)),
		errMsg:   errString(err, ""), err: err, valid: true,
	}
}
