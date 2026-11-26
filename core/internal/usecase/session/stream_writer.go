package session

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/ports"
)

// terminalEventEmitTimeout 为终态 OperationCompletedEvent 发射设定有界宽限：
// 脱离已取消的父 ctx 确保终态事件不被静默丢弃，同时有界防止无人读取的满缓冲阻塞停机。
const terminalEventEmitTimeout = 50 * time.Millisecond

// operationEmitter 封装单次受权会话向可选 OperationStream 发射强类型事件的全部状态；
// 当 stream 为 nil 时全部方法静默空转，绝不阻断核心执行路径。
type operationEmitter struct {
	stream                    *events.OperationStream
	clock                     ports.Clock
	traceID                   security.TraceID
	opID                      security.OperationID
	nodeID                    algebraic.Option[inventory.NodeID]
	capability                security.CapabilityKind
	seq, stdoutSeq, stderrSeq atomic.Uint64
}

func newOperationEmitterFor(stream *events.OperationStream, clock ports.Clock, traceID security.TraceID, opID security.OperationID, nodeLabel string, capKind security.CapabilityKind) *operationEmitter {
	if stream == nil {
		return nil
	}
	var nodeOpt algebraic.Option[inventory.NodeID]
	if nid, err := inventory.ParseNodeID(nodeLabel); err == nil {
		nodeOpt = algebraic.Some(nid)
	}
	if !capKind.IsValid() {
		capKind = security.CapabilityExecute
	}
	return &operationEmitter{stream: stream, clock: clock, traceID: traceID, opID: opID, nodeID: nodeOpt, capability: capKind}
}

func (e *operationEmitter) active() bool { return e != nil && e.stream != nil && !e.stream.IsClosed() }
func (e *operationEmitter) nextMeta() (events.EventMeta, error) {
	if !e.active() {
		return zeroVal[events.EventMeta](), ports.ErrClosed
	}
	return events.NewEventMeta(events.EventMetaSpec{
		TraceID: e.traceID, OperationID: algebraic.Some(e.opID),
		OccurredAt: e.clock.Now().UTC().Round(0), Seq: e.seq.Add(1), NodeID: e.nodeID,
	})
}
func (e *operationEmitter) emitStarted(ctx context.Context, action string, planDigest plan.PlanDigest, summary string) {
	if meta, err := e.nextMeta(); err == nil {
		if ev, err := events.NewOperationStartedEvent(events.OperationStartedSpec{Meta: meta, Capability: e.capability, Tool: "ssh", Action: action, PlanDigest: algebraic.Some(planDigest), Summary: summary}); err == nil {
			_ = e.stream.Emit(ctx, ev)
		}
	}
}
func (e *operationEmitter) emitOutputChunk(ctx context.Context, kind events.OutputStreamKind, data []byte) {
	if len(data) == 0 || !e.active() {
		return
	}
	counter := &e.stdoutSeq
	if kind == events.OutputStreamStderr {
		counter = &e.stderrSeq
	}
	for off := 0; off < len(data); off += outputChunkMaxSize {
		meta, err := e.nextMeta()
		if err != nil {
			return
		}
		ev, err := events.NewOutputChunkEvent(events.OutputChunkSpec{Meta: meta, Stream: kind, ChunkIndex: counter.Add(1) - 1, Data: data[off:min(off+outputChunkMaxSize, len(data))]})
		if err != nil || e.stream.Emit(ctx, ev) != nil {
			return
		}
	}
}
func (e *operationEmitter) emitCompleted(ctx context.Context, startedAt time.Time, outcome execution.ExecutionOutcome, finalErr error) {
	meta, err := e.nextMeta()
	if err != nil {
		return
	}
	outOpt, succeeded, code, msg := classifyCompletedEventFields(outcome, finalErr)
	if ev, err := events.NewOperationCompletedEvent(events.OperationCompletedSpec{Meta: meta, Capability: e.capability, Duration: algebraic.FromStdDuration(max(e.clock.Since(startedAt), 0)), Outcome: outOpt, Succeeded: succeeded, Code: code, Message: msg}); err == nil {
		emitCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), terminalEventEmitTimeout)
		defer cancel()
		_ = e.stream.Emit(emitCtx, ev)
	}
}

// classifyCompletedEventFields 穷尽投影 (ExecutionOutcome, finalErr) 至 OperationCompletedEvent 字段，
// 严格维持与 events.completedOutcomeConsistent 的跨字段不变量：
// 若远端命令返回退出码 0 但门控终态审计/熔断报错（finalErr != nil），必须发射 Succeeded=false 且 Outcome=None。
func classifyCompletedEventFields(outcome execution.ExecutionOutcome, finalErr error) (algebraic.Option[execution.ExecutionOutcome], bool, string, string) {
	if outcome != nil && outcome.IsValid() {
		switch v := outcome.(type) {
		case *execution.OutcomeCompleted:
			if v.Succeeded() {
				if finalErr != nil {
					return algebraic.None[execution.ExecutionOutcome](), false, classifyFinalErrorCode(finalErr), finalErr.Error()
				}
				return algebraic.Some(outcome), true, "", "completed"
			}
			return algebraic.Some(outcome), false, "non_zero_exit", "completed with non-zero status"
		case *execution.OutcomeNotStarted:
			return algebraic.Some(outcome), false, sanitizeEventCode(v.Code(), "not_started"), v.Reason()
		case *execution.OutcomeUnknown:
			return algebraic.Some(outcome), false, sanitizeEventCode(v.Code(), "outcome_unknown"), v.Reason()
		default:
			return algebraic.None[execution.ExecutionOutcome](), false, "invalid_outcome", "unexpected execution outcome"
		}
	}
	if finalErr != nil {
		return algebraic.None[execution.ExecutionOutcome](), false, classifyFinalErrorCode(finalErr), finalErr.Error()
	}
	return algebraic.None[execution.ExecutionOutcome](), true, "", "completed"
}

func classifyFinalErrorCode(err error) string {
	if errors.Is(err, ports.ErrAuditPostWrite) {
		return "audit_post_write_failed"
	}
	if errors.Is(err, gate.ErrGateHalted) {
		return "gate_halted"
	}
	return "session_error"
}
func sanitizeEventCode(raw, fallback string) string {
	if raw == "" || len(raw) > 64 {
		return fallback
	}
	for i := range len(raw) {
		if raw[i] < 0x21 || raw[i] > 0x7E {
			return fallback
		}
	}
	return raw
}

type chunkTeeWriter struct {
	ctx     context.Context
	dst     io.Writer
	emitter *operationEmitter
	kind    events.OutputStreamKind
}

func wrapOutputWriter(ctx context.Context, dst io.Writer, emitter *operationEmitter, kind events.OutputStreamKind) io.Writer {
	if !emitter.active() {
		return dst
	}
	return &chunkTeeWriter{ctx: ctx, dst: dst, emitter: emitter, kind: kind}
}
func (w *chunkTeeWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n, writeErr := len(p), error(nil)
	if w.dst != nil {
		n, writeErr = w.dst.Write(p)
	}
	if n > 0 {
		w.emitter.emitOutputChunk(w.ctx, w.kind, p[:n])
	}
	return n, writeErr
}
