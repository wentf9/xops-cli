package events_test

import (
	"context"
	"encoding"
	jsonv2 "encoding/json/v2"
	"errors"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/playbook"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
)

// 编译期契约断言统一集中于 *_ext_test.go，验证公开接口满足性且零生产包级 var 污染。
var (
	_ events.Event = (*events.OperationStartedEvent)(nil)
	_ events.Event = (*events.OperationCompletedEvent)(nil)
	_ events.Event = (*events.OutputChunkEvent)(nil)
	_ events.Event = (*events.StepEvent)(nil)
	_ events.Event = (*events.FSMTransitionEvent)(nil)
	_ events.Event = (*events.ApprovalChallengeEvent)(nil)
	_ events.Event = (*events.TransferProgressEvent)(nil)
	_ events.Event = (*events.MetricSampleEvent)(nil)
	_ events.Event = (*events.AuditRecordEvent)(nil)
	_ events.Event = (*events.PoolStateEvent)(nil)
	_ events.Event = (*events.DiagnosticEvent)(nil)
	_ events.Event = (*events.BusDroppedEvent)(nil)

	_ jsonv2.UnmarshalerFrom = (*events.EventMeta)(nil)
	_ jsonv2.UnmarshalerFrom = (*events.EventEnvelope)(nil)
	_ jsonv2.UnmarshalerFrom = (*events.OperationStartedEvent)(nil)
	_ jsonv2.UnmarshalerFrom = (*events.OperationCompletedEvent)(nil)
	_ jsonv2.UnmarshalerFrom = (*events.OutputChunkEvent)(nil)
	_ jsonv2.UnmarshalerFrom = (*events.StepEvent)(nil)
	_ jsonv2.UnmarshalerFrom = (*events.FSMTransitionEvent)(nil)
	_ jsonv2.UnmarshalerFrom = (*events.ApprovalChallengeEvent)(nil)
	_ jsonv2.UnmarshalerFrom = (*events.TransferProgressEvent)(nil)
	_ jsonv2.UnmarshalerFrom = (*events.MetricSampleEvent)(nil)
	_ jsonv2.UnmarshalerFrom = (*events.AuditRecordEvent)(nil)
	_ jsonv2.UnmarshalerFrom = (*events.PoolStateEvent)(nil)
	_ jsonv2.UnmarshalerFrom = (*events.DiagnosticEvent)(nil)
	_ jsonv2.UnmarshalerFrom = (*events.BusDroppedEvent)(nil)

	_ encoding.TextAppender    = events.EventKindInvalid
	_ encoding.TextMarshaler   = events.EventKindInvalid
	_ encoding.TextUnmarshaler = (*events.EventKind)(nil)
	_ encoding.TextAppender    = events.EventClassInvalid
	_ encoding.TextMarshaler   = events.EventClassInvalid
	_ encoding.TextUnmarshaler = (*events.EventClass)(nil)
	_ encoding.TextAppender    = events.BackpressureInvalid
	_ encoding.TextMarshaler   = events.BackpressureInvalid
	_ encoding.TextUnmarshaler = (*events.BackpressurePolicy)(nil)
	_ encoding.TextAppender    = events.SeverityInvalid
	_ encoding.TextMarshaler   = events.SeverityInvalid
	_ encoding.TextUnmarshaler = (*events.Severity)(nil)
	_ encoding.TextAppender    = events.OutputStreamInvalid
	_ encoding.TextMarshaler   = events.OutputStreamInvalid
	_ encoding.TextUnmarshaler = (*events.OutputStreamKind)(nil)
	_ encoding.TextAppender    = events.AuditStageInvalid
	_ encoding.TextMarshaler   = events.AuditStageInvalid
	_ encoding.TextUnmarshaler = (*events.AuditStage)(nil)
	_ encoding.TextAppender    = events.PoolActionInvalid
	_ encoding.TextMarshaler   = events.PoolActionInvalid
	_ encoding.TextUnmarshaler = (*events.PoolEventAction)(nil)
	_ encoding.TextAppender    = events.DiagnosticScopeInvalid
	_ encoding.TextMarshaler   = events.DiagnosticScopeInvalid
	_ encoding.TextUnmarshaler = (*events.DiagnosticScope)(nil)
	_ encoding.TextAppender    = events.FSMMachineInvalid
	_ encoding.TextMarshaler   = events.FSMMachineInvalid
	_ encoding.TextUnmarshaler = (*events.FSMMachineKind)(nil)

	_ events.AuditWriter = events.AuditWriterFunc(nil)
)

// assertValueJSONMarshaler 在编译期验证 //xops:opaque 值类型实现 jsonv2.MarshalerTo（不触发外部字面量构造）。
func assertValueJSONMarshaler[T jsonv2.MarshalerTo]() {}

func TestCompileTimeValueJSONMarshalers(_ *testing.T) {
	assertValueJSONMarshaler[events.EventMeta]()
	assertValueJSONMarshaler[events.EventEnvelope]()
	assertValueJSONMarshaler[events.OperationStartedEvent]()
	assertValueJSONMarshaler[events.OperationCompletedEvent]()
	assertValueJSONMarshaler[events.OutputChunkEvent]()
	assertValueJSONMarshaler[events.StepEvent]()
	assertValueJSONMarshaler[events.FSMTransitionEvent]()
	assertValueJSONMarshaler[events.ApprovalChallengeEvent]()
	assertValueJSONMarshaler[events.TransferProgressEvent]()
	assertValueJSONMarshaler[events.MetricSampleEvent]()
	assertValueJSONMarshaler[events.AuditRecordEvent]()
	assertValueJSONMarshaler[events.PoolStateEvent]()
	assertValueJSONMarshaler[events.DiagnosticEvent]()
	assertValueJSONMarshaler[events.BusDroppedEvent]()
}

func checkExt(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestExternalPublicContractAndExhaustiveSwitch 验证外部调用方视角下的端到端双层事件流与穷尽 Event 匹配。
func TestExternalPublicContractAndExhaustiveSwitch(t *testing.T) {
	tid, err := security.ParseTraceID("trace-ext-001")
	checkExt(t, err)
	opID, err := security.ParseOperationID("op-ext-001")
	checkExt(t, err)
	now := time.Date(2026, 11, 25, 4, 30, 0, 123456789, time.UTC)
	meta, err := events.NewEventMeta(events.EventMetaSpec{
		TraceID: tid, OperationID: algebraic.Some(opID), OccurredAt: now, Seq: 1,
	})
	checkExt(t, err)
	bus, err := events.NewSystemBus(events.SystemBusConfig{DefaultSubscriberBuffer: 8})
	checkExt(t, err)
	defer bus.Close()

	verifyExtAuditDispatch(t, bus, meta)
	evs := buildExtOpLifecycleEvents(t, meta)
	verifyExtOperationStreamFold(t, tid, opID, evs)
	if label := classifyEventExhaustive(t, evs[0]); label != "operation_started" {
		t.Fatalf("classifyEventExhaustive = %q", label)
	}
}

func verifyExtAuditDispatch(t *testing.T, bus *events.SystemBus, meta events.EventMeta) {
	t.Helper()
	var auditCount int
	auditDisp, err := events.NewAuditDispatcher(events.AuditDispatcherConfig{
		Writer: events.AuditWriterFunc(func(_ context.Context, ev *events.AuditRecordEvent) error {
			auditCount++
			if ev.Stage() != events.AuditStageAuthorized {
				return errors.New("unexpected stage")
			}
			return nil
		}),
		HaltOnWriteError: true,
		DiagnosticBus:    bus,
	})
	checkExt(t, err)
	binding, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityExecute, Tool: "terminal_exec", Action: "run", NodeID: "web-01",
	})
	checkExt(t, err)
	auditEv, err := events.NewAuditRecordEvent(events.AuditRecordSpec{
		Meta: meta, Stage: events.AuditStageAuthorized, ProcessInstanceID: "proc-ext-1",
		Capability: security.CapabilityExecute, Decision: security.NewDecisionAllow("policy ok"),
		Risk: security.RiskModerate, Binding: algebraic.Some(binding), Duration: algebraic.ZeroDuration(),
	})
	checkExt(t, err)
	checkExt(t, auditDisp.DispatchEvent(context.Background(), auditEv))
	if auditCount != 1 {
		t.Fatalf("auditCount = %d, want 1", auditCount)
	}
}

func buildExtOpLifecycleEvents(t *testing.T, meta events.EventMeta) []events.Event {
	t.Helper()
	startEv, err := events.NewOperationStartedEvent(events.OperationStartedSpec{
		Meta: meta, Capability: security.CapabilityExecute, Tool: "terminal_exec", Action: "run",
	})
	checkExt(t, err)
	chunkEv, err := events.NewOutputChunkEvent(events.OutputChunkSpec{
		Meta: meta.WithSeq(2), Stream: events.OutputStreamStdout, ChunkIndex: 0, Data: []byte("hello\n"),
	})
	checkExt(t, err)
	completedOut, err := execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	checkExt(t, err)
	doneEv, err := events.NewOperationCompletedEvent(events.OperationCompletedSpec{
		Meta: meta.WithSeq(3), Capability: security.CapabilityExecute,
		Duration: algebraic.FromStdDuration(25 * time.Millisecond),
		Outcome:  algebraic.Some[execution.ExecutionOutcome](completedOut), Succeeded: true,
	})
	checkExt(t, err)
	return []events.Event{startEv, chunkEv, doneEv}
}

func verifyExtOperationStreamFold(t *testing.T, tid security.TraceID, opID security.OperationID, evs []events.Event) {
	t.Helper()
	stream, err := events.NewOperationStream(events.OperationStreamConfig{
		TraceID: tid, OperationID: opID, OperationBuffer: 8,
	})
	checkExt(t, err)
	var summary events.OperationSummary
	runErr := conc.RunWait(context.Background(), func(ctx context.Context, n *conc.Nursery) error {
		if goErr := n.Go(func(childCtx context.Context) error {
			defer stream.Close()
			for _, ev := range evs {
				if emitErr := stream.Emit(childCtx, ev); emitErr != nil {
					return emitErr
				}
			}
			return nil
		}); goErr != nil {
			return goErr
		}
		var foldErr error
		summary, foldErr = events.FoldOperationStreamSummary(ctx, stream)
		return foldErr
	})
	checkExt(t, runErr)
	if !summary.IsValid() || !summary.Started() || !summary.Completed() || !summary.Succeeded() || summary.OutputBytes() != 6 {
		t.Fatalf("unexpected summary: valid=%v started=%v completed=%v succeeded=%v bytes=%d",
			summary.IsValid(), summary.Started(), summary.Completed(), summary.Succeeded(), summary.OutputBytes())
	}
}

func classifyEventExhaustive(t *testing.T, ev events.Event) string {
	t.Helper()
	switch v := ev.(type) {
	case *events.OperationStartedEvent:
		return v.Kind().String()
	case *events.OperationCompletedEvent:
		return v.Kind().String()
	case *events.OutputChunkEvent:
		return v.Kind().String()
	case *events.StepEvent:
		return v.Kind().String()
	case *events.FSMTransitionEvent:
		return v.Kind().String()
	case *events.ApprovalChallengeEvent:
		return v.Kind().String()
	case *events.TransferProgressEvent:
		return v.Kind().String()
	case *events.MetricSampleEvent:
		return v.Kind().String()
	case *events.AuditRecordEvent:
		return v.Kind().String()
	case *events.PoolStateEvent:
		return v.Kind().String()
	case *events.DiagnosticEvent:
		return v.Kind().String()
	case *events.BusDroppedEvent:
		return v.Kind().String()
	default:
		t.Fatalf("unexpected event variant %T", ev)
		return ""
	}
}

// TestExternalTypedNilAndZeroFailClosed 验证外部包对全部事件变体的 typed-nil 与零值调用绝不 panic 且严格失败关闭。
func TestExternalTypedNilAndZeroFailClosed(t *testing.T) {
	var (
		nStart *events.OperationStartedEvent
		nComp  *events.OperationCompletedEvent
		nChunk *events.OutputChunkEvent
		nStep  *events.StepEvent
		nFSM   *events.FSMTransitionEvent
		nAppr  *events.ApprovalChallengeEvent
		nProg  *events.TransferProgressEvent
		nMet   *events.MetricSampleEvent
		nAud   *events.AuditRecordEvent
		nPool  *events.PoolStateEvent
		nDiag  *events.DiagnosticEvent
		nDrop  *events.BusDroppedEvent
	)
	nilEvents := []events.Event{nStart, nComp, nChunk, nStep, nFSM, nAppr, nProg, nMet, nAud, nPool, nDiag, nDrop}
	for i, ev := range nilEvents {
		if ev.IsValid() || ev.Kind() != events.EventKindInvalid || ev.Class() != events.EventClassInvalid ||
			ev.Backpressure() != events.BackpressureInvalid || ev.CoalesceKey() != "" || ev.Meta().IsValid() {
			t.Fatalf("nil event #%d failed closed invariant", i)
		}
		if _, err := events.MarshalEvent(ev); !errors.Is(err, events.ErrInvalidEvent) {
			t.Fatalf("MarshalEvent(nil #%d) = %v, want ErrInvalidEvent", i, err)
		}
	}
	// 验证指针访问器对 typed-nil 零空指针解引用。
	if nStart.Tool() != "" || nComp.Succeeded() || nChunk.Data() != nil || nStep.Status() != playbook.StepStatusInvalid ||
		nFSM.Machine() != events.FSMMachineInvalid || nAppr.Phase() != fsm.ApprovalPhaseInvalid ||
		nProg.BytesTransferred() != 0 || nMet.Labels() != nil || nAud.Decision().Kind() != security.DecisionKindDeny ||
		nPool.Action() != events.PoolActionInvalid || nDiag.Attrs() != nil || nDrop.DroppedTotal() != 0 {
		t.Fatal("typed-nil accessors did not fail closed")
	}

	var zeroStream events.OperationStream
	var zeroBus events.SystemBus
	var zeroSub events.SystemSubscription
	var zeroDisp events.AuditDispatcher
	var zeroEnv events.EventEnvelope
	if !zeroStream.IsClosed() || !zeroBus.IsClosed() || !zeroSub.IsClosed() || !zeroDisp.IsHalted() || zeroEnv.IsValid() {
		t.Fatal("zero-value runtime primitives must fail closed")
	}
}
