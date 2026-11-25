package events

import (
	"context"
	"fmt"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/playbook"
	"github.com/wentf9/xops-cli/core/domain/security"
)

// FoldEvents 以纯函数方式按序将事件切片折叠为聚合状态 Acc（ADR-010）；遇 nil 函数或无效事件即失败关闭。
//
//xops:syncclosure
func FoldEvents[Acc any](initial Acc, items []Event, fn func(acc Acc, ev Event) (Acc, error)) (Acc, error) {
	if fn == nil {
		return zeroVal[Acc](), ErrInvalidFoldFunc
	}
	acc := initial
	for i, ev := range items {
		if ev == nil || !ev.IsValid() {
			return zeroVal[Acc](), fmt.Errorf("%w: items[%d] 无效", ErrInvalidEvent, i)
		}
		next, err := fn(acc, ev)
		if err != nil {
			return zeroVal[Acc](), err
		}
		acc = next
	}
	return acc, nil
}

// FoldStream 持续消费 OperationStream 直至确定性 EOF，将全部事件按序纯函数折叠为最终聚合状态 Acc。
//
//xops:syncclosure
func FoldStream[Acc any](ctx context.Context, stream *OperationStream, initial Acc, fn func(acc Acc, ev Event) (Acc, error)) (Acc, error) {
	if stream == nil || !stream.initialized {
		return zeroVal[Acc](), ErrStreamNotInitialized
	}
	if ctx == nil {
		return zeroVal[Acc](), ErrNilContext
	}
	if fn == nil {
		return zeroVal[Acc](), ErrInvalidFoldFunc
	}
	acc := initial
	for {
		ev, ok, err := stream.Next(ctx)
		if err != nil {
			return zeroVal[Acc](), err
		}
		if !ok {
			return acc, nil
		}
		next, err := fn(acc, ev)
		if err != nil {
			return zeroVal[Acc](), err
		}
		acc = next
	}
}

// OperationSummary 表示单次操作事件流纯函数折叠产出的不可变摘要；零值恒无效并单调锁存 HasUnknownOutcome。
//
//xops:opaque
//xops:failclosed
type OperationSummary struct {
	traceID                                                                                     security.TraceID
	opID                                                                                        security.OperationID
	started, completed, succeeded, hasUnknownOutcome, valid                                     bool
	totalEvents, outputChunks, outputBytes, stepEvents, fsmTransitions, approvalCh, progressCnt uint64
	latestTransferBytes                                                                         uint64
	duration                                                                                    algebraic.Duration
}

func (s OperationSummary) IsValid() bool { return s.valid && s.traceID.IsValid() && s.opID.IsValid() }
func (s OperationSummary) IsZero() bool  { return !s.IsValid() }
func (s OperationSummary) TraceID() security.TraceID {
	return pickIf(s.IsValid(), s.traceID, zeroVal[security.TraceID]())
}
func (s OperationSummary) OperationID() security.OperationID {
	return pickIf(s.IsValid(), s.opID, zeroVal[security.OperationID]())
}
func (s OperationSummary) Started() bool              { return s.IsValid() && s.started }
func (s OperationSummary) Completed() bool            { return s.IsValid() && s.completed }
func (s OperationSummary) Succeeded() bool            { return s.IsValid() && s.succeeded && !s.hasUnknownOutcome }
func (s OperationSummary) HasUnknownOutcome() bool    { return s.IsValid() && s.hasUnknownOutcome }
func (s OperationSummary) TotalEvents() uint64        { return pickIf(s.IsValid(), s.totalEvents, 0) }
func (s OperationSummary) OutputChunks() uint64       { return pickIf(s.IsValid(), s.outputChunks, 0) }
func (s OperationSummary) OutputBytes() uint64        { return pickIf(s.IsValid(), s.outputBytes, 0) }
func (s OperationSummary) StepEvents() uint64         { return pickIf(s.IsValid(), s.stepEvents, 0) }
func (s OperationSummary) FSMTransitions() uint64     { return pickIf(s.IsValid(), s.fsmTransitions, 0) }
func (s OperationSummary) ApprovalChallenges() uint64 { return pickIf(s.IsValid(), s.approvalCh, 0) }
func (s OperationSummary) ProgressUpdates() uint64    { return pickIf(s.IsValid(), s.progressCnt, 0) }
func (s OperationSummary) LatestTransferBytes() uint64 {
	return pickIf(s.IsValid(), s.latestTransferBytes, 0)
}
func (s OperationSummary) Duration() algebraic.Duration {
	return pickIf(s.IsValid(), s.duration, algebraic.ZeroDuration())
}

// Equal 按值严格比对两个 OperationSummary 是否均有效且全部字段完全相等（零值永不相等）。
func (s OperationSummary) Equal(o OperationSummary) bool {
	return s.IsValid() && o.IsValid() && s.traceID.Equal(o.traceID) && s.opID.Equal(o.opID) &&
		s.started == o.started && s.completed == o.completed && s.succeeded == o.succeeded &&
		s.hasUnknownOutcome == o.hasUnknownOutcome && s.totalEvents == o.totalEvents &&
		s.outputChunks == o.outputChunks && s.outputBytes == o.outputBytes && s.stepEvents == o.stepEvents &&
		s.fsmTransitions == o.fsmTransitions && s.approvalCh == o.approvalCh &&
		s.progressCnt == o.progressCnt && s.latestTransferBytes == o.latestTransferBytes && s.duration.Equal(o.duration)
}

// FoldOperationSummary 以纯函数方式将单次操作的事件切片归约为不可变 OperationSummary。
func FoldOperationSummary(items []Event) (OperationSummary, error) {
	if len(items) == 0 {
		return OperationSummary{}, fmt.Errorf("%w: 空事件切片无法折叠 OperationSummary", ErrInvalidEvent)
	}
	return FoldEvents(OperationSummary{}, items, applySummaryEvent)
}

// FoldOperationStreamSummary 排空 OperationStream 直至确定性 EOF 并折叠为不可变 OperationSummary。
func FoldOperationStreamSummary(ctx context.Context, stream *OperationStream) (OperationSummary, error) {
	if stream == nil || !stream.initialized {
		return OperationSummary{}, ErrStreamNotInitialized
	}
	return FoldStream(ctx, stream, OperationSummary{traceID: stream.traceID, opID: stream.opID, valid: true}, applySummaryEvent)
}

func applySummaryEvent(acc OperationSummary, ev Event) (OperationSummary, error) {
	next, err := bindSummaryIdentity(acc, ev)
	if err != nil {
		return OperationSummary{}, err
	}
	next.totalEvents++
	switch v := ev.(type) {
	case *OperationStartedEvent:
		next.started = true
	case *OperationCompletedEvent:
		next.completed, next.duration = true, v.Duration()
		next.hasUnknownOutcome = next.hasUnknownOutcome || isOutcomeUnknown(v.Outcome())
		next.succeeded = v.Succeeded() && !next.hasUnknownOutcome
	case *OutputChunkEvent:
		next.outputChunks++
		next.outputBytes += uint64(len(v.data))
	case *StepEvent:
		next.stepEvents++
		if v.Status() == playbook.StepStatusOutcomeUnknown || isOutcomeUnknown(v.Outcome()) {
			next.hasUnknownOutcome, next.succeeded = true, false
		}
	case *FSMTransitionEvent:
		next.fsmTransitions++
	case *ApprovalChallengeEvent:
		next.approvalCh++
	case *TransferProgressEvent:
		next.progressCnt++
		next.latestTransferBytes = v.BytesTransferred()
	case *MetricSampleEvent:
		next.progressCnt++
	case *AuditRecordEvent, *PoolStateEvent, *DiagnosticEvent, *BusDroppedEvent:
		return OperationSummary{}, fmt.Errorf("%w: OperationSummary 仅折叠操作流事件，拒绝 %s", ErrUnsupportedEventClass, ev.Kind())
	default:
		return OperationSummary{}, ErrInvalidEvent
	}
	return next, nil
}

func bindSummaryIdentity(acc OperationSummary, ev Event) (OperationSummary, error) {
	meta := ev.Meta()
	opID, hasOp := meta.OperationID().Get()
	if !meta.IsValid() || !hasOp {
		return OperationSummary{}, fmt.Errorf("%w: 操作摘要折叠要求事件绑定有效 OperationID", ErrOperationMismatch)
	}
	if !acc.valid {
		acc.traceID, acc.opID, acc.valid = meta.TraceID(), opID, true
		return acc, nil
	}
	if !acc.traceID.Equal(meta.TraceID()) || !acc.opID.Equal(opID) {
		return OperationSummary{}, fmt.Errorf("%w: 事件归属与当前摘要不一致", ErrOperationMismatch)
	}
	return acc, nil
}

func isOutcomeUnknown(opt algebraic.Option[execution.ExecutionOutcome]) bool {
	out, ok := opt.Get()
	return ok && out != nil && out.Kind() == execution.OutcomeKindUnknown
}
