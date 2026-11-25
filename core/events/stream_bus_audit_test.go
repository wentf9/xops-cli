package events

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/playbook"
	"github.com/wentf9/xops-cli/core/domain/security"
)

func TestOperationStreamIsolationAndValidation(t *testing.T) {
	f := makeFixture(t)
	if _, err := NewOperationStream(OperationStreamConfig{TraceID: f.tid, OperationID: f.opID, OperationBuffer: 0}); !errors.Is(err, ErrInvalidStreamConfig) {
		t.Fatalf("buffer=0 want ErrInvalidStreamConfig, got %v", err)
	}
	stream, err := NewOperationStream(OperationStreamConfig{TraceID: f.tid, OperationID: f.opID, OperationBuffer: 4})
	mustNoErr(t, err)
	defer stream.Close()

	// 跨操作事件（不同 OperationID）必须被物理隔离拒绝。
	otherMeta, err := NewEventMeta(EventMetaSpec{TraceID: f.tid, OperationID: algebraic.Some(f.opID2), OccurredAt: f.now})
	mustNoErr(t, err)
	otherEv, err := NewOperationStartedEvent(OperationStartedSpec{
		Meta: otherMeta, Capability: security.CapabilityInspect, Tool: "nodes", Action: "list",
	})
	mustNoErr(t, err)
	if err := stream.Emit(context.Background(), otherEv); !errors.Is(err, ErrOperationMismatch) {
		t.Fatalf("cross-operation Emit got %v, want ErrOperationMismatch", err)
	}

	// 审计事件与系统事件不得进入 OperationStream。
	all := buildAll12Events(t, f)
	if err := stream.Emit(context.Background(), all[8]); !errors.Is(err, ErrUnsupportedEventClass) {
		t.Fatalf("audit event into stream got %v, want ErrUnsupportedEventClass", err)
	}
	if err := stream.Emit(context.Background(), all[10]); !errors.Is(err, ErrUnsupportedEventClass) {
		t.Fatalf("system event into stream got %v, want ErrUnsupportedEventClass", err)
	}
	var nilCtx context.Context
	if err := stream.Emit(nilCtx, all[0]); !errors.Is(err, ErrNilContext) {
		t.Fatalf("nil ctx Emit got %v, want ErrNilContext", err)
	}
	if _, _, err := stream.Next(nilCtx); !errors.Is(err, ErrNilContext) {
		t.Fatalf("nil ctx Next got %v, want ErrNilContext", err)
	}
}

// TestOperationStreamBlockWithContextAndCancel 验证 EventClassOperation 满队列阻塞、释放与 ctx 取消响应。
func TestOperationStreamBlockWithContextAndCancel(t *testing.T) {
	f := makeFixture(t)
	stream, err := NewOperationStream(OperationStreamConfig{TraceID: f.tid, OperationID: f.opID, OperationBuffer: 2})
	mustNoErr(t, err)

	mkChunk := func(idx uint64) Event {
		ev, err := NewOutputChunkEvent(OutputChunkSpec{
			Meta: f.opMeta.WithSeq(idx), Stream: OutputStreamStdout, ChunkIndex: idx, Data: []byte(fmt.Sprintf("c%d", idx)),
		})
		mustNoErr(t, err)
		return ev
	}
	mustNoErr(t, stream.Emit(context.Background(), mkChunk(1)))
	mustNoErr(t, stream.Emit(context.Background(), mkChunk(2)))

	// 队列已满：带超时的 Emit 必须因背压阻塞并按 ctx 取消退出。
	shortCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := stream.Emit(shortCtx, mkChunk(3)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked Emit with timeout got %v, want DeadlineExceeded", err)
	}

	// 并发验证：生产者阻塞于第 3 帧，消费者消费第 1 帧后生产者立即解除阻塞并完成关闭。
	unblocked := make(chan struct{})
	runErr := conc.RunWait(context.Background(), func(ctx context.Context, n *conc.Nursery) error {
		if goErr := n.Go(func(childCtx context.Context) error {
			if emitErr := stream.Emit(childCtx, mkChunk(3)); emitErr != nil {
				return emitErr
			}
			close(unblocked)
			stream.Close()
			return nil
		}); goErr != nil {
			return goErr
		}
		return verifyStreamFIFODrain(ctx, stream, unblocked)
	})
	mustNoErr(t, runErr)
	// EOF 必须幂等且后续 Emit 返回 ErrStreamClosed。
	if ev, ok, err := stream.Next(context.Background()); err != nil || ok || ev != nil {
		t.Fatalf("idempotent EOF check got ev=%v ok=%v err=%v", ev, ok, err)
	}
	if err := stream.Emit(context.Background(), mkChunk(4)); !errors.Is(err, ErrStreamClosed) {
		t.Fatalf("Emit after Close got %v, want ErrStreamClosed", err)
	}
}

func verifyStreamFIFODrain(ctx context.Context, stream *OperationStream, unblocked <-chan struct{}) error {
	ev1, ok, nextErr := stream.Next(ctx)
	if nextErr != nil {
		return fmt.Errorf("read first chunk failed: %w", nextErr)
	}
	if !ok || ev1.(*OutputChunkEvent).ChunkIndex() != 1 {
		return fmt.Errorf("unexpected first event: ok=%v", ok)
	}
	<-unblocked
	ev2, ok2, err2 := stream.Next(ctx)
	ev3, ok3, err3 := stream.Next(ctx)
	evEOF, okEOF, errEOF := stream.Next(ctx)
	if err := errors.Join(err2, err3, errEOF); err != nil {
		return err
	}
	if !ok2 || !ok3 || okEOF || evEOF != nil {
		return fmt.Errorf("unexpected drain sequence: ok2=%v ok3=%v okEOF=%v", ok2, ok3, okEOF)
	}
	if ev2.(*OutputChunkEvent).ChunkIndex() != 2 || ev3.(*OutputChunkEvent).ChunkIndex() != 3 {
		return errors.New("FIFO order violated for operation events")
	}
	return nil
}

// TestOperationStreamCoalesceLatestSlowRendererNonBlocking 验证慢渲染器完全冻结时高频进度/指标事件绝不阻塞生产者，
// 且多键独立合并、关闭后确定性交付每个键的最新快照并触发 EOF。
func TestOperationStreamCoalesceLatestSlowRendererNonBlocking(t *testing.T) {
	f := makeFixture(t)
	stream, err := NewOperationStream(OperationStreamConfig{
		TraceID: f.tid, OperationID: f.opID, OperationBuffer: 2, MaxCoalesceKeys: 8,
	})
	mustNoErr(t, err)

	// 即使操作队列已填满且消费者完全停滞，1,000 次传输进度与指标采样仍必须零阻塞瞬时完成。
	chunk, err := NewOutputChunkEvent(OutputChunkSpec{Meta: f.opMeta, Stream: OutputStreamStdout, ChunkIndex: 0, Data: []byte("a")})
	mustNoErr(t, err)
	mustNoErr(t, stream.Emit(context.Background(), chunk))
	mustNoErr(t, stream.Emit(context.Background(), chunk))

	const totalUpdates = 500
	for i := uint64(1); i <= totalUpdates; i++ {
		p1, err := NewTransferProgressEvent(TransferProgressSpec{
			Meta: f.opMeta, TransferID: f.opID, Direction: fsm.TransferDirectionUpload,
			BytesTransferred: i * 10, TotalBytes: totalUpdates * 10, Elapsed: algebraic.ZeroDuration(),
		})
		mustNoErr(t, err)
		p2, err := NewTransferProgressEvent(TransferProgressSpec{
			Meta: f.opMeta, TransferID: f.opID2, Direction: fsm.TransferDirectionDownload,
			BytesTransferred: i * 20, TotalBytes: totalUpdates * 20, Elapsed: algebraic.ZeroDuration(),
		})
		mustNoErr(t, err)
		m1, err := NewMetricSampleEvent(MetricSampleSpec{
			Meta: f.opMeta, MetricName: "mem_mb", Value: float64(i), Interval: algebraic.ZeroDuration(),
		})
		mustNoErr(t, err)
		mustNoErr(t, stream.Emit(context.Background(), p1))
		mustNoErr(t, stream.Emit(context.Background(), p2))
		mustNoErr(t, stream.Emit(context.Background(), m1))
	}
	stream.Close()

	stats := stream.Stats()
	if stats.Coalesced != 3*(totalUpdates-1) || stats.PendingCoalescedKeys != 3 {
		t.Fatalf("unexpected coalescing stats: %+v", stats)
	}

	gotBytes := make(map[string]uint64)
	var gotMetric float64
	var opChunks int
	for ev, iterErr := range stream.All(context.Background()) {
		mustNoErr(t, iterErr)
		switch v := ev.(type) {
		case *OutputChunkEvent:
			opChunks++
		case *TransferProgressEvent:
			gotBytes[v.TransferID().String()] = v.BytesTransferred()
		case *MetricSampleEvent:
			gotMetric = v.Value()
		case *OperationStartedEvent, *OperationCompletedEvent, *StepEvent, *FSMTransitionEvent,
			*ApprovalChallengeEvent, *AuditRecordEvent, *PoolStateEvent, *DiagnosticEvent, *BusDroppedEvent:
			t.Fatalf("unexpected event kind %s", ev.Kind())
		default:
			t.Fatalf("unknown event %T", ev)
		}
	}
	if opChunks != 2 || gotBytes[f.opID.String()] != totalUpdates*10 || gotBytes[f.opID2.String()] != totalUpdates*20 || gotMetric != float64(totalUpdates) {
		t.Fatalf("unexpected drained coalesced snapshots: chunks=%d bytes=%v metric=%v", opChunks, gotBytes, gotMetric)
	}
}

func TestOperationStreamMaxCoalesceKeysBounded(t *testing.T) {
	f := makeFixture(t)
	stream, err := NewOperationStream(OperationStreamConfig{
		TraceID: f.tid, OperationID: f.opID, OperationBuffer: 4, MaxCoalesceKeys: 3,
	})
	mustNoErr(t, err)
	defer stream.Close()
	for i := range 10 {
		m, err := NewMetricSampleEvent(MetricSampleSpec{
			Meta: f.opMeta, MetricName: fmt.Sprintf("m_%d", i), Value: float64(i), Interval: algebraic.ZeroDuration(),
		})
		mustNoErr(t, err)
		mustNoErr(t, stream.Emit(context.Background(), m))
	}
	if st := stream.Stats(); st.PendingCoalescedKeys != 3 || st.Coalesced != 7 {
		t.Fatalf("bounded coalesce keys mismatch: %+v", st)
	}
}

func TestOperationStreamConcurrentStress(t *testing.T) {
	f := makeFixture(t)
	s2, err := NewOperationStream(OperationStreamConfig{TraceID: f.tid, OperationID: f.opID, OperationBuffer: 4})
	mustNoErr(t, err)
	var consumed atomic.Int64
	reached := make(chan struct{})
	var reachedOnce sync.Once
	runErr := conc.RunWait(context.Background(), func(ctx context.Context, n *conc.Nursery) error {
		if goErr := n.Go(func(childCtx context.Context) error {
			return consumeAllStreamEvents(childCtx, s2, &consumed, func(n int64) {
				if n >= 16 {
					reachedOnce.Do(func() { close(reached) })
				}
			})
		}); goErr != nil {
			return goErr
		}
		for p := range 4 {
			if goErr := n.Go(func(childCtx context.Context) error {
				return emitStressChunks(childCtx, s2, f.opMeta, p)
			}); goErr != nil {
				return goErr
			}
		}
		// 确定性等待消费者至少收到 16 帧后再关闭流，消除基于 wall-clock time.Sleep 的脆弱竞态。
		<-reached
		s2.Close()
		return nil
	})
	mustNoErr(t, runErr)
	if consumed.Load() < 16 {
		t.Fatalf("consumer received %d events, want >= 16", consumed.Load())
	}
}

func consumeAllStreamEvents(ctx context.Context, s *OperationStream, counter *atomic.Int64, onCount func(int64)) error {
	for _, iterErr := range s.All(ctx) {
		if iterErr != nil {
			return iterErr
		}
		onCount(counter.Add(1))
	}
	return nil
}

func emitStressChunks(ctx context.Context, s *OperationStream, meta EventMeta, producerID int) error {
	for i := range 200 {
		ev, err := NewOutputChunkEvent(OutputChunkSpec{
			Meta: meta, Stream: OutputStreamStdout, ChunkIndex: uint64(producerID*1000 + i), Data: []byte("x"),
		})
		if err != nil {
			return err
		}
		if emitErr := s.Emit(ctx, ev); emitErr != nil && !errors.Is(emitErr, ErrStreamClosed) {
			return emitErr
		}
	}
	return nil
}

// TestOperationStreamCompletedOrderingAndLatch 验证 OperationCompletedEvent 锁存终态并确保全部待消费进度快照先于完成事件交付。
func TestOperationStreamCompletedOrderingAndLatch(t *testing.T) {
	f := makeFixture(t)
	stream, err := NewOperationStream(OperationStreamConfig{TraceID: f.tid, OperationID: f.opID, OperationBuffer: 8})
	mustNoErr(t, err)
	if !stream.TraceID().Equal(f.tid) || !stream.OperationID().Equal(f.opID) {
		t.Fatal("OperationStream TraceID/OperationID mismatch")
	}
	var zeroStream OperationStream
	if zeroStream.TraceID().IsValid() || zeroStream.OperationID().IsValid() {
		t.Fatal("zero OperationStream must return invalid TraceID/OperationID")
	}

	startEv, err := NewOperationStartedEvent(OperationStartedSpec{Meta: f.opMeta, Capability: security.CapabilityExecute, Tool: "exec", Action: "run"})
	mustNoErr(t, err)
	p1, err := NewTransferProgressEvent(TransferProgressSpec{Meta: f.opMeta, TransferID: f.opID, Direction: fsm.TransferDirectionUpload, BytesTransferred: 10, TotalBytes: 10, Elapsed: algebraic.ZeroDuration()})
	mustNoErr(t, err)
	p2, err := NewTransferProgressEvent(TransferProgressSpec{Meta: f.opMeta, TransferID: f.opID2, Direction: fsm.TransferDirectionDownload, BytesTransferred: 20, TotalBytes: 20, Elapsed: algebraic.ZeroDuration()})
	mustNoErr(t, err)
	m1, err := NewMetricSampleEvent(MetricSampleSpec{Meta: f.opMeta, MetricName: "rate", Value: 99, Interval: algebraic.ZeroDuration()})
	mustNoErr(t, err)
	compEv, err := NewOperationCompletedEvent(OperationCompletedSpec{Meta: f.opMeta, Capability: security.CapabilityExecute, Duration: algebraic.ZeroDuration(), Succeeded: true})
	mustNoErr(t, err)

	for _, ev := range []Event{startEv, p1, p2, m1, compEv} {
		mustNoErr(t, stream.Emit(context.Background(), ev))
	}
	// 入队 OperationCompletedEvent 后，后续任意操作/进度/重复完成事件均须立即失败关闭。
	chunkEv, err := NewOutputChunkEvent(OutputChunkSpec{Meta: f.opMeta, Stream: OutputStreamStdout, Data: []byte("late")})
	mustNoErr(t, err)
	for _, late := range []Event{chunkEv, m1, compEv} {
		if err := stream.Emit(context.Background(), late); !errors.Is(err, ErrInvalidEvent) {
			t.Fatalf("post-completion Emit(%s) got %v, want ErrInvalidEvent", late.Kind(), err)
		}
	}
	stream.Close()

	var kinds []EventKind
	for ev, iterErr := range stream.All(context.Background()) {
		mustNoErr(t, iterErr)
		kinds = append(kinds, ev.Kind())
	}
	if len(kinds) != 5 || kinds[0] != EventKindOperationStarted || kinds[len(kinds)-1] != EventKindOperationCompleted {
		t.Fatalf("unexpected delivery order around OperationCompleted: %v", kinds)
	}
}

// TestOperationStreamFairAlternationAndFoldStreamErrors 验证操作/进度公平交替排空以及 FoldStream 取消与错误传播。
func TestOperationStreamFairAlternationAndFoldStreamErrors(t *testing.T) {
	f := makeFixture(t)
	stream, err := NewOperationStream(OperationStreamConfig{TraceID: f.tid, OperationID: f.opID, OperationBuffer: 8})
	mustNoErr(t, err)
	for i := range 3 {
		c, err := NewOutputChunkEvent(OutputChunkSpec{Meta: f.opMeta, Stream: OutputStreamStdout, ChunkIndex: uint64(i), Data: []byte("a")})
		mustNoErr(t, err)
		m, err := NewMetricSampleEvent(MetricSampleSpec{Meta: f.opMeta, MetricName: fmt.Sprintf("k%d", i), Value: float64(i), Interval: algebraic.ZeroDuration()})
		mustNoErr(t, err)
		mustNoErr(t, stream.Emit(context.Background(), c))
		mustNoErr(t, stream.Emit(context.Background(), m))
	}
	stream.Close()
	wantClasses := []EventClass{EventClassOperation, EventClassProgress, EventClassOperation, EventClassProgress, EventClassOperation, EventClassProgress}
	var gotClasses []EventClass
	for ev, iterErr := range stream.All(context.Background()) {
		mustNoErr(t, iterErr)
		gotClasses = append(gotClasses, ev.Class())
	}
	if len(gotClasses) != len(wantClasses) {
		t.Fatalf("got %d events, want %d", len(gotClasses), len(wantClasses))
	}
	for i := range wantClasses {
		if gotClasses[i] != wantClasses[i] {
			t.Fatalf("fair alternation violated at #%d: got %v, want %v", i, gotClasses, wantClasses)
		}
	}

	// FoldStream 错误与取消路径校验。
	assertFoldStreamErrorPaths(t, f)
}

func assertFoldStreamErrorPaths(t *testing.T, f testFixture) {
	t.Helper()
	s, err := NewOperationStream(OperationStreamConfig{TraceID: f.tid, OperationID: f.opID, OperationBuffer: 4})
	mustNoErr(t, err)
	defer s.Close()
	c, err := NewOutputChunkEvent(OutputChunkSpec{Meta: f.opMeta, Stream: OutputStreamStdout, Data: []byte("x")})
	mustNoErr(t, err)
	mustNoErr(t, s.Emit(context.Background(), c))

	foldBoom := errors.New("fold boom")
	if _, err := FoldStream(context.Background(), s, 0, func(int, Event) (int, error) { return 0, foldBoom }); !errors.Is(err, foldBoom) {
		t.Fatalf("FoldStream callback err got %v, want %v", err, foldBoom)
	}
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := FoldStream(cancelCtx, s, 0, func(acc int, _ Event) (int, error) { return acc + 1, nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("FoldStream canceled ctx got %v, want context.Canceled", err)
	}
}

func TestFoldEventsAndOperationSummaryMonotonicUnknown(t *testing.T) {
	f := makeFixture(t)
	startEv, err := NewOperationStartedEvent(OperationStartedSpec{
		Meta: f.opMeta, Capability: security.CapabilityExecute, Tool: "play", Action: "run",
	})
	mustNoErr(t, err)
	stepID, err := playbook.ParseStepID("s1")
	mustNoErr(t, err)
	outUnknown, err := execution.NewOutcomeUnknown(execution.ExecPhaseTimedOut, "TIMEOUT", "timed out")
	mustNoErr(t, err)
	stepUnknown, err := NewStepEvent(StepEventSpec{
		Meta: f.opMeta, StepID: stepID, Status: playbook.StepStatusOutcomeUnknown,
		Duration: algebraic.FromStdDuration(time.Second),
		Outcome:  algebraic.Some[execution.ExecutionOutcome](outUnknown),
	})
	mustNoErr(t, err)
	// 即使后续 OperationCompleted 声明 succeeded=true（无 Outcome），HasUnknownOutcome 仍须单调锁存并阻止 Succeeded()==true。
	compEv, err := NewOperationCompletedEvent(OperationCompletedSpec{
		Meta: f.opMeta, Capability: security.CapabilityExecute,
		Duration: algebraic.FromStdDuration(2 * time.Second), Succeeded: true,
	})
	mustNoErr(t, err)

	sum, err := FoldOperationSummary([]Event{startEv, stepUnknown, compEv})
	mustNoErr(t, err)
	if !sum.IsValid() || !sum.Started() || !sum.Completed() || !sum.HasUnknownOutcome() || sum.Succeeded() || sum.StepEvents() != 1 || sum.TotalEvents() != 3 {
		t.Fatalf("unexpected monotonic unknown summary: valid=%v unknown=%v succeeded=%v", sum.IsValid(), sum.HasUnknownOutcome(), sum.Succeeded())
	}

	// 空切片与审计事件均必须失败关闭。
	if _, err := FoldOperationSummary(nil); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("empty FoldOperationSummary got %v", err)
	}
	all := buildAll12Events(t, f)
	if _, err := FoldOperationSummary([]Event{all[8]}); !errors.Is(err, ErrUnsupportedEventClass) {
		t.Fatalf("audit event FoldOperationSummary got %v", err)
	}
	if _, err := FoldEvents(0, []Event{startEv}, nil); !errors.Is(err, ErrInvalidFoldFunc) {
		t.Fatalf("nil FoldEvents fn got %v", err)
	}
}

func TestAuditDispatcherSyncFailClosedAndHaltedCircuitBreaker(t *testing.T) {
	f := makeFixture(t)
	all := buildAll12Events(t, f)
	auditEv := all[8].(*AuditRecordEvent)

	bus, err := NewSystemBus(SystemBusConfig{DefaultSubscriberBuffer: 8})
	mustNoErr(t, err)
	defer bus.Close()
	diagSub, err := bus.Subscribe()
	mustNoErr(t, err)

	var failNext atomic.Bool
	var writeCalls, haltCalls atomic.Int32
	var disp *AuditDispatcher

	writerErr := errors.New("ENOSPC: disk full")
	disp, err = NewAuditDispatcher(AuditDispatcherConfig{
		Writer: AuditWriterFunc(func(_ context.Context, _ *AuditRecordEvent) error {
			writeCalls.Add(1)
			return pickIf(failNext.Load(), writerErr, nil)
		}),
		HaltOnWriteError: true,
		OnHalt: func(reason string, cause error) {
			haltCalls.Add(1)
			// 验证 OnHalt 在锁外触发：回调内重入调用 IsHalted()/Stats() 绝不死锁。
			if !disp.IsHalted() || reason != "audit_write_failed" || !errors.Is(cause, writerErr) {
				t.Errorf("unexpected OnHalt args: halted=%v reason=%q cause=%v", disp.IsHalted(), reason, cause)
			}
		},
		DiagnosticBus: bus,
	})
	mustNoErr(t, err)

	mustNoErr(t, disp.Dispatch(context.Background(), auditEv))
	if disp.Stats().Dispatched != 1 || disp.IsHalted() {
		t.Fatalf("unexpected stats after success: %+v", disp.Stats())
	}
	assertAuditRejectsNonAuditEvents(t, disp, all)
	assertAuditHaltedIrreversible(t, disp, auditEv, writerErr, diagSub, &failNext, &writeCalls, &haltCalls)
}

func assertAuditRejectsNonAuditEvents(t *testing.T, disp *AuditDispatcher, all []Event) {
	t.Helper()
	for _, ev := range all {
		if ev.Kind() == EventKindAuditRecord {
			continue
		}
		if err := disp.DispatchEvent(context.Background(), ev); !errors.Is(err, ErrUnsupportedEventClass) {
			t.Fatalf("DispatchEvent(%s) got %v, want ErrUnsupportedEventClass", ev.Kind(), err)
		}
	}
}

func assertAuditHaltedIrreversible(t *testing.T, disp *AuditDispatcher, auditEv *AuditRecordEvent, writerErr error, diagSub *SystemSubscription, failNext *atomic.Bool, writeCalls, haltCalls *atomic.Int32) {
	t.Helper()
	// 写入失败触发 StrictAgentProfile 不可逆 Halted 熔断 + OnHalt 仅触发一次 + 诊断总线镜像。
	failNext.Store(true)
	err := disp.Dispatch(context.Background(), auditEv)
	if !errors.Is(err, ErrAuditDispatchFailed) || !errors.Is(err, writerErr) {
		t.Fatalf("expected wrapped write error, got %v", err)
	}
	if !disp.IsHalted() || haltCalls.Load() != 1 || disp.HaltReason() != "audit_write_failed" {
		t.Fatalf("halted state mismatch: halted=%v haltCalls=%d reason=%q", disp.IsHalted(), haltCalls.Load(), disp.HaltReason())
	}
	// 即使恢复写入成功，Halted 态也必须不可逆拒绝一切新请求且不再触发 writer 或重复触发 OnHalt。
	failNext.Store(false)
	writesBefore := writeCalls.Load()
	err = disp.Dispatch(context.Background(), auditEv)
	if !errors.Is(err, ErrAuditHalted) || !errors.Is(err, writerErr) || writeCalls.Load() != writesBefore {
		t.Fatalf("post-halt dispatch got err=%v writes=%d->%d", err, writesBefore, writeCalls.Load())
	}
	disp.Halt("duplicate", nil)
	if haltCalls.Load() != 1 {
		t.Fatalf("OnHalt invoked %d times, want 1", haltCalls.Load())
	}
	diagEv, ok, dErr := diagSub.Next(context.Background())
	mustNoErr(t, dErr)
	if !ok || diagEv.Kind() != EventKindDiagnostic {
		t.Fatalf("expected mirrored DiagnosticEvent, got ok=%v ev=%v", ok, diagEv)
	}
}

// TestAuditDispatcherConcurrentDispatchAndHalt 验证并发 Dispatch 与外部 Halt 竞争下 OnHalt 精确触发一次且零竞态。
func TestAuditDispatcherConcurrentDispatchAndHalt(t *testing.T) {
	f := makeFixture(t)
	auditEv := buildAll12Events(t, f)[8].(*AuditRecordEvent)
	var haltCalls atomic.Int32
	disp, err := NewAuditDispatcher(AuditDispatcherConfig{
		Writer:           AuditWriterFunc(func(context.Context, *AuditRecordEvent) error { return nil }),
		HaltOnWriteError: true,
		OnHalt:           func(string, error) { haltCalls.Add(1) },
	})
	mustNoErr(t, err)
	runErr := conc.RunWait(context.Background(), func(ctx context.Context, n *conc.Nursery) error {
		for range 4 {
			if goErr := n.Go(func(childCtx context.Context) error {
				return dispatchAuditBurst(childCtx, disp, auditEv)
			}); goErr != nil {
				return goErr
			}
		}
		disp.Halt("operator_halt", nil)
		disp.Halt("operator_halt_dup", nil)
		return nil
	})
	mustNoErr(t, runErr)
	if !disp.IsHalted() || haltCalls.Load() != 1 {
		t.Fatalf("concurrent halt invariant violated: halted=%v haltCalls=%d", disp.IsHalted(), haltCalls.Load())
	}
}

func dispatchAuditBurst(ctx context.Context, disp *AuditDispatcher, auditEv *AuditRecordEvent) error {
	for range 30 {
		err := disp.Dispatch(ctx, auditEv)
		if err != nil && !errors.Is(err, ErrAuditHalted) {
			return err
		}
	}
	return nil
}

func TestSystemBusDropAndCountAndConcurrentLifecycle(t *testing.T) {
	f := makeFixture(t)
	all := buildAll12Events(t, f)
	sysEv := all[9] // PoolStateEvent

	bus, err := NewSystemBus(SystemBusConfig{DefaultSubscriberBuffer: 2, MaxSubscribers: 4})
	mustNoErr(t, err)
	// 非系统事件必须失败关闭拒绝。
	if err := bus.Publish(all[0]); !errors.Is(err, ErrUnsupportedEventClass) {
		t.Fatalf("Publish operation event got %v, want ErrUnsupportedEventClass", err)
	}

	slowSub, err := bus.SubscribeWithBuffer(2)
	mustNoErr(t, err)
	fastSub, err := bus.SubscribeWithBuffer(256)
	mustNoErr(t, err)

	const totalPub = 200
	for range totalPub {
		mustNoErr(t, bus.Publish(sysEv))
	}
	// 慢订阅者只缓冲 2 条、丢弃 198 条；快订阅者完整接收全部 200 条且发布者全程零阻塞。
	if slowSub.Dropped() != totalPub-2 || slowSub.Delivered() != 2 || fastSub.Dropped() != 0 || fastSub.Delivered() != totalPub {
		t.Fatalf("drop/deliver mismatch: slow=(del=%d drop=%d) fast=(del=%d drop=%d)",
			slowSub.Delivered(), slowSub.Dropped(), fastSub.Delivered(), fastSub.Dropped())
	}
	if delta1 := slowSub.DrainDroppedDelta(); delta1 != totalPub-2 {
		t.Fatalf("first DrainDroppedDelta = %d, want %d", delta1, totalPub-2)
	}
	if delta2 := slowSub.DrainDroppedDelta(); delta2 != 0 {
		t.Fatalf("second DrainDroppedDelta = %d, want 0", delta2)
	}

	// 验证 MaxSubscribers 限制。
	s3, err := bus.Subscribe()
	mustNoErr(t, err)
	s4, err := bus.Subscribe()
	mustNoErr(t, err)
	if _, err := bus.Subscribe(); !errors.Is(err, ErrBusSubscriberLimit) {
		t.Fatalf("exceed MaxSubscribers got %v, want ErrBusSubscriberLimit", err)
	}
	s3.Close()
	s4.Close()
	bus.Close()

	// 关闭后 fastSub 排空全部 200 条缓冲事件后稳定返回确定性 EOF。
	var drained int
	for _, iterErr := range fastSub.All(context.Background()) {
		mustNoErr(t, iterErr)
		drained++
	}
	if drained != totalPub {
		t.Fatalf("fastSub drained = %d, want %d", drained, totalPub)
	}
	if err := bus.Publish(sysEv); !errors.Is(err, ErrBusClosed) {
		t.Fatalf("Publish after Close got %v, want ErrBusClosed", err)
	}

	// 并发 Publish + Subscribe + Unsubscribe + Close 压力测试（0 panic / 0 race / 确定性收敛）。
	stressSystemBusLifecycle(t, sysEv)
}

// TestAuditDispatcherInitValidationAndLinearizableHalt 验证 typed-nil Writer、未初始化 Bus 拒绝与并发 Halt 线性化。
func TestAuditDispatcherInitValidationAndLinearizableHalt(t *testing.T) {
	if _, err := NewAuditDispatcher(AuditDispatcherConfig{Writer: AuditWriterFunc(nil)}); !errors.Is(err, ErrNilAuditWriter) {
		t.Fatalf("typed-nil AuditWriterFunc(nil) got %v, want ErrNilAuditWriter", err)
	}
	var uninitBus SystemBus
	if _, err := NewAuditDispatcher(AuditDispatcherConfig{
		Writer:        AuditWriterFunc(func(context.Context, *AuditRecordEvent) error { return nil }),
		DiagnosticBus: &uninitBus,
	}); !errors.Is(err, ErrInvalidAuditConfig) {
		t.Fatalf("uninitialized DiagnosticBus got %v, want ErrInvalidAuditConfig", err)
	}

	// 验证第二个并发 Halt 调用者线性化等待首个 OnHalt 完成后才返回。
	inOnHalt := make(chan struct{})
	releaseOnHalt := make(chan struct{})
	var onHaltDone atomic.Bool
	disp, err := NewAuditDispatcher(AuditDispatcherConfig{
		Writer: AuditWriterFunc(func(context.Context, *AuditRecordEvent) error { return nil }),
		OnHalt: func(string, error) {
			close(inOnHalt)
			<-releaseOnHalt
			onHaltDone.Store(true)
		},
	})
	mustNoErr(t, err)
	secondReturned := make(chan struct{})
	runErr := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if goErr := n.Go(func(context.Context) error { disp.Halt("first", nil); return nil }); goErr != nil {
			return goErr
		}
		<-inOnHalt
		if goErr := n.Go(func(context.Context) error {
			disp.Halt("second", nil)
			if !onHaltDone.Load() {
				return errors.New("second Halt returned before OnHalt completed")
			}
			close(secondReturned)
			return nil
		}); goErr != nil {
			return goErr
		}
		close(releaseOnHalt)
		<-secondReturned
		return nil
	})
	mustNoErr(t, runErr)
}

// TestSystemSubscriptionNextUnblocksOnCloseAndCancel 验证阻塞态 Next 在 ctx 取消、sub.Close 与 bus.Close 下均确定性唤醒。
func TestSystemSubscriptionNextUnblocksOnCloseAndCancel(t *testing.T) {
	bus, err := NewSystemBus(SystemBusConfig{DefaultSubscriberBuffer: 2})
	mustNoErr(t, err)
	subCancel, err := bus.Subscribe()
	mustNoErr(t, err)
	subSelfClose, err := bus.Subscribe()
	mustNoErr(t, err)
	subBusClose, err := bus.Subscribe()
	mustNoErr(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := subCancel.Next(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Next got %v, want context.Canceled", err)
	}
	subCancel.Close()

	runErr := conc.RunWait(context.Background(), func(childCtx context.Context, n *conc.Nursery) error {
		if goErr := n.Go(func(context.Context) error { subSelfClose.Close(); return nil }); goErr != nil {
			return goErr
		}
		if _, ok, nErr := subSelfClose.Next(childCtx); nErr != nil || ok {
			return fmt.Errorf("subSelfClose.Next got ok=%v err=%w", ok, nErr)
		}
		if goErr := n.Go(func(context.Context) error { bus.Close(); return nil }); goErr != nil {
			return goErr
		}
		if _, ok, nErr := subBusClose.Next(childCtx); nErr != nil || ok {
			return fmt.Errorf("subBusClose.Next got ok=%v err=%w", ok, nErr)
		}
		return nil
	})
	mustNoErr(t, runErr)
}

func stressSystemBusLifecycle(t *testing.T, sysEv Event) {
	t.Helper()
	bus, err := NewSystemBus(SystemBusConfig{DefaultSubscriberBuffer: 4})
	mustNoErr(t, err)
	var readySubs atomic.Int32
	allSubsReady := make(chan struct{})
	var readyOnce, gotOnce sync.Once
	gotEvent := make(chan struct{})

	runErr := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		for range 4 {
			if goErr := n.Go(func(context.Context) error { return runBusStressPublisher(bus, sysEv, allSubsReady) }); goErr != nil {
				return goErr
			}
			if goErr := n.Go(func(childCtx context.Context) error {
				return runBusStressSubscriber(childCtx, bus, &readySubs, &readyOnce, allSubsReady, &gotOnce, gotEvent)
			}); goErr != nil {
				return goErr
			}
		}
		// 确定性等待订阅者就绪并收到至少一条事件后再并发关闭总线，彻底消除 time.Sleep。
		<-gotEvent
		bus.Close()
		return nil
	})
	mustNoErr(t, runErr)
	if !bus.IsClosed() || bus.Stats().ActiveSubscribers != 0 {
		t.Fatalf("bus not cleanly closed: %+v", bus.Stats())
	}
}

func runBusStressPublisher(bus *SystemBus, sysEv Event, start <-chan struct{}) error {
	<-start
	for range 100 {
		if pErr := bus.Publish(sysEv); pErr != nil && !errors.Is(pErr, ErrBusClosed) {
			return pErr
		}
	}
	return nil
}

func runBusStressSubscriber(ctx context.Context, bus *SystemBus, readySubs *atomic.Int32, readyOnce *sync.Once, allReady chan struct{}, gotOnce *sync.Once, gotEvent chan struct{}) error {
	sub, sErr := bus.Subscribe()
	if errors.Is(sErr, ErrBusClosed) {
		return nil
	}
	if sErr != nil {
		return sErr
	}
	defer sub.Close()
	if readySubs.Add(1) == 4 {
		readyOnce.Do(func() { close(allReady) })
	}
	for i := range 10 {
		_, ok, nErr := sub.Next(ctx)
		if nErr != nil || !ok {
			return nErr
		}
		gotOnce.Do(func() { close(gotEvent) })
		if i == 9 {
			return nil
		}
	}
	return nil
}
