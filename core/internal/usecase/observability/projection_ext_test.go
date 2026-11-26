package observability_test

import (
	"bytes"
	"context"
	"encoding"
	jsonv2 "encoding/json/v2"
	"errors"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/playbook"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/internal/usecase/observability"
)

// 编译期契约断言集中于外置测试文件，验证全部枚举文本编解码与快照 JSON/v2 契约。
var (
	_ encoding.TextAppender    = observability.LogTargetFile
	_ encoding.TextMarshaler   = observability.LogTargetFile
	_ encoding.TextUnmarshaler = (*observability.LogTargetKind)(nil)
	_ encoding.TextAppender    = observability.ProcessSortCPU
	_ encoding.TextUnmarshaler = (*observability.ProcessSortBy)(nil)
	_ encoding.TextAppender    = observability.GUIActionScreenshot
	_ encoding.TextUnmarshaler = (*observability.GUIActionKind)(nil)
	_ encoding.TextAppender    = observability.ScrollUp
	_ encoding.TextUnmarshaler = (*observability.ScrollDirection)(nil)
	_ encoding.TextAppender    = observability.GUISessionX11
	_ encoding.TextUnmarshaler = (*observability.GUISessionKind)(nil)
	_ jsonv2.MarshalerTo       = (*observability.ProjectionSnapshot)(nil)
)

func mustNoErr(t *testing.T, err error, label string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s failed: %v", label, err)
	}
}

func makeMeta(t *testing.T, tidStr, opStr, nodeStr string, seq uint64, at time.Time) events.EventMeta {
	t.Helper()
	tid, err := security.ParseTraceID(tidStr)
	mustNoErr(t, err, "ParseTraceID")
	var opOpt algebraic.Option[security.OperationID]
	if opStr != "" {
		oid, oErr := security.ParseOperationID(opStr)
		mustNoErr(t, oErr, "ParseOperationID")
		opOpt = algebraic.Some(oid)
	}
	var nodeOpt algebraic.Option[inventory.NodeID]
	if nodeStr != "" {
		nid, nErr := inventory.ParseNodeID(nodeStr)
		mustNoErr(t, nErr, "ParseNodeID")
		nodeOpt = algebraic.Some(nid)
	}
	meta, err := events.NewEventMeta(events.EventMetaSpec{
		TraceID: tid, OperationID: opOpt, OccurredAt: at, Seq: seq, NodeID: nodeOpt,
	})
	mustNoErr(t, err, "NewEventMeta")
	return meta
}

func TestProjectionAll12VariantsAndRingEviction(t *testing.T) {
	defer goleak.VerifyNone(t)
	now := sim.DefaultBaseTime()

	// 零值失败关闭核验。
	var zeroProj observability.Projection
	if zeroProj.Snapshot().IsValid() {
		t.Fatalf("zero Projection snapshot must be invalid")
	}
	if _, err := zeroProj.WaitUpdate(context.Background(), 0); !errors.Is(err, observability.ErrProjectionClosed) {
		t.Fatalf("expected ErrProjectionClosed, got %v", err)
	}
	var zeroSnap observability.ProjectionSnapshot
	if _, err := zeroSnap.CanonicalJSON(); !errors.Is(err, observability.ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest on zero snapshot, got %v", err)
	}

	proj, err := observability.NewProjection(context.Background(), observability.ProjectionConfig{
		MaxLogEntries: 2, MaxDiagnostics: 2, MaxPoolEvents: 2, MaxOperations: 2, MaxMetrics: 2,
	})
	mustNoErr(t, err, "NewProjection")
	defer func() { _ = proj.Close() }()

	evs := buildAll12Events(t, now)
	for _, ev := range evs {
		mustNoErr(t, proj.ApplyEvent(ev), "ApplyEvent")
	}
	// 再写入 2 条日志触发环形缓冲覆盖最旧记录（容量=2）。
	for i := range uint64(2) {
		m := makeMeta(t, "trace-1", "op-1", "node-1", 100+i, now)
		ev, eErr := events.NewOutputChunkEvent(events.OutputChunkSpec{
			Meta: m, Stream: events.OutputStreamStdout, ChunkIndex: i + 1, Data: []byte("extra-log"),
		})
		mustNoErr(t, eErr, "NewOutputChunkEvent extra")
		mustNoErr(t, proj.ApplyEvent(ev), "ApplyEvent extra")
	}

	snap := proj.Snapshot()
	if !snap.IsValid() || snap.TotalEvents() != uint64(len(evs)+2) {
		t.Fatalf("unexpected total events: %d", snap.TotalEvents())
	}
	if !snap.GateHalted() || !snap.HasUnknownOutcome() || snap.DroppedEvents() != 3 {
		t.Fatalf("expected GateHalted=true Unknown=true Dropped=3, got halted=%v unk=%v drop=%d",
			snap.GateHalted(), snap.HasUnknownOutcome(), snap.DroppedEvents())
	}
	if len(snap.Logs()) != 2 {
		t.Fatalf("expected bounded log ring size 2, got %d", len(snap.Logs()))
	}
	raw, err := snap.CanonicalJSON()
	mustNoErr(t, err, "CanonicalJSON")
	if !bytes.Contains(raw, []byte(`"gate_halted":true`)) || !bytes.Contains(raw, []byte(`"has_unknown_outcome":true`)) {
		t.Fatalf("unexpected snapshot json: %s", raw)
	}
}

func buildAll12Events(t *testing.T, now time.Time) []events.Event {
	t.Helper()
	opMeta := makeMeta(t, "trace-1", "op-1", "node-1", 1, now)
	sysMeta := makeMeta(t, "trace-sys", "", "", 2, now)
	unk, err := execution.NewOutcomeUnknown(execution.ExecPhaseRunning, "drop", "lost")
	mustNoErr(t, err, "NewOutcomeUnknown")

	e1, err := events.NewOperationStartedEvent(events.OperationStartedSpec{
		Meta: opMeta, Capability: security.CapabilityExecute, Tool: "obs", Action: "test", Summary: "start",
	})
	mustNoErr(t, err, "e1")
	e2, err := events.NewOutputChunkEvent(events.OutputChunkSpec{
		Meta: opMeta, Stream: events.OutputStreamStdout, ChunkIndex: 0, Data: []byte("first"),
	})
	mustNoErr(t, err, "e2")
	sid, _ := playbook.ParseStepID("s1")
	e3, err := events.NewStepEvent(events.StepEventSpec{
		Meta: opMeta, StepID: sid, Status: playbook.StepStatusSucceeded, Duration: algebraic.ZeroDuration(), Message: "ok",
	})
	mustNoErr(t, err, "e3")
	e4, err := events.NewFSMTransitionEvent(events.FSMTransitionSpec{
		Meta: opMeta, Machine: events.FSMMachineEnsure, FromState: "pending", ToState: "checking", EventName: "start",
	})
	mustNoErr(t, err, "e4")
	binding, _ := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityExecute, Tool: "obs", Action: "test", NodeID: "node-1",
	})
	opID, _ := security.ParseOperationID("op-1")
	var nonce [16]byte
	nonce[0] = 7
	needAppr, err := security.NewDecisionNeedApproval(security.RiskDangerous, "high risk")
	mustNoErr(t, err, "NewDecisionNeedApproval")
	env, err := security.NewApprovalEnvelope(security.ApprovalEnvelopeSpec{
		OperationID: opID, Binding: binding, Risk: security.RiskDangerous,
		Decision: needAppr, ScopeSummary: "need ok",
		Nonce: nonce, IssuedAt: now, TTL: algebraic.FromStdDuration(time.Minute),
	})
	mustNoErr(t, err, "NewApprovalEnvelope")
	e5, err := events.NewApprovalChallengeEvent(events.ApprovalChallengeSpec{
		Meta: opMeta, Envelope: env, Phase: fsm.ApprovalPhaseChallengeIssued, Reason: "high risk",
	})
	mustNoErr(t, err, "e5")
	e6, err := events.NewTransferProgressEvent(events.TransferProgressSpec{
		Meta: opMeta, TransferID: opID, Direction: fsm.TransferDirectionUpload,
		BytesTransferred: 50, TotalBytes: 100, Elapsed: algebraic.ZeroDuration(), Stage: "copy",
	})
	mustNoErr(t, err, "e6")
	e7, err := events.NewMetricSampleEvent(events.MetricSampleSpec{
		Meta: opMeta, MetricName: "host.cpu.percent", Unit: "percent", Value: 42.5,
		Interval: algebraic.FromStdDuration(time.Second), Labels: map[string]string{"node": "node-1"},
	})
	mustNoErr(t, err, "e7")
	e8, err := events.NewOperationCompletedEvent(events.OperationCompletedSpec{
		Meta: opMeta, Capability: security.CapabilityExecute, Duration: algebraic.ZeroDuration(),
		Outcome: algebraic.Some[execution.ExecutionOutcome](unk), Succeeded: false, Code: "outcome_unknown", Message: "lost",
	})
	mustNoErr(t, err, "e8")
	e9, err := events.NewAuditRecordEvent(events.AuditRecordSpec{
		Meta: opMeta, Stage: events.AuditStageFinalized, ProcessInstanceID: "proc-1",
		Capability: security.CapabilityExecute, Decision: security.NewDecisionAllow("ok"),
		Risk: security.RiskSafe, Binding: algebraic.Some(binding), Duration: algebraic.ZeroDuration(), Reason: "done",
	})
	mustNoErr(t, err, "e9")
	e10, err := events.NewPoolStateEvent(events.PoolStateSpec{
		Meta: sysMeta, Action: events.PoolActionGateHalted, Latency: algebraic.ZeroDuration(), Detail: "halted",
	})
	mustNoErr(t, err, "e10")
	e11, err := events.NewDiagnosticEvent(events.DiagnosticSpec{
		Meta: sysMeta, Scope: events.DiagnosticScopeGate, Severity: events.SeverityError, Code: "gate_halted", Message: "halted",
	})
	mustNoErr(t, err, "e11")
	e12, err := events.NewBusDroppedEvent(events.BusDroppedSpec{
		Meta: sysMeta, Scope: events.DiagnosticScopeRuntime, DroppedTotal: 3, DroppedDelta: 3, Reason: "slow",
	})
	mustNoErr(t, err, "e12")
	return []events.Event{e1, e2, e3, e4, e5, e6, e7, e8, e9, e10, e11, e12}
}

func TestProjectionBusStreamAttachWaitUpdateAndCleanClose(t *testing.T) {
	defer goleak.VerifyNone(t)
	now := sim.DefaultBaseTime()
	bus, err := events.NewSystemBus(events.SystemBusConfig{DefaultSubscriberBuffer: 8})
	mustNoErr(t, err, "NewSystemBus")
	defer bus.Close()

	proj, err := observability.NewProjection(context.Background(), observability.ProjectionConfig{
		SystemBus: bus, BusBuffer: 8,
	})
	mustNoErr(t, err, "NewProjection")

	tid, _ := security.ParseTraceID("trace-live")
	oid, _ := security.ParseOperationID("op-live")
	st, err := events.NewOperationStream(events.OperationStreamConfig{
		TraceID: tid, OperationID: oid, OperationBuffer: 8,
	})
	mustNoErr(t, err, "NewOperationStream")
	mustNoErr(t, proj.AttachOperationStream(st), "AttachOperationStream")

	// 通过事件驱动 WaitUpdate 等待消费完成，0 time.Sleep。
	var finalSnap observability.ProjectionSnapshot
	mustNoErr(t, conc.RunWait(context.Background(), func(wCtx context.Context, n *conc.Nursery) error {
		_ = n.Go(func(c context.Context) error {
			m := makeMeta(t, "trace-live", "op-live", "web-1", 1, now)
			ev1, _ := events.NewOutputChunkEvent(events.OutputChunkSpec{
				Meta: m, Stream: events.OutputStreamStdout, ChunkIndex: 0, Data: []byte("hello-tui"),
			})
			_ = st.Emit(c, ev1)
			st.Close()
			sm := makeMeta(t, "trace-bus", "", "", 1, now)
			diag, _ := events.NewDiagnosticEvent(events.DiagnosticSpec{
				Meta: sm, Scope: events.DiagnosticScopeRuntime, Severity: events.SeverityInfo, Code: "ready", Message: "bus ok",
			})
			_ = bus.Publish(diag)
			return nil
		})
		return n.Go(func(c context.Context) error {
			ver := uint64(0)
			for {
				snap, wErr := proj.WaitUpdate(c, ver)
				if wErr != nil {
					return wErr
				}
				ver = snap.Version()
				if len(snap.Logs()) >= 1 && len(snap.Diagnostics()) >= 1 && snap.ActiveStreams() == 0 {
					finalSnap = snap
					return nil
				}
			}
		})
	}), "RunWait")

	if finalSnap.Logs()[0].Data != "hello-tui" || finalSnap.Diagnostics()[0].Code != "ready" {
		t.Fatalf("unexpected live projection snapshot: logs=%+v diags=%+v", finalSnap.Logs(), finalSnap.Diagnostics())
	}
	mustNoErr(t, proj.Close(), "Projection.Close")
	if err := proj.AttachOperationStream(st); !errors.Is(err, observability.ErrProjectionClosed) {
		t.Fatalf("expected ErrProjectionClosed after close, got %v", err)
	}
}
