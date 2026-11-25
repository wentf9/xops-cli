package events

import (
	"bytes"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/playbook"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
)

type testFixture struct {
	tid      security.TraceID
	opID     security.OperationID
	opID2    security.OperationID
	nodeID   inventory.NodeID
	now      time.Time
	opMeta   EventMeta
	sysMeta  EventMeta
	binding  security.OperationBinding
	envelope security.ApprovalEnvelope
	planDig  plan.PlanDigest
	hopDig   plan.HopDigest
	endpoint netaddr.Endpoint
	handleID plan.HandleID
}

func makeFixture(t *testing.T) testFixture {
	t.Helper()
	tid, err := security.ParseTraceID("trace-0123456789abcdef")
	mustNoErr(t, err)
	opID, err := security.ParseOperationID("op-0123456789abcdef")
	mustNoErr(t, err)
	opID2, err := security.ParseOperationID("op-fedcba9876543210")
	mustNoErr(t, err)
	nodeID, err := inventory.ParseNodeID("web-01")
	mustNoErr(t, err)
	loc := time.FixedZone("UTC+8", 8*3600)
	now := time.Date(2026, 11, 25, 12, 30, 45, 987654321, loc)

	opMeta, err := NewEventMeta(EventMetaSpec{
		TraceID: tid, OperationID: algebraic.Some(opID), OccurredAt: now, Seq: 7, NodeID: algebraic.Some(nodeID),
	})
	mustNoErr(t, err)
	sysMeta, err := NewEventMeta(EventMetaSpec{TraceID: tid, OccurredAt: now, Seq: 1})
	mustNoErr(t, err)

	var sum [32]byte
	for i := range sum {
		sum[i] = byte(i + 1)
	}
	planDig := plan.PlanDigestFromSHA256(sum)
	hopDig := plan.HopDigestFromSHA256(sum)
	binding, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityExecute, Tool: "terminal_exec", Action: "run",
		NodeID: "web-01", PlanDigest: algebraic.Some(planDig.SecurityDigest()),
	})
	mustNoErr(t, err)

	needAppr, err := security.NewDecisionNeedApproval(security.RiskDangerous, "protected path write")
	mustNoErr(t, err)
	var nonce [16]byte
	nonce[0] = 0xAB
	envelope, err := security.NewApprovalEnvelope(security.ApprovalEnvelopeSpec{
		OperationID: opID, Binding: binding, Risk: security.RiskDangerous, Decision: needAppr,
		ScopeSummary: "write /etc/app.conf", IssuedAt: now.UTC(), TTL: algebraic.FromStdDuration(2 * time.Minute), Nonce: nonce,
	})
	mustNoErr(t, err)

	ep, err := netaddr.ParseEndpoint("192.0.2.10:22")
	mustNoErr(t, err)
	hid, err := plan.ParseHandleID("pty-slot-01")
	mustNoErr(t, err)

	return testFixture{tid, opID, opID2, nodeID, now, opMeta, sysMeta, binding, envelope, planDig, hopDig, ep, hid}
}

func mustNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func buildAll12Events(t *testing.T, f testFixture) []Event {
	t.Helper()
	outCompleted, err := execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	mustNoErr(t, err)
	outUnknown, err := execution.NewOutcomeUnknown(execution.ExecPhaseTransportLost, "E_CONN", "tcp reset")
	mustNoErr(t, err)
	pbID, err := playbook.ParsePlaybookID("deploy-prod")
	mustNoErr(t, err)
	stepID, err := playbook.ParseStepID("restart-nginx")
	mustNoErr(t, err)

	ev1, err := NewOperationStartedEvent(OperationStartedSpec{
		Meta: f.opMeta, Capability: security.CapabilityExecute, Tool: "terminal_exec", Action: "exec",
		PlanDigest: algebraic.Some(f.planDig), Summary: "run deploy",
	})
	mustNoErr(t, err)
	ev2, err := NewOperationCompletedEvent(OperationCompletedSpec{
		Meta: f.opMeta, Capability: security.CapabilityExecute,
		Duration: algebraic.FromStdDuration(150 * time.Millisecond),
		Outcome:  algebraic.Some[execution.ExecutionOutcome](outCompleted), Succeeded: true,
		Code: "OK", Message: "done",
	})
	mustNoErr(t, err)
	ev3, err := NewOutputChunkEvent(OutputChunkSpec{
		Meta: f.opMeta, Stream: OutputStreamStdout, ChunkIndex: 3,
		Data: []byte{0x00, 0x01, 'o', 'k', '\n', 0xff}, Truncated: false,
	})
	mustNoErr(t, err)
	ev4, err := NewStepEvent(StepEventSpec{
		Meta: f.opMeta, PlaybookID: algebraic.Some(pbID), StepID: stepID,
		Status: playbook.StepStatusOutcomeUnknown, Duration: algebraic.FromStdDuration(3 * time.Second),
		Outcome: algebraic.Some[execution.ExecutionOutcome](outUnknown), Message: "connection dropped",
	})
	mustNoErr(t, err)
	ev5, err := NewFSMTransitionEvent(FSMTransitionSpec{
		Meta: f.opMeta, Machine: FSMMachineTransfer, FromState: "streaming", ToState: "verifying",
		EventName: "stream_completed", Detail: "sha256 check", Terminal: false,
	})
	mustNoErr(t, err)
	ev6, err := NewApprovalChallengeEvent(ApprovalChallengeSpec{
		Meta: f.opMeta, Envelope: f.envelope, Phase: fsm.ApprovalPhaseChallengeIssued,
		Escalated: true, Reason: "symlink target in /etc",
	})
	mustNoErr(t, err)
	ev7, err := NewTransferProgressEvent(TransferProgressSpec{
		Meta: f.opMeta, TransferID: f.opID2, Direction: fsm.TransferDirectionUpload,
		BytesTransferred: 4096, TotalBytes: 8192, ChunksCompleted: 4,
		Elapsed: algebraic.FromStdDuration(2 * time.Second), RateBytesPerSec: 2048, Stage: "streaming",
	})
	mustNoErr(t, err)
	ev8, err := NewMetricSampleEvent(MetricSampleSpec{
		Meta: f.opMeta, MetricName: "cpu_usage", Unit: "percent", Value: 42.5,
		Interval: algebraic.FromStdDuration(time.Second),
		Labels:   map[string]string{"z_key": "last", "a_key": "first"},
	})
	mustNoErr(t, err)
	ev9, err := NewAuditRecordEvent(AuditRecordSpec{
		Meta: f.opMeta, Stage: AuditStageFinalized, ProcessInstanceID: "xops-proc-99",
		Capability: security.CapabilityExecute, Decision: security.NewDecisionAllow("approved"),
		Risk: security.RiskModerate, Binding: algebraic.Some(f.binding),
		Outcome:  algebraic.Some[execution.ExecutionOutcome](outCompleted),
		Duration: algebraic.FromStdDuration(250 * time.Millisecond), Reason: "completed cleanly",
	})
	mustNoErr(t, err)
	ev10, err := NewPoolStateEvent(PoolStateSpec{
		Meta: f.sysMeta, Action: PoolActionLeaseAcquired, PlanDigest: algebraic.Some(f.planDig),
		HopDigest: algebraic.Some(f.hopDig), Endpoint: algebraic.Some(f.endpoint),
		HandleKind: algebraic.Some(plan.HandleKindSession), HandleID: algebraic.Some(f.handleID),
		Generation: 2, ActiveLeases: 3, Latency: algebraic.FromStdDuration(12 * time.Millisecond), Detail: "pooled",
	})
	mustNoErr(t, err)
	ev11, err := NewDiagnosticEvent(DiagnosticSpec{
		Meta: f.sysMeta, Scope: DiagnosticScopeTransport, Severity: SeverityWarn,
		Code: "KEEPALIVE_LATE", Message: "keepalive delayed",
		Attrs: map[string]string{"z": "2", "a": "1"},
	})
	mustNoErr(t, err)
	ev12, err := NewBusDroppedEvent(BusDroppedSpec{
		Meta: f.sysMeta, Scope: DiagnosticScopePool, DroppedTotal: 15, DroppedDelta: 5, Reason: "slow tui subscriber",
	})
	mustNoErr(t, err)
	return []Event{ev1, ev2, ev3, ev4, ev5, ev6, ev7, ev8, ev9, ev10, ev11, ev12}
}

func TestAll12VariantsJSONv2DeterministicRoundTrip(t *testing.T) {
	f := makeFixture(t)
	all := buildAll12Events(t, f)
	if len(all) != 12 {
		t.Fatalf("expected 12 variants, got %d", len(all))
	}
	for _, ev := range all {
		t.Run(ev.Kind().String(), func(t *testing.T) {
			verifyEventDeterministicRoundTrip(t, ev)
		})
	}
}

func verifyEventDeterministicRoundTrip(t *testing.T, ev Event) {
	t.Helper()
	b1, err := MarshalEvent(ev)
	mustNoErr(t, err)
	b2, err := MarshalEvent(ev)
	mustNoErr(t, err)
	if !bytes.Equal(b1, b2) {
		t.Fatalf("non-deterministic json/v2 encoding:\n%s\nvs\n%s", b1, b2)
	}
	decoded, err := UnmarshalEvent(b1)
	mustNoErr(t, err)
	if !EqualEvent(ev, decoded) {
		t.Fatalf("round-trip mismatch for %s:\nraw=%s", ev.Kind(), b1)
	}
	// 验证 EventEnvelope 无显式选项编码及 MarshalEventTo 均无条件 Deterministic(true)。
	env, err := NewEventEnvelope(ev)
	mustNoErr(t, err)
	envBytes, err := jsonv2.Marshal(env)
	mustNoErr(t, err)
	if !bytes.Equal(envBytes, b1) {
		t.Fatalf("unoptioned EventEnvelope bytes mismatch:\n%s\nvs\n%s", envBytes, b1)
	}
	var directBuf bytes.Buffer
	mustNoErr(t, MarshalEventTo(jsontext.NewEncoder(&directBuf), ev))
	if !bytes.Equal(bytes.TrimSuffix(directBuf.Bytes(), []byte{'\n'}), b1) {
		t.Fatalf("MarshalEventTo bytes mismatch:\n%s\nvs\n%s", directBuf.Bytes(), b1)
	}
	assertCanonicalMapKeyOrder(t, ev.Kind(), string(b1))
	var gotEnv EventEnvelope
	mustNoErr(t, jsonv2.Unmarshal(envBytes, &gotEnv))
	if !env.Equal(gotEnv) {
		t.Fatalf("EventEnvelope round-trip unequal for %s", ev.Kind())
	}
	verifyConcreteRoundTrip(t, ev, b1)
}

func assertCanonicalMapKeyOrder(t *testing.T, kind EventKind, encoded string) {
	t.Helper()
	if kind == EventKindMetricSample && strings.Index(encoded, `"a_key"`) >= strings.Index(encoded, `"z_key"`) {
		t.Fatalf("MetricSampleEvent labels not canonically ordered: %s", encoded)
	}
	if kind == EventKindDiagnostic && strings.Index(encoded, `"a"`) >= strings.Index(encoded, `"z"`) {
		t.Fatalf("DiagnosticEvent attrs not canonically ordered: %s", encoded)
	}
}

func verifyConcreteRoundTrip(t *testing.T, ev Event, canonical []byte) {
	t.Helper()
	var decoded Event
	switch ev.(type) {
	case *OperationStartedEvent:
		var v OperationStartedEvent
		mustNoErr(t, jsonv2.Unmarshal(canonical, &v))
		decoded = &v
	case *OperationCompletedEvent:
		var v OperationCompletedEvent
		mustNoErr(t, jsonv2.Unmarshal(canonical, &v))
		decoded = &v
	case *OutputChunkEvent:
		var v OutputChunkEvent
		mustNoErr(t, jsonv2.Unmarshal(canonical, &v))
		decoded = &v
	case *StepEvent:
		var v StepEvent
		mustNoErr(t, jsonv2.Unmarshal(canonical, &v))
		decoded = &v
	case *FSMTransitionEvent:
		var v FSMTransitionEvent
		mustNoErr(t, jsonv2.Unmarshal(canonical, &v))
		decoded = &v
	case *ApprovalChallengeEvent:
		var v ApprovalChallengeEvent
		mustNoErr(t, jsonv2.Unmarshal(canonical, &v))
		decoded = &v
	case *TransferProgressEvent:
		var v TransferProgressEvent
		mustNoErr(t, jsonv2.Unmarshal(canonical, &v))
		decoded = &v
	case *MetricSampleEvent:
		var v MetricSampleEvent
		mustNoErr(t, jsonv2.Unmarshal(canonical, &v))
		decoded = &v
	case *AuditRecordEvent:
		var v AuditRecordEvent
		mustNoErr(t, jsonv2.Unmarshal(canonical, &v))
		decoded = &v
	case *PoolStateEvent:
		var v PoolStateEvent
		mustNoErr(t, jsonv2.Unmarshal(canonical, &v))
		decoded = &v
	case *DiagnosticEvent:
		var v DiagnosticEvent
		mustNoErr(t, jsonv2.Unmarshal(canonical, &v))
		decoded = &v
	case *BusDroppedEvent:
		var v BusDroppedEvent
		mustNoErr(t, jsonv2.Unmarshal(canonical, &v))
		decoded = &v
	default:
		t.Fatalf("unhandled variant %T", ev)
	}
	if !EqualEvent(ev, decoded) {
		t.Fatalf("concrete round-trip mismatch for %s", ev.Kind())
	}
}

func TestJSONv2NegativeRejectionsAllVariants(t *testing.T) {
	f := makeFixture(t)
	all := buildAll12Events(t, f)

	// 1. 顶层结构负例：null、非对象、未知 kind、重复 kind、非字符串 kind、空对象、尾随数据。
	topNegatives := []string{
		`null`, `[]`, `"operation_started"`, `123`, `{}`,
		`{"kind":"unknown_variant"}`,
		`{"kind":123}`,
		`{"kind":null}`,
		`{"kind":"diagnostic","kind":"diagnostic"}`,
		`{"kind":"diagnostic","meta":{"trace_id":"t","occurred_at":"2026-11-25T04:00:00Z"},"scope":"pool","severity":"info","message":"hi"} {"extra":1}`,
	}
	for _, raw := range topNegatives {
		if _, err := UnmarshalEvent([]byte(raw)); err == nil {
			t.Fatalf("UnmarshalEvent(%s) expected error, got nil", raw)
		}
	}

	// 2. 对全部 12 个变体逐一注入未知字段与删除必填字段、替换必填字段为 null，确保全部失败关闭。
	for _, ev := range all {
		rawBytes, err := MarshalEvent(ev)
		mustNoErr(t, err)
		t.Run("unknown_field/"+ev.Kind().String(), func(t *testing.T) {
			injected := strings.TrimSuffix(string(rawBytes), "}") + `,"unexpected_extra_field":1}`
			if _, err := UnmarshalEvent([]byte(injected)); err == nil {
				t.Fatalf("expected unknown field rejection for %s", ev.Kind())
			}
		})
		t.Run("missing_and_null_required/"+ev.Kind().String(), func(t *testing.T) {
			verifyRequiredFieldRejection(t, ev.Kind(), rawBytes)
		})
	}

	// 3. 具体变体反序列化不匹配必须失败关闭（例如 diagnostic 不可解码进 *PoolStateEvent）。
	diagBytes, err := MarshalEvent(all[10])
	mustNoErr(t, err)
	var wrongPool PoolStateEvent
	if err := jsonv2.Unmarshal(diagBytes, &wrongPool); !errors.Is(err, ErrInvalidEventKind) || wrongPool.IsValid() {
		t.Fatalf("mismatched concrete decode got err=%v valid=%v, want ErrInvalidEventKind", err, wrongPool.IsValid())
	}
	if err := jsonv2.Unmarshal([]byte("null"), &wrongPool); err == nil || wrongPool.IsValid() {
		t.Fatalf("null concrete decode must fail closed, got err=%v", err)
	}
	var env EventEnvelope
	if err := jsonv2.Unmarshal([]byte("null"), &env); !errors.Is(err, ErrInvalidEvent) || env.IsValid() {
		t.Fatalf("null EventEnvelope decode got err=%v", err)
	}
}

func verifyRequiredFieldRejection(t *testing.T, kind EventKind, rawBytes []byte) {
	t.Helper()
	var obj map[string]jsontext.Value
	mustNoErr(t, jsonv2.Unmarshal(rawBytes, &obj))
	for _, key := range requiredKeysForKind(kind) {
		// 删除必填字段
		without := make(map[string]jsontext.Value, len(obj))
		for k, v := range obj {
			if k != key {
				without[k] = v
			}
		}
		bDel, err := jsonv2.Marshal(without)
		mustNoErr(t, err)
		if _, err := UnmarshalEvent(bDel); err == nil {
			t.Fatalf("%s missing required key %q was not rejected", kind, key)
		}
		// 将必填字段置为 JSON null
		withNull := make(map[string]jsontext.Value, len(obj))
		for k, v := range obj {
			withNull[k] = v
		}
		withNull[key] = jsontext.Value("null")
		bNull, err := jsonv2.Marshal(withNull)
		mustNoErr(t, err)
		if _, err := UnmarshalEvent(bNull); err == nil {
			t.Fatalf("%s null required key %q was not rejected", kind, key)
		}
	}
}

func requiredKeysForKind(kind EventKind) []string {
	switch kind {
	case EventKindOperationStarted:
		return []string{"kind", "meta", "capability", "tool", "action"}
	case EventKindOperationCompleted:
		return []string{"kind", "meta", "capability", "duration", "succeeded"}
	case EventKindOutputChunk:
		return []string{"kind", "meta", "stream", "chunk_index", "data"}
	case EventKindStep:
		return []string{"kind", "meta", "step_id", "status", "duration"}
	case EventKindFSMTransition:
		return []string{"kind", "meta", "machine", "from_state", "to_state", "event_name"}
	case EventKindApprovalChallenge:
		return []string{"kind", "meta", "envelope", "phase"}
	case EventKindTransferProgress:
		return []string{"kind", "meta", "transfer_id", "direction", "bytes_transferred", "elapsed"}
	case EventKindMetricSample:
		return []string{"kind", "meta", "metric_name", "value", "interval"}
	case EventKindAuditRecord:
		return []string{"kind", "meta", "stage", "process_instance_id", "capability", "decision", "risk", "binding", "duration"}
	case EventKindPoolState:
		return []string{"kind", "meta", "action", "latency"}
	case EventKindDiagnostic:
		return []string{"kind", "meta", "scope", "severity", "message"}
	case EventKindBusDropped:
		return []string{"kind", "meta", "scope", "dropped_total", "dropped_delta"}
	default:
		return nil
	}
}

func TestEnumsAndMetaCodecsAndSemanticInvariants(t *testing.T) {
	f := makeFixture(t)
	checkEnumCodec(t, EventKindOperationStarted, EventKindBusDropped, ParseEventKind)
	checkEnumCodec(t, EventClassAudit, EventClassSystem, ParseEventClass)
	checkEnumCodec(t, BackpressureFailClosed, BackpressureDropAndCount, ParseBackpressurePolicy)
	checkEnumCodec(t, SeverityDebug, SeverityError, ParseSeverity)
	checkEnumCodec(t, OutputStreamStdout, OutputStreamSystem, ParseOutputStreamKind)
	checkEnumCodec(t, AuditStageAuthorized, AuditStageHalted, ParseAuditStage)
	checkEnumCodec(t, PoolActionDialStarted, PoolActionMuxHandover, ParsePoolEventAction)
	checkEnumCodec(t, DiagnosticScopePool, DiagnosticScopeRuntime, ParseDiagnosticScope)
	checkEnumCodec(t, FSMMachineVaultSaga, FSMMachinePendingEnroll, ParseFSMMachineKind)

	// EventMeta UTC 归一化、单调时钟剥离、Seq 与 RFC 3339 年份边界 [1, 9999] 校验。
	if f.opMeta.OccurredAt().Location() != time.UTC || f.opMeta.Seq() != 7 {
		t.Fatalf("EventMeta UTC/Seq mismatch: loc=%v seq=%d", f.opMeta.OccurredAt().Location(), f.opMeta.Seq())
	}
	monoMeta, err := NewEventMeta(EventMetaSpec{TraceID: f.tid, OccurredAt: time.Now()})
	mustNoErr(t, err)
	if strings.Contains(monoMeta.OccurredAt().String(), "m=") {
		t.Fatalf("EventMeta did not strip monotonic clock: %s", monoMeta.OccurredAt().String())
	}
	for _, badTime := range []time.Time{
		time.Date(0, 12, 31, 23, 59, 59, 0, time.UTC),
		time.Date(-5, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC),
	} {
		if _, err := NewEventMeta(EventMetaSpec{TraceID: f.tid, OccurredAt: badTime}); !errors.Is(err, ErrInvalidEventMeta) {
			t.Fatalf("out-of-range year %d must fail, got %v", badTime.Year(), err)
		}
		crafted := EventMeta{traceID: f.tid, occurredAt: badTime, valid: true}
		if crafted.IsValid() {
			t.Fatalf("crafted out-of-range EventMeta year %d must report IsValid()==false", badTime.Year())
		}
	}
	checkEnumUnmarshalEdgeCases(t)
	var badMeta EventMeta
	for _, bad := range []string{
		`null`, `{}`, `{"trace_id":"t"}`, `{"occurred_at":"2026-11-25T04:00:00Z"}`,
		`{"trace_id":"t","occurred_at":"0001-01-01T00:00:00Z"}`,
		`{"trace_id":"t","occurred_at":"2026-11-25T04:00:00Z","extra":1}`,
	} {
		if err := jsonv2.Unmarshal([]byte(bad), &badMeta); err == nil || badMeta.IsValid() {
			t.Fatalf("EventMeta.Unmarshal(%s) expected error", bad)
		}
	}

	// 语义不变式拒绝测试与全 5 大 FSM 桥接构造器正反例测试。
	assertVariantSemanticRejections(t, f)
	assertPositiveAdditionalVariants(t, f)
	assertFSMTransitionHelpers(t, f)
}

func checkEnumUnmarshalEdgeCases(t *testing.T) {
	t.Helper()
	var nilKind *EventKind
	if err := nilKind.UnmarshalText([]byte("step")); !errors.Is(err, ErrNilReceiver) {
		t.Fatalf("nil UnmarshalText got %v, want ErrNilReceiver", err)
	}
	k := EventKindStep
	if err := k.UnmarshalText([]byte("bad_kind")); !errors.Is(err, ErrInvalidEventKind) || k != EventKindInvalid {
		t.Fatalf("failed UnmarshalText must reset receiver to Invalid, got k=%v err=%v", k, err)
	}
}

func checkEnumCodec[T interface {
	~uint8
	IsValid() bool
	IsZero() bool
	String() string
	AppendText([]byte) ([]byte, error)
	MarshalText() ([]byte, error)
}](t *testing.T, lo, hi T, parse func(string) (T, error)) {
	t.Helper()
	var zero T
	if zero.IsValid() || !zero.IsZero() {
		t.Fatalf("enum zero %T must be invalid", zero)
	}
	if _, err := zero.MarshalText(); err == nil {
		t.Fatalf("zero enum %T MarshalText must fail", zero)
	}
	for v := lo; v <= hi; v++ {
		if !v.IsValid() || v.IsZero() {
			t.Fatalf("enum %T(%d) should be valid", v, v)
		}
		txt, err := v.MarshalText()
		mustNoErr(t, err)
		got, err := parse(string(txt))
		mustNoErr(t, err)
		if got != v {
			t.Fatalf("parse(%q) = %v, want %v", txt, got, v)
		}
	}
	for _, bad := range []string{"", "invalid", " " + lo.String(), strings.ToUpper(lo.String()), "unknown_xyz"} {
		if _, err := parse(bad); err == nil {
			t.Fatalf("parse(%q) for %T must fail closed", bad, zero)
		}
	}
	checkEnumOutOfRange[T](t)
}

func checkEnumOutOfRange[T interface {
	~uint8
	IsValid() bool
	String() string
	AppendText([]byte) ([]byte, error)
	MarshalText() ([]byte, error)
}](t *testing.T) {
	t.Helper()
	for _, oob := range []T{T(99), T(255)} {
		if oob.IsValid() || oob.String() != "invalid" {
			t.Fatalf("out-of-range %T(%d) must fail closed, got valid=%v str=%q", oob, oob, oob.IsValid(), oob.String())
		}
		if _, err := oob.AppendText(nil); err == nil {
			t.Fatalf("out-of-range %T(%d) AppendText must fail", oob, oob)
		}
		if _, err := oob.MarshalText(); err == nil {
			t.Fatalf("out-of-range %T(%d) MarshalText must fail", oob, oob)
		}
		if _, err := jsonv2.Marshal(oob); err == nil {
			t.Fatalf("out-of-range %T(%d) jsonv2.Marshal must fail", oob, oob)
		}
	}
}

func assertVariantSemanticRejections(t *testing.T, f testFixture) {
	t.Helper()
	negDur := algebraic.FromStdDuration(-time.Second)
	outUnknown, err := execution.NewOutcomeUnknown(execution.ExecPhaseRunning, "LOST", "lost")
	mustNoErr(t, err)

	if _, err := NewOperationCompletedEvent(OperationCompletedSpec{
		Meta: f.opMeta, Capability: security.CapabilityExecute, Duration: algebraic.ZeroDuration(),
		Outcome: algebraic.Some[execution.ExecutionOutcome](outUnknown), Succeeded: true,
	}); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("OutcomeUnknown + succeeded=true must fail, got %v", err)
	}
	if _, err := NewOperationCompletedEvent(OperationCompletedSpec{
		Meta: f.opMeta, Capability: security.CapabilityExecute, Duration: negDur, Succeeded: false,
	}); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("negative duration must fail, got %v", err)
	}
	if _, err := NewTransferProgressEvent(TransferProgressSpec{
		Meta: f.opMeta, TransferID: f.opID2, Direction: fsm.TransferDirectionUpload,
		BytesTransferred: 100, TotalBytes: 50, Elapsed: algebraic.ZeroDuration(),
	}); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("bytes > total must fail, got %v", err)
	}
	if _, err := NewMetricSampleEvent(MetricSampleSpec{
		Meta: f.opMeta, MetricName: "cpu", Value: math.NaN(), Interval: algebraic.ZeroDuration(),
	}); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("NaN metric must fail, got %v", err)
	}
	// -0.0 应归一化为 +0.0 以确保规范 JSON 输出 "0"。
	negZero := math.Copysign(0, -1)
	mEv, err := NewMetricSampleEvent(MetricSampleSpec{
		Meta: f.opMeta, MetricName: "load", Value: negZero, Interval: algebraic.ZeroDuration(),
		Labels: map[string]string{"host": "a\x00b\u202ec"},
	})
	mustNoErr(t, err)
	if math.Signbit(mEv.Value()) {
		t.Fatal("-0.0 was not normalized to +0.0")
	}
	if strings.ContainsRune(mEv.Labels()["host"], '\u202e') {
		t.Fatal("bidi control rune was not sanitized in metric labels")
	}
	// 审计 Authorized 缺少 Binding 必须失败关闭。
	if _, err := NewAuditRecordEvent(AuditRecordSpec{
		Meta: f.opMeta, Stage: AuditStageAuthorized, ProcessInstanceID: "p1",
		Capability: security.CapabilityExecute, Decision: security.NewDecisionAllow("ok"),
		Risk: security.RiskSafe, Duration: algebraic.ZeroDuration(),
	}); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("authorized audit without binding must fail, got %v", err)
	}
	// OutputChunk 防御性切片拷贝与空载荷拒绝。
	if _, err := NewOutputChunkEvent(OutputChunkSpec{Meta: f.opMeta, Stream: OutputStreamStdout}); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("empty non-truncated chunk must fail, got %v", err)
	}
	src := []byte("abc")
	cEv, err := NewOutputChunkEvent(OutputChunkSpec{Meta: f.opMeta, Stream: OutputStreamStdout, Data: src})
	mustNoErr(t, err)
	src[0] = 'X'
	gotData := cEv.Data()
	gotData[1] = 'Y'
	if string(cEv.Data()) != "abc" {
		t.Fatalf("OutputChunkEvent data mutated externally: %q", cEv.Data())
	}
	if _, err := NewBusDroppedEvent(BusDroppedSpec{
		Meta: f.sysMeta, Scope: DiagnosticScopePool, DroppedTotal: 3, DroppedDelta: 5,
	}); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("dropped_total < dropped_delta must fail, got %v", err)
	}
}

func assertPositiveAdditionalVariants(t *testing.T, f testFixture) {
	t.Helper()
	// Truncated=true 且 Data=nil 的 OutputChunkEvent 必须支持无损 JSON 往返。
	truncEv, err := NewOutputChunkEvent(OutputChunkSpec{
		Meta: f.opMeta, Stream: OutputStreamStderr, ChunkIndex: 9, Data: nil, Truncated: true,
	})
	mustNoErr(t, err)
	bTrunc, err := MarshalEvent(truncEv)
	mustNoErr(t, err)
	decTrunc, err := UnmarshalEvent(bTrunc)
	mustNoErr(t, err)
	if !EqualEvent(truncEv, decTrunc) || !decTrunc.(*OutputChunkEvent).Truncated() || decTrunc.(*OutputChunkEvent).Data() != nil {
		t.Fatalf("truncated nil-data OutputChunk round-trip mismatch: %s", bTrunc)
	}

	// AuditRecordEvent 覆盖 Denied / NeedApproval / Halted 三类非 Allow 阶段往返。
	needAppr, err := security.NewDecisionNeedApproval(security.RiskDangerous, "confirm required")
	mustNoErr(t, err)
	specs := []AuditRecordSpec{
		{Meta: f.opMeta, Stage: AuditStageDenied, ProcessInstanceID: "p-deny", Capability: security.CapabilityExecute, Decision: security.NewDecisionDeny("blocked"), Risk: security.RiskDangerous, Duration: algebraic.ZeroDuration()},
		{Meta: f.opMeta, Stage: AuditStageNeedApproval, ProcessInstanceID: "p-appr", Capability: security.CapabilityExecute, Decision: needAppr, Risk: security.RiskDangerous, Duration: algebraic.ZeroDuration()},
		{Meta: f.opMeta, Stage: AuditStageHalted, ProcessInstanceID: "p-halt", Capability: security.CapabilityExecute, Decision: security.NewDecisionDeny("halted"), Risk: security.RiskDangerous, Duration: algebraic.ZeroDuration()},
	}
	for _, sp := range specs {
		ev, err := NewAuditRecordEvent(sp)
		mustNoErr(t, err)
		raw, err := MarshalEvent(ev)
		mustNoErr(t, err)
		got, err := UnmarshalEvent(raw)
		mustNoErr(t, err)
		if !EqualEvent(ev, got) {
			t.Fatalf("audit stage %s round-trip mismatch", sp.Stage)
		}
	}
}

// TestCrossFieldSecurityAndIsValidParity 验证跨字段安全不变式在构造器、JSON 解码与 IsValid() 三处完全等价。
func TestCrossFieldSecurityAndIsValidParity(t *testing.T) {
	f := makeFixture(t)
	assertApprovalOpIDBinding(t, f)
	assertAuditCrossFieldRejections(t, f)
	assertCraftedInconsistentIsValidFalse(t, f)
}

func assertApprovalOpIDBinding(t *testing.T, f testFixture) {
	t.Helper()
	otherMeta, err := NewEventMeta(EventMetaSpec{TraceID: f.tid, OperationID: algebraic.Some(f.opID2), OccurredAt: f.now})
	mustNoErr(t, err)
	if _, err := NewApprovalChallengeEvent(ApprovalChallengeSpec{
		Meta: otherMeta, Envelope: f.envelope, Phase: fsm.ApprovalPhaseChallengeIssued,
	}); !errors.Is(err, ErrOperationMismatch) {
		t.Fatalf("mismatched ApprovalEnvelope opID got %v, want ErrOperationMismatch", err)
	}
	// JSON 伪造 meta.operation_id 也必须被 UnmarshalEvent 拒绝。
	validEv, err := NewApprovalChallengeEvent(ApprovalChallengeSpec{
		Meta: f.opMeta, Envelope: f.envelope, Phase: fsm.ApprovalPhaseChallengeIssued,
	})
	mustNoErr(t, err)
	raw, err := MarshalEvent(validEv)
	mustNoErr(t, err)
	forged := strings.Replace(string(raw), `"operation_id":"`+f.opID.String()+`"`, `"operation_id":"`+f.opID2.String()+`"`, 1)
	if _, err := UnmarshalEvent([]byte(forged)); !errors.Is(err, ErrOperationMismatch) {
		t.Fatalf("forged JSON ApprovalChallenge meta.operation_id got %v, want ErrOperationMismatch", err)
	}
}

func assertAuditCrossFieldRejections(t *testing.T, f testFixture) {
	t.Helper()
	needAppr, err := security.NewDecisionNeedApproval(security.RiskDangerous, "need confirm")
	mustNoErr(t, err)
	// 验证与 core/ports.AuditEntry 一致的审批流合法组合：NeedApproval 允许出现在 Authorized/Finalized/AbortedByCrash/Denied。
	for _, st := range []AuditStage{AuditStageAuthorized, AuditStageFinalized, AuditStageAbortedByCrash, AuditStageDenied} {
		sp := AuditRecordSpec{
			Meta: f.opMeta, Stage: st, ProcessInstanceID: "p1",
			Capability: security.CapabilityExecute, Decision: needAppr,
			Risk: security.RiskDangerous, Duration: algebraic.ZeroDuration(),
		}
		if st != AuditStageDenied {
			sp.Binding = algebraic.Some(f.binding)
		}
		ev, cErr := NewAuditRecordEvent(sp)
		mustNoErr(t, cErr)
		raw, mErr := MarshalEvent(ev)
		mustNoErr(t, mErr)
		back, uErr := UnmarshalEvent(raw)
		mustNoErr(t, uErr)
		if !EqualEvent(ev, back) {
			t.Fatalf("approval audit stage %s JSON roundtrip mismatch", st)
		}
	}
	badSpecs := []AuditRecordSpec{
		// Binding.Capability (Execute) != Spec.Capability (Transfer)
		{Meta: f.opMeta, Stage: AuditStageAuthorized, ProcessInstanceID: "p1", Capability: security.CapabilityTransfer, Decision: security.NewDecisionAllow("ok"), Risk: security.RiskModerate, Binding: algebraic.Some(f.binding), Duration: algebraic.ZeroDuration()},
		// Stage <-> Decision 矛盾组合
		{Meta: f.opMeta, Stage: AuditStageAuthorized, ProcessInstanceID: "p1", Capability: security.CapabilityExecute, Decision: security.NewDecisionDeny("no"), Risk: security.RiskModerate, Binding: algebraic.Some(f.binding), Duration: algebraic.ZeroDuration()},
		{Meta: f.opMeta, Stage: AuditStageFinalized, ProcessInstanceID: "p1", Capability: security.CapabilityExecute, Decision: security.NewDecisionDeny("no"), Risk: security.RiskDangerous, Binding: algebraic.Some(f.binding), Duration: algebraic.ZeroDuration()},
		{Meta: f.opMeta, Stage: AuditStageAbortedByCrash, ProcessInstanceID: "p1", Capability: security.CapabilityExecute, Decision: security.NewDecisionDeny("no"), Risk: security.RiskDangerous, Binding: algebraic.Some(f.binding), Duration: algebraic.ZeroDuration()},
		{Meta: f.opMeta, Stage: AuditStageDenied, ProcessInstanceID: "p1", Capability: security.CapabilityExecute, Decision: security.NewDecisionAllow("ok"), Risk: security.RiskSafe, Duration: algebraic.ZeroDuration()},
		{Meta: f.opMeta, Stage: AuditStageNeedApproval, ProcessInstanceID: "p1", Capability: security.CapabilityExecute, Decision: security.NewDecisionAllow("ok"), Risk: security.RiskSafe, Duration: algebraic.ZeroDuration()},
		{Meta: f.opMeta, Stage: AuditStageHalted, ProcessInstanceID: "p1", Capability: security.CapabilityExecute, Decision: security.NewDecisionAllow("ok"), Risk: security.RiskDangerous, Duration: algebraic.ZeroDuration()},
		{Meta: f.opMeta, Stage: AuditStageHalted, ProcessInstanceID: "p1", Capability: security.CapabilityExecute, Decision: needAppr, Risk: security.RiskDangerous, Duration: algebraic.ZeroDuration()},
	}
	for i, sp := range badSpecs {
		if _, err := NewAuditRecordEvent(sp); !errors.Is(err, ErrInvalidEvent) {
			t.Fatalf("bad audit spec #%d expected ErrInvalidEvent, got %v", i, err)
		}
	}
	// JSON 篡改 audit_record stage 为 denied 但保留 allow decision 必须拒绝。
	validAud, err := NewAuditRecordEvent(AuditRecordSpec{
		Meta: f.opMeta, Stage: AuditStageAuthorized, ProcessInstanceID: "p1",
		Capability: security.CapabilityExecute, Decision: security.NewDecisionAllow("ok"),
		Risk: security.RiskModerate, Binding: algebraic.Some(f.binding), Duration: algebraic.ZeroDuration(),
	})
	mustNoErr(t, err)
	raw, err := MarshalEvent(validAud)
	mustNoErr(t, err)
	forged := strings.Replace(string(raw), `"stage":"authorized"`, `"stage":"denied"`, 1)
	if _, err := UnmarshalEvent([]byte(forged)); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("forged JSON contradictory audit stage/decision got %v, want ErrInvalidEvent", err)
	}
}

func assertCraftedInconsistentIsValidFalse(t *testing.T, f testFixture) {
	t.Helper()
	outUnknown, err := execution.NewOutcomeUnknown(execution.ExecPhaseRunning, "LOST", "lost")
	mustNoErr(t, err)
	stepID, err := playbook.ParseStepID("s1")
	mustNoErr(t, err)
	otherMeta, err := NewEventMeta(EventMetaSpec{TraceID: f.tid, OperationID: algebraic.Some(f.opID2), OccurredAt: f.now})
	mustNoErr(t, err)

	badComp := &OperationCompletedEvent{sealedEventMixin: newBase(EventKindOperationCompleted, EventClassOperation, f.opMeta), capability: security.CapabilityExecute, outcome: algebraic.Some[execution.ExecutionOutcome](outUnknown), succeeded: true}
	badStep := &StepEvent{sealedEventMixin: newBase(EventKindStep, EventClassOperation, f.opMeta), stepID: stepID, status: playbook.StepStatusSucceeded, outcome: algebraic.Some[execution.ExecutionOutcome](outUnknown)}
	badAppr := &ApprovalChallengeEvent{sealedEventMixin: newBase(EventKindApprovalChallenge, EventClassOperation, otherMeta), envelope: f.envelope, phase: fsm.ApprovalPhaseChallengeIssued}
	badAud := &AuditRecordEvent{sealedEventMixin: newBase(EventKindAuditRecord, EventClassAudit, f.opMeta), stage: AuditStageDenied, processInstanceID: "p1", capability: security.CapabilityExecute, decision: security.NewDecisionAllow("ok"), risk: security.RiskSafe}
	if badComp.IsValid() || badStep.IsValid() || badAppr.IsValid() || badAud.IsValid() {
		t.Fatal("crafted cross-field inconsistent events must report IsValid()==false")
	}
}

// TestMetricCoalesceKeyInjectivity 验证 MetricSampleEvent.CoalesceKey 长度前缀帧编码无跨序列分隔符碰撞。
func TestMetricCoalesceKeyInjectivity(t *testing.T) {
	f := makeFixture(t)
	metaNoNode, err := NewEventMeta(EventMetaSpec{TraceID: f.tid, OperationID: algebraic.Some(f.opID), OccurredAt: f.now})
	mustNoErr(t, err)
	mk := func(meta EventMeta, name string, labels map[string]string, val float64) *MetricSampleEvent {
		ev, err := NewMetricSampleEvent(MetricSampleSpec{
			Meta: meta, MetricName: name, Value: val, Interval: algebraic.ZeroDuration(), Labels: labels,
		})
		mustNoErr(t, err)
		return ev
	}
	series := []*MetricSampleEvent{
		mk(f.opMeta, "cpu", nil, 1),                                     // NodeID=Some("web-01"), Metric="cpu"
		mk(metaNoNode, "web-01:cpu", nil, 2),                            // NodeID=None, Metric="web-01:cpu"
		mk(metaNoNode, "cpu", map[string]string{"a": "1|b=2"}, 3),       // value 含 | 与 =
		mk(metaNoNode, "cpu", map[string]string{"a": "1", "b": "2"}, 4), // 拆分为两键
		mk(metaNoNode, "cpu|a=1", nil, 5),                               // Metric 含 | 与 =
		mk(metaNoNode, "cpu", map[string]string{"a": "1"}, 6),           // Metric="cpu" + label
	}
	seen := make(map[string]int, len(series))
	for i, ev := range series {
		k := ev.CoalesceKey()
		if prev, dup := seen[k]; dup {
			t.Fatalf("CoalesceKey collision between series #%d and #%d: %q", prev, i, k)
		}
		seen[k] = i
	}
	// 全部 6 个易碰撞序列同时写入同一 OperationStream，不得发生相互覆盖。
	stream, err := NewOperationStream(OperationStreamConfig{TraceID: f.tid, OperationID: f.opID, OperationBuffer: 4})
	mustNoErr(t, err)
	for _, ev := range series {
		mustNoErr(t, stream.Emit(t.Context(), ev))
	}
	stream.Close()
	if st := stream.Stats(); st.PendingCoalescedKeys != len(series) || st.Coalesced != 0 {
		t.Fatalf("unexpected coalescing across distinct series: %+v", st)
	}
}

func assertFSMTransitionHelpers(t *testing.T, f testFixture) {
	t.Helper()
	assertPositiveFSMTransitions(t, f)
	// 无效零值 FSM 事件必须失败关闭。
	var zVault fsm.VaultSagaEvent
	var zAppr fsm.ApprovalEvent
	var zTrans fsm.TransferEvent
	var zEnroll fsm.PendingEnrollEvent
	if _, err := NewVaultSagaTransitionEvent(f.opMeta, fsm.VaultSagaKindInit, fsm.VaultSagaKindWritingNew, zVault, false); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("invalid VaultSagaEvent must fail, got %v", err)
	}
	if _, err := NewApprovalTransitionEvent(f.opMeta, fsm.ApprovalPhaseLexicalPrecheck, fsm.ApprovalPhaseApproved, zAppr, true); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("invalid ApprovalEvent must fail, got %v", err)
	}
	if _, err := NewTransferTransitionEvent(f.opMeta, fsm.TransferKindInitialized, fsm.TransferKindStreaming, zTrans, false); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("invalid TransferEvent must fail, got %v", err)
	}
	if _, err := NewPendingEnrollTransitionEvent(f.opMeta, fsm.PendingEnrollPhaseIdle, fsm.PendingEnrollPhaseStaged, zEnroll, false); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("invalid PendingEnrollEvent must fail, got %v", err)
	}
}

func assertPositiveFSMTransitions(t *testing.T, f testFixture) {
	t.Helper()
	// 1. EnsureFSM
	eCtx, err := fsm.NewEnsureContext(f.opID, "ensure-nginx", 1)
	mustNoErr(t, err)
	eState, err := fsm.NewEnsureState(eCtx)
	mustNoErr(t, err)
	nextE, _, eEvs, err := fsm.TransitionEnsure(eState, fsm.EnsureInputStart())
	mustNoErr(t, err)
	trE, err := NewEnsureTransitionEvent(f.opMeta, eState.Phase(), nextE.Phase(), eEvs[0], nextE.IsTerminal())
	mustNoErr(t, err)
	if trE.Machine() != FSMMachineEnsure || trE.FromState() != "pending" || trE.ToState() != "checking" {
		t.Fatalf("unexpected ensure transition: %+v", trE)
	}

	// 2. VaultSagaFSM
	ref, err := secret.NewRef("vault", "ssh-key-1")
	mustNoErr(t, err)
	vCtx, err := fsm.NewVaultSagaContext(fsm.VaultSagaContextSpec{SagaID: f.opID, NewRef: ref, ExpectedCASVersion: 1})
	mustNoErr(t, err)
	vState, err := fsm.NewVaultSagaState(vCtx)
	mustNoErr(t, err)
	nextV, _, vEvs, err := fsm.TransitionVaultSaga(vState, fsm.VaultInputStart())
	mustNoErr(t, err)
	trV, err := NewVaultSagaTransitionEvent(f.opMeta, vState.Kind(), nextV.Kind(), vEvs[0], nextV.IsTerminal())
	mustNoErr(t, err)
	if trV.Machine() != FSMMachineVaultSaga || trV.ToState() != "writing_new" {
		t.Fatalf("unexpected vault transition: %+v", trV)
	}

	// 3. ApprovalFSM
	snap, err := security.NewScopeSnapshot(security.ScopeSnapshotSpec{
		Capability: security.CapabilityExecute, TargetNode: "web-01", Verdict: security.VerdictAllow,
		Risk: security.RiskSafe, Decision: security.NewDecisionAllow("ok"),
	})
	mustNoErr(t, err)
	aCtx, err := fsm.NewApprovalContext(fsm.ApprovalContextSpec{OperationID: f.opID, LexicalBinding: f.binding, LexicalSnapshot: snap})
	mustNoErr(t, err)
	aState, err := fsm.NewApprovalState(aCtx)
	mustNoErr(t, err)
	nextA, _, aEvs, err := fsm.TransitionApproval(aState, fsm.ApprovalInputEvaluateLexical(false))
	mustNoErr(t, err)
	trA, err := NewApprovalTransitionEvent(f.opMeta, aState.Phase(), nextA.Phase(), aEvs[0], nextA.IsTerminal())
	mustNoErr(t, err)
	if trA.Machine() != FSMMachineApproval || trA.ToState() != "approved" {
		t.Fatalf("unexpected approval transition: %+v", trA)
	}

	// 4. TransferFSM
	rp, err := pathalg.ParseRemotePath("/tmp/app.bin")
	mustNoErr(t, err)
	dest, err := fsm.NewUploadDest(rp)
	mustNoErr(t, err)
	tMeta, err := fsm.NewTransferMeta(fsm.TransferMetaSpec{
		TransferID: f.opID, Dest: dest, TotalBytes: 1024, JournalVersion: fsm.JournalVersionV2, Generation: 1,
	})
	mustNoErr(t, err)
	tState, err := fsm.NewTransferState(tMeta)
	mustNoErr(t, err)
	nextT, _, tEvs, err := fsm.TransitionTransfer(tState, fsm.TransferInputStart())
	mustNoErr(t, err)
	trT, err := NewTransferTransitionEvent(f.opMeta, tState.Kind(), nextT.Kind(), tEvs[0], nextT.IsTerminal())
	mustNoErr(t, err)
	if trT.Machine() != FSMMachineTransfer || trT.ToState() != "streaming" {
		t.Fatalf("unexpected transfer transition: %+v", trT)
	}

	// 5. PendingEnrollFSM
	pCtx, err := fsm.NewPendingEnrollContext(fsm.PendingEnrollContextSpec{
		LeaseID: f.opID, TargetNode: f.nodeID, PinnedRefs: []secret.Ref{ref},
		StagedAt: f.now, TTL: algebraic.FromStdDuration(time.Minute),
	})
	mustNoErr(t, err)
	pState := fsm.NewPendingEnrollState()
	stageIn, err := fsm.EnrollInputStage(pCtx)
	mustNoErr(t, err)
	nextP, _, pEvs, err := fsm.TransitionPendingEnroll(pState, stageIn)
	mustNoErr(t, err)
	trP, err := NewPendingEnrollTransitionEvent(f.opMeta, pState.Phase(), nextP.Phase(), pEvs[0], nextP.IsTerminal())
	mustNoErr(t, err)
	if trP.Machine() != FSMMachinePendingEnroll || trP.ToState() != "staged" {
		t.Fatalf("unexpected pending_enroll transition: %+v", trP)
	}
}
