package events

import (
	"bytes"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/playbook"
	"github.com/wentf9/xops-cli/core/domain/security"
)

// outcomeJSONBox 与 decisionJSONBox 将多态领域接口适配为 json/v2 值编解码器。
type (
	outcomeJSONBox  struct{ value execution.ExecutionOutcome }
	decisionJSONBox struct{ value security.GuardrailDecision }
)

func (b outcomeJSONBox) MarshalJSONTo(enc *jsontext.Encoder) error {
	return execution.MarshalOutcomeTo(enc, b.value)
}
func (b *outcomeJSONBox) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	if b == nil {
		return ErrNilReceiver
	}
	v, err := execution.UnmarshalOutcomeFrom(dec)
	b.value = pickIf(err == nil, v, nil)
	return err
}
func (b decisionJSONBox) MarshalJSONTo(enc *jsontext.Encoder) error {
	return security.MarshalDecisionTo(enc, b.value)
}
func (b *decisionJSONBox) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	if b == nil {
		return ErrNilReceiver
	}
	v, err := security.UnmarshalDecisionFrom(dec)
	b.value = pickIf(err == nil, v, nil)
	return err
}
func optOutcomeToBox(opt algebraic.Option[execution.ExecutionOutcome]) algebraic.Option[outcomeJSONBox] {
	if v, ok := opt.Get(); ok {
		return algebraic.Some(outcomeJSONBox{value: v})
	}
	return algebraic.None[outcomeJSONBox]()
}
func optOutcomeFromBox(opt algebraic.Option[outcomeJSONBox]) algebraic.Option[execution.ExecutionOutcome] {
	if v, ok := opt.Get(); ok {
		return algebraic.Some(v.value)
	}
	return algebraic.None[execution.ExecutionOutcome]()
}

// 各事件变体独占强类型线缆结构体：配合 RejectUnknownMembers(true) 严格拒绝未知字段、重复键与跨变体字段混用。
type (
	opStartedWire struct {
		Kind       algebraic.Option[EventKind]               `json:"kind"`
		Meta       algebraic.Option[EventMeta]               `json:"meta"`
		Capability algebraic.Option[security.CapabilityKind] `json:"capability"`
		Tool       algebraic.Option[string]                  `json:"tool"`
		Action     algebraic.Option[string]                  `json:"action"`
		PlanDigest algebraic.Option[plan.PlanDigest]         `json:"plan_digest,omitzero"`
		Summary    string                                    `json:"summary,omitzero"`
	}
	opCompletedWire struct {
		Kind       algebraic.Option[EventKind]               `json:"kind"`
		Meta       algebraic.Option[EventMeta]               `json:"meta"`
		Capability algebraic.Option[security.CapabilityKind] `json:"capability"`
		Duration   algebraic.Option[algebraic.Duration]      `json:"duration"`
		Outcome    algebraic.Option[outcomeJSONBox]          `json:"outcome,omitzero"`
		Succeeded  algebraic.Option[bool]                    `json:"succeeded"`
		Code       string                                    `json:"code,omitzero"`
		Message    string                                    `json:"message,omitzero"`
	}
	outputChunkWire struct {
		Kind       algebraic.Option[EventKind]        `json:"kind"`
		Meta       algebraic.Option[EventMeta]        `json:"meta"`
		Stream     algebraic.Option[OutputStreamKind] `json:"stream"`
		ChunkIndex algebraic.Option[uint64]           `json:"chunk_index"`
		Data       algebraic.Option[[]byte]           `json:"data,omitzero"`
		Truncated  bool                               `json:"truncated,omitzero"`
	}
	stepEventWire struct {
		Kind       algebraic.Option[EventKind]           `json:"kind"`
		Meta       algebraic.Option[EventMeta]           `json:"meta"`
		PlaybookID algebraic.Option[playbook.PlaybookID] `json:"playbook_id,omitzero"`
		StepID     algebraic.Option[playbook.StepID]     `json:"step_id"`
		Status     algebraic.Option[playbook.StepStatus] `json:"status"`
		Duration   algebraic.Option[algebraic.Duration]  `json:"duration"`
		Outcome    algebraic.Option[outcomeJSONBox]      `json:"outcome,omitzero"`
		Message    string                                `json:"message,omitzero"`
	}
	fsmTransitionWire struct {
		Kind      algebraic.Option[EventKind]      `json:"kind"`
		Meta      algebraic.Option[EventMeta]      `json:"meta"`
		Machine   algebraic.Option[FSMMachineKind] `json:"machine"`
		FromState algebraic.Option[string]         `json:"from_state"`
		ToState   algebraic.Option[string]         `json:"to_state"`
		EventName algebraic.Option[string]         `json:"event_name"`
		Detail    string                           `json:"detail,omitzero"`
		Terminal  bool                             `json:"terminal,omitzero"`
	}
	approvalChallengeWire struct {
		Kind      algebraic.Option[EventKind]                 `json:"kind"`
		Meta      algebraic.Option[EventMeta]                 `json:"meta"`
		Envelope  algebraic.Option[security.ApprovalEnvelope] `json:"envelope"`
		Phase     algebraic.Option[fsm.ApprovalPhase]         `json:"phase"`
		Escalated bool                                        `json:"escalated,omitzero"`
		Reason    string                                      `json:"reason,omitzero"`
	}
	transferProgressWire struct {
		Kind             algebraic.Option[EventKind]             `json:"kind"`
		Meta             algebraic.Option[EventMeta]             `json:"meta"`
		TransferID       algebraic.Option[security.OperationID]  `json:"transfer_id"`
		Direction        algebraic.Option[fsm.TransferDirection] `json:"direction"`
		BytesTransferred algebraic.Option[uint64]                `json:"bytes_transferred"`
		TotalBytes       uint64                                  `json:"total_bytes,omitzero"`
		ChunksCompleted  uint64                                  `json:"chunks_completed,omitzero"`
		Elapsed          algebraic.Option[algebraic.Duration]    `json:"elapsed"`
		RateBytesPerSec  uint64                                  `json:"rate_bytes_per_sec,omitzero"`
		Stage            string                                  `json:"stage,omitzero"`
	}
	metricSampleWire struct {
		Kind       algebraic.Option[EventKind]          `json:"kind"`
		Meta       algebraic.Option[EventMeta]          `json:"meta"`
		MetricName algebraic.Option[string]             `json:"metric_name"`
		Unit       string                               `json:"unit,omitzero"`
		Value      algebraic.Option[float64]            `json:"value"`
		Interval   algebraic.Option[algebraic.Duration] `json:"interval"`
		Labels     map[string]string                    `json:"labels,omitzero"`
	}
	auditRecordWire struct {
		Kind              algebraic.Option[EventKind]                 `json:"kind"`
		Meta              algebraic.Option[EventMeta]                 `json:"meta"`
		Stage             algebraic.Option[AuditStage]                `json:"stage"`
		ProcessInstanceID algebraic.Option[string]                    `json:"process_instance_id"`
		Capability        algebraic.Option[security.CapabilityKind]   `json:"capability"`
		Decision          algebraic.Option[decisionJSONBox]           `json:"decision"`
		Risk              algebraic.Option[security.RiskLevel]        `json:"risk"`
		Binding           algebraic.Option[security.OperationBinding] `json:"binding,omitzero"`
		Outcome           algebraic.Option[outcomeJSONBox]            `json:"outcome,omitzero"`
		Duration          algebraic.Option[algebraic.Duration]        `json:"duration"`
		Reason            string                                      `json:"reason,omitzero"`
	}
	poolStateWire struct {
		Kind         algebraic.Option[EventKind]           `json:"kind"`
		Meta         algebraic.Option[EventMeta]           `json:"meta"`
		Action       algebraic.Option[PoolEventAction]     `json:"action"`
		PlanDigest   algebraic.Option[plan.PlanDigest]     `json:"plan_digest,omitzero"`
		HopDigest    algebraic.Option[plan.HopDigest]      `json:"hop_digest,omitzero"`
		Endpoint     algebraic.Option[netaddr.Endpoint]    `json:"endpoint,omitzero"`
		HandleKind   algebraic.Option[plan.HandleKindCode] `json:"handle_kind,omitzero"`
		HandleID     algebraic.Option[plan.HandleID]       `json:"handle_id,omitzero"`
		Generation   uint64                                `json:"generation,omitzero"`
		ActiveLeases uint32                                `json:"active_leases,omitzero"`
		Latency      algebraic.Option[algebraic.Duration]  `json:"latency"`
		Detail       string                                `json:"detail,omitzero"`
	}
	diagnosticWire struct {
		Kind     algebraic.Option[EventKind]       `json:"kind"`
		Meta     algebraic.Option[EventMeta]       `json:"meta"`
		Scope    algebraic.Option[DiagnosticScope] `json:"scope"`
		Severity algebraic.Option[Severity]        `json:"severity"`
		Code     string                            `json:"code,omitzero"`
		Message  algebraic.Option[string]          `json:"message"`
		Attrs    map[string]string                 `json:"attrs,omitzero"`
	}
	busDroppedWire struct {
		Kind         algebraic.Option[EventKind]       `json:"kind"`
		Meta         algebraic.Option[EventMeta]       `json:"meta"`
		Scope        algebraic.Option[DiagnosticScope] `json:"scope"`
		DroppedTotal algebraic.Option[uint64]          `json:"dropped_total"`
		DroppedDelta algebraic.Option[uint64]          `json:"dropped_delta"`
		Reason       string                            `json:"reason,omitzero"`
	}
)

// EventEnvelope 是包装多态 Event 的不可变值容器，便于在结构体字段或切片中直接参与 encoding/json/v2 编解码。
//
//xops:opaque
//xops:failclosed
type EventEnvelope struct {
	event Event
	valid bool
}

// NewEventEnvelope 校验事件有效性并封装为不可变 EventEnvelope；nil 或无效零值失败关闭。
func NewEventEnvelope(ev Event) (EventEnvelope, error) {
	if ev == nil || !ev.IsValid() {
		return EventEnvelope{}, ErrInvalidEvent
	}
	return EventEnvelope{event: ev, valid: true}, nil
}

func (e EventEnvelope) IsValid() bool { return e.valid && e.event != nil && e.event.IsValid() }
func (e EventEnvelope) IsZero() bool  { return !e.IsValid() }
func (e EventEnvelope) Event() Event  { return pickIf(e.IsValid(), e.event, nil) }
func (e EventEnvelope) Equal(other EventEnvelope) bool {
	return e.IsValid() && other.IsValid() && EqualEvent(e.event, other.event)
}
func (e EventEnvelope) MarshalJSONTo(enc *jsontext.Encoder) error {
	return MarshalEventTo(enc, e.Event())
}
func (e *EventEnvelope) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	if e == nil || dec == nil {
		return ErrNilReceiver
	}
	*e = EventEnvelope{}
	ev, err := UnmarshalEventFrom(dec)
	if err == nil {
		*e = EventEnvelope{event: ev, valid: true}
	}
	return err
}

// MarshalEvent 以 Go 1.27 encoding/json/v2 规范确定性模式（Deterministic(true)）编码任意有效 Event。
func MarshalEvent(ev Event) ([]byte, error) {
	if ev == nil || !ev.IsValid() {
		return nil, ErrInvalidEvent
	}
	var buf bytes.Buffer
	enc := jsontext.NewEncoder(&buf)
	if err := MarshalEventTo(enc, ev); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), nil
}

// UnmarshalEvent 从完整 JSON 字节切片严格解码单条多态 Event；拒绝 null、未知变体、缺失/未知字段与尾随内容。
func UnmarshalEvent(data []byte) (Event, error) {
	dec := jsontext.NewDecoder(bytes.NewReader(data))
	ev, err := UnmarshalEventFrom(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.ReadToken(); !errors.Is(err, io.EOF) {
		return nil, domi18n.EF(ErrInvalidEvent, domi18n.KeyCommonJSONTrailingData)
	}
	return ev, nil
}

// MarshalEventTo 以无条件 Deterministic(true) 规范模式将任意有效 Event 编码至既有 jsontext.Encoder 流。
func MarshalEventTo(enc *jsontext.Encoder, ev Event) error {
	if enc == nil {
		return ErrNilWriter
	}
	if ev == nil || !ev.IsValid() {
		return ErrInvalidEvent
	}
	wire, err := encodeEventWire(ev)
	if err != nil {
		return err
	}
	return jsonv2.MarshalEncode(enc, wire, jsonv2.Deterministic(true))
}

// UnmarshalEventFrom 从 jsontext.Decoder 严格读取并解码一条多态 Event。
func UnmarshalEventFrom(dec *jsontext.Decoder) (Event, error) {
	if dec == nil {
		return nil, ErrNilReceiver
	}
	if isNull, err := rejectJSONNull(dec, ErrInvalidEvent); isNull {
		return nil, err
	}
	raw, err := dec.ReadValue()
	if err != nil {
		return nil, err
	}
	kind, err := peekEventKind(raw)
	if err != nil {
		return nil, err
	}
	return decodeEventByKind(kind, raw)
}

func encodeEventWire(ev Event) (any, error) {
	switch v := ev.(type) {
	case *OperationStartedEvent:
		return opStartedWire{algebraic.Some(EventKindOperationStarted), algebraic.Some(v.meta), algebraic.Some(v.capability), algebraic.Some(v.tool), algebraic.Some(v.action), v.planDigest, v.sum}, nil
	case *OperationCompletedEvent:
		return opCompletedWire{algebraic.Some(EventKindOperationCompleted), algebraic.Some(v.meta), algebraic.Some(v.capability), algebraic.Some(v.duration), optOutcomeToBox(v.outcome), algebraic.Some(v.succeeded), v.code, v.message}, nil
	case *OutputChunkEvent:
		dataOpt := pickIf(len(v.data) > 0, algebraic.Some(v.data), algebraic.None[[]byte]())
		return outputChunkWire{algebraic.Some(EventKindOutputChunk), algebraic.Some(v.meta), algebraic.Some(v.stream), algebraic.Some(v.chunkIndex), dataOpt, v.truncated}, nil
	case *StepEvent:
		return stepEventWire{algebraic.Some(EventKindStep), algebraic.Some(v.meta), v.playbookID, algebraic.Some(v.stepID), algebraic.Some(v.status), algebraic.Some(v.duration), optOutcomeToBox(v.outcome), v.message}, nil
	case *FSMTransitionEvent:
		return fsmTransitionWire{algebraic.Some(EventKindFSMTransition), algebraic.Some(v.meta), algebraic.Some(v.machine), algebraic.Some(v.fromState), algebraic.Some(v.toState), algebraic.Some(v.eventName), v.detail, v.terminal}, nil
	case *ApprovalChallengeEvent:
		return approvalChallengeWire{algebraic.Some(EventKindApprovalChallenge), algebraic.Some(v.meta), algebraic.Some(v.envelope), algebraic.Some(v.phase), v.escalated, v.reason}, nil
	case *TransferProgressEvent:
		return transferProgressWire{algebraic.Some(EventKindTransferProgress), algebraic.Some(v.meta), algebraic.Some(v.transferID), algebraic.Some(v.direction), algebraic.Some(v.bytesTransferred), v.totalBytes, v.chunksCompleted, algebraic.Some(v.elapsed), v.rateBytesPerSec, v.stage}, nil
	case *MetricSampleEvent:
		return metricSampleWire{algebraic.Some(EventKindMetricSample), algebraic.Some(v.meta), algebraic.Some(v.metricName), v.unit, algebraic.Some(v.value), algebraic.Some(v.interval), v.labels}, nil
	case *AuditRecordEvent:
		return auditRecordWire{algebraic.Some(EventKindAuditRecord), algebraic.Some(v.meta), algebraic.Some(v.stage), algebraic.Some(v.processInstanceID), algebraic.Some(v.capability), algebraic.Some(decisionJSONBox{v.decision}), algebraic.Some(v.risk), v.binding, optOutcomeToBox(v.outcome), algebraic.Some(v.duration), v.reason}, nil
	case *PoolStateEvent:
		return poolStateWire{algebraic.Some(EventKindPoolState), algebraic.Some(v.meta), algebraic.Some(v.action), v.planDigest, v.hopDigest, v.endpoint, v.handleKind, v.handleID, v.generation, v.activeLeases, algebraic.Some(v.latency), v.detail}, nil
	case *DiagnosticEvent:
		return diagnosticWire{algebraic.Some(EventKindDiagnostic), algebraic.Some(v.meta), algebraic.Some(v.scope), algebraic.Some(v.severity), v.code, algebraic.Some(v.message), v.attrs}, nil
	case *BusDroppedEvent:
		return busDroppedWire{algebraic.Some(EventKindBusDropped), algebraic.Some(v.meta), algebraic.Some(v.scope), algebraic.Some(v.droppedTotal), algebraic.Some(v.droppedDelta), v.reason}, nil
	default:
		return nil, ErrInvalidEvent
	}
}

// peekEventKind 在单次顶层扫描中提取并严格校验唯一字符串判别字段 "kind"，拒绝非对象与重复 kind 键。
func peekEventKind(raw jsontext.Value) (EventKind, error) {
	if raw.Kind() != '{' {
		return EventKindInvalid, domi18n.EF(ErrInvalidEvent, domi18n.KeyEventsJSONObjectRequired)
	}
	dec := jsontext.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.ReadToken(); err != nil || tok.Kind() != '{' {
		return EventKindInvalid, domi18n.EF(ErrInvalidEvent, domi18n.KeyEventsJSONObjectRequired)
	}
	return scanKindField(dec)
}

func scanKindField(dec *jsontext.Decoder) (EventKind, error) {
	var kind EventKind
	found := false
	for dec.PeekKind() != '}' {
		keyTok, err := dec.ReadToken()
		if err != nil || keyTok.Kind() != '"' {
			return EventKindInvalid, fieldErr(ErrInvalidEvent, "json_key")
		}
		if keyTok.String() != "kind" {
			if err := dec.SkipValue(); err != nil {
				return EventKindInvalid, err
			}
			continue
		}
		parsed, err := readUniqueKindToken(dec, found)
		if err != nil {
			return EventKindInvalid, err
		}
		kind, found = parsed, true
	}
	if !found {
		return EventKindInvalid, missingFieldErr(ErrInvalidEventKind, "kind")
	}
	return kind, nil
}

func readUniqueKindToken(dec *jsontext.Decoder, alreadyFound bool) (EventKind, error) {
	if alreadyFound {
		return EventKindInvalid, domi18n.EF(ErrInvalidEvent, domi18n.KeyCommonDuplicateItem, domi18n.Str("kind", "field"), domi18n.Str("value", "kind"))
	}
	valTok, err := dec.ReadToken()
	if err != nil || valTok.Kind() != '"' {
		return EventKindInvalid, fieldErr(ErrInvalidEventKind, "kind")
	}
	return ParseEventKind(valTok.String())
}

func decodeEventByKind(kind EventKind, raw jsontext.Value) (Event, error) {
	switch kind {
	case EventKindOperationStarted:
		return decodeStrictWire(raw, decodeOpStartedWire)
	case EventKindOperationCompleted:
		return decodeStrictWire(raw, decodeOpCompletedWire)
	case EventKindOutputChunk:
		return decodeStrictWire(raw, decodeOutputChunkWire)
	case EventKindStep:
		return decodeStrictWire(raw, decodeStepWire)
	case EventKindFSMTransition:
		return decodeStrictWire(raw, decodeFSMTransitionWire)
	case EventKindApprovalChallenge:
		return decodeStrictWire(raw, decodeApprovalChallengeWire)
	case EventKindTransferProgress:
		return decodeStrictWire(raw, decodeTransferProgressWire)
	case EventKindMetricSample:
		return decodeStrictWire(raw, decodeMetricSampleWire)
	case EventKindAuditRecord:
		return decodeStrictWire(raw, decodeAuditRecordWire)
	case EventKindPoolState:
		return decodeStrictWire(raw, decodePoolStateWire)
	case EventKindDiagnostic:
		return decodeStrictWire(raw, decodeDiagnosticWire)
	case EventKindBusDropped:
		return decodeStrictWire(raw, decodeBusDroppedWire)
	default:
		return nil, domi18n.EF(ErrInvalidEventKind, domi18n.KeyCommonUnknownValue, domi18n.Str("kind", "event_kind"), domi18n.Uint64("value", uint64(kind)))
	}
}

func decodeStrictWire[W any, E Event](raw jsontext.Value, build func(W) (E, error)) (Event, error) {
	var w W
	if err := jsonv2.Unmarshal(raw, &w, jsonv2.RejectUnknownMembers(true)); err != nil {
		return nil, err
	}
	return build(w)
}

func optVal[T any](o algebraic.Option[T]) T {
	v, _ := o.Get()
	return v
}

func decodeOpStartedWire(w opStartedWire) (*OperationStartedEvent, error) {
	return NewOperationStartedEvent(OperationStartedSpec{optVal(w.Meta), optVal(w.Capability), optVal(w.Tool), optVal(w.Action), w.PlanDigest, w.Summary})
}
func decodeOpCompletedWire(w opCompletedWire) (*OperationCompletedEvent, error) {
	if w.Duration.IsNone() || w.Succeeded.IsNone() {
		return nil, missingFieldErr(ErrInvalidEvent, "duration/succeeded")
	}
	return NewOperationCompletedEvent(OperationCompletedSpec{optVal(w.Meta), optVal(w.Capability), optVal(w.Duration), optOutcomeFromBox(w.Outcome), optVal(w.Succeeded), w.Code, w.Message})
}
func decodeOutputChunkWire(w outputChunkWire) (*OutputChunkEvent, error) {
	if w.ChunkIndex.IsNone() {
		return nil, missingFieldErr(ErrInvalidEvent, "chunk_index")
	}
	return NewOutputChunkEvent(OutputChunkSpec{optVal(w.Meta), optVal(w.Stream), optVal(w.ChunkIndex), optVal(w.Data), w.Truncated})
}
func decodeStepWire(w stepEventWire) (*StepEvent, error) {
	if w.Duration.IsNone() {
		return nil, missingFieldErr(ErrInvalidEvent, "duration")
	}
	return NewStepEvent(StepEventSpec{optVal(w.Meta), w.PlaybookID, optVal(w.StepID), optVal(w.Status), optVal(w.Duration), optOutcomeFromBox(w.Outcome), w.Message})
}
func decodeFSMTransitionWire(w fsmTransitionWire) (*FSMTransitionEvent, error) {
	return NewFSMTransitionEvent(FSMTransitionSpec{optVal(w.Meta), optVal(w.Machine), optVal(w.FromState), optVal(w.ToState), optVal(w.EventName), w.Detail, w.Terminal})
}
func decodeApprovalChallengeWire(w approvalChallengeWire) (*ApprovalChallengeEvent, error) {
	return NewApprovalChallengeEvent(ApprovalChallengeSpec{optVal(w.Meta), optVal(w.Envelope), optVal(w.Phase), w.Escalated, w.Reason})
}
func decodeTransferProgressWire(w transferProgressWire) (*TransferProgressEvent, error) {
	if w.BytesTransferred.IsNone() || w.Elapsed.IsNone() {
		return nil, missingFieldErr(ErrInvalidEvent, "bytes_transferred/elapsed")
	}
	return NewTransferProgressEvent(TransferProgressSpec{optVal(w.Meta), optVal(w.TransferID), optVal(w.Direction), optVal(w.BytesTransferred), w.TotalBytes, w.ChunksCompleted, optVal(w.Elapsed), w.RateBytesPerSec, w.Stage})
}
func decodeMetricSampleWire(w metricSampleWire) (*MetricSampleEvent, error) {
	if w.Value.IsNone() || w.Interval.IsNone() {
		return nil, missingFieldErr(ErrInvalidEvent, "value/interval")
	}
	return NewMetricSampleEvent(MetricSampleSpec{optVal(w.Meta), optVal(w.MetricName), w.Unit, optVal(w.Value), optVal(w.Interval), w.Labels})
}
func decodeAuditRecordWire(w auditRecordWire) (*AuditRecordEvent, error) {
	if w.Duration.IsNone() {
		return nil, missingFieldErr(ErrInvalidEvent, "duration")
	}
	return NewAuditRecordEvent(AuditRecordSpec{optVal(w.Meta), optVal(w.Stage), optVal(w.ProcessInstanceID), optVal(w.Capability), optVal(w.Decision).value, optVal(w.Risk), w.Binding, optOutcomeFromBox(w.Outcome), optVal(w.Duration), w.Reason})
}
func decodePoolStateWire(w poolStateWire) (*PoolStateEvent, error) {
	if w.Latency.IsNone() {
		return nil, missingFieldErr(ErrInvalidEvent, "latency")
	}
	return NewPoolStateEvent(PoolStateSpec{optVal(w.Meta), optVal(w.Action), w.PlanDigest, w.HopDigest, w.Endpoint, w.HandleKind, w.HandleID, w.Generation, w.ActiveLeases, optVal(w.Latency), w.Detail})
}
func decodeDiagnosticWire(w diagnosticWire) (*DiagnosticEvent, error) {
	return NewDiagnosticEvent(DiagnosticSpec{optVal(w.Meta), optVal(w.Scope), optVal(w.Severity), w.Code, optVal(w.Message), w.Attrs})
}
func decodeBusDroppedWire(w busDroppedWire) (*BusDroppedEvent, error) {
	return NewBusDroppedEvent(BusDroppedSpec{optVal(w.Meta), optVal(w.Scope), optVal(w.DroppedTotal), optVal(w.DroppedDelta), w.Reason})
}

func uEv[T any, P interface {
	*T
	Event
}](dst P, dec *jsontext.Decoder, want EventKind) error {
	if dst == nil || dec == nil {
		return ErrNilReceiver
	}
	*dst = zeroVal[T]()
	ev, err := UnmarshalEventFrom(dec)
	if err != nil {
		return err
	}
	if ev.Kind() != want {
		return domi18n.EF(ErrInvalidEventKind, domi18n.KeyCommonMismatch, domi18n.Str("field", "kind"), domi18n.Str("expected", want.String()), domi18n.Str("actual", ev.Kind().String()))
	}
	typed, ok := ev.(P)
	if !ok || typed == nil {
		return ErrInvalidEvent
	}
	*dst = *typed
	return nil
}

func mEv(enc *jsontext.Encoder, ev Event) error { return MarshalEventTo(enc, ev) }

// 为全部 12 个具体事件变体提供值接收者 MarshalJSONTo 与严格变体匹配的指针接收者 UnmarshalJSONFrom。
func (e OperationStartedEvent) MarshalJSONTo(enc *jsontext.Encoder) error { return mEv(enc, &e) }
func (e *OperationStartedEvent) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	return uEv(e, d, EventKindOperationStarted)
}
func (e OperationCompletedEvent) MarshalJSONTo(enc *jsontext.Encoder) error { return mEv(enc, &e) }
func (e *OperationCompletedEvent) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	return uEv(e, d, EventKindOperationCompleted)
}
func (e OutputChunkEvent) MarshalJSONTo(enc *jsontext.Encoder) error { return mEv(enc, &e) }
func (e *OutputChunkEvent) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	return uEv(e, d, EventKindOutputChunk)
}
func (e StepEvent) MarshalJSONTo(enc *jsontext.Encoder) error          { return mEv(enc, &e) }
func (e *StepEvent) UnmarshalJSONFrom(d *jsontext.Decoder) error       { return uEv(e, d, EventKindStep) }
func (e FSMTransitionEvent) MarshalJSONTo(enc *jsontext.Encoder) error { return mEv(enc, &e) }
func (e *FSMTransitionEvent) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	return uEv(e, d, EventKindFSMTransition)
}
func (e ApprovalChallengeEvent) MarshalJSONTo(enc *jsontext.Encoder) error { return mEv(enc, &e) }
func (e *ApprovalChallengeEvent) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	return uEv(e, d, EventKindApprovalChallenge)
}
func (e TransferProgressEvent) MarshalJSONTo(enc *jsontext.Encoder) error { return mEv(enc, &e) }
func (e *TransferProgressEvent) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	return uEv(e, d, EventKindTransferProgress)
}
func (e MetricSampleEvent) MarshalJSONTo(enc *jsontext.Encoder) error { return mEv(enc, &e) }
func (e *MetricSampleEvent) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	return uEv(e, d, EventKindMetricSample)
}
func (e AuditRecordEvent) MarshalJSONTo(enc *jsontext.Encoder) error { return mEv(enc, &e) }
func (e *AuditRecordEvent) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	return uEv(e, d, EventKindAuditRecord)
}
func (e PoolStateEvent) MarshalJSONTo(enc *jsontext.Encoder) error { return mEv(enc, &e) }
func (e *PoolStateEvent) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	return uEv(e, d, EventKindPoolState)
}
func (e DiagnosticEvent) MarshalJSONTo(enc *jsontext.Encoder) error { return mEv(enc, &e) }
func (e *DiagnosticEvent) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	return uEv(e, d, EventKindDiagnostic)
}
func (e BusDroppedEvent) MarshalJSONTo(enc *jsontext.Encoder) error { return mEv(enc, &e) }
func (e *BusDroppedEvent) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	return uEv(e, d, EventKindBusDropped)
}
