package events

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/security"
)

// 全包 9 个失败关闭事件枚举的单一事实源名称表（索引 0 为无效零值，1..N 为规范小写文本）。
const (
	nmEventKind = "invalid,operation_started,operation_completed,output_chunk,step,fsm_transition,approval_challenge,transfer_progress,metric_sample,audit_record,pool_state,diagnostic,bus_dropped"
	nmEventCls  = "invalid,audit,operation,progress,system"
	nmBackpress = "invalid,fail_closed,block_with_context,coalesce_latest,drop_and_count"
	nmSeverity  = "invalid,debug,info,warn,error"
	nmOutStream = "invalid,stdout,stderr,system"
	nmAuditStg  = "invalid,authorized,denied,need_approval,finalized,aborted_by_crash,halted"
	nmPoolAct   = "invalid,dial_started,dial_succeeded,dial_failed,lease_acquired,lease_released,evicted,retired,gate_halted,mux_handover"
	nmDiagScope = "invalid,pool,gate,transport,mux,sftp,transfer,mcp,runtime"
	nmFSMMach   = "invalid,vault_saga,approval,transfer,ensure,pending_enroll"
)

// EventKind..FSMMachineKind 为事件流系统的 9 个失败关闭枚举类型，零值恒为 *Invalid。
type (
	//xops:opaque
	//xops:failclosed
	EventKind uint8
	//xops:opaque
	//xops:failclosed
	EventClass uint8
	//xops:opaque
	//xops:failclosed
	BackpressurePolicy uint8
	//xops:opaque
	//xops:failclosed
	Severity uint8
	//xops:opaque
	//xops:failclosed
	OutputStreamKind uint8
	//xops:opaque
	//xops:failclosed
	AuditStage uint8
	//xops:opaque
	//xops:failclosed
	PoolEventAction uint8
	//xops:opaque
	//xops:failclosed
	DiagnosticScope uint8
	//xops:opaque
	//xops:failclosed
	FSMMachineKind uint8
)

// EventKind 常量：标识封闭事件和类型 Event 的 12 个具体变体。
const (
	EventKindInvalid EventKind = iota
	EventKindOperationStarted
	EventKindOperationCompleted
	EventKindOutputChunk
	EventKindStep
	EventKindFSMTransition
	EventKindApprovalChallenge
	EventKindTransferProgress
	EventKindMetricSample
	EventKindAuditRecord
	EventKindPoolState
	EventKindDiagnostic
	EventKindBusDropped
)

// EventClass 与 BackpressurePolicy 常量：刻画 ADR-010 作用域双层事件流的事件分类与差异化背压策略。
const (
	EventClassInvalid EventClass = iota
	EventClassAudit
	EventClassOperation
	EventClassProgress
	EventClassSystem
	BackpressureInvalid          BackpressurePolicy = 0
	BackpressureFailClosed       BackpressurePolicy = 1
	BackpressureBlockWithContext BackpressurePolicy = 2
	BackpressureCoalesceLatest   BackpressurePolicy = 3
	BackpressureDropAndCount     BackpressurePolicy = 4
)

// Severity、OutputStreamKind、AuditStage、PoolEventAction、DiagnosticScope 与 FSMMachineKind 枚举常量。
const (
	SeverityInvalid          Severity         = 0
	SeverityDebug            Severity         = 1
	SeverityInfo             Severity         = 2
	SeverityWarn             Severity         = 3
	SeverityError            Severity         = 4
	OutputStreamInvalid      OutputStreamKind = 0
	OutputStreamStdout       OutputStreamKind = 1
	OutputStreamStderr       OutputStreamKind = 2
	OutputStreamSystem       OutputStreamKind = 3
	AuditStageInvalid        AuditStage       = 0
	AuditStageAuthorized     AuditStage       = 1
	AuditStageDenied         AuditStage       = 2
	AuditStageNeedApproval   AuditStage       = 3
	AuditStageFinalized      AuditStage       = 4
	AuditStageAbortedByCrash AuditStage       = 5
	AuditStageHalted         AuditStage       = 6
	PoolActionInvalid        PoolEventAction  = 0
	PoolActionDialStarted    PoolEventAction  = 1
	PoolActionDialSucceeded  PoolEventAction  = 2
	PoolActionDialFailed     PoolEventAction  = 3
	PoolActionLeaseAcquired  PoolEventAction  = 4
	PoolActionLeaseReleased  PoolEventAction  = 5
	PoolActionEvicted        PoolEventAction  = 6
	PoolActionRetired        PoolEventAction  = 7
	PoolActionGateHalted     PoolEventAction  = 8
	PoolActionMuxHandover    PoolEventAction  = 9
	DiagnosticScopeInvalid   DiagnosticScope  = 0
	DiagnosticScopePool      DiagnosticScope  = 1
	DiagnosticScopeGate      DiagnosticScope  = 2
	DiagnosticScopeTransport DiagnosticScope  = 3
	DiagnosticScopeMux       DiagnosticScope  = 4
	DiagnosticScopeSFTP      DiagnosticScope  = 5
	DiagnosticScopeTransfer  DiagnosticScope  = 6
	DiagnosticScopeMCP       DiagnosticScope  = 7
	DiagnosticScopeRuntime   DiagnosticScope  = 8
	FSMMachineInvalid        FSMMachineKind   = 0
	FSMMachineVaultSaga      FSMMachineKind   = 1
	FSMMachineApproval       FSMMachineKind   = 2
	FSMMachineTransfer       FSMMachineKind   = 3
	FSMMachineEnsure         FSMMachineKind   = 4
	FSMMachinePendingEnroll  FSMMachineKind   = 5
)

// DefaultBackpressure 返回事件类别对应的默认背压策略；无效类别失败关闭返回 BackpressureInvalid。
func (c EventClass) DefaultBackpressure() BackpressurePolicy {
	switch c {
	case EventClassAudit:
		return BackpressureFailClosed
	case EventClassOperation:
		return BackpressureBlockWithContext
	case EventClassProgress:
		return BackpressureCoalesceLatest
	case EventClassSystem:
		return BackpressureDropAndCount
	default:
		return BackpressureInvalid
	}
}

type eventEnum interface {
	~uint8
	IsValid() bool
	String() string
}

func eOk(idx uint8, csv string) bool { return idx >= 1 && int(idx) <= strings.Count(csv, ",") }
func eStr(idx uint8, csv string) string {
	parts := strings.Split(csv, ",")
	if int(idx) < len(parts) {
		return parts[idx]
	}
	return parts[0]
}
func eP[T eventEnum](raw string, _ T, err error) (T, error) {
	for v := T(1); raw != "" && v < 255 && v.IsValid(); v++ {
		if v.String() == raw {
			return v, nil
		}
	}
	return 0, domi18n.EF(err, domi18n.KeyCommonValueInvalid, domi18n.BoundStr("value", raw))
}
func eA[T eventEnum](b []byte, v T, err error) ([]byte, error) {
	if !v.IsValid() {
		return nil, domi18n.EF(err, domi18n.KeyCommonValueInvalid, domi18n.Uint64("value", uint64(v)))
	}
	return append(b, v.String()...), nil
}
func eU[T eventEnum](dst *T, text []byte, baseErr error) error {
	if dst == nil {
		return ErrNilReceiver
	}
	parsed, err := eP(string(text), *dst, baseErr)
	*dst = parsed
	return err
}

// 全包 9 个失败关闭枚举的 IsValid / IsZero / String / Parse* / TextCodec 统一实现。
func (k EventKind) IsValid() bool                        { return eOk(uint8(k), nmEventKind) }
func (k EventKind) IsZero() bool                         { return k == EventKindInvalid }
func (k EventKind) String() string                       { return eStr(uint8(k), nmEventKind) }
func ParseEventKind(s string) (v EventKind, e error)     { return eP(s, v, ErrInvalidEventKind) }
func (k EventKind) AppendText(b []byte) ([]byte, error)  { return eA(b, k, ErrInvalidEventKind) }
func (k EventKind) MarshalText() ([]byte, error)         { return k.AppendText(nil) }
func (k *EventKind) UnmarshalText(t []byte) error        { return eU(k, t, ErrInvalidEventKind) }
func (c EventClass) IsValid() bool                       { return eOk(uint8(c), nmEventCls) }
func (c EventClass) IsZero() bool                        { return c == EventClassInvalid }
func (c EventClass) String() string                      { return eStr(uint8(c), nmEventCls) }
func ParseEventClass(s string) (v EventClass, e error)   { return eP(s, v, ErrInvalidEventClass) }
func (c EventClass) AppendText(b []byte) ([]byte, error) { return eA(b, c, ErrInvalidEventClass) }
func (c EventClass) MarshalText() ([]byte, error)        { return c.AppendText(nil) }
func (c *EventClass) UnmarshalText(t []byte) error       { return eU(c, t, ErrInvalidEventClass) }
func (p BackpressurePolicy) IsValid() bool               { return eOk(uint8(p), nmBackpress) }
func (p BackpressurePolicy) IsZero() bool                { return p == BackpressureInvalid }
func (p BackpressurePolicy) String() string              { return eStr(uint8(p), nmBackpress) }
func ParseBackpressurePolicy(s string) (v BackpressurePolicy, e error) {
	return eP(s, v, ErrInvalidBackpressure)
}
func (p BackpressurePolicy) AppendText(b []byte) ([]byte, error) {
	return eA(b, p, ErrInvalidBackpressure)
}
func (p BackpressurePolicy) MarshalText() ([]byte, error)  { return p.AppendText(nil) }
func (p *BackpressurePolicy) UnmarshalText(t []byte) error { return eU(p, t, ErrInvalidBackpressure) }
func (s Severity) IsValid() bool                           { return eOk(uint8(s), nmSeverity) }
func (s Severity) IsZero() bool                            { return s == SeverityInvalid }
func (s Severity) String() string                          { return eStr(uint8(s), nmSeverity) }
func ParseSeverity(s string) (v Severity, e error)         { return eP(s, v, ErrInvalidSeverity) }
func (s Severity) AppendText(b []byte) ([]byte, error)     { return eA(b, s, ErrInvalidSeverity) }
func (s Severity) MarshalText() ([]byte, error)            { return s.AppendText(nil) }
func (s *Severity) UnmarshalText(t []byte) error           { return eU(s, t, ErrInvalidSeverity) }
func (o OutputStreamKind) IsValid() bool                   { return eOk(uint8(o), nmOutStream) }
func (o OutputStreamKind) IsZero() bool                    { return o == OutputStreamInvalid }
func (o OutputStreamKind) String() string                  { return eStr(uint8(o), nmOutStream) }
func ParseOutputStreamKind(s string) (v OutputStreamKind, e error) {
	return eP(s, v, ErrInvalidOutputStream)
}
func (o OutputStreamKind) AppendText(b []byte) ([]byte, error) {
	return eA(b, o, ErrInvalidOutputStream)
}
func (o OutputStreamKind) MarshalText() ([]byte, error)  { return o.AppendText(nil) }
func (o *OutputStreamKind) UnmarshalText(t []byte) error { return eU(o, t, ErrInvalidOutputStream) }
func (s AuditStage) IsValid() bool                       { return eOk(uint8(s), nmAuditStg) }
func (s AuditStage) IsZero() bool                        { return s == AuditStageInvalid }
func (s AuditStage) String() string                      { return eStr(uint8(s), nmAuditStg) }
func ParseAuditStage(s string) (v AuditStage, e error)   { return eP(s, v, ErrInvalidAuditStage) }
func (s AuditStage) AppendText(b []byte) ([]byte, error) { return eA(b, s, ErrInvalidAuditStage) }
func (s AuditStage) MarshalText() ([]byte, error)        { return s.AppendText(nil) }
func (s *AuditStage) UnmarshalText(t []byte) error       { return eU(s, t, ErrInvalidAuditStage) }
func (a PoolEventAction) IsValid() bool                  { return eOk(uint8(a), nmPoolAct) }
func (a PoolEventAction) IsZero() bool                   { return a == PoolActionInvalid }
func (a PoolEventAction) String() string                 { return eStr(uint8(a), nmPoolAct) }
func ParsePoolEventAction(s string) (v PoolEventAction, e error) {
	return eP(s, v, ErrInvalidPoolAction)
}
func (a PoolEventAction) AppendText(b []byte) ([]byte, error) { return eA(b, a, ErrInvalidPoolAction) }
func (a PoolEventAction) MarshalText() ([]byte, error)        { return a.AppendText(nil) }
func (a *PoolEventAction) UnmarshalText(t []byte) error       { return eU(a, t, ErrInvalidPoolAction) }
func (d DiagnosticScope) IsValid() bool                       { return eOk(uint8(d), nmDiagScope) }
func (d DiagnosticScope) IsZero() bool                        { return d == DiagnosticScopeInvalid }
func (d DiagnosticScope) String() string                      { return eStr(uint8(d), nmDiagScope) }
func ParseDiagnosticScope(s string) (v DiagnosticScope, e error) {
	return eP(s, v, ErrInvalidDiagnosticScope)
}
func (d DiagnosticScope) AppendText(b []byte) ([]byte, error) {
	return eA(b, d, ErrInvalidDiagnosticScope)
}
func (d DiagnosticScope) MarshalText() ([]byte, error)         { return d.AppendText(nil) }
func (d *DiagnosticScope) UnmarshalText(t []byte) error        { return eU(d, t, ErrInvalidDiagnosticScope) }
func (m FSMMachineKind) IsValid() bool                         { return eOk(uint8(m), nmFSMMach) }
func (m FSMMachineKind) IsZero() bool                          { return m == FSMMachineInvalid }
func (m FSMMachineKind) String() string                        { return eStr(uint8(m), nmFSMMach) }
func ParseFSMMachineKind(s string) (v FSMMachineKind, e error) { return eP(s, v, ErrInvalidFSMMachine) }
func (m FSMMachineKind) AppendText(b []byte) ([]byte, error)   { return eA(b, m, ErrInvalidFSMMachine) }
func (m FSMMachineKind) MarshalText() ([]byte, error)          { return m.AppendText(nil) }
func (m *FSMMachineKind) UnmarshalText(t []byte) error         { return eU(m, t, ErrInvalidFSMMachine) }

// EventMetaSpec 与 EventMeta 承载所有事件变体共享的不可变链路追踪、UTC 时间戳与可选节点标识元数据；零值恒无效。
type EventMetaSpec struct {
	TraceID     security.TraceID
	OperationID algebraic.Option[security.OperationID]
	OccurredAt  time.Time
	Seq         uint64
	NodeID      algebraic.Option[inventory.NodeID]
}

//xops:opaque
//xops:failclosed
type EventMeta struct {
	traceID    security.TraceID
	opID       algebraic.Option[security.OperationID]
	occurredAt time.Time
	seq        uint64
	nodeID     algebraic.Option[inventory.NodeID]
	valid      bool
}

func isValidEventTime(t time.Time) bool {
	if t.IsZero() {
		return false
	}
	y := t.UTC().Year()
	return y >= 1 && y <= 9999
}

// NewEventMeta 校验 TraceID、RFC 3339 年份范围 [1, 9999] 时间戳以及可选 OperationID/NodeID，
// 并将时间归一化为去除单调时钟读数的 UTC 时间戳，构造不可变 EventMeta。
func NewEventMeta(spec EventMetaSpec) (EventMeta, error) {
	opID, hasOp := spec.OperationID.Get()
	nodeID, hasNode := spec.NodeID.Get()
	utc := spec.OccurredAt.UTC().Round(0)
	if !spec.TraceID.IsValid() || !isValidEventTime(utc) || (hasOp && !opID.IsValid()) || (hasNode && !nodeID.IsValid()) {
		return EventMeta{}, fieldErr(ErrInvalidEventMeta, "event_meta")
	}
	return EventMeta{spec.TraceID, spec.OperationID, utc, spec.Seq, spec.NodeID, true}, nil
}

func (m EventMeta) IsValid() bool {
	opID, hasOp := m.opID.Get()
	nodeID, hasNode := m.nodeID.Get()
	return m.valid && m.traceID.IsValid() && isValidEventTime(m.occurredAt) && (!hasOp || opID.IsValid()) && (!hasNode || nodeID.IsValid())
}
func (m EventMeta) IsZero() bool { return !m.IsValid() }
func (m EventMeta) TraceID() security.TraceID {
	return pickIf(m.IsValid(), m.traceID, zeroVal[security.TraceID]())
}
func (m EventMeta) OperationID() algebraic.Option[security.OperationID] {
	return pickIf(m.IsValid(), m.opID, algebraic.None[security.OperationID]())
}
func (m EventMeta) OccurredAt() time.Time { return pickIf(m.IsValid(), m.occurredAt, time.Time{}) }
func (m EventMeta) Seq() uint64           { return pickIf(m.IsValid(), m.seq, 0) }
func (m EventMeta) NodeID() algebraic.Option[inventory.NodeID] {
	return pickIf(m.IsValid(), m.nodeID, algebraic.None[inventory.NodeID]())
}
func (m EventMeta) WithSeq(seq uint64) EventMeta {
	if !m.IsValid() {
		return EventMeta{}
	}
	m.seq = seq
	return m
}
func (m EventMeta) Equal(other EventMeta) bool {
	return m.IsValid() && other.IsValid() && m.traceID.Equal(other.traceID) &&
		equalOptComparable(m.opID, other.opID) && m.occurredAt.Equal(other.occurredAt) &&
		m.seq == other.seq && equalOptComparable(m.nodeID, other.nodeID)
}

type eventMetaWire struct {
	TraceID     algebraic.Option[security.TraceID]     `json:"trace_id"`
	OperationID algebraic.Option[security.OperationID] `json:"operation_id,omitzero"`
	OccurredAt  algebraic.Option[time.Time]            `json:"occurred_at"`
	Seq         uint64                                 `json:"seq,omitzero"`
	NodeID      algebraic.Option[inventory.NodeID]     `json:"node_id,omitzero"`
}

// MarshalJSONTo 与 UnmarshalJSONFrom 实现 EventMeta 的 Go 1.27 encoding/json/v2 严格失败关闭编解码。
func (m EventMeta) MarshalJSONTo(enc *jsontext.Encoder) error {
	if enc == nil {
		return ErrNilWriter
	}
	if !m.IsValid() {
		return ErrInvalidEventMeta
	}
	return jsonv2.MarshalEncode(enc, eventMetaWire{algebraic.Some(m.traceID), m.opID, algebraic.Some(m.occurredAt.UTC()), m.seq, m.nodeID})
}
func (m *EventMeta) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(m, dec, ErrInvalidEventMeta, func(w eventMetaWire) (EventMeta, error) {
		if w.TraceID.IsNone() || w.OccurredAt.IsNone() {
			return EventMeta{}, missingFieldErr(ErrInvalidEventMeta, "trace_id/occurred_at")
		}
		return NewEventMeta(EventMetaSpec{optVal(w.TraceID), w.OperationID, optVal(w.OccurredAt), w.Seq, w.NodeID})
	})
}
