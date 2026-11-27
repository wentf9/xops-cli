package ports

import (
	"cmp"
	"context"
	"encoding/hex"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
)

const processInstanceEntropyBytes, maxProcessInstanceIDLen, maxAuditErrorCodeLen = 16, 64, 64

// ProcessInstanceID 唯一标识单个运行期 Engine 实例，映射 ~/.xops/run/<ProcessInstanceID>.lock（ADR-008）。
//
//xops:opaque
//xops:failclosed
type ProcessInstanceID struct{ value string }

// NewProcessInstanceIDFrom 从显式熵源读取 16 字节非全零随机数据并生成 32 位小写十六进制 ProcessInstanceID。
func NewProcessInstanceIDFrom(entropy io.Reader) (ProcessInstanceID, error) {
	if entropy == nil {
		return ProcessInstanceID{}, domi18n.EF(ErrInvalidProcessInstanceID, domi18n.KeyCommonFieldNil, domi18n.Str("field", "entropy"))
	}
	var raw [processInstanceEntropyBytes]byte
	if _, err := io.ReadFull(entropy, raw[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			err = domi18n.WrapSentinel(ErrEntropyShortRead, err)
		}
		return ProcessInstanceID{}, domi18n.WrapSentinel(ErrInvalidProcessInstanceID, err)
	}
	if raw == ([processInstanceEntropyBytes]byte{}) {
		return ProcessInstanceID{}, domi18n.EF(ErrInvalidProcessInstanceID, domi18n.KeyCommonZeroEntropy)
	}
	return ProcessInstanceID{value: hex.EncodeToString(raw[:])}, nil
}

// ParseProcessInstanceID 校验并构造 ProcessInstanceID（1..64 位安全 ASCII 标识符，满足跨平台单文件名规则）。
func ParseProcessInstanceID(raw string) (ProcessInstanceID, error) {
	if len(raw) == 0 || len(raw) > maxProcessInstanceIDLen || !isSafeProcessIDChars(raw) {
		return ProcessInstanceID{}, domi18n.EF(ErrInvalidProcessInstanceID, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "process_instance_id"), domi18n.BoundStr("value", raw))
	}
	if err := pathalg.ValidateLocalComponent(raw + ".lock"); err != nil {
		return ProcessInstanceID{}, domi18n.WrapSentinel(ErrInvalidProcessInstanceID, err)
	}
	return ProcessInstanceID{value: raw}, nil
}
func isSafeProcessIDChars(s string) bool {
	return len(s) > 0 && s[0] != '-' && s[0] != '.' && s[len(s)-1] != '.' && !strings.ContainsFunc(s, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' && r != '-' && r != '.'
	})
}
func (id ProcessInstanceID) IsValid() bool  { return id.value != "" }
func (id ProcessInstanceID) IsZero() bool   { return id.value == "" }
func (id ProcessInstanceID) String() string { return id.value }
func (id ProcessInstanceID) Equal(o ProcessInstanceID) bool {
	return id.IsValid() && o.IsValid() && id.value == o.value
}
func (id ProcessInstanceID) Compare(o ProcessInstanceID) int { return cmp.Compare(id.value, o.value) }
func (id ProcessInstanceID) LockFileName() (pathalg.LocalRootedDest, error) {
	if !id.IsValid() {
		return zeroVal[pathalg.LocalRootedDest](), ErrInvalidProcessInstanceID
	}
	return pathalg.ParseLocalRootedDest(id.value + ".lock")
}
func (id ProcessInstanceID) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, id.IsValid(), id.value, ErrInvalidProcessInstanceID)
}
func (id ProcessInstanceID) MarshalText() ([]byte, error) { return id.AppendText(nil) }
func (id *ProcessInstanceID) UnmarshalText(t []byte) error {
	return unmarshalTextWithReset(id, ProcessInstanceID{}, t, ParseProcessInstanceID)
}

// AuditPhase 标识单条审计记录所处的操作生命周期阶段（ADR-008）；零值 AuditPhaseInvalid 失败关闭。
//
//xops:opaque
//xops:failclosed
type AuditPhase uint8

const (
	AuditPhaseInvalid    AuditPhase = iota // 无效阶段（零值失败关闭）
	AuditPhaseDenied                       // 准入或审批阶段直接拒绝
	AuditPhaseAuthorized                   // 能力证明签发前置落盘记录
	AuditPhaseFinalized                    // 操作终态闭合记录
)

// AuditOutcome 标识审计记录对应的结果语义；零值 AuditOutcomeInvalid 失败关闭。
//
//xops:opaque
//xops:failclosed
type AuditOutcome uint8

const (
	AuditOutcomeInvalid        AuditOutcome = iota // 无效结果（零值失败关闭）
	AuditOutcomePending                            // 已授权待执行闭合（仅配对 Authorized）
	AuditOutcomeDenied                             // 策略或审批拒绝（仅配对 Denied）
	AuditOutcomeSucceeded                          // 终态：执行成功
	AuditOutcomeFailed                             // 终态：执行失败
	AuditOutcomeCanceled                           // 终态：上下文取消或中断
	AuditOutcomeEscalated                          // 终态：二阶段规范化作用域升级并撤销放行
	AuditOutcomeAbortedByCrash                     // 终态：崩溃恢复对账补写
	AuditOutcomeUnknown                            // 终态：副作用结果未知（严禁降级为 Failed）
)

// AuditEntrySpec 是构造不可变 AuditEntry 的显式入参规格（严禁 SecretBox 或裸 time.Duration）。
type AuditEntrySpec struct {
	ProcessID         ProcessInstanceID
	TraceID           security.TraceID
	OperationID       security.OperationID
	Phase             AuditPhase
	Outcome           AuditOutcome
	Risk              security.RiskLevel
	Decision          security.DecisionKind
	Binding           security.OperationBinding
	Timestamp         time.Time
	Duration          algebraic.Option[algebraic.Duration]
	ErrorCode, Reason string
}

// AuditEntry 表示一条面向 JSONL 同步落盘的不可变安全审计记录（ADR-008）；零值恒无效。
//
//xops:opaque
//xops:failclosed
type AuditEntry struct {
	s     AuditEntrySpec
	valid bool
}

// NewAuditEntry 校验标识、阶段/结果/决策配对、RFC 3339 时间戳与非负可选耗时并构造 AuditEntry。
func NewAuditEntry(spec AuditEntrySpec) (AuditEntry, error) {
	reason, e2 := sanitizeBoundedText(spec.Reason, maxPortDetailBytes, true, ErrInvalidAuditEntry)
	if err := firstErr(validateAuditEntrySpec(spec), e2); err != nil {
		return AuditEntry{}, err
	}
	spec.Timestamp, spec.Reason = spec.Timestamp.UTC().Round(0), reason
	return AuditEntry{s: spec, valid: true}, nil
}
func isValidAuditEntrySpec(s AuditEntrySpec) bool {
	dur, hasDur := s.Duration.Get()
	return s.ProcessID.IsValid() && s.TraceID.IsValid() && s.OperationID.IsValid() && s.Risk.IsValid() && s.Binding.IsValid() && isValidRFC3339Time(s.Timestamp) && isValidAuditPhaseOutcome(s.Phase, s.Outcome) && isValidAuditPhaseDecision(s.Phase, s.Decision) && (!hasDur || !dur.IsNegative()) && (s.ErrorCode == "" || isValidASCIIToken(s.ErrorCode, maxAuditErrorCodeLen))
}
func validateAuditEntrySpec(s AuditEntrySpec) error {
	if !isValidAuditEntrySpec(s) {
		return fieldErr(ErrInvalidAuditEntry, "audit_entry")
	}
	return nil
}
func isValidAuditPhaseOutcome(p AuditPhase, o AuditOutcome) bool {
	return (p == AuditPhaseAuthorized && o == AuditOutcomePending) || (p == AuditPhaseDenied && o == AuditOutcomeDenied) || (p == AuditPhaseFinalized && o >= AuditOutcomeSucceeded && o <= AuditOutcomeUnknown)
}
func isValidAuditPhaseDecision(p AuditPhase, d security.DecisionKind) bool {
	return d.IsValid() && ((p == AuditPhaseDenied && d != security.DecisionKindAllow) || ((p == AuditPhaseAuthorized || p == AuditPhaseFinalized) && d != security.DecisionKindDeny))
}
func (e AuditEntry) IsValid() bool                                  { return e.valid && isValidAuditEntrySpec(e.s) }
func (e AuditEntry) IsZero() bool                                   { return !e.IsValid() }
func (e AuditEntry) ProcessID() ProcessInstanceID                   { return e.s.ProcessID }
func (e AuditEntry) TraceID() security.TraceID                      { return e.s.TraceID }
func (e AuditEntry) OperationID() security.OperationID              { return e.s.OperationID }
func (e AuditEntry) Phase() AuditPhase                              { return orZero(e.IsValid(), e.s.Phase) }
func (e AuditEntry) Outcome() AuditOutcome                          { return orZero(e.IsValid(), e.s.Outcome) }
func (e AuditEntry) Risk() security.RiskLevel                       { return orZero(e.IsValid(), e.s.Risk) }
func (e AuditEntry) Decision() security.DecisionKind                { return orZero(e.IsValid(), e.s.Decision) }
func (e AuditEntry) Binding() security.OperationBinding             { return e.s.Binding }
func (e AuditEntry) Timestamp() time.Time                           { return e.s.Timestamp }
func (e AuditEntry) Duration() algebraic.Option[algebraic.Duration] { return e.s.Duration }
func (e AuditEntry) ErrorCode() string                              { return e.s.ErrorCode }
func (e AuditEntry) Reason() string                                 { return e.s.Reason }
func (e AuditEntry) CanonicalJSON() ([]byte, error) {
	if !e.IsValid() {
		return nil, ErrInvalidAuditEntry
	}
	return jsonv2.Marshal(e, jsonv2.Deterministic(true))
}
func (e AuditEntry) Equal(o AuditEntry) bool {
	return e.IsValid() && o.IsValid() && e.s.ProcessID.Equal(o.s.ProcessID) && e.s.TraceID.Equal(o.s.TraceID) && e.s.OperationID.Equal(o.s.OperationID) && e.s.Phase == o.s.Phase && e.s.Outcome == o.s.Outcome && e.s.Risk == o.s.Risk && e.s.Decision == o.s.Decision && e.s.Binding.Equal(o.s.Binding) && e.s.Timestamp.Equal(o.s.Timestamp) && optEqualFunc(e.s.Duration, o.s.Duration, algebraic.Duration.Equal) && e.s.ErrorCode == o.s.ErrorCode && e.s.Reason == o.s.Reason
}

// AuditPostWriteError 表示副作用完成后写入终态审计失败的致命故障（ADR-008）；实现单值 Unwrap 与 Is(ErrAuditPostWrite)。
//
//xops:opaque
//xops:failclosed
type AuditPostWriteError struct {
	operationID security.OperationID
	cause       error
	valid       bool
}

// NewAuditPostWriteError 校验 operationID 有效后构造不可变 *AuditPostWriteError。
func NewAuditPostWriteError(opID security.OperationID, cause error) (*AuditPostWriteError, error) {
	if !opID.IsValid() {
		return nil, domi18n.EF(ErrInvalidArgument, domi18n.KeyCommonFieldRequired, domi18n.Str("field", "operation_id"))
	}
	return &AuditPostWriteError{operationID: opID, cause: pickIf[error](cause != nil, cause, ErrAuditPostWrite), valid: true}, nil
}
func (e *AuditPostWriteError) IsValid() bool {
	return e != nil && e.valid && e.operationID.IsValid() && e.cause != nil
}
func (e *AuditPostWriteError) OperationID() security.OperationID {
	if !e.IsValid() {
		return zeroVal[security.OperationID]()
	}
	return e.operationID
}

// LocalizableView 返回结构化错误节点视图，供边界无穿透本地化并在默认 cause==ErrAuditPostWrite 时精准折叠。
func (e *AuditPostWriteError) LocalizableView() domi18n.ErrorNode {
	if !e.IsValid() {
		return domi18n.ErrorNode{Message: domi18n.NewMessage(domi18n.KeyPortsAuditPostWrite)}
	}
	return domi18n.ErrorNode{
		Sentinel:            ErrAuditPostWrite,
		Message:             domi18n.NewMessage(domi18n.KeyPortsAuditPostWriteOp, domi18n.BoundStr("op", e.operationID.String())),
		Cause:               e.cause,
		SuppressedSentinels: []error{ErrAuditPostWrite},
	}
}
func (e *AuditPostWriteError) Error() string { return domi18n.CanonicalError(e) }
func (e *AuditPostWriteError) Unwrap() error {
	if !e.IsValid() {
		return nil
	}
	return e.cause
}
func (e *AuditPostWriteError) Is(t error) bool { return e.IsValid() && t == ErrAuditPostWrite }

// CrashReconcileReportSpec 是构造不可变 CrashReconcileReport 的显式入参规格。
type CrashReconcileReportSpec struct {
	ScannedLocks, LiveLocksSkipped, DeadLocksClaimed int
	AbortedOperations                                []security.OperationID
}

// CrashReconcileReport 描述启动期 O(1) 崩溃对账的确定性汇总报告（RFC §3.4）；零值恒无效。
//
//xops:opaque
//xops:failclosed
type CrashReconcileReport struct {
	s     CrashReconcileReportSpec
	valid bool
}

// NewCrashReconcileReport 校验计数非负、一致性及全部补写 OperationID 有效后构造不可变报告。
func NewCrashReconcileReport(spec CrashReconcileReportSpec) (CrashReconcileReport, error) {
	if spec.ScannedLocks < 0 || spec.LiveLocksSkipped < 0 || spec.DeadLocksClaimed < 0 ||
		spec.LiveLocksSkipped+spec.DeadLocksClaimed > spec.ScannedLocks ||
		slices.ContainsFunc(spec.AbortedOperations, security.OperationID.IsZero) {
		return CrashReconcileReport{}, fieldErr(ErrInvalidArgument, "crash_reconcile_report")
	}
	ops := cloneSliceNilIfEmpty(spec.AbortedOperations)
	slices.SortFunc(ops, security.OperationID.Compare)
	spec.AbortedOperations = slices.CompactFunc(ops, security.OperationID.Equal)
	return CrashReconcileReport{s: spec, valid: true}, nil
}
func (r CrashReconcileReport) IsValid() bool     { return r.valid && r.s.ScannedLocks >= 0 }
func (r CrashReconcileReport) IsZero() bool      { return !r.IsValid() }
func (r CrashReconcileReport) ScannedLocks() int { return orZero(r.IsValid(), r.s.ScannedLocks) }
func (r CrashReconcileReport) LiveLocksSkipped() int {
	return orZero(r.IsValid(), r.s.LiveLocksSkipped)
}
func (r CrashReconcileReport) DeadLocksClaimed() int {
	return orZero(r.IsValid(), r.s.DeadLocksClaimed)
}
func (r CrashReconcileReport) AbortedOperations() []security.OperationID {
	return slices.Clone(r.s.AbortedOperations)
}
func (r CrashReconcileReport) Equal(o CrashReconcileReport) bool {
	return r.IsValid() && o.IsValid() && r.s.ScannedLocks == o.s.ScannedLocks && r.s.LiveLocksSkipped == o.s.LiveLocksSkipped && r.s.DeadLocksClaimed == o.s.DeadLocksClaimed && slices.EqualFunc(r.s.AbortedOperations, o.s.AbortedOperations, security.OperationID.Equal)
}

// AuditSink 定义同步 Fail-Closed 审计写入与只追加活跃操作登记出站端口（ADR-008）。
type AuditSink interface {
	ProcessInstanceID() ProcessInstanceID
	StageOperation(ctx context.Context, opID security.OperationID) error
	UnstageOperation(ctx context.Context, opID security.OperationID) error
	Record(ctx context.Context, entry AuditEntry) error
	Close() error
}

// AuditReconciler 定义引擎启动期 O(1) 跨进程崩溃审计对账出站端口（ADR-008 / RFC §3.4）。
type AuditReconciler interface {
	ReconcileCrashedAudits(ctx context.Context, now time.Time) (CrashReconcileReport, error)
}
