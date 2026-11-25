package ports

import (
	"cmp"
	"context"
	"encoding/hex"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
)

const (
	processInstanceEntropyBytes = 16
	maxProcessInstanceIDLen     = 64
	maxAuditErrorCodeLen        = 64
)

// ProcessInstanceID 唯一标识单个运行期 Engine 实例，映射 ~/.xops/run/<ProcessInstanceID>.lock（ADR-008）。
//
//xops:opaque
//xops:failclosed
type ProcessInstanceID struct{ value string }

// NewProcessInstanceIDFrom 从显式熵源读取 16 字节非全零随机数据并生成 32 位小写十六进制 ProcessInstanceID。
func NewProcessInstanceIDFrom(entropy io.Reader) (ProcessInstanceID, error) {
	if entropy == nil {
		return ProcessInstanceID{}, fmt.Errorf("%w: 熵源不能为 nil", ErrInvalidProcessInstanceID)
	}
	var raw [processInstanceEntropyBytes]byte
	if _, err := io.ReadFull(entropy, raw[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return ProcessInstanceID{}, fmt.Errorf("%w: %w: %w", ErrInvalidProcessInstanceID, ErrEntropyShortRead, err)
		}
		return ProcessInstanceID{}, fmt.Errorf("%w: %w", ErrInvalidProcessInstanceID, err)
	}
	if raw == ([processInstanceEntropyBytes]byte{}) {
		return ProcessInstanceID{}, fmt.Errorf("%w: 熵源返回全零字节", ErrInvalidProcessInstanceID)
	}
	return ProcessInstanceID{value: hex.EncodeToString(raw[:])}, nil
}

// ParseProcessInstanceID 校验并构造 ProcessInstanceID（1..64 位安全 ASCII 标识符，满足跨平台单文件名规则）。
func ParseProcessInstanceID(raw string) (ProcessInstanceID, error) {
	if len(raw) == 0 || len(raw) > maxProcessInstanceIDLen || !isSafeProcessIDChars(raw) {
		return ProcessInstanceID{}, fmt.Errorf("%w: %q 格式非法", ErrInvalidProcessInstanceID, raw)
	}
	if err := pathalg.ValidateLocalComponent(raw + ".lock"); err != nil {
		return ProcessInstanceID{}, fmt.Errorf("%w: %w", ErrInvalidProcessInstanceID, err)
	}
	return ProcessInstanceID{value: raw}, nil
}

func isSafeProcessIDChars(raw string) bool {
	for i := range len(raw) {
		b := raw[i]
		alnum := (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
		if !alnum && (i == 0 || (b != '-' && b != '.') || (i == len(raw)-1 && b == '.')) {
			return false
		}
	}
	return true
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
	processID         ProcessInstanceID
	traceID           security.TraceID
	operationID       security.OperationID
	phase             AuditPhase
	outcome           AuditOutcome
	risk              security.RiskLevel
	decision          security.DecisionKind
	binding           security.OperationBinding
	timestamp         time.Time
	duration          algebraic.Option[algebraic.Duration]
	errorCode, reason string
	valid             bool
}

// NewAuditEntry 校验标识、阶段/结果/决策配对、RFC 3339 时间戳与非负可选耗时并构造 AuditEntry。
func NewAuditEntry(spec AuditEntrySpec) (AuditEntry, error) {
	reason, e2 := sanitizeBoundedText(spec.Reason, maxPortDetailBytes, true, ErrInvalidAuditEntry)
	if err := firstErr(validateAuditEntrySpec(spec), e2); err != nil {
		return AuditEntry{}, err
	}
	return AuditEntry{
		processID: spec.ProcessID, traceID: spec.TraceID, operationID: spec.OperationID,
		phase: spec.Phase, outcome: spec.Outcome, risk: spec.Risk, decision: spec.Decision,
		binding: spec.Binding, timestamp: spec.Timestamp.UTC().Round(0), duration: spec.Duration,
		errorCode: spec.ErrorCode, reason: reason, valid: true,
	}, nil
}

func validateAuditEntrySpec(s AuditEntrySpec) error {
	dur, hasDur := s.Duration.Get()
	if !s.ProcessID.IsValid() || !s.TraceID.IsValid() || !s.OperationID.IsValid() || !s.Risk.IsValid() || !s.Binding.IsValid() ||
		!isValidRFC3339Time(s.Timestamp) || !isValidAuditPhaseOutcome(s.Phase, s.Outcome) || !isValidAuditPhaseDecision(s.Phase, s.Decision) ||
		(hasDur && dur.IsNegative()) || (s.ErrorCode != "" && !isValidASCIIToken(s.ErrorCode, maxAuditErrorCodeLen)) {
		return fmt.Errorf("%w: 审计记录字段或阶段/结果/决策组合非法", ErrInvalidAuditEntry)
	}
	return nil
}

func isValidAuditPhaseOutcome(p AuditPhase, o AuditOutcome) bool {
	return (p == AuditPhaseAuthorized && o == AuditOutcomePending) ||
		(p == AuditPhaseDenied && o == AuditOutcomeDenied) ||
		(p == AuditPhaseFinalized && o >= AuditOutcomeSucceeded && o <= AuditOutcomeUnknown)
}

func isValidAuditPhaseDecision(p AuditPhase, d security.DecisionKind) bool {
	return d.IsValid() && ((p == AuditPhaseDenied && d != security.DecisionKindAllow) ||
		((p == AuditPhaseAuthorized || p == AuditPhaseFinalized) && d != security.DecisionKindDeny))
}

func (e AuditEntry) IsValid() bool {
	dur, hasDur := e.duration.Get()
	return e.valid && e.processID.IsValid() && e.traceID.IsValid() && e.operationID.IsValid() &&
		isValidAuditPhaseOutcome(e.phase, e.outcome) && isValidAuditPhaseDecision(e.phase, e.decision) &&
		e.risk.IsValid() && e.binding.IsValid() && isValidRFC3339Time(e.timestamp) && (!hasDur || !dur.IsNegative())
}
func (e AuditEntry) IsZero() bool                      { return !e.IsValid() }
func (e AuditEntry) ProcessID() ProcessInstanceID      { return e.processID }
func (e AuditEntry) TraceID() security.TraceID         { return e.traceID }
func (e AuditEntry) OperationID() security.OperationID { return e.operationID }
func (e AuditEntry) Phase() AuditPhase                 { return pickIf(e.IsValid(), e.phase, AuditPhaseInvalid) }
func (e AuditEntry) Outcome() AuditOutcome {
	return pickIf(e.IsValid(), e.outcome, AuditOutcomeInvalid)
}
func (e AuditEntry) Risk() security.RiskLevel {
	return pickIf(e.IsValid(), e.risk, security.RiskUnknown)
}
func (e AuditEntry) Decision() security.DecisionKind {
	return pickIf(e.IsValid(), e.decision, security.DecisionKindDeny)
}
func (e AuditEntry) Binding() security.OperationBinding             { return e.binding }
func (e AuditEntry) Timestamp() time.Time                           { return e.timestamp }
func (e AuditEntry) Duration() algebraic.Option[algebraic.Duration] { return e.duration }
func (e AuditEntry) ErrorCode() string                              { return e.errorCode }
func (e AuditEntry) Reason() string                                 { return e.reason }
func (e AuditEntry) CanonicalJSON() ([]byte, error) {
	if !e.IsValid() {
		return nil, ErrInvalidAuditEntry
	}
	return jsonv2.Marshal(e, jsonv2.Deterministic(true))
}
func (e AuditEntry) Equal(o AuditEntry) bool {
	return e.IsValid() && o.IsValid() && e.processID.Equal(o.processID) && e.traceID.Equal(o.traceID) &&
		e.operationID.Equal(o.operationID) && e.phase == o.phase && e.outcome == o.outcome &&
		e.risk == o.risk && e.decision == o.decision && e.binding.Equal(o.binding) &&
		e.timestamp.Equal(o.timestamp) && optEqualFunc(e.duration, o.duration, algebraic.Duration.Equal) &&
		e.errorCode == o.errorCode && e.reason == o.reason
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
		return nil, fmt.Errorf("%w: AuditPostWriteError 需要有效 OperationID", ErrInvalidArgument)
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
func (e *AuditPostWriteError) Error() string {
	if !e.IsValid() {
		return ErrAuditPostWrite.Error()
	}
	return fmt.Sprintf("%s (op=%s): %v", ErrAuditPostWrite.Error(), e.operationID, e.cause)
}
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
	scannedLocks, liveLocksSkipped, deadLocksClaimed int
	abortedOperations                                []security.OperationID
	valid                                            bool
}

// NewCrashReconcileReport 校验计数非负、一致性及全部补写 OperationID 有效后构造不可变报告。
func NewCrashReconcileReport(spec CrashReconcileReportSpec) (CrashReconcileReport, error) {
	if spec.ScannedLocks < 0 || spec.LiveLocksSkipped < 0 || spec.DeadLocksClaimed < 0 ||
		spec.LiveLocksSkipped+spec.DeadLocksClaimed > spec.ScannedLocks {
		return CrashReconcileReport{}, fmt.Errorf("%w: 崩溃对账锁统计计数非法", ErrInvalidArgument)
	}
	var ops []security.OperationID
	if len(spec.AbortedOperations) > 0 {
		ops = slices.Clone(spec.AbortedOperations)
		if slices.ContainsFunc(ops, security.OperationID.IsZero) {
			return CrashReconcileReport{}, fmt.Errorf("%w: aborted_operations 包含无效 OperationID", ErrInvalidArgument)
		}
		slices.SortFunc(ops, security.OperationID.Compare)
		ops = slices.CompactFunc(ops, security.OperationID.Equal)
	}
	return CrashReconcileReport{scannedLocks: spec.ScannedLocks, liveLocksSkipped: spec.LiveLocksSkipped, deadLocksClaimed: spec.DeadLocksClaimed, abortedOperations: ops, valid: true}, nil
}
func (r CrashReconcileReport) IsValid() bool     { return r.valid && r.scannedLocks >= 0 }
func (r CrashReconcileReport) IsZero() bool      { return !r.IsValid() }
func (r CrashReconcileReport) ScannedLocks() int { return pickIf(r.IsValid(), r.scannedLocks, 0) }
func (r CrashReconcileReport) LiveLocksSkipped() int {
	return pickIf(r.IsValid(), r.liveLocksSkipped, 0)
}
func (r CrashReconcileReport) DeadLocksClaimed() int {
	return pickIf(r.IsValid(), r.deadLocksClaimed, 0)
}
func (r CrashReconcileReport) AbortedOperations() []security.OperationID {
	return slices.Clone(r.abortedOperations)
}
func (r CrashReconcileReport) Equal(o CrashReconcileReport) bool {
	return r.IsValid() && o.IsValid() && r.scannedLocks == o.scannedLocks && r.liveLocksSkipped == o.liveLocksSkipped &&
		r.deadLocksClaimed == o.deadLocksClaimed && slices.EqualFunc(r.abortedOperations, o.abortedOperations, security.OperationID.Equal)
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
