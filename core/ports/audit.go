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

// ProcessInstanceID 唯一标识单个运行期 Engine 实例，直接映射 ~/.xops/run/<ProcessInstanceID>.lock（ADR-008 / RFC §3.4）。
// 构造期强制校验跨平台单文件名分量合法性（兼容 pathalg.ValidateLocalComponent），零值恒无效并失败关闭。
//
//xops:opaque
//xops:failclosed
type ProcessInstanceID struct{ value string }

// NewProcessInstanceIDFrom 从显式注入的熵源 io.Reader 读取 16 字节非全零随机数据并生成 32 位小写十六进制 ProcessInstanceID。
// 短读（io.EOF / io.ErrUnexpectedEOF）包装返回 ErrEntropyShortRead，全零字节严格失败关闭。
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

// ParseProcessInstanceID 校验并构造 ProcessInstanceID（长度 1..64 的安全 ASCII 标识符，满足跨平台单文件名安全规则）。
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
	if !isProcessIDStartByte(raw[0]) || raw[len(raw)-1] == '.' {
		return false
	}
	for i := 1; i < len(raw); i++ {
		if c := raw[i]; !isProcessIDStartByte(c) && c != '-' && c != '.' {
			return false
		}
	}
	return true
}
func isProcessIDStartByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

// ProcessInstanceID 只读访问器、锁文件名映射、确定性全序与文本编解码。
func (id ProcessInstanceID) IsValid() bool  { return id.value != "" }
func (id ProcessInstanceID) IsZero() bool   { return id.value == "" }
func (id ProcessInstanceID) String() string { return id.value }
func (id ProcessInstanceID) LockFileName() (pathalg.LocalRootedDest, error) {
	if !id.IsValid() {
		return zeroVal[pathalg.LocalRootedDest](), ErrInvalidProcessInstanceID
	}
	return pathalg.ParseLocalRootedDest(id.value + ".lock")
}
func (id ProcessInstanceID) Equal(o ProcessInstanceID) bool {
	return id.IsValid() && o.IsValid() && id.value == o.value
}
func (id ProcessInstanceID) Compare(o ProcessInstanceID) int { return cmp.Compare(id.value, o.value) }
func (id ProcessInstanceID) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, id.IsValid(), id.value, ErrInvalidProcessInstanceID)
}
func (id ProcessInstanceID) MarshalText() ([]byte, error) { return id.AppendText(nil) }
func (id *ProcessInstanceID) UnmarshalText(text []byte) error {
	return unmarshalTextWithReset(id, ProcessInstanceID{}, text, ParseProcessInstanceID)
}

// AuditPhase 标识单条审计记录所处的操作生命周期阶段（ADR-008 / INV-E5）；零值 AuditPhaseInvalid 失败关闭。
//
//xops:opaque
//xops:failclosed
type AuditPhase uint8

const (
	AuditPhaseInvalid    AuditPhase = iota // 无效阶段（零值失败关闭）
	AuditPhaseDenied                       // 准入或审批阶段直接拒绝（无后续副作用）
	AuditPhaseAuthorized                   // 能力证明签发前置落盘记录（必须与后续 Finalized 配对闭合）
	AuditPhaseFinalized                    // 操作终态闭合记录（含正常完成、失败、取消、升级或崩溃补写）
)

// AuditOutcome 标识审计记录对应的结果语义；零值 AuditOutcomeInvalid 失败关闭。
//
//xops:opaque
//xops:failclosed
type AuditOutcome uint8

const (
	AuditOutcomeInvalid        AuditOutcome = iota // 无效结果（零值失败关闭）
	AuditOutcomePending                            // 已授权待执行闭合（仅配对 AuditPhaseAuthorized）
	AuditOutcomeDenied                             // 策略或审批拒绝（仅配对 AuditPhaseDenied）
	AuditOutcomeSucceeded                          // 终态：执行成功（配对 AuditPhaseFinalized）
	AuditOutcomeFailed                             // 终态：执行失败（配对 AuditPhaseFinalized）
	AuditOutcomeCanceled                           // 终态：上下文取消或中断（配对 AuditPhaseFinalized）
	AuditOutcomeEscalated                          // 终态：二阶段规范化检测到作用域升级并撤销放行（配对 AuditPhaseFinalized）
	AuditOutcomeAbortedByCrash                     // 终态：崩溃恢复对账补写（配对 AuditPhaseFinalized，RFC §3.4）
	AuditOutcomeUnknown                            // 终态：副作用结果未知（配对 AuditPhaseFinalized，严禁降级为 Failed，INV-C6 / ADR-016）
)

// AuditEntrySpec 是构造不可变 AuditEntry 的显式入参规格。
// 严格约束：使用 security.TraceID / security.OperationID 与 algebraic.Duration，严禁引入 SecretBox 或裸 time.Duration。
type AuditEntrySpec struct {
	ProcessID   ProcessInstanceID
	TraceID     security.TraceID
	OperationID security.OperationID
	Phase       AuditPhase
	Outcome     AuditOutcome
	Risk        security.RiskLevel
	Decision    security.DecisionKind
	Binding     security.OperationBinding
	Timestamp   time.Time
	Duration    algebraic.Option[algebraic.Duration]
	ErrorCode   string
	Reason      string
}

// AuditEntry 表示一条面向 JSONL 同步落盘的不可变安全审计记录（ADR-008 / RFC §3.4–3.5）；
// 零值恒无效并失败关闭，严禁包含任何 SecretBox 或明文凭据。
//
//xops:opaque
//xops:failclosed
type AuditEntry struct {
	processID   ProcessInstanceID
	traceID     security.TraceID
	operationID security.OperationID
	phase       AuditPhase
	outcome     AuditOutcome
	risk        security.RiskLevel
	decision    security.DecisionKind
	binding     security.OperationBinding
	timestamp   time.Time
	duration    algebraic.Option[algebraic.Duration]
	errorCode   string
	reason      string
	valid       bool
}

// NewAuditEntry 校验标识、阶段与结果配对不变量、RFC 3339 时间戳与非负可选耗时并构造不可变 AuditEntry。
func NewAuditEntry(spec AuditEntrySpec) (AuditEntry, error) {
	if err := validateAuditEntrySpec(spec); err != nil {
		return AuditEntry{}, err
	}
	reason, err := sanitizeBoundedText(spec.Reason, maxPortDetailBytes, true, ErrInvalidAuditEntry)
	if err != nil {
		return AuditEntry{}, err
	}
	return AuditEntry{
		processID: spec.ProcessID, traceID: spec.TraceID, operationID: spec.OperationID,
		phase: spec.Phase, outcome: spec.Outcome, risk: spec.Risk, decision: spec.Decision,
		binding: spec.Binding, timestamp: spec.Timestamp.UTC().Round(0), duration: spec.Duration,
		errorCode: spec.ErrorCode, reason: reason, valid: true,
	}, nil
}

func validateAuditEntrySpec(spec AuditEntrySpec) error {
	if !spec.ProcessID.IsValid() || !spec.TraceID.IsValid() || !spec.OperationID.IsValid() {
		return fmt.Errorf("%w: process_id/trace_id/operation_id 均须有效", ErrInvalidAuditEntry)
	}
	if !isValidAuditPhaseOutcome(spec.Phase, spec.Outcome) {
		return fmt.Errorf("%w: 阶段 %s 与结果 %s 组合非法", ErrInvalidAuditEntry, spec.Phase, spec.Outcome)
	}
	if !isValidAuditPhaseDecision(spec.Phase, spec.Decision) {
		return fmt.Errorf("%w: 阶段 %s 与护栏决策 %s 组合矛盾", ErrInvalidAuditEntry, spec.Phase, spec.Decision)
	}
	if !spec.Risk.IsValid() || !spec.Binding.IsValid() || !isValidRFC3339Time(spec.Timestamp) {
		return fmt.Errorf("%w: risk/binding/timestamp 均须有效", ErrInvalidAuditEntry)
	}
	if dur, ok := spec.Duration.Get(); ok && dur.IsNegative() {
		return fmt.Errorf("%w: duration 不能为负时长", ErrInvalidAuditEntry)
	}
	if spec.ErrorCode != "" && !isValidASCIIToken(spec.ErrorCode, maxAuditErrorCodeLen) {
		return fmt.Errorf("%w: 非法 error_code %q", ErrInvalidAuditEntry, spec.ErrorCode)
	}
	return nil
}

func isValidAuditPhaseOutcome(phase AuditPhase, outcome AuditOutcome) bool {
	switch phase {
	case AuditPhaseAuthorized:
		return outcome == AuditOutcomePending
	case AuditPhaseDenied:
		return outcome == AuditOutcomeDenied
	case AuditPhaseFinalized:
		return outcome >= AuditOutcomeSucceeded && outcome <= AuditOutcomeUnknown
	default:
		return false
	}
}

// isValidAuditPhaseDecision 校验审计阶段与护栏决策语义一致（失败关闭）：
// Denied 阶段禁止出现 DecisionKindAllow；Authorized/Finalized 阶段禁止出现零值 DecisionKindDeny。
func isValidAuditPhaseDecision(phase AuditPhase, decision security.DecisionKind) bool {
	if !decision.IsValid() {
		return false
	}
	switch phase {
	case AuditPhaseDenied:
		return decision != security.DecisionKindAllow
	case AuditPhaseAuthorized, AuditPhaseFinalized:
		return decision != security.DecisionKindDeny
	default:
		return false
	}
}

// AuditEntry 只读访问器、规范 JSON 编码与严格等价比对。
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

// AuditPostWriteError 表示副作用执行完毕后写入终态审计记录失败的致命故障（ADR-008）。
// 在 StrictAgentProfile 下，core/internal/gate 捕获此错误必须立即进入 Halted 熔断态并经 OnHaltFunc 吊销全部句柄；
// 本类型实现单值 Unwrap() error（满足 conc.RunScoped 防吞噬契约）与 Is(ErrAuditPostWrite)。
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
	if cause == nil {
		cause = ErrAuditPostWrite
	}
	return &AuditPostWriteError{operationID: opID, cause: cause, valid: true}, nil
}

// AuditPostWriteError 只读访问器与标准错误链契约（显式空指针/有效性守卫，杜绝 typed-nil 解引用 panic）。
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
func (e *AuditPostWriteError) Is(target error) bool {
	return e.IsValid() && target == ErrAuditPostWrite
}

// CrashReconcileReportSpec 是构造不可变 CrashReconcileReport 的显式入参规格。
type CrashReconcileReportSpec struct {
	ScannedLocks      int
	LiveLocksSkipped  int
	DeadLocksClaimed  int
	AbortedOperations []security.OperationID
}

// CrashReconcileReport 描述启动期 O(1) 崩溃对账的确定性汇总报告（RFC §3.4）；零值恒无效。
//
//xops:opaque
//xops:failclosed
type CrashReconcileReport struct {
	scannedLocks      int
	liveLocksSkipped  int
	deadLocksClaimed  int
	abortedOperations []security.OperationID
	valid             bool
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
	return CrashReconcileReport{
		scannedLocks: spec.ScannedLocks, liveLocksSkipped: spec.LiveLocksSkipped,
		deadLocksClaimed: spec.DeadLocksClaimed, abortedOperations: ops, valid: true,
	}, nil
}

// CrashReconcileReport 只读访问器与等价比对。
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
	return r.IsValid() && o.IsValid() && r.scannedLocks == o.scannedLocks &&
		r.liveLocksSkipped == o.liveLocksSkipped && r.deadLocksClaimed == o.deadLocksClaimed &&
		slices.EqualFunc(r.abortedOperations, o.abortedOperations, security.OperationID.Equal)
}

// AuditSink 定义同步 Fail-Closed 审计写入与只追加活跃操作登记出站端口（ADR-008 / Plan §4.4）。
// gate.WithAuthorized 严格按 StageOperation(+opID) -> Record(Authorized) -> run() -> Record(Finalized) -> UnstageOperation(-opID) 推进。
type AuditSink interface {
	// ProcessInstanceID 返回当前审计接收器持有的进程级唯一实例标识。
	ProcessInstanceID() ProcessInstanceID
	// StageOperation 以只追加协议向当前进程 .lock 记录 "+<opID>\n" 登记在途操作。
	StageOperation(ctx context.Context, opID security.OperationID) error
	// UnstageOperation 以只追加协议向当前进程 .lock 记录 "-<opID>\n" 注销已闭合操作；仅活跃集归零时可截断压缩。
	UnstageOperation(ctx context.Context, opID security.OperationID) error
	// Record 同步追加单条已校验 AuditEntry 并刷盘；终态落盘失败须返回 *AuditPostWriteError 触发熔断。
	Record(ctx context.Context, entry AuditEntry) error
	// Close 清空本进程 .lock、解锁关闭句柄并安全移除锁文件（兼容 Windows 共享冲突规则）。
	Close() error
}

// AuditReconciler 定义引擎启动期 O(1) 跨进程崩溃审计对账出站端口（ADR-008 / RFC §3.4 / Plan §4.4）。
type AuditReconciler interface {
	// ReconcileCrashedAudits 扫描 ~/.xops/run/*.lock：无死亡进程锁时 O(1) 零读取 audit.jsonl；
	// 抢占死亡锁后核验真实未闭合操作并以 now 补写 AuditPhaseFinalized + AuditOutcomeAbortedByCrash，再清空解锁删锁。
	ReconcileCrashedAudits(ctx context.Context, now time.Time) (CrashReconcileReport, error)
}
