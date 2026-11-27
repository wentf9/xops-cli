package execution

import (
	"strings"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/security"
)

// StartPhase 标识命令尚未启动前的失败阶段；零值 StartPhaseUnknown 失败关闭。
//
//xops:opaque
//xops:failclosed
type StartPhase uint8

const (
	StartPhaseUnknown         StartPhase = iota // 未知阶段（零值失败关闭）
	StartPhaseValidate                          // 本地计划/参数预检失败
	StartPhaseAuthorize                         // 能力门控或审批拒绝
	StartPhaseDial                              // SSH 连接拨号或跳板链建立失败
	StartPhaseSessionOpen                       // SSH 会话通道打开失败
	StartPhaseRequestRejected                   // 服务端明确拒绝 exec/shell/pty 启动请求
)

// ParseStartPhase 严格解析规范小写启动前阶段文本。
func ParseStartPhase(raw string) (StartPhase, error) {
	if !hasForbiddenStrictText(raw) {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "validate":
			return StartPhaseValidate, nil
		case "authorize":
			return StartPhaseAuthorize, nil
		case "dial":
			return StartPhaseDial, nil
		case "session_open":
			return StartPhaseSessionOpen, nil
		case "request_rejected":
			return StartPhaseRequestRejected, nil
		}
	}
	return StartPhaseUnknown, domi18n.EF(ErrInvalidPhase, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "start_phase"), domi18n.BoundStr("value", raw))
}

func (p StartPhase) IsValid() bool { return p >= StartPhaseValidate && p <= StartPhaseRequestRejected }
func (p StartPhase) IsZero() bool  { return p == StartPhaseUnknown }
func (p StartPhase) String() string {
	return enumName(uint8(p), "unknown", "unknown", "validate", "authorize", "dial", "session_open", "request_rejected")
}
func (p StartPhase) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, p.IsValid(), p.String(), ErrInvalidPhase, uint8(p))
}
func (p StartPhase) MarshalText() ([]byte, error) { return p.AppendText(nil) }
func (p *StartPhase) UnmarshalText(text []byte) error {
	return unmarshalTextWithReset(p, StartPhaseUnknown, text, ParseStartPhase)
}

// ExecPhase 标识请求已发送后执行结果陷入未知的运行阶段；零值 ExecPhaseUnknown 失败关闭。
//
//xops:opaque
//xops:failclosed
type ExecPhase uint8

const (
	ExecPhaseUnknown       ExecPhase = iota // 未知阶段（零值失败关闭）
	ExecPhaseRequestSent                    // 启动请求已发出但未收到确定响应
	ExecPhaseRunning                        // 远端进程运行期间失联或中止
	ExecPhaseWaitingExit                    // 已进入退出等待阶段但未收到终止帧
	ExecPhaseTransportLost                  // 底层 SSH 传输断开或被拆断
	ExecPhaseTimedOut                       // 执行超时（远端进程可能仍在运行）
	ExecPhaseCanceled                       // 本地主动取消（无法证明远端已终止）
)

// ParseExecPhase 严格解析规范小写执行阶段文本。
func ParseExecPhase(raw string) (ExecPhase, error) {
	if !hasForbiddenStrictText(raw) {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "request_sent":
			return ExecPhaseRequestSent, nil
		case "running":
			return ExecPhaseRunning, nil
		case "waiting_exit":
			return ExecPhaseWaitingExit, nil
		case "transport_lost":
			return ExecPhaseTransportLost, nil
		case "timed_out":
			return ExecPhaseTimedOut, nil
		case "canceled":
			return ExecPhaseCanceled, nil
		}
	}
	return ExecPhaseUnknown, domi18n.EF(ErrInvalidPhase, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "exec_phase"), domi18n.BoundStr("value", raw))
}

func (p ExecPhase) IsValid() bool { return p >= ExecPhaseRequestSent && p <= ExecPhaseCanceled }
func (p ExecPhase) IsZero() bool  { return p == ExecPhaseUnknown }
func (p ExecPhase) String() string {
	return enumName(uint8(p), "unknown", "unknown", "request_sent", "running", "waiting_exit", "transport_lost", "timed_out", "canceled")
}
func (p ExecPhase) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, p.IsValid(), p.String(), ErrInvalidPhase, uint8(p))
}
func (p ExecPhase) MarshalText() ([]byte, error) { return p.AppendText(nil) }
func (p *ExecPhase) UnmarshalText(text []byte) error {
	return unmarshalTextWithReset(p, ExecPhaseUnknown, text, ParseExecPhase)
}

// OutcomeKind 标识 ExecutionOutcome 的判别类别；零值 OutcomeKindInvalid 失败关闭。
//
//xops:opaque
//xops:failclosed
type OutcomeKind uint8

const (
	OutcomeKindInvalid    OutcomeKind = iota // 无效结果（零值失败关闭）
	OutcomeKindNotStarted                    // 确认未启动远端执行（唯一允许重试）
	OutcomeKindCompleted                     // 已取得远端终止结果（严禁自动重试）
	OutcomeKindUnknown                       // 请求已发出但结果不确定（严禁自动重试）
)

// ParseOutcomeKind 严格解析执行结果类别（"not_started"、"completed"、"unknown"）。
func ParseOutcomeKind(raw string) (OutcomeKind, error) {
	if !hasForbiddenStrictText(raw) {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "not_started":
			return OutcomeKindNotStarted, nil
		case "completed":
			return OutcomeKindCompleted, nil
		case "unknown":
			return OutcomeKindUnknown, nil
		}
	}
	return OutcomeKindInvalid, domi18n.EF(ErrInvalidExecutionOutcome, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "outcome.kind"), domi18n.BoundStr("value", raw))
}

func (k OutcomeKind) IsValid() bool { return k >= OutcomeKindNotStarted && k <= OutcomeKindUnknown }
func (k OutcomeKind) IsZero() bool  { return k == OutcomeKindInvalid }
func (k OutcomeKind) String() string {
	return enumName(uint8(k), "invalid", "invalid", "not_started", "completed", "unknown")
}
func (k OutcomeKind) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, k.IsValid(), k.String(), ErrInvalidExecutionOutcome, uint8(k))
}
func (k OutcomeKind) MarshalText() ([]byte, error) { return k.AppendText(nil) }
func (k *OutcomeKind) UnmarshalText(text []byte) error {
	return unmarshalTextWithReset(k, OutcomeKindInvalid, text, ParseOutcomeKind)
}

// ExecutionOutcome 是命令执行终态的封闭代数和类型（RFC §3.6 / INV-C6）：
// 仅含三个具体变体 *OutcomeNotStarted、*OutcomeCompleted 与 *OutcomeUnknown；
// 严格不变量：CanRetry() 仅对有效 *OutcomeNotStarted 返回 true，其余一律失败关闭返回 false。
//
//xops:failclosed
type ExecutionOutcome interface {
	sealedExecutionOutcome()
	Kind() OutcomeKind
	CanRetry() bool
	IsValid() bool
}

// OutcomeNotStarted 表示可证明用户操作尚未在远端启动（唯一允许安全重试的变体）。
//
//xops:opaque
//xops:failclosed
type OutcomeNotStarted struct {
	phase  StartPhase
	code   string
	reason string
	valid  bool
}

// NewOutcomeNotStarted 校验启动前阶段与错误代码并构造 *OutcomeNotStarted。
func NewOutcomeNotStarted(phase StartPhase, code, reason string) (*OutcomeNotStarted, error) {
	if !phase.IsValid() {
		return nil, domi18n.WrapSentinel(ErrInvalidExecutionOutcome, ErrInvalidPhase)
	}
	if code != "" && !isValidASCIICode(code, maxCodeLen) {
		return nil, domi18n.EF(ErrInvalidExecutionOutcome, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "code"), domi18n.BoundStr("value", code))
	}
	return &OutcomeNotStarted{
		phase: phase, code: code, reason: security.SanitizePromptText(reason), valid: true,
	}, nil
}

func (*OutcomeNotStarted) sealedExecutionOutcome() {}
func (o *OutcomeNotStarted) IsValid() bool         { return o != nil && o.valid && o.phase.IsValid() }
func (o *OutcomeNotStarted) Kind() OutcomeKind {
	return pickIf(o.IsValid(), OutcomeKindNotStarted, OutcomeKindInvalid)
}

// CanRetry 当且仅当为有效 *OutcomeNotStarted 时返回 true。
func (o *OutcomeNotStarted) CanRetry() bool { return o.IsValid() }
func (o *OutcomeNotStarted) Phase() StartPhase {
	if !o.IsValid() {
		return StartPhaseUnknown
	}
	return o.phase
}
func (o *OutcomeNotStarted) Code() string {
	if !o.IsValid() {
		return ""
	}
	return o.code
}
func (o *OutcomeNotStarted) Reason() string {
	if !o.IsValid() {
		return ""
	}
	return o.reason
}

// OutcomeCompleted 表示已收到远端进程终态（退出码、信号或缺失退出帧）；严禁自动重试。
//
//xops:opaque
//xops:failclosed
type OutcomeCompleted struct {
	status    ExitStatus
	truncated bool
	valid     bool
}

// NewOutcomeCompleted 校验 ExitStatus 非空有效并构造 *OutcomeCompleted。
func NewOutcomeCompleted(status ExitStatus, truncated bool) (*OutcomeCompleted, error) {
	cloned, err := cloneExitStatus(status)
	if err != nil {
		return nil, domi18n.WrapSentinel(ErrInvalidExecutionOutcome, err)
	}
	return &OutcomeCompleted{status: cloned, truncated: truncated, valid: true}, nil
}

func (*OutcomeCompleted) sealedExecutionOutcome() {}
func (o *OutcomeCompleted) IsValid() bool {
	return o != nil && o.valid && o.status != nil && o.status.IsValid()
}
func (o *OutcomeCompleted) Kind() OutcomeKind {
	return pickIf(o.IsValid(), OutcomeKindCompleted, OutcomeKindInvalid)
}

// CanRetry 已完成执行恒返回 false。
func (*OutcomeCompleted) CanRetry() bool { return false }

// Status 返回终止状态副本；无效零值失败关闭返回 nil。
func (o *OutcomeCompleted) Status() ExitStatus {
	if !o.IsValid() {
		return nil
	}
	return copyValidExitStatus(o.status)
}

// Truncated 报告命令输出是否触发上限截断。
func (o *OutcomeCompleted) Truncated() bool { return o.IsValid() && o.truncated }

// Succeeded 当且仅当结果有效且退出状态为显式退出码 0 时返回 true。
func (o *OutcomeCompleted) Succeeded() bool { return o.IsValid() && o.status.IsSuccess() }

// OutcomeUnknown 表示启动请求已发出但未取得确定终态（副作用可能已发生，严禁自动重试）。
//
//xops:opaque
//xops:failclosed
type OutcomeUnknown struct {
	phase  ExecPhase
	code   string
	reason string
	valid  bool
}

// NewOutcomeUnknown 校验执行阶段与错误代码并构造 *OutcomeUnknown。
func NewOutcomeUnknown(phase ExecPhase, code, reason string) (*OutcomeUnknown, error) {
	if !phase.IsValid() {
		return nil, domi18n.WrapSentinel(ErrInvalidExecutionOutcome, ErrInvalidPhase)
	}
	if code != "" && !isValidASCIICode(code, maxCodeLen) {
		return nil, domi18n.EF(ErrInvalidExecutionOutcome, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "code"), domi18n.BoundStr("value", code))
	}
	return &OutcomeUnknown{
		phase: phase, code: code, reason: security.SanitizePromptText(reason), valid: true,
	}, nil
}

func (*OutcomeUnknown) sealedExecutionOutcome() {}
func (o *OutcomeUnknown) IsValid() bool         { return o != nil && o.valid && o.phase.IsValid() }
func (o *OutcomeUnknown) Kind() OutcomeKind {
	return pickIf(o.IsValid(), OutcomeKindUnknown, OutcomeKindInvalid)
}

// CanRetry 结果未知恒返回 false（严禁自动重放以防重复副作用）。
func (*OutcomeUnknown) CanRetry() bool { return false }
func (o *OutcomeUnknown) Phase() ExecPhase {
	if !o.IsValid() {
		return ExecPhaseUnknown
	}
	return o.phase
}
func (o *OutcomeUnknown) Code() string {
	if !o.IsValid() {
		return ""
	}
	return o.code
}
func (o *OutcomeUnknown) Reason() string {
	if !o.IsValid() {
		return ""
	}
	return o.reason
}

// CanRetryOutcome 穷尽判定任意 ExecutionOutcome 是否允许安全重试；仅有效 *OutcomeNotStarted 返回 true。
func CanRetryOutcome(o ExecutionOutcome) bool {
	if o == nil {
		return false
	}
	switch v := o.(type) {
	case *OutcomeNotStarted:
		return v.IsValid()
	case *OutcomeCompleted:
		return false
	case *OutcomeUnknown:
		return false
	default:
		return false
	}
}

// EqualOutcome 严格比较两个 ExecutionOutcome 是否均有效且完全一致（nil 或零值恒返回 false）。
func EqualOutcome(a, b ExecutionOutcome) bool {
	if a == nil || b == nil || !a.IsValid() || !b.IsValid() {
		return false
	}
	switch va := a.(type) {
	case *OutcomeNotStarted:
		vb, ok := b.(*OutcomeNotStarted)
		return ok && vb.IsValid() && va.phase == vb.phase && va.code == vb.code && va.reason == vb.reason
	case *OutcomeCompleted:
		vb, ok := b.(*OutcomeCompleted)
		return ok && vb.IsValid() && va.truncated == vb.truncated && EqualExitStatus(va.status, vb.status)
	case *OutcomeUnknown:
		vb, ok := b.(*OutcomeUnknown)
		return ok && vb.IsValid() && va.phase == vb.phase && va.code == vb.code && va.reason == vb.reason
	default:
		return false
	}
}
