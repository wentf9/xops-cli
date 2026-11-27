package execution

import (
	"strings"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/security"
)

// ExitStatusKind 标识 ExitStatus 的判别类别；零值 ExitStatusKindInvalid 失败关闭。
//
//xops:opaque
//xops:failclosed
type ExitStatusKind uint8

const (
	ExitStatusKindInvalid ExitStatusKind = iota // 无效退出状态（零值失败关闭）
	ExitStatusKindCode                          // 显式整数退出码（*ExitCode）
	ExitStatusKindSignal                        // 信号终止（*ExitSignal）
	ExitStatusKindUnknown                       // 远端关闭通道但未回报退出码或信号（*ExitUnknown）
)

// ParseExitStatusKind 严格解析退出状态类别（"code"、"signal"、"unknown"）。
func ParseExitStatusKind(raw string) (ExitStatusKind, error) {
	if !hasForbiddenStrictText(raw) {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "code":
			return ExitStatusKindCode, nil
		case "signal":
			return ExitStatusKindSignal, nil
		case "unknown":
			return ExitStatusKindUnknown, nil
		}
	}
	return ExitStatusKindInvalid, domi18n.EF(ErrInvalidExitStatus, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "exit_status.kind"), domi18n.BoundStr("value", raw))
}

// IsValid 报告 k 是否为合法退出状态类别。
func (k ExitStatusKind) IsValid() bool { return k >= ExitStatusKindCode && k <= ExitStatusKindUnknown }

// IsZero 报告 k 是否为无效零值。
func (k ExitStatusKind) IsZero() bool { return k == ExitStatusKindInvalid }

// String 返回退出状态类别的规范小写文本。
func (k ExitStatusKind) String() string {
	return enumName(uint8(k), "invalid", "invalid", "code", "signal", "unknown")
}

// AppendText 实现 encoding.TextAppender（值接收者）；对非法值失败关闭。
func (k ExitStatusKind) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, k.IsValid(), k.String(), ErrInvalidExitStatus, uint8(k))
}

// MarshalText 实现 encoding.TextMarshaler（值接收者）。
func (k ExitStatusKind) MarshalText() ([]byte, error) { return k.AppendText(nil) }

// UnmarshalText 实现 encoding.TextUnmarshaler；失败时重置为 ExitStatusKindInvalid 并失败关闭。
func (k *ExitStatusKind) UnmarshalText(text []byte) error {
	return unmarshalTextWithReset(k, ExitStatusKindInvalid, text, ParseExitStatusKind)
}

// ExitStatus 是命令终止状态的封闭代数和类型（*ExitCode | *ExitSignal | *ExitUnknown）。
// 缺失退出状态绝不等价于退出码 0；仅有效 *ExitCode(0) 的 IsSuccess() 为 true。
//
//xops:failclosed
type ExitStatus interface {
	sealedExitStatus()
	Kind() ExitStatusKind
	IsValid() bool
	IsSuccess() bool
}

// ExitCode 表示远端显式回报的整数退出码（兼容 POSIX 0..255 与 Windows int32 退出码）。
//
//xops:opaque
//xops:failclosed
type ExitCode struct {
	code  int32
	valid bool
}

// NewExitCode 构造携带显式退出码的不可变 *ExitCode。
func NewExitCode(code int32) *ExitCode { return &ExitCode{code: code, valid: true} }

func (*ExitCode) sealedExitStatus() {}

// IsValid 报告 *ExitCode 是否经构造器合法初始化。
func (e *ExitCode) IsValid() bool { return e != nil && e.valid }

// Kind 有效时返回 ExitStatusKindCode，无效时失败关闭返回 ExitStatusKindInvalid。
func (e *ExitCode) Kind() ExitStatusKind {
	return pickIf(e.IsValid(), ExitStatusKindCode, ExitStatusKindInvalid)
}

// Code 返回退出码与有效性标志；无效零值返回 (0, false) 以防与退出码 0 混淆。
func (e *ExitCode) Code() (int32, bool) {
	if !e.IsValid() {
		return 0, false
	}
	return e.code, true
}

// IsSuccess 当且仅当有效且退出码显式为 0 时返回 true。
func (e *ExitCode) IsSuccess() bool { return e.IsValid() && e.code == 0 }

// ExitSignal 表示远端进程因 POSIX 信号终止（RFC 4254 exit-signal）。
//
//xops:opaque
//xops:failclosed
type ExitSignal struct {
	signal     string
	coreDumped bool
	message    string
	valid      bool
}

// NewExitSignal 校验信号名称（长度 1..32 的大写 ASCII 信号标识）并构造 *ExitSignal。
func NewExitSignal(signal string, coreDumped bool, message string) (*ExitSignal, error) {
	norm := strings.ToUpper(strings.TrimSpace(signal))
	if !isValidSignalName(norm) {
		return nil, domi18n.EF(ErrInvalidExitStatus, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "signal"), domi18n.BoundStr("value", signal))
	}
	return &ExitSignal{
		signal: norm, coreDumped: coreDumped,
		message: security.SanitizePromptText(message), valid: true,
	}, nil
}

func isValidSignalName(s string) bool {
	if len(s) == 0 || len(s) > maxSignalNameLen {
		return false
	}
	for i := range len(s) {
		c := s[i]
		ok := (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}

func (*ExitSignal) sealedExitStatus() {}

// IsValid 报告 *ExitSignal 是否有效。
func (e *ExitSignal) IsValid() bool { return e != nil && e.valid && e.signal != "" }

// Kind 有效时返回 ExitStatusKindSignal，无效时返回 ExitStatusKindInvalid。
func (e *ExitSignal) Kind() ExitStatusKind {
	return pickIf(e.IsValid(), ExitStatusKindSignal, ExitStatusKindInvalid)
}

// Signal 返回规范化信号名（如 "KILL"、"TERM"）；无效返回空串。
func (e *ExitSignal) Signal() string {
	if !e.IsValid() {
		return ""
	}
	return e.signal
}

// CoreDumped 报告服务端是否声明产生了 core dump。
func (e *ExitSignal) CoreDumped() bool { return e.IsValid() && e.coreDumped }

// Message 返回经脱敏的信号终止附加说明。
func (e *ExitSignal) Message() string {
	if !e.IsValid() {
		return ""
	}
	return e.message
}

// IsSuccess 信号终止恒返回 false。
func (*ExitSignal) IsSuccess() bool { return false }

// ExitUnknown 表示远端会话结束但未回报退出码或信号（例如缺失 exit-status 帧）。
//
//xops:opaque
//xops:failclosed
type ExitUnknown struct {
	reason string
	valid  bool
}

// NewExitUnknown 构造携带脱敏原因说明的 *ExitUnknown。
func NewExitUnknown(reason string) *ExitUnknown {
	return &ExitUnknown{reason: security.SanitizePromptText(reason), valid: true}
}

func (*ExitUnknown) sealedExitStatus() {}

// IsValid 报告 *ExitUnknown 是否有效。
func (e *ExitUnknown) IsValid() bool { return e != nil && e.valid }

// Kind 有效时返回 ExitStatusKindUnknown，无效时返回 ExitStatusKindInvalid。
func (e *ExitUnknown) Kind() ExitStatusKind {
	return pickIf(e.IsValid(), ExitStatusKindUnknown, ExitStatusKindInvalid)
}

// Reason 返回脱敏原因文本；无效返回空串。
func (e *ExitUnknown) Reason() string {
	if !e.IsValid() {
		return ""
	}
	return e.reason
}

// IsSuccess 未知退出状态恒返回 false（绝不将缺失退出码推断为成功）。
func (*ExitUnknown) IsSuccess() bool { return false }

// EqualExitStatus 严格比较两个 ExitStatus 是否均有效且完全一致（nil 或零值恒返回 false）。
func EqualExitStatus(a, b ExitStatus) bool {
	if a == nil || b == nil || !a.IsValid() || !b.IsValid() {
		return false
	}
	switch va := a.(type) {
	case *ExitCode:
		vb, ok := b.(*ExitCode)
		return ok && vb.IsValid() && va.code == vb.code
	case *ExitSignal:
		vb, ok := b.(*ExitSignal)
		return ok && vb.IsValid() && va.signal == vb.signal && va.coreDumped == vb.coreDumped && va.message == vb.message
	case *ExitUnknown:
		vb, ok := b.(*ExitUnknown)
		return ok && vb.IsValid() && va.reason == vb.reason
	default:
		return false
	}
}

func cloneExitStatus(s ExitStatus) (ExitStatus, error) {
	if s == nil || !s.IsValid() {
		return nil, ErrInvalidExitStatus
	}
	switch v := s.(type) {
	case *ExitCode:
		return &ExitCode{code: v.code, valid: true}, nil
	case *ExitSignal:
		return &ExitSignal{signal: v.signal, coreDumped: v.coreDumped, message: v.message, valid: true}, nil
	case *ExitUnknown:
		return &ExitUnknown{reason: v.reason, valid: true}, nil
	default:
		return nil, ErrInvalidExitStatus
	}
}

func copyValidExitStatus(s ExitStatus) ExitStatus {
	switch v := s.(type) {
	case *ExitCode:
		return &ExitCode{code: v.code, valid: true}
	case *ExitSignal:
		return &ExitSignal{signal: v.signal, coreDumped: v.coreDumped, message: v.message, valid: true}
	case *ExitUnknown:
		return &ExitUnknown{reason: v.reason, valid: true}
	default:
		return nil
	}
}
