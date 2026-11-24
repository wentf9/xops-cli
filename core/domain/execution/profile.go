package execution

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"io"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
)

const launchProfileDomainTag = "xops.execution.launch_profile.v1"

// LaunchDialect 表示 SSH 服务端用于解析外层启动命令的方言；零值 DialectUnknown 失败关闭。
//
//xops:opaque
//xops:failclosed
type LaunchDialect uint8

const (
	DialectUnknown    LaunchDialect = iota // 未知服务端方言（零值；仅 server 直通允许）
	DialectPOSIX                           // POSIX Bourne 兼容启动方言（sh/bash/zsh/dash/ash）
	DialectPowerShell                      // Windows/跨平台 PowerShell 启动方言
	DialectCmd                             // Windows cmd.exe 启动方言
	DialectRaw                             // 原始直通方言（不执行任何外层壳引用或包装）
)

// ParseLaunchDialect 严格解析规范小写启动方言名称（"posix"、"powershell"、"cmd"、"raw"）。
func ParseLaunchDialect(raw string) (LaunchDialect, error) {
	if !hasForbiddenStrictText(raw) {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "posix":
			return DialectPOSIX, nil
		case "powershell":
			return DialectPowerShell, nil
		case "cmd":
			return DialectCmd, nil
		case "raw":
			return DialectRaw, nil
		}
	}
	return DialectUnknown, fmt.Errorf("%w: %q", ErrInvalidLaunchDialect, raw)
}

// IsValid 报告 d 是否为已明确声明的合法启动方言（不含零值 DialectUnknown）。
func (d LaunchDialect) IsValid() bool { return d >= DialectPOSIX && d <= DialectRaw }

// IsZero 报告 d 是否处于未知零值状态。
func (d LaunchDialect) IsZero() bool { return d == DialectUnknown }

// String 返回启动方言的规范小写文本；零值返回 "unknown"。
func (d LaunchDialect) String() string {
	return enumName(uint8(d), "unknown", "unknown", "posix", "powershell", "cmd", "raw")
}

// AppendText 实现 encoding.TextAppender（值接收者）；对零值/非法值失败关闭。
func (d LaunchDialect) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, d.IsValid(), d.String(), ErrInvalidLaunchDialect, uint8(d))
}

// MarshalText 实现 encoding.TextMarshaler（值接收者）。
func (d LaunchDialect) MarshalText() ([]byte, error) { return d.AppendText(nil) }

// UnmarshalText 实现 encoding.TextUnmarshaler；失败时重置为 DialectUnknown 并失败关闭。
func (d *LaunchDialect) UnmarshalText(text []byte) error {
	return unmarshalTextWithReset(d, DialectUnknown, text, ParseLaunchDialect)
}

// Interpreter 表示命令或脚本执行时使用的远端解释器；零值 InterpreterInvalid 失败关闭。
//
//xops:opaque
//xops:failclosed
type Interpreter uint8

const (
	InterpreterInvalid    Interpreter = iota // 无效解释器（零值失败关闭）
	InterpreterServer                        // 服务端默认直通（原样发送 SSH exec 载荷）
	InterpreterSH                            // POSIX /bin/sh 解释器
	InterpreterBash                          // GNU Bash 解释器
	InterpreterZsh                           // Zsh 解释器
	InterpreterPowerShell                    // Windows powershell.exe
	InterpreterPwsh                          // 跨平台 PowerShell Core (pwsh)
	InterpreterCmd                           // Windows cmd.exe
)

// ParseInterpreter 严格解析规范解释器标识（server/sh/bash/zsh/powershell/pwsh/cmd）。
func ParseInterpreter(raw string) (Interpreter, error) {
	if !hasForbiddenStrictText(raw) {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "server":
			return InterpreterServer, nil
		case "sh":
			return InterpreterSH, nil
		case "bash":
			return InterpreterBash, nil
		case "zsh":
			return InterpreterZsh, nil
		case "powershell":
			return InterpreterPowerShell, nil
		case "pwsh":
			return InterpreterPwsh, nil
		case "cmd":
			return InterpreterCmd, nil
		}
	}
	return InterpreterInvalid, fmt.Errorf("%w: %q", ErrInvalidInterpreter, raw)
}

// IsValid 报告 i 是否为受支持的合法解释器。
func (i Interpreter) IsValid() bool { return i >= InterpreterServer && i <= InterpreterCmd }

// IsZero 报告 i 是否为无效零值。
func (i Interpreter) IsZero() bool { return i == InterpreterInvalid }

// IsPOSIXShell 报告解释器本身是否属于 POSIX Bourne 族（sh/bash/zsh）。
func (i Interpreter) IsPOSIXShell() bool {
	return i == InterpreterSH || i == InterpreterBash || i == InterpreterZsh
}

// IsPowerShell 报告解释器是否为 powershell 或 pwsh。
func (i Interpreter) IsPowerShell() bool {
	return i == InterpreterPowerShell || i == InterpreterPwsh
}

// String 返回解释器规范小写标识；非法值返回 "invalid"。
func (i Interpreter) String() string {
	return enumName(uint8(i), "invalid", "invalid", "server", "sh", "bash", "zsh", "powershell", "pwsh", "cmd")
}

// AppendText 实现 encoding.TextAppender（值接收者）；对非法值失败关闭。
func (i Interpreter) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, i.IsValid(), i.String(), ErrInvalidInterpreter, uint8(i))
}

// MarshalText 实现 encoding.TextMarshaler（值接收者）。
func (i Interpreter) MarshalText() ([]byte, error) { return i.AppendText(nil) }

// UnmarshalText 实现 encoding.TextUnmarshaler；失败时重置为 InterpreterInvalid 并失败关闭。
func (i *Interpreter) UnmarshalText(text []byte) error {
	return unmarshalTextWithReset(i, InterpreterInvalid, text, ParseInterpreter)
}

// LoginMode 表示显式解释器的登录环境模式；零值 LoginModeUnset 失败关闭。
//
//xops:opaque
//xops:failclosed
type LoginMode uint8

const (
	LoginModeUnset    LoginMode = iota // 未初始化零值（失败关闭）
	LoginModeDisabled                  // 显式关闭登录 Shell（non-login）
	LoginModeLogin                     // 显式启用登录 Shell（如 bash -l / zsh -l）
	LoginModeInherit                   // 继承服务端或解释器默认行为（不主动注入登录标志）
)

// ParseLoginMode 严格解析登录模式（支持 canonical: "disabled"/"login"/"inherit" 及常见等价别名）。
func ParseLoginMode(raw string) (LoginMode, error) {
	if !hasForbiddenStrictText(raw) {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "disabled", "non_login", "non-login", "false":
			return LoginModeDisabled, nil
		case "login", "enabled", "true":
			return LoginModeLogin, nil
		case "inherit":
			return LoginModeInherit, nil
		}
	}
	return LoginModeUnset, fmt.Errorf("%w: %q", ErrInvalidLoginMode, raw)
}

// IsValid 报告 m 是否为合法登录模式。
func (m LoginMode) IsValid() bool { return m >= LoginModeDisabled && m <= LoginModeInherit }

// IsZero 报告 m 是否为未初始化零值。
func (m LoginMode) IsZero() bool { return m == LoginModeUnset }

// String 返回登录模式规范小写文本；未初始化返回 "unset"。
func (m LoginMode) String() string {
	return enumName(uint8(m), "unset", "unset", "disabled", "login", "inherit")
}

// AppendText 实现 encoding.TextAppender（值接收者）；对零值/非法值失败关闭。
func (m LoginMode) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, m.IsValid(), m.String(), ErrInvalidLoginMode, uint8(m))
}

// MarshalText 实现 encoding.TextMarshaler（值接收者）。
func (m LoginMode) MarshalText() ([]byte, error) { return m.AppendText(nil) }

// UnmarshalText 实现 encoding.TextUnmarshaler；失败时重置为 LoginModeUnset 并失败关闭。
func (m *LoginMode) UnmarshalText(text []byte) error {
	return unmarshalTextWithReset(m, LoginModeUnset, text, ParseLoginMode)
}

// LaunchProfileSpec 是构造不可变 LaunchProfile 的显式入参规格。
type LaunchProfileSpec struct {
	Dialect     algebraic.Option[LaunchDialect]
	Interpreter Interpreter
	Login       LoginMode
}

// LaunchProfile 表示经过兼容性矩阵校验的不可变命令启动配置（方言 × 解释器 × 登录模式）；
// 零值恒无效并失败关闭，且经 //xops:canonicalhash 校验全字段规范摘要覆盖。
//
//xops:opaque
//xops:failclosed
//xops:canonicalhash
type LaunchProfile struct {
	dialect     algebraic.Option[LaunchDialect]
	interpreter Interpreter
	login       LoginMode
	valid       bool
}

// DefaultServerLaunchProfile 返回默认服务端直通启动配置（DialectUnknown + server + inherit）。
func DefaultServerLaunchProfile() LaunchProfile {
	return LaunchProfile{
		dialect:     algebraic.None[LaunchDialect](),
		interpreter: InterpreterServer,
		login:       LoginModeInherit,
		valid:       true,
	}
}

// POSIXLaunchProfile 便捷构造 POSIX 启动方言下指定解释器与登录模式的不可变 LaunchProfile。
func POSIXLaunchProfile(interp Interpreter, login LoginMode) (LaunchProfile, error) {
	return NewLaunchProfile(LaunchProfileSpec{
		Dialect:     algebraic.Some(DialectPOSIX),
		Interpreter: interp,
		Login:       login,
	})
}

// NewLaunchProfile 按严格兼容性矩阵校验并构造不可变 LaunchProfile。
func NewLaunchProfile(spec LaunchProfileSpec) (LaunchProfile, error) {
	if !spec.Interpreter.IsValid() {
		return LaunchProfile{}, fmt.Errorf("%w: %w", ErrInvalidLaunchProfile, ErrInvalidInterpreter)
	}
	if !spec.Login.IsValid() {
		return LaunchProfile{}, fmt.Errorf("%w: %w", ErrInvalidLaunchProfile, ErrInvalidLoginMode)
	}
	dialect, hasDialect := spec.Dialect.Get()
	if hasDialect && !dialect.IsValid() {
		return LaunchProfile{}, fmt.Errorf("%w: %w", ErrInvalidLaunchProfile, ErrInvalidLaunchDialect)
	}
	if err := validateProfileCombination(dialect, hasDialect, spec.Interpreter, spec.Login); err != nil {
		return LaunchProfile{}, err
	}
	return LaunchProfile{
		dialect:     spec.Dialect,
		interpreter: spec.Interpreter,
		login:       spec.Login,
		valid:       true,
	}, nil
}

func validateProfileCombination(dialect LaunchDialect, hasDialect bool, interp Interpreter, login LoginMode) error {
	switch interp {
	case InterpreterServer:
		if login != LoginModeInherit {
			return fmt.Errorf("%w: server 解释器仅允许 login=inherit", ErrUnsupportedExecutionCombination)
		}
		return nil
	case InterpreterSH, InterpreterBash, InterpreterZsh:
		return validatePOSIXProfile(dialect, hasDialect, interp, login)
	case InterpreterPowerShell, InterpreterPwsh:
		return validatePowerShellProfile(dialect, hasDialect, interp, login)
	case InterpreterCmd:
		return validateCmdProfile(dialect, hasDialect, login)
	default:
		return fmt.Errorf("%w: 未知解释器 %d", ErrInvalidLaunchProfile, uint8(interp))
	}
}

func validatePOSIXProfile(dialect LaunchDialect, hasDialect bool, interp Interpreter, login LoginMode) error {
	if !hasDialect || dialect != DialectPOSIX {
		return fmt.Errorf("%w: %s 要求 launch_dialect=posix", ErrUnsupportedExecutionCombination, interp)
	}
	if interp == InterpreterSH && login == LoginModeLogin {
		return fmt.Errorf("%w: sh 不支持 login=login", ErrUnsupportedExecutionCombination)
	}
	return nil
}

func validatePowerShellProfile(dialect LaunchDialect, hasDialect bool, interp Interpreter, login LoginMode) error {
	if !hasDialect || dialect == DialectRaw || login == LoginModeLogin {
		return fmt.Errorf("%w: %s 要求已知非 raw 方言且不支持 POSIX login=login", ErrUnsupportedExecutionCombination, interp)
	}
	return nil
}

func validateCmdProfile(dialect LaunchDialect, hasDialect bool, login LoginMode) error {
	if !hasDialect || dialect != DialectCmd || login == LoginModeLogin {
		return fmt.Errorf("%w: cmd 要求 launch_dialect=cmd 且不支持 login=login", ErrUnsupportedExecutionCombination)
	}
	return nil
}

// IsValid 报告 LaunchProfile 是否经构造器合法初始化。
func (p LaunchProfile) IsValid() bool {
	return p.valid && p.interpreter.IsValid() && p.login.IsValid()
}

// IsZero 报告 LaunchProfile 是否为无效零值。
func (p LaunchProfile) IsZero() bool { return !p.IsValid() }

// Dialect 返回生效启动方言；未声明或无效配置返回 DialectUnknown。
func (p LaunchProfile) Dialect() LaunchDialect {
	if !p.IsValid() {
		return DialectUnknown
	}
	return p.dialect.OrElse(DialectUnknown)
}

// DialectOption 返回可选启动方言 Option[LaunchDialect]。
func (p LaunchProfile) DialectOption() algebraic.Option[LaunchDialect] {
	if !p.IsValid() {
		return algebraic.None[LaunchDialect]()
	}
	return p.dialect
}

// Interpreter 返回生效解释器；无效零值返回 InterpreterInvalid。
func (p LaunchProfile) Interpreter() Interpreter {
	return pickIf(p.IsValid(), p.interpreter, InterpreterInvalid)
}

// LoginMode 返回生效登录模式；无效零值返回 LoginModeUnset。
func (p LaunchProfile) LoginMode() LoginMode {
	return pickIf(p.IsValid(), p.login, LoginModeUnset)
}

// IsPOSIXBourne 报告当前启动配置是否满足 INV-E4 的 POSIX Bourne 解释器要求
// （即 server+DialectPOSIX，或已知 POSIX 方言下的 sh/bash/zsh）。
func (p LaunchProfile) IsPOSIXBourne() bool {
	if !p.IsValid() {
		return false
	}
	d := p.Dialect()
	if p.interpreter == InterpreterServer {
		return d == DialectPOSIX
	}
	return d == DialectPOSIX && p.interpreter.IsPOSIXShell()
}

// ValidatePOSIXBourne 校验当前配置是否满足 POSIX Bourne 要求，不满足时返回 ErrNotPOSIXBourne。
func (p LaunchProfile) ValidatePOSIXBourne() error {
	if !p.IsPOSIXBourne() {
		return fmt.Errorf("%w: dialect=%s interpreter=%s", ErrNotPOSIXBourne, p.Dialect(), p.Interpreter())
	}
	return nil
}

// Equal 严格比对两个 LaunchProfile 是否均有效且三元组完全一致（无效零值永不相等）。
func (p LaunchProfile) Equal(other LaunchProfile) bool {
	return p.IsValid() && other.IsValid() &&
		algebraic.EqualOption(p.dialect, other.dialect) &&
		p.interpreter == other.interpreter &&
		p.login == other.login
}

// WriteCanonical 以零反射、长度前缀与域分离方式写入 LaunchProfile 全字段规范字节流（受 digestcover 校验）。
func (p LaunchProfile) WriteCanonical(w io.Writer) error {
	if w == nil {
		return ErrNilWriter
	}
	if !p.valid || !p.IsValid() {
		return ErrInvalidLaunchProfile
	}
	enc := &canonicalEncoder{w: w}
	enc.writeString(launchProfileDomainTag)
	if d, ok := p.dialect.Get(); ok {
		enc.writeUint8(1)
		enc.writeUint8(uint8(d))
	} else {
		enc.writeUint8(0)
	}
	enc.writeUint8(uint8(p.interpreter))
	enc.writeUint8(uint8(p.login))
	return enc.err
}

type launchProfileWire struct {
	Dialect     algebraic.Option[LaunchDialect] `json:"launch_dialect,omitzero"`
	Interpreter algebraic.Option[Interpreter]   `json:"interpreter"`
	Login       algebraic.Option[LoginMode]     `json:"login"`
}

// MarshalJSONTo 实现 encoding/json/v2.MarshalerTo（值接收者）；对零值失败关闭。
func (p LaunchProfile) MarshalJSONTo(enc *jsontext.Encoder) error {
	if !p.IsValid() {
		return ErrInvalidLaunchProfile
	}
	return jsonv2.MarshalEncode(enc, launchProfileWire{
		Dialect:     p.dialect,
		Interpreter: algebraic.Some(p.interpreter),
		Login:       algebraic.Some(p.login),
	})
}

// UnmarshalJSONFrom 实现 encoding/json/v2.UnmarshalerFrom；对 JSON null、缺失必需字段或非法组合失败关闭。
func (p *LaunchProfile) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(p, dec, ErrInvalidLaunchProfile, func(w launchProfileWire) (LaunchProfile, error) {
		interp, okI := w.Interpreter.Get()
		login, okL := w.Login.Get()
		if !okI || !okL {
			return LaunchProfile{}, fmt.Errorf("%w: 缺少必需的 interpreter 或 login 字段", ErrInvalidLaunchProfile)
		}
		return NewLaunchProfile(LaunchProfileSpec{
			Dialect:     w.Dialect,
			Interpreter: interp,
			Login:       login,
		})
	})
}
