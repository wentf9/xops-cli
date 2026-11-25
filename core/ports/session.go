package ports

import (
	"context"
	"fmt"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/secret"
)

const (
	// TUNUnitAny 表示由对端动态分配 TUN/TAP 单元号（对应 OpenSSH -w any:any）。
	TUNUnitAny uint32 = 0x7fffffff
	maxTUNUnit uint32 = 4096
)

// TUNMode 标识 OpenSSH tun@openssh.com 隧道工作模式（L3 点对点 / L2 以太网）；零值 TUNModeInvalid 失败关闭。
//
//xops:opaque
//xops:failclosed
type TUNMode uint8

const (
	TUNModeInvalid      TUNMode = iota // 无效模式（零值失败关闭）
	TUNModePointToPoint                // L3 点对点 IP 隧道（tun）
	TUNModeEthernet                    // L2 以太网帧隧道（tap）
)

// TUNSpec 描述 OpenSSH tun@openssh.com 通道规格（模式与本地/远端单元号）；零值恒无效。
//
//xops:opaque
//xops:failclosed
type TUNSpec struct {
	mode                  TUNMode
	localUnit, remoteUnit uint32
	valid                 bool
}

// NewTUNSpec 校验 TUN 模式与合法单元号（0..4096 或 TUNUnitAny）并构造不可变 TUNSpec。
func NewTUNSpec(mode TUNMode, localUnit, remoteUnit uint32) (TUNSpec, error) {
	if !mode.IsValid() || !isValidTUNUnit(localUnit) || !isValidTUNUnit(remoteUnit) {
		return TUNSpec{}, fmt.Errorf("%w: TUNSpec 模式或单元号非法", ErrInvalidArgument)
	}
	return TUNSpec{mode: mode, localUnit: localUnit, remoteUnit: remoteUnit, valid: true}, nil
}
func isValidTUNUnit(u uint32) bool { return u <= maxTUNUnit || u == TUNUnitAny }
func (s TUNSpec) IsValid() bool {
	return s.valid && s.mode.IsValid() && isValidTUNUnit(s.localUnit) && isValidTUNUnit(s.remoteUnit)
}
func (s TUNSpec) IsZero() bool       { return !s.IsValid() }
func (s TUNSpec) Mode() TUNMode      { return pickIf(s.IsValid(), s.mode, TUNModeInvalid) }
func (s TUNSpec) LocalUnit() uint32  { return pickIf(s.IsValid(), s.localUnit, 0) }
func (s TUNSpec) RemoteUnit() uint32 { return pickIf(s.IsValid(), s.remoteUnit, 0) }
func (s TUNSpec) Equal(o TUNSpec) bool {
	return s.IsValid() && o.IsValid() && s.mode == o.mode && s.localUnit == o.localUnit && s.remoteUnit == o.remoteUnit
}

// ForwardHandle 表示一条受管长生命周期隧道转发实例（天然满足 core/internal/pool.ManagedResource），
// 可直接交由 pool.RegisterLeaseHandle 纳入世代句柄生命周期、跳板钉选与断连联动撤销。
type ForwardHandle interface {
	IsValid() bool
	Spec() ForwardSpec
	BoundAddr() string
	Done() <-chan struct{}
	Err() error
	Close() error
}

// ForwarderPort 定义 SSH 端口转发（-L/-R/-D）、StreamLocal 与 TUN 启动出站端口（P3-T2 <-> P4-T1 sshnet/forward）。
type ForwarderPort interface {
	StartForward(ctx context.Context, transport TunnelTransport, spec ForwardSpec) (ForwardHandle, error)
}

// PrivilegeMethod 标识远端提权执行协议类别（sudo/su/doas）；零值 PrivilegeMethodInvalid 失败关闭。
//
//xops:opaque
//xops:failclosed
type PrivilegeMethod uint8

const (
	PrivilegeMethodInvalid PrivilegeMethod = iota // 无效提权方式（零值失败关闭）
	PrivilegeMethodSudo                           // POSIX sudo 提权
	PrivilegeMethodSu                             // POSIX su 提权
	PrivilegeMethodDoas                           // OpenBSD/Linux doas 提权
)

// PrivilegeRequestSpec 是构造不可变 PrivilegeRequest 的显式入参规格（严禁携带 SecretBox）。
type PrivilegeRequestSpec struct {
	Method         PrivilegeMethod                      `json:"method"`
	Command        execution.CommandPlan                `json:"command"`
	TargetUser     algebraic.Option[option.Username]    `json:"target_user,omitzero"`
	NonInteractive bool                                 `json:"non_interactive,omitzero"`
	Timeout        algebraic.Option[algebraic.Duration] `json:"timeout,omitzero"`
}

// PrivilegeRequest 描述不含明文凭据的不可变远端提权请求；零值恒无效。
// 提权口令须作为独立借用参数 *secret.SecretBox 经 PrivilegeEscalationPort.RunPrivileged 传入。
//
//xops:opaque
//xops:failclosed
type PrivilegeRequest struct {
	method                PrivilegeMethod
	command               execution.CommandPlan
	targetUser            algebraic.Option[option.Username]
	timeout               algebraic.Option[algebraic.Duration]
	nonInteractive, valid bool
}

// NewPrivilegeRequest 校验提权方式、命令计划、可选目标用户与可选正时长超时并构造不可变 PrivilegeRequest。
func NewPrivilegeRequest(spec PrivilegeRequestSpec) (PrivilegeRequest, error) {
	u, hasU := spec.TargetUser.Get()
	d, hasD := spec.Timeout.Get()
	if !spec.Method.IsValid() || !spec.Command.IsValid() || (hasU && !u.IsValid()) || (hasD && !d.IsPositive()) {
		return PrivilegeRequest{}, fmt.Errorf("%w: PrivilegeRequest 字段无效", ErrInvalidArgument)
	}
	return PrivilegeRequest{method: spec.Method, command: spec.Command, targetUser: spec.TargetUser, nonInteractive: spec.NonInteractive, timeout: spec.Timeout, valid: true}, nil
}
func (r PrivilegeRequest) IsValid() bool { return r.valid && r.method.IsValid() && r.command.IsValid() }
func (r PrivilegeRequest) IsZero() bool  { return !r.IsValid() }
func (r PrivilegeRequest) Method() PrivilegeMethod {
	return pickIf(r.IsValid(), r.method, PrivilegeMethodInvalid)
}
func (r PrivilegeRequest) Command() execution.CommandPlan                { return r.command }
func (r PrivilegeRequest) TargetUser() algebraic.Option[option.Username] { return r.targetUser }
func (r PrivilegeRequest) NonInteractive() bool                          { return r.IsValid() && r.nonInteractive }
func (r PrivilegeRequest) Timeout() algebraic.Option[algebraic.Duration] { return r.timeout }
func (r PrivilegeRequest) Equal(o PrivilegeRequest) bool {
	return r.IsValid() && o.IsValid() && r.method == o.method && r.command.Equal(o.command) &&
		optEqualFunc(r.targetUser, o.targetUser, option.Username.Equal) && r.nonInteractive == o.nonInteractive &&
		optEqualFunc(r.timeout, o.timeout, algebraic.Duration.Equal)
}

// PrivilegeEscalationPort 定义远端提权执行（sudo/su/doas）出站端口（P3-T2 <-> P4-T1 sshnet/priv）。
// 仅 sshnet/priv 与 sim 列入明文消费白名单；RunPrivileged 无回调参数，password 由 secretbox Rule 1
// 与具体实现上的参数级 //xops:borrowed 共同强制零逃逸（严禁跨调用留存 opener 或 password）。
type PrivilegeEscalationPort interface {
	// RunPrivileged 通过 opener 打开远端会话并按 req 执行提权命令，流向 streams 并返回封闭 ExecutionOutcome。
	RunPrivileged(ctx context.Context, opener SessionOpener, req PrivilegeRequest, password *secret.SecretBox, streams ExecStreams) (execution.ExecutionOutcome, error)
}

// ShellProbeResultSpec 是构造不可变 ShellProbeResult 的显式入参规格。
type ShellProbeResultSpec struct {
	Dialect     execution.LaunchDialect `json:"dialect"`
	Interpreter execution.Interpreter   `json:"interpreter"`
	OSFamily    string                  `json:"os_family,omitzero"`
	ProbeStage  uint8                   `json:"probe_stage"`
	RawBanner   string                  `json:"raw_banner,omitzero"`
}

// ShellProbeResult 表示远端两阶段 Shell 探测产出的已校验启动方言与解释器快照；零值恒无效。
//
//xops:opaque
//xops:failclosed
type ShellProbeResult struct {
	profile             execution.LaunchProfile
	dialect             execution.LaunchDialect
	osFamily, rawBanner string
	probeStage          uint8
	valid               bool
}

// NewShellProbeResult 校验方言/解释器兼容性矩阵、探测阶段（1 或 2）与可选元信息并构造不可变结果。
func NewShellProbeResult(spec ShellProbeResultSpec) (ShellProbeResult, error) {
	if !spec.Dialect.IsValid() || !spec.Interpreter.IsValid() || (spec.ProbeStage != 1 && spec.ProbeStage != 2) ||
		(spec.OSFamily != "" && !isValidASCIIToken(spec.OSFamily, maxPortTokenLen)) {
		return ShellProbeResult{}, fmt.Errorf("%w: ShellProbeResult 方言/解释器/阶段或 os_family 非法", ErrInvalidArgument)
	}
	profile, e1 := execution.NewLaunchProfile(execution.LaunchProfileSpec{Dialect: algebraic.Some(spec.Dialect), Interpreter: spec.Interpreter, Login: execution.LoginModeInherit})
	banner, e2 := sanitizeBoundedText(spec.RawBanner, maxPortDetailBytes, true, ErrInvalidArgument)
	if err := firstErr(e1, e2); err != nil {
		return ShellProbeResult{}, fmt.Errorf("%w: %w", ErrInvalidArgument, err)
	}
	return ShellProbeResult{profile: profile, dialect: spec.Dialect, osFamily: spec.OSFamily, probeStage: spec.ProbeStage, rawBanner: banner, valid: true}, nil
}
func (r ShellProbeResult) IsValid() bool {
	return r.valid && r.profile.IsValid() && r.dialect.IsValid()
}
func (r ShellProbeResult) IsZero() bool { return !r.IsValid() }
func (r ShellProbeResult) Dialect() execution.LaunchDialect {
	return pickIf(r.IsValid(), r.dialect, execution.DialectUnknown)
}
func (r ShellProbeResult) Interpreter() execution.Interpreter {
	return pickIf(r.IsValid(), r.profile.Interpreter(), execution.InterpreterInvalid)
}
func (r ShellProbeResult) LaunchProfile() execution.LaunchProfile {
	return pickIf(r.IsValid(), r.profile, zeroVal[execution.LaunchProfile]())
}
func (r ShellProbeResult) OSFamily() string  { return r.osFamily }
func (r ShellProbeResult) ProbeStage() uint8 { return pickIf(r.IsValid(), r.probeStage, 0) }
func (r ShellProbeResult) RawBanner() string { return r.rawBanner }
func (r ShellProbeResult) Equal(o ShellProbeResult) bool {
	return r.IsValid() && o.IsValid() && r.profile.Equal(o.profile) && r.dialect == o.dialect && r.osFamily == o.osFamily && r.probeStage == o.probeStage && r.rawBanner == o.rawBanner
}

// ShellProbePort 定义远端默认启动方言与解释器两阶段探测出站端口（P3-T2 <-> P4-T1 sshnet/probe）。
type ShellProbePort interface {
	ProbeShell(ctx context.Context, opener SessionOpener) (ShellProbeResult, error)
}
