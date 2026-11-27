package ports

import (
	"context"
	"io"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/secret"
)

// TUNUnitAny 表示由对端动态分配 TUN/TAP 单元号（对应 OpenSSH -w any:any）；maxTUNUnit 为显式单元号上限。
const TUNUnitAny, maxTUNUnit uint32 = 0x7fffffff, 4096

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
		return TUNSpec{}, fieldErr(ErrInvalidArgument, "tun_spec")
	}
	return TUNSpec{mode: mode, localUnit: localUnit, remoteUnit: remoteUnit, valid: true}, nil
}
func isValidTUNUnit(u uint32) bool { return u <= maxTUNUnit || u == TUNUnitAny }
func (s TUNSpec) IsValid() bool {
	return s.valid && s.mode.IsValid() && isValidTUNUnit(s.localUnit) && isValidTUNUnit(s.remoteUnit)
}
func (s TUNSpec) IsZero() bool       { return !s.IsValid() }
func (s TUNSpec) Mode() TUNMode      { return orZero(s.IsValid(), s.mode) }
func (s TUNSpec) LocalUnit() uint32  { return orZero(s.IsValid(), s.localUnit) }
func (s TUNSpec) RemoteUnit() uint32 { return orZero(s.IsValid(), s.remoteUnit) }
func (s TUNSpec) Equal(o TUNSpec) bool {
	return s.IsValid() && o.IsValid() && s.mode == o.mode && s.localUnit == o.localUnit && s.remoteUnit == o.remoteUnit
}

// TUNDevicePort 定义本机 TUN/TAP 虚拟网卡打开出站端口（P4-T4 internal/host/sys <-> P4-T2 sshnet/forward），隔离平台系统调用。
type TUNDevicePort interface {
	// OpenLocalTUN 按 spec 打开本机 TUN/TAP 设备，返回双向帧流与操作系统实际分配的接口名（如 "tun0"/"utun3"）。
	OpenLocalTUN(ctx context.Context, spec TUNSpec) (dev io.ReadWriteCloser, ifaceName string, err error)
}

// ForwardHandle 表示受管长生命周期隧道转发实例（满足 pool.ManagedResource），经 pool.RegisterLeaseHandleWith 纳入世代撤销与跳板钉选。
type ForwardHandle interface {
	IsValid() bool
	Spec() ForwardSpec
	BoundAddr() string
	Done() <-chan struct{}
	Err() error
	Close() error
}

// ForwarderPort 定义 SSH 端口转发（-L/-R/-D）、StreamLocal 与 TUN 启动出站端口（P3-T2 <-> P4-T2 sshnet/forward）。
type ForwarderPort interface {
	// StartForward 启动受管隧道转发；transport 持留至 ForwardHandle.Close()（非 //xops:borrowed），须由 pool.RegisterLeaseHandleWith 传入池钉选视图。
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
	s     PrivilegeRequestSpec
	valid bool
}

// NewPrivilegeRequest 校验提权方式、命令计划、可选目标用户与可选正时长超时并构造不可变 PrivilegeRequest。
func NewPrivilegeRequest(spec PrivilegeRequestSpec) (PrivilegeRequest, error) {
	u, hasU := spec.TargetUser.Get()
	d, hasD := spec.Timeout.Get()
	if !spec.Method.IsValid() || !spec.Command.IsValid() || (hasU && !u.IsValid()) || (hasD && !d.IsPositive()) {
		return PrivilegeRequest{}, fieldErr(ErrInvalidArgument, "privilege_request")
	}
	return PrivilegeRequest{s: spec, valid: true}, nil
}
func (r PrivilegeRequest) IsValid() bool {
	return r.valid && r.s.Method.IsValid() && r.s.Command.IsValid()
}
func (r PrivilegeRequest) IsZero() bool                                  { return !r.IsValid() }
func (r PrivilegeRequest) Method() PrivilegeMethod                       { return orZero(r.IsValid(), r.s.Method) }
func (r PrivilegeRequest) Command() execution.CommandPlan                { return r.s.Command }
func (r PrivilegeRequest) TargetUser() algebraic.Option[option.Username] { return r.s.TargetUser }
func (r PrivilegeRequest) NonInteractive() bool                          { return r.IsValid() && r.s.NonInteractive }
func (r PrivilegeRequest) Timeout() algebraic.Option[algebraic.Duration] { return r.s.Timeout }
func (r PrivilegeRequest) Equal(o PrivilegeRequest) bool {
	return r.IsValid() && o.IsValid() && r.s.Method == o.s.Method && r.s.Command.Equal(o.s.Command) && optEqualFunc(r.s.TargetUser, o.s.TargetUser, option.Username.Equal) && r.s.NonInteractive == o.s.NonInteractive && optEqualFunc(r.s.Timeout, o.s.Timeout, algebraic.Duration.Equal)
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
	s       ShellProbeResultSpec
	profile execution.LaunchProfile
	valid   bool
}

// NewShellProbeResult 校验方言/解释器兼容性矩阵、探测阶段（1 或 2）与可选元信息并构造不可变结果。
func NewShellProbeResult(spec ShellProbeResultSpec) (ShellProbeResult, error) {
	if !spec.Dialect.IsValid() || !spec.Interpreter.IsValid() || (spec.ProbeStage != 1 && spec.ProbeStage != 2) ||
		(spec.OSFamily != "" && !isValidASCIIToken(spec.OSFamily, maxPortTokenLen)) {
		return ShellProbeResult{}, fieldErr(ErrInvalidArgument, "shell_probe_result")
	}
	profile, e1 := execution.NewLaunchProfile(execution.LaunchProfileSpec{Dialect: algebraic.Some(spec.Dialect), Interpreter: spec.Interpreter, Login: execution.LoginModeInherit})
	banner, e2 := sanitizeBoundedText(spec.RawBanner, maxPortDetailBytes, true, ErrInvalidArgument)
	if err := firstErr(e1, e2); err != nil {
		return ShellProbeResult{}, domi18n.WrapSentinel(ErrInvalidArgument, err)
	}
	spec.RawBanner = banner
	return ShellProbeResult{s: spec, profile: profile, valid: true}, nil
}
func (r ShellProbeResult) IsValid() bool {
	return r.valid && r.profile.IsValid() && r.s.Dialect.IsValid()
}
func (r ShellProbeResult) IsZero() bool                     { return !r.IsValid() }
func (r ShellProbeResult) Dialect() execution.LaunchDialect { return orZero(r.IsValid(), r.s.Dialect) }
func (r ShellProbeResult) Interpreter() execution.Interpreter {
	return orZero(r.IsValid(), r.s.Interpreter)
}
func (r ShellProbeResult) LaunchProfile() execution.LaunchProfile {
	return orZero(r.IsValid(), r.profile)
}
func (r ShellProbeResult) OSFamily() string  { return r.s.OSFamily }
func (r ShellProbeResult) ProbeStage() uint8 { return orZero(r.IsValid(), r.s.ProbeStage) }
func (r ShellProbeResult) RawBanner() string { return r.s.RawBanner }
func (r ShellProbeResult) Equal(o ShellProbeResult) bool {
	return r.IsValid() && o.IsValid() && r.profile.Equal(o.profile) && r.s == o.s
}

// ShellProbePort 定义远端默认启动方言与解释器两阶段探测出站端口（P3-T2 <-> P4-T1 sshnet/probe）。
type ShellProbePort interface {
	ProbeShell(ctx context.Context, opener SessionOpener) (ShellProbeResult, error)
}
