package ports

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"net"
	"slices"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
)

const (
	defaultProcessMaxOutputBytes uint64 = 1 << 20  // 默认进程输出捕获上限（1 MiB）
	maxProcessOutputBytes        uint64 = 64 << 20 // 允许的最大进程输出捕获上限（64 MiB）
	maxProcessArgs                      = 256
)

// Timer 表示由 Clock 创建的可取消单次定时器，支撑确定性仿真时钟与真实系统时钟一致抽象。
type Timer interface {
	C() <-chan time.Time
	Stop() bool
	Reset(d time.Duration) bool
}

// Clock 定义时钟与定时等待出站端口（ADR-002 / DST 确定性基础）。
type Clock interface {
	Now() time.Time
	Since(t time.Time) time.Duration
	NewTimer(d time.Duration) Timer
	Sleep(ctx context.Context, d time.Duration) error
}

// Entropy 定义显式密码学/确定性熵源出站端口（ADR-003）；所有实现必须并发安全。
type Entropy interface{ io.Reader }

// LocalIdentityInfoSpec 是构造不可变 LocalIdentityInfo 的显式入参规格。
type LocalIdentityInfoSpec struct {
	LocalHost string `json:"local_host"`
	LocalUser string `json:"local_user"`
	LocalUID  string `json:"local_uid,omitzero"`
	HomeDir   string `json:"home_dir"`
}

// LocalIdentityInfo 表示用于填充 OpenSSH option.TokenContext 的本机非敏感主机/用户元信息快照；零值恒无效。
//
//xops:opaque
//xops:failclosed
type LocalIdentityInfo struct {
	localHost, localUser, localUID, homeDir string
	valid                                   bool
}

// NewLocalIdentityInfo 校验本机主机名、用户名、可选数值 UID 与主目录并构造不可变 LocalIdentityInfo。
func NewLocalIdentityInfo(spec LocalIdentityInfoSpec) (LocalIdentityInfo, error) {
	host, e1 := sanitizeBoundedText(spec.LocalHost, maxPortDetailBytes, false, ErrInvalidArgument)
	user, e2 := sanitizeBoundedText(spec.LocalUser, maxPortTokenLen, false, ErrInvalidArgument)
	uid, e3 := sanitizeBoundedText(spec.LocalUID, maxPortTokenLen, true, ErrInvalidArgument)
	home, e4 := sanitizeBoundedText(spec.HomeDir, maxPortDetailBytes, false, ErrInvalidArgument)
	if err := firstErr(e1, e2, e3, e4); err != nil {
		return LocalIdentityInfo{}, err
	}
	return LocalIdentityInfo{localHost: host, localUser: user, localUID: uid, homeDir: home, valid: true}, nil
}
func (i LocalIdentityInfo) IsValid() bool {
	return i.valid && i.localHost != "" && i.localUser != "" && i.homeDir != ""
}
func (i LocalIdentityInfo) IsZero() bool      { return !i.IsValid() }
func (i LocalIdentityInfo) LocalHost() string { return i.localHost }
func (i LocalIdentityInfo) LocalUser() string { return i.localUser }
func (i LocalIdentityInfo) LocalUID() string  { return i.localUID }
func (i LocalIdentityInfo) HomeDir() string   { return i.homeDir }
func (i LocalIdentityInfo) Equal(o LocalIdentityInfo) bool {
	return i.IsValid() && o.IsValid() && i.localHost == o.localHost && i.localUser == o.localUser && i.localUID == o.localUID && i.homeDir == o.homeDir
}

// ApplyToTokenContext 将本机主机/用户/UID/主目录写入基础 TokenContext 副本并返回（零值时原样返回）。
func (i LocalIdentityInfo) ApplyToTokenContext(base option.TokenContext) option.TokenContext {
	if i.IsValid() {
		base.LocalHost, base.LocalUser, base.LocalUID, base.HomeDir = i.localHost, i.localUser, i.localUID, i.homeDir
	}
	return base
}

// EnvPort 定义只读本机环境变量与本机主机/用户元信息出站端口（由 internal/host/sys 或 sim 实现，ADR-002）。
type EnvPort interface {
	LookupEnv(key string) (string, bool)
	Environ() map[string]string
	LookupLocalIdentity() (LocalIdentityInfo, error)
}

type processEnvEntry struct{ key, value string }

// ProcessSpecInput 是构造不可变 ProcessSpec 的显式入参规格（超时统一使用 algebraic.Duration）。
type ProcessSpecInput struct {
	Command        string                               `json:"command"`
	Args           []string                             `json:"args,omitzero"`
	WorkDir        algebraic.Option[pathalg.LocalDir]   `json:"work_dir,omitzero"`
	Env            map[string]string                    `json:"env,omitzero"`
	Timeout        algebraic.Option[algebraic.Duration] `json:"timeout,omitzero"`
	MaxOutputBytes algebraic.Option[uint64]             `json:"max_output_bytes"`
}

// ProcessSpec 描述面向 ProcessPort 的本机受控子进程执行规格；零值恒无效并失败关闭。
//
//xops:opaque
//xops:failclosed
type ProcessSpec struct {
	command        string
	args           []string
	workDir        algebraic.Option[pathalg.LocalDir]
	env            []processEnvEntry
	timeout        algebraic.Option[algebraic.Duration]
	maxOutputBytes uint64
	valid          bool
}

// NewProcessSpec 校验命令路径、参数向量、工作目录、环境变量、超时与输出上限并构造 ProcessSpec。
func NewProcessSpec(in ProcessSpecInput) (ProcessSpec, error) {
	cmd, e1 := sanitizeBoundedText(in.Command, maxPortDetailBytes, false, ErrInvalidArgument)
	args, e2 := validateProcessArgs(in.Args)
	maxOut, e3 := validateProcessOpts(in.WorkDir, in.Timeout, in.MaxOutputBytes)
	env, e4 := canonicalizeProcessEnv(in.Env)
	if err := firstErr(e1, e2, e3, e4); err != nil {
		return ProcessSpec{}, err
	}
	return ProcessSpec{command: cmd, args: args, workDir: in.WorkDir, env: env, timeout: in.Timeout, maxOutputBytes: maxOut, valid: true}, nil
}

func validateProcessArgs(raw []string) ([]string, error) {
	if len(raw) > maxProcessArgs {
		return nil, fmt.Errorf("%w: 参数数量超限", ErrInvalidArgument)
	}
	for i, a := range raw {
		if len(a) > maxPortEnvValBytes || hasForbiddenControl(a) {
			return nil, fmt.Errorf("%w: args[%d] 非法", ErrInvalidArgument, i)
		}
	}
	return slices.Clone(raw), nil
}
func validateProcessOpts(wd algebraic.Option[pathalg.LocalDir], to algebraic.Option[algebraic.Duration], mo algebraic.Option[uint64]) (uint64, error) {
	d, hasD := wd.Get()
	t, hasT := to.Get()
	if (hasD && !d.IsValid()) || (hasT && !t.IsPositive()) {
		return 0, fmt.Errorf("%w: work_dir 或 timeout 无效", ErrInvalidArgument)
	}
	v, ok := mo.Get()
	if !ok {
		return defaultProcessMaxOutputBytes, nil
	}
	if v == 0 || v > maxProcessOutputBytes {
		return 0, fmt.Errorf("%w: max_output_bytes=%d 超出范围", ErrInvalidArgument, v)
	}
	return v, nil
}
func canonicalizeProcessEnv(raw map[string]string) ([]processEnvEntry, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > maxPortEnvCount {
		return nil, fmt.Errorf("%w: 环境变量数量超限", ErrInvalidArgument)
	}
	out := make([]processEnvEntry, 0, len(raw))
	for _, k := range slices.Sorted(maps.Keys(raw)) {
		if v := raw[k]; !isValidASCIIToken(k, maxPortTokenLen) || slices.Contains([]byte(k), '=') || len(v) > maxPortEnvValBytes || hasForbiddenControl(v) {
			return nil, fmt.Errorf("%w: 环境变量 %q 非法", ErrInvalidArgument, k)
		}
		out = append(out, processEnvEntry{key: k, value: raw[k]})
	}
	return out, nil
}
func (p ProcessSpec) IsValid() bool                                 { return p.valid && p.command != "" && p.maxOutputBytes > 0 }
func (p ProcessSpec) IsZero() bool                                  { return !p.IsValid() }
func (p ProcessSpec) Command() string                               { return p.command }
func (p ProcessSpec) Args() []string                                { return slices.Clone(p.args) }
func (p ProcessSpec) WorkDir() algebraic.Option[pathalg.LocalDir]   { return p.workDir }
func (p ProcessSpec) Timeout() algebraic.Option[algebraic.Duration] { return p.timeout }
func (p ProcessSpec) MaxOutputBytes() uint64                        { return pickIf(p.IsValid(), p.maxOutputBytes, 0) }
func (p ProcessSpec) Env() map[string]string {
	if !p.IsValid() || len(p.env) == 0 {
		return nil
	}
	out := make(map[string]string, len(p.env))
	for _, kv := range p.env {
		out[kv.key] = kv.value
	}
	return out
}
func (p ProcessSpec) Equal(o ProcessSpec) bool {
	return p.IsValid() && o.IsValid() && p.command == o.command && slices.Equal(p.args, o.args) &&
		optEqualFunc(p.workDir, o.workDir, pathalg.LocalDir.Equal) && slices.Equal(p.env, o.env) &&
		optEqualFunc(p.timeout, o.timeout, algebraic.Duration.Equal) && p.maxOutputBytes == o.maxOutputBytes
}

// ProcessResultSpec 是构造不可变 ProcessResult 的显式入参规格。
type ProcessResultSpec struct {
	ExitStatus     execution.ExitStatus
	Stdout, Stderr []byte
	Truncated      bool
}

// ProcessResult 描述本机子进程一次性执行的不可变结果；零值恒无效。
//
//xops:opaque
//xops:failclosed
type ProcessResult struct {
	exitStatus       execution.ExitStatus
	stdout, stderr   []byte
	truncated, valid bool
}

// NewProcessResult 校验 ExitStatus 非空有效并构造不可变 ProcessResult。
func NewProcessResult(spec ProcessResultSpec) (ProcessResult, error) {
	if spec.ExitStatus == nil || !spec.ExitStatus.IsValid() {
		return ProcessResult{}, fmt.Errorf("%w: ProcessResult 需要有效 ExitStatus", ErrInvalidArgument)
	}
	return ProcessResult{exitStatus: spec.ExitStatus, stdout: bytes.Clone(spec.Stdout), stderr: bytes.Clone(spec.Stderr), truncated: spec.Truncated, valid: true}, nil
}
func (r ProcessResult) IsValid() bool {
	return r.valid && r.exitStatus != nil && r.exitStatus.IsValid()
}
func (r ProcessResult) IsZero() bool { return !r.IsValid() }
func (r ProcessResult) ExitStatus() execution.ExitStatus {
	return pickIf(r.IsValid(), r.exitStatus, nil)
}
func (r ProcessResult) Succeeded() bool { return r.IsValid() && r.exitStatus.IsSuccess() }
func (r ProcessResult) Stdout() []byte  { return bytes.Clone(r.stdout) }
func (r ProcessResult) Stderr() []byte  { return bytes.Clone(r.stderr) }
func (r ProcessResult) Truncated() bool { return r.IsValid() && r.truncated }
func (r ProcessResult) Equal(o ProcessResult) bool {
	return r.IsValid() && o.IsValid() && execution.EqualExitStatus(r.exitStatus, o.exitStatus) && bytes.Equal(r.stdout, o.stdout) && bytes.Equal(r.stderr, o.stderr) && r.truncated == o.truncated
}

// ProcessPort 定义本机外部进程执行与 stdio 管道连接出站端口（仅由 internal/host/sys 或 sim 实现）。
type ProcessPort interface {
	Run(ctx context.Context, spec ProcessSpec, stdin io.Reader) (ProcessResult, error)
	DialStdio(ctx context.Context, spec ProcessSpec) (net.Conn, error)
}

// TerminalSize 表示本机或远端终端窗口尺寸（列数与行数均须 >= 1）；零值恒无效。
//
//xops:opaque
//xops:failclosed
type TerminalSize struct {
	cols, rows uint16
	valid      bool
}

// NewTerminalSize 校验列数与行数均为正整数并构造不可变 TerminalSize。
func NewTerminalSize(cols, rows uint16) (TerminalSize, error) {
	if cols == 0 || rows == 0 {
		return TerminalSize{}, fmt.Errorf("%w: cols=%d rows=%d 必须大于 0", ErrInvalidTTYSize, cols, rows)
	}
	return TerminalSize{cols: cols, rows: rows, valid: true}, nil
}
func (s TerminalSize) IsValid() bool { return s.valid && s.cols > 0 && s.rows > 0 }
func (s TerminalSize) IsZero() bool  { return !s.IsValid() }
func (s TerminalSize) Cols() uint16  { return pickIf(s.IsValid(), s.cols, 0) }
func (s TerminalSize) Rows() uint16  { return pickIf(s.IsValid(), s.rows, 0) }
func (s TerminalSize) Equal(o TerminalSize) bool {
	return s.IsValid() && o.IsValid() && s.cols == o.cols && s.rows == o.rows
}

// TerminalHandle 是 TerminalPort.WithRawTerminal 在同步作用域闭包内借出的原始终端句柄。
type TerminalHandle interface {
	io.Reader
	io.Writer
	Size() (TerminalSize, error)
	ResizeEvents() <-chan TerminalSize
	// Relay 在同步作用域内将本机终端输入/输出与窗口尺寸变更并发中继至远端读写流（RFC §2.1 ConsoleRelay）；
	// 退出前须收敛全部内部泵协程，onResize 可为 nil，remoteIn/remoteOut 为 nil 返回 ErrInvalidArgument。
	//
	//xops:syncclosure
	Relay(ctx context.Context, remoteIn io.Writer, remoteOut io.Reader, onResize func(ctx context.Context, size TerminalSize) error) error
}

// TerminalPort 定义本机 PTY / Windows ConPTY 控制台与进程组挂起判定出站端口（仅由 internal/host/sys 或 sim 实现）。
type TerminalPort interface {
	IsInteractive() bool
	Size() (TerminalSize, error)
	// WithRawTerminal 进入原始终端/ConPTY 模式并在同步闭包内借出 TerminalHandle，退出前无条件恢复。
	//
	//xops:syncclosure
	//xops:borrowed
	WithRawTerminal(ctx context.Context, fn func(term TerminalHandle) error) error
	// CanSuspendProcessGroup 执行 POSIX 孤儿进程组安全挂起判定（INV-E1：任何错误失败关闭返回 VerdictDeny + error）。
	CanSuspendProcessGroup() (security.Verdict, error)
}
