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
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
)

const (
	defaultProcessMaxOutputBytes uint64 = 1 << 20  // 默认进程输出捕获上限（1 MiB）
	maxProcessOutputBytes        uint64 = 64 << 20 // 允许的最大进程输出捕获上限（64 MiB）
	maxProcessArgs                      = 256
)

// Timer 表示由 Clock 创建的可取消单次定时器，支撑确定性仿真时钟（SimClock）与真实系统时钟一致抽象。
type Timer interface {
	// C 返回到期事件通道。
	C() <-chan time.Time
	// Stop 停止定时器并回报调用前是否仍处于激活状态。
	Stop() bool
	// Reset 将定时器重置为延迟 d 后触发。
	Reset(d time.Duration) bool
}

// Clock 定义时钟与定时等待出站端口（ADR-002 / P2-T6 DST 确定性基础）。
type Clock interface {
	// Now 返回当前时钟时刻（建议统一返回 UTC 时间）。
	Now() time.Time
	// Since 返回自 t 以来流逝的时长。
	Since(t time.Time) time.Duration
	// NewTimer 创建在延迟 d 后触发的定时器。
	NewTimer(d time.Duration) Timer
	// Sleep 在延迟 d 或 ctx 取消时返回；ctx 为 nil 返回 ErrNilContext。
	Sleep(ctx context.Context, d time.Duration) error
}

// Entropy 定义显式密码学/确定性熵源出站端口（ADR-003 / RFC §3.3）。
// 直接嵌入 io.Reader 以零摩擦喂给 trace.NewTraceIDFrom / trace.NewOpIDFrom、
// security.NewOperationIDFrom / NewApprovalNonceFrom、plan.NewHandleIDFrom 与 ports.NewProcessInstanceIDFrom。
// 并发契约：所有 Entropy 实现的 Read 方法必须并发安全，可由 gate/pool/usecase/mcpruntime 多协程并发调用。
type Entropy interface {
	io.Reader
}

type processEnvEntry struct{ key, value string }

// ProcessSpecInput 是构造不可变 ProcessSpec 的显式入参规格（超时统一使用 algebraic.Duration）。
type ProcessSpecInput struct {
	Command        string
	Args           []string
	WorkDir        algebraic.Option[pathalg.LocalDir]
	Env            map[string]string
	Timeout        algebraic.Option[algebraic.Duration]
	MaxOutputBytes algebraic.Option[uint64]
}

// ProcessSpec 描述面向 ProcessPort 的本机受控子进程执行规格（如 ProxyCommand、LocalCommand、External Helper）；
// 零值恒无效并失败关闭，严禁使用裸 time.Duration。
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

// NewProcessSpec 校验命令路径、参数向量、工作目录、环境变量、超时与输出上限并构造不可变 ProcessSpec。
func NewProcessSpec(in ProcessSpecInput) (ProcessSpec, error) {
	cmd, err := sanitizeBoundedText(in.Command, maxPortDetailBytes, false, ErrInvalidArgument)
	if err != nil {
		return ProcessSpec{}, fmt.Errorf("%w: command 非法", err)
	}
	args, err := validateProcessArgs(in.Args)
	if err != nil {
		return ProcessSpec{}, err
	}
	if err := validateProcessOptFields(in.WorkDir, in.Timeout); err != nil {
		return ProcessSpec{}, err
	}
	env, err := canonicalizeProcessEnv(in.Env)
	if err != nil {
		return ProcessSpec{}, err
	}
	maxOut, err := resolveProcessMaxOutput(in.MaxOutputBytes)
	if err != nil {
		return ProcessSpec{}, err
	}
	return ProcessSpec{
		command: cmd, args: args, workDir: in.WorkDir, env: env,
		timeout: in.Timeout, maxOutputBytes: maxOut, valid: true,
	}, nil
}

func validateProcessArgs(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > maxProcessArgs {
		return nil, fmt.Errorf("%w: 参数数量 %d 超过上限 %d", ErrInvalidArgument, len(raw), maxProcessArgs)
	}
	out := make([]string, len(raw))
	for i, a := range raw {
		if len(a) > maxPortEnvValBytes || hasForbiddenControl(a) {
			return nil, fmt.Errorf("%w: args[%d] 超长或包含非法字符", ErrInvalidArgument, i)
		}
		out[i] = a
	}
	return out, nil
}
func validateProcessOptFields(wd algebraic.Option[pathalg.LocalDir], to algebraic.Option[algebraic.Duration]) error {
	if d, ok := wd.Get(); ok && !d.IsValid() {
		return fmt.Errorf("%w: work_dir 无效", ErrInvalidArgument)
	}
	if d, ok := to.Get(); ok && !d.IsPositive() {
		return fmt.Errorf("%w: timeout 必须为正时长", ErrInvalidArgument)
	}
	return nil
}
func canonicalizeProcessEnv(raw map[string]string) ([]processEnvEntry, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > maxPortEnvCount {
		return nil, fmt.Errorf("%w: 环境变量数量超过上限 %d", ErrInvalidArgument, maxPortEnvCount)
	}
	out := make([]processEnvEntry, 0, len(raw))
	for _, k := range slices.Sorted(maps.Keys(raw)) {
		v := raw[k]
		if !isValidASCIIToken(k, maxPortTokenLen) || slices.Contains([]byte(k), '=') || len(v) > maxPortEnvValBytes || hasForbiddenControl(v) {
			return nil, fmt.Errorf("%w: 环境变量 %q 名称或值非法", ErrInvalidArgument, k)
		}
		out = append(out, processEnvEntry{key: k, value: v})
	}
	return out, nil
}
func resolveProcessMaxOutput(opt algebraic.Option[uint64]) (uint64, error) {
	v, ok := opt.Get()
	if !ok {
		return defaultProcessMaxOutputBytes, nil
	}
	if v == 0 || v > maxProcessOutputBytes {
		return 0, fmt.Errorf("%w: max_output_bytes=%d 超出允许范围 [1, %d]", ErrInvalidArgument, v, maxProcessOutputBytes)
	}
	return v, nil
}

// ProcessSpec 只读访问器与等价比对。
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
	ExitStatus execution.ExitStatus
	Stdout     []byte
	Stderr     []byte
	Truncated  bool
}

// ProcessResult 描述本机子进程一次性执行的不可变结果；零值恒无效。
//
//xops:opaque
//xops:failclosed
type ProcessResult struct {
	exitStatus execution.ExitStatus
	stdout     []byte
	stderr     []byte
	truncated  bool
	valid      bool
}

// NewProcessResult 校验 ExitStatus 非空有效并构造不可变 ProcessResult。
func NewProcessResult(spec ProcessResultSpec) (ProcessResult, error) {
	if spec.ExitStatus == nil || !spec.ExitStatus.IsValid() {
		return ProcessResult{}, fmt.Errorf("%w: ProcessResult 需要有效 ExitStatus", ErrInvalidArgument)
	}
	return ProcessResult{
		exitStatus: spec.ExitStatus, stdout: bytes.Clone(spec.Stdout),
		stderr: bytes.Clone(spec.Stderr), truncated: spec.Truncated, valid: true,
	}, nil
}

// ProcessResult 只读访问器与等价比对。
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
	return r.IsValid() && o.IsValid() && execution.EqualExitStatus(r.exitStatus, o.exitStatus) &&
		bytes.Equal(r.stdout, o.stdout) && bytes.Equal(r.stderr, o.stderr) && r.truncated == o.truncated
}

// ProcessPort 定义本机外部进程执行与 stdio 管道连接出站端口（仅由 internal/host/sys 或 sim 实现）。
type ProcessPort interface {
	// Run 以有界输出与上下文取消控制执行一次性子进程并返回结构化 ProcessResult。
	Run(ctx context.Context, spec ProcessSpec, stdin io.Reader) (ProcessResult, error)
	// DialStdio 启动子进程并将其 stdin/stdout 封装为双向 net.Conn（供 OpenSSH ProxyCommand 使用，Plan P4-T4）。
	DialStdio(ctx context.Context, spec ProcessSpec) (net.Conn, error)
}

// TerminalSize 表示本机或远端终端窗口尺寸（列数与行数均须 >= 1）；零值恒无效。
//
//xops:opaque
//xops:failclosed
type TerminalSize struct {
	cols  uint16
	rows  uint16
	valid bool
}

// NewTerminalSize 校验列数与行数均为正整数并构造不可变 TerminalSize。
func NewTerminalSize(cols, rows uint16) (TerminalSize, error) {
	if cols == 0 || rows == 0 {
		return TerminalSize{}, fmt.Errorf("%w: cols=%d rows=%d 必须大于 0", ErrInvalidTTYSize, cols, rows)
	}
	return TerminalSize{cols: cols, rows: rows, valid: true}, nil
}

// TerminalSize 只读访问器与等价比对。
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
	// Size 查询当前本机终端实时窗口尺寸。
	Size() (TerminalSize, error)
	// ResizeEvents 返回窗口尺寸变更通知只读通道（回调退出时关闭）。
	ResizeEvents() <-chan TerminalSize
}

// TerminalPort 定义本机 PTY / Windows ConPTY 控制台与进程组挂起判定出站端口（仅由 internal/host/sys 或 sim 实现）。
type TerminalPort interface {
	// IsInteractive 报告当前标准输入/输出是否连接到交互式 TTY/ConPTY。
	IsInteractive() bool
	// Size 查询当前本机终端窗口尺寸。
	Size() (TerminalSize, error)
	// WithRawTerminal 进入原始终端/ConPTY 中继模式并在同步闭包内借出 TerminalHandle，退出前无条件恢复终端状态。
	//
	//xops:syncclosure
	//xops:borrowed
	WithRawTerminal(ctx context.Context, fn func(term TerminalHandle) error) error
	// CanSuspendProcessGroup 执行 POSIX 孤儿进程组安全挂起判定（INV-E1：任何错误一律失败关闭返回 VerdictDeny + error）。
	CanSuspendProcessGroup() (security.Verdict, error)
}
