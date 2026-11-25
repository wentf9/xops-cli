package engine

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	ucinv "github.com/wentf9/xops-cli/core/internal/usecase/inventory"
	ucsess "github.com/wentf9/xops-cli/core/internal/usecase/session"
)

// ResolveTargetRequest 描述单次目标解析与 Merkle 多跳连接计划编译的公开请求。
type ResolveTargetRequest struct {
	// Target 为目标连接串（[user@]host[:port]、[ipv6][:port]、裸 IPv6 或 OpenSSH 虚拟别名）。
	Target string
	// CLIOptions 为 CLI 最高优先级选项层（t1：-l/-p/-i/-J/-o 等）。
	CLIOptions option.OptionLayer
	// ExplicitOrigin 可选强制指定目标来源（仅支持 OriginAdHoc 与 OriginOpenSSHVirtual；None 自动判定）。
	ExplicitOrigin algebraic.Option[option.OriginKind]
	// ExplicitAuth 可选覆盖末跳认证方式（为 nil 时依据生效策略自动编译）。
	ExplicitAuth inventory.AuthMethod
}

// ExecRequest 描述单次远端命令执行的公开请求（Phase 2.5 Walking Skeleton）。
// Target（预解析结果）与 TargetSpec（现场解析串）须二选一提供；
// CommandPlan、Command 与 CommandArgs 须三选一提供且互斥。
type ExecRequest struct {
	// Target 可选直接传入已由 ResolveTarget 编译的不可变 ResolvedTarget。
	Target ResolvedTarget
	// TargetSpec 在 Target 为零值时用于现场解析目标连接串。
	TargetSpec string
	// CLIOptions 仅在现场解析 TargetSpec 时生效（CLI t1 选项层）。
	CLIOptions option.OptionLayer
	// ExplicitOrigin 仅在现场解析 TargetSpec 时生效。
	ExplicitOrigin algebraic.Option[option.OriginKind]
	// ExplicitAuth 仅在现场解析 TargetSpec 时生效。
	ExplicitAuth inventory.AuthMethod

	// CommandPlan 可选直接提供已编译校验的不可变 execution.CommandPlan。
	CommandPlan algebraic.Option[execution.CommandPlan]
	// Command 可选提供原始远端执行命令串（自动按 DefaultServerLaunchProfile 编译）。
	Command string
	// CommandArgs 可选提供 CLI 位置命令参数切片（按 OpenSSH 规范以单空格拼接后编译）。
	CommandArgs []string
	// CommandTimeout 可选为自动编译的 CommandPlan 附加单命令超时。
	CommandTimeout algebraic.Option[algebraic.Duration]

	// Stdin/Stdout/Stderr 为命令标准输入输出流。
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	// RequestTTY 控制伪终端分配策略（零值 RequestTTYUnset 默认不分配 PTY，除非 CommandPlan.PTY()==true）。
	RequestTTY RequestTTYMode
	// Term 可选显式覆盖 PTY TERM 名称。
	Term string
	// Risk 可选显式指定操作风险等级（None 默认 security.RiskModerate）。
	Risk algebraic.Option[security.RiskLevel]
	// OperationStream 可选绑定单次操作隔离事件流（返回前保证确定性 EOF 关闭）。
	OperationStream *events.OperationStream
}

// InteractiveSSHRequest 描述交互式远端 Shell 会话的公开请求（Phase 2.5 Walking Skeleton）。
// Target（预解析结果）与 TargetSpec（现场解析串）须二选一提供。
type InteractiveSSHRequest struct {
	// Target 可选直接传入已由 ResolveTarget 编译的不可变 ResolvedTarget。
	Target ResolvedTarget
	// TargetSpec 在 Target 为零值时用于现场解析目标连接串。
	TargetSpec string
	// CLIOptions 仅在现场解析 TargetSpec 时生效（CLI t1 选项层）。
	CLIOptions option.OptionLayer
	// ExplicitOrigin 仅在现场解析 TargetSpec 时生效。
	ExplicitOrigin algebraic.Option[option.OriginKind]
	// ExplicitAuth 仅在现场解析 TargetSpec 时生效。
	ExplicitAuth inventory.AuthMethod

	// Stdin/Stdout/Stderr 用于非原始终端模式流式读写及远端扩展错误流。
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	// RequestTTY 控制伪终端分配策略（零值 RequestTTYUnset 默认等价 RequestTTYAuto）。
	RequestTTY RequestTTYMode
	// Term 可选显式覆盖 PTY TERM 名称。
	Term string
	// Risk 可选显式指定操作风险等级（None 默认 security.RiskModerate）。
	Risk algebraic.Option[security.RiskLevel]
	// OperationStream 可选绑定单次操作隔离事件流（返回前保证确定性 EOF 关闭）。
	OperationStream *events.OperationStream
}

// RunSSHRequest 描述统一 SSH 入口请求（对应 CLI `xops ssh [flags] <target> [command [args...]]`）：
// 当提供 CommandPlan / Command / CommandArgs 任一项时自动分派至 Exec，否则进入 InteractiveSSH。
type RunSSHRequest struct {
	Target          ResolvedTarget
	TargetSpec      string
	CLIOptions      option.OptionLayer
	ExplicitOrigin  algebraic.Option[option.OriginKind]
	ExplicitAuth    inventory.AuthMethod
	CommandPlan     algebraic.Option[execution.CommandPlan]
	Command         string
	CommandArgs     []string
	CommandTimeout  algebraic.Option[algebraic.Duration]
	Stdin           io.Reader
	Stdout          io.Writer
	Stderr          io.Writer
	RequestTTY      RequestTTYMode
	Term            string
	Risk            algebraic.Option[security.RiskLevel]
	OperationStream *events.OperationStream
}

// ResolveTarget 解析 AdHoc 或 OpenSSH 虚拟目标，递归展开 ProxyJump（带环路与深度护栏）
// 并编译出不可变 ResolvedTarget 与 Merkle 链式连接计划。
func (e *Engine) ResolveTarget(ctx context.Context, req ResolveTargetRequest) (ResolvedTarget, error) {
	runCtx, cleanup, err := e.beginOp(ctx)
	if err != nil {
		return ResolvedTarget{}, err
	}
	defer cleanup()

	res, err := e.inventory.ResolveTarget(runCtx, ucinv.ResolveTargetRequest{
		Target:         req.Target,
		CLIOptions:     req.CLIOptions,
		ExplicitOrigin: req.ExplicitOrigin,
		ExplicitAuth:   req.ExplicitAuth,
	})
	if err != nil {
		return ResolvedTarget{}, err
	}
	return ResolvedTarget{inner: res, valid: true}, nil
}

// Exec 执行单条远端 SSH 命令（严格经 gate.WithAuthorized 包裹 pool.WithLease）；
// 返回封闭和类型 execution.ExecutionOutcome 供入站层精确映射退出码与终态诊断。
func (e *Engine) Exec(ctx context.Context, req ExecRequest) (execution.ExecutionOutcome, error) {
	if req.OperationStream != nil {
		defer req.OperationStream.Close()
	}
	runCtx, cleanup, err := e.beginOp(ctx)
	if err != nil {
		return notStartedOutcome(execution.StartPhaseValidate, "engine_unavailable", err), err
	}
	defer cleanup()

	ttyMode, err := req.RequestTTY.toSessionTTYMode()
	if err != nil {
		return notStartedOutcome(execution.StartPhaseValidate, "invalid_request_tty", err), err
	}
	cmdPlan, err := compileExecCommandPlan(req.CommandPlan, req.Command, req.CommandArgs, req.CommandTimeout)
	if err != nil {
		return notStartedOutcome(execution.StartPhaseValidate, "invalid_command", err), err
	}
	resolved, err := e.resolveTargetForSession(runCtx, req.Target, req.TargetSpec, req.CLIOptions, req.ExplicitOrigin, req.ExplicitAuth)
	if err != nil {
		return notStartedOutcome(execution.StartPhaseValidate, "resolve_target_failed", err), err
	}
	out, execErr := e.session.Exec(runCtx, ucsess.ExecRequest{
		Plan:            resolved.Plan(),
		Command:         cmdPlan,
		NodeID:          resolved.NodeID(),
		Stdin:           req.Stdin,
		Stdout:          req.Stdout,
		Stderr:          req.Stderr,
		RequestTTY:      ttyMode,
		Term:            req.Term,
		Risk:            req.Risk,
		OperationStream: req.OperationStream,
	})
	return out, mapGateError(execErr)
}

// InteractiveSSH 启动交互式远端 SSH Shell 会话（严格经 gate.WithAuthorized 包裹 pool.WithLease），
// 按 RequestTTY 策略接管本机原始终端并中继标准输入输出与窗口缩放事件。
func (e *Engine) InteractiveSSH(ctx context.Context, req InteractiveSSHRequest) (execution.ExecutionOutcome, error) {
	if req.OperationStream != nil {
		defer req.OperationStream.Close()
	}
	runCtx, cleanup, err := e.beginOp(ctx)
	if err != nil {
		return notStartedOutcome(execution.StartPhaseValidate, "engine_unavailable", err), err
	}
	defer cleanup()

	ttyMode, err := req.RequestTTY.toSessionTTYMode()
	if err != nil {
		return notStartedOutcome(execution.StartPhaseValidate, "invalid_request_tty", err), err
	}
	resolved, err := e.resolveTargetForSession(runCtx, req.Target, req.TargetSpec, req.CLIOptions, req.ExplicitOrigin, req.ExplicitAuth)
	if err != nil {
		return notStartedOutcome(execution.StartPhaseValidate, "resolve_target_failed", err), err
	}
	out, runErr := e.session.Interactive(runCtx, ucsess.InteractiveRequest{
		Plan:            resolved.Plan(),
		NodeID:          resolved.NodeID(),
		Stdin:           req.Stdin,
		Stdout:          req.Stdout,
		Stderr:          req.Stderr,
		RequestTTY:      ttyMode,
		Term:            req.Term,
		Risk:            req.Risk,
		OperationStream: req.OperationStream,
	})
	return out, mapGateError(runErr)
}

// RunSSH 作为统一 SSH 门面入口，依据是否携带命令载荷自动路由至 Exec 或 InteractiveSSH。
func (e *Engine) RunSSH(ctx context.Context, req RunSSHRequest) (execution.ExecutionOutcome, error) {
	if req.CommandPlan.IsSome() || req.Command != "" || len(req.CommandArgs) > 0 {
		return e.Exec(ctx, ExecRequest(req))
	}
	return e.InteractiveSSH(ctx, InteractiveSSHRequest{
		Target:          req.Target,
		TargetSpec:      req.TargetSpec,
		CLIOptions:      req.CLIOptions,
		ExplicitOrigin:  req.ExplicitOrigin,
		ExplicitAuth:    req.ExplicitAuth,
		Stdin:           req.Stdin,
		Stdout:          req.Stdout,
		Stderr:          req.Stderr,
		RequestTTY:      req.RequestTTY,
		Term:            req.Term,
		Risk:            req.Risk,
		OperationStream: req.OperationStream,
	})
}

func (e *Engine) resolveTargetForSession(
	ctx context.Context,
	preResolved ResolvedTarget,
	targetSpec string,
	cliOpts option.OptionLayer,
	explicitOrigin algebraic.Option[option.OriginKind],
	explicitAuth inventory.AuthMethod,
) (ResolvedTarget, error) {
	hasPre := !preResolved.IsZero()
	hasSpec := strings.TrimSpace(targetSpec) != ""
	if hasPre && hasSpec {
		return ResolvedTarget{}, fmt.Errorf("%w: Target 与 TargetSpec 不可同时指定", ErrInvalidRequest)
	}
	if hasPre {
		if !preResolved.IsValid() {
			return ResolvedTarget{}, fmt.Errorf("%w: 预解析 Target 无效", ErrInvalidRequest)
		}
		if !cliOpts.IsUnset() || explicitOrigin.IsSome() || explicitAuth != nil {
			return ResolvedTarget{}, fmt.Errorf("%w: 传入预解析 Target 时禁止同时指定 CLIOptions/ExplicitOrigin/ExplicitAuth", ErrInvalidRequest)
		}
		return preResolved, nil
	}
	if !hasSpec {
		return ResolvedTarget{}, fmt.Errorf("%w: 必须提供 Target 或 TargetSpec", ErrInvalidRequest)
	}
	res, err := e.inventory.ResolveTarget(ctx, ucinv.ResolveTargetRequest{
		Target:         targetSpec,
		CLIOptions:     cliOpts,
		ExplicitOrigin: explicitOrigin,
		ExplicitAuth:   explicitAuth,
	})
	if err != nil {
		return ResolvedTarget{}, err
	}
	return ResolvedTarget{inner: res, valid: true}, nil
}

func compileExecCommandPlan(
	planOpt algebraic.Option[execution.CommandPlan],
	rawCmd string,
	args []string,
	timeout algebraic.Option[algebraic.Duration],
) (execution.CommandPlan, error) {
	zeroCP := zeroVal[execution.CommandPlan]()
	sources := 0
	if planOpt.IsSome() {
		sources++
	}
	if rawCmd != "" {
		sources++
	}
	if len(args) > 0 {
		sources++
	}
	if sources != 1 {
		return zeroCP, fmt.Errorf("%w: CommandPlan、Command 与 CommandArgs 必须三选一", ErrInvalidRequest)
	}
	if cp, ok := planOpt.Get(); ok {
		if !cp.IsValid() {
			return zeroCP, fmt.Errorf("%w: CommandPlan 无效", ErrInvalidRequest)
		}
		return cp, nil
	}
	cmdText := rawCmd
	if len(args) > 0 {
		cmdText = strings.Join(args, " ")
	}
	cp, err := execution.NewCommandPlan(execution.CommandPlanSpec{
		Kind:    execution.PlanKindCommand,
		Profile: execution.DefaultServerLaunchProfile(),
		Command: cmdText,
		Timeout: timeout,
	})
	if err != nil {
		return zeroCP, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	return cp, nil
}

func notStartedOutcome(phase execution.StartPhase, code string, err error) execution.ExecutionOutcome {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	out, _ := execution.NewOutcomeNotStarted(phase, code, msg)
	return out
}
