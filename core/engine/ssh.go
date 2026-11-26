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
	Target         string                              // 目标连接串（[user@]host[:port]、[ipv6][:port]、裸 IPv6、托管节点或 OpenSSH 虚拟别名）
	CLIOptions     option.OptionLayer                  // CLI t1 最高优先级选项层（-l/-p/-i/-J/-o 等）
	ExplicitOrigin algebraic.Option[option.OriginKind] // 可选强制指定来源（OriginAdHoc / OriginOpenSSHVirtual；None 自动判定）
	ExplicitAuth   inventory.AuthMethod                // 可选覆盖末跳认证方式（nil 时按生效策略自动编译）
}

// ExecRequest 描述单次远端命令执行的公开请求（兼容 Phase 2.5，并支持两步审批回执 Approval）；
// Target 与 TargetSpec 须二选一，CommandPlan / Command / CommandArgs 须三选一且互斥。
type ExecRequest struct {
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
	Stdout, Stderr  io.Writer
	RequestTTY      RequestTTYMode
	Term            string
	Risk            algebraic.Option[security.RiskLevel]
	Approval        algebraic.Option[ApprovalSubmission]
	OperationStream *events.OperationStream
}

// InteractiveSSHRequest 描述交互式远端 Shell 会话的公开请求（兼容 Phase 2.5，并支持两步审批回执 Approval）；
// Target 与 TargetSpec 须二选一；零值 RequestTTYUnset 默认等价 RequestTTYAuto。
type InteractiveSSHRequest struct {
	Target          ResolvedTarget
	TargetSpec      string
	CLIOptions      option.OptionLayer
	ExplicitOrigin  algebraic.Option[option.OriginKind]
	ExplicitAuth    inventory.AuthMethod
	Stdin           io.Reader
	Stdout, Stderr  io.Writer
	RequestTTY      RequestTTYMode
	Term            string
	Risk            algebraic.Option[security.RiskLevel]
	Approval        algebraic.Option[ApprovalSubmission]
	OperationStream *events.OperationStream
}

// RunSSHRequest 描述统一 SSH 入口请求（对应 CLI `xops ssh [flags] <target> [command [args...]]`）：
// 携带 CommandPlan / Command / CommandArgs 任一项时自动分派至 Exec，否则进入 InteractiveSSH。
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
	Stdout, Stderr  io.Writer
	RequestTTY      RequestTTYMode
	Term            string
	Risk            algebraic.Option[security.RiskLevel]
	Approval        algebraic.Option[ApprovalSubmission]
	OperationStream *events.OperationStream
}

// ResolveTarget 解析托管节点、AdHoc 或 OpenSSH 虚拟目标，递归展开 ProxyJump 并编译不可变 Merkle 连接计划。
func (e *Engine) ResolveTarget(ctx context.Context, req ResolveTargetRequest) (ResolvedTarget, error) {
	return runOp(e, ctx, func(runCtx context.Context) (ResolvedTarget, error) {
		res, err := e.inventory.ResolveTarget(runCtx, ucinv.ResolveTargetRequest{
			Target: req.Target, CLIOptions: req.CLIOptions, ExplicitOrigin: req.ExplicitOrigin, ExplicitAuth: req.ExplicitAuth,
		})
		if err != nil {
			return ResolvedTarget{}, err
		}
		return ResolvedTarget{inner: res, valid: true}, nil
	})
}

// Exec 执行单条远端 SSH 命令（严格经 gate.WithAuthorized 包裹 pool.WithLease，完整透传两步审批回执）；
// 返回封闭和类型 execution.ExecutionOutcome 供入站层精确映射退出码与终态诊断。
func (e *Engine) Exec(ctx context.Context, req ExecRequest) (execution.ExecutionOutcome, error) {
	if req.OperationStream != nil {
		defer req.OperationStream.Close()
	}
	runCtx, cleanup, ttyMode, resolved, out, err := e.prepareSSHSession(ctx, req.RequestTTY, req.Target, req.TargetSpec, req.CLIOptions, req.ExplicitOrigin, req.ExplicitAuth)
	if err != nil {
		return out, err
	}
	defer cleanup()
	cmdPlan, err := compileExecCommandPlan(req.CommandPlan, req.Command, req.CommandArgs, req.CommandTimeout)
	if err != nil {
		return notStartedOutcome(execution.StartPhaseValidate, "invalid_command", err), err
	}
	execOut, execErr := e.session.Exec(runCtx, ucsess.ExecRequest{
		Plan: resolved.Plan(), Command: cmdPlan, NodeID: resolved.NodeID(),
		Stdin: req.Stdin, Stdout: req.Stdout, Stderr: req.Stderr, RequestTTY: ttyMode, Term: req.Term,
		Risk: req.Risk, Approval: toGateApproval(req.Approval), OperationStream: req.OperationStream,
	})
	return execOut, mapGateError(execErr)
}

// InteractiveSSH 启动交互式远端 SSH Shell 会话（严格经 gate.WithAuthorized 包裹 pool.WithLease，透传两步审批回执）。
func (e *Engine) InteractiveSSH(ctx context.Context, req InteractiveSSHRequest) (execution.ExecutionOutcome, error) {
	if req.OperationStream != nil {
		defer req.OperationStream.Close()
	}
	runCtx, cleanup, ttyMode, resolved, out, err := e.prepareSSHSession(ctx, req.RequestTTY, req.Target, req.TargetSpec, req.CLIOptions, req.ExplicitOrigin, req.ExplicitAuth)
	if err != nil {
		return out, err
	}
	defer cleanup()
	runOut, runErr := e.session.Interactive(runCtx, ucsess.InteractiveRequest{
		Plan: resolved.Plan(), NodeID: resolved.NodeID(),
		Stdin: req.Stdin, Stdout: req.Stdout, Stderr: req.Stderr, RequestTTY: ttyMode, Term: req.Term,
		Risk: req.Risk, Approval: toGateApproval(req.Approval), OperationStream: req.OperationStream,
	})
	return runOut, mapGateError(runErr)
}

func (e *Engine) prepareSSHSession(
	ctx context.Context, reqTTY RequestTTYMode, pre ResolvedTarget, spec string,
	cliOpts option.OptionLayer, origin algebraic.Option[option.OriginKind], auth inventory.AuthMethod,
) (context.Context, func(), ucsess.RequestTTYMode, ResolvedTarget, execution.ExecutionOutcome, error) {
	runCtx, cleanup, err := e.beginOp(ctx)
	if err != nil {
		return nil, nil, ucsess.RequestTTYUnset, ResolvedTarget{}, notStartedOutcome(execution.StartPhaseValidate, "engine_unavailable", err), err
	}
	ttyMode, err := reqTTY.toSessionTTYMode()
	if err != nil {
		cleanup()
		return nil, nil, ucsess.RequestTTYUnset, ResolvedTarget{}, notStartedOutcome(execution.StartPhaseValidate, "invalid_request_tty", err), err
	}
	resolved, err := e.resolveTargetForSession(runCtx, pre, spec, cliOpts, origin, auth)
	if err != nil {
		cleanup()
		return nil, nil, ucsess.RequestTTYUnset, ResolvedTarget{}, notStartedOutcome(execution.StartPhaseValidate, "resolve_target_failed", err), err
	}
	return runCtx, cleanup, ttyMode, resolved, nil, nil
}

// RunSSH 作为统一 SSH 门面入口，依据是否携带命令载荷自动路由至 Exec 或 InteractiveSSH。
func (e *Engine) RunSSH(ctx context.Context, req RunSSHRequest) (execution.ExecutionOutcome, error) {
	if req.CommandPlan.IsSome() || req.Command != "" || len(req.CommandArgs) > 0 {
		return e.Exec(ctx, ExecRequest(req))
	}
	return e.InteractiveSSH(ctx, InteractiveSSHRequest{
		Target: req.Target, TargetSpec: req.TargetSpec, CLIOptions: req.CLIOptions,
		ExplicitOrigin: req.ExplicitOrigin, ExplicitAuth: req.ExplicitAuth,
		Stdin: req.Stdin, Stdout: req.Stdout, Stderr: req.Stderr, RequestTTY: req.RequestTTY, Term: req.Term,
		Risk: req.Risk, Approval: req.Approval, OperationStream: req.OperationStream,
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

func compileExecCommandPlan(planOpt algebraic.Option[execution.CommandPlan], rawCmd string, args []string, timeout algebraic.Option[algebraic.Duration]) (execution.CommandPlan, error) {
	zeroCP := zeroVal[execution.CommandPlan]()
	sources := boolInt(planOpt.IsSome()) + boolInt(rawCmd != "") + boolInt(len(args) > 0)
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
		Kind: execution.PlanKindCommand, Profile: execution.DefaultServerLaunchProfile(), Command: cmdText, Timeout: timeout,
	})
	if err != nil {
		return zeroCP, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	return cp, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func notStartedOutcome(phase execution.StartPhase, code string, err error) execution.ExecutionOutcome {
	var msg string
	if err != nil {
		msg = err.Error()
	}
	out, _ := execution.NewOutcomeNotStarted(phase, code, msg)
	return out
}
