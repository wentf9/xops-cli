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

// ResolveTargetRequest / ExecRequest / InteractiveSSHRequest / RunSSHRequest 描述 SSH 目标解析、命令执行与交互会话公开请求。
// Target 与 TargetSpec 须二选一；ExecRequest 的 CommandPlan / Command / CommandArgs 须三选一互斥；RunSSHRequest 与 ExecRequest 同构零拷贝。
type (
	ResolveTargetRequest = ucinv.ResolveTargetRequest
	ExecRequest          struct {
		Target                    ResolvedTarget
		TargetSpec, Command, Term string
		CLIOptions                option.OptionLayer
		ExplicitOrigin            algebraic.Option[option.OriginKind]
		ExplicitAuth              inventory.AuthMethod
		CommandPlan               algebraic.Option[execution.CommandPlan]
		CommandArgs               []string
		CommandTimeout            algebraic.Option[algebraic.Duration]
		Stdin                     io.Reader
		Stdout, Stderr            io.Writer
		RequestTTY                RequestTTYMode
		Risk                      algebraic.Option[security.RiskLevel]
		Approval                  algebraic.Option[ApprovalSubmission]
		OperationStream           *events.OperationStream
	}
	InteractiveSSHRequest struct {
		Target           ResolvedTarget
		TargetSpec, Term string
		CLIOptions       option.OptionLayer
		ExplicitOrigin   algebraic.Option[option.OriginKind]
		ExplicitAuth     inventory.AuthMethod
		Stdin            io.Reader
		Stdout, Stderr   io.Writer
		RequestTTY       RequestTTYMode
		Risk             algebraic.Option[security.RiskLevel]
		Approval         algebraic.Option[ApprovalSubmission]
		OperationStream  *events.OperationStream
	}
	RunSSHRequest = ExecRequest
)

// ResolveTarget 解析托管节点、AdHoc 或 OpenSSH 虚拟目标，递归展开 ProxyJump 并编译不可变 Merkle 连接计划。
func (e *Engine) ResolveTarget(ctx context.Context, req ResolveTargetRequest) (ResolvedTarget, error) {
	return callInv(e, ctx, nil, (*ucinv.Service).ResolveTarget, req)
}

// Exec 执行单条远端 SSH 命令（严格经 gate.WithAuthorized 包裹 pool.WithLease），全路径确保 OperationStream 确定性 EOF。
func (e *Engine) Exec(ctx context.Context, req ExecRequest) (execution.ExecutionOutcome, error) {
	defer closeStreamIfNonNil(req.OperationStream)
	runCtx, cleanup, ttyMode, resolved, out, err := e.prepareSSHSession(ctx, req.RequestTTY, req.Target, req.TargetSpec, req.CLIOptions, req.ExplicitOrigin, req.ExplicitAuth)
	if err != nil {
		return out, err
	}
	defer cleanup()
	cmdPlan, err := compileExecCommandPlan(req.CommandPlan, req.Command, req.CommandArgs, req.CommandTimeout)
	if err != nil {
		return notStartedOutcome(execution.StartPhaseValidate, "invalid_command", err), err
	}
	return mapRes(e.session.Exec(runCtx, ucsess.ExecRequest{
		Plan: resolved.Plan(), Command: cmdPlan, NodeID: resolved.NodeID(), Stdin: req.Stdin, Stdout: req.Stdout, Stderr: req.Stderr,
		RequestTTY: ttyMode, Term: req.Term, Risk: req.Risk, Approval: req.Approval, OperationStream: req.OperationStream,
	}))
}

// InteractiveSSH 启动交互式远端 SSH Shell 会话（严格经 gate.WithAuthorized 包裹 pool.WithLease），全路径确保 OperationStream 确定性 EOF。
func (e *Engine) InteractiveSSH(ctx context.Context, req InteractiveSSHRequest) (execution.ExecutionOutcome, error) {
	defer closeStreamIfNonNil(req.OperationStream)
	runCtx, cleanup, ttyMode, resolved, out, err := e.prepareSSHSession(ctx, req.RequestTTY, req.Target, req.TargetSpec, req.CLIOptions, req.ExplicitOrigin, req.ExplicitAuth)
	if err != nil {
		return out, err
	}
	defer cleanup()
	return mapRes(e.session.Interactive(runCtx, ucsess.InteractiveRequest{
		Plan: resolved.Plan(), NodeID: resolved.NodeID(), Stdin: req.Stdin, Stdout: req.Stdout, Stderr: req.Stderr,
		RequestTTY: ttyMode, Term: req.Term, Risk: req.Risk, Approval: req.Approval, OperationStream: req.OperationStream,
	}))
}
func (e *Engine) prepareSSHSession(ctx context.Context, reqTTY RequestTTYMode, pre ResolvedTarget, spec string, cliOpts option.OptionLayer, origin algebraic.Option[option.OriginKind], auth inventory.AuthMethod) (context.Context, func(), ucsess.RequestTTYMode, ResolvedTarget, execution.ExecutionOutcome, error) {
	zr := zeroVal[ResolvedTarget]()
	runCtx, cleanup, err := e.beginOp(ctx)
	if err != nil {
		return nil, nil, ucsess.RequestTTYUnset, zr, notStartedOutcome(execution.StartPhaseValidate, "engine_unavailable", err), err
	}
	ttyMode, err := reqTTY.toSessionTTYMode()
	if err != nil {
		cleanup()
		return nil, nil, ucsess.RequestTTYUnset, zr, notStartedOutcome(execution.StartPhaseValidate, "invalid_request_tty", err), err
	}
	resolved, err := e.resolveTargetForSession(runCtx, pre, spec, cliOpts, origin, auth)
	if err != nil {
		cleanup()
		err = mapEngineError(err)
		return nil, nil, ucsess.RequestTTYUnset, zr, notStartedOutcome(execution.StartPhaseValidate, "resolve_target_failed", err), err
	}
	return runCtx, cleanup, ttyMode, resolved, nil, nil
}

// RunSSH 作为统一 SSH 门面入口，依据是否携带命令载荷自动路由至 Exec 或 InteractiveSSH。
func (e *Engine) RunSSH(ctx context.Context, req RunSSHRequest) (execution.ExecutionOutcome, error) {
	if req.CommandPlan.IsSome() || req.Command != "" || len(req.CommandArgs) > 0 {
		return e.Exec(ctx, req)
	}
	return e.InteractiveSSH(ctx, InteractiveSSHRequest{
		Target: req.Target, TargetSpec: req.TargetSpec, CLIOptions: req.CLIOptions, ExplicitOrigin: req.ExplicitOrigin, ExplicitAuth: req.ExplicitAuth,
		Stdin: req.Stdin, Stdout: req.Stdout, Stderr: req.Stderr, RequestTTY: req.RequestTTY, Term: req.Term,
		Risk: req.Risk, Approval: req.Approval, OperationStream: req.OperationStream,
	})
}
func (e *Engine) resolveTargetForSession(ctx context.Context, preResolved ResolvedTarget, targetSpec string, cliOpts option.OptionLayer, explicitOrigin algebraic.Option[option.OriginKind], explicitAuth inventory.AuthMethod) (ResolvedTarget, error) {
	hasPre, hasSpec := !preResolved.IsZero(), strings.TrimSpace(targetSpec) != ""
	if hasPre == hasSpec {
		return zeroVal[ResolvedTarget](), fmt.Errorf("%w: Target 与 TargetSpec 必须二选一", ErrInvalidRequest)
	}
	if hasPre {
		if !preResolved.IsValid() || !cliOpts.IsUnset() || explicitOrigin.IsSome() || explicitAuth != nil {
			return zeroVal[ResolvedTarget](), fmt.Errorf("%w: 预解析 Target 无效或禁止同时指定 CLIOptions/ExplicitOrigin/ExplicitAuth", ErrInvalidRequest)
		}
		return preResolved, nil
	}
	return e.inventory.ResolveTarget(ctx, ucinv.ResolveTargetRequest{Target: targetSpec, CLIOptions: cliOpts, ExplicitOrigin: explicitOrigin, ExplicitAuth: explicitAuth})
}
func compileExecCommandPlan(planOpt algebraic.Option[execution.CommandPlan], rawCmd string, args []string, timeout algebraic.Option[algebraic.Duration]) (execution.CommandPlan, error) {
	zeroCP, sources := zeroVal[execution.CommandPlan](), 0
	for _, ok := range [3]bool{planOpt.IsSome(), rawCmd != "", len(args) > 0} {
		if ok {
			sources++
		}
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
	if len(args) > 0 {
		rawCmd = strings.Join(args, " ")
	}
	cp, err := execution.NewCommandPlan(execution.CommandPlanSpec{Kind: execution.PlanKindCommand, Profile: execution.DefaultServerLaunchProfile(), Command: rawCmd, Timeout: timeout})
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
