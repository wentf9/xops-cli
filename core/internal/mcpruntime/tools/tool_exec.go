package tools

import (
	"context"
	"encoding/json/jsontext"
	"fmt"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/playbook"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/mcpruntime/protocol"
	ucauto "github.com/wentf9/xops-cli/core/internal/usecase/automation"
	ucsess "github.com/wentf9/xops-cli/core/internal/usecase/session"
	"github.com/wentf9/xops-cli/core/ports"
)

type terminalExecArgs struct {
	Action          string                                           `json:"action"`
	Target          string                                           `json:"target,omitzero"`
	Targets         []string                                         `json:"targets,omitzero"`
	Selector        algebraic.Option[playbook.TargetSelector]        `json:"selector,omitzero"`
	ExcludeNodes    []inventory.NodeID                               `json:"exclude_nodes,omitzero"`
	ExcludeTags     []inventory.Tag                                  `json:"exclude_tags,omitzero"`
	Command         string                                           `json:"command,omitzero"`
	WorkDir         string                                           `json:"work_dir,omitzero"`
	Env             map[string]string                                `json:"env,omitzero"`
	Stdin           string                                           `json:"stdin,omitzero"`
	Timeout         algebraic.Option[algebraic.Duration]             `json:"timeout,omitzero"`
	MaxOutputBytes  uint64                                           `json:"max_output_bytes,omitzero"`
	PTY             bool                                             `json:"pty,omitzero"`
	Term            string                                           `json:"term,omitzero"`
	PrivilegeMethod algebraic.Option[ports.PrivilegeMethod]          `json:"privilege_method,omitzero"`
	TargetUser      string                                           `json:"target_user,omitzero"`
	NonInteractive  bool                                             `json:"non_interactive,omitzero"`
	PasswordRef     string                                           `json:"password_ref,omitzero"`
	Paths           []string                                         `json:"paths,omitzero"`
	RecursivePaths  []string                                         `json:"recursive_paths,omitzero"`
	Concurrency     int                                              `json:"concurrency,omitzero"`
	FailFast        bool                                             `json:"fail_fast,omitzero"`
	Playbook        algebraic.Option[playbook.Playbook]              `json:"playbook,omitzero"`
	ExtraVars       map[string]string                                `json:"extra_vars,omitzero"`
	Risk            algebraic.Option[security.RiskLevel]             `json:"risk,omitzero"`
	Approval        algebraic.Option[protocol.ApprovalSubmissionDTO] `json:"approval,omitzero"`
}

func (r *Registry) callTerminalExec(ctx context.Context, rawArgs jsontext.Value) (protocol.CallToolResult, error) {
	args, err := decodeToolArgs[terminalExecArgs](rawArgs)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	risk, approval, err := validateApprovalAndRisk(args.Risk, args.Approval)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	switch args.Action {
	case "exec":
		return r.execSingle(ctx, args, risk, approval)
	case "exec_privileged":
		return r.execPrivileged(ctx, args, risk, approval)
	case "probe_shell":
		return r.execProbeShell(ctx, args, risk, approval)
	case "batch_exec":
		return r.execBatch(ctx, args, risk, approval)
	case "run_playbook":
		return r.execPlaybook(ctx, args, risk, approval)
	default:
		return protocol.CallToolResult{}, fmt.Errorf("%w: 未知 terminal_exec action %q", protocol.ErrInvalidParams, args.Action)
	}
}

func compileMCPCommandPlan(args terminalExecArgs) (execution.CommandPlan, error) {
	if strings.TrimSpace(args.Command) == "" {
		return zeroVal[execution.CommandPlan](), fmt.Errorf("%w: command 不能为空", protocol.ErrInvalidParams)
	}
	var wdOpt algebraic.Option[pathalg.RemotePath]
	if args.WorkDir != "" {
		wd, err := parseRemotePathParam("work_dir", args.WorkDir)
		if err != nil {
			return zeroVal[execution.CommandPlan](), err
		}
		wdOpt = algebraic.Some(wd)
	}
	var maxOutOpt algebraic.Option[uint64]
	if args.MaxOutputBytes > 0 {
		maxOutOpt = algebraic.Some(args.MaxOutputBytes)
	}
	cp, err := execution.NewCommandPlan(execution.CommandPlanSpec{
		Kind:           execution.PlanKindCommand,
		Profile:        execution.DefaultServerLaunchProfile(),
		Command:        args.Command,
		WorkDir:        wdOpt,
		Env:            args.Env,
		Timeout:        args.Timeout,
		MaxOutputBytes: maxOutOpt,
		PTY:            args.PTY,
	})
	if err != nil {
		return zeroVal[execution.CommandPlan](), fmt.Errorf("%w: %w", protocol.ErrInvalidParams, err)
	}
	return cp, nil
}

func (r *Registry) execSingle(
	ctx context.Context,
	args terminalExecArgs,
	risk algebraic.Option[security.RiskLevel],
	approval algebraic.Option[gate.ApprovalSubmission],
) (protocol.CallToolResult, error) {
	if r.session == nil {
		return protocol.CallToolResult{}, fmt.Errorf("%w: SessionService 未配置", ErrServiceUnavailable)
	}
	resolved, err := r.resolveTarget(ctx, args.Target, option.UnsetOptionLayer())
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	cp, err := compileMCPCommandPlan(args)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	limit := int(args.MaxOutputBytes)
	stdout, stderr := newBoundedBuffer(limit), newBoundedBuffer(limit)
	ttyMode := ucsess.RequestTTYNo
	if args.PTY {
		ttyMode = ucsess.RequestTTYForce
	}
	var stdinReader *strings.Reader
	if args.Stdin != "" {
		stdinReader = strings.NewReader(args.Stdin)
	}
	out, execErr := r.session.Exec(ctx, ucsess.ExecRequest{
		Plan:       resolved.Plan(),
		Command:    cp,
		NodeID:     resolved.NodeID(),
		Term:       args.Term,
		Stdin:      stdinReader,
		Stdout:     stdout,
		Stderr:     stderr,
		RequestTTY: ttyMode,
		Risk:       risk,
		Approval:   approval,
	})
	if execErr != nil {
		return protocol.CallToolResult{}, execErr
	}
	return protocol.NewToolSuccessResult(struct {
		NodeID    string      `json:"node_id"`
		Outcome   outcomeJSON `json:"outcome"`
		Stdout    string      `json:"stdout"`
		Stderr    string      `json:"stderr"`
		Truncated bool        `json:"truncated"`
	}{
		NodeID:    resolved.NodeID(),
		Outcome:   outcomeJSON{outcome: out},
		Stdout:    stdout.String(),
		Stderr:    stderr.String(),
		Truncated: stdout.Truncated() || stderr.Truncated(),
	})
}

func (r *Registry) execPrivileged(
	ctx context.Context,
	args terminalExecArgs,
	risk algebraic.Option[security.RiskLevel],
	approval algebraic.Option[gate.ApprovalSubmission],
) (protocol.CallToolResult, error) {
	if r.session == nil {
		return protocol.CallToolResult{}, fmt.Errorf("%w: SessionService 未配置", ErrServiceUnavailable)
	}
	resolved, err := r.resolveTarget(ctx, args.Target, option.UnsetOptionLayer())
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	method, ok := args.PrivilegeMethod.Get()
	if !ok || !method.IsValid() {
		return protocol.CallToolResult{}, fmt.Errorf("%w: privilege_method 必填且须为 sudo/su/doas", protocol.ErrInvalidParams)
	}
	cp, err := compileMCPCommandPlan(args)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	var targetUser algebraic.Option[option.Username]
	if args.TargetUser != "" {
		u, uErr := option.ParseUsername(args.TargetUser)
		if uErr != nil {
			return protocol.CallToolResult{}, fmt.Errorf("%w: target_user 非法: %w", protocol.ErrInvalidParams, uErr)
		}
		targetUser = algebraic.Some(u)
	}
	var pwRef algebraic.Option[secret.Ref]
	if args.PasswordRef != "" {
		ref, rErr := secret.ParseRef(args.PasswordRef)
		if rErr != nil {
			return protocol.CallToolResult{}, fmt.Errorf("%w: password_ref 非法: %w", protocol.ErrInvalidParams, rErr)
		}
		pwRef = algebraic.Some(ref)
	}
	privReq, err := ports.NewPrivilegeRequest(ports.PrivilegeRequestSpec{
		Method:         method,
		Command:        cp,
		TargetUser:     targetUser,
		NonInteractive: args.NonInteractive,
		Timeout:        args.Timeout,
	})
	if err != nil {
		return protocol.CallToolResult{}, fmt.Errorf("%w: %w", protocol.ErrInvalidParams, err)
	}
	limit := int(args.MaxOutputBytes)
	stdout, stderr := newBoundedBuffer(limit), newBoundedBuffer(limit)
	out, execErr := r.session.ExecPrivileged(ctx, ucsess.PrivilegeExecRequest{
		Plan:           resolved.Plan(),
		Privilege:      privReq,
		NodeID:         resolved.NodeID(),
		Term:           args.Term,
		PasswordRef:    pwRef,
		Paths:          args.Paths,
		RecursivePaths: args.RecursivePaths,
		Stdout:         stdout,
		Stderr:         stderr,
		Risk:           risk,
		Approval:       approval,
	})
	if execErr != nil {
		return protocol.CallToolResult{}, execErr
	}
	return protocol.NewToolSuccessResult(struct {
		NodeID    string      `json:"node_id"`
		Outcome   outcomeJSON `json:"outcome"`
		Stdout    string      `json:"stdout"`
		Stderr    string      `json:"stderr"`
		Truncated bool        `json:"truncated"`
	}{
		NodeID:    resolved.NodeID(),
		Outcome:   outcomeJSON{outcome: out},
		Stdout:    stdout.String(),
		Stderr:    stderr.String(),
		Truncated: stdout.Truncated() || stderr.Truncated(),
	})
}

func (r *Registry) execProbeShell(
	ctx context.Context,
	args terminalExecArgs,
	risk algebraic.Option[security.RiskLevel],
	approval algebraic.Option[gate.ApprovalSubmission],
) (protocol.CallToolResult, error) {
	if r.session == nil {
		return protocol.CallToolResult{}, fmt.Errorf("%w: SessionService 未配置", ErrServiceUnavailable)
	}
	resolved, err := r.resolveTarget(ctx, args.Target, option.UnsetOptionLayer())
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	res, err := r.session.ProbeShell(ctx, ucsess.ProbeShellRequest{
		Plan:     resolved.Plan(),
		NodeID:   resolved.NodeID(),
		Timeout:  args.Timeout,
		Risk:     risk,
		Approval: approval,
	})
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	return protocol.NewToolSuccessResult(struct {
		NodeID string                 `json:"node_id"`
		Probe  ports.ShellProbeResult `json:"probe"`
	}{resolved.NodeID(), res})
}

func (r *Registry) resolveTargetNodes(ctx context.Context, targets []string) ([]ucauto.TargetNode, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	out := make([]ucauto.TargetNode, 0, len(targets))
	for _, raw := range targets {
		resolved, err := r.resolveTarget(ctx, raw, option.UnsetOptionLayer())
		if err != nil {
			return nil, err
		}
		nid, err := inventory.ParseNodeID(resolved.NodeID())
		if err != nil {
			return nil, fmt.Errorf("%w: 目标节点标识 %q 非法: %w", protocol.ErrInvalidParams, resolved.NodeID(), err)
		}
		tn, err := ucauto.NewTargetNode(ucauto.TargetNodeSpec{NodeID: nid, Plan: resolved.Plan()})
		if err != nil {
			return nil, fmt.Errorf("%w: %w", protocol.ErrInvalidParams, err)
		}
		out = append(out, tn)
	}
	return out, nil
}

func (r *Registry) execBatch(
	ctx context.Context,
	args terminalExecArgs,
	risk algebraic.Option[security.RiskLevel],
	approval algebraic.Option[gate.ApprovalSubmission],
) (protocol.CallToolResult, error) {
	if r.automation == nil {
		return protocol.CallToolResult{}, fmt.Errorf("%w: AutomationService 未配置", ErrServiceUnavailable)
	}
	cp, err := compileMCPCommandPlan(args)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	nodes, err := r.resolveTargetNodes(ctx, args.Targets)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	rep, err := r.automation.BatchExec(ctx, ucauto.BatchExecRequest{
		Targets:        nodes,
		Selector:       args.Selector,
		ExcludeNodes:   args.ExcludeNodes,
		ExcludeTags:    args.ExcludeTags,
		Command:        cp,
		Concurrency:    args.Concurrency,
		MaxOutputBytes: args.MaxOutputBytes,
		FailFast:       args.FailFast,
		Risk:           risk,
		Approval:       approval,
	})
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	return protocol.NewToolSuccessResult(rep)
}

func (r *Registry) execPlaybook(
	ctx context.Context,
	args terminalExecArgs,
	risk algebraic.Option[security.RiskLevel],
	approval algebraic.Option[gate.ApprovalSubmission],
) (protocol.CallToolResult, error) {
	if r.automation == nil {
		return protocol.CallToolResult{}, fmt.Errorf("%w: AutomationService 未配置", ErrServiceUnavailable)
	}
	pb, ok := args.Playbook.Get()
	if !ok || !pb.IsValid() {
		return protocol.CallToolResult{}, fmt.Errorf("%w: 缺少有效的 playbook 对象", protocol.ErrInvalidParams)
	}
	nodes, err := r.resolveTargetNodes(ctx, args.Targets)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	// MCP 路径物理不持有 OperatorReadFS，仅可选传入沙箱根 ScopedSourceRoot（来自 ArtifactRoot/TransferRoot）。
	res, err := r.automation.RunPlaybook(ctx, ucauto.PlaybookRequest{
		Playbook:         pb,
		Targets:          nodes,
		ScopedSourceRoot: r.transferRoot,
		Concurrency:      args.Concurrency,
		Timeout:          args.Timeout,
		ExtraVars:        args.ExtraVars,
		Risk:             risk,
		Approval:         approval,
	})
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	return protocol.NewToolSuccessResult(res)
}
