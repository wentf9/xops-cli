package tools

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
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
		return protocol.CallToolResult{}, domi18n.EF(protocol.ErrInvalidParams, domi18n.KeyMCPUnknownToolAction, domi18n.Str("tool", protocol.ToolNameTerminalExec), domi18n.BoundStr("action", args.Action))
	}
}

func compileMCPCommandPlan(args terminalExecArgs) (execution.CommandPlan, error) {
	if strings.TrimSpace(args.Command) == "" {
		return zeroVal[execution.CommandPlan](), domi18n.EF(protocol.ErrInvalidParams, domi18n.KeyCommonFieldEmpty, domi18n.Str("field", "command"))
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
		return zeroVal[execution.CommandPlan](), domi18n.WrapSentinel(protocol.ErrInvalidParams, err)
	}
	return cp, nil
}

func (r *Registry) execSingle(ctx context.Context, args terminalExecArgs, risk algebraic.Option[security.RiskLevel], approval algebraic.Option[gate.ApprovalSubmission]) (protocol.CallToolResult, error) {
	if r.session == nil {
		return protocol.CallToolResult{}, domi18n.EF(ErrServiceUnavailable, domi18n.KeyCommonMissingDep, domi18n.Str("component", "SessionService"))
	}
	resolved, err := r.resolveTarget(ctx, args.Target, option.UnsetOptionLayer())
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	cp, err := compileMCPCommandPlan(args)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	limit := clampOutputLimit(args.MaxOutputBytes)
	stdout, stderr := newBoundedBuffer(limit), newBoundedBuffer(limit)
	ttyMode := ucsess.RequestTTYNo
	if args.PTY {
		ttyMode = ucsess.RequestTTYForce
	}
	out, execErr := r.session.Exec(ctx, ucsess.ExecRequest{
		Plan: resolved.Plan(), Command: cp, NodeID: resolved.NodeID(), Term: args.Term,
		Stdin: optionalStringReader(args.Stdin), Stdout: stdout, Stderr: stderr,
		RequestTTY: ttyMode, Risk: risk, Approval: approval,
	})
	if err := r.checkExecOutcomeError(out, execErr); err != nil {
		return protocol.CallToolResult{}, err
	}
	return encodeExecResult(resolved.NodeID(), out, stdout, stderr)
}

func encodeExecResult(nodeID string, out execution.ExecutionOutcome, stdout, stderr *boundedBuffer) (protocol.CallToolResult, error) {
	return protocol.NewToolSuccessResult(struct {
		NodeID    string      `json:"node_id"`
		Outcome   outcomeJSON `json:"outcome"`
		Stdout    string      `json:"stdout"`
		Stderr    string      `json:"stderr"`
		Truncated bool        `json:"truncated"`
	}{nodeID, outcomeJSON{outcome: out}, stdout.String(), stderr.String(), stdout.Truncated() || stderr.Truncated()})
}

// checkExecOutcomeError 维护 ADR-008 / ADR-016 优先级：Halted 熔断（-32001）最高优先，
// 其次将 *execution.OutcomeUnknown 映射为 protocol.ErrOutcomeUnknown（uncertain:true, retryable:false，禁止重试）。
func (r *Registry) checkExecOutcomeError(out execution.ExecutionOutcome, execErr error) error {
	if r.gate.IsHalted() || errors.Is(execErr, gate.ErrGateHalted) || errors.Is(execErr, ports.ErrAuditPostWrite) {
		if execErr != nil {
			return execErr
		}
		return gate.ErrGateHalted
	}
	if unk, ok := out.(*execution.OutcomeUnknown); ok && unk != nil && unk.IsValid() {
		if execErr != nil {
			return domi18n.WrapS(protocol.ErrOutcomeUnknown, execErr, domi18n.KeyMCPProtoOutcomeUnkDetail, domi18n.BoundStr("code", unk.Code()))
		}
		if unk.Reason() == "" {
			return domi18n.EF(protocol.ErrOutcomeUnknown, domi18n.KeyMCPProtoOutcomeUnkDetail, domi18n.BoundStr("code", unk.Code()))
		}
		return domi18n.EF(protocol.ErrOutcomeUnknown, domi18n.KeyMCPProtoOutcomeUnkReason, domi18n.BoundStr("code", unk.Code()), domi18n.BoundStr("reason", unk.Reason()))
	}
	return execErr
}

func (r *Registry) execPrivileged(ctx context.Context, args terminalExecArgs, risk algebraic.Option[security.RiskLevel], approval algebraic.Option[gate.ApprovalSubmission]) (protocol.CallToolResult, error) {
	if r.session == nil {
		return protocol.CallToolResult{}, domi18n.EF(ErrServiceUnavailable, domi18n.KeyCommonMissingDep, domi18n.Str("component", "SessionService"))
	}
	resolved, err := r.resolveTarget(ctx, args.Target, option.UnsetOptionLayer())
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	privReq, pwRef, err := buildPrivilegeReq(args)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	limit := clampOutputLimit(args.MaxOutputBytes)
	stdout, stderr := newBoundedBuffer(limit), newBoundedBuffer(limit)
	out, execErr := r.session.ExecPrivileged(ctx, ucsess.PrivilegeExecRequest{
		Plan: resolved.Plan(), Privilege: privReq, NodeID: resolved.NodeID(), Term: args.Term,
		PasswordRef: pwRef, Paths: args.Paths, RecursivePaths: args.RecursivePaths,
		Stdin: optionalStringReader(args.Stdin), Stdout: stdout, Stderr: stderr, Risk: risk, Approval: approval,
	})
	if err := r.checkExecOutcomeError(out, execErr); err != nil {
		return protocol.CallToolResult{}, err
	}
	return encodeExecResult(resolved.NodeID(), out, stdout, stderr)
}

func buildPrivilegeReq(args terminalExecArgs) (ports.PrivilegeRequest, algebraic.Option[secret.Ref], error) {
	zeroReq, zeroRef := zeroVal[ports.PrivilegeRequest](), algebraic.None[secret.Ref]()
	method, ok := args.PrivilegeMethod.Get()
	if !ok || !method.IsValid() {
		return zeroReq, zeroRef, domi18n.EF(protocol.ErrInvalidParams, domi18n.KeyCommonFieldRequired, domi18n.Str("field", "privilege_method"))
	}
	cp, err := compileMCPCommandPlan(args)
	if err != nil {
		return zeroReq, zeroRef, err
	}
	var targetUser algebraic.Option[option.Username]
	if args.TargetUser != "" {
		u, uErr := option.ParseUsername(args.TargetUser)
		if uErr != nil {
			return zeroReq, zeroRef, domi18n.WrapS(protocol.ErrInvalidParams, uErr, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "target_user"))
		}
		targetUser = algebraic.Some(u)
	}
	var pwRef algebraic.Option[secret.Ref]
	if args.PasswordRef != "" {
		ref, rErr := secret.ParseRef(args.PasswordRef)
		if rErr != nil {
			return zeroReq, zeroRef, domi18n.WrapS(protocol.ErrInvalidParams, rErr, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "password_ref"))
		}
		pwRef = algebraic.Some(ref)
	}
	privReq, err := ports.NewPrivilegeRequest(ports.PrivilegeRequestSpec{
		Method: method, Command: cp, TargetUser: targetUser, NonInteractive: args.NonInteractive, Timeout: args.Timeout,
	})
	if err != nil {
		return zeroReq, zeroRef, domi18n.WrapSentinel(protocol.ErrInvalidParams, err)
	}
	return privReq, pwRef, nil
}

func (r *Registry) execProbeShell(ctx context.Context, args terminalExecArgs, risk algebraic.Option[security.RiskLevel], approval algebraic.Option[gate.ApprovalSubmission]) (protocol.CallToolResult, error) {
	if r.session == nil {
		return protocol.CallToolResult{}, domi18n.EF(ErrServiceUnavailable, domi18n.KeyCommonMissingDep, domi18n.Str("component", "SessionService"))
	}
	resolved, err := r.resolveTarget(ctx, args.Target, option.UnsetOptionLayer())
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	res, err := r.session.ProbeShell(ctx, ucsess.ProbeShellRequest{
		Plan: resolved.Plan(), NodeID: resolved.NodeID(), Timeout: args.Timeout, Risk: risk, Approval: approval,
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
		nid, nErr := SynthesizeTargetNodeID(resolved.NodeID(), resolved.OriginKind(), resolved.Plan())
		if nErr != nil {
			return nil, domi18n.WrapS(protocol.ErrInvalidParams, nErr, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "node_id"), domi18n.BoundStr("value", resolved.NodeID()))
		}
		tn, tErr := ucauto.NewTargetNode(ucauto.TargetNodeSpec{
			NodeID: nid, Plan: resolved.Plan(), Tags: resolved.Tags(), DefaultProfile: resolved.DefaultProfile(),
		})
		if tErr != nil {
			return nil, domi18n.WrapSentinel(protocol.ErrInvalidParams, tErr)
		}
		out = append(out, tn)
	}
	return out, nil
}

func (r *Registry) execBatch(ctx context.Context, args terminalExecArgs, risk algebraic.Option[security.RiskLevel], approval algebraic.Option[gate.ApprovalSubmission]) (protocol.CallToolResult, error) {
	if r.automation == nil {
		return protocol.CallToolResult{}, domi18n.EF(ErrServiceUnavailable, domi18n.KeyCommonMissingDep, domi18n.Str("component", "AutomationService"))
	}
	if args.Stdin != "" {
		return protocol.CallToolResult{}, domi18n.EF(protocol.ErrInvalidParams, domi18n.KeyMCPBatchExecStdinUnsup)
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
		Targets: nodes, Selector: args.Selector, ExcludeNodes: args.ExcludeNodes, ExcludeTags: args.ExcludeTags,
		Command: cp, Concurrency: args.Concurrency, MaxOutputBytes: args.MaxOutputBytes, FailFast: args.FailFast,
		Risk: risk, Approval: approval,
	})
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	return protocol.NewToolSuccessResult(rep)
}

func (r *Registry) execPlaybook(ctx context.Context, args terminalExecArgs, risk algebraic.Option[security.RiskLevel], approval algebraic.Option[gate.ApprovalSubmission]) (protocol.CallToolResult, error) {
	if r.automation == nil {
		return protocol.CallToolResult{}, domi18n.EF(ErrServiceUnavailable, domi18n.KeyCommonMissingDep, domi18n.Str("component", "AutomationService"))
	}
	pb, ok := args.Playbook.Get()
	if !ok || !pb.IsValid() {
		return protocol.CallToolResult{}, domi18n.EF(protocol.ErrInvalidParams, domi18n.KeyCommonFieldRequired, domi18n.Str("field", "playbook"))
	}
	nodes, err := r.resolveTargetNodes(ctx, args.Targets)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	// MCP 路径物理不持有 OperatorReadFS，仅可选传入沙箱根 ScopedSourceRoot（来自 TransferRoot）。
	res, err := r.automation.RunPlaybook(ctx, ucauto.PlaybookRequest{
		Playbook: pb, Targets: nodes, ScopedSourceRoot: r.transferRoot, Concurrency: args.Concurrency,
		Timeout: args.Timeout, ExtraVars: args.ExtraVars, Risk: risk, Approval: approval,
	})
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	return protocol.NewToolSuccessResult(res)
}
