package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/ports"
)

// PrivilegeExecRequest 描述远端提权执行（sudo/su/doas）用例的强类型输入（ADR-008 / ADR-011 / P3-T2）。
// 提权口令严禁以明文字节传递，仅允许经 Vault PasswordRef 或交互 PromptPassword 在同步闭包内借用传递。
type PrivilegeExecRequest struct {
	Plan                  plan.SealedConnectionPlan
	Privilege             ports.PrivilegeRequest
	NodeID, Term          string
	PasswordRef           algebraic.Option[secret.Ref]
	PromptPassword        bool
	Paths, RecursivePaths []string
	LexicalScope          algebraic.Option[security.ScopeSnapshot]
	Canonicalize          gate.CanonicalizeFunc
	Stdin                 io.Reader
	Stdout, Stderr        io.Writer
	RequestTTY            RequestTTYMode
	Risk                  algebraic.Option[security.RiskLevel]
	Approval              algebraic.Option[gate.ApprovalSubmission]
	OperationStream       *events.OperationStream
}

// ProbeShellRequest 描述远端 2 阶段默认 Shell 方言与解释器探测用例的强类型输入（P3-T2）。
type ProbeShellRequest struct {
	Plan            plan.SealedConnectionPlan
	NodeID          string
	Timeout         algebraic.Option[algebraic.Duration]
	Risk            algebraic.Option[security.RiskLevel]
	Approval        algebraic.Option[gate.ApprovalSubmission]
	OperationStream *events.OperationStream
}

// ExecPrivileged 执行远端提权命令（sudo/su/doas）：经 security.CanonicalScopeEscalated 复核提权作用域，
// 强制 gate.WithAuthorized[security.CapExecute] 包裹 pool.WithLease，并经作用域借用透传提权口令（0 明文消费）。
func (s *Service) ExecPrivileged(ctx context.Context, req PrivilegeExecRequest) (execution.ExecutionOutcome, error) {
	defer closeStream(req.OperationStream)
	if err := s.validatePrivilegeCall(ctx, req); err != nil {
		return notStartedSessionOutcome(execution.StartPhaseValidate, "invalid_privilege_request", err), err
	}
	targetHop, nodeID, err := resolvePlanTargetAndNode(req.Plan, req.NodeID)
	if err != nil {
		return notStartedSessionOutcome(execution.StartPhaseValidate, "invalid_plan", err), err
	}
	gateReq, err := buildPrivilegeGateRequest(req, targetHop, nodeID)
	if err != nil {
		code := "invalid_binding"
		if errors.Is(err, ErrEscalationScopeChanged) {
			code = "scope_escalated"
		}
		return notStartedSessionOutcome(execution.StartPhaseValidate, code, err), err
	}
	out, entered, gateErr := runAuthorized[security.CapExecute](ctx, s, req.Plan.PlanDigest(), nodeID, "exec_privileged", gateReq, req.OperationStream, true,
		func(authCtx context.Context, _ security.OperationBinding, emitter *operationEmitter) (execution.ExecutionOutcome, error) {
			runCtx, cancel := applyOptionalTimeout(authCtx, resolvePrivilegeTimeout(req.Privilege))
			defer cancel()
			return s.runLeasedPrivilege(runCtx, req, targetHop, nodeID, emitter)
		})
	if !entered {
		return notStartedSessionOutcome(execution.StartPhaseAuthorize, "authorization_failed", gateErr), gateErr
	}
	return out, gateErr
}

func (s *Service) validatePrivilegeCall(ctx context.Context, req PrivilegeExecRequest) error {
	if err := s.validateBaseCall(ctx, req.Plan, req.RequestTTY, req.Risk); err != nil {
		return err
	}
	if s.cfg.Escalator == nil {
		return fmt.Errorf("%w: PrivilegeEscalationPort 未配置", ErrPortUnavailable)
	}
	if !req.Privilege.IsValid() {
		return fmt.Errorf("%w: PrivilegeRequest 无效", ErrInvalidRequest)
	}
	if cmd := req.Privilege.Command(); cmd.Kind() == execution.PlanKindScript && (cmd.PTY() || req.RequestTTY == RequestTTYYes || req.RequestTTY == RequestTTYForce) {
		return fmt.Errorf("%w: 提权脚本计划禁止与 RequestTTY yes/force 或 PTY 组合", ErrInvalidRequest)
	}
	if lex, ok := req.LexicalScope.Get(); ok && !lex.IsValid() {
		return fmt.Errorf("%w: 提供的 LexicalScope 快照无效", ErrEscalationScopeChanged)
	}
	return s.validatePrivilegeSecretSource(req)
}

func (s *Service) validatePrivilegeSecretSource(req PrivilegeExecRequest) error {
	ref, hasRef := req.PasswordRef.Get()
	if (hasRef && !ref.IsValid()) || (req.PromptPassword && req.Privilege.NonInteractive()) {
		return fmt.Errorf("%w: 提权口令源配置冲突或 PasswordRef 无效", ErrInvalidRequest)
	}
	if req.Privilege.NonInteractive() {
		return nil
	}
	if hasRef && s.cfg.Vault == nil {
		return fmt.Errorf("%w: 使用 PasswordRef 需要配置 SecretVault", ErrPortUnavailable)
	}
	if !hasRef && req.PromptPassword && (s.cfg.Interaction == nil || !s.cfg.Interaction.CanInteract()) {
		return fmt.Errorf("%w: 提权口令交互提示不可用", ports.ErrInteractionUnavailable)
	}
	return nil
}

func buildPrivilegeGateRequest(req PrivilegeExecRequest, targetHop plan.HopSpec, nodeID string) (gate.GateRequest[security.CapExecute], error) {
	cmd := req.Privilege.Command()
	cmdDig, err := cmd.Digest()
	if err != nil {
		return zeroVal[gate.GateRequest[security.CapExecute]](), err
	}
	paths := slices.Clone(req.Paths)
	if wd, ok := cmd.WorkDir().Get(); ok && wd.IsValid() && !slices.Contains(paths, wd.String()) {
		paths = append(paths, wd.String())
	}
	effRisk, floorOpt, scopeEscalated, err := evaluatePrivilegeEscalationScope(req, targetHop, nodeID, paths)
	if err != nil {
		return zeroVal[gate.GateRequest[security.CapExecute]](), err
	}
	targetUser := "root"
	if u, ok := req.Privilege.TargetUser().Get(); ok && u.IsValid() {
		targetUser = u.String()
	}
	return buildGateReq[security.CapExecute](gateReqInput{
		plan: req.Plan, targetHop: targetHop, nodeID: nodeID, action: "exec_privileged",
		summary: fmt.Sprintf("%s: %s", req.Privilege.Method().String(), cmd.RedactedSummary()),
		risk:    effRisk, cmdDigest: algebraic.Some(cmdDig), paths: paths, recursivePaths: req.RecursivePaths,
		params: map[string]string{
			"user": targetHop.Username().String(), "privilege_method": req.Privilege.Method().String(),
			"target_user": targetUser, "non_interactive": strconv.FormatBool(req.Privilege.NonInteractive()),
			"scope_escalated": strconv.FormatBool(scopeEscalated),
		},
		decisionFloor: floorOpt, canonicalize: req.Canonicalize, approval: req.Approval, stream: req.OperationStream,
	})
}

// evaluatePrivilegeEscalationScope 构造提权规范作用域（风险下限恒为 RiskDangerous）并经
// security.CanonicalScopeEscalated / InspectScopeEscalation 复核提权前后作用域：
// 身份漂移或判定收紧立即拒绝；存在词法作用域升级时抬升 DecisionFloor 为 NeedApproval。
func evaluatePrivilegeEscalationScope(req PrivilegeExecRequest, targetHop plan.HopSpec, nodeID string, paths []string) (security.RiskLevel, algebraic.Option[security.GuardrailDecision], bool, error) {
	noneFloor, effRisk := algebraic.None[security.GuardrailDecision](), security.RiskDangerous
	if r, ok := req.Risk.Get(); ok {
		effRisk = effRisk.Join(r)
	}
	needApp, err := security.NewDecisionNeedApproval(effRisk, "privilege escalation requires approval")
	if err != nil {
		return effRisk, noneFloor, false, err
	}
	scopedPaths, err := buildScopedPaths(paths, req.RecursivePaths)
	if err != nil {
		return effRisk, noneFloor, false, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	mkSnap := func(risk security.RiskLevel, dec security.GuardrailDecision) (security.ScopeSnapshot, error) {
		return security.NewScopeSnapshot(security.ScopeSnapshotSpec{
			Capability: security.CapabilityExecute, TargetNode: nodeID, Endpoint: algebraic.Some(targetHop.Endpoint()),
			Verdict: security.VerdictAllow, Risk: risk, Decision: dec, Paths: scopedPaths,
		})
	}
	canonicalSnap, err := mkSnap(effRisk, needApp)
	if err != nil {
		return effRisk, noneFloor, false, err
	}
	if lex, hasLex := req.LexicalScope.Get(); hasLex {
		escRes := security.InspectScopeEscalation(lex, canonicalSnap)
		if hasScopeDriftOrTighten(escRes) {
			return effRisk, noneFloor, true, fmt.Errorf("%w: 提权作用域身份漂移或判定收紧（%v）", ErrEscalationScopeChanged, escRes.Reasons())
		}
		if security.CanonicalScopeEscalated(lex, canonicalSnap) {
			return effRisk, algebraic.Some(security.GuardrailDecision(needApp)), true, nil
		}
		return effRisk, noneFloor, false, nil
	}
	baseSnap, err := mkSnap(req.Risk.OrElse(security.RiskModerate), security.NewDecisionAllow("pre-escalation baseline"))
	if err != nil {
		return effRisk, noneFloor, false, err
	}
	return effRisk, noneFloor, security.CanonicalScopeEscalated(baseSnap, canonicalSnap), nil
}

func hasScopeDriftOrTighten(r security.ScopeEscalationResult) bool {
	return r.HasReason(security.EscalationInvalidInput) || r.HasReason(security.EscalationCapabilityDrift) ||
		r.HasReason(security.EscalationTargetNodeDrift) || r.HasReason(security.EscalationEndpointDrift) ||
		r.HasReason(security.EscalationVerdictTightened)
}

func buildScopedPaths(direct, recursive []string) ([]security.ScopedPath, error) {
	out := make([]security.ScopedPath, 0, len(direct)+len(recursive))
	add := func(list []string, rec bool) error {
		for _, p := range list {
			sp, err := security.NewScopedPath(p, rec)
			if err != nil {
				return err
			}
			out = append(out, sp)
		}
		return nil
	}
	if err := add(direct, false); err != nil {
		return nil, err
	}
	return out, add(recursive, true)
}

func (s *Service) runLeasedPrivilege(ctx context.Context, req PrivilegeExecRequest, targetHop plan.HopSpec, nodeID string, emitter *operationEmitter) (execution.ExecutionOutcome, error) {
	var outcome execution.ExecutionOutcome
	var enteredLease bool
	leaseErr := s.cfg.Pool.WithLease(ctx, req.Plan, func(leaseCtx context.Context, lease *pool.Lease) error {
		enteredLease = true
		streams, err := s.buildPrivilegeStreams(leaseCtx, req, targetHop, emitter)
		if err != nil {
			outcome = notStartedSessionOutcome(execution.StartPhaseValidate, "invalid_pty", err)
			return err
		}
		return s.withPrivilegePassword(leaseCtx, req, nodeID, func(passBox *secret.SecretBox) error {
			out, rErr := s.cfg.Escalator.RunPrivileged(leaseCtx, lease, req.Privilege, passBox, streams)
			outcome = classifyPrivilegeOutcome(leaseCtx, out, rErr)
			return rErr
		})
	})
	if !enteredLease {
		return notStartedSessionOutcome(execution.StartPhaseDial, "lease_failed", leaseErr), leaseErr
	}
	if outcome == nil || !outcome.IsValid() {
		outcome = classifyPrivilegeOutcome(ctx, nil, leaseErr)
	}
	return outcome, leaseErr
}

func (s *Service) buildPrivilegeStreams(ctx context.Context, req PrivilegeExecRequest, targetHop plan.HopSpec, emitter *operationEmitter) (ports.ExecStreams, error) {
	var ptyOpt algebraic.Option[ports.PTYRequest]
	if localInteractive := s.cfg.Terminal != nil && s.cfg.Terminal.IsInteractive(); resolveTTYDecision(req.RequestTTY, false, req.Privilege.Command().PTY(), localInteractive).requestPTY {
		var sz ports.TerminalSize
		if localInteractive {
			sz, _ = s.cfg.Terminal.Size()
		}
		ptyReq, err := buildPTYRequest(resolvePTYTerm(req.Term, s.cfg.Env), sz)
		if err != nil {
			return ports.ExecStreams{}, err
		}
		ptyOpt = algebraic.Some(ptyReq)
	}
	return ports.ExecStreams{
		Stdin: req.Stdin, Stdout: wrapOutputWriter(ctx, req.Stdout, emitter, events.OutputStreamStdout),
		Stderr: wrapOutputWriter(ctx, req.Stderr, emitter, events.OutputStreamStderr), PTY: ptyOpt, Env: s.filterSendEnv(targetHop),
	}, nil
}

// withPrivilegePassword 在同步作用域闭包内借用可选提权口令 *secret.SecretBox 并透传给回调（0 明文消费）。
//
//xops:syncclosure
//xops:borrowed
func (s *Service) withPrivilegePassword(ctx context.Context, req PrivilegeExecRequest, nodeID string, fn func(passBox *secret.SecretBox) error) error {
	if req.Privilege.NonInteractive() {
		return fn(nil)
	}
	if ref, hasRef := req.PasswordRef.Get(); hasRef {
		return s.cfg.Vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error { return fn(box) })
	}
	if !req.PromptPassword {
		return fn(nil)
	}
	promptReq, err := ports.NewSecretPromptRequest(ports.SecretPromptRequestSpec{Title: "Privilege Escalation", Prompt: fmt.Sprintf("Enter %s password for %s", req.Privilege.Method().String(), nodeID), Subject: nodeID})
	if err != nil {
		return err
	}
	return s.cfg.Interaction.PromptSecret(ctx, promptReq, func(box *secret.SecretBox) error { return fn(box) })
}

func resolvePrivilegeTimeout(priv ports.PrivilegeRequest) algebraic.Option[algebraic.Duration] {
	pDur, hasP := priv.Timeout().Get()
	cDur, hasC := priv.Command().Timeout().Get()
	if hasP && (!hasC || pDur.Std() <= cDur.Std()) {
		return algebraic.Some(pDur)
	}
	return priv.Command().Timeout()
}

func classifyPrivilegeOutcome(ctx context.Context, out execution.ExecutionOutcome, runErr error) execution.ExecutionOutcome {
	if out != nil && out.IsValid() {
		return out
	}
	if runErr == nil {
		return outcomeForAbortedRun(ctx, errors.New("privilege escalator returned empty outcome"))
	}
	for _, t := range []error{ports.ErrAuthFailed, ports.ErrVaultLocked, ports.ErrSecretNotFound, ports.ErrInteractionUnavailable, ports.ErrInteractionCanceled, ports.ErrInvalidArgument, ports.ErrUnsupported} {
		if errors.Is(runErr, t) {
			return notStartedSessionOutcome(execution.StartPhaseRequestRejected, "privilege_prestart_failed", runErr)
		}
	}
	return outcomeForAbortedRun(ctx, runErr)
}

func notStartedSessionOutcome(phase execution.StartPhase, code string, err error) execution.ExecutionOutcome {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	out, _ := execution.NewOutcomeNotStarted(phase, code, msg)
	return out
}

// ProbeShell 通过冻结的 ports.ShellProbePort 执行规范化 2 阶段远端 Shell 探测：
// 严格经 gate.WithAuthorized[security.CapInspect] 包裹 pool.WithLease，并对探测快照实施二次失败关闭校验（零盲猜回退）。
func (s *Service) ProbeShell(ctx context.Context, req ProbeShellRequest) (ports.ShellProbeResult, error) {
	defer closeStream(req.OperationStream)
	zr := zeroVal[ports.ShellProbeResult]()
	if err := s.validateBaseCall(ctx, req.Plan, RequestTTYUnset, req.Risk); err != nil {
		return zr, err
	}
	if s.cfg.ShellProbe == nil {
		return zr, fmt.Errorf("%w: ShellProbePort 未配置", ErrPortUnavailable)
	}
	if d, ok := req.Timeout.Get(); ok && !d.IsPositive() {
		return zr, fmt.Errorf("%w: ProbeShell Timeout 必须为正时长", ErrInvalidRequest)
	}
	targetHop, nodeID, err := resolvePlanTargetAndNode(req.Plan, req.NodeID)
	if err != nil {
		return zr, err
	}
	gateReq, err := buildGateReq[security.CapInspect](gateReqInput{
		plan: req.Plan, targetHop: targetHop, nodeID: nodeID, action: "probe_shell",
		summary: fmt.Sprintf("probe remote shell on %s", nodeID), risk: req.Risk.OrElse(security.RiskSafe),
		params: map[string]string{"user": targetHop.Username().String()}, approval: req.Approval, stream: req.OperationStream,
	})
	if err != nil {
		return zr, err
	}
	var result ports.ShellProbeResult
	if _, _, gateErr := runAuthorized[security.CapInspect](ctx, s, req.Plan.PlanDigest(), nodeID, "probe_shell", gateReq, req.OperationStream, false,
		func(authCtx context.Context, _ security.OperationBinding, _ *operationEmitter) (execution.ExecutionOutcome, error) {
			runCtx, cancel := applyOptionalTimeout(authCtx, req.Timeout)
			defer cancel()
			return nil, s.cfg.Pool.WithLease(runCtx, req.Plan, func(leaseCtx context.Context, lease *pool.Lease) error {
				raw, pErr := s.cfg.ShellProbe.ProbeShell(leaseCtx, lease)
				if pErr != nil {
					return pErr
				}
				var nErr error
				result, nErr = normalizeShellProbeResult(raw)
				return nErr
			})
		}); gateErr != nil {
		return zr, gateErr
	}
	return result, nil
}

func normalizeShellProbeResult(raw ports.ShellProbeResult) (ports.ShellProbeResult, error) {
	if !raw.IsValid() || !raw.Dialect().IsValid() || !raw.Interpreter().IsValid() || !raw.LaunchProfile().IsValid() || raw.Dialect() == execution.DialectUnknown {
		return zeroVal[ports.ShellProbeResult](), fmt.Errorf("%w: 探测快照缺少有效方言、解释器或 LaunchProfile", ErrInvalidProbeResult)
	}
	if stage := raw.ProbeStage(); stage != 1 && stage != 2 {
		return zeroVal[ports.ShellProbeResult](), fmt.Errorf("%w: 探测阶段 %d 非法（仅允许 1 或 2）", ErrInvalidProbeResult, stage)
	}
	norm, err := ports.NewShellProbeResult(ports.ShellProbeResultSpec{Dialect: raw.Dialect(), Interpreter: raw.Interpreter(), OSFamily: raw.OSFamily(), ProbeStage: raw.ProbeStage(), RawBanner: raw.RawBanner()})
	if err != nil {
		return zeroVal[ports.ShellProbeResult](), fmt.Errorf("%w: %w", ErrInvalidProbeResult, err)
	}
	return norm, nil
}
