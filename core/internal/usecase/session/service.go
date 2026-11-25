package session

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/ports"
)

// ServiceConfig 定义会话执行用例服务 Service 的显式出站依赖配置。
type ServiceConfig struct {
	// Gate 是必填的能力门控授权器（ADR-008：严禁 nil 逃生口）。
	Gate gate.Authorizer
	// Pool 是必填的双通道纯内存 Actor 连接池（ADR-009）。
	Pool *pool.Pool
	// Clock 是必填的时钟端口（用于事件时间戳与执行耗时统计）。
	Clock ports.Clock
	// Env 可选注入只读环境变量端口（用于按计划 EnvFilter 过滤 SendEnv 与读取 TERM）。
	Env ports.EnvPort
	// Terminal 可选注入本机原始终端端口（交互式 PTY 与 Relay 所需）。
	Terminal ports.TerminalPort
}

// Service 是 XOps v2 单命令执行与交互式 SSH 会话用例服务（Phase 2.5 Walking Skeleton 切片）；
// 零值恒未初始化并严格失败关闭。
//
//xops:opaque
//xops:failclosed
type Service struct {
	gate     gate.Authorizer
	pool     *pool.Pool
	clock    ports.Clock
	env      ports.EnvPort
	terminal ports.TerminalPort
	valid    bool
}

// NewService 校验必填依赖（Gate、Pool、Clock）并构造会话执行 Service。
func NewService(cfg ServiceConfig) (*Service, error) {
	if cfg.Gate == nil {
		return nil, fmt.Errorf("%w: Gate 授权器不能为 nil", ErrInvalidConfig)
	}
	if cfg.Pool == nil || cfg.Pool.IsClosed() {
		return nil, fmt.Errorf("%w: Pool 连接池不能为 nil 或已关闭", ErrInvalidConfig)
	}
	if cfg.Clock == nil {
		return nil, fmt.Errorf("%w: Clock 时钟端口不能为 nil", ErrInvalidConfig)
	}
	return &Service{
		gate:     cfg.Gate,
		pool:     cfg.Pool,
		clock:    cfg.Clock,
		env:      cfg.Env,
		terminal: cfg.Terminal,
		valid:    true,
	}, nil
}

// ExecRequest 描述单次远端命令执行用例的强类型输入。
type ExecRequest struct {
	Plan            plan.SealedConnectionPlan            // 必填：已封缄 Merkle 连接计划
	Command         execution.CommandPlan                // 必填：不可变命令/脚本执行计划
	NodeID          string                               // 可选：目标节点标识（为空时取计划末跳 NodeID）
	Stdin           io.Reader                            // 可选：标准输入流
	Stdout          io.Writer                            // 可选：标准输出流
	Stderr          io.Writer                            // 可选：标准错误流
	RequestTTY      RequestTTYMode                       // 可选：伪终端分配模式
	Term            string                               // 可选：显式 TERM 标识
	Risk            algebraic.Option[security.RiskLevel] // 可选：风险等级（None 默认 RiskModerate）
	Approval        algebraic.Option[gate.ApprovalSubmission]
	OperationStream *events.OperationStream // 可选：隔离操作事件流（返回前保证确定性 EOF）
}

// InteractiveRequest 描述交互式远端 Shell 会话用例的强类型输入。
type InteractiveRequest struct {
	Plan            plan.SealedConnectionPlan            // 必填：已封缄 Merkle 连接计划
	NodeID          string                               // 可选：目标节点标识（为空时取计划末跳 NodeID）
	Stdin           io.Reader                            // 非 PTY 模式下标准输入流
	Stdout          io.Writer                            // 非 PTY 模式下标准输出流
	Stderr          io.Writer                            // 标准错误流（非 PTY 或远端扩展错误输出）
	RequestTTY      RequestTTYMode                       // 可选：伪终端分配模式（Unset 默认 Auto）
	Term            string                               // 可选：显式 TERM 标识
	Risk            algebraic.Option[security.RiskLevel] // 可选：风险等级（None 默认 RiskModerate）
	Approval        algebraic.Option[gate.ApprovalSubmission]
	OperationStream *events.OperationStream // 可选：隔离操作事件流（返回前保证确定性 EOF）
}

type sessionRunSpec struct {
	plan            plan.SealedConnectionPlan
	command         algebraic.Option[execution.CommandPlan]
	action          string
	nodeID          string
	stdin           io.Reader
	stdout          io.Writer
	stderr          io.Writer
	requestTTY      RequestTTYMode
	term            string
	risk            algebraic.Option[security.RiskLevel]
	approval        algebraic.Option[gate.ApprovalSubmission]
	operationStream *events.OperationStream
	summary         string
}

// Exec 执行单条远端命令（严格按 gate.WithAuthorized 包裹 pool.WithLease），
// 过滤 SendEnv、按策略决定 PTY/流模式并向可选 OperationStream 发射完整事件序列与确定性 EOF。
func (s *Service) Exec(ctx context.Context, req ExecRequest) (execution.ExecutionOutcome, error) {
	if req.OperationStream != nil {
		defer req.OperationStream.Close()
	}
	if err := s.validateBaseCall(ctx, req.Plan, req.RequestTTY, req.Risk); err != nil {
		out, _ := execution.NewOutcomeNotStarted(execution.StartPhaseValidate, "invalid_request", err.Error())
		return out, err
	}
	if !req.Command.IsValid() {
		err := fmt.Errorf("%w: CommandPlan 无效", ErrInvalidRequest)
		out, _ := execution.NewOutcomeNotStarted(execution.StartPhaseValidate, "invalid_command", err.Error())
		return out, err
	}
	if req.Command.Kind() == execution.PlanKindScript &&
		(req.Command.PTY() || req.RequestTTY == RequestTTYYes || req.RequestTTY == RequestTTYForce) {
		err := fmt.Errorf("%w: PlanKindScript 经 stdin 投递脚本正文，禁止与 RequestTTY yes/force 或 PTY 组合", ErrInvalidRequest)
		out, _ := execution.NewOutcomeNotStarted(execution.StartPhaseValidate, "invalid_script_tty", err.Error())
		return out, err
	}
	return s.executeSession(ctx, sessionRunSpec{
		plan:            req.Plan,
		command:         algebraic.Some(req.Command),
		action:          "exec",
		nodeID:          req.NodeID,
		stdin:           req.Stdin,
		stdout:          req.Stdout,
		stderr:          req.Stderr,
		requestTTY:      req.RequestTTY,
		term:            req.Term,
		risk:            req.Risk,
		approval:        req.Approval,
		operationStream: req.OperationStream,
		summary:         req.Command.RedactedSummary(),
	})
}

// Interactive 启动远端交互式 Shell 会话（严格按 gate.WithAuthorized 包裹 pool.WithLease），
// 按 RequestTTY 策略经 TerminalPort.WithRawTerminal + TerminalHandle.Relay 中继交互流与窗口缩放。
func (s *Service) Interactive(ctx context.Context, req InteractiveRequest) (execution.ExecutionOutcome, error) {
	if req.OperationStream != nil {
		defer req.OperationStream.Close()
	}
	if err := s.validateBaseCall(ctx, req.Plan, req.RequestTTY, req.Risk); err != nil {
		out, _ := execution.NewOutcomeNotStarted(execution.StartPhaseValidate, "invalid_request", err.Error())
		return out, err
	}
	return s.executeSession(ctx, sessionRunSpec{
		plan:            req.Plan,
		command:         algebraic.None[execution.CommandPlan](),
		action:          "shell",
		nodeID:          req.NodeID,
		stdin:           req.Stdin,
		stdout:          req.Stdout,
		stderr:          req.Stderr,
		requestTTY:      req.RequestTTY,
		term:            req.Term,
		risk:            req.Risk,
		approval:        req.Approval,
		operationStream: req.OperationStream,
		summary:         "interactive shell",
	})
}

func (s *Service) validateBaseCall(
	ctx context.Context,
	connPlan plan.SealedConnectionPlan,
	ttyMode RequestTTYMode,
	risk algebraic.Option[security.RiskLevel],
) error {
	if s == nil || !s.valid {
		return ErrServiceNotInitialized
	}
	if ctx == nil {
		return ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !connPlan.IsValid() {
		return fmt.Errorf("%w: SealedConnectionPlan 无效", ErrInvalidRequest)
	}
	if !ttyMode.IsZero() && !ttyMode.IsValid() {
		return ErrInvalidRequestTTY
	}
	if r, ok := risk.Get(); ok && !r.IsValid() {
		return fmt.Errorf("%w: RiskLevel 无效", ErrInvalidRequest)
	}
	return nil
}

func (s *Service) executeSession(ctx context.Context, spec sessionRunSpec) (execution.ExecutionOutcome, error) {
	targetHop, ok := spec.plan.Target()
	if !ok {
		err := fmt.Errorf("%w: 连接计划缺少末跳目标", ErrInvalidRequest)
		out, _ := execution.NewOutcomeNotStarted(execution.StartPhaseValidate, "invalid_plan", err.Error())
		return out, err
	}
	nodeID := spec.nodeID
	if nodeID == "" {
		nodeID = targetHop.NodeID()
	}
	gateReq, err := buildSessionGateRequest(spec, targetHop, nodeID)
	if err != nil {
		out, _ := execution.NewOutcomeNotStarted(execution.StartPhaseValidate, "invalid_binding", err.Error())
		return out, err
	}
	return s.runAuthorizedSession(ctx, spec, targetHop, nodeID, gateReq)
}

func buildSessionGateRequest(
	spec sessionRunSpec,
	targetHop plan.HopSpec,
	nodeID string,
) (gate.GateRequest[security.CapExecute], error) {
	var zeroReq gate.GateRequest[security.CapExecute]
	var cmdDigOpt algebraic.Option[security.Digest]
	if cmd, hasCmd := spec.command.Get(); hasCmd {
		dig, err := cmd.Digest()
		if err != nil {
			return zeroReq, err
		}
		cmdDigOpt = algebraic.Some(dig)
	}
	binding, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability:    security.CapabilityExecute,
		Tool:          "ssh",
		Action:        spec.action,
		NodeID:        nodeID,
		Endpoint:      algebraic.Some(targetHop.Endpoint()),
		CommandDigest: cmdDigOpt,
		PlanDigest:    algebraic.Some(spec.plan.PlanDigest().SecurityDigest()),
		Parameters: map[string]string{
			"user": targetHop.Username().String(),
		},
	})
	if err != nil {
		return zeroReq, err
	}
	return gate.NewGateRequest[security.CapExecute](gate.GateRequestSpec[security.CapExecute]{
		Binding:         binding,
		Risk:            spec.risk.OrElse(security.RiskModerate),
		ScopeSummary:    spec.summary,
		Approval:        spec.approval,
		OperationStream: spec.operationStream,
	})
}

// runAuthorizedSession 严格遵循 ADR-008 / ADR-009 嵌套铁律：
// 先进入 gate.WithAuthorized[security.CapExecute]，再在其回调内部调用 pool.WithLease；
// OperationCompletedEvent 在 gate.WithAuthorized 完整闭合终态审计后发射，以真实反映审计/熔断结果。
func (s *Service) runAuthorizedSession(
	ctx context.Context,
	spec sessionRunSpec,
	targetHop plan.HopSpec,
	nodeID string,
	gateReq gate.GateRequest[security.CapExecute],
) (execution.ExecutionOutcome, error) {
	var outcome execution.ExecutionOutcome
	var enteredAuth bool
	var emitter *operationEmitter
	var startedAt time.Time
	gateErr := gate.WithAuthorized[security.CapExecute](ctx, s.gate, gateReq, func(authCtx context.Context, auth gate.Authorized[security.CapExecute]) error {
		enteredAuth = true
		startedAt = s.clock.Now().UTC().Round(0)
		emitter = newOperationEmitter(spec.operationStream, s.clock, auth.TraceID(), auth.OperationID(), nodeID)
		emitter.emitStarted(authCtx, spec.action, spec.plan.PlanDigest(), spec.summary)

		runCtx, cancelTimeout := applyCommandTimeout(authCtx, spec.command)
		defer cancelTimeout()

		var runErr error
		outcome, runErr = s.runLeasedSession(runCtx, spec, targetHop, emitter)
		if outcome != nil && outcome.IsValid() {
			_ = auth.ReportOutcome(outcome)
		}
		return runErr
	})
	if !enteredAuth {
		out, _ := execution.NewOutcomeNotStarted(execution.StartPhaseAuthorize, "authorization_failed", gateErr.Error())
		return out, gateErr
	}
	if outcome == nil || !outcome.IsValid() {
		outcome = outcomeForAbortedRun(ctx, gateErr)
	}
	emitter.emitCompleted(ctx, startedAt, outcome, gateErr)
	return outcome, gateErr
}

func (s *Service) runLeasedSession(
	ctx context.Context,
	spec sessionRunSpec,
	targetHop plan.HopSpec,
	emitter *operationEmitter,
) (execution.ExecutionOutcome, error) {
	var outcome execution.ExecutionOutcome
	var enteredLease bool
	leaseErr := s.pool.WithLease(ctx, spec.plan, func(leaseCtx context.Context, lease *pool.Lease) error {
		enteredLease = true
		var sErr error
		outcome, sErr = s.runOnLease(leaseCtx, lease, spec, targetHop, emitter)
		return sErr
	})
	if !enteredLease {
		out, _ := execution.NewOutcomeNotStarted(execution.StartPhaseDial, "lease_failed", leaseErr.Error())
		return out, leaseErr
	}
	return outcome, leaseErr
}

func (s *Service) runOnLease(
	leaseCtx context.Context,
	lease *pool.Lease,
	spec sessionRunSpec,
	targetHop plan.HopSpec,
	emitter *operationEmitter,
) (execution.ExecutionOutcome, error) {
	sess, err := lease.OpenSession(leaseCtx)
	if err != nil {
		out, _ := execution.NewOutcomeNotStarted(execution.StartPhaseSessionOpen, "open_session_failed", err.Error())
		return out, err
	}
	defer func() { _ = sess.Close() }()

	sendEnv := s.filterSendEnv(targetHop)
	termName := resolvePTYTerm(spec.term, s.env)
	cmd, hasCmd := spec.command.Get()
	localInteractive := s.terminal != nil && s.terminal.IsInteractive()
	decision := resolveTTYDecision(spec.requestTTY, !hasCmd, hasCmd && cmd.PTY(), localInteractive)

	starter := buildSessionStarter(spec.command, sess)
	if decision.useRawTerminal {
		return runRawTerminalSession(
			leaseCtx, sess, s.terminal, starter, termName, sendEnv, spec.stderr, emitter, decision.requestPTY,
		)
	}
	return runStreamSession(
		leaseCtx, sess, starter, termName, sendEnv, spec.stdin, spec.stdout, spec.stderr, emitter, decision.requestPTY,
	)
}

func buildSessionStarter(cmdOpt algebraic.Option[execution.CommandPlan], sess ports.RemoteSession) sessionStarter {
	if cmd, ok := cmdOpt.Get(); ok {
		return func(c context.Context, streams ports.ExecStreams) error {
			return sess.Start(c, cmd, streams)
		}
	}
	return func(c context.Context, streams ports.ExecStreams) error {
		return sess.StartShell(c, streams)
	}
}

func (s *Service) filterSendEnv(targetHop plan.HopSpec) map[string]string {
	filter := targetHop.Transport().SendEnv()
	if filter.IsUnset() || s.env == nil {
		return nil
	}
	return filter.Filter(s.env.Environ())
}

func applyCommandTimeout(ctx context.Context, cmdOpt algebraic.Option[execution.CommandPlan]) (context.Context, context.CancelFunc) {
	if cmd, ok := cmdOpt.Get(); ok {
		if d, hasTimeout := cmd.Timeout().Get(); hasTimeout && d.IsPositive() {
			return context.WithTimeout(ctx, d.Std())
		}
	}
	return ctx, func() {}
}
