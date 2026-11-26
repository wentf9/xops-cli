package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
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
	Gate        gate.Authorizer               // 必填：能力门控授权器（ADR-008：严禁 nil）
	Pool        *pool.Pool                    // 必填：双通道纯内存 Actor 连接池（ADR-009）
	Clock       ports.Clock                   // 必填：时钟端口（事件时间戳、ControlPersist 与耗时统计）
	Env         ports.EnvPort                 // 可选：只读环境变量与本机身份端口
	Terminal    ports.TerminalPort            // 可选：本机原始终端端口
	Escalator   ports.PrivilegeEscalationPort // 可选：远端提权（sudo/su/doas）端口
	Vault       ports.SecretVault             // 可选：全作用域凭据库端口
	Interaction ports.InteractionPort         // 可选：人工交互端口
	ShellProbe  ports.ShellProbePort          // 可选：2 阶段远端 Shell 探测端口
	Forwarder   ports.ForwarderPort           // 可选：-L/-R/-D/StreamLocal/TUN 转发端口
	TUNDevice   ports.TUNDevicePort           // 可选：本机 TUN/TAP 虚拟网卡端口
	MuxSocket   ports.MuxSocketPort           // 可选：ControlMaster AF_UNIX 控制面端口
}

// Service 是 XOps v2 全量会话、提权、探测、持久 PTY、隧道转发与多路复用控制面用例服务；
// 零值恒未初始化并严格失败关闭。
//
//xops:opaque
//xops:failclosed
type Service struct {
	cfg   ServiceConfig
	valid bool
}

// NewService 校验必填依赖（Gate、Pool、Clock）并构造会话执行 Service。
func NewService(cfg ServiceConfig) (*Service, error) {
	if cfg.Gate == nil || cfg.Pool == nil || cfg.Pool.IsClosed() || cfg.Clock == nil {
		return nil, fmt.Errorf("%w: Gate/Pool/Clock 为必填且不可关闭", ErrInvalidConfig)
	}
	return &Service{cfg: cfg, valid: true}, nil
}

// CanSuspendProcessGroup 委托 TerminalPort 执行 POSIX 孤儿进程组安全挂起判定（INV-E1）；
// 未初始化、未配置 TerminalPort 或底层异常时严格失败关闭返回 (security.VerdictDeny, error)。
func (s *Service) CanSuspendProcessGroup() (security.Verdict, error) {
	if s == nil || !s.valid {
		return security.VerdictDeny, ErrServiceNotInitialized
	}
	if s.cfg.Terminal == nil {
		return security.VerdictDeny, fmt.Errorf("%w: TerminalPort 未配置", ErrPortUnavailable)
	}
	v, err := s.cfg.Terminal.CanSuspendProcessGroup()
	if err != nil || !v.IsValid() {
		return security.VerdictDeny, firstNonNilErr(err, ports.ErrInvalidArgument)
	}
	return v.Normalize(), nil
}

// ExecRequest 描述单次远端命令执行用例的强类型输入。
type ExecRequest struct {
	Plan            plan.SealedConnectionPlan
	Command         execution.CommandPlan
	NodeID, Term    string
	Stdin           io.Reader
	Stdout, Stderr  io.Writer
	RequestTTY      RequestTTYMode
	Risk            algebraic.Option[security.RiskLevel]
	Approval        algebraic.Option[gate.ApprovalSubmission]
	OperationStream *events.OperationStream
}

// InteractiveRequest 描述交互式远端 Shell 会话用例的强类型输入。
type InteractiveRequest struct {
	Plan            plan.SealedConnectionPlan
	NodeID, Term    string
	Stdin           io.Reader
	Stdout, Stderr  io.Writer
	RequestTTY      RequestTTYMode
	Risk            algebraic.Option[security.RiskLevel]
	Approval        algebraic.Option[gate.ApprovalSubmission]
	OperationStream *events.OperationStream
}

type sessionRunSpec struct {
	plan                 plan.SealedConnectionPlan
	command              algebraic.Option[execution.CommandPlan]
	action, nodeID, term string
	summary              string
	stdin                io.Reader
	stdout, stderr       io.Writer
	requestTTY           RequestTTYMode
	risk                 algebraic.Option[security.RiskLevel]
	approval             algebraic.Option[gate.ApprovalSubmission]
	operationStream      *events.OperationStream
}

// Exec 执行单条远端命令（严格按 gate.WithAuthorized 包裹 pool.WithLease），
// 过滤 SendEnv、按策略决定 PTY/流模式并向可选 OperationStream 发射完整事件序列与确定性 EOF。
func (s *Service) Exec(ctx context.Context, req ExecRequest) (execution.ExecutionOutcome, error) {
	defer closeStream(req.OperationStream)
	if err := s.validateBaseCall(ctx, req.Plan, req.RequestTTY, req.Risk); err != nil {
		return notStartedSessionOutcome(execution.StartPhaseValidate, "invalid_request", err), err
	}
	if !req.Command.IsValid() {
		err := fmt.Errorf("%w: CommandPlan 无效", ErrInvalidRequest)
		return notStartedSessionOutcome(execution.StartPhaseValidate, "invalid_command", err), err
	}
	if err := validateScriptTTY(req.Command, req.RequestTTY); err != nil {
		return notStartedSessionOutcome(execution.StartPhaseValidate, "invalid_script_tty", err), err
	}
	return s.executeSession(ctx, sessionRunSpec{plan: req.Plan, command: algebraic.Some(req.Command), action: "exec", nodeID: req.NodeID, term: req.Term, stdin: req.Stdin, stdout: req.Stdout, stderr: req.Stderr, requestTTY: req.RequestTTY, risk: req.Risk, approval: req.Approval, operationStream: req.OperationStream, summary: req.Command.RedactedSummary()})
}

// Interactive 启动远端交互式 Shell 会话（严格按 gate.WithAuthorized 包裹 pool.WithLease），
// 按 RequestTTY 策略经 TerminalPort.WithRawTerminal + TerminalHandle.Relay 中继交互流与窗口缩放。
func (s *Service) Interactive(ctx context.Context, req InteractiveRequest) (execution.ExecutionOutcome, error) {
	defer closeStream(req.OperationStream)
	if err := s.validateBaseCall(ctx, req.Plan, req.RequestTTY, req.Risk); err != nil {
		return notStartedSessionOutcome(execution.StartPhaseValidate, "invalid_request", err), err
	}
	return s.executeSession(ctx, sessionRunSpec{plan: req.Plan, command: algebraic.None[execution.CommandPlan](), action: "shell", nodeID: req.NodeID, term: req.Term, stdin: req.Stdin, stdout: req.Stdout, stderr: req.Stderr, requestTTY: req.RequestTTY, risk: req.Risk, approval: req.Approval, operationStream: req.OperationStream, summary: "interactive shell"})
}
func zeroVal[T any]() (z T) { return z }
func closeStream(stream *events.OperationStream) {
	if stream != nil {
		stream.Close()
	}
}
func closeClosers(cs ...io.Closer) error {
	var errs []error
	for _, c := range cs {
		if c != nil {
			errs = append(errs, c.Close())
		}
	}
	return errors.Join(errs...)
}

type firstErr struct {
	mu  sync.Mutex
	err error
}

func (e *firstErr) record(err error) {
	if err != nil {
		e.mu.Lock()
		if e.err == nil {
			e.err = err
		}
		e.mu.Unlock()
	}
}
func (e *firstErr) get() error { e.mu.Lock(); defer e.mu.Unlock(); return e.err }
func validateScriptTTY(cmd execution.CommandPlan, tty RequestTTYMode) error {
	if cmd.Kind() == execution.PlanKindScript && (cmd.PTY() || tty == RequestTTYYes || tty == RequestTTYForce) {
		return fmt.Errorf("%w: PlanKindScript 经 stdin 投递脚本正文，禁止与 RequestTTY yes/force 或 PTY 组合", ErrInvalidRequest)
	}
	return nil
}
func (s *Service) validateServiceAndCtx(ctx context.Context) error {
	switch {
	case s == nil || !s.valid:
		return ErrServiceNotInitialized
	case ctx == nil:
		return ErrNilContext
	default:
		return ctx.Err()
	}
}
func (s *Service) validateBaseCall(ctx context.Context, connPlan plan.SealedConnectionPlan, ttyMode RequestTTYMode, risk algebraic.Option[security.RiskLevel]) error {
	if err := s.validateServiceAndCtx(ctx); err != nil {
		return err
	}
	switch {
	case !connPlan.IsValid():
		return fmt.Errorf("%w: SealedConnectionPlan 无效", ErrInvalidRequest)
	case !ttyMode.IsZero() && !ttyMode.IsValid():
		return ErrInvalidRequestTTY
	case risk.IsSome() && !risk.OrElse(security.RiskUnknown).IsValid():
		return fmt.Errorf("%w: RiskLevel 无效", ErrInvalidRequest)
	}
	return nil
}
func resolvePlanTargetAndNode(connPlan plan.SealedConnectionPlan, explicitNodeID string) (plan.HopSpec, string, error) {
	targetHop, ok := connPlan.Target()
	if !ok {
		return zeroVal[plan.HopSpec](), "", fmt.Errorf("%w: 连接计划缺少末跳目标", ErrInvalidRequest)
	}
	if explicitNodeID == "" {
		explicitNodeID = targetHop.NodeID()
	}
	return targetHop, explicitNodeID, nil
}
func applyOptionalTimeout(ctx context.Context, durOpt algebraic.Option[algebraic.Duration]) (context.Context, context.CancelFunc) {
	if d, ok := durOpt.Get(); ok && d.IsPositive() {
		return context.WithTimeout(ctx, d.Std())
	}
	return ctx, func() {}
}

// registerSyncAbort 在 ctx 取消时同步触发 abort；返回的清理函数保证注销或等待已触发的回调完整收敛（0 泄漏）。
func registerSyncAbort(ctx context.Context, abort func()) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(done); abort() })
	return func() {
		if !stop() {
			<-done
		}
	}
}

// deriveHandshakeContext 为单次同步建链握手合并 leaseCtx 与 revokeCtx 的取消信号，退出时同步回收 AfterFunc 防泄漏。
func deriveHandshakeContext(leaseCtx, revokeCtx context.Context) (context.Context, func()) {
	hsCtx, cancel := context.WithCancelCause(leaseCtx)
	if revokeCtx == nil || revokeCtx.Err() != nil {
		if revokeCtx != nil {
			cancel(context.Cause(revokeCtx))
		}
		return hsCtx, func() { cancel(nil) }
	}
	stop := registerSyncAbort(revokeCtx, func() { cancel(context.Cause(revokeCtx)) })
	return hsCtx, func() { stop(); cancel(nil) }
}

type gateReqInput struct {
	plan                    plan.SealedConnectionPlan
	targetHop               plan.HopSpec
	nodeID, action, summary string
	risk                    security.RiskLevel
	verdict                 algebraic.Option[security.Verdict]
	cmdDigest               algebraic.Option[security.Digest]
	paths, recursivePaths   []string
	params                  map[string]string
	decisionFloor           algebraic.Option[security.GuardrailDecision]
	canonicalize            gate.CanonicalizeFunc
	approval                algebraic.Option[gate.ApprovalSubmission]
	stream                  *events.OperationStream
}

func buildGateReq[C security.Capability](in gateReqInput) (gate.GateRequest[C], error) {
	binding, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityKindOf[C](), Tool: "ssh", Action: in.action, NodeID: in.nodeID, Endpoint: algebraic.Some(in.targetHop.Endpoint()),
		CanonicalPaths: in.paths, RecursivePaths: in.recursivePaths, CommandDigest: in.cmdDigest, PlanDigest: algebraic.Some(in.plan.PlanDigest().SecurityDigest()), Parameters: in.params,
	})
	if err != nil {
		return zeroVal[gate.GateRequest[C]](), err
	}
	return gate.NewGateRequest[C](gate.GateRequestSpec[C]{
		Binding: binding, Risk: in.risk, Verdict: in.verdict, DecisionFloor: in.decisionFloor, ScopeSummary: in.summary,
		Paths: in.paths, RecursivePaths: in.recursivePaths, Canonicalize: in.canonicalize, Approval: in.approval, OperationStream: in.stream,
	})
}

// runAuthorized 统一封装 gate.WithAuthorized[C]、Outcome 上报与可选 OperationStream 生命周期发射；
// 内部直接消费借用证明 auth（不透传至外部回调），并在 defer 中闭合终态事件确保 panic 路径亦发 OperationCompletedEvent。
//
//xops:syncclosure
func runAuthorized[C security.Capability](ctx context.Context, s *Service, planDigest plan.PlanDigest, nodeID, action string, gateReq gate.GateRequest[C], stream *events.OperationStream, isExec bool, run func(authCtx context.Context, binding security.OperationBinding, emitter *operationEmitter) (execution.ExecutionOutcome, error)) (outcome execution.ExecutionOutcome, entered bool, gateErr error) {
	var emitter *operationEmitter
	var startedAt time.Time
	panicked := true
	defer func() {
		if entered {
			out, err := outcome, gateErr
			if panicked {
				out, err = nil, gate.ErrOperationPanicked
			}
			emitter.emitCompleted(ctx, startedAt, out, err)
		}
	}()
	gateErr = gate.WithAuthorized[C](ctx, s.cfg.Gate, gateReq, func(authCtx context.Context, auth gate.Authorized[C]) error {
		entered, startedAt = true, s.cfg.Clock.Now().UTC().Round(0)
		emitter = newOperationEmitterFor(stream, s.cfg.Clock, auth.TraceID(), auth.OperationID(), nodeID, auth.Capability())
		emitter.emitStarted(authCtx, action, planDigest, gateReq.ScopeSummary())
		var runErr error
		if outcome, runErr = run(authCtx, auth.Binding(), emitter); outcome != nil && outcome.IsValid() {
			_ = auth.ReportOutcome(outcome)
		}
		return runErr
	})
	panicked = false
	if !entered {
		return nil, false, gateErr
	}
	if isExec && (outcome == nil || !outcome.IsValid()) {
		outcome = outcomeForAbortedRun(ctx, gateErr)
	}
	return outcome, true, gateErr
}

// registerAuthorizedHandle 在 gate.WithAuthorized 包裹 pool.WithLease 内调用 pool.RegisterLeaseHandleWith
// 登记跨请求托管资源；若门控后置审计失败则立即回滚释放句柄，绝不泄漏池钉选。
func registerAuthorizedHandle[C security.Capability, K plan.HandleKind, R pool.ComparableManagedResource](ctx context.Context, s *Service, connPlan plan.SealedConnectionPlan, nodeID, action string, gateReq gate.GateRequest[C], stream *events.OperationStream, build func(leaseCtx, revokeCtx context.Context, conn ports.TransportConn) (R, error)) (plan.ManagedHandle[K], error) {
	var handle plan.ManagedHandle[K]
	_, _, gateErr := runAuthorized[C](ctx, s, connPlan.PlanDigest(), nodeID, action, gateReq, stream, false,
		func(authCtx context.Context, binding security.OperationBinding, _ *operationEmitter) (execution.ExecutionOutcome, error) {
			return nil, s.cfg.Pool.WithLease(authCtx, connPlan, func(leaseCtx context.Context, lease *pool.Lease) error {
				var rErr error
				handle, rErr = pool.RegisterLeaseHandleWith[K](s.cfg.Pool, lease, binding, func(revokeCtx context.Context, conn ports.TransportConn) (R, error) {
					return build(leaseCtx, revokeCtx, conn)
				})
				return rErr
			})
		})
	if gateErr != nil {
		if handle.IsValid() {
			_ = pool.ReleaseHandle[K](s.cfg.Pool, handle)
		}
		return zeroVal[plan.ManagedHandle[K]](), gateErr
	}
	return handle, nil
}

type snapshotResource[S any] interface {
	pool.ManagedResource
	snapshot(hs pool.HandleStatus) S
}

func inspectManagedHandle[K plan.HandleKind, S any](ctx context.Context, s *Service, handle plan.ManagedHandle[K]) (st S, err error) {
	if err = s.validateActiveHandleOp(ctx, handle.IsValid()); err != nil {
		return st, err
	}
	hs, err := pool.InspectHandle[K](s.cfg.Pool, handle)
	if err != nil {
		return st, err
	}
	return st, pool.WithManagedHandle[K, snapshotResource[S]](ctx, s.cfg.Pool, handle, func(_ context.Context, res snapshotResource[S]) error { st = res.snapshot(hs); return nil })
}
func (s *Service) validateActiveHandleOp(ctx context.Context, handleValid bool) error {
	switch err := s.validateServiceAndCtx(ctx); {
	case err != nil:
		return err
	case s.cfg.Gate.IsHalted():
		return gate.ErrGateHalted
	case !handleValid:
		return pool.ErrInvalidHandle
	default:
		return nil
	}
}
func releaseManagedHandle[K plan.HandleKind](ctx context.Context, s *Service, handle plan.ManagedHandle[K]) error {
	if err := s.validateServiceAndCtx(ctx); err != nil {
		return err
	}
	if !handle.IsValid() {
		return pool.ErrInvalidHandle
	}
	return pool.ReleaseHandle[K](s.cfg.Pool, handle)
}
func (s *Service) executeSession(ctx context.Context, spec sessionRunSpec) (execution.ExecutionOutcome, error) {
	targetHop, nodeID, err := resolvePlanTargetAndNode(spec.plan, spec.nodeID)
	if err != nil {
		return notStartedSessionOutcome(execution.StartPhaseValidate, "invalid_plan", err), err
	}
	var cmdDigOpt algebraic.Option[security.Digest]
	var timeoutOpt algebraic.Option[algebraic.Duration]
	if cmd, hasCmd := spec.command.Get(); hasCmd {
		dig, dErr := cmd.Digest()
		if dErr != nil {
			return notStartedSessionOutcome(execution.StartPhaseValidate, "invalid_binding", dErr), dErr
		}
		cmdDigOpt, timeoutOpt = algebraic.Some(dig), cmd.Timeout()
	}
	gateReq, err := buildGateReq[security.CapExecute](gateReqInput{
		plan: spec.plan, targetHop: targetHop, nodeID: nodeID, action: spec.action, summary: spec.summary, risk: spec.risk.OrElse(security.RiskModerate),
		cmdDigest: cmdDigOpt, params: map[string]string{"user": targetHop.Username().String()}, approval: spec.approval, stream: spec.operationStream,
	})
	if err != nil {
		return notStartedSessionOutcome(execution.StartPhaseValidate, "invalid_binding", err), err
	}
	out, entered, gateErr := runAuthorized[security.CapExecute](ctx, s, spec.plan.PlanDigest(), nodeID, spec.action, gateReq, spec.operationStream, true,
		func(authCtx context.Context, _ security.OperationBinding, emitter *operationEmitter) (execution.ExecutionOutcome, error) {
			runCtx, cancel := applyOptionalTimeout(authCtx, timeoutOpt)
			defer cancel()
			return s.runLeasedSession(runCtx, spec, targetHop, emitter)
		})
	if !entered {
		return notStartedSessionOutcome(execution.StartPhaseAuthorize, "authorization_failed", gateErr), gateErr
	}
	return out, gateErr
}
func (s *Service) runLeasedSession(ctx context.Context, spec sessionRunSpec, targetHop plan.HopSpec, emitter *operationEmitter) (execution.ExecutionOutcome, error) {
	var outcome execution.ExecutionOutcome
	var enteredLease bool
	leaseErr := s.cfg.Pool.WithLease(ctx, spec.plan, func(leaseCtx context.Context, lease *pool.Lease) error {
		enteredLease = true
		sess, err := lease.OpenSession(leaseCtx)
		if err != nil {
			outcome = notStartedSessionOutcome(execution.StartPhaseSessionOpen, "open_session_failed", err)
			return err
		}
		defer func() { _ = sess.Close() }()
		sendEnv, termName := s.filterSendEnv(targetHop), resolvePTYTerm(spec.term, s.cfg.Env)
		cmd, hasCmd := spec.command.Get()
		decision := resolveTTYDecision(spec.requestTTY, !hasCmd, hasCmd && cmd.PTY(), s.cfg.Terminal != nil && s.cfg.Terminal.IsInteractive())
		starter := sess.StartShell
		if hasCmd {
			starter = func(c context.Context, streams ports.ExecStreams) error { return sess.Start(c, cmd, streams) }
		}
		if decision.useRawTerminal {
			outcome, err = runRawTerminalSession(leaseCtx, sess, s.cfg.Terminal, starter, termName, sendEnv, spec.stderr, emitter, decision.requestPTY)
		} else {
			outcome, err = runStreamSession(leaseCtx, sess, starter, termName, sendEnv, spec.stdin, spec.stdout, spec.stderr, emitter, decision.requestPTY)
		}
		return err
	})
	if !enteredLease {
		return notStartedSessionOutcome(execution.StartPhaseDial, "lease_failed", leaseErr), leaseErr
	}
	return outcome, leaseErr
}

func (s *Service) filterSendEnv(targetHop plan.HopSpec) map[string]string {
	if filter := targetHop.Transport().SendEnv(); !filter.IsUnset() && s.cfg.Env != nil {
		return filter.Filter(s.cfg.Env.Environ())
	}
	return nil
}
