package observability

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/ports"
)

// Service 是 XOps v2 可观测性（日志/指标流）与 POSIX 强校验 GUI 自动化/隧道会话用例服务；
// 物理不依赖 OperatorReadFS，零值恒未初始化并严格失败关闭。
//
//xops:opaque
//xops:failclosed
type Service struct {
	gate       gate.Authorizer
	pool       *pool.Pool
	clock      ports.Clock
	entropy    ports.Entropy
	env        ports.EnvPort
	scopedFS   ports.ScopedRootFS
	forwarder  ports.ForwarderPort
	shellProbe ports.ShellProbePort
	bus        *events.SystemBus
	valid      bool
}

// NewService 校验必填出站依赖并构造不可绕过能力门控的 observability.Service。
func NewService(cfg ServiceConfig) (*Service, error) {
	if cfg.Gate == nil || cfg.Pool == nil || cfg.Pool.IsClosed() || cfg.Clock == nil || cfg.Entropy == nil {
		return nil, domi18n.EF(ErrInvalidConfig, domi18n.KeyCommonMissingDep, domi18n.Str("component", "Gate/Pool/Clock/Entropy"))
	}
	if cfg.SystemBus != nil && cfg.SystemBus.IsClosed() {
		return nil, domi18n.EF(ErrInvalidConfig, domi18n.KeyCommonComponentClosed, domi18n.Str("component", "SystemBus"))
	}
	return &Service{
		gate: cfg.Gate, pool: cfg.Pool, clock: cfg.Clock, entropy: cfg.Entropy,
		env: cfg.Env, scopedFS: cfg.ScopedFS, forwarder: cfg.Forwarder,
		shellProbe: cfg.ShellProbe, bus: cfg.SystemBus, valid: true,
	}, nil
}

func zeroVal[T any]() (z T) { return z }
func pickIf[T any](cond bool, y, n T) T {
	if cond {
		return y
	}
	return n
}
func closeStream(st *events.OperationStream) {
	if st != nil {
		st.Close()
	}
}
func (s *Service) enforceStrictPaths() bool {
	return s.gate.Profile() != gate.PolicyProfileDirectOperator
}
func resolveNodeID(hop plan.HopSpec, explicit string) string {
	return pickIf(explicit != "", explicit, hop.NodeID())
}
func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
func (s *Service) checkReady(ctx context.Context) error {
	switch {
	case s == nil || !s.valid:
		return ErrServiceNotInitialized
	case ctx == nil:
		return ErrNilContext
	case s.gate.IsHalted():
		return gate.ErrGateHalted
	default:
		return ctx.Err()
	}
}
func (s *Service) validatePlanCall(ctx context.Context, connPlan plan.SealedConnectionPlan, risk algebraic.Option[security.RiskLevel]) (plan.HopSpec, error) {
	if err := s.checkReady(ctx); err != nil {
		return zeroVal[plan.HopSpec](), err
	}
	if !connPlan.IsValid() {
		return zeroVal[plan.HopSpec](), domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "SealedConnectionPlan"))
	}
	if r, ok := risk.Get(); ok && !r.IsValid() {
		return zeroVal[plan.HopSpec](), domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "RiskLevel"))
	}
	hop, ok := connPlan.Target()
	if !ok {
		return zeroVal[plan.HopSpec](), domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldRequired, domi18n.Str("field", "target_hop"))
	}
	return hop, nil
}

func (s *Service) elapsed(since time.Time) algebraic.Duration {
	return algebraic.FromStdDuration(max(s.clock.Since(since), 0))
}

type posixCallBase struct {
	hop     plan.HopSpec
	prof    execution.LaunchProfile
	hasProf bool
}

// validatePOSIXCall 统一校验执行计划、风险等级、显式 POSIX Bourne 启动配置（INV-E4）与正时长超时。
func (s *Service) validatePOSIXCall(ctx context.Context, connPlan plan.SealedConnectionPlan, risk algebraic.Option[security.RiskLevel], profOpt algebraic.Option[execution.LaunchProfile], timeout algebraic.Option[algebraic.Duration]) (posixCallBase, error) {
	hop, err := s.validatePlanCall(ctx, connPlan, risk)
	if err != nil {
		return posixCallBase{}, err
	}
	prof, hasProf := profOpt.Get()
	if hasProf {
		if !prof.IsValid() {
			return posixCallBase{}, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "LaunchProfile"))
		}
		if err := prof.ValidatePOSIXBourne(); err != nil {
			return posixCallBase{}, domi18n.WrapSentinel(ErrPOSIXShellRequired, err)
		}
	}
	if d, ok := timeout.Get(); ok && !d.IsPositive() {
		return posixCallBase{}, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldPositive, domi18n.Str("field", "Timeout"))
	}
	return posixCallBase{hop: hop, prof: prof, hasProf: hasProf}, nil
}

func newObsGateReq[C security.Capability](spec security.OperationBindingSpec, risk security.RiskLevel, summary string, paths []string, canon gate.CanonicalizeFunc, appr algebraic.Option[gate.ApprovalSubmission], st *events.OperationStream) (gate.GateRequest[C], error) {
	binding, err := security.NewOperationBinding(spec)
	if err != nil {
		return zeroVal[gate.GateRequest[C]](), err
	}
	return gate.NewGateRequest[C](gate.GateRequestSpec[C]{
		Binding: binding, Risk: risk, ScopeSummary: summary, Paths: paths, Canonicalize: canon, Approval: appr, OperationStream: st,
	})
}

// withLeaseRemoteFS 在已持有的 pool.Lease 内打开 RemoteFSPort 并确定性闭合。
//
//xops:syncclosure
func withLeaseRemoteFS(ctx context.Context, lease *pool.Lease, fn func(ports.RemoteFSPort) error) error {
	rfs, err := lease.OpenRemoteFS(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = rfs.Close() }()
	return fn(rfs)
}

// resolvePOSIXProfileInLease 在未显式指定启动配置时，若注入 ShellProbePort 则先执行两阶段探测并验证 POSIX Bourne，
// 否则使用显式 POSIX sh；若探测为 PowerShell/cmd/raw/unknown 立即失败关闭返回 ErrPOSIXShellRequired。
func (s *Service) resolvePOSIXProfileInLease(ctx context.Context, opener ports.SessionOpener, explicit execution.LaunchProfile, hasExplicit bool) (execution.LaunchProfile, error) {
	if hasExplicit {
		if err := explicit.ValidatePOSIXBourne(); err != nil {
			return zeroVal[execution.LaunchProfile](), domi18n.WrapSentinel(ErrPOSIXShellRequired, err)
		}
		return explicit, nil
	}
	if s.shellProbe == nil {
		return execution.POSIXLaunchProfile(execution.InterpreterSH, execution.LoginModeInherit)
	}
	res, err := s.shellProbe.ProbeShell(ctx, opener)
	if err != nil {
		return zeroVal[execution.LaunchProfile](), domi18n.WrapS(ErrPOSIXShellRequired, err, domi18n.KeyCommonOpFailed, domi18n.Str("op", "probe_shell"))
	}
	if err := res.LaunchProfile().ValidatePOSIXBourne(); err != nil {
		return zeroVal[execution.LaunchProfile](), domi18n.WrapS(ErrPOSIXShellRequired, err, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "shell_dialect"), domi18n.BoundStr("value", res.Dialect().String()+"/"+res.Interpreter().String()))
	}
	return res.LaunchProfile(), nil
}

func (s *Service) filterSendEnv(targetHop plan.HopSpec) map[string]string {
	if f := targetHop.Transport().SendEnv(); !f.IsUnset() && s.env != nil {
		return f.Filter(s.env.Environ())
	}
	return nil
}
func applyOptionalTimeout(ctx context.Context, durOpt algebraic.Option[algebraic.Duration]) (context.Context, context.CancelFunc) {
	if d, ok := durOpt.Get(); ok && d.IsPositive() {
		return context.WithTimeout(ctx, d.Std())
	}
	return ctx, func() {}
}

// runAuthorized 统一封装 gate.WithAuthorized[C]、Outcome 上报与隔离 OperationStream 生命周期发射（含 panic defer 终态闭合）。
//
//xops:syncclosure
func runAuthorized[C security.Capability](ctx context.Context, s *Service, planDigest plan.PlanDigest, nodeID, action string, gateReq gate.GateRequest[C], stream *events.OperationStream, run func(authCtx context.Context, binding security.OperationBinding, emitter *obsEmitter) (execution.ExecutionOutcome, error)) (execution.ExecutionOutcome, error) {
	var outcome execution.ExecutionOutcome
	var emitter *obsEmitter
	var gateErr error
	startedAt, entered, panicked := s.clock.Now().UTC().Round(0), false, true
	defer func() {
		if entered {
			out, ok, code, msg := classifyObsTerminal(outcome, gateErr, panicked)
			emitter.emitCompleted(ctx, startedAt, out, ok, code, msg)
		}
	}()
	gateErr = gate.WithAuthorized[C](ctx, s.gate, gateReq, func(authCtx context.Context, auth gate.Authorized[C]) error {
		entered, startedAt = true, s.clock.Now().UTC().Round(0)
		emitter = newObsEmitter(stream, s.clock, auth.TraceID(), auth.OperationID(), nodeID, auth.Capability())
		emitter.emitStarted(authCtx, action, algebraic.Some(planDigest), gateReq.ScopeSummary())
		var runErr error
		outcome, runErr = run(authCtx, auth.Binding(), emitter)
		if outcome != nil && outcome.IsValid() {
			_ = auth.ReportOutcome(outcome)
		}
		if outcome != nil && outcome.Kind() == execution.OutcomeKindUnknown {
			cause := pickIf(runErr != nil && !errors.Is(runErr, ErrUncertainOutcome), domi18n.WrapSentinel(ErrUncertainOutcome, runErr), ErrUncertainOutcome)
			if wrapped, wErr := gate.WrapOutcomeError(outcome, cause); wErr == nil {
				return wrapped
			}
			return cause
		}
		return runErr
	})
	panicked = false
	return outcome, gateErr
}

func classifyObsTerminal(outcome execution.ExecutionOutcome, err error, panicked bool) (execution.ExecutionOutcome, bool, string, string) {
	switch {
	case panicked:
		return nil, false, "operation_panicked", "observability operation panicked"
	case outcome != nil && outcome.IsValid() && outcome.Kind() == execution.OutcomeKindUnknown:
		return outcome, false, "outcome_unknown", "execution outcome unknown"
	case err != nil:
		return outcome, false, pickIf(errors.Is(err, gate.ErrGateHalted), "gate_halted", "operation_failed"), err.Error()
	default:
		return outcome, true, "", "completed"
	}
}
func makeNotStartedOutcome(phase execution.StartPhase, code string, err error) execution.ExecutionOutcome {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	out, _ := execution.NewOutcomeNotStarted(phase, code, msg)
	return out
}
func classifyPostStartOutcome(ctx context.Context, out execution.ExecutionOutcome, waitErr error) execution.ExecutionOutcome {
	if out != nil && out.IsValid() {
		return out
	}
	phase, code, msg := execution.ExecPhaseTransportLost, "transport_lost", "remote session ended without terminal outcome"
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(waitErr, context.DeadlineExceeded) {
		phase, code = execution.ExecPhaseTimedOut, "timed_out"
	} else if ctx.Err() != nil || errors.Is(waitErr, context.Canceled) {
		phase, code = execution.ExecPhaseCanceled, "canceled"
	}
	if waitErr != nil {
		msg = waitErr.Error()
	}
	unk, _ := execution.NewOutcomeUnknown(phase, code, msg)
	return unk
}

// execPOSIXInLease 统一封装租约内可选前置校验、POSIX Bourne 探测、命令构造与会话执行，
// 消除 StreamLogs / StreamMetrics / ExecuteGUI 的重复生命周期样板并严分 OutcomeNotStarted 与 OutcomeUnknown。
//
//xops:syncclosure
func (s *Service) execPOSIXInLease(ctx context.Context, connPlan plan.SealedConnectionPlan, targetHop plan.HopSpec, explicitProf execution.LaunchProfile, hasProf bool, preCheck func(context.Context, *pool.Lease) error, buildCmd func(execution.LaunchProfile) (execution.CommandPlan, error), stdout, stderr io.Writer) (execution.ExecutionOutcome, error) {
	var outcome execution.ExecutionOutcome
	var enteredLease, started bool
	leaseErr := s.pool.WithLease(ctx, connPlan, func(leaseCtx context.Context, lease *pool.Lease) error {
		enteredLease = true
		var err error
		outcome, started, err = s.runPOSIXSessionInLease(leaseCtx, lease, targetHop, explicitProf, hasProf, preCheck, buildCmd, stdout, stderr)
		return err
	})
	if !enteredLease {
		return makeNotStartedOutcome(execution.StartPhaseDial, "lease_failed", leaseErr), leaseErr
	}
	if started && (outcome == nil || !outcome.IsValid()) {
		return classifyPostStartOutcome(ctx, nil, leaseErr), leaseErr
	}
	return outcome, leaseErr
}

func (s *Service) runPOSIXSessionInLease(ctx context.Context, lease *pool.Lease, targetHop plan.HopSpec, explicitProf execution.LaunchProfile, hasProf bool, preCheck func(context.Context, *pool.Lease) error, buildCmd func(execution.LaunchProfile) (execution.CommandPlan, error), stdout, stderr io.Writer) (execution.ExecutionOutcome, bool, error) {
	if preCheck != nil {
		if err := preCheck(ctx, lease); err != nil {
			return makeNotStartedOutcome(execution.StartPhaseAuthorize, "precheck_failed", err), false, err
		}
	}
	prof, err := s.resolvePOSIXProfileInLease(ctx, lease, explicitProf, hasProf)
	if err != nil {
		return makeNotStartedOutcome(execution.StartPhaseValidate, "posix_shell_required", err), false, err
	}
	cmdPlan, err := buildCmd(prof)
	if err != nil {
		return makeNotStartedOutcome(execution.StartPhaseValidate, "invalid_command_plan", err), false, err
	}
	sess, err := lease.OpenSession(ctx)
	if err != nil {
		return makeNotStartedOutcome(execution.StartPhaseSessionOpen, "open_session_failed", err), false, err
	}
	defer func() { _ = sess.Close() }()
	if err := sess.Start(ctx, cmdPlan, ports.ExecStreams{Stdout: stdout, Stderr: stderr, Env: s.filterSendEnv(targetHop)}); err != nil {
		return makeNotStartedOutcome(execution.StartPhaseRequestRejected, "session_start_failed", err), false, err
	}
	waitOut, waitErr := sess.Wait(ctx)
	return classifyPostStartOutcome(ctx, waitOut, waitErr), true, waitErr
}
