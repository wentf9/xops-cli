package automation

import (
	"context"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/ports"
)

type batchJob struct {
	index  int
	target TargetNode
	stream *events.OperationStream
}

// BatchExec 在 core/conc.Nursery（RunWait）有界并发监督下对多节点执行同一不可变 CommandPlan：
//   - 严格遵循 gate.WithAuthorized[security.CapExecute] 外包 pool.WithLease 嵌套序（ADR-008 / ADR-009）；
//   - 非 DirectOperator 配置档下对 Command.WorkDir 执行 Round-2 软链规范化与执行前 TOCTOU 复核；
//   - 两步审批绑定完全由排序后目标节点、连接计划摘要、命令摘要与显式参数确定（零门控前抽熵漂移）；
//   - 支持单节点独立隔离 OperationStream（确定性 EOF + panic defer 终态事件）与 ScopedRootFS --out-dir 原子落盘；
//   - 严分 OutcomeNotStarted 与 OutcomeUnknown，任一节点出现 OutcomeUnknown 时绝不重试并忠实上报 AuditOutcomeUnknown。
func (s *Service) BatchExec(ctx context.Context, req BatchExecRequest) (BatchExecReport, error) {
	defer closeAllStreams(req.OperationStream, req.NodeStreams)
	targets, concurrency, maxOut, err := s.validateAndPrepareBatch(ctx, req)
	if err != nil {
		return BatchExecReport{}, err
	}
	gateReq, err := s.buildBatchGateRequest(req, targets, concurrency)
	if err != nil {
		return BatchExecReport{}, err
	}
	return s.executeAuthorizedBatch(ctx, req, gateReq, targets, concurrency, maxOut)
}

func (s *Service) validateAndPrepareBatch(ctx context.Context, req BatchExecRequest) ([]TargetNode, int, uint64, error) {
	if err := s.checkReady(ctx); err != nil {
		return nil, 0, 0, err
	}
	if !req.Command.IsValid() {
		return nil, 0, 0, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "CommandPlan"))
	}
	if r, ok := req.Risk.Get(); ok && !r.IsValid() {
		return nil, 0, 0, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "RiskLevel"))
	}
	if outDir, hasOut := req.OutputDir.Get(); hasOut {
		if !outDir.IsValid() {
			return nil, 0, 0, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "OutputDir"))
		}
		if s.scopedFS == nil {
			return nil, 0, 0, ErrScopedFSUnavailable
		}
	}
	concurrency, err := s.resolveConcurrency(req.Concurrency)
	if err != nil {
		return nil, 0, 0, err
	}
	maxOut := pickIf(req.MaxOutputBytes == 0, req.Command.MaxOutputBytes(), req.MaxOutputBytes)
	if maxOut == 0 || maxOut > execution.MaxAllowedOutputBytes {
		return nil, 0, 0, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldRange, domi18n.Str("field", "max_output_bytes"), domi18n.Uint64("value", maxOut), domi18n.Uint64("min", 1), domi18n.Uint64("max", execution.MaxAllowedOutputBytes))
	}
	targets, err := s.resolveTargets(ctx, req.Targets, req.Selector, req.CLIOptions, req.ExcludeNodes, req.ExcludeTags)
	if err != nil {
		return nil, 0, 0, err
	}
	return targets, concurrency, maxOut, nil
}

func singleTargetMeta(targets []TargetNode, nodeIDs []string) (string, algebraic.Option[netaddr.Endpoint]) {
	if len(targets) != 1 {
		return "", algebraic.None[netaddr.Endpoint]()
	}
	if hop, ok := targets[0].plan.Target(); ok {
		return nodeIDs[0], algebraic.Some(hop.Endpoint())
	}
	return nodeIDs[0], algebraic.None[netaddr.Endpoint]()
}

func buildBatchBinding(req BatchExecRequest, targets []TargetNode, concurrency int, cmdDigest security.Digest, paths []string) (security.OperationBinding, error) {
	nodeIDs := extractNodeIDStrings(targets)
	singleNode, singleEP := singleTargetMeta(targets, nodeIDs)
	params := map[string]string{
		"concurrency": strconv.Itoa(concurrency),
		"fail_fast":   strconv.FormatBool(req.FailFast),
		"node_count":  strconv.Itoa(len(targets)),
	}
	if outDir, ok := req.OutputDir.Get(); ok {
		params["out_dir"] = outDir.String()
	}
	return security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityExecute, Tool: toolAutomation, Action: "batch_exec",
		NodeID: singleNode, NodeIDs: nodeIDs, Endpoint: singleEP, CanonicalPaths: paths,
		CommandDigest: algebraic.Some(cmdDigest), PlanDigest: algebraic.Some(digestTargetPlans(targets)), Parameters: params,
	})
}

func (s *Service) buildBatchGateRequest(req BatchExecRequest, targets []TargetNode, concurrency int) (gate.GateRequest[security.CapExecute], error) {
	cmdDigest, err := req.Command.Digest()
	if err != nil {
		return zeroVal[gate.GateRequest[security.CapExecute]](), err
	}
	var paths []string
	var canonFn gate.CanonicalizeFunc
	if wd, ok := req.Command.WorkDir().Get(); ok && wd.IsValid() {
		paths = []string{wd.String()}
		if s.enforceStrictPaths() {
			canonFn = s.makeBatchWorkDirCanonicalizer(req, targets, concurrency, cmdDigest, wd)
		}
	}
	binding, err := buildBatchBinding(req, targets, concurrency, cmdDigest, paths)
	if err != nil {
		return zeroVal[gate.GateRequest[security.CapExecute]](), err
	}
	return gate.NewGateRequest[security.CapExecute](gate.GateRequestSpec[security.CapExecute]{
		Binding: binding, Risk: req.Risk.OrElse(security.RiskModerate),
		ScopeSummary: fmt.Sprintf("batch exec (%d nodes): %s", len(targets), req.Command.RedactedSummary()),
		Paths:        paths, Canonicalize: canonFn, Approval: req.Approval, OperationStream: req.OperationStream,
	})
}

func (s *Service) makeBatchWorkDirCanonicalizer(req BatchExecRequest, targets []TargetNode, concurrency int, cmdDigest security.Digest, wd pathalg.RemotePath) gate.CanonicalizeFunc {
	return func(ctx context.Context) (gate.CanonicalizeResult, error) {
		pathSet := map[string]struct{}{wd.String(): {}}
		wdSlice := []pathalg.RemotePath{wd}
		for _, target := range targets {
			if err := s.canonicalizeNodeRemotePaths(ctx, target.plan, wdSlice, pathSet); err != nil {
				return gate.CanonicalizeResult{}, err
			}
		}
		allPaths := slices.Sorted(maps.Keys(pathSet))
		canBind, err := buildBatchBinding(req, targets, concurrency, cmdDigest, allPaths)
		if err != nil {
			return gate.CanonicalizeResult{}, err
		}
		return gate.CanonicalizeResult{Binding: canBind, Paths: allPaths}, nil
	}
}

func (s *Service) executeAuthorizedBatch(ctx context.Context, req BatchExecRequest, gateReq gate.GateRequest[security.CapExecute], targets []TargetNode, concurrency int, maxOut uint64) (BatchExecReport, error) {
	var report BatchExecReport
	var emitter *streamEmitter
	var firstUnknown execution.ExecutionOutcome
	var gateErr error
	startedAt, entered, panicked := s.clock.Now().UTC().Round(0), false, true
	defer func() {
		if entered {
			out, ok, code, msg := batchCompletedFields(report, firstUnknown, gateErr, panicked)
			emitter.emitCompleted(ctx, startedAt, out, ok, code, msg)
		}
	}()
	gateErr = gate.WithAuthorized[security.CapExecute](ctx, s.gate, gateReq, func(authCtx context.Context, auth gate.Authorized[security.CapExecute]) error {
		entered, startedAt = true, s.clock.Now().UTC().Round(0)
		emitter = newStreamEmitter(req.OperationStream, s.clock, auth.TraceID(), auth.OperationID(), algebraic.None[inventory.NodeID](), security.CapabilityExecute)
		emitter.emitStarted(authCtx, "batch_exec", algebraic.None[plan.PlanDigest](), gateReq.ScopeSummary())
		if outDir, hasOut := req.OutputDir.Get(); hasOut {
			if eErr := s.scopedFS.EnsureRoot(outDir, defaultOutDirPerm); eErr != nil {
				return eErr
			}
		}
		results, runErr := s.runBatchWorkers(authCtx, req, targets, concurrency, maxOut, auth.Binding(), auth.TraceID(), auth.OperationID())
		report = foldBatchExecReport(results, algebraic.FromStdDuration(max(s.clock.Since(startedAt), 0)))
		firstUnknown = findFirstUnknownBatchOutcome(results)
		if firstUnknown != nil {
			_ = auth.ReportOutcome(firstUnknown)
		}
		return classifyBatchRunError(report, firstUnknown, runErr, s.gate.IsHalted())
	})
	panicked = false
	return report, gateErr
}

func (s *Service) runBatchWorkers(ctx context.Context, req BatchExecRequest, targets []TargetNode, concurrency int, maxOut uint64, authBinding security.OperationBinding, traceID security.TraceID, opID security.OperationID) ([]BatchNodeResult, error) {
	jobs, factoryStreams, err := prepareBatchJobs(targets, req.NodeStreams, req.NodeStreamFactory, traceID, opID)
	defer func() {
		for _, st := range factoryStreams {
			closeStream(st)
		}
	}()
	if err != nil {
		return nil, err
	}
	results := make([]BatchNodeResult, len(targets))
	jobsCh := make(chan batchJob, len(jobs))
	for _, job := range jobs {
		jobsCh <- job
	}
	close(jobsCh)
	runCtx, cancelRun := context.WithCancelCause(ctx)
	defer cancelRun(nil)
	runErr := conc.RunWait(runCtx, func(_ context.Context, n *conc.Nursery) error {
		for range min(concurrency, len(targets)) {
			if gErr := n.Go(func(workerCtx context.Context) error {
				return s.consumeBatchJobs(workerCtx, req, jobsCh, results, maxOut, authBinding, traceID, opID, cancelRun)
			}); gErr != nil {
				return gErr
			}
		}
		return nil
	})
	fillMissingBatchResults(targets, results, runCtx, runErr, s.gate.IsHalted())
	return results, runErr
}

func prepareBatchJobs(targets []TargetNode, prebound map[inventory.NodeID]*events.OperationStream, factory NodeStreamFactory, traceID security.TraceID, opID security.OperationID) ([]batchJob, []*events.OperationStream, error) {
	jobs := make([]batchJob, len(targets))
	var created []*events.OperationStream
	for i, target := range targets {
		st := prebound[target.nodeID]
		if st == nil && factory != nil {
			var err error
			if st, err = factory(target.nodeID, traceID, opID); err != nil {
				return nil, created, domi18n.Wrap(err, domi18n.KeyCommonOpTargetFailed, domi18n.Str("op", "create node event stream"), domi18n.BoundStr("target", target.nodeID.String()))
			}
			if st != nil {
				created = append(created, st)
			}
		}
		jobs[i] = batchJob{index: i, target: target, stream: st}
	}
	return jobs, created, nil
}

func (s *Service) consumeBatchJobs(ctx context.Context, req BatchExecRequest, jobsCh <-chan batchJob, results []BatchNodeResult, maxOut uint64, authBinding security.OperationBinding, traceID security.TraceID, opID security.OperationID, cancelRun context.CancelCauseFunc) error {
	for job := range jobsCh {
		res := s.execBatchNode(ctx, req, job, maxOut, authBinding, traceID, opID)
		results[job.index] = res
		if s.gate.IsHalted() {
			cancelRun(gate.ErrGateHalted)
		} else if req.FailFast && !res.Succeeded() {
			cancelRun(firstErr(res.err, ErrBatchFailed))
		}
	}
	return nil
}

func (s *Service) execBatchNode(ctx context.Context, req BatchExecRequest, job batchJob, maxOut uint64, authBinding security.OperationBinding, traceID security.TraceID, opID security.OperationID) BatchNodeResult {
	// LIFO 顺序：先注册 closeStream，再注册 emitCompleted，确保节点回调 panic 时仍先发射终态事件再确定性 EOF。
	defer closeStream(job.stream)
	startedAt := s.clock.Now().UTC().Round(0)
	emitter := newStreamEmitter(job.stream, s.clock, traceID, opID, algebraic.Some(job.target.nodeID), security.CapabilityExecute)
	emitter.emitStarted(ctx, "batch_exec_node", algebraic.Some(job.target.plan.PlanDigest()), req.Command.RedactedSummary())

	var res BatchNodeResult
	panicked := true
	defer func() {
		if panicked {
			emitter.emitCompleted(ctx, startedAt, nil, false, "operation_panicked", "batch node execution panicked")
			return
		}
		code, msg := classifyNodeCompletedMeta(res)
		emitter.emitCompleted(ctx, startedAt, res.outcome, res.Succeeded(), code, msg)
	}()

	res = s.runSingleNodeCommand(ctx, req, job.target, maxOut, authBinding, emitter, startedAt)
	panicked = false
	return res
}

func effectiveBatchCommand(base execution.CommandPlan, target TargetNode) (execution.CommandPlan, error) {
	if !base.Profile().Equal(execution.DefaultServerLaunchProfile()) {
		return base, nil
	}
	prof, ok := target.defaultProfile.Get()
	if !ok || !prof.IsValid() || prof.Equal(base.Profile()) {
		return base, nil
	}
	return execution.NewCommandPlan(execution.CommandPlanSpec{
		Kind: base.Kind(), Profile: prof, Command: base.Command(), Argv: base.Argv(),
		WorkDir: base.WorkDir(), Env: base.Env(), Timeout: base.Timeout(),
		MaxOutputBytes: algebraic.Some(base.MaxOutputBytes()), PTY: base.PTY(),
	})
}

func (s *Service) runSingleNodeCommand(ctx context.Context, req BatchExecRequest, target TargetNode, maxOut uint64, authBinding security.OperationBinding, emitter *streamEmitter, startedAt time.Time) BatchNodeResult {
	if s.gate.IsHalted() {
		return makeNotStartedBatchResult(target.nodeID, execution.StartPhaseAuthorize, "gate_halted", gate.ErrGateHalted, s.clock.Since(startedAt))
	}
	if err := ctx.Err(); err != nil {
		return makeNotStartedBatchResult(target.nodeID, execution.StartPhaseValidate, "canceled", firstErr(context.Cause(ctx), err), s.clock.Since(startedAt))
	}
	cmdPlan, err := effectiveBatchCommand(req.Command, target)
	if err != nil {
		return makeNotStartedBatchResult(target.nodeID, execution.StartPhaseValidate, "invalid_node_profile", err, s.clock.Since(startedAt))
	}
	execCtx, cancel := applyOptionalTimeout(ctx, cmdPlan.Timeout())
	defer cancel()
	outW := newBoundedCaptureWriter(execCtx, emitter, events.OutputStreamStdout, maxOut)
	errW := newBoundedCaptureWriter(execCtx, emitter, events.OutputStreamStderr, maxOut)
	outcome, execErr := s.execCommandWithLease(execCtx, target.plan, cmdPlan, authBinding, s.enforceStrictPaths(), outW, errW)
	stdout, outTrunc := outW.snapshot()
	stderr, errTrunc := errW.snapshot()
	stdoutFile, stderrFile, writeErr := s.writeNodeOutputsIfConfigured(req.OutputDir, target.nodeID, stdout, stderr)
	finalErr := firstErr(execErr, writeErr)
	return BatchNodeResult{
		nodeID: target.nodeID, outcome: outcome, stdout: stdout, stderr: stderr,
		truncated:  outTrunc || errTrunc || outcomeTruncated(outcome),
		duration:   algebraic.FromStdDuration(max(s.clock.Since(startedAt), 0)),
		stdoutFile: stdoutFile, stderrFile: stderrFile,
		errMsg: errString(finalErr, ""), err: finalErr, valid: true,
	}
}

// execCommandWithLease 在 pool.WithLease 作用域内执行单条不可变 CommandPlan，
// 严格执行 WorkDir 写/执行前 TOCTOU 复核，并精确区分 OutcomeNotStarted 与 OutcomeUnknown（严禁重试）。
func (s *Service) execCommandWithLease(ctx context.Context, connPlan plan.SealedConnectionPlan, cmd execution.CommandPlan, authBinding security.OperationBinding, verifyWorkDir bool, stdout, stderr io.Writer) (execution.ExecutionOutcome, error) {
	targetHop, ok := connPlan.Target()
	if !ok {
		err := domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldRequired, domi18n.Str("field", "connection plan target hop"))
		return makeNotStartedOutcome(execution.StartPhaseValidate, "invalid_plan", err), err
	}
	var outcome execution.ExecutionOutcome
	var enteredLease, started bool
	leaseErr := s.pool.WithLease(ctx, connPlan, func(leaseCtx context.Context, lease *pool.Lease) error {
		enteredLease = true
		var err error
		outcome, started, err = s.runCommandInLease(leaseCtx, lease, targetHop, cmd, authBinding, verifyWorkDir, stdout, stderr)
		return err
	})
	if !enteredLease {
		return makeNotStartedOutcome(execution.StartPhaseDial, "lease_failed", leaseErr), leaseErr
	}
	if outcome == nil || !outcome.IsValid() {
		if started {
			return classifyPostStartOutcome(ctx, nil, leaseErr), leaseErr
		}
		return makeNotStartedOutcome(execution.StartPhaseSessionOpen, "prestart_failed", leaseErr), leaseErr
	}
	return outcome, leaseErr
}

func (s *Service) runCommandInLease(ctx context.Context, lease *pool.Lease, targetHop plan.HopSpec, cmd execution.CommandPlan, authBinding security.OperationBinding, verifyWorkDir bool, stdout, stderr io.Writer) (execution.ExecutionOutcome, bool, error) {
	if err := verifyCommandWorkDirInLease(ctx, lease, authBinding, verifyWorkDir, cmd.WorkDir()); err != nil {
		return makeNotStartedOutcome(execution.StartPhaseAuthorize, "workdir_scope_escalated", err), false, err
	}
	sess, err := lease.OpenSession(ctx)
	if err != nil {
		return makeNotStartedOutcome(execution.StartPhaseSessionOpen, "open_session_failed", err), false, err
	}
	defer func() { _ = sess.Close() }()
	var stdin io.Reader
	if payload, hasStdin := cmd.StdinPayload(); hasStdin {
		stdin = strings.NewReader(payload)
	}
	if err := sess.Start(ctx, cmd, ports.ExecStreams{Stdin: stdin, Stdout: stdout, Stderr: stderr, Env: s.filterSendEnv(targetHop)}); err != nil {
		return makeNotStartedOutcome(execution.StartPhaseRequestRejected, "session_start_failed", err), false, err
	}
	waitOut, waitErr := sess.Wait(ctx)
	return classifyPostStartOutcome(ctx, waitOut, waitErr), true, waitErr
}

func verifyCommandWorkDirInLease(ctx context.Context, lease *pool.Lease, binding security.OperationBinding, enforce bool, wdOpt algebraic.Option[pathalg.RemotePath]) error {
	wd, hasWD := wdOpt.Get()
	if !enforce || !hasWD || !wd.IsValid() {
		return nil
	}
	rfs, err := lease.OpenRemoteFS(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = rfs.Close() }()
	return verifyRemotePathAuthorized(ctx, true, rfs, binding, wd)
}

func (s *Service) writeNodeOutputsIfConfigured(
	outDirOpt algebraic.Option[pathalg.LocalDir],
	nodeID inventory.NodeID,
	stdout, stderr []byte,
) (algebraic.Option[pathalg.LocalRootedDest], algebraic.Option[pathalg.LocalRootedDest], error) {
	noneDest := algebraic.None[pathalg.LocalRootedDest]()
	outDir, hasOut := outDirOpt.Get()
	if !hasOut {
		return noneDest, noneDest, nil
	}
	// 加固定非保留前缀 "node-"，防止合法 NodeID（如 con/nul/aux/com1）触发 Windows 保留设备名拒绝。
	outDest, e1 := pathalg.ParseLocalRootedDest("node-" + nodeID.String() + ".stdout.log")
	errDest, e2 := pathalg.ParseLocalRootedDest("node-" + nodeID.String() + ".stderr.log")
	if err := firstErr(e1, e2); err != nil {
		return noneDest, noneDest, err
	}
	writeBytes := func(w io.Writer, data []byte) error {
		if len(data) == 0 {
			return nil
		}
		_, err := w.Write(data)
		return err
	}
	err := s.scopedFS.WithRoot(outDir, func(root ports.RootHandle) error {
		if wErr := root.AtomicReplace(outDest, defaultOutFilePerm, func(w io.Writer) error { return writeBytes(w, stdout) }); wErr != nil {
			return wErr
		}
		return root.AtomicReplace(errDest, defaultOutFilePerm, func(w io.Writer) error { return writeBytes(w, stderr) })
	})
	if err != nil {
		return noneDest, noneDest, err
	}
	return algebraic.Some(outDest), algebraic.Some(errDest), nil
}
