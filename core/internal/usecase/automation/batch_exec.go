package automation

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
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
//   - 两步审批绑定完全由排序后目标节点、连接计划摘要、命令摘要与显式参数确定（零门控前抽熵漂移）；
//   - 支持单节点独立隔离 OperationStream（确定性 EOF + panic defer 终态事件）与 ScopedRootFS --out-dir 原子落盘；
//   - 严分 OutcomeNotStarted 与 OutcomeUnknown，任一节点出现 OutcomeUnknown 时绝不重试并忠实上报 AuditOutcomeUnknown。
func (s *Service) BatchExec(ctx context.Context, req BatchExecRequest) (BatchExecReport, error) {
	defer closeAllStreams(req.OperationStream, req.NodeStreams)
	targets, concurrency, maxOut, err := s.validateAndPrepareBatch(ctx, req)
	if err != nil {
		return BatchExecReport{}, err
	}
	gateReq, err := buildBatchGateRequest(req, targets, concurrency)
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
		return nil, 0, 0, fmt.Errorf("%w: CommandPlan 无效", ErrInvalidRequest)
	}
	if r, ok := req.Risk.Get(); ok && !r.IsValid() {
		return nil, 0, 0, fmt.Errorf("%w: RiskLevel 无效", ErrInvalidRequest)
	}
	if outDir, hasOut := req.OutputDir.Get(); hasOut {
		if !outDir.IsValid() {
			return nil, 0, 0, fmt.Errorf("%w: OutputDir 无效", ErrInvalidRequest)
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
		return nil, 0, 0, fmt.Errorf("%w: max_output_bytes=%d 越界", ErrInvalidRequest, maxOut)
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

func buildBatchGateRequest(req BatchExecRequest, targets []TargetNode, concurrency int) (gate.GateRequest[security.CapExecute], error) {
	cmdDigest, err := req.Command.Digest()
	if err != nil {
		return zeroVal[gate.GateRequest[security.CapExecute]](), err
	}
	nodeIDs := extractNodeIDStrings(targets)
	singleNode, singleEP := singleTargetMeta(targets, nodeIDs)
	var paths []string
	if wd, ok := req.Command.WorkDir().Get(); ok && wd.IsValid() {
		paths = []string{wd.String()}
	}
	params := map[string]string{
		"concurrency": strconv.Itoa(concurrency),
		"fail_fast":   strconv.FormatBool(req.FailFast),
		"node_count":  strconv.Itoa(len(targets)),
	}
	if outDir, ok := req.OutputDir.Get(); ok {
		params["out_dir"] = outDir.String()
	}
	binding, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityExecute, Tool: toolAutomation, Action: "batch_exec",
		NodeID: singleNode, NodeIDs: nodeIDs, Endpoint: singleEP, CanonicalPaths: paths,
		CommandDigest: algebraic.Some(cmdDigest), PlanDigest: algebraic.Some(digestTargetPlans(targets)), Parameters: params,
	})
	if err != nil {
		return zeroVal[gate.GateRequest[security.CapExecute]](), err
	}
	return gate.NewGateRequest[security.CapExecute](gate.GateRequestSpec[security.CapExecute]{
		Binding: binding, Risk: req.Risk.OrElse(security.RiskModerate),
		ScopeSummary:    fmt.Sprintf("batch exec (%d nodes): %s", len(targets), req.Command.RedactedSummary()),
		Paths:           paths,
		Approval:        req.Approval,
		OperationStream: req.OperationStream,
	})
}

func (s *Service) executeAuthorizedBatch(
	ctx context.Context,
	req BatchExecRequest,
	gateReq gate.GateRequest[security.CapExecute],
	targets []TargetNode,
	concurrency int,
	maxOut uint64,
) (BatchExecReport, error) {
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
		results, runErr := s.runBatchWorkers(authCtx, req, targets, concurrency, maxOut, auth.TraceID(), auth.OperationID())
		report = foldBatchExecReport(results, algebraic.FromStdDuration(max(s.clock.Since(startedAt), 0)))
		firstUnknown = findFirstUnknownBatchOutcome(results)
		if firstUnknown != nil {
			_ = auth.ReportOutcome(firstUnknown)
		}
		return classifyBatchRunError(report, firstUnknown, runErr)
	})
	panicked = false
	return report, gateErr
}

func (s *Service) runBatchWorkers(
	ctx context.Context,
	req BatchExecRequest,
	targets []TargetNode,
	concurrency int,
	maxOut uint64,
	traceID security.TraceID,
	opID security.OperationID,
) ([]BatchNodeResult, error) {
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
				return s.consumeBatchJobs(workerCtx, req, jobsCh, results, maxOut, traceID, opID, cancelRun)
			}); gErr != nil {
				return gErr
			}
		}
		return nil
	})
	fillMissingBatchResults(targets, results, runCtx, runErr)
	return results, runErr
}

func prepareBatchJobs(
	targets []TargetNode,
	prebound map[inventory.NodeID]*events.OperationStream,
	factory NodeStreamFactory,
	traceID security.TraceID,
	opID security.OperationID,
) ([]batchJob, []*events.OperationStream, error) {
	jobs := make([]batchJob, len(targets))
	var created []*events.OperationStream
	for i, target := range targets {
		st := prebound[target.nodeID]
		if st == nil && factory != nil {
			var err error
			if st, err = factory(target.nodeID, traceID, opID); err != nil {
				return nil, created, fmt.Errorf("创建节点 %s 隔离事件流失败: %w", target.nodeID, err)
			}
			if st != nil {
				created = append(created, st)
			}
		}
		jobs[i] = batchJob{index: i, target: target, stream: st}
	}
	return jobs, created, nil
}

func (s *Service) consumeBatchJobs(
	ctx context.Context,
	req BatchExecRequest,
	jobsCh <-chan batchJob,
	results []BatchNodeResult,
	maxOut uint64,
	traceID security.TraceID,
	opID security.OperationID,
	cancelRun context.CancelCauseFunc,
) error {
	for job := range jobsCh {
		res := s.execBatchNode(ctx, req, job, maxOut, traceID, opID)
		results[job.index] = res
		if s.gate.IsHalted() {
			cancelRun(gate.ErrGateHalted)
		} else if req.FailFast && !res.Succeeded() {
			cancelRun(firstErr(res.err, ErrBatchFailed))
		}
	}
	return nil
}

func (s *Service) execBatchNode(
	ctx context.Context,
	req BatchExecRequest,
	job batchJob,
	maxOut uint64,
	traceID security.TraceID,
	opID security.OperationID,
) BatchNodeResult {
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

	res = s.runSingleNodeCommand(ctx, req, job.target, maxOut, emitter, startedAt)
	panicked = false
	return res
}

func (s *Service) runSingleNodeCommand(
	ctx context.Context,
	req BatchExecRequest,
	target TargetNode,
	maxOut uint64,
	emitter *streamEmitter,
	startedAt time.Time,
) BatchNodeResult {
	if s.gate.IsHalted() {
		return makeNotStartedBatchResult(target.nodeID, execution.StartPhaseAuthorize, "gate_halted", gate.ErrGateHalted, s.clock.Since(startedAt))
	}
	if err := ctx.Err(); err != nil {
		return makeNotStartedBatchResult(target.nodeID, execution.StartPhaseValidate, "canceled", err, s.clock.Since(startedAt))
	}
	execCtx, cancel := applyOptionalTimeout(ctx, req.Command.Timeout())
	defer cancel()

	outW := newBoundedCaptureWriter(execCtx, emitter, events.OutputStreamStdout, maxOut)
	errW := newBoundedCaptureWriter(execCtx, emitter, events.OutputStreamStderr, maxOut)
	outcome, execErr := s.execCommandWithLease(execCtx, target.plan, req.Command, outW, errW)

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
// 精确区分启动前失败（OutcomeNotStarted）与启动后中断/未知结果（OutcomeUnknown，严禁重试）。
func (s *Service) execCommandWithLease(
	ctx context.Context,
	connPlan plan.SealedConnectionPlan,
	cmd execution.CommandPlan,
	stdout, stderr io.Writer,
) (execution.ExecutionOutcome, error) {
	targetHop, ok := connPlan.Target()
	if !ok {
		err := fmt.Errorf("%w: 连接计划缺少末跳目标", ErrInvalidRequest)
		return makeNotStartedOutcome(execution.StartPhaseValidate, "invalid_plan", err), err
	}
	var outcome execution.ExecutionOutcome
	var enteredLease, started bool
	leaseErr := s.pool.WithLease(ctx, connPlan, func(leaseCtx context.Context, lease *pool.Lease) error {
		enteredLease = true
		sess, err := lease.OpenSession(leaseCtx)
		if err != nil {
			outcome = makeNotStartedOutcome(execution.StartPhaseSessionOpen, "open_session_failed", err)
			return err
		}
		defer func() { _ = sess.Close() }()
		var stdin io.Reader
		if payload, hasStdin := cmd.StdinPayload(); hasStdin {
			stdin = strings.NewReader(payload)
		}
		streams := ports.ExecStreams{Stdin: stdin, Stdout: stdout, Stderr: stderr, Env: s.filterSendEnv(targetHop)}
		if err := sess.Start(leaseCtx, cmd, streams); err != nil {
			outcome = makeNotStartedOutcome(execution.StartPhaseRequestRejected, "session_start_failed", err)
			return err
		}
		started = true
		waitOut, waitErr := sess.Wait(leaseCtx)
		outcome = classifyPostStartOutcome(leaseCtx, waitOut, waitErr)
		return waitErr
	})
	if !enteredLease {
		return makeNotStartedOutcome(execution.StartPhaseDial, "lease_failed", leaseErr), leaseErr
	}
	if !started && (outcome == nil || !outcome.IsValid()) {
		return makeNotStartedOutcome(execution.StartPhaseSessionOpen, "prestart_failed", leaseErr), leaseErr
	}
	if started && (outcome == nil || !outcome.IsValid()) {
		return classifyPostStartOutcome(ctx, nil, leaseErr), leaseErr
	}
	return outcome, leaseErr
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
	outDest, e1 := pathalg.ParseLocalRootedDest(nodeID.String() + ".stdout.log")
	errDest, e2 := pathalg.ParseLocalRootedDest(nodeID.String() + ".stderr.log")
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

func fillMissingBatchResults(targets []TargetNode, results []BatchNodeResult, ctx context.Context, runErr error) {
	fallbackErr := firstErr(runErr, ctx.Err(), ErrBatchFailed)
	for i, target := range targets {
		if !results[i].IsValid() {
			results[i] = makeNotStartedBatchResult(target.nodeID, execution.StartPhaseValidate, "batch_aborted", fallbackErr, 0)
		}
	}
}

func foldBatchExecReport(results []BatchNodeResult, dur algebraic.Duration) BatchExecReport {
	var okCnt, failCnt, unkCnt, notStartedCnt int
	for _, r := range results {
		switch {
		case r.IsOutcomeUnknown():
			unkCnt++
		case r.Succeeded():
			okCnt++
		case r.IsNotStarted():
			notStartedCnt++
			failCnt++
		default:
			failCnt++
		}
	}
	return BatchExecReport{
		results: results, succeededCount: okCnt, failedCount: failCnt,
		unknownCount: unkCnt, notStartedCount: notStartedCnt,
		hasUnknownOutcome: unkCnt > 0, duration: dur, valid: len(results) > 0,
	}
}

func findFirstUnknownBatchOutcome(results []BatchNodeResult) execution.ExecutionOutcome {
	for _, r := range results {
		if r.IsOutcomeUnknown() {
			return r.outcome
		}
	}
	return nil
}

func classifyBatchRunError(report BatchExecReport, firstUnknown execution.ExecutionOutcome, runErr error) error {
	if firstUnknown != nil {
		cause := ErrUncertainOutcome
		if runErr != nil && !errors.Is(runErr, ErrUncertainOutcome) {
			cause = fmt.Errorf("%w: %w", ErrUncertainOutcome, runErr)
		}
		if wrapped, err := gate.WrapOutcomeError(firstUnknown, cause); err == nil {
			return wrapped
		}
		return cause
	}
	if runErr != nil {
		return runErr
	}
	if report.failedCount > 0 {
		return fmt.Errorf("%w: succeeded=%d failed=%d", ErrBatchFailed, report.succeededCount, report.failedCount)
	}
	return nil
}

func batchCompletedFields(report BatchExecReport, firstUnknown execution.ExecutionOutcome, gateErr error, panicked bool) (execution.ExecutionOutcome, bool, string, string) {
	if panicked {
		return nil, false, "operation_panicked", "batch exec panicked"
	}
	if firstUnknown != nil {
		return firstUnknown, false, "outcome_unknown", "batch exec has unknown node outcome"
	}
	if gateErr != nil {
		return nil, false, pickIf(errors.Is(gateErr, gate.ErrGateHalted), "gate_halted", "batch_failed"), gateErr.Error()
	}
	return nil, report.failedCount == 0, "", "completed"
}

func classifyNodeCompletedMeta(res BatchNodeResult) (string, string) {
	if !res.IsValid() {
		return "invalid_result", "node result invalid"
	}
	if res.Succeeded() {
		return "", "completed"
	}
	if res.IsOutcomeUnknown() {
		return "outcome_unknown", pickIf(res.errMsg != "", res.errMsg, "execution outcome unknown")
	}
	return "node_failed", pickIf(res.errMsg != "", res.errMsg, "node execution failed")
}

func makeNotStartedBatchResult(nodeID inventory.NodeID, phase execution.StartPhase, code string, err error, elapsed time.Duration) BatchNodeResult {
	return BatchNodeResult{
		nodeID: nodeID, outcome: makeNotStartedOutcome(phase, code, err),
		duration: algebraic.FromStdDuration(max(elapsed, 0)),
		errMsg:   errString(err, ""), err: err, valid: true,
	}
}
