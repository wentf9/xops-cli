package automation

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/playbook"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/gate"
)

type playbookPathInventory struct {
	lexicalPaths []string
	nodePaths    map[inventory.NodeID][]pathalg.RemotePath
	hasProbePath bool
	hasFileWrite bool
}

type playbookPrepared struct {
	targets          []TargetNode
	concurrency      int
	vars             map[string]string
	varsDigest       security.Digest
	paths            playbookPathInventory
	defProfile       execution.LaunchProfile
	scopedSourceRoot algebraic.Option[pathalg.LocalDir]
	timeout          algebraic.Option[algebraic.Duration]
}

// RunPlaybook 执行声明式 Playbook vNext 不可变 AST（P3-T4）：
//   - 全程遵守 gate.WithAuthorized[security.CapExecute] 外包 pool.WithLease；
//   - 两步审批绑定 100% 由显式 Playbook 规范摘要、排序目标集合、合并变量摘要与远端路径集合确定（零门控前抽熵漂移）；
//   - 非 DirectOperator 配置档下对全部 copy/template 远端写目标（含 ensure.action 内嵌写步骤）执行 Round-2 软链规范化探测；
//   - 按双模态本地 FS 隔离原则加载 script/copy/template 源内容（MCP 缺席 OperatorReadFS 即 Fail-Closed）；
//   - 穷尽执行 5 类封闭 StepAction、驱动 EnsureFSM 状态机并经 playbook.FoldPlaybookReport 产出确定性不可变报表。
func (s *Service) RunPlaybook(ctx context.Context, req PlaybookRequest) (PlaybookRunResult, error) {
	defer closeAllStreams(req.OperationStream, req.NodeStreams)
	prep, err := s.validateAndPreparePlaybook(ctx, req)
	if err != nil {
		return PlaybookRunResult{}, err
	}
	gateReq, err := s.buildPlaybookGateRequest(req, prep)
	if err != nil {
		return PlaybookRunResult{}, err
	}
	return s.executeAuthorizedPlaybook(ctx, req, prep, gateReq)
}

func (s *Service) validateAndPreparePlaybook(ctx context.Context, req PlaybookRequest) (playbookPrepared, error) {
	if err := s.checkReady(ctx); err != nil {
		return playbookPrepared{}, err
	}
	if !req.Playbook.IsValid() {
		return playbookPrepared{}, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "Playbook"))
	}
	if err := validatePlaybookOptionals(req); err != nil {
		return playbookPrepared{}, err
	}
	concurrency, err := s.resolveConcurrency(req.Concurrency)
	if err != nil {
		return playbookPrepared{}, err
	}
	if err := s.validatePlaybookLocalSourceAccess(req.Playbook, req.ScopedSourceRoot); err != nil {
		return playbookPrepared{}, err
	}
	targets, err := s.resolveTargets(ctx, req.Targets, algebraic.Some(req.Playbook.Target()), req.CLIOptions, nil, nil)
	if err != nil {
		return playbookPrepared{}, err
	}
	vars := mergeStringMaps(req.Playbook.Vars(), req.ExtraVars)
	paths, err := collectPlaybookRemotePaths(req.Playbook, targets)
	if err != nil {
		return playbookPrepared{}, err
	}
	return playbookPrepared{
		targets:          targets,
		concurrency:      concurrency,
		vars:             vars,
		varsDigest:       digestStringMap(varsDigestDomainTag, vars),
		paths:            paths,
		defProfile:       req.DefaultProfile.OrElse(execution.DefaultServerLaunchProfile()),
		scopedSourceRoot: req.ScopedSourceRoot,
		timeout:          req.Timeout,
	}, nil
}

func validatePlaybookOptionals(req PlaybookRequest) error {
	if p, ok := req.DefaultProfile.Get(); ok && !p.IsValid() {
		return domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "DefaultProfile"))
	}
	if d, ok := req.Timeout.Get(); ok && !d.IsPositive() {
		return domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldPositive, domi18n.Str("field", "Timeout"))
	}
	if r, ok := req.Risk.Get(); ok && !r.IsValid() {
		return domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "RiskLevel"))
	}
	if root, ok := req.ScopedSourceRoot.Get(); ok && !root.IsValid() {
		return domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "ScopedSourceRoot"))
	}
	return nil
}

func mergeStringMaps(base, extra map[string]string) map[string]string {
	if len(base) == 0 && len(extra) == 0 {
		return nil
	}
	out := make(map[string]string, len(base)+len(extra))
	maps.Copy(out, base)
	maps.Copy(out, extra)
	return out
}

func (s *Service) buildPlaybookGateRequest(req PlaybookRequest, prep playbookPrepared) (gate.GateRequest[security.CapExecute], error) {
	binding, err := buildPlaybookBinding(req.Playbook, prep, prep.paths.lexicalPaths)
	if err != nil {
		return zeroVal[gate.GateRequest[security.CapExecute]](), err
	}
	var canonFn gate.CanonicalizeFunc
	if s.enforceStrictPaths() && prep.paths.hasProbePath {
		canonFn = s.makePlaybookCanonicalizer(req.Playbook, prep)
	}
	return gate.NewGateRequest[security.CapExecute](gate.GateRequestSpec[security.CapExecute]{
		Binding:         binding,
		Risk:            req.Risk.OrElse(security.RiskModerate),
		ScopeSummary:    fmt.Sprintf("playbook %s (%d steps, %d nodes)", req.Playbook.ID(), req.Playbook.Steps().Len(), len(prep.targets)),
		Paths:           prep.paths.lexicalPaths,
		Canonicalize:    canonFn,
		Approval:        req.Approval,
		OperationStream: req.OperationStream,
	})
}

func buildPlaybookBinding(pb playbook.Playbook, prep playbookPrepared, paths []string) (security.OperationBinding, error) {
	nodeIDs := extractNodeIDStrings(prep.targets)
	singleNode, singleEP := singleTargetMeta(prep.targets, nodeIDs)
	params := map[string]string{
		"playbook_id":        pb.ID().String(),
		"playbook_digest":    pb.Digest().String(),
		"on_error":           pb.OnError().String(),
		"vars_digest":        prep.varsDigest.String(),
		"step_count":         strconv.Itoa(pb.Steps().Len()),
		"has_file_write":     strconv.FormatBool(prep.paths.hasFileWrite),
		"concurrency":        strconv.Itoa(prep.concurrency),
		"default_profile":    formatLaunchProfile(prep.defProfile),
		"scoped_source_mode": "operator",
	}
	if root, ok := prep.scopedSourceRoot.Get(); ok {
		params["scoped_source_mode"] = "scoped"
		params["scoped_source_root"] = root.String()
	}
	if d, ok := prep.timeout.Get(); ok {
		params["timeout"] = d.String()
	}
	return security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityExecute, Tool: toolAutomation, Action: "playbook",
		NodeID: singleNode, NodeIDs: nodeIDs, Endpoint: singleEP, CanonicalPaths: paths,
		CommandDigest: algebraic.Some(pb.Digest()), PlanDigest: algebraic.Some(digestTargetPlans(prep.targets)),
		Parameters: params,
	})
}

// makePlaybookCanonicalizer 为非 DirectOperator 下按节点标签实际命中的 copy/template 写目标与 WorkDir 执行 Round-2 软链规范化探测，
// 仅探测各节点实际匹配的远端路径并取单调并集，避免跨标签误探同时杜绝受保护路径软链绕过。
func (s *Service) makePlaybookCanonicalizer(pb playbook.Playbook, prep playbookPrepared) gate.CanonicalizeFunc {
	return func(ctx context.Context) (gate.CanonicalizeResult, error) {
		pathSet := make(map[string]struct{}, len(prep.paths.lexicalPaths))
		for _, p := range prep.paths.lexicalPaths {
			pathSet[p] = struct{}{}
		}
		for _, target := range prep.targets {
			if err := s.canonicalizeNodeRemotePaths(ctx, target.plan, prep.paths.nodePaths[target.nodeID], pathSet); err != nil {
				return gate.CanonicalizeResult{}, err
			}
		}
		allPaths := slices.Sorted(maps.Keys(pathSet))
		canBind, err := buildPlaybookBinding(pb, prep, allPaths)
		if err != nil {
			return gate.CanonicalizeResult{}, err
		}
		return gate.CanonicalizeResult{Binding: canBind, Paths: allPaths}, nil
	}
}

func (s *Service) executeAuthorizedPlaybook(
	ctx context.Context,
	req PlaybookRequest,
	prep playbookPrepared,
	gateReq gate.GateRequest[security.CapExecute],
) (PlaybookRunResult, error) {
	var result PlaybookRunResult
	var emitter *streamEmitter
	var firstUnknown execution.ExecutionOutcome
	var gateErr error
	startedAt, entered, panicked := s.clock.Now().UTC().Round(0), false, true
	defer func() {
		if entered {
			out, ok, code, msg := playbookCompletedFields(result, firstUnknown, gateErr, panicked)
			emitter.emitCompleted(ctx, startedAt, out, ok, code, msg)
		}
	}()
	gateErr = gate.WithAuthorized[security.CapExecute](ctx, s.gate, gateReq, func(authCtx context.Context, auth gate.Authorized[security.CapExecute]) error {
		entered, startedAt = true, s.clock.Now().UTC().Round(0)
		emitter = newStreamEmitter(req.OperationStream, s.clock, auth.TraceID(), auth.OperationID(), algebraic.None[inventory.NodeID](), security.CapabilityExecute)
		emitter.emitStarted(authCtx, "playbook", algebraic.None[plan.PlanDigest](), gateReq.ScopeSummary())

		runCtx, cancelTimeout := applyOptionalTimeout(authCtx, req.Timeout)
		defer cancelTimeout()

		// 授权通过后再读取本地源文件快照，杜绝未授权/熔断路径触碰任何本地文件系统。
		sources, err := s.preloadPlaybookSources(runCtx, req.Playbook, prep.targets, req.ScopedSourceRoot)
		if err != nil {
			return err
		}
		rc := &playbookRunContext{
			svc: s, req: req, prep: prep, sources: sources,
			authBinding: auth.Binding(), traceID: auth.TraceID(), opID: auth.OperationID(),
			batchEmitter: emitter, valid: true,
		}
		records, aborted, runErr := rc.runAllNodes(runCtx)
		rep, foldErr := playbook.FoldPlaybookReport(req.Playbook, records)
		if foldErr != nil {
			return firstErr(runErr, foldErr)
		}
		result = PlaybookRunResult{
			report: rep, aborted: aborted, hasUnknownOutcome: rep.HasUnknownOutcome(),
			duration: algebraic.FromStdDuration(max(s.clock.Since(startedAt), 0)), valid: true,
		}
		firstUnknown = findFirstUnknownPlaybookOutcome(records)
		if firstUnknown != nil {
			_ = auth.ReportOutcome(firstUnknown)
		}
		return classifyPlaybookRunError(result, firstUnknown, runErr, s.gate.IsHalted())
	})
	panicked = false
	return result, gateErr
}

// playbookRunContext 封装单次已授权 Playbook 运行的共享不可变快照与中止协调状态。
//
//xops:failclosed
type playbookRunContext struct {
	svc          *Service
	req          PlaybookRequest
	prep         playbookPrepared
	sources      map[string][]byte
	authBinding  security.OperationBinding
	traceID      security.TraceID
	opID         security.OperationID
	batchEmitter *streamEmitter
	aborted      atomic.Bool
	valid        bool
}

func (rc *playbookRunContext) runAllNodes(ctx context.Context) ([]playbook.StepExecutionRecord, bool, error) {
	jobs, factoryStreams, err := prepareBatchJobs(rc.prep.targets, rc.req.NodeStreams, rc.req.NodeStreamFactory, rc.traceID, rc.opID)
	defer func() {
		for _, st := range factoryStreams {
			closeStream(st)
		}
	}()
	if err != nil {
		return nil, false, err
	}
	steps := rc.req.Playbook.StepSlice()
	jobsCh := make(chan batchJob, len(jobs))
	for _, job := range jobs {
		jobsCh <- job
	}
	close(jobsCh)
	var recMu sync.Mutex
	completedNodes := make(map[inventory.NodeID]bool, len(jobs))
	allRecords := make([]playbook.StepExecutionRecord, 0, len(jobs)*len(steps))
	runCtx, cancelRun := context.WithCancelCause(ctx)
	defer cancelRun(nil)
	runErr := conc.RunWait(runCtx, func(_ context.Context, n *conc.Nursery) error {
		for range min(rc.prep.concurrency, len(jobs)) {
			if gErr := n.Go(func(workerCtx context.Context) error {
				for job := range jobsCh {
					nodeRecs := rc.runPlaybookNode(workerCtx, job, steps, cancelRun)
					recMu.Lock()
					completedNodes[job.target.nodeID] = true
					allRecords = append(allRecords, nodeRecs...)
					recMu.Unlock()
				}
				return nil
			}); gErr != nil {
				return gErr
			}
		}
		return nil
	})
	allRecords = rc.backfillMissingNodeRecords(runCtx, allRecords, completedNodes, steps, runErr)
	return allRecords, rc.aborted.Load(), runErr
}

func (rc *playbookRunContext) backfillMissingNodeRecords(ctx context.Context, records []playbook.StepExecutionRecord, completed map[inventory.NodeID]bool, steps []playbook.Step, runErr error) []playbook.StepExecutionRecord {
	reason := abortReasonForContext(rc.svc.gate.IsHalted(), rc.aborted.Load(), firstErr(runErr, context.Cause(ctx), ctx.Err()))
	for _, target := range rc.prep.targets {
		if completed[target.nodeID] {
			continue
		}
		for _, st := range steps {
			records = append(records, buildSimpleStepRecord(target.nodeID, st.ID(), playbook.StepStatusAborted, algebraic.None[execution.ExecutionOutcome](), algebraic.ZeroDuration(), reason))
		}
	}
	return records
}

func (rc *playbookRunContext) runPlaybookNode(ctx context.Context, job batchJob, steps []playbook.Step, cancelRun context.CancelCauseFunc) []playbook.StepExecutionRecord {
	defer closeStream(job.stream)
	startedAt := rc.svc.clock.Now().UTC().Round(0)
	nodeEmitter := newStreamEmitter(job.stream, rc.svc.clock, rc.traceID, rc.opID, algebraic.Some(job.target.nodeID), security.CapabilityExecute)
	nodeEmitter.emitStarted(ctx, "playbook_node", algebraic.Some(job.target.plan.PlanDigest()), rc.req.Playbook.Name())

	var records []playbook.StepExecutionRecord
	panicked := true
	defer func() {
		if panicked {
			nodeEmitter.emitCompleted(ctx, startedAt, nil, false, "operation_panicked", "playbook node execution panicked")
			return
		}
		out, ok, code, msg := summarizeNodePlaybookTerminal(records)
		nodeEmitter.emitCompleted(ctx, startedAt, out, ok, code, msg)
	}()

	records = rc.executeNodeSteps(ctx, job.target, steps, nodeEmitter, cancelRun)
	panicked = false
	return records
}

func (rc *playbookRunContext) executeNodeSteps(ctx context.Context, target TargetNode, steps []playbook.Step, nodeEmitter *streamEmitter, cancelRun context.CancelCauseFunc) []playbook.StepExecutionRecord {
	records := make([]playbook.StepExecutionRecord, 0, len(steps))
	nodeStopped, stopReason := false, ""
	for _, st := range steps {
		if nodeStopped || rc.aborted.Load() || rc.svc.gate.IsHalted() || ctx.Err() != nil {
			reason := pickIf(stopReason != "", stopReason, abortReasonForContext(rc.svc.gate.IsHalted(), rc.aborted.Load(), ctx.Err()))
			rec := buildSimpleStepRecord(target.nodeID, st.ID(), playbook.StepStatusAborted, algebraic.None[execution.ExecutionOutcome](), algebraic.ZeroDuration(), reason)
			records = append(records, rec)
			rc.emitStepToBoth(ctx, nodeEmitter, rec)
			continue
		}
		if !st.MatchesTags(target.tags) {
			rec := buildSimpleStepRecord(target.nodeID, st.ID(), playbook.StepStatusSkipped, algebraic.None[execution.ExecutionOutcome](), algebraic.ZeroDuration(), "step tags not matched")
			records = append(records, rec)
			rc.emitStepToBoth(ctx, nodeEmitter, rec)
			continue
		}
		rec := rc.executeSingleStep(ctx, target, st, nodeEmitter)
		records = append(records, rec)
		rc.emitStepToBoth(ctx, nodeEmitter, rec)
		// OutcomeUnknown 严禁在 OnErrorContinue 下继续向不确定主机执行后续变更（ADR-016）：
		// 除 OnErrorAbort 升级为全盘中止外，均强制停止当前节点后续步骤且不影响独立兄弟节点。
		if rec.Status() == playbook.StepStatusOutcomeUnknown {
			nodeStopped, stopReason = rc.applyUnknownOutcomeStop(rc.req.Playbook.EffectiveOnError(st), st.ID(), cancelRun)
		} else if rec.Status() == playbook.StepStatusFailed {
			nodeStopped, stopReason = rc.applyOnErrorPolicy(rc.req.Playbook.EffectiveOnError(st), st.ID(), cancelRun)
		}
	}
	return records
}

func (rc *playbookRunContext) applyUnknownOutcomeStop(pol playbook.OnErrorPolicy, stepID playbook.StepID, cancelRun context.CancelCauseFunc) (bool, string) {
	if pol == playbook.OnErrorAbort {
		rc.aborted.Store(true)
		cancelRun(ErrPlaybookAborted)
		return true, fmt.Sprintf("playbook aborted after step %s outcome_unknown", stepID)
	}
	return true, fmt.Sprintf("aborted after step %s outcome_unknown (halted uncertain node)", stepID)
}

func (rc *playbookRunContext) applyOnErrorPolicy(pol playbook.OnErrorPolicy, stepID playbook.StepID, cancelRun context.CancelCauseFunc) (bool, string) {
	switch pol {
	case playbook.OnErrorContinue:
		return false, ""
	case playbook.OnErrorFailFast:
		return true, fmt.Sprintf("aborted after step %s failed (fail_fast)", stepID)
	case playbook.OnErrorAbort:
		rc.aborted.Store(true)
		cancelRun(ErrPlaybookAborted)
		return true, fmt.Sprintf("playbook aborted after step %s failed", stepID)
	default:
		return true, "aborted due to invalid on_error policy"
	}
}

func (rc *playbookRunContext) emitStepToBoth(ctx context.Context, nodeEmitter *streamEmitter, rec playbook.StepExecutionRecord) {
	pbID := rc.req.Playbook.ID()
	nodeEmitter.emitStep(ctx, pbID, rec)
	rc.batchEmitter.emitStep(ctx, pbID, rec)
}

func findFirstUnknownPlaybookOutcome(records []playbook.StepExecutionRecord) execution.ExecutionOutcome {
	for _, rec := range records {
		if out, ok := rec.Outcome().Get(); ok && out != nil && out.Kind() == execution.OutcomeKindUnknown {
			return out
		}
	}
	return nil
}

func classifyPlaybookRunError(res PlaybookRunResult, firstUnknown execution.ExecutionOutcome, runErr error, halted bool) error {
	if firstUnknown != nil {
		cause := ErrUncertainOutcome
		if halted {
			cause = domi18n.WrapSentinel(ErrUncertainOutcome, gate.ErrGateHalted)
		} else if runErr != nil && !errors.Is(runErr, ErrUncertainOutcome) {
			cause = domi18n.WrapSentinel(ErrUncertainOutcome, runErr)
		}
		if wrapped, err := gate.WrapOutcomeError(firstUnknown, cause); err == nil {
			return wrapped
		}
		return cause
	}
	if halted && !errors.Is(runErr, gate.ErrGateHalted) {
		return pickIf[error](runErr != nil, domi18n.WrapSentinel(gate.ErrGateHalted, runErr), gate.ErrGateHalted)
	}
	if runErr != nil {
		return runErr
	}
	switch res.report.Status() {
	case playbook.NodeStatusSucceeded, playbook.NodeStatusChanged:
		return nil
	case playbook.NodeStatusAborted:
		return ErrPlaybookAborted
	case playbook.NodeStatusOutcomeUnknown:
		return ErrUncertainOutcome
	default:
		return pickIf[error](res.aborted, domi18n.WrapSentinel(ErrPlaybookAborted, ErrPlaybookFailed), ErrPlaybookFailed)
	}
}

func playbookCompletedFields(res PlaybookRunResult, firstUnknown execution.ExecutionOutcome, gateErr error, panicked bool) (execution.ExecutionOutcome, bool, string, string) {
	if panicked {
		return nil, false, "operation_panicked", "playbook panicked"
	}
	if firstUnknown != nil {
		return firstUnknown, false, "outcome_unknown", "playbook contains unknown step outcome"
	}
	if gateErr != nil {
		return nil, false, pickIf(errors.Is(gateErr, gate.ErrGateHalted), "gate_halted", "playbook_failed"), gateErr.Error()
	}
	ok := res.IsValid() && (res.report.Status() == playbook.NodeStatusSucceeded || res.report.Status() == playbook.NodeStatusChanged)
	return nil, ok, "", "completed"
}

func summarizeNodePlaybookTerminal(records []playbook.StepExecutionRecord) (execution.ExecutionOutcome, bool, string, string) {
	for _, rec := range records {
		if rec.IsOutcomeUnknown() {
			out, _ := rec.Outcome().Get()
			return out, false, "outcome_unknown", rec.Message()
		}
	}
	for _, rec := range records {
		if rec.Status() == playbook.StepStatusFailed || rec.Status() == playbook.StepStatusAborted {
			return nil, false, "playbook_node_failed", rec.Message()
		}
	}
	return nil, true, "", "completed"
}

func abortReasonForContext(halted, aborted bool, ctxErr error) string {
	switch {
	case halted:
		return "aborted: gate halted"
	case aborted:
		return "aborted: playbook on_error=abort triggered"
	case ctxErr != nil:
		return "aborted: " + ctxErr.Error()
	default:
		return "aborted"
	}
}
