package automation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"slices"
	"text/template"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/playbook"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/ports"
)

func (s *Service) validatePlaybookLocalSourceAccess(pb playbook.Playbook, scopedRoot algebraic.Option[pathalg.LocalDir]) error {
	for _, st := range pb.StepSlice() {
		if err := s.validateActionLocalSource(st.Action(), scopedRoot); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) validateActionLocalSource(act playbook.StepAction, scopedRoot algebraic.Option[pathalg.LocalDir]) error {
	switch v := act.(type) {
	case *playbook.StepShell:
		return nil
	case *playbook.StepScript:
		return s.validateSingleLocalSource(v.Source(), v.SymlinkPolicy(), scopedRoot)
	case *playbook.StepCopy:
		return s.validateSingleLocalSource(v.Source(), v.SymlinkPolicy(), scopedRoot)
	case *playbook.StepTemplate:
		return s.validateSingleLocalSource(v.Source(), v.SymlinkPolicy(), scopedRoot)
	case *playbook.StepEnsure:
		return firstErr(s.validateActionLocalSource(v.Check(), scopedRoot), s.validateActionLocalSource(v.Action(), scopedRoot))
	default:
		return ErrUnsupportedAction
	}
}

func (s *Service) validateSingleLocalSource(src pathalg.LocalSourcePath, policy pathalg.SymlinkPolicy, scopedRoot algebraic.Option[pathalg.LocalDir]) error {
	if _, hasScoped := scopedRoot.Get(); hasScoped {
		if s.scopedFS == nil {
			return ErrScopedFSUnavailable
		}
		if src.IsAbs() {
			return fmt.Errorf("%w: 沙箱模式禁止绝对本地源路径 %s", ErrInvalidRequest, src)
		}
		if policy.AllowsOperatorFollow() {
			return fmt.Errorf("%w: 沙箱模式禁止 follow_operator_source 软链策略", ErrSymlinkPolicyDenied)
		}
		if _, err := pathalg.ParseLocalRootedDest(src.String()); err != nil {
			return fmt.Errorf("%w: 沙箱本地源路径 %s 非法: %w", ErrInvalidRequest, src, err)
		}
		return nil
	}
	if s.operatorReadFS == nil {
		return ErrOperatorReadUnavailable
	}
	return nil
}

func collectPlaybookRemotePaths(pb playbook.Playbook, targets []TargetNode) (playbookPathInventory, error) {
	lexSet := make(map[string]struct{})
	nodeSets := make(map[inventory.NodeID]map[string]pathalg.RemotePath, len(targets))
	hasWrite := false
	for _, st := range pb.StepSlice() {
		stepPaths, stepWrites, err := extractActionRemotePaths(st.Action())
		if err != nil {
			return playbookPathInventory{}, err
		}
		hasWrite = hasWrite || stepWrites
		recordStepNodePaths(st, stepPaths, targets, lexSet, nodeSets)
	}
	nodePaths, hasProbe := sortNodeRemotePaths(nodeSets)
	return playbookPathInventory{
		lexicalPaths: slices.Sorted(maps.Keys(lexSet)), nodePaths: nodePaths,
		hasProbePath: hasProbe, hasFileWrite: hasWrite,
	}, nil
}

func recordStepNodePaths(st playbook.Step, stepPaths []pathalg.RemotePath, targets []TargetNode, lexSet map[string]struct{}, nodeSets map[inventory.NodeID]map[string]pathalg.RemotePath) {
	if len(stepPaths) == 0 {
		return
	}
	for _, target := range targets {
		if !st.MatchesTags(target.tags) {
			continue
		}
		m := nodeSets[target.nodeID]
		if m == nil {
			m = make(map[string]pathalg.RemotePath, len(stepPaths))
			nodeSets[target.nodeID] = m
		}
		for _, p := range stepPaths {
			lexSet[p.String()], m[p.String()] = struct{}{}, p
		}
	}
}

func sortNodeRemotePaths(nodeSets map[inventory.NodeID]map[string]pathalg.RemotePath) (map[inventory.NodeID][]pathalg.RemotePath, bool) {
	nodePaths := make(map[inventory.NodeID][]pathalg.RemotePath, len(nodeSets))
	hasProbe := false
	for id, m := range nodeSets {
		keys := slices.Sorted(maps.Keys(m))
		list := make([]pathalg.RemotePath, 0, len(keys))
		for _, k := range keys {
			list = append(list, m[k])
		}
		hasProbe = hasProbe || len(list) > 0
		nodePaths[id] = list
	}
	return nodePaths, hasProbe
}

func extractActionRemotePaths(act playbook.StepAction) ([]pathalg.RemotePath, bool, error) {
	switch v := act.(type) {
	case *playbook.StepShell:
		if wd, ok := v.WorkDir().Get(); ok && wd.IsValid() {
			return []pathalg.RemotePath{wd}, false, nil
		}
		return nil, false, nil
	case *playbook.StepScript:
		if wd, ok := v.WorkDir().Get(); ok && wd.IsValid() {
			return []pathalg.RemotePath{wd}, false, nil
		}
		return nil, false, nil
	case *playbook.StepCopy:
		return []pathalg.RemotePath{v.Dest()}, true, nil
	case *playbook.StepTemplate:
		return []pathalg.RemotePath{v.Dest()}, true, nil
	case *playbook.StepEnsure:
		p1, w1, e1 := extractActionRemotePaths(v.Check())
		p2, w2, e2 := extractActionRemotePaths(v.Action())
		return append(p1, p2...), w1 || w2, firstErr(e1, e2)
	default:
		return nil, false, ErrUnsupportedAction
	}
}

// preloadPlaybookSources 在门控授权通过后冻结本轮 Playbook 所需的本地脚本、文件与模板不可变字节快照，
// 保证并发多节点读取完全一致且零本地文件句柄逃逸至后台协程。
func (s *Service) preloadPlaybookSources(ctx context.Context, pb playbook.Playbook, targets []TargetNode, scopedRoot algebraic.Option[pathalg.LocalDir]) (map[string][]byte, error) {
	sources := make(map[string][]byte)
	for _, st := range pb.StepSlice() {
		if !stepMatchesAnyTarget(st, targets) {
			continue
		}
		if err := s.preloadActionSources(ctx, st.Action(), scopedRoot, sources); err != nil {
			return nil, err
		}
	}
	return sources, nil
}

func stepMatchesAnyTarget(st playbook.Step, targets []TargetNode) bool {
	return slices.ContainsFunc(targets, func(t TargetNode) bool { return st.MatchesTags(t.tags) })
}

func (s *Service) preloadActionSources(ctx context.Context, act playbook.StepAction, scopedRoot algebraic.Option[pathalg.LocalDir], cache map[string][]byte) error {
	switch v := act.(type) {
	case *playbook.StepShell:
		return nil
	case *playbook.StepScript:
		return s.loadLocalSourceInto(ctx, v.Source(), v.SymlinkPolicy(), s.maxScriptBytes, scopedRoot, cache)
	case *playbook.StepCopy:
		return s.loadLocalSourceInto(ctx, v.Source(), v.SymlinkPolicy(), s.maxCopyBytes, scopedRoot, cache)
	case *playbook.StepTemplate:
		return s.loadLocalSourceInto(ctx, v.Source(), v.SymlinkPolicy(), s.maxTemplateBytes, scopedRoot, cache)
	case *playbook.StepEnsure:
		return firstErr(s.preloadActionSources(ctx, v.Check(), scopedRoot, cache), s.preloadActionSources(ctx, v.Action(), scopedRoot, cache))
	default:
		return ErrUnsupportedAction
	}
}

func sourceCacheKey(src pathalg.LocalSourcePath, policy pathalg.SymlinkPolicy) string {
	return policy.String() + "\x00" + src.String()
}

func (s *Service) loadLocalSourceInto(ctx context.Context, src pathalg.LocalSourcePath, policy pathalg.SymlinkPolicy, maxBytes int64, scopedRoot algebraic.Option[pathalg.LocalDir], cache map[string][]byte) error {
	key := sourceCacheKey(src, policy)
	if existing, ok := cache[key]; ok {
		if int64(len(existing)) > maxBytes {
			return fmt.Errorf("%w: 本地源文件 %s 大小 %d 超过当前步骤上限 %d", ports.ErrLimitExceeded, src, len(existing), maxBytes)
		}
		return nil
	}
	data, err := s.readLocalSourceBounded(ctx, src, policy, maxBytes, scopedRoot)
	if err != nil {
		return err
	}
	cache[key] = data
	return nil
}

func (s *Service) readLocalSourceBounded(ctx context.Context, src pathalg.LocalSourcePath, policy pathalg.SymlinkPolicy, maxBytes int64, scopedRoot algebraic.Option[pathalg.LocalDir]) ([]byte, error) {
	limits, err := ports.NewReadLimits(maxBytes)
	if err != nil {
		return nil, err
	}
	if rootDir, hasScoped := scopedRoot.Get(); hasScoped {
		if s.scopedFS == nil {
			return nil, ErrScopedFSUnavailable
		}
		dest, err := pathalg.ParseLocalRootedDest(src.String())
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
		}
		var data []byte
		err = s.scopedFS.WithRoot(rootDir, func(root ports.RootHandle) error {
			var rErr error
			data, rErr = root.ReadAllBounded(dest, limits)
			return rErr
		})
		return data, err
	}
	if s.operatorReadFS == nil {
		return nil, ErrOperatorReadUnavailable
	}
	var data []byte
	err = s.operatorReadFS.WithOperatorRead(ctx, src, policy, func(r ports.BoundedReadHandle, size int64) error {
		if size > maxBytes {
			return fmt.Errorf("%w: 本地源文件 %s 大小 %d 超过上限 %d", ports.ErrLimitExceeded, src, size, maxBytes)
		}
		var rErr error
		data, rErr = io.ReadAll(io.LimitReader(r, maxBytes+1))
		if rErr == nil && int64(len(data)) > maxBytes {
			return fmt.Errorf("%w: 本地源文件 %s 超出上限 %d", ports.ErrLimitExceeded, src, maxBytes)
		}
		return rErr
	})
	return data, err
}

// executeSingleStep 穷尽分派 5 类封闭 playbook.StepAction（含 fail-closed default），产出校验后的 StepExecutionRecord。
func (rc *playbookRunContext) executeSingleStep(ctx context.Context, target TargetNode, step playbook.Step, nodeEmitter *streamEmitter) playbook.StepExecutionRecord {
	startedAt := rc.svc.clock.Now().UTC().Round(0)
	status, outcome, msg := rc.dispatchStepAction(ctx, target, step, nodeEmitter)
	dur := algebraic.FromStdDuration(max(rc.svc.clock.Since(startedAt), 0))
	outOpt := algebraic.None[execution.ExecutionOutcome]()
	if outcome != nil && outcome.IsValid() {
		outOpt = algebraic.Some(outcome)
	}
	return buildSimpleStepRecord(target.nodeID, step.ID(), status, outOpt, dur, msg)
}

func (rc *playbookRunContext) dispatchStepAction(ctx context.Context, target TargetNode, step playbook.Step, nodeEmitter *streamEmitter) (playbook.StepStatus, execution.ExecutionOutcome, string) {
	switch act := step.Action().(type) {
	case *playbook.StepShell:
		return rc.runShellAction(ctx, target, act, nodeEmitter)
	case *playbook.StepScript:
		return rc.runScriptAction(ctx, target, act, nodeEmitter)
	case *playbook.StepCopy:
		return rc.runCopyAction(ctx, target, act)
	case *playbook.StepTemplate:
		return rc.runTemplateAction(ctx, target, act)
	case *playbook.StepEnsure:
		return rc.runEnsureAction(ctx, target, step.ID(), act, nodeEmitter)
	default:
		return playbook.StepStatusFailed, makeNotStartedOutcome(execution.StartPhaseValidate, "unsupported_action", ErrUnsupportedAction), ErrUnsupportedAction.Error()
	}
}

func (rc *playbookRunContext) effectiveProfile(target TargetNode, stepProf algebraic.Option[execution.LaunchProfile]) execution.LaunchProfile {
	if p, ok := stepProf.Get(); ok && p.IsValid() {
		return p
	}
	if p, ok := target.defaultProfile.Get(); ok && p.IsValid() {
		return p
	}
	return rc.prep.defProfile
}

func (rc *playbookRunContext) runShellAction(ctx context.Context, target TargetNode, act *playbook.StepShell, nodeEmitter *streamEmitter) (playbook.StepStatus, execution.ExecutionOutcome, string) {
	cmdPlan, err := execution.NewCommandPlan(execution.CommandPlanSpec{
		Kind: execution.PlanKindCommand, Profile: rc.effectiveProfile(target, act.Profile()),
		Command: act.Command(), WorkDir: act.WorkDir(), Env: act.Env(), Timeout: act.Timeout(),
	})
	if err != nil {
		return playbook.StepStatusFailed, makeNotStartedOutcome(execution.StartPhaseValidate, "invalid_shell_plan", err), err.Error()
	}
	return rc.runCommandPlanForStep(ctx, target, cmdPlan, nodeEmitter, playbook.StepStatusChanged)
}

func (rc *playbookRunContext) runScriptAction(ctx context.Context, target TargetNode, act *playbook.StepScript, nodeEmitter *streamEmitter) (playbook.StepStatus, execution.ExecutionOutcome, string) {
	raw, ok := rc.sources[sourceCacheKey(act.Source(), act.SymlinkPolicy())]
	if !ok {
		err := fmt.Errorf("%w: 脚本快照缺失 %s", ErrInvalidRequest, act.Source())
		return playbook.StepStatusFailed, makeNotStartedOutcome(execution.StartPhaseValidate, "missing_script", err), err.Error()
	}
	prof := rc.resolveScriptProfile(target, act.Profile())
	cmdPlan, err := execution.NewCommandPlan(execution.CommandPlanSpec{
		Kind: execution.PlanKindScript, Profile: prof, Command: string(raw),
		Argv: act.Args(), WorkDir: act.WorkDir(), Env: act.Env(), Timeout: act.Timeout(),
	})
	if err != nil {
		return playbook.StepStatusFailed, makeNotStartedOutcome(execution.StartPhaseValidate, "invalid_script_plan", err), err.Error()
	}
	return rc.runCommandPlanForStep(ctx, target, cmdPlan, nodeEmitter, playbook.StepStatusChanged)
}

func (rc *playbookRunContext) resolveScriptProfile(target TargetNode, stepProf algebraic.Option[execution.LaunchProfile]) execution.LaunchProfile {
	prof := rc.effectiveProfile(target, stepProf)
	// PlanKindScript 要求显式 POSIX 或 PowerShell 解释器；若节点未指定具体解释器则回退 POSIX sh。
	if prof.Interpreter() == execution.InterpreterServer {
		if posixSH, err := execution.POSIXLaunchProfile(execution.InterpreterSH, execution.LoginModeInherit); err == nil {
			return posixSH
		}
	}
	return prof
}

func (rc *playbookRunContext) runCommandPlanForStep(ctx context.Context, target TargetNode, cmdPlan execution.CommandPlan, nodeEmitter *streamEmitter, successStatus playbook.StepStatus) (playbook.StepStatus, execution.ExecutionOutcome, string) {
	execCtx, cancel := applyOptionalTimeout(ctx, cmdPlan.Timeout())
	defer cancel()
	outW := newBoundedCaptureWriter(execCtx, nodeEmitter, events.OutputStreamStdout, cmdPlan.MaxOutputBytes())
	errW := newBoundedCaptureWriter(execCtx, nodeEmitter, events.OutputStreamStderr, cmdPlan.MaxOutputBytes())
	outcome, execErr := rc.svc.execCommandWithLease(execCtx, target.plan, cmdPlan, rc.authBinding, rc.svc.enforceStrictPaths(), outW, errW)
	return mapOutcomeToStepStatus(outcome, execErr, successStatus)
}

func (rc *playbookRunContext) runCopyAction(ctx context.Context, target TargetNode, act *playbook.StepCopy) (playbook.StepStatus, execution.ExecutionOutcome, string) {
	payload, ok := rc.sources[sourceCacheKey(act.Source(), act.SymlinkPolicy())]
	if !ok {
		err := fmt.Errorf("%w: copy 源快照缺失 %s", ErrInvalidRequest, act.Source())
		return playbook.StepStatusFailed, makeNotStartedOutcome(execution.StartPhaseValidate, "missing_copy_source", err), err.Error()
	}
	return rc.writeRemoteStepPayload(ctx, target, act.Dest(), act.Mode(), act.Overwrite(), act.Atomic(), payload)
}

func (rc *playbookRunContext) runTemplateAction(ctx context.Context, target TargetNode, act *playbook.StepTemplate) (playbook.StepStatus, execution.ExecutionOutcome, string) {
	rawTmpl, ok := rc.sources[sourceCacheKey(act.Source(), act.SymlinkPolicy())]
	if !ok {
		err := fmt.Errorf("%w: template 源快照缺失 %s", ErrInvalidRequest, act.Source())
		return playbook.StepStatusFailed, makeNotStartedOutcome(execution.StartPhaseValidate, "missing_template_source", err), err.Error()
	}
	rendered, err := renderPlaybookTemplate(string(rawTmpl), mergeStringMaps(rc.prep.vars, act.Vars()), rc.svc.maxTemplateBytes)
	if err != nil {
		return playbook.StepStatusFailed, makeNotStartedOutcome(execution.StartPhaseValidate, "template_render_failed", err), err.Error()
	}
	return rc.writeRemoteStepPayload(ctx, target, act.Dest(), act.Mode(), act.Overwrite(), act.Atomic(), rendered)
}

type limitedBufferWriter struct {
	buf   *bytes.Buffer
	limit int64
}

func (w *limitedBufferWriter) Write(p []byte) (int, error) {
	if int64(w.buf.Len())+int64(len(p)) > w.limit {
		return 0, fmt.Errorf("%w: 渲染输出超过字节上限 %d", ports.ErrLimitExceeded, w.limit)
	}
	return w.buf.Write(p)
}

func renderPlaybookTemplate(tmplText string, vars map[string]string, maxBytes int64) ([]byte, error) {
	t, err := template.New("playbook").Option("missingkey=error").Parse(tmplText)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTemplateRender, err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&limitedBufferWriter{buf: &buf, limit: maxBytes}, vars); err != nil {
		if errors.Is(err, ports.ErrLimitExceeded) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %w", ErrTemplateRender, err)
	}
	return buf.Bytes(), nil
}

func (rc *playbookRunContext) writeRemoteStepPayload(ctx context.Context, target TargetNode, dest pathalg.RemotePath, modeOpt algebraic.Option[playbook.FileMode], overwrite, atomicWrite bool, payload []byte) (playbook.StepStatus, execution.ExecutionOutcome, string) {
	perm, err := resolveStepFilePerm(modeOpt)
	if err != nil {
		return playbook.StepStatusFailed, makeNotStartedOutcome(execution.StartPhaseValidate, "invalid_file_mode", err), err.Error()
	}
	writeSpec, err := ports.NewRemoteWriteSpec(ports.RemoteWriteSpecInput{Perm: perm, NoClobber: !overwrite, AtomicRename: atomicWrite})
	if err != nil {
		return playbook.StepStatusFailed, makeNotStartedOutcome(execution.StartPhaseValidate, "invalid_write_spec", err), err.Error()
	}
	outcome, writeErr := rc.execRemoteWriteWithLease(ctx, target.plan, dest, writeSpec, payload)
	return mapOutcomeToStepStatus(outcome, writeErr, playbook.StepStatusChanged)
}

func resolveStepFilePerm(modeOpt algebraic.Option[playbook.FileMode]) (fs.FileMode, error) {
	m, ok := modeOpt.Get()
	if !ok {
		return defaultRemoteFilePerm, nil
	}
	if !m.IsValid() {
		return 0, fmt.Errorf("%w: 无效文件权限位", ErrInvalidRequest)
	}
	p := fs.FileMode(m.Bits())
	if p == 0 || p != p.Perm() {
		return 0, fmt.Errorf("%w: 远端文件权限位 %#o 必须落在 0001..0777", ErrInvalidRequest, m.Bits())
	}
	return p, nil
}

// execRemoteWriteWithLease 在 pool.WithLease 作用域内校验远端目标未漂移出授权范围后写入远端文件，
// 精确区分写前失败（OutcomeNotStarted）与写期中断/半提交（OutcomeUnknown / Applied&&!Durable，绝不重试）。
func (rc *playbookRunContext) execRemoteWriteWithLease(ctx context.Context, connPlan plan.SealedConnectionPlan, dest pathalg.RemotePath, writeSpec ports.RemoteWriteSpec, payload []byte) (execution.ExecutionOutcome, error) {
	var outcome execution.ExecutionOutcome
	var enteredLease, writeInvoked bool
	leaseErr := rc.svc.pool.WithLease(ctx, connPlan, func(leaseCtx context.Context, lease *pool.Lease) error {
		enteredLease = true
		rfs, err := lease.OpenRemoteFS(leaseCtx)
		if err != nil {
			outcome = makeNotStartedOutcome(execution.StartPhaseSessionOpen, "open_remotefs_failed", err)
			return err
		}
		defer func() { _ = rfs.Close() }()
		if err := verifyRemotePathAuthorized(leaseCtx, rc.svc.enforceStrictPaths(), rfs, rc.authBinding, dest); err != nil {
			outcome = makeNotStartedOutcome(execution.StartPhaseAuthorize, "scope_escalated", err)
			return err
		}
		if err := checkRemoteNoClobber(leaseCtx, rfs, dest, writeSpec); err != nil {
			outcome = makeNotStartedOutcome(execution.StartPhaseRequestRejected, "no_clobber_rejected", err)
			return err
		}
		writeInvoked = true
		if _, wErr := rfs.WriteFileAtomic(leaseCtx, dest, writeSpec, bytes.NewReader(payload)); wErr != nil {
			outcome = classifyRemoteWriteError(leaseCtx, wErr)
			return wErr
		}
		out, _ := execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
		outcome = out
		return nil
	})
	if !enteredLease {
		return makeNotStartedOutcome(execution.StartPhaseDial, "lease_failed", leaseErr), leaseErr
	}
	if writeInvoked && (outcome == nil || !outcome.IsValid()) {
		return classifyRemoteWriteError(ctx, leaseErr), leaseErr
	}
	return outcome, leaseErr
}

func checkRemoteNoClobber(ctx context.Context, rfs ports.RemoteFSPort, dest pathalg.RemotePath, spec ports.RemoteWriteSpec) error {
	if !spec.NoClobber() {
		return nil
	}
	_, err := rfs.Lstat(ctx, dest)
	if err == nil {
		return fmt.Errorf("%w: 远端目标 %s 已存在（overwrite=false）", ports.ErrAlreadyExists, dest)
	}
	if errors.Is(err, ports.ErrNotFound) {
		return nil
	}
	return err
}

func classifyRemoteWriteError(ctx context.Context, err error) execution.ExecutionOutcome {
	// 写前拒绝（已存在/不存在/权限/目录/软链/非常规文件/锚点冲突/无效参数）确认未修改目标 -> OutcomeNotStarted；
	// Applied&&!Durable 或写期网络/上下文中断 -> OutcomeUnknown（严禁重试）。
	for _, preErr := range [...]error{
		ports.ErrAlreadyExists, ports.ErrNotFound, ports.ErrRemoteIsDir, ports.ErrRemoteAnchorMismatch,
		ports.ErrSymlinkRejected, ports.ErrNotRegularFile, ports.ErrPermissionDenied, ports.ErrInvalidArgument, gate.ErrScopeEscalated,
	} {
		if errors.Is(err, preErr) {
			return makeNotStartedOutcome(execution.StartPhaseRequestRejected, "remote_write_rejected", err)
		}
	}
	if errors.Is(err, ErrUncertainDurability) {
		out, _ := execution.NewOutcomeUnknown(execution.ExecPhaseRunning, "applied_not_durable", err.Error())
		return out
	}
	return classifyPostStartOutcome(ctx, nil, err)
}
