package automation_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/playbook"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/usecase/automation"
	"github.com/wentf9/xops-cli/core/ports"
)

func mustPlaybookFromSteps(t *testing.T, id string, onErr playbook.OnErrorPolicy, vars map[string]string, steps ...playbook.Step) playbook.Playbook {
	t.Helper()
	pbID, err := playbook.ParsePlaybookID(id)
	mustOK(t, err, "ParsePlaybookID")
	sel, err := playbook.NewTargetSelector(playbook.TargetSelectorSpec{All: true})
	mustOK(t, err, "NewTargetSelector")
	stList := algebraic.NewNonEmpty(steps[0], steps[1:]...)
	pb, err := playbook.NewPlaybook(playbook.PlaybookSpec{
		Version: playbook.VersionV2, ID: pbID, Name: "Playbook " + id, Target: sel, OnError: onErr, Vars: vars, Steps: stList,
	})
	mustOK(t, err, "NewPlaybook")
	return pb
}

func mustStep(t *testing.T, id string, act playbook.StepAction, whenTags ...string) playbook.Step {
	t.Helper()
	sid, err := playbook.ParseStepID(id)
	mustOK(t, err, "ParseStepID")
	tags := make([]inventory.Tag, 0, len(whenTags))
	for _, raw := range whenTags {
		tg, tErr := inventory.ParseTag(raw)
		mustOK(t, tErr, "ParseTag")
		tags = append(tags, tg)
	}
	st, err := playbook.NewStep(playbook.StepSpec{ID: sid, Name: id, Action: act, WhenTags: tags})
	mustOK(t, err, "NewStep")
	return st
}

func TestPlaybookAllVariantsTagsAndFolding(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newAutoRig(t, autoRigOpts{})
	defer rig.close()

	scriptSrc, _ := pathalg.ParseLocalSourcePath("/ops/init.sh")
	copySrc, _ := pathalg.ParseLocalSourcePath("/ops/app.bin")
	tmplSrc, _ := pathalg.ParseLocalSourcePath("/ops/app.conf.tmpl")
	mustOK(t, rig.opReadFS.PutFile(scriptSrc, []byte("#!/bin/sh\necho script-ok\n")), "PutFile script")
	mustOK(t, rig.opReadFS.PutFile(copySrc, []byte("binary-data")), "PutFile copy")
	mustOK(t, rig.opReadFS.PutFile(tmplSrc, []byte("env={{.env}} host={{.role}}")), "PutFile tmpl")

	copyDest, _ := pathalg.ParseRemotePath("/srv/app.bin")
	tmplDest, _ := pathalg.ParseRemotePath("/srv/app.conf")
	srvDir, _ := pathalg.ParseRemotePath("/srv")
	mustOK(t, rig.dialer.rfsFor("web-1", rig.clock).MkdirAll(context.Background(), srvDir, 0o755), "MkdirAll web-1")
	mustOK(t, rig.dialer.rfsFor("worker-1", rig.clock).MkdirAll(context.Background(), srvDir, 0o755), "MkdirAll worker-1")

	var checkDone atomic.Bool
	rig.dialer.onCmd = func(_ context.Context, _ string, cmd execution.CommandPlan, _ []byte, stdout, _ io.Writer) (execution.ExecutionOutcome, error) {
		switch {
		case cmd.Kind() == execution.PlanKindScript:
			_, _ = io.WriteString(stdout, "ran-script")
			return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
		case cmd.Command() == "test -f /srv/ready":
			if checkDone.Load() {
				return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
			}
			return execution.NewOutcomeCompleted(execution.NewExitCode(1), false)
		case cmd.Command() == "touch /srv/ready":
			checkDone.Store(true)
			return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
		default:
			return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
		}
	}

	shAct, err := playbook.NewStepShell(playbook.StepShellSpec{Command: "echo hi"})
	mustOK(t, err, "NewStepShell")
	scAct, err := playbook.NewStepScript(playbook.StepScriptSpec{Source: scriptSrc, Args: []string{"--fast"}})
	mustOK(t, err, "NewStepScript")
	cpAct, err := playbook.NewStepCopy(playbook.StepCopySpec{Source: copySrc, Dest: copyDest, Overwrite: true, Atomic: true})
	mustOK(t, err, "NewStepCopy")
	tmAct, err := playbook.NewStepTemplate(playbook.StepTemplateSpec{
		Source: tmplSrc, Dest: tmplDest, Overwrite: true, Atomic: true, Vars: map[string]string{"role": "api"},
	})
	mustOK(t, err, "NewStepTemplate")
	chkAct, _ := playbook.NewStepShell(playbook.StepShellSpec{Command: "test -f /srv/ready"})
	appAct, _ := playbook.NewStepShell(playbook.StepShellSpec{Command: "touch /srv/ready"})
	enAct, err := playbook.NewStepEnsure(playbook.StepEnsureSpec{Check: chkAct, Action: appAct, MaxRetries: 1})
	mustOK(t, err, "NewStepEnsure")

	pb := mustPlaybookFromSteps(t, "deploy-v2", playbook.OnErrorFailFast, map[string]string{"env": "prod"},
		mustStep(t, "s-shell", shAct),
		mustStep(t, "s-script", scAct, "web"),
		mustStep(t, "s-copy", cpAct),
		mustStep(t, "s-tmpl", tmAct),
		mustStep(t, "s-ensure", enAct),
	)

	webNode := makeTargetNode(t, "web-1", "10.1.0.1:22", "web")
	workerNode := makeTargetNode(t, "worker-1", "10.1.0.2:22", "worker")
	mainSt := makeOpStream(t, "pb-main")

	var evs []events.Event
	var res automation.PlaybookRunResult
	var runErr error
	mustOK(t, conc.RunWait(context.Background(), func(wCtx context.Context, n *conc.Nursery) error {
		_ = n.Go(func(c context.Context) error { evs = drainStream(c, mainSt); return nil })
		return n.Go(func(c context.Context) error {
			res, runErr = rig.svc.RunPlaybook(c, automation.PlaybookRequest{
				Playbook: pb, Targets: []automation.TargetNode{workerNode, webNode}, OperationStream: mainSt,
			})
			return nil
		})
	}), "RunWait")
	mustOK(t, runErr, "RunPlaybook")
	if !res.IsValid() || res.Report().Status() != playbook.NodeStatusChanged {
		t.Fatalf("unexpected playbook status: %v", res.Report().Status())
	}
	assertStreamHasTerminal(t, "pb-main", evs, true)

	// 验证 worker-1 跳过了仅限 tag:web 的 script 步骤，且 web-1 模板渲染准确写入远端。
	webRFS := rig.dialer.rfsFor("web-1", rig.clock)
	limits, _ := ports.NewReadLimits(4096)
	var rendered []byte
	mustOK(t, webRFS.WithReadFile(context.Background(), tmplDest, limits, func(r io.Reader, _ int64) error {
		var rErr error
		rendered, rErr = io.ReadAll(r)
		return rErr
	}), "WithReadFile rendered")
	if string(rendered) != "env=prod host=api" {
		t.Fatalf("unexpected rendered template %q", rendered)
	}
	workerRep := res.Report().Nodes()[1]
	if workerRep.NodeID().String() != "worker-1" || workerRep.Steps()[1].Status() != playbook.StepStatusSkipped {
		t.Fatalf("expected worker-1 s-script skipped, got %+v", workerRep.Steps()[1])
	}
}

func TestPlaybookEnsureFSMRetryUnknownAndAppliedNotDurable(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newAutoRig(t, autoRigOpts{})
	defer rig.close()
	node := makeTargetNode(t, "ens-1", "10.1.1.1:22")

	// 场景 1：Check 首次 NotStarted（可重试），第 2 次退出 0 -> ConvergedUnchanged（Action 0 次调用）。
	var checkCalls, applyCalls atomic.Int32
	rig.dialer.onCmd = func(_ context.Context, _ string, cmd execution.CommandPlan, _ []byte, _, _ io.Writer) (execution.ExecutionOutcome, error) {
		if cmd.Command() == "chk" {
			if checkCalls.Add(1) == 1 {
				out, _ := execution.NewOutcomeNotStarted(execution.StartPhaseDial, "dial_tmp", "transient")
				return out, errors.New("transient")
			}
			return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
		}
		applyCalls.Add(1)
		return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	}
	chk, _ := playbook.NewStepShell(playbook.StepShellSpec{Command: "chk"})
	app, _ := playbook.NewStepShell(playbook.StepShellSpec{Command: "app"})
	ens, _ := playbook.NewStepEnsure(playbook.StepEnsureSpec{Check: chk, Action: app, MaxRetries: 2})
	pb := mustPlaybookFromSteps(t, "ens-retry", playbook.OnErrorFailFast, nil, mustStep(t, "s1", ens))

	res, err := rig.svc.RunPlaybook(context.Background(), automation.PlaybookRequest{Playbook: pb, Targets: []automation.TargetNode{node}})
	mustOK(t, err, "RunPlaybook retry unchanged")
	if checkCalls.Load() != 2 || applyCalls.Load() != 0 || res.Report().Status() != playbook.NodeStatusSucceeded {
		t.Fatalf("unexpected ensure retry unchanged: check=%d apply=%d status=%v", checkCalls.Load(), applyCalls.Load(), res.Report().Status())
	}

	// 场景 2：Apply 返回 OutcomeUnknown -> 绝不重试（applyCalls==1），上报 AuditOutcomeUnknown。
	applyCalls.Store(0)
	rig.dialer.onCmd = func(_ context.Context, _ string, cmd execution.CommandPlan, _ []byte, _, _ io.Writer) (execution.ExecutionOutcome, error) {
		if cmd.Command() == "chk" {
			return execution.NewOutcomeCompleted(execution.NewExitCode(1), false)
		}
		applyCalls.Add(1)
		return nil, errors.New("connection lost during apply")
	}
	res, err = rig.svc.RunPlaybook(context.Background(), automation.PlaybookRequest{Playbook: pb, Targets: []automation.TargetNode{node}})
	if !errors.Is(err, automation.ErrUncertainOutcome) || applyCalls.Load() != 1 || !res.HasUnknownOutcome() {
		t.Fatalf("expected 0-retry OutcomeUnknown, err=%v apply=%d unk=%v", err, applyCalls.Load(), res.HasUnknownOutcome())
	}
	if !hasAuditOutcome(rig.auditClust.Entries(), ports.AuditOutcomeUnknown) {
		t.Fatalf("expected AuditOutcomeUnknown in audit ledger")
	}

	// 场景 3：Ensure 内嵌 Copy 遇到 Applied && !Durable（ErrUncertainDurability）-> 0 重试且转 OutcomeUnknown。
	srcP, _ := pathalg.ParseLocalSourcePath("/ops/cfg.yaml")
	dstP, _ := pathalg.ParseRemotePath("/srv/cfg.yaml")
	mustOK(t, rig.opReadFS.PutFile(srcP, []byte("k: v\n")), "PutFile cfg")
	var writeCalls atomic.Int32
	rig.dialer.onWrite = func(context.Context, string, pathalg.RemotePath) error {
		writeCalls.Add(1)
		return automation.ErrUncertainDurability
	}
	cpAct, _ := playbook.NewStepCopy(playbook.StepCopySpec{Source: srcP, Dest: dstP, Overwrite: true, Atomic: true})
	ensCopy, _ := playbook.NewStepEnsure(playbook.StepEnsureSpec{Check: chk, Action: cpAct, MaxRetries: 3})
	pbCopy := mustPlaybookFromSteps(t, "ens-durability", playbook.OnErrorFailFast, nil, mustStep(t, "s1", ensCopy))

	res, err = rig.svc.RunPlaybook(context.Background(), automation.PlaybookRequest{Playbook: pbCopy, Targets: []automation.TargetNode{node}})
	if !errors.Is(err, automation.ErrUncertainOutcome) || writeCalls.Load() != 1 || !res.HasUnknownOutcome() {
		t.Fatalf("Applied&&!Durable must never retry, err=%v writes=%d unk=%v", err, writeCalls.Load(), res.HasUnknownOutcome())
	}
}

func TestPlaybookOnErrorPolicies(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newAutoRig(t, autoRigOpts{})
	defer rig.close()
	s1, _ := playbook.NewStepShell(playbook.StepShellSpec{Command: "step1"})
	s2, _ := playbook.NewStepShell(playbook.StepShellSpec{Command: "step2"})

	rig.dialer.onCmd = func(_ context.Context, nodeID string, cmd execution.CommandPlan, _ []byte, _, _ io.Writer) (execution.ExecutionOutcome, error) {
		if nodeID == "n1" && cmd.Command() == "step1" {
			return execution.NewOutcomeCompleted(execution.NewExitCode(1), false)
		}
		return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	}
	n1 := makeTargetNode(t, "n1", "10.1.2.1:22")
	n2 := makeTargetNode(t, "n2", "10.1.2.2:22")

	// OnErrorFailFast：n1 中止后续 step2，但 n2 正常执行完毕。
	pbFF := mustPlaybookFromSteps(t, "pb-ff", playbook.OnErrorFailFast, nil, mustStep(t, "s1", s1), mustStep(t, "s2", s2))
	resFF, err := rig.svc.RunPlaybook(context.Background(), automation.PlaybookRequest{Playbook: pbFF, Targets: []automation.TargetNode{n1, n2}})
	if !errors.Is(err, automation.ErrPlaybookFailed) {
		t.Fatalf("expected ErrPlaybookFailed, got %v", err)
	}
	if resFF.Report().Nodes()[0].Steps()[1].Status() != playbook.StepStatusAborted || resFF.Report().Nodes()[1].Status() != playbook.NodeStatusChanged {
		t.Fatalf("unexpected FailFast node states: n1=%+v n2=%+v", resFF.Report().Nodes()[0].Steps(), resFF.Report().Nodes()[1].Status())
	}

	// OnErrorAbort：n1 失败后触发全盘中止，Concurrency=1 确保 n2 全部步骤为 Aborted。
	pbAb := mustPlaybookFromSteps(t, "pb-ab", playbook.OnErrorAbort, nil, mustStep(t, "s1", s1), mustStep(t, "s2", s2))
	resAb, err := rig.svc.RunPlaybook(context.Background(), automation.PlaybookRequest{
		Playbook: pbAb, Targets: []automation.TargetNode{n1, n2}, Concurrency: 1,
	})
	if !errors.Is(err, automation.ErrPlaybookAborted) || !resAb.Aborted() {
		t.Fatalf("expected ErrPlaybookAborted, err=%v aborted=%v", err, resAb.Aborted())
	}
	if resAb.Report().Nodes()[1].Steps()[0].Status() != playbook.StepStatusAborted {
		t.Fatalf("expected n2 s1 aborted under OnErrorAbort, got %v", resAb.Report().Nodes()[1].Steps()[0].Status())
	}
}

func TestPlaybookDualModalLocalFSAndHaltedZeroTouch(t *testing.T) {
	defer goleak.VerifyNone(t)
	relSrc, _ := pathalg.ParseLocalSourcePath("app.conf")
	absSrc, _ := pathalg.ParseLocalSourcePath("/etc/app.conf")
	dst, _ := pathalg.ParseRemotePath("/srv/app.conf")
	node := makeTargetNode(t, "fs-1", "10.1.3.1:22")

	// MCP 路径（无 OperatorReadFS 且未传 ScopedSourceRoot）必须 Fail-Closed。
	mcpRig := newAutoRig(t, autoRigOpts{omitOperatorRead: true})
	defer mcpRig.close()
	srvDir, _ := pathalg.ParseRemotePath("/srv")
	mustOK(t, mcpRig.dialer.rfsFor("fs-1", mcpRig.clock).MkdirAll(context.Background(), srvDir, 0o755), "MkdirAll fs-1")
	cpRel, _ := playbook.NewStepCopy(playbook.StepCopySpec{Source: relSrc, Dest: dst, Overwrite: true, Atomic: true})
	pbRel := mustPlaybookFromSteps(t, "pb-mcp", playbook.OnErrorFailFast, nil, mustStep(t, "c1", cpRel))
	if _, err := mcpRig.svc.RunPlaybook(context.Background(), automation.PlaybookRequest{
		Playbook: pbRel, Targets: []automation.TargetNode{node},
	}); !errors.Is(err, automation.ErrOperatorReadUnavailable) {
		t.Fatalf("expected ErrOperatorReadUnavailable, got %v", err)
	}

	// 沙箱模式经 ScopedSourceRoot 允许相对路径读取，禁止绝对路径与 follow_operator_source。
	rootDir, _ := pathalg.ParseLocalDir("/sandbox")
	mustOK(t, mcpRig.scopedFS.EnsureRoot(rootDir, 0o700), "EnsureRoot")
	rootedFile, _ := pathalg.ParseLocalRootedDest("app.conf")
	mustOK(t, mcpRig.scopedFS.WithRoot(rootDir, func(root ports.RootHandle) error {
		return root.AtomicReplace(rootedFile, 0o600, func(w io.Writer) error {
			_, wErr := w.Write([]byte("sandbox-body"))
			return wErr
		})
	}), "seed sandbox file")

	res, err := mcpRig.svc.RunPlaybook(context.Background(), automation.PlaybookRequest{
		Playbook: pbRel, Targets: []automation.TargetNode{node}, ScopedSourceRoot: algebraic.Some(rootDir),
	})
	mustOK(t, err, "RunPlaybook sandboxed")
	if res.Report().Status() != playbook.NodeStatusChanged {
		t.Fatalf("expected Changed, got %v", res.Report().Status())
	}

	cpAbs, _ := playbook.NewStepCopy(playbook.StepCopySpec{Source: absSrc, Dest: dst, Overwrite: true, Atomic: true})
	pbAbs := mustPlaybookFromSteps(t, "pb-abs", playbook.OnErrorFailFast, nil, mustStep(t, "c1", cpAbs))
	if _, err := mcpRig.svc.RunPlaybook(context.Background(), automation.PlaybookRequest{
		Playbook: pbAbs, Targets: []automation.TargetNode{node}, ScopedSourceRoot: algebraic.Some(rootDir),
	}); !errors.Is(err, automation.ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest for abs path in sandbox, got %v", err)
	}

	cpFollow, _ := playbook.NewStepCopy(playbook.StepCopySpec{
		Source: relSrc, Dest: dst, Overwrite: true, Atomic: true,
		SymlinkPolicy: pathalg.SymlinkFollowOperatorSource,
	})
	pbFollow := mustPlaybookFromSteps(t, "pb-follow", playbook.OnErrorFailFast, nil, mustStep(t, "c1", cpFollow))
	if _, err := mcpRig.svc.RunPlaybook(context.Background(), automation.PlaybookRequest{
		Playbook: pbFollow, Targets: []automation.TargetNode{node}, ScopedSourceRoot: algebraic.Some(rootDir),
	}); !errors.Is(err, automation.ErrSymlinkPolicyDenied) {
		t.Fatalf("expected ErrSymlinkPolicyDenied in sandbox, got %v", err)
	}
}

func TestPlaybookRound2ProtectedPathTOCTOUAndApprovalDeterminism(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newAutoRig(t, autoRigOpts{
		profile:        gate.PolicyProfileStrictAgent,
		approvalThresh: security.RiskDangerous,
		fallback:       gate.NoElicitFallbackChallenge,
	})
	defer rig.close()
	srcP, _ := pathalg.ParseLocalSourcePath("/ops/cron.conf")
	mustOK(t, rig.opReadFS.PutFile(srcP, []byte("* * * * * root true\n")), "PutFile cron")
	linkDest, _ := pathalg.ParseRemotePath("/tmp/drop/job")
	evilTarget, _ := pathalg.ParseRemotePath("/etc/cron.d/evil")

	node := makeTargetNode(t, "strict-1", "10.1.4.1:22")
	rfs := rig.dialer.rfsFor("strict-1", rig.clock)
	mustOK(t, rfs.PutSymlink(linkDest, evilTarget.String()), "PutSymlink")

	cpAct, _ := playbook.NewStepCopy(playbook.StepCopySpec{Source: srcP, Dest: linkDest, Overwrite: true, Atomic: true})
	pb := mustPlaybookFromSteps(t, "pb-r2", playbook.OnErrorFailFast, nil, mustStep(t, "c1", cpAct))

	// Round-2 软链规范化将 /tmp/drop/job 展开至受保护路径 /etc/cron.d/evil -> 被策略门控拦截或升级审批（绝不直接放行）。
	_, err := rig.svc.RunPlaybook(context.Background(), automation.PlaybookRequest{
		Playbook: pb, Targets: []automation.TargetNode{node}, Risk: algebraic.Some(security.RiskSafe),
	})
	if err == nil {
		t.Fatalf("expected Round-2 protected path redirect to be blocked or challenged")
	}

	// 改写至安全路径 /tmp/safe/out，验证两步审批确定性（改变 ExtraVars 须拒绝；新一轮原参数 Round 2 通过）。
	safeDir, _ := pathalg.ParseRemotePath("/tmp/safe")
	mustOK(t, rfs.MkdirAll(context.Background(), safeDir, 0o755), "MkdirAll /tmp/safe")
	safeDest, _ := pathalg.ParseRemotePath("/tmp/safe/out")
	cpSafe, _ := playbook.NewStepCopy(playbook.StepCopySpec{Source: srcP, Dest: safeDest, Overwrite: true, Atomic: true})
	pbSafe := mustPlaybookFromSteps(t, "pb-safe", playbook.OnErrorFailFast, nil, mustStep(t, "c1", cpSafe))

	_, err = rig.svc.RunPlaybook(context.Background(), automation.PlaybookRequest{
		Playbook: pbSafe, Targets: []automation.TargetNode{node},
		ExtraVars: map[string]string{"ver": "1"}, Risk: algebraic.Some(security.RiskDangerous),
	})
	var chalErr *gate.ApprovalChallengeError
	if !errors.Is(err, gate.ErrApprovalRequired) || !errors.As(err, &chalErr) {
		t.Fatalf("expected ApprovalChallengeError, got %v", err)
	}
	sub := makeApprovalSub(t, chalErr)

	if _, err := rig.svc.RunPlaybook(context.Background(), automation.PlaybookRequest{
		Playbook: pbSafe, Targets: []automation.TargetNode{node},
		ExtraVars: map[string]string{"ver": "2"}, Risk: algebraic.Some(security.RiskDangerous),
		Approval: algebraic.Some(sub),
	}); err == nil {
		t.Fatalf("expected ExtraVars drift to fail approval verification")
	}

	_, err = rig.svc.RunPlaybook(context.Background(), automation.PlaybookRequest{
		Playbook: pbSafe, Targets: []automation.TargetNode{node},
		ExtraVars: map[string]string{"ver": "1"}, Risk: algebraic.Some(security.RiskDangerous),
	})
	var chalErr2 *gate.ApprovalChallengeError
	if !errors.Is(err, gate.ErrApprovalRequired) || !errors.As(err, &chalErr2) {
		t.Fatalf("expected second ApprovalChallengeError, got %v", err)
	}
	sub2 := makeApprovalSub(t, chalErr2)
	res, err := rig.svc.RunPlaybook(context.Background(), automation.PlaybookRequest{
		Playbook: pbSafe, Targets: []automation.TargetNode{node},
		ExtraVars: map[string]string{"ver": "1"}, Risk: algebraic.Some(security.RiskDangerous),
		Approval: algebraic.Some(sub2),
	})
	mustOK(t, err, "RunPlaybook Round 2 exact vars")
	if res.Report().Status() != playbook.NodeStatusChanged {
		t.Fatalf("expected Changed, got %v", res.Report().Status())
	}

	// 验证写前 TOCTOU 漂移校验：授权时 toctou 指向安全位置，执行中先被翻转为 /etc/shadow -> 拒绝写入并报作用域漂移。
	toctouDest, _ := pathalg.ParseRemotePath("/tmp/safe/toctou")
	shadowTarget, _ := pathalg.ParseRemotePath("/etc/shadow")
	cpTOCTOU, _ := playbook.NewStepCopy(playbook.StepCopySpec{Source: srcP, Dest: toctouDest, Overwrite: true, Atomic: true})
	flipAct, _ := playbook.NewStepShell(playbook.StepShellSpec{Command: "flip-symlink"})
	rig.dialer.onCmd = func(context.Context, string, execution.CommandPlan, []byte, io.Writer, io.Writer) (execution.ExecutionOutcome, error) {
		_ = rfs.PutSymlink(toctouDest, shadowTarget.String())
		return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	}
	pbFlip := mustPlaybookFromSteps(t, "pb-flip", playbook.OnErrorFailFast, nil, mustStep(t, "s0", flipAct), mustStep(t, "s1", cpTOCTOU))
	resFlip, err := rig.svc.RunPlaybook(context.Background(), automation.PlaybookRequest{
		Playbook: pbFlip, Targets: []automation.TargetNode{node}, Risk: algebraic.Some(security.RiskSafe),
	})
	if !errors.Is(err, automation.ErrPlaybookFailed) {
		t.Fatalf("expected TOCTOU write failure, got err=%v", err)
	}
	if !strings.Contains(resFlip.Report().Nodes()[0].Steps()[1].Message(), "漂移") {
		t.Fatalf("expected scope drift message, got %q", resFlip.Report().Nodes()[0].Steps()[1].Message())
	}
}
