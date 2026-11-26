package engine_test

import (
	"bytes"
	"context"
	"encoding"
	"errors"
	"maps"
	"sync/atomic"
	"testing"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
)

// 编译期契约断言：确保 Engine 公开不透明枚举与测试桩均满足对应标准库及端口接口。
var (
	_ encoding.TextAppender     = engine.PolicyProfileInvalid
	_ encoding.TextMarshaler    = engine.PolicyProfileInvalid
	_ encoding.TextUnmarshaler  = (*engine.PolicyProfile)(nil)
	_ encoding.TextAppender     = engine.NoElicitFallbackDeny
	_ encoding.TextMarshaler    = engine.NoElicitFallbackDeny
	_ encoding.TextUnmarshaler  = (*engine.NoElicitFallback)(nil)
	_ encoding.TextAppender     = engine.RequestTTYUnset
	_ encoding.TextMarshaler    = engine.RequestTTYUnset
	_ encoding.TextUnmarshaler  = (*engine.RequestTTYMode)(nil)
	_ ports.OpenSSHConfigSource = (*mapOpenSSHSource)(nil)
	_ ports.AuditSink           = (*faultInjectAuditSink)(nil)
)

type loopbackEngineRig struct {
	homeDir   pathalg.LocalDir
	sshDir    pathalg.LocalDir
	rootFS    ports.ScopedRootFS
	readFS    ports.OperatorReadFS
	clk       *sim.SimClock
	rng       *sim.SeededRand
	cluster   *sim.SimAuditCluster
	auditSink *faultInjectAuditSink
	env       *sim.SimEnvPort
	term      *sim.SimTerminalPort
}

func newLoopbackRigBase(t *testing.T, interactive bool) *loopbackEngineRig {
	t.Helper()
	homeDir, err := pathalg.ParseLocalDir(t.TempDir())
	if err != nil {
		t.Fatalf("ParseLocalDir(TempDir): %v", err)
	}
	sshDir, err := homeDir.JoinComponent(".ssh")
	if err != nil {
		t.Fatalf("JoinComponent(.ssh): %v", err)
	}
	rootFS := osfs.NewScopedRootFS()
	readFS := osfs.NewOperatorReadFS()
	clk := sim.NewSimClock(sim.DefaultBaseTime())
	rng := sim.NewSeededRand(20261126)
	cluster := sim.NewSimAuditCluster()
	rawSink, err := cluster.NewSinkFromEntropy(rng)
	if err != nil {
		t.Fatalf("NewSinkFromEntropy: %v", err)
	}
	id, err := ports.NewLocalIdentityInfo(ports.LocalIdentityInfoSpec{
		LocalHost: "ws-host",
		LocalUser: "operator",
		LocalUID:  "1000",
		HomeDir:   homeDir.String(),
	})
	if err != nil {
		t.Fatalf("NewLocalIdentityInfo: %v", err)
	}
	env := sim.NewSimEnvPort(map[string]string{
		"LANG":         "en_US.UTF-8",
		"LC_ALL":       "C.UTF-8",
		"APP_STAGE":    "canary",
		"SECRET_TOKEN": "never-leak-me",
		"TERM":         "xterm-256color",
	}, id)
	term := sim.NewSimTerminalPort(interactive, 100, 32)
	return &loopbackEngineRig{
		homeDir:   homeDir,
		sshDir:    sshDir,
		rootFS:    rootFS,
		readFS:    readFS,
		clk:       clk,
		rng:       rng,
		cluster:   cluster,
		auditSink: &faultInjectAuditSink{inner: rawSink},
		env:       env,
		term:      term,
	}
}

func mustIdentityPathList(t *testing.T, paths ...string) option.PathList {
	t.Helper()
	pl, err := option.ParsePathListEntries(paths)
	if err != nil {
		t.Fatalf("ParsePathListEntries(%v): %v", paths, err)
	}
	return pl
}

func TestEngine_LoopbackExecSendEnvAuditAndOperationStream(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newLoopbackRigBase(t, false)
	clientPub, keyPath := writeTestKeyInRoot(t, rig.rootFS, rig.sshDir, "id_ed25519")
	srv := newLoopbackSSHServer(t, clientPub)
	eng := mustNewDirectLoopbackEngine(t, rig, srv, nil)
	defer closeEngineChecked(t, eng)

	assertLoopbackFirstExecWithSendEnv(t, eng, srv, keyPath)
	assertLoopbackStrictNonZeroExec(t, eng, keyPath)
	assertFourEntryAuditSequence(t, rig.cluster.Entries())
}

func mustNewDirectLoopbackEngine(t *testing.T, rig *loopbackEngineRig, srv *loopbackSSHServer, openSSH ports.OpenSSHConfigSource) *engine.Engine {
	t.Helper()
	eng, err := engine.New(engine.Config{
		Profile:        engine.PolicyProfileDirectOperator,
		Guardrail:      engine.DefaultGuardrailConfig(),
		Clock:          rig.clk,
		Entropy:        rig.rng.Fork(),
		AuditSink:      rig.auditSink,
		Reconciler:     rig.cluster,
		ScopedFS:       rig.rootFS,
		OperatorReadFS: rig.readFS,
		Env:            rig.env,
		Terminal:       rig.term,
		OpenSSH:        openSSH,
		DialContext:    srv.dialFunc(),
	})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	return eng
}

func closeEngineChecked(t *testing.T, eng *engine.Engine) {
	t.Helper()
	if err := eng.Close(context.Background()); err != nil {
		t.Errorf("Engine.Close: %v", err)
	}
}

func assertLoopbackFirstExecWithSendEnv(t *testing.T, eng *engine.Engine, srv *loopbackSSHServer, keyPath string) {
	t.Helper()
	envFilter, err := option.ParseEnvFilter("LANG LC_* APP_*")
	if err != nil {
		t.Fatalf("ParseEnvFilter: %v", err)
	}
	t1First := option.UnsetOptionLayer().
		WithIdentityFiles(mustIdentityPathList(t, keyPath)).
		WithIdentitiesOnly(true).
		WithStrictHostKeyChecking(option.StrictHostKeyCheckingAcceptNew).
		WithSendEnv(envFilter)

	stream, err := eng.NewOperationStream(context.Background(), 32)
	if err != nil {
		t.Fatalf("NewOperationStream: %v", err)
	}
	var stdout, stderr bytes.Buffer
	out, err := eng.Exec(context.Background(), engine.ExecRequest{
		TargetSpec:      "deploy@127.0.0.1:22022",
		CLIOptions:      t1First,
		Command:         "uname -sr",
		Stdout:          &stdout,
		Stderr:          &stderr,
		OperationStream: stream,
	})
	if err != nil {
		t.Fatalf("Engine.Exec: %v", err)
	}
	comp, ok := out.(*execution.OutcomeCompleted)
	if !ok || !comp.Succeeded() {
		t.Fatalf("期望成功 OutcomeCompleted，实际=%#v", out)
	}
	if stdout.String() != "ok:uname -sr\n" || stderr.Len() != 0 {
		t.Fatalf("命令输出失配: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	wantEnv := map[string]string{"LANG": "en_US.UTF-8", "LC_ALL": "C.UTF-8", "APP_STAGE": "canary"}
	if gotEnv := srv.envSnapshot(); !maps.Equal(gotEnv, wantEnv) {
		t.Fatalf("SendEnv 过滤失配: want=%v got=%v", wantEnv, gotEnv)
	}
	assertStreamCompletedEOF(t, stream)
}

func assertStreamCompletedEOF(t *testing.T, stream *events.OperationStream) {
	t.Helper()
	var kinds []events.EventKind
	for ev, iterErr := range stream.All(context.Background()) {
		if iterErr != nil {
			t.Fatalf("OperationStream.All: %v", iterErr)
		}
		kinds = append(kinds, ev.Kind())
	}
	if len(kinds) < 4 || kinds[len(kinds)-1] != events.EventKindOperationCompleted {
		t.Fatalf("OperationStream 事件序列异常: %v", kinds)
	}
}

func assertLoopbackStrictNonZeroExec(t *testing.T, eng *engine.Engine, keyPath string) {
	t.Helper()
	t1Strict := option.UnsetOptionLayer().
		WithIdentityFiles(mustIdentityPathList(t, keyPath)).
		WithIdentitiesOnly(true).
		WithStrictHostKeyChecking(option.StrictHostKeyCheckingYes)
	var stdout, stderr bytes.Buffer
	out2, err := eng.RunSSH(context.Background(), engine.RunSSHRequest{
		TargetSpec:  "deploy@127.0.0.1:22022",
		CLIOptions:  t1Strict,
		CommandArgs: []string{"run", "exit-42"},
		Stdout:      &stdout,
		Stderr:      &stderr,
	})
	if err != nil {
		t.Fatalf("Engine.RunSSH(exit-42) 不应返回传输错误，实际=%v", err)
	}
	comp2, ok := out2.(*execution.OutcomeCompleted)
	if !ok || comp2.Succeeded() {
		t.Fatalf("期望非零退出 OutcomeCompleted，实际=%#v", out2)
	}
	exitCode, okCode := comp2.Status().(*execution.ExitCode)
	if !okCode {
		t.Fatalf("期望 ExitCode，实际=%#v", comp2.Status())
	}
	if code, hasCode := exitCode.Code(); !hasCode || code != 42 {
		t.Fatalf("期望退出码 42，实际 has=%v code=%d", hasCode, code)
	}
	if stdout.String() != "cmd-out:run exit-42\n" || stderr.String() != "cmd-err:nonzero\n" {
		t.Fatalf("非零退出输出失配: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func assertFourEntryAuditSequence(t *testing.T, entries []ports.AuditEntry) {
	t.Helper()
	if len(entries) != 4 ||
		entries[0].Phase() != ports.AuditPhaseAuthorized ||
		entries[1].Phase() != ports.AuditPhaseFinalized || entries[1].Outcome() != ports.AuditOutcomeSucceeded ||
		entries[2].Phase() != ports.AuditPhaseAuthorized ||
		entries[3].Phase() != ports.AuditPhaseFinalized || entries[3].Outcome() != ports.AuditOutcomeFailed {
		t.Fatalf("审计闭环失配: %+v", entries)
	}
}

func TestEngine_LoopbackInteractivePTYRelayAndResize(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newLoopbackRigBase(t, true)
	clientPub, keyPath := writeTestKeyInRoot(t, rig.rootFS, rig.sshDir, "id_interactive")
	srv := newLoopbackSSHServer(t, clientPub)
	srv.expectResize()

	eng, err := engine.New(engine.Config{
		Profile:        engine.PolicyProfileDirectOperator,
		Guardrail:      engine.DefaultGuardrailConfig(),
		Clock:          rig.clk,
		Entropy:        rig.rng.Fork(),
		AuditSink:      rig.auditSink,
		ScopedFS:       rig.rootFS,
		OperatorReadFS: rig.readFS,
		Env:            rig.env,
		Terminal:       rig.term,
		DialContext:    srv.dialFunc(),
	})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	defer func() {
		if cErr := eng.Close(context.Background()); cErr != nil {
			t.Errorf("Engine.Close: %v", cErr)
		}
	}()

	rig.term.SetInput([]byte("hello from engine\n"))
	szResize, err := ports.NewTerminalSize(140, 48)
	if err != nil {
		t.Fatalf("NewTerminalSize: %v", err)
	}
	rig.term.QueueResize(szResize)

	cliOpts := option.UnsetOptionLayer().
		WithIdentityFiles(mustIdentityPathList(t, keyPath)).
		WithIdentitiesOnly(true).
		WithStrictHostKeyChecking(option.StrictHostKeyCheckingAcceptNew)

	out, err := eng.RunSSH(context.Background(), engine.RunSSHRequest{
		TargetSpec: "ops@127.0.0.1:22023",
		CLIOptions: cliOpts,
		RequestTTY: engine.RequestTTYAuto,
	})
	if err != nil {
		t.Fatalf("Engine.RunSSH(interactive): %v", err)
	}
	comp, ok := out.(*execution.OutcomeCompleted)
	if !ok || !comp.Succeeded() {
		t.Fatalf("期望交互会话成功退出，实际=%#v", out)
	}
	if got := string(rig.term.Output()); got != "loopback-shell> hello from engine\n" {
		t.Fatalf("交互式 Relay 回显失配: %q", got)
	}
	termName, cols, rows, rCols, rRows, resizes := srv.ptySnapshot()
	if termName != "xterm-256color" || cols != 100 || rows != 32 {
		t.Fatalf("PTY 请求失配: term=%q size=%dx%d", termName, cols, rows)
	}
	if resizes < 1 || rCols != 140 || rRows != 48 {
		t.Fatalf("窗口缩放事件未送达远端 SSH 服务端: count=%d size=%dx%d", resizes, rCols, rRows)
	}
}

func TestEngine_LoopbackProxyJumpTwoHop(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newLoopbackRigBase(t, false)
	bastionPub, bastionKey := writeTestKeyInRoot(t, rig.rootFS, rig.sshDir, "id_bastion")
	targetPub, targetKey := writeTestKeyInRoot(t, rig.rootFS, rig.sshDir, "id_target")

	targetSrv := newLoopbackSSHServer(t, targetPub)
	bastionSrv := newLoopbackSSHServer(t, bastionPub)
	bastionSrv.forwardTargets["10.99.0.20:2222"] = targetSrv

	openSSH := buildTwoHopOpenSSHSource(t, bastionKey, targetKey)
	eng, err := engine.New(engine.Config{
		Profile:        engine.PolicyProfileDirectOperator,
		Guardrail:      engine.DefaultGuardrailConfig(),
		Clock:          rig.clk,
		Entropy:        rig.rng.Fork(),
		AuditSink:      rig.auditSink,
		ScopedFS:       rig.rootFS,
		OperatorReadFS: rig.readFS,
		Env:            rig.env,
		OpenSSH:        openSSH,
		DialContext:    bastionSrv.dialFunc(),
	})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	defer func() {
		if cErr := eng.Close(context.Background()); cErr != nil {
			t.Errorf("Engine.Close: %v", cErr)
		}
	}()

	resolved, err := eng.ResolveTarget(context.Background(), engine.ResolveTargetRequest{
		Target: "app-prod",
	})
	if err != nil {
		t.Fatalf("ResolveTarget(app-prod): %v", err)
	}
	if !resolved.IsValid() || resolved.OriginKind() != option.OriginOpenSSHVirtual || resolved.Plan().Len() != 2 {
		t.Fatalf("两跳连接计划解析失配: valid=%v origin=%s hops=%d", resolved.IsValid(), resolved.OriginKind(), resolved.Plan().Len())
	}

	var stdout bytes.Buffer
	out, err := eng.Exec(context.Background(), engine.ExecRequest{
		Target:  resolved,
		Command: "hostname",
		Stdout:  &stdout,
	})
	if err != nil {
		t.Fatalf("Engine.Exec(ProxyJump): %v", err)
	}
	comp, ok := out.(*execution.OutcomeCompleted)
	if !ok || !comp.Succeeded() {
		t.Fatalf("期望 ProxyJump 命令成功退出，实际=%#v", out)
	}
	if stdout.String() != "ok:hostname\n" {
		t.Fatalf("ProxyJump 远端输出失配: %q", stdout.String())
	}
	if bastionSrv.dialCount.Load() != 1 || targetSrv.dialCount.Load() != 1 || targetSrv.execCount.Load() != 1 {
		t.Fatalf("两跳拨号/执行计数失配: bastionDials=%d targetDials=%d targetExecs=%d",
			bastionSrv.dialCount.Load(), targetSrv.dialCount.Load(), targetSrv.execCount.Load())
	}
}

func buildTwoHopOpenSSHSource(t *testing.T, bastionKey, targetKey string) *mapOpenSSHSource {
	t.Helper()
	bastionHN, err := option.ParseHostNameSpec("198.51.100.10")
	if err != nil {
		t.Fatalf("ParseHostNameSpec(bastion): %v", err)
	}
	targetHN, err := option.ParseHostNameSpec("10.99.0.20")
	if err != nil {
		t.Fatalf("ParseHostNameSpec(target): %v", err)
	}
	bastionCH, _ := netaddr.ParseCanonicalHost("198.51.100.10")
	targetCH, _ := netaddr.ParseCanonicalHost("10.99.0.20")
	bastionEP, _ := netaddr.NewEndpoint(bastionCH, 2200)
	targetEP, _ := netaddr.NewEndpoint(targetCH, 2222)
	bastionUser, _ := option.ParseUsername("jumpop")
	targetUser, _ := option.ParseUsername("appop")
	jumpRoute, err := option.ParseProxyJump("bastion")
	if err != nil {
		t.Fatalf("ParseProxyJump(bastion): %v", err)
	}
	bastionLayer := option.UnsetOptionLayer().
		WithHostName(bastionHN).
		WithPort(2200).
		WithUser(bastionUser).
		WithIdentityFiles(mustIdentityPathList(t, bastionKey)).
		WithIdentitiesOnly(true).
		WithStrictHostKeyChecking(option.StrictHostKeyCheckingAcceptNew)
	appLayer := option.UnsetOptionLayer().
		WithHostName(targetHN).
		WithPort(2222).
		WithUser(targetUser).
		WithProxyRoute(jumpRoute).
		WithIdentityFiles(mustIdentityPathList(t, targetKey)).
		WithIdentitiesOnly(true).
		WithStrictHostKeyChecking(option.StrictHostKeyCheckingAcceptNew)
	vhBastion, err := ports.NewOpenSSHVirtualHost(ports.OpenSSHVirtualHostSpec{
		Alias:      "bastion",
		SourceFile: "~/.ssh/config",
		Endpoint:   algebraic.Some(bastionEP),
		User:       algebraic.Some(bastionUser),
		Layer:      bastionLayer,
	})
	if err != nil {
		t.Fatalf("NewOpenSSHVirtualHost(bastion): %v", err)
	}
	vhApp, err := ports.NewOpenSSHVirtualHost(ports.OpenSSHVirtualHostSpec{
		Alias:      "app-prod",
		SourceFile: "~/.ssh/config",
		Endpoint:   algebraic.Some(targetEP),
		User:       algebraic.Some(targetUser),
		Proxy:      jumpRoute,
		Layer:      appLayer,
	})
	if err != nil {
		t.Fatalf("NewOpenSSHVirtualHost(app-prod): %v", err)
	}
	return &mapOpenSSHSource{
		hosts: []ports.OpenSSHVirtualHost{vhBastion, vhApp},
		tiers: map[string]option.OptionLayer{
			"bastion":  bastionLayer,
			"app-prod": appLayer,
		},
	}
}

func TestEngine_ReconcileCrashedAuditsAndStrictAgentGateHalted(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newLoopbackRigBase(t, false)
	clientPub, keyPath := writeTestKeyInRoot(t, rig.rootFS, rig.sshDir, "id_agent")
	srv := newLoopbackSSHServer(t, clientPub)

	var onHaltCalls atomic.Int32
	eng, err := engine.New(engine.Config{
		Profile:        engine.PolicyProfileStrictAgent,
		Guardrail:      engine.DefaultGuardrailConfig(),
		Clock:          rig.clk,
		Entropy:        rig.rng.Fork(),
		AuditSink:      rig.auditSink,
		Reconciler:     rig.cluster,
		ScopedFS:       rig.rootFS,
		OperatorReadFS: rig.readFS,
		Env:            rig.env,
		DialContext:    srv.dialFunc(),
		OnHalt: func(info engine.HaltInfo) {
			if info.IsValid() {
				onHaltCalls.Add(1)
			}
		},
	})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	defer closeEngineChecked(t, eng)

	assertCrashReconciliationPaths(t, eng, rig)
	assertStrictAgentHaltPropagation(t, eng, rig, srv, keyPath, &onHaltCalls)
	assertEngineZeroClosedAndCodecs(t, eng)
}

func assertCrashReconciliationPaths(t *testing.T, eng *engine.Engine, rig *loopbackEngineRig) {
	t.Helper()
	cleanRep, err := eng.ReconcileCrashedAudits(context.Background())
	if err != nil || !cleanRep.IsValid() || cleanRep.DeadLocksClaimed() != 0 {
		t.Fatalf("干净对账失配: rep=%+v err=%v", cleanRep, err)
	}
	crashedOpID := simulateCrashedAuditOperation(t, rig)
	recRep, err := eng.ReconcileCrashedAudits(context.Background())
	if err != nil || recRep.DeadLocksClaimed() != 1 || len(recRep.AbortedOperations()) != 1 || !recRep.AbortedOperations()[0].Equal(crashedOpID) {
		t.Fatalf("崩溃恢复对账失配: rep=%+v err=%v", recRep, err)
	}
}

func simulateCrashedAuditOperation(t *testing.T, rig *loopbackEngineRig) security.OperationID {
	t.Helper()
	crashedSink, err := rig.cluster.NewSinkFromEntropy(rig.rng)
	if err != nil {
		t.Fatalf("NewSinkFromEntropy(crashed): %v", err)
	}
	opID, _ := security.ParseOperationID("0123456789abcdef0123456789abcdef")
	if err := crashedSink.StageOperation(context.Background(), opID); err != nil {
		t.Fatalf("StageOperation(crashed): %v", err)
	}
	tid, _ := security.ParseTraceID("trace-crashed-proc-01")
	binding, _ := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityExecute,
		Tool:       "ssh",
		Action:     "exec",
		NodeID:     "crashed-node",
	})
	entry, err := ports.NewAuditEntry(ports.AuditEntrySpec{
		ProcessID:   crashedSink.ProcessInstanceID(),
		TraceID:     tid,
		OperationID: opID,
		Phase:       ports.AuditPhaseAuthorized,
		Outcome:     ports.AuditOutcomePending,
		Risk:        security.RiskSafe,
		Decision:    security.DecisionKindAllow,
		Binding:     binding,
		Timestamp:   rig.clk.Now().UTC(),
		Reason:      "authorized before simulated crash",
	})
	if err != nil {
		t.Fatalf("NewAuditEntry(crashed): %v", err)
	}
	if err := crashedSink.Record(context.Background(), entry); err != nil {
		t.Fatalf("Record(crashed): %v", err)
	}
	crashedSink.SimulateSIGKILL()
	return opID
}

func assertStrictAgentHaltPropagation(
	t *testing.T,
	eng *engine.Engine,
	rig *loopbackEngineRig,
	srv *loopbackSSHServer,
	keyPath string,
	onHaltCalls *atomic.Int32,
) {
	t.Helper()
	rig.auditSink.failFinalized.Store(true)
	cliOpts := option.UnsetOptionLayer().
		WithIdentityFiles(mustIdentityPathList(t, keyPath)).
		WithIdentitiesOnly(true).
		WithStrictHostKeyChecking(option.StrictHostKeyCheckingAcceptNew)

	_, err := eng.Exec(context.Background(), engine.ExecRequest{
		TargetSpec: "agent@127.0.0.1:22024",
		CLIOptions: cliOpts,
		Command:    "uname",
		Risk:       algebraic.Some(security.RiskSafe),
	})
	if err == nil || !errors.Is(err, ports.ErrAuditPostWrite) {
		t.Fatalf("期望 AuditPostWriteError，实际=%v", err)
	}
	if !eng.IsHalted() || onHaltCalls.Load() != 1 {
		t.Fatalf("StrictAgent 熔断状态失配: halted=%v onHaltCalls=%d", eng.IsHalted(), onHaltCalls.Load())
	}
	haltInfo, hasHalt := eng.HaltInfo()
	if !hasHalt || !haltInfo.IsValid() || haltInfo.ProcessID() == "" {
		t.Fatalf("HaltInfo 诊断快照失配: has=%v info=%+v", hasHalt, haltInfo)
	}
	dialsBefore := srv.dialCount.Load()
	_, errAfter := eng.Exec(context.Background(), engine.ExecRequest{
		TargetSpec: "agent@127.0.0.1:22024",
		CLIOptions: cliOpts,
		Command:    "uname",
		Risk:       algebraic.Some(security.RiskSafe),
	})
	if !errors.Is(errAfter, engine.ErrEngineHalted) || !errors.Is(errAfter, gate.ErrGateHalted) || srv.dialCount.Load() != dialsBefore {
		t.Fatalf("熔断后请求失配: err=%v dialsBefore=%d dialsAfter=%d", errAfter, dialsBefore, srv.dialCount.Load())
	}
}

func assertEngineZeroClosedAndCodecs(t *testing.T, eng *engine.Engine) {
	t.Helper()
	var zeroEng engine.Engine
	if !zeroEng.IsClosed() || !zeroEng.IsHalted() {
		t.Fatalf("零值 Engine 必须失败关闭报告 IsClosed=true && IsHalted=true")
	}
	if _, zErr := zeroEng.ResolveTarget(context.Background(), engine.ResolveTargetRequest{Target: "127.0.0.1"}); !errors.Is(zErr, engine.ErrEngineNotInitialized) {
		t.Fatalf("零值 Engine 期望 ErrEngineNotInitialized，实际=%v", zErr)
	}
	if err := eng.Close(context.Background()); err != nil {
		t.Fatalf("Engine.Close: %v", err)
	}
	if _, cErr := eng.ResolveTarget(context.Background(), engine.ResolveTargetRequest{Target: "127.0.0.1"}); !errors.Is(cErr, engine.ErrEngineClosed) {
		t.Fatalf("关闭后调用期望 ErrEngineClosed，实际=%v", cErr)
	}
	assertEngineEnumCodecs(t)
}

func assertEngineEnumCodecs(t *testing.T) {
	t.Helper()
	var p engine.PolicyProfile
	if err := p.UnmarshalText([]byte("strict")); err != nil || p != engine.PolicyProfileStrictOperator {
		t.Fatalf("PolicyProfile UnmarshalText 失配: p=%v err=%v", p, err)
	}
	if _, err := engine.PolicyProfileInvalid.MarshalText(); !errors.Is(err, engine.ErrInvalidProfile) {
		t.Fatalf("零值 PolicyProfile 序列化必须失败关闭: %v", err)
	}
	var fb engine.NoElicitFallback
	if err := fb.UnmarshalText([]byte("challenge")); err != nil || fb != engine.NoElicitFallbackChallenge {
		t.Fatalf("NoElicitFallback UnmarshalText 失配: fb=%v err=%v", fb, err)
	}
	var tty engine.RequestTTYMode
	if err := tty.UnmarshalText([]byte("force")); err != nil || tty != engine.RequestTTYForce {
		t.Fatalf("RequestTTYMode UnmarshalText 失配: tty=%v err=%v", tty, err)
	}
	if _, err := engine.RequestTTYUnset.MarshalText(); !errors.Is(err, engine.ErrInvalidRequestTTY) {
		t.Fatalf("零值 RequestTTYMode 序列化必须失败关闭: %v", err)
	}
}
