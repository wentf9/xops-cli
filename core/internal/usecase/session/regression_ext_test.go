package session_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/internal/sim"
	ucsess "github.com/wentf9/xops-cli/core/internal/usecase/session"
	"github.com/wentf9/xops-cli/core/ports"
)

// failingTerminalPort 在进入 WithRawTerminal 回调前直接返回底层终端配置错误，
// 用于验证启动前失败必须归类为 OutcomeNotStarted 而非 OutcomeUnknown。
type failingTerminalPort struct {
	err error
}

func (f *failingTerminalPort) IsInteractive() bool { return true }
func (f *failingTerminalPort) Size() (ports.TerminalSize, error) {
	return ports.NewTerminalSize(80, 24)
}

// WithRawTerminal 在进入回调前直接返回预置底层终端错误。
//
//xops:syncclosure
//xops:borrowed
func (f *failingTerminalPort) WithRawTerminal(context.Context, func(ports.TerminalHandle) error) error {
	return f.err
}
func (f *failingTerminalPort) CanSuspendProcessGroup() (security.Verdict, error) {
	return security.VerdictDeny, ports.ErrUnsupported
}

// failingWriter 首次 Write 即返回指定错误，用于验证 stderrDst 写错时触发双向打断且零死锁。
type failingWriter struct{ err error }

func (f *failingWriter) Write([]byte) (int, error) { return 0, f.err }

// postWriteFaultSink 包装 SimAuditSink，在终态审计阶段注入 AuditPostWriteError。
type postWriteFaultSink struct {
	inner ports.AuditSink
}

func (s *postWriteFaultSink) ProcessInstanceID() ports.ProcessInstanceID {
	return s.inner.ProcessInstanceID()
}
func (s *postWriteFaultSink) StageOperation(ctx context.Context, opID security.OperationID) error {
	return s.inner.StageOperation(ctx, opID)
}
func (s *postWriteFaultSink) UnstageOperation(ctx context.Context, opID security.OperationID) error {
	return s.inner.UnstageOperation(ctx, opID)
}
func (s *postWriteFaultSink) Close() error { return s.inner.Close() }
func (s *postWriteFaultSink) Record(ctx context.Context, entry ports.AuditEntry) error {
	if entry.Phase() == ports.AuditPhaseFinalized {
		postErr, _ := ports.NewAuditPostWriteError(entry.OperationID(), errors.New("injected audit finalize error"))
		return postErr
	}
	return s.inner.Record(ctx, entry)
}

// 编译期端口契约断言：确认测试桩严格满足对应端口接口。
var (
	_ ports.TerminalPort = (*failingTerminalPort)(nil)
	_ ports.AuditSink    = (*postWriteFaultSink)(nil)
)

func TestSessionInteractive_CancelAndStderrErrorNoDeadlock(t *testing.T) {
	defer goleak.VerifyNone(t)
	// 多轮触发取消竞态，验证任何调度序下均返回 context.Canceled 而非内部管道关闭态 io.ErrClosedPipe。
	for range 10 {
		assertIdleRawTerminalCancelNoDeadlock(t)
	}
	assertIdleRawTerminalStderrWriteErrorNoDeadlock(t)
}

func assertIdleRawTerminalCancelNoDeadlock(t *testing.T) {
	t.Helper()
	rig := newTestRig(t, gate.PolicyProfileDirectOperator, true)
	defer rig.close()
	rig.term.SetInput(nil)
	rig.term.SetBlockInputAfterData(true)

	started := make(chan struct{}, 1)
	rig.dialer.onStart = started
	rig.dialer.blockOutputUntilClose = true

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := mustTestOperationStream(t, rig.rng)

	var out execution.ExecutionOutcome
	var runErr error
	err := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			<-started
			cancel()
			return nil
		}); gErr != nil {
			return gErr
		}
		out, runErr = rig.svc.Interactive(ctx, ucsess.InteractiveRequest{
			Plan:            mustTestPlan(t, ""),
			RequestTTY:      ucsess.RequestTTYAuto,
			OperationStream: stream,
		})
		return nil
	})
	if err != nil {
		t.Fatalf("RunWait: %v", err)
	}
	if !errors.Is(runErr, context.Canceled) {
		t.Fatalf("空闲原始终端取消期望 context.Canceled，实际=%v", runErr)
	}
	unk, ok := out.(*execution.OutcomeUnknown)
	if !ok || unk.Phase() != execution.ExecPhaseCanceled {
		t.Fatalf("期望 OutcomeUnknown(canceled)，实际=%#v", out)
	}
	// 验证即使 ctx 已取消，OperationStream 仍收到终态 OperationCompletedEvent 而非裸 EOF。
	assertStreamHasCompletedEvent(t, stream, false)
}

func assertIdleRawTerminalStderrWriteErrorNoDeadlock(t *testing.T) {
	t.Helper()
	rig := newTestRig(t, gate.PolicyProfileDirectOperator, true)
	defer rig.close()
	rig.term.SetInput(nil)
	rig.term.SetBlockInputAfterData(true)
	rig.dialer.blockOutputUntilClose = true
	rig.dialer.stderrBurst = "boom-stderr\n"

	diskErr := errors.New("stderr disk full")
	out, err := rig.svc.Interactive(context.Background(), ucsess.InteractiveRequest{
		Plan:       mustTestPlan(t, ""),
		RequestTTY: ucsess.RequestTTYAuto,
		Stderr:     &failingWriter{err: diskErr},
	})
	if !errors.Is(err, diskErr) {
		t.Fatalf("stderr 写错期望返回原始错误 %v，实际=%v", diskErr, err)
	}
	if out.Kind() != execution.OutcomeKindUnknown {
		t.Fatalf("已启动会话写错期望 OutcomeUnknown，实际=%#v", out)
	}
}

func TestSessionInteractive_ConcurrentRemoteExitAndPreStartNotStarted(t *testing.T) {
	defer goleak.VerifyNone(t)
	assertConcurrentRemoteExitDrainsWithoutSpuriousUnknown(t)
	assertPreStartWithRawTerminalFailureIsNotStarted(t)
}

func assertConcurrentRemoteExitDrainsWithoutSpuriousUnknown(t *testing.T) {
	t.Helper()
	rig := newTestRig(t, gate.PolicyProfileDirectOperator, true)
	defer rig.close()
	// 远端立即关闭 stdin（模拟远端退出关闭写端），同时本地粘贴多行输入；
	// gracefulStdinWriter 必须宽容吸收并发写入并让 remoteOut 完整排空，最终返回 OutcomeCompleted(0)。
	rig.term.SetInput([]byte("exit\nextra-pasted-line-1\nextra-pasted-line-2\n"))
	rig.dialer.closeStdinBeforeGreeting = true
	rig.dialer.remoteFirstClose = true
	rig.dialer.remoteGreeting = "final-remote-output\n"

	out, err := rig.svc.Interactive(context.Background(), ucsess.InteractiveRequest{
		Plan:       mustTestPlan(t, ""),
		RequestTTY: ucsess.RequestTTYAuto,
	})
	if err != nil {
		t.Fatalf("并发远端退出不应误报错误，实际=%v", err)
	}
	assertSucceededOutcome(t, out)
	if got := string(rig.term.Output()); got != "final-remote-output\n" {
		t.Fatalf("远端输出截断或失配: %q", got)
	}
}

func assertPreStartWithRawTerminalFailureIsNotStarted(t *testing.T) {
	t.Helper()
	rig := newTestRig(t, gate.PolicyProfileDirectOperator, true)
	defer rig.close()
	termErr := errors.New("tcgetattr failed")
	svc, err := ucsess.NewService(ucsess.ServiceConfig{
		Gate:     rig.gate,
		Pool:     rig.pool,
		Clock:    rig.clk,
		Env:      rig.env,
		Terminal: &failingTerminalPort{err: termErr},
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	out, runErr := svc.Interactive(context.Background(), ucsess.InteractiveRequest{
		Plan:       mustTestPlan(t, ""),
		RequestTTY: ucsess.RequestTTYAuto,
	})
	if !errors.Is(runErr, termErr) {
		t.Fatalf("期望返回 %v，实际=%v", termErr, runErr)
	}
	ns, ok := out.(*execution.OutcomeNotStarted)
	if !ok || !ns.CanRetry() {
		t.Fatalf("启动前 WithRawTerminal 失败必须返回 OutcomeNotStarted，实际=%#v", out)
	}
	entries := rig.cluster.Entries()
	last := entries[len(entries)-1]
	if last.Outcome() != ports.AuditOutcomeFailed {
		t.Fatalf("启动前失败审计不应记为 OutcomeUnknown，实际=%s", last.Outcome())
	}
}

func TestSessionExec_ScriptTTYGuardUnsetCmdPTYAndPostGateAuditEvent(t *testing.T) {
	defer goleak.VerifyNone(t)
	assertPlanKindScriptRejectsTTYBeforeGate(t)
	assertRequestTTYUnsetHonorsCommandPlanPTY(t)
	assertPostGateAuditFailureEmitsFailedCompletedEvent(t)
}

func assertPlanKindScriptRejectsTTYBeforeGate(t *testing.T) {
	t.Helper()
	rig := newTestRig(t, gate.PolicyProfileDirectOperator, true)
	defer rig.close()
	prof, err := execution.POSIXLaunchProfile(execution.InterpreterSH, execution.LoginModeDisabled)
	if err != nil {
		t.Fatalf("POSIXLaunchProfile: %v", err)
	}
	scriptPlan, err := execution.NewCommandPlan(execution.CommandPlanSpec{
		Kind:    execution.PlanKindScript,
		Profile: prof,
		Command: "echo hi",
	})
	if err != nil {
		t.Fatalf("NewCommandPlan(script): %v", err)
	}
	for _, mode := range []ucsess.RequestTTYMode{ucsess.RequestTTYYes, ucsess.RequestTTYForce} {
		out, execErr := rig.svc.Exec(context.Background(), ucsess.ExecRequest{
			Plan:       mustTestPlan(t, ""),
			Command:    scriptPlan,
			RequestTTY: mode,
		})
		if !errors.Is(execErr, ucsess.ErrInvalidRequest) {
			t.Fatalf("PlanKindScript + %s 期望 ErrInvalidRequest，实际=%v", mode, execErr)
		}
		if ns, ok := out.(*execution.OutcomeNotStarted); !ok || ns.Phase() != execution.StartPhaseValidate {
			t.Fatalf("PlanKindScript + %s 期望 OutcomeNotStarted(validate)，实际=%#v", mode, out)
		}
	}
	if rig.dialer.dialCount.Load() != 0 || len(rig.cluster.Entries()) != 0 {
		t.Fatalf("前置参数拒绝不得触发审计或拨号: dials=%d audits=%d", rig.dialer.dialCount.Load(), len(rig.cluster.Entries()))
	}
}

func assertRequestTTYUnsetHonorsCommandPlanPTY(t *testing.T) {
	t.Helper()
	// 非交互终端下，CommandPlan.PTY()==true 且 RequestTTYUnset 仍须申请远端 PTY 并走流模式。
	rig := newTestRig(t, gate.PolicyProfileDirectOperator, false)
	defer rig.close()
	cmdPTY, err := execution.NewCommandPlan(execution.CommandPlanSpec{
		Kind:    execution.PlanKindCommand,
		Profile: execution.DefaultServerLaunchProfile(),
		Command: "top -b -n 1",
		PTY:     true,
	})
	if err != nil {
		t.Fatalf("NewCommandPlan(PTY): %v", err)
	}
	var outBuf bytes.Buffer
	if _, err := rig.svc.Exec(context.Background(), ucsess.ExecRequest{
		Plan:       mustTestPlan(t, ""),
		Command:    cmdPTY,
		RequestTTY: ucsess.RequestTTYUnset,
		Stdout:     &outBuf,
	}); err != nil {
		t.Fatalf("Exec(CommandPlan.PTY): %v", err)
	}
	if !rig.dialer.seenPTY.IsSome() || rig.dialer.usedPipes {
		t.Fatalf("RequestTTYUnset + CommandPlan.PTY 在非交互环境期望远端 PTY 且走流模式: hasPTY=%v pipes=%v",
			rig.dialer.seenPTY.IsSome(), rig.dialer.usedPipes)
	}
}

func assertPostGateAuditFailureEmitsFailedCompletedEvent(t *testing.T) {
	t.Helper()
	clk := sim.NewSimClock(sim.DefaultBaseTime())
	rng := sim.NewSeededRand(9090)
	cluster := sim.NewSimAuditCluster()
	rawSink, _ := cluster.NewSinkFromEntropy(rng)
	bus, _ := events.NewSystemBus(events.SystemBusConfig{DefaultSubscriberBuffer: 16})
	dialer := &spyDialer{}
	p, err := pool.NewPool(context.Background(), pool.PoolConfig{
		Dialer: dialer, Clock: clk, Entropy: rng.Fork(), Bus: bus,
	})
	if err != nil {
		bus.Close()
		t.Fatalf("NewPool: %v", err)
	}
	defer func() {
		_ = p.Close()
		bus.Close()
	}()
	pol, _ := gate.NewGuardrailPolicy(gate.GuardrailPolicySpec{
		ApprovalThreshold: security.RiskModerate,
		NoElicitFallback:  gate.NoElicitFallbackDeny,
	})
	g, err := gate.NewGate(gate.GateConfig{
		Profile:   gate.PolicyProfileStrictAgent,
		Policy:    pol,
		AuditSink: &postWriteFaultSink{inner: rawSink},
		Clock:     clk,
		Entropy:   rng.Fork(),
		SystemBus: bus,
		OnHalt:    func(info gate.HaltInfo) { p.GateHalted(info.Cause()) },
	})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	svc, err := ucsess.NewService(ucsess.ServiceConfig{Gate: g, Pool: p, Clock: clk})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	stream := mustTestOperationStream(t, rng)
	_, execErr := svc.Exec(context.Background(), ucsess.ExecRequest{
		Plan:            mustTestPlan(t, ""),
		Command:         mustCommandPlan(t, "uname"),
		Risk:            algebraic.Some(security.RiskSafe),
		OperationStream: stream,
	})
	if !errors.Is(execErr, ports.ErrAuditPostWrite) {
		t.Fatalf("期望 AuditPostWriteError，实际=%v", execErr)
	}
	compEv := assertStreamHasCompletedEvent(t, stream, false)
	if compEv.Outcome().IsSome() || compEv.Code() != "audit_post_write_failed" {
		t.Fatalf("终态审计失败后 OperationCompletedEvent 失配: outcomeSome=%v code=%q", compEv.Outcome().IsSome(), compEv.Code())
	}
}

func assertStreamHasCompletedEvent(t *testing.T, stream *events.OperationStream, wantSucceeded bool) *events.OperationCompletedEvent {
	t.Helper()
	var completed *events.OperationCompletedEvent
	for ev, err := range stream.All(context.Background()) {
		if err != nil {
			t.Fatalf("OperationStream.All: %v", err)
		}
		if c, ok := ev.(*events.OperationCompletedEvent); ok {
			completed = c
		}
	}
	if completed == nil {
		t.Fatalf("OperationStream 缺失终态 OperationCompletedEvent")
	}
	if completed.Succeeded() != wantSucceeded {
		t.Fatalf("OperationCompletedEvent.Succeeded 失配: want=%v got=%v", wantSucceeded, completed.Succeeded())
	}
	return completed
}
