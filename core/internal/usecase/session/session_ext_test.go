package session_test

import (
	"bytes"
	"context"
	"encoding"
	"errors"
	"io"
	"maps"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/foundation/trace"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/internal/sim"
	ucsess "github.com/wentf9/xops-cli/core/internal/usecase/session"
	"github.com/wentf9/xops-cli/core/ports"
)

// 编译期契约断言：确认 RequestTTYMode 实现 encoding 文本编解码接口。
var (
	_ encoding.TextAppender    = ucsess.RequestTTYUnset
	_ encoding.TextMarshaler   = ucsess.RequestTTYUnset
	_ encoding.TextUnmarshaler = (*ucsess.RequestTTYMode)(nil)
)

// spyDialer 实现 ports.DialerPort，在纯内存中验证 ADR-008/ADR-009 嵌套顺序、SendEnv、PTY 与 Relay。
type spyDialer struct {
	mu                       sync.Mutex
	dialCount                atomic.Int32
	dialSawLease             atomic.Bool
	sessionSawLease          atomic.Bool
	sessionSawOpID           atomic.Bool
	seenEnv                  map[string]string
	seenPTY                  algebraic.Option[ports.PTYRequest]
	seenResizes              []ports.TerminalSize
	startedShell             bool
	usedPipes                bool
	remoteFirstClose         bool
	closeStdinBeforeGreeting bool
	blockOutputUntilClose    bool
	stderrBurst              string
	onStart                  chan struct{}
	remoteGreeting           string
	waitOutcome              execution.ExecutionOutcome
	waitErr                  error
}

func (d *spyDialer) DialHop(ctx context.Context, hop plan.HopSpec, dig plan.HopDigest, _ ports.TransportConn) (ports.TransportConn, error) {
	d.dialCount.Add(1)
	if trace.InLeaseScope(ctx) {
		d.dialSawLease.Store(true)
	}
	return &spyConn{owner: d, dig: dig, ep: hop.Endpoint()}, nil
}

type spyConn struct {
	owner  *spyDialer
	dig    plan.HopDigest
	ep     netaddr.Endpoint
	closed atomic.Bool
}

func (c *spyConn) HopDigest() plan.HopDigest           { return c.dig }
func (c *spyConn) Endpoint() netaddr.Endpoint          { return c.ep }
func (c *spyConn) IsAlive() bool                       { return !c.closed.Load() }
func (c *spyConn) SendKeepalive(context.Context) error { return nil }
func (c *spyConn) Close() error                        { c.closed.Store(true); return nil }
func (c *spyConn) OpenRemoteFS(context.Context) (ports.RemoteFSPort, error) {
	return nil, ports.ErrUnsupported
}
func (c *spyConn) DialTCP(context.Context, netaddr.HostPort) (net.Conn, error) {
	return nil, ports.ErrUnsupported
}
func (c *spyConn) ListenTCP(context.Context, string) (net.Listener, error) {
	return nil, ports.ErrUnsupported
}
func (c *spyConn) DialStreamLocal(context.Context, pathalg.RemotePath) (net.Conn, error) {
	return nil, ports.ErrUnsupported
}
func (c *spyConn) ListenStreamLocal(context.Context, pathalg.RemotePath) (net.Listener, error) {
	return nil, ports.ErrUnsupported
}
func (c *spyConn) OpenTUN(context.Context, ports.TUNSpec) (io.ReadWriteCloser, error) {
	return nil, ports.ErrUnsupported
}
func (c *spyConn) OpenSession(ctx context.Context) (ports.RemoteSession, error) {
	if trace.InLeaseScope(ctx) {
		c.owner.sessionSawLease.Store(true)
	}
	if _, ok := trace.OpIDFromContext(ctx); ok {
		c.owner.sessionSawOpID.Store(true)
	}
	return &spySession{owner: c.owner}, nil
}

type spySession struct {
	owner     *spyDialer
	inR       *io.PipeReader
	inW       *io.PipeWriter
	outR      *io.PipeReader
	outW      *io.PipeWriter
	errR      *io.PipeReader
	errW      *io.PipeWriter
	pumpDone  chan struct{}
	closeSig  chan struct{}
	closeOnce sync.Once
	pumpGuard sync.Once
	nursery   *conc.Nursery
	closed    atomic.Bool
}

func (s *spySession) StdinPipe() (io.WriteCloser, error) {
	s.inR, s.inW = io.Pipe()
	return s.inW, nil
}
func (s *spySession) StdoutPipe() (io.Reader, error) {
	s.outR, s.outW = io.Pipe()
	return s.outR, nil
}
func (s *spySession) StderrPipe() (io.Reader, error) {
	s.errR, s.errW = io.Pipe()
	return s.errR, nil
}
func (s *spySession) Start(ctx context.Context, _ execution.CommandPlan, streams ports.ExecStreams) error {
	return s.begin(ctx, false, streams)
}
func (s *spySession) StartShell(ctx context.Context, streams ports.ExecStreams) error {
	return s.begin(ctx, true, streams)
}

type pipePumpBehavior struct {
	remoteFirst     bool
	closeStdinEarly bool
	blockOut        bool
	stderrBurst     string
	onStart         chan struct{}
	greeting        string
}

func (s *spySession) begin(ctx context.Context, isShell bool, streams ports.ExecStreams) error {
	s.owner.mu.Lock()
	s.owner.startedShell = isShell
	s.owner.seenEnv = maps.Clone(streams.Env)
	s.owner.seenPTY = streams.PTY
	s.owner.usedPipes = s.inW != nil && s.outW != nil && s.errW != nil
	beh := pipePumpBehavior{
		remoteFirst:     s.owner.remoteFirstClose,
		closeStdinEarly: s.owner.closeStdinBeforeGreeting,
		blockOut:        s.owner.blockOutputUntilClose,
		stderrBurst:     s.owner.stderrBurst,
		onStart:         s.owner.onStart,
		greeting:        s.owner.remoteGreeting,
	}
	s.owner.mu.Unlock()

	if s.outW != nil {
		return s.startPipePump(ctx, beh)
	}
	if streams.Stdout != nil {
		_, _ = io.WriteString(streams.Stdout, "exec-stdout\n")
	}
	if streams.Stderr != nil {
		_, _ = io.WriteString(streams.Stderr, "exec-stderr\n")
	}
	return nil
}

func (s *spySession) startPipePump(_ context.Context, beh pipePumpBehavior) error {
	n, err := conc.NewNursery(context.Background())
	if err != nil {
		return err
	}
	s.nursery = n
	s.pumpDone = make(chan struct{})
	s.closeSig = make(chan struct{})
	return n.Go(func(context.Context) error {
		defer close(s.pumpDone)
		defer s.closeOutputWriters()
		s.runPipePumpBody(beh)
		return nil
	})
}

func (s *spySession) closeOutputWriters() {
	if s.outW != nil {
		_ = s.outW.Close()
	}
	if s.errW != nil {
		_ = s.errW.Close()
	}
}

func (s *spySession) runPipePumpBody(beh pipePumpBehavior) {
	if beh.closeStdinEarly && s.inR != nil {
		_ = s.inR.Close()
	}
	if beh.onStart != nil {
		select {
		case beh.onStart <- struct{}{}:
		default:
		}
	}
	if beh.stderrBurst != "" && s.errW != nil {
		_, _ = io.WriteString(s.errW, beh.stderrBurst)
	}
	if beh.greeting != "" {
		_, _ = io.WriteString(s.outW, beh.greeting)
	}
	if beh.blockOut {
		<-s.closeSig
		return
	}
	if !beh.remoteFirst && s.inR != nil {
		_, _ = io.Copy(s.outW, s.inR)
	}
}

func (s *spySession) ResizePTY(_ context.Context, sz ports.TerminalSize) error {
	if s.closed.Load() {
		return ports.ErrClosed
	}
	s.owner.mu.Lock()
	s.owner.seenResizes = append(s.owner.seenResizes, sz)
	s.owner.mu.Unlock()
	return nil
}
func (s *spySession) Signal(context.Context, string) error { return nil }
func (s *spySession) Wait(context.Context) (execution.ExecutionOutcome, error) {
	if s.pumpDone != nil {
		<-s.pumpDone
	}
	s.owner.mu.Lock()
	out, err := s.owner.waitOutcome, s.owner.waitErr
	s.owner.mu.Unlock()
	if out != nil {
		return out, err
	}
	return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
}
func (s *spySession) Close() error {
	s.closed.Store(true)
	s.closeOnce.Do(func() {
		if s.closeSig != nil {
			close(s.closeSig)
		}
	})
	if s.inR != nil {
		_ = s.inR.Close()
	}
	if s.inW != nil {
		_ = s.inW.Close()
	}
	if s.outW != nil {
		_ = s.outW.Close()
	}
	if s.errW != nil {
		_ = s.errW.Close()
	}
	if s.nursery != nil {
		s.pumpGuard.Do(func() {
			_ = s.nursery.Close()
		})
	}
	return nil
}

type testRig struct {
	clk     *sim.SimClock
	rng     *sim.SeededRand
	cluster *sim.SimAuditCluster
	bus     *events.SystemBus
	dialer  *spyDialer
	pool    *pool.Pool
	gate    *gate.Gate
	env     *sim.SimEnvPort
	term    *sim.SimTerminalPort
	svc     *ucsess.Service
}

func (r *testRig) close() {
	if r == nil {
		return
	}
	_ = r.pool.Close()
	r.bus.Close()
}

func newTestRig(t *testing.T, profile gate.PolicyProfileKind, interactive bool) *testRig {
	return newTestRigWithPolicy(t, profile, interactive, gate.GuardrailPolicySpec{
		ApprovalThreshold: security.RiskModerate,
		NoElicitFallback:  gate.NoElicitFallbackDeny,
	})
}

func newTestRigWithPolicy(t *testing.T, profile gate.PolicyProfileKind, interactive bool, polSpec gate.GuardrailPolicySpec) *testRig {
	t.Helper()
	clk := sim.NewSimClock(sim.DefaultBaseTime())
	rng := sim.NewSeededRand(2026)
	cluster := sim.NewSimAuditCluster()
	sink, err := cluster.NewSinkFromEntropy(rng)
	if err != nil {
		t.Fatalf("NewSinkFromEntropy: %v", err)
	}
	bus, err := events.NewSystemBus(events.SystemBusConfig{DefaultSubscriberBuffer: 16})
	if err != nil {
		t.Fatalf("NewSystemBus: %v", err)
	}
	dialer := &spyDialer{}
	p, err := pool.NewPool(context.Background(), pool.PoolConfig{
		Dialer:  dialer,
		Clock:   clk,
		Entropy: rng.Fork(),
		Bus:     bus,
	})
	if err != nil {
		bus.Close()
		t.Fatalf("NewPool: %v", err)
	}
	pol, err := gate.NewGuardrailPolicy(polSpec)
	if err != nil {
		_ = p.Close()
		bus.Close()
		t.Fatalf("NewGuardrailPolicy: %v", err)
	}
	g, err := gate.NewGate(gate.GateConfig{
		Profile:    profile,
		Policy:     pol,
		AuditSink:  sink,
		Reconciler: cluster,
		Clock:      clk,
		Entropy:    rng.Fork(),
		SystemBus:  bus,
		OnHalt:     func(info gate.HaltInfo) { p.GateHalted(info.Cause()) },
	})
	if err != nil {
		_ = p.Close()
		bus.Close()
		t.Fatalf("NewGate: %v", err)
	}
	id, err := ports.NewLocalIdentityInfo(ports.LocalIdentityInfoSpec{
		LocalHost: "devbox", LocalUser: "dev", LocalUID: "1000", HomeDir: "/home/dev",
	})
	if err != nil {
		_ = p.Close()
		bus.Close()
		t.Fatalf("NewLocalIdentityInfo: %v", err)
	}
	env := sim.NewSimEnvPort(map[string]string{
		"LANG":         "en_US.UTF-8",
		"LC_CTYPE":     "UTF-8",
		"APP_MODE":     "prod",
		"SECRET_TOKEN": "must-not-send",
		"TERM":         "xterm-256color",
	}, id)
	term := sim.NewSimTerminalPort(interactive, 120, 40)
	svc, err := ucsess.NewService(ucsess.ServiceConfig{
		Gate:     g,
		Pool:     p,
		Clock:    clk,
		Env:      env,
		Terminal: term,
	})
	if err != nil {
		_ = p.Close()
		bus.Close()
		t.Fatalf("NewService: %v", err)
	}
	return &testRig{clk, rng, cluster, bus, dialer, p, g, env, term, svc}
}

func mustTestPlan(t *testing.T, sendEnvRaw string) plan.SealedConnectionPlan {
	t.Helper()
	ch, err := netaddr.ParseCanonicalHost("198.51.100.42")
	if err != nil {
		t.Fatalf("ParseCanonicalHost: %v", err)
	}
	ep, err := netaddr.NewEndpoint(ch, 22)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	u, err := option.ParseUsername("deploy")
	if err != nil {
		t.Fatalf("ParseUsername: %v", err)
	}
	auth, err := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	if err != nil {
		t.Fatalf("NewAuthAgent: %v", err)
	}
	t1 := option.UnsetOptionLayer()
	if sendEnvRaw != "" {
		ef, err := option.ParseEnvFilter(sendEnvRaw)
		if err != nil {
			t.Fatalf("ParseEnvFilter: %v", err)
		}
		t1 = t1.WithSendEnv(ef)
	}
	eff, err := option.ResolveEffectivePolicy(option.OriginAdHoc, ep, t1, option.UnsetOptionLayer(), option.UnsetOptionLayer(), option.UnsetOptionLayer())
	if err != nil {
		t.Fatalf("ResolveEffectivePolicy: %v", err)
	}
	hop, err := plan.NewHopSpecFromAuth(0, "web-01", u, auth, eff)
	if err != nil {
		t.Fatalf("NewHopSpecFromAuth: %v", err)
	}
	pl, err := plan.SealConnectionPlan(hop)
	if err != nil {
		t.Fatalf("SealConnectionPlan: %v", err)
	}
	return pl
}

func mustCommandPlan(t *testing.T, cmd string) execution.CommandPlan {
	t.Helper()
	cp, err := execution.NewCommandPlan(execution.CommandPlanSpec{
		Kind:    execution.PlanKindCommand,
		Profile: execution.DefaultServerLaunchProfile(),
		Command: cmd,
	})
	if err != nil {
		t.Fatalf("NewCommandPlan: %v", err)
	}
	return cp
}

func TestSessionExec_SendEnvAuditAndOperationStreamEOF(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newTestRig(t, gate.PolicyProfileDirectOperator, false)
	defer rig.close()
	pl := mustTestPlan(t, "LANG LC_* APP_*")
	cmd := mustCommandPlan(t, "uname -a")
	stream := mustTestOperationStream(t, rig.rng)

	var stdout, stderr bytes.Buffer
	out, err := rig.svc.Exec(context.Background(), ucsess.ExecRequest{
		Plan:            pl,
		Command:         cmd,
		Stdout:          &stdout,
		Stderr:          &stderr,
		OperationStream: stream,
	})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	assertSucceededOutcome(t, out)
	if stdout.String() != "exec-stdout\n" || stderr.String() != "exec-stderr\n" {
		t.Fatalf("输出流失配: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	wantEnv := map[string]string{"LANG": "en_US.UTF-8", "LC_CTYPE": "UTF-8", "APP_MODE": "prod"}
	if !maps.Equal(rig.dialer.seenEnv, wantEnv) {
		t.Fatalf("SendEnv 过滤失配: want=%v got=%v", wantEnv, rig.dialer.seenEnv)
	}
	if rig.dialer.dialSawLease.Load() || !rig.dialer.sessionSawLease.Load() || !rig.dialer.sessionSawOpID.Load() {
		t.Fatalf("嵌套与作用域失配: dialSawLease=%v sessionSawLease=%v opID=%v",
			rig.dialer.dialSawLease.Load(), rig.dialer.sessionSawLease.Load(), rig.dialer.sessionSawOpID.Load())
	}
	assertOperationStreamKinds(t, stream, []events.EventKind{
		events.EventKindFSMTransition,
		events.EventKindOperationStarted,
		events.EventKindOutputChunk,
		events.EventKindOutputChunk,
		events.EventKindOperationCompleted,
	})
	entries := rig.cluster.Entries()
	if len(entries) != 2 || entries[0].Phase() != ports.AuditPhaseAuthorized || entries[1].Phase() != ports.AuditPhaseFinalized || entries[1].Outcome() != ports.AuditOutcomeSucceeded {
		t.Fatalf("审计记录失配: %+v", entries)
	}
}

func mustTestOperationStream(t *testing.T, rng *sim.SeededRand) *events.OperationStream {
	t.Helper()
	tid, err := trace.NewTraceIDFrom(rng)
	if err != nil {
		t.Fatalf("NewTraceIDFrom: %v", err)
	}
	oid, err := trace.NewOpIDFrom(rng)
	if err != nil {
		t.Fatalf("NewOpIDFrom: %v", err)
	}
	stream, err := events.NewOperationStream(events.OperationStreamConfig{
		TraceID: tid, OperationID: oid, OperationBuffer: 16,
	})
	if err != nil {
		t.Fatalf("NewOperationStream: %v", err)
	}
	return stream
}

func assertSucceededOutcome(t *testing.T, out execution.ExecutionOutcome) {
	t.Helper()
	comp, ok := out.(*execution.OutcomeCompleted)
	if !ok || !comp.Succeeded() {
		t.Fatalf("期望成功 OutcomeCompleted，实际=%#v", out)
	}
}

func assertOperationStreamKinds(t *testing.T, stream *events.OperationStream, want []events.EventKind) {
	t.Helper()
	var kinds []events.EventKind
	for ev, iterErr := range stream.All(context.Background()) {
		if iterErr != nil {
			t.Fatalf("OperationStream.All: %v", iterErr)
		}
		kinds = append(kinds, ev.Kind())
	}
	if !slices.Equal(kinds, want) {
		t.Fatalf("事件序列失配: want=%v got=%v", want, kinds)
	}
}

func TestSessionInteractive_RawTerminalRelayResizeAndRemoteFirstEOF(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newTestRig(t, gate.PolicyProfileDirectOperator, true)
	defer rig.close()
	pl := mustTestPlan(t, "LANG")

	// 场景 1：本地输入半关闭后远端回显并退出，期间转发窗口缩放事件。
	rig.term.SetInput([]byte("hello interactive\n"))
	sz1, _ := ports.NewTerminalSize(132, 43)
	rig.term.QueueResize(sz1)
	rig.dialer.remoteGreeting = "welcome> "

	out, err := rig.svc.Interactive(context.Background(), ucsess.InteractiveRequest{
		Plan:       pl,
		RequestTTY: ucsess.RequestTTYAuto,
	})
	if err != nil {
		t.Fatalf("Interactive(half-close): %v", err)
	}
	if comp, ok := out.(*execution.OutcomeCompleted); !ok || !comp.Succeeded() {
		t.Fatalf("期望成功退出，实际=%#v", out)
	}
	if !rig.dialer.startedShell || !rig.dialer.usedPipes {
		t.Fatalf("交互会话必须经 StartShell + 三管道接线: shell=%v pipes=%v", rig.dialer.startedShell, rig.dialer.usedPipes)
	}
	ptyReq, hasPTY := rig.dialer.seenPTY.Get()
	if !hasPTY || ptyReq.Size().Cols() != 120 || ptyReq.Size().Rows() != 40 {
		t.Fatalf("PTY 请求失配: has=%v req=%+v", hasPTY, ptyReq)
	}
	if len(rig.dialer.seenResizes) != 1 || !rig.dialer.seenResizes[0].Equal(sz1) {
		t.Fatalf("窗口缩放事件未转发: %+v", rig.dialer.seenResizes)
	}
	if got := string(rig.term.Output()); got != "welcome> hello interactive\n" {
		t.Fatalf("Relay 输出失配: %q", got)
	}

	// 场景 2：远端先达 EOF 且本地输入阻塞，Relay 必须立刻唤醒并零泄漏退出。
	rig.term.SetInput(nil)
	rig.term.SetBlockInputAfterData(true)
	rig.dialer.remoteFirstClose = true
	rig.dialer.remoteGreeting = "bye\n"
	out2, err := rig.svc.Interactive(context.Background(), ucsess.InteractiveRequest{
		Plan:       pl,
		RequestTTY: ucsess.RequestTTYYes,
	})
	if err != nil {
		t.Fatalf("Interactive(remote-first EOF): %v", err)
	}
	if comp, ok := out2.(*execution.OutcomeCompleted); !ok || !comp.Succeeded() {
		t.Fatalf("远端先达 EOF 期望成功退出，实际=%#v", out2)
	}
}

func TestSessionInteractive_RequestTTYNoAndForceModes(t *testing.T) {
	defer goleak.VerifyNone(t)
	// RequestTTYNo 即使在本机为交互终端时也不分配 PTY 且不接管原始终端。
	rigNo := newTestRig(t, gate.PolicyProfileDirectOperator, true)
	defer rigNo.close()
	pl := mustTestPlan(t, "")
	var outBuf bytes.Buffer
	if _, err := rigNo.svc.Interactive(context.Background(), ucsess.InteractiveRequest{
		Plan:       pl,
		RequestTTY: ucsess.RequestTTYNo,
		Stdout:     &outBuf,
	}); err != nil {
		t.Fatalf("Interactive(RequestTTYNo): %v", err)
	}
	if rigNo.dialer.seenPTY.IsSome() || rigNo.dialer.usedPipes {
		t.Fatalf("RequestTTYNo 不应分配 PTY 或进入原始终端管道模式")
	}

	// RequestTTYForce 在非交互环境下仍强制申请远端 PTY（80x24 回退尺寸）并走流模式。
	rigForce := newTestRig(t, gate.PolicyProfileDirectOperator, false)
	defer rigForce.close()
	if _, err := rigForce.svc.Interactive(context.Background(), ucsess.InteractiveRequest{
		Plan:       pl,
		RequestTTY: ucsess.RequestTTYForce,
		Stdout:     &outBuf,
	}); err != nil {
		t.Fatalf("Interactive(RequestTTYForce): %v", err)
	}
	ptyReq, ok := rigForce.dialer.seenPTY.Get()
	if !ok || ptyReq.Size().Cols() != 80 || ptyReq.Size().Rows() != 24 {
		t.Fatalf("RequestTTYForce 期望 80x24 远端 PTY，实际 ok=%v req=%+v", ok, ptyReq)
	}
}

func TestSessionExec_GateDenySkipsDialAndOutcomeUnknownAudit(t *testing.T) {
	defer goleak.VerifyNone(t)
	pl := mustTestPlan(t, "")
	cmd := mustCommandPlan(t, "rm -rf /tmp/demo")
	assertStrictAgentApprovalRejection(t, pl, cmd)
	assertExplicitNodeOverrideDeny(t, pl, cmd)
	assertSessionFailClosedAndCodecs(t, pl, cmd)
}

func assertStrictAgentApprovalRejection(t *testing.T, pl plan.SealedConnectionPlan, cmd execution.CommandPlan) {
	t.Helper()
	rig := newTestRig(t, gate.PolicyProfileStrictAgent, false)
	defer rig.close()
	out, err := rig.svc.Exec(context.Background(), ucsess.ExecRequest{
		Plan:    pl,
		Command: cmd,
		Risk:    algebraic.Some(security.RiskModerate),
	})
	if !errors.Is(err, gate.ErrApprovalRequired) || rig.dialer.dialCount.Load() != 0 {
		t.Fatalf("期望 ErrApprovalRequired 且 dialCount=0，实际 err=%v dials=%d", err, rig.dialer.dialCount.Load())
	}
	ns, ok := out.(*execution.OutcomeNotStarted)
	if !ok || ns.Phase() != execution.StartPhaseAuthorize {
		t.Fatalf("期望 OutcomeNotStarted(authorize)，实际=%#v", out)
	}
	// RiskSafe 放行，但远端返回 OutcomeUnknown -> 终态审计必须保留 AuditOutcomeUnknown 绝不降级。
	unk, _ := execution.NewOutcomeUnknown(execution.ExecPhaseTransportLost, "conn_reset", "peer reset")
	rig.dialer.waitOutcome = unk
	rig.dialer.waitErr = errors.New("connection reset")
	gotOut, err := rig.svc.Exec(context.Background(), ucsess.ExecRequest{
		Plan:    pl,
		Command: cmd,
		Risk:    algebraic.Some(security.RiskSafe),
	})
	if err == nil || gotOut.Kind() != execution.OutcomeKindUnknown {
		t.Fatalf("期望 OutcomeUnknown 与非 nil 错误，实际 out=%#v err=%v", gotOut, err)
	}
	entries := rig.cluster.Entries()
	last := entries[len(entries)-1]
	if last.Phase() != ports.AuditPhaseFinalized || last.Outcome() != ports.AuditOutcomeUnknown {
		t.Fatalf("终态审计必须严格保留 AuditOutcomeUnknown，实际 phase=%s outcome=%s", last.Phase(), last.Outcome())
	}
}

func assertExplicitNodeOverrideDeny(t *testing.T, pl plan.SealedConnectionPlan, cmd execution.CommandPlan) {
	t.Helper()
	denyRule, err := security.NewNodeOverrideRuleWithFloor("web-01", security.RiskDangerous, security.DecisionKindDeny)
	if err != nil {
		t.Fatalf("NewNodeOverrideRuleWithFloor: %v", err)
	}
	denyOverrides, err := security.NewNodeOverrides(denyRule)
	if err != nil {
		t.Fatalf("NewNodeOverrides: %v", err)
	}
	denyRig := newTestRigWithPolicy(t, gate.PolicyProfileDirectOperator, false, gate.GuardrailPolicySpec{
		ApprovalThreshold: security.RiskDangerous,
		NoElicitFallback:  gate.NoElicitFallbackDeny,
		NodeOverrides:     algebraic.Some(denyOverrides),
	})
	defer denyRig.close()
	if _, denyErr := denyRig.svc.Exec(context.Background(), ucsess.ExecRequest{
		Plan:    pl,
		Command: cmd,
		Risk:    algebraic.Some(security.RiskSafe),
	}); !errors.Is(denyErr, gate.ErrAuthorizationDenied) || denyRig.dialer.dialCount.Load() != 0 {
		t.Fatalf("显式 DecisionDeny 期望 ErrAuthorizationDenied 且 dialCount=0，实际 err=%v dials=%d", denyErr, denyRig.dialer.dialCount.Load())
	}
}

func assertSessionFailClosedAndCodecs(t *testing.T, pl plan.SealedConnectionPlan, cmd execution.CommandPlan) {
	t.Helper()
	var zeroSvc ucsess.Service
	if _, err := zeroSvc.Exec(context.Background(), ucsess.ExecRequest{Plan: pl, Command: cmd}); !errors.Is(err, ucsess.ErrServiceNotInitialized) {
		t.Fatalf("零值 Service 期望 ErrServiceNotInitialized，实际=%v", err)
	}
	var mode ucsess.RequestTTYMode
	if err := mode.UnmarshalText([]byte("force")); err != nil || mode != ucsess.RequestTTYForce {
		t.Fatalf("RequestTTYMode UnmarshalText 失配: mode=%v err=%v", mode, err)
	}
	if _, err := ucsess.RequestTTYUnset.MarshalText(); !errors.Is(err, ucsess.ErrInvalidRequestTTY) {
		t.Fatalf("零值 RequestTTYUnset 序列化必须失败关闭，实际=%v", err)
	}
}
