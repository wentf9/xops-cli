package session_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/internal/sim"
	ucsess "github.com/wentf9/xops-cli/core/internal/usecase/session"
	"github.com/wentf9/xops-cli/core/ports"
)

// ptyPipeDialer 提供跨请求持续存活的双向回显 PTY 会话，用于验证 SlotMap 持久 PTY 读写、缩放、信号与 4 条吊销路径。
type ptyPipeDialer struct {
	mu           sync.Mutex
	dialCount    atomic.Int32
	resizes      []ports.TerminalSize
	signals      []string
	lastSession  *ptyPipeSession
	noAutoEcho   bool
	writeEntered chan struct{}
}

func (d *ptyPipeDialer) DialHop(_ context.Context, hop plan.HopSpec, dig plan.HopDigest, _ ports.TransportConn) (ports.TransportConn, error) {
	d.dialCount.Add(1)
	return &ptyPipeConn{owner: d, dig: dig, ep: hop.Endpoint()}, nil
}

type ptyPipeConn struct {
	owner  *ptyPipeDialer
	dig    plan.HopDigest
	ep     netaddr.Endpoint
	closed atomic.Bool
}

func (c *ptyPipeConn) HopDigest() plan.HopDigest           { return c.dig }
func (c *ptyPipeConn) Endpoint() netaddr.Endpoint          { return c.ep }
func (c *ptyPipeConn) IsAlive() bool                       { return !c.closed.Load() }
func (c *ptyPipeConn) SendKeepalive(context.Context) error { return nil }
func (c *ptyPipeConn) Close() error                        { c.closed.Store(true); return nil }
func (c *ptyPipeConn) OpenRemoteFS(context.Context) (ports.RemoteFSPort, error) {
	return nil, ports.ErrUnsupported
}
func (c *ptyPipeConn) DialTCP(context.Context, netaddr.HostPort) (net.Conn, error) {
	return nil, ports.ErrUnsupported
}
func (c *ptyPipeConn) ListenTCP(context.Context, string) (net.Listener, error) {
	return nil, ports.ErrUnsupported
}
func (c *ptyPipeConn) DialStreamLocal(context.Context, pathalg.RemotePath) (net.Conn, error) {
	return nil, ports.ErrUnsupported
}
func (c *ptyPipeConn) ListenStreamLocal(context.Context, pathalg.RemotePath) (net.Listener, error) {
	return nil, ports.ErrUnsupported
}
func (c *ptyPipeConn) OpenTUN(context.Context, ports.TUNSpec) (io.ReadWriteCloser, error) {
	return nil, ports.ErrUnsupported
}
func (c *ptyPipeConn) OpenSession(context.Context) (ports.RemoteSession, error) {
	if c.closed.Load() {
		return nil, ports.ErrClosed
	}
	s := &ptyPipeSession{owner: c.owner}
	c.owner.mu.Lock()
	c.owner.lastSession = s
	c.owner.mu.Unlock()
	return s, nil
}

type ptyPipeSession struct {
	owner     *ptyPipeDialer
	inR       *io.PipeReader
	inW       *io.PipeWriter
	outR      *io.PipeReader
	outW      *io.PipeWriter
	errR      *io.PipeReader
	errW      *io.PipeWriter
	nursery   *conc.Nursery
	closeOnce sync.Once
}

type notifyWriteCloser struct {
	w    io.WriteCloser
	once sync.Once
	ch   chan struct{}
}

func (n *notifyWriteCloser) Write(p []byte) (int, error) {
	n.once.Do(func() { close(n.ch) })
	return n.w.Write(p)
}
func (n *notifyWriteCloser) Close() error { return n.w.Close() }

func (s *ptyPipeSession) StdinPipe() (io.WriteCloser, error) {
	s.inR, s.inW = io.Pipe()
	if s.owner.writeEntered != nil {
		return &notifyWriteCloser{w: s.inW, ch: s.owner.writeEntered}, nil
	}
	return s.inW, nil
}
func (s *ptyPipeSession) StdoutPipe() (io.Reader, error) {
	s.outR, s.outW = io.Pipe()
	return s.outR, nil
}
func (s *ptyPipeSession) StderrPipe() (io.Reader, error) {
	s.errR, s.errW = io.Pipe()
	return s.errR, nil
}
func (s *ptyPipeSession) Start(_ context.Context, _ execution.CommandPlan, streams ports.ExecStreams) error {
	if streams.Stdout != nil {
		_, _ = io.WriteString(streams.Stdout, "reused-hop-ok")
	}
	return nil
}
func (s *ptyPipeSession) StartShell(ctx context.Context, _ ports.ExecStreams) error {
	n, err := conc.NewNursery(ctx)
	if err != nil {
		return err
	}
	s.nursery = n
	return n.Go(func(wCtx context.Context) error {
		defer func() { _ = s.outW.Close(); _ = s.errW.Close() }()
		if s.owner.noAutoEcho {
			<-wCtx.Done()
			return nil
		}
		_, _ = io.Copy(s.outW, s.inR)
		return nil
	})
}
func (s *ptyPipeSession) ResizePTY(_ context.Context, sz ports.TerminalSize) error {
	s.owner.mu.Lock()
	s.owner.resizes = append(s.owner.resizes, sz)
	s.owner.mu.Unlock()
	return nil
}
func (s *ptyPipeSession) Signal(_ context.Context, sig string) error {
	s.owner.mu.Lock()
	s.owner.signals = append(s.owner.signals, sig)
	s.owner.mu.Unlock()
	return nil
}
func (s *ptyPipeSession) Wait(context.Context) (execution.ExecutionOutcome, error) {
	return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
}
func (s *ptyPipeSession) closeRemoteOutput() {
	_ = s.inR.Close()
	_ = s.outW.Close()
	_ = s.errW.Close()
}
func closePipeR(r *io.PipeReader) {
	if r != nil {
		_ = r.Close()
	}
}
func closePipeW(w *io.PipeWriter) {
	if w != nil {
		_ = w.Close()
	}
}
func (s *ptyPipeSession) Close() error {
	s.closeOnce.Do(func() {
		if s.nursery != nil {
			s.nursery.Cancel(ports.ErrClosed)
		}
		closePipeR(s.inR)
		closePipeW(s.inW)
		closePipeR(s.outR)
		closePipeW(s.outW)
		closePipeR(s.errR)
		closePipeW(s.errW)
		if s.nursery != nil {
			_ = s.nursery.Close()
		}
	})
	return nil
}

func TestSessionPTY_CrossRequestLifecycleAndBufferOverflow(t *testing.T) {
	defer goleak.VerifyNone(t)
	pd := &ptyPipeDialer{}
	rig := newFullSessionRig(t, fullRigOptions{customDialer: pd})
	defer rig.close()
	pl := mustTestPlan(t, "LANG")
	initSz, _ := ports.NewTerminalSize(100, 30)

	h, err := rig.svc.OpenPTY(context.Background(), ucsess.OpenPTYRequest{
		Plan: pl, Term: "xterm-256color", Size: algebraic.Some(initSz), MaxBufferBytes: 16,
	})
	if err != nil || !h.IsValid() {
		t.Fatalf("OpenPTY 失败: h=%v err=%v", h, err)
	}
	if snap := rig.pool.Stats(); snap.ActiveLeases != 0 || snap.ActiveHandles != 1 || rig.pool.EvictIdle() != 0 {
		t.Fatalf("池钉选状态失配: snap=%+v", snap)
	}
	assertPTYReadWriteResizeSignal(t, rig, pd, h)
	assertPTYOverflowAndEOF(t, rig, pd, h)
	assertPTYCloseAndHopReuse(t, rig, pd, pl, h)
}

func assertPTYReadWriteResizeSignal(t *testing.T, rig *fullSessionRig, pd *ptyPipeDialer, h plan.ManagedHandle[plan.KindPTY]) {
	t.Helper()
	if n, err := rig.svc.WritePTY(context.Background(), h, []byte("ping-1")); err != nil || n != 6 {
		t.Fatalf("WritePTY: n=%d err=%v", n, err)
	}
	res, err := rig.svc.ReadPTY(context.Background(), ucsess.PTYReadRequest{Handle: h, MaxBytes: 64, Wait: true})
	if err != nil || !res.IsValid() || string(res.Data()) != "ping-1" {
		t.Fatalf("ReadPTY 失配: res=%q err=%v", string(res.Data()), err)
	}
	newSz, _ := ports.NewTerminalSize(132, 42)
	if err := rig.svc.ResizePTY(context.Background(), h, newSz); err != nil {
		t.Fatalf("ResizePTY: %v", err)
	}
	if err := rig.svc.SignalPTY(context.Background(), h, "SIGINT"); err != nil {
		t.Fatalf("SignalPTY: %v", err)
	}
	st, err := rig.svc.InspectPTY(context.Background(), h)
	if err != nil || !st.Active() || !st.Size().Equal(newSz) || st.Term() != "xterm-256color" {
		t.Fatalf("InspectPTY 失配: st=%#v err=%v", st, err)
	}
	if !slices.Equal(pd.signals, []string{"SIGINT"}) || len(pd.resizes) != 1 || !pd.resizes[0].Equal(newSz) {
		t.Fatalf("远端未收到 Resize/Signal: resizes=%v signals=%v", pd.resizes, pd.signals)
	}
}

func assertPTYOverflowAndEOF(t *testing.T, rig *fullSessionRig, pd *ptyPipeDialer, h plan.ManagedHandle[plan.KindPTY]) {
	t.Helper()
	payload := []byte("0123456789abcdefghijklmnopqrstuvwxyzABCD")
	if _, err := rig.svc.WritePTY(context.Background(), h, payload); err != nil {
		t.Fatalf("WritePTY(overflow): %v", err)
	}
	// 等待泵协程完整回显并触发环形缓冲溢出后再关闭远端管道，杜绝 GOMAXPROCS=1 下的写前关管竞态。
	waitUntilErr(t, func() (bool, error) {
		st, iErr := rig.svc.InspectPTY(context.Background(), h)
		if iErr != nil {
			return false, iErr
		}
		return st.DroppedBytes() >= uint64(len(payload)-16), nil
	})
	pd.lastSession.closeRemoteOutput()
	var collected []byte
	var dropped uint64
	for {
		r, rErr := rig.svc.ReadPTY(context.Background(), ucsess.PTYReadRequest{Handle: h, MaxBytes: 64, Wait: true})
		if rErr != nil {
			t.Fatalf("ReadPTY(drain): %v", rErr)
		}
		collected = append(collected, r.Data()...)
		dropped = r.DroppedBytes()
		if r.EOF() {
			break
		}
	}
	if dropped == 0 || !bytes.HasSuffix(collected, []byte("ABCD")) {
		t.Fatalf("溢出/EOF 统计失配: dropped=%d collected=%q", dropped, string(collected))
	}
}

func assertPTYCloseAndHopReuse(t *testing.T, rig *fullSessionRig, pd *ptyPipeDialer, pl plan.SealedConnectionPlan, h plan.ManagedHandle[plan.KindPTY]) {
	t.Helper()
	if err := rig.svc.ClosePTY(context.Background(), h); err != nil {
		t.Fatalf("ClosePTY: %v", err)
	}
	if _, err := rig.svc.WritePTY(context.Background(), h, []byte("stale")); !errors.Is(err, pool.ErrHandleNotFound) {
		t.Fatalf("释放后复用旧世代句柄期望 ErrHandleNotFound，实际=%v", err)
	}
	var zeroHandle plan.ManagedHandle[plan.KindPTY]
	if _, err := rig.svc.InspectPTY(context.Background(), zeroHandle); !errors.Is(err, pool.ErrInvalidHandle) {
		t.Fatalf("零值句柄期望 ErrInvalidHandle，实际=%v", err)
	}
	if rig.pool.Stats().ActiveHandles != 0 {
		t.Fatalf("ClosePTY 后 ActiveHandles 必须归零: %+v", rig.pool.Stats())
	}
	out, err := rig.svc.Exec(context.Background(), ucsess.ExecRequest{Plan: pl, Command: mustCommandPlan(t, "echo ok")})
	if err != nil {
		t.Fatalf("释放 PTY 后复用共享跳板 Exec 失败: %v", err)
	}
	assertSucceededOutcome(t, out)
	if pd.dialCount.Load() != 1 {
		t.Fatalf("ClosePTY 不得拆除健康共享跳板: dials=%d", pd.dialCount.Load())
	}
}

func TestSessionPTY_RevocationPathsUnblockAndZeroLeak(t *testing.T) {
	defer goleak.VerifyNone(t)
	for _, mode := range []string{"ReleaseHandle", "RetireHop", "GateHalted", "PoolClose"} {
		t.Run(mode, func(t *testing.T) { assertPTYRevocationMode(t, mode) })
	}
}

func assertPTYRevocationMode(t *testing.T, mode string) {
	t.Helper()
	pd := &ptyPipeDialer{noAutoEcho: true}
	opt := fullRigOptions{customDialer: pd}
	var faultArmed atomic.Bool
	if mode == "GateHalted" {
		opt.profile = gate.PolicyProfileStrictAgent
		opt.approvalThreshold = security.RiskDangerous
		opt.customAuditSink = func(inner ports.AuditSink) ports.AuditSink {
			return &armedPostWriteFaultSink{inner: inner, armed: &faultArmed}
		}
	}
	rig := newFullSessionRig(t, opt)
	defer rig.close()
	pl := mustTestPlan(t, "")
	h, err := rig.svc.OpenPTY(context.Background(), ucsess.OpenPTYRequest{Plan: pl, Risk: algebraic.Some(security.RiskSafe)})
	if err != nil {
		t.Fatalf("OpenPTY: %v", err)
	}
	var readErr error
	if err := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		readStarted := make(chan struct{})
		if gErr := n.Go(func(ctx context.Context) error {
			close(readStarted)
			_, readErr = rig.svc.ReadPTY(ctx, ucsess.PTYReadRequest{Handle: h, Wait: true})
			return nil
		}); gErr != nil {
			return gErr
		}
		<-readStarted
		triggerPTYRevocation(t, rig, pl, h, mode, &faultArmed)
		return nil
	}); err != nil {
		t.Fatalf("RunWait: %v", err)
	}
	if readErr == nil {
		t.Fatalf("%s 吊销后阻塞 ReadPTY 必须返回错误", mode)
	}
	if _, err := rig.svc.WritePTY(context.Background(), h, []byte("after-revoke")); err == nil {
		t.Fatalf("%s 吊销后 WritePTY 必须拒绝", mode)
	}
	if rig.pool.Stats().ActiveHandles != 0 {
		t.Fatalf("%s 后 ActiveHandles 必须为 0: %+v", mode, rig.pool.Stats())
	}
	assertTeardownClean(t, rig, "PTYRevocation/"+mode)
}

func triggerPTYRevocation(t *testing.T, rig *fullSessionRig, pl plan.SealedConnectionPlan, h plan.ManagedHandle[plan.KindPTY], mode string, faultArmed *atomic.Bool) {
	switch mode {
	case "ReleaseHandle":
		_ = rig.svc.ClosePTY(context.Background(), h)
	case "RetireHop":
		leaf, _ := pl.HopDigestAt(pl.Len() - 1)
		_ = rig.pool.RetireHop(leaf)
	case "GateHalted":
		faultArmed.Store(true)
		_, _ = rig.svc.Exec(context.Background(), ucsess.ExecRequest{Plan: pl, Command: mustCommandPlan(t, "id"), Risk: algebraic.Some(security.RiskSafe)})
	case "PoolClose":
		_ = rig.pool.Close()
	}
}

type armedPostWriteFaultSink struct {
	inner ports.AuditSink
	armed *atomic.Bool
}

func (s *armedPostWriteFaultSink) ProcessInstanceID() ports.ProcessInstanceID {
	return s.inner.ProcessInstanceID()
}
func (s *armedPostWriteFaultSink) StageOperation(ctx context.Context, opID security.OperationID) error {
	return s.inner.StageOperation(ctx, opID)
}
func (s *armedPostWriteFaultSink) UnstageOperation(ctx context.Context, opID security.OperationID) error {
	return s.inner.UnstageOperation(ctx, opID)
}
func (s *armedPostWriteFaultSink) Close() error { return s.inner.Close() }
func (s *armedPostWriteFaultSink) Record(ctx context.Context, entry ports.AuditEntry) error {
	if s.armed.Load() && entry.Phase() == ports.AuditPhaseFinalized {
		postErr, _ := ports.NewAuditPostWriteError(entry.OperationID(), errors.New("injected audit post write fault"))
		return postErr
	}
	return s.inner.Record(ctx, entry)
}

func TestSessionForward_AllModesStreamLocalAndPostLeaseChannelOpen(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newFullSessionRig(t, fullRigOptions{profile: gate.PolicyProfileDirectOperator})
	defer rig.close()
	pl := mustTestPlan(t, "")

	assertDelegatedForwardMatrix(t, rig, pl)
	assertDirectAndFallbackTUNForwards(t, rig, pl)
	assertForwardDefaultRiskGate(t, pl)
}

func assertDelegatedForwardMatrix(t *testing.T, rig *fullSessionRig, pl plan.SealedConnectionPlan) {
	t.Helper()
	lTCP, _ := ports.NewForwardSpec(ports.ForwardLocal, "127.0.0.1:18080", "10.0.0.2:80")
	lTCPUnix, _ := ports.NewTypedForwardSpec(ports.ForwardLocal, ports.ForwardEndpointTCP, "127.0.0.1:18081", ports.ForwardEndpointUnix, "/var/run/docker.sock")
	lUnixTCP, _ := ports.NewTypedForwardSpec(ports.ForwardLocal, ports.ForwardEndpointUnix, "/tmp/local.sock", ports.ForwardEndpointTCP, "10.0.0.2:5432")
	lUnixUnix, _ := ports.NewTypedForwardSpec(ports.ForwardLocal, ports.ForwardEndpointUnix, "/tmp/a.sock", ports.ForwardEndpointUnix, "/run/b.sock")
	rTCP, _ := ports.NewForwardSpec(ports.ForwardRemote, "0.0.0.0:19090", "127.0.0.1:3000")
	rUnixTCP, _ := ports.NewTypedForwardSpec(ports.ForwardRemote, ports.ForwardEndpointUnix, "/run/rev.sock", ports.ForwardEndpointTCP, "127.0.0.1:3001")
	rTCPUnix, _ := ports.NewTypedForwardSpec(ports.ForwardRemote, ports.ForwardEndpointTCP, "0.0.0.0:19091", ports.ForwardEndpointUnix, "/tmp/local-target.sock")
	dyn, _ := ports.NewForwardSpec(ports.ForwardDynamic, "127.0.0.1:1080", "")
	for _, spec := range []ports.ForwardSpec{lTCP, lTCPUnix, lUnixTCP, lUnixUnix, rTCP, rUnixTCP, rTCPUnix, dyn} {
		assertSingleDelegatedForward(t, rig, pl, spec)
	}
}

func assertSingleDelegatedForward(t *testing.T, rig *fullSessionRig, pl plan.SealedConnectionPlan, spec ports.ForwardSpec) {
	t.Helper()
	info, err := rig.svc.StartForward(context.Background(), ucsess.StartForwardRequest{Plan: pl, Spec: spec})
	if err != nil || !info.IsValid() {
		t.Fatalf("StartForward(%v) 失败: info=%#v err=%v", spec.Direction(), info, err)
	}
	if snap := rig.pool.Stats(); snap.ActiveLeases != 0 || snap.ActiveHandles != 1 {
		t.Fatalf("WithLease 返回后应保持 0 租约 + 1 句柄: %+v", snap)
	}
	st, err := rig.svc.InspectForward(context.Background(), info.Handle())
	if err != nil || !st.Active() || st.BoundAddr() != info.BoundAddr() {
		t.Fatalf("InspectForward 失配: st=%#v err=%v", st, err)
	}
	if err := rig.svc.WithForwardHandle(context.Background(), info.Handle(), func(hCtx context.Context, fh ports.ForwardHandle) error {
		sfh, ok := fh.(*sim.SimForwardHandle)
		if !ok {
			t.Fatalf("期望 *sim.SimForwardHandle，实际=%T", fh)
		}
		return sfh.OpenChannel(hCtx)
	}); err != nil {
		t.Fatalf("WithLease 退出后 OpenChannel(%v) 失败: %v", spec.Direction(), err)
	}
	if err := rig.svc.StopForward(context.Background(), info.Handle()); err != nil {
		t.Fatalf("StopForward: %v", err)
	}
}

func assertDirectAndFallbackTUNForwards(t *testing.T, rig *fullSessionRig, pl plan.SealedConnectionPlan) {
	t.Helper()
	assertSingleDirectTUNForward(t, rig, pl, ports.TUNModePointToPoint, "tun")
	assertSingleDirectTUNForward(t, rig, pl, ports.TUNModeEthernet, "tap")
	rig.tunDevice.SetAvailable(false)
	ts, _ := ports.NewTUNSpec(ports.TUNModePointToPoint, 0, 0)
	fSpec, _ := ports.NewForwardTUNSpec(ts)
	if _, err := rig.svc.StartForward(context.Background(), ucsess.StartForwardRequest{Plan: pl, Spec: fSpec}); !errors.Is(err, ports.ErrPermissionDenied) {
		t.Fatalf("TUN 设备无权限期望 ErrPermissionDenied，实际=%v", err)
	}
	if rig.pool.Stats().ActiveHandles != 0 {
		t.Fatalf("TUN 启动失败必须回滚 SlotMap 句柄: %+v", rig.pool.Stats())
	}
	noTUNRig := newFullSessionRig(t, fullRigOptions{disableTUN: true})
	defer noTUNRig.close()
	info, err := noTUNRig.svc.StartForward(context.Background(), ucsess.StartForwardRequest{Plan: pl, Spec: fSpec})
	if err != nil || !info.IsValid() {
		t.Fatalf("Delegated ForwardTUN 失败: info=%#v err=%v", info, err)
	}
	_ = noTUNRig.svc.StopForward(context.Background(), info.Handle())
}

func assertSingleDirectTUNForward(t *testing.T, _ *fullSessionRig, pl plan.SealedConnectionPlan, mode ports.TUNMode, pref string) {
	t.Helper()
	remR, remW := io.Pipe()
	locR, locW := io.Pipe()
	defer func() { _ = remW.Close(); _ = locW.Close() }()
	tunRig := newFullSessionRig(t, fullRigOptions{
		profile:      gate.PolicyProfileDirectOperator,
		customDialer: &tunEOFDialer{remoteR: remR, remoteW: remW},
		customTUN:    &pipeTUNPort{localR: locR, localW: locW, ifaceName: pref + "0"},
	})
	defer tunRig.close()
	ts, _ := ports.NewTUNSpec(mode, ports.TUNUnitAny, 1)
	fSpec, _ := ports.NewForwardTUNSpec(ts)
	info, err := tunRig.svc.StartForward(context.Background(), ucsess.StartForwardRequest{Plan: pl, Spec: fSpec})
	if err != nil || !info.IsValid() || len(info.BoundAddr()) < 4 || info.BoundAddr()[:3] != pref {
		t.Fatalf("Direct TUN(%v) 失败: info=%#v err=%v", mode, info, err)
	}
	if err := tunRig.svc.WithForwardHandle(context.Background(), info.Handle(), func(_ context.Context, fh ports.ForwardHandle) error {
		if !fh.IsValid() || fh.BoundAddr() != info.BoundAddr() {
			return errors.New("unexpected direct TUN ForwardHandle")
		}
		return nil
	}); err != nil {
		t.Fatalf("WithForwardHandle(TUN): %v", err)
	}
	if err := tunRig.svc.StopForward(context.Background(), info.Handle()); err != nil {
		t.Fatalf("StopForward(TUN): %v", err)
	}
	assertTeardownClean(t, tunRig, "DirectTUN/"+pref)
}

func assertForwardDefaultRiskGate(t *testing.T, pl plan.SealedConnectionPlan) {
	t.Helper()
	lTCP, _ := ports.NewForwardSpec(ports.ForwardLocal, "127.0.0.1:18080", "10.0.0.2:80")
	rTCP, _ := ports.NewForwardSpec(ports.ForwardRemote, "0.0.0.0:19090", "127.0.0.1:3000")
	strictRig := newFullSessionRig(t, fullRigOptions{profile: gate.PolicyProfileStrictAgent, approvalThreshold: security.RiskDangerous})
	defer strictRig.close()
	if _, err := strictRig.svc.StartForward(context.Background(), ucsess.StartForwardRequest{Plan: pl, Spec: rTCP}); err == nil || strictRig.dialer.DialCount() != 0 {
		t.Fatalf("-R 默认 RiskDangerous 在未审批时禁止拨号: err=%v dials=%d", err, strictRig.dialer.DialCount())
	}
	if lInfo, err := strictRig.svc.StartForward(context.Background(), ucsess.StartForwardRequest{Plan: pl, Spec: lTCP}); err != nil {
		t.Fatalf("-L 默认 RiskModerate 应放行: %v", err)
	} else {
		_ = strictRig.svc.StopForward(context.Background(), lInfo.Handle())
	}
}

func TestSessionForward_RevocationPathsZeroLeak(t *testing.T) {
	defer goleak.VerifyNone(t)
	lTCP, _ := ports.NewForwardSpec(ports.ForwardLocal, "127.0.0.1:28080", "10.0.0.2:80")
	ts, _ := ports.NewTUNSpec(ports.TUNModePointToPoint, 2, 2)
	tunSpec, _ := ports.NewForwardTUNSpec(ts)

	for _, spec := range []ports.ForwardSpec{lTCP, tunSpec} {
		for _, mode := range []string{"StopForward", "RetireHop", "GateHalted", "PoolClose"} {
			t.Run(spec.Direction().String()+"_"+mode, func(t *testing.T) {
				assertForwardRevocationMode(t, spec, mode)
			})
		}
	}
}

func assertForwardRevocationMode(t *testing.T, spec ports.ForwardSpec, mode string) {
	t.Helper()
	var faultArmed atomic.Bool
	opt := fullRigOptions{profile: gate.PolicyProfileDirectOperator}
	if spec.Direction() == ports.ForwardTUN {
		remR, remW := io.Pipe()
		locR, locW := io.Pipe()
		defer func() { _ = remW.Close(); _ = locW.Close() }()
		opt.customDialer = &tunEOFDialer{remoteR: remR, remoteW: remW}
		opt.customTUN = &pipeTUNPort{localR: locR, localW: locW, ifaceName: "tun2"}
	}
	if mode == "GateHalted" {
		opt.profile = gate.PolicyProfileStrictAgent
		opt.approvalThreshold = security.RiskDangerous
		opt.customAuditSink = func(inner ports.AuditSink) ports.AuditSink {
			return &armedPostWriteFaultSink{inner: inner, armed: &faultArmed}
		}
	}
	rig := newFullSessionRig(t, opt)
	defer rig.close()
	pl := mustTestPlan(t, "")
	info, err := rig.svc.StartForward(context.Background(), ucsess.StartForwardRequest{
		Plan: pl, Spec: spec, Risk: algebraic.Some(security.RiskSafe),
	})
	if err != nil {
		t.Fatalf("StartForward: %v", err)
	}
	switch mode {
	case "StopForward":
		_ = rig.svc.StopForward(context.Background(), info.Handle())
	case "RetireHop":
		leaf, _ := pl.HopDigestAt(pl.Len() - 1)
		_ = rig.pool.RetireHop(leaf)
	case "GateHalted":
		faultArmed.Store(true)
		_, _ = rig.svc.Exec(context.Background(), ucsess.ExecRequest{Plan: pl, Command: mustCommandPlan(t, "id"), Risk: algebraic.Some(security.RiskSafe)})
	case "PoolClose":
		_ = rig.pool.Close()
	}
	if _, err := rig.svc.InspectForward(context.Background(), info.Handle()); err == nil {
		t.Fatalf("%s 吊销后 InspectForward 必须失败", mode)
	}
	if rig.pool.Stats().ActiveHandles != 0 {
		t.Fatalf("%s 吊销后 ActiveHandles 必须归零: %+v", mode, rig.pool.Stats())
	}
	assertTeardownClean(t, rig, "ForwardRevocation/"+mode)
}

// tunEOFDialer 与 blockingLocalTUN 用于验证 Direct TUN 远端正常 EOF 即时关闭本地设备、Done() 闭合与 Active()==false。
type tunEOFDialer struct {
	remoteR *io.PipeReader
	remoteW *io.PipeWriter
}

func (d *tunEOFDialer) DialHop(_ context.Context, hop plan.HopSpec, dig plan.HopDigest, _ ports.TransportConn) (ports.TransportConn, error) {
	return &tunEOFConn{dig: dig, ep: hop.Endpoint(), rw: &pipeRWC{r: d.remoteR, w: d.remoteW}}, nil
}

type pipeRWC struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func (p *pipeRWC) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *pipeRWC) Write(b []byte) (int, error) { return p.w.Write(b) }
func (p *pipeRWC) Close() error                { return errors.Join(p.r.Close(), p.w.Close()) }

type tunEOFConn struct {
	dig    plan.HopDigest
	ep     netaddr.Endpoint
	rw     io.ReadWriteCloser
	closed atomic.Bool
}

func (c *tunEOFConn) HopDigest() plan.HopDigest           { return c.dig }
func (c *tunEOFConn) Endpoint() netaddr.Endpoint          { return c.ep }
func (c *tunEOFConn) IsAlive() bool                       { return !c.closed.Load() }
func (c *tunEOFConn) SendKeepalive(context.Context) error { return nil }
func (c *tunEOFConn) Close() error                        { c.closed.Store(true); return c.rw.Close() }
func (c *tunEOFConn) OpenSession(context.Context) (ports.RemoteSession, error) {
	return nil, ports.ErrUnsupported
}
func (c *tunEOFConn) OpenRemoteFS(context.Context) (ports.RemoteFSPort, error) {
	return nil, ports.ErrUnsupported
}
func (c *tunEOFConn) DialTCP(context.Context, netaddr.HostPort) (net.Conn, error) {
	return nil, ports.ErrUnsupported
}
func (c *tunEOFConn) ListenTCP(context.Context, string) (net.Listener, error) {
	return nil, ports.ErrUnsupported
}
func (c *tunEOFConn) DialStreamLocal(context.Context, pathalg.RemotePath) (net.Conn, error) {
	return nil, ports.ErrUnsupported
}
func (c *tunEOFConn) ListenStreamLocal(context.Context, pathalg.RemotePath) (net.Listener, error) {
	return nil, ports.ErrUnsupported
}
func (c *tunEOFConn) OpenTUN(context.Context, ports.TUNSpec) (io.ReadWriteCloser, error) {
	return c.rw, nil
}

type pipeTUNPort struct {
	localR      *io.PipeReader
	localW      *io.PipeWriter
	ifaceName   string
	openEntered chan struct{}
}

func (p *pipeTUNPort) Available() bool { return true }
func (p *pipeTUNPort) OpenLocalTUN(ctx context.Context, _ ports.TUNSpec) (io.ReadWriteCloser, string, error) {
	if p.openEntered != nil {
		close(p.openEntered)
		<-ctx.Done()
		return nil, "", ctx.Err()
	}
	name := p.ifaceName
	if name == "" {
		name = "tun9"
	}
	return &pipeRWC{r: p.localR, w: p.localW}, name, nil
}

// TestSessionForward_DirectTUNRemoteCleanEOFClosesBridge 验证 Direct TUN 远端正常 EOF 立即收尾双向泵、闭合 Done() 且 Active()==false（0 goleak）。
func TestSessionForward_DirectTUNRemoteCleanEOFClosesBridge(t *testing.T) {
	defer goleak.VerifyNone(t)
	remR, remW := io.Pipe()
	locR, locW := io.Pipe()
	defer func() { _ = remW.Close(); _ = locW.Close() }()
	rig := newFullSessionRig(t, fullRigOptions{
		customDialer: &tunEOFDialer{remoteR: remR, remoteW: remW},
		customTUN:    &pipeTUNPort{localR: locR, localW: locW},
	})
	defer rig.close()
	ts, _ := ports.NewTUNSpec(ports.TUNModePointToPoint, 9, 9)
	spec, _ := ports.NewForwardTUNSpec(ts)
	info, err := rig.svc.StartForward(context.Background(), ucsess.StartForwardRequest{Plan: mustTestPlan(t, ""), Spec: spec})
	if err != nil {
		t.Fatalf("StartForward(TUN): %v", err)
	}
	var doneCh <-chan struct{}
	if err := rig.svc.WithForwardHandle(context.Background(), info.Handle(), func(_ context.Context, fh ports.ForwardHandle) error {
		doneCh = fh.Done()
		return nil
	}); err != nil {
		t.Fatalf("WithForwardHandle: %v", err)
	}
	// 远端正常关闭发送端产出干净 io.EOF，必须立即触发双向收尾与 Done() 闭合。
	_ = remW.Close()
	<-doneCh
	st, err := rig.svc.InspectForward(context.Background(), info.Handle())
	if err != nil || st.Active() {
		t.Fatalf("远端 EOF 后 InspectForward 必须报告 Active()==false: st=%#v err=%v", st, err)
	}
	if err := rig.svc.StopForward(context.Background(), info.Handle()); err != nil {
		t.Fatalf("StopForward: %v", err)
	}
	assertTeardownClean(t, rig, "DirectTUNEOF")
}

// TestSessionPTYAndTUN_CtxMutexAndHandshakeCancel 验证 WritePTY 持锁阻塞时次调用可经 CtxMutex 及时取消，
// 以及 Direct TUN 建链握手阻塞时立即响应调用方 leaseCtx 取消（0 死锁、0 goleak）。
func TestSessionPTYAndTUN_CtxMutexAndHandshakeCancel(t *testing.T) {
	defer goleak.VerifyNone(t)
	// 1. WritePTY 经 conc.CtxMutex 串行化：首个写入持锁阻塞在无读端 pipe 上，次写入经 CtxMutex 及时响应 ctx 取消。
	writeEntered := make(chan struct{})
	pd := &ptyPipeDialer{noAutoEcho: true, writeEntered: writeEntered}
	rig := newFullSessionRig(t, fullRigOptions{customDialer: pd})
	defer rig.close()
	h, err := rig.svc.OpenPTY(context.Background(), ucsess.OpenPTYRequest{Plan: mustTestPlan(t, "")})
	if err != nil {
		t.Fatalf("OpenPTY: %v", err)
	}
	var secondErr error
	if err := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(ctx context.Context) error {
			_, _ = rig.svc.WritePTY(ctx, h, []byte("block-on-unbuffered-pipe"))
			return nil
		}); gErr != nil {
			return gErr
		}
		<-writeEntered
		cCtx, cancel := context.WithCancel(context.Background())
		if gErr := n.Go(func(context.Context) error {
			cancel()
			return nil
		}); gErr != nil {
			return gErr
		}
		_, secondErr = rig.svc.WritePTY(cCtx, h, []byte("canceled-waiter"))
		_ = rig.svc.ClosePTY(context.Background(), h)
		return nil
	}); err != nil {
		t.Fatalf("RunWait(WritePTY CtxMutex): %v", err)
	}
	if !errors.Is(secondErr, context.Canceled) {
		t.Fatalf("次 WritePTY 取消期望 context.Canceled，实际=%v", secondErr)
	}
	assertTeardownClean(t, rig, "WritePTYCtxMutex")

	// 2. Direct TUN OpenLocalTUN 建链阻塞时取消调用方 ctx（leaseCtx）必须立即返回错误且 0 句柄残留。
	openEntered := make(chan struct{})
	hsRig := newFullSessionRig(t, fullRigOptions{
		profile:   gate.PolicyProfileDirectOperator,
		customTUN: &pipeTUNPort{openEntered: openEntered},
	})
	defer hsRig.close()
	ts, _ := ports.NewTUNSpec(ports.TUNModePointToPoint, 3, 3)
	spec, _ := ports.NewForwardTUNSpec(ts)
	hsCtx, hsCancel := context.WithCancel(context.Background())
	var startErr error
	if err := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error { <-openEntered; hsCancel(); return nil }); gErr != nil {
			return gErr
		}
		_, startErr = hsRig.svc.StartForward(hsCtx, ucsess.StartForwardRequest{Plan: mustTestPlan(t, ""), Spec: spec})
		return nil
	}); err != nil {
		t.Fatalf("RunWait(TUN handshake cancel): %v", err)
	}
	if !errors.Is(startErr, context.Canceled) {
		t.Fatalf("TUN 建链取消期望 context.Canceled，实际=%v", startErr)
	}
	if hsRig.pool.Stats().ActiveHandles != 0 {
		t.Fatalf("TUN 建链取消后 ActiveHandles 必须归零: %+v", hsRig.pool.Stats())
	}
	assertTeardownClean(t, hsRig, "TUNHandshakeCancel")

	// 3. 委托 ForwarderPort.StartForward 窗口内调用方取消 leaseCtx：必须关闭已返回句柄且返 context.Canceled。
	cFwd := &cancelingForwarder{inner: sim.NewSimForwarder()}
	fwdRig := newFullSessionRig(t, fullRigOptions{profile: gate.PolicyProfileDirectOperator, customForwarder: cFwd})
	defer fwdRig.close()
	lSpec, _ := ports.NewForwardSpec(ports.ForwardLocal, "127.0.0.1:18888", "10.0.0.2:80")
	fCtx, fCancel := context.WithCancel(context.Background())
	cFwd.onStart = fCancel
	if _, err := fwdRig.svc.StartForward(fCtx, ucsess.StartForwardRequest{Plan: mustTestPlan(t, ""), Spec: lSpec}); !errors.Is(err, context.Canceled) {
		t.Fatalf("委托 StartForward 建链期取消期望 context.Canceled，实际=%v", err)
	}
	if cFwd.lastHandle == nil || cFwd.lastHandle.IsValid() || fwdRig.pool.Stats().ActiveHandles != 0 {
		t.Fatalf("建链期取消后底层 ForwardHandle 必须已关闭且 0 句柄残留: active=%d", fwdRig.pool.Stats().ActiveHandles)
	}
	assertTeardownClean(t, fwdRig, "DelegatedForwardHandshakeCancel")
}

type cancelingForwarder struct {
	inner      *sim.SimForwarder
	onStart    func()
	lastHandle ports.ForwardHandle
}

func (f *cancelingForwarder) StartForward(ctx context.Context, transport ports.TunnelTransport, spec ports.ForwardSpec) (ports.ForwardHandle, error) {
	h, err := f.inner.StartForward(ctx, transport, spec)
	f.lastHandle = h
	if f.onStart != nil {
		f.onStart()
	}
	return h, err
}

type failingForwardHandle struct {
	spec      ports.ForwardSpec
	boundAddr string
	doneCh    chan struct{}
	closeOnce sync.Once
	err       atomic.Value
}

func (h *failingForwardHandle) IsValid() bool {
	select {
	case <-h.doneCh:
		return false
	default:
		return true
	}
}
func (h *failingForwardHandle) Spec() ports.ForwardSpec { return h.spec }
func (h *failingForwardHandle) BoundAddr() string       { return h.boundAddr }
func (h *failingForwardHandle) Done() <-chan struct{}   { return h.doneCh }
func (h *failingForwardHandle) Err() error {
	if v := h.err.Load(); v != nil {
		if err, ok := v.(error); ok {
			return err
		}
	}
	return nil
}
func (h *failingForwardHandle) Close() error {
	h.closeOnce.Do(func() { close(h.doneCh) })
	return nil
}
func (h *failingForwardHandle) fail(err error) {
	if err != nil {
		h.err.Store(err)
	}
	h.closeOnce.Do(func() { close(h.doneCh) })
}

type failingForwarder struct {
	last *failingForwardHandle
}

func (f *failingForwarder) StartForward(_ context.Context, _ ports.TunnelTransport, spec ports.ForwardSpec) (ports.ForwardHandle, error) {
	h := &failingForwardHandle{spec: spec, boundAddr: spec.BindAddr(), doneCh: make(chan struct{})}
	f.last = h
	return h, nil
}

// TestForwardInfo_DoneAndWaitAllTerminationPaths 验证 #160 Major-2：
//   - 零值 ForwardInfo 失败关闭（Done()==nil、Wait 返回 ErrInvalidRequest / ErrNilContext）；
//   - 正常 StopForward 后 Done() 关闭且 Wait(ctx) 返回 nil；
//   - 等待期取消调用方 ctx 立即返回 context.Canceled 且转发保持活跃；
//   - 上游/底层转发故障关闭时 Done() 关闭且 Wait(ctx) 传播终态错误。
func TestForwardInfo_DoneAndWaitAllTerminationPaths(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()

	// 1. 零值失败关闭。
	var zeroInfo ucsess.ForwardInfo
	if zeroInfo.Done() != nil {
		t.Fatal("零值 ForwardInfo.Done() 必须返回 nil")
	}
	if err := zeroInfo.Wait(ctx); !errors.Is(err, ucsess.ErrInvalidRequest) || !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("零值 ForwardInfo.Wait 期望 ErrInvalidRequest/ErrInvalidArgument，实际=%v", err)
	}
	var nilCtx context.Context
	if err := zeroInfo.Wait(nilCtx); !errors.Is(err, ucsess.ErrNilContext) || !errors.Is(err, ports.ErrNilContext) {
		t.Fatalf("nil ctx Wait 期望 ErrNilContext，实际=%v", err)
	}

	// 2. 正常 StopForward 与等待期 ctx 取消。
	rig := newFullSessionRig(t, fullRigOptions{profile: gate.PolicyProfileDirectOperator})
	defer rig.close()
	spec, _ := ports.NewForwardSpec(ports.ForwardLocal, "127.0.0.1:18901", "10.0.0.5:80")
	info, err := rig.svc.StartForward(ctx, ucsess.StartForwardRequest{Plan: mustTestPlan(t, ""), Spec: spec})
	if err != nil {
		t.Fatalf("StartForward: %v", err)
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	if err := info.Wait(cancelCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("取消 ctx Wait 期望 context.Canceled，实际=%v", err)
	}
	if err := rig.svc.StopForward(ctx, info.Handle()); err != nil {
		t.Fatalf("StopForward: %v", err)
	}
	<-info.Done()
	if err := info.Wait(ctx); err != nil {
		t.Fatalf("正常 StopForward 后 Wait(ctx) 期望 nil，实际=%v", err)
	}
	assertTeardownClean(t, rig, "ForwardWaitStop")

	// 3. 底层转发故障退出：Done() 关闭且 Wait(ctx) 精确返回故障错误。
	dropErr := errors.New("forward upstream broken")
	ff := &failingForwarder{}
	dRig := newFullSessionRig(t, fullRigOptions{profile: gate.PolicyProfileDirectOperator, customForwarder: ff})
	defer dRig.close()
	dInfo, err := dRig.svc.StartForward(ctx, ucsess.StartForwardRequest{Plan: mustTestPlan(t, ""), Spec: spec})
	if err != nil {
		t.Fatalf("StartForward(fail): %v", err)
	}
	ff.last.fail(dropErr)
	<-dInfo.Done()
	if err := dInfo.Wait(ctx); !errors.Is(err, dropErr) {
		t.Fatalf("转发故障终止后 Wait(ctx) 期望 %v，实际=%v", dropErr, err)
	}
	_ = dRig.svc.StopForward(ctx, dInfo.Handle())
	assertTeardownClean(t, dRig, "ForwardWaitDrop")
}
