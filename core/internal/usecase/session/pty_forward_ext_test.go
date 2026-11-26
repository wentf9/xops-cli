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
	mu          sync.Mutex
	dialCount   atomic.Int32
	resizes     []ports.TerminalSize
	signals     []string
	lastSession *ptyPipeSession
	noAutoEcho  bool
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

func (s *ptyPipeSession) StdinPipe() (io.WriteCloser, error) {
	s.inR, s.inW = io.Pipe()
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

func assertSingleDirectTUNForward(t *testing.T, rig *fullSessionRig, pl plan.SealedConnectionPlan, mode ports.TUNMode, pref string) {
	t.Helper()
	ts, _ := ports.NewTUNSpec(mode, ports.TUNUnitAny, 1)
	fSpec, _ := ports.NewForwardTUNSpec(ts)
	info, err := rig.svc.StartForward(context.Background(), ucsess.StartForwardRequest{Plan: pl, Spec: fSpec})
	if err != nil || !info.IsValid() || len(info.BoundAddr()) < 4 || info.BoundAddr()[:3] != pref {
		t.Fatalf("Direct TUN(%v) 失败: info=%#v err=%v", mode, info, err)
	}
	if err := rig.svc.WithForwardHandle(context.Background(), info.Handle(), func(_ context.Context, fh ports.ForwardHandle) error {
		if !fh.IsValid() || fh.BoundAddr() != info.BoundAddr() {
			return errors.New("unexpected direct TUN ForwardHandle")
		}
		return nil
	}); err != nil {
		t.Fatalf("WithForwardHandle(TUN): %v", err)
	}
	if err := rig.svc.StopForward(context.Background(), info.Handle()); err != nil {
		t.Fatalf("StopForward(TUN): %v", err)
	}
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
}
