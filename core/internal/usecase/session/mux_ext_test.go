package session_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/sim"
	ucsess "github.com/wentf9/xops-cli/core/internal/usecase/session"
	"github.com/wentf9/xops-cli/core/ports"
)

// denyConfirmInteraction 包装 SimInteractionPort 并强制 Confirm 返回 VerdictDeny，测试 ask/autoask 拒绝分支。
type denyConfirmInteraction struct{ inner *sim.SimInteractionPort }

func (d *denyConfirmInteraction) CanInteract() bool { return d.inner.CanInteract() }
func (d *denyConfirmInteraction) Confirm(context.Context, ports.ConfirmRequest) (security.Verdict, error) {
	return security.VerdictDeny, nil
}
func (d *denyConfirmInteraction) PromptApproval(ctx context.Context, env security.ApprovalEnvelope) (ports.ApprovalDecisionResponse, error) {
	return d.inner.PromptApproval(ctx, env)
}
func (d *denyConfirmInteraction) PromptText(ctx context.Context, req ports.TextPromptRequest) (string, error) {
	return d.inner.PromptText(ctx, req)
}

//xops:syncclosure
//xops:borrowed
func (d *denyConfirmInteraction) PromptSecret(ctx context.Context, req ports.SecretPromptRequest, fn func(box *secret.SecretBox) error) error {
	return d.inner.PromptSecret(ctx, req, func(box *secret.SecretBox) error { return fn(box) })
}

// pipeEchoConn 基于内存 io.Pipe 提供支持半关闭的阻塞回显 net.Conn，用于确定性验证 RunMuxProxy 双向中继（0 协程/0 睡眠）。
type pipeEchoConn struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func newPipeEchoConn() *pipeEchoConn {
	r, w := io.Pipe()
	return &pipeEchoConn{r: r, w: w}
}

func (c *pipeEchoConn) Read(p []byte) (int, error)       { return c.r.Read(p) }
func (c *pipeEchoConn) Write(p []byte) (int, error)      { return c.w.Write(p) }
func (c *pipeEchoConn) CloseWrite() error                { return c.w.Close() }
func (c *pipeEchoConn) Close() error                     { return errors.Join(c.w.Close(), c.r.Close()) }
func (c *pipeEchoConn) LocalAddr() net.Addr              { return &net.UnixAddr{Name: "pipe-local", Net: "unix"} }
func (c *pipeEchoConn) RemoteAddr() net.Addr             { return &net.UnixAddr{Name: "pipe-remote", Net: "unix"} }
func (c *pipeEchoConn) SetDeadline(time.Time) error      { return nil }
func (c *pipeEchoConn) SetReadDeadline(time.Time) error  { return nil }
func (c *pipeEchoConn) SetWriteDeadline(time.Time) error { return nil }

// spoofDialMuxSocket 包装 SimMuxSocket，支持按需覆盖 DialMux（测试身份失配）或 OpenProxy（测试阻塞双向中继）。
type spoofDialMuxSocket struct {
	inner     *sim.SimMuxSocket
	spoofConn ports.TransportConn
	pipeProxy bool
}

func (s *spoofDialMuxSocket) Probe(ctx context.Context, p pathalg.LocalSourcePath) (ports.MuxControlResponse, error) {
	return s.inner.Probe(ctx, p)
}
func (s *spoofDialMuxSocket) Control(ctx context.Context, req ports.MuxControlRequest) (ports.MuxControlResponse, error) {
	return s.inner.Control(ctx, req)
}
func (s *spoofDialMuxSocket) DialMux(ctx context.Context, p pathalg.LocalSourcePath, d plan.HopDigest, ep netaddr.Endpoint) (ports.TransportConn, error) {
	if s.spoofConn != nil {
		return s.spoofConn, nil
	}
	return s.inner.DialMux(ctx, p, d, ep)
}
func (s *spoofDialMuxSocket) OpenProxy(ctx context.Context, p pathalg.LocalSourcePath) (net.Conn, error) {
	if s.pipeProxy {
		return newPipeEchoConn(), nil
	}
	return s.inner.OpenProxy(ctx, p)
}
func (s *spoofDialMuxSocket) Serve(ctx context.Context, ln net.Listener, up ports.TransportConn, fwd ports.ForwarderPort) error {
	return s.inner.Serve(ctx, ln, up, fwd)
}

//xops:syncclosure
//xops:borrowed
func (s *spoofDialMuxSocket) WithListener(ctx context.Context, p pathalg.LocalSourcePath, fn func(ln net.Listener) error) error {
	return s.inner.WithListener(ctx, p, func(ln net.Listener) error { return fn(ln) })
}

var (
	_ ports.InteractionPort = (*denyConfirmInteraction)(nil)
	_ ports.MuxSocketPort   = (*spoofDialMuxSocket)(nil)
)

func mustPlanWithControl(t *testing.T, cp option.ControlPolicy, withJump bool) plan.SealedConnectionPlan {
	t.Helper()
	auth, err := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	if err != nil {
		t.Fatalf("NewAuthAgent: %v", err)
	}
	u, _ := option.ParseUsername("ops")
	var hops []plan.HopSpec
	if withJump {
		jh, _ := netaddr.ParseCanonicalHost("198.51.100.10")
		jep, _ := netaddr.NewEndpoint(jh, 2222)
		jeff, err := option.ResolveEffectivePolicy(option.OriginAdHoc, jep, option.UnsetOptionLayer(), option.UnsetOptionLayer(), option.UnsetOptionLayer(), option.UnsetOptionLayer())
		if err != nil {
			t.Fatalf("ResolveEffectivePolicy(jump): %v", err)
		}
		jHop, err := plan.NewHopSpecFromAuth(0, "bastion-01", u, auth, jeff)
		if err != nil {
			t.Fatalf("NewHopSpecFromAuth(jump): %v", err)
		}
		hops = append(hops, jHop)
	}
	th, _ := netaddr.ParseCanonicalHost("198.51.100.42")
	tep, _ := netaddr.NewEndpoint(th, 22)
	layer := option.UnsetOptionLayer().WithControlPolicy(cp)
	eff, err := option.ResolveEffectivePolicy(option.OriginAdHoc, tep, layer, option.UnsetOptionLayer(), option.UnsetOptionLayer(), option.UnsetOptionLayer())
	if err != nil {
		t.Fatalf("ResolveEffectivePolicy(target): %v", err)
	}
	tHop, err := plan.NewHopSpecFromAuth(uint32(len(hops)), "app-01", u, auth, eff)
	if err != nil {
		t.Fatalf("NewHopSpecFromAuth(target): %v", err)
	}
	hops = append(hops, tHop)
	pl, err := plan.SealConnectionPlan(hops...)
	if err != nil {
		t.Fatalf("SealConnectionPlan: %v", err)
	}
	return pl
}

func TestSessionMux_EffectivePolicyProjectionFailClosed(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newFullSessionRig(t, fullRigOptions{profile: gate.PolicyProfileDirectOperator})
	defer rig.close()

	// ControlPath=none 即使 ControlMaster=yes 且 ControlPersist=60s，EffectiveMaster/EffectivePersist 投影也必为 no。
	persist60, _ := option.ParseControlPersist("60s")
	disabledCP := option.UnsetControlPolicy().
		WithMaster(option.ControlMasterYes).
		WithPath(option.DisabledControlPath()).
		WithPersist(persist60)
	disabledPlan := mustPlanWithControl(t, disabledCP, false)
	explicitSock, _ := pathalg.ParseLocalSourcePath("/tmp/should-not-bypass.sock")

	if _, err := rig.svc.StartControlMaster(context.Background(), ucsess.ControlMasterRequest{Plan: disabledPlan}); !errors.Is(err, ucsess.ErrControlMasterDisabled) {
		t.Fatalf("ControlPath=none 时 StartControlMaster 必须失败关闭: %v", err)
	}
	if _, err := rig.svc.ProbeMux(context.Background(), ucsess.MuxRequest{Plan: disabledPlan, SocketPath: algebraic.Some(explicitSock)}); !errors.Is(err, ucsess.ErrControlMasterDisabled) {
		t.Fatalf("ControlPath=none 时 ProbeMux 不得被显式 SocketPath 绕过: %v", err)
	}
	if _, err := rig.svc.ControlMux(context.Background(), ucsess.MuxControlRequest{
		Target: ucsess.MuxRequest{Plan: disabledPlan}, Action: ports.MuxActionCheck,
	}); !errors.Is(err, ucsess.ErrControlMasterDisabled) {
		t.Fatalf("ControlPath=none 时 ControlMux 必须失败关闭: %v", err)
	}
	if err := rig.svc.WithMuxProxy(context.Background(), ucsess.MuxRequest{Plan: disabledPlan}, func(context.Context, net.Conn) error { return nil }); !errors.Is(err, ucsess.ErrControlMasterDisabled) {
		t.Fatalf("ControlPath=none 时 WithMuxProxy 必须失败关闭: %v", err)
	}
	if err := rig.svc.WithMuxConn(context.Background(), ucsess.MuxRequest{Plan: disabledPlan}, func(context.Context, ports.TransportConn) error { return nil }); !errors.Is(err, ucsess.ErrControlMasterDisabled) {
		t.Fatalf("ControlPath=none 时 WithMuxConn 必须失败关闭: %v", err)
	}

	// ControlPath=unset + ControlMaster=yes 与 ControlMaster=no + 合法 Path 均须拒绝启动。
	unsetPathPlan := mustPlanWithControl(t, option.UnsetControlPolicy().WithMaster(option.ControlMasterYes), false)
	if _, err := rig.svc.StartControlMaster(context.Background(), ucsess.ControlMasterRequest{Plan: unsetPathPlan}); !errors.Is(err, ucsess.ErrControlMasterDisabled) {
		t.Fatalf("ControlPath=unset 时 StartControlMaster 必须拒绝: %v", err)
	}
	litPath, _ := option.NewLiteralControlPath("/tmp/no-master.sock")
	masterNoPlan := mustPlanWithControl(t, option.UnsetControlPolicy().WithPath(litPath).WithMaster(option.ControlMasterNo), false)
	if _, err := rig.svc.StartControlMaster(context.Background(), ucsess.ControlMasterRequest{Plan: masterNoPlan}); !errors.Is(err, ucsess.ErrControlMasterDisabled) {
		t.Fatalf("ControlMaster=no 时 StartControlMaster 必须拒绝: %v", err)
	}
	if rig.dialer.DialCount() != 0 {
		t.Fatalf("失败关闭拦截后禁止拨号: dials=%d", rig.dialer.DialCount())
	}
}

func TestSessionMux_TemplateExpansionMasterReuseAndConfirm(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newFullSessionRig(t, fullRigOptions{profile: gate.PolicyProfileDirectOperator, interactive: true})
	defer rig.close()

	tplPath, err := option.ParseControlPath("~/.xops/mux-%r@%h-%p-%j-%C.sock")
	if err != nil {
		t.Fatalf("ParseControlPath: %v", err)
	}
	autoCP := option.UnsetControlPolicy().WithMaster(option.ControlMasterAuto).WithPath(tplPath).WithPersist(option.IndefiniteControlPersist())
	pl := mustPlanWithControl(t, autoCP, true)

	// 1. 首次 auto 启动新主进程，且模板 %r/%h/%p/%j/%C 与 ~/ 正确展开。
	info1, err := rig.svc.StartControlMaster(context.Background(), ucsess.ControlMasterRequest{Plan: pl})
	if err != nil || !info1.IsValid() || info1.ReusedExisting() {
		t.Fatalf("首次 StartControlMaster(auto) 失败: info=%#v err=%v", info1, err)
	}
	sockStr := info1.SocketPath().String()
	if !strings.HasPrefix(sockStr, "/home/alice/.xops/mux-ops@198.51.100.42-22-198.51.100.10-") || strings.Contains(sockStr, "%") {
		t.Fatalf("ControlPath 模板展开异常: %q", sockStr)
	}
	h1, ok := info1.Handle().Get()
	if !ok || !h1.IsValid() {
		t.Fatalf("新启主进程必须返回有效 KindMux 句柄")
	}

	// 2. 第二次 auto 应探活复用已有主进程，零新增拨号。
	dialsBefore := rig.dialer.DialCount()
	info2, err := rig.svc.StartControlMaster(context.Background(), ucsess.ControlMasterRequest{Plan: pl})
	if err != nil || !info2.IsValid() || !info2.ReusedExisting() || info2.MasterPID() == 0 || !info2.Handle().IsNone() {
		t.Fatalf("二次 StartControlMaster(auto) 复用失败: info=%#v err=%v", info2, err)
	}
	if rig.dialer.DialCount() != dialsBefore {
		t.Fatalf("复用已有主进程禁止重拨: before=%d after=%d", dialsBefore, rig.dialer.DialCount())
	}
	if err := rig.svc.StopControlMaster(context.Background(), h1); err != nil {
		t.Fatalf("StopControlMaster: %v", err)
	}
	assertTeardownClean(t, rig, "StopControlMaster")

	// 3. ControlMaster=ask / autoask 确认拒绝与非交互不可用必须失败关闭。
	askPath, _ := option.NewLiteralControlPath("/tmp/mux-ask.sock")
	askPlan := mustPlanWithControl(t, option.UnsetControlPolicy().WithMaster(option.ControlMasterAsk).WithPath(askPath), false)
	denyRig := newFullSessionRig(t, fullRigOptions{
		interactive:       true,
		customInteraction: &denyConfirmInteraction{inner: sim.NewSimInteractionPort(true)},
	})
	defer denyRig.close()
	if _, err := denyRig.svc.StartControlMaster(context.Background(), ucsess.ControlMasterRequest{Plan: askPlan}); !errors.Is(err, ucsess.ErrMuxMasterUnavailable) {
		t.Fatalf("ask 被操作员拒绝期望 ErrMuxMasterUnavailable，实际=%v", err)
	}
	nonInterRig := newFullSessionRig(t, fullRigOptions{interactive: false})
	defer nonInterRig.close()
	if _, err := nonInterRig.svc.StartControlMaster(context.Background(), ucsess.ControlMasterRequest{Plan: askPlan}); !errors.Is(err, ports.ErrInteractionUnavailable) {
		t.Fatalf("非交互下 ask 期望 ErrInteractionUnavailable，实际=%v", err)
	}
}

func TestSessionMux_ControlActionsProxyAndVerifiedDialMux(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newFullSessionRig(t, fullRigOptions{profile: gate.PolicyProfileDirectOperator})
	defer rig.close()

	litPath, _ := option.NewLiteralControlPath("/tmp/mux-full.sock")
	cp := option.UnsetControlPolicy().WithMaster(option.ControlMasterYes).WithPath(litPath).WithPersist(option.IndefiniteControlPersist())
	pl := mustPlanWithControl(t, cp, false)
	info, err := rig.svc.StartControlMaster(context.Background(), ucsess.ControlMasterRequest{Plan: pl})
	if err != nil {
		t.Fatalf("StartControlMaster: %v", err)
	}
	h, _ := info.Handle().Get()

	assertMuxControlActions(t, rig, pl)
	assertMuxProxyAndDialVerified(t, rig, pl)

	// ControlMux(Exit) 触发 Serve 退出并自动释放 SlotMap 句柄（ActiveHandles==0）。
	if _, err := rig.svc.ControlMux(context.Background(), ucsess.MuxControlRequest{
		Target: ucsess.MuxRequest{Plan: pl}, Action: ports.MuxActionExit,
	}); err != nil {
		t.Fatalf("ControlMux(Exit): %v", err)
	}
	waitUntil(t, func() bool { return rig.pool.Stats().ActiveHandles == 0 })
	assertTeardownClean(t, rig, "ControlMux(Exit)")
	if _, err := rig.svc.InspectControlMaster(context.Background(), h); err == nil {
		t.Fatalf("Exit 后旧 ControlMaster 句柄必须已失效")
	}
	if pResp, err := rig.svc.ProbeMux(context.Background(), ucsess.MuxRequest{Plan: pl}); err != nil || pResp.Alive() {
		t.Fatalf("Exit 后套接字必须已释放: resp=%#v err=%v", pResp, err)
	}
}

func assertMuxControlActions(t *testing.T, rig *fullSessionRig, pl plan.SealedConnectionPlan) {
	t.Helper()
	pResp, err := rig.svc.ProbeMux(context.Background(), ucsess.MuxRequest{Plan: pl})
	if err != nil || !pResp.Alive() || pResp.MasterPID() == 0 {
		t.Fatalf("ProbeMux 失配: resp=%#v err=%v", pResp, err)
	}
	cResp, err := rig.svc.ControlMux(context.Background(), ucsess.MuxControlRequest{Target: ucsess.MuxRequest{Plan: pl}, Action: ports.MuxActionCheck})
	if err != nil || !cResp.Alive() {
		t.Fatalf("ControlMux(Check): resp=%#v err=%v", cResp, err)
	}
	fwdSpec, _ := ports.NewForwardSpec(ports.ForwardLocal, "127.0.0.1:22000", "10.0.0.5:80")
	if _, err := rig.svc.ControlMux(context.Background(), ucsess.MuxControlRequest{
		Target: ucsess.MuxRequest{Plan: pl}, Action: ports.MuxActionForward, Forward: algebraic.Some(fwdSpec),
	}); err != nil {
		t.Fatalf("ControlMux(Forward): %v", err)
	}
	if _, err := rig.svc.ControlMux(context.Background(), ucsess.MuxControlRequest{
		Target: ucsess.MuxRequest{Plan: pl}, Action: ports.MuxActionCancel, Forward: algebraic.Some(fwdSpec),
	}); err != nil {
		t.Fatalf("ControlMux(Cancel): %v", err)
	}
	if _, err := rig.svc.ControlMux(context.Background(), ucsess.MuxControlRequest{
		Target: ucsess.MuxRequest{Plan: pl}, Action: ports.MuxActionProxy,
	}); !errors.Is(err, ucsess.ErrInvalidRequest) {
		t.Fatalf("ControlMux(Proxy) 必须失败关闭: %v", err)
	}
}

func assertMuxProxyAndDialVerified(t *testing.T, rig *fullSessionRig, pl plan.SealedConnectionPlan) {
	t.Helper()
	if err := rig.svc.WithMuxProxy(context.Background(), ucsess.MuxRequest{Plan: pl}, func(_ context.Context, conn net.Conn) error {
		if _, wErr := conn.Write([]byte("mux-proxy-ping")); wErr != nil {
			return wErr
		}
		buf := make([]byte, 32)
		n, rErr := conn.Read(buf)
		if rErr != nil || string(buf[:n]) != "mux-proxy-ping" {
			return errors.New("proxy echo mismatch")
		}
		return nil
	}); err != nil {
		t.Fatalf("WithMuxProxy: %v", err)
	}
	proxyRig := newFullSessionRig(t, fullRigOptions{
		customMux: &spoofDialMuxSocket{inner: rig.muxSocket, pipeProxy: true},
	})
	defer proxyRig.close()
	var proxyOut bytes.Buffer
	if err := proxyRig.svc.RunMuxProxy(context.Background(), ucsess.MuxRequest{Plan: pl}, bytes.NewBufferString("stdio-relay"), &proxyOut); err != nil {
		t.Fatalf("RunMuxProxy: %v", err)
	}
	if proxyOut.String() != "stdio-relay" {
		t.Fatalf("RunMuxProxy 输出失配: %q", proxyOut.String())
	}
	if err := rig.svc.WithMuxConn(context.Background(), ucsess.MuxRequest{Plan: pl}, func(dCtx context.Context, conn ports.TransportConn) error {
		sess, sErr := conn.OpenSession(dCtx)
		if sErr != nil {
			return sErr
		}
		return sess.Close()
	}); err != nil {
		t.Fatalf("WithMuxConn(valid): %v", err)
	}
	spoofHost, _ := netaddr.ParseCanonicalHost("203.0.113.99")
	spoofEP, _ := netaddr.NewEndpoint(spoofHost, 22)
	spoofLeaf, _ := pl.HopDigestAt(pl.Len() - 1)
	spoofConn := &spyConn{owner: &spyDialer{}, dig: spoofLeaf, ep: spoofEP}
	spoofRig := newFullSessionRig(t, fullRigOptions{
		customMux: &spoofDialMuxSocket{inner: sim.NewSimMuxSocket(nil), spoofConn: spoofConn},
	})
	defer spoofRig.close()
	if err := spoofRig.svc.WithMuxConn(context.Background(), ucsess.MuxRequest{Plan: pl}, func(context.Context, ports.TransportConn) error {
		return nil
	}); !errors.Is(err, ucsess.ErrMuxMasterUnavailable) || spoofConn.IsAlive() {
		t.Fatalf("身份失配的 DialMux 必须拒绝且关闭连接: err=%v alive=%v", err, spoofConn.IsAlive())
	}
}

func TestSessionMux_ControlPersistDeterministicTimerAndRevocation(t *testing.T) {
	defer goleak.VerifyNone(t)
	litPath, _ := option.NewLiteralControlPath("/tmp/mux-persist.sock")
	persist10, _ := option.ParseControlPersist("10s")
	cp := option.UnsetControlPolicy().WithMaster(option.ControlMasterYes).WithPath(litPath).WithPersist(persist10)
	pl := mustPlanWithControl(t, cp, false)

	assertMuxPersistTouchAndExpire(t, pl)
	for _, mode := range []string{"RetireHop", "GateHalted", "PoolClose"} {
		t.Run(mode, func(t *testing.T) { assertMuxRevocationMode(t, pl, mode) })
	}
}

func assertMuxPersistTouchAndExpire(t *testing.T, pl plan.SealedConnectionPlan) {
	t.Helper()
	rig := newFullSessionRig(t, fullRigOptions{profile: gate.PolicyProfileDirectOperator})
	defer rig.close()
	baseTimers := rig.clk.PendingTimers()
	info, err := rig.svc.StartControlMaster(context.Background(), ucsess.ControlMasterRequest{Plan: pl})
	if err != nil {
		t.Fatalf("StartControlMaster(persist=10s): %v", err)
	}
	h, _ := info.Handle().Get()
	if err := rig.clk.WaitPending(context.Background(), baseTimers+1); err != nil {
		t.Fatalf("WaitPending(persist timer): %v", err)
	}
	rig.clk.Advance(6 * time.Second)
	if err := rig.svc.TouchControlMaster(context.Background(), h); err != nil {
		t.Fatalf("TouchControlMaster: %v", err)
	}
	rig.clk.Advance(6 * time.Second)
	st, err := rig.svc.InspectControlMaster(context.Background(), h)
	if err != nil || !st.Active() {
		t.Fatalf("Touch 后 6s ControlMaster 必须仍活跃: st=%#v err=%v", st, err)
	}
	rig.clk.Advance(10 * time.Second)
	waitUntil(t, func() bool { return rig.pool.Stats().ActiveHandles == 0 })
	// ActiveHandles 归零前 WithListener 已退出解绑，此处直接 ProbeMux 即可确定性观测套接字释放，
	// 随后再等待 pool.scheduleResourceClose 收敛确认 0 拆断升级与 0 协程泄漏。
	pResp, err := rig.svc.ProbeMux(context.Background(), ucsess.MuxRequest{Plan: pl})
	if err != nil || pResp.Alive() {
		t.Fatalf("Persist 过期后套接字必须已释放: resp=%#v err=%v", pResp, err)
	}
	assertTeardownClean(t, rig, "ControlPersistExpired")
}

func assertMuxRevocationMode(t *testing.T, pl plan.SealedConnectionPlan, mode string) {
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
	r2 := newFullSessionRig(t, opt)
	defer r2.close()
	inf, err := r2.svc.StartControlMaster(context.Background(), ucsess.ControlMasterRequest{
		Plan: pl, Risk: algebraic.Some(security.RiskSafe),
	})
	if err != nil {
		t.Fatalf("StartControlMaster(%s): %v", mode, err)
	}
	mh, _ := inf.Handle().Get()
	switch mode {
	case "RetireHop":
		leaf, _ := pl.HopDigestAt(pl.Len() - 1)
		_ = r2.pool.RetireHop(leaf)
	case "GateHalted":
		faultArmed.Store(true)
		_, _ = r2.svc.Exec(context.Background(), ucsess.ExecRequest{Plan: pl, Command: mustCommandPlan(t, "id"), Risk: algebraic.Some(security.RiskSafe)})
	case "PoolClose":
		_ = r2.pool.Close()
	}
	if _, err := r2.svc.InspectControlMaster(context.Background(), mh); err == nil {
		t.Fatalf("%s 吊销后 InspectControlMaster 必须失败", mode)
	}
	if r2.pool.Stats().ActiveHandles != 0 {
		t.Fatalf("%s 吊销后 ActiveHandles 必须归零: %+v", mode, r2.pool.Stats())
	}
	assertTeardownClean(t, r2, "MuxRevocation/"+mode)
	if pResp, err := r2.muxSocket.Probe(context.Background(), inf.SocketPath()); err != nil || pResp.Alive() {
		t.Fatalf("%s 吊销后底层监听套接字必须已释放: resp=%#v err=%v", mode, pResp, err)
	}
}

func assertTeardownClean(t *testing.T, rig *fullSessionRig, label string) {
	t.Helper()
	if err := rig.pool.WaitPendingTeardowns(context.Background()); err != nil {
		t.Fatalf("%s WaitPendingTeardowns: %v", label, err)
	}
	if esc := rig.pool.Stats().TeardownEscalations; esc != 0 {
		t.Fatalf("%s 不得触发有界拆断升级: escalations=%d", label, esc)
	}
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	waitUntilErr(t, func() (bool, error) { return cond(), nil })
}

func waitUntilErr(t *testing.T, cond func() (bool, error)) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		ok, err := cond()
		if err != nil {
			t.Fatalf("等待状态收敛出错: %v", err)
		}
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("等待状态收敛超时")
		}
		runtime.Gosched()
	}
}
