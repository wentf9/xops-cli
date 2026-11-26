package session_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
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
	return mustPlanWithControlRoute(t, cp, withJump, nil)
}

func mustPlanWithControlRoute(t *testing.T, cp option.ControlPolicy, withJump bool, explicitRoute option.ProxyRoute) plan.SealedConnectionPlan {
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
	if explicitRoute != nil {
		layer = layer.WithProxyRoute(explicitRoute)
	} else if withJump {
		pj, err := option.ParseProxyJump("ops@198.51.100.10:2222")
		if err != nil {
			t.Fatalf("ParseProxyJump: %v", err)
		}
		layer = layer.WithProxyRoute(pj)
	}
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
	if err := proxyRig.svc.RunMuxProxy(context.Background(), ucsess.MuxRequest{Plan: pl}, io.NopCloser(bytes.NewBufferString("stdio-relay")), &proxyOut); err != nil {
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

func TestSessionMux_ControlPersistConcurrentRaceWithCloseHaltAndStop(t *testing.T) {
	defer goleak.VerifyNone(t)
	litPath, _ := option.NewLiteralControlPath("/tmp/mux-persist-race.sock")
	persist10, _ := option.ParseControlPersist("10s")
	cp := option.UnsetControlPolicy().WithMaster(option.ControlMasterYes).WithPath(litPath).WithPersist(persist10)
	pl := mustPlanWithControl(t, cp, false)
	for _, mode := range []string{"PoolClose", "StopControlMaster", "RetireHop", "GateHalted"} {
		t.Run(mode, func(t *testing.T) { assertMuxPersistConcurrentRace(t, pl, mode) })
	}
}

func assertMuxPersistConcurrentRace(t *testing.T, pl plan.SealedConnectionPlan, mode string) {
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
	baseTimers := rig.clk.PendingTimers()
	inf, err := rig.svc.StartControlMaster(context.Background(), ucsess.ControlMasterRequest{
		Plan: pl, Risk: algebraic.Some(security.RiskSafe),
	})
	if err != nil {
		t.Fatalf("StartControlMaster(%s): %v", mode, err)
	}
	mh, _ := inf.Handle().Get()
	if err := rig.clk.WaitPending(context.Background(), baseTimers+1); err != nil {
		t.Fatalf("WaitPending(%s): %v", mode, err)
	}
	// 同时触发 ControlPersist 过期自释放与外部关闭/吊销，验证绝不自等待死锁且 0 泄漏。
	if err := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		start := make(chan struct{})
		if gErr := n.Go(func(context.Context) error {
			<-start
			rig.clk.Advance(10 * time.Second)
			return nil
		}); gErr != nil {
			return gErr
		}
		if gErr := n.Go(func(context.Context) error {
			<-start
			triggerMuxAdversary(t, rig, pl, mh, mode, &faultArmed)
			return nil
		}); gErr != nil {
			return gErr
		}
		close(start)
		return nil
	}); err != nil {
		t.Fatalf("RunWait(%s): %v", mode, err)
	}
	waitUntil(t, func() bool { return rig.pool.Stats().ActiveHandles == 0 })
	// 注意：本并发对抗用例在同一 SimClock 上同时 Advance(10s) 与触发 90ms 拆断宽限，虚拟时钟跨越 90ms 属预期，
	// 此处重点验证 WaitPendingTeardowns 无死锁收敛、底层套接字彻底释放且 goleak 零泄漏。
	if err := rig.pool.WaitPendingTeardowns(context.Background()); err != nil {
		t.Fatalf("PersistRace/%s WaitPendingTeardowns: %v", mode, err)
	}
	if pResp, err := rig.muxSocket.Probe(context.Background(), inf.SocketPath()); err != nil || pResp.Alive() {
		t.Fatalf("%s 并发竞态后套接字必须已释放: resp=%#v err=%v", mode, pResp, err)
	}
}

func triggerMuxAdversary(t *testing.T, rig *fullSessionRig, pl plan.SealedConnectionPlan, mh plan.ManagedHandle[plan.KindMux], mode string, faultArmed *atomic.Bool) {
	switch mode {
	case "PoolClose":
		_ = rig.pool.Close()
	case "StopControlMaster":
		_ = rig.svc.StopControlMaster(context.Background(), mh)
	case "RetireHop":
		leaf, _ := pl.HopDigestAt(pl.Len() - 1)
		_ = rig.pool.RetireHop(leaf)
	case "GateHalted":
		faultArmed.Store(true)
		_, _ = rig.svc.Exec(context.Background(), ucsess.ExecRequest{Plan: pl, Command: mustCommandPlan(t, "id"), Risk: algebraic.Some(security.RiskSafe)})
	}
}

// blockingProxyConn 用于对抗验证 RunMuxProxy 远端先达 EOF、stdin 故障与阻塞写/取消路径（0 死锁、0 goleak）。
type blockingProxyConn struct {
	eofImmediately bool
	readEntered    chan struct{}
	readOnce       sync.Once
	closed         chan struct{}
	closeOnce      sync.Once
}

func newBlockingProxyConn(eofImmediately bool) *blockingProxyConn {
	return &blockingProxyConn{eofImmediately: eofImmediately, readEntered: make(chan struct{}), closed: make(chan struct{})}
}
func (c *blockingProxyConn) Read([]byte) (int, error) {
	c.readOnce.Do(func() { close(c.readEntered) })
	if c.eofImmediately {
		return 0, io.EOF
	}
	<-c.closed
	return 0, net.ErrClosed
}
func (c *blockingProxyConn) Write([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}
func (c *blockingProxyConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}
func (c *blockingProxyConn) LocalAddr() net.Addr              { return &net.UnixAddr{Name: "blk-l", Net: "unix"} }
func (c *blockingProxyConn) RemoteAddr() net.Addr             { return &net.UnixAddr{Name: "blk-r", Net: "unix"} }
func (c *blockingProxyConn) SetDeadline(time.Time) error      { return nil }
func (c *blockingProxyConn) SetReadDeadline(time.Time) error  { return nil }
func (c *blockingProxyConn) SetWriteDeadline(time.Time) error { return nil }

// fsErrClosedStdin 模拟真实 *os.File stdin：关闭后 Read 返回包装 fs.ErrClosed 的 *fs.PathError；
// 若指定 failErr 则立即返回真实非关闭 I/O 故障。
type fsErrClosedStdin struct {
	failErr   error
	closed    chan struct{}
	closeOnce sync.Once
}

func newFSErrClosedStdin(failErr error) *fsErrClosedStdin {
	return &fsErrClosedStdin{failErr: failErr, closed: make(chan struct{})}
}
func (s *fsErrClosedStdin) Read([]byte) (int, error) {
	if s.failErr != nil {
		return 0, s.failErr
	}
	<-s.closed
	return 0, &fs.PathError{Op: "read", Path: "/dev/stdin", Err: fs.ErrClosed}
}
func (s *fsErrClosedStdin) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

type customProxyMuxSocket struct {
	*spoofDialMuxSocket
	openProxy func() net.Conn
}

func (c *customProxyMuxSocket) OpenProxy(context.Context, pathalg.LocalSourcePath) (net.Conn, error) {
	return c.openProxy(), nil
}

// TestSessionMux_AdversarialPathsProxyAndValidationOrder 覆盖评审要求的全部对抗边界：
// 1. RunMuxProxy 阻塞 stdin 下远端先达 EOF 与 ctx 取消均确定性退出（0 死锁、0 goleak）；
// 2. expandControlPath：ProxyDisabled / ProxyCommandSpec / ProxyUnset 均产生 %j==""，未展开 ~ 失败关闭；
// 3. 显式 SocketPath 覆盖未设置 ControlPath 时仍强制执行 ControlMaster=ask 确认；
// 4. 零值 Service{} / nil ctx 校验严格早于字段参数校验。
func TestSessionMux_AdversarialPathsProxyAndValidationOrder(t *testing.T) {
	defer goleak.VerifyNone(t)
	litPath, _ := option.NewLiteralControlPath("/tmp/mux-adv.sock")
	cp := option.UnsetControlPolicy().WithMaster(option.ControlMasterYes).WithPath(litPath)
	pl := mustPlanWithControl(t, cp, false)

	assertRunMuxProxyBlockingStdinAndCancel(t, pl)
	assertExpandControlPathJumpAndTildeFailClosed(t)
	assertExplicitSocketPathEnforcesAskConfirmAndOrder(t)
}

func assertRunMuxProxyBlockingStdinAndCancel(t *testing.T, pl plan.SealedConnectionPlan) {
	t.Helper()
	// (a) 阻塞 stdin + 远端立即 EOF：必须同步关闭 stdin 并立即返回（0 死锁、0 goleak）。
	eofRig := newFullSessionRig(t, fullRigOptions{
		customMux: &customProxyMuxSocket{
			spoofDialMuxSocket: &spoofDialMuxSocket{inner: sim.NewSimMuxSocket(nil)},
			openProxy:          func() net.Conn { return newBlockingProxyConn(true) },
		},
	})
	defer eofRig.close()
	inR, inW := io.Pipe()
	defer func() { _ = inW.Close() }()
	var out bytes.Buffer
	if err := eofRig.svc.RunMuxProxy(context.Background(), ucsess.MuxRequest{Plan: pl}, inR, &out); err != nil {
		t.Fatalf("RunMuxProxy(remote EOF + blocking stdin): %v", err)
	}

	// (b) 阻塞 stdin + 背压阻塞 conn + 进中继后取消 ctx：必须即时解除阻塞、同步回收 AfterFunc 且绝不静默返回 nil。
	blkConn := newBlockingProxyConn(false)
	cancelRig := newFullSessionRig(t, fullRigOptions{
		customMux: &customProxyMuxSocket{
			spoofDialMuxSocket: &spoofDialMuxSocket{inner: sim.NewSimMuxSocket(nil)},
			openProxy:          func() net.Conn { return blkConn },
		},
	})
	defer cancelRig.close()
	inR2, inW2 := io.Pipe()
	defer func() { _ = inW2.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	var cancelRunErr error
	if err := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error { <-blkConn.readEntered; cancel(); return nil }); gErr != nil {
			return gErr
		}
		cancelRunErr = cancelRig.svc.RunMuxProxy(ctx, ucsess.MuxRequest{Plan: pl}, inR2, &out)
		return nil
	}); err != nil {
		t.Fatalf("RunWait(cancel RunMuxProxy): %v", err)
	}
	if !errors.Is(cancelRunErr, context.Canceled) {
		t.Fatalf("RunMuxProxy 在 ctx 取消时必须返回 context.Canceled（绝不伪造成功），实际=%v", cancelRunErr)
	}

	assertRunMuxProxyStdinFaultAndFSErrClosed(t, pl)
}

func assertRunMuxProxyStdinFaultAndFSErrClosed(t *testing.T, pl plan.SealedConnectionPlan) {
	t.Helper()
	var out bytes.Buffer
	// (c) stdin.Read 返回真实非关闭故障时，必须主动 abort 关闭空闲 conn 解除阻塞并原样返回错误（0 挂死）。
	stdinIOErr := errors.New("injected stdin EIO")
	faultRig := newFullSessionRig(t, fullRigOptions{
		customMux: &customProxyMuxSocket{
			spoofDialMuxSocket: &spoofDialMuxSocket{inner: sim.NewSimMuxSocket(nil)},
			openProxy:          func() net.Conn { return newBlockingProxyConn(false) },
		},
	})
	defer faultRig.close()
	if err := faultRig.svc.RunMuxProxy(context.Background(), ucsess.MuxRequest{Plan: pl}, newFSErrClosedStdin(stdinIOErr), &out); !errors.Is(err, stdinIOErr) {
		t.Fatalf("RunMuxProxy(stdin EIO) 期望原样返回 stdinIOErr，实际=%v", err)
	}

	// (d) 模拟真实 *os.File stdin（返回 *fs.PathError{Err: fs.ErrClosed}）：
	//     远端先达 EOF 触发 abort 关闭 stdin 时必须干净返回 nil；而调用方传入已关闭坏 stdin 必须报错。
	osEOFRig := newFullSessionRig(t, fullRigOptions{
		customMux: &customProxyMuxSocket{
			spoofDialMuxSocket: &spoofDialMuxSocket{inner: sim.NewSimMuxSocket(nil)},
			openProxy:          func() net.Conn { return newBlockingProxyConn(true) },
		},
	})
	defer osEOFRig.close()
	if err := osEOFRig.svc.RunMuxProxy(context.Background(), ucsess.MuxRequest{Plan: pl}, newFSErrClosedStdin(nil), &out); err != nil {
		t.Fatalf("RunMuxProxy(远端先 EOF + 真实 *os.File fs.ErrClosed) 期望 nil，实际=%v", err)
	}
	preClosedStdin := newFSErrClosedStdin(nil)
	_ = preClosedStdin.Close()
	if err := faultRig.svc.RunMuxProxy(context.Background(), ucsess.MuxRequest{Plan: pl}, preClosedStdin, &out); !errors.Is(err, fs.ErrClosed) {
		t.Fatalf("RunMuxProxy(预关闭 *os.File stdin) 不得吞噬 fs.ErrClosed，实际=%v", err)
	}
}

func assertExpandControlPathJumpAndTildeFailClosed(t *testing.T) {
	t.Helper()
	rig := newFullSessionRig(t, fullRigOptions{profile: gate.PolicyProfileDirectOperator})
	defer rig.close()
	tplJ, _ := option.ParseControlPath("/tmp/mux-j[%j]-end.sock")
	cpJ := option.UnsetControlPolicy().WithMaster(option.ControlMasterYes).WithPath(tplJ)
	pCmd, _ := option.ParseProxyCommand("ssh -W %h:%p gw")
	for _, route := range []option.ProxyRoute{option.NewProxyUnset(), option.NewProxyDisabled(), pCmd} {
		pl := mustPlanWithControlRoute(t, cpJ, true, route)
		inf, err := rig.svc.StartControlMaster(context.Background(), ucsess.ControlMasterRequest{Plan: pl})
		if err != nil {
			t.Fatalf("StartControlMaster(route=%T): %v", route, err)
		}
		if inf.SocketPath().String() != "/tmp/mux-j[]-end.sock" {
			t.Fatalf("非 ProxyJumpChain 路由 %%j 必须为空串: route=%T got=%q", route, inf.SocketPath().String())
		}
		h, _ := inf.Handle().Get()
		_ = rig.svc.StopControlMaster(context.Background(), h)
		assertTeardownClean(t, rig, "non-jump-stop")
	}

	// 缺失 HomeDir 或 HomeDir 为非绝对路径（如 "~"）时，前导 ~/ 模板与字面量均必须失败关闭。
	noEnvRig := newFullSessionRig(t, fullRigOptions{disableEnv: true})
	defer noEnvRig.close()
	badHomeID, _ := ports.NewLocalIdentityInfo(ports.LocalIdentityInfoSpec{LocalHost: "workstation", LocalUser: "alice", LocalUID: "1001", HomeDir: "~"})
	badHomeRig := newFullSessionRig(t, fullRigOptions{customEnv: sim.NewSimEnvPort(nil, badHomeID)})
	defer badHomeRig.close()
	tildeTpl, _ := option.ParseControlPath("~/.xops/mux-%h.sock")
	tildeLit, _ := option.NewLiteralControlPath("~/.xops/literal.sock")
	for _, r := range []*fullSessionRig{noEnvRig, badHomeRig} {
		for _, cpT := range []option.ControlPathSpec{tildeTpl, tildeLit} {
			plT := mustPlanWithControl(t, option.UnsetControlPolicy().WithMaster(option.ControlMasterYes).WithPath(cpT), false)
			if _, err := r.svc.StartControlMaster(context.Background(), ucsess.ControlMasterRequest{Plan: plT}); !errors.Is(err, ucsess.ErrInvalidRequest) {
				t.Fatalf("非绝对/缺失 HomeDir 的前导 ~ 路径(%s)期望 ErrInvalidRequest，实际=%v", cpT, err)
			}
		}
	}
}

func assertExplicitSocketPathEnforcesAskConfirmAndOrder(t *testing.T) {
	t.Helper()
	// ControlPath=unset + ControlMaster=ask + 显式 SocketPath -> WithMuxConn 仍须触发确认门控。
	askUnsetPathPlan := mustPlanWithControl(t, option.UnsetControlPolicy().WithMaster(option.ControlMasterAsk), false)
	explicitSock, _ := pathalg.ParseLocalSourcePath("/tmp/mux-explicit-ask.sock")
	denyRig := newFullSessionRig(t, fullRigOptions{
		interactive:       true,
		customInteraction: &denyConfirmInteraction{inner: sim.NewSimInteractionPort(true)},
	})
	defer denyRig.close()
	denyRig.muxSocket.RegisterMaster(explicitSock, 5151)
	if err := denyRig.svc.WithMuxConn(context.Background(), ucsess.MuxRequest{
		Plan: askUnsetPathPlan, SocketPath: algebraic.Some(explicitSock),
	}, func(context.Context, ports.TransportConn) error { return nil }); !errors.Is(err, ucsess.ErrMuxMasterUnavailable) {
		t.Fatalf("显式 SocketPath 仍须执行 ask 确认并被拒绝: err=%v", err)
	}

	// 零值 Service{} / nil ctx 校验顺序优先于字段参数校验。
	var zeroSvc ucsess.Service
	if _, err := zeroSvc.ControlMux(context.Background(), ucsess.MuxControlRequest{Action: ports.MuxActionProxy}); !errors.Is(err, ucsess.ErrServiceNotInitialized) {
		t.Fatalf("零值 Service.ControlMux 期望 ErrServiceNotInitialized，实际=%v", err)
	}
	if err := zeroSvc.WithMuxProxy(context.Background(), ucsess.MuxRequest{}, nil); !errors.Is(err, ucsess.ErrServiceNotInitialized) {
		t.Fatalf("零值 Service.WithMuxProxy 期望 ErrServiceNotInitialized，实际=%v", err)
	}
	if err := zeroSvc.WithMuxConn(context.Background(), ucsess.MuxRequest{}, nil); !errors.Is(err, ucsess.ErrServiceNotInitialized) {
		t.Fatalf("零值 Service.WithMuxConn 期望 ErrServiceNotInitialized，实际=%v", err)
	}
	if _, err := zeroSvc.ReadPTY(context.Background(), ucsess.PTYReadRequest{MaxBytes: -1}); !errors.Is(err, ucsess.ErrServiceNotInitialized) {
		t.Fatalf("零值 Service.ReadPTY 期望 ErrServiceNotInitialized，实际=%v", err)
	}
	var zeroPTY plan.ManagedHandle[plan.KindPTY]
	if err := zeroSvc.SignalPTY(context.Background(), zeroPTY, ""); !errors.Is(err, ucsess.ErrServiceNotInitialized) {
		t.Fatalf("零值 Service.SignalPTY 期望 ErrServiceNotInitialized，实际=%v", err)
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

type failingServeMuxSocket struct {
	inner     *sim.SimMuxSocket
	triggerCh chan struct{}
	serveErr  error
}

func (f *failingServeMuxSocket) Probe(ctx context.Context, p pathalg.LocalSourcePath) (ports.MuxControlResponse, error) {
	return f.inner.Probe(ctx, p)
}
func (f *failingServeMuxSocket) Control(ctx context.Context, req ports.MuxControlRequest) (ports.MuxControlResponse, error) {
	return f.inner.Control(ctx, req)
}
func (f *failingServeMuxSocket) DialMux(ctx context.Context, p pathalg.LocalSourcePath, d plan.HopDigest, ep netaddr.Endpoint) (ports.TransportConn, error) {
	return f.inner.DialMux(ctx, p, d, ep)
}
func (f *failingServeMuxSocket) OpenProxy(ctx context.Context, p pathalg.LocalSourcePath) (net.Conn, error) {
	return f.inner.OpenProxy(ctx, p)
}

//xops:syncclosure
//xops:borrowed
func (f *failingServeMuxSocket) WithListener(ctx context.Context, p pathalg.LocalSourcePath, fn func(ln net.Listener) error) error {
	return f.inner.WithListener(ctx, p, func(ln net.Listener) error { return fn(ln) })
}
func (f *failingServeMuxSocket) Serve(ctx context.Context, _ net.Listener, _ ports.TransportConn, _ ports.ForwarderPort) error {
	select {
	case <-f.triggerCh:
		return f.serveErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

// TestControlMasterInfo_DoneAndWaitAllTerminationPaths 验证 #160 Major-2：
//   - 零值 ControlMasterInfo 失败关闭（Done()==nil、Wait 返回 ErrInvalidRequest / ErrNilContext）；
//   - reusedExisting==true 时 Done() 已关闭且 Wait(ctx) 返回 nil / ctx.Err()；
//   - 正常 -O exit 与 ControlPersist 空闲到期映射为 nil（且 runAutoRelease 回收句柄后仍稳定返回）；
//   - 上游/Serve 传输故障在句柄自动回收后仍被 Wait(ctx) 精确保留透传；
//   - 等待期取消调用方 ctx 立即返回 context.Canceled 且不中断主进程。
func TestControlMasterInfo_DoneAndWaitAllTerminationPaths(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()

	// 1. 零值失败关闭。
	var zeroInfo ucsess.ControlMasterInfo
	if zeroInfo.Done() != nil {
		t.Fatal("零值 ControlMasterInfo.Done() 必须返回 nil")
	}
	if err := zeroInfo.Wait(ctx); !errors.Is(err, ucsess.ErrInvalidRequest) || !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("零值 ControlMasterInfo.Wait 期望 ErrInvalidRequest/ErrInvalidArgument，实际=%v", err)
	}
	var nilCtx context.Context
	if err := zeroInfo.Wait(nilCtx); !errors.Is(err, ucsess.ErrNilContext) || !errors.Is(err, ports.ErrNilContext) {
		t.Fatalf("nil ctx Wait 期望 ErrNilContext，实际=%v", err)
	}

	assertMuxInfoWaitNormalExitAndReuse(t, ctx)
	assertMuxInfoWaitPersistAndUpstreamDrop(t, ctx)
}

func assertMuxInfoWaitNormalExitAndReuse(t *testing.T, ctx context.Context) {
	t.Helper()
	rig := newFullSessionRig(t, fullRigOptions{profile: gate.PolicyProfileDirectOperator})
	defer rig.close()
	cpPath, _ := option.ParseControlPath("/tmp/wait-exit.sock")
	pl := mustPlanWithControl(t, option.UnsetControlPolicy().WithPath(cpPath).WithMaster(option.ControlMasterYes), false)

	info, err := rig.svc.StartControlMaster(ctx, ucsess.ControlMasterRequest{Plan: pl})
	if err != nil {
		t.Fatalf("StartControlMaster: %v", err)
	}
	// 等待期取消调用方 ctx 立即返回 context.Canceled，主进程仍存活。
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	if err := info.Wait(cancelCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("取消 ctx Wait 期望 context.Canceled，实际=%v", err)
	}
	// 复用已有主进程：Done() 已关闭且 Wait(ctx) 返回 nil。
	autoPl := mustPlanWithControl(t, option.UnsetControlPolicy().WithPath(cpPath).WithMaster(option.ControlMasterAuto), false)
	reused, err := rig.svc.StartControlMaster(ctx, ucsess.ControlMasterRequest{Plan: autoPl})
	if err != nil || !reused.ReusedExisting() {
		t.Fatalf("复用主进程失败: reused=%+v err=%v", reused, err)
	}
	select {
	case <-reused.Done():
	default:
		t.Fatal("reusedExisting ControlMasterInfo.Done() 必须已关闭")
	}
	if err := reused.Wait(ctx); err != nil {
		t.Fatalf("reusedExisting Wait 期望 nil，实际=%v", err)
	}

	// 发送 -O exit 正常退出：等待句柄被 runAutoRelease 自动清理后再调用 Wait(ctx)，须仍返回 nil。
	if _, err := rig.svc.ControlMux(ctx, ucsess.MuxControlRequest{Target: ucsess.MuxRequest{Plan: pl}, Action: ports.MuxActionExit}); err != nil {
		t.Fatalf("ControlMux(exit): %v", err)
	}
	<-info.Done()
	h, _ := info.Handle().Get()
	waitUntilErr(t, func() (bool, error) {
		_, iErr := rig.svc.InspectControlMaster(ctx, h)
		if errors.Is(iErr, pool.ErrHandleNotFound) {
			return true, nil
		}
		if iErr == nil || errors.Is(iErr, pool.ErrInvalidResource) || errors.Is(iErr, pool.ErrHandleRevoked) {
			return false, nil
		}
		return false, iErr
	})
	if err := info.Wait(ctx); err != nil {
		t.Fatalf("-O exit 后 Wait(ctx) 期望 nil，实际=%v", err)
	}
}

func assertMuxInfoWaitPersistAndUpstreamDrop(t *testing.T, ctx context.Context) {
	t.Helper()
	// 1. ControlPersist 空闲到期：Wait(ctx) 映射 ErrMuxPersistExpired 为 nil。
	pRig := newFullSessionRig(t, fullRigOptions{profile: gate.PolicyProfileDirectOperator})
	defer pRig.close()
	cpPersist, _ := option.ParseControlPath("/tmp/wait-persist.sock")
	persist5, _ := option.ParseControlPersist("5s")
	plPersist := mustPlanWithControl(t, option.UnsetControlPolicy().WithPath(cpPersist).WithMaster(option.ControlMasterYes).WithPersist(persist5), false)
	pInfo, err := pRig.svc.StartControlMaster(ctx, ucsess.ControlMasterRequest{Plan: plPersist})
	if err != nil {
		t.Fatalf("StartControlMaster(persist): %v", err)
	}
	waitUntil(t, func() bool { return pRig.clk.PendingTimers() > 0 })
	pRig.clk.Advance(6 * time.Second)
	<-pInfo.Done()
	if err := pInfo.Wait(ctx); err != nil {
		t.Fatalf("ControlPersist 到期后 Wait(ctx) 期望 nil，实际=%v", err)
	}
	assertTeardownClean(t, pRig, "MuxWaitPersist")

	// 2. 上游断连/Serve 故障：runAutoRelease 清理句柄后 Wait(ctx) 仍必须精确返回传输错误。
	dropErr := errors.New("upstream ssh dropped")
	failMux := &failingServeMuxSocket{inner: sim.NewSimMuxSocket(nil), triggerCh: make(chan struct{}), serveErr: dropErr}
	dRig := newFullSessionRig(t, fullRigOptions{profile: gate.PolicyProfileDirectOperator, customMux: failMux})
	defer dRig.close()
	cpDrop, _ := option.ParseControlPath("/tmp/wait-drop.sock")
	plDrop := mustPlanWithControl(t, option.UnsetControlPolicy().WithPath(cpDrop).WithMaster(option.ControlMasterYes), false)
	dInfo, err := dRig.svc.StartControlMaster(ctx, ucsess.ControlMasterRequest{Plan: plDrop})
	if err != nil {
		t.Fatalf("StartControlMaster(drop): %v", err)
	}
	close(failMux.triggerCh)
	<-dInfo.Done()
	dh, _ := dInfo.Handle().Get()
	waitUntilErr(t, func() (bool, error) {
		_, iErr := dRig.svc.InspectControlMaster(ctx, dh)
		if errors.Is(iErr, pool.ErrHandleNotFound) {
			return true, nil
		}
		if iErr == nil || errors.Is(iErr, pool.ErrInvalidResource) || errors.Is(iErr, pool.ErrHandleRevoked) {
			return false, nil
		}
		return false, iErr
	})
	if err := dInfo.Wait(ctx); !errors.Is(err, dropErr) {
		t.Fatalf("上游断连且句柄自动回收后 Wait(ctx) 期望保留 %v，实际=%v", dropErr, err)
	}
	assertTeardownClean(t, dRig, "MuxWaitDrop")
}
