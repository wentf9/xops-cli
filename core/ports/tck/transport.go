package tck

import (
	"bytes"
	"context"
	"errors"
	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/ports"
	"io"
	"net"
	"strings"
	"testing"
)

// DialerFixture 描述 DialerPort / TransportConn / RemoteSession 契约测试夹具。
type DialerFixture struct {
	// NewDialer 返回待测拨号器；可与已连接的仿真/回环服务端交互。
	NewDialer func(t *testing.T) ports.DialerPort
	// TestCommand 指定用于验证 RemoteSession.Start + Wait 的只读命令（为空时默认 "echo tck-ok"）。
	TestCommand string
	// CheckMultiHop 为 true 时额外验证基于首跳 parent TransportConn 的二跳拨号契约。
	CheckMultiHop bool
	// CheckRemoteFS 为 true 时验证 TransportConn.OpenRemoteFS 可打开可用 RemoteFSPort。
	CheckRemoteFS bool
	// CheckTunnelExtensions 为 true 时验证 DialStreamLocal、ListenStreamLocal 与 OpenTUN 成功返回并可关闭。
	CheckTunnelExtensions bool
}

// MuxSocketFixture 描述 MuxSocketPort 契约测试夹具。
type MuxSocketFixture struct {
	// NewMux 返回待测多路复用套接字端口与用于 WithListener 的合法本机套接字路径（可含 OpenSSH ':'）。
	NewMux func(t *testing.T) (ports.MuxSocketPort, pathalg.LocalSourcePath)
	// ExistingSocket 指向活跃 ControlMaster 套接字路径（可选；提供时验证 Probe/Control/DialMux/OpenProxy）。
	ExistingSocket algebraic.Option[pathalg.LocalSourcePath]
	// NewUpstream 提供用于验证 Serve 服务端生命周期的活跃上游传输连接（可选）。
	NewUpstream func(t *testing.T) ports.TransportConn
	// NewForwarder 提供可选的 ForwarderPort 以配合 Serve 服务端验证（可选）。
	NewForwarder func(t *testing.T) ports.ForwarderPort
}

// RunDialerSuite 验证 DialerPort、TransportConn 与 RemoteSession 的单跳/多跳拨号、命令执行、保活与关闭幂等契约。
func RunDialerSuite(t *testing.T, fx DialerFixture) {
	t.Helper()
	requireTrue(t, fx.NewDialer != nil, "DialerFixture.NewDialer 不能为 nil")
	cmdText := fx.TestCommand
	if cmdText == "" {
		cmdText = "echo tck-ok"
	}
	t.Run("ValidationAndSingleHopLifecycle", func(t *testing.T) {
		defer VerifyNoLeaks(t)
		ctx := context.Background()
		dialer := fx.NewDialer(t)
		singlePlan, multiPlan := MustHopAndPlan(t)
		hop0, ok := singlePlan.HopAt(0)
		requireTrue(t, ok, "HopAt(0)")
		dig0, ok := singlePlan.HopDigestAt(0)
		requireTrue(t, ok, "HopDigestAt(0)")
		var nilCtx context.Context
		var zeroHop plan.HopSpec
		var zeroDig plan.HopDigest
		_, err := dialer.DialHop(nilCtx, hop0, dig0, nil)
		requireErrIs(t, err, ports.ErrNilContext, "DialHop(nil ctx)")
		_, err = dialer.DialHop(ctx, zeroHop, dig0, nil)
		requireErr(t, err, "DialHop(zero hop)")
		_, err = dialer.DialHop(ctx, hop0, zeroDig, nil)
		requireErr(t, err, "DialHop(zero digest)")
		conn, err := dialer.DialHop(ctx, hop0, dig0, nil)
		requireNoErr(t, err, "DialHop(hop0)")
		requireTrue(t, conn.IsAlive() && conn.HopDigest().Equal(dig0) && conn.Endpoint().Equal(hop0.Endpoint()), "TransportConn 元信息须与 HopSpec/HopDigest 一致")
		requireNoErr(t, conn.SendKeepalive(ctx), "SendKeepalive")
		verifyRemoteSessionLifecycle(t, ctx, conn, cmdText)
		verifyTransportTunnelExtensions(t, ctx, conn, fx.CheckTunnelExtensions)
		if fx.CheckRemoteFS {
			rfs, rErr := conn.OpenRemoteFS(ctx)
			requireNoErr(t, rErr, "OpenRemoteFS")
			requireNoErr(t, rfs.Close(), "RemoteFS.Close")
		}
		if fx.CheckMultiHop {
			hop1, okH := multiPlan.HopAt(1)
			dig1, okD := multiPlan.HopDigestAt(1)
			requireTrue(t, okH && okD, "multiPlan hop1")
			conn2, dErr := dialer.DialHop(ctx, hop1, dig1, conn)
			requireNoErr(t, dErr, "DialHop(hop1 via parent)")
			requireTrue(t, conn2.IsAlive() && conn2.HopDigest().Equal(dig1), "二跳连接摘要须匹配")
			requireNoErr(t, conn2.Close(), "conn2.Close")
		}
		requireNoErr(t, conn.Close(), "conn.Close(1)")
		requireNoErr(t, conn.Close(), "conn.Close(2, idempotent)")
		requireTrue(t, !conn.IsAlive(), "关闭后 IsAlive 须为 false")
		requireErrIs(t, conn.SendKeepalive(ctx), ports.ErrClosed, "关闭后 SendKeepalive 须返回 ErrClosed")
	})
}
func verifyRemoteSessionLifecycle(t *testing.T, ctx context.Context, conn ports.TransportConn, cmdText string) {
	t.Helper()
	sess, err := conn.OpenSession(ctx)
	requireNoErr(t, err, "OpenSession")
	var stdout, stderr bytes.Buffer
	err = sess.Start(ctx, MustCommandPlan(t, cmdText), ports.ExecStreams{Stdout: &stdout, Stderr: &stderr})
	requireNoErr(t, err, "RemoteSession.Start")
	out, err := sess.Wait(ctx)
	requireNoErr(t, err, "RemoteSession.Wait")
	requireTrue(t, out != nil && out.IsValid(), "ExecutionOutcome 必须有效")
	completed, ok := out.(*execution.OutcomeCompleted)
	requireTrue(t, ok && completed.Succeeded(), "测试命令须以成功 ExitStatus 完成")
	requireNoErr(t, sess.Close(), "RemoteSession.Close(1)")
	requireNoErr(t, sess.Close(), "RemoteSession.Close(2, idempotent)")
	// 验证统一 ExecStreams.PTY + Env 驱动的 StartShell 契约。
	shellSess, err := conn.OpenSession(ctx)
	requireNoErr(t, err, "OpenSession(shell)")
	sz, err := ports.NewTerminalSize(80, 24)
	requireNoErr(t, err, "NewTerminalSize")
	ptyReq, err := ports.NewPTYRequest("xterm-256color", sz)
	requireNoErr(t, err, "NewPTYRequest")
	err = shellSess.StartShell(ctx, ports.ExecStreams{PTY: algebraic.Some(ptyReq), Env: map[string]string{"LANG": "C.UTF-8"}})
	requireNoErr(t, err, "RemoteSession.StartShell")
	_, pErr := shellSess.StdinPipe()
	requireErr(t, pErr, "StartShell 后获取 StdinPipe 必须拒绝")
	requireNoErr(t, shellSess.Close(), "RemoteSession(shell).Close")
	verifyRemoteSessionPipes(t, ctx, conn, cmdText)
}
func verifyRemoteSessionPipes(t *testing.T, ctx context.Context, conn ports.TransportConn, cmdText string) {
	t.Helper()
	sess, err := conn.OpenSession(ctx)
	requireNoErr(t, err, "OpenSession(pipes)")
	stdinW, err := sess.StdinPipe()
	requireNoErr(t, err, "StdinPipe")
	stdoutR, err := sess.StdoutPipe()
	requireNoErr(t, err, "StdoutPipe")
	stderrR, err := sess.StderrPipe()
	requireNoErr(t, err, "StderrPipe")
	// 重复获取与非空 ExecStreams 混用均须严格拒绝。
	_, err = sess.StdinPipe()
	requireErr(t, err, "重复 StdinPipe 必须拒绝")
	_, err = sess.StdoutPipe()
	requireErr(t, err, "重复 StdoutPipe 必须拒绝")
	_, err = sess.StderrPipe()
	requireErr(t, err, "重复 StderrPipe 必须拒绝")
	cmd := MustCommandPlan(t, cmdText)
	var clash bytes.Buffer
	requireErr(t, sess.Start(ctx, cmd, ports.ExecStreams{Stdin: strings.NewReader("x")}), "StdinPipe 与 ExecStreams.Stdin 互斥")
	requireErr(t, sess.Start(ctx, cmd, ports.ExecStreams{Stdout: &clash}), "StdoutPipe 与 ExecStreams.Stdout 互斥")
	requireErr(t, sess.Start(ctx, cmd, ports.ExecStreams{Stderr: &clash}), "StderrPipe 与 ExecStreams.Stderr 互斥")
	requireNoErr(t, sess.Start(ctx, cmd, ports.ExecStreams{}), "Start(pipes)")
	_, err = sess.StdoutPipe()
	requireErr(t, err, "Start 后 StdoutPipe 必须拒绝")
	requireNoErr(t, stdinW.Close(), "StdinPipe.Close")
	outBytes, err := io.ReadAll(stdoutR)
	requireNoErr(t, err, "ReadAll(StdoutPipe)")
	_, err = io.ReadAll(stderrR)
	requireNoErr(t, err, "ReadAll(StderrPipe)")
	requireTrue(t, len(outBytes) > 0, "StdoutPipe 应读到命令输出")
	out, err := sess.Wait(ctx)
	requireNoErr(t, err, "Wait(pipes)")
	requireTrue(t, out != nil && out.IsValid(), "Wait(pipes) Outcome 必须有效")
	requireNoErr(t, sess.Close(), "Close(pipes)")
	_, err = sess.StdinPipe()
	requireErr(t, err, "Close 后 StdinPipe 必须拒绝")
}
func verifyTransportTunnelExtensions(t *testing.T, ctx context.Context, conn ports.TransportConn, requireOK bool) {
	t.Helper()
	var zeroRP pathalg.RemotePath
	var zeroTUN ports.TUNSpec
	_, err := conn.DialStreamLocal(ctx, zeroRP)
	requireErr(t, err, "DialStreamLocal(zero path)")
	_, err = conn.ListenStreamLocal(ctx, zeroRP)
	requireErr(t, err, "ListenStreamLocal(zero path)")
	_, err = conn.OpenTUN(ctx, zeroTUN)
	requireErr(t, err, "OpenTUN(zero spec)")
	if !requireOK {
		return
	}
	rp, err := pathalg.ParseRemotePath("/run/tck.sock")
	requireNoErr(t, err, "ParseRemotePath")
	c, err := conn.DialStreamLocal(ctx, rp)
	requireNoErr(t, err, "DialStreamLocal")
	requireNoErr(t, c.Close(), "DialStreamLocal.Close")
	ln, err := conn.ListenStreamLocal(ctx, rp)
	requireNoErr(t, err, "ListenStreamLocal")
	requireNoErr(t, ln.Close(), "ListenStreamLocal.Close")
	ts, err := ports.NewTUNSpec(ports.TUNModePointToPoint, 0, 0)
	requireNoErr(t, err, "NewTUNSpec")
	tun, err := conn.OpenTUN(ctx, ts)
	requireNoErr(t, err, "OpenTUN")
	requireNoErr(t, tun.Close(), "OpenTUN.Close")
}

// RunMuxSocketSuite 验证 MuxSocketPort 的参数校验、统一 socketPath 作用域监听、Serve、OpenProxy 与精确身份 DialMux 契约（INV-A3 / INV-C4）。
func RunMuxSocketSuite(t *testing.T, fx MuxSocketFixture) {
	t.Helper()
	requireTrue(t, fx.NewMux != nil, "MuxSocketFixture.NewMux 不能为 nil")
	t.Run("ValidationAndScopedListener", func(t *testing.T) {
		defer VerifyNoLeaks(t)
		ctx := context.Background()
		mux, listenPath := fx.NewMux(t)
		singlePlan, _ := MustHopAndPlan(t)
		hop0, _ := singlePlan.HopAt(0)
		dig0, _ := singlePlan.HopDigestAt(0)
		verifyMuxGuards(t, ctx, mux, listenPath, dig0, hop0.Endpoint())
		var observedAddr string
		err := mux.WithListener(ctx, listenPath, func(ln net.Listener) error {
			requireTrue(t, ln != nil && ln.Addr() != nil, "WithListener 借出的 net.Listener 必须非 nil")
			observedAddr = ln.Addr().String()
			return nil
		})
		requireNoErr(t, err, "WithListener")
		requireTrue(t, observedAddr != "", "监听地址不能为空")
		if sockPath, ok := fx.ExistingSocket.Get(); ok {
			verifyExistingMuxControl(t, ctx, mux, sockPath, dig0, hop0.Endpoint())
		}
		if fx.NewUpstream != nil {
			var fwd ports.ForwarderPort
			if fx.NewForwarder != nil {
				fwd = fx.NewForwarder(t)
			}
			verifyMuxServeLifecycle(t, ctx, mux, listenPath, fx.NewUpstream(t), fwd)
		}
	})
}
func verifyMuxGuards(t *testing.T, ctx context.Context, mux ports.MuxSocketPort, listenPath pathalg.LocalSourcePath, dig plan.HopDigest, ep netaddr.Endpoint) {
	t.Helper()
	var nilCtx context.Context
	var zeroSrc pathalg.LocalSourcePath
	var zeroReq ports.MuxControlRequest
	var zeroDig plan.HopDigest
	var zeroEP netaddr.Endpoint
	_, err := mux.Probe(nilCtx, zeroSrc)
	requireErrIs(t, err, ports.ErrNilContext, "Probe(nil ctx)")
	_, err = mux.Probe(ctx, zeroSrc)
	requireErr(t, err, "Probe(zero path)")
	_, err = mux.Control(nilCtx, zeroReq)
	requireErrIs(t, err, ports.ErrNilContext, "Control(nil ctx)")
	_, err = mux.Control(ctx, zeroReq)
	requireErr(t, err, "Control(zero req)")
	_, err = mux.DialMux(nilCtx, listenPath, dig, ep)
	requireErrIs(t, err, ports.ErrNilContext, "DialMux(nil ctx)")
	_, err = mux.DialMux(ctx, zeroSrc, dig, ep)
	requireErr(t, err, "DialMux(zero path)")
	_, err = mux.DialMux(ctx, listenPath, zeroDig, ep)
	requireErr(t, err, "DialMux(zero hopDigest)")
	_, err = mux.DialMux(ctx, listenPath, dig, zeroEP)
	requireErr(t, err, "DialMux(zero endpoint)")
	_, err = mux.OpenProxy(nilCtx, listenPath)
	requireErrIs(t, err, ports.ErrNilContext, "OpenProxy(nil ctx)")
	_, err = mux.OpenProxy(ctx, zeroSrc)
	requireErr(t, err, "OpenProxy(zero path)")
	requireErrIs(t, mux.Serve(nilCtx, nil, nil, nil), ports.ErrNilContext, "Serve(nil ctx)")
	requireErr(t, mux.Serve(ctx, nil, nil, nil), "Serve(nil ln/upstream)")
	requireErrIs(t, mux.WithListener(nilCtx, listenPath, func(net.Listener) error { return nil }), ports.ErrNilContext, "WithListener(nil ctx)")
	requireErrIs(t, mux.WithListener(ctx, listenPath, nil), ports.ErrNilCallback, "WithListener(nil fn)")
	requireErr(t, mux.WithListener(ctx, zeroSrc, func(net.Listener) error { return nil }), "WithListener(zero path)")
}
func verifyExistingMuxControl(t *testing.T, ctx context.Context, mux ports.MuxSocketPort, sockPath pathalg.LocalSourcePath, dig plan.HopDigest, ep netaddr.Endpoint) {
	t.Helper()
	resp, err := mux.Probe(ctx, sockPath)
	requireNoErr(t, err, "Probe(existing)")
	requireTrue(t, resp.IsValid(), "Probe 响应必须有效")
	req, err := ports.NewMuxControlRequest(ports.MuxActionCheck, sockPath, algebraic.None[ports.ForwardSpec]())
	requireNoErr(t, err, "NewMuxControlRequest(check)")
	cResp, err := mux.Control(ctx, req)
	requireNoErr(t, err, "Control(check)")
	requireTrue(t, cResp.IsValid(), "Control(check) 响应必须有效")
	if conn, dErr := mux.DialMux(ctx, sockPath, dig, ep); !errors.Is(dErr, ports.ErrUnsupported) {
		requireNoErr(t, dErr, "DialMux(existing)")
		requireTrue(t, conn != nil && conn.IsAlive() && conn.HopDigest().Equal(dig) && conn.Endpoint().Equal(ep), "DialMux 返回连接须绑定精确 (hopDigest, endpoint)")
		requireNoErr(t, conn.Close(), "DialMux.Close")
	}
	if pConn, pErr := mux.OpenProxy(ctx, sockPath); !errors.Is(pErr, ports.ErrUnsupported) {
		requireNoErr(t, pErr, "OpenProxy(existing)")
		requireTrue(t, pConn != nil, "OpenProxy 须返回非 nil net.Conn")
		requireNoErr(t, pConn.Close(), "OpenProxy.Close")
	}
}
func verifyMuxServeLifecycle(t *testing.T, ctx context.Context, mux ports.MuxSocketPort, listenPath pathalg.LocalSourcePath, up ports.TransportConn, fwd ports.ForwarderPort) {
	t.Helper()
	serveCtx, cancelServe := context.WithCancel(ctx)
	defer cancelServe()
	ready := make(chan struct{})
	exitReq, err := ports.NewMuxControlRequest(ports.MuxActionExit, listenPath, algebraic.None[ports.ForwardSpec]())
	requireNoErr(t, err, "NewMuxControlRequest(exit)")
	err = conc.RunWait(serveCtx, func(rCtx context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(c context.Context) error {
			return mux.WithListener(c, listenPath, func(ln net.Listener) error {
				close(ready)
				sErr := mux.Serve(c, ln, up, fwd)
				if errors.Is(sErr, ports.ErrUnsupported) {
					cancelServe()
					return nil
				}
				return sErr
			})
		}); gErr != nil {
			return gErr
		}
		return n.Go(func(c context.Context) error {
			return probeAndExitMuxServer(c, ready, cancelServe, mux, listenPath, exitReq)
		})
	})
	requireNoErr(t, err, "MuxSocketPort.Serve 并发探活与优雅退出")
}
func probeAndExitMuxServer(c context.Context, ready <-chan struct{}, cancel context.CancelFunc, mux ports.MuxSocketPort, listenPath pathalg.LocalSourcePath, exitReq ports.MuxControlRequest) error {
	select {
	case <-ready:
	case <-c.Done():
		return nil
	}
	pResp, pErr := mux.Probe(c, listenPath)
	if pErr != nil || !pResp.IsValid() || !pResp.Alive() {
		cancel()
		if pErr != nil {
			return pErr
		}
		return ports.ErrMuxUnavailable
	}
	_, eErr := mux.Control(c, exitReq)
	if eErr != nil {
		cancel()
	}
	return eErr
}
