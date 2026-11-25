package dial_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
)

func setupDialedPair(t *testing.T) (ports.DialerPort, *loopbackSSHSpec, *loopbackSSHSpec, ports.TransportConn, netaddr.Endpoint) {
	t.Helper()
	ctx := context.Background()
	signer, _, _, pub := generateTestEd25519Key(t, "")
	bastion, bPub := newLoopbackSSHSpec(t)
	target, tPub := newLoopbackSSHSpec(t)
	bastion.authorizedPubs = []ssh.PublicKey{signer.PublicKey()}
	target.authorizedPubs = []ssh.PublicKey{signer.PublicKey()}

	epBastion := tck.MustEndpoint(t, "bastion.local.test", 22)
	epTarget := tck.MustEndpoint(t, "target.local.test", 2222)
	bastion.forwardTargets[epTarget.String()] = target
	bastion.stallTargets["198.51.100.99:22"] = true
	bastion.echoTargets["127.0.0.1:9999"] = true

	db, _ := newRealKnownHostsDB(t)
	if err := db.RecordHostKey(ctx, epBastion, bPub, option.UnsetKnownHostsList()); err != nil {
		t.Fatalf("RecordHostKey(bastion): %v", err)
	}
	if err := db.RecordHostKey(ctx, epTarget, tPub, option.UnsetKnownHostsList()); err != nil {
		t.Fatalf("RecordHostKey(target): %v", err)
	}
	d, err := dial.NewDialer(dial.Config{
		HostTrust:   db,
		Agent:       &testSignerPort{signer: signer, pub: pub},
		DialContext: bastion.dialFunc(),
	})
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	hop, dig := mustSingleHopPlan(t, epBastion, mustAgentAuth(t), option.UnsetOptionLayer())
	conn, err := d.DialHop(ctx, hop, dig, nil)
	if err != nil {
		t.Fatalf("DialHop(bastion): %v", err)
	}
	return d, bastion, target, conn, epTarget
}

func TestDialer_SessionScriptTruncationSignalsAndExitStates(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	_, srv, _, conn, _ := setupDialedPair(t)
	defer func() { _ = conn.Close() }()

	// 1. PlanKindScript stdin 投递 + stderr 读取。
	assertScriptExec(t, ctx, conn)
	// 2. MaxOutputBytes 截断且排空不死锁。
	assertTruncatedExec(t, ctx, conn)
	// 3. 非零退出码 42、信号退出 TERM、缺失 exit-status -> ExitUnknown。
	assertExitStatusVariants(t, ctx, conn)
	// 4. ResizePTY + Signal + Wait(canceledCtx) -> OutcomeUnknown。
	assertSignalResizeAndCancelWait(t, ctx, srv, conn)
	// 5. DialTCP 数据回环 + ListenTCP + OpenRemoteFS(未配置返回 ErrUnsupported)。
	assertTCPForwardAndUnsupportedRFS(t, ctx, conn)
}

func assertScriptExec(t *testing.T, ctx context.Context, conn ports.TransportConn) {
	t.Helper()
	sess, err := conn.OpenSession(ctx)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer func() { _ = sess.Close() }()
	bashProf, err := execution.POSIXLaunchProfile(execution.InterpreterBash, execution.LoginModeDisabled)
	if err != nil {
		t.Fatalf("POSIXLaunchProfile: %v", err)
	}
	cmd, err := execution.NewCommandPlan(execution.CommandPlanSpec{
		Kind:    execution.PlanKindScript,
		Profile: bashProf,
		Command: "hello-script-body",
	})
	if err != nil {
		t.Fatalf("NewCommandPlan(script): %v", err)
	}
	var stdout, stderr bytes.Buffer
	if err := sess.Start(ctx, cmd, ports.ExecStreams{Stdout: &stdout, Stderr: &stderr}); err != nil {
		t.Fatalf("Start(script): %v", err)
	}
	out, err := sess.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait(script): %v", err)
	}
	comp, ok := out.(*execution.OutcomeCompleted)
	if !ok || !comp.Succeeded() || !strings.Contains(stdout.String(), "hello-script-body") || stderr.String() != "err-msg" {
		t.Fatalf("脚本输出异常: ok=%v out=%q err=%q", ok, stdout.String(), stderr.String())
	}
}

func assertTruncatedExec(t *testing.T, ctx context.Context, conn ports.TransportConn) {
	t.Helper()
	sess, err := conn.OpenSession(ctx)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer func() { _ = sess.Close() }()
	cmd, err := execution.NewCommandPlan(execution.CommandPlanSpec{
		Kind:           execution.PlanKindCommand,
		Profile:        execution.DefaultServerLaunchProfile(),
		Command:        "big-output",
		MaxOutputBytes: algebraic.Some[uint64](128),
	})
	if err != nil {
		t.Fatalf("NewCommandPlan(big): %v", err)
	}
	var stdout bytes.Buffer
	if err := sess.Start(ctx, cmd, ports.ExecStreams{Stdout: &stdout}); err != nil {
		t.Fatalf("Start(big): %v", err)
	}
	out, err := sess.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait(big): %v", err)
	}
	comp, ok := out.(*execution.OutcomeCompleted)
	if !ok || !comp.Truncated() || stdout.Len() != 128 {
		t.Fatalf("输出截断契约未满足: ok=%v trunc=%v len=%d", ok, ok && comp.Truncated(), stdout.Len())
	}
}

func assertExitStatusVariants(t *testing.T, ctx context.Context, conn ports.TransportConn) {
	t.Helper()
	// 退出码 42
	out42 := runSimpleCommand(t, ctx, conn, "exit-42")
	comp42, ok := out42.(*execution.OutcomeCompleted)
	if !ok || comp42.Succeeded() {
		t.Fatalf("exit-42 须返回失败 OutcomeCompleted，实际 %T", out42)
	}
	code, isCode := comp42.Status().(*execution.ExitCode)
	if !isCode {
		t.Fatalf("期望 *ExitCode，实际 %#v", comp42.Status())
	}
	if exitVal, okCode := code.Code(); !okCode || exitVal != 42 {
		t.Fatalf("期望 ExitCode(42)，实际 (%d, %v)", exitVal, okCode)
	}
	// 信号退出 TERM
	outSig := runSimpleCommand(t, ctx, conn, "exit-sig")
	compSig, ok := outSig.(*execution.OutcomeCompleted)
	if !ok {
		t.Fatalf("exit-sig 期望 OutcomeCompleted，实际 %T", outSig)
	}
	sig, isSig := compSig.Status().(*execution.ExitSignal)
	if !isSig || sig.Signal() != "TERM" {
		t.Fatalf("期望 ExitSignal(TERM)，实际 %#v", compSig.Status())
	}
	// 缺失 exit-status -> ExitUnknown
	outMiss := runSimpleCommand(t, ctx, conn, "exit-missing")
	compMiss, ok := outMiss.(*execution.OutcomeCompleted)
	if !ok {
		t.Fatalf("exit-missing 期望 OutcomeCompleted，实际 %T", outMiss)
	}
	if _, isUnknown := compMiss.Status().(*execution.ExitUnknown); !isUnknown {
		t.Fatalf("期望 ExitUnknown，实际 %#v", compMiss.Status())
	}
}

func runSimpleCommand(t *testing.T, ctx context.Context, conn ports.TransportConn, text string) execution.ExecutionOutcome {
	t.Helper()
	sess, err := conn.OpenSession(ctx)
	if err != nil {
		t.Fatalf("OpenSession(%s): %v", text, err)
	}
	defer func() { _ = sess.Close() }()
	if err := sess.Start(ctx, tck.MustCommandPlan(t, text), ports.ExecStreams{}); err != nil {
		t.Fatalf("Start(%s): %v", text, err)
	}
	out, err := sess.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait(%s): %v", text, err)
	}
	return out
}

func assertSignalResizeAndCancelWait(t *testing.T, ctx context.Context, srv *loopbackSSHSpec, conn ports.TransportConn) {
	t.Helper()
	srv.hangStarted = make(chan struct{}, 2)

	// 1. PTY + ResizePTY + Signal 正常终止。
	sess1, err := conn.OpenSession(ctx)
	if err != nil {
		t.Fatalf("OpenSession(hang1): %v", err)
	}
	sz, _ := ports.NewTerminalSize(100, 30)
	ptyReq, _ := ports.NewPTYRequest("xterm-256color", sz)
	if err := sess1.Start(ctx, tck.MustCommandPlan(t, "hang-until-signal"), ports.ExecStreams{PTY: algebraic.Some(ptyReq)}); err != nil {
		t.Fatalf("Start(hang1): %v", err)
	}
	<-srv.hangStarted
	newSz, _ := ports.NewTerminalSize(132, 43)
	if err := sess1.ResizePTY(ctx, newSz); err != nil {
		t.Fatalf("ResizePTY: %v", err)
	}
	if err := sess1.Signal(ctx, "INT"); err != nil {
		t.Fatalf("Signal(INT): %v", err)
	}
	out, err := sess1.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait(hang1): %v", err)
	}
	comp, ok := out.(*execution.OutcomeCompleted)
	sig, isSig := comp.Status().(*execution.ExitSignal)
	if !ok || !isSig || sig.Signal() != "INT" {
		t.Fatalf("期望 ExitSignal(INT)，实际 %#v", out)
	}
	_ = sess1.Close()

	// 2. Wait(canceledCtx) 必须返回 OutcomeUnknown 与 context.Canceled 且安全收敛。
	sess2, err := conn.OpenSession(ctx)
	if err != nil {
		t.Fatalf("OpenSession(hang2): %v", err)
	}
	if err := sess2.Start(ctx, tck.MustCommandPlan(t, "hang-until-signal"), ports.ExecStreams{}); err != nil {
		t.Fatalf("Start(hang2): %v", err)
	}
	<-srv.hangStarted
	wCtx, wCancel := context.WithCancel(ctx)
	wCancel()
	uOut, uErr := sess2.Wait(wCtx)
	if !errors.Is(uErr, context.Canceled) {
		t.Fatalf("Wait(canceledCtx) 须返回 context.Canceled，实际 %v", uErr)
	}
	if _, isUnk := uOut.(*execution.OutcomeUnknown); !isUnk {
		t.Fatalf("Wait(canceledCtx) 须返回 OutcomeUnknown，实际 %T", uOut)
	}
	_ = sess2.Close()
}

func assertTCPForwardAndUnsupportedRFS(t *testing.T, ctx context.Context, conn ports.TransportConn) {
	t.Helper()
	epEcho := tck.MustEndpoint(t, "127.0.0.1", 9999)
	c, err := conn.DialTCP(ctx, epEcho.HostPort())
	if err != nil {
		t.Fatalf("DialTCP(echo): %v", err)
	}
	if _, err := c.Write([]byte("ping-tcp")); err != nil {
		t.Fatalf("DialTCP Write: %v", err)
	}
	buf := make([]byte, 8)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping-tcp" {
		t.Fatalf("DialTCP ReadFull: buf=%q err=%v", string(buf), err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("DialTCP Close: %v", err)
	}
	ln, err := conn.ListenTCP(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	_ = ln.Close()
	if _, err := conn.OpenRemoteFS(ctx); !errors.Is(err, ports.ErrUnsupported) {
		t.Fatalf("未注入 RemoteFSFactory 时 OpenRemoteFS 须返回 ErrUnsupported，实际 %v", err)
	}
}

// TestDialer_MultiHopWatchdog_CancelAndDeadlineDuringHandshake_ZeroLeak 验证多跳握手阻塞时
// 取消上下文与超时截止均由 core/conc.Nursery RunScoped Watchdog 及时中断底层 ssh.Channel 且零协程泄漏。
func TestDialer_MultiHopWatchdog_CancelAndDeadlineDuringHandshake_ZeroLeak(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	d, bastion, _, conn, _ := setupDialedPair(t)
	defer func() { _ = conn.Close() }()

	bastion.stallEntered = make(chan struct{}, 2)
	epStall := tck.MustEndpoint(t, "198.51.100.99", 22)
	hopStall, digStall := mustSingleHopPlan(t, epStall, mustAgentAuth(t), option.UnsetOptionLayer())

	// 场景 1：多跳目标静默卡死 SSH 握手时取消 ctx -> 确定性唤醒并中断 ssh.Channel。
	cCtx, cancel := context.WithCancel(ctx)
	var dialErr error
	if err := conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			<-bastion.stallEntered
			cancel()
			return nil
		}); gErr != nil {
			return gErr
		}
		_, dialErr = d.DialHop(cCtx, hopStall, digStall, conn)
		return nil
	}); err != nil {
		t.Fatalf("RunWait: %v", err)
	}
	if !errors.Is(dialErr, context.Canceled) {
		t.Fatalf("多跳握手取消须返回 context.Canceled，实际 %v", dialErr)
	}

	// 场景 2：短超时截止中断多跳握手，且跳板机连接仍保持健康。
	tCtx, tCancel := context.WithTimeout(ctx, 40*time.Millisecond)
	defer tCancel()
	if _, err := d.DialHop(tCtx, hopStall, digStall, conn); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("多跳握手超时须返回 context.DeadlineExceeded，实际 %v", err)
	}
	if !conn.IsAlive() || conn.SendKeepalive(ctx) != nil {
		t.Fatal("子跳取消/超时后父跳板机连接必须保持存活健康")
	}
}

// TestDialer_WatchedChannelConn_DeadlinesAndParentDisconnect_ZeroLeak 验证 ssh.Channel 封装的
// Read/Write 截止时间 Watchdog 与父跳断连级联收敛（0 泄漏）。
func TestDialer_WatchedChannelConn_DeadlinesAndParentDisconnect_ZeroLeak(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	d, bastion, _, parentConn, epTarget := setupDialedPair(t)

	// 1. 阻塞 Read 中设置过去截止时间与并发动态设置截止时间 -> 必须返回 os.ErrDeadlineExceeded。
	epStall := tck.MustEndpoint(t, "198.51.100.99", 22)
	ch1, err := parentConn.DialTCP(ctx, epStall.HostPort())
	if err != nil {
		t.Fatalf("DialTCP(stall1): %v", err)
	}
	if err := ch1.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(past): %v", err)
	}
	if _, rErr := ch1.Read(make([]byte, 16)); !errors.Is(rErr, os.ErrDeadlineExceeded) {
		t.Fatalf("过去读截止时间须返回 os.ErrDeadlineExceeded，实际 %v", rErr)
	}
	_ = ch1.Close()

	ch2, err := parentConn.DialTCP(ctx, epStall.HostPort())
	if err != nil {
		t.Fatalf("DialTCP(stall2): %v", err)
	}
	if err := ch2.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline(future): %v", err)
	}
	if _, rErr := ch2.Read(make([]byte, 16)); !errors.Is(rErr, os.ErrDeadlineExceeded) {
		t.Fatalf("运行期读截止时间触发须返回 os.ErrDeadlineExceeded，实际 %v", rErr)
	}
	_ = ch2.Close()

	// 2. 父跳连接在活跃二跳会话存在时意外断开 -> 子跳 IsAlive 迅速转 false 且 Close 零泄漏收敛。
	hopTarget, digTarget := mustSingleHopPlan(t, epTarget, mustAgentAuth(t), option.UnsetOptionLayer())
	childConn, err := d.DialHop(ctx, hopTarget, digTarget, parentConn)
	if err != nil {
		t.Fatalf("DialHop(child): %v", err)
	}
	if !childConn.IsAlive() {
		t.Fatal("childConn 刚建连时须存活")
	}
	bastion.killActiveServerConns()
	// 通过 SendKeepalive 确定性感知底层断连并等待被动状态同步收敛（不依赖 time.Sleep）。
	if kErr := childConn.SendKeepalive(ctx); kErr == nil {
		t.Fatal("父跳断开后子跳 SendKeepalive 必须失败")
	}
	if err := childConn.Close(); err != nil {
		t.Fatalf("父跳断开后 childConn.Close 失败: %v", err)
	}
	if childConn.IsAlive() {
		t.Fatal("关闭后 childConn.IsAlive 必须为 false")
	}
	_ = parentConn.Close()
}

// TestDialer_ProxyCommandViaProcessPort 验证 ProxyCommand 经 ProcessPort.DialStdio 建立真实 SSH 会话。
func TestDialer_ProxyCommandViaProcessPort(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	signer, _, _, pub := generateTestEd25519Key(t, "")
	srv, srvPub := newLoopbackSSHSpec(t)
	srv.authorizedPubs = []ssh.PublicKey{signer.PublicKey()}

	db, _ := newRealKnownHostsDB(t)
	ep := tck.MustEndpoint(t, "proxycmd.example.test", 22)
	if err := db.RecordHostKey(ctx, ep, srvPub, option.UnsetKnownHostsList()); err != nil {
		t.Fatalf("RecordHostKey: %v", err)
	}
	procStub := &loopbackProxyProcessPort{srv: srv}
	d, err := dial.NewDialer(dial.Config{
		HostTrust: db,
		Agent:     &testSignerPort{signer: signer, pub: pub},
		Process:   procStub,
	})
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	pc, err := option.ParseProxyCommand("nc %h %p")
	if err != nil {
		t.Fatalf("ParseProxyCommand: %v", err)
	}
	layer := option.UnsetOptionLayer().WithProxyRoute(pc)
	hop, dig := mustSingleHopPlan(t, ep, mustAgentAuth(t), layer)
	conn, err := d.DialHop(ctx, hop, dig, nil)
	if err != nil {
		t.Fatalf("DialHop(ProxyCommand): %v", err)
	}
	defer func() { _ = conn.Close() }()
	if !strings.Contains(procStub.lastCmd, "nc proxycmd.example.test 22") {
		t.Fatalf("ProxyCommand 令牌展开不符预期: %q", procStub.lastCmd)
	}
	out := runSimpleCommand(t, ctx, conn, "echo tck-ok")
	if comp, ok := out.(*execution.OutcomeCompleted); !ok || !comp.Succeeded() {
		t.Fatalf("ProxyCommand 会话执行失败: %#v", out)
	}
}

type loopbackProxyProcessPort struct {
	srv     *loopbackSSHSpec
	lastCmd string
}

func (p *loopbackProxyProcessPort) Run(context.Context, ports.ProcessSpec, io.Reader) (ports.ProcessResult, error) {
	var zero ports.ProcessResult
	return zero, ports.ErrUnsupported
}

func (p *loopbackProxyProcessPort) DialStdio(ctx context.Context, spec ports.ProcessSpec) (net.Conn, error) {
	p.lastCmd = strings.Join(append([]string{spec.Command()}, spec.Args()...), " ")
	return p.srv.dialOnDemandLoopback(ctx)
}
