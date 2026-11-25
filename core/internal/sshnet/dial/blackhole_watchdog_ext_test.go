package dial_test

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
)

// blackholeConn 封装真实回环 TCP 连接；调用 freeze() 后进入单向 TCP 半开黑洞状态
// （吞没全部后续写并阻塞读直至 Close），用于模拟对端不回传 SSH_MSG_CHANNEL_CLOSE 的冻结跳板。
type blackholeConn struct {
	net.Conn
	frozen    atomic.Bool
	closedCh  chan struct{}
	closeOnce sync.Once
}

func newBlackholeConn(inner net.Conn) *blackholeConn {
	return &blackholeConn{Conn: inner, closedCh: make(chan struct{})}
}

func (b *blackholeConn) freeze() { b.frozen.Store(true) }

func (b *blackholeConn) Read(p []byte) (int, error) {
	if b.frozen.Load() {
		<-b.closedCh
		return 0, net.ErrClosed
	}
	n, err := b.Conn.Read(p)
	if b.frozen.Load() {
		<-b.closedCh
		return 0, net.ErrClosed
	}
	return n, err
}

func (b *blackholeConn) Write(p []byte) (int, error) {
	if b.frozen.Load() {
		select {
		case <-b.closedCh:
			return 0, net.ErrClosed
		default:
			return len(p), nil
		}
	}
	return b.Conn.Write(p)
}

func (b *blackholeConn) Close() error {
	var err error
	b.closeOnce.Do(func() {
		close(b.closedCh)
		err = b.Conn.Close()
	})
	return err
}

// TestDialer_HalfOpenBlackhole_AllWatchdogs_ZeroLeak 验证对端进入半开黑洞（不回传 SSH_MSG_CHANNEL_CLOSE）时，
// openWatchedChannel、watchedChannelConn 截止时间、多跳握手超时、remoteSession.Wait 均即时解阻，
// 且父连接关闭后 100% 零协程泄漏。
func TestDialer_HalfOpenBlackhole_AllWatchdogs_ZeroLeak(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()

	// 1. openWatchedChannel / watchedChannelConn 截止与多跳握手在半开黑洞下不挂死。
	_, bh, parentConn := dialWithBlackholeParent(t)
	epTarget := tck.MustEndpoint(t, "198.51.100.99", 22)
	// 先建一条通道与一条挂起会话，再冻结底层连接模拟真实 TCP 半开黑洞。
	chConn, err := parentConn.DialTCP(ctx, epTarget.HostPort())
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	sess, err := parentConn.OpenSession(ctx)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	if err := sess.Start(ctx, tck.MustCommandPlan(t, "hang-until-signal"), ports.ExecStreams{}); err != nil {
		t.Fatalf("Start: %v", err)
	}

	bh.freeze()

	// 1a. openWatchedChannel 在黑洞上取消须即时返回（cleanup 异步排空 reqs 不卡死调用方）。
	cCtx, cCancel := context.WithTimeout(ctx, 25*time.Millisecond)
	defer cCancel()
	if _, dErr := parentConn.DialTCP(cCtx, epTarget.HostPort()); !errors.Is(dErr, context.DeadlineExceeded) {
		t.Fatalf("黑洞上 DialTCP 超时须返回 DeadlineExceeded，实际 %v", dErr)
	}

	// 1b. watchedChannelConn 读截止在黑洞上须立即唤醒返回 os.ErrDeadlineExceeded 且 Close 有界返回。
	if err := chConn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, rErr := chConn.Read(make([]byte, 16)); !errors.Is(rErr, os.ErrDeadlineExceeded) {
		t.Fatalf("黑洞通道读截止须返回 os.ErrDeadlineExceeded，实际 %v", rErr)
	}
	_ = chConn.Close()

	// 1c. remoteSession.Wait 在黑洞上超时须立即返回 OutcomeUnknown + DeadlineExceeded 且 Close 不挂死。
	wCtx, wCancel := context.WithTimeout(ctx, 25*time.Millisecond)
	defer wCancel()
	out, wErr := sess.Wait(wCtx)
	if !errors.Is(wErr, context.DeadlineExceeded) {
		t.Fatalf("黑洞会话 Wait 超时须返回 DeadlineExceeded，实际 %v", wErr)
	}
	if _, isUnk := out.(*execution.OutcomeUnknown); !isUnk {
		t.Fatalf("黑洞会话 Wait 超时须返回 OutcomeUnknown，实际 %T", out)
	}
	_ = sess.Close()
	_ = parentConn.Close()

	// 2. 多跳 DialHop 握手阶段冻结父跳板（纯半开黑洞）：timeoutCtx 必须即时中止握手且父连接 Close 零泄漏。
	d2, bh2, parent2 := dialWithBlackholeParent(t)
	hop2, dig2 := mustSingleHopPlan(t, epTarget, mustAgentAuth(t), option.UnsetOptionLayer())
	bh2.freeze()
	hCtx, hCancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer hCancel()
	if _, hErr := d2.DialHop(hCtx, hop2, dig2, parent2); !errors.Is(hErr, context.DeadlineExceeded) {
		t.Fatalf("黑洞多跳 DialHop 超时须返回 DeadlineExceeded，实际 %v", hErr)
	}
	_ = parent2.Close()
}

func dialWithBlackholeParent(t *testing.T) (ports.DialerPort, *blackholeConn, ports.TransportConn) {
	t.Helper()
	ctx := context.Background()
	signer, _, _, pub := generateTestEd25519Key(t, "")
	bastion, bPub := newLoopbackSSHSpec(t)
	bastion.authorizedPubs = []ssh.PublicKey{signer.PublicKey()}
	bastion.stallTargets["198.51.100.99:22"] = true
	db, _ := newRealKnownHostsDB(t)
	ep := tck.MustEndpoint(t, "bh.local.test", 22)
	if err := db.RecordHostKey(ctx, ep, bPub, option.UnsetKnownHostsList()); err != nil {
		t.Fatalf("RecordHostKey: %v", err)
	}
	var bh *blackholeConn
	d, err := dial.NewDialer(dial.Config{
		HostTrust: db,
		Agent:     &testSignerPort{signer: signer, pub: pub},
		DialContext: func(c context.Context, _ string, _ string) (net.Conn, error) {
			raw, dErr := bastion.dialOnDemandLoopback(c)
			if dErr != nil {
				return nil, dErr
			}
			bh = newBlackholeConn(raw)
			return bh, nil
		},
	})
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	hop, dig := mustSingleHopPlan(t, ep, mustAgentAuth(t), option.UnsetOptionLayer())
	conn, err := d.DialHop(ctx, hop, dig, nil)
	if err != nil {
		t.Fatalf("DialHop: %v", err)
	}
	return d, bh, conn
}

// TestDialer_WatchedChannelConn_ClearExtendIdleAndPastDeadline 验证 O(1) 时钟感知看门狗：
// 无活跃 I/O 设过去截止再清零、活跃读期间清零/延长截止、读完成后旧截止过期、高频滑动刷新均绝不误杀健康通道。
func TestDialer_WatchedChannelConn_ClearExtendIdleAndPastDeadline(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	base := time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC)
	clk := sim.NewSimClock(base)

	signer, _, _, pub := generateTestEd25519Key(t, "")
	bastion, bPub := newLoopbackSSHSpec(t)
	bastion.authorizedPubs = []ssh.PublicKey{signer.PublicKey()}
	bastion.echoTargets["127.0.0.1:9999"] = true
	db, _ := newRealKnownHostsDB(t)
	ep := tck.MustEndpoint(t, "clk.local.test", 22)
	_ = db.RecordHostKey(ctx, ep, bPub, option.UnsetKnownHostsList())
	d, _ := dial.NewDialer(dial.Config{
		HostTrust:   db,
		Agent:       &testSignerPort{signer: signer, pub: pub},
		Clock:       clk,
		DialContext: bastion.dialFunc(),
	})
	hop, dig := mustSingleHopPlan(t, ep, mustAgentAuth(t), option.UnsetOptionLayer())
	conn, err := d.DialHop(ctx, hop, dig, nil)
	if err != nil {
		t.Fatalf("DialHop: %v", err)
	}
	defer func() { _ = conn.Close() }()

	ch, err := conn.DialTCP(ctx, tck.MustEndpoint(t, "127.0.0.1", 9999).HostPort())
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer func() { _ = ch.Close() }()

	// 1. 无活跃读时设过去截止再清零：不得破坏通道，随后读写须正常成功。
	_ = ch.SetReadDeadline(base.Add(-time.Second))
	_ = ch.SetReadDeadline(time.Time{})
	assertEchoRoundTrip(t, ch, "step1")

	// 2. 设未来截止并完成读后，推进时钟越过该截止时间：空闲通道绝不被误杀。
	_ = ch.SetReadDeadline(clk.Now().Add(100 * time.Millisecond))
	assertEchoRoundTrip(t, ch, "step2")
	clk.Advance(500 * time.Millisecond)
	_ = ch.SetReadDeadline(time.Time{})
	assertEchoRoundTrip(t, ch, "step3")

	// 3. 活跃读阻塞期间，先设短截止、高频滑动延长再清零并推进时钟越过原短截止：绝不误杀且回包可读。
	_ = ch.SetReadDeadline(clk.Now().Add(50 * time.Millisecond))
	readOut := make(chan string, 1)
	if err := conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			buf := make([]byte, 5)
			if _, rErr := io.ReadFull(ch, buf); rErr != nil {
				return rErr
			}
			readOut <- string(buf)
			return nil
		}); gErr != nil {
			return gErr
		}
		for range 20 {
			_ = ch.SetReadDeadline(clk.Now().Add(5 * time.Second))
		}
		_ = ch.SetReadDeadline(time.Time{})
		clk.Advance(time.Second)
		_, wErr := ch.Write([]byte("step4"))
		return wErr
	}); err != nil {
		t.Fatalf("活跃读清零/滑动延长截止失败: %v", err)
	}
	if got := <-readOut; got != "step4" {
		t.Fatalf("期望回显 step4，实际 %q", got)
	}
}

func assertEchoRoundTrip(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatalf("Write(%s): %v", msg, err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != msg {
		t.Fatalf("ReadFull(%s): got=%q err=%v", msg, string(buf), err)
	}
}

// TestDialer_SessionEnvWatchdogWriteErrAndScriptPipeClash 验证 env 看门狗、dst.Write 失败不死锁且透传错误、
// 以及 StdinPipe + PlanKindScript 互斥失败关闭。
func TestDialer_SessionEnvWatchdogWriteErrAndScriptPipeClash(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	_, srv, _, conn, _ := setupDialedPair(t)
	defer func() { _ = conn.Close() }()

	// 1. StdinPipe() + PlanKindScript 严禁静默丢弃脚本文本，必须返回 ErrInvalidArgument。
	sessClash, err := conn.OpenSession(ctx)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	if _, err := sessClash.StdinPipe(); err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	bashProf, _ := execution.POSIXLaunchProfile(execution.InterpreterBash, execution.LoginModeDisabled)
	scriptPlan, _ := execution.NewCommandPlan(execution.CommandPlanSpec{
		Kind: execution.PlanKindScript, Profile: bashProf, Command: "echo hi",
	})
	if err := sessClash.Start(ctx, scriptPlan, ports.ExecStreams{}); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("StdinPipe + PlanKindScript 须返回 ErrInvalidArgument，实际 %v", err)
	}
	_ = sessClash.Close()

	// 2. dst.Write 失败时须排空远端流至 EOF（不死锁）并在 Wait 中返回本地写错误。
	wantWriteErr := errors.New("local stdout writer broken")
	sessW, _ := conn.OpenSession(ctx)
	if err := sessW.Start(ctx, tck.MustCommandPlan(t, "big-output"), ports.ExecStreams{Stdout: errWriter{err: wantWriteErr}}); err != nil {
		t.Fatalf("Start(big-output): %v", err)
	}
	if _, wErr := sessW.Wait(ctx); !errors.Is(wErr, wantWriteErr) {
		t.Fatalf("Wait 必须透传本地 dst.Write 错误，实际 %v", wErr)
	}
	_ = sessW.Close()

	// 3. env 请求挂起时取消 ctx 须及时中止 Start 并关闭会话（后续 Start 返回 ErrClosed）。
	srv.hangEnv = true
	srv.envEntered = make(chan struct{}, 1)
	sessEnv, _ := conn.OpenSession(ctx)
	eCtx, eCancel := context.WithCancel(ctx)
	var startErr error
	if err := conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		_ = n.Go(func(context.Context) error {
			<-srv.envEntered
			eCancel()
			return nil
		})
		startErr = sessEnv.Start(eCtx, tck.MustCommandPlan(t, "echo ok"), ports.ExecStreams{Env: map[string]string{"FOO": "bar"}})
		return nil
	}); err != nil {
		t.Fatalf("RunWait: %v", err)
	}
	if !errors.Is(startErr, context.Canceled) {
		t.Fatalf("env 挂起取消须返回 context.Canceled，实际 %v", startErr)
	}
	if retryErr := sessEnv.Start(ctx, tck.MustCommandPlan(t, "echo ok"), ports.ExecStreams{}); !errors.Is(retryErr, ports.ErrClosed) {
		t.Fatalf("中止后会话须关闭并返回 ErrClosed，实际 %v", retryErr)
	}
	_ = sessEnv.Close()
}

type errWriter struct{ err error }

func (w errWriter) Write([]byte) (int, error) { return 0, w.err }
