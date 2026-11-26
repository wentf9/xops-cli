package remotesess_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"

	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial/remotesess"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
)

// 编译期接口断言：确保 *remotesess.Session 完整实现 ports.RemoteSession 契约。
var _ ports.RemoteSession = (*remotesess.Session)(nil)

func TestSession_ZeroValueFailClosedAndNewValidation(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	var zero remotesess.Session

	if _, err := zero.StdinPipe(); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("零值 StdinPipe 期望 ErrClosed，实际 %v", err)
	}
	if err := zero.Start(ctx, tck.MustCommandPlan(t, "id"), ports.ExecStreams{}); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("零值 Start 期望 ErrClosed，实际 %v", err)
	}
	if _, err := zero.Wait(ctx); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("零值 Wait 期望 ErrClosed，实际 %v", err)
	}
	sz, _ := ports.NewTerminalSize(24, 80)
	if err := zero.ResizePTY(ctx, sz); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("零值 ResizePTY 期望 ErrClosed，实际 %v", err)
	}
	if err := zero.Signal(ctx, "TERM"); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("零值 Signal 期望 ErrClosed，实际 %v", err)
	}
	if err := zero.Close(); err != nil {
		t.Fatalf("零值 Close 应幂等返回 nil，实际 %v", err)
	}
	if _, err := remotesess.New(nil, nil, nil); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("remotesess.New(nil) 须返回 ErrClosed，实际 %v", err)
	}
}

func TestSession_DeadParentGuardsAndPumpSpawnFailureCleanup(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()

	cli, closePair := newLoopbackSSHClient(t)
	defer closePair()

	n, err := conc.NewNursery(ctx)
	if err != nil {
		t.Fatalf("NewNursery: %v", err)
	}
	defer func() { _ = n.Close() }()

	sshSess, err := cli.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	var alive atomic.Bool
	alive.Store(true)
	sess, err := remotesess.New(n, alive.Load, sshSess)
	if err != nil {
		t.Fatalf("remotesess.New: %v", err)
	}

	// 1. 父连接掉线（isAlive() == false）时，ResizePTY 与 Signal 须直接返回 ports.ErrClosed。
	alive.Store(false)
	sz, _ := ports.NewTerminalSize(30, 100)
	if err := sess.ResizePTY(ctx, sz); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("父连接失活时 ResizePTY 须返回 ErrClosed，实际 %v", err)
	}
	if err := sess.Signal(ctx, "INT"); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("父连接失活时 Signal 须返回 ErrClosed，实际 %v", err)
	}
	_ = sess.Close()

	// 2. lifeNursery 已关闭时启动输出泵失败，pumpsDone 仍须确定性关闭且 Close 零残留。
	closedN, err := conc.NewNursery(ctx)
	if err != nil {
		t.Fatalf("NewNursery(2): %v", err)
	}
	sshSess2, err := cli.NewSession()
	if err != nil {
		t.Fatalf("NewSession(2): %v", err)
	}
	alive.Store(true)
	sess2, err := remotesess.New(closedN, alive.Load, sshSess2)
	if err != nil {
		t.Fatalf("remotesess.New(2): %v", err)
	}
	_ = closedN.Close()
	if err := sess2.Start(ctx, tck.MustCommandPlan(t, "echo hi"), ports.ExecStreams{}); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("lifeNursery 关闭后 Start 须返回 ErrClosed，实际 %v", err)
	}
	if err := sess2.Close(); err != nil {
		t.Fatalf("sess2.Close: %v", err)
	}
}

// TestSession_ClaimedPipesDecoupledEOFAndCloseO1Unblock 验证评审 #45 [M1] 与 ADR-015：
//   - StdoutPipe() / StderrPipe() 各自拥有独立的 lifeNursery 桥接，远端通道挂起时 Session.Close O(1) 解除阻塞；
//   - 调用方未读取借出管道时执行 Session.Close + Wait 绝不死锁且零协程泄漏。
func TestSession_ClaimedPipesDecoupledEOFAndCloseO1Unblock(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()

	cli, closePair := newLoopbackSSHClient(t)
	defer closePair()

	n, err := conc.NewNursery(ctx)
	if err != nil {
		t.Fatalf("NewNursery: %v", err)
	}
	defer func() { _ = n.Close() }()

	sshSess, err := cli.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	sess, err := remotesess.New(n, func() bool { return true }, sshSess)
	if err != nil {
		t.Fatalf("remotesess.New: %v", err)
	}
	outPipe, err := sess.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	errPipe, err := sess.StderrPipe()
	if err != nil {
		t.Fatalf("StderrPipe: %v", err)
	}
	if err := sess.Start(ctx, tck.MustCommandPlan(t, "hang"), ports.ExecStreams{}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// 在远端通道持续保持打开（无 EOF）时，并发读取借出管道并在 Session.Close 后 O(1) 收到 EOF。
	readDone := make(chan error, 2)
	_ = n.Go(func(context.Context) error {
		_, rErr := io.ReadAll(outPipe)
		readDone <- rErr
		return nil
	})
	_ = n.Go(func(context.Context) error {
		_, rErr := io.ReadAll(errPipe)
		readDone <- rErr
		return nil
	})
	if err := sess.Close(); err != nil {
		t.Fatalf("sess.Close: %v", err)
	}
	for range 2 {
		if rErr := <-readDone; rErr != nil {
			t.Fatalf("Close 后借出管道应平滑返回 EOF，实际 %v", rErr)
		}
	}
}

func newLoopbackSSHClient(t *testing.T) (*ssh.Client, func()) {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	srvN, err := conc.NewNursery(context.Background())
	if err != nil {
		_ = ln.Close()
		t.Fatalf("NewNursery(srv): %v", err)
	}
	_ = srvN.Go(func(context.Context) error {
		defer func() { _ = ln.Close() }()
		srvConn, aErr := ln.Accept()
		if aErr != nil {
			return nil
		}
		serveLoopbackSSH(srvConn, hostSigner)
		return nil
	})
	var nd net.Dialer
	cliConn, err := nd.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		_ = ln.Close()
		_ = srvN.Close()
		t.Fatalf("DialContext: %v", err)
	}
	cc, cchans, creqs, err := ssh.NewClientConn(cliConn, ln.Addr().String(), &ssh.ClientConfig{
		User:            "ops",
		HostKeyCallback: ssh.FixedHostKey(hostSigner.PublicKey()),
	})
	if err != nil {
		_ = cliConn.Close()
		_ = ln.Close()
		_ = srvN.Close()
		t.Fatalf("NewClientConn: %v", err)
	}
	client := ssh.NewClient(cc, cchans, creqs)
	return client, func() {
		_ = client.Close()
		_ = cliConn.Close()
		_ = ln.Close()
		_ = srvN.Close()
	}
}

func serveLoopbackSSH(srvConn net.Conn, hostSigner ssh.Signer) {
	defer func() { _ = srvConn.Close() }()
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(hostSigner)
	sc, chans, reqs, err := ssh.NewServerConn(srvConn, cfg)
	if err != nil {
		return
	}
	defer func() { _ = sc.Close() }()
	_ = conc.RunWait(context.Background(), func(_ context.Context, inner *conc.Nursery) error {
		_ = inner.Go(func(context.Context) error { ssh.DiscardRequests(reqs); return nil })
		for nc := range chans {
			acceptLoopbackSessionChan(inner, nc)
		}
		return nil
	})
}

func acceptLoopbackSessionChan(inner *conc.Nursery, nc ssh.NewChannel) {
	ch, creqs, err := nc.Accept()
	if err != nil {
		return
	}
	_ = inner.Go(func(context.Context) error {
		defer func() { _ = ch.Close() }()
		for r := range creqs {
			if r.WantReply {
				_ = r.Reply(true, nil)
			}
		}
		return nil
	})
}
