package chanconn_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial/chanconn"
	"github.com/wentf9/xops-cli/core/ports"
)

// 编译期接口断言：确保 *chanconn.WatchedConn 完整实现标准 net.Conn 契约。
var _ net.Conn = (*chanconn.WatchedConn)(nil)

type fakeSSHChannel struct {
	r       *io.PipeReader
	w       *io.PipeWriter
	peerR   *io.PipeReader
	peerW   *io.PipeWriter
	closed  atomic.Bool
	wClosed atomic.Bool
	once    sync.Once
}

func newFakeSSHChannel() *fakeSSHChannel {
	c2pR, c2pW := io.Pipe()
	p2cR, p2cW := io.Pipe()
	return &fakeSSHChannel{r: p2cR, w: c2pW, peerR: c2pR, peerW: p2cW}
}

func (f *fakeSSHChannel) Read(b []byte) (int, error)  { return f.r.Read(b) }
func (f *fakeSSHChannel) Write(b []byte) (int, error) { return f.w.Write(b) }
func (f *fakeSSHChannel) CloseWrite() error {
	f.wClosed.Store(true)
	return f.w.Close()
}
func (f *fakeSSHChannel) Close() error {
	f.once.Do(func() {
		f.closed.Store(true)
		_ = f.r.Close()
		_ = f.w.Close()
		_ = f.peerR.Close()
		_ = f.peerW.Close()
	})
	return nil
}
func (*fakeSSHChannel) SendRequest(string, bool, []byte) (bool, error) { return true, nil }
func (*fakeSSHChannel) Stderr() io.ReadWriter                          { return bytes.NewBuffer(nil) }

func TestRunWithAbortWatchdog_AndMultiplexedOp(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()

	// 1. nil op 须返回 ports.ErrNilCallback（不触发 panic）。
	if err := chanconn.RunWithAbortWatchdog(ctx, nil, nil); !errors.Is(err, ports.ErrNilCallback) {
		t.Fatalf("RunWithAbortWatchdog(nil op) 期望 ErrNilCallback，实际 %v", err)
	}
	n, err := conc.NewNursery(ctx)
	if err != nil {
		t.Fatalf("NewNursery: %v", err)
	}
	defer func() { _ = n.Close() }()
	if _, err := chanconn.RunMultiplexedOp[int](ctx, n, nil, nil); !errors.Is(err, ports.ErrNilCallback) {
		t.Fatalf("RunMultiplexedOp(nil op) 期望 ErrNilCallback，实际 %v", err)
	}

	// 2. 取消触发 onAbort 解除阻塞操作。
	cancelCtx, cancel := context.WithCancel(ctx)
	started := make(chan struct{})
	aborted := make(chan struct{})
	var abortCount atomic.Int32
	wErr := chanconn.RunWithAbortWatchdog(cancelCtx, func() {
		if abortCount.Add(1) == 1 {
			close(aborted)
		}
	}, func() error {
		close(started)
		cancel()
		<-aborted
		return context.Canceled
	})
	<-started
	if !errors.Is(wErr, context.Canceled) || abortCount.Load() != 1 {
		t.Fatalf("Watchdog 取消路径异常: err=%v aborts=%d", wErr, abortCount.Load())
	}

	// 3. RunMultiplexedOp 取消时保证迟到完成的孤立资源恰好释放一次。
	opCtx, opCancel := context.WithCancel(ctx)
	releaseOp := make(chan struct{})
	cleaned := make(chan int, 1)
	_, mErr := chanconn.RunMultiplexedOp(opCtx, n, func() (int, error) {
		opCancel()
		<-releaseOp
		return 42, nil
	}, func(v int) {
		cleaned <- v
	})
	if !errors.Is(mErr, context.Canceled) {
		t.Fatalf("RunMultiplexedOp 取消期望 Canceled，实际 %v", mErr)
	}
	close(releaseOp)
	if got := <-cleaned; got != 42 {
		t.Fatalf("迟到孤立资源清理值异常: got=%d want=42", got)
	}
}

func TestWatchedConn_IOCloseWriteAndDeadlineSentinels(t *testing.T) {
	defer goleak.VerifyNone(t)
	n, err := conc.NewNursery(context.Background())
	if err != nil {
		t.Fatalf("NewNursery: %v", err)
	}
	defer func() { _ = n.Close() }()

	ch := newFakeSSHChannel()
	reqs := make(chan *ssh.Request)
	wc, err := chanconn.WrapChannel(n, ch, reqs, chanconn.NewAddr("tcp", "local"), chanconn.NewAddr("tcp", "remote"), nil)
	if err != nil {
		t.Fatalf("WrapChannel: %v", err)
	}

	// 1. 正常读写与 CloseWrite 半关闭（io.Pipe 无缓冲，对端先读后写避免互锁）。
	_ = n.Go(func(context.Context) error {
		buf := make([]byte, 4)
		_, _ = io.ReadFull(ch.peerR, buf)
		_, _ = ch.peerW.Write([]byte("pong"))
		return nil
	})
	if _, err := wc.Write([]byte("ping")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(wc, got); err != nil || !bytes.Equal(got, []byte("pong")) {
		t.Fatalf("Read: got=%q err=%v", got, err)
	}
	if err := wc.CloseWrite(); err != nil || !ch.wClosed.Load() {
		t.Fatalf("CloseWrite: err=%v wClosed=%v", err, ch.wClosed.Load())
	}

	// 2. 活跃读截止触发看门狗自动关闭并返回超时错误。
	if err := wc.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	_, rErr := wc.Read(make([]byte, 8))
	var netErr net.Error
	if !errors.As(rErr, &netErr) || !netErr.Timeout() {
		t.Fatalf("活跃读截止到期须返回 net.Error Timeout，实际 %v", rErr)
	}
	close(reqs)
	if err := wc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// 3. 关闭后 Set*Deadline 同时满足 errors.Is(err, net.ErrClosed) 与 ports.ErrClosed。
	for _, dErr := range []error{
		wc.SetDeadline(time.Now()),
		wc.SetReadDeadline(time.Now()),
		wc.SetWriteDeadline(time.Now()),
	} {
		if !errors.Is(dErr, net.ErrClosed) || !errors.Is(dErr, ports.ErrClosed) {
			t.Fatalf("关闭后 Set*Deadline 须同时匹配 net.ErrClosed 与 ports.ErrClosed，实际 %v", dErr)
		}
	}
}
