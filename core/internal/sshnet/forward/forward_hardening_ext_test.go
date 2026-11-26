package forward_test

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/internal/sshnet/forward"
	"github.com/wentf9/xops-cli/core/ports"
)

// watchableTunnelTransport 为 memTunnelTransport 增加 WaitDone()/IsAlive() 与可远程关闭的 TUN 通道，
// 用于确定性测试 #124 M2（启动 ctx 解耦 + 上游断连自动回收）与 #123 M4（无僵尸 TUN 隧道）。
type watchableTunnelTransport struct {
	*memTunnelTransport
	waitDone  chan struct{}
	alive     atomic.Bool
	closeOnce sync.Once
	remoteTUN io.ReadWriteCloser
}

func newWatchableTransport() *watchableTunnelTransport {
	w := &watchableTunnelTransport{
		memTunnelTransport: newMemTunnelTransport(),
		waitDone:           make(chan struct{}),
	}
	w.alive.Store(true)
	return w
}

func (w *watchableTunnelTransport) WaitDone() <-chan struct{} { return w.waitDone }
func (w *watchableTunnelTransport) IsAlive() bool             { return w.alive.Load() }

func (w *watchableTunnelTransport) disconnect() {
	w.closeOnce.Do(func() {
		w.alive.Store(false)
		close(w.waitDone)
	})
}

func (w *watchableTunnelTransport) OpenTUN(_ context.Context, _ ports.TUNSpec) (io.ReadWriteCloser, error) {
	return w.remoteTUN, nil
}

// blockingTUNDev 模拟真实本机 TUN 虚拟网卡：无 CloseWrite() 方法，在 Close() 被调用前 Read 永远阻塞不返回 EOF。
type blockingTUNDev struct {
	closed chan struct{}
	once   sync.Once
}

func newBlockingTUNDev() *blockingTUNDev { return &blockingTUNDev{closed: make(chan struct{})} }

func (d *blockingTUNDev) Read([]byte) (int, error) {
	<-d.closed
	return 0, io.EOF
}

func (d *blockingTUNDev) Write(p []byte) (int, error) {
	select {
	case <-d.closed:
		return 0, io.ErrClosedPipe
	default:
		return len(p), nil
	}
}

func (d *blockingTUNDev) Close() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}

type stubBlockingTUNPort struct{ dev *blockingTUNDev }

func (p stubBlockingTUNPort) OpenLocalTUN(_ context.Context, _ ports.TUNSpec) (io.ReadWriteCloser, string, error) {
	return p.dev, "tun-test0", nil
}

// TestForwarder_StartupCtxDecoupledUpstreamAutoCloseAndNoZombieTUN 验证 #124 M2 与 #123 M4 修复。
func TestForwarder_StartupCtxDecoupledUpstreamAutoCloseAndNoZombieTUN(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()

	// 1. StartForward 返回后立即取消启动 ctx：长生命周期 Handle 必须保持存活且正常转发数据。
	tr := newWatchableTransport()
	fwd := forward.NewForwarder(forward.Config{})
	startCtx, cancelStart := context.WithTimeout(ctx, 5*time.Second)
	lSpec, _ := ports.NewForwardSpec(ports.ForwardLocal, "127.0.0.1:0", "10.0.0.2:80")
	h, err := fwd.StartForward(startCtx, tr, lSpec)
	if err != nil {
		cancelStart()
		t.Fatalf("StartForward(-L): %v", err)
	}
	cancelStart()
	if !h.IsValid() {
		_ = h.Close()
		t.Fatal("启动 ctx 取消后长生命周期 ForwardHandle 不应被误杀")
	}
	if err := roundTripTCPForward(ctx, h.BoundAddr(), "survive-cancel"); err != nil {
		_ = h.Close()
		t.Fatalf("启动 ctx 取消后数据面仍须正常工作: %v", err)
	}

	// 2. 上游 transport 断开（WaitDone 关闭）：空闲 Handle 必须自动收敛关闭且零泄漏。
	tr.disconnect()
	select {
	case <-h.Done():
	case <-time.After(500 * time.Millisecond):
		_ = h.Close()
		t.Fatal("上游断开后空闲 ForwardHandle 未在 500ms 内自动关闭")
	}
	if h.IsValid() {
		t.Fatal("上游断开后 Handle.IsValid() 必须为 false")
	}
	if err := h.Close(); err != nil {
		t.Fatalf("重复 Close: %v", err)
	}

	// 3. 已断开的 transport 上发起 StartForward 必须立即失败关闭返回 ErrClosed。
	if _, err := fwd.StartForward(ctx, tr, lSpec); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("已断开 transport StartForward = %v, 期望 ErrClosed", err)
	}

	// 4. ForwardTUN 无僵尸隧道回归：remoteTUN 到达 EOF 而 localDev 永不自然 EOF 时，桥接必须立即双端关闭。
	verifyNoZombieTUNBridge(t, ctx)
}

func verifyNoZombieTUNBridge(t *testing.T, ctx context.Context) {
	t.Helper()
	localDev := newBlockingTUNDev()
	remoteR, remoteW := io.Pipe()
	tr := newWatchableTransport()
	tr.remoteTUN = &pipeRWC{r: remoteR, w: remoteW}
	fwd := forward.NewForwarder(forward.Config{TUNDevice: stubBlockingTUNPort{dev: localDev}})

	tunSpec, _ := ports.NewTUNSpec(ports.TUNModePointToPoint, 0, 0)
	fwdSpec, _ := ports.NewForwardTUNSpec(tunSpec)
	h, err := fwd.StartForward(ctx, tr, fwdSpec)
	if err != nil {
		t.Fatalf("StartForward(TUN): %v", err)
	}
	// 关闭远端写端触发 remoteTUN.Read -> io.EOF，localDev 必须随之被立即关闭而非僵死。
	_ = remoteW.Close()
	select {
	case <-h.Done():
	case <-time.After(500 * time.Millisecond):
		_ = h.Close()
		t.Fatal("remoteTUN EOF 后 TUN 桥接僵死，未关闭 localDev")
	}
	_ = h.Close()
}

type pipeRWC struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func (p *pipeRWC) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *pipeRWC) Write(b []byte) (int, error) { return p.w.Write(b) }
func (p *pipeRWC) Close() error                { _ = p.r.Close(); return p.w.Close() }
