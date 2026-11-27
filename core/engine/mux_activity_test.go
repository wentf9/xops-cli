package engine

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/sshnet/mux"
	"github.com/wentf9/xops-cli/core/ports"
)

type stubAliveTransport struct {
	ports.TransportConn
}

func (stubAliveTransport) IsAlive() bool { return true }
func (stubAliveTransport) Close() error  { return nil }

func TestNormalizeMuxSocketKey_RelativeAlphaColonAndWindowsPrefix(t *testing.T) {
	defer goleak.VerifyNone(t)
	if got, want := normalizeMuxSocketKey("./u:22"), normalizeMuxSocketKey("u:22"); got != want || got != "u:22" {
		t.Fatalf("./<alpha>: 规范化失配: got=%q want=%q", got, want)
	}
	if got := normalizeMuxSocketKey("././sub/cm.sock"); got != "sub/cm.sock" {
		t.Fatalf("多层 ./ 规范化失配: got=%q", got)
	}
	if got := normalizeMuxSocketKey(`\\?\C:\Users\ops\cm.sock`); got != "c:/Users/ops/cm.sock" {
		t.Fatalf("Windows 扩展前缀与盘符规范化失配: got=%q", got)
	}
}

func TestMuxActivityHub_UnregistersOnSocketClosedAndRealMuxServeExit(t *testing.T) {
	defer goleak.VerifyNone(t)
	hub := newMuxActivityHub()

	pd := plan.PlanDigestFromSHA256([32]byte{1})
	hid, err := plan.ParseHandleID("mux-test-1")
	if err != nil {
		t.Fatalf("ParseHandleID: %v", err)
	}
	binding, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityTunnel, Tool: "mux", Action: "start", NodeID: "node-1",
		PlanDigest: algebraic.Some(pd.SecurityDigest()),
	})
	if err != nil {
		t.Fatalf("NewOperationBinding: %v", err)
	}
	handle, err := plan.NewManagedHandle[plan.KindMux](hid, 1, pd, binding)
	if err != nil {
		t.Fatalf("NewManagedHandle: %v", err)
	}

	// 1. 已关闭 doneCh 的句柄不会写入 bySock，避免快速自退出竞态残留。
	closedCh := make(chan struct{})
	close(closedCh)
	hub.register("./fast:22", handle, closedCh)
	if len(hub.bySock) != 0 {
		t.Fatalf("已关闭 doneCh 不应写入 bySock，实际 len=%d", len(hub.bySock))
	}

	// 2. 即使上下文已取消，SocketActivityClosed 仍须精确注销（含 ./<alpha>: 键对齐）。
	hub.register("./u:22", handle, nil)
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	hub.notify(canceledCtx, "u:22", mux.SocketActivityClosed)
	if len(hub.bySock) != 0 {
		t.Fatalf("SocketActivityClosed 后 bySock 必须归零，实际 len=%d", len(hub.bySock))
	}

	// 3. 联动真实 MuxSocket.WithListener + Serve：无论运行中取消还是 Serve 前取消，退出均自动触发 SocketActivityClosed 归零 bySock。
	assertMuxServeUnregistersOnExit(t, hub, handle)
}

func assertMuxServeUnregistersOnExit(t *testing.T, hub *muxActivityHub, handle plan.ManagedHandle[plan.KindMux]) {
	t.Helper()
	sockPath, err := pathalg.ParseLocalSourcePath(filepath.Join(t.TempDir(), "cm-close.sock"))
	if err != nil {
		t.Fatalf("ParseLocalSourcePath: %v", err)
	}
	ms := mux.NewMuxSocket(mux.Config{OnSocketActivity: hub.notify})

	// 3a. Serve 运行中被取消（真实监听路径）。
	hub.register(sockPath.String(), handle, nil)
	if len(hub.bySock) != 1 {
		t.Fatalf("注册后 bySock 应为 1，实际=%d", len(hub.bySock))
	}
	serveCtx, stopServe := context.WithCancel(context.Background())
	defer stopServe()
	started := make(chan struct{})
	if err := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			<-started
			_, _ = ms.Probe(context.Background(), sockPath)
			stopServe()
			return nil
		}); gErr != nil {
			return gErr
		}
		err := ms.WithListener(serveCtx, sockPath, func(ln net.Listener) error {
			close(started)
			return ms.Serve(serveCtx, ln, stubAliveTransport{}, nil)
		})
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		return nil
	}); err != nil {
		t.Fatalf("运行中取消 MuxSocket.Serve 返回意外错误: %v", err)
	}
	if len(hub.bySock) != 0 {
		t.Fatalf("运行中取消 MuxSocket.Serve 后 bySock 必须归零，实际=%v", hub.bySock)
	}

	// 3b. 进入 Serve 前取消（WithListener 兜底路径）。
	hub.register(sockPath.String(), handle, nil)
	serveCtx2, stopServe2 := context.WithCancel(context.Background())
	defer stopServe2()
	if err := ms.WithListener(serveCtx2, sockPath, func(ln net.Listener) error {
		stopServe2()
		return ms.Serve(serveCtx2, ln, stubAliveTransport{}, nil)
	}); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("进入 Serve 前取消返回意外错误: %v", err)
	}
	if len(hub.bySock) != 0 {
		t.Fatalf("进入 Serve 前取消后 bySock 必须归零，实际=%v", hub.bySock)
	}
}
