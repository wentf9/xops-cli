package mux_test

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/internal/sshnet/forward"
	"github.com/wentf9/xops-cli/core/internal/sshnet/mux"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
)

// TestMuxSocket_StopListeningDrainsAndEphemeralForwards 验证：
//  1. 多个临时端口 :0 转发共存不误报重复，且可分别取消；
//  2. ListenTCP 对非法地址失败关闭；
//  3. 单次调用 ctx 取消绝不误杀健康的 MuxTransportConn.IsAlive()；
//  4. CStopListening (-O stop) 停止接收新连接同时允许已在途代理连接平滑排空退出。
func TestMuxSocket_StopListeningDrainsAndEphemeralForwards(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dir := shortMuxTempDir(t)
	sockPath := mustLocalSource(t, filepath.Join(dir, "drain.sock"))

	proxyRelease := make(chan struct{})
	m := mux.NewMuxSocket(mux.Config{
		ProxyHandler: func(pCtx context.Context, conn net.Conn, _ ports.TransportConn) error {
			select {
			case <-proxyRelease:
				_, err := conn.Write([]byte("DRAINED"))
				return err
			case <-pCtx.Done():
				return pCtx.Err()
			}
		},
	})
	simDialer := sim.NewSimDialer(nil, nil)
	singlePlan, _ := tck.MustHopAndPlan(t)
	hop0, _ := singlePlan.HopAt(0)
	dig0, _ := singlePlan.HopDigestAt(0)
	up, err := simDialer.DialHop(ctx, hop0, dig0, nil)
	if err != nil {
		t.Fatalf("DialHop: %v", err)
	}
	defer func() { _ = up.Close() }()
	fwd := forward.NewForwarder(forward.Config{})

	ready := make(chan struct{})
	err = conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(c context.Context) error {
			return m.WithListener(c, sockPath, func(ln net.Listener) error {
				close(ready)
				return m.Serve(c, ln, up, fwd)
			})
		}); gErr != nil {
			return gErr
		}
		return n.Go(func(c context.Context) error {
			select {
			case <-ready:
			case <-c.Done():
				return c.Err()
			}
			return runMuxHardeningChecks(c, m, sockPath, proxyRelease)
		})
	})
	if err != nil {
		t.Fatalf("Mux 强化回归验证失败: %v", err)
	}
}

func runMuxHardeningChecks(
	ctx context.Context,
	m *mux.MuxSocket,
	sockPath pathalg.LocalSourcePath,
	proxyRelease chan struct{},
) error {
	// 1. 同一目标启动两个临时 :0 转发必须同时成功并支持逐一取消。
	fwdSpec, _ := ports.NewForwardSpec(ports.ForwardLocal, "127.0.0.1:0", "10.0.0.8:80")
	openReq, _ := ports.NewMuxControlRequest(ports.MuxActionForward, sockPath, algebraic.Some(fwdSpec))
	if _, err := m.Control(ctx, openReq); err != nil {
		return err
	}
	if _, err := m.Control(ctx, openReq); err != nil {
		return errors.Join(errors.New("第二个临时 :0 转发不应误报重复"), err)
	}
	cancelReq, _ := ports.NewMuxControlRequest(ports.MuxActionCancel, sockPath, algebraic.Some(fwdSpec))
	if _, err := m.Control(ctx, cancelReq); err != nil {
		return err
	}
	if _, err := m.Control(ctx, cancelReq); err != nil {
		return err
	}

	// 2. 打开一条活跃代理流，然后发送 Control(Stop)：新连接被拒绝，但已打开的代理流必须完好排空。
	pConn, err := m.OpenProxy(ctx, sockPath)
	if err != nil {
		return err
	}
	defer func() { _ = pConn.Close() }()

	stopReq, _ := ports.NewMuxControlRequest(ports.MuxActionStop, sockPath, algebraic.None[ports.ForwardSpec]())
	if _, err := m.Control(ctx, stopReq); err != nil {
		return err
	}
	close(proxyRelease)
	var drained [7]byte
	if _, err := io.ReadFull(pConn, drained[:]); err != nil || string(drained[:]) != "DRAINED" {
		return errors.Join(errors.New("CStopListening 提前中断了在途活跃代理流"), err)
	}
	return nil
}

// TestMuxSocket_ClientCancelDoesNotPoisonAliveAndListenTCPValidation 验证 #123 m1 与 #124 m4 修复。
func TestMuxSocket_ClientCancelDoesNotPoisonAliveAndListenTCPValidation(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	dir := shortMuxTempDir(t)
	sockPath := mustLocalSource(t, filepath.Join(dir, "alive.sock"))
	m := mux.NewMuxSocket(mux.Config{})

	simDialer := sim.NewSimDialer(nil, nil)
	singlePlan, _ := tck.MustHopAndPlan(t)
	hop0, _ := singlePlan.HopAt(0)
	dig0, _ := singlePlan.HopDigestAt(0)
	up, err := simDialer.DialHop(ctx, hop0, dig0, nil)
	if err != nil {
		t.Fatalf("DialHop: %v", err)
	}
	defer func() { _ = up.Close() }()

	ready := make(chan struct{})
	err = conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(c context.Context) error {
			return m.WithListener(c, sockPath, func(ln net.Listener) error {
				close(ready)
				return m.Serve(c, ln, up, nil)
			})
		}); gErr != nil {
			return gErr
		}
		return n.Go(func(c context.Context) error {
			select {
			case <-ready:
			case <-c.Done():
				return c.Err()
			}
			mc, dErr := m.DialMux(c, sockPath, dig0, hop0.Endpoint())
			if dErr != nil {
				return dErr
			}
			defer func() { _ = mc.Close() }()
			return runClientAliveAndListenTCPChecks(c, m, sockPath, mc)
		})
	})
	if err != nil {
		t.Fatalf("客户端存活隔离与 ListenTCP 校验失败: %v", err)
	}
}

func runClientAliveAndListenTCPChecks(
	ctx context.Context,
	m *mux.MuxSocket,
	sockPath pathalg.LocalSourcePath,
	mc ports.TransportConn,
) error {
	// 1. 非法 ListenTCP 地址立即失败关闭。
	if _, lErr := mc.ListenTCP(ctx, "missing-port"); !errors.Is(lErr, ports.ErrInvalidArgument) {
		return errors.New("非法 ListenTCP 地址应返回 ErrInvalidArgument")
	}
	// 2. 已取消的调用方 ctx 绝不能把健康的 MuxTransportConn.IsAlive() 误置为 false。
	canceledCtx, cCancel := context.WithCancel(ctx)
	cCancel()
	if kErr := mc.SendKeepalive(canceledCtx); !errors.Is(kErr, context.Canceled) {
		return errors.New("已取消 ctx 应返回 context.Canceled")
	}
	if !mc.IsAlive() {
		return errors.New("单次调用方 ctx 取消错误地污染了 MuxTransportConn.IsAlive()")
	}
	if kErr := mc.SendKeepalive(ctx); kErr != nil {
		return kErr
	}
	exitReq, _ := ports.NewMuxControlRequest(ports.MuxActionExit, sockPath, algebraic.None[ports.ForwardSpec]())
	_, cErr := m.Control(ctx, exitReq)
	return cErr
}
