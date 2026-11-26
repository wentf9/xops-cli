package mux_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial/chanconn"
	"github.com/wentf9/xops-cli/core/internal/sshnet/forward"
	"github.com/wentf9/xops-cli/core/internal/sshnet/mux"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
)

// 编译期契约断言：确保 MuxSocket 与 MuxTransportConn 严格满足 core/ports 导出接口。
var (
	_ ports.MuxSocketPort = (*mux.MuxSocket)(nil)
	_ ports.TransportConn = (*mux.MuxTransportConn)(nil)
)

func shortMuxTempDir(t *testing.T) string {
	t.Helper()
	parent := os.TempDir()
	if runtime.GOOS != "windows" {
		parent = "/tmp"
	}
	dir, err := os.MkdirTemp(parent, "xm-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sub := filepath.Join(dir, "s")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	return sub
}

func mustLocalSource(t *testing.T, raw string) pathalg.LocalSourcePath {
	t.Helper()
	p, err := pathalg.ParseLocalSourcePath(raw)
	if err != nil {
		t.Fatalf("ParseLocalSourcePath(%q): %v", raw, err)
	}
	return p
}

func TestMuxSocket_TCKSuite(t *testing.T) {
	dir := shortMuxTempDir(t)
	listenPath := mustLocalSource(t, filepath.Join(dir, "live.sock"))
	if runtime.GOOS != "windows" {
		// Unix 上显式验证含 OpenSSH ':' 的 ControlPath（INV-A3）。
		listenPath = mustLocalSource(t, filepath.Join(dir, "cm-op@h:22"))
	}
	simDialer := sim.NewSimDialer(nil, nil)
	singlePlan, _ := tck.MustHopAndPlan(t)
	hop0, _ := singlePlan.HopAt(0)
	dig0, _ := singlePlan.HopDigestAt(0)

	tck.RunMuxSocketSuite(t, tck.MuxSocketFixture{
		NewMux: func(t *testing.T) (ports.MuxSocketPort, pathalg.LocalSourcePath) {
			return mux.NewMuxSocket(mux.Config{}), listenPath
		},
		NewUpstream: func(t *testing.T) ports.TransportConn {
			up, dErr := simDialer.DialHop(context.Background(), hop0, dig0, nil)
			if dErr != nil {
				t.Fatalf("DialHop(serveUp): %v", dErr)
			}
			t.Cleanup(func() { _ = up.Close() })
			return up
		},
		NewForwarder: func(t *testing.T) ports.ForwarderPort {
			return forward.NewForwarder(forward.Config{TUNDevice: sim.NewSimTUNDevicePort()})
		},
	})
}

func TestMuxSocket_ControlForwardCancelStopAndProxy(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dir := shortMuxTempDir(t)
	sockPath := mustLocalSource(t, filepath.Join(dir, "ctrl.sock"))

	// 未运行主进程时 Probe 返回 alive=false，Control/OpenProxy/DialMux 返回 ErrMuxUnavailable。
	m := mux.NewMuxSocket(mux.Config{
		ProxyHandler: func(_ context.Context, conn net.Conn, _ ports.TransportConn) error {
			buf := make([]byte, 16)
			n, err := conn.Read(buf)
			if err != nil {
				return err
			}
			_, err = conn.Write(bytes.ToUpper(buf[:n]))
			return err
		},
	})
	resp, err := m.Probe(ctx, sockPath)
	if err != nil || !resp.IsValid() || resp.Alive() || resp.MasterPID() != 0 {
		t.Fatalf("缺失套接字 Probe = (%#v, %v), 期望 alive=false", resp, err)
	}
	checkReq, _ := ports.NewMuxControlRequest(ports.MuxActionCheck, sockPath, algebraic.None[ports.ForwardSpec]())
	if _, err := m.Control(ctx, checkReq); !errors.Is(err, ports.ErrMuxUnavailable) {
		t.Fatalf("缺失套接字 Control = %v, 期望 ErrMuxUnavailable", err)
	}
	if _, err := m.OpenProxy(ctx, sockPath); !errors.Is(err, ports.ErrMuxUnavailable) {
		t.Fatalf("缺失套接字 OpenProxy = %v, 期望 ErrMuxUnavailable", err)
	}

	simDialer := sim.NewSimDialer(nil, nil)
	singlePlan, _ := tck.MustHopAndPlan(t)
	hop0, _ := singlePlan.HopAt(0)
	dig0, _ := singlePlan.HopDigestAt(0)
	up, err := simDialer.DialHop(ctx, hop0, dig0, nil)
	if err != nil {
		t.Fatalf("DialHop: %v", err)
	}
	defer func() { _ = up.Close() }()
	fwd := forward.NewForwarder(forward.Config{TUNDevice: sim.NewSimTUNDevicePort()})

	ready := make(chan struct{})
	err = conc.RunWait(ctx, func(rCtx context.Context, n *conc.Nursery) error {
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
			return exerciseControlAndProxy(t, c, m, sockPath, dig0, hop0.Endpoint())
		})
	})
	if err != nil {
		t.Fatalf("Control/Proxy 生命周期验证失败: %v", err)
	}
}

func exerciseControlAndProxy(t *testing.T, ctx context.Context, m *mux.MuxSocket, sockPath pathalg.LocalSourcePath, dig plan.HopDigest, ep netaddr.Endpoint) error {
	// 1. Control(Forward) 与 Control(Cancel) 动态开关本地 TCP 转发。
	fwdSpec, _ := ports.NewForwardSpec(ports.ForwardLocal, "127.0.0.1:0", "10.0.0.5:80")
	openReq, _ := ports.NewMuxControlRequest(ports.MuxActionForward, sockPath, algebraic.Some(fwdSpec))
	if r, err := m.Control(ctx, openReq); err != nil || !r.Alive() || r.MasterPID() == 0 {
		return errors.Join(errors.New("Control(forward) 失败"), err)
	}
	cancelReq, _ := ports.NewMuxControlRequest(ports.MuxActionCancel, sockPath, algebraic.Some(fwdSpec))
	if r, err := m.Control(ctx, cancelReq); err != nil || !r.Alive() {
		return errors.Join(errors.New("Control(cancel) 失败"), err)
	}

	// 2. OpenProxy 双向流透传校验。
	pConn, err := m.OpenProxy(ctx, sockPath)
	if err != nil {
		return err
	}
	if _, err := pConn.Write([]byte("mux-proxy")); err != nil {
		_ = pConn.Close()
		return err
	}
	var pBuf [9]byte
	if _, err := io.ReadFull(pConn, pBuf[:]); err != nil {
		_ = pConn.Close()
		return err
	}
	_ = pConn.Close()
	if string(pBuf[:]) != "MUX-PROXY" {
		return errors.New("OpenProxy 回显数据不匹配")
	}

	// 3. DialMux 复用执行命令、保活与隧道能力。
	mConn, err := m.DialMux(ctx, sockPath, dig, ep)
	if err != nil {
		return err
	}
	defer func() { _ = mConn.Close() }()
	if err := mConn.SendKeepalive(ctx); err != nil {
		return err
	}
	if err := exerciseMuxSession(t, ctx, mConn); err != nil {
		return err
	}

	// 4. Control(Stop) 优雅停止 ControlMaster。
	stopReq, _ := ports.NewMuxControlRequest(ports.MuxActionStop, sockPath, algebraic.None[ports.ForwardSpec]())
	_, err = m.Control(ctx, stopReq)
	return err
}

func exerciseMuxSession(t *testing.T, ctx context.Context, conn ports.TransportConn) error {
	sess, err := conn.OpenSession(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = sess.Close() }()
	cmd := tck.MustCommandPlan(t, "echo mux-ok")
	var outBuf bytes.Buffer
	if err := sess.Start(ctx, cmd, ports.ExecStreams{Stdout: &outBuf}); err != nil {
		return err
	}
	out, err := sess.Wait(ctx)
	if err != nil || out == nil || !out.IsValid() {
		return errors.Join(errors.New("mux session Wait 失败"), err)
	}
	if _, ok := out.(*execution.OutcomeCompleted); !ok {
		return errors.New("期望 OutcomeCompleted")
	}
	return nil
}

// TestMuxSocket_RawOpenSSHProtocolV4Interop 验证客户端与纯 OpenSSH PROTOCOL.mux v4（不含 XOps 扩展）服务端互操作。
func TestMuxSocket_RawOpenSSHProtocolV4Interop(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dir := shortMuxTempDir(t)
	sockPath := mustLocalSource(t, filepath.Join(dir, "openssh.sock"))
	m := mux.NewMuxSocket(mux.Config{})

	ready := make(chan struct{})
	srvDone := make(chan struct{})
	srvCtx, cancelSrv := context.WithCancel(ctx)
	defer cancelSrv()
	n, err := conc.NewNursery(srvCtx)
	if err != nil {
		t.Fatalf("NewNursery: %v", err)
	}
	if err := n.Go(func(c context.Context) error {
		defer close(srvDone)
		return m.WithListener(c, sockPath, func(ln net.Listener) error {
			close(ready)
			return serveRawOpenSSHMuxStub(c, ln)
		})
	}); err != nil {
		t.Fatalf("Nursery.Go: %v", err)
	}
	select {
	case <-ready:
	case <-srvDone:
		_ = n.Close()
		t.Fatal("OpenSSH v4 测试桩在就绪前提前退出")
	case <-ctx.Done():
		cancelSrv()
		<-srvDone
		_ = n.Close()
		t.Fatalf("等待 OpenSSH v4 测试桩就绪超时: %v", ctx.Err())
	}

	resp, err := m.Probe(ctx, sockPath)
	if err != nil || !resp.Alive() || resp.MasterPID() != 7788 {
		t.Fatalf("OpenSSH v4 互操作 Probe = (%#v, %v), 期望 pid=7788", resp, err)
	}
	singlePlan, _ := tck.MustHopAndPlan(t)
	hop0, _ := singlePlan.HopAt(0)
	dig0, _ := singlePlan.HopDigestAt(0)
	mc, err := m.DialMux(ctx, sockPath, dig0, hop0.Endpoint())
	if err != nil {
		t.Fatalf("DialMux(OpenSSH stub): %v", err)
	}
	if err := mc.SendKeepalive(ctx); err != nil {
		t.Fatalf("SendKeepalive(OpenSSH stub): %v", err)
	}
	// 无 xops-stream-mux 扩展时，流式方法必须明确失败关闭返回 ErrUnsupported。
	if _, err := mc.OpenSession(ctx); !errors.Is(err, ports.ErrUnsupported) {
		t.Fatalf("纯 OpenSSH 桩 OpenSession = %v, 期望 ErrUnsupported", err)
	}
	_ = mc.Close()

	exitReq, _ := ports.NewMuxControlRequest(ports.MuxActionExit, sockPath, algebraic.None[ports.ForwardSpec]())
	if _, err := m.Control(ctx, exitReq); err != nil {
		t.Fatalf("Control(exit) OpenSSH stub: %v", err)
	}
	cancelSrv()
	<-srvDone
	_ = n.Close()
}

func serveRawOpenSSHMuxStub(ctx context.Context, ln net.Listener) error {
	return chanconn.RunWithAbortWatchdog(ctx, func() { _ = ln.Close() }, func() error {
		for {
			c, err := ln.Accept()
			if err != nil {
				return nil
			}
			shouldStop, _ := handleRawOpenSSHConn(c)
			_ = c.Close()
			if shouldStop {
				_ = ln.Close()
				return nil
			}
		}
	})
}

func handleRawOpenSSHConn(c net.Conn) (bool, error) {
	// 标准 OpenSSH MUX_MSG_HELLO: [len=8][type=0x00000001][ver=4]，零扩展。
	hello := []byte{0, 0, 0, 8, 0, 0, 0, 1, 0, 0, 0, 4}
	if _, err := c.Write(hello); err != nil {
		return false, err
	}
	if _, _, err := readRawMuxFrame(c); err != nil {
		return false, err
	}
	for {
		mType, body, err := readRawMuxFrame(c)
		if err != nil || len(body) < 4 {
			return false, err
		}
		reqID := binary.BigEndian.Uint32(body[:4])
		switch mType {
		case 0x10000004: // MUX_C_ALIVE_CHECK -> MUX_S_ALIVE (pid=7788)
			var out [16]byte
			binary.BigEndian.PutUint32(out[0:4], 12)
			binary.BigEndian.PutUint32(out[4:8], 0x80000005)
			binary.BigEndian.PutUint32(out[8:12], reqID)
			binary.BigEndian.PutUint32(out[12:16], 7788)
			if _, wErr := c.Write(out[:]); wErr != nil {
				return false, wErr
			}
		case 0x10000005: // MUX_C_TERMINATE -> MUX_S_OK
			var out [12]byte
			binary.BigEndian.PutUint32(out[0:4], 8)
			binary.BigEndian.PutUint32(out[4:8], 0x80000001)
			binary.BigEndian.PutUint32(out[8:12], reqID)
			_, wErr := c.Write(out[:])
			return true, wErr
		default:
			return false, nil
		}
	}
}

func readRawMuxFrame(r io.Reader) (uint32, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return binary.BigEndian.Uint32(buf[:4]), buf[4:], nil
}

func TestMuxSocket_ZeroValueFailClosed(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	var zeroMux mux.MuxSocket
	var zeroConn mux.MuxTransportConn
	dir := shortMuxTempDir(t)
	p := mustLocalSource(t, filepath.Join(dir, "z.sock"))
	if _, err := zeroMux.Probe(ctx, p); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("零值 MuxSocket.Probe = %v, 期望 ErrClosed", err)
	}
	if zeroConn.IsAlive() || zeroConn.HopDigest().IsValid() || zeroConn.Endpoint().IsValid() {
		t.Fatal("零值 MuxTransportConn 必须失败关闭")
	}
	if err := zeroConn.SendKeepalive(ctx); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("零值 MuxTransportConn.SendKeepalive = %v, 期望 ErrClosed", err)
	}
	if err := zeroConn.Close(); err != nil {
		t.Fatalf("零值 MuxTransportConn.Close: %v", err)
	}
	// 非套接字常规文件保护：Probe 返回 ErrMuxUnavailable，WithListener 返回 ErrInvalidArgument 且绝不误删。
	reg := filepath.Join(dir, "keep.txt")
	if err := os.WriteFile(reg, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	regSrc := mustLocalSource(t, reg)
	m := mux.NewMuxSocket(mux.Config{})
	if _, err := m.Probe(ctx, regSrc); !errors.Is(err, ports.ErrMuxUnavailable) {
		t.Fatalf("常规文件 Probe = %v, 期望 ErrMuxUnavailable", err)
	}
	if err := m.WithListener(ctx, regSrc, func(net.Listener) error { return nil }); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("常规文件 WithListener = %v, 期望 ErrInvalidArgument", err)
	}
	if raw, rErr := os.ReadFile(reg); rErr != nil || !strings.EqualFold(string(raw), "precious") {
		t.Fatalf("常规文件受损: (%q, %v)", string(raw), rErr)
	}
}

// TestMuxSocket_IdleClientO1Shutdown 验证存在空闲已连接客户端时，Control(Exit) 触发 Serve 在 O(1) 时间内收敛退出。
func TestMuxSocket_IdleClientO1Shutdown(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dir := shortMuxTempDir(t)
	sockPath := mustLocalSource(t, filepath.Join(dir, "idle.sock"))
	m := mux.NewMuxSocket(mux.Config{HandshakeTimeout: 30 * time.Second})

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
	var stopElapsed time.Duration
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
			// 打开一条长连代理连接并故意保持空闲不发数据。
			idleConn, oErr := m.OpenProxy(c, sockPath)
			if oErr != nil {
				return oErr
			}
			defer func() { _ = idleConn.Close() }()

			start := time.Now()
			exitReq, _ := ports.NewMuxControlRequest(ports.MuxActionExit, sockPath, algebraic.None[ports.ForwardSpec]())
			if _, cErr := m.Control(c, exitReq); cErr != nil {
				return cErr
			}
			// 确认空闲连接在主进程退出时被及时断开。
			buf := make([]byte, 1)
			_, _ = idleConn.Read(buf)
			stopElapsed = time.Since(start)
			return nil
		})
	})
	if err != nil {
		t.Fatalf("空闲客户端停机验证失败: %v", err)
	}
	if stopElapsed > 500*time.Millisecond {
		t.Fatalf("存在空闲客户端时 ControlMaster 停机耗时 %v 过长", stopElapsed)
	}
}
