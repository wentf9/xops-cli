package muxstream_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/internal/sshnet/mux/muxstream"
	"github.com/wentf9/xops-cli/core/ports"
)

// 编译期契约断言：确保 RemoteSession 与 RemoteListener 满足核心接口。
var (
	_ ports.RemoteSession = (*muxstream.RemoteSession)(nil)
	_ net.Listener        = (*muxstream.RemoteListener)(nil)
)

func TestMuxStream_ZeroValuesAndListenerBridgeRoundTrip(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var zeroSess muxstream.RemoteSession
	if _, err := zeroSess.StdinPipe(); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("零值 RemoteSession.StdinPipe = %v, 期望 ErrClosed", err)
	}
	if _, err := zeroSess.Wait(ctx); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("零值 RemoteSession.Wait = %v, 期望 ErrClosed", err)
	}
	if err := zeroSess.Close(); err != nil {
		t.Fatalf("零值 RemoteSession.Close: %v", err)
	}

	var zeroLn muxstream.RemoteListener
	if _, err := zeroLn.Accept(); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("零值 RemoteListener.Accept = %v, 期望 ErrClosed", err)
	}
	if err := zeroLn.Close(); err != nil {
		t.Fatalf("零值 RemoteListener.Close: %v", err)
	}

	// 验证 RemoteListener <-> ServeListenerBridge 端到端数据帧与半关闭透传。
	var lc net.ListenConfig
	rawLn, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	cliPipe, srvPipe := net.Pipe()
	bridgeCtx, cancelBridge := context.WithCancel(ctx)
	defer cancelBridge()

	err = conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			muxstream.ServeListenerBridge(bridgeCtx, srvPipe, rawLn)
			return nil
		}); gErr != nil {
			return gErr
		}
		defer cancelBridge()
		rl, rErr := muxstream.NewRemoteListener(n, cliPipe, "tcp", rawLn.Addr().String())
		if rErr != nil {
			return rErr
		}
		defer func() { _ = rl.Close() }()
		return verifyMuxListenerEcho(ctx, n, rawLn.Addr().String(), rl)
	})
	if err != nil {
		t.Fatalf("ListenerBridge 往返失败: %v", err)
	}
}

func verifyMuxListenerEcho(ctx context.Context, n *conc.Nursery, dialAddr string, rl *muxstream.RemoteListener) error {
	dialErrCh := make(chan error, 1)
	if err := n.Go(func(context.Context) error {
		dialErrCh <- dialAndVerifyMuxEcho(ctx, dialAddr)
		return nil
	}); err != nil {
		return err
	}
	ac, err := rl.Accept()
	if err != nil {
		return err
	}
	buf := make([]byte, 18)
	if _, err := io.ReadFull(ac, buf); err != nil {
		_ = ac.Close()
		return err
	}
	if _, err := ac.Write(bytes.ToUpper(buf)); err != nil {
		_ = ac.Close()
		return err
	}
	if hc, ok := ac.(muxstream.HalfWriteCloser); ok {
		_ = hc.CloseWrite()
	}
	_ = ac.Close()
	if _, rErr := ac.Read(make([]byte, 1)); !errors.Is(rErr, net.ErrClosed) {
		return errors.New("本地 Close 后 Read 必须返回 net.ErrClosed")
	}
	select {
	case err := <-dialErrCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func dialAndVerifyMuxEcho(ctx context.Context, dialAddr string) error {
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", dialAddr)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte("hello-mux-listener")); err != nil {
		return err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	got, err := io.ReadAll(c)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, []byte("HELLO-MUX-LISTENER")) {
		return errors.New("ListenerBridge 回显内容不一致")
	}
	return nil
}
