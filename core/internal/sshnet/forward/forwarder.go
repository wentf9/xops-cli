package forward

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/conc"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial/chanconn"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
)

type (
	waitDoneProvider interface{ WaitDone() <-chan struct{} }
	aliveChecker     interface{ IsAlive() bool }
)

// Handle 表示运行中的受管隧道转发实例，实现 ports.ForwardHandle（兼容 pool.ManagedResource）；零值恒无效。
//
//xops:opaque
//xops:failclosed
type Handle struct {
	spec      ports.ForwardSpec
	boundAddr string
	nursery   *conc.Nursery
	doneCh    chan struct{}

	errMu    sync.Mutex
	firstErr error

	onStopOnce sync.Once
	onStop     func()

	closed    atomic.Bool
	closeOnce sync.Once
	valid     bool
}

// IsValid 报告转发句柄是否已正确初始化且尚未关闭或终止。
func (h *Handle) IsValid() bool { return h != nil && h.valid && !h.closed.Load() }

// Spec 返回转发句柄绑定的不可变 ForwardSpec。
func (h *Handle) Spec() ports.ForwardSpec {
	if h == nil || !h.valid {
		return zeroVal[ports.ForwardSpec]()
	}
	return h.spec
}

// BoundAddr 返回实际绑定的监听地址（TCP 含分配端口、Unix 为原生路径、TUN 为本机网卡名）。
func (h *Handle) BoundAddr() string {
	if h == nil || !h.valid {
		return ""
	}
	return h.boundAddr
}

// Done 返回只读通道，当转发彻底终止且后台监听/中继协程全部退出后关闭。
func (h *Handle) Done() <-chan struct{} {
	if h == nil || !h.valid {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return h.doneCh
}

// Err 返回转发运行或关闭期间记录的首个非预期故障。
func (h *Handle) Err() error {
	if h == nil || !h.valid {
		return ports.ErrClosed
	}
	h.errMu.Lock()
	defer h.errMu.Unlock()
	return h.firstErr
}

// Close 幂等停止监听、关闭活动连接与 TUN 设备并同步排空全部受监督协程（零泄漏）。
func (h *Handle) Close() error {
	if h == nil || !h.valid {
		return nil
	}
	h.closeOnce.Do(func() {
		h.closed.Store(true)
		h.triggerStop()
		h.nursery.Cancel(ports.ErrClosed)
		_ = h.nursery.Close()
		<-h.doneCh
	})
	return nil
}

func (h *Handle) recordErr(err error) {
	if err == nil || isBenignCloseErr(err) {
		return
	}
	h.errMu.Lock()
	if h.firstErr == nil {
		h.firstErr = err
	}
	h.errMu.Unlock()
}

func (h *Handle) triggerStop() {
	h.onStopOnce.Do(func() {
		if h.onStop != nil {
			h.onStop()
		}
	})
}

// StartForward 校验规格与安全绑定边界，启动受管长生命周期隧道转发并返回 ports.ForwardHandle。
// 参数 ctx 仅约束本次同步建链/绑定阶段，返回后 Handle 独立运行，并随上游 transport 断连或 Close() 收敛退出。
func (f *Forwarder) StartForward(ctx context.Context, transport ports.TunnelTransport, spec ports.ForwardSpec) (ports.ForwardHandle, error) {
	if ctx == nil {
		return nil, ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f == nil || !f.valid {
		return nil, ports.ErrClosed
	}
	if transport == nil || !spec.IsValid() {
		return nil, domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "TunnelTransport or ForwardSpec"))
	}
	if ac, ok := transport.(aliveChecker); ok && !ac.IsAlive() {
		return nil, ports.ErrClosed
	}
	switch spec.Direction() {
	case ports.ForwardLocal:
		return f.startLocalForward(ctx, transport, spec)
	case ports.ForwardRemote:
		return f.startRemoteForward(ctx, transport, spec)
	case ports.ForwardDynamic:
		return f.startDynamicForward(ctx, transport, spec)
	case ports.ForwardTUN:
		return f.startTUNForward(ctx, transport, spec)
	default:
		return nil, domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyCommonNotSupported, domi18n.Str("feature", "forward direction "+spec.Direction().String()))
	}
}

func (f *Forwarder) startLocalForward(ctx context.Context, transport ports.TunnelTransport, spec ports.ForwardSpec) (*Handle, error) {
	remoteDial, err := buildRemoteTargetDialer(transport, spec)
	if err != nil {
		return nil, err
	}
	if spec.BindKind() == ports.ForwardEndpointUnix {
		return f.startLocalUnixForward(ctx, transport, spec, remoteDial)
	}
	ln, err := f.listenLocalTCP(ctx, spec.BindAddr(), "listen local TCP")
	if err != nil {
		return nil, err
	}
	return startListenerHandle(ctx, transport, spec, ln, func(cCtx context.Context, c net.Conn) error {
		return relayAcceptedToDial(cCtx, c, remoteDial)
	})
}

func (f *Forwarder) listenLocalTCP(ctx context.Context, bindAddr, label string) (net.Listener, error) {
	listenAddr, err := validateLocalTCPBind(bindAddr, f.allowGatewayPorts)
	if err != nil {
		return nil, err
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", listenAddr)
	if err != nil {
		return nil, domi18n.WrapS(ports.ErrDialFailed, err, domi18n.KeyCommonOpTargetFailed, domi18n.Str("op", label), domi18n.BoundStr("target", listenAddr))
	}
	if !f.allowGatewayPorts {
		if err := verifyBoundLoopback(ln); err != nil {
			_ = ln.Close()
			return nil, err
		}
	}
	return ln, nil
}

func (f *Forwarder) startLocalUnixForward(ctx context.Context, transport ports.TunnelTransport, spec ports.ForwardSpec, remoteDial connDialFunc) (*Handle, error) {
	sockPath, err := osfs.ValidateControlSocketPath(spec.BindAddr())
	if err != nil {
		return nil, domi18n.WrapS(ports.ErrInvalidArgument, err, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "local Unix bind path"))
	}
	n, err := conc.NewNursery(context.Background())
	if err != nil {
		return nil, err
	}
	h := &Handle{spec: spec, nursery: n, doneCh: make(chan struct{}), valid: true}
	readyCh := make(chan string, 1)
	startErrCh := make(chan error, 1)
	if err := n.Go(func(runCtx context.Context) error {
		defer close(h.doneCh)
		defer h.closed.Store(true)
		bound := false
		wErr := runWithUpstreamWatch(runCtx, transport, h, func(wCtx context.Context) error {
			return osfs.WithSocketSlot(wCtx, sockPath, osfs.SocketSlotOptions{ReplaceStale: f.replaceStaleUnix}, func(slot *osfs.SocketSlot) error {
				bound = true
				readyCh <- slot.Path().NativePath()
				return serveBorrowedListener(wCtx, slot.Listener(), func(cCtx context.Context, c net.Conn) error {
					return relayAcceptedToDial(cCtx, c, remoteDial)
				})
			})
		})
		if !bound {
			startErrCh <- mapUnixSlotErr(wErr)
			return nil
		}
		h.recordErr(wErr)
		return nil
	}); err != nil {
		close(h.doneCh)
		_ = n.Close()
		return nil, err
	}
	return awaitAsyncUnixBind(ctx, h, readyCh, startErrCh)
}

func awaitAsyncUnixBind(ctx context.Context, h *Handle, readyCh <-chan string, startErrCh <-chan error) (*Handle, error) {
	select {
	case addr := <-readyCh:
		if err := ctx.Err(); err != nil {
			_ = h.Close()
			return nil, err
		}
		h.boundAddr = addr
		return h, nil
	case err := <-startErrCh:
		_ = h.Close()
		return nil, err
	case <-ctx.Done():
		_ = h.Close()
		return nil, ctx.Err()
	}
}

func (f *Forwarder) startRemoteForward(ctx context.Context, transport ports.TunnelTransport, spec ports.ForwardSpec) (*Handle, error) {
	localDial, err := f.buildLocalTargetDialer(spec)
	if err != nil {
		return nil, err
	}
	ln, err := openRemoteListener(ctx, transport, spec)
	if err != nil {
		return nil, err
	}
	return startListenerHandle(ctx, transport, spec, ln, func(cCtx context.Context, c net.Conn) error {
		return relayAcceptedToDial(cCtx, c, localDial)
	})
}

func openRemoteListener(ctx context.Context, transport ports.TunnelTransport, spec ports.ForwardSpec) (net.Listener, error) {
	if spec.BindKind() == ports.ForwardEndpointUnix {
		rp, err := pathalg.ParseRemotePath(spec.BindAddr())
		if err != nil {
			return nil, domi18n.WrapS(ports.ErrInvalidArgument, err, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "remote Unix bind path"))
		}
		return transport.ListenStreamLocal(ctx, rp)
	}
	if err := validateRemoteTCPBind(spec.BindAddr()); err != nil {
		return nil, err
	}
	return transport.ListenTCP(ctx, spec.BindAddr())
}

func (f *Forwarder) startDynamicForward(ctx context.Context, transport ports.TunnelTransport, spec ports.ForwardSpec) (*Handle, error) {
	ln, err := f.listenLocalTCP(ctx, spec.BindAddr(), "listen local SOCKS5")
	if err != nil {
		return nil, err
	}
	return startListenerHandle(ctx, transport, spec, ln, func(cCtx context.Context, c net.Conn) error {
		return f.serveSOCKS5Conn(cCtx, c, transport)
	})
}

func (f *Forwarder) startTUNForward(ctx context.Context, transport ports.TunnelTransport, spec ports.ForwardSpec) (*Handle, error) {
	tunSpec, ok := spec.TUN().Get()
	if !ok || !tunSpec.IsValid() {
		return nil, domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "TUNSpec"))
	}
	if f.tunDevice == nil {
		return nil, domi18n.EF(ports.ErrUnsupported, domi18n.KeyCommonMissingDep, domi18n.Str("component", "TUNDevicePort"))
	}
	localDev, ifaceName, err := f.tunDevice.OpenLocalTUN(ctx, tunSpec)
	if err != nil {
		return nil, err
	}
	if localDev == nil || ifaceName == "" {
		if localDev != nil {
			_ = localDev.Close()
		}
		return nil, domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "TUN device handle or interface name"))
	}
	remoteTUN, err := transport.OpenTUN(ctx, tunSpec)
	if err != nil {
		_ = localDev.Close()
		return nil, err
	}
	return startTUNBridgeHandle(ctx, transport, spec, ifaceName, localDev, remoteTUN)
}

func startTUNBridgeHandle(ctx context.Context, transport ports.TunnelTransport, spec ports.ForwardSpec, ifaceName string, localDev, remoteTUN io.ReadWriteCloser) (*Handle, error) {
	n, err := conc.NewNursery(context.Background())
	if err != nil {
		_ = localDev.Close()
		_ = remoteTUN.Close()
		return nil, err
	}
	closeBoth := func() {
		_ = localDev.Close()
		_ = remoteTUN.Close()
	}
	h := &Handle{spec: spec, boundAddr: ifaceName, nursery: n, doneCh: make(chan struct{}), onStop: closeBoth, valid: true}
	if err := n.Go(func(runCtx context.Context) error {
		defer close(h.doneCh)
		defer h.closed.Store(true)
		defer h.triggerStop()
		err := runWithUpstreamWatch(runCtx, transport, h, func(wCtx context.Context) error {
			return bridgeStreamsStrict(wCtx, localDev, remoteTUN)
		})
		h.recordErr(err)
		return nil
	}); err != nil {
		closeBoth()
		close(h.doneCh)
		_ = n.Close()
		return nil, err
	}
	return finishStartupHandle(ctx, h)
}

func startListenerHandle(ctx context.Context, transport ports.TunnelTransport, spec ports.ForwardSpec, ln net.Listener, handleConn connHandlerFunc) (*Handle, error) {
	n, err := conc.NewNursery(context.Background())
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	bound := ""
	if ln.Addr() != nil {
		bound = ln.Addr().String()
	}
	if bound == "" {
		bound = spec.BindAddr()
	}
	h := &Handle{
		spec:      spec,
		boundAddr: bound,
		nursery:   n,
		doneCh:    make(chan struct{}),
		onStop:    func() { _ = ln.Close() },
		valid:     true,
	}
	if err := n.Go(func(runCtx context.Context) error {
		defer close(h.doneCh)
		defer h.closed.Store(true)
		defer h.triggerStop()
		err := runWithUpstreamWatch(runCtx, transport, h, func(wCtx context.Context) error {
			return serveBorrowedListener(wCtx, ln, handleConn)
		})
		h.recordErr(err)
		return nil
	}); err != nil {
		_ = ln.Close()
		close(h.doneCh)
		_ = n.Close()
		return nil, err
	}
	return finishStartupHandle(ctx, h)
}

func finishStartupHandle(ctx context.Context, h *Handle) (*Handle, error) {
	if err := ctx.Err(); err != nil {
		_ = h.Close()
		return nil, err
	}
	return h, nil
}

// runWithUpstreamWatch 在上游 transport 暴露 WaitDone() 时同步监督其断连信号：
// 一旦上游连接终止，立即触发 Handle 停止并取消内部作用域，杜绝空闲本地监听端口/套接字僵死。
func runWithUpstreamWatch(runCtx context.Context, transport ports.TunnelTransport, h *Handle, body func(context.Context) error) error {
	wp, ok := transport.(waitDoneProvider)
	if !ok {
		return body(runCtx)
	}
	done := wp.WaitDone()
	return conc.RunScoped(runCtx, func(wCtx context.Context, n *conc.Nursery) error {
		if err := n.Go(func(c context.Context) error {
			select {
			case <-done:
				h.triggerStop()
				h.nursery.Cancel(ports.ErrClosed)
			case <-c.Done():
			}
			return nil
		}); err != nil {
			return err
		}
		return body(wCtx)
	})
}

// serveBorrowedListener 在同步作用域内通过 chanconn.RunWithAbortWatchdog 驱动 Accept 循环，
// 确保借用的 net.Listener（包括 osfs.SocketSlot.Listener()）绝不逃逸至异步协程。
func serveBorrowedListener(
	ctx context.Context,
	//xops:borrowed
	ln net.Listener,
	handleConn connHandlerFunc,
) error {
	return conc.RunWait(ctx, func(wCtx context.Context, connNursery *conc.Nursery) error {
		defer connNursery.Cancel(ports.ErrClosed)
		return chanconn.RunWithAbortWatchdog(wCtx, func() { _ = ln.Close() }, func() error {
			return acceptIntoNursery(wCtx, connNursery, ln, handleConn)
		})
	})
}

func acceptIntoNursery(
	ctx context.Context,
	connNursery *conc.Nursery,
	//xops:borrowed
	ln net.Listener,
	handleConn connHandlerFunc,
) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || isBenignCloseErr(err) {
				return nil
			}
			return err
		}
		if err := spawnConnWorker(connNursery, conn, handleConn); err != nil {
			return nil
		}
	}
}

func spawnConnWorker(n *conc.Nursery, conn net.Conn, handleConn connHandlerFunc) error {
	if err := n.Go(func(cCtx context.Context) error {
		defer func() { _ = conn.Close() }()
		_ = handleConn(cCtx, conn)
		return nil
	}); err != nil {
		_ = conn.Close()
		return err
	}
	return nil
}
