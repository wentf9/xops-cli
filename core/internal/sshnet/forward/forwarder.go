package forward

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial/chanconn"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
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
		return nil, fmt.Errorf("%w: StartForward 缺少有效 TunnelTransport 或 ForwardSpec", ports.ErrInvalidArgument)
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
		return nil, fmt.Errorf("%w: 不支持的转发方向 %s", ports.ErrInvalidArgument, spec.Direction())
	}
}

func (f *Forwarder) startLocalForward(ctx context.Context, transport ports.TunnelTransport, spec ports.ForwardSpec) (*Handle, error) {
	remoteDial, err := buildRemoteTargetDialer(transport, spec)
	if err != nil {
		return nil, err
	}
	if spec.BindKind() == ports.ForwardEndpointUnix {
		return f.startLocalUnixForward(ctx, spec, remoteDial)
	}
	listenAddr, err := validateLocalTCPBind(spec.BindAddr(), f.allowGatewayPorts)
	if err != nil {
		return nil, err
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("%w: 监听本地 TCP %q 失败: %w", ports.ErrDialFailed, listenAddr, err)
	}
	return startListenerHandle(ctx, spec, ln, func(cCtx context.Context, c net.Conn) error {
		return relayAcceptedToDial(cCtx, c, remoteDial)
	})
}

func (f *Forwarder) startLocalUnixForward(ctx context.Context, spec ports.ForwardSpec, remoteDial connDialFunc) (*Handle, error) {
	sockPath, err := osfs.ValidateControlSocketPath(spec.BindAddr())
	if err != nil {
		return nil, fmt.Errorf("%w: 本地 Unix 监听路径非法: %w", ports.ErrInvalidArgument, err)
	}
	n, err := conc.NewNursery(ctx)
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
		wErr := osfs.WithSocketSlot(runCtx, sockPath, osfs.SocketSlotOptions{ReplaceStale: f.replaceStaleUnix}, func(slot *osfs.SocketSlot) error {
			bound = true
			readyCh <- slot.Path().NativePath()
			return serveBorrowedListener(runCtx, slot.Listener(), func(cCtx context.Context, c net.Conn) error {
				return relayAcceptedToDial(cCtx, c, remoteDial)
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
	return startListenerHandle(ctx, spec, ln, func(cCtx context.Context, c net.Conn) error {
		return relayAcceptedToDial(cCtx, c, localDial)
	})
}

func openRemoteListener(ctx context.Context, transport ports.TunnelTransport, spec ports.ForwardSpec) (net.Listener, error) {
	if spec.BindKind() == ports.ForwardEndpointUnix {
		rp, err := pathalg.ParseRemotePath(spec.BindAddr())
		if err != nil {
			return nil, fmt.Errorf("%w: 远端 Unix 监听路径非法: %w", ports.ErrInvalidArgument, err)
		}
		return transport.ListenStreamLocal(ctx, rp)
	}
	if err := validateRemoteTCPBind(spec.BindAddr()); err != nil {
		return nil, err
	}
	return transport.ListenTCP(ctx, spec.BindAddr())
}

func (f *Forwarder) startDynamicForward(ctx context.Context, transport ports.TunnelTransport, spec ports.ForwardSpec) (*Handle, error) {
	listenAddr, err := validateLocalTCPBind(spec.BindAddr(), f.allowGatewayPorts)
	if err != nil {
		return nil, err
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("%w: 监听本地 SOCKS5 %q 失败: %w", ports.ErrDialFailed, listenAddr, err)
	}
	return startListenerHandle(ctx, spec, ln, func(cCtx context.Context, c net.Conn) error {
		return f.serveSOCKS5Conn(cCtx, c, transport)
	})
}

func (f *Forwarder) startTUNForward(ctx context.Context, transport ports.TunnelTransport, spec ports.ForwardSpec) (*Handle, error) {
	tunSpec, ok := spec.TUN().Get()
	if !ok || !tunSpec.IsValid() {
		return nil, fmt.Errorf("%w: ForwardTUN 缺少有效 TUNSpec", ports.ErrInvalidArgument)
	}
	if f.tunDevice == nil {
		return nil, fmt.Errorf("%w: 未配置 TUNDevicePort", ports.ErrUnsupported)
	}
	localDev, ifaceName, err := f.tunDevice.OpenLocalTUN(ctx, tunSpec)
	if err != nil {
		return nil, err
	}
	if localDev == nil || ifaceName == "" {
		if localDev != nil {
			_ = localDev.Close()
		}
		return nil, fmt.Errorf("%w: TUNDevicePort 返回无效设备句柄或空接口名", ports.ErrInvalidArgument)
	}
	remoteTUN, err := transport.OpenTUN(ctx, tunSpec)
	if err != nil {
		_ = localDev.Close()
		return nil, err
	}
	return startTUNBridgeHandle(ctx, spec, ifaceName, localDev, remoteTUN)
}

func startTUNBridgeHandle(ctx context.Context, spec ports.ForwardSpec, ifaceName string, localDev, remoteTUN io.ReadWriteCloser) (*Handle, error) {
	n, err := conc.NewNursery(ctx)
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
		err := bridgeStreams(runCtx, localDev, remoteTUN)
		h.recordErr(err)
		return nil
	}); err != nil {
		closeBoth()
		close(h.doneCh)
		_ = n.Close()
		return nil, err
	}
	return h, nil
}

func startListenerHandle(ctx context.Context, spec ports.ForwardSpec, ln net.Listener, handleConn connHandlerFunc) (*Handle, error) {
	n, err := conc.NewNursery(ctx)
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
		err := serveBorrowedListener(runCtx, ln, handleConn)
		h.recordErr(err)
		return nil
	}); err != nil {
		_ = ln.Close()
		close(h.doneCh)
		_ = n.Close()
		return nil, err
	}
	return h, nil
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

func validateLocalTCPBind(raw string, allowGateway bool) (string, error) {
	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		return "", fmt.Errorf("%w: 非法本地 TCP 绑定地址 %q: %w", ports.ErrInvalidArgument, raw, err)
	}
	if _, err := parseTCPBindPort(portStr); err != nil {
		return "", fmt.Errorf("%w: 非法本地 TCP 绑定端口 %q: %w", ports.ErrInvalidArgument, portStr, err)
	}
	if host == "*" {
		host = ""
	}
	if !allowGateway {
		if err := checkLoopbackBindHost(host, raw); err != nil {
			return "", err
		}
	}
	return net.JoinHostPort(host, portStr), nil
}

func validateRemoteTCPBind(raw string) error {
	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		return fmt.Errorf("%w: 非法远端 TCP 绑定地址 %q: %w", ports.ErrInvalidArgument, raw, err)
	}
	if _, err := parseTCPBindPort(portStr); err != nil {
		return fmt.Errorf("%w: 非法远端 TCP 绑定端口 %q: %w", ports.ErrInvalidArgument, portStr, err)
	}
	if host != "" && host != "*" {
		if _, pErr := netaddr.ParseCanonicalHost(host); pErr != nil {
			return fmt.Errorf("%w: 非法远端绑定主机 %q: %w", ports.ErrInvalidArgument, host, pErr)
		}
	}
	return nil
}

func parseTCPBindPort(raw string) (uint16, error) {
	if raw == "" || strings.HasPrefix(raw, "+") || strings.HasPrefix(raw, "-") {
		return 0, ports.ErrInvalidArgument
	}
	v, err := strconv.ParseUint(raw, 10, 16)
	if err != nil {
		return 0, err
	}
	return uint16(v), nil
}

func checkLoopbackBindHost(host, raw string) error {
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.IsLoopback() {
		return fmt.Errorf("%w: 默认禁止绑定非回环本地地址 %q（需显式开启 GatewayPorts）", ports.ErrPermissionDenied, raw)
	}
	return nil
}

func mapUnixSlotErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, osfs.ErrSlotOccupied) {
		return fmt.Errorf("%w: %w", ports.ErrAlreadyExists, err)
	}
	if errors.Is(err, osfs.ErrInvalidControlPath) || errors.Is(err, osfs.ErrControlPathTooLong) || errors.Is(err, osfs.ErrNotSocket) {
		return fmt.Errorf("%w: %w", ports.ErrInvalidArgument, err)
	}
	return err
}
