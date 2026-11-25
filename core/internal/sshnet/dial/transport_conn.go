package dial

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/ports"
)

// TransportConn 封装已认证的 *ssh.Client 及其被动断连监督生命周期，实现 ports.TransportConn；零值恒失败关闭。
//
//xops:opaque
//xops:failclosed
type TransportConn struct {
	client       *ssh.Client
	rawConn      net.Conn
	hopDigest    plan.HopDigest
	endpoint     netaddr.Endpoint
	clock        ports.Clock
	openRemoteFS RemoteFSFactory
	lifeNursery  *conc.Nursery
	waitDone     chan struct{}

	alive     atomic.Bool
	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
	valid     bool
}

func newTransportConn(
	sshConn ssh.Conn,
	chans <-chan ssh.NewChannel,
	reqs <-chan *ssh.Request,
	rawConn net.Conn,
	hopDigest plan.HopDigest,
	endpoint netaddr.Endpoint,
	clk ports.Clock,
	openRemoteFS RemoteFSFactory,
) (*TransportConn, error) {
	lifeN, err := conc.NewNursery(context.Background())
	if err != nil {
		_ = sshConn.Close()
		_ = rawConn.Close()
		return nil, err
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	tc := &TransportConn{
		client:       client,
		rawConn:      rawConn,
		hopDigest:    hopDigest,
		endpoint:     endpoint,
		clock:        clk,
		openRemoteFS: openRemoteFS,
		lifeNursery:  lifeN,
		waitDone:     make(chan struct{}),
		valid:        true,
	}
	tc.alive.Store(true)
	if err := tc.lifeNursery.Go(func(context.Context) error {
		defer close(tc.waitDone)
		defer tc.alive.Store(false)
		_ = tc.client.Wait()
		return nil
	}); err != nil {
		_ = tc.Close()
		return nil, err
	}
	return tc, nil
}

// HopDigest 返回当前传输连接绑定的不可变 Merkle 跳板摘要。
func (c *TransportConn) HopDigest() plan.HopDigest {
	if c == nil || !c.valid {
		var zero plan.HopDigest
		return zero
	}
	return c.hopDigest
}

// Endpoint 返回当前传输连接绑定的不可变规范化目标端点。
func (c *TransportConn) Endpoint() netaddr.Endpoint {
	if c == nil || !c.valid {
		var zero netaddr.Endpoint
		return zero
	}
	return c.endpoint
}

// IsAlive 报告底层 SSH 传输是否仍处于已初始化且未断连/未关闭的存活状态。
func (c *TransportConn) IsAlive() bool {
	return c != nil && c.valid && c.alive.Load() && !c.closed.Load()
}

// Close 幂等关闭底层 SSH 传输连接、等待 client.Wait 退出并收敛所有看门狗协程（零泄漏）。
func (c *TransportConn) Close() error {
	if c == nil || !c.valid {
		return nil
	}
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.alive.Store(false)
		cErr := c.client.Close()
		if errors.Is(cErr, net.ErrClosed) || errors.Is(cErr, io.EOF) {
			cErr = nil
		}
		var rErr error
		if c.rawConn != nil {
			if err := c.rawConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
				rErr = err
			}
		}
		<-c.waitDone
		nErr := c.lifeNursery.Close()
		c.closeErr = errors.Join(cErr, rErr, nErr)
	})
	return c.closeErr
}

func (c *TransportConn) checkAlive(ctx context.Context) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !c.IsAlive() {
		return ports.ErrClosed
	}
	return nil
}

// SendKeepalive 发送标准 OpenSSH "keepalive@openssh.com" 全局保活请求（受连接生命周期 Nursery 监督，单次取消不误杀父连接）。
// OpenSSH 服务端按惯例回复 REQUEST_FAILURE（ok==false, err==nil），仅传输级 err!=nil 视为探测失败。
func (c *TransportConn) SendKeepalive(ctx context.Context) error {
	if err := c.checkAlive(ctx); err != nil {
		return err
	}
	_, err := runMultiplexedOp(ctx, c, func() (struct{}, error) {
		_, _, reqErr := c.client.SendRequest("keepalive@openssh.com", true, nil)
		return struct{}{}, reqErr
	}, nil)
	if err != nil && ctx.Err() == nil {
		c.alive.Store(false)
	}
	return err
}

// OpenSession 打开隔离的 SSH 会话通道，并立即预绑定 StdinPipe/StdoutPipe/StderrPipe（绝不赋值 Session.Stdin）。
func (c *TransportConn) OpenSession(ctx context.Context) (ports.RemoteSession, error) {
	if err := c.checkAlive(ctx); err != nil {
		return nil, err
	}
	sshSess, err := runMultiplexedOp(ctx, c, func() (*ssh.Session, error) {
		return c.client.NewSession()
	}, func(s *ssh.Session) {
		if s != nil {
			_ = s.Close()
		}
	})
	if err != nil {
		return nil, err
	}
	return newRemoteSession(c, sshSess)
}

// directTCPIPMsg 对应 RFC 4254 Section 7.2 "direct-tcpip" 通道打开载荷。
type directTCPIPMsg struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

// DialTCP 经 "direct-tcpip" 打开上游 SSH 隧道并强制封装为 watchedChannelConn（ADR-015）。
// 绝不调用 (*ssh.Client).DialContext（其在上游库内部存在取消后孤儿 goroutine 泄漏风险）。
func (c *TransportConn) DialTCP(ctx context.Context, target netaddr.HostPort) (net.Conn, error) {
	if err := c.checkAlive(ctx); err != nil {
		return nil, err
	}
	if !target.IsValid() {
		return nil, fmt.Errorf("%w: 无效 DialTCP 目标 HostPort", ports.ErrInvalidArgument)
	}
	payload := ssh.Marshal(&directTCPIPMsg{
		DestAddr:   target.Host().String(),
		DestPort:   uint32(target.Port()),
		OriginAddr: "127.0.0.1",
		OriginPort: 0,
	})
	return c.openWatchedChannel(ctx, "direct-tcpip", payload, channelAddr{network: "tcp", address: target.String()})
}

// ListenTCP 在远端 SSH 服务端发起 tcpip-forward 监听。
func (c *TransportConn) ListenTCP(ctx context.Context, bindAddr string) (net.Listener, error) {
	if err := c.checkAlive(ctx); err != nil {
		return nil, err
	}
	if bindAddr == "" {
		return nil, fmt.Errorf("%w: bindAddr 不能为空", ports.ErrInvalidArgument)
	}
	return runMultiplexedOp(ctx, c, func() (net.Listener, error) {
		return c.client.Listen("tcp", bindAddr)
	}, closeListenerIfNonNil)
}

// directStreamLocalMsg 对应 OpenSSH PROTOCOL 2.4 "direct-streamlocal@openssh.com" 载荷。
type directStreamLocalMsg struct {
	SocketPath string
	Reserved0  string
	Reserved1  uint32
}

// DialStreamLocal 经 "direct-streamlocal@openssh.com" 连接远端 Unix 域套接字并封装为 watchedChannelConn。
func (c *TransportConn) DialStreamLocal(ctx context.Context, remoteSocket pathalg.RemotePath) (net.Conn, error) {
	if err := c.checkAlive(ctx); err != nil {
		return nil, err
	}
	if !remoteSocket.IsValid() {
		return nil, fmt.Errorf("%w: 无效远端 Unix 套接字路径", ports.ErrInvalidArgument)
	}
	payload := ssh.Marshal(&directStreamLocalMsg{SocketPath: remoteSocket.String()})
	return c.openWatchedChannel(ctx, "direct-streamlocal@openssh.com", payload, channelAddr{network: "unix", address: remoteSocket.String()})
}

// ListenStreamLocal 在远端 SSH 服务端发起 streamlocal-forward@openssh.com 监听。
func (c *TransportConn) ListenStreamLocal(ctx context.Context, remoteSocket pathalg.RemotePath) (net.Listener, error) {
	if err := c.checkAlive(ctx); err != nil {
		return nil, err
	}
	if !remoteSocket.IsValid() {
		return nil, fmt.Errorf("%w: 无效远端 Unix 监听路径", ports.ErrInvalidArgument)
	}
	return runMultiplexedOp(ctx, c, func() (net.Listener, error) {
		return c.client.ListenUnix(remoteSocket.String())
	}, closeListenerIfNonNil)
}

// tunChannelMsg 对应 OpenSSH "tun@openssh.com" 通道打开载荷。
type tunChannelMsg struct {
	Mode uint32
	Unit uint32
}

// OpenTUN 经 OpenSSH "tun@openssh.com" 协议打开 L2/L3 隧道通道并封装为 watchedChannelConn。
func (c *TransportConn) OpenTUN(ctx context.Context, spec ports.TUNSpec) (io.ReadWriteCloser, error) {
	if err := c.checkAlive(ctx); err != nil {
		return nil, err
	}
	if !spec.IsValid() {
		return nil, fmt.Errorf("%w: 无效 TUNSpec", ports.ErrInvalidArgument)
	}
	mode := uint32(1)
	if spec.Mode() == ports.TUNModeEthernet {
		mode = 2
	}
	payload := ssh.Marshal(&tunChannelMsg{Mode: mode, Unit: spec.RemoteUnit()})
	addr := channelAddr{network: "tun", address: fmt.Sprintf("%s:%d", spec.Mode(), spec.RemoteUnit())}
	return c.openWatchedChannel(ctx, "tun@openssh.com", payload, addr)
}

// OpenRemoteFS 若已注入 SFTP 子系统工厂则打开 RemoteFSPort，否则返回 ports.ErrUnsupported。
func (c *TransportConn) OpenRemoteFS(ctx context.Context) (ports.RemoteFSPort, error) {
	if err := c.checkAlive(ctx); err != nil {
		return nil, err
	}
	if c.openRemoteFS == nil {
		return nil, ports.ErrUnsupported
	}
	return c.openRemoteFS(ctx, c.client)
}

type openedChannelPair struct {
	ch   ssh.Channel
	reqs <-chan *ssh.Request
}

func (c *TransportConn) openWatchedChannel(ctx context.Context, chanType string, payload []byte, remoteAddr net.Addr) (net.Conn, error) {
	pair, err := runMultiplexedOp(ctx, c, func() (openedChannelPair, error) {
		ch, reqs, oErr := c.client.OpenChannel(chanType, payload)
		return openedChannelPair{ch: ch, reqs: reqs}, oErr
	}, func(p openedChannelPair) {
		if p.ch != nil {
			_ = p.ch.Close()
		}
		// 严禁在调用方协程同步 DiscardRequests：半开黑洞对端不会关闭 p.reqs，须交由 lifeNursery 异步排空。
		if p.reqs != nil {
			_ = c.lifeNursery.Go(func(context.Context) error {
				ssh.DiscardRequests(p.reqs)
				return nil
			})
		}
	})
	if err != nil {
		return nil, err
	}
	localAddr := channelAddr{network: remoteAddr.Network(), address: c.endpoint.String()}
	return newWatchedChannelConn(c, pair.ch, pair.reqs, localAddr, remoteAddr, c.clock)
}

func closeListenerIfNonNil(ln net.Listener) {
	if ln != nil {
		_ = ln.Close()
	}
}

// runMultiplexedOp 在连接生命周期 Nursery 监督下执行单次多路复用控制操作：
// 单一调用方取消 ctx 时绝不关闭共享父连接 c.client（避免误杀同连接上其他活跃会话或子跳），
// 并在互斥锁线性化下保证迟到完成的孤立资源恰好被 cleanup 释放一次且随 c.Close() 零泄漏收敛。
func runMultiplexedOp[T any](
	ctx context.Context,
	c *TransportConn,
	op func() (T, error),
	cleanup func(T),
) (T, error) {
	var zero T
	type result struct {
		val T
		err error
	}
	var mu sync.Mutex
	abandoned := false
	resCh := make(chan result, 1)
	if err := c.lifeNursery.Go(func(context.Context) error {
		v, err := op()
		mu.Lock()
		if abandoned {
			mu.Unlock()
			runCleanupIfOK(err, v, cleanup)
			return nil
		}
		resCh <- result{val: v, err: err}
		mu.Unlock()
		return nil
	}); err != nil {
		return zero, ports.ErrClosed
	}
	select {
	case res := <-resCh:
		if ctxErr := ctx.Err(); ctxErr != nil {
			runCleanupIfOK(res.err, res.val, cleanup)
			return zero, ctxErr
		}
		return res.val, res.err
	case <-ctx.Done():
		mu.Lock()
		abandoned = true
		var late *result
		select {
		case r := <-resCh:
			late = &r
		default:
		}
		mu.Unlock()
		if late != nil {
			runCleanupIfOK(late.err, late.val, cleanup)
		}
		return zero, ctx.Err()
	}
}

func runCleanupIfOK[T any](err error, val T, cleanup func(T)) {
	if err == nil && cleanup != nil {
		cleanup(val)
	}
}
