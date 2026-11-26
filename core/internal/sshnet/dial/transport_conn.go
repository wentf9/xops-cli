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
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial/chanconn"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial/remotesess"
	"github.com/wentf9/xops-cli/core/ports"
)

// TransportConn 封装已认证的 *ssh.Client 及其被动断连监督生命周期，实现 ports.TransportConn；零值恒失败关闭。
// 同时面向 Wave 2（sshnet/{sftp,forward,mux}）暴露受 lifeNursery 监督的通道、子系统与全局请求原语。
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

// WaitDone 返回只读通道，当底层 SSH 传输断开或关闭完成后立即关闭；供 sshnet/{forward,mux} 零轮询感知断连。
func (c *TransportConn) WaitDone() <-chan struct{} {
	if c == nil || !c.valid {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return c.waitDone
}

// SSHClient 返回底层 *ssh.Client 仅供同仓 Wave 2（sshnet/sftp）在确需直连协议库时使用；
// 若连接未初始化或已关闭则返回 nil，优先推荐直接调用 OpenSubsystem / OpenWatchedChannel。
func (c *TransportConn) SSHClient() *ssh.Client {
	if !c.IsAlive() {
		return nil
	}
	return c.client
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

// SendGlobalRequest 在连接生命周期 Nursery 监督下发送 RFC 4254 全局请求，供 sshnet/{forward,mux} 复用。
func (c *TransportConn) SendGlobalRequest(ctx context.Context, name string, wantReply bool, payload []byte) (bool, []byte, error) {
	if err := c.checkAlive(ctx); err != nil {
		return false, nil, err
	}
	if name == "" {
		return false, nil, fmt.Errorf("%w: 全局请求名不能为空", ports.ErrInvalidArgument)
	}
	type reqResp struct {
		ok   bool
		data []byte
	}
	resp, err := chanconn.RunMultiplexedOp(ctx, c.lifeNursery, func() (reqResp, error) {
		ok, data, reqErr := c.client.SendRequest(name, wantReply, payload)
		return reqResp{ok: ok, data: data}, reqErr
	}, nil)
	return resp.ok, resp.data, err
}

// SendKeepalive 发送标准 OpenSSH "keepalive@openssh.com" 全局保活请求（受连接生命周期 Nursery 监督，单次取消不误杀父连接）。
// OpenSSH 服务端按惯例回复 REQUEST_FAILURE（ok==false, err==nil），仅传输级 err!=nil 视为探测失败。
func (c *TransportConn) SendKeepalive(ctx context.Context) error {
	_, _, err := c.SendGlobalRequest(ctx, "keepalive@openssh.com", true, nil)
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
	sshSess, err := chanconn.RunMultiplexedOp(ctx, c.lifeNursery, func() (*ssh.Session, error) {
		return c.client.NewSession()
	}, func(s *ssh.Session) {
		if s != nil {
			_ = s.Close()
		}
	})
	if err != nil {
		return nil, err
	}
	return remotesess.New(c.lifeNursery, c.IsAlive, sshSess)
}

type openedChannelPair struct {
	ch   ssh.Channel
	reqs <-chan *ssh.Request
}

// OpenChannel 在 lifeNursery 监督下打开任意 RFC 4254 SSH 通道（取消时异步关闭并排空孤立请求，零泄漏）。
// 供 Wave 2 sshnet/{sftp,forward,mux} 打开受控底层通道使用。
func (c *TransportConn) OpenChannel(ctx context.Context, chanType string, extraData []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	if err := c.checkAlive(ctx); err != nil {
		return nil, nil, err
	}
	if chanType == "" {
		return nil, nil, fmt.Errorf("%w: 通道类型不能为空", ports.ErrInvalidArgument)
	}
	pair, err := chanconn.RunMultiplexedOp(ctx, c.lifeNursery, func() (openedChannelPair, error) {
		ch, reqs, oErr := c.client.OpenChannel(chanType, extraData)
		return openedChannelPair{ch: ch, reqs: reqs}, oErr
	}, func(p openedChannelPair) {
		c.discardAbandonedChannel(p)
	})
	if err != nil {
		return nil, nil, err
	}
	return pair.ch, pair.reqs, nil
}

// OpenWatchedChannel 打开 SSH 通道并强制封装为带 ADR-015 O(1) 截止/黑洞看门狗的 *chanconn.WatchedConn，
// 直接暴露 CloseWrite() 与完整 net.Conn 能力（零额外类型断言）。
func (c *TransportConn) OpenWatchedChannel(ctx context.Context, chanType string, extraData []byte, remoteAddr net.Addr) (*chanconn.WatchedConn, error) {
	ch, reqs, err := c.OpenChannel(ctx, chanType, extraData)
	if err != nil {
		return nil, err
	}
	if remoteAddr == nil {
		remoteAddr = chanconn.NewAddr(chanType, c.endpoint.String())
	}
	localAddr := chanconn.NewAddr(remoteAddr.Network(), c.endpoint.String())
	return chanconn.WrapChannel(c.lifeNursery, ch, reqs, localAddr, remoteAddr, c.clock)
}

type subsystemReqMsg struct {
	Subsystem string
}

// OpenSubsystemStream 以纯标准库 io.ReadWriteCloser 签名暴露受看门狗保护的命名 SSH 子系统流，
// 供 pool.pinnedTransportConn 与 sshnet/mux 在零额外跨包依赖下透明透传 SFTP 子系统。
func (c *TransportConn) OpenSubsystemStream(ctx context.Context, subsystem string) (io.ReadWriteCloser, error) {
	return c.OpenSubsystem(ctx, subsystem)
}

// OpenSubsystem 在 "session" 通道上请求启动命名 SSH 子系统（如 "sftp"），
// 全程受 lifeNursery 取消看门狗监督并返回带截止看门狗与 CloseWrite() 的 *chanconn.WatchedConn（供 P4-T2 sshnet/sftp 复用）。
func (c *TransportConn) OpenSubsystem(ctx context.Context, subsystem string) (*chanconn.WatchedConn, error) {
	if err := c.checkAlive(ctx); err != nil {
		return nil, err
	}
	if subsystem == "" {
		return nil, fmt.Errorf("%w: 子系统名称不能为空", ports.ErrInvalidArgument)
	}
	ch, reqs, err := c.OpenChannel(ctx, "session", nil)
	if err != nil {
		return nil, err
	}
	payload := ssh.Marshal(&subsystemReqMsg{Subsystem: subsystem})
	ok, rErr := chanconn.RunMultiplexedOp(ctx, c.lifeNursery, func() (bool, error) {
		return ch.SendRequest("subsystem", true, payload)
	}, nil)
	if rErr != nil || !ok {
		c.discardAbandonedChannel(openedChannelPair{ch: ch, reqs: reqs})
		if rErr != nil {
			return nil, rErr
		}
		return nil, fmt.Errorf("%w: 远端拒绝启动子系统 %q", ports.ErrUnsupported, subsystem)
	}
	localAddr := chanconn.NewAddr("subsystem", c.endpoint.String())
	remoteAddr := chanconn.NewAddr("subsystem", subsystem+"@"+c.endpoint.String())
	return chanconn.WrapChannel(c.lifeNursery, ch, reqs, localAddr, remoteAddr, c.clock)
}

// directTCPIPMsg 对应 RFC 4254 Section 7.2 "direct-tcpip" 通道打开载荷。
type directTCPIPMsg struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

// DialTCP 经 "direct-tcpip" 打开上游 SSH 隧道并强制封装为 chanconn.WatchedConn（ADR-015）。
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
	wc, err := c.OpenWatchedChannel(ctx, "direct-tcpip", payload, chanconn.NewAddr("tcp", target.String()))
	if err != nil {
		return nil, err
	}
	return wc, nil
}

// ListenTCP 在远端 SSH 服务端发起 tcpip-forward 监听。
func (c *TransportConn) ListenTCP(ctx context.Context, bindAddr string) (net.Listener, error) {
	if err := c.checkAlive(ctx); err != nil {
		return nil, err
	}
	if bindAddr == "" {
		return nil, fmt.Errorf("%w: bindAddr 不能为空", ports.ErrInvalidArgument)
	}
	return chanconn.RunMultiplexedOp(ctx, c.lifeNursery, func() (net.Listener, error) {
		return c.client.Listen("tcp", bindAddr)
	}, closeListenerIfNonNil)
}

// directStreamLocalMsg 对应 OpenSSH PROTOCOL 2.4 "direct-streamlocal@openssh.com" 载荷。
type directStreamLocalMsg struct {
	SocketPath string
	Reserved0  string
	Reserved1  uint32
}

// DialStreamLocal 经 "direct-streamlocal@openssh.com" 连接远端 Unix 域套接字并封装为 chanconn.WatchedConn。
func (c *TransportConn) DialStreamLocal(ctx context.Context, remoteSocket pathalg.RemotePath) (net.Conn, error) {
	if err := c.checkAlive(ctx); err != nil {
		return nil, err
	}
	if !remoteSocket.IsValid() {
		return nil, fmt.Errorf("%w: 无效远端 Unix 套接字路径", ports.ErrInvalidArgument)
	}
	payload := ssh.Marshal(&directStreamLocalMsg{SocketPath: remoteSocket.String()})
	wc, err := c.OpenWatchedChannel(ctx, "direct-streamlocal@openssh.com", payload, chanconn.NewAddr("unix", remoteSocket.String()))
	if err != nil {
		return nil, err
	}
	return wc, nil
}

// ListenStreamLocal 在远端 SSH 服务端发起 streamlocal-forward@openssh.com 监听。
func (c *TransportConn) ListenStreamLocal(ctx context.Context, remoteSocket pathalg.RemotePath) (net.Listener, error) {
	if err := c.checkAlive(ctx); err != nil {
		return nil, err
	}
	if !remoteSocket.IsValid() {
		return nil, fmt.Errorf("%w: 无效远端 Unix 监听路径", ports.ErrInvalidArgument)
	}
	return chanconn.RunMultiplexedOp(ctx, c.lifeNursery, func() (net.Listener, error) {
		return c.client.ListenUnix(remoteSocket.String())
	}, closeListenerIfNonNil)
}

// tunChannelMsg 对应 OpenSSH "tun@openssh.com" 通道打开载荷。
type tunChannelMsg struct {
	Mode uint32
	Unit uint32
}

// OpenTUN 经 OpenSSH "tun@openssh.com" 协议打开 L2/L3 隧道通道并封装为 chanconn.WatchedConn。
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
	addr := chanconn.NewAddr("tun", fmt.Sprintf("%s:%d", spec.Mode(), spec.RemoteUnit()))
	wc, err := c.OpenWatchedChannel(ctx, "tun@openssh.com", payload, addr)
	if err != nil {
		return nil, err
	}
	return wc, nil
}

// OpenRemoteFS 若已注入 SFTP 子系统工厂则传入当前 *TransportConn 打开 RemoteFSPort，否则返回 ports.ErrUnsupported。
func (c *TransportConn) OpenRemoteFS(ctx context.Context) (ports.RemoteFSPort, error) {
	if err := c.checkAlive(ctx); err != nil {
		return nil, err
	}
	if c.openRemoteFS == nil {
		return nil, ports.ErrUnsupported
	}
	return c.openRemoteFS(ctx, c)
}

func (c *TransportConn) discardAbandonedChannel(p openedChannelPair) {
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
}

func closeListenerIfNonNil(ln net.Listener) {
	if ln != nil {
		_ = ln.Close()
	}
}
