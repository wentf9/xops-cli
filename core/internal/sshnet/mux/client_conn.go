package mux

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial/chanconn"
	"github.com/wentf9/xops-cli/core/internal/sshnet/mux/muxstream"
	"github.com/wentf9/xops-cli/core/internal/sshnet/sftp"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
)

// MuxTransportConn 表示经 DialMux 附着至活跃 ControlMaster 的多路复用客户端传输连接，
// 实现 ports.TransportConn 并精确绑定不可变 (HopDigest, Endpoint) 身份（INV-C4）；零值恒失败关闭。
//
//xops:opaque
//xops:failclosed
type MuxTransportConn struct {
	mux          *MuxSocket
	ctrlPath     osfs.ControlSocketPath
	hopDigest    plan.HopDigest
	endpoint     netaddr.Endpoint
	supportsXOps bool
	peerDetail   string
	lifeNursery  *conc.Nursery

	alive     atomic.Bool
	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
	valid     bool
}

func newMuxTransportConn(
	mux *MuxSocket,
	ctrlPath osfs.ControlSocketPath,
	hopDigest plan.HopDigest,
	endpoint netaddr.Endpoint,
	supportsXOps bool,
	peerDetail string,
) (*MuxTransportConn, error) {
	lifeN, err := conc.NewNursery(context.Background())
	if err != nil {
		return nil, err
	}
	c := &MuxTransportConn{
		mux:          mux,
		ctrlPath:     ctrlPath,
		hopDigest:    hopDigest,
		endpoint:     endpoint,
		supportsXOps: supportsXOps,
		peerDetail:   peerDetail,
		lifeNursery:  lifeN,
		valid:        true,
	}
	c.alive.Store(true)
	return c, nil
}

// HopDigest 返回本复用连接绑定的不可变 Merkle 跳板摘要。
func (c *MuxTransportConn) HopDigest() plan.HopDigest {
	if c == nil || !c.valid {
		return muxstream.ZeroVal[plan.HopDigest]()
	}
	return c.hopDigest
}

// Endpoint 返回本复用连接绑定的不可变规范目标端点。
func (c *MuxTransportConn) Endpoint() netaddr.Endpoint {
	if c == nil || !c.valid {
		return muxstream.ZeroVal[netaddr.Endpoint]()
	}
	return c.endpoint
}

// PeerDetail 返回附着握手时记录的非敏感平台对端身份诊断标签。
func (c *MuxTransportConn) PeerDetail() string {
	if c == nil || !c.valid {
		return ""
	}
	return c.peerDetail
}

// IsAlive 报告当前复用连接是否已初始化且未关闭、未探测断连。
func (c *MuxTransportConn) IsAlive() bool {
	return c != nil && c.valid && c.alive.Load() && !c.closed.Load()
}

// Close 幂等关闭复用客户端连接并同步回收全部受监督子会话与监听器协程（零泄漏）。
func (c *MuxTransportConn) Close() error {
	if c == nil || !c.valid {
		return nil
	}
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.alive.Store(false)
		c.closeErr = c.lifeNursery.Close()
	})
	return c.closeErr
}

func (c *MuxTransportConn) checkAlive(ctx context.Context) error {
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

func (c *MuxTransportConn) dialXOpsStream(ctx context.Context, msgType uint32, body []byte) (*net.UnixConn, error) {
	if err := c.checkAlive(ctx); err != nil {
		return nil, err
	}
	if !c.supportsXOps {
		return nil, domi18n.EF(ports.ErrUnsupported, domi18n.KeyMuxExtNotNegotiated)
	}
	conn, _, err := c.mux.dialVerified(ctx, c.ctrlPath)
	if err != nil {
		if ctx.Err() == nil {
			c.alive.Store(false)
		}
		return nil, err
	}
	if err := chanconn.RunWithAbortWatchdog(ctx, func() { _ = conn.Close() }, func() error {
		if _, hErr := muxstream.ExchangeClientHello(conn); hErr != nil {
			return domi18n.WrapSentinel(ports.ErrMuxUnavailable, hErr)
		}
		return roundTripControlOK(conn, msgType, body, 1)
	}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// SendKeepalive 向 ControlMaster 发送 PROTOCOL.mux v4 MUX_C_ALIVE_CHECK 探活。
func (c *MuxTransportConn) SendKeepalive(ctx context.Context) error {
	if err := c.checkAlive(ctx); err != nil {
		return err
	}
	conn, _, err := c.mux.dialVerified(ctx, c.ctrlPath)
	if err != nil {
		if ctx.Err() == nil {
			c.alive.Store(false)
		}
		return err
	}
	defer func() { _ = conn.Close() }()
	err = chanconn.RunWithAbortWatchdog(ctx, func() { _ = conn.Close() }, func() error {
		if _, hErr := muxstream.ExchangeClientHello(conn); hErr != nil {
			return domi18n.WrapSentinel(ports.ErrMuxUnavailable, hErr)
		}
		_, aErr := muxstream.SendAliveCheck(conn, 1)
		return aErr
	})
	if err != nil {
		if ctx.Err() == nil {
			c.alive.Store(false)
		}
		return err
	}
	return nil
}

// OpenSession 通过 ControlMaster 打开隔离远端会话通道，返回完整 ports.RemoteSession。
func (c *MuxTransportConn) OpenSession(ctx context.Context) (ports.RemoteSession, error) {
	conn, err := c.dialXOpsStream(ctx, muxstream.XOpsCOpenSession, muxstream.AppendU32(nil, 1))
	if err != nil {
		return nil, err
	}
	return muxstream.NewRemoteSession(c.lifeNursery, c.IsAlive, conn)
}

// OpenRemoteFS 通过 ControlMaster 打开上游 "sftp" 子系统流并构造纯 Go SFTP v3 客户端。
func (c *MuxTransportConn) OpenRemoteFS(ctx context.Context) (ports.RemoteFSPort, error) {
	conn, err := c.dialXOpsStream(ctx, muxstream.XOpsCOpenSFTP, muxstream.AppendU32(nil, 1))
	if err != nil {
		return nil, err
	}
	rfs, err := sftp.OpenStream(ctx, conn, sftp.Config{})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return rfs, nil
}

// DialTCP 经 ControlMaster 发起远端 direct-tcpip 通道并返回原始双向流。
func (c *MuxTransportConn) DialTCP(ctx context.Context, target netaddr.HostPort) (net.Conn, error) {
	if !target.IsValid() {
		return nil, domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "DialTCP target"))
	}
	body := muxstream.AppendU32(muxstream.AppendStr(muxstream.AppendU32(nil, 1), target.Host().String()), uint32(target.Port()))
	return c.dialXOpsStream(ctx, muxstream.XOpsCDialTCP, body)
}

// DialStreamLocal 经 ControlMaster 发起远端 direct-streamlocal@openssh.com 通道并返回原始双向流。
func (c *MuxTransportConn) DialStreamLocal(ctx context.Context, remoteSocket pathalg.RemotePath) (net.Conn, error) {
	if !remoteSocket.IsValid() {
		return nil, domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "remote Unix socket path"))
	}
	return c.dialXOpsStream(ctx, muxstream.XOpsCDialStreamLocal, muxstream.AppendStr(muxstream.AppendU32(nil, 1), remoteSocket.String()))
}

// OpenTUN 经 ControlMaster 打开远端 tun@openssh.com 通道并返回双向帧流。
func (c *MuxTransportConn) OpenTUN(ctx context.Context, spec ports.TUNSpec) (io.ReadWriteCloser, error) {
	if !spec.IsValid() {
		return nil, domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "TUNSpec"))
	}
	body := muxstream.AppendU32(muxstream.AppendU32(muxstream.AppendU32(muxstream.AppendU32(nil, 1), uint32(spec.Mode())), spec.LocalUnit()), spec.RemoteUnit())
	return c.dialXOpsStream(ctx, muxstream.XOpsCOpenTUN, body)
}

// ListenTCP 经 ControlMaster 在远端 SSH 服务端发起 tcpip-forward 监听并返回多路复用 net.Listener。
func (c *MuxTransportConn) ListenTCP(ctx context.Context, bindAddr string) (net.Listener, error) {
	if err := validateMuxListenTCPAddr(bindAddr); err != nil {
		return nil, err
	}
	return c.openRemoteMuxListener(ctx, muxstream.XOpsCListenTCP, "tcp", bindAddr)
}

func validateMuxListenTCPAddr(bindAddr string) error {
	host, portStr, err := net.SplitHostPort(bindAddr)
	if err != nil || portStr == "" || strings.HasPrefix(portStr, "+") || strings.HasPrefix(portStr, "-") {
		return domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "ListenTCP bind address"), domi18n.BoundStr("value", bindAddr))
	}
	if _, err := strconv.ParseUint(portStr, 10, 16); err != nil {
		return domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "ListenTCP bind port"), domi18n.BoundStr("value", portStr))
	}
	if host != "" && host != "*" {
		if _, err := netaddr.ParseCanonicalHost(host); err != nil {
			return domi18n.WrapS(ports.ErrInvalidArgument, err, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "ListenTCP bind host"), domi18n.BoundStr("value", host))
		}
	}
	return nil
}

// ListenStreamLocal 经 ControlMaster 在远端发起 streamlocal-forward@openssh.com 监听并返回 net.Listener。
func (c *MuxTransportConn) ListenStreamLocal(ctx context.Context, remoteSocket pathalg.RemotePath) (net.Listener, error) {
	if !remoteSocket.IsValid() {
		return nil, domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "remote Unix listen path"))
	}
	return c.openRemoteMuxListener(ctx, muxstream.XOpsCListenStreamLocal, "unix", remoteSocket.String())
}

func (c *MuxTransportConn) openRemoteMuxListener(ctx context.Context, msgType uint32, network, addr string) (net.Listener, error) {
	if err := c.checkAlive(ctx); err != nil {
		return nil, err
	}
	if !c.supportsXOps {
		return nil, domi18n.EF(ports.ErrUnsupported, domi18n.KeyMuxExtNotNegotiated)
	}
	conn, _, err := c.mux.dialVerified(ctx, c.ctrlPath)
	if err != nil {
		if ctx.Err() == nil {
			c.alive.Store(false)
		}
		return nil, err
	}
	var boundAddr string
	if err := chanconn.RunWithAbortWatchdog(ctx, func() { _ = conn.Close() }, func() error {
		b, hErr := handshakeRemoteListener(conn, msgType, addr)
		if hErr != nil {
			return hErr
		}
		boundAddr = b
		return nil
	}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return muxstream.NewRemoteListener(c.lifeNursery, conn, network, boundAddr)
}

func handshakeRemoteListener(conn *net.UnixConn, msgType uint32, addr string) (string, error) {
	if _, err := muxstream.ExchangeClientHello(conn); err != nil {
		return "", domi18n.WrapSentinel(ports.ErrMuxUnavailable, err)
	}
	if err := muxstream.WritePacket(conn, msgType, muxstream.AppendStr(muxstream.AppendU32(nil, 1), addr)); err != nil {
		return "", err
	}
	respType, respBody, err := muxstream.ReadPacket(conn)
	if err != nil {
		return "", err
	}
	if respType != muxstream.XOpsSBoundAddr {
		return "", muxstream.DecodeServerError(respType, respBody)
	}
	rd := muxstream.NewReader(respBody)
	gotID, e1 := rd.ReadUint32()
	boundAddr, e2 := rd.ReadString()
	if err := muxstream.FirstErr(e1, e2); err != nil || gotID != 1 {
		return "", ports.ErrCorruptData
	}
	return boundAddr, nil
}
