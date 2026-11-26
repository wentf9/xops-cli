// Package mux 实现 XOps v2 OpenSSH PROTOCOL.mux v4 控制面与跨平台多路复用数据面适配器
// （ports.MuxSocketPort / ports.TransportConn，INV-A3 / INV-C4 / ADR-009）。
//
// 核心安全、并发与跨平台不变量：
//   - 全部本地 AF_UNIX 监听、陈旧套接字探活/清理与客户端连接严格经 core/osfs（WithSocketSlot /
//     DialUnixVerified / ProbeStaleUnixSocket）完成，强制核验对端用户凭证（Unix UID / Windows SID）
//     与 INV-A3 目录锁安全释放顺序，严禁在包内直接调用 net.Listen("unix", ...) 或裸 os 文件 API；
//   - 完整实现 OpenSSH PROTOCOL.mux v4 控制面线缆格式（MUX_MSG_HELLO v4、MUX_C_ALIVE_CHECK、
//     MUX_C_OPEN_FWD/MUX_C_CLOSE_FWD 含 Unix 0xfffffffe 哨兵、MUX_C_TERMINATE、MUX_C_STOP_LISTENING、
//     MUX_C_PROXY），可与外部 OpenSSH ssh -M 互操作，同时在 HELLO 中协商 xops-stream-mux@xops.dev
//     扩展并委托子包 core/internal/sshnet/mux/muxstream 以纯字节帧跨四平台统一承载会话、SFTP 与隧道；
//   - 全包 0 裸 go 语句，所有监听、客户端控制连接与握手均受 core/conc.Nursery 与 chanconn 看门狗监督，
//     Serve 对 ln 参数显式标注 //xops:borrowed 确保借用监听器零逃逸；
//   - 全包 0 行内 lint 豁免，零值 MuxSocket / MuxTransportConn 恒失败关闭。
package mux

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial/chanconn"
	"github.com/wentf9/xops-cli/core/internal/sshnet/mux/muxstream"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
)

const defaultHandshakeTimeout = 5 * time.Second

// ProxyHandler 定义 ControlMaster 收到 MUX_C_PROXY 请求并回复 MUX_S_PROXY 后的可选自定义代理流处理函数。
type ProxyHandler func(ctx context.Context, conn net.Conn, upstream ports.TransportConn) error

// Config 描述 MuxSocket 适配器的显式配置项（零值即安全失败关闭默认配置）。
type Config struct {
	// KeepStaleSocket 为 true 时禁止 WithListener 自动清理目录锁内确证为过期的套接字（默认 false：安全接管陈旧槽位）。
	KeepStaleSocket bool
	// HandshakeTimeout 限制单次控制面握手与探活超时（默认 5s）。
	HandshakeTimeout time.Duration
	// Clock 可选注入时钟端口用于计算握手截止时间（为空时回退系统时间）。
	Clock ports.Clock
	// SelfPID 可选覆写 Serve 响应 MUX_S_ALIVE 时通告的主进程 PID（为 0 时使用 os.Getpid()）。
	SelfPID uint32
	// OnActivity 可选在 ControlMaster 收到活跃客户端请求时回调（供上层刷新 ControlPersist 空闲计时器）。
	OnActivity func()
	// ProxyHandler 可选定制 Serve 收到 MUX_C_PROXY 后的双向代理流处理逻辑。
	ProxyHandler ProxyHandler
}

// MuxSocket 实现 ports.MuxSocketPort，提供基于 core/osfs 与 OpenSSH PROTOCOL.mux v4 的本地多路复用端口；零值恒失败关闭。
//
//xops:opaque
//xops:failclosed
type MuxSocket struct {
	keepStale        bool
	handshakeTimeout time.Duration
	clock            ports.Clock
	selfPID          uint32
	onActivity       func()
	proxyHandler     ProxyHandler
	valid            bool
}

// NewMuxSocket 构造不可变 MuxSocket 适配器。
func NewMuxSocket(cfg Config) *MuxSocket {
	timeout := cfg.HandshakeTimeout
	if timeout <= 0 {
		timeout = defaultHandshakeTimeout
	}
	pid := cfg.SelfPID
	if pid == 0 {
		pid = uint32(os.Getpid())
	}
	return &MuxSocket{
		keepStale:        cfg.KeepStaleSocket,
		handshakeTimeout: timeout,
		clock:            cfg.Clock,
		selfPID:          pid,
		onActivity:       cfg.OnActivity,
		proxyHandler:     cfg.ProxyHandler,
		valid:            true,
	}
}

func (m *MuxSocket) checkReady(ctx context.Context) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if m == nil || !m.valid {
		return ports.ErrClosed
	}
	return nil
}

func (m *MuxSocket) now() time.Time {
	if m.clock != nil {
		return m.clock.Now()
	}
	return time.Now()
}

func (m *MuxSocket) handshakeDeadline(ctx context.Context) time.Time {
	dl := m.now().Add(m.handshakeTimeout)
	if ctxDL, ok := ctx.Deadline(); ok && ctxDL.Before(dl) {
		return ctxDL
	}
	return dl
}

// WithListener 在独占目录锁下安全绑定本地 AF_UNIX 控制套接字（Accept 强制核验对端用户凭证），
// 并在同步作用域闭包内借出 net.Listener；退出时按 INV-A3 顺序无条件清理释放。
//
//xops:syncclosure
//xops:borrowed
func (m *MuxSocket) WithListener(ctx context.Context, socketPath pathalg.LocalSourcePath, fn func(ln net.Listener) error) error {
	if fn == nil {
		return ports.ErrNilCallback
	}
	if err := m.checkReady(ctx); err != nil {
		return err
	}
	ctrlPath, err := toControlSocketPath(socketPath)
	if err != nil {
		return err
	}
	err = osfs.WithSocketSlot(ctx, ctrlPath, osfs.SocketSlotOptions{ReplaceStale: !m.keepStale}, func(slot *osfs.SocketSlot) error {
		return fn(slot.Listener())
	})
	return mapSlotBindError(err)
}

// Probe 探测指定 ControlMaster 套接字是否存活并返回主进程 PID（缺失或陈旧返回 alive=false）。
func (m *MuxSocket) Probe(ctx context.Context, socketPath pathalg.LocalSourcePath) (ports.MuxControlResponse, error) {
	if err := m.checkReady(ctx); err != nil {
		return muxstream.ZeroVal[ports.MuxControlResponse](), err
	}
	ctrlPath, err := toControlSocketPath(socketPath)
	if err != nil {
		return muxstream.ZeroVal[ports.MuxControlResponse](), err
	}
	st, err := osfs.ProbeStaleUnixSocket(ctx, ctrlPath)
	if err != nil {
		if isMuxUnavailableErr(err) {
			return ports.NewMuxControlResponse(false, 0, "not running")
		}
		return muxstream.ZeroVal[ports.MuxControlResponse](), err
	}
	switch st {
	case osfs.SocketProbeMissing, osfs.SocketProbeStale:
		return ports.NewMuxControlResponse(false, 0, "not running")
	case osfs.SocketProbeNotSocket:
		return muxstream.ZeroVal[ports.MuxControlResponse](), fmt.Errorf("%w: 目标路径不是控制套接字", ports.ErrMuxUnavailable)
	}
	return m.probeLiveSocket(ctx, ctrlPath)
}

func (m *MuxSocket) probeLiveSocket(ctx context.Context, ctrlPath osfs.ControlSocketPath) (ports.MuxControlResponse, error) {
	conn, _, err := m.dialVerified(ctx, ctrlPath)
	if err != nil {
		if errors.Is(err, ports.ErrMuxUnavailable) {
			return ports.NewMuxControlResponse(false, 0, "not running")
		}
		return muxstream.ZeroVal[ports.MuxControlResponse](), err
	}
	defer func() { _ = conn.Close() }()
	var pid uint32
	err = chanconn.RunWithAbortWatchdog(ctx, func() { _ = conn.Close() }, func() error {
		if _, hErr := muxstream.ExchangeClientHello(conn); hErr != nil {
			return fmt.Errorf("%w: PROTOCOL.mux 握手失败: %w", ports.ErrMuxUnavailable, hErr)
		}
		p, aErr := muxstream.SendAliveCheck(conn, 1)
		if aErr != nil {
			return fmt.Errorf("%w: 探活失败: %w", ports.ErrMuxUnavailable, aErr)
		}
		pid = p
		return nil
	})
	if err != nil {
		return muxstream.ZeroVal[ports.MuxControlResponse](), err
	}
	return ports.NewMuxControlResponse(true, pid, "alive")
}

// Control 向活跃 ControlMaster 发送 PROTOCOL.mux v4 控制动作（check/forward/cancel/exit/stop）。
func (m *MuxSocket) Control(ctx context.Context, req ports.MuxControlRequest) (ports.MuxControlResponse, error) {
	if err := m.checkReady(ctx); err != nil {
		return muxstream.ZeroVal[ports.MuxControlResponse](), err
	}
	if !req.IsValid() || req.Action() == ports.MuxActionProxy {
		return muxstream.ZeroVal[ports.MuxControlResponse](), fmt.Errorf("%w: MuxControlRequest 无效或需改用 OpenProxy", ports.ErrInvalidArgument)
	}
	ctrlPath, err := toControlSocketPath(req.SocketPath())
	if err != nil {
		return muxstream.ZeroVal[ports.MuxControlResponse](), err
	}
	conn, _, err := m.dialVerified(ctx, ctrlPath)
	if err != nil {
		return muxstream.ZeroVal[ports.MuxControlResponse](), err
	}
	defer func() { _ = conn.Close() }()
	var resp ports.MuxControlResponse
	err = chanconn.RunWithAbortWatchdog(ctx, func() { _ = conn.Close() }, func() error {
		exts, hErr := muxstream.ExchangeClientHello(conn)
		if hErr != nil {
			return fmt.Errorf("%w: %w", ports.ErrMuxUnavailable, hErr)
		}
		r, cErr := m.execControlAction(conn, req, exts)
		if cErr != nil {
			return cErr
		}
		resp = r
		return nil
	})
	if err != nil {
		return muxstream.ZeroVal[ports.MuxControlResponse](), err
	}
	return resp, nil
}

// OpenProxy 以 PROTOCOL.mux v4 MUX_C_PROXY 模式打开与 ControlMaster 的双向透传流。
func (m *MuxSocket) OpenProxy(ctx context.Context, socketPath pathalg.LocalSourcePath) (net.Conn, error) {
	if err := m.checkReady(ctx); err != nil {
		return nil, err
	}
	ctrlPath, err := toControlSocketPath(socketPath)
	if err != nil {
		return nil, err
	}
	conn, _, err := m.dialVerified(ctx, ctrlPath)
	if err != nil {
		return nil, err
	}
	if err := chanconn.RunWithAbortWatchdog(ctx, func() { _ = conn.Close() }, func() error {
		return negotiateProxyMode(conn)
	}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// DialMux 连接活跃 ControlMaster，校验对端凭证与存活状态后返回绑定精确 (hopDigest, endpoint) 的 ports.TransportConn。
func (m *MuxSocket) DialMux(ctx context.Context, socketPath pathalg.LocalSourcePath, hopDigest plan.HopDigest, endpoint netaddr.Endpoint) (ports.TransportConn, error) {
	if err := m.checkReady(ctx); err != nil {
		return nil, err
	}
	if !hopDigest.IsValid() || !endpoint.IsValid() {
		return nil, fmt.Errorf("%w: DialMux 需要有效 HopDigest 与 Endpoint", ports.ErrInvalidArgument)
	}
	ctrlPath, err := toControlSocketPath(socketPath)
	if err != nil {
		return nil, err
	}
	conn, cred, err := m.dialVerified(ctx, ctrlPath)
	if err != nil {
		return nil, err
	}
	var exts map[string]string
	err = chanconn.RunWithAbortWatchdog(ctx, func() { _ = conn.Close() }, func() error {
		e, hErr := muxstream.ExchangeClientHello(conn)
		if hErr != nil {
			return hErr
		}
		if _, aErr := muxstream.SendAliveCheck(conn, 1); aErr != nil {
			return aErr
		}
		exts = e
		return nil
	})
	_ = conn.Close()
	if err != nil {
		return nil, fmt.Errorf("%w: ControlMaster 握手或探活失败: %w", ports.ErrMuxUnavailable, err)
	}
	return newMuxTransportConn(m, ctrlPath, hopDigest, endpoint, exts[muxstream.ExtXOpsStreamMux] == "1", formatPeerDetail(cred))
}

func (m *MuxSocket) dialVerified(ctx context.Context, ctrlPath osfs.ControlSocketPath) (*net.UnixConn, osfs.PeerCred, error) {
	conn, cred, err := osfs.DialUnixVerified(ctx, ctrlPath)
	if err != nil {
		if isMuxUnavailableErr(err) {
			return nil, muxstream.ZeroVal[osfs.PeerCred](), fmt.Errorf("%w: %w", ports.ErrMuxUnavailable, err)
		}
		if errors.Is(err, osfs.ErrUnauthorizedPeer) {
			return nil, muxstream.ZeroVal[osfs.PeerCred](), fmt.Errorf("%w: %w", ports.ErrPermissionDenied, err)
		}
		return nil, muxstream.ZeroVal[osfs.PeerCred](), err
	}
	_ = conn.SetDeadline(m.handshakeDeadline(ctx))
	return conn, cred, nil
}

func toControlSocketPath(src pathalg.LocalSourcePath) (osfs.ControlSocketPath, error) {
	if !src.IsValid() {
		return muxstream.ZeroVal[osfs.ControlSocketPath](), fmt.Errorf("%w: 控制套接字路径无效", ports.ErrInvalidArgument)
	}
	cp, err := osfs.ControlSocketPathFromSource(src)
	if err != nil {
		return muxstream.ZeroVal[osfs.ControlSocketPath](), fmt.Errorf("%w: %w", ports.ErrInvalidArgument, err)
	}
	return cp, nil
}

func mapSlotBindError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, osfs.ErrSlotOccupied) {
		return fmt.Errorf("%w: %w", ports.ErrAlreadyExists, err)
	}
	if errors.Is(err, osfs.ErrNotSocket) || errors.Is(err, osfs.ErrInvalidControlPath) || errors.Is(err, osfs.ErrControlPathTooLong) {
		return fmt.Errorf("%w: %w", ports.ErrInvalidArgument, err)
	}
	return err
}
