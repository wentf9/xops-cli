package ports

import (
	"context"
	"fmt"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"io"
	"net"
)

// PTYRequest 描述远端伪终端分配请求（终端类型与窗口尺寸）；零值恒无效。
//
//xops:opaque
//xops:failclosed
type PTYRequest struct {
	term  string
	size  TerminalSize
	valid bool
}

// NewPTYRequest 校验终端类型名称与窗口尺寸并构造不可变 PTYRequest。
func NewPTYRequest(term string, size TerminalSize) (PTYRequest, error) {
	switch {
	case !isValidASCIIToken(term, maxPortTokenLen):
		return PTYRequest{}, fmt.Errorf("%w: 非法 TERM 标识 %q", ErrInvalidArgument, term)
	case !size.IsValid():
		return PTYRequest{}, fmt.Errorf("%w: %w", ErrInvalidArgument, ErrInvalidTTYSize)
	default:
		return PTYRequest{term: term, size: size, valid: true}, nil
	}
}
func (p PTYRequest) IsValid() bool      { return p.valid && p.term != "" && p.size.IsValid() }
func (p PTYRequest) IsZero() bool       { return !p.IsValid() }
func (p PTYRequest) Term() string       { return p.term }
func (p PTYRequest) Size() TerminalSize { return p.size }
func (p PTYRequest) Equal(o PTYRequest) bool {
	return p.IsValid() && o.IsValid() && p.term == o.term && p.size.Equal(o.size)
}

// ForwardDirection 标识 SSH 隧道转发方向类别（-L/-R/-D/TUN）；零值 ForwardDirectionInvalid 失败关闭。
//
//xops:opaque
//xops:failclosed
type ForwardDirection uint8

const (
	ForwardDirectionInvalid ForwardDirection = iota // 无效转发方向（零值失败关闭）
	ForwardLocal                                    // 本地监听 -> 远端目标转发（-L，支持 TCP 与 StreamLocal 双向/混合）
	ForwardRemote                                   // 远端监听 -> 本地目标转发（-R，支持 TCP 与 StreamLocal 双向/混合）
	ForwardDynamic                                  // 本地动态 SOCKS5 转发（-D）
	ForwardTUN                                      // L2/L3 隧道设备转发（-w）
)

// ForwardEndpointKind 标识隧道转发监听端或目标端的端点协议类别（TCP / Unix Domain Socket）；零值失败关闭。
//
//xops:opaque
//xops:failclosed
type ForwardEndpointKind uint8

const (
	ForwardEndpointInvalid ForwardEndpointKind = iota // 无效端点类别（零值失败关闭）
	ForwardEndpointTCP                                // TCP host:port 端点
	ForwardEndpointUnix                               // Unix Domain Socket (StreamLocal) 端点
)

// ForwardSpec 描述单条 SSH 隧道转发规则（显式区分方向、监听/目标端点类型与强类型 TUNSpec）；零值恒无效。
//
//xops:opaque
//xops:failclosed
type ForwardSpec struct {
	direction            ForwardDirection
	bindKind, targetKind ForwardEndpointKind
	bindAddr, targetAddr string
	tun                  algebraic.Option[TUNSpec]
	valid                bool
}

// NewForwardSpec 构造默认 TCP 端点的非 TUN 转发规则（ForwardLocal/ForwardRemote 为 TCP->TCP，
// ForwardDynamic 为 TCP 无目标）；涉及 StreamLocal（Unix 套接字）请使用 NewTypedForwardSpec，ForwardTUN 须经 NewForwardTUNSpec。
func NewForwardSpec(direction ForwardDirection, bindAddr, targetAddr string) (ForwardSpec, error) {
	return NewTypedForwardSpec(direction, ForwardEndpointTCP, bindAddr, pickIf(direction == ForwardDynamic, ForwardEndpointInvalid, ForwardEndpointTCP), targetAddr)
}

// NewTypedForwardSpec 校验非 TUN 转发方向、显式监听/目标端点类型与地址组合并构造不可变 ForwardSpec，
// 完整支持 -L/-R 下的 TCP↔TCP、Unix↔Unix、TCP↔Unix 四类组合而零字符串嗅探。
func NewTypedForwardSpec(direction ForwardDirection, bindKind ForwardEndpointKind, bindAddr string, targetKind ForwardEndpointKind, targetAddr string) (ForwardSpec, error) {
	bind, e1 := sanitizeBoundedText(bindAddr, maxPortDetailBytes, false, ErrInvalidArgument)
	target, e2 := sanitizeBoundedText(targetAddr, maxPortDetailBytes, direction == ForwardDynamic, ErrInvalidArgument)
	validKinds := pickIf(direction == ForwardDynamic, bindKind == ForwardEndpointTCP && targetKind == ForwardEndpointInvalid && target == "", bindKind.IsValid() && targetKind.IsValid() && target != "")
	if !direction.IsValid() || direction == ForwardTUN || firstErr(e1, e2) != nil || !validKinds {
		return ForwardSpec{}, fmt.Errorf("%w: ForwardSpec 方向、端点类型或地址组合非法", ErrInvalidArgument)
	}
	return ForwardSpec{direction: direction, bindKind: bindKind, targetKind: targetKind, bindAddr: bind, targetAddr: target, valid: true}, nil
}

// NewForwardTUNSpec 校验强类型 TUNSpec 并构造 ForwardTUN 方向的不可变 ForwardSpec。
func NewForwardTUNSpec(tun TUNSpec) (ForwardSpec, error) {
	if !tun.IsValid() {
		return ForwardSpec{}, fmt.Errorf("%w: ForwardTUN 需要有效 TUNSpec", ErrInvalidArgument)
	}
	return ForwardSpec{direction: ForwardTUN, bindAddr: formatTUNUnitAddr(tun.Mode(), tun.LocalUnit()), targetAddr: formatTUNUnitAddr(tun.Mode(), tun.RemoteUnit()), tun: algebraic.Some(tun), valid: true}, nil
}
func formatTUNUnitAddr(mode TUNMode, unit uint32) string {
	p := pickIf(mode == TUNModeEthernet, "tap", "tun")
	return pickIf(unit == TUNUnitAny, p+"any", fmt.Sprintf("%s%d", p, unit))
}
func (f ForwardSpec) IsValid() bool {
	if !f.valid || !f.direction.IsValid() || f.bindAddr == "" {
		return false
	}
	t, hasT := f.tun.Get()
	switch f.direction {
	case ForwardTUN:
		return hasT && t.IsValid() && f.targetAddr != "" && f.bindKind == ForwardEndpointInvalid && f.targetKind == ForwardEndpointInvalid
	case ForwardDynamic:
		return !hasT && f.bindKind == ForwardEndpointTCP && f.targetKind == ForwardEndpointInvalid && f.targetAddr == ""
	default:
		return !hasT && f.bindKind.IsValid() && f.targetKind.IsValid() && f.targetAddr != ""
	}
}
func (f ForwardSpec) IsZero() bool                    { return !f.IsValid() }
func (f ForwardSpec) Direction() ForwardDirection     { return orZero(f.IsValid(), f.direction) }
func (f ForwardSpec) BindKind() ForwardEndpointKind   { return orZero(f.IsValid(), f.bindKind) }
func (f ForwardSpec) TargetKind() ForwardEndpointKind { return orZero(f.IsValid(), f.targetKind) }
func (f ForwardSpec) BindAddr() string                { return f.bindAddr }
func (f ForwardSpec) TargetAddr() string              { return f.targetAddr }
func (f ForwardSpec) TUN() algebraic.Option[TUNSpec]  { return f.tun }
func (f ForwardSpec) Equal(o ForwardSpec) bool {
	return f.IsValid() && o.IsValid() && f.direction == o.direction && f.bindKind == o.bindKind && f.targetKind == o.targetKind && f.bindAddr == o.bindAddr && f.targetAddr == o.targetAddr && optEqualFunc(f.tun, o.tun, TUNSpec.Equal)
}

// ExecStreams 聚合单次远端会话执行的运行期数据面流、可选 PTY 与经 SendEnv 过滤后的环境变量（非持久化 DTO）。
type ExecStreams struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	PTY            algebraic.Option[PTYRequest]
	Env            map[string]string
}

// RemoteSession 表示单条 SSH 通道上建立的远端命令或交互式 Shell 会话（隔离 x/crypto/ssh.Session）。
// StdinPipe / StdoutPipe / StderrPipe 须在 Start / StartShell 前获取且分别与非空 ExecStreams.{Stdin,Stdout,Stderr} 互斥，
// 支撑 TerminalHandle.Relay 双向流中继与 sshnet/priv 随机 -p 提权握手（含 PROTOCOL.mux v4）。
type RemoteSession interface {
	StdinPipe() (io.WriteCloser, error)
	StdoutPipe() (io.Reader, error)
	StderrPipe() (io.Reader, error)
	Start(ctx context.Context, cmd execution.CommandPlan, streams ExecStreams) error
	// StartShell 启动远端交互式 Shell 会话（可选 PTY 与环境变量统一由 streams.PTY / streams.Env 承载）。
	StartShell(ctx context.Context, streams ExecStreams) error
	ResizePTY(ctx context.Context, size TerminalSize) error
	Signal(ctx context.Context, signal string) error
	Wait(ctx context.Context) (execution.ExecutionOutcome, error)
	Close() error
}

// SessionOpener 是打开隔离远端会话通道的最小能力窄接口；*pool.Lease 与 TransportConn 均天然满足。
type SessionOpener interface {
	OpenSession(ctx context.Context) (RemoteSession, error)
}

// TunnelTransport 是面向端口转发、StreamLocal 与 TUN 隧道的最小数据面窄接口；*pool.Lease 与 TransportConn 均满足。
type TunnelTransport interface {
	DialTCP(ctx context.Context, target netaddr.HostPort) (net.Conn, error)
	ListenTCP(ctx context.Context, bindAddr string) (net.Listener, error)
	DialStreamLocal(ctx context.Context, remoteSocket pathalg.RemotePath) (net.Conn, error)
	ListenStreamLocal(ctx context.Context, remoteSocket pathalg.RemotePath) (net.Listener, error)
	OpenTUN(ctx context.Context, spec TUNSpec) (io.ReadWriteCloser, error)
}

// TransportConn 表示一条已认证的实时 SSH 传输连接，由 core/internal/pool 独占托管（ADR-009）。
type TransportConn interface {
	SessionOpener
	TunnelTransport
	HopDigest() plan.HopDigest
	Endpoint() netaddr.Endpoint
	OpenRemoteFS(ctx context.Context) (RemoteFSPort, error)
	SendKeepalive(ctx context.Context) error
	IsAlive() bool
	Close() error
}

// DialerPort 定义协议无关的 SSH 单跳/多跳拨号出站端口（ADR-009 / ADR-015）。
type DialerPort interface {
	DialHop(ctx context.Context, hop plan.HopSpec, hopDigest plan.HopDigest, parent TransportConn) (TransportConn, error)
}

// MuxControlAction 标识 OpenSSH PROTOCOL.mux v4 控制面动作；零值 MuxActionInvalid 严格失败关闭。
//
//xops:opaque
//xops:failclosed
type MuxControlAction uint8

const (
	MuxActionInvalid MuxControlAction = iota // 无效控制动作（零值失败关闭）
	MuxActionCheck                           // 探测存活并查询 PID
	MuxActionForward                         // 开启端口转发
	MuxActionCancel                          // 取消端口转发
	MuxActionExit                            // 优雅退出
	MuxActionStop                            // 立即停止
	MuxActionProxy                           // 代理透传模式
)

// MuxControlRequest 描述面向 MuxSocketPort.Control 的多路复用控制面请求；零值恒无效。
//
//xops:opaque
//xops:failclosed
type MuxControlRequest struct {
	action     MuxControlAction
	socketPath pathalg.LocalSourcePath
	forward    algebraic.Option[ForwardSpec]
	valid      bool
}

// NewMuxControlRequest 校验控制动作、套接字路径与可选转发规格（forward/cancel 必填）并构造请求。
func NewMuxControlRequest(action MuxControlAction, socketPath pathalg.LocalSourcePath, forward algebraic.Option[ForwardSpec]) (MuxControlRequest, error) {
	fwd, hasFwd := forward.Get()
	needsFwd := action == MuxActionForward || action == MuxActionCancel
	if !action.IsValid() || !socketPath.IsValid() || (needsFwd && (!hasFwd || !fwd.IsValid())) || (!needsFwd && hasFwd) {
		return MuxControlRequest{}, fmt.Errorf("%w: MuxControlRequest 动作、路径或 ForwardSpec 组合非法", ErrInvalidArgument)
	}
	return MuxControlRequest{action: action, socketPath: socketPath, forward: forward, valid: true}, nil
}
func (r MuxControlRequest) IsValid() bool {
	return r.valid && r.action.IsValid() && r.socketPath.IsValid()
}
func (r MuxControlRequest) IsZero() bool                           { return !r.IsValid() }
func (r MuxControlRequest) Action() MuxControlAction               { return orZero(r.IsValid(), r.action) }
func (r MuxControlRequest) SocketPath() pathalg.LocalSourcePath    { return r.socketPath }
func (r MuxControlRequest) Forward() algebraic.Option[ForwardSpec] { return r.forward }

// MuxControlResponse 描述多路复用探测或控制动作的不可变结果；零值恒无效。
//
//xops:opaque
//xops:failclosed
type MuxControlResponse struct {
	alive, valid bool
	masterPID    uint32
	detail       string
}

// NewMuxControlResponse 校验主进程状态与诊断说明并构造不可变 MuxControlResponse。
func NewMuxControlResponse(alive bool, masterPID uint32, detail string) (MuxControlResponse, error) {
	if !alive && masterPID != 0 {
		return MuxControlResponse{}, fmt.Errorf("%w: 非存活响应不得携带非零 master_pid", ErrInvalidArgument)
	}
	clean, err := sanitizeBoundedText(detail, maxPortDetailBytes, true, ErrInvalidArgument)
	return pickIf(err == nil, MuxControlResponse{alive: alive, masterPID: masterPID, detail: clean, valid: true}, MuxControlResponse{}), err
}
func (r MuxControlResponse) IsValid() bool     { return r.valid }
func (r MuxControlResponse) IsZero() bool      { return !r.IsValid() }
func (r MuxControlResponse) Alive() bool       { return r.IsValid() && r.alive }
func (r MuxControlResponse) MasterPID() uint32 { return pickIf(r.IsValid(), r.masterPID, 0) }
func (r MuxControlResponse) Detail() string    { return r.detail }
func (r MuxControlResponse) Equal(o MuxControlResponse) bool {
	return r.IsValid() && o.IsValid() && r.alive == o.alive && r.masterPID == o.masterPID && r.detail == o.detail
}

// MuxSocketPort 定义本地 ControlMaster/ControlPersist AF_UNIX 套接字探测、控制、服务端与代理出站端口（INV-A3 / INV-C4）。
type MuxSocketPort interface {
	Probe(ctx context.Context, socketPath pathalg.LocalSourcePath) (MuxControlResponse, error)
	Control(ctx context.Context, req MuxControlRequest) (MuxControlResponse, error)
	// DialMux 连接至活跃 ControlMaster 并返回绑定精确 (hopDigest, endpoint) 身份的 TransportConn。
	DialMux(ctx context.Context, socketPath pathalg.LocalSourcePath, hopDigest plan.HopDigest, endpoint netaddr.Endpoint) (TransportConn, error)
	// OpenProxy 以 PROTOCOL.mux v4 `-O proxy`（MuxActionProxy）模式打开与 ControlMaster 的双向 stdio 透传流。
	OpenProxy(ctx context.Context, socketPath pathalg.LocalSourcePath) (net.Conn, error)
	// Serve 在 ln 上以 PROTOCOL.mux v4 服务端模式响应会话、转发、探活、退出与代理请求（upstream 为非借用池钉选连接，forwarder 可选；具体实现如 P4-T2 sshnet/mux 须在 ln 参数上标注参数级 //xops:borrowed 确保零逃逸）。
	Serve(ctx context.Context, ln net.Listener, upstream TransportConn, forwarder ForwarderPort) error
	// WithListener 在独占目录锁下绑定 AF_UNIX 套接字（Accept 校验对端凭证），退出时按锁->SameFile->unlink->close->解锁释放。
	//xops:syncclosure
	//xops:borrowed
	WithListener(ctx context.Context, socketPath pathalg.LocalSourcePath, fn func(ln net.Listener) error) error
}
