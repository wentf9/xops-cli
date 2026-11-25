package ports

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
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
	if !isValidASCIIToken(term, maxPortTokenLen) {
		return PTYRequest{}, fmt.Errorf("%w: 非法 TERM 标识 %q", ErrInvalidArgument, term)
	}
	if !size.IsValid() {
		return PTYRequest{}, fmt.Errorf("%w: %w", ErrInvalidArgument, ErrInvalidTTYSize)
	}
	return PTYRequest{term: term, size: size, valid: true}, nil
}
func (p PTYRequest) IsValid() bool      { return p.valid && p.term != "" && p.size.IsValid() }
func (p PTYRequest) IsZero() bool       { return !p.IsValid() }
func (p PTYRequest) Term() string       { return p.term }
func (p PTYRequest) Size() TerminalSize { return p.size }
func (p PTYRequest) Equal(o PTYRequest) bool {
	return p.IsValid() && o.IsValid() && p.term == o.term && p.size.Equal(o.size)
}

// ForwardDirection 标识 SSH 隧道转发方向类别（-L/-R/-D/StreamLocal/TUN）；零值 ForwardDirectionInvalid 失败关闭。
//
//xops:opaque
//xops:failclosed
type ForwardDirection uint8

const (
	ForwardDirectionInvalid ForwardDirection = iota // 无效转发方向（零值失败关闭）
	ForwardLocal                                    // 本地端口转发（-L）
	ForwardRemote                                   // 远端端口转发（-R）
	ForwardDynamic                                  // 动态 SOCKS5 转发（-D）
	ForwardStreamLocal                              // Unix Domain Socket 转发
	ForwardTUN                                      // L2/L3 隧道设备转发（-w）
)

// ForwardSpec 描述单条 SSH 隧道转发规则（含 ForwardTUN 强类型 TUNSpec）；零值恒无效。
//
//xops:opaque
//xops:failclosed
type ForwardSpec struct {
	direction            ForwardDirection
	bindAddr, targetAddr string
	tun                  algebraic.Option[TUNSpec]
	valid                bool
}

// NewForwardSpec 校验非 TUN 转发方向、监听地址与目标地址组合并构造不可变 ForwardSpec；
// ForwardDynamic 要求 targetAddr 为空，ForwardTUN 须经 NewForwardTUNSpec 构造。
func NewForwardSpec(direction ForwardDirection, bindAddr, targetAddr string) (ForwardSpec, error) {
	bind, e1 := sanitizeBoundedText(bindAddr, maxPortDetailBytes, false, ErrInvalidArgument)
	target, e2 := sanitizeBoundedText(targetAddr, maxPortDetailBytes, direction == ForwardDynamic, ErrInvalidArgument)
	if !direction.IsValid() || direction == ForwardTUN || firstErr(e1, e2) != nil || (direction == ForwardDynamic && target != "") {
		return ForwardSpec{}, fmt.Errorf("%w: ForwardSpec 方向或地址组合非法（ForwardTUN 须使用 NewForwardTUNSpec）", ErrInvalidArgument)
	}
	return ForwardSpec{direction: direction, bindAddr: bind, targetAddr: target, valid: true}, nil
}

// NewForwardTUNSpec 校验强类型 TUNSpec 并构造 ForwardTUN 方向的不可变 ForwardSpec。
func NewForwardTUNSpec(tun TUNSpec) (ForwardSpec, error) {
	if !tun.IsValid() {
		return ForwardSpec{}, fmt.Errorf("%w: ForwardTUN 需要有效 TUNSpec", ErrInvalidArgument)
	}
	return ForwardSpec{
		direction: ForwardTUN, bindAddr: formatTUNUnitAddr(tun.Mode(), tun.LocalUnit()),
		targetAddr: formatTUNUnitAddr(tun.Mode(), tun.RemoteUnit()), tun: algebraic.Some(tun), valid: true,
	}, nil
}

func formatTUNUnitAddr(mode TUNMode, unit uint32) string {
	prefix := pickIf(mode == TUNModeEthernet, "tap", "tun")
	if unit == TUNUnitAny {
		return prefix + "any"
	}
	return fmt.Sprintf("%s%d", prefix, unit)
}
func (f ForwardSpec) IsValid() bool {
	if !f.valid || !f.direction.IsValid() || f.bindAddr == "" {
		return false
	}
	if f.direction == ForwardTUN {
		t, ok := f.tun.Get()
		return ok && t.IsValid() && f.targetAddr != ""
	}
	return f.tun.IsNone() && (f.direction == ForwardDynamic || f.targetAddr != "")
}
func (f ForwardSpec) IsZero() bool { return !f.IsValid() }
func (f ForwardSpec) Direction() ForwardDirection {
	return pickIf(f.IsValid(), f.direction, ForwardDirectionInvalid)
}
func (f ForwardSpec) BindAddr() string               { return f.bindAddr }
func (f ForwardSpec) TargetAddr() string             { return f.targetAddr }
func (f ForwardSpec) TUN() algebraic.Option[TUNSpec] { return f.tun }
func (f ForwardSpec) Equal(o ForwardSpec) bool {
	return f.IsValid() && o.IsValid() && f.direction == o.direction && f.bindAddr == o.bindAddr &&
		f.targetAddr == o.targetAddr && optEqualFunc(f.tun, o.tun, TUNSpec.Equal)
}

// ExecStreams 聚合单次远端会话执行的运行期数据面流、可选 PTY 与经 SendEnv 过滤后的环境变量（非持久化 DTO）。
type ExecStreams struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	PTY    algebraic.Option[PTYRequest]
	Env    map[string]string
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
	if !action.IsValid() || !socketPath.IsValid() {
		return MuxControlRequest{}, fmt.Errorf("%w: action 与 socketPath 均须有效", ErrInvalidArgument)
	}
	fwd, hasFwd := forward.Get()
	needsFwd := action == MuxActionForward || action == MuxActionCancel
	if (needsFwd && (!hasFwd || !fwd.IsValid())) || (!needsFwd && hasFwd) {
		return MuxControlRequest{}, fmt.Errorf("%w: %s 控制动作与 ForwardSpec 组合非法", ErrInvalidArgument, action)
	}
	return MuxControlRequest{action: action, socketPath: socketPath, forward: forward, valid: true}, nil
}
func (r MuxControlRequest) IsValid() bool {
	return r.valid && r.action.IsValid() && r.socketPath.IsValid()
}
func (r MuxControlRequest) IsZero() bool { return !r.IsValid() }
func (r MuxControlRequest) Action() MuxControlAction {
	return pickIf(r.IsValid(), r.action, MuxActionInvalid)
}
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
	clean, err := sanitizeBoundedText(detail, maxPortDetailBytes, true, ErrInvalidArgument)
	if err != nil {
		return MuxControlResponse{}, err
	}
	if !alive && masterPID != 0 {
		return MuxControlResponse{}, fmt.Errorf("%w: 非存活响应不得携带非零 master_pid", ErrInvalidArgument)
	}
	return MuxControlResponse{alive: alive, masterPID: masterPID, detail: clean, valid: true}, nil
}
func (r MuxControlResponse) IsValid() bool     { return r.valid }
func (r MuxControlResponse) IsZero() bool      { return !r.IsValid() }
func (r MuxControlResponse) Alive() bool       { return r.IsValid() && r.alive }
func (r MuxControlResponse) MasterPID() uint32 { return pickIf(r.IsValid(), r.masterPID, 0) }
func (r MuxControlResponse) Detail() string    { return r.detail }
func (r MuxControlResponse) Equal(o MuxControlResponse) bool {
	return r.IsValid() && o.IsValid() && r.alive == o.alive && r.masterPID == o.masterPID && r.detail == o.detail
}

// MuxSocketPort 定义本地 ControlMaster/ControlPersist AF_UNIX 套接字探测、控制与监听出站端口（INV-A3 / INV-C4）。
// 全部四个方法统一接收经校验的 socketPath pathalg.LocalSourcePath（兼容 OpenSSH %r@%h:%p 含 ':' 路径）。
type MuxSocketPort interface {
	Probe(ctx context.Context, socketPath pathalg.LocalSourcePath) (MuxControlResponse, error)
	Control(ctx context.Context, req MuxControlRequest) (MuxControlResponse, error)
	DialMux(ctx context.Context, socketPath pathalg.LocalSourcePath) (TransportConn, error)
	// WithListener 在 socketPath 对应独占目录锁下绑定 AF_UNIX 监听套接字（Accept 强制校验对端凭证），
	// 同步闭包退出时按「加锁 -> SameFile 校验 -> unlink -> close -> 解锁」固定顺序释放。
	//
	//xops:syncclosure
	//xops:borrowed
	WithListener(ctx context.Context, socketPath pathalg.LocalSourcePath, fn func(ln net.Listener) error) error
}
