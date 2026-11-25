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

// PTYRequest 只读访问器与等价比对。
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

// ForwardSpec 描述单条 SSH 隧道转发规则；零值恒无效。
//
//xops:opaque
//xops:failclosed
type ForwardSpec struct {
	direction  ForwardDirection
	bindAddr   string
	targetAddr string
	valid      bool
}

// NewForwardSpec 校验转发方向、监听地址与目标地址组合并构造不可变 ForwardSpec；
// ForwardDynamic 要求 targetAddr 为空，其余方向要求 bindAddr 与 targetAddr 均非空。
func NewForwardSpec(direction ForwardDirection, bindAddr, targetAddr string) (ForwardSpec, error) {
	if !direction.IsValid() {
		return ForwardSpec{}, fmt.Errorf("%w: 无效 ForwardDirection", ErrInvalidArgument)
	}
	bind, err := sanitizeBoundedText(bindAddr, maxPortDetailBytes, false, ErrInvalidArgument)
	if err != nil {
		return ForwardSpec{}, fmt.Errorf("%w: bind_addr 非法", err)
	}
	target, err := sanitizeBoundedText(targetAddr, maxPortDetailBytes, direction == ForwardDynamic, ErrInvalidArgument)
	if err != nil {
		return ForwardSpec{}, fmt.Errorf("%w: target_addr 非法", err)
	}
	if direction == ForwardDynamic && target != "" {
		return ForwardSpec{}, fmt.Errorf("%w: dynamic 转发不得指定 target_addr", ErrInvalidArgument)
	}
	return ForwardSpec{direction: direction, bindAddr: bind, targetAddr: target, valid: true}, nil
}

// ForwardSpec 只读访问器与等价比对。
func (f ForwardSpec) IsValid() bool {
	return f.valid && f.direction.IsValid() && f.bindAddr != "" && (f.direction == ForwardDynamic || f.targetAddr != "")
}
func (f ForwardSpec) IsZero() bool { return !f.IsValid() }
func (f ForwardSpec) Direction() ForwardDirection {
	return pickIf(f.IsValid(), f.direction, ForwardDirectionInvalid)
}
func (f ForwardSpec) BindAddr() string   { return f.bindAddr }
func (f ForwardSpec) TargetAddr() string { return f.targetAddr }
func (f ForwardSpec) Equal(o ForwardSpec) bool {
	return f.IsValid() && o.IsValid() && f.direction == o.direction && f.bindAddr == o.bindAddr && f.targetAddr == o.targetAddr
}

// ExecStreams 聚合单次远端会话执行的运行期数据面流（纯运行期管道，非持久化 DTO）。
type ExecStreams struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	PTY    algebraic.Option[PTYRequest]
}

// RemoteSession 表示单条 SSH 通道上建立的远端命令或交互式 Shell 会话（完全隔离 x/crypto/ssh.Session）。
type RemoteSession interface {
	// Start 按不可变 CommandPlan 启动单次远端命令或脚本执行（流向数据面 streams）。
	Start(ctx context.Context, cmd execution.CommandPlan, streams ExecStreams) error
	// StartShell 启动远端交互式 Shell 会话（可选分配 PTY）。
	StartShell(ctx context.Context, pty algebraic.Option[PTYRequest], streams ExecStreams) error
	// ResizePTY 在已启用 PTY 的交互会话中调整远端窗口尺寸。
	ResizePTY(ctx context.Context, size TerminalSize) error
	// Signal 向远端运行进程发送 POSIX 信号名（如 "INT"、"TERM"、"KILL"）。
	Signal(ctx context.Context, signal string) error
	// Wait 等待远端进程结束并返回不可变封闭 ExecutionOutcome（严分 NotStarted / Completed / Unknown）。
	Wait(ctx context.Context) (execution.ExecutionOutcome, error)
	// Close 关闭会话通道并释放关联传输资源（幂等）。
	Close() error
}

// TransportConn 表示一条已认证的实时 SSH 传输连接（单跳或多跳末跳），由 core/internal/pool 独占托管（ADR-009）。
// 本接口完全剥离 golang.org/x/crypto/ssh 具体类型，确保 core/internal/pool 与 usecase 100% 零 sshnet 依赖。
type TransportConn interface {
	// HopDigest 返回该连接建立时锁定的 Merkle 单跳摘要（含全部上游跳板）。
	HopDigest() plan.HopDigest
	// Endpoint 返回该连接指向的规范化目标端点。
	Endpoint() netaddr.Endpoint
	// OpenSession 在当前传输连接上打开一条隔离的远端命令/Shell 会话通道。
	OpenSession(ctx context.Context) (RemoteSession, error)
	// DialTCP 通过当前 SSH 传输向 target 发起 direct-tcpip 隧道连接（用于多跳拨号与 -L/-D 转发）；
	// 多跳连接须由适配器封装 core/conc.Nursery 取消/超时看门狗（ADR-015）。
	DialTCP(ctx context.Context, target netaddr.HostPort) (net.Conn, error)
	// ListenTCP 在远端 SSH 服务端请求 tcpip-forward 监听（用于 -R 远端转发）。
	ListenTCP(ctx context.Context, bindAddr string) (net.Listener, error)
	// OpenRemoteFS 在当前传输连接上打开受保护的 SFTP 子系统出站端口（无裸客户端逃生口）。
	OpenRemoteFS(ctx context.Context) (RemoteFSPort, error)
	// SendKeepalive 发送单次协议保活探针（归池内 PooledClient 独有，INV-C2）。
	SendKeepalive(ctx context.Context) error
	// IsAlive 报告底层传输连接当前是否仍处于活跃可用状态。
	IsAlive() bool
	// Close 关闭传输连接并释放底层通道与看门狗资源（幂等）。
	Close() error
}

// DialerPort 定义协议无关的 SSH 单跳/多跳拨号出站端口（ADR-009 / ADR-015）。
// core/internal/pool 仅依赖本端口，生产环境由 core/engine 注入 core/internal/sshnet/dial，DST 注入 sim。
type DialerPort interface {
	// DialHop 按不可变单跳规格 hop 与 Merkle 摘要 hopDigest 建立传输连接；
	// parent == nil 表示直连或经 ProxyCommand 建立首跳，parent != nil 表示经上游跳板建立多跳隧道。
	DialHop(ctx context.Context, hop plan.HopSpec, hopDigest plan.HopDigest, parent TransportConn) (TransportConn, error)
}

// MuxControlAction 标识 OpenSSH PROTOCOL.mux v4 控制面动作（-O check/forward/cancel/exit/stop/proxy）；
// 零值 MuxActionInvalid 严格失败关闭。
//
//xops:opaque
//xops:failclosed
type MuxControlAction uint8

const (
	MuxActionInvalid MuxControlAction = iota // 无效控制动作（零值失败关闭）
	MuxActionCheck                           // 探测控制主进程存活并查询 PID
	MuxActionForward                         // 请求主进程开启端口转发
	MuxActionCancel                          // 请求主进程取消端口转发
	MuxActionExit                            // 优雅退出（等待现有会话结束后停止）
	MuxActionStop                            // 立即停止接收并终止主进程
	MuxActionProxy                           // 启动 PROTOCOL.mux 代理透传模式
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

// NewMuxControlRequest 校验控制动作、控制套接字路径与可选转发规格（forward/cancel 必填）并构造请求。
func NewMuxControlRequest(action MuxControlAction, socketPath pathalg.LocalSourcePath, forward algebraic.Option[ForwardSpec]) (MuxControlRequest, error) {
	if !action.IsValid() || !socketPath.IsValid() {
		return MuxControlRequest{}, fmt.Errorf("%w: action 与 socketPath 均须有效", ErrInvalidArgument)
	}
	fwd, hasFwd := forward.Get()
	needsFwd := action == MuxActionForward || action == MuxActionCancel
	if needsFwd && (!hasFwd || !fwd.IsValid()) {
		return MuxControlRequest{}, fmt.Errorf("%w: %s 控制动作必须提供有效 ForwardSpec", ErrInvalidArgument, action)
	}
	if !needsFwd && hasFwd {
		return MuxControlRequest{}, fmt.Errorf("%w: %s 控制动作不得携带 ForwardSpec", ErrInvalidArgument, action)
	}
	return MuxControlRequest{action: action, socketPath: socketPath, forward: forward, valid: true}, nil
}

// MuxControlRequest 只读访问器。
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
	alive     bool
	masterPID uint32
	detail    string
	valid     bool
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

// MuxControlResponse 只读访问器与等价比对。
func (r MuxControlResponse) IsValid() bool     { return r.valid }
func (r MuxControlResponse) IsZero() bool      { return !r.IsValid() }
func (r MuxControlResponse) Alive() bool       { return r.IsValid() && r.alive }
func (r MuxControlResponse) MasterPID() uint32 { return pickIf(r.IsValid(), r.masterPID, 0) }
func (r MuxControlResponse) Detail() string    { return r.detail }
func (r MuxControlResponse) Equal(o MuxControlResponse) bool {
	return r.IsValid() && o.IsValid() && r.alive == o.alive && r.masterPID == o.masterPID && r.detail == o.detail
}

// MuxSocketPort 定义本地 ControlMaster/ControlPersist AF_UNIX 套接字探测、控制与监听出站端口（INV-A3 / INV-C4）。
type MuxSocketPort interface {
	// Probe 对已存在控制套接字执行非侵入式存活探测（如对端 UID/令牌核验与 ping）。
	Probe(ctx context.Context, socketPath pathalg.LocalSourcePath) (MuxControlResponse, error)
	// Control 向运行中的 ControlMaster 发送 PROTOCOL.mux 控制指令并返回结果。
	Control(ctx context.Context, req MuxControlRequest) (MuxControlResponse, error)
	// DialMux 连接到已存在的 ControlMaster 并返回可复用的 TransportConn 视图。
	DialMux(ctx context.Context, socketPath pathalg.LocalSourcePath) (TransportConn, error)
	// WithListener 在沙箱目录 dir 下按 INV-A3 独占目录锁绑定本地 AF_UNIX 监听套接字，
	// 并在同步作用域闭包 fn 退出时按「加目录锁 -> SameFile 校验 -> unlink -> close -> 解锁」固定顺序释放。
	//
	//xops:syncclosure
	//xops:borrowed
	WithListener(ctx context.Context, dir pathalg.LocalDir, name pathalg.LocalRootedDest, fn func(ln net.Listener) error) error
}
