// Package forward 实现 XOps v2 真实 SSH 端口转发（-L/-R/-D）、双向/混合 TCP↔Unix StreamLocal
// 转发与 L2/L3 SSH TUN 隧道桥接适配器（ports.ForwarderPort / ports.ForwardHandle，ADR-009 / ADR-015）。
//
// 核心安全、并发与边界不变量：
//   - 全包 0 裸 go 语句，全部监听循环、连接中继与 TUN 桥接均受 core/conc.Nursery 监督，关闭零协程泄漏；
//   - 本地 AF_UNIX StreamLocal 监听严格委托 core/osfs.WithSocketSlot，默认本机 Unix 目标拨号委托
//     core/osfs.DialUnixVerified（含目录锁、对端用户凭证核验与 INV-A3 退出释放顺序）；
//   - 默认遵循 OpenSSH GatewayPorts=no 失败关闭策略，绑定前后双阶段核验仅允许回环地址，
//     拒绝本地非回环或通配地址（0.0.0.0 / :: / *）绑定，仅在显式配置 AllowGatewayPorts=true 时放行；
//   - StartForward 的 ctx 仅约束同步建链/绑定阶段，返回后的长生命周期 Handle 独立运行并在上游传输
//     WaitDone 断开时自动收敛关闭；
//   - 纯 Go RFC 1928 SOCKS5 服务端（-D）仅允许 CONNECT（拒绝 BIND 与 UDP ASSOCIATE 防旁路泄露），
//     对 ATYP=DOMAINNAME 零本机 DNS 解析，原样透传域名交由远端 direct-tcpip 通道解析（彻底阻断 DNS 泄露）；
//   - 全包 0 行内 lint 豁免，零值 Forwarder / Handle 恒失败关闭。
package forward

import (
	"context"
	"net"
	"time"

	"github.com/wentf9/xops-cli/core/ports"
)

const (
	defaultSOCKSHandshakeTimeout = 10 * time.Second
	relayCopyBufferBytes         = 32 * 1024
)

// DialLocalFunc 定义反向转发（-R）连接本机 TCP 或 Unix 目标的拨号函数签名（为空时 TCP 走 net.Dialer，Unix 走 osfs.DialUnixVerified）。
type DialLocalFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Config 描述 Forwarder 的显式出站依赖与安全边界配置（零值即安全失败关闭默认配置）。
type Config struct {
	// TUNDevice 可选注入本机 TUN/TAP 虚拟网卡端口；未配置时 ForwardTUN 返回 ports.ErrUnsupported。
	TUNDevice ports.TUNDevicePort
	// AllowGatewayPorts 允许本地 -L/-D TCP 转发绑定非回环或通配地址（默认 false，遵循 OpenSSH GatewayPorts=no）。
	AllowGatewayPorts bool
	// ReplaceStaleUnix 允许本地 -L Unix StreamLocal 监听在目录锁确证过期套接字后安全接管（绝不抢占活套接字）。
	ReplaceStaleUnix bool
	// LocalDialer 可选覆盖反向转发（-R）的本机目标拨号器。
	LocalDialer DialLocalFunc
	// SOCKSHandshakeTimeout 限制单条 -D SOCKS5 客户端握手超时（默认 10s），防御慢速连接耗尽协程。
	SOCKSHandshakeTimeout time.Duration
	// Clock 保留用于配置注入兼容；真实 OS 套接字 SetDeadline 严格使用系统墙钟避免虚拟时钟触发虚假超时。
	Clock ports.Clock
}

// Forwarder 实现 ports.ForwarderPort，支持 -L/-R/-D、TCP↔Unix 双向/混合转发与 TUN 桥接；零值恒失败关闭。
//
//xops:opaque
//xops:failclosed
type Forwarder struct {
	tunDevice            ports.TUNDevicePort
	allowGatewayPorts    bool
	replaceStaleUnix     bool
	localDialer          DialLocalFunc
	hasCustomLocalDialer bool
	socksTimeout         time.Duration
	valid                bool
}

// NewForwarder 构造不可变 Forwarder 适配器。
func NewForwarder(cfg Config) *Forwarder {
	dialer := cfg.LocalDialer
	hasCustom := dialer != nil
	if dialer == nil {
		dialer = (&net.Dialer{}).DialContext
	}
	timeout := cfg.SOCKSHandshakeTimeout
	if timeout <= 0 {
		timeout = defaultSOCKSHandshakeTimeout
	}
	return &Forwarder{
		tunDevice:            cfg.TUNDevice,
		allowGatewayPorts:    cfg.AllowGatewayPorts,
		replaceStaleUnix:     cfg.ReplaceStaleUnix,
		localDialer:          dialer,
		hasCustomLocalDialer: hasCustom,
		socksTimeout:         timeout,
		valid:                true,
	}
}

func zeroVal[T any]() (z T) { return z }
