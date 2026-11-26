// Package chanconn 为 XOps v2 的 ssh.Channel 虚拟连接提供受 core/conc.Nursery 监督的
// 取消/截止时间看门狗与多路复用操作原语（ADR-009 / ADR-015）。
//
// 本包隶属 core/internal/sshnet/dial 体系，供 sshnet/dial 及后续 sshnet/{sftp,forward,mux}
// 复用：
//   - 全包 0 裸 go 语句，所有后台看门狗、带外排空与脱离读写均受 core/conc.Nursery 托管；
//   - WatchedConn 将无原生 SetDeadline 的 ssh.Channel 封装为标准 net.Conn，在半开黑洞或
//     截止到期时立即解阻并零协程泄漏收敛；
//   - RunWithAbortWatchdog 基于 core/conc.RunScoped 保护单次阻塞操作（如 SSH 握手）。
package chanconn

import "time"

const (
	// MaxCopyChunk 定义通道分块读写与拷贝的默认单次缓冲上限（32 KiB）。
	MaxCopyChunk = 32 * 1024
	// CloseGraceTimeout 定义关闭通道或会话时等待后台排空协程收敛的有界宽限时长。
	CloseGraceTimeout = 5 * time.Millisecond
)

// Addr 为基于 ssh.Channel 的虚拟 net.Conn 提供轻量级 net.Addr 实现。
type Addr struct {
	network string
	address string
}

// NewAddr 构造基于网络类型与地址文本的不可变通道地址。
func NewAddr(network, address string) Addr {
	return Addr{network: network, address: address}
}

// Network 返回通道地址所属网络类型（如 "tcp"、"unix"、"tun"、"subsystem"）。
func (a Addr) Network() string { return a.network }

// String 返回通道地址文本表示。
func (a Addr) String() string { return a.address }
