package ssh

import (
	"context"
	"net"
)

// Dialer 定义网络连接行为的接口
// 用于统一 "直连" 和 "通过 SSH 跳板机连接" 的行为
type Dialer interface {
	Dial(network, addr string) (net.Conn, error)
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}
