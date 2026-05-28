package ssh

import (
	"context"
	"net"

	"golang.org/x/crypto/ssh"
)

// SSHProxyDialer 实现了 Dialer 接口，通过 SSH 隧道转发流量
type SSHProxyDialer struct {
	Client *ssh.Client
}

func (s *SSHProxyDialer) Dial(network, addr string) (net.Conn, error) {
	return s.Client.Dial(network, addr)
}

func (s *SSHProxyDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// ssh.Client.Dial 本身不支持 Context，
	// 但我们可以简单的直接调用 Dial。
	// 如果需要严格的超时控制，可以在外层使用带有超时的 Context 并在 Dial 完成后检查。

	// 一个简单的异步实现以支持 Context 取消：
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)

	go func() {
		conn, err := s.Client.Dial(network, addr)
		ch <- result{conn: conn, err: err}
	}()

	select {
	case <-ctx.Done():
		go func() {
			res := <-ch
			if res.conn != nil {
				_ = res.conn.Close()
			}
		}()
		return nil, ctx.Err()
	case res := <-ch:
		if res.err != nil {
			return nil, res.err
		}
		return res.conn, nil
	}
}
