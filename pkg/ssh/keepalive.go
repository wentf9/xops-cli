package ssh

import (
	"context"
	"time"

	"golang.org/x/crypto/ssh"
)

// StartKeepAlive 开启一个协程，定期向 SSH Server 发送心跳
// ctx: 用于控制协程退出的上下文
// interval: 心跳间隔 (建议 15s - 60s)
// fallback: 可选的回调函数，用于在心跳失败后执行,心跳失败时会关闭连接
func StartKeepAlive(ctx context.Context, client *ssh.Client, interval time.Duration, fallback func(err error)) {
	go func() {
		// 创建一个定时器
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// 发送心跳请求
				// "keepalive@openssh.com" 是 OpenSSH 标准的心跳请求类型
				// wantReply = true: 要求服务器回复。如果服务器挂了或网络断了，SendRequest 会报错
				// payload = nil: 不需要携带额外数据
				_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)

				if err != nil {
					// 如果发送心跳失败，说明连接已经断了
					// 显式关闭 Client，这样主程序中正在使用的 Session 也会收到错误通知
					_ = client.Close()
					if fallback != nil {
						fallback(err)
					}
					return
				}
			}
		}
	}()
}
