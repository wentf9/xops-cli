package ssh

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

// errKeepaliveTimeout 心跳请求在超时时间内未收到服务器响应
var errKeepaliveTimeout = errors.New("keepalive probe timed out")

// StartKeepAlive 开启一个协程，定期向 SSH Server 发送心跳
// ctx: 用于控制协程退出的上下文
// client: 目标 SSH 客户端
// interval: 心跳间隔 (建议 15s - 60s)
// timeout: 单次心跳等待响应的超时时间 (建议 5s - 15s)，超时视为连接已断开
// fallback: 可选的回调函数，用于在心跳失败后执行,心跳失败时会关闭连接
func StartKeepAlive(ctx context.Context, client *ssh.Client, interval, timeout time.Duration, fallback func(err error)) {
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
				if err := probeWithTimeout(client, timeout); err != nil {
					// 心跳失败或超时，说明连接已经断了
					// 显式关闭 Client，这样主程序中正在使用的 Session 也会收到错误通知，
					// 同时使阻塞在 SendRequest 上的探测协程解除阻塞
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

// probeWithTimeout 发送一次心跳请求并在 timeout 内等待响应。
// SendRequest 本身无法取消，超时后由调用方通过 Close 关闭连接使其返回，
// 内部协程向带缓冲通道发送结果后即退出，不会泄漏。
func probeWithTimeout(client *ssh.Client, timeout time.Duration) error {
	type probeResult struct{ err error }
	done := make(chan probeResult, 1)
	go func() {
		// payload = nil: 不需要携带额外数据
		// "keepalive@openssh.com" 是 OpenSSH 标准的心跳请求类型
		// wantReply = true: 要求服务器回复。如果服务器挂了或网络断了，探测会报错或超时
		_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
		done <- probeResult{err: err}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-done:
		return r.err
	case <-timer.C:
		return fmt.Errorf("ssh keepalive: %w", errKeepaliveTimeout)
	}
}
