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

// 心跳默认参数：间隔 15s 对齐 OpenSSH ServerAliveInterval 推荐值；
// 单次探测超时 10s，超时即判定网络不可达（覆盖网络黑洞场景）
const (
	DefaultKeepAliveInterval = 15 * time.Second
	DefaultKeepAliveTimeout  = 10 * time.Second
)

// StartKeepAlive 开启一个协程，定期向 SSH Server 发送心跳
// ctx: 用于控制协程退出的上下文
// client: 目标 SSH 客户端
// interval: 心跳间隔 (建议 15s - 60s)
// timeout: 单次心跳等待响应的超时时间 (建议 5s - 15s)，超时视为连接已断开
// fallback: 可选的回调函数，用于在心跳失败后执行,心跳失败时会关闭连接
// 返回的通道在心跳 goroutine 完全退出后关闭，调用方可据此等待资源回收。
// client.Close 必须能解除本地 I/O 阻塞；嵌套 ProxyJump 使用 Connector.EnableKeepAlive
// 或 Client.Wait，由连接所有者提供最外层传输的中断路径。
func StartKeepAlive(ctx context.Context, client *ssh.Client, interval, timeout time.Duration, fallback func(err error)) <-chan struct{} {
	return startKeepAlive(ctx, client, interval, timeout, fallback, func() error {
		return closeResource(client, "SSH client after keepalive")
	})
}

func startKeepAlive(ctx context.Context, client *ssh.Client, interval, timeout time.Duration, fallback func(error), interrupt func() error) <-chan struct{} {
	done := make(chan struct{})
	if interval <= 0 {
		interval = DefaultKeepAliveInterval
	}
	if timeout <= 0 {
		timeout = DefaultKeepAliveTimeout
	}

	go func() {
		defer close(done)
		// 创建一个定时器
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// 发送心跳请求
				if err := probeWithTimeoutAndInterrupt(ctx, client, timeout, interrupt); err != nil {
					if ctx.Err() != nil {
						return
					}
					// 心跳失败或超时，说明连接已经断了
					if fallback != nil {
						fallback(err)
					}
					return
				}
			}
		}
	}()
	return done
}

// probeWithTimeout 发送一次心跳请求并在 timeout 内等待响应。
// SendRequest 本身无法取消，因此探测失败、超时或 ctx 取消时都会关闭 Client，
// 既驱动所有使用者及时失败，也确保内部探测 goroutine 有确定的退出路径。
func probeWithTimeout(ctx context.Context, client *ssh.Client, timeout time.Duration) error {
	return probeWithTimeoutAndInterrupt(ctx, client, timeout, func() error {
		return closeResource(client, "SSH client after keepalive")
	})
}

// interrupt must release transport reads and writes without a peer response.
// Connector-owned ProxyJump clients provide the outermost transport's abort path.
func probeWithTimeoutAndInterrupt(ctx context.Context, client *ssh.Client, timeout time.Duration, interrupt func() error) error {
	if timeout <= 0 {
		timeout = DefaultKeepAliveTimeout
	}

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
	terminateProbe := func(probeErr error) error {
		closeErr := interrupt()
		// Abort the transport before joining the pending request.
		<-done
		if closeErr != nil {
			return fmt.Errorf("%w; close SSH client after keepalive failed: %w", probeErr, closeErr)
		}
		return probeErr
	}
	select {
	case r := <-done:
		if r.err == nil {
			return nil
		}
		// The request has already returned. A closed target can be replaced
		// over a healthy jump, so do not abort the shared root in this case.
		return errors.Join(fmt.Errorf("ssh keepalive request failed: %w", r.err), closeResource(client, "SSH client after keepalive"))
	case <-timer.C:
		return terminateProbe(fmt.Errorf("ssh keepalive: %w", errKeepaliveTimeout))
	case <-ctx.Done():
		return terminateProbe(fmt.Errorf("ssh keepalive canceled: %w", ctx.Err()))
	}
}
