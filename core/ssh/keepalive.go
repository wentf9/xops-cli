package ssh

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

// errKeepaliveTimeout 等待心跳回复期间持续未收到远端数据
var errKeepaliveTimeout = errors.New("keepalive probe timed out")

// 心跳默认参数：接收空闲 15s 后探测；等待回复期间连续 10s 无接收进展才超时。
// 网络拥塞下的有效接收进展会推迟探测或刷新等待时间，网络黑洞仍有确定的退出路径。
const (
	DefaultKeepAliveInterval = 15 * time.Second
	DefaultKeepAliveTimeout  = 10 * time.Second
)

// StartKeepAlive 开启一个协程，定期向 SSH Server 发送心跳
// ctx: 用于控制协程退出的上下文
// client: 目标 SSH 客户端
// interval: 接收空闲探测间隔 (建议 15s - 60s)
// timeout: 等待心跳回复期间允许连续无接收进展的时间 (建议 5s - 15s)
// fallback: 可选的回调函数，用于在心跳失败后执行,心跳失败时会关闭连接
// 返回的通道在心跳 goroutine 完全退出后关闭，调用方可据此等待资源回收。
// client.Close 必须能解除本地 I/O 阻塞；嵌套 ProxyJump 使用 Connector.EnableKeepAlive
// 或 Client.Wait，由连接所有者提供最外层传输的中断路径。
// 接收进展由 Connector 创建的连接提供；外部构造的 client 保留固定探测超时。
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
		timer := time.NewTimer(interval)
		defer timer.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				if remaining := keepAliveReadTimeout(client, interval); remaining > 0 {
					timer.Reset(remaining)
					continue
				}
				// 发送心跳请求
				if err := probeWithTimeoutAndInterrupt(ctx, client, timeout, interrupt); err != nil {
					if ctx.Err() != nil {
						return
					}
					// 请求失败，或等待期间持续没有远端数据
					if fallback != nil {
						fallback(err)
					}
					return
				}
				timer.Reset(interval)
			}
		}
	}()
	return done
}

// probeWithTimeout 发送一次心跳请求，等待期间连续 timeout 无接收进展才超时。
// SendRequest 本身无法取消，因此探测失败、超时或 ctx 取消时都会关闭 Client，
// 既驱动所有使用者及时失败，也确保内部探测 goroutine 有确定的退出路径。
func probeWithTimeout(ctx context.Context, client *ssh.Client, timeout time.Duration) error {
	return probeWithTimeoutAndInterrupt(ctx, client, timeout, func() error {
		return closeResource(client, "SSH client after keepalive")
	})
}

// interrupt must release transport reads and writes without a peer response.
// Connector-owned ProxyJump clients provide the outermost transport's abort path.
// Keep exactly one request in flight while receive progress extends its timer;
// SendRequest cannot be canceled independently or safely retried after timeout.
// Synchronous acquisition must also supply a context deadline, since receive
// progress can extend this idle timeout for the lifetime of a busy connection.
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
	for {
		select {
		case r := <-done:
			if r.err == nil {
				return nil
			}
			// The request has already returned. A closed target can be replaced
			// over a healthy jump, so do not abort the shared root in this case.
			return errors.Join(fmt.Errorf("ssh keepalive request failed: %w", r.err), closeResource(client, "SSH client after keepalive"))
		case <-timer.C:
			if remaining := keepAliveReadTimeout(client, timeout); remaining > 0 {
				timer.Reset(remaining)
				continue
			}
			return terminateProbe(fmt.Errorf("ssh keepalive: %w", errKeepaliveTimeout))
		case <-ctx.Done():
			return terminateProbe(fmt.Errorf("ssh keepalive canceled: %w", ctx.Err()))
		}
	}
}
