package ssh

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// errKeepaliveTimeout 等待心跳回复期间持续未收到远端数据
var errKeepaliveTimeout = errors.New("keepalive probe timed out")

// errKeepaliveStopped reports a non-disruptive keepalive detach (e.g. pool
// displacement, retire, or StopGlobalKeepAlives) while abortCtx remains active.
var errKeepaliveStopped = errors.New("keepalive stopped non-disruptively")

// keepAliveCloseGrace caps how long runBoundedClose waits for a hop-scoped
// close on a jump child before escalating to fallbackInterrupt (or returning
// under probeWG tracking for background keepalives).
var keepAliveCloseGrace = 50 * time.Millisecond

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
	if ctx == nil || client == nil || client.Conn == nil {
		done := make(chan struct{})
		close(done)
		return done
	}
	return startKeepAlive(ctx, client, interval, timeout, fallback, func() error {
		return closeResource(client, "SSH client after keepalive")
	})
}

func startKeepAlive(ctx context.Context, client *ssh.Client, interval, timeout time.Duration, fallback func(error), interrupt func() error) <-chan struct{} {
	return startKeepAliveWithContexts(ctx, ctx, client, interval, timeout, fallback, interrupt, nil, false, nil)
}

// startKeepAliveWithContexts separates stopCtx (non-disruptive detach such as
// pool displacement, Retire, or StopGlobalKeepAlives) from abortCtx (hard
// lifecycle shutdown such as Connector.CloseAll or public StartKeepAlive cancel).
// When stopCtx cancels while abortCtx is still active, an in-flight probe exits
// cleanly without calling interrupt or fallback, leaving the live transport
// intact. When wg is non-nil, the caller has already added 1 for this keepalive
// loop; startKeepAliveWithContexts releases that count on exit and tracks any
// in-flight SendRequest (and async hop-scoped interrupt) goroutines on wg so
// CloseAll joins them after closing pooled transports.
func canStartKeepAlive(stopCtx, abortCtx context.Context, client *ssh.Client) bool {
	return client != nil && client.Conn != nil && (stopCtx != nil || abortCtx != nil)
}

func startKeepAliveWithContexts(
	stopCtx context.Context,
	abortCtx context.Context,
	client *ssh.Client,
	interval, timeout time.Duration,
	fallback func(error),
	interrupt func() error,
	beforeClose func() func(),
	hopScopedClose bool,
	wg *sync.WaitGroup,
) <-chan struct{} {
	done := make(chan struct{})
	if !canStartKeepAlive(stopCtx, abortCtx, client) {
		if wg != nil {
			wg.Done()
		}
		close(done)
		return done
	}
	if interval <= 0 {
		interval = DefaultKeepAliveInterval
	}
	if timeout <= 0 {
		timeout = DefaultKeepAliveTimeout
	}

	go func() {
		defer close(done)
		if wg != nil {
			defer wg.Done()
		}
		runKeepAliveLoop(stopCtx, abortCtx, client, interval, timeout, fallback, interrupt, beforeClose, hopScopedClose, wg)
	}()
	return done
}

func runKeepAliveLoop(
	stopCtx context.Context,
	abortCtx context.Context,
	client *ssh.Client,
	interval, timeout time.Duration,
	fallback func(error),
	interrupt func() error,
	beforeClose func() func(),
	hopScopedClose bool,
	wg *sync.WaitGroup,
) {
	stopDone := ctxDoneCh(stopCtx)
	abortDone := ctxDoneCh(abortCtx)
	timer := time.NewTimer(interval)
	defer timer.Stop()

	for {
		select {
		case <-abortDone:
			return
		case <-stopDone:
			return
		case <-timer.C:
			if isCtxCanceled(abortCtx) || isCtxCanceled(stopCtx) {
				return
			}
			if remaining := keepAliveReadTimeout(client, interval); remaining > 0 {
				timer.Reset(remaining)
				continue
			}
			// 发送心跳请求
			if err := probeWithContexts(stopCtx, abortCtx, client, timeout, interrupt, nil, beforeClose, hopScopedClose, wg); err != nil {
				if errors.Is(err, errKeepaliveStopped) || isCtxCanceled(abortCtx) {
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
	return probeWithContexts(ctx, ctx, client, timeout, interrupt, nil, nil, false, nil)
}

func ctxDoneCh(ctx context.Context) <-chan struct{} {
	if ctx == nil {
		return nil
	}
	return ctx.Done()
}

func isCtxCanceled(ctx context.Context) bool {
	return ctx != nil && ctx.Err() != nil
}

func isNonDisruptiveKeepAliveStop(stopCtx, abortCtx context.Context) bool {
	return stopCtx != abortCtx && isCtxCanceled(stopCtx) && !isCtxCanceled(abortCtx)
}

type keepAliveProbeResult struct{ err error }

func launchKeepAliveProbe(client *ssh.Client, probeWG *sync.WaitGroup) <-chan keepAliveProbeResult {
	done := make(chan keepAliveProbeResult, 1)
	if probeWG != nil {
		probeWG.Add(1)
	}
	go func() {
		if probeWG != nil {
			defer probeWG.Done()
		}
		// payload = nil: 不需要携带额外数据
		// "keepalive@openssh.com" 是 OpenSSH 标准的心跳请求类型
		// wantReply = true: 要求服务器回复。如果服务器挂了或网络断了，探测会报错或超时
		_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
		done <- keepAliveProbeResult{err: err}
	}()
	return done
}

func launchAsyncKeepAliveClose(
	closeFn func() error,
	afterClose func(),
	probeWG *sync.WaitGroup,
) <-chan error {
	closeDone := make(chan error, 1)
	if probeWG != nil {
		probeWG.Add(1)
	}
	go func() {
		if probeWG != nil {
			defer probeWG.Done()
		}
		err := closeFn()
		if afterClose != nil {
			afterClose()
		}
		closeDone <- err
	}()
	return closeDone
}

func escalateBoundedClose(
	fallbackInterrupt func() error,
	probeDone bool,
	waitDone <-chan keepAliveProbeResult,
	closed bool,
	waitClose <-chan error,
) error {
	if fallbackInterrupt == nil {
		return nil
	}
	closeErr := fallbackInterrupt()
	if !probeDone {
		<-waitDone
	}
	if !closed {
		closeErr = errors.Join(closeErr, <-waitClose)
	}
	return closeErr
}

// runBoundedClose runs closeFn (followed by afterClose) either synchronously
// (when neither boundedJoin nor fallbackInterrupt is requested, e.g. root hops
// whose RootConn.Close never blocks on an upstream bastion) or asynchronously
// behind a bounded grace timer. Running closeFn asynchronously prevents a
// write-wedged upstream bastion (full TCP SO_SNDBUF or stalled KEX) from
// blocking graceTimer before fallbackInterrupt can close the shared RootConn
// and unblock both closeFn and any in-flight SendRequest.
func runBoundedClose(
	timeout time.Duration,
	closeFn func() error,
	afterClose func(),
	fallbackInterrupt func() error,
	done <-chan keepAliveProbeResult,
	abortDone <-chan struct{},
	boundedJoin bool,
	probeWG *sync.WaitGroup,
) error {
	if !boundedJoin && fallbackInterrupt == nil {
		closeErr := closeFn()
		if afterClose != nil {
			afterClose()
		}
		if done != nil {
			<-done
		}
		return closeErr
	}

	waitClose := launchAsyncKeepAliveClose(closeFn, afterClose, probeWG)

	// A hop-scoped close on a child over a healthy bastion replies with
	// SSH_MSG_CHANNEL_CLOSE promptly; if the bastion itself is blackholed or
	// write-wedged, either return under probeWG tracking (background keepalive)
	// or escalate to fallbackInterrupt (synchronous probe) and join both
	// goroutines once RootConn closes.
	maxGrace := keepAliveCloseGrace
	if maxGrace <= 0 {
		maxGrace = 50 * time.Millisecond
	}
	grace := min(timeout, maxGrace)
	if grace <= 0 {
		grace = maxGrace
	}
	graceTimer := time.NewTimer(grace)
	defer graceTimer.Stop()

	probeDone := done == nil
	waitDone := done
	closed := false
	var closeErr error
	for !probeDone || !closed {
		// When abortDone is already closed (e.g. probeCachedClient's probeCtx
		// deadline expired), escalate deterministically rather than racing
		// select against an already-closed abortDone channel.
		select {
		case <-abortDone:
			return errors.Join(closeErr, escalateBoundedClose(fallbackInterrupt, probeDone, waitDone, closed, waitClose))
		default:
		}
		select {
		case <-waitDone:
			probeDone = true
			waitDone = nil
		case err := <-waitClose:
			closeErr = errors.Join(closeErr, err)
			closed = true
			waitClose = nil
		case <-abortDone:
			return errors.Join(closeErr, escalateBoundedClose(fallbackInterrupt, probeDone, waitDone, closed, waitClose))
		case <-graceTimer.C:
			return errors.Join(closeErr, escalateBoundedClose(fallbackInterrupt, probeDone, waitDone, closed, waitClose))
		}
	}
	return closeErr
}

func terminateKeepAliveProbe(
	probeErr error,
	timeout time.Duration,
	interrupt func() error,
	fallbackInterrupt func() error,
	beforeClose func() func(),
	done <-chan keepAliveProbeResult,
	abortDone <-chan struct{},
	boundedJoin bool,
	probeWG *sync.WaitGroup,
) error {
	var afterClose func()
	if beforeClose != nil {
		afterClose = beforeClose()
	}
	closeErr := runBoundedClose(timeout, interrupt, afterClose, fallbackInterrupt, done, abortDone, boundedJoin, probeWG)
	if closeErr != nil {
		return fmt.Errorf("%w; close SSH client after keepalive failed: %w", probeErr, closeErr)
	}
	return probeErr
}

func probeWithContexts(
	stopCtx context.Context,
	abortCtx context.Context,
	client *ssh.Client,
	timeout time.Duration,
	interrupt func() error,
	fallbackInterrupt func() error,
	beforeClose func() func(),
	hopScopedClose bool,
	probeWG *sync.WaitGroup,
) error {
	if client == nil || client.Conn == nil {
		return errors.New("ssh client is not connected")
	}
	if timeout <= 0 {
		timeout = DefaultKeepAliveTimeout
	}
	if isCtxCanceled(abortCtx) {
		return fmt.Errorf("ssh keepalive canceled: %w", abortCtx.Err())
	}
	if isCtxCanceled(stopCtx) {
		return errKeepaliveStopped
	}

	done := launchKeepAliveProbe(client, probeWG)
	stopDone := ctxDoneCh(stopCtx)
	abortDone := ctxDoneCh(abortCtx)
	nonDisruptiveStop := stopCtx != abortCtx
	boundedJoin := hopScopedClose && nonDisruptiveStop && probeWG != nil

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case res := <-done:
			if res.err == nil {
				return nil
			}
			if isNonDisruptiveKeepAliveStop(stopCtx, abortCtx) {
				return errKeepaliveStopped
			}
			var afterClose func()
			if beforeClose != nil {
				afterClose = beforeClose()
			}
			// The request has already returned. A closed target can be replaced
			// over a healthy jump, so close only the client transport unless a
			// wedged upstream bastion blocks close and forces fallbackInterrupt.
			closeErr := runBoundedClose(
				timeout,
				func() error { return closeResource(client, "SSH client after keepalive") },
				afterClose,
				fallbackInterrupt,
				nil,
				abortDone,
				boundedJoin,
				probeWG,
			)
			return errors.Join(fmt.Errorf("ssh keepalive request failed: %w", res.err), closeErr)
		case <-timer.C:
			if isNonDisruptiveKeepAliveStop(stopCtx, abortCtx) {
				return errKeepaliveStopped
			}
			if remaining := keepAliveReadTimeout(client, timeout); remaining > 0 {
				timer.Reset(remaining)
				continue
			}
			return terminateKeepAliveProbe(
				fmt.Errorf("ssh keepalive: %w", errKeepaliveTimeout),
				timeout, interrupt, fallbackInterrupt, beforeClose, done, abortDone, boundedJoin, probeWG,
			)
		case <-abortDone:
			return terminateKeepAliveProbe(
				fmt.Errorf("ssh keepalive canceled: %w", abortCtx.Err()),
				timeout, interrupt, fallbackInterrupt, beforeClose, done, abortDone, false, probeWG,
			)
		case <-stopDone:
			if isCtxCanceled(abortCtx) {
				return terminateKeepAliveProbe(
					fmt.Errorf("ssh keepalive canceled: %w", abortCtx.Err()),
					timeout, interrupt, fallbackInterrupt, beforeClose, done, abortDone, false, probeWG,
				)
			}
			if nonDisruptiveStop {
				return errKeepaliveStopped
			}
			return terminateKeepAliveProbe(
				fmt.Errorf("ssh keepalive canceled: %w", stopCtx.Err()),
				timeout, interrupt, fallbackInterrupt, beforeClose, done, abortDone, false, probeWG,
			)
		}
	}
}
