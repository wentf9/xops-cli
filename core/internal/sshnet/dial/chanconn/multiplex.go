package chanconn

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/ports"
)

// RunWithAbortWatchdog 在 core/conc.RunScoped 监督下执行阻塞操作 op：
// 一旦 ctx 取消或超时且 op 尚未完成，看门狗协程立即调用 onAbort（通常关闭底层连接或 ssh.Channel）
// 解除阻塞；op 正常完成时先原子置位 completed 再关闭 doneCh，杜绝 select 随机竞态误伤健康连接。
//
//xops:syncclosure
func RunWithAbortWatchdog(ctx context.Context, onAbort func(), op func() error) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if op == nil {
		return ports.ErrNilCallback
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var completed atomic.Bool
	doneCh := make(chan struct{})
	var opErr error
	scopeErr := conc.RunScoped(ctx, func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(wCtx context.Context) error {
			select {
			case <-doneCh:
				return nil
			case <-wCtx.Done():
				if !completed.Load() && onAbort != nil {
					onAbort()
				}
				return nil
			}
		}); gErr != nil {
			return gErr
		}
		opErr = op()
		completed.Store(true)
		close(doneCh)
		return nil
	})
	if opErr != nil {
		return opErr
	}
	return scopeErr
}

// RunMultiplexedOp 在连接生命周期 Nursery 监督下执行单次多路复用控制操作：
// 单一调用方取消 ctx 时绝不关闭共享父连接（避免误杀同连接上其他活跃会话或子跳），
// 并在互斥锁线性化下保证迟到完成的孤立资源恰好被 cleanup 释放一次且随父连接关闭零泄漏收敛。
func RunMultiplexedOp[T any](
	ctx context.Context,
	lifeNursery *conc.Nursery,
	op func() (T, error),
	cleanup func(T),
) (T, error) {
	var zero T
	if ctx == nil {
		return zero, ports.ErrNilContext
	}
	if op == nil {
		return zero, ports.ErrNilCallback
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if lifeNursery == nil {
		return zero, ports.ErrClosed
	}
	type result struct {
		val T
		err error
	}
	var mu sync.Mutex
	abandoned := false
	resCh := make(chan result, 1)
	if err := lifeNursery.Go(func(context.Context) error {
		v, err := op()
		mu.Lock()
		if abandoned {
			mu.Unlock()
			runCleanupIfOK(err, v, cleanup)
			return nil
		}
		resCh <- result{val: v, err: err}
		mu.Unlock()
		return nil
	}); err != nil {
		return zero, ports.ErrClosed
	}
	select {
	case res := <-resCh:
		if ctxErr := ctx.Err(); ctxErr != nil {
			runCleanupIfOK(res.err, res.val, cleanup)
			return zero, ctxErr
		}
		return res.val, res.err
	case <-ctx.Done():
		mu.Lock()
		abandoned = true
		var late *result
		select {
		case r := <-resCh:
			late = &r
		default:
		}
		mu.Unlock()
		if late != nil {
			runCleanupIfOK(late.err, late.val, cleanup)
		}
		return zero, ctx.Err()
	}
}

func runCleanupIfOK[T any](err error, val T, cleanup func(T)) {
	if err == nil && cleanup != nil {
		cleanup(val)
	}
}

// WaitBounded 在最多 grace 时长内等待 done 关闭，避免半开黑洞对端在关闭路径造成永久阻塞。
func WaitBounded(done <-chan struct{}, grace time.Duration) {
	select {
	case <-done:
		return
	default:
	}
	tm := time.NewTimer(grace)
	defer tm.Stop()
	select {
	case <-done:
	case <-tm.C:
	}
}
