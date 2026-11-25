package pool

import (
	"context"
	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/ports"
	"time"
)

// runDial 在 Actor 循环外部的 workNursery 中执行单跳拨号（零 I/O 阻塞 Actor），
// 并在拨号完成后将结果通过永不阻塞的 SendControl 回传；若 Actor 已停机则立即托管拆断孤儿连接。
func (p *Pool) runDial(dialCtx context.Context, inf *dialInflight, parentConn ports.TransportConn) {
	conn, err := p.dialer.DialHop(dialCtx, inf.hopSpec, inf.digest, parentConn)
	if !p.actor.SendControl(controlMsg{
		kind:     ctrlDialDone,
		inflight: inf,
		conn:     conn,
		err:      err,
	}) {
		p.scheduleOrphanConnClose(conn)
	}
}

// startKeepalive 为刚发布的单跳连接实例启动其独占的保活协程（INV-C2）。
// 直接绑定并发安全的 inst.revokeCtx（零可变取消字段），实例在任何路径被停用、熔断或关闭时即刻退出；
// 连续失败上限严格尊重 HopSpec.Transport().ServerAliveCountMax()（显式配置 0 按 1 次失败即退役处理）。
func (p *Pool) startKeepalive(inst *hopInstance) {
	interval := inst.hopSpec.Transport().ServerAliveInterval().Std()
	if interval <= 0 {
		interval = p.defaultKeepaliveInterval
	}
	if interval <= 0 {
		return
	}
	maxMisses := max(inst.hopSpec.Transport().ServerAliveCountMax(), 1)
	_ = p.workNursery.Go(func(_ context.Context) error {
		p.runKeepalive(inst.revokeCtx, inst, interval, maxMisses)
		return nil
	})
}
func (p *Pool) runKeepalive(ctx context.Context, inst *hopInstance, interval time.Duration, maxMisses uint32) {
	tm := p.clock.NewTimer(interval)
	defer tm.Stop()
	var misses uint32
	for {
		select {
		case <-ctx.Done():
			return
		case <-tm.C():
		}
		if !inst.active.Load() || ctx.Err() != nil {
			return
		}
		err := p.sendBoundedKeepalive(ctx, inst, interval)
		if err == nil {
			misses = 0
			tm.Reset(interval)
			continue
		}
		if ctx.Err() != nil {
			return
		}
		misses++
		if misses >= maxMisses {
			p.actor.SendControl(controlMsg{
				kind: ctrlKeepaliveFailed,
				inst: inst,
				err:  err,
			})
			return
		}
		tm.Reset(interval)
	}
}

// sendBoundedKeepalive 使用注入的 ports.Clock 在 conc.RunScoped 看门狗内为单次 SendKeepalive 施加有界超时，
// 防止黑洞 TCP 连接阻塞保活协程长达 OS 重传周期，并保证在虚拟 SimClock 下 100% 确定性触发超时计数。
func (p *Pool) sendBoundedKeepalive(ctx context.Context, inst *hopInstance, timeout time.Duration) error {
	probeCtx, cancelProbe := context.WithCancelCause(ctx)
	defer cancelProbe(nil)
	var probeErr error
	runErr := conc.RunScoped(probeCtx, func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(wCtx context.Context) error {
			ptm := p.clock.NewTimer(timeout)
			defer ptm.Stop()
			select {
			case <-wCtx.Done():
				return nil
			case <-ptm.C():
				cancelProbe(context.DeadlineExceeded)
				return nil
			}
		}); gErr != nil {
			return gErr
		}
		probeErr = inst.conn.SendKeepalive(probeCtx)
		return nil
	})
	if probeErr != nil {
		return probeErr
	}
	if runErr != nil {
		return runErr
	}
	return probeCtx.Err()
}

// runIdleSweeper 在配置了 IdleTTL > 0 时基于注入的 ports.Clock 定期触发空闲叶子连接清理。
func (p *Pool) runIdleSweeper(ctx context.Context) error {
	step := max(p.idleTTL/2, time.Millisecond)
	tm := p.clock.NewTimer(step)
	defer tm.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tm.C():
			p.actor.SendControl(controlMsg{
				kind:   ctrlEvictIdle,
				cutoff: p.clock.Now().Add(-p.idleTTL),
			})
			tm.Reset(step)
		}
	}
}
func (p *Pool) incTeardownPending() {
	p.tdMu.Lock()
	if p.tdPending == 0 {
		p.tdIdleCh = make(chan struct{})
	}
	p.tdPending++
	p.tdMu.Unlock()
}
func (p *Pool) decTeardownPending() {
	p.tdMu.Lock()
	p.tdPending--
	if p.tdPending == 0 {
		close(p.tdIdleCh)
	}
	p.tdMu.Unlock()
}

// scheduleTeardownBatch 在独立的 teardownNursery 中按叶子优先顺序异步执行 90ms 有界拆断（INV-C3）。
func (p *Pool) scheduleTeardownBatch(batch []*hopInstance) {
	if len(batch) == 0 {
		return
	}
	p.incTeardownPending()
	if err := p.teardownNursery.Go(func(_ context.Context) error {
		defer p.decTeardownPending()
		p.executeTeardownBatch(batch)
		return nil
	}); err != nil {
		p.decTeardownPending()
		for _, inst := range batch {
			p.closeInstanceDirect(inst)
		}
	}
}
func (p *Pool) executeTeardownBatch(batch []*hopInstance) {
	for _, inst := range batch {
		p.teardownSingleInstance(inst)
	}
}

// teardownSingleInstance 对单个连接实例执行 90ms 有界拆断：
//   - 若连接在宽限期内优雅关闭，则直接完成且绝不触碰健康的父跳板；
//   - 若超过 teardownGrace（默认 90ms，由注入 ports.Clock 驱动）仍未返回，则升级拆断根跳板（INV-C3）。
func (p *Pool) teardownSingleInstance(inst *hopInstance) {
	if inst == nil || inst.conn == nil {
		return
	}
	alreadyClosing := inst.closing.Swap(true)
	if !alreadyClosing {
		p.launchInstanceCloseWorker(inst)
	}
	tm := p.clock.NewTimer(p.teardownGrace)
	defer tm.Stop()
	select {
	case <-inst.closeDone:
		if !alreadyClosing {
			p.teardownCompleted.Add(1)
		}
	case <-tm.C():
		if !alreadyClosing {
			p.teardownEscalated.Add(1)
			p.escalateStuckTeardown(inst)
		}
	}
}
func (p *Pool) launchInstanceCloseWorker(inst *hopInstance) {
	if err := p.teardownNursery.Go(func(_ context.Context) error {
		p.closeInstanceDirect(inst)
		return nil
	}); err != nil {
		p.closeInstanceDirect(inst)
	}
}
func (p *Pool) closeInstanceDirect(inst *hopInstance) {
	if inst == nil || inst.conn == nil {
		return
	}
	inst.closeOnce.Do(func() {
		defer close(inst.closeDone)
		_ = inst.conn.Close()
	})
}

// escalateStuckTeardown 实现 INV-C3 升级拆断：
//   - 若存在上游父跳板，定位根跳板并经控制通道触发单赢者 detachAndAbortRoot（跳过已 closing 节点防 AB-BA 死锁）；
//   - 若 Actor 已停机，直接以单赢者 CAS 认领根跳板并启动其关闭协程；
//   - 若本节点本身已是根跳板，则记录诊断事件并在宽限预算点立即结束等待，绝不无限阻塞调用方。
func (p *Pool) escalateStuckTeardown(inst *hopInstance) {
	root := inst.rootAncestor()
	if root == nil || root == inst {
		p.emitDiagnostic(events.SeverityWarn, "teardown_grace_exceeded", "root transport close exceeded 90ms teardown grace")
		return
	}
	doneCh := make(chan struct{})
	if p.actor.SendControl(controlMsg{
		kind:   ctrlAbortRoot,
		inst:   root,
		doneCh: doneCh,
	}) {
		select {
		case <-doneCh:
		case <-p.actor.Done():
			p.fallbackAbortRootDirect(root)
		}
		return
	}
	p.fallbackAbortRootDirect(root)
}
func (p *Pool) fallbackAbortRootDirect(root *hopInstance) {
	if root == nil || !root.abortClaimed.CompareAndSwap(false, true) {
		return
	}
	p.deactivateInstance(root, ErrTeardownEscalated)
	if !root.closing.Swap(true) {
		p.launchInstanceCloseWorker(root)
	}
}

// scheduleOrphanConnClose / scheduleResourceClose 在独立 teardownNursery 中以 90ms 有界宽限释放孤儿连接或托管资源。
func (p *Pool) scheduleOrphanConnClose(conn ports.TransportConn) { p.scheduleCloserBounded(conn) }
func (p *Pool) scheduleResourceClose(res ManagedResource)        { p.scheduleCloserBounded(res) }
func (p *Pool) scheduleCloserBounded(c closeOnly) {
	if c == nil {
		return
	}
	p.incTeardownPending()
	if err := p.teardownNursery.Go(func(_ context.Context) error {
		defer p.decTeardownPending()
		p.closeCloserBounded(c)
		return nil
	}); err != nil {
		p.decTeardownPending()
		_ = c.Close()
	}
}

type closeOnly interface {
	Close() error
}

func (p *Pool) closeCloserBounded(c closeOnly) {
	done := make(chan struct{})
	if err := p.teardownNursery.Go(func(_ context.Context) error {
		defer close(done)
		_ = c.Close()
		return nil
	}); err != nil {
		_ = c.Close()
		p.teardownCompleted.Add(1)
		return
	}
	tm := p.clock.NewTimer(p.teardownGrace)
	defer tm.Stop()
	select {
	case <-done:
		p.teardownCompleted.Add(1)
	case <-tm.C():
		p.teardownEscalated.Add(1)
		p.emitDiagnostic(events.SeverityWarn, "resource_teardown_grace_exceeded", "managed resource close exceeded 90ms teardown grace")
	}
}
