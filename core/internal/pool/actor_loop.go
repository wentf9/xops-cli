package pool

import (
	"context"
	"errors"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/ports"
)

// runActor 在 workNursery 监督下驱动 DualActor 的单线程纯内存事件循环。
// 退出时自动触发残余资源收尾（防止外部父 ctx 取消而未立即调用 Close 时出现悬空句柄/连接）。
func (p *Pool) runActor(ctx context.Context) error {
	err := p.actor.Run(ctx)
	if !p.closed.Load() {
		p.closed.Store(true)
		p.haltCancel(ErrPoolClosed)
		p.revokeAllSlots(events.PoolActionRetired, ErrPoolClosed)
	}
	p.cleanupAfterActorExit()
	if err != nil && errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

// cleanupAfterActorExit 在 DualActor 完全退出（actorDone 关闭）后执行一次性的残余连接拆断。
// 此时零其他协程读写 active/dialing 映射，可安全无锁清理并归还在途多跳拨号的父代固定计数。
func (p *Pool) cleanupAfterActorExit() {
	p.finalCleanupOnce.Do(func() {
		cause := p.terminalStateError()
		for _, inf := range p.dialing {
			inf.dialCancel(cause)
			p.releaseInflightParentPin(inf)
			p.failInflightWaiters(inf, cause)
		}
		clear(p.dialing)
		p.dialingConns.Store(0)

		batch := make([]*hopInstance, 0, len(p.active))
		for _, inst := range p.active {
			p.deactivateInstance(inst, cause)
			batch = append(batch, inst)
		}
		clear(p.active)
		clear(p.byPlan)
		if len(batch) > 0 {
			sortLeavesFirst(batch)
			p.scheduleTeardownBatch(batch)
		}
		p.activeConns.Store(0)
	})
}

func (p *Pool) handleAcquireReq(req acquireMsg) {
	if p.halted.Load() || p.closed.Load() {
		_ = req.waiter.tryGrant(nil, p.terminalStateError())
		return
	}
	switch req.kind {
	case acqFastPlan:
		p.handleFastPlanAcquire(req)
	case acqHop:
		p.handleHopAcquire(req)
	default:
		_ = req.waiter.tryGrant(nil, ErrInvalidPlan)
	}
}

func (p *Pool) handleDrainAcquireReq(req acquireMsg) {
	_ = req.waiter.tryGrant(nil, p.terminalStateError())
}

func (p *Pool) handleFastPlanAcquire(req acquireMsg) {
	hopCount := req.connPlan.Len()
	leafDig, okD := req.connPlan.HopDigestAt(hopCount - 1)
	if !okD {
		_ = req.waiter.tryGrant(nil, ErrInvalidPlan)
		return
	}
	if inst, found := p.active[leafDig]; found {
		if dead := p.findDeadChainAncestor(inst, req.connPlan); dead != nil {
			p.retireSubtree(dead, ErrHopRetired, events.PoolActionEvicted, "cached hop or ancestor is dead")
		} else {
			p.recordPlanIndex(inst, algebraic.Some(req.connPlan.PlanDigest()))
			p.grantCachedInstance(req.waiter, inst, algebraic.Some(req.connPlan.PlanDigest()))
			return
		}
	}
	if hopCount == 1 {
		hop0, okH := req.connPlan.HopAt(0)
		if !okH {
			_ = req.waiter.tryGrant(nil, ErrInvalidPlan)
			return
		}
		req.hopSpec = hop0
		req.hopDigest = leafDig
		req.planDigest = algebraic.Some(req.connPlan.PlanDigest())
		p.handleHopAcquire(req)
		return
	}
	_ = req.waiter.tryGrant(nil, errFastPathMiss)
}

// findDeadChainAncestor 按 INV-C2 沿父代指针链校验缓存末跳及其全部祖先跳板仍处于活跃代且存活。
// 若发现任意已失活或世代不匹配的祖先节点，返回最顶层的失效节点以级联退役整个受损子树。
func (p *Pool) findDeadChainAncestor(leaf *hopInstance, connPlan plan.SealedConnectionPlan) *hopInstance {
	cur := leaf
	var topDead *hopInstance
	for i := connPlan.Len() - 1; i >= 0; i-- {
		wantDig, ok := connPlan.HopDigestAt(i)
		if !ok || cur == nil || !cur.digest.Equal(wantDig) {
			return leaf
		}
		if !p.isChainNodeAlive(cur, i) {
			topDead = cur
		}
		cur = cur.parent
	}
	return topDead
}

func (p *Pool) isChainNodeAlive(cur *hopInstance, hopIdx int) bool {
	if !cur.inActiveMap || p.active[cur.digest] != cur || !cur.active.Load() || !cur.conn.IsAlive() {
		return false
	}
	if hopIdx == 0 {
		return cur.parent == nil
	}
	return cur.parent != nil && cur.parentEpoch == cur.parent.epoch
}

func (p *Pool) handleHopAcquire(req acquireMsg) {
	if req.parent != nil && !p.isCurrentParent(req.parent, req.parentEpoch) {
		p.parentCASRejects.Add(1)
		_ = req.waiter.tryGrant(nil, ErrParentEpochChanged)
		return
	}
	if inst, ok := p.active[req.hopDigest]; ok {
		if p.isReusableInstance(inst, req.parent, req.parentEpoch) {
			p.recordPlanIndex(inst, req.planDigest)
			p.grantCachedInstance(req.waiter, inst, req.planDigest)
			return
		}
		p.retireSubtree(inst, ErrHopRetired, events.PoolActionEvicted, "stale or dead cached hop")
	}
	p.joinOrStartDial(req)
}

func (p *Pool) isCurrentParent(parent *hopInstance, expectEpoch uint64) bool {
	if parent == nil {
		return true
	}
	cur, ok := p.active[parent.digest]
	return ok && cur == parent && parent.epoch == expectEpoch && parent.active.Load() && parent.conn.IsAlive()
}

func (p *Pool) isReusableInstance(inst *hopInstance, parent *hopInstance, parentEpoch uint64) bool {
	if inst == nil || !inst.inActiveMap || !inst.active.Load() || !inst.conn.IsAlive() {
		return false
	}
	if parent == nil {
		return inst.parent == nil
	}
	return inst.parent == parent && inst.parentEpoch == parentEpoch
}

func (p *Pool) grantCachedInstance(w *acquireWaiter, inst *hopInstance, pdOpt algebraic.Option[plan.PlanDigest]) {
	if !w.tryGrant(inst, nil) {
		return
	}
	inst.activeLeases++
	inst.lastUsed = p.clock.Now()
	p.activeLeases.Add(1)
	p.cacheHits.Add(1)
	p.emitPoolEvent(poolEventInput{
		traceID: w.traceID, opID: w.opID, action: events.PoolActionLeaseAcquired,
		planDigest: pdOpt, hopDigest: algebraic.Some(inst.digest),
		endpoint: algebraic.Some(inst.hopSpec.Endpoint()), generation: inst.epoch, activeLeases: inst.activeLeases,
	})
}

func (p *Pool) joinOrStartDial(req acquireMsg) {
	if inf, exists := p.dialing[req.hopDigest]; exists {
		if inf.parent == req.parent && inf.parentEpoch == req.parentEpoch {
			if pd, ok := req.planDigest.Get(); ok && inf.planDigest.IsNone() {
				inf.planDigest = algebraic.Some(pd)
			}
			inf.waiters = append(inf.waiters, req.waiter)
			return
		}
		p.cancelInflight(inf, ErrParentEpochChanged)
	}
	if !p.ensureCapacityForNewDial() {
		_ = req.waiter.tryGrant(nil, ErrPoolCapacityExceeded)
		return
	}
	p.startNewDial(req)
}

func (p *Pool) ensureCapacityForNewDial() bool {
	if p.maxConns <= 0 {
		return true
	}
	for len(p.active)+len(p.dialing) >= p.maxConns {
		victim := p.pickLRUIdleLeaf()
		if victim == nil {
			return false
		}
		p.retireSubtree(victim, ErrHopRetired, events.PoolActionEvicted, "capacity lru eviction")
	}
	return true
}

func (p *Pool) pickLRUIdleLeaf() *hopInstance {
	var best *hopInstance
	for _, inst := range p.active {
		if inst.activeLeases > 0 || len(inst.children) > 0 {
			continue
		}
		if isOlderIdleCandidate(inst, best) {
			best = inst
		}
	}
	return best
}

func isOlderIdleCandidate(cand, best *hopInstance) bool {
	if best == nil {
		return true
	}
	if !cand.lastUsed.Equal(best.lastUsed) {
		return cand.lastUsed.Before(best.lastUsed)
	}
	return cand.digest.Compare(best.digest) < 0
}

func (p *Pool) startNewDial(req acquireMsg) {
	// 派生自 p.haltCtx（链式绑定 workNursery.Context），确保 GateHalted 触发瞬间即刻中断在途拨号。
	dialCtx, dialCancel := context.WithCancelCause(p.haltCtx)
	inf := &dialInflight{
		digest: req.hopDigest, hopSpec: req.hopSpec, planDigest: req.planDigest,
		parent: req.parent, parentEpoch: req.parentEpoch, startedAt: p.clock.Now(),
		dialCancel: dialCancel, waiters: []*acquireWaiter{req.waiter},
	}
	if req.parent != nil {
		// 在子跳拨号期间临时固定父跳板，避免父跳被空闲/LRU 驱逐。
		req.parent.activeLeases++
		p.activeLeases.Add(1)
	}
	p.dialing[req.hopDigest] = inf
	p.dialingConns.Store(int64(len(p.dialing)))
	p.totalDials.Add(1)

	p.emitPoolEvent(poolEventInput{
		traceID: req.waiter.traceID, opID: req.waiter.opID, action: events.PoolActionDialStarted,
		planDigest: req.planDigest, hopDigest: algebraic.Some(req.hopDigest),
		endpoint: algebraic.Some(req.hopSpec.Endpoint()),
	})

	var parentConn ports.TransportConn
	if req.parent != nil {
		parentConn = req.parent.conn
	}
	if err := p.workNursery.Go(func(_ context.Context) error {
		p.runDial(dialCtx, inf, parentConn)
		return nil
	}); err != nil {
		p.cancelInflight(inf, p.terminalStateError())
	}
}
