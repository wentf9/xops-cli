package pool

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/ports"
)

func (p *Pool) handleControlMsg(msg controlMsg) {
	switch msg.kind {
	case ctrlReleaseLease:
		p.onReleaseLease(msg.inst, msg.doneCh)
	case ctrlDialDone:
		p.onDialDone(msg.inflight, msg.conn, msg.err)
	case ctrlCancelWaiter:
		p.onCancelWaiter(msg.hopDigest, msg.waiter)
	case ctrlRetireHop:
		p.onRetireHop(msg.hopDigest, msg.doneCh)
	case ctrlRetirePlan:
		p.onRetirePlan(msg.planDigest, msg.doneCh)
	case ctrlRetireInstance:
		p.onRetireInstance(msg.inst)
	case ctrlKeepaliveFailed:
		p.onKeepaliveFailed(msg.inst, msg.err)
	case ctrlEvictIdle:
		p.onEvictIdle(msg.cutoff, msg.forceIdle, msg.countCh)
	case ctrlAbortRoot:
		p.onAbortRoot(msg.inst, msg.doneCh)
	case ctrlGateHalted:
		p.onGateHalted(msg.err, msg.doneCh)
	case ctrlPinHandle:
		p.onPinHandle(msg)
	case ctrlUnpinHandle:
		p.onUnpinHandle(msg)
	}
}

func (p *Pool) onPinHandle(msg controlMsg) {
	if p.halted.Load() || p.closed.Load() {
		msg.pinErrCh <- p.terminalStateError()
		return
	}
	target, err := p.resolvePinTarget(msg)
	if err != nil {
		msg.pinErrCh <- err
		return
	}
	if target != nil {
		if !p.slots.bindSlotToHop(msg.handleID, msg.handleGen, target.digest, target.epoch) {
			msg.pinErrCh <- ErrHandleRevoked
			return
		}
		if target.pinnedHandles == nil {
			target.pinnedHandles = make(map[plan.HandleID]uint64)
		}
		target.pinnedHandles[msg.handleID] = msg.handleGen
	}
	msg.pinErrCh <- nil
}

func (p *Pool) resolvePinTarget(msg controlMsg) (*hopInstance, error) {
	if msg.pinStrict {
		cand := p.active[msg.hopDigest]
		if cand == nil || !cand.inActiveMap || cand.epoch != msg.hopEpoch || !cand.active.Load() {
			return nil, ErrLeaseRevoked
		}
		return cand, nil
	}
	if dig, ok := p.byPlan[msg.planDigest]; ok {
		if cand := p.active[dig]; cand != nil && cand.inActiveMap && cand.active.Load() {
			return cand, nil
		}
	}
	return nil, nil
}

func (p *Pool) onUnpinHandle(msg controlMsg) {
	inst := p.active[msg.hopDigest]
	if inst == nil || inst.epoch != msg.hopEpoch || inst.pinnedHandles[msg.handleID] != msg.handleGen {
		return
	}
	delete(inst.pinnedHandles, msg.handleID)
	inst.lastUsed = p.clock.Now()
}

func (p *Pool) onReleaseLease(inst *hopInstance, doneCh chan struct{}) {
	defer closeSignal(doneCh)
	if inst == nil || inst.activeLeases <= 0 {
		return
	}
	inst.activeLeases--
	inst.lastUsed = p.clock.Now()
	p.activeLeases.Add(-1)
	p.emitPoolEvent(poolEventInput{
		action: events.PoolActionLeaseReleased, hopDigest: algebraic.Some(inst.digest),
		endpoint: algebraic.Some(inst.hopSpec.Endpoint()), generation: inst.epoch, activeLeases: inst.activeLeases,
	})
}

func (p *Pool) onDialDone(inf *dialInflight, conn ports.TransportConn, dialErr error) {
	if inf == nil {
		p.scheduleOrphanConnClose(conn)
		return
	}
	// 若该单飞拨号已被取消或替换，直接回收刚拨出的连接，绝不泄漏或毒化池。
	if p.dialing[inf.digest] != inf {
		p.releaseInflightParentPin(inf)
		p.scheduleOrphanConnClose(conn)
		return
	}
	delete(p.dialing, inf.digest)
	p.dialingConns.Store(int64(len(p.dialing)))
	p.releaseInflightParentPin(inf)
	inf.dialCancel(nil)

	latency := p.clock.Since(inf.startedAt)
	if failErr := p.validateDialPublish(inf, conn, dialErr); failErr != nil {
		p.scheduleOrphanConnClose(conn)
		p.emitDialResultEvent(inf, events.PoolActionDialFailed, 0, latency, failErr.Error())
		p.failInflightWaiters(inf, failErr)
		return
	}
	p.publishDialedInstance(inf, conn, latency)
}

func (p *Pool) validateDialPublish(inf *dialInflight, conn ports.TransportConn, dialErr error) error {
	if p.halted.Load() || p.closed.Load() {
		return p.terminalStateError()
	}
	if dialErr != nil {
		p.dialErrors.Add(1)
		return dialErr
	}
	if conn == nil || !conn.HopDigest().Equal(inf.digest) || !conn.IsAlive() {
		p.dialErrors.Add(1)
		return ErrInvalidTransportConn
	}
	// INV-C2 核心护栏：多跳子连接发布前强制执行父代 Epoch CAS 校验，拒绝陈旧拨号毒化池。
	if inf.parent != nil && !p.isCurrentParent(inf.parent, inf.parentEpoch) {
		p.parentCASRejects.Add(1)
		return ErrParentEpochChanged
	}
	return nil
}

func (p *Pool) publishDialedInstance(inf *dialInflight, conn ports.TransportConn, latency time.Duration) {
	if old, exists := p.active[inf.digest]; exists {
		p.retireSubtree(old, ErrHopRetired, events.PoolActionRetired, "replaced by newer generation")
	}
	p.nextEpoch++
	revokeCtx, revokeCancel := context.WithCancelCause(p.haltCtx)
	inst := &hopInstance{
		digest: inf.digest, hopSpec: inf.hopSpec, epoch: p.nextEpoch,
		parent: inf.parent, parentEpoch: inf.parentEpoch, conn: conn,
		revokeCtx: revokeCtx, revokeCancel: revokeCancel,
		closeDone: make(chan struct{}), children: make(map[*hopInstance]struct{}),
		planDigests: make(map[plan.PlanDigest]struct{}), lastUsed: p.clock.Now(), inActiveMap: true,
	}
	inst.epochAtom.Store(p.nextEpoch)
	inst.active.Store(true)
	p.active[inf.digest] = inst
	p.activeConns.Store(int64(len(p.active)))
	if inf.parent != nil {
		inf.parent.children[inst] = struct{}{}
	}
	p.recordPlanIndex(inst, inf.planDigest)
	p.startKeepalive(inst)
	p.emitDialResultEvent(inf, events.PoolActionDialSucceeded, inst.epoch, latency, "")
	p.grantDialWaiters(inf, inst)
}

func (p *Pool) grantDialWaiters(inf *dialInflight, inst *hopInstance) {
	for _, w := range inf.waiters {
		if w.tryGrant(inst, nil) {
			inst.activeLeases++
			p.activeLeases.Add(1)
			p.emitPoolEvent(poolEventInput{
				traceID: w.traceID, opID: w.opID, action: events.PoolActionLeaseAcquired,
				planDigest: inf.planDigest, hopDigest: algebraic.Some(inst.digest),
				endpoint: algebraic.Some(inst.hopSpec.Endpoint()), generation: inst.epoch, activeLeases: inst.activeLeases,
			})
		}
	}
}

func (p *Pool) recordPlanIndex(inst *hopInstance, pdOpt algebraic.Option[plan.PlanDigest]) {
	if pd, ok := pdOpt.Get(); ok {
		inst.planDigests[pd] = struct{}{}
		p.byPlan[pd] = inst.digest
	}
}

func (p *Pool) onCancelWaiter(digest plan.HopDigest, target *acquireWaiter) {
	inf, ok := p.dialing[digest]
	if !ok || target == nil {
		return
	}
	inf.waiters = slices.DeleteFunc(inf.waiters, func(w *acquireWaiter) bool {
		return w == target
	})
	if len(inf.waiters) == 0 {
		p.cancelInflight(inf, context.Canceled)
	}
}

func (p *Pool) onRetireHop(digest plan.HopDigest, doneCh chan struct{}) {
	defer closeSignal(doneCh)
	if inst, ok := p.active[digest]; ok {
		p.retireSubtree(inst, ErrHopRetired, events.PoolActionRetired, "explicit retire hop")
	}
	if inf, ok := p.dialing[digest]; ok {
		p.cancelInflight(inf, ErrHopRetired)
	}
}

func (p *Pool) onRetirePlan(planDigest plan.PlanDigest, doneCh chan struct{}) {
	defer closeSignal(doneCh)
	if dig, ok := p.byPlan[planDigest]; ok {
		if inst, exists := p.active[dig]; exists {
			p.retireSubtree(inst, ErrHopRetired, events.PoolActionRetired, "explicit retire plan")
		}
		delete(p.byPlan, planDigest)
	}
	// 同步取消绑定到同一 planDigest 的在途单飞拨号，杜绝已退役计划的在途拨号延迟发布入池。
	var victims []*dialInflight
	for _, inf := range p.dialing {
		if pd, ok := inf.planDigest.Get(); ok && pd.Equal(planDigest) {
			victims = append(victims, inf)
		}
	}
	sortInflightByDigest(victims)
	for _, inf := range victims {
		p.cancelInflight(inf, ErrHopRetired)
	}
}

func (p *Pool) onRetireInstance(inst *hopInstance) {
	if inst != nil && inst.inActiveMap && p.active[inst.digest] == inst {
		p.retireSubtree(inst, ErrHopRetired, events.PoolActionRetired, "lease reported broken")
	}
}

func (p *Pool) onKeepaliveFailed(inst *hopInstance, err error) {
	if inst == nil || !inst.inActiveMap || p.active[inst.digest] != inst {
		return
	}
	detail := "keepalive failed"
	if err != nil {
		detail = err.Error()
	}
	p.retireSubtree(inst, ErrHopRetired, events.PoolActionEvicted, detail)
}

func (p *Pool) onEvictIdle(cutoff time.Time, forceAll bool, countCh chan int) {
	evicted := 0
	for {
		batch := p.collectIdleLeaves(cutoff, forceAll)
		if len(batch) == 0 {
			break
		}
		sortLeavesFirst(batch)
		for _, inst := range batch {
			p.retireSubtree(inst, ErrHopRetired, events.PoolActionEvicted, "idle eviction")
			evicted++
		}
	}
	if countCh != nil {
		countCh <- evicted
	}
}

func (p *Pool) collectIdleLeaves(cutoff time.Time, forceAll bool) []*hopInstance {
	var batch []*hopInstance
	for _, inst := range p.active {
		if inst.activeLeases == 0 && len(inst.pinnedHandles) == 0 && len(inst.children) == 0 && (forceAll || !inst.lastUsed.After(cutoff)) {
			batch = append(batch, inst)
		}
	}
	return batch
}

func (p *Pool) onAbortRoot(root *hopInstance, doneCh chan struct{}) {
	defer closeSignal(doneCh)
	if root == nil || !root.abortClaimed.CompareAndSwap(false, true) {
		return
	}
	batch := p.collectAndDetachSubtree(root, ErrTeardownEscalated, events.PoolActionEvicted, "90ms teardown escalation abort root")
	// INV-C3：立即优先关闭根跳板以解除卡死子跳阻塞，并跳过已处于 closing==true 的节点防 AB-BA 死锁。
	toClose := make([]*hopInstance, 0, len(batch))
	if !root.closing.Load() {
		p.deactivateInstance(root, ErrTeardownEscalated)
		toClose = append(toClose, root)
	}
	for _, inst := range batch {
		if inst != root && !inst.closing.Load() {
			toClose = append(toClose, inst)
		}
	}
	if len(toClose) > 0 {
		p.scheduleTeardownBatch(toClose)
	}
	p.activeConns.Store(int64(len(p.active)))
}

func (p *Pool) onGateHalted(cause error, doneCh chan struct{}) {
	defer closeSignal(doneCh)
	if cause == nil {
		cause = ErrGateHalted
	}
	for _, inf := range p.dialing {
		inf.dialCancel(cause)
		p.releaseInflightParentPin(inf)
		p.failInflightWaiters(inf, cause)
	}
	clear(p.dialing)
	p.dialingConns.Store(0)

	batch := make([]*hopInstance, 0, len(p.active))
	for _, inst := range p.active {
		pinned := inst.pinnedHandles
		inst.pinnedHandles = nil
		p.deactivateInstance(inst, cause)
		p.revokeSlotsForHop(pinned, cause)
		batch = append(batch, inst)
	}
	clear(p.active)
	clear(p.byPlan)

	p.emitPoolEvent(poolEventInput{action: events.PoolActionGateHalted, detail: cause.Error()})
	if len(batch) > 0 {
		sortLeavesFirst(batch)
		p.scheduleTeardownBatch(batch)
	}
	// 严格在 scheduleTeardownBatch 增加 tdPending 之后再对外归零 activeConns，
	// 保证观测到 ActiveConns==0 的调用方调用 WaitPendingTeardowns 绝无提前返回窗口。
	p.activeConns.Store(0)
}

func (p *Pool) retireSubtree(root *hopInstance, cause error, action events.PoolEventAction, detail string) {
	batch := p.collectAndDetachSubtree(root, cause, action, detail)
	if len(batch) > 0 {
		sortLeavesFirst(batch)
		p.scheduleTeardownBatch(batch)
	}
	p.activeConns.Store(int64(len(p.active)))
}

func (p *Pool) collectAndDetachSubtree(root *hopInstance, cause error, action events.PoolEventAction, detail string) []*hopInstance {
	if root == nil {
		return nil
	}
	queue := []*hopInstance{root}
	seen := map[*hopInstance]bool{root: true}
	var batch []*hopInstance
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for child := range cur.children {
			if !seen[child] {
				seen[child] = true
				queue = append(queue, child)
			}
		}
		p.detachInstance(cur, cause, action, detail)
		batch = append(batch, cur)
	}
	p.cancelInflightChildren(seen, cause)
	return batch
}

func (p *Pool) detachInstance(inst *hopInstance, cause error, action events.PoolEventAction, detail string) {
	if inst.inActiveMap && p.active[inst.digest] == inst {
		delete(p.active, inst.digest)
	}
	inst.inActiveMap = false
	for pd := range inst.planDigests {
		if p.byPlan[pd] == inst.digest {
			delete(p.byPlan, pd)
		}
	}
	clear(inst.planDigests)
	if inst.parent != nil {
		delete(inst.parent.children, inst)
	}
	clear(inst.children)
	pinned := inst.pinnedHandles
	inst.pinnedHandles = nil
	p.deactivateInstance(inst, cause)
	p.revokeSlotsForHop(pinned, cause)
	p.emitPoolEvent(poolEventInput{
		action: action, hopDigest: algebraic.Some(inst.digest),
		endpoint:   algebraic.Some(inst.hopSpec.Endpoint()),
		generation: inst.epoch, activeLeases: inst.activeLeases, detail: detail,
	})
}

func (p *Pool) deactivateInstance(inst *hopInstance, cause error) {
	inst.active.Store(false)
	inst.epochAtom.Store(0)
	inst.revokeCancel(cause)
}

func (p *Pool) cancelInflightChildren(detached map[*hopInstance]bool, cause error) {
	var victims []*dialInflight
	for _, inf := range p.dialing {
		if inf.parent != nil && detached[inf.parent] {
			victims = append(victims, inf)
		}
	}
	sortInflightByDigest(victims)
	childErr := pickIf(errors.Is(cause, ErrGateHalted), cause, ErrParentEpochChanged)
	for _, inf := range victims {
		if errors.Is(childErr, ErrParentEpochChanged) {
			p.parentCASRejects.Add(1)
		}
		p.cancelInflight(inf, childErr)
	}
}

func sortInflightByDigest(victims []*dialInflight) {
	slices.SortFunc(victims, func(a, b *dialInflight) int { return a.digest.Compare(b.digest) })
}

func (p *Pool) cancelInflight(inf *dialInflight, err error) {
	if p.dialing[inf.digest] == inf {
		delete(p.dialing, inf.digest)
		p.dialingConns.Store(int64(len(p.dialing)))
	}
	p.releaseInflightParentPin(inf)
	inf.dialCancel(err)
	p.failInflightWaiters(inf, err)
}

func (p *Pool) releaseInflightParentPin(inf *dialInflight) {
	if inf == nil || inf.parent == nil || inf.parentPinReleased {
		return
	}
	inf.parentPinReleased = true
	if inf.parent.activeLeases > 0 {
		inf.parent.activeLeases--
		p.activeLeases.Add(-1)
	}
}

func (p *Pool) failInflightWaiters(inf *dialInflight, err error) {
	for _, w := range inf.waiters {
		_ = w.tryGrant(nil, err)
	}
	inf.waiters = nil
}

func (p *Pool) emitDialResultEvent(inf *dialInflight, action events.PoolEventAction, epoch uint64, lat time.Duration, detail string) {
	var tid security.TraceID
	var oid algebraic.Option[security.OperationID]
	if len(inf.waiters) > 0 {
		tid, oid = inf.waiters[0].traceID, inf.waiters[0].opID
	}
	p.emitPoolEvent(poolEventInput{
		traceID: tid, opID: oid, action: action, planDigest: inf.planDigest,
		hopDigest: algebraic.Some(inf.digest), endpoint: algebraic.Some(inf.hopSpec.Endpoint()),
		generation: epoch, latency: lat, detail: detail,
	})
}

func sortLeavesFirst(batch []*hopInstance) {
	slices.SortFunc(batch, func(a, b *hopInstance) int {
		if a.hopSpec.HopIndex() != b.hopSpec.HopIndex() {
			if a.hopSpec.HopIndex() > b.hopSpec.HopIndex() {
				return -1
			}
			return 1
		}
		return a.digest.Compare(b.digest)
	})
}

func closeSignal(ch chan struct{}) {
	if ch != nil {
		close(ch)
	}
}
