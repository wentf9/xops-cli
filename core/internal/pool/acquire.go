package pool

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/internal/foundation/actor"
	"github.com/wentf9/xops-cli/core/internal/foundation/trace"
)

// WithLease 按不可变 Merkle 连接计划申请单条同步借用连接租约，在即将进入用户回调 fn 前注入
// 全局单层不可重入 trace.LeaseScope（绝不在池内多跳 DAG 拨号前注入，防止内部多跳误触 ErrReentrantLease）。
// 回调返回（含错误与 panic）时无条件使借用哨兵失效，并通过监听 actorDone 的控制通道归还租约。
//
//xops:syncclosure
//xops:borrowed
func (p *Pool) WithLease(
	ctx context.Context,
	connPlan plan.SealedConnectionPlan,
	fn func(ctx context.Context, lease *Lease) error,
) error {
	if err := p.checkAcquirePreconditions(ctx, fn != nil); err != nil {
		return err
	}
	if !connPlan.IsValid() {
		return ErrInvalidPlan
	}
	inst, err := p.acquirePlan(ctx, connPlan)
	if err != nil {
		return err
	}
	return p.invokeSingleLease(ctx, connPlan, inst, fn)
}

func (p *Pool) invokeSingleLease(
	ctx context.Context,
	connPlan plan.SealedConnectionPlan,
	inst *hopInstance,
	fn func(ctx context.Context, lease *Lease) error,
) error {
	leaseID := p.nextLeaseID()
	scope, err := trace.NewLeaseScope(p.domain, leaseID)
	if err != nil {
		p.releaseHopLease(inst)
		return err
	}
	leaseCtx, cleanupCtx := deriveRevocableContext(ctx, inst.revokeCtx)
	scopedCtx, err := trace.WithLeaseScope(leaseCtx, scope)
	if err != nil {
		cleanupCtx()
		p.releaseHopLease(inst)
		return err
	}
	lease := newLease(p, inst, connPlan.PlanDigest(), leaseID)
	defer func() {
		lease.invalidate()
		cleanupCtx()
		p.releaseHopLease(inst)
	}()
	if err := p.checkPreCallbackAlive(inst); err != nil {
		return err
	}
	return fn(scopedCtx, lease)
}

// WithMultiLease 按规范拓扑深度优先 + PlanDigest 全序一次性申请多个连接计划的同步借用租约，
// 从根源消除并发反序申请的锁序/容量死锁（ADR-009），并在即将进入用户回调 fn 前注入单一
// 全局不可重入 trace.LeaseScope。回调收到的 leases 切片严格保持调用方传入 plans 的原始顺序。
//
//xops:syncclosure
//xops:borrowed
func (p *Pool) WithMultiLease(
	ctx context.Context,
	plans []plan.SealedConnectionPlan,
	fn func(ctx context.Context, leases []*Lease) error,
) error {
	if err := p.checkAcquirePreconditions(ctx, fn != nil); err != nil {
		return err
	}
	if len(plans) == 0 {
		return ErrEmptyPlanList
	}
	uniquePlans, origToUnique, err := canonicalizePlanList(plans)
	if err != nil {
		return err
	}
	acquired, err := p.acquireCanonicalPlans(ctx, uniquePlans)
	if err != nil {
		return err
	}
	return p.invokeMultiLease(ctx, plans, origToUnique, acquired, fn)
}

type indexedPlan struct {
	origIdx int
	plan    plan.SealedConnectionPlan
}

// canonicalizePlanList 校验计划切片，按 (跳数升序, PlanDigest 升序) 排序并按 PlanDigest 去重，
// 返回规范顺序的唯一计划列表与原始索引到唯一计划下标的映射，消除 AB-BA 死锁与重复计划自锁。
func canonicalizePlanList(plans []plan.SealedConnectionPlan) ([]plan.SealedConnectionPlan, []int, error) {
	items := make([]indexedPlan, len(plans))
	for i, pl := range plans {
		if !pl.IsValid() {
			return nil, nil, fmt.Errorf("%w: plans[%d] 无效", ErrInvalidPlan, i)
		}
		items[i] = indexedPlan{origIdx: i, plan: pl}
	}
	slices.SortFunc(items, func(a, b indexedPlan) int {
		if c := cmp.Compare(a.plan.Len(), b.plan.Len()); c != 0 {
			return c
		}
		return a.plan.PlanDigest().Compare(b.plan.PlanDigest())
	})
	unique := make([]plan.SealedConnectionPlan, 0, len(items))
	origToUnique := make([]int, len(items))
	for _, it := range items {
		if len(unique) == 0 || !unique[len(unique)-1].PlanDigest().Equal(it.plan.PlanDigest()) {
			unique = append(unique, it.plan)
		}
		origToUnique[it.origIdx] = len(unique) - 1
	}
	return unique, origToUnique, nil
}

func (p *Pool) acquireCanonicalPlans(ctx context.Context, uniquePlans []plan.SealedConnectionPlan) ([]*hopInstance, error) {
	acquired := make([]*hopInstance, 0, len(uniquePlans))
	for _, pl := range uniquePlans {
		inst, err := p.acquirePlan(ctx, pl)
		if err != nil {
			p.releaseAllHops(acquired)
			return nil, err
		}
		acquired = append(acquired, inst)
	}
	return acquired, nil
}

func (p *Pool) invokeMultiLease(
	ctx context.Context,
	origPlans []plan.SealedConnectionPlan,
	origToUnique []int,
	acquired []*hopInstance,
	fn func(ctx context.Context, leases []*Lease) error,
) error {
	leaseID := p.nextLeaseID()
	scope, err := trace.NewLeaseScope(p.domain, leaseID)
	if err != nil {
		p.releaseAllHops(acquired)
		return err
	}
	leaseCtx, cleanups := combineRevocableContexts(ctx, acquired)
	scopedCtx, err := trace.WithLeaseScope(leaseCtx, scope)
	if err != nil {
		runCleanupsReverse(cleanups)
		p.releaseAllHops(acquired)
		return err
	}
	leases := make([]*Lease, len(origPlans))
	for i, pl := range origPlans {
		leases[i] = newLease(p, acquired[origToUnique[i]], pl.PlanDigest(), leaseID)
	}
	defer func() {
		for _, l := range leases {
			l.invalidate()
		}
		runCleanupsReverse(cleanups)
		p.releaseAllHops(acquired)
	}()
	if err := p.checkPreCallbackAlive(acquired...); err != nil {
		return err
	}
	return fn(scopedCtx, leases)
}

func (p *Pool) checkPreCallbackAlive(insts ...*hopInstance) error {
	if p.halted.Load() {
		return p.haltCause()
	}
	if p.closed.Load() {
		return ErrPoolClosed
	}
	for _, inst := range insts {
		if inst == nil || !inst.active.Load() {
			return ErrLeaseRevoked
		}
	}
	return nil
}

func combineRevocableContexts(parent context.Context, insts []*hopInstance) (context.Context, []func()) {
	cur := parent
	cleanups := make([]func(), 0, len(insts))
	for _, inst := range insts {
		next, cleanup := deriveRevocableContext(cur, inst.revokeCtx)
		cur = next
		cleanups = append(cleanups, cleanup)
	}
	return cur, cleanups
}

func runCleanupsReverse(cleanups []func()) {
	for i := len(cleanups) - 1; i >= 0; i-- {
		cleanups[i]()
	}
}

func (p *Pool) releaseAllHops(insts []*hopInstance) {
	for i := len(insts) - 1; i >= 0; i-- {
		p.releaseHopLease(insts[i])
	}
}

func (p *Pool) checkAcquirePreconditions(ctx context.Context, hasFn bool) error {
	if p == nil || !p.initialized {
		return ErrPoolNotInitialized
	}
	if ctx == nil {
		return ErrNilContext
	}
	if !hasFn {
		return ErrNilCallback
	}
	if p.halted.Load() {
		return p.haltCause()
	}
	if p.closed.Load() {
		return ErrPoolClosed
	}
	if err := trace.CheckNonReentrant(ctx); err != nil {
		return err
	}
	return ctx.Err()
}

func (p *Pool) acquirePlan(ctx context.Context, connPlan plan.SealedConnectionPlan) (*hopInstance, error) {
	leafDig, ok := connPlan.HopDigestAt(connPlan.Len() - 1)
	if !ok {
		return nil, ErrInvalidPlan
	}
	tid, oid := traceFromContextOrDefault(ctx, p.poolTraceID)
	w := newAcquireWaiter(tid, oid)
	inst, err := p.submitAcquire(ctx, acquireMsg{
		kind:      acqFastPlan,
		connPlan:  connPlan,
		hopDigest: leafDig,
		waiter:    w,
	})
	if err == nil {
		return inst, nil
	}
	if !errors.Is(err, errFastPathMiss) {
		return nil, err
	}
	return p.acquireMultiHopPlan(ctx, connPlan)
}

func (p *Pool) acquireMultiHopPlan(ctx context.Context, connPlan plan.SealedConnectionPlan) (*hopInstance, error) {
	var parent *hopInstance
	var parentEpoch uint64
	hopCount := connPlan.Len()
	for i := range hopCount {
		hop, okH := connPlan.HopAt(i)
		dig, okD := connPlan.HopDigestAt(i)
		if !okH || !okD {
			p.releaseHopLease(parent)
			return nil, ErrInvalidPlan
		}
		var pdOpt algebraic.Option[plan.PlanDigest]
		if i == hopCount-1 {
			pdOpt = algebraic.Some(connPlan.PlanDigest())
		}
		inst, err := p.acquireHop(ctx, hop, dig, pdOpt, parent, parentEpoch)
		if parent != nil {
			p.releaseHopLease(parent)
		}
		if err != nil {
			return nil, err
		}
		parent, parentEpoch = inst, inst.epoch
	}
	return parent, nil
}

func (p *Pool) acquireHop(
	ctx context.Context,
	hop plan.HopSpec,
	dig plan.HopDigest,
	pdOpt algebraic.Option[plan.PlanDigest],
	parent *hopInstance,
	parentEpoch uint64,
) (*hopInstance, error) {
	tid, oid := traceFromContextOrDefault(ctx, p.poolTraceID)
	w := newAcquireWaiter(tid, oid)
	return p.submitAcquire(ctx, acquireMsg{
		kind:        acqHop,
		hopSpec:     hop,
		hopDigest:   dig,
		planDigest:  pdOpt,
		parent:      parent,
		parentEpoch: parentEpoch,
		waiter:      w,
	})
}

func (p *Pool) submitAcquire(ctx context.Context, msg acquireMsg) (*hopInstance, error) {
	if err := p.actor.SendAcquire(ctx, msg); err != nil {
		return nil, p.translateActorSendError(err)
	}
	select {
	case rep := <-msg.waiter.replyCh:
		return rep.inst, rep.err
	case <-ctx.Done():
		return p.cancelOrDrainWaiter(msg, ctx.Err())
	case <-p.actor.Done():
		return p.cancelOrDrainWaiter(msg, p.terminalStateError())
	}
}

func (p *Pool) cancelOrDrainWaiter(msg acquireMsg, fallbackErr error) (*hopInstance, error) {
	if msg.waiter.tryCancel() {
		p.actor.SendControl(controlMsg{
			kind:      ctrlCancelWaiter,
			hopDigest: msg.hopDigest,
			waiter:    msg.waiter,
		})
		return nil, fallbackErr
	}
	// Actor 已先赢得 CAS 并将结果写入 replyCh，立即接收并在已授予租约时经控制通道归还防泄漏。
	rep := <-msg.waiter.replyCh
	if rep.err == nil && rep.inst != nil {
		p.releaseHopLease(rep.inst)
	}
	return nil, fallbackErr
}

func (p *Pool) translateActorSendError(err error) error {
	if errors.Is(err, actor.ErrActorStopped) {
		return p.terminalStateError()
	}
	return err
}

// releaseHopLease 经 DualActor 永不阻塞控制通道归还单跳租约并等待 Actor 线性化完成；
// 同步监听 actorDone，确保邮箱满载或连接池关闭后绝不挂起（ADR-009 #1/#4）；
// 若因停机导致 SendControl 返回 false（onReleaseLease 绝不会再运行），则在本地原子扣减 activeLeases 保证 1:1 守恒。
func (p *Pool) releaseHopLease(inst *hopInstance) {
	if p == nil || !p.initialized || inst == nil {
		return
	}
	doneCh := make(chan struct{})
	if !p.actor.SendControl(controlMsg{
		kind:   ctrlReleaseLease,
		inst:   inst,
		doneCh: doneCh,
	}) {
		p.activeLeases.Add(-1)
		return
	}
	select {
	case <-doneCh:
	case <-p.actor.Done():
	}
}
