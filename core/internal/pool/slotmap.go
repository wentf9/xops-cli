package pool

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
)

// ManagedResource 表示可托管于连接池世代 SlotMap 的跨请求长生命周期资源契约
// （如持久 PTY、隧道转发器、可恢复文件传输会话或 ControlMaster 守护句柄，ADR-009）。
type ManagedResource interface {
	IsValid() bool
	Close() error
}

// ComparableManagedResource 约束可登记与借用的可比较托管资源类型，零 reflect 拦截 nil/typed-nil/零值。
type ComparableManagedResource interface {
	ManagedResource
	comparable
}

type slotRecord struct {
	occupied     bool
	gen          uint64
	id           plan.HandleID
	kind         plan.HandleKindCode
	planDigest   plan.PlanDigest
	boundHop     plan.HopDigest // 钉选的底层跳板摘要（纯值类型，零 *hopInstance GC 滞留）
	boundEpoch   uint64         // 钉选的底层跳板精确世代号（0 表示无跳板钉选）
	binding      security.OperationBinding
	resource     ManagedResource
	revokeCtx    context.Context
	revokeCancel context.CancelCauseFunc
}

// slotMap 是固定槽位复用 + 单调世代防 ABA 的线程安全托管句柄表（严格作为 Pool 叶级锁，禁止持锁调用 Actor）。
type slotMap struct {
	mu         sync.Mutex
	maxHandles int
	nextGen    uint64
	slots      []slotRecord
	freeList   []uint32
	byID       map[plan.HandleID]uint32
	activeCnt  atomic.Int64
}

func newSlotMap(maxHandles int) *slotMap {
	return &slotMap{maxHandles: maxHandles, byID: make(map[plan.HandleID]uint32)}
}
func (m *slotMap) len() int {
	if m == nil {
		return 0
	}
	return int(m.activeCnt.Load())
}

// RegisterLeaseHandle 在当前有效租约 lease 锁定的底层跳板世代上登记托管句柄并严格钉选该跳板实例：
//   - 租约无效/跨池/过期/底层跳板已退役或熔断时严格失败关闭；
//   - 句柄存活期间底层跳板及其祖先链绝不会被空闲/LRU 驱逐；
//   - 底层跳板因保活失败、RetireHop/RetirePlan、Lease.Retire 或父跳级联退役时，句柄被同步撤销并关闭资源。
func RegisterLeaseHandle[K plan.HandleKind, R ComparableManagedResource](
	p *Pool, lease *Lease, binding security.OperationBinding, resource R,
) (plan.ManagedHandle[K], error) {
	var zero plan.ManagedHandle[K]
	if err := checkPoolAvailable(p); err != nil {
		return zero, err
	}
	if lease == nil || !lease.valid || lease.pool != p || lease.inst == nil {
		return zero, ErrLeaseInvalid
	}
	if !lease.active.Load() {
		return zero, ErrLeaseExpired
	}
	hopDig, hopEpoch, planDig := lease.HopDigest(), lease.Epoch(), lease.PlanDigest()
	if !hopDig.IsValid() || hopEpoch == 0 || !planDig.IsValid() {
		return zero, ErrLeaseRevoked
	}
	return registerHandleCore[K, R](p, planDig, binding, resource, hopDig, hopEpoch, true)
}

// RegisterHandle 在连接池世代 SlotMap 中登记类别为 K 的托管资源；
// 若当前 planDigest 已存在活跃连接实例，自动将其钉选到该跳板（防空闲/LRU 驱逐并支持断连联动撤销）。
func RegisterHandle[K plan.HandleKind, R ComparableManagedResource](
	p *Pool, planDigest plan.PlanDigest, binding security.OperationBinding, resource R,
) (plan.ManagedHandle[K], error) {
	return registerHandleCore[K, R](p, planDigest, binding, resource, zeroVal[plan.HopDigest](), 0, false)
}

func registerHandleCore[K plan.HandleKind, R ComparableManagedResource](
	p *Pool, planDigest plan.PlanDigest, binding security.OperationBinding, resource R,
	hopDigest plan.HopDigest, hopEpoch uint64, pinStrict bool,
) (plan.ManagedHandle[K], error) {
	var zero plan.ManagedHandle[K]
	if err := validateRegisterInputs[K](p, planDigest, binding, resource); err != nil {
		return zero, err
	}
	id, err := plan.NewHandleIDFrom(p.entropy)
	if err != nil {
		return zero, fmt.Errorf("%w: 生成 HandleID 失败: %w", ErrInvalidHandle, err)
	}
	meta, err := p.slots.allocateHandle(p, id, planDigest, binding, resource, plan.HandleKindOf[K]())
	if err != nil {
		return zero, err
	}
	typed, err := plan.NewManagedHandle[K](meta.id, meta.gen, planDigest, binding)
	if err != nil {
		p.rollbackSlot(meta.id)
		return zero, err
	}
	if pinErr := p.pinHandleOnActor(meta.id, meta.gen, planDigest, hopDigest, hopEpoch, pinStrict); pinErr != nil {
		p.rollbackSlot(meta.id)
		return zero, pinErr
	}
	p.emitHandleEvent(events.PoolActionMuxHandover, typed.Kind(), typed.ID(), planDigest, typed.Generation(), "managed handle registered")
	return typed, nil
}

func (p *Pool) pinHandleOnActor(id plan.HandleID, gen uint64, pd plan.PlanDigest, hopDig plan.HopDigest, hopEpoch uint64, strict bool) error {
	pinErrCh := make(chan error, 1)
	if !p.actor.SendControl(controlMsg{
		kind: ctrlPinHandle, hopDigest: hopDig, hopEpoch: hopEpoch,
		planDigest: pd, handleID: id, handleGen: gen, pinStrict: strict, pinErrCh: pinErrCh,
	}) {
		return p.terminalStateError()
	}
	select {
	case err := <-pinErrCh:
		return err
	case <-p.actor.Done():
		return p.terminalStateError()
	}
}

func validateRegisterInputs[K plan.HandleKind, R ComparableManagedResource](
	p *Pool, planDigest plan.PlanDigest, binding security.OperationBinding, resource R,
) error {
	if err := checkPoolAvailable(p); err != nil {
		return err
	}
	if !plan.HandleKindOf[K]().IsValid() || !planDigest.IsValid() || !binding.IsValid() {
		return ErrInvalidHandle
	}
	var zeroRes R
	if resource == zeroRes {
		return ErrInvalidResource
	}
	var iface ManagedResource = resource
	if iface == nil || !iface.IsValid() {
		return ErrInvalidResource
	}
	if bpd, ok := binding.PlanDigest().Get(); !ok || !bpd.Equal(planDigest.SecurityDigest()) {
		return ErrHandleBindingMismatch
	}
	return nil
}

func checkPoolAvailable(p *Pool) error {
	if p == nil || !p.initialized {
		return ErrPoolNotInitialized
	}
	if p.halted.Load() {
		return p.haltCause()
	}
	if p.closed.Load() {
		return ErrPoolClosed
	}
	return nil
}

type allocatedSlotMeta struct {
	id  plan.HandleID
	gen uint64
}

func (m *slotMap) allocateHandle(
	p *Pool, id plan.HandleID, planDigest plan.PlanDigest, binding security.OperationBinding, res ManagedResource, kind plan.HandleKindCode,
) (allocatedSlotMeta, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := checkPoolAvailable(p); err != nil {
		return allocatedSlotMeta{}, err
	}
	if m.maxHandles > 0 && len(m.byID) >= m.maxHandles {
		return allocatedSlotMeta{}, ErrHandleLimitExceeded
	}
	if _, dup := m.byID[id]; dup {
		return allocatedSlotMeta{}, ErrInvalidHandle
	}
	idx := m.claimFreeSlotLocked()
	m.nextGen++
	gen := m.nextGen
	revokeCtx, revokeCancel := context.WithCancelCause(p.haltCtx)
	m.slots[idx] = slotRecord{
		occupied: true, gen: gen, id: id, kind: kind, planDigest: planDigest,
		binding: binding, resource: res, revokeCtx: revokeCtx, revokeCancel: revokeCancel,
	}
	m.byID[id] = idx
	m.activeCnt.Store(int64(len(m.byID)))
	return allocatedSlotMeta{id: id, gen: gen}, nil
}

func (m *slotMap) claimFreeSlotLocked() uint32 {
	if n := len(m.freeList); n > 0 {
		idx := m.freeList[n-1]
		m.freeList = m.freeList[:n-1]
		return idx
	}
	idx := uint32(len(m.slots))
	m.slots = append(m.slots, slotRecord{})
	return idx
}

func (m *slotMap) bindSlotToHop(id plan.HandleID, gen uint64, hopDig plan.HopDigest, hopEpoch uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	idx, ok := m.byID[id]
	if !ok || !m.slots[idx].occupied || m.slots[idx].gen != gen {
		return false
	}
	m.slots[idx].boundHop = hopDig
	m.slots[idx].boundEpoch = hopEpoch
	return true
}

func (p *Pool) rollbackSlot(id plan.HandleID) {
	p.slots.mu.Lock()
	if idx, ok := p.slots.byID[id]; ok {
		rec := &p.slots.slots[idx]
		if rec.revokeCancel != nil {
			rec.revokeCancel(ErrHandleRevoked)
		}
		delete(p.slots.byID, id)
		p.slots.slots[idx] = slotRecord{gen: rec.gen}
		p.slots.freeList = append(p.slots.freeList, idx)
		p.slots.activeCnt.Store(int64(len(p.slots.byID)))
	}
	p.slots.mu.Unlock()
}

// WithManagedHandle 凭世代句柄在同步闭包内借用类型为 R 的托管资源，绝不在回调期间持有 SlotMap 锁。
//
//xops:syncclosure
//xops:borrowed
func WithManagedHandle[K plan.HandleKind, R ComparableManagedResource](
	ctx context.Context, p *Pool, handle plan.ManagedHandle[K], fn func(ctx context.Context, res R) error,
) error {
	if err := checkWithHandleArgs(ctx, p, fn == nil, !handle.IsValid()); err != nil {
		return err
	}
	typed, revokeCtx, err := lookupTypedHandle[K, R](p, handle)
	if err != nil {
		return err
	}
	scopedCtx, cleanup := deriveRevocableContext(ctx, revokeCtx)
	defer cleanup()
	if err := checkPreHandleCallback(p, revokeCtx, typed); err != nil {
		return err
	}
	return fn(scopedCtx, typed)
}

func checkWithHandleArgs(ctx context.Context, p *Pool, nilFn, invalidHandle bool) error {
	if err := checkPoolAvailable(p); err != nil {
		return err
	}
	switch {
	case ctx == nil:
		return ErrNilContext
	case nilFn:
		return ErrNilCallback
	case invalidHandle:
		return ErrInvalidHandle
	default:
		return ctx.Err()
	}
}

func checkPreHandleCallback[R ComparableManagedResource](p *Pool, revokeCtx context.Context, typed R) error {
	if err := checkPoolAvailable(p); err != nil {
		return err
	}
	if revokeCtx.Err() != nil {
		return ErrHandleRevoked
	}
	var zeroRes R
	if typed == zeroRes || !typed.IsValid() {
		return ErrInvalidResource
	}
	return nil
}

func lookupTypedHandle[K plan.HandleKind, R ComparableManagedResource](p *Pool, handle plan.ManagedHandle[K]) (R, context.Context, error) {
	var zero R
	p.slots.mu.Lock()
	defer p.slots.mu.Unlock()
	if err := checkPoolAvailable(p); err != nil {
		return zero, nil, err
	}
	rec, err := p.slots.matchLocked(handle.ID(), handle.Kind(), handle.Generation(), handle.PlanDigest(), handle.Binding())
	if err != nil {
		return zero, nil, err
	}
	typed, ok := rec.resource.(R)
	if !ok {
		return zero, nil, ErrHandleTypeMismatch
	}
	return typed, rec.revokeCtx, nil
}

// ReleaseHandle 显式释放指定世代句柄、非阻塞解除底层跳板钉选，并在 90ms 有界预算内关闭底层资源。
func ReleaseHandle[K plan.HandleKind](p *Pool, handle plan.ManagedHandle[K]) error {
	if p == nil || !p.initialized {
		return ErrPoolNotInitialized
	}
	if !handle.IsValid() {
		return ErrInvalidHandle
	}
	p.slots.mu.Lock()
	rec, err := p.slots.matchLocked(handle.ID(), handle.Kind(), handle.Generation(), handle.PlanDigest(), handle.Binding())
	if err != nil {
		p.slots.mu.Unlock()
		return err
	}
	idx := p.slots.byID[handle.ID()]
	res := p.slots.evictIndexLocked(idx, ErrHandleRevoked)
	p.slots.mu.Unlock()

	p.sendUnpinIfBound(rec.boundHop, rec.boundEpoch, rec.id, rec.gen)
	p.emitHandleEvent(events.PoolActionRetired, rec.kind, rec.id, rec.planDigest, rec.gen, "managed handle released")
	p.scheduleResourceClose(res)
	return nil
}

// InspectHandle 只读查询指定世代句柄当前是否有效活跃（不暴露底层资源指针）。
func InspectHandle[K plan.HandleKind](p *Pool, handle plan.ManagedHandle[K]) (HandleStatus, error) {
	if err := checkPoolAvailable(p); err != nil {
		return HandleStatus{}, err
	}
	if !handle.IsValid() {
		return HandleStatus{}, ErrInvalidHandle
	}
	p.slots.mu.Lock()
	rec, err := p.slots.matchLocked(handle.ID(), handle.Kind(), handle.Generation(), handle.PlanDigest(), handle.Binding())
	if err != nil {
		p.slots.mu.Unlock()
		return HandleStatus{}, err
	}
	status := HandleStatus{
		kind: rec.kind, id: rec.id, gen: rec.gen, planDigest: rec.planDigest, binding: rec.binding,
		active: rec.occupied && !p.halted.Load() && !p.closed.Load(), valid: true,
	}
	p.slots.mu.Unlock()
	return status, nil
}

type revokedSlot struct {
	id         plan.HandleID
	kind       plan.HandleKindCode
	gen        uint64
	pd         plan.PlanDigest
	boundHop   plan.HopDigest
	boundEpoch uint64
	res        ManagedResource
}

// RevokeHandlesByPlan 吊销并回收全部绑定到指定 PlanDigest 的活跃托管句柄，非阻塞解钉并返回吊销数量。
func (p *Pool) RevokeHandlesByPlan(planDigest plan.PlanDigest) int {
	if p == nil || !p.initialized || !planDigest.IsValid() {
		return 0
	}
	var evicted []revokedSlot
	p.slots.mu.Lock()
	for id, idx := range p.slots.byID {
		rec := p.slots.slots[idx]
		if rec.occupied && rec.planDigest.Equal(planDigest) {
			res := p.slots.evictIndexLocked(idx, ErrHandleRevoked)
			evicted = append(evicted, revokedSlot{id: id, kind: rec.kind, gen: rec.gen, pd: rec.planDigest, boundHop: rec.boundHop, boundEpoch: rec.boundEpoch, res: res})
		}
	}
	p.slots.mu.Unlock()
	p.finalizeRevokedSlots(evicted, events.PoolActionEvicted, "revoked by plan digest", true)
	return len(evicted)
}

// revokeSlotsForHop 由 DualActor 在 detachInstance 中同步调用，吊销全部钉选在该跳实例上的活跃托管句柄。
func (p *Pool) revokeSlotsForHop(pinned map[plan.HandleID]uint64, cause error) {
	if p == nil || p.slots == nil || len(pinned) == 0 {
		return
	}
	if cause == nil {
		cause = ErrHandleRevoked
	}
	var evicted []revokedSlot
	p.slots.mu.Lock()
	for id, gen := range pinned {
		idx, ok := p.slots.byID[id]
		if !ok {
			continue
		}
		rec := p.slots.slots[idx]
		if rec.occupied && rec.gen == gen {
			res := p.slots.evictIndexLocked(idx, cause)
			evicted = append(evicted, revokedSlot{id: id, kind: rec.kind, gen: rec.gen, pd: rec.planDigest, res: res})
		}
	}
	p.slots.mu.Unlock()
	p.finalizeRevokedSlots(evicted, events.PoolActionEvicted, "revoked by detached hop", false)
}

// revokeAllSlots 在 GateHalted 或 Close 路径上原子吊销全部活跃托管句柄并派发有界关闭。
func (p *Pool) revokeAllSlots(action events.PoolEventAction, cause error) {
	if p == nil || p.slots == nil {
		return
	}
	var evicted []revokedSlot
	p.slots.mu.Lock()
	for id, idx := range p.slots.byID {
		rec := p.slots.slots[idx]
		res := p.slots.evictIndexLocked(idx, cause)
		evicted = append(evicted, revokedSlot{id: id, kind: rec.kind, gen: rec.gen, pd: rec.planDigest, res: res})
	}
	p.slots.mu.Unlock()
	p.finalizeRevokedSlots(evicted, action, cause.Error(), false)
}

func (p *Pool) finalizeRevokedSlots(evicted []revokedSlot, action events.PoolEventAction, detail string, sendUnpin bool) {
	if len(evicted) == 0 {
		return
	}
	slices.SortFunc(evicted, func(a, b revokedSlot) int { return cmp.Compare(a.gen, b.gen) })
	for _, ev := range evicted {
		if sendUnpin {
			p.sendUnpinIfBound(ev.boundHop, ev.boundEpoch, ev.id, ev.gen)
		}
		p.emitHandleEvent(action, ev.kind, ev.id, ev.pd, ev.gen, detail)
		p.scheduleResourceClose(ev.res)
	}
}

func (p *Pool) sendUnpinIfBound(hopDig plan.HopDigest, hopEpoch uint64, id plan.HandleID, gen uint64) {
	if hopEpoch == 0 || !hopDig.IsValid() || p.actor == nil {
		return
	}
	p.actor.SendControl(controlMsg{kind: ctrlUnpinHandle, hopDigest: hopDig, hopEpoch: hopEpoch, handleID: id, handleGen: gen})
}

func (m *slotMap) matchLocked(id plan.HandleID, kind plan.HandleKindCode, gen uint64, pd plan.PlanDigest, binding security.OperationBinding) (slotRecord, error) {
	idx, ok := m.byID[id]
	if !ok {
		return slotRecord{}, ErrHandleNotFound
	}
	rec := m.slots[idx]
	if rec.gen != gen {
		return slotRecord{}, ErrHandleGenerationMismatch
	}
	if rec.kind != kind || !rec.planDigest.Equal(pd) || !rec.binding.Equal(binding) {
		return slotRecord{}, ErrHandleBindingMismatch
	}
	return rec, nil
}

func (m *slotMap) evictIndexLocked(idx uint32, cause error) ManagedResource {
	rec := &m.slots[idx]
	res, id, gen := rec.resource, rec.id, rec.gen
	if rec.revokeCancel != nil {
		rec.revokeCancel(cause)
	}
	delete(m.byID, id)
	m.slots[idx] = slotRecord{gen: gen}
	m.freeList = append(m.freeList, idx)
	m.activeCnt.Store(int64(len(m.byID)))
	return res
}

func (p *Pool) emitHandleEvent(action events.PoolEventAction, kind plan.HandleKindCode, id plan.HandleID, pd plan.PlanDigest, gen uint64, detail string) {
	p.emitPoolEvent(poolEventInput{
		action: action, planDigest: algebraic.Some(pd), handleKind: algebraic.Some(kind),
		handleID: algebraic.Some(id), generation: gen, detail: detail,
	})
}
