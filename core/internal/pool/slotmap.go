package pool

import (
	"cmp"
	"context"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
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
	occupied        bool
	active          *atomic.Bool // 正向槽位活跃哨兵，供 pinnedTransportConn 无锁校验句柄未被吊销
	gen, boundEpoch uint64
	id              plan.HandleID
	kind            plan.HandleKindCode
	planDigest      plan.PlanDigest
	boundHop        plan.HopDigest // 钉选的底层跳板摘要（纯值类型，零 *hopInstance GC 滞留）
	binding         security.OperationBinding
	resource        ManagedResource
	revokeCtx       context.Context
	revokeCancel    context.CancelCauseFunc
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
// 租约无效/过期/跳板已退役或熔断时失败关闭；存活期间底层跳板及其祖先绝不被空闲/LRU 驱逐，断连时同步撤销句柄。
func RegisterLeaseHandle[K plan.HandleKind, R ComparableManagedResource](p *Pool, lease *Lease, binding security.OperationBinding, resource R) (plan.ManagedHandle[K], error) {
	hopDig, hopEpoch, planDig, err := extractLeasePinMeta[K](p, lease, binding)
	if err != nil {
		return zeroVal[plan.ManagedHandle[K]](), err
	}
	return registerHandleCore[K, R](p, planDig, binding, resource, hopDig, hopEpoch, true)
}

// RegisterHandle 在连接池世代 SlotMap 中登记类别为 K 的托管资源；若当前 planDigest 存在活跃实例则自动钉选。
func RegisterHandle[K plan.HandleKind, R ComparableManagedResource](p *Pool, planDigest plan.PlanDigest, binding security.OperationBinding, resource R) (plan.ManagedHandle[K], error) {
	return registerHandleCore[K, R](p, planDigest, binding, resource, zeroVal[plan.HopDigest](), 0, false)
}
func registerHandleCore[K plan.HandleKind, R ComparableManagedResource](p *Pool, planDigest plan.PlanDigest, binding security.OperationBinding, resource R, hopDigest plan.HopDigest, hopEpoch uint64, pinStrict bool) (plan.ManagedHandle[K], error) {
	var zero plan.ManagedHandle[K]
	if err := validateRegisterInputs[K](p, planDigest, binding, resource); err != nil {
		return zero, err
	}
	id, err := plan.NewHandleIDFrom(p.entropy)
	if err != nil {
		return zero, domi18n.WrapS(ErrInvalidHandle, err, domi18n.KeyCommonIDGenFailed, domi18n.Str("kind", "HandleID"))
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
	if _, pinErr := p.pinHandleOnActor(meta.id, meta.gen, planDigest, hopDigest, hopEpoch, pinStrict); pinErr != nil {
		p.rollbackSlot(meta.id)
		return zero, pinErr
	}
	p.emitHandleEvent(events.PoolActionMuxHandover, typed.Kind(), typed.ID(), planDigest, typed.Generation(), "managed handle registered")
	return typed, nil
}
func (p *Pool) pinHandleOnActor(id plan.HandleID, gen uint64, pd plan.PlanDigest, hopDig plan.HopDigest, hopEpoch uint64, strict bool) (*hopInstance, error) {
	pinResCh := make(chan pinHandleReply, 1)
	if !p.actor.SendControl(controlMsg{kind: ctrlPinHandle, hopDigest: hopDig, hopEpoch: hopEpoch, planDigest: pd, handleID: id, handleGen: gen, pinStrict: strict, pinResCh: pinResCh}) {
		return nil, p.terminalStateError()
	}
	select {
	case rep := <-pinResCh:
		return rep.inst, rep.err
	case <-p.actor.Done():
		return nil, p.terminalStateError()
	}
}
func validateRegisterInputs[K plan.HandleKind, R ComparableManagedResource](p *Pool, planDigest plan.PlanDigest, binding security.OperationBinding, resource R) error {
	if err := checkPoolAvailable(p); err != nil {
		return err
	}
	if err := validateHandleBinding[K](planDigest, binding); err != nil {
		return err
	}
	return checkValidManagedResource(resource)
}
func checkPoolAvailable(p *Pool) error {
	switch {
	case p == nil || !p.initialized:
		return ErrPoolNotInitialized
	case p.halted.Load():
		return p.haltCause()
	case p.closed.Load():
		return ErrPoolClosed
	default:
		return nil
	}
}

type allocatedSlotMeta struct {
	id        plan.HandleID
	gen       uint64
	revokeCtx context.Context
	active    *atomic.Bool
}

func (m *slotMap) allocateHandle(p *Pool, id plan.HandleID, planDigest plan.PlanDigest, binding security.OperationBinding, res ManagedResource, kind plan.HandleKindCode) (allocatedSlotMeta, error) {
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
	slotActive := new(atomic.Bool)
	slotActive.Store(true)
	m.slots[idx] = slotRecord{
		occupied: true, active: slotActive, gen: gen, id: id, kind: kind, planDigest: planDigest,
		binding: binding, resource: res, revokeCtx: revokeCtx, revokeCancel: revokeCancel,
	}
	m.byID[id] = idx
	m.activeCnt.Store(int64(len(m.byID)))
	return allocatedSlotMeta{id: id, gen: gen, revokeCtx: revokeCtx, active: slotActive}, nil
}
func (m *slotMap) attachResource(p *Pool, id plan.HandleID, gen uint64, res ManagedResource) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := checkPoolAvailable(p); err != nil {
		return err
	}
	idx, ok := m.byID[id]
	if !ok || !m.slots[idx].occupied || m.slots[idx].gen != gen || m.slots[idx].active == nil || !m.slots[idx].active.Load() {
		return ErrHandleRevoked
	}
	m.slots[idx].resource = res
	return nil
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
	m.slots[idx].boundHop, m.slots[idx].boundEpoch = hopDig, hopEpoch
	return true
}
func (p *Pool) rollbackSlot(id plan.HandleID) {
	p.slots.mu.Lock()
	if idx, ok := p.slots.byID[id]; ok {
		_ = p.slots.evictIndexLocked(idx, ErrHandleRevoked)
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
	if res != nil {
		// 持 slots.mu 期间原子预增 tdPending，与 Pool.Close() 的 revokeAllSlots -> WaitPendingTeardowns
		// 严格线性化，确保 ReleaseHandle 永不落入 teardownNursery 已关闭的同步 Close 回退窗口。
		p.incTeardownPending()
	}
	p.slots.mu.Unlock()
	p.sendUnpinIfBound(rec.boundHop, rec.boundEpoch, rec.id, rec.gen)
	p.emitHandleEvent(events.PoolActionRetired, rec.kind, rec.id, rec.planDigest, rec.gen, "managed handle released")
	p.scheduleResourceCloseReserved(res)
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
	evicted := p.evictMatchingSlots(ErrHandleRevoked, func(rec slotRecord) bool {
		return rec.occupied && rec.planDigest.Equal(planDigest)
	})
	p.finalizeRevokedSlots(evicted, events.PoolActionEvicted, "revoked by plan digest", true)
	return len(evicted)
}

// revokeSlotsForHop 由 DualActor 在 detachInstance 中同步调用，吊销全部钉选在该跳实例上的活跃托管句柄。
func (p *Pool) revokeSlotsForHop(pinned map[plan.HandleID]uint64, cause error) {
	if p == nil || p.slots == nil || len(pinned) == 0 {
		return
	}
	cause = pickIf[error](cause != nil, cause, ErrHandleRevoked)
	evicted := p.evictMatchingSlots(cause, func(rec slotRecord) bool {
		gen, ok := pinned[rec.id]
		return ok && rec.occupied && rec.gen == gen
	})
	p.finalizeRevokedSlots(evicted, events.PoolActionEvicted, "revoked by detached hop", false)
}

// revokeAllSlots 在 GateHalted 或 Close 路径上原子吊销全部活跃托管句柄并派发有界关闭。
func (p *Pool) revokeAllSlots(action events.PoolEventAction, cause error) {
	if p == nil || p.slots == nil {
		return
	}
	evicted := p.evictMatchingSlots(cause, func(slotRecord) bool { return true })
	p.finalizeRevokedSlots(evicted, action, cause.Error(), false)
}
func (p *Pool) evictMatchingSlots(cause error, match func(slotRecord) bool) []revokedSlot {
	var evicted []revokedSlot
	p.slots.mu.Lock()
	for id, idx := range p.slots.byID {
		rec := p.slots.slots[idx]
		if match(rec) {
			res := p.slots.evictIndexLocked(idx, cause)
			if res != nil {
				p.incTeardownPending()
			}
			evicted = append(evicted, revokedSlot{id: id, kind: rec.kind, gen: rec.gen, pd: rec.planDigest, boundHop: rec.boundHop, boundEpoch: rec.boundEpoch, res: res})
		}
	}
	p.slots.mu.Unlock()
	return evicted
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
		p.scheduleResourceCloseReserved(ev.res)
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
	if !ok || m.slots[idx].resource == nil {
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
	if rec.active != nil {
		rec.active.Store(false)
	}
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
