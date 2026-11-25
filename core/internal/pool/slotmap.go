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
	// IsValid 报告托管资源实例当前是否处于有效初始化状态（零值与 nil 接收者必须返回 false）。
	IsValid() bool
	// Close 幂等关闭底层资源；在主动释放、按计划回收、池关闭或 GateHalted 熔断时调用。
	Close() error
}

// ComparableManagedResource 约束可登记与借用的可比较托管资源类型，
// 在零 reflect 前提下于进入 IsValid/Close 前即拦截 nil 接口、typed-nil 指针与零值结构体。
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
	binding      security.OperationBinding
	resource     ManagedResource
	revokeCtx    context.Context
	revokeCancel context.CancelCauseFunc
}

// slotMap 是固定槽位复用 + 单调世代防 ABA 的线程安全托管句柄表（仅作为 Pool 内部叶级结构使用）。
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
	return &slotMap{
		maxHandles: maxHandles,
		byID:       make(map[plan.HandleID]uint32),
	}
}

func (m *slotMap) len() int {
	if m == nil {
		return 0
	}
	return int(m.activeCnt.Load())
}

// RegisterHandle 在连接池的世代 SlotMap 中登记一个类别为 K 的长生命周期托管资源，
// 生成不可伪造且绑定 PlanDigest 与 OperationBinding 的 plan.ManagedHandle[K]（gen >= 1）。
// 若池未初始化、已关闭、已触发 GateHalted，或 resource 为零值/typed-nil/IsValid()==false，均严格失败关闭。
func RegisterHandle[K plan.HandleKind, R ComparableManagedResource](
	p *Pool,
	planDigest plan.PlanDigest,
	binding security.OperationBinding,
	resource R,
) (plan.ManagedHandle[K], error) {
	var zero plan.ManagedHandle[K]
	if err := validateRegisterInputs[K](p, planDigest, binding, resource); err != nil {
		return zero, err
	}
	id, err := plan.NewHandleIDFrom(p.entropy)
	if err != nil {
		return zero, fmt.Errorf("%w: 生成 HandleID 失败: %w", ErrInvalidHandle, err)
	}
	handle, err := p.slots.allocateHandle(p, id, planDigest, binding, resource, plan.HandleKindOf[K]())
	if err != nil {
		return zero, err
	}
	typed, err := plan.NewManagedHandle[K](handle.id, handle.gen, planDigest, binding)
	if err != nil {
		// 理论上参数均已前置校验，防御性回滚槽位以维持绝对原子性。
		p.rollbackSlot(handle.id)
		return zero, err
	}
	p.emitHandleEvent(events.PoolActionMuxHandover, typed.Kind(), typed.ID(), planDigest, typed.Generation(), "managed handle registered")
	return typed, nil
}

func validateRegisterInputs[K plan.HandleKind, R ComparableManagedResource](
	p *Pool,
	planDigest plan.PlanDigest,
	binding security.OperationBinding,
	resource R,
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
	// 预先校验 binding.PlanDigest 与 planDigest 一致性，确保拒绝非法绑定时不消耗槽位或熵源。
	bpd, ok := binding.PlanDigest().Get()
	if !ok || !bpd.Equal(planDigest.SecurityDigest()) {
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
	p *Pool,
	id plan.HandleID,
	planDigest plan.PlanDigest,
	binding security.OperationBinding,
	res ManagedResource,
	kind plan.HandleKindCode,
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

// WithManagedHandle 凭世代句柄 handle 在同步闭包内借用类型为 R 的托管资源，
// 严格校验池状态、句柄类别、世代号、PlanDigest 与 OperationBinding，且绝不在回调期间持有 SlotMap 锁。
// 若回调期间触发 ReleaseHandle、Pool.Close 或 GateHalted，派生 ctx 将立即被取消。
//
//xops:syncclosure
//xops:borrowed
func WithManagedHandle[K plan.HandleKind, R ComparableManagedResource](
	ctx context.Context,
	p *Pool,
	handle plan.ManagedHandle[K],
	fn func(ctx context.Context, res R) error,
) error {
	if err := checkPoolAvailable(p); err != nil {
		return err
	}
	if ctx == nil {
		return ErrNilContext
	}
	if fn == nil {
		return ErrNilCallback
	}
	if !handle.IsValid() {
		return ErrInvalidHandle
	}
	if err := ctx.Err(); err != nil {
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

// ReleaseHandle 显式释放指定世代句柄并摘除 SlotMap 槽位，随后在 90ms 有界预算内异步关闭底层托管资源。
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

	p.emitHandleEvent(events.PoolActionRetired, rec.kind, rec.id, rec.planDigest, rec.gen, "managed handle released")
	p.scheduleResourceClose(res)
	return nil
}

// InspectHandle 只读查询指定世代句柄当前是否有效活跃（不暴露底层资源指针）。
func InspectHandle[K plan.HandleKind](p *Pool, handle plan.ManagedHandle[K]) (HandleStatus, error) {
	if p == nil || !p.initialized {
		return HandleStatus{}, ErrPoolNotInitialized
	}
	if !handle.IsValid() {
		return HandleStatus{}, ErrInvalidHandle
	}
	if p.halted.Load() {
		return HandleStatus{}, p.haltCause()
	}
	if p.closed.Load() {
		return HandleStatus{}, ErrPoolClosed
	}
	p.slots.mu.Lock()
	rec, err := p.slots.matchLocked(handle.ID(), handle.Kind(), handle.Generation(), handle.PlanDigest(), handle.Binding())
	if err != nil {
		p.slots.mu.Unlock()
		return HandleStatus{}, err
	}
	status := HandleStatus{
		kind:       rec.kind,
		id:         rec.id,
		gen:        rec.gen,
		planDigest: rec.planDigest,
		binding:    rec.binding,
		active:     rec.occupied && !p.halted.Load() && !p.closed.Load(),
		valid:      true,
	}
	p.slots.mu.Unlock()
	return status, nil
}

// RevokeHandlesByPlan 吊销并回收全部绑定到指定 PlanDigest 的活跃托管句柄，返回吊销数量。
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
			evicted = append(evicted, revokedSlot{id: id, kind: rec.kind, gen: rec.gen, pd: rec.planDigest, res: res})
		}
	}
	p.slots.mu.Unlock()
	slices.SortFunc(evicted, func(a, b revokedSlot) int { return cmp.Compare(a.gen, b.gen) })
	for _, ev := range evicted {
		p.emitHandleEvent(events.PoolActionEvicted, ev.kind, ev.id, ev.pd, ev.gen, "revoked by plan digest")
		p.scheduleResourceClose(ev.res)
	}
	return len(evicted)
}

type revokedSlot struct {
	id   plan.HandleID
	kind plan.HandleKindCode
	gen  uint64
	pd   plan.PlanDigest
	res  ManagedResource
}

// revokeAllSlots 在 GateHalted（PoolActionGateHalted）或正常关闭/停机（PoolActionRetired）路径上
// 原子吊销全部活跃托管句柄并派发有界关闭。
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
	slices.SortFunc(evicted, func(a, b revokedSlot) int { return cmp.Compare(a.gen, b.gen) })
	for _, ev := range evicted {
		p.emitHandleEvent(action, ev.kind, ev.id, ev.pd, ev.gen, cause.Error())
		p.scheduleResourceClose(ev.res)
	}
}

func (m *slotMap) matchLocked(
	id plan.HandleID,
	kind plan.HandleKindCode,
	gen uint64,
	pd plan.PlanDigest,
	binding security.OperationBinding,
) (slotRecord, error) {
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
	res := rec.resource
	id := rec.id
	gen := rec.gen
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
		action:     action,
		planDigest: algebraic.Some(pd),
		handleKind: algebraic.Some(kind),
		handleID:   algebraic.Some(id),
		generation: gen,
		detail:     detail,
	})
}
