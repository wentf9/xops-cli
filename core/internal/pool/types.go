package pool

import (
	"context"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/ports"
	"sync"
	"sync/atomic"
	"time"
)

// PoolConfig 定义连接池 Pool 的运行期初始化配置（纯内存构造参数，非持久化 DTO）。
// Dialer、Clock 与 Entropy 为必需依赖；Clock 与 Entropy 经接口注入确保确定性仿真。
type PoolConfig struct {
	Dialer                   ports.DialerPort  // 协议无关 SSH 单跳/多跳拨号端口（必需）
	Clock                    ports.Clock       // 时钟与定时器端口（驱动 90ms 拆断、保活与空闲回收，必需）
	Entropy                  ports.Entropy     // 并发安全显式熵源（必需）
	Bus                      *events.SystemBus // 可选系统诊断事件总线
	Domain                   string            // trace.LeaseScope 诊断归属标签（默认 "pool"）
	AcquireBuffer            int               // DualActor 有界请求通道容量（0 取 DefaultAcquireBuffer）
	MaxConns                 int               // 活跃连接与在途拨号总数上限（0 不限，负值非法）
	MaxHandles               int               // 世代 SlotMap 活跃托管句柄上限（0 不限，负值非法）
	TeardownGrace            time.Duration     // 连接拆断宽限时长（0 取 DefaultTeardownGrace=90ms）
	IdleTTL                  time.Duration     // 空闲叶子连接过期回收时长（0 禁用后台扫描）
	DefaultKeepaliveInterval time.Duration     // HopSpec 未指定 ServerAliveInterval 时的保活回退间隔
}

// PoolStats 提供连接池当前的无锁并发安全运行期统计快照。
type PoolStats struct {
	ActiveConns, DialingConns, ActiveHandles int
	ActiveLeases                             int64
	TotalDials, DialErrors, CacheHits        uint64
	ParentCASRejections                      uint64
	TeardownCompleted, TeardownEscalations   uint64
	Halted, Closed                           bool
}

// HandleStatus 表示世代 SlotMap 中某个托管句柄的不可变只读状态快照；零值恒无效并失败关闭。
//
//xops:opaque
//xops:failclosed
type HandleStatus struct {
	kind          plan.HandleKindCode
	id            plan.HandleID
	gen           uint64
	planDigest    plan.PlanDigest
	binding       security.OperationBinding
	active, valid bool
}

func zeroVal[T any]() (z T) { return z }
func pickIf[T any](ok bool, yes, no T) T {
	if ok {
		return yes
	}
	return no
}
func orZero[T any](ok bool, v T) T { return pickIf(ok, v, zeroVal[T]()) }

// HandleStatus 只读访问器（全字段失败关闭，无效零值返回零值或 false）。
func (s HandleStatus) IsValid() bool {
	return s.valid && s.kind.IsValid() && s.id.IsValid() && s.gen > 0 && s.planDigest.IsValid() && s.binding.IsValid()
}
func (s HandleStatus) IsZero() bool                       { return !s.IsValid() }
func (s HandleStatus) Active() bool                       { return s.IsValid() && s.active }
func (s HandleStatus) Kind() plan.HandleKindCode          { return orZero(s.IsValid(), s.kind) }
func (s HandleStatus) ID() plan.HandleID                  { return orZero(s.IsValid(), s.id) }
func (s HandleStatus) Generation() uint64                 { return orZero(s.IsValid(), s.gen) }
func (s HandleStatus) PlanDigest() plan.PlanDigest        { return orZero(s.IsValid(), s.planDigest) }
func (s HandleStatus) Binding() security.OperationBinding { return orZero(s.IsValid(), s.binding) }

// hopInstance 表示池内某一特定世代（epoch >= 1）的已认证单跳传输连接实例。
// 不可变字段与原子状态支持数据面/拆断面无锁并发读取；
// activeLeases/pinnedHandles/children/planDigests/lastUsed/inActiveMap 归 DualActor 单线程独占管理。
type hopInstance struct {
	digest                        plan.HopDigest
	hopSpec                       plan.HopSpec
	epoch, parentEpoch            uint64
	parent                        *hopInstance
	conn                          ports.TransportConn
	revokeCtx                     context.Context
	revokeCancel                  context.CancelCauseFunc
	epochAtom                     atomic.Uint64
	active, closing, abortClaimed atomic.Bool
	closeOnce                     sync.Once
	closeDone                     chan struct{}
	activeLeases                  int
	pinnedHandles                 map[plan.HandleID]uint64
	children                      map[*hopInstance]struct{}
	planDigests                   map[plan.PlanDigest]struct{}
	lastUsed                      time.Time
	inActiveMap                   bool
}

func (h *hopInstance) isValidEpoch(expect uint64) bool {
	return h != nil && expect > 0 && h.active.Load() && h.epochAtom.Load() == expect
}
func (h *hopInstance) rootAncestor() *hopInstance {
	cur := h
	for cur != nil && cur.parent != nil {
		cur = cur.parent
	}
	return cur
}

// waiterState 描述单次入站租约等待器的无锁 CAS 握手状态，消除 ctx 取消与 Actor 授权间的租约泄漏窗口。
const (
	waiterWaiting int32 = iota
	waiterGranted
	waiterCanceled
)

type acquireReply struct {
	inst *hopInstance
	err  error
}
type acquireWaiter struct {
	state   atomic.Int32
	replyCh chan acquireReply
	traceID security.TraceID
	opID    algebraic.Option[security.OperationID]
}

func newAcquireWaiter(tid security.TraceID, oid algebraic.Option[security.OperationID]) *acquireWaiter {
	return &acquireWaiter{replyCh: make(chan acquireReply, 1), traceID: tid, opID: oid}
}
func (w *acquireWaiter) tryGrant(inst *hopInstance, err error) bool {
	if !w.state.CompareAndSwap(waiterWaiting, waiterGranted) {
		return false
	}
	w.replyCh <- acquireReply{inst: inst, err: err}
	return true
}
func (w *acquireWaiter) tryCancel() bool {
	return w.state.CompareAndSwap(waiterWaiting, waiterCanceled)
}

// dialInflight 记录某个 HopDigest 正在进行的单飞后台拨号状态（仅在 Actor 循环内读写）。
type dialInflight struct {
	digest            plan.HopDigest
	hopSpec           plan.HopSpec
	planDigest        algebraic.Option[plan.PlanDigest]
	parent            *hopInstance
	parentEpoch       uint64
	startedAt         time.Time
	dialCancel        context.CancelCauseFunc
	waiters           []*acquireWaiter
	parentPinReleased bool
}

type acquireKind uint8

const (
	acqFastPlan acquireKind = iota + 1 // 整链快路径命中缓存末跳
	acqHop                             // 申请或拨号单个指定跳
)

type acquireMsg struct {
	kind        acquireKind
	connPlan    plan.SealedConnectionPlan
	hopSpec     plan.HopSpec
	hopDigest   plan.HopDigest
	planDigest  algebraic.Option[plan.PlanDigest]
	parent      *hopInstance
	parentEpoch uint64
	waiter      *acquireWaiter
}

type controlKind uint8

const (
	ctrlReleaseLease controlKind = iota + 1
	ctrlDialDone
	ctrlCancelWaiter
	ctrlRetireHop
	ctrlRetirePlan
	ctrlRetireInstance
	ctrlKeepaliveFailed
	ctrlEvictIdle
	ctrlAbortRoot
	ctrlGateHalted
	ctrlPinHandle
	ctrlUnpinHandle
)

type pinHandleReply struct {
	inst *hopInstance
	err  error
}
type controlMsg struct {
	kind                 controlKind
	inst                 *hopInstance
	inflight             *dialInflight
	waiter               *acquireWaiter
	hopDigest            plan.HopDigest
	hopEpoch, handleGen  uint64
	planDigest           plan.PlanDigest
	handleID             plan.HandleID
	pinStrict, forceIdle bool
	conn                 ports.TransportConn
	err                  error
	cutoff               time.Time
	doneCh               chan struct{}
	countCh              chan int
	pinResCh             chan pinHandleReply
}
