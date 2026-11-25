package pool

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/ports"
)

// PoolConfig 定义连接池 Pool 的运行期初始化配置（纯内存构造参数，非持久化 DTO）。
// 其中 Dialer、Clock 与 Entropy 为必需依赖；Clock 与 Entropy 经接口注入以确保 P2-T6 仿真完全确定性。
type PoolConfig struct {
	// Dialer 为协议无关的 SSH 单跳/多跳拨号出站端口（必需）。
	Dialer ports.DialerPort
	// Clock 为时钟与定时器出站端口，驱动 90ms 有界拆断、保活与空闲回收（必需）。
	Clock ports.Clock
	// Entropy 为并发安全的显式熵源（满足 io.Reader），用于生成 HandleID 与池级 TraceID（必需）。
	Entropy ports.Entropy
	// Bus 为可选系统诊断事件总线（nil 表示不发布系统事件；非 nil 时必须处于已初始化未关闭状态）。
	Bus *events.SystemBus
	// Domain 为 trace.LeaseScope 诊断归属标签（为空时默认 "pool"；仅用于诊断，不豁免跨池重入）。
	Domain string
	// AcquireBuffer 为 DualActor 有界请求通道 acquireCh 容量（0 使用默认值 DefaultAcquireBuffer）。
	AcquireBuffer int
	// MaxConns 为池内活跃连接与在途拨号总数上限（0 表示不设额外上限，负值非法）。
	MaxConns int
	// MaxHandles 为世代 SlotMap 活跃托管句柄上限（0 表示不设额外上限，负值非法）。
	MaxHandles int
	// TeardownGrace 为连接拆断宽限时长（0 使用默认值 DefaultTeardownGrace=90ms，负值非法）。
	TeardownGrace time.Duration
	// IdleTTL 为空闲叶子连接过期回收时长（0 表示禁用后台定时空闲扫描，负值非法）。
	IdleTTL time.Duration
	// DefaultKeepaliveInterval 为 HopSpec 未指定 ServerAliveInterval 时的保活回退间隔（0 表示不启用，负值非法）。
	// 连续保活失败阈值一律严格遵循 HopSpec.Transport().ServerAliveCountMax()（显式 0 按首次超时/失败即退役处理）。
	DefaultKeepaliveInterval time.Duration
}

// PoolStats 提供连接池当前的无锁并发安全运行期统计快照。
type PoolStats struct {
	ActiveConns         int
	DialingConns        int
	ActiveLeases        int64
	ActiveHandles       int
	TotalDials          uint64
	DialErrors          uint64
	CacheHits           uint64
	ParentCASRejections uint64
	TeardownCompleted   uint64
	TeardownEscalations uint64
	Halted              bool
	Closed              bool
}

// HandleStatus 表示世代 SlotMap 中某个托管句柄的不可变只读状态快照；零值恒无效并失败关闭。
//
//xops:opaque
//xops:failclosed
type HandleStatus struct {
	kind       plan.HandleKindCode
	id         plan.HandleID
	gen        uint64
	planDigest plan.PlanDigest
	binding    security.OperationBinding
	active     bool
	valid      bool
}

func zeroVal[T any]() (z T) { return z }

// HandleStatus 只读访问器（全字段失败关闭，无效零值返回零值或 false）。
func (s HandleStatus) IsValid() bool {
	return s.valid && s.kind.IsValid() && s.id.IsValid() && s.gen > 0 && s.planDigest.IsValid() && s.binding.IsValid()
}
func (s HandleStatus) IsZero() bool { return !s.IsValid() }
func (s HandleStatus) Active() bool { return s.IsValid() && s.active }
func (s HandleStatus) Kind() plan.HandleKindCode {
	if !s.IsValid() {
		return plan.HandleKindInvalid
	}
	return s.kind
}
func (s HandleStatus) ID() plan.HandleID {
	if !s.IsValid() {
		return zeroVal[plan.HandleID]()
	}
	return s.id
}
func (s HandleStatus) Generation() uint64 {
	if !s.IsValid() {
		return 0
	}
	return s.gen
}
func (s HandleStatus) PlanDigest() plan.PlanDigest {
	if !s.IsValid() {
		return zeroVal[plan.PlanDigest]()
	}
	return s.planDigest
}
func (s HandleStatus) Binding() security.OperationBinding {
	if !s.IsValid() {
		return zeroVal[security.OperationBinding]()
	}
	return s.binding
}

// hopInstance 表示池内某一特定世代（epoch >= 1）的已认证单跳传输连接实例。
//
// 并发所有权切分：
//   - 不可变字段（digest/hopSpec/epoch/parent/parentEpoch/conn/revokeCtx/revokeCancel/closeDone）在发布后只读，
//     数据面、保活协程（直接绑定 revokeCtx）与拆断协程可完全无锁并发读取；
//   - 原子字段（epochAtom/active/closing/abortClaimed）与 closeOnce 支持控制面与拆断面无锁并发协调；
//   - Actor 独占字段（activeLeases/children/lastUsed/inActiveMap/planDigests）仅允许在
//     DualActor 单线程循环（及停机收尾阶段）内读写，零互斥锁竞争。
type hopInstance struct {
	digest      plan.HopDigest
	hopSpec     plan.HopSpec
	epoch       uint64
	parent      *hopInstance
	parentEpoch uint64
	conn        ports.TransportConn

	revokeCtx    context.Context
	revokeCancel context.CancelCauseFunc

	epochAtom    atomic.Uint64 // 数据面无锁原子世代读视图（与 epoch 同步初始化，退役/吊销清零）
	active       atomic.Bool
	closing      atomic.Bool
	abortClaimed atomic.Bool
	closeOnce    sync.Once
	closeDone    chan struct{}

	// 以下字段归 DualActor 单线程独占管理。
	activeLeases int
	children     map[*hopInstance]struct{}
	planDigests  map[plan.PlanDigest]struct{}
	lastUsed     time.Time
	inActiveMap  bool
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

// waiterState 描述单次入站租约等待器的无锁 CAS 握手状态，彻底消除 ctx 取消与 Actor 授权间的租约泄漏窗口。
const (
	waiterWaiting  int32 = 0
	waiterGranted  int32 = 1
	waiterCanceled int32 = 2
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
	return &acquireWaiter{
		replyCh: make(chan acquireReply, 1),
		traceID: tid,
		opID:    oid,
	}
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

// dialInflight 记录某个 HopDigest 正在进行的单飞（single-flight）后台拨号状态（仅在 Actor 循环内读写）。
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

// acquireKind 区分通过有界 acquireCh 投递的请求类别。
type acquireKind uint8

const (
	acqFastPlan acquireKind = iota + 1 // 尝试单次命中整条已缓存且祖先链全存活的末跳计划
	acqHop                             // 申请或拨号单个指定跳（可携带父代实例与世代）
)

// acquireMsg 为 DualActor 请求通道 acquireCh 的内部消息载体。
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

// controlKind 区分通过永不阻塞 controlCh 投递的高优先级控制消息类别。
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
)

// controlMsg 为 DualActor 永不阻塞控制队列 controlCh 的内部消息载体。
type controlMsg struct {
	kind       controlKind
	inst       *hopInstance
	inflight   *dialInflight
	waiter     *acquireWaiter
	hopDigest  plan.HopDigest
	planDigest plan.PlanDigest
	conn       ports.TransportConn
	err        error
	cutoff     time.Time
	forceIdle  bool
	doneCh     chan struct{}
	countCh    chan int
}
