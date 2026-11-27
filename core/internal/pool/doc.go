// Package pool 实现 XOps v2 彻底解耦的双通道纯内存 Actor Merkle 连接池（ADR-009 / Plan P2-T5）。
//
// 本包物理封锁在 core/internal/pool 下，严禁导入 core/internal/sshnet/**、core/osfs 与
// core/internal/gate，仅依赖 core/ports、core/domain/**、core/events、core/conc 与
// core/internal/foundation/{actor,trace}（生产拨号适配器由 core/engine 注入，DST 由 sim 注入）。
//
// 核心并发与安全不变量（ADR-009 / INV-C1..C3）：
//   - 双通道纯内存非阻塞 Actor：基于 actor.DualActor 的有界请求通道 acquireCh 与永不阻塞控制队列
//     controlCh（两段式 select 始终优先排空控制消息），Actor 主循环 100% 纯内存非阻塞，
//     所有网络拨号、保活探测与连接拆断均在 Actor 外部由 core/conc.Nursery 监督执行（0 裸 go）；
//   - 控制面与数据面彻底分离：租约 Lease 借出后，数据面操作（OpenSession/DialTCP/ListenTCP/
//     OpenRemoteFS）仅做无锁原子 Epoch 与失效哨兵校验，不触碰 Actor 循环；
//   - 归还防挂起：所有 ReleaseLease 控制回传均通过 DualActor.SendControl 监听 actorDone，
//     在邮箱满载或连接池关闭后绝不挂起；
//   - 全局单层非重入租约作用域：trace.LeaseScope 仅在即将进入用户回调 fn(scopedCtx, ...) 前注入，
//     绝不在池内多跳 DAG 拨号前注入，避免内部多跳解析误触 ErrReentrantLease；
//   - 严格 Merkle 缓存键、父代 Epoch CAS 与 90ms 有界拆断：按 HopDigest 共享公共跳板前缀，
//     子跳发布强制核验父代实例与精确世代（拒绝陈旧拨号毒化池），连接拆断统一基于注入的
//     ports.Clock 执行 90ms 宽限期并在超时后以单赢者 CAS 升级拆断卡死根跳板；
//   - 世代 SlotMap 与 GateHalted 熔断：通过封闭幻影类型 plan.ManagedHandle[K] 托管跨请求长会话，
//     接收来自 gate.OnHaltFunc 的 GateHalted 通知后立即原子吊销全部活跃租约与托管句柄、
//     触发有界拆断并使后续一切申请失败关闭。
package pool

import (
	"time"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

const (
	// DefaultAcquireBuffer 是 DualActor 有界请求通道 acquireCh 的默认容量。
	DefaultAcquireBuffer = 64
	// DefaultTeardownGrace 是连接拆断默认宽限时长（90ms，INV-C3 / ADR-009）。
	DefaultTeardownGrace = 90 * time.Millisecond
	// DefaultDomain 是未显式指定 LeaseScope 诊断归属标签时的默认域名。
	DefaultDomain = "pool"
)

// 本包导出的不可变哨兵错误，供用例服务、引擎、仿真测试与调用方通过 errors.Is 精确匹配。
var (
	// ErrPoolNotInitialized 表示在 nil 或零值未初始化的 Pool 实例上执行操作。
	ErrPoolNotInitialized = domi18n.Sentinel(domi18n.KeyPoolNotInitialized)
	// ErrInvalidPoolConfig 表示 NewPool 收到的配置项或依赖端口无效。
	ErrInvalidPoolConfig = domi18n.Sentinel(domi18n.KeyPoolInvalidConfig)
	// ErrPoolClosed 表示连接池已关闭，拒绝继续受理租约申请或句柄操作。
	ErrPoolClosed = domi18n.Sentinel(domi18n.KeyPoolClosed)
	// ErrGateHalted 表示能力门控已触发 Halted 熔断，连接池拒绝全部申请并吊销既有资源。
	ErrGateHalted = domi18n.Sentinel(domi18n.KeyPoolGateHalted)
	// ErrNilContext 表示传入的 context.Context 为 nil（拒绝隐式回退到 Background）。
	ErrNilContext = domi18n.Sentinel(domi18n.KeyPoolNilContext)
	// ErrNilCallback 表示作用域闭包回调 fn 为 nil。
	ErrNilCallback = domi18n.Sentinel(domi18n.KeyPoolNilCallback)
	// ErrInvalidPlan 表示传入的 SealedConnectionPlan 或摘要无效。
	ErrInvalidPlan = domi18n.Sentinel(domi18n.KeyPoolInvalidPlan)
	// ErrEmptyPlanList 表示 WithMultiLease 传入的计划列表为空。
	ErrEmptyPlanList = domi18n.Sentinel(domi18n.KeyPoolEmptyPlanList)
	// ErrPoolCapacityExceeded 表示活跃连接与在途拨号数已达 MaxConns 上限且无可驱逐空闲叶子连接。
	ErrPoolCapacityExceeded = domi18n.Sentinel(domi18n.KeyPoolCapacityExceeded)
	// ErrParentEpochChanged 表示多跳拨号完成时上游父跳板已被替换、退役或失活，父代 Epoch CAS 拒绝发布。
	ErrParentEpochChanged = domi18n.Sentinel(domi18n.KeyPoolParentEpochChanged)
	// ErrInvalidTransportConn 表示 DialerPort 返回了 nil、失活或摘要不匹配的 TransportConn。
	ErrInvalidTransportConn = domi18n.Sentinel(domi18n.KeyPoolInvalidTransportConn)
	// ErrLeaseInvalid 表示在 nil 或零值未初始化的 Lease 上执行操作。
	ErrLeaseInvalid = domi18n.Sentinel(domi18n.KeyPoolLeaseInvalid)
	// ErrLeaseExpired 表示作用域借用租约已在回调退出后失效（运行时借用失效哨兵）。
	ErrLeaseExpired = domi18n.Sentinel(domi18n.KeyPoolLeaseExpired)
	// ErrLeaseRevoked 表示租约绑定的底层传输连接已被驱逐、退役或拆断。
	ErrLeaseRevoked = domi18n.Sentinel(domi18n.KeyPoolLeaseRevoked)
	// ErrHopRetired 表示该跳传输连接已退役。
	ErrHopRetired = domi18n.Sentinel(domi18n.KeyPoolHopRetired)
	// ErrTeardownEscalated 表示子跳连接关闭超过 90ms 宽限期，已升级拆断上游根跳板连接。
	ErrTeardownEscalated = domi18n.Sentinel(domi18n.KeyPoolTeardownEscalated)
	// ErrInvalidResource 表示注册至世代 SlotMap 的托管资源为 nil 或无效。
	ErrInvalidResource = domi18n.Sentinel(domi18n.KeyPoolInvalidResource)
	// ErrInvalidHandle 表示传入的 ManagedHandle 为零值或字段不合法。
	ErrInvalidHandle = domi18n.Sentinel(domi18n.KeyPoolInvalidHandle)
	// ErrHandleNotFound 表示指定 HandleID 不存在于活跃 SlotMap 中（未登记或已被释放/回收）。
	ErrHandleNotFound = domi18n.Sentinel(domi18n.KeyPoolHandleNotFound)
	// ErrHandleRevoked 表示托管句柄在借用上下文存活期间或进入回调前被吊销（见 context.Cause(scopedCtx) 与回调前置门控）；
	// 槽位摘除后的后续查找将返回 ErrHandleNotFound（池关闭/熔断时返回 ErrPoolClosed / ErrGateHalted）。
	ErrHandleRevoked = domi18n.Sentinel(domi18n.KeyPoolHandleRevoked)
	// ErrHandleGenerationMismatch 表示句柄携带的世代号与当前槽位世代不匹配（拒绝陈旧句柄复用）。
	ErrHandleGenerationMismatch = domi18n.Sentinel(domi18n.KeyPoolHandleGenMismatch)
	// ErrHandleBindingMismatch 表示句柄的类别、PlanDigest 或 OperationBinding 与登记槽位不一致。
	ErrHandleBindingMismatch = domi18n.Sentinel(domi18n.KeyPoolHandleBindMismatch)
	// ErrHandleTypeMismatch 表示槽位内托管资源的实际类型与调用方期望类型 R 不匹配。
	ErrHandleTypeMismatch = domi18n.Sentinel(domi18n.KeyPoolHandleTypeMismatch)
	// ErrHandleLimitExceeded 表示活跃托管句柄数已达 MaxHandles 上限。
	ErrHandleLimitExceeded = domi18n.Sentinel(domi18n.KeyPoolHandleLimitExceeded)
)
