// Package actor 提供 XOps v2 核心内部专用的双通道纯内存并发调度原语（DualActor）。
//
// 本包物理封锁在 core/internal/foundation/actor 下，遵守以下工程不变量：
//   - 零裸 go 语句：Actor 主循环由调用方在 core/conc.Nursery 监督下驱动；
//   - 100% 纯内存非阻塞：禁止导入任何文件/网络/系统 I/O 包与外部第三方依赖；
//   - 双通道优先级与发送者屏障：控制面采用无界环形队列 + 1 缓冲唤醒通道永不阻塞发送方，
//     请求面采用有界通道提供背压并经 acqMu/acqClosed/acqSenders 屏障保证停机排空零丢请求。
package actor

import domi18n "github.com/wentf9/xops-cli/core/domain/i18n"

// ErrActorNotInitialized 表示在未通过 NewDualActor 初始化的 DualActor 实例（含 nil）上执行操作。
var ErrActorNotInitialized = domi18n.Sentinel(domi18n.KeyActorNotInitialized)

// ErrActorAlreadyStarted 表示同一个 DualActor 实例被重复调用 Run 启动。
var ErrActorAlreadyStarted = domi18n.Sentinel(domi18n.KeyActorAlreadyStarted)

// ErrActorStopped 表示 DualActor 已停止或正在停机排空，无法继续受理请求。
var ErrActorStopped = domi18n.Sentinel(domi18n.KeyActorStopped)

// ErrInvalidActorConfig 表示 NewDualActor 收到的配置参数非法（如缓冲区大小非正或缺少必需回调）。
var ErrInvalidActorConfig = domi18n.Sentinel(domi18n.KeyActorInvalidConfig)

// ErrNilContext 表示传入的 context.Context 为 nil（拒绝隐式回退到 Background）。
var ErrNilContext = domi18n.Sentinel(domi18n.KeyActorNilContext)
