// Package conc 提供 XOps v2 结构化并发原语与特权后台协程监督白名单地基。
//
// 本包是全仓唯一允许使用裸 go 语句的特权白名单包，负责将所有并发生命周期收口到
// 可验证的结构化抽象中：
//   - Nursery：作用域化子协程监督器，退出时强制执行 Cancel + Wait 并聚合子任务错误与 panic。
//   - DualActor：双通道纯内存 Actor，采用两段式 select 优先排空无界环形控制队列，
//     搭配 1 缓冲非阻塞唤醒信号 controlReady、有界请求通道 acquireCh 与停机哨兵 actorDone。
//   - CtxMutex：基于容量为 1 的通道实现的可取消互斥锁，支持上下文中断与作用域闭包加锁。
package conc

import "errors"

// ErrNurseryNotInitialized 表示在未通过 NewNursery 初始化的 Nursery 实例（含 nil）上执行操作。
var ErrNurseryNotInitialized = errors.New("conc: Nursery 未初始化")

// ErrNurseryClosed 表示 Nursery 已关闭或已进入 Wait 阶段，拒绝再派生新子协程。
var ErrNurseryClosed = errors.New("conc: Nursery 已关闭或已进入 Wait，拒绝新增任务")

// ErrNilTask 表示传入的任务闭包或回调函数为 nil。
var ErrNilTask = errors.New("conc: 任务回调不能为 nil")

// ErrTaskPanicked 表示受 Nursery 监督的协程在执行过程中发生 panic。
var ErrTaskPanicked = errors.New("conc: 受监督协程发生 panic")

// ErrActorNotInitialized 表示在未通过 NewDualActor 初始化的 DualActor 实例（含 nil）上执行操作。
var ErrActorNotInitialized = errors.New("conc: DualActor 未初始化")

// ErrActorAlreadyStarted 表示同一个 DualActor 实例被重复调用 Run 启动。
var ErrActorAlreadyStarted = errors.New("conc: DualActor 已启动，禁止重复调用 Run")

// ErrActorStopped 表示 DualActor 已停止或正在停机排空，无法继续受理请求。
var ErrActorStopped = errors.New("conc: DualActor 已停止")

// ErrInvalidActorConfig 表示 NewDualActor 收到的配置参数非法（如缓冲区大小非正或缺少必需回调）。
var ErrInvalidActorConfig = errors.New("conc: DualActor 配置无效")

// ErrMutexNotInitialized 表示在未通过 NewCtxMutex 初始化的 CtxMutex 实例（含 nil）上执行操作。
var ErrMutexNotInitialized = errors.New("conc: CtxMutex 未初始化")

// ErrNilContext 表示传入的 context.Context 为 nil（所有阻塞或作用域原语均采用失败关闭策略）。
var ErrNilContext = errors.New("conc: context 不能为 nil")
