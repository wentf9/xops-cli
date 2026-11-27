// Package conc 提供 XOps v2 结构化并发原语，是 core/ 的极简公开契约包之一，
// 也是全仓唯一允许使用裸 go 语句的特权白名单包。
//
// 本包负责将全部并发协程生命周期收口到可静态验证、零泄漏的结构化抽象中：
//   - Nursery：作用域化子协程监督器，提供 RunWait（Fork-Join：等待全部子任务自然退出后再释放取消）
//     与 RunScoped（守护/Watchdog：退出时无条件先取消再等待，并精准过滤正常退场时的裸预期取消错误），
//     同时自动捕获子任务与作用域闭包中的 panic 并聚合错误。
//   - CtxMutex：基于容量为 1 的通道实现的可取消互斥锁，支持上下文中断与作用域闭包加锁。
//
// 注意：双通道纯内存 Actor（DualActor）不包含任何裸 go 语句，物理封锁于
// core/internal/foundation/actor，不暴露在本包公开契约面中。
package conc

import "errors"

// ErrNurseryNotInitialized 表示在未通过 NewNursery 初始化的 Nursery 实例（含 nil）上执行操作。
var ErrNurseryNotInitialized = errors.New("conc: nursery is not initialized")

// ErrNurseryClosed 表示 Nursery 已关闭或已进入 Wait 阶段，拒绝再派生新子协程。
var ErrNurseryClosed = errors.New("conc: nursery is closed or waiting and rejects new tasks")

// ErrNilTask 表示传入的任务闭包或回调函数为 nil。
var ErrNilTask = errors.New("conc: task callback must not be nil")

// ErrTaskPanicked 表示受 Nursery 监督的协程或作用域闭包在执行过程中发生 panic。
var ErrTaskPanicked = errors.New("conc: supervised goroutine panicked")

// ErrMutexNotInitialized 表示在未通过 NewCtxMutex 初始化的 CtxMutex 实例（含 nil）上执行操作。
var ErrMutexNotInitialized = errors.New("conc: CtxMutex is not initialized")

// ErrNilContext 表示传入的 context.Context 为 nil（所有阻塞或作用域原语均采用失败关闭策略）。
var ErrNilContext = errors.New("conc: context must not be nil")
