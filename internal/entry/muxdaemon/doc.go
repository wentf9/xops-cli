// Package muxdaemon 实现 XOps v2 极薄 ControlMaster / ControlPersist 守护进程入站入口
// （ADR-001 / ADR-009 / ADR-011 / Phase 5 P5-T3）。
//
// 核心工程与安全不变量：
//   - 仅依赖 core/{domain,conc,engine} 与 Go 标准库，零引用 internal/host/**、core/osfs 与 core/ports；
//   - 全部生命周期监督与响应式退出监听（ControlMasterInfo.Done/Wait、ForwardInfo.Done/Wait）
//     严格受 core/conc.Nursery 托管，零裸 go、零轮询、零 time.Sleep；
//   - 严格尊重 !ControlMasterInfo.ReusedExisting() 守卫：绝不关闭外部既有 ControlMaster；
//   - 停机阶段按「已启动转发（逆序）-> 自建 ControlMaster」确定性逆序排空，采用剥离取消的有限超时上下文，
//     如实通过 errors.Join 向上暴露清理失败（仅容忍已自退出句柄自动回收产生的 ErrHandleNotFound/ErrHandleRevoked）；
//   - 全包零 init()、零可变包级状态、零 //nolint:、零裸 time.Duration 配置字段。
package muxdaemon

import "errors"

// 本包导出的不可变规范哨兵错误，便于组合根与调用方通过 errors.Is 区分配置或入参错误。
var (
	ErrNilContext    = errors.New("muxdaemon: context 不能为 nil")
	ErrInvalidConfig = errors.New("muxdaemon: 无效的 muxdaemon 配置")
)
