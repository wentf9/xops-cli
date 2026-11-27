// Package mcpruntime 实现 XOps v2 MCP（Model Context Protocol）协议运行时与双传输引擎
// （stdio JSON-RPC 2.0 + Streamable HTTP + 10 GiB HTTP 流式传输，ADR-006 / ADR-007 / ADR-008 / Plan P3-T5）。
//
// 核心安全与架构不变量：
//   - 双模态 FS 物理隔离（ADR-007）：本包及全部子包物理禁止引用 ports.OperatorReadFS
//     （由 xopsvet/archbound 强制），所有本地文件读写均仅通过基于 os.Root 的 ports.ScopedRootFS 完成；
//   - 严格六边形解耦：严禁导入 core/internal/pool、core/internal/sshnet/** 或 core/osfs，
//     全部业务操作均经 usecase/* 与 gate.Authorizer 执行；
//   - 启动期自动对账与恢复：ServeStdio / ServeHTTPListener / ListenAndServeHTTP 均在放行任何入站请求前
//     自动执行 O(1) 崩溃审计对账（Gate reconciler）与传输日志恢复（TransferService.RecoverAllTransfers），
//     遇存储/门控故障严格 Fail-Closed，对 TransferUncertainCommit 忠实记录且保持零副作用；
//   - StrictAgentProfile + Halted 熔断：任一 AuditPostWriteError 触发 Gate.IsHalted() 后，
//     全部 JSON-RPC 方法、7 个判别式工具与 HTTP 流式传输端点均立即拒绝新请求；
//   - 全部后台协程受 core/conc.Nursery 监督（0 裸 go、0 goleak、0 init()、0 可变包级 var、0 nolint 豁免）。
package mcpruntime

import domi18n "github.com/wentf9/xops-cli/core/domain/i18n"

// 本包导出的不可变哨兵错误，供 core/engine、entry/mcpcmd 与测试经 errors.Is 精确区分运行期故障。
var (
	// ErrInvalidConfig 表示 ServerConfig 缺少必填依赖或限流/超时参数非法。
	ErrInvalidConfig = domi18n.Sentinel(domi18n.KeyMCPInvalidConfig)
	// ErrServerNotInitialized 表示在 nil 或零值未初始化 Server 上调用方法。
	ErrServerNotInitialized = domi18n.Sentinel(domi18n.KeyMCPServerNotInit)
	// ErrServerClosed 表示 MCP Server 已关闭，拒绝新请求或启动传输。
	ErrServerClosed = domi18n.Sentinel(domi18n.KeyMCPServerClosed)
	// ErrNonLoopbackAddress 表示在未显式允许非回环监听时传入了非回环 HTTP 监听地址。
	ErrNonLoopbackAddress = domi18n.Sentinel(domi18n.KeyMCPNonLoopback)
	// ErrMessageTooLarge 表示入站 JSON-RPC 报文超出最大允许字节上限。
	ErrMessageTooLarge = domi18n.Sentinel(domi18n.KeyMCPMessageTooLarge)
	// ErrStartupReconcileFailed 表示启动期 O(1) 崩溃审计对账失败，严格 Fail-Closed 拒绝启动服务。
	ErrStartupReconcileFailed = domi18n.Sentinel(domi18n.KeyMCPStartupReconcile)
	// ErrStartupRecoveryFailed 表示启动期传输 Journal 恢复遇到基础设施或损坏故障，拒绝启动服务。
	ErrStartupRecoveryFailed = domi18n.Sentinel(domi18n.KeyMCPStartupRecovery)
)
