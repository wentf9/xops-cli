// Package tui 实现 XOps v2 基于 Bubble Tea v2 的实时流式终端工作台入口层（ADR-001 / ADR-010 / Plan P5-T2）。
//
// 核心架构边界与安全不变量：
//   - 极薄入站适配器：仅依赖 core/{domain/...,events,conc,engine} 与 charm.land/{bubbletea,lipgloss}/v2，
//     物理零 internal/host/**、零 core/osfs、零 core/ports 导入，零业务域规则实现；
//   - 实时事件流投影：将 core/events（OperationStream / SystemBus 全部 12 类封闭 Event 变体）
//     与 core/engine（Projection / InventorySnapshot / StreamMetrics / StreamLogs）无阻塞投影为 tea.Msg；
//   - 结构化并发全监督：所有后台订阅、投影监听、指标/日志流与终端接管恢复均严格由 core/conc.Nursery
//     （RunScoped / RunWait）监督与排空——全包 0 裸 go 语句、0 time.Sleep 同步、0 goroutine 泄漏；
//   - 确定性终端恢复：正常退出（q）、Ctrl+C、父 ctx 取消或交互会话接管（SSH/SFTP）均先完整排空
//     Bubble Tea 事件循环与后台协程再移交/恢复终端状态，零竞态零残留。
package tui
