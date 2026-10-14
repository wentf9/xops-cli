# core/mcp/ — MCP 契约、授权与执行（高风险）

必读 `core/README.md` 的 MCP 概览、`core/mcp/state/README.md`、`docs/development/mcp-http-transfer-design.md`。

- `ports/` 定义宿主 `StateSource`、`ExecutionGate`、`Backend`、`Audit` 等契约；`sshexec/` 实现依赖这些契约的 SSH/SFTP 适配；`runtime/` 负责 MCP 工具/协议与调用编排。
- `guardrail/` 的审批、路径策略与风险分析不得绕过。审计事件属于操作语义的一部分。
- 每次操作应保留 snapshot/binding/permit 关系，不将显示级 NodeInfo 当成可执行授权，不以计划摘要代替许可。
- `state/Coordinator` 的 `BeginUpdate -> BeginPersistence -> ConfirmCommit/ConfirmRollback -> Publish` 为敏感序列；未知提交结果不得重试事务或宣称激活成功。
- 传输任务包含独立 journal/lease/authorization 与阶段转移；不能直接重试未知提交状态；跨阶段容量交接需保留原 permit/binding/operation ID 一致性。
- HTTP 与 stdio 语义不同；修改 token、origin、host admission、streaming、审批回调、文件路径绑定时必须测试拒绝路径、并发取消、恢复与错误处理。
- `core/mcp/runtime/*` 或 `core/mcp/ports/*` 修改同时检查 `internal/mcphost` 与 `internal/clicontract` 的回归和 schema fixture；需显式批准时才能刷新协议基线。
- 常用验证：`go test ./core/mcp/... ./internal/mcphost ./internal/clicontract`；并发/状态修改再执行受影响包的 `-race` 测试和 core 隔离检查。
