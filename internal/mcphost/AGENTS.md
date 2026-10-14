# internal/mcphost/ — XOps CLI 的 MCP 宿主装配

- `Config.RuntimeOptions` 把 CLI 配置、凭据、日志、HTTP 选项转换为 `core/mcp/runtime` 的显式依赖，不自行实现协议、审批/工具或 SSH 状态机。
- `Config` 文档说明 HTTP/Recovery 使用启动快照，stdio 按调用读取；不得因复用代码无意统一为单一策略。
- 维护 `ports.StateSource/ExecutionGate` 的数据一致性、域 ID、版本与 Policy；不得以 display 信息代替可执行快照。
- 与 `pkg/config`, `pkg/adapter`, `core/mcp/ports`, `core/mcp/runtime`, `core/mcp/sshexec` 同时对照；更改 runtime 构建/关闭流程需要验证关闭顺序和错误返回。
- 验证：`go test ./internal/mcphost ./internal/clicontract ./core/mcp/...`；契约/schema 变化须评估旧客户端兼容性。
