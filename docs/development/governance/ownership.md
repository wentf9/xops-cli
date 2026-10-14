# XOps 功能归属速查

> 查找模块前先查此表，再用 `rg` / `go list` 追踪真实入口。目录归属是初始导航，不替代符号级确认。

| 想修改的行为 | 首选调查位置 | 先不要这样做 | 必须联动验证 |
|---|---|---|---|
| CLI 命令 flags、帮助、参数校验 | `cmd/root.go`, 对应 `cmd/*.go` | 修改 core API 来补救 CLI 参数逻辑 | `cmd`、i18n、双语文档 |
| 节点/身份/跳板选择与更新 | `pkg/config/{target,provider,repository}.go`, `cmd/host/*` | 直接更新配置 map/文件跳过 Repository | 冲突、导入/导出、引用、解析 |
| 密码/私钥引用保存、迁移 | `pkg/credential/*`, `pkg/config/*`, `internal/credentialfile/*` | 将凭据明文塞进 YAML 或打印日志 | CAS、durability、清理/恢复/跨 OS |
| SSH 连接、跳板、重连、keepalive | `core/ssh/connector.go`, `plan.go` | 在 CLI/Playbook/MCP 另造连接池 | 生命周期/并发/主机信任 |
| 单条远程命令执行与 shell 探测 | `core/ssh/command_*`, `execution_config.go`, `probe*.go` | 执行失败自动换解释器重试 | 结果分类、OS 解释器、PTY/取消 |
| 批量命令与脚本 | `cmd/exec*.go`, `pkg/playbook/*` | 不经过 core/ssh 重写执行管线 | 冻结脚本、未知结果不重试 |
| SFTP/SCP 文件传输 | `core/sftp/*`, `cmd/{scp,sftp}.go`, `cmd/sftpshell/*` | CLI 与 MCP 建平行传输语义 | 原子替换、权限、取消、恢复 |
| MCP 工具/schema | `core/mcp/runtime/*`, `core/mcp/ports/*` | 只改 schema fixture 或只改 CLI | `internal/clicontract`, MCP 客户端 |
| MCP 状态授权/审批 | `core/mcp/{state,guardrail,ports}/*` | 绕过 permit、binding、Policy | 拒绝路径、竞态、权限撤销 |
| MCP 宿主适配/HTTP 模式 | `internal/mcphost/*`, `cmd/mcp*.go` | core 读取 CLI 配置或全局 stdout | 生命周期、HTTP/stdin 差异 |
| TUI/终端输入与编辑 | `pkg/tui/*`, `cmd/sftpshell/*`, `internal/terminal/*` | 以共享核心承担终端 UI 状态 | 真实 TTY / ConPTY / Windows |
| 跨平台构建/发布 | `Makefile`, `.github/workflows/*`, `scripts/*` | 将交叉编译当原生行为验证 | Linux/Windows/macOS CI |

## 红线：三类状态必须分开

- **配置权威状态**：`pkg/config.Repository` 对磁盘及版本负责，`Provider` 提供内存读快照。
- **连接/执行状态**：`core/ssh.Connector` 与执行计划/连接租约负责连接、会话、回收；在 `core/mcp` 中还必须额外经过 operation permit。
- **任务/授权状态**：MCP 的 binding、permit、transfer journal 与审批是另一组生命周期；仅有 SSH 连接并不意味着被授权执行。

交叉修改这些状态之前应绘制时序图并做失败路径检查。
