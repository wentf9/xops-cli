# Playbook 与 MCP

通过 Agent 直接执行 CLI 的方式见 [Agent Skill 与功能概览](./agent-skill)。Skill 的运维流程独立于本页介绍的 MCP 服务接入。

`--var key=value` 覆盖 YAML 同名变量，并统一用于步骤字段和外部 template 文件；CLI 新增变量也可用于模板，空值是有效覆盖。不存在的变量报错，不递归展开变量值。

## Playbook

Playbook 使用 YAML 组合 shell、script、copy、ensure 和 template 步骤。将以下内容保存为 `check-hosts.yaml`，先用只读任务验证目标选择和凭据：

```yaml
name: check-hosts
targets:
  tags: [web]
settings:
  concurrency: 2
  on_error: stop
steps:
  - name: uptime
    shell: uptime
```

```bash
xops play check-hosts.yaml
xops play --help
```

`stop` 停止当前主机的后续步骤；`abort_all` 在失败后取消其他主机任务；`continue` 允许当前主机继续后续步骤。运行前检查目标标签和提权配置。

当前源码支持 execution 配置。未配置时，MCP 和 Playbook 命令保留登录 Bash 默认；显式 server 的未知启动方言按不确定风险处理，不通过 POSIX 安全前缀自动放行。提权会应用已解析的登录选项；未支持的 server 提权或配置化 su 组合在执行前报错。脚本通过 shebang 选中 Bash 后仍须具备已知 POSIX 启动方言，不能把 cmd/PowerShell 方言丢弃后继续运行。CLI 当前可用选项见[命令执行指南](./exec)。

## MCP

```bash
xops mcp serve
```

MCP 将主机操作提供给 AI 客户端。将客户端的启动命令设为 `xops` 的完整路径，参数设为 `["mcp", "serve"]`。在配置文件的 `guardrail` 中可设置审批阈值、禁止执行的命令、受保护路径和审计日志。

stdio 模式的单次工具调用默认限时 5 分钟。长任务可在配置中设置 `mcp.tool_timeout`，例如 `30m`；到期会取消该次调用。后台 SSH 隧道使用独立的 TTL，HTTP 文件传输使用传输任务的期限。

需要审批时，在客户端表单中确认 `approved=true`。拒绝、取消或超时都会停止该操作；审批过期或操作参数改变后，需要重新确认。若客户端无法显示或提交表单，请改用支持审批的客户端。

运行前准备好凭据和已确认的主机密钥；MCP 不会显示终端认证或解锁提示。凭据不可用时，先用 `xops credential doctor` 检查存储，并恢复访问。

子命令与配置参数见 [MCP 命令参考](../reference/commands/xops-mcp)。

[局域网 HTTP 接入、客户端文件传输和恢复](mcp-http)。

stdio 模式还提供 [SSH 隧道工具](mcp-tunnels)，支持本地（`-L`）和远程（`-R`）转发的创建、查询和停止。

`xops_fs_cp` 通过 SFTP 复制：普通源链接保留为链接，目录源 `link/` 跟随目录并保留 `link` 作为目的 basename，`link/.` 则直接复制目录内容。常规文件复制到既有文件链接时更新其目标并保留链接；悬空目的文件链接会报错。路径中的空白和反斜杠都是字面字符，只有 `/` 是分隔符。
