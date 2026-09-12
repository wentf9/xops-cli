# Playbook 与 MCP

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

## MCP

```bash
xops mcp serve
```

MCP 将主机操作提供给 AI 客户端。将客户端的启动命令设为 `xops` 的完整路径，参数设为 `["mcp", "serve"]`。在配置文件的 `guardrail` 中可设置审批阈值、禁止执行的命令、受保护路径和审计日志。

运行前准备好凭据和已确认的主机密钥；MCP 不会显示终端认证或解锁提示。凭据不可用时，先用 `xops credential doctor` 检查存储，并恢复访问。

子命令与配置参数见 [MCP 命令参考](../reference/commands/xops-mcp)。
