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
xops mcp --help
```

MCP 将主机操作提供给 AI 客户端，配合策略、审批与审计控制使用。不要因为启用了 MCP 就默认允许全部命令。无交互路径需要可非交互访问的凭据；配置的引用不可用时应修复凭据后端，而非绕过失败。

子命令与配置参数见 [MCP 命令参考](../reference/commands/xops-mcp)，开发背景见[开发资料](../development/)。
