# Playbook 与 MCP

XOps 提供 YAML 声明式任务编排（`xops play`）和内置 Model Context Protocol 服务端（`xops mcp`）。

> 若希望让支持 Skill 的 AI 助手在本地直接调用 `xops` CLI 完成运维操作（无需启动 MCP 服务），请参阅 [Agent Skill 与功能概览](./agent-skill)。

## Playbook 声明式编排

Playbook 使用 YAML 编排多台主机上的自动化步骤，支持 `shell`（执行命令）、`script`（分发执行本地脚本）、`copy`（上传文件）、`ensure`（状态检查与幂等收敛）和 `template`（渲染配置模板）。

### 1. 快速上手示例

创建 `deploy-service.yaml`：

```yaml
name: deploy-service
targets:
  tags: [web]
settings:
  concurrency: 5
  on_error: stop
  execution:
    interpreter: bash
    launch_dialect: posix
    login: true
vars:
  http_port: "8080"
steps:
  - name: 检查系统运行时间
    shell: uptime

  - name: 确保 Nginx 已安装
    ensure:
      check: "nginx -v"
      action: "apt-get update && apt-get install -y nginx"
    sudo: true

  - name: 渲染并分发配置文件
    template:
      src: "./nginx.conf.tmpl"
      dest: "/etc/nginx/nginx.conf"
    sudo: true

  - name: 重启服务
    shell: "systemctl restart nginx"
    sudo: true
```

运行与调试命令：

```bash
# 预览目标主机与执行步骤（不连接远端、不执行任何更改）
xops play deploy-service.yaml --dry-run

# 正式运行 Playbook
xops play deploy-service.yaml

# 命令行注入或覆盖变量（未定义的模板变量会在执行前报错）
xops play deploy-service.yaml --var http_port=8081

# 仅在指定节点列表上执行
xops play deploy-service.yaml --limit web-01,web-02
```

### 2. 失败策略、重试与执行配置

- **失败控制（`settings.on_error`）**：
  - `stop`（默认）：出错主机停止后续步骤，其他并行主机继续执行。
  - `abort_all`：任一主机连接失败或步骤失败时，立即取消所有其他正在运行的主机任务。
  - `continue`：当前主机忽略该步骤错误，继续执行后续步骤。
- **安全重试边界**：步骤配置 `retries` 后，仅当远端命令**确认已执行完毕且无 I/O 或通道清理错误**时才会按 `retry_delay` 重试；若连接中断导致远端执行结果不确定（`unknown`），XOps 绝不自动重放，避免重复产生副作用。本地脚本内容在任务开始前一次性读取并冻结。
- **执行环境继承（`execution`）**：支持在步骤级 `step.execution`、全局 `settings.execution` 或节点配置中指定 `interpreter`（如 `bash`、`sh`、`zsh`、`fish`、`powershell`、`pwsh`、`cmd`、`server`）与 `launch_dialect`。

### 3. `script` 与 `ensure` 按需探测及状态码规则

当未指定解释器且启动方言未知时，**无 shebang 的 `script` 步骤**和 **`ensure` 步骤**会在运行用户代码前自动发起一次有界只读探测（同一连接共享缓存，不改写磁盘配置，也不影响普通 `shell` 步骤的默认 `server` 直通）：
- **支持范围**：`script` 与 `ensure` 支持 `bash`、`sh`、`zsh` 和原生 `fish`（外层启动方言须为 `posix` 或 `fish`）。若探测到 Windows 环境，会在执行用户代码前直接报错拒绝，不做跨平台语法翻译。显式解释器（含 `server`）、UTF-8 BOM 和非白名单 shebang 不会被自动替换；白名单 shebang 仍需已知兼容的外层方言。
- **`ensure` 收敛与保留退出码保护**：
  - `ensure` 先运行 `check`：返回 `0` 则判定满足条件并跳过 `action`（`StatusSkipped`）；确认返回普通非零状态（如 `false` 返回 `1`）时执行 `action`，随后再次运行 `check` 复查（`check`、`action`、复查全程冻结使用同一执行配置）。
  - **异常退出码拦截**：若 `check` 返回保留错误码 `126`/`127`（命令不可执行或未找到）、fish 保留错误码 `121`/`123`/`124`/`125`、发生语法错误、超时、断连或丢失控制帧（例如在 `check` 中调用 `exec` 替换了 Shell 进程），均直接判定步骤失败（`StatusFailed`），**严禁触发 `action`**。

## MCP 服务接入

XOps 内置 MCP 服务端，可供 Claude Desktop、Cursor、Codex 等 AI 客户端调用受控的主机查询、远程命令、文件传输与 SSH 隧道工具。

```bash
# 启动默认 stdio 模式 MCP 服务
xops mcp serve
```

### 1. 客户端接入与安全护栏

在 AI 客户端的 MCP 配置中，将启动命令设为 `xops` 的绝对路径，参数设为 `["mcp", "serve"]`。

在 `~/.xops/xops_config.yaml` 的 `guardrail` 字段中可配置审批阈值、高危命令拦截、受保护文件路径和审计日志路径：
- **操作审批**：当工具调用达到需审批的风险级别时，客户端会弹出审批请求（需确认 `approved=true`），拒绝、取消或超时均不会执行远端操作。
- **默认超时与非交互凭据**：单次工具调用默认超时为 5 分钟（可通过 `mcp.tool_timeout` 调整，如 `30m`）。MCP 全程运行在非交互模式下，不会弹出终端密码提示或密钥环解锁窗口，启动前可用 `xops credential doctor` 检查凭据可用性。

### 2. 进阶指南与参考

- [MCP 命令参考](../reference/commands/xops-mcp)
- [MCP HTTP 局域网接入、大文件传输与异常恢复](./mcp-http)
- [MCP stdio SSH 隧道工具（`-L` / `-R`）](./mcp-tunnels)
