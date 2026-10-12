# Playbook 与 MCP

XOps 提供了面向运维工程师的声明式任务编排（Playbook）以及面向 AI Agent 的工具调用服务（MCP），帮助您实现基础设施的自动化管理。

通过 Agent 直接执行 CLI 的方式见 [Agent Skill 与功能概览](./agent-skill)。Skill 的运维流程独立于本页介绍的 MCP 服务接入。

## Playbook 声明式编排

Playbook 使用 YAML 格式定义任务流程，支持组合 `shell`、`script`、`copy`、`ensure`（状态收敛）和 `template`（配置渲染）步骤，并提供主机并发控制与失败策略。

### 示例 Playbook

将以下内容保存为 `deploy-service.yaml`：

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

运行 Playbook：

```bash
# 执行 Playbook
xops play deploy-service.yaml

# 通过命令行参数覆盖变量
xops play deploy-service.yaml --var http_port=8081

# 仅进行试运行预览（Dry Run）
xops play deploy-service.yaml --dry-run

# 将执行范围限制到特定主机
xops play deploy-service.yaml --limit web-01
```

### 失败处理与变量控制

- **失败处理策略 (`on_error`)**：
  - `stop`（默认）：当前主机停止执行后续步骤，其他主机不受影响；
  - `abort_all`：一旦任意主机失败，立即取消所有其他主机的任务；
  - `continue`：当前主机忽略错误，继续执行后续步骤。
- **变量覆盖 (`--var key=value`)**：命令行指定的变量会优先覆盖 YAML 内同名变量，并可被模板文件和步骤命令引用；未定义变量会导致解析报错。
- **执行环境定制 (`execution`)**：
  - 可以在 `settings.execution` 中声明全局默认解释器（如 `bash`、`powershell`、`cmd` 或 `server`）；
  - 也可以在单个步骤中通过 `execution` 覆盖（例如针对 Windows 节点的步骤使用 `interpreter: cmd`）；
  - 步骤未配置时，依次继承 Playbook 设置、目标节点配置或系统默认。

### Playbook 按需探测

未指定解释器且启动方言未知时，无 shebang 的 `script` 和 `ensure` 会在执行用户代码前进行有界只读
探测，同一 SSH 连接只探测一次，失败结果也会缓存。结果仅用于本次受限操作，不改写节点配置或普通
`shell` 步骤的默认执行方式。显式解释器（包括 `server`）、BOM 和未支持的 shebang 不会被自动替换。
白名单 bash/sh/zsh/fish shebang 仍不能证明外层方言，需已有兼容配置。

script/ensure 支持 bash、sh、zsh 和原生 fish，外层启动方言可为 posix 或 fish。探测到 Windows 时会在执行用户代码前明确拒绝，不会翻译
脚本或 ensure 检查语法。ensure 的检查、action 和复查使用同一受控配置；探针失败不会执行 action，
也不会触发用户命令重试。试运行不连接远端、不运行探针。

fish ensure 在 fish 中执行 check、action 与复查，并通过退出事件捕获检查状态，包括显式 `exit`。检查通过时跳过 action；确认非零状态后才执行 action 并复查。126/127、fish 保留的执行错误码 121/123/124/125、语法错误、超时、断连或缺少结果帧都会停止流程；检查中的 `exec` 替换进程会绕过退出事件，因此会作为缺少结果帧处理。默认 fish 的自动探测结果会直接用于此流程。

这些保留退出码即使由检查程序显式返回，也不会触发 action：无法区分用户返回值与展开失败、不可执行等错误时，按检查失败处理。普通条件不满足（如 `false` 返回 1）仍按原流程执行 action 与复查。

## MCP 服务集成

```bash
xops mcp serve
```

XOps 内置了符合 Model Context Protocol 标准的服务端，可供 Claude Desktop、Cursor 等支持 MCP 的 AI 客户端无缝调用。

### 客户端接入配置

将 AI 客户端中的 MCP 服务器启动命令配置为 `xops` 的绝对路径，参数设置为 `["mcp", "serve"]`。

在配置文件 `~/.xops/xops_config.yaml` 的 `guardrail` 中可设置安全审批阈值、禁止执行的命令、受保护的文件路径与审计日志输出。

### 工具超时与长任务处理

- **调用超时控制**：stdio 模式的单次工具调用默认时限为 5 分钟。若需运行大型构建或长时间命令，可在配置中调整 `mcp.tool_timeout`（例如 `30m`）。
- **审批安全机制**：当操作触发安全防护规则时，客户端会弹出审批表单，需确认 `approved=true` 后方可继续执行。审批被拒绝、取消或超时均会安全终止操作。
- **免交互凭据保障**：MCP 运行在非交互模式下，不会弹出终端凭据输入或密码库解锁提示。请确保相关主机的凭据已成功导入或配置免密访问。可用 `xops credential doctor` 检查存储状态。

子命令与配置参数见 [MCP 命令参考](../reference/commands/xops-mcp)。更多高级特性：
- [局域网 HTTP 接入、客户端文件传输和恢复](mcp-http)
- [MCP SSH 隧道工具](mcp-tunnels)（支持通过 AI 动态建立和管理端口转发）
