# Agent Skill 与 AI 集成概览

XOps v2 为 AI 助手提供两种互补且安全边界清晰的接入模式：

1. **内置 MCP 服务端（`xops mcp serve`）**：面向 Claude Desktop、Cursor、Codex、Antigravity 等原生 MCP 客户端，暴露 **7 个强类型判别式工具**，默认运行在 **`strict_agent` 熔断档**与 **物理 0 `OperatorReadFS`** 沙箱下。
2. **`xops-agent` Agent Skill**：面向具备终端命令执行能力的 AI 编程/运维助手，通过规范化 Skill 指令引导 AI 直接调用 `xops` CLI（结合 `--json`、`--policy` 与防盲目重试准则）。

## 1. MCP 服务 vs Agent Skill 选型对比

| 维度 | 内置 MCP 服务端（`xops mcp`） | `xops-agent` Skill（直接调 CLI） |
| --- | --- | --- |
| 启动前提 | 需运行 `xops mcp serve`（`stdio` 或 Streamable HTTP） | 仅需环境中存在 `xops` 二进制与配置，无需常驻服务 |
| 默认安全策略档 | `strict_agent`（风险审批 + `audit.jsonl` 写失败不可逆 `Halted` 熔断） | CLI 默认 `direct_operator`；建议 AI 显式附加 `--policy strict_agent` 或 `--policy strict` |
| 本地文件系统隔离 | **物理禁用 `OperatorReadFS`**，仅允许在 `ScopedRootFS`（`--transfer-root` / `--artifact-root`）内读写 | 继承 CLI 进程本地文件访问权限（仍受 `ScopedRootFS` 下载/递归上传沙箱与软链策略约束） |
| 私钥认证要求 | 因 `OperatorReadFS == nil`，`AuthPrivateKey` 需提前加载至 **`ssh-agent`**（或使用 `kind: agent` / Vault 凭据） | 可直接读取本地私钥文件或使用 `ssh-agent` / Vault |
| 持久化长会话 | 原生托管 PTY（`terminal_session`）、10 GiB 可恢复流式传输（`transfer`）、隧道/Mux（`tunnel`）与 GUI（`gui`） | 通过单次 `exec`/`scp`/`sftp`/`playbook` 与独立进程运行 `tunnel`/`mux` |
| 审计日志 | 全量同步写入 `~/.xops/audit.jsonl` 并支持启动期 O(1) 崩溃对账 | 同样经核心引擎能力门控写入 `~/.xops/audit.jsonl` |

## 2. 安装 `xops-agent` Skill

### 方式一：通过 `skills` CLI 安装

```bash
npx skills add https://github.com/wentf9/xops-cli --skill xops-agent
```

### 方式二：在源码仓库内安装

```bash
make install-skill
```

默认将 `skills/xops-agent/` 完整复制到 `~/.gemini/skills/xops-agent/`。

### 方式三：手动复制到其他 Agent 的 Skill 目录

将仓库内的 `skills/xops-agent/` 目录（完整保留 `SKILL.md` 及 `references/` 下全部 4 个参考文件）复制到目标 AI 客户端的技能目录即可：

```text
skills/xops-agent/
├── SKILL.md
└── references/
    ├── inventory.md   # 资产图查询、config import、Vault 与 doctor
    ├── execution.md   # 单机/批量 exec、提权、LaunchProfile、Playbook v2 与审计
    ├── files.md       # scp 并行续传、单步 sftp 原子操作与 SFTP Shell
    └── networking.md  # ssh -L/-R/-D/-w、tunnel 与 mux ControlMaster
```

## 3. AI 调用 CLI 的核心安全准则

`xops-agent` Skill 内置了面向 XOps v2 的强约束规范，确保 AI 助手在自动化执行时遵循以下铁律：

1. **优先机器可读输出与规范英文契约**：使用 `--json` 解析确定性 JSON/v2 结果与结构化 `error_code`、`do_not_retry`、`approval_challenge` 字段。无论终端环境或 `--lang <en|zh>` / `XOPS_LANG` 设置为何种语言，`--json` 结构字段名、`error_code`、`approval_challenge.reason`、`doctor --json` 与 `config import --json` 诊断字段，以及 MCP 7 工具描述、JSON Schema、JSON-RPC 错误响应与 `OutcomeUnknown` 禁止自动重试警告均恒保持**规范英文机器契约**（CLI `--json` 仅面向人工排障的 `error`/`diagnostic` 文本随语种本地化）。
2. **显式护栏档位**：在无人值守或高风险环境通过 `--policy strict_agent` 或 `--policy strict` 启用风险阈值拦截与两步审批。
3. **零明文凭据**：严禁向命令行或 YAML 写入明文密码；凭据操作一律通过 `xops creds` 交互录入或只读引用 `<store>/<item>`。
4. **严禁盲目重试不确定终态**：遇到 `outcome_unknown`（`do_not_retry: true`）或 Vault `uncertain_durability`（`Applied && !Durable`）时，必须先人工或只读核验远端/磁盘状态，严禁自动重放写操作或删除凭据。
5. **熔断响应**：收到 `engine_halted` 时立即停止后续操作，排查磁盘/审计权限并通过 `xops audit reconcile` 与 `xops audit tail` 核查状态。

## 相关文档

- [MCP 服务与 HTTP 流式传输](./mcp-http)
- [MCP 7 工具协议参考](../reference/mcp)
- [CLI 命令参考](../reference/)
