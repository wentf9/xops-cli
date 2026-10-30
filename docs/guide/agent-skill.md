# Agent Skill 与功能概览

`xops-agent` 将 XOps CLI 的操作规范提供给支持 Skill 的 AI 助手（如 Claude Code、Codex、Cursor 等）。助手读取技能说明后，直接在自身的命令执行环境中运行 `xops` 命令并检查输出。

它与 MCP 服务是两套独立体系，使用 Skill 时无需启动 `xops mcp serve` 或注册 MCP 工具。

## 快速安装与使用

先在 AI 助手所在的命令环境中[安装 XOps](./getting-started)，准备好 SSH 配置、可信主机密钥与可访问的凭据，然后安装 Skill：

```bash
npx skills add https://github.com/wentf9/xops-cli --skill xops-agent
```

若手动安装，将仓库中完整的 [`skills/xops-agent/`](https://github.com/wentf9/xops-cli/tree/master/skills/xops-agent) 目录复制到客户端的技能目录（保留 `SKILL.md` 和 `references/` 子目录；更新仓库源码不会自动同步其他位置已安装的副本）。

安装后可直接用自然语言向助手下达任务，例如：
- “用 xops-agent 检查 `web` 标签所有主机的磁盘占用，列出失败节点。”
- “读取 `web-01` 的应用配置，修改端口并验证文件内容。”
- “将本地 `assets` 目录分发到 `web` 标签主机，已有文件不要覆盖。”
- “通过 `web-01` 转发远端 3000 端口，验证网页后关闭隧道。”
- “把这组部署步骤整理成 Playbook，先用 `--dry-run` 预览目标和执行顺序。”

**Skill 内部参考文件（按需加载）**：

| 文件 | 内容 |
| --- | --- |
| `references/inventory.md` | 主机、身份、标签、凭据和离线加密库维护 |
| `references/execution.md` | 单机/批量执行、脚本、Playbook、交互终端与本地工具 |
| `references/files.md` | 读写文件、目录操作、SCP/SFTP 与传输校验 |
| `references/networking.md` | 隧道进程管理、防火墙、网络诊断与本地转发 |

## CLI 功能总览

| 功能领域 | CLI 入口 | Skill 中的常用操作 |
| --- | --- | --- |
| 初始化与 OpenSSH 导入 | `init` | 检查现有配置，按需初始化或导入 `~/.ssh/config` |
| 主机、身份、别名与标签 | `host`、`identity` | 查询节点、CSV 批量导入、增删改资产、维护标签 |
| 凭据与离线加密库 | `credential`、`identity credential` | 检查存储状态、配置凭据，按需执行迁移、轮换、恢复和清理 |
| SSH 连接与提权 | `ssh`、`exec --sudo` | 指定身份、端口、ProxyJump；按需申请终端或 `sudo`/`su` 提权 |
| 单机与批量命令 | `exec` | 按主机/标签/列表文件选择目标，控制并发数，检查逐主机输出 |
| 文件读写与目录操作 | `exec`、批处理 `sftp` | 有界读取、写入/追加、列目录、创建、复制、移动和删除 |
| 文件与目录传输 | `scp`、`sftp` | 上传、下载、远端中转、按标签分发，选择覆盖策略并校验结果 |
| SSH 隧道与代理 | `ssh -L/-R/-D -N` | 管理转发进程或会话、检查监听与目标服务、停止并验证端口释放 |
| 声明式任务编排 | `play` | 组合 `shell`、`script`、`copy`、`ensure`、`template`，先预览再执行 |
| 防火墙管理 | `firewall` | 查询状态与规则，管理端口、服务、来源规则及重载（自动适配 firewalld/ufw/iptables/nftables） |
| 网络诊断与本地转发 | `dns`、`ping`、`nc`、`forward` | 从 CLI 所在机器检查 DNS/ICMP/TCP，或建立本地 TCP/UDP 转发 |
| 交互界面与编码工具 | `tui`、`sudo`、`encode` | 终端可视化管理、本地提权、`base64`/`url`/`utf8`/`unicode` 编码转换 |
| 服务管理与命令发现 | `mcp serve/recover`、`version`、`help`、`completion` | 按明确任务管理 MCP 服务或查看命令帮助 |

> 注意：`host import --template` 仅导出空白 CSV 模板，而非导出已有主机清单；`encode` 子命令包含 `base64`、`url`、`utf8`、`unicode`（无独立 `hex` 子命令）。完整选项以[命令参考](../reference/)和 `xops <command> --help` 为准。

## 执行语义与操作边界

- **普通命令默认直通（`server`）**：命令直接发给远端默认 SSH Shell，不再隐式包装 `bash -l -c`。请按远端实际 Shell 编写语法（Windows 节点无需为了默认命令额外安装 Bash）。
- **显式解释器与配置继承**：全局、节点、Playbook `settings.execution` 和步骤均可配置 `execution`。显式使用 `bash`、`sh`、`zsh`、`fish`、`powershell`、`pwsh` 或 `cmd` 时，需搭配描述**远端外层 Shell** 的 `launch_dialect`；`--no-login` 仅保留非登录 Bash 兼容语义。
- **脚本与按需探测**：本地脚本需要明确的解释器与已知启动方言（白名单 `sh`/`bash`/`zsh`/`fish` shebang 仅选择解释器，不能单独证明外层方言为 POSIX；无可靠解释器或含 UTF-8 BOM 的脚本会在执行前拒绝）。Playbook 无 shebang 的 `script`/`ensure` 以及 SFTP 带非空 `cwd` 的 `exec` 会对未指定的执行环境按需探测并缓存于连接内存；显式解释器（含 `server`）不会被替换（已知 `server/cmd` 的 SFTP `exec` 使用临时 CMD 适配器继承 `cwd`，其余显式 `server` 配置拒绝非空 `cwd`）。
- **入口组合与参数支持**：`exec` 的命令行显式解释器参数（`--interpreter`、`--launch-dialect`、`--login-shell`）可与 `--shell`（脚本）、`--sudo`、`--stream` 或 `--out-dir` 组合（脚本与提权支持 `bash`/`sh`/`zsh`/`fish`）；`ssh` 的命令行显式执行参数跨 Linux、macOS 与 Windows 统一按宿主 I/O 能力检查并执行。`host add` 与 `host import` 支持录入阶段的 `--interpreter`、`--launch-dialect` 及 `--probe`/`--no-probe`。
- **本地环境与路径注意**：本地文件路径和监听端口均位于**运行 `xops` 的机器**（若 Agent 运行在容器或远程沙箱中，不等同于用户桌面）。交互与批处理 SFTP 均支持单双引号及反斜杠转义，含空格的路径可直接使用引号包裹或 `\ ` 转义。

## MCP 工具与 CLI 命令对照

Skill 实际执行右侧的 CLI 命令，不经过 MCP 服务端：

| MCP 工具 | 对应 CLI 工作流 |
| --- | --- |
| `nodes` | `xops host list`（可加 `--tag`） |
| `terminal`（`session: "once"`） | `xops exec --host NODE -c COMMAND`（可加 `--sudo`）；目录操作同样通过 `exec` 调用目标系统命令 |
| `terminal`（命名持久会话） | 无直接对应；CLI 每次 `exec` 都是独立会话，需要时用 `xops ssh` 交互终端 |
| `file`（`read`/`write`/`patch`/`stat`） | 通过 `exec` 调用目标系统读取/写入命令，或批处理 `sftp`；大文件或二进制文件用 `scp` |
| `gui` | 无 CLI 对应 |
| stdio `transfer`（`push`/`pull`） | `xops scp` 上传/下载文件与目录，或使用批处理 `sftp` |
| HTTP `transfer`（`prepare_push`/`prepare_pull`/`status`/`cancel`） | 直接运行 `xops scp`，检查进程退出码与目标文件；取消时终止当前进程 |
| stdio `tunnel`（`create`/`list`/`status`/`stop`） | `xops ssh -L/-R -N`（CLI 另支持 `-D` SOCKS5；通过进程/会话管理启停） |

> **生命周期与授权差异**：CLI 不生成 MCP 传输任务 ID、隧道 ID 或 TTL，也没有 `xops tunnel list` 命令；终止 CLI 传输进程不会回滚已写入的数据。Skill 调用 CLI 时遵循 Agent 自身的命令执行授权机制，当目标、覆盖范围或端口暴露范围不明确时应先向用户确认。
