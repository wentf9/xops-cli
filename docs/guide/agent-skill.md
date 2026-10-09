# Agent Skill 与功能概览

`xops-agent` 将 XOps 的操作方法提供给支持 Skill 的 Agent。Agent 读取说明后，在自己的命令执行环境中运行 `xops`，再检查输出和实际结果。它与 MCP 是两套独立体系，不要求注册 MCP 工具或连接 MCP 服务。

## 项目功能

| 功能 | CLI 入口 | Skill 中的操作方式 |
| --- | --- | --- |
| 初始化、OpenSSH 导入 | `init` | 检查现有配置，按需初始化或选择导入来源 |
| 主机、身份、别名与标签 | `host`、`identity` | 查询目标、CSV 导入、增删改资产、维护标签 |
| 凭据与离线加密库 | `credential`、`identity credential` | 检查访问、配置凭据，按任务执行迁移、轮换、恢复和清理 |
| SSH 与提权 | `ssh`、`exec --sudo` | 指定身份、端口、ProxyJump；按需申请终端或提权 |
| 单机与批量命令 | `exec` | 选择主机/标签/主机文件，限制并发，检查逐主机结果 |
| 文件读写与目录操作 | `exec`、批处理 `sftp` | 有界读取、写入/追加、列目录、创建、复制、移动和删除 |
| 文件与目录传输 | `scp`、`sftp` | 上传、下载、远端中转、按标签分发，选择覆盖策略并核验 |
| SSH 隧道与代理 | `ssh -L/-R/-D -N` | 跟踪进程或会话、检查监听与目标服务、停止并验证释放 |
| 声明式任务 | `play` | 组合 shell、script、copy、ensure、template，预览后按目标执行 |
| 防火墙 | `firewall` | 查询状态与规则，管理端口、服务、来源规则及重载 |
| 网络诊断与本地转发 | `dns`、`ping`、`nc`、`forward` | 从 CLI 所在环境检查 DNS/ICMP/TCP，或创建 TCP/UDP 转发 |
| 交互与本地辅助 | `tui`、`sudo`、`encode` | 终端管理、本地提权、Base64/URL/UTF-8/Unicode 转换 |
| 服务管理与命令发现 | `mcp serve/recover`、`version`、`help`、`completion` | 按明确的服务管理任务使用 CLI；Skill 的普通运维流程不依赖 MCP |

`host import --template` 导出的是 CSV 导入模板，不是已有主机清单。编码子命令是 `base64`、`url`、`utf8`、`unicode`，没有独立的 `hex` 子命令。完整参数以[命令参考](../reference/)及已安装版本的 `--help` 为准。

## MCP 能力如何通过 CLI 完成

下表用于说明能力对应关系，Skill 实际执行右侧 CLI 工作流。

| MCP 能力 | 对应 CLI 工作流 |
| --- | --- |
| `xops_list_nodes` | `xops host list`，需要时添加 `--tag` |
| `xops_ssh_run` | `xops exec --host NODE -c COMMAND`，按需添加 `--sudo` |
| `xops_read_file` | `exec` 调用目标系统的文本读取命令；大文件/二进制先用 `scp` 下载 |
| `xops_write_file` | 本地生成文件后 `scp` 上传，或通过 `exec` 执行明确的写入/追加操作 |
| `xops_fs_ls/mkdir/touch/cp/mv/rm` | 批处理 `sftp` 或 `exec` 调用目标系统的文件命令；创建空文件使用后者 |
| stdio `xops_upload/download` | `xops scp` 上传/下载文件和目录，或批处理 SFTP |
| HTTP `xops_prepare_upload/download`、`xops_transfer_status/cancel` | CLI 直接传输，检查进程、退出码与目标文件；取消时终止本次拥有的进程 |
| stdio `xops_tunnel_create/list/status/stop` | `xops ssh -L/-R -N` 配合进程/会话跟踪、连通性检查与停止操作 |

两种入口的生命周期语义不同。CLI 不产生 MCP 传输任务 ID、隧道 ID 或 TTL，也没有 `xops tunnel list` 等命令。终止传输进程不会回滚已经写入的内容。CLI 隧道还支持 `-D` SOCKS5；MCP 隧道仅提供 stdio 下的 `-L/-R`。

Skill 调用 CLI 时不经过 MCP 服务端的风险评估、审批表单和审计，需遵循 Agent 自身的命令执行授权机制。现有任务授权应继续沿用；目标、覆盖范围或网络暴露范围不明确时再澄清。

## 安装与使用

在 Agent 的命令环境中[安装 XOps](./getting-started)，准备 SSH 配置、可信主机密钥与可访问的凭据，然后安装 Skill：

```bash
npx skills add https://github.com/wentf9/xops-cli --skill xops-agent
```

手工安装时将完整的 [`skills/xops-agent/`](https://github.com/wentf9/xops-cli/tree/master/skills/xops-agent) 目录复制到客户端支持的技能目录，保留 `SKILL.md` 和 `references/`。更新当前仓库中的文件不会自动更新其他位置已安装的副本。

Skill 主文件负责环境检查、任务选择和结果验证，四份参考按需加载：

| 文件 | 内容 |
| --- | --- |
| `references/inventory.md` | 主机、身份、标签、凭据和离线库维护 |
| `references/execution.md` | 单机/批量执行、脚本、Playbook、交互与本地工具 |
| `references/files.md` | 读写文件、目录操作、SCP/SFTP 和传输校验 |
| `references/networking.md` | 隧道进程管理、防火墙、网络诊断与转发 |

示例请求：

- “用 xops-agent 检查 web 标签所有主机的磁盘占用，列出失败节点。”
- “读取 web-01 的应用配置，修改端口并验证文件内容。”
- “将本地 assets 目录分发到 web 标签主机，已有文件不要覆盖。”
- “通过 web-01 转发远端 3000 端口，验证网页后关闭隧道。”
- “把这组部署步骤整理成 Playbook，先预览目标和执行顺序。”

本地文件和监听地址属于 Agent 实际运行 CLI 的机器；容器或远程沙箱不等于用户桌面。批处理 SFTP 按空白拆分参数，带空格的路径应使用正确引用的 SCP 参数或远端命令。详细限制见 [SFTP 指南](./sftp)、[SSH 指南](./ssh)和 Skill 参考。
