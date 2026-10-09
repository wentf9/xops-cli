# 🚀 XOps CLI

<div align="center">
  <h3>在终端中管理远程主机</h3>

  <p>
    <img alt="Go Version" src="https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go" />
    <img alt="License" src="https://img.shields.io/badge/License-MIT-blue.svg" />
    <img alt="Platform" src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey" />
  </p>

[English](README_en.md) | [简体中文](README.md)

</div>

---

**XOps CLI** 在一个终端工具中提供主机管理、SSH 连接、文件传输、批量执行和 Playbook 任务编排，也可通过 **Model Context Protocol (MCP)** 接入 AI 客户端，配置操作审批和审计。

[使用指南](https://wentf9.github.io/xops-cli/) · [命令参考](https://wentf9.github.io/xops-cli/reference/) · [故障排查](docs/troubleshooting/index.md)

文档随当前源码更新，可能包含尚未发布的改动。已安装版本支持的选项以 `xops <command> --help` 为准。

### ✨ 核心特性

- 🤖 **AI 接入**: 独立的 Agent Skill 指导助手通过 CLI 完成运维任务；内置 MCP 服务端提供另一套工具接入，支持命令风险评估、审批和审计。
- 🛡️ **SSH 增强与 TUI**: 支持导入 OpenSSH 配置、跳板机、隧道和 SSH Agent 转发。内置 **TUI (终端用户界面)**，并支持自动 Sudo 提权模式。
- ⚡ **批量执行与传输**: 基于标签 (Tags) 对多台主机并行执行命令或本地脚本。内置 SCP/SFTP 支持，轻松实现文件批量分发。交互式 SFTP shell 会在连接中断后提示并退出，返回非零状态。
- 🔄 **声明式任务编排 (Playbook)**: 支持 YAML 格式的任务编排，组合 shell、script、copy、ensure (幂等性状态收敛) 和 template 步骤，支持并发控制与失败策略。
- 🗂️ **资产与凭据管理**: 本地统一管理主机、凭据 (Identity) 和标签，支持将验证成功的密码保存到离线加密库或其他已配置的凭据存储。支持导出 CSV 导入模板和批量导入主机。
- 🌐 **网络与安全工具**: 集成 DNS 查询、Ping、Netcat (nc)、本地 TCP/UDP 转发、Base64/URL/UTF-8/Unicode 编码转换，以及统一的**防火墙管理器** (自动适配 firewalld, ufw, iptables, nftables)。
- 🌍 **国际化 (i18n)**: 原生支持简体中文与英文，可根据环境自动切换。

### 📦 安装指南

使用预编译版本安装（Linux/macOS）：

```bash
curl -sSL https://raw.githubusercontent.com/wentf9/xops-cli/master/install.sh | bash
```

从源码构建需要 Go 1.26 或更高版本（Makefile 已原生适配 Linux、macOS 与 Windows 环境）：

```bash
git clone https://github.com/wentf9/xops-cli.git
cd xops-cli
make build
# Windows 环境会自动生成 bin/xops.exe；亦可在任意平台使用 make windows 进行交叉编译
# 或者手动编译: go build -o xops ./cmd/cli/main.go
```

### 🚀 快速上手

#### 1. 初始化

```bash
# 创建 Schema v2 配置 ~/.xops/xops_config.yaml（不创建加密密钥）
# 默认导入 ~/.ssh/config 中不含通配符的 Host；不会连接远程主机
xops init

# 使用指定的 OpenSSH 配置，或完全跳过导入
xops init --ssh-config ~/.ssh/config.work
xops init --skip-ssh-import
```

该命令可重复执行，不会覆盖已有节点。初始化完成后可运行 `xops host list` 查看导入结果。

新安装默认将验证成功的密码和私钥口令保存在内置离线加密库中，首次保存时自动创建凭据库和密钥文件。连接时加上 `--remember never` 可关闭本次自动保存；在配置中设置 `credential.remember_prompted: never` 可全局关闭。

通过 SSH、SFTP、SCP 或 exec 首次连接的新节点，仅在 SSH 握手和身份认证成功后自动保存。连接超时、拒绝连接或认证失败不会新增节点；认证成功后即保存，无须等待 Shell 或远程命令成功。已有节点不会因连接失败被删除。显式添加或导入可使用 `--skip-verify` 离线保存。`--remember` 控制凭据机密的保存，不影响认证成功后的节点信息保存。

存储选择与备份方法见[凭据存储](docs/guide/credentials.md)，旧配置升级和更换存储位置见[凭据迁移](docs/guide/migration.md)。

#### 2. 主机与资产管理

```bash
# 从 CSV 文件批量导入主机，并打上 'web' 标签
xops host import hosts.csv --tag web

# 手动添加单台主机
xops host add --address 192.0.2.10 --user root --key ~/.ssh/id_ed25519 --alias web-01 --tags web

# 查看主机列表或标签
xops host list
xops host tags
```

`inventory` 仍可作为 `host` 的兼容别名，`host load` 仍可作为 `host import` 的兼容别名；新脚本应使用上面的规范命令。

导入默认只保存 SSH 验证通过的节点，失败行会明确标记“未保存”；`--skip-verify` 跳过验证直接保存，`--save-on-verify-failure` 验证失败也保存，两者互斥。`host add` 和 TUI 添加节点默认先验证，失败后询问是否保存（默认否）；CLI 使用 `--skip-verify`、TUI 使用表单中的“跳过验证直接保存”选项进行离线添加。

#### 3. SSH 连接与 TUI

```bash
# 启动交互式 TUI 界面管理
xops tui

# 通过别名快速连接
xops ssh web-01

# 显式指定新用户连接同一主机 (自动复用已有 Host，独立隔离凭证，自动继承 ProxyJump)
xops ssh test@192.0.2.20
xops ssh test@web-01

# 兼容 OpenSSH 习惯：通过跳板机和私钥连接 (直连跳板支持 FQDN/IP/host:port；单标签跳板需预先配置为 Node/Alias)
xops ssh -J bastion.example.com -i ~/.ssh/id_rsa root@192.0.2.13 # 直连跳板 (FQDN 或 192.0.2.1 或 jumphost:22)
xops ssh -J jumphost -i ~/.ssh/id_rsa root@192.0.2.13            # 别名跳板 (jumphost 为已有节点/别名)

# 以 Sudo 模式连接
xops ssh --sudo web-01
```

#### 4. 批量执行与文件分发

```bash
# 对 web 标签组的所有主机并行执行 uptime 命令
xops exec --tag web -c "uptime"

# 将本地脚本在远程批量执行，并发数为 5
xops exec --tag web --shell ./setup.sh --task 5

# 批量分发配置文件到目标服务器
xops scp ./config.conf --tag web --dest /etc/app/
```

普通 `exec` 可以读取 Linux 桌面密钥库中已解锁的现有凭据，无需 `-x`。
`-x` 用于需要远端终端交互的命令（如 `top`、`vim`）；普通批处理不会弹出解锁提示。
密钥库锁定时返回 `locked`，需先在桌面解锁；执行进程须能访问该桌面的 D-Bus 会话。

#### 5. 声明式任务编排 (Playbook)

Playbook 使用 YAML 描述部署任务。支持 shell、script、copy、ensure (状态期望收敛)、template 等操作。

示例 Playbook `deploy.yaml`:

```yaml
name: deploy-web
targets:
  tags: [web]
settings:
  concurrency: 2
  on_error: stop
vars:
  app_port: "8080"
steps:
  - name: "安装 nginx"
    ensure:
      check: "nginx -v"
      action: "apt-get install -y nginx"
    sudo: true
  - name: "渲染并分发配置"
    template:
      src: "./nginx.conf.tmpl"
      dest: "/etc/nginx/nginx.conf"
    sudo: true
  - name: "启动 nginx 服务"
    shell: "systemctl start nginx"
    sudo: true
```

`settings.on_error: abort_all` 会在任一主机连接失败或步骤失败时取消其他正在进行的主机任务；`continue` 仅让当前主机继续执行后续步骤。

执行 Playbook：

```bash
# 执行 Playbook 并覆盖/注入变量
xops play deploy.yaml --var app_port=8081

# 仅预览执行步骤（不实际执行）
xops play deploy.yaml --dry-run

# 限制执行到特定主机节点
xops play deploy.yaml --limit web-01
```

#### 6. AI 与 MCP 集成

XOps 内置了 **Model Context Protocol (MCP)** 服务端，支持 **Claude** 等 MCP 客户端查询和操作服务器。

**A. 启动 MCP 服务:**

```bash
xops mcp serve
```

局域网 Codex / Antigravity CLI 可使用 `xops mcp serve --transport http`。认证、流式文件传输与客户端限制见 [HTTP MCP 指南](docs/guide/mcp-http.md)。

stdio 模式提供 SSH `-L/-R` 隧道的创建、查询和停止工具，使用方法见 [MCP SSH 隧道](docs/guide/mcp-tunnels.md)。

**B. 配置示例：集成到 Claude Desktop**
`claude_desktop_config.json` 配置示例：

```json
{
  "mcpServers": {
    "xops": {
      "command": "/usr/local/bin/xops",
      "args": ["mcp", "serve"]
    }
  }
}
```

**C. 安全护栏:**

- **风险评估**: 自动分析 AI 请求的命令风险等级（如识别 `rm -rf` 等危险操作）。
- **策略控制**: 支持配置审批阈值、禁止执行的命令和受保护路径。
- **审计日志**: 记录 MCP 工具调用及处理结果，便于追踪操作。

#### 7. AI Agent 技能 (Skill) 集成

[`xops-agent`](skills/xops-agent/SKILL.md) 指导 Agent 通过本地命令执行环境调用 `xops`。Skill 与 MCP 是两套独立接入方式：使用 Skill 需要安装 CLI、准备 SSH 配置和凭据，无须启动或连接 MCP 服务。

Skill 按任务覆盖主机与身份管理、单机/批量执行、远端文件读写和传输、SSH 隧道、防火墙、网络诊断与 Playbook。文件操作组合 `exec`、`scp` 和批处理 `sftp`；隧道通过 `ssh -L/-R/-D -N` 创建，并由 Agent 跟踪进程、检查连通性和停止会话。

CLI 操作遵循 Agent 的命令执行授权机制，不经过 MCP 服务端的审批和审计。Skill 文件提供操作指导，本身不实施服务端安全策略。

**安装技能:**
不同客户端的技能目录不同，安装命令使用通用的 `npx skills` 工具。

XOps CLI 安装命令：

```bash
curl -sSL https://raw.githubusercontent.com/wentf9/xops-cli/master/install.sh | bash
```

Skill 安装命令：

```bash
npx skills add https://github.com/wentf9/xops-cli --skill xops-agent
```

手工安装时请复制完整的 `skills/xops-agent/` 目录，保留 `references/`。功能梳理、CLI 与 MCP 能力对应关系及使用示例见 [Agent Skill 指南](docs/guide/agent-skill.md)。

## 🌍 国际化配置 / I18n

语言由 `--lang` 参数指定，未指定时根据系统环境识别。

```bash
xops --lang en host list
xops --lang zh host list
```

## 📄 开源协议 / License

项目采用 MIT 开源协议，详见 [LICENSE](LICENSE) 文件。
