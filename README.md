# 🚀 XOps CLI 

<div align="center">
  <h3>新一代 AI 驱动的全能运维命令行工具箱</h3>
  
  <p>
    <img alt="Go Version" src="https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go" />
    <img alt="License" src="https://img.shields.io/badge/License-MIT-blue.svg" />
    <img alt="Platform" src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey" />
  </p>

[English](README_en.md) | [简体中文](README.md)

</div>

---

**XOps CLI** 是一个基于 Go 语言开发的现代化命令行运维工具集，旨在简化并自动化日常的服务器管理工作。

除了传统的 SSH 管理和批量执行功能外，XOps 原生集成了 **Model Context Protocol (MCP)** 服务端，允许 AI Agent (如 Claude 等) 在安全护栏下直接与你的基础设施进行交互。它是连接 AI 助手与真实服务器环境的完美桥梁。

### ✨ 核心特性

- 🤖 **AI 原生 (MCP 服务端)**: 内置 Model Context Protocol 服务端，包含完整的安全护栏、风险评估和策略控制。让 AI 助手安全地替你管理服务器。
- 🛡️ **SSH 增强与 TUI**: 完全兼容 OpenSSH (支持跳板机 JumpHost、隧道、Agent 转发)。内置精美的 **TUI (终端用户界面)**，并支持自动 Sudo 提权模式。
- ⚡ **批量执行与传输**: 基于标签 (Tags) 对多台主机并行执行命令或本地脚本。内置 SCP/SFTP 支持，轻松实现文件批量分发。
- 🗂️ **加密资产管理**: 本地统一管理主机、凭据 (Identity) 和标签，敏感信息(密码/私钥)采用 AES 加密存储。支持通过 CSV 模板批量导入导出。
- 🌐 **网络与安全工具**: 集成 DNS 查询、Ping、Netcat (nc)、Base64/Hex 编码转换，以及统一的**防火墙管理器** (自动适配 firewalld, ufw, iptables, nftables)。
- 🌍 **国际化 (i18n)**: 原生支持简体中文与英文，可根据环境自动切换。

### 📦 安装指南

**环境要求:** Go 1.26 或更高版本。

```bash
git clone https://github.com/wentf9/xops-cli.git
cd xops-cli
make build
# 或者手动编译: go build -o xops ./cmd/cli/main.go
```

### 🚀 快速上手

#### 1. 主机与资产管理
```bash
# 从 CSV 文件批量导入主机，并打上 'web' 标签
xops loadHost hosts.csv -t web

# 手动添加单台主机
xops host add --name web-01 --address 192.168.1.10 --user root --tag web

# 查看主机列表或标签
xops host list
xops host tags
```

#### 2. SSH 连接与 TUI
```bash
# 启动交互式 TUI 界面管理
xops tui

# 通过别名快速连接 (自动保存历史凭证)
xops ssh web-01

# 兼容 OpenSSH 习惯：通过跳板机和私钥连接
xops ssh -J jumphost -i ~/.ssh/id_rsa root@192.168.1.13

# 以 Sudo 模式连接
xops ssh --sudo web-01
```

#### 3. 批量执行与文件分发
```bash
# 对 web 标签组的所有主机并行执行 uptime 命令
xops exec --tag web -c "uptime"

# 将本地脚本在远程批量执行，并发数为 5
xops exec --tag web --shell ./setup.sh --task 5

# 批量分发配置文件到目标服务器
xops scp ./config.conf --tag web --dest /etc/app/
```

#### 4. AI 与 MCP 集成 (赋予 AI 运维能力)
XOps 内置了 **Model Context Protocol (MCP)** 服务端，让 **Claude** 等 AI 助手可以直接感知并操作你的服务器。

**A. 启动 MCP 服务:**
```bash
xops mcp serve
```

**B. 配置示例：集成到 Claude Desktop**
在你的 `claude_desktop_config.json` 中添加以下内容，即可让 Claude 拥有执行运维任务的能力：
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
- **策略控制**: 支持配置只读模式或“先审批后执行”策略。
- **全量审计**: 完整记录 AI 执行的每一条指令，确保过程透明可追溯。

#### 5. AI Agent 技能 (Skill) 集成
XOps 提供开箱即用的 AI Agent 技能 (Skill)，让你的命令行 AI 助手一键获得强大的服务器运维和故障排查能力。

> [!CAUTION]
> **⚠️ 风险提示**：本技能通过赋予 AI 助手执行 `xops` 命令的能力来工作。由于 AI 助手（如 Claude Code）是根据自然语言指令自主生成命令的，**本技能文件本身不包含强制性的服务端安全护栏**。在生产环境使用时，AI 可能会误执行高危命令（如 `rm -rf` 或重启服务）。请务必开启 AI 助手的“命令执行前确认”功能，并仔细审核 AI 计划执行的每一条指令。

**安装技能:**
由于不同大模型助手（Claude Code, Gemini CLI 等）的安装路径不一致，请使用通用的 `npx skills` 工具进行独立的技能安装。

首先，确保已经安装好 XOps CLI：
```bash
curl -sSL https://raw.githubusercontent.com/wentf9/xops-cli/master/install.sh | bash
```

然后，使用以下命令安装对应的 AI 扩展技能：
```bash
npx skills add https://github.com/wentf9/xops-cli/master/skills/xops-agent
```

安装后，只需在 AI 助手中要求“帮我查看 web 服务器的状态”或“开放数据库主机的 3306 端口”，它便会自动调用 XOps 完成任务！

## 🌍 国际化配置 / I18n

你可以通过 `--lang` 参数强制指定语言，或者依赖系统环境变量自动识别。

```bash
xops --lang en host list
xops --lang zh host list
```

## 🤝 参与贡献 / Contributing

请阅读 [AGENTS.md](./AGENTS.md) 了解详细的开发规范、编码约定和测试要求。

## 📄 开源协议 / License

本项目采用 MIT 开源协议 - 详情请参阅 [LICENSE](LICENSE) 文件。
