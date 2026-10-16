# XOps CLI

<div align="center">
  <img src="docs/public/logo.svg" width="88" alt="XOps CLI Logo" />
  <h3>单二进制、零远端依赖的现代终端运维与 AI 自动化工具箱</h3>
  <p><b>SSH / SFTP · 终端 TUI · 离线加密凭据库 · 批量并行执行 · YAML Playbook · 受控 MCP 服务与 Agent Skill</b></p>

  <p>
    <img alt="Go Version" src="https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat-square&logo=go" />
    <img alt="Platform" src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-4c8bf5?style=flat-square" />
    <img alt="MCP Ready" src="https://img.shields.io/badge/AI-MCP%20%26%20Agent%20Skill-8A2BE2?style=flat-square" />
    <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/License-MIT-2ea44f?style=flat-square" /></a>
  </p>

  <p>
    <a href="https://wentf9.github.io/xops-cli/"><b>📖 在线文档</b></a> ·
    <a href="https://wentf9.github.io/xops-cli/guide/getting-started"><b>🚀 快速开始</b></a> ·
    <a href="https://wentf9.github.io/xops-cli/reference/"><b>⌨️ 命令参考</b></a> ·
    <a href="docs/troubleshooting/index.md"><b>🔧 故障排查</b></a> ·
    <a href="README_en.md"><b>English</b></a>
  </p>
</div>

---

日常运维和基础设施管理中，你是否经常在这些工具之间来回切换：
- 手写 `~/.ssh/config`，或者为了免输密码冒险使用 `sshpass` 把明文密码留在 Shell 历史里？
- 面对几十台机器时，觉得搭一套 Ansible / Python 环境太重，只想要一个单文件二进制并行跑命令、传文件、做状态收敛？
- 连上 Alpine 容器（无 Bash）、Windows OpenSSH（CMD / PowerShell）或 fish/zsh 节点时，脚本总是因为 Shell 方言不兼容而报错？
- 想让 Claude、Codex、Cursor 等 AI 助手帮你排查和运维服务器，又担心放开权限后 AI 误执行高危命令？

**XOps CLI** 将这些能力收敛进**一个跨平台 Go 二进制文件**中：零远端依赖、凭据默认本机加密存储、自动探测目标 Shell 环境，同时原生提供带风险护栏与审批审计的 **MCP 服务端**和 **AI Agent Skill**。

---

## ⚡ 30 秒极速上手

```bash
# 1. 一键安装（Linux / macOS）
curl -fsSL https://raw.githubusercontent.com/wentf9/xops-cli/master/install.sh | bash
```
```powershell
# Windows 在 PowerShell 5.1+ 中安装（支持 x64 / ARM64，无需管理员权限）：
irm https://raw.githubusercontent.com/wentf9/xops-cli/master/install.ps1 | iex
```
```bash
# 2. 导入现有的 ~/.ssh/config（纯本地读取，不连远端，不覆盖已有节点）
xops init

# 3. 直接连接任意主机 —— 首次验证成功后自动保存节点，并将密码/口令加密存入本机凭据库
xops ssh root@192.0.2.10

# 4. 打开交互式终端管理面板（SSH 会话、实时系统监控、远端日志搜索、标签管理）
xops tui
```

> **从源码编译**（需 Go 1.26+，Makefile 原生支持 Linux、macOS 与 Windows）：
> ```bash
> git clone https://github.com/wentf9/xops-cli.git && cd xops-cli && make build
> # Windows 下自动生成 bin/xops.exe；任意平台均可执行 make windows 交叉编译
> ```

---

## ✨ 为什么选择 XOps CLI？

| 痛点场景 | XOps CLI 的解决方案 |
| --- | --- |
| **密码管理繁琐且不安全** | **验证一次，加密记住**：首次连接认证通过后，登录密码、私钥口令和 `sudo`/`su` 密码自动加密保存在本机 `~/.xops/credentials/`（亦支持系统原生 Keychain、`pass` 或自定义 helper），YAML 配置中绝不出现明文密码。 |
| **异构环境与无 Bash 容器报错** | **零远端依赖 + 自动 Shell 探针**：默认 `server` 直通模式不依赖远端预装 Bash；首次添加/连接节点时复用同一 SSH 连接自动探测外层方言（`posix`/`fish`/`cmd`/`powershell`）与可用解释器（`bash`/`sh`/`zsh`/`fish`/`powershell`/`pwsh`/`cmd`），Alpine 与 Windows OpenSSH 开箱即用。 |
| **交互式与批量运维割裂** | **从 1 台无缝扩展到 100 台**：同一套主机与凭据资产，既能用 `xops ssh`、`xops tui`、`xops sftp` 交互操作，也能用 `xops exec --tag web`、`xops scp --tag web` 并行批处理。 |
| **轻量级部署无需重型编排** | **声明式 YAML Playbook**：内置 `shell`、`script`、`copy`、`template` 和幂等收敛步骤 `ensure`（`check` → `action` → 复查）；严格区分远程执行结果三态（`not_started` / `completed` / `unknown`），断连结果未知时绝不盲目重试。 |
| **AI 自动化缺乏安全护栏** | **双模 AI 接入（MCP + Agent Skill）**：内置 MCP 服务端（支持 `stdio` 与局域网 Streamable `HTTP`），自带命令风险分析、交互式审批（Elicitation）、路径保护与操作审计；或直接安装 `xops-agent` Skill 让 AI 操作 CLI。 |

---

## 🛠️ 核心功能一览

### 1. 主机资产、自动探针与加密凭据

XOps 将网络地址（**Host**）、认证身份（**Identity**）与连接节点（**Node**）解耦管理，同一 IP 可关联多个不同权限的账户：

```bash
# 从 CSV 批量导入主机并打上 web 标签（默认验证 SSH 连接并自动探测保存远端 Shell 配置）
xops host import hosts.csv --tag web

# 手动添加单台主机
xops host add --address 192.0.2.10 --user deploy --key ~/.ssh/id_ed25519 --alias web-01 --tags web

# 查看主机列表、标签，或诊断节点的远端 OS 与可用解释器
xops host list
xops host probe web-01
xops host probe --all --save

# 检查凭据存储健康状态
xops credential store list
xops credential doctor
```

- **先验证后入库**：`ssh`、`sftp`、`scp`、`exec` 首次连接新主机时，仅在 SSH 握手与认证成功后才保存节点；连接超时或密码错误不会留下垃圾记录。
- **灵活的保存策略**：单次连接可加 `--remember never` 禁止记住密码，或在配置中设置 `credential.remember_prompted: ask | never`。离线添加或导入可使用 `--skip-verify`（或 `--no-probe` 跳过 Shell 探针）。
- 详见：[主机与身份](docs/guide/hosts.md) · [凭据存储](docs/guide/credentials.md) · [离线凭据库](docs/guide/offline-store.md) · [凭据迁移](docs/guide/migration.md)

### 2. 增强型 SSH、提权与交互式 SFTP

```bash
# 通过别名快速登录，或以其他用户连接同一台主机（自动复用 Host 并隔离凭据）
xops ssh web-01
xops ssh audit@web-01

# 跳板机穿透（支持多级 ProxyJump、直连 IP/FQDN 或已保存的节点别名）
xops ssh -J bastion.example.com -i ~/.ssh/id_rsa root@192.0.2.13

# 免开放 root SSH 登录：普通用户连接后自动完成 sudo / sudo-rs / su 提权握手
xops ssh --sudo web-01
xops exec -x --sudo web-01 id

# 端口转发与 SOCKS5 动态代理（内置智能心跳保活与断线自动清理）
xops ssh -L 8080:127.0.0.1:80 -D 1080 -N web-01

# 交互式 SFTP 终端（支持 Tab 跨页路径补全、Ctrl+R 历史搜索、当前远端目录下 exec 命令）
xops sftp web-01
```

- 详见：[SSH 与提权](docs/guide/ssh.md) · [SFTP 与文件传输](docs/guide/sftp.md) · [终端管理界面 (TUI)](docs/guide/tui.md)

### 3. 并行批量执行与 YAML Playbook

```bash
# 对 web 标签组的所有主机并行执行命令（排除维护节点）
xops exec --tag web --exclude web-maint-01 -c "uptime"

# 并发分发并执行本地脚本（并发度 5）
xops exec --tag web --shell ./setup.sh --task 5

# 批量分发配置文件到目标服务器群
xops scp --tag web ./config.conf /etc/app/
```

使用 YAML 编写声明式 Playbook（`deploy.yaml`），实现幂等部署：

```yaml
name: deploy-web
targets:
  tags: [web]
settings:
  concurrency: 2
  on_error: stop # 可选 stop | abort_all | continue
vars:
  app_port: "8080"
steps:
  - name: "确保 nginx 已安装"
    ensure:
      check: "nginx -v"
      action: "apt-get update && apt-get install -y nginx"
    sudo: true

  - name: "渲染并分发配置"
    template:
      src: "./nginx.conf.tmpl"
      dest: "/etc/nginx/nginx.conf"
    sudo: true

  - name: "启动 nginx 服务"
    shell: "systemctl restart nginx"
    sudo: true
```

```bash
# 预览执行计划（Dry Run）与正式运行
xops play deploy.yaml --dry-run
xops play deploy.yaml --var app_port=8081 --limit web-01
```

- 详见：[命令执行](docs/guide/exec.md) · [Playbook 与自动化](docs/guide/automation.md)

### 4. AI 接入：MCP 服务端 & Agent Skill

XOps 提供两种互补的 AI 接入方式，适配不同客户端：

#### 方式 A：内置 MCP 服务端（Claude Desktop / Cursor / Codex / Antigravity）

```bash
# 本地 stdio 模式启动（提供节点查询、命令执行、SFTP 文件读写与 -L/-R SSH 隧道工具）
xops mcp serve

# 局域网 Streamable HTTP 模式启动（支持 Bearer Token 认证与 10 GiB 级流式文件上下传）
xops mcp serve --transport http --listen 0.0.0.0:8080 \
  --public-url http://192.168.1.10:8080 --token-file ~/.xops/mcp.token
```

在 `claude_desktop_config.json` 中接入：

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

- **内置安全护栏（Guardrail）**：自动评估命令与路径风险，高风险操作触发客户端交互式审批表单，审批期间若目标配置被篡改则自动废止许可，并完整记录审计日志。
- 详见：[MCP HTTP 与文件传输](docs/guide/mcp-http.md) · [MCP SSH 隧道](docs/guide/mcp-tunnels.md)

#### 方式 B：`xops-agent` Skill（让 AI 直接在终端操作 CLI）

无需启动 MCP 服务，一行命令为支持 Skill 的 Agent 安装 [`xops-agent`](skills/xops-agent/SKILL.md) 操作规范：

```bash
npx skills add https://github.com/wentf9/xops-cli --skill xops-agent
```

手工安装可直接复制 `skills/xops-agent/` 目录（保留 `SKILL.md` 与 `references/`）。详见 [Agent Skill 指南](docs/guide/agent-skill.md)。

### 5. 内置网络诊断与安全工具箱

无需记忆不同发行版的防火墙命令或额外安装小工具：
- **`xops firewall`**：统一管理 `firewalld`、`ufw`、`iptables` 与 `nftables`（查状态、开端口、管服务、重载规则）。
- **`xops dns` / `ping` / `nc` / `forward`**：跨平台 DNS 查询、ICMP Ping、TCP/UDP 端口探测与本机流量转发。
- **`xops encode`**：命令行 `base64`、`url`、`utf8`、`unicode` 编码转换。
- **双语切换**：根据系统环境自动识别中英文，或随时通过 `--lang zh` / `--lang en` 切换。

---

## 📄 开源协议

本项目基于 [MIT License](LICENSE) 开源。如果 XOps CLI 帮到了你的日常运维或 AI 工作流，欢迎点亮一颗 **Star ⭐** 支持项目发展！
