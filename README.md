# XOps CLI (v2)

<div align="center">
  <img src="docs/public/logo.svg" width="88" alt="XOps CLI Logo" />
  <h3>单二进制、零远端依赖的现代 SSH 运维与安全受控 AI 自动化平台</h3>
  <p><b>OpenSSH 兼容 CLI · 并发执行与 Playbook v2 · 并行 SFTP/SCP · Bubble Tea v2 终端工作台 · AEAD 加密凭据库 · 7 工具沙箱 MCP 服务与 Agent Skill</b></p>

  <p>
    <img alt="Go Version" src="https://img.shields.io/badge/Go-1.27+-00ADD8?style=flat-square&logo=go" />
    <img alt="Platform" src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-4c8bf5?style=flat-square" />
    <img alt="MCP Ready" src="https://img.shields.io/badge/AI-MCP%20%26%20Agent%20Skill-8A2BE2?style=flat-square" />
    <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/License-MIT-2ea44f?style=flat-square" /></a>
  </p>

  <p>
    <a href="https://wentf9.github.io/xops-cli/"><b>📖 在线文档</b></a> ·
    <a href="docs/guide/getting-started.md"><b>🚀 快速开始</b></a> ·
    <a href="docs/reference/index.md"><b>⌨️ CLI 参考</b></a> ·
    <a href="docs/reference/config.md"><b>🧩 配置 Schema v2</b></a> ·
    <a href="docs/reference/mcp.md"><b>🤖 MCP 参考</b></a> ·
    <a href="docs/troubleshooting/index.md"><b>🔧 故障排查</b></a> ·
    <a href="README_en.md"><b>English</b></a>
  </p>
</div>

---

**XOps v2** 是基于全新零历史包袱架构重写的单二进制跨平台 SSH/SFTP 运维与 AI 自动化工具箱（Go 1.27+、`CGO_ENABLED=0`）：

- **OpenSSH 原生体验与四层选项求解**：直接支持 `-p/-l/-i/-J/-L/-R/-D/-w/-W/-o/-O/-M/-S/-F/-t/-tt/-T/-N/-f`，统一按 `CLI > 托管节点 > XOps 全局 > ~/.ssh/config` 四层代数求解；支持 ControlMaster/ControlPersist 多路复用守护（`xops mux`）与本地/远端/SOCKS5/StreamLocal/TUN 隧道（`xops tunnel`）。
- **结构化资产图与安全凭据路由**：Host / Identity / Node 三实体解耦 + Tarjan 跳板 DAG 环路检测 + 乐观锁 CAS 落盘；配置采用严格 `version: 2` YAML（`~/.xops/config.yaml`，支持 `XOPS_HOME`），零明文密码字段，零明文密码 CLI 参数；内置 `offline_aead`（Argon2id + XChaCha20-Poly1305）、平台原生 `os_keychain`（Windows Credential Manager / macOS Keychain / Linux Secret Service）、`external_helper`（JSON v2 stdin/stdout）与 `none` 四类凭据存储。
- **并发批量执行、SFTP 原子操作与 Playbook v2**：支持单机/多机并发执行、受控提权（`--sudo`/`--su`/`--doas`）、多方言启动配置（`posix`/`powershell`/`cmd`/`raw` × `server`/`sh`/`bash`/`zsh`/`powershell`/`pwsh`/`cmd`）、并行分片可续传 SCP、单步与交互式 SFTP Shell、以及声明式 Playbook v2（`shell`/`script`/`copy`/`template`/`ensure`）；全链路严格区分三态结果，面对 `OutcomeUnknown` 显式标记 `do_not_retry` 防止盲目重试。
- **Fail-Closed 安全护栏、O(1) 审计对账与沙箱 MCP**：所有操作经能力门控签发、同步写入 `audit.jsonl`（含启动期 O(1) 进程锁崩溃对账）；内置 **7 个强类型判别式 MCP 工具**（`stdio` 与 Streamable HTTP 双传输 + 10 GiB 双代 WAL 流式端点），默认启用 `strict_agent` 熔断档并**物理禁用 `OperatorReadFS`**（仅暴露基于 `os.Root` 的 `ScopedRootFS` 沙箱）。

---

## ⚡ 快速上手

### 1. 安装或从源码构建

```bash
# Linux / macOS 一键安装预编译二进制
curl -fsSL https://raw.githubusercontent.com/wentf9/xops-cli/master/install.sh | bash
```

```powershell
# Windows (PowerShell 5.1+，无需管理员权限)
irm https://raw.githubusercontent.com/wentf9/xops-cli/master/install.ps1 | iex
```

```bash
# 从源码构建（需 Go 1.27+，CGO_ENABLED=0 原生支持 Linux / macOS / Windows）
git clone https://github.com/wentf9/xops-cli.git && cd xops-cli && make build
./bin/xops version
```

### 2. 导入现有资产并体检

```bash
# 预览并导入 ~/.ssh/config（纯本地解析，零远端连接；同样支持 --format csv）
xops config import --format openssh --file ~/.ssh/config --plan
xops config import --format openssh --file ~/.ssh/config

# 查看资产并执行只读健康诊断（校验 DAG 与凭据引用）
xops hosts list
xops doctor
```

### 3. 连接主机、并发执行与打开 TUI 工作台

```bash
# 直接 SSH 登录或透传 OpenSSH 选项与跳板链
xops ssh web-01
xops ssh -J bastion -i ~/.ssh/id_ed25519 deploy@192.0.2.10

# 跨节点并发执行并实时流式输出（支持 --json 输出规范 JSON/v2）
xops exec --tags web --exclude-nodes web-maint-01 --concurrency 5 --stream -- uptime

# 启动 Bubble Tea v2 实时终端工作台（资产/指标/日志/操作视图 + Enter 接管 SSH）
xops tui
```

---

## 🛠️ 核心能力速览

### 1. 资产图、统一导入与四层 OpenSSH 策略

```bash
# 声明式创建 Host、Identity 与 Node（支持 CAS --expected-revision）
xops hosts create-host --id h-web1 --address 192.0.2.10:22 --tag web
xops hosts create-identity --id id-deploy --user deploy --auth-kind private_key --key-path ~/.ssh/id_ed25519
xops hosts create-node --id web-01 --host h-web1 --identity id-deploy --tag web --jump bastion

# 解析最终生效连接计划（含 4 层 OpenSSH 策略折叠与摘要）与校验跳板 DAG
xops hosts resolve web-01 --json
xops hosts validate-dag

# 从 CSV 批量导入（严格拒绝任何明文 password/passphrase/secret 列）
xops config import --format csv --file ./hosts.csv --plan
xops config import --format csv --file ./hosts.csv
```

- 详见：[主机资产与配置导入](docs/guide/hosts.md) · [配置 Schema v2 参考](docs/reference/config.md)

### 2. 零明文凭据库与多后端路由

```bash
# 初始化并检查本地离线 AEAD 凭据库（Argon2id + XChaCha20-Poly1305）
xops creds init
xops creds status
xops creds doctor

# 交互式录入登录密码、加密私钥口令或节点提权密码（零明文 CLI 标志）
xops creds enroll-password --id id-app --user app --store offline
xops creds enroll-key --id id-key --user deploy --key-path ~/.ssh/id_ed25519 --store offline
xops creds set-node-privilege --node web-01 --store offline

# 原子轮换凭据与安全垃圾回收（引用未清空时拒绝删除）
xops creds rotate offline/old-item --store offline
xops creds gc offline/orphan-item
```

- 详见：[凭据路由与密钥管理](docs/guide/credentials.md) · [离线加密凭据库](docs/guide/offline-store.md)

### 3. SSH、隧道、ControlMaster 多路复用与 SFTP/SCP

```bash
# 单目标提权执行（sudo / su / doas）与明确启动方言
xops exec --sudo --password-ref offline/web01-sudo web-01 -- systemctl status nginx
xops exec --dialect powershell --interpreter pwsh win-01 -- 'Get-Process | Select-Object -First 5'

# 本地 (-L)、远端 (-R)、动态 SOCKS5 (-D)、StreamLocal 或 TUN (-w) 转发
xops tunnel local web-01 127.0.0.1:18080:127.0.0.1:80
xops ssh -M -f -N -S ~/.xops/mux-%C -o ControlPersist=10m web-01
xops mux check -S ~/.xops/mux-%C web-01

# 并行可续传 SCP 与单步/交互式 SFTP
xops scp -r --resume --concurrency 4 ./dist web-01:/srv/app/
xops sftp patch --old "debug=true" --new "debug=false" web-01 /srv/app/app.ini
xops sftp web-01
```

- 详见：[SSH、隧道与多路复用](docs/guide/ssh.md) · [命令执行与批量并发](docs/guide/exec.md) · [SFTP 与 SCP 文件传输](docs/guide/sftp.md) · [终端工作台 (TUI)](docs/guide/tui.md)

### 4. Playbook v2、护栏策略与审计对账

编写声明式 Playbook v2（`deploy.yaml`，同时支持严格 JSON）：

```yaml
version: 2
id: deploy-web
name: "Deploy Nginx Web Fleet"
on_error: fail_fast # fail_fast | continue | abort
target:
  tags: [web]
  exclude_nodes: [web-maint-01]
vars:
  app_port: "8080"
steps:
  - id: ensure-nginx
    name: "Ensure nginx is installed"
    action:
      kind: ensure
      check:
        kind: shell
        command: "nginx -v"
      action:
        kind: shell
        command: "apt-get update && apt-get install -y nginx"
  - id: render-conf
    name: "Render and atomically upload config"
    action:
      kind: template
      source: "./nginx.conf.tmpl"
      dest: "/etc/nginx/nginx.conf"
      mode: "0644"
      overwrite: true
      atomic: true
  - id: reload-nginx
    name: "Reload nginx"
    action:
      kind: shell
      command: "systemctl reload nginx"
```

```bash
# 纯离线 AST 与 Schema 校验（不初始化引擎、不连远端）
xops playbook validate deploy.yaml

# 执行 Playbook（支持 --var、--target、--concurrency、--scoped-root、--policy、--json）
xops playbook run deploy.yaml --var app_port=8081 --concurrency 2 --json

# 审计日志查询与跨进程崩溃锁 O(1) 对账
xops audit tail --limit 20
xops audit reconcile --json
```

- 详见：[Playbook v2、护栏与审计](docs/guide/automation.md)

### 5. AI 集成：7 工具沙箱 MCP 服务 & `xops-agent` Skill

#### 方式 A：内置 MCP 服务端（Claude Desktop / Cursor / Codex / Antigravity）

```bash
# stdio 模式（默认 strict_agent 安全档，物理 0 OperatorReadFS）
xops mcp serve --transfer-root ~/.xops/transfers

# Streamable HTTP 模式（默认仅绑定 127.0.0.1:8080，含 DNS Rebinding/CSRF 防护与 10 GiB 流式端点）
xops mcp serve --transport http --listen 127.0.0.1:8080 --transfer-root ~/.xops/transfers
```

> **安全边界提示**：MCP 模式出于最小权限隔离物理禁用了 `OperatorReadFS`（仅允许访问 `ScopedRootFS` 沙箱目录）。因此使用本地私钥文件（`AuthPrivateKey`）的节点在 MCP 模式下**请提前将密钥加载到 `ssh-agent`**（或使用 `kind: agent` / 已解锁的 Vault 凭据），不要期望 MCP 服务端直接读取宿主机任意磁盘路径上的私钥文件。

- 详见：[MCP 服务与 HTTP 流式传输](docs/guide/mcp-http.md) · [MCP 隧道与多路复用工具](docs/guide/mcp-tunnels.md) · [MCP 7 工具协议参考](docs/reference/mcp.md)

#### 方式 B：`xops-agent` Agent Skill

让支持 Skill 的 AI 助手在本地直接调用 `xops` CLI（搭配 `--json` 与 `--policy`）：

```bash
npx skills add https://github.com/wentf9/xops-cli --skill xops-agent
# 或在源码仓库内一键安装
make install-skill
```

- 详见：[Agent Skill 与 AI 集成概览](docs/guide/agent-skill.md) · [`skills/xops-agent/SKILL.md`](skills/xops-agent/SKILL.md)

---

## 📄 开源协议

本项目基于 [MIT License](LICENSE) 开源。
