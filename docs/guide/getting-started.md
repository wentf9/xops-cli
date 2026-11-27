# 安装与快速开始

XOps v2 是单二进制、零远端依赖的跨平台 SSH/SFTP 运维与受控 AI 自动化平台，支持 Linux、macOS 与 Windows（amd64 / arm64），纯 Go 1.27+ 构建（`CGO_ENABLED=0`）。

## 1. 安装

### 方式一：一键安装脚本

**Linux / macOS**：

```bash
curl -fsSL https://raw.githubusercontent.com/wentf9/xops-cli/master/install.sh | bash
```

**Windows（PowerShell 5.1+，无需管理员权限）**：

```powershell
irm https://raw.githubusercontent.com/wentf9/xops-cli/master/install.ps1 | iex
```

也可直接从 [GitHub Releases](https://github.com/wentf9/xops-cli/releases) 下载对应平台的预编译归档。

### 方式二：从源码编译

需要 **Go 1.27+**（仓库采用 Go Multi-Module Workspace，组合根位于 `./cmd/xops`）：

```bash
git clone https://github.com/wentf9/xops-cli.git
cd xops-cli
make build
```

编译产物位于 `bin/xops`（Windows 为 `bin/xops.exe`）。如需为其他平台交叉编译，可使用 `make linux`、`make linux-arm64`、`make darwin`、`make windows`、`make windows-arm64` 或 `make release`。

### 验证安装

```bash
xops version
xops version --json
```

> `xops version`（或 `-V`/`--version`）仅输出编译期注入的版本元信息，**不会初始化核心引擎或创建任何本地状态目录**。

## 2. 本地状态目录与配置文件

XOps v2 默认使用 `~/.xops/` 作为私有状态根目录，可通过环境变量 **`XOPS_HOME`** 覆盖：

| 路径 | 用途 |
| --- | --- |
| `~/.xops/config.yaml` | YAML vNext（`version: 2`）主配置文件：凭据存储、护栏策略、全局 OpenSSH 选项与 Host/Identity/Node 资产图 |
| `~/.xops/vault/` | 默认离线加密凭据库目录（`vault.meta.json` + `items/<sha256>.enc`） |
| `~/.xops/audit.jsonl` | 同步 Fail-Closed JSONL 审计日志（路径可在 `policy.guardrail.audit_log` 覆写） |
| `~/.xops/run/<process_id>.lock` | 进程生命周期活跃操作锁，用于启动期 O(1) 崩溃对账 |
| `~/.xops/journals/` | 最高 10 GiB 可恢复传输的双代 CRC32 WAL 日志目录 |

首次运行时如果 `~/.xops/config.yaml` 尚不存在，只读命令会自动加载空资产图（零副作用）；执行写操作或导入时会自动以 `0700`/`0600` 权限（Windows 为受保护 Owner-Only DACL）创建目录与文件。

> XOps v2 **仅接受 `version: 2` 配置 Schema**，解码时强制启用 `KnownFields(true)`，拒绝未知字段、多文档尾随内容以及任何明文密码字段。详细 Schema 请参阅 [配置 Schema v2 参考](../reference/config)。

## 3. 导入已有主机资产

XOps v2 通过统一 `xops config import` 导入外部配置（纯本地读取、零远端建连、支持 `--plan` 冲突/DAG 预览与 `--dry-run`）：

```bash
# 查看已注册的导入格式（内置 openssh、csv）
xops config formats

# 1. 先预览 ~/.ssh/config 导入计划与告警（不落盘）
xops config import --format openssh --file ~/.ssh/config --plan

# 2. 确认无误后正式导入
xops config import --format openssh --file ~/.ssh/config

# 或从 CSV 批量导入（严格拒绝明文 password/passphrase/secret 列）
xops config import --format csv --file ./hosts.csv --plan
xops config import --format csv --file ./hosts.csv
```

也可以直接使用命令行声明式创建资产：

```bash
xops hosts create-host --id h-web1 --address 192.0.2.10:22 --tag web
xops hosts create-identity --id id-deploy --user deploy --auth-kind private_key --key-path ~/.ssh/id_ed25519
xops hosts create-node --id web-01 --host h-web1 --identity id-deploy --tag web
```

## 4. 初始化凭据库（如需密码或加密私钥口令）

若你的连接仅依赖未加密私钥或本机 `ssh-agent`，可跳过本步骤。如需托管登录密码、加密私钥口令或 `sudo`/`su`/`doas` 提权密码：

```bash
# 交互式初始化默认离线 AEAD 凭据库（Argon2id + XChaCha20-Poly1305）
xops creds init

# 查看状态与健康检查
xops creds status
xops doctor
```

详细凭据录入与多后端配置请参阅 [凭据路由与密钥管理](./credentials) 与 [离线加密凭据库](./offline-store)。

## 5. 首次连接与常用工作流

```bash
# 1. 预览目标的最终连接计划（四层 OpenSSH 选项折叠结果）
xops hosts resolve web-01

# 2. 交互式 SSH 登录（兼容标准 OpenSSH 标志）
xops ssh web-01
xops ssh -J bastion -i ~/.ssh/id_ed25519 deploy@192.0.2.10

# 3. 跨节点并发执行命令并流式输出
xops exec --tags web --concurrency 4 --stream -- uptime

# 4. 上传/下载文件与交互式 SFTP Shell
xops scp ./app.tar.gz web-01:/tmp/app.tar.gz
xops sftp web-01

# 5. 打开 Bubble Tea v2 交互式终端工作台
xops tui
```

## 6. 全局选项速览

几乎所有命令均支持统一的前置或子命令级全局选项：

- `--lang <en|zh>`：显式指定本次运行的界面显示语言（`en` 英文、`zh` 简体中文，可置于子命令前或后、`--` 之前，末次覆盖；详见下方 §7）。
- `--json`：在 `stdout` 输出规范确定性 JSON/v2（开启 `Deterministic(true)`）；报错时输出统一结构化错误信封。
- `--policy <profile>`：指定本次运行的安全策略配置档：`direct_operator`（CLI 默认）、`strict` / `strict_operator`、`strict_agent`（MCP 默认）。
- `-F <configfile>`（或 `--ssh-config <path>`）：覆写 OpenSSH 配置文件路径；传入 `none` 可禁用 OpenSSH 配置读取。
- `-h` / `--help`、`xops help <command>`：查看任意命令精确帮助（与 `version` 一样零引擎初始化、零触盘）。

## 7. 语言设置与国际化（`--lang` / `XOPS_LANG`）

XOps v2 内置纯内存 `embed.FS` **英文（`en`）与简体中文（`zh`）**双语词库，按进程生效且**不向 `~/.xops/config.yaml` 写入持久化语言配置**（所有 `zh*` 区域变体如 `zh_CN`、`zh-Hans`、`zh-TW` 均归并至简体中文 `zh`）。

### 语言探测优先级

启动期零子进程（零 `os/exec`）、零磁盘 I/O，按以下优先级自高向低确定显示语言：

```text
1. CLI 标志 --lang <en|zh>（或 --lang=<en|zh>）
2. 环境变量 XOPS_LANG
3. 环境变量 LC_ALL
4. 环境变量 LC_MESSAGES
5. 环境变量 LANG
6. 操作系统原生区域（Windows 经 kernel32 GetUserDefaultLocaleName 查询；Unix/macOS 为空，仅依赖 POSIX 环境变量）
7. 默认兜底 en（英文）
```

- **POSIX 覆盖语义**：`LC_ALL=C`、`LC_ALL=POSIX`（含 `.UTF-8` 等后缀，如 `C.UTF-8`）显式解析为 `en` 并**阻断**更低优先级的 `LANG`（例如 `LC_ALL=C LANG=zh_CN.UTF-8` 结果为英文）；刻意忽略 GNU `LANGUAGE` 列表。
- **失败关闭与容错差异**：显式传入非法或缺值的 `--lang`（如 `--lang fr`、`--lang C`）会立即以退出码 `2`（`usage_error`）失败关闭（零引擎初始化、零触盘），并按环境探测语种渲染报错；环境变量或系统区域中的未知非空标签则会安全回退为 `en` 并阻断继续穿透。
- **命令感知扫描与透传保护**：`--lang` 可写在子命令前、子命令后（多级命令族如 `xops hosts --lang zh list` 或 `xops hosts list --lang zh` 均支持），遵循**末次覆盖**并在 `--` 处停止扫描。对于 `xops ssh` 与 `xops exec`，预扫描遇到首个位置参数（目标主机）或 `--` 即停止，因此远端命令自带的参数（如 `xops ssh web-01 mytool --lang=fr`）绝不会被误拦截。

### 常用示例

```bash
# 查看中文或英文帮助与版本（纯内存渲染，绝不初始化引擎或创建 ~/.xops/）
xops --lang zh --help
xops help ssh --lang zh
xops version --lang zh

# 通过环境变量为当前 Shell 会话默认启用中文
export XOPS_LANG=zh
xops hosts list
xops doctor

# 单次覆盖为英文，或使用 POSIX LC_ALL=C 强制英文输出
xops --lang en doctor
LC_ALL=C LANG=zh_CN.UTF-8 xops version

# 远端命令自带 --lang 参数完整透传，不触发 XOps 语法错误
xops ssh web-01 mytool --lang=fr
xops exec --lang zh web-01 -- echo --lang=fr
```

### 机器契约规范英文边界

为确保脚本、CI 与 AI Agent 解析稳定性，以下结构化与协议输出**恒保持规范英文**，不受 `--lang` 或 `XOPS_LANG` 影响：

- **CLI `--json` 输出**：所有 JSON 字段名、枚举值、`exit_code`、`do_not_retry` 与 `error_code` 常量恒为规范英文；仅面向人工排障的 `error` 与 `diagnostic` 字段随当前语种本地化，且 `doctor --json`（诊断项与 `vault_note`）、`config import --json`（导入报告与告警）及 `approval_challenge.reason` 始终保持规范英文。
- **MCP 服务端**：全部 7 个 MCP 工具的名称、描述、JSON Schema、JSON-RPC 错误响应、审批挑战信封与 `OutcomeUnknown` 警告恒为规范英文。
- **审计日志与 OpenSSH 控制契约**：`~/.xops/audit.jsonl` 以及 `xops ssh -O` / `xops mux` 控制文本回执恒为规范英文。
- **TUI 热切换**：在 `xops tui` 界面中可随时按大写 **`L`** 实时切换中英文（详见 [终端工作台（TUI）](./tui)）。

## 下一步

- [主机资产与配置导入](./hosts) — 深入了解 Host/Identity/Node 三实体图、Tarjan 跳板 DAG 校验与四层 OpenSSH 优先级。
- [SSH、隧道与多路复用](./ssh) — 使用跳板机、端口转发、SOCKS5、TUN 与 ControlMaster 守护进程。
- [Playbook v2、护栏与审计](./automation) — 编排声明式多节点部署与安全审批审计。
- [MCP 服务与 HTTP 流式传输](./mcp-http) 或 [Agent Skill 概览](./agent-skill) — 将 XOps 接入 AI 助手。
