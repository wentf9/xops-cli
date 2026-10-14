# 主机与身份

XOps 将网络地址（**Host**）、认证身份（**Identity**）和连接节点（**Node**）分开保存。同一台服务器地址可以关联多个不同账号（如 `deploy` 和 `audit`），互不混淆凭据。

## 快速上手

```bash
# 手动添加单台主机（默认自动验证 SSH 连接并探测远端 Shell）
xops host add --address 192.0.2.10 --user deploy --key ~/.ssh/id_ed25519 --alias web-01 --tags web

# 从 CSV 批量导入主机并打上 web 标签
xops host import hosts.csv --tag web

# 查看主机列表与标签汇总
xops host list
xops host tags

# 导出 CSV 导入模板（仅生成空白表头模板，非导出已有主机）
xops host import --template
```

`inventory` 仍可作为 `host` 的兼容别名，`host load` 仍可作为 `host import` 的兼容别名；新脚本建议统一使用 `host` 与 `host import`。

以不同用户名直接连接同一台主机时，XOps 会自动复用同一个 `Host`，并创建独立的 `Identity` 和 `Node`：

```bash
xops ssh deploy@web-01
xops ssh audit@192.0.2.10
```

更多身份管理操作可通过 `xops identity --help` 查看，或运行 `xops tui` 在[终端管理界面](./tui)中可视化编辑。

## 添加与导入时的验证策略

### 1. 添加单台节点（`host add`）

`host add` 默认先发起 SSH 连接验证身份：
- **验证成功**：自动保存节点、凭据与探针推荐的执行配置。
- **验证失败**：显示失败原因并询问 `是否仍然保存此节点？[y/N]`。只有明确输入 `y` 或 `yes` 才会保存；直接按回车、输入 `n` 或无法读取输入时均不保存。
- **离线添加（`--skip-verify`）**：自动化脚本或不具备网络连通条件时，可显式跳过连接检查（配置合法性与凭据库检查仍会执行），未提供密码或私钥时也可先保存节点骨架：

```bash
xops host add --address 192.0.2.10 --user deploy --skip-verify
```

### 2. 批量导入（`host import`）

默认按行验证 SSH 身份认证，仅保存验证通过的节点；验证失败的行会输出节点 ID、原因并标记“验证失败，未保存”（若该行指向已有节点，失败时不会修改原配置或凭据）。

```bash
# 默认：仅保存验证通过的节点
xops host import hosts.csv

# 离线导入：不建立 SSH 连接，直接保存所有有效记录
xops host import hosts.csv --skip-verify

# 强制保留：仍执行连接验证，但验证失败的节点也保存并在结果中标记
xops host import hosts.csv --save-on-verify-failure
```

- `--skip-verify` 与 `--save-on-verify-failure` 互斥；只要存在验证失败的行，命令均返回非零退出码（取消操作不会强制保存）。
- **并发与顺序**：不同节点并行验证；同一节点的重复行严格按 CSV 顺序串行验证与保存，别名累积保留，后出现的成功行可更新凭据，最终结果始终按 CSV 行顺序输出。
- **IPv6 兼容**：导入时自动兼容旧版本不带方括号的节点 ID（如 `root@2001:db8::1:22`），匹配后就地更新；新建 IPv6 节点统一使用带方括号格式（如 `root@[2001:db8::1]:22`）。

## 节点执行环境配置（`execution`）

### 1. 自动探测与 `host probe` 诊断

新节点在 `host add`、`host import` 或**启用凭据记忆的首次交互式 `ssh`/`exec` 连接**通过认证后，会直接复用已认证连接探测远端启动方言与可用解释器（最多约 9 秒，无需二次握手），并将推荐的 `execution` 随节点一同保存。

```bash
# 添加或导入时验证连接，但跳过执行环境探针（也可写 --probe=false）
xops host add --address 192.0.2.10 --user deploy --key ~/.ssh/id_ed25519 --no-probe
xops host import hosts.csv --no-probe

# 显式指定解释器或方言（显式字段优先于探针推荐；导入时仅作用于新节点）
xops host add --address 192.0.2.10 --user deploy --key ~/.ssh/id_ed25519 --interpreter sh --launch-dialect posix

# 诊断单个已保存节点（默认只输出表格，不改配置；加 --save 写回该节点 execution）
xops host probe web-01
xops host probe web-01 --save

# 批量探测所有已保存节点（不含 OpenSSH 虚拟节点），加 --save 保存成功节点的推荐配置
xops host probe --all
xops host probe --all --save
```

**探测规则与边界**：
- **失败不阻断入库**：`host add`/`import` 或首次连接时，若探针超时或失败，仅输出警告，认证成功的节点照常按未配置状态保存（TUI 添加节点、仅会话级凭据、非交互批处理、已有节点导入不触发自动重探）。
- **显式参数隔离**：添加节点时 `--skip-verify` 会同时跳过探针；显式指定的 `--interpreter` / `--launch-dialect` 始终优先保留（探测连接自身固定使用独立的 `server/unknown` 视图，因此即使全局配置为 `bash/posix`，新节点也可仅指定 `--interpreter powershell` 并由探针自动补齐 Windows 启动方言）。在 `xops ssh` / `xops exec` 中传入 `--interpreter`、`--launch-dialect`、`--login-shell` 或 `--no-login` 时，参数仅用于当次会话并跳过该节点的首次连接入库探测。
- **推荐优先级**：
  - **Unix / Linux（`posix` 或 `fish` 方言）**：优先选用远端 `$SHELL` 报告且在 `PATH` 中可用的默认 Shell（支持 `bash`、`sh`、`zsh`、`fish`；`ash`/`dash` 映射为 `sh`），默认 `login: false`。若外层探针确认为原生 `fish` 则优先推荐 `fish`（不受过期 `$SHELL` 影响）；若默认 Shell 未知或不可用，按 `bash` → `sh` → `zsh` → `fish` 顺序回退。
  - **Windows**：CMD 外层同时存在 Windows PowerShell 时推荐 `server/cmd`（兼顾基础命令直通与受限操作按需切换），仅 CMD 时推荐 `cmd/cmd`；PowerShell 外层优先推荐 `powershell`（仅安装 Core 时推荐 `pwsh`）。
- **各 Shell 支持范围**：
  - **`fish`（`launch_dialect: fish`）**：支持命令、Playbook 脚本（含 `#!/usr/bin/env fish`）、`ensure` 检查及免密/密码 `sudo` 与 `su`（提权握手固定使用 `/bin/sh`，见[SSH 与提权](./ssh)）。
  - **`zsh`（`launch_dialect: posix`）**：支持命令、工作目录、登录模式、`#!/usr/bin/env zsh` 脚本、`ensure` 检查及 `sudo`/`su`（注意 zsh 与 Bash 并非完全兼容，见 [zsh 兼容性说明](https://zsh.sourceforge.io/Doc/Release/Invocation.html#Compatibility)）。
- **运行时按需探测**：Playbook 无 shebang 的 `script`、`ensure` 以及 SFTP 带非空工作目录的 `exec` 在节点未配置执行环境时会按需探测，结果仅缓存在当前连接内存中，不写回磁盘。

### 2. 手动配置 `execution`

你也可以在 `~/.xops/xops_config.yaml` 中为全局或单个节点手动设置 `execution`：

```yaml
schema_version: 2
# 全局默认执行配置（可选，缺省即为 server）
execution:
  interpreter: server

nodes:
  # 场景 1：精简容器 / Alpine Linux（无 Bash，原样直通或指定 sh）
  alpine-01:
    host_ref: h_alpine
    identity_ref: id_root
    execution:
      interpreter: sh
      launch_dialect: posix

  # 场景 2：依赖个人登录环境变量的传统 Linux 节点
  web-prod-01:
    host_ref: h_web
    identity_ref: id_deploy
    execution:
      interpreter: bash
      launch_dialect: posix
      login: true

  # 场景 3：Windows Server（使用 PowerShell 执行命令）
  win-ad-01:
    host_ref: h_win
    identity_ref: id_admin
    execution:
      interpreter: powershell
      launch_dialect: powershell
```

**生效优先级**：CLI 命令行参数 > Playbook 步骤 `execution` > Playbook 全局 `settings.execution` > 节点配置 (`node.execution`) > 全局配置 (`cfg.execution`) > 系统默认 (`server`)。

## 已删除的凭据参数

`host add|edit` 和 `identity add|edit` 已移除明文参数 `--password`、`--key-pass` 及其短参数，避免密码泄露在命令行参数和 Shell 历史中；旧命令 `loadHost` 也已移除（请改用 `xops host import`）。

请使用交互式密码提示、`xops identity credential set`，或通过可信管道/重定向传入 `--password-stdin`（登录密码）与 `--passphrase-stdin`（私钥口令）：

```bash
# 从标准输入更新身份密码
xops identity edit admin --password-stdin

# 从标准输入更新节点私钥与口令
xops host edit web-01 --key ~/.ssh/id_ed25519 --passphrase-stdin
```

- `--password-stdin` 与 `--passphrase-stdin` 互斥，`--password-stdin` 不能与 `--key` 同用，`host add` 中两者均不能与 `--identity` 同用。
- 空输入会在保存前被拒绝；编辑节点或身份时若省略这些选项，将保留原有凭据（切换认证方式或更换私钥路径时会同步更新凭据引用）。
