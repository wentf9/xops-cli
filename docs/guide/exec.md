# 命令执行与批量并发

`xops exec` 统一处理单目标远端命令、单目标受控提权（`sudo`/`su`/`doas`）以及多节点并发批量执行，并在全部路径上严格落实启动配置校验与三态执行结果追踪。

## 1. 单目标命令执行

```bash
# 基本用法（支持 -- 分隔远端命令中的 -flag）
xops exec web-01 -- uname -a
xops exec -p 2222 -l deploy -J bastion 192.0.2.10 -- df -h

# 设置工作目录、环境变量、超时与最大捕获字节数
xops exec --workdir /srv/app --env APP_ENV=prod --timeout 30s --max-output-bytes 1048576 web-01 -- ./healthcheck.sh

# 强制分配 PTY（-t / -tt）或禁用 PTY（-T）
xops exec -t web-01 -- top -b -n 1

# 规范 JSON/v2 输出（含 exit_code、outcome_kind、stdout、stderr、do_not_retry）
xops exec --json web-01 -- hostname
```

> 默认最大捕获输出上限为 **4 MiB**（可配置上限 **64 MiB**），单条命令文本上限 **1 MiB**。超过上限时返回结果中会显式标记 `truncated: true`。

## 2. 受控提权执行（单目标）

单目标 `xops exec` 支持 `--sudo`、`--su` 与 `--doas` 三种提权方式：

```bash
# 使用 Vault 中的提权密码引用（推荐，支持无人值守）
xops exec --sudo --password-ref offline/web01-sudo web-01 -- systemctl status nginx

# 指定目标提权用户（默认 root）
xops exec --sudo --privilege-user postgres --password-ref offline/web01-sudo web-01 -- id

# 交互式输入提权口令（零明文 CLI 标志）
xops exec --sudo --prompt-password web-01 -- cat /etc/shadow
xops exec --su --prompt-password web-01 -- id
xops exec --doas --prompt-password web-01 -- id
```

- 如果目标节点已在配置中绑定 `privilege_password_ref`（可通过 `xops creds set-node-privilege --node <id> --store <store>` 设置），未传 `--password-ref` 时会自动解析使用该节点引用。
- **批量模式限制**：`xops exec` 批量模式禁止直接使用 `--sudo`/`--su`/`--doas` 交互提权；跨多机执行运维编排请使用 [Playbook v2](./automation) 或逐节点调用。

## 3. 多节点并发批量执行

指定 `--all`、`--nodes`、`--tags` 或多个 `--target` 时，`xops exec` 自动进入多节点并发批量模式：

```bash
# 按标签并发执行并排除维护节点
xops exec --tags web --exclude-nodes web-maint-01 --concurrency 5 -- uptime

# 按节点 ID 列表执行，开启实时带前缀流式输出（--stream）与快速失败（--fail-fast）
xops exec --nodes web-01,web-02,web-03 --concurrency 3 --stream --fail-fast -- df -h

# 对全部托管节点执行（排除 canary 标签），并将每节点日志写入沙箱目录（ScopedRootFS）
xops exec --all --exclude-tags canary --out-dir ./batch-logs --timeout 1m -- uname -r

# 显式传入多个任意目标规格
xops exec --target web-01 --target deploy@192.0.2.20 --json -- hostname
```

### 批量选择器与运行时标志

| 标志 | 说明 |
| --- | --- |
| `--all` | 选中资产库中全部托管节点 |
| `--nodes <id,...>` | 按节点 ID 选择（逗号分隔，可重复） |
| `--tags <tag,...>` | 按标签选择（逗号分隔，可重复） |
| `--target <spec,...>` | 显式目标规格（可重复；指定多个时自动进入批量模式） |
| `--exclude-nodes <id,...>` | 批量模式下排除指定节点 ID |
| `--exclude-tags <tag,...>` | 批量模式下排除带指定标签的节点 |
| `--concurrency <n>` | 最大并发节点数 |
| `--fail-fast` | 首个节点失败后立即取消其余待执行节点 |
| `--stream` | 实时将各节点输出按节点前缀流式打印 |
| `--out-dir <dir>` | 通过 `ScopedRootFS` 将每节点 stdout/stderr 落盘到指定目录 |

## 4. 启动配置矩阵（`LaunchProfile`）

默认情况下，`xops exec` 使用 **`interpreter: server` + `login: inherit`** 直通模式，直接将命令载荷原样发给远端 SSH 默认 Shell，**不假设远端预装 Bash**（Alpine、macOS zsh、Windows OpenSSH 均可直接工作）。

当需要显式指定解释器、登录模式或跨平台方言引用时，可使用 `--dialect`、`--interpreter`、`--login`：

- `--dialect`：`posix` | `powershell` | `cmd` | `raw`
- `--interpreter`：`server` | `sh` | `bash` | `zsh` | `powershell` | `pwsh` | `cmd`
- `--login`：`disabled` | `login` | `inherit`

```bash
# 显式使用 POSIX bash（非登录 / 登录模式）
xops exec --dialect posix --interpreter bash --login disabled web-01 -- 'echo "$PATH"'
xops exec --dialect posix --interpreter bash --login login web-01 -- 'env'

# 在 Windows OpenSSH 节点上显式调用 PowerShell / pwsh / cmd
xops exec --dialect powershell --interpreter pwsh win-01 -- 'Get-Service | Select-Object -First 5'
xops exec --dialect cmd --interpreter cmd win-01 -- 'ver'
```

> 若仅提供其中部分参数，CLI 会依据兼容性矩阵自动推导其余默认值（如仅传 `--interpreter bash` 自动补全 `dialect=posix, login=disabled`）；对不合法组合（如 `sh` + `login=login` 或 `raw` + 非 `server`）立即返回退出码 `2`（`usage_error`）。

## 5. 三态执行结果与退出码规范

XOps v2 在领域核将所有远端执行结果建模为封闭三态和类型 `ExecutionOutcome`，绝不把不确定故障静默归类为失败或成功：

| `outcome_kind` | 含义 | 可否自动重试 | 退出码 / `do_not_retry` |
| --- | --- | :---: | --- |
| `completed` | 远端进程已结束并回报明确退出状态（退出码或 POSIX 信号） | 视业务幂等性 | 进程退出码（规范化至 `0..255`）或 `128 + signal`；若终态审计写失败则强制非零 |
| `not_started` | 在建连、认证、护栏拒绝或启动前失败，远端命令**确定未开始** | **是** | `255`（`ExitSSHError`） |
| `unknown` | 命令已启动但中途断连、超时或未收到退出状态，**无法确定远端是否已生效** | **严禁自动重试** | `255`，JSON 中强制置位 `"do_not_retry": true` |

> **安全铁律**：收到 `outcome_unknown`（或 `do_not_retry: true`）后，切勿盲目重放写操作或变更命令；请先通过只读命令或 `xops audit tail` 确认远端实际状态。
