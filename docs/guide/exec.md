# 命令执行

`xops exec` 用于在单台或多台远程主机上执行命令、分发运行本地脚本，或分配交互式终端（PTY）。

## 快速上手

```bash
# 单台主机执行命令
xops exec web-01 uptime

# 按标签对多台主机并行执行命令
xops exec --tag web -c 'uptime'

# 按标签并行分发并执行本地脚本（设置并发数为 5）
xops exec --tag web --shell ./check.sh --task 5

# 排除特定节点
xops exec --tag web --exclude web-maintenance-01 -c 'df -h'
```

**目标与参数规则**：
- `--host`、`--ifile`/`-I`（主机列表文件）、`--tag` 三种目标选择方式互斥；指定其中之一后，第一个位置参数即可作为远程命令（如 `xops exec --host web-01 uname -a`），或用 `-c` 显式传入命令字符串。
- 全局参数可放在子命令前后（如 `xops --color never exec --host web-01 uname -a`）。若远程命令自身带有以 `-` 开头的参数，可用 `-c` 引起来，或使用 `--` 分隔（如 `xops exec --host web-01 -- echo --help`）。
- **批处理凭据**：批处理不会弹出凭据库解锁对话框；运行前请先解锁所需的凭据库。
- **脚本来源**：`--shell` 需指定普通文件；管道脚本请通过标准输入传入，且不能同时使用 `--password-stdin` 或 `--passphrase-stdin` 提供凭据。
- **显式解释器模式的限额**：普通命令最长 64 KiB，脚本最长 16 MiB，非交互执行默认时限为 5 分钟。默认结果保留最后 5 MiB 输出，超出时会提示截断；使用 `--stream` 实时显示或 `--out-dir` 保存日志时不受此结果保留限制。部分 Shell 还可能有更严格的命令长度限制。

## 解释器选择与跨平台执行

### 1. 默认模式：原生直通（`server`）

未指定 `--interpreter` 且节点未配置 `execution` 时，默认使用 `server` 模式：
- 使用远端默认 Shell 执行命令，不会自动改用 Bash。
- 远端无需预装 Bash，可直接用于 Alpine Linux（`ash`/`sh`）、Windows OpenSSH（默认 CMD 或 PowerShell）及网络设备。
- `server` 模式不接受 `--login-shell` 参数。

### 2. 指定解释器与启动方言

当命令依赖特定 Shell 语法、登录环境变量或跨平台脚本转义时，可通过 `--interpreter` 和 `--launch-dialect` 指定：

```bash
# 使用 Bash 并加载登录环境
xops exec --host linux-01 --interpreter bash --launch-dialect posix --login-shell -c 'echo $PATH'

# 使用 Bash 或 sh，不加载登录环境
xops exec --host linux-01 --interpreter bash --launch-dialect posix --login-shell=false -c 'echo $VAR'
xops exec --host alpine-01 --interpreter sh --launch-dialect posix -c 'id'

# 默认 Shell 为 zsh 或 fish 的节点
xops exec --host zsh-01 --interpreter zsh --launch-dialect posix -c 'print -r -- $ZSH_VERSION'
xops exec --host fish-01 --interpreter fish --launch-dialect fish -c 'set greeting hello; echo $greeting'

# Windows 节点：远端 SSH 默认 Shell 为 CMD 时
xops exec --host win-01 --interpreter powershell --launch-dialect cmd -c 'Get-Process | Select-Object -First 5'
xops exec --host win-01 --interpreter cmd --launch-dialect cmd -c 'dir'
```

`--launch-dialect` 应与远端 SSH 默认 Shell 一致；例如默认 Shell 是 PowerShell 时使用 `powershell`。

| 解释器 (`--interpreter`) | 适用启动方言 (`--launch-dialect`) | 使用说明 |
| --- | --- | --- |
| `server`（默认） | `unknown`（或缺省） | 使用远端默认 Shell，不接受 `--login-shell`；运行本地脚本时需选择具体解释器 |
| `bash` | `posix`、`fish` | 用 `--login-shell` 加载登录环境；用 `--no-login` 或 `--login-shell=false` 跳过 |
| `sh` | `posix`、`fish` | 不加载登录环境，不支持登录模式 |
| `zsh` | `posix`、`fish` | 支持登录环境、脚本及 `sudo`/`su` |
| `fish` | `posix`、`fish` | 支持登录环境、脚本及 `sudo`/`su` |
| `powershell` / `pwsh` | `cmd`、`powershell`（`pwsh` 另支持 `posix`/`fish`） | 不加载用户配置文件，保留命令退出码 |
| `cmd` | `cmd` | 受 CMD 的 8191 字符长度限制；命令中暂不支持 `%`、`!`、换行或未配对的双引号 |

解释器参数可与 `--shell`、`--sudo`、`--stream` 或 `--out-dir` 组合：

```bash
# 指定 sh 执行本地脚本，提权并将各主机日志保存到 logs
xops exec --tag web --interpreter sh --launch-dialect posix --sudo --shell check.sh --out-dir logs

# 使用 Bash 批量执行并实时显示输出
xops exec --tag web --interpreter bash --launch-dialect posix --stream -c 'uptime'

# 使用远端默认 Shell，将输出保存到日志
xops exec --host web-01 --interpreter server --out-dir logs -c 'df -h'
```

脚本和 Unix 提权支持 `bash`、`sh`、`zsh`、`fish`，不支持 `server`、`powershell`、`pwsh` 或 `cmd`。`--stream` 与 `--out-dir` 仍互斥；交互模式的限制见下文。

若不想每次在命令行传入解释器参数，可在 `~/.xops/xops_config.yaml` 的节点配置中保存 `execution`（`host add`/`import` 默认也会自动探测保存），详见[主机与身份](./hosts#节点执行环境配置-execution)。显式 `--no-login`（含 `--no-login=false`）保留选择 Bash 的兼容语义。

## 交互式终端与 PTY（`-x`）

需要对单台主机运行全屏程序（如 `top`、`htop`、`vim`）或交互式提权命令时，添加 `-x` / `--interactive` 分配伪终端（PTY）：

```bash
# 运行交互式终端程序
xops exec -x web-01 top

# 交互式提权执行单条命令
xops exec -x --sudo web-01 ls -la /root

# 指定解释器，将交互命令的输出保存到文件（输入仍来自终端）
xops exec --host web-01 -x --interpreter bash --launch-dialect posix -c 'uptime' >output.log 2>error.log
```

- **单主机专用**：`-x` 仅支持单台目标主机，不能与多主机批量执行、本地脚本（`--shell`）、`--stream` 或 `--out-dir` 组合。
- **输出与退出码**：输出默认显示在终端，也可用 `>output.log`、`2>error.log` 或 `>output.log 2>&1` 保存到文件，包括显式指定解释器时。不受上述 5 MiB 结果保留限制，并保留远端命令的非零退出码与信号状态。输入仍须来自本地终端；终端程序的日志可能包含颜色或光标控制字符，且远端标准输出和错误输出不一定分开。
- **中断操作**：可按 `Ctrl+C` 中断。保存日志时若磁盘或文件系统无响应，中断可能需要等待；命令返回后不会继续写入日志。连接断开后，先确认远端执行结果，再决定是否重试；不要直接重复可能修改数据的命令。

## 引号与变量展开建议

命令中包含空格、管道或环境变量时，建议使用 `-c` 并根据需求选择单双引号：

```bash
# 单引号：保护 $HOME 不在本地展开，交由远端 Shell 解析
xops exec web-01 -c 'printf "%s\n" "$HOME"'

# 双引号：先在本地展开 $USER，再把结果传给远端
xops exec web-01 -c "echo Current User is $USER"
```

在本地 Windows（PowerShell 或 CMD）终端下调用时，请注意本地 Shell 的引号转义差异；多行或复杂逻辑建议写成脚本文件并通过 `--shell` 执行。完整参数列表见 [`xops exec` 命令参考](../reference/commands/xops-exec)。
