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
- **批处理与限额**：非交互批处理不会弹出凭据库解锁对话框（Linux 桌面密钥库若已解锁可直接读取；若锁定则返回 `locked`）。单次命令与包装载荷上限各为 64 KiB，默认总超时 5 分钟，内存保留最后 5 MiB 输出（超出部分继续排空并标记截断）。

## 解释器选择与跨平台执行

### 1. 默认模式：原生直通（`server`）

未指定 `--interpreter` 且节点未配置 `execution` 时，默认使用 `server` 模式：
- 命令字符串不加任何外层 `bash -l -c` 包装，直接通过 SSH `exec` 请求发给远端默认 Shell。
- 远端无需预装 Bash，可直接用于 Alpine Linux（`ash`/`sh`）、Windows OpenSSH（默认 CMD 或 PowerShell）及网络设备。
- `server` 模式不接受 `--login-shell` 参数。

### 2. 指定解释器与启动方言

当命令依赖特定 Shell 语法、登录环境变量或跨平台脚本转义时，可通过 `--interpreter` 和 `--launch-dialect` 指定：

```bash
# 显式使用 Bash 并加载登录环境（bash -l -c）
xops exec --host linux-01 --interpreter bash --launch-dialect posix --login-shell -c 'echo $PATH'

# 显式使用非登录 Bash（bash -c）或 POSIX sh（sh -c）
xops exec --host linux-01 --interpreter bash --launch-dialect posix --login-shell=false -c 'echo $VAR'
xops exec --host alpine-01 --interpreter sh --launch-dialect posix -c 'id'

# 默认 Shell 为 zsh 或 fish 的节点
xops exec --host zsh-01 --interpreter zsh --launch-dialect posix -c 'print -r -- $ZSH_VERSION'
xops exec --host fish-01 --interpreter fish --launch-dialect fish -c 'set greeting hello; echo $greeting'

# Windows 节点：使用 PowerShell 或 CMD
xops exec --host win-01 --interpreter powershell -c 'Get-Process | Select-Object -First 5'
xops exec --host win-01 --interpreter cmd -c 'dir'
```

| 解释器 (`--interpreter`) | 适用外层方言 (`--launch-dialect`) | 登录与转义说明 |
| --- | --- | --- |
| `server`（默认） | `unknown`（或缺省） | 原样发送，不接受 `--login-shell`；不可用于无解释器的本地脚本 |
| `bash` | `posix`、`fish` | 支持 `--login-shell`（`bash -l -c`）与 `--no-login` / `--login-shell=false`（`bash -c`） |
| `sh` | `posix`、`fish` | 标准非登录 `sh -c` / `sh -s`，不支持登录模式 |
| `zsh` | `posix`、`fish` | 支持 `--login-shell`（`zsh -l -c`）、脚本 `zsh -s` 及 `sudo`/`su` |
| `fish` | `posix`、`fish` | 支持 `--login-shell`（`fish -l -c`）、脚本及 `sudo`/`su` |
| `powershell` / `pwsh` | `cmd`、`powershell`（`pwsh` 另支持 `posix`/`fish`） | UTF-16LE Base64 编码载荷，自动处理参数转义与 `$LASTEXITCODE` 退出码传递（载荷上限 32767 字符） |
| `cmd` | `cmd` | `cmd.exe /d /s /c` 双层引号转义保护，保留 `%ERRORLEVEL%`（长度上限 8191 字符，拦截外层 `%VAR%`/`!VAR!` 展开） |

若不想每次在命令行传入解释器参数，可在 `~/.xops/xops_config.yaml` 的节点配置中保存 `execution`（`host add`/`import` 默认也会自动探测保存），详见[主机与身份](./hosts#节点执行环境配置-execution)。显式 `--no-login`（含 `--no-login=false`）保留选择 Bash 的兼容语义。

## 交互式终端与 PTY（`-x`）

需要对单台主机运行全屏程序（如 `top`、`htop`、`vim`）或交互式提权命令时，添加 `-x` / `--interactive` 分配伪终端（PTY）：

```bash
# 运行交互式终端程序
xops exec -x web-01 top

# 交互式提权执行单条命令
xops exec -x --sudo web-01 ls -la /root
```

- **单主机专用**：`-x` 仅支持单台目标主机，不能与多主机批量执行、本地脚本（`--shell`）、`--stream` 或 `--out-dir` 组合。
- **实时流与退出码**：输出直接连接到本地终端（无 5 MiB 内存窗口限制），支持标准输出/错误重定向（如 `xops exec -x web-01 uptime 2>error.log`），并完整保留远端命令的非零退出码与信号状态。
- **中断清理**：收到 `Ctrl+C` 或连接断开时，会在有界时间内释放本地终端、关闭 SSH 通道并回收后台协程。

## 引号与变量展开建议

命令中包含空格、管道或环境变量时，建议使用 `-c` 并根据需求选择单双引号：

```bash
# 单引号：保护 $HOME 不在本地展开，交由远端 Shell 解析
xops exec web-01 -c 'printf "%s\n" "$HOME"'

# 双引号：先在本地展开 $USER，再把结果传给远端
xops exec web-01 -c "echo Current User is $USER"
```

在本地 Windows（PowerShell 或 CMD）终端下调用时，请注意本地 Shell 的引号转义差异；多行或复杂逻辑建议写成脚本文件并通过 `--shell` 执行。完整参数列表见 [`xops exec` 命令参考](../reference/commands/xops-exec)。
