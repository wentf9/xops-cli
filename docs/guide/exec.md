# 命令执行

XOps CLI 提供了强大的远程命令执行能力（`xops exec`），支持单主机交互、多主机并行批处理、脚本分发执行以及跨平台的命令解释器适配。

通过 `--host`、`--ifile`/`-I` 或 `--tag` 选择目标后，第一个位置参数即为远程命令。例如 `xops exec --host web-01 uname -a`。`--host`、`--ifile`/`-I`、`--tag` 三种目标选择参数互斥，选择其一后可使用 `--exclude` 排除部分节点。

全局参数可置于子命令前后，例如 `xops --color never exec --host web-01 uname -a`。远程命令后的参数会保持原样传递；若参数可能引起歧义，可使用 `--` 明确分隔，例如 `xops exec --host web-01 -- echo --help`。

## 普通与批量执行

```bash
# 单节点执行命令
xops exec web-01 uptime

# 基于标签对多台主机批量执行
xops exec --tag web -c 'uptime'

# 批量执行本地脚本，设置并发数为 5
xops exec --tag web --shell ./check.sh --task 5
```

- **批处理适用场景**：适合日常运维巡检、批量部署和自动化任务。批处理模式下不会弹出交互式凭据解锁对话框，需预先配置可非交互访问的凭据（如免密私钥或已解锁的凭据库）。
- **缓冲与截断保护**：普通命令执行保留最近 5 MiB 的输出内容，超出上限后继续排空读取并在控制台显示截断标记，防止海量日志输出耗尽本地内存。
- **长度与超时限制**：原始命令及参数包装载荷最大支持 64 KiB，单次执行总超时默认为 5 分钟。

## 执行解释器与环境配置

XOps 支持多种远程解释器，以适应 Linux、Alpine、Windows 等不同操作系统与执行环境。

### 默认解释器：原生执行 (`server`)

在未显式指定解释器且未配置节点解释器时，XOps 默认采用 `server` 模式：
- **无依赖的原生命令执行**：命令原样通过 SSH exec 请求发送至远端，由远端用户的默认 Shell 或 SSH 守护进程直接执行。
- **广泛的系统兼容性**：远端无需预装 Bash，天然适配精简容器、Alpine Linux（仅内置 `ash`/`sh`）、Windows（默认 PowerShell 或 CMD）以及各类网络设备。
- **行为规范**：`server` 模式不添加任何外层包装，不接受 `--login-shell` 选项。

### 多解释器支持

针对需要特定 Shell 语法、环境变量或登录脚本的场景，可通过 `--interpreter` 指定目标解释器：

```bash
# 原生 SSH 执行（默认）
xops exec --host alpine-01 --interpreter server -c 'uname -a'

# 显式使用 Bash 执行并加载登录环境
xops exec --host linux-01 --interpreter bash --launch-dialect posix --login-shell -c 'echo $PATH'

# 显式使用 Bash 执行（非登录模式）
xops exec --host linux-01 --interpreter bash --launch-dialect posix --login-shell=false -c 'echo $VAR'

# 显式使用 POSIX sh 执行
xops exec --host linux-01 --interpreter sh --launch-dialect posix -c 'id'

# 默认 Shell 为 zsh 的节点
xops exec --host zsh-01 --interpreter zsh --launch-dialect posix -c 'print -r -- $ZSH_VERSION'

# 默认 Shell 为 fish 的节点
xops exec --host fish-01 --interpreter fish --launch-dialect fish -c 'set greeting hello; echo $greeting'

# Windows 目标：通过 PowerShell 执行
xops exec --host win-01 --interpreter powershell -c 'Get-Process | Select-Object -First 5'

# Windows 目标：通过 CMD 执行
xops exec --host win-01 --interpreter cmd -c 'dir'
```

- **`bash`**：调用远端 `bash`。支持 `--login-shell`（等效于 `bash -l -c`）或 `--no-login` / `--login-shell=false`（等效于 `bash -c`）。要求启动方言为 `posix` 或 `fish`。
- **`sh`**：调用标准 POSIX `sh -c`。适用于不依赖 Bash 特性的标准 Shell 脚本，不支持登录 Shell。
- **`zsh`**：使用 `zsh -c`，通过 `--login-shell` 使用 `zsh -l -c`。外层启动方言可为 `posix` 或 `fish`。脚本使用 `zsh -s`；sudo/su 复用 POSIX 认证握手并保留 zsh 语义。
- **`fish`**：使用 `fish -c`，可通过 `--login-shell` 使用 `fish -l -c`。要求外层启动方言为 `posix` 或 `fish`；`--no-login` 仍为Bash 兼容参数。
- **`powershell` / `pwsh`**：针对 Windows 主机或跨平台 PowerShell 目标，自动处理命令安全转义与退出码传递。
- **`cmd`**：针对 Windows 命令提示符（`cmd /c`），自动处理参数引号并限制命令长度在 8191 字符安全范围以内。

使用已保存的 zsh/fish 执行配置时，普通与提权 `exec` 命令均保留节点的 login 模式。显式 `--no-login`（包括 `--no-login=false`）继续使用原有的 Bash 选择语义。

### 启动方言 (`--launch-dialect`)

启动方言用于指导 XOps 对命令载荷进行语法校验与转义：
- `posix`：适用于各类 Linux/UNIX Shell（Bash、sh、Zsh 等）。
- `fish`：适用于默认 fish Shell，单独处理引号与反斜杠转义。
- `powershell`：适用于 Windows PowerShell 与跨平台 PowerShell。
- `cmd`：适用于 Windows 命令提示符。

> 💡 **提示**：除了在命令行临时指定，您可以在主机配置文件 `~/.xops/xops_config.yaml` 中为节点持久化设置 `execution`，详情参见[主机与身份配置](./hosts)。

## 交互式终端与 PTY (`-x`)

使用 `-x` 参数可为单台主机分配伪终端（PTY），支持交互式全屏终端程序与需要 TTY 的工具：

```bash
# 运行实时系统监控
xops exec -x web-01 top

# 查看需要交互确认的程序
xops exec -x web-01 htop

# 交互式提权执行命令
xops exec -x --sudo web-01 ls -la /root
```

- **单主机限制**：PTY 模式仅支持针对单台主机的即时交互，不支持多主机批处理或本地脚本文件。
- **原生终端流**：交互式命令直接连接本地终端，不设 5 MiB 缓冲上限，命令退出后即刻返回本地终端。
- **输出重定向与兼容性**：支持标准输出与错误重定向（例如 `xops exec -x web-01 uptime 2>error.log`）。
- **取消与清理保障**：当收到中断信号（Ctrl+C）或发生网络断开时，XOps 会在有界时间内主动释放终端资源、终止 SSH 通道并回收后台协程，避免远端进程悬挂。

## 参数引用与转义建议

当命令包含空格、环境变量或特殊符号时，推荐使用 `-c` 并配合正确的单双引号：

```bash
# 在本地保护变量，使其在远端解析
xops exec web-01 -c 'printf "%s\n" "$HOME"'

# 在本地解析变量后传入远端
xops exec web-01 -c "echo Current User is $USER"
```

在本地 Windows（PowerShell 或 CMD）中使用时，请注意本地 Shell 的转义规则差异。更复杂的任务推荐编写为脚本文件，通过 `--shell` 选项分发执行。完整选项见[命令参考](../reference/commands/xops-exec)。
