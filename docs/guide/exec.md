# 命令执行

通过 `--host`、`--ifile`/`-I` 或 `--tag` 选择目标后，第一个位置参数就是远程命令，不需要再提供位置主机参数。`ssh --host` 同样保留完整的位置命令。例如 `xops exec --host web-01 uname -a` 和 `xops ssh --host web-01 uname -a` 均执行 `uname -a`。

`exec` 和 `scp` 的 `--host`、`--ifile`/`-I`、`--tag` 三种目标选择参数互斥，组合使用会在执行前报错。选择其中一种后，可用 `--exclude` 排除部分节点。

全局参数可放在子命令前后，例如 `xops --color never exec --host web-01 uname -a`。SSH/exec 从远程命令开始保留后续参数原样；有歧义时用 `--` 显式分隔，例如 `xops exec --host web-01 -- echo --help`。

## 普通与批量执行

```bash
xops exec web-01 uptime
xops exec --tag web -c 'uptime'
xops exec --tag web --shell ./check.sh --task 5
```

普通模式适合有限输出、脚本和批处理。批处理不会弹出凭据库解锁提示；需要预先准备可非交互访问的凭据。

`exec` 的默认兼容模式要求远端 SSH 执行环境中可调用 Bash：普通命令包装为 `bash -l -c`，`--no-login` 仅改为 `bash -c`。Windows SSH 目标同样需要 Bash；命令中显式调用 `powershell.exe` 不会去掉外层 Bash。没有 Bash 时，文件任务可通过 SCP/SFTP 下载、本地编辑、上传并重新下载核验；目录操作使用 SFTP 文件命令，SFTP 的 `exec` 也依赖 Bash。

## 显式解释器

当前源码已实现 P1 阶段（P1-A 与 P1-B）的全部能力。`exec` 与 `ssh` 均支持显式选择 server 或 Bash 执行，旧入口委托统一命令计划，并为终端/管道提供可取消输出桥；已安装版本以 `xops exec --help` 与 `xops ssh --help` 为准，默认兼容模式尚未切换。

```bash
xops exec --host alpine-01 --interpreter server -c 'uname -a'
xops exec --host linux-01 --interpreter bash --launch-dialect posix --login-shell -c 'printf "%s\n" "$PATH"'
```

server 将 `-c` 字符串原样发送到 SSH exec，不添加 Bash，也不自动探测或转换命令。服务端仍可使用自己的 Shell 或强制命令；Windows 或设备命令必须符合服务端语法。位置参数仍以空格连接；需要保留引用和空白时使用 `-c`。

显式 Bash 要求已知 POSIX 启动方言，默认不加载登录环境；`--login-shell` 启用登录模式，`--login-shell=false` 显式关闭。server 不接受登录选项。P1 中只覆盖方言或登录模式时，解释器仍沿用 Bash+login 的阶段默认，且须提供已知 POSIX 启动方言；切换 server 必须显式指定 `--interpreter server`。`--no-login` 的旧 Bash 含义保留，与 `--login-shell` 互斥。

显式模式支持普通缓冲命令和单主机 PTY 命令，仍拒绝脚本/管道脚本、`--sudo`、`--stream` 和 `--out-dir` 组合。`exec -c` 不把管道输入转发为用户数据。普通缓冲执行保留最后 5 MiB 输出，超出后继续读取并显示截断标记；原命令及引用后的 exec 载荷各最多 64 KiB；单次命令总时限为 5 分钟。非零退出、信号退出和执行结果不确定均报告失败；`outcome=unknown` 表示命令可能已产生副作用，不能直接重跑。关闭连接不证明远端进程已终止。

显式 PTY 示例（客户端 Linux 终端）：

```bash
xops exec --host linux-01 --interpreter server -x top
xops exec --host linux-01 --interpreter bash --launch-dialect posix --login-shell=false -x top
```

新 PTY 路径要求本地终端输入，实时输出不使用 5 MiB 缓冲窗口。Linux 的终端/管道输出使用独立可取消句柄，单次写入上限 10 秒、退出后的输出排空宽限 1 秒；原始标准流不会被关闭或修改文件标志。输入桥初始化失败、输出管道断开或写入超时会立即触发有界清理，不等待整个命令时限；对端不确认通道关闭时会中断 transport，并汇合输出协程。普通文件重定向与其他客户端平台的原生输出桥尚未验收，新路径会在发送命令前拒绝；core 消费者可提供遵守取消契约的 `ContextWriter`。旧 `Run`、`RunWithoutLogin`、`RunCommandWithIO`、`RunStream` 及 `ssh` 命令均已统一委托至命令计划与可取消输出桥；P2 阶段将进一步拓展全局/节点执行配置与多平台适配器。

## 交互式命令

```bash
xops exec -x web-01 top
xops exec -x web-01 ls
xops exec -x --sudo web-01 ls /root
```

`-x` 为单台主机提供交互终端，适合 `top`、`vim` 等终端程序，不支持多主机或本地脚本文件，默认兼容路径需要远端安装 Bash；显式 server 不新增 Bash 包装。命令结束后返回本地终端，不额外打开远端 shell。一次性命令的非零退出、信号退出或退出状态缺失均报告失败；完整登录 Shell 保留既有退出策略。普通 PTY 的 `--no-login` 现在生效；与提权 PTY 组合时暂不支持，提前报错。PTY 也不能组合脚本输入、`--stream` 或 `--out-dir`。

命令自身或登录启动脚本打印的内容仍保留。需要完整交互 shell 时使用 `xops ssh`。仅执行 `ls` 等命令时通常不需要 `-x`。

## 引号

将希望交给远端解释的表达式用本地 shell 的正确引号保护。例如 Bash 中：

```bash
xops exec web-01 -c 'printf "%s\n" "$HOME"'
```

在本地使用 PowerShell 时，引号规则不同；复杂任务优先使用脚本文件，远端仍需 Bash。完整选项见[命令参考](../reference/commands/xops-exec)。
