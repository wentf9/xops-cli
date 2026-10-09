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

`exec` 要求远端 SSH 执行环境中可调用 Bash：普通命令包装为 `bash -l -c`，`--no-login` 仅改为 `bash -c`。Windows SSH 目标同样需要 Bash；命令中显式调用 `powershell.exe` 不会去掉外层 Bash。没有 Bash 时，文件任务可通过 SCP/SFTP 下载、本地编辑、上传并重新下载核验；目录操作使用 SFTP 文件命令，SFTP 的 `exec` 也依赖 Bash。

## 交互式命令

```bash
xops exec -x web-01 top
xops exec -x web-01 ls
xops exec -x --sudo web-01 ls /root
```

`-x` 为单台主机提供交互终端，适合 `top`、`vim` 等终端程序，不支持多主机或本地脚本文件，也需要远端安装 Bash。命令结束后返回本地终端，不额外打开远端 shell。

命令自身或登录启动脚本打印的内容仍保留。需要完整交互 shell 时使用 `xops ssh`。仅执行 `ls` 等命令时通常不需要 `-x`。

## 引号

将希望交给远端解释的表达式用本地 shell 的正确引号保护。例如 Bash 中：

```bash
xops exec web-01 -c 'printf "%s\n" "$HOME"'
```

在本地使用 PowerShell 时，引号规则不同；复杂任务优先使用脚本文件，远端仍需 Bash。完整选项见[命令参考](../reference/commands/xops-exec)。
