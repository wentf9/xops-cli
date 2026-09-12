# 命令执行

## 普通与批量执行

```bash
xops exec web-01 uptime
xops exec --tag web -c 'uptime'
xops exec --tag web --shell ./check.sh --task 5
```

普通模式适合有限输出、脚本和批处理。批处理不会弹出凭据库解锁提示；需要预先准备可非交互访问的凭据。

## 交互式命令

```bash
xops exec -x web-01 top
xops exec -x web-01 ls
xops exec -x --sudo web-01 ls /root
```

`-x` 为单主机分配 PTY，不支持多主机或本地脚本文件。普通交互命令通过 SSH exec 请求执行 `bash -l -c`，提权命令直接交由 sudo/su 执行，不先打开额外交互 shell，因此没有外层提示符和命令注入回显。

命令自身或登录启动脚本打印的内容仍保留。需要完整交互 shell 时使用 `xops ssh`。仅执行 `ls` 等命令时通常不需要 `-x`。

## 引号

将希望交给远端解释的表达式用本地 shell 的正确引号保护。例如 Bash 中：

```bash
xops exec web-01 -c 'printf "%s\n" "$HOME"'
```

PowerShell 的引号规则不同，复杂任务优先使用脚本文件。完整选项见[命令参考](../reference/commands/xops-exec)。
