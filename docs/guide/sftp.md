# SFTP 与文件传输

批处理中的 `lls`/`lll` 和远端 `ls`/`ll` 遇到路径不存在或目录读取失败时也会立即失败；通配符匹配结果中任一路径列出失败，会停止剩余匹配及后续命令。

管道或文件输入自动进入批处理模式：任一命令失败立即停止并返回非零状态，不执行后续命令，不写交互历史。批处理 `exec` 不申请 PTY；`exec` 和 `lexec` 的标准输入为 EOF，不会读取后续 SFTP 命令。`shell/lshell` 需要交互终端；覆盖或删除需要确认时，必须使用已有的 force/no-clobber 选项，否则报错。单行命令上限为 1 MiB。交互终端中普通命令失败会显示错误并允许继续，连接或输出故障仍会终止会话。

```bash
xops sftp web-01
```

进入 SFTP shell 后用 `help` 查看完整命令。常用操作：

```text
pwd
ls
cd /var/tmp
put ./report.txt
get report.txt
exec date
exit
```

`exec` 在当前远端目录执行命令，并提供 PTY 以支持终端程序。命令结束后返回 SFTP 提示符。`shell` 进入远端 shell，`lexec` 执行本地命令；退出远端交互程序后才继续输入 SFTP 命令。

批量文件分发使用 SCP：

```bash
xops scp ./config.conf --tag web --dest /etc/app/
```

确认目标目录权限，避免覆盖不应修改的文件。连接中断时 SFTP shell 会退出并返回失败状态，不会继续接受无效操作。
