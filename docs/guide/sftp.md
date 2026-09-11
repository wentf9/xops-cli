# SFTP 与文件传输

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
