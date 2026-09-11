# 交互式命令执行

`xops exec -x <host> <command>` 分配 PTY，并通过 SSH exec 请求直接执行
`bash -l -c '<command>'`。它加载 Bash 登录环境，支持 `vim`、`top` 等终端程序，
不再先启动交互式登录 shell 或向 stdin 注入命令，因此不会产生外层提示符和命令回显。
远端启动脚本及命令自身输出仍会保留；不会通过文本过滤删除输出。

需要完整交互式 shell 时使用 `xops ssh <host>`。
`exec -x --sudo` 同样通过 SSH exec 请求直接运行 sudo/su 目标命令，不再进入 root 交互式 shell 后注入命令。PTY 密码认证仍被保留，认证完成后原样转发命令输出。
