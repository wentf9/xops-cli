# SSH 与提权

```bash
xops ssh web-01
xops ssh -i ~/.ssh/id_ed25519 deploy@192.0.2.10
xops ssh -J bastion.example.com deploy@192.0.2.10
```

单标签跳板名称需要预先配置为节点或别名。显式用户连接同一主机时，凭据保持独立。

## 提权

```bash
xops ssh --sudo web-01
xops exec -x --sudo web-01 id
```

提权方式由节点配置决定，包括 root、免密 sudo、密码 sudo、su 等模式。只能普通用户登录的服务器可以使用 su 模式，在普通用户的 SSH 连接中通过 root 密码切换身份，不要求开放 root SSH 登录。

`ssh --sudo` 提供提权后的交互 shell；`exec -x --sudo` 直接执行提权命令。后者保留 PTY 认证，但不额外显示 root shell 提示符和注入命令回显。自定义 su/PAM 多轮认证和登录脚本应在目标环境验证。

## 隧道

```bash
xops ssh -L 8080:127.0.0.1:80 -N web-01
xops ssh -D 1080 -N web-01
```

会话退出后隧道关闭。连接、密钥指纹和凭据问题见[故障排查](../troubleshooting/)。
