# 主机与身份

XOps 将网络地址（Host）、认证身份（Identity）及连接节点（Node）分开管理。同一地址可关联多个用户身份。

```bash
xops host add --address 192.0.2.10 --user deploy --key ~/.ssh/id_ed25519 --alias web-01 --tags web
xops host list
xops host tags
xops host import hosts.csv --tag web
```

CSV 格式及完整参数见 `xops host import --help` 和仓库中的示例文件。`inventory` 是 `host` 的兼容别名，新脚本优先使用 `host`。

显式指定不同用户时复用相同 Host，并使用独立 Identity/Node，避免继承另一个用户的凭据：

```bash
xops ssh deploy@web-01
xops ssh audit@192.0.2.10
```

使用 `xops identity --help` 查看身份管理操作，或运行 `xops tui` 进入[终端管理界面](./tui)。不要将密码放入共享命令记录或文档示例。
