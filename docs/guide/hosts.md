# 主机与身份

XOps 将网络地址（Host）、认证身份（Identity）及连接节点（Node）分开管理。同一地址可关联多个用户身份。

```bash
xops host add --address 192.0.2.10 --user deploy --key ~/.ssh/id_ed25519 --alias web-01 --tags web
xops host list
xops host tags
xops host import hosts.csv --tag web
```

CSV 格式及完整参数见 `xops host import --help` 和仓库中的示例文件。`inventory` 是 `host` 的兼容别名，新脚本优先使用 `host`。

## 导入时的验证策略

默认先用每行的连接参数验证 SSH 身份认证，仅保存验证通过的节点及凭据。失败行会输出节点 ID、失败原因和“验证失败，未保存”；更新已有节点时，验证失败也不会修改原配置或凭据。

同一节点的重复记录按 CSV 行顺序完成验证和保存，别名会累积保留，后续成功保存的行可更新凭据；不同节点仍并行处理。该规则适用于三种验证模式，结果始终按 CSV 行顺序输出。

导入 IPv6 地址时兼容旧版本不带方括号的节点 ID（如 `root@2001:db8::1:22`）。匹配后保留已有节点 ID 并更新记录；新节点使用带方括号的格式（如 `root@[2001:db8::1]:22`）。

```bash
# 默认：只保存验证通过的节点
xops host import hosts.csv
# 不建立 SSH 连接，直接保存所有有效记录
xops host import hosts.csv --skip-verify
# 仍进行验证，但失败的节点也保存，并在结果中明确标记
xops host import hosts.csv --save-on-verify-failure
```

两个选项互斥，也适用于 `host load` 和 `inventory import`。验证失败会返回非零退出码，包括指定 `--save-on-verify-failure` 的情况；取消操作不会强制保存。跳过验证只跳过连接检查，配置和凭据存储的有效性检查仍会执行。

## 单节点添加

`host add` 默认先验证连接。成功后保存；失败时显示原因，并询问“是否仍然保存此节点？[y/N]”。只有明确回答 `y` 或 `yes` 才会保存，回车、拒绝或无法读取回答都不会保存。自动化脚本需要离线添加时应显式指定：

```bash
xops host add --address 192.0.2.10 --user deploy --skip-verify
```

未提供密码、私钥或认证模板且指定 `--skip-verify` 时，可以先保存节点信息，之后再配置凭据。TUI 添加节点提供相同策略，详见[终端管理界面](./tui)。

显式指定不同用户时复用相同 Host，并使用独立 Identity/Node，避免继承另一个用户的凭据：

```bash
xops ssh deploy@web-01
xops ssh audit@192.0.2.10
```

使用 `xops identity --help` 查看身份管理操作，或运行 `xops tui` 进入[终端管理界面](./tui)。不要将密码放入共享命令记录或文档示例。

## 已删除的凭据参数

`host add|edit` 和 `identity add|edit` 已删除明文参数 `--password`、`--key-pass` 及其短参数。登录密码改用 `--password-stdin`，私钥口令改用 `--passphrase-stdin`。这两个选项互斥，`--password-stdin` 也不能与 `--key` 同时使用。`host add` 的两个标准输入选项均不能与 `--identity` 同时使用。

例如，`xops identity edit admin --password-stdin` 从标准输入读取新密码；`xops host edit web --key ~/.ssh/id_ed25519 --passphrase-stdin` 从标准输入读取私钥口令。通过可信管道或文件重定向提供输入，避免将凭据值写入命令参数和 Shell 历史。空输入会在保存资产变更前被拒绝。编辑时省略这些选项会保留现有凭据，但切换认证方式或私钥时会相应更新凭据引用。

交互式密码提示和 `xops identity credential set` 仍可使用。旧命令 `loadHost` 已删除，请改用 `xops host import`。
