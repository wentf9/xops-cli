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

## 节点执行环境配置 (`execution`)

### 自动探测与诊断

`host add` 和 `host import`（包括 `host load` 别名）默认在新节点认证成功后，复用同一连接
探测启动方言与可用解释器，并将推荐的 `execution` 随节点一起保存。探针最多约 9 秒；失败时
输出警告，仍可保存认证成功的节点，并保留未配置状态。导入已有节点不会自动重探或覆盖其执行配置。

```bash
# 验证连接，但跳过探针；也可使用 --probe=false
xops host add --address 192.0.2.10 --user deploy --key ~/.ssh/id_ed25519 --no-probe
xops host import hosts.csv --no-probe
# 显式字段优先于探测推荐；导入时仅应用于新节点
xops host add --address 192.0.2.10 --user deploy --key ~/.ssh/id_ed25519 --interpreter sh --launch-dialect posix
# 诊断已保存的节点或别名，默认只展示结果
xops host probe web-01
# 替换该节点的 execution，其他字段及凭据保持不变
xops host probe web-01 --save
```

`--skip-verify` 同时跳过探针；`--probe` 与 `--no-probe` 不能同时指定。显式执行字段始终保留，
若与探测结果不兼容，会输出警告并仅保存显式字段。探测失败时不会持久化部分推荐。

探测连接使用独立的 `server/unknown` 配置，目标及跳板的命令执行配置不参与探测连接的解析。
例如全局为 `bash/posix` 时，新节点仍可仅指定 `--interpreter powershell`，由探针补齐 Windows
启动方言；全局配置保持不变，连接凭据、主机密钥校验和跳板路径照常使用。

`host probe` 使用现有连接凭据进行非交互式认证，显示远端系统、Shell 路径、SSH 标识、启动方言、
可用解释器与推荐配置；无法确定的元数据以 `-` 显示。仅 `--save` 写回配置；探测失败或节点在探测
期间被修改时不保存，并返回非零退出码。Linux 通常推荐 bash（其次 sh），关闭 login；Windows CMD
存在 Windows PowerShell 时仍推荐 `server/cmd`。探测不会翻译用户命令。

直接 SSH/交互式 exec 首次连接新节点时，若已启用凭据记忆且执行配置未指定，会在认证成功后、
节点确认前复用连接探测，并随新节点原子保存推荐。仅会话凭据、非交互 exec 批处理、已有节点及显式执行配置不触发此路径。CLI 显式 `--interpreter`、`--launch-dialect`、`--login-shell` 或 `--no-login`（包括显式 false）会跳过目标节点的录入探测，参数仅用于本次会话；凭据记忆和其他节点的探测策略照常生效。
探针失败只警告，认证成功的节点仍按原策略保存。如果底层连接已断开，连接请求返回错误，不缓存该连接或派发用户命令。TUI 添加仍使用原有纯连接验证。

Playbook 无 shebang 的 script、ensure 及 SFTP 非空 cwd 的 `exec` 可在执行配置未指定时按需探测。
这些运行时结果仅保留在连接缓存中，不自动写入磁盘；显式解释器（包括 `server`）始终保留。

### 手动配置

除了网络地址与认证身份外，您可以在配置文件 `~/.xops/xops_config.yaml` 中为每个节点持久化预设执行环境（如解释器、启动方言及登录模式），使得 `xops exec`、`xops ssh`、Playbook 以及 MCP 能够自动采用最契合该主机的执行方式：

```yaml
schema_version: 2
# 全局默认执行配置（可选）
execution:
  interpreter: server

nodes:
  # 场景 1：精简容器 / Alpine Linux（无 Bash 环境，原生执行）
  alpine-01:
    host_ref: h_alpine
    identity_ref: id_root
    execution:
      interpreter: server

  # 场景 2：传统 Linux 服务器（需要加载个人登录环境变量）
  web-prod-01:
    host_ref: h_web
    identity_ref: id_deploy
    execution:
      interpreter: bash
      launch_dialect: posix
      login: true

  # 场景 3：Windows Server（通过 PowerShell 执行命令）
  win-ad-01:
    host_ref: h_win
    identity_ref: id_admin
    execution:
      interpreter: powershell
      launch_dialect: powershell
```

- **配置优先级**：CLI 显式命令行参数 > Playbook 步骤设置 > Playbook 全局设置 > 节点配置 (`node.execution`) > 全局配置 (`cfg.execution`) > 系统默认 (`server`)。
- **免显式指定**：一旦为节点配置了正确的解释器，在执行命令或通过管道传入脚本（如 `cat script.sh | xops ssh web-prod-01`）时，XOps 会自动应用对应的解释器与登录环境，无需每次手动指定 `--interpreter`。


## 已删除的凭据参数

`host add|edit` 和 `identity add|edit` 已删除明文参数 `--password`、`--key-pass` 及其短参数。登录密码改用 `--password-stdin`，私钥口令改用 `--passphrase-stdin`。这两个选项互斥，`--password-stdin` 也不能与 `--key` 同时使用。`host add` 的两个标准输入选项均不能与 `--identity` 同时使用。

例如，`xops identity edit admin --password-stdin` 从标准输入读取新密码；`xops host edit web --key ~/.ssh/id_ed25519 --passphrase-stdin` 从标准输入读取私钥口令。通过可信管道或文件重定向提供输入，避免将凭据值写入命令参数和 Shell 历史。空输入会在保存资产变更前被拒绝。编辑时省略这些选项会保留现有凭据，但切换认证方式或私钥时会相应更新凭据引用。

交互式密码提示和 `xops identity credential set` 仍可使用。旧命令 `loadHost` 已删除，请改用 `xops host import`。
