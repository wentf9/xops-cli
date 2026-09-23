# 凭据存储

`credential doctor` 对尚无凭据引用、库和密钥均不存在且允许自动初始化的离线库显示 WARN（not initialized），不因此返回失败，也不创建库或密钥。有凭据引用但库缺失、部分初始化或异常路径仍报告失败。元数据可读不等于已验证解密或写入权限。

XOps 将登录密码、私钥解锁口令和提权密码保存在凭据库中，配置文件只记录它们的引用。新安装默认使用内置离线加密库，无需先安装系统密钥环或外部工具。

本文描述当前源码中的功能；已安装版本的选项以 `xops credential --help` 为准。

## 默认保存行为

首次保存凭据时，XOps 在配置文件所在目录创建 `credentials/` 和密钥文件 `credentials.key`。默认配置下，它们位于 `~/.xops/`。密码只有在认证成功后才会自动保存，私钥口令还需要成功解锁对应私钥。

`credential.remember_prompted` 控制提示输入的凭据是否保存：

| 值 | 行为 |
| --- | --- |
| `always`（默认） | 验证成功后自动保存 |
| `ask` | 验证成功后询问是否保存 |
| `never` | 仅用于当前连接，不自动保存 |

连接时可以临时覆盖，不修改全局设置：

```bash
xops ssh --remember never web-01
xops tui --remember ask
```

`never` 同时禁止自动升级旧配置，但不阻止手动提交凭据表单或显式执行迁移。已有配置中明确选择的存储和保存策略会保留。

## 选择存储

| 后端类型 | 用途 | 前置要求 |
| --- | --- | --- |
| `encrypted-file` | 内置离线加密库，默认存储 | Linux、Windows 或 macOS 的 amd64/arm64 平台 |
| `system` | 操作系统密钥库 | 系统密钥库可访问、已解锁 |
| `pass` | 使用现有 pass 密码库 | pass、GPG 及已初始化的密码库 |
| `helper` | 接入外部凭据服务 | 支持 XOps 凭据协议的外部程序 |
| `none` | 临时交互会话 | 不持久化凭据 |

默认配置中的 `file` 是存储名称，`encrypted-file` 是后端类型：

```yaml
credential:
  default_store: file
  remember_prompted: always
  stores:
    file:
      type: encrypted-file
      path: credentials
      unlock: key-file
      key_file: credentials.key
```

相对路径均以配置文件所在目录为基准。其他后端配置见[配置示例](https://github.com/wentf9/xops-cli/blob/master/xops_config.example.yaml)。检查已配置的存储：

```bash
xops credential store list
xops credential doctor
```

`doctor` 检查非交互读取是否可用，不会初始化离线库或弹出解锁提示，也不证明存储目录具有写权限。更换后端时请按[迁移指南](./migration)操作；只修改 `default_store` 不会搬迁已有凭据。

### Linux 系统密钥库

`system` 需要 `secret-tool`（Ubuntu/Debian 包名为 `libsecret-tools`）、用户 D-Bus 会话和 Secret Service。批处理和 MCP 不会弹出解锁窗口。交互式删除节点、身份或执行 `xops credential gc` 时，XOps 会先请求解锁匹配的密钥库条目，再删除凭据；取消解锁或清理失败时会保留恢复 Journal，可在解锁密钥库后重新运行 `xops credential gc`。

如果匹配条目分布在多个密钥环中，只解锁其中一部分仍算清理未完成。系统工具在 stderr 中输出的正常 `attribute.*` 元数据不算错误；即使退出码为 0，解锁或删除报告的条目错误仍会使 XOps 保留恢复 Journal。解锁其余密钥环后可再次运行 `xops credential gc`。

## 认证失败与临时输入

在交互式连接中，服务器拒绝密码后可重新输入，总计最多尝试三次。私钥口令错误也最多尝试三次；私钥文件损坏时应修复或更换文件。

凭据库锁定、不可用、损坏或原记录无法读取时，支持交互的连接可以提示您临时输入。XOps 不会用临时输入覆盖无法读取的记录，也不会自动替换损坏的库或丢失的密钥。MCP 和批处理等非交互操作会报错，需要先恢复凭据访问。

SSH 认证成功后，即使自动保存失败，本次连接仍可使用。请根据提示检查配置和目录权限；新输入的凭据可能需要在下次连接时重新输入。

## 提权密码

SSH 登录与 sudo/su 提权分别验证。登录成功不代表提权成功；sudo 密码单独保存，不会覆盖登录密码。免密或已有有效授权缓存的 sudo 不要求输入密码。

提权密码验证成功后，即使命令本身失败，密码仍可按策略保存，命令仍返回失败状态。密码最多尝试三次；可能已经开始执行的命令不会为了重试认证而自动重跑。交互式提权需要远端具备 Bash 和 `stty`。

## 备份与恢复

请同时备份配置文件、整个凭据库目录和对应解锁材料，并将密钥备份与库文件备份分开保管。仅备份配置文件无法恢复密码。读取、检查和解锁不会创建替代密钥；已有库的密钥丢失时，需要找回原密钥备份。

初始化、主口令模式、密钥轮换和恢复步骤见[离线凭据库](./offline-store)。

## 已删除的明文参数

`--password`、`--passphrase` 和 `--suPwd` 已不再接受。SSH、SFTP、SCP 和 exec 支持 `--password-stdin`、`--passphrase-stdin`；交互连接也可使用安全提示或已保存的凭据。sudo/su 密码通过安全提示或已配置的凭据库提供。防火墙命令不再接受 `--password/-w`，无人值守执行前应先配置身份凭据。资产命令的替代方式见[主机与身份管理](./hosts#已删除的凭据参数)。

SSH 和 exec 会拒绝远端命令之前的未知参数。远端命令名或显式 `--` 分隔符之后的参数保持原样传递。
