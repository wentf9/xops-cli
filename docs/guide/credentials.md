# 凭据存储

XOps 将登录密码、私钥解锁口令和 `sudo`/`su` 提权密码保存在专门的凭据库中，配置文件 `~/.xops/xops_config.yaml` 只记录凭据引用（Reference），不保存明文或旧版 `ENC:` 字段。

新安装默认使用内置离线加密库（`encrypted-file`），开箱即用，无需预先安装桌面密钥环或外部工具。可用选项可通过 `xops credential --help` 查看。

## 默认保存行为

首次保存凭据时，XOps 会在配置文件同级目录自动创建加密库目录 `credentials/` 与密钥文件 `credentials.key`（默认位于 `~/.xops/`）。
- **先验证后保存**：登录密码仅在 SSH 认证成功后保存；私钥口令必须成功解锁对应私钥后才会保存。
- **保存策略控制**：配置项 `credential.remember_prompted` 控制交互式输入的凭据是否自动保存：

| 值 | 行为 |
| --- | --- |
| `always`（默认） | 验证成功后自动保存 |
| `ask` | 验证成功后询问是否保存 |
| `never` | 仅用于当前连接，不自动保存 |

连接时可通过 `--remember` 临时覆盖单次行为，不会修改全局配置：

```bash
xops ssh --remember never web-01
xops tui --remember ask
```

`never` 仅禁止连接过程中的自动记住，不影响手动提交凭据表单或显式执行迁移。Schema v1 兼容期已结束，若仍在使用旧版配置，请先按[凭据迁移](./migration)显式升级为 v2。

## 选择与检查存储

| 后端类型 | 适用场景 | 前置要求 |
| --- | --- | --- |
| `encrypted-file` | 内置离线加密库（默认） | Linux、Windows 或 macOS（amd64 / arm64） |
| `system` | 操作系统原生密钥库 | 系统密钥库可访问且已解锁 |
| `pass` | 复用现有 `pass` 密码库 | 已安装 `pass`、`gpg` 并完成密码库初始化 |
| `helper` | 接入外部自定义凭据服务 | 实现 XOps 凭据协议的外部可执行程序 |
| `none` | 纯临时会话 | 不持久化任何凭据 |

默认配置中，`file` 是存储实例名，`encrypted-file` 是后端类型（相对路径以配置文件所在目录为基准）：

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

其他后端的完整写法可参考仓库中的 [`xops_config.example.yaml`](https://github.com/wentf9/xops-cli/blob/master/xops_config.example.yaml)。日常可用以下命令查看存储列表与健康状态：

```bash
xops credential store list
xops credential doctor
```

- **`credential doctor` 检查说明**：`doctor` 仅执行只读、非交互检查，不会自动初始化离线库、不会弹出解锁窗口，也不代表目录具备写入权限。对于尚无任何凭据引用、库和密钥文件均尚未创建且允许自动初始化的默认离线库，`doctor` 会显示 `WARN (not initialized)` 并正常退出（不报错、不创建文件）；但如果配置中已有凭据引用而库缺失、部分初始化或路径不安全，则会明确报告 `FAIL`。
- **切换后端**：仅修改 `default_store` 不会搬迁已有凭据；更换存储后端请按[凭据迁移](./migration)操作。

### Linux 系统密钥库（`system`）

在 Linux 上使用 `system` 后端需要安装 `secret-tool`（Ubuntu/Debian 包名为 `libsecret-tools`），且当前进程能够访问用户的 D-Bus 会话与 Secret Service。
- 批处理（`exec`、`play`）和 MCP 不会弹出桌面解锁对话框；若密钥库处于锁定状态会返回 `locked`，需先在桌面会话中解锁。
- 交互式删除节点/身份或运行 `xops credential gc` 时，XOps 会先请求解锁匹配的密钥环条目再执行清理。若取消解锁、仅解锁了部分密钥环或工具报告条目错误（即使退出码为 0；正常的 `attribute.*` stderr 元数据除外），XOps 会保留恢复日志，待全部解锁后再次运行 `xops credential gc` 即可完成清理。

## 认证重试与临时输入

- **密码与口令重试**：交互式连接中，若服务器拒绝密码或私钥口令错误，最多可重新输入 3 次（若私钥文件本身损坏，请先修复或更换私钥）。
- **凭据库故障时的临时输入**：当凭据库锁定、不可用、损坏或某条记录无法读取时，交互式命令允许临时输入密码继续连接，但**不会**用临时输入覆盖无法读取的记录，也不会自动替换损坏的库或生成新密钥。MCP 与批处理等非交互模式会直接报错。
- **保存失败不中断连接**：若 SSH 认证已成功但写入凭据库失败，本次连接仍可正常使用，请按提示排查目录或配置权限（下次连接可能需重新输入）。

## 提权密码（`sudo` / `su`）

SSH 登录密码与 `sudo`/`su` 提权密码独立验证、分开存储：
- 免密 `sudo` 或尚在有效期内的 `sudo` 授权缓存不会请求密码。
- 提权密码一旦通过握手验证，即使后续用户命令返回非零退出码，该提权密码仍会按策略保存，同时命令正常返回失败状态。
- 提权密码同样最多尝试 3 次；一旦用户命令可能已经开始执行，绝不会为了重试认证而重复运行命令。交互式提权要求远端具备受支持的 Shell 与 `stty`。

## 备份与恢复

备份时请同时保存：**配置文件**、**整个凭据库目录**以及**对应的解锁密钥文件**，并将密钥文件与凭据库分开存放。仅备份配置文件无法找回密码；已有凭据库的密钥一旦丢失，读取、检查或解锁均不会生成替代密钥，必须从备份恢复原密钥。

主口令模式、密钥轮换与跨目录恢复步骤见[离线凭据库](./offline-store)。

## 已移除的明文参数

为防止密码留在进程列表或 Shell 历史中，所有命令均已移除 `--password`、`--passphrase`、`--suPwd` 及防火墙的 `--password/-w` 明文参数：
- **SSH / SFTP / SCP / exec**：使用安全交互提示、已保存凭据，或通过受控管道传入 `--password-stdin` / `--passphrase-stdin`。
- **主机与身份管理（`host` / `identity`）**：使用 `--password-stdin`、`--passphrase-stdin` 或 `xops identity credential set`，详见[主机与身份管理](./hosts#已删除的凭据参数)。
- **参数边界**：`ssh` 和 `exec` 会拒绝远端命令之前的未知参数；远端命令名或显式 `--` 分隔符之后的参数则原样传给远端。
