# 凭据存储

::: info 实施中（未发布）
当前工作分支已实现默认离线配置和 v1 自动升级；SSH 认证恢复已实现，TUI 认证与自动保存已接入，通用 v2 后端迁移已实现，最终六平台原生验收仍待完成。详见[实施进度](../development/credential-experience-plan)。
:::

Schema v2 在配置中保存 `CredentialRef`，不保存明文密码。新安装默认使用 `file`（`encrypted-file`、`unlock: key-file`），策略为 `remember_prompted: always`。库目录 `credentials/` 与密钥 `credentials.key` 相对配置文件定位。单次 `--remember never` 或全局 `remember_prompted: never` 禁止保存及自动迁移；已有显式后端保持不变。

| 后端 | 适用环境 | 前置要求 |
| --- | --- | --- |
| `none` | 临时交互会话 | 不持久化秘密 |
| `system` | 桌面操作系统 | 系统密钥库可访问、已解锁 |
| `pass` | Linux 运维环境 | pass、GPG 及已有密码库 |
| `helper` | 外部凭据系统 | 实现 XOps helper 协议 |
| `encrypted-file` | 默认离线库 | Linux、Windows、macOS 64 位平台，独立解锁和恢复流程 |

配置示例见 [xops_config.example.yaml](https://github.com/wentf9/xops-cli/blob/master/xops_config.example.yaml)。先配置并检查后端，再设为默认：

```bash
xops credential store list
xops credential doctor
```

配置引用无法读取时，具备交互能力的 CLI 可以提示后临时输入；不静默切换后端，也不覆盖无法读取的原记录。MCP、批处理等无交互路径明确报错，不弹出解锁提示。

## Linux system

需要 `secret-tool`（Ubuntu/Debian 包名 `libsecret-tools`）、用户 D-Bus 会话以及 Secret Service。doctor 不自动启动服务，也不解锁密钥库。服务未启动时先启动桌面密钥环服务，再重试。

## 离线库

key-file 离线库首次写入时自动初始化，读取、doctor、dry-run 不初始化；已有库丢失密钥或存在中断事务时必须恢复，不能生成替代密钥。主口令模式继续使用显式初始化和解锁。格式/接口 v1 已冻结，但冻结不等于正式版本已发布。请先阅读[现有离线库操作手册](https://github.com/wentf9/xops-cli/blob/master/docs/development/archive/offline-encrypted-credentials.md)，不要把库文件和恢复材料放在同一备份位置。

doctor 是有限的非交互读取检查，不证明写权限；离线库的元数据检查也不代表已经解锁或完成完整性验证。

### 自动或手动准备 key-file

配置 `unlock: key-file` 和 `key_file` 后，运行 `xops credential store init <storeID>`：文件不存在时自动生成 32 字节随机密钥（权限 0600），已有合规文件直接复用。rewrap、clone、restore 等准备新包裹材料的操作也支持此行为。父目录需已存在；初始化及跨库操作的 key_file 必须放在目标库目录之外。

可手动生成后再初始化，例如 Bash 中：

```bash
(umask 077; set -C; openssl rand 32 > ~/.xops/offline.key)
```

已有文件仍须满足长度、权限、所有者和非链接要求，非法文件不会被自动修复或覆盖。读、解锁、doctor 和 resume 不生成替代密钥，丢失原密钥必须恢复备份。已生成密钥不会因后续操作失败而被删除，重试会复用；请独立备份。

初始化前可使用 `xops credential store probe <storeID>` 检查目标文件系统的实际操作能力，详见[兼容性矩阵](../development/compatibility)。

## SSH 认证恢复（实施中，未发布）

交互式 CLI 的 password/auto 认证在服务器拒绝密码后允许重输，总计最多三次认证尝试；每次重试直接请求新输入，不反复读取失效的旧密码。key/auto 认证只有口令错误才重试解锁，总计最多三次；私钥格式损坏不会反复提示。新密码只在 SSH 握手成功后交给保存流程，私钥口令还必须实际解锁对应私钥成功。

已保存凭据缺失、锁定、不可用或访问被拒绝时，允许交互临时输入。快照不匹配、取消和超时不进入该恢复路径。没有交互能力的调用保持明确报错。

SSH 握手成功后保存失败，会给出提示并保留连接；该连接的认证和提权写回令牌被禁用，避免用不确定的配置版本继续覆盖凭据。不会因此覆盖无法读取的原记录。网络目标发生不兼容变化时仍拒绝发布连接。

SSH 握手和提权各自验证，不能将 SSH 握手成功视为提权成功。TUI 行为见 [TUI 指南](./tui)，剩余平台门禁见实施计划。

## 提权凭据（未发布）

普通命令、脚本和流式 IO 已区分 sudo/su 认证结果与用户命令退出码。密码验证成功后，即使命令失败仍可保存；命令错误继续返回调用者。交互密码最多尝试三次，已经可能开始的用户命令不会被自动重跑。

密码与命令输入分阶段发送。缓存或免密 sudo 的交互调用不会索要密码，也不会把密码混入 stdin。错误密码不保存；sudo 密码独立保存，不覆盖登录记录，也不误用旧 SuPwd。

独立交互式 PTY shell/exec 也支持有界认证重输。密码输入完成前不切换本地 raw 模式，远端恢复回显后才发送键盘输入；退出时先停止读取器与尺寸监听，再恢复终端模式。远端交接使用 Bash 和 stty。剩余验收门禁见[实施进度](../development/credential-experience-plan)。
