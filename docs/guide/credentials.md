# 凭据存储

Schema v2 在配置中保存 `CredentialRef`，不保存明文密码。新安装默认使用 `none`，只在当前会话使用输入的密码。

| 后端 | 适用环境 | 前置要求 |
| --- | --- | --- |
| `none` | 临时交互会话 | 不持久化秘密 |
| `system` | 桌面操作系统 | 系统密钥库可访问、已解锁 |
| `pass` | Linux 运维环境 | pass、GPG 及已有密码库 |
| `helper` | 外部凭据系统 | 实现 XOps helper 协议 |
| `encrypted-file` | 显式选择离线库 | Linux、Windows、macOS 64 位平台，独立解锁和恢复流程 |

配置示例见 [xops_config.example.yaml](https://github.com/wentf9/xops-cli/blob/master/xops_config.example.yaml)。先配置并检查后端，再设为默认：

```bash
xops credential store list
xops credential doctor
```

配置引用指向不可用后端时会报错，不会自动改用其他秘密。MCP、批处理等无交互路径不会静默弹出解锁提示。

## Linux system

需要 `secret-tool`（Ubuntu/Debian 包名 `libsecret-tools`）、用户 D-Bus 会话以及 Secret Service。doctor 不自动启动服务，也不解锁密钥库。服务未启动时先启动桌面密钥环服务，再重试。

## 离线库

离线库需要显式初始化、解锁与恢复操作。格式/接口 v1 已冻结，但冻结不等于正式版本已发布。请先阅读[现有离线库操作手册](https://github.com/wentf9/xops-cli/blob/master/docs/development/archive/offline-encrypted-credentials.md)，不要把库文件和恢复材料放在同一备份位置。

doctor 是有限的非交互读取检查，不证明写权限；离线库的元数据检查也不代表已经解锁或完成完整性验证。

### 自动或手动准备 key-file

配置 `unlock: key-file` 和 `key_file` 后，运行 `xops credential store init <storeID>`：文件不存在时自动生成 32 字节随机密钥（权限 0600），已有合规文件直接复用。rewrap、clone、restore 等准备新包裹材料的操作也支持此行为。父目录需已存在；初始化及跨库操作的 key_file 必须放在目标库目录之外。

可手动生成后再初始化，例如 Bash 中：

```bash
(umask 077; set -C; openssl rand 32 > ~/.xops/offline.key)
```

已有文件仍须满足长度、权限、所有者和非链接要求，非法文件不会被自动修复或覆盖。读、解锁、doctor 和 resume 不生成替代密钥，丢失原密钥必须恢复备份。已生成密钥不会因后续操作失败而被删除，重试会复用；请独立备份。

初始化前可使用 `xops credential store probe <storeID>` 检查目标文件系统的实际操作能力，详见[兼容性矩阵](../development/compatibility)。
