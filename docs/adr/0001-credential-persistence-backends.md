# ADR-0001：凭据持久化采用可插拔后端与引用模型

- 状态：提议
- 日期：2026-09-04
- 决策范围：登录密码、私钥 passphrase、sudo/su 提权密码

## 背景

当前配置模型直接包含 `Password`、`Passphrase` 和 `SuPwd`。文件存储使用本地
`secret.key` 对这些字段执行 AES-GCM 加密，但配置加载时会解密全部秘密，内存快照、
编辑表单和 SSH 客户端配置都可能长期持有明文。

该方案能够避免配置文件直接出现明文，但配置密文与解密密钥通常位于同一用户目录，
无法充分抵御整个用户目录被复制、同用户恶意进程或运行时内存泄露。它也无法自然接入
Windows Credential Manager、macOS Keychain、Linux Secret Service、`pass` 或远程
Secret Manager。

XOps 同时存在 CLI、TUI、MCP、Playbook 和批处理调用方。部分调用方允许交互，部分
调用方必须严格非交互，因此凭据持久化不能与终端提示或 SSH 握手状态机绑定。

## 决策

采用“配置平面与凭据平面分离”的模型：

1. YAML 和所有 `config.Provider` 快照只保存凭据引用，不保存明文或可逆密文。
2. 凭据引用由 `StoreID` 和不可变的随机 `ItemID` 组成。
3. 系统密钥库、`pass`、外部 Secret Manager 和兼容存储通过统一 Credential Helper
   协议接入。
4. SSH 层保留调用方注入的 `InteractionHandler`，并额外接收配置、秘密解析和成功后
   凭据记录三个小接口。
5. 有引用但后端缺失、锁定或不可用时失败关闭，不自动改用终端输入或文件后端。
6. 没有引用时，只有交互调用方可以询问用户；MCP 和批处理返回
   `ErrInteractionRequired`。
7. 新秘密使用 copy-on-write：写入新的 `ItemID`，配置 CAS 成功且 durable 后再清理
   旧引用。
8. 旧 AES 存储只保留显式迁移能力，不作为 Schema v2 的默认写入后端。

## 默认策略

- Windows/macOS 桌面：`credential doctor` 通过后建议 `system`。
- Linux 桌面：Secret Service 检查通过后建议 `system`。
- Linux headless：默认 `none`，提示用户显式配置 `pass` 或 `external`。
- MCP/CI：建议 SSH agent 或 `external`，禁止交互式解锁。
- 交互获得的新秘密：默认 `remember_prompted: ask`。
- 非交互调用方：默认 `remember_prompted: never`。
- 禁止密钥库失败后自动回退到明文、Base64 或旧加密文件。

## 后端集合

| 类型 | 用途 | 是否持久化 | 说明 |
| --- | --- | --- | --- |
| `system` | 桌面用户 | 是 | Keychain、Credential Manager、Secret Service |
| `pass` | 无桌面 Linux | 是 | 使用 GPG/`pass`，解锁由 GPG agent 管理 |
| `external` | Vault、1Password、企业系统 | 由后端决定 | 通常只读，可返回过期时间 |
| `none` | 每次输入 | 否 | 非交互调用方失败关闭 |
| `legacy-file` | 迁移旧配置 | 是 | 仅兼容读取和迁移，不接受新写入 |

进程内缓存是后端装饰器，不是独立持久化后端。缓存必须有 TTL、容量上限，并在淘汰时
尽力清零秘密字节。

## 被否决的方案

### 仅将 `secret.key` 保存到系统密钥库

该方案仍会在 `Store.Load` 时解密整份配置，无法阻止明文进入全局快照，也无法按身份或
秘密粒度进行授权、轮换和清理。

### 直接在配置模型中保存密码

即使序列化层负责加密，领域模型和复制接口仍会传播明文，容易在调试输出、测试失败或
未来新增调用方中泄露。

### 系统密钥库失败后自动回退文件

这会让用户无法判断秘密实际存放位置，并在 headless 环境中悄然降低安全等级。

### 删除 `InteractionHandler`，由 CLI 捕获错误后重新连接

密码、多个私钥 passphrase 和 HostKey 确认可能在一次 SSH 握手中多次发生。让 CLI、
TUI、MCP 和 Playbook 重建握手状态会复制状态机并引入错误的临时凭据持久化。

## 影响

### 正面影响

- 配置、快照、列表和普通编辑流程不再接触秘密。
- 可以为桌面、headless 和自动化场景选择不同后端。
- 后端故障具有统一、可判断的错误语义。
- 凭据轮换与现有配置版本 CAS 可以组合，避免并发覆盖。

### 代价

- YAML 与凭据后端之间不存在原子事务，需要补偿和恢复日志。
- SSH 连接配置、sudo 执行和 TUI 编辑需要拆分明文生命周期。
- 系统后端需要原生平台集成测试。
- Schema v1 到 v2 需要显式、可恢复的迁移过程。

## 决策门

开始行为变更前必须确认：

1. 是否接受 headless 新安装默认 `none`，不自动启用 `pass`。
2. 是否接受交互式自动发现的凭据默认询问后再保存，而不是保持当前自动写回行为。
3. Schema v1 的普通运行兼容期采用一个还是两个正式发布周期。

如果这些决策变化，应先更新本 ADR，再修改代码。
