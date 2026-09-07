# 凭据持久化详细设计

## 1. 目标

本设计覆盖登录密码、私钥 passphrase 和提权密码的创建、读取、更新、删除、缓存与迁移。

目标：

- 配置文件和配置快照不包含秘密值；
- 桌面、headless 和自动化环境使用一致的上层契约；
- 每次外部调用可取消、有超时、无 goroutine 和子进程泄漏；
- 配置并发更新继续使用版本前置条件，失败关闭；
- 错误和日志不包含秘密；
- 迁移任一阶段失败时不丢失唯一可用副本。

非目标：

- 不保存 SSH 私钥本体，私钥认证优先使用 `ssh-agent`；
- 不在第一阶段实现远程 Vault 的具体业务协议；
- 不承诺从 Go 堆中绝对擦除所有秘密副本；
- 不改变 HostKey 校验与确认策略。

## 2. 当前数据流

```text
xops_config.yaml + secret.key
          │
          ▼
config.Store.Load：解密所有秘密
          │
          ▼
Repository / Provider：保存并复制明文快照
          │
          ▼
adapter.SSHAdapter：复制到 ssh.ClientConfig
          │
          ▼
Connector / 池化 Client / sudo 执行
```

需要特别处理的现有入口包括：

- `identity add/edit`、`host add/edit`；
- `ssh`、`sftp`、`scp`、`exec` 的密码和 passphrase flag；
- `sudo`、`firewall` 和本地 sudo 密码；
- TUI 节点编辑表单；
- MCP、Playbook 和批量非交互连接；
- `auth_type:auto` 成功后自动发现凭据的写回。

## 3. 目标数据模型

```go
type CredentialRef struct {
	StoreID string `yaml:"store_id"`
	ItemID  string `yaml:"item_id"`
}

type Identity struct {
	User             string         `yaml:"user"`
	KeyPath          string         `yaml:"key_path,omitempty"`
	KeyFingerprint   string         `yaml:"key_fingerprint,omitempty"`
	LoginPasswordRef *CredentialRef `yaml:"login_password_ref,omitempty"`
	PassphraseRef    *CredentialRef `yaml:"passphrase_ref,omitempty"`
	AuthType         string         `yaml:"auth_type"`
}
```

`Node` 使用 `PrivilegePasswordRef`。该名称允许未来表达“sudo 使用独立密码”，而不把字段
永久限制为当前 `su` 语义。

引用必须满足：

- `StoreID` 与 `ItemID` 同时为空或同时非空；
- `StoreID` 必须命中已配置且启用的 Store；
- XOps 创建的 `ItemID` 使用随机不可变 ID；
- 更新秘密必须创建新 `ItemID`，不能原地覆盖；
- passphrase 引用与私钥公钥指纹一起校验；
- 引用本身不是秘密，可以出现在配置版本哈希和错误上下文中。

## 4. 配置结构

```yaml
schema_version: 2

credential:
  default_store: system
  remember_prompted: ask
  stores:
    system:
      type: system
      timeout: 5s
      cache_ttl: 0s
    ops-pass:
      type: pass
      timeout: 15s
      cache_ttl: 10m
      prefix: xops
    prod-vault:
      type: helper
      command: /usr/local/bin/xops-credential-vault
      args: []
      timeout: 10s
      cache_ttl: 5m
      read_only: true
```

`command` 不能是 shell 字符串；它表示一个固定可执行文件，`args` 是独立参数数组。
配置加载时验证超时、TTL、Store 名称和命令路径，但不主动读取秘密。

## 5. 包与接口

建议新增：

```text
pkg/credential/
  ref.go          引用、种类、验证
  errors.go       稳定的错误分类
  store.go        Store 与只读 Source 契约
  registry.go     StoreID 到后端的只读注册表
  service.go      写入、轮换、删除协调
  cache.go        有界 lazy-expiration 缓存
  journal.go      非敏感恢复日志

internal/credentialhelper/
  protocol.go     helper v1 编解码
  process.go      受 context 控制的子进程
  system.go       系统密钥库 helper 组装
  pass.go         pass helper 组装
```

存储契约：

```go
type Source interface {
	Get(ctx context.Context, ref Ref) (Secret, error)
}

type Store interface {
	Source
	Put(ctx context.Context, ref Ref, secret Secret) error
	Delete(ctx context.Context, ref Ref) error
}
```

只读外部来源只实现 `Source`。需要写入时由 `CredentialService` 检查能力并返回
`ErrReadOnly`，不做隐式降级。

SSH 消费方定义自己的小接口：

```go
type ConnectionProvider interface {
	GetConnectionConfig(ctx context.Context, nodeID string) (*ConnectionConfig, error)
}

type SecretResolver interface {
	ResolveSecret(ctx context.Context, request SecretRequest) ([]byte, error)
}

type CredentialRecorder interface {
	RecordAuthentication(ctx context.Context, update AuthenticationUpdate) error
	RecordPrivilegeSecret(ctx context.Context, update PrivilegeUpdate) error
}
```

`adapter.SSHAdapter` 继续作为配置模型与 SSH 模型之间的防腐层。`pkg/ssh` 不导入具体
keyring 库，也不生成终端文案。

## 6. 读取流程

```text
Connector.Connect(ctx, nodeID)
  ├─ ConnectionProvider：取得同一配置版本的元数据与 refs
  ├─ 当前命令有 session-only 覆盖值 → 使用覆盖值
  ├─ ref 非空 → SecretResolver → Registry → 指定 Store
  ├─ ref 为空且调用方可交互 → SecretPrompter
  └─ ref 为空且不可交互 → ErrInteractionRequired
```

ref 已存在时：

- `ErrNotFound` 表示配置与 Store 不一致，直接失败；
- `ErrLocked` 提示用户解锁后重试；
- `ErrUnavailable` 表示后端当前不可达；
- `ErrAccessDenied` 表示当前用户或程序无权读取；
- 以上错误都不能自动触发输入或换用另一 Store。

## 7. 明文生命周期

将当前 SSH 配置拆成：

- `ConnectionConfig`：地址、用户、认证类型、KeyPath、refs、版本令牌；
- `AuthMaterial`：单次握手所需密码或 passphrase；
- `PrivilegeMaterial`：单次 sudo/su 执行所需密码。

登录成功后池化 Client 不保存登录密码。passphrase 在 signer 创建后释放。提权密码在每次
执行时按需读取。秘密优先使用 `[]byte` 表达，并在最后一个明确使用点后清零；由于 Go
字符串和第三方库可能复制数据，只把这视为缩短生命周期，而不是绝对擦除保证。

## 8. Helper 协议 v1

helper 接收固定动作参数：`get`、`store`、`erase`。业务数据通过 stdin/stdout 传输，
秘密禁止进入 argv。

请求：

```json
{
  "protocolVersion": 1,
  "storeID": "system",
  "itemID": "01JXYZ",
  "secret": "base64"
}
```

成功响应：

```json
{
  "secret": "base64",
  "expiresAt": "2026-09-04T14:00:00Z"
}
```

错误响应：

```json
{
  "code": "locked",
  "message": "credential store is locked"
}
```

协议约束：

- stdout 只允许一个有大小上限的 JSON 响应；
- stderr 只用于不含秘密的诊断，并设置大小上限；
- 未知字段可忽略，未知协议主版本必须拒绝；
- secret 使用 Base64，允许将来传输非 UTF-8 数据；
- helper 错误映射为稳定 sentinel error；
- 日志不得打印请求体、响应体或 secret 长度以外的秘密信息。

## 9. 子进程生命周期

Store 调用必须使用调用方 `context.Context` 和后端超时的较早者：

- 使用 `exec.CommandContext`，禁止 shell；
- Unix 创建独立进程组并在取消时终止整个进程组；
- Windows 使用 Job Object 约束子进程树；
- 限制 stdin/stdout/stderr 数据量；
- 所有 pipe 都有确定关闭路径；
- 必须调用 `Wait` 并返回其错误；
- 不能用“后台 goroutine 调同步 keyring，超时后丢弃结果”的方式伪造取消；
- Registry 或缓存锁不能覆盖外部 I/O。

## 10. 写入与轮换事务

YAML 与凭据后端不能形成单一 ACID 事务。所有操作使用新 ref 和非敏感恢复日志。

### 轮换

1. 创建 journal intent，记录旧 ref、新 ref、配置前置版本和阶段；
2. `Put(newRef, secret)`；
3. `Get(newRef)` 读回并常量时间比较；
4. Repository 使用配置版本 CAS 切换到新 ref；
5. 配置 durable 后，将 journal 标记为 committed；
6. 确认旧 ref 当前无引用后删除；
7. 清除 journal。

### 删除

1. Repository 先删除配置引用并 durable；
2. 重新加载当前配置，确认没有任何引用；
3. 删除 Store 项；
4. 删除失败时保留 cleanup journal，不回滚配置。

### 故障结果

| 故障点 | 权威状态 | 后续动作 |
| --- | --- | --- |
| Put 前或 Put 失败 | 旧配置、旧 ref | 清除 intent |
| 读回校验失败 | 旧配置、旧 ref | 尝试删除新 ref |
| 配置 CAS 冲突 | 旧/其他进程的新配置 | 删除本次新 ref |
| 配置未 Applied | 旧配置 | 删除本次新 ref |
| Applied 但非 Durable | 新旧都保留 | 返回 durability error，不补偿 |
| 旧 ref 删除失败 | 新配置、新 ref | 返回 cleanup error，稍后 GC |

journal 使用 `0600` 和原子替换，只记录 refs、操作类型、配置版本与阶段，严禁记录秘密。

## 11. 缓存

- 默认容量 64，可按 Store 配置更小值；
- lazy expiration，不启动清理 goroutine；
- 有效期为 `min(cache_ttl, backend_expires_at)`；
- Put/Delete 后立即使旧缓存失效；
- 淘汰时尽力清零独占的字节切片；
- 返回调用方前复制数据，避免并发修改；
- MCP 和短期动态凭据可按策略完全禁用缓存。

## 12. 调用方行为

### CLI

- 废弃将秘密直接放入 argv 的 `--password`、`--passphrase`、`--suPwd`；
- 增加 `--password-stdin` 等标准输入选项；
- 运行命令的覆盖值默认 session-only；
- `--remember=ask|always|never` 显式控制保存；
- 错误由 cmd 层统一展示一次。

### TUI

编辑页面只显示 `stored in <StoreID>`，不读取和回填旧秘密。秘密字段使用明确的
`keep`、`replace`、`delete` 操作，不能再用空字符串区分状态。

### MCP、Playbook 与批处理

- 不得调用终端输入；
- MCP stdout 只用于 JSON-RPC；
- 推荐 `agent` 或可非交互读取的 external Store；
- 未配置、锁定或不可用都返回类型化错误；
- 默认不记录自动发现的凭据。

## 13. 安全模型

该设计保护：

- 配置文件、普通备份和配置快照中的秘密；
- argv、帮助输出、列表、日志和普通错误中的秘密；
- 后端故障引发的意外明文降级；
- 并发更新导致的旧凭据覆盖。

该设计不保护：

- 已经能以相同用户执行代码并读取该用户密钥库的恶意进程；
- root、内核或调试器读取进程内存；
- 用户主动把秘密通过不安全 helper 输出；
- 已经泄露到旧备份、shell history 或日志中的历史密码。

## 14. 错误与可观测性

稳定错误至少包括：

```text
ErrCredentialNotFound
ErrCredentialStoreLocked
ErrCredentialStoreUnavailable
ErrCredentialAccessDenied
ErrCredentialStoreReadOnly
ErrInteractionRequired
ErrConfigConflict
```

pkg 层只包装并返回。允许记录 StoreID、操作、耗时、结果分类和 ItemID 的短哈希；禁止
记录秘密、完整协议载荷或能被误解为秘密的字段。

## 15. 验收条件

- Schema v2 YAML 和 `Provider.Snapshot()` 不含秘密；
- identity/host 列表和 TUI 初始化不读取 Store；
- 登录密码不进入池化 Client；
- ref 存在但 Store 故障时失败关闭；
- helper 取消后没有进程、pipe 或 goroutine 泄漏；
- 并发轮换只有一个配置 CAS 成功；
- Applied 但非 Durable 时新旧秘密都保留；
- MCP 永不触发凭据输入或密钥库解锁提示；
- v1 到 v2 的每个故障注入点都不丢失唯一秘密副本。

## 16. 原生平台验证记录与 Spike 实验报告

根据阶段 4 实施计划与架构设计约束，对主流操作系统的原生系统凭据库及子进程隔离机制完成了独立 Spike 实验与行为验证，确认技术选型与实现机制如下：

### 16.1 Windows 原生平台验证 (Windows Credential Manager)

- **调用路径**：通过 `advapi32.dll` 导出的 Win32 API（`CredReadW`, `CredWriteW`, `CredDeleteW`, `CredFree`）直接操作 Windows Generic Credentials，完全避免引入 CGO 或依赖第三方外部编译产物。
- **目标规范**：TargetName 使用 `xops:<storeID>/<itemID>`；凭据类型使用 `CRED_TYPE_GENERIC (1)`；持久化级别设置为 `CRED_PERSIST_LOCAL_MACHINE (2)`。
- **错误映射验证**：
  - 读取不存在目标时，系统错误码为 `ERROR_NOT_FOUND (1168 / 0x490)`，精准映射为 `credential.ErrCredentialNotFound`；
  - 权限不足或会话受限时（`ERROR_ACCESS_DENIED (5)`、`ERROR_NO_SUCH_LOGON_SESSION (1312)`），映射为 `credential.ErrCredentialAccessDenied`；
  - 成功读出后，对解包字节切片进行防御性拷贝并调用 `CredFree` 释放 Win32 内部非托管内存。
- **进程树隔离机制 (Job Object)**：
  - 验证表明：若 Helper 派生子进程并继承标准 I/O，仅调用 `cmd.Process.Kill()` 无法终止后台孙进程，会导致管道写端持续挂起；
  - 本设计通过 Win32 Job Object（配置 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`）与 `AssignProcessToJobObject` 绑定整个进程树。无论是超时取消还是句柄关闭，Windows 内核均保证原子性销毁包含所有子孙进程的完整进程树。

### 16.2 macOS 原生平台验证 (Keychain Services)

- **调用路径**：基于系统内置 `/usr/bin/security` 命令行工具（`find-generic-password`, `add-generic-password`, `delete-generic-password`），服务名为 `xops:<storeID>`，账户名为 `<itemID>`。
- **错误映射验证**：
  - 未找到目标时，返回码 `44` (`errSecItemNotFound`) 或 stderr 提示 `The specified item could not be found in the keychain`，映射为 `credential.ErrCredentialNotFound`；
  - 钥匙串锁定或禁止交互（`errSecAuthFailed` / `user interaction is not allowed`）映射为 `credential.ErrCredentialStoreLocked`；
  - 秘密输出完整保留末尾换行与字节切片内容，空字节输出映射为 `ErrCredentialNotFound`。
- **进程隔离与超时**：配置独立进程组与 `cmd.WaitDelay`，配合 context 超时强制回收管道。

### 16.3 Linux 原生平台验证 (Secret Service & Headless 检测)

- **规范与调用**：遵循 FreeDesktop.org Secret Service 规范；原生命令行交互集成系统标准 `secret-tool` (`libsecret`)。
- **属性标签**：存储属性为 `xops-store = <storeID>`、`xops-item = <itemID>`，展示标签为 `xops:<storeID>/<itemID>`。
- **Headless 与环境前置检测**：
  - Spike 实验表明：在无 D-Bus 会话（如 SSH 远程会话、无桌面环境的 Linux 服务器、容器等）中调用 Secret Service，会导致长时间阻塞或失败；
  - 本设计提供显式可用性前置检查 `checkPlatformSystemAvailability`：当缺少 `DBUS_SESSION_BUS_ADDRESS`、`DISPLAY` 和 `WAYLAND_DISPLAY` 时直接 fail-closed，返回明确的 `ErrCredentialStoreUnavailable`；
  - 在 headless 环境下，引导用户采用 `pass`（结合 GPG key）或自定义 `helper` 存储凭据。

### 16.4 进程隔离与安全诊断脱敏

- **默认超时上限**：所有 Helper 和 Pass 子进程执行强制应用 `DefaultHelperTimeout = 30s`，禁止无超时阻塞；
- **管道防死锁与等待上限**：配置 `DefaultProcessWaitDelay = 50ms`，配合各平台进程组/Job Object 终止机制，彻底解决“父进程提前退出但孙进程继承管道导致长时间挂死”的问题；
- **诊断信息清洗**：通过 `SanitizeDiagnostic` 自动屏蔽 Base64 载荷（匹配 16 字符以上 Base64）与请求机密原文，杜绝错误回显导致的机密逆向泄露。

