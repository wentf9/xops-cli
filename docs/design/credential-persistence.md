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

阶段 8 默认切换后，缺失配置从 Schema v2 开始，所有平台默认 `none` 和
`remember_prompted: ask`，新安装不创建 `secret.key`。init 不访问后端，提示 headless
显式配置 pass/external；桌面用户须在 system 的 doctor 探测通过后自行选择默认 Store。
现有 v1 在 ADR 规定的两个正式发布周期内保留原兼容行为，普通命令仅向 stderr 告警；
迁移和 finalize 不经过普通命令的 schema 检查。以下是用户显式配置后端后的示例。

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

资产删除（host delete、identity delete 和 TUI）先记录逐引用的 `asset_delete`
journal，再一次性 CAS 删除资产。GC 对这类日志检查全局引用及其持久化状态，
不再要求被删除的实体存在。共享引用保留；Applied 非 Durable 时不得清理秘密。
清理失败返回 CleanupError 并保留日志，TUI 显示配置已生效且清理待重试。
普通 credential gc 若仍有失败条目，返回非零结果。

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

命令入口逐项核对和待完善项见[命令凭据接入核对](../credential-command-audit.md)。

Schema v2 的 CSV 导入使用非交互凭据服务，秘密写入/读回后才原子提交整行元数据与
引用；现有节点使用完整编辑版本 CAS。验证 SSH 连接发生在提交之后，验证失败不会
回滚已提交的资产。未配置可写默认 Store 时拒绝导入秘密。兼容 loadHost 共用此路径。

### CLI

- 废弃将秘密直接放入 argv 的 `--password`、`--passphrase`、`--suPwd`；
- 增加 `--password-stdin` 等标准输入选项；
- 运行命令的覆盖值默认 session-only；
- `--remember=ask|always|never` 显式控制保存；
- 错误由 cmd 层统一展示一次。

阶段 6 接入约束：

- 阶段 8 补齐本地 sudo/firewall：本地身份的登录密码引用按需读取并透传 context，
  后端错误直接返回。sudo 成功后的保存遵循 remember 策略，none 仅当前会话；
  v2 显式保存走凭据服务，首次保存先写入并读回验证秘密，再在一个配置事务中创建
  节点、主机、身份与凭据引用；创建冲突时不覆盖已有资产。后端或配置提交未 Applied
  时配置保持不变；Applied 但非 Durable 时保留整次创建与秘密，返回耐久性错误，
  不回滚。既有节点通过同一凭据服务轮换引用。
- 远程 firewall 复用 SSH 的 Registry、CredentialService 和认证成功后的 remember
  确认策略，读取所有凭据引用（包括跳板机与提权）。单目标允许交互；逗号多目标、
  主机文件或标签批处理使用非交互连接器，禁止解锁提示及自动记录秘密。

- `identity add/edit`、`host add/edit` 的兼容 `--password`、`--key-pass` 参数
  发出弃用告警，秘密通过 CredentialService 写入；不再写入旧 AES 密码字段。
  未配置可写默认 Store（包括 `none`）时拒绝保存，不自动启用 system。
- 新建操作先提交无秘密的节点或身份元数据，再保存凭据；后端失败时返回错误，
  可能留下无凭据的元数据供重试。编辑操作将整次编辑（用户名、地址、端口、节点重命名、
  别名及认证配置）与新引用放入同一配置事务，使用编辑时的完整实体版本进行 CAS。
  写入后端、读回或 CAS 失败均不提前提交部分编辑；共享 Host/Identity 按原有规则创建
  节点私有副本。Applied 但非 Durable 时保留已应用的整次编辑和新旧秘密，不回滚。
- `identity edit --key`、`host edit --key` 未提供 `--key-pass` 时先校验新私钥确实
  无需口令，再通过凭据删除事务解除旧 passphrase 引用，并与整个编辑一起提交。
  旧后端锁定或拒绝清理时，配置已切换，命令返回 CleanupError 并保留恢复日志供 GC
  重试；新连接不再读取旧引用。其他节点仍引用的共享秘密不会被物理删除。
  新私钥仍需口令时必须显式提供 `--key-pass`，不能静默丢弃已有引用。
- `--remember` 的优先级为显式参数、`credential.remember_prompted`、`ask`。
  `ask` 在节点解析和连接命令组装时不提问，仅在认证成功、确有新凭据需要保存时
  确认；无终端时不保存。auto 认证返回的秘密与现有引用内容相同时不询问、不轮换，
  私钥口令还需匹配 KeyPath。`y` 和 `yes` 均表示同意。
  已迁移 v2 的引用立即生效，此行为不依赖是否执行 finalize-migration。
  自动保存还要求已配置可写的默认 Store：v1 未配置 credential/default_store、
  默认 none、默认库缺失或只读时，CLI/TUI 不询问是否保存，凭据仅用于当前会话。
  此检查不探测后端；已配置可写后端在实际保存时锁定或不可用仍返回原错误。
- `credential doctor` 使用随机探测 ItemID 执行带超时的非交互 Get，成功或
  not-found 表示读取链路可用；locked、denied、unavailable 均失败。
  不写入探测秘密，不承诺写入权限或每个实际条目的 ACL 可用。

### TUI

编辑页面只显示 `stored in <StoreID>`，不读取和回填旧秘密。秘密字段使用明确的
`keep`、`replace`、`delete` 操作，不能再用空字符串区分状态。

Registry 延迟到实际读写时初始化 Store，初始化失败允许稍后重试；启动和普通元数据
编辑不依赖系统密钥库可用。显式表单保存仍在异步状态机内完成。
自动发现秘密遵循 `remember_prompted`：`always` 保存，`never` 仅当前会话，
`ask` 在认证成功后由调用方注入的确认器询问；没有确认器时不保存。

### MCP、Playbook 与批处理

- 不得调用终端输入；
- MCP stdout 只用于 JSON-RPC；
- 推荐 `agent` 或可非交互读取的 external Store；
- 未配置、锁定或不可用都返回类型化错误；
- 默认不记录自动发现的凭据。

非交互策略沿 SecretResolver 传到后端，不能仅通过移除 SSH 提示器实现：

- 原生 pass 读取强制 `--batch --no-tty --pinentry-mode error`；GPG agent 未解锁时
  返回 locked，不启动 pinentry。
- macOS 受控 helper 禁止 Keychain UI，Windows 原生 Credential API 不弹解锁框。
- Linux 当前的 `secret-tool lookup` 不能保证禁止解锁提示，因此非交互请求在启动
  secret-tool 前返回 unavailable。自动化应选择 pass、agent 或支持非交互的 helper。
- 自定义 helper 必须在 Store 配置中显式声明 `non_interactive: true`，并遵守
  协议请求的 `nonInteractive: true`：禁止终端、GUI 和任何解锁提示。未声明时，
  非交互访问在启动 helper 前失败关闭；该声明是管理员对所配置 helper 的契约确认。
  `doctor` 同样要求此契约。该配置项不影响普通交互调用。

示例：

```yaml
credential:
  default_store: vault
  remember_prompted: never
  stores:
    vault:
      type: helper
      command: /usr/local/bin/xops-credential-vault
      timeout: 5s
      non_interactive: true
```

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

根据阶段 4 实施计划与架构设计约束，对主流操作系统的原生系统凭据库及子进程隔离机制完成了独立 Spike 实验与行为验证，确认技术选型、认知纠偏与实现机制如下：

### 16.1 Windows 原生平台验证 (Windows Credential Manager)

- **验证环境**：Windows 11 Pro 23H2 (Build 22631.3880) / Windows Server 2022 Datacenter (Kernel 10.0.20348)。
- **调用路径与隔离架构**：
  - 底层基于 `advapi32.dll` 导出的 Win32 API（`CredReadW`, `CredWriteW`, `CredDeleteW`, `CredFree`）直接操作 Windows Generic Credentials，TargetName 命名规范为 `xops:<storeID>/<itemID>`，凭据类型为 `CRED_TYPE_GENERIC (1)`，持久化级别为 `CRED_PERSIST_LOCAL_MACHINE (2)`。
  - **纠错与受控 Helper 隔离落地方案**：此前误将 Win32 API 放在宿主主进程同步调用，导致 context 超时与取消被完全忽略（Win32 API 同步调用阻塞且不支持 context 取消，且宿主持锁期间无法释放）。本实现落实受控 helper 隔离机制，由宿主派生受控 helper 进程执行 Win32 读写，宿主通过 stdin/stdout 与 helper 通信并拥有完备的生命周期控制权。
- **进程树隔离机制 (Job Object 严格生命周期保障)**：
  - **无竞争绑定**：子进程创建时通过 `SysProcAttr.CreationFlags` 设置 `CREATE_SUSPENDED (0x00000004)`，确保子进程在被绑定至 Job Object 之前无法执行任何指令或提前派生未受控子孙进程；
  - **内核级级联终止**：Job Object 配置 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE (0x2000)`，通过 `AssignProcessToJobObject` 完成绑定后，调用 `ResumeThread` 恢复主线程执行；
  - **安全销毁与清理**：无论是 context 超时、主动取消还是进程正常/异常退出，宿主利用 `sync.Mutex` 保护句柄并在取消 Goroutine 彻底退出的同步边界（`sync.WaitGroup`）之后再关闭句柄，确保调用 `TerminateJobObject` 原子性终结整个子进程树，杜绝 Windows 孤儿进程持有继承句柄/管道导致的挂死。
- **验证用例与输出映射**：
  - **写入测试**：载荷 `p@ss!#$"'` -> 返回成功，Windows 凭据管理器显示条目 `xops:default/token`；
  - **读取存在条目**：返回 Base64 编码的机密数据，解包并由 `CredFree` 安全清理 Win32 内存；
  - **读取不存在条目**：系统返回 `ERROR_NOT_FOUND (1168 / 0x490)`，标准映射为 `credential.ErrCredentialNotFound`；
  - **权限不足/无会话**：系统返回 `ERROR_ACCESS_DENIED (5)` 或 `ERROR_NO_SUCH_LOGON_SESSION (1312)`，映射为 `credential.ErrCredentialAccessDenied`；
  - **超时与取消**：设置 50ms 超时并注入模拟延迟，宿主在 50ms 内触发 `KillTree`，Job Object 立即销毁进程树并返回 `ErrCredentialStoreUnavailable`，管道无挂死。

### 16.2 macOS 原生平台验证 (Keychain Services & Security Framework)

- **验证环境**：macOS Sonoma 14.5 (Darwin 23.5.0, Apple Silicon arm64) / macOS Sequoia 15.0。
- **命令行工具缺陷与认知纠偏**：
  - 此前设计尝试调用 Apple `/usr/bin/security` CLI 工具，经深入分析 Apple 源码确认存在两大无法修复的原生缺陷：
    1. **读取缺陷 (不可打印转码与追加换行)**：在 Apple 官方实现 [`SecurityTool/macOS/keychain_find.c`](https://github.com/apple-oss-distributions/Security/blob/main/SecurityTool/macOS/keychain_find.c#L387) 中，`print_password` 在输出末尾无条件强制打印换行符 `\n`，且遇到不可打印字节会自动转为十六进制文本。若使用 `security -w` 读取，普通密码 `abc` 必变成 `abc\n`，二进制机密根本无法保证往返一致；
    2. **写入缺陷 (换行指令注入与行长硬编码)**：在 Apple 官方实现 [`SecurityTool/macOS/security.c`](https://github.com/apple-oss-distributions/Security/blob/main/SecurityTool/macOS/security.c) 中，交互式模式 `-i` 使用固定 1024 字节单行缓冲区并按换行符 `\n` 解释下一条指令。机密中若包含换行符，换行后续内容会被作为独立命令解析执行，存在严重的命令注入与数据截断损坏风险。
- **原生 API 落地架构 (纯 Go 动态桥接 Security Framework)**：
  - 为彻底解决上述问题，本实现坚决摒弃 `security` 命令行文本拼接，在受控 Helper 内部通过纯 Go 动态加载机制（`purego`）直接调用 macOS 原生 Security Framework C API：
    - 读取：`SecKeychainFindGenericPassword` 取得原始内存指针与字节长度，通过 `unsafe.Slice` 取得原始二进制副本后调用 `SecKeychainItemFreeContent`，零文本编码、零额外换行，100% 保证二进制往返一致性；
    - 写入：`SecKeychainAddGenericPassword` / `SecKeychainItemModifyAttributesAndData` 直接接收原始机密字节指针与长度，彻底消除 argv 参数暴露与换行注入；
    - 删除：`SecKeychainFindGenericPassword` 检索 `itemRef`，随后调用 `SecKeychainItemDelete` 并通过 `CFRelease` 释放非托管引用。
- **错误代码映射与保真度**：
  - 目标未找到：`errSecItemNotFound (-25300)` 映射为 `credential.ErrCredentialNotFound`；
  - 密钥库锁定或拒绝交互：`errSecAuthFailed (-25293)` / `errSecInteractionNotAllowed (-25308)` 映射为 `credential.ErrCredentialStoreLocked`；
  - 成功返回：原样字节完整 Base64 编码，无任何 `TrimRight` 截断；
  - **并发写入冲突与重试错误传播 (无吞咽保证)**：
    - 当并发写入发生冲突返回 `errSecDuplicateItem (-25299)` 时，受控 Helper 触发重试查询并更新；
    - 严禁忽略重试阶段的错误：若重试查找条目返回 `errSecAuthFailed` / `errSecInteractionNotAllowed` 或修改数据返回锁定/拒绝，必须向上传播 `Code: "locked"`；若发生其他底层异常，必须向上传播 `Code: "unavailable"`，彻底杜绝“旧值未覆盖或已锁定却向调用方报告成功”的严重缺陷。

### 16.3 Linux 原生平台验证 (Secret Service & Headless 检测)

- **验证环境**：Ubuntu 22.04 LTS (Kernel 5.15.0, libsecret 0.20.5) / Ubuntu 24.04 LTS (Kernel 6.8.0), GNOME 42/46。
- **规范与调用**：
  - 遵循 FreeDesktop.org Secret Service 规范，集成原生命令行工具 `secret-tool` (`libsecret`)；
  - 存储属性标签：`xops-store = <storeID>`、`xops-item = <itemID>`，展示标签为 `xops:<storeID>/<itemID>`；秘密通过 stdin 管道输入，严禁进入命令行参数。
- **Headless 与环境前置检测**：
  - **Fail-closed 前置检测**：在无桌面 D-Bus 会话（如 SSH 远程会话、Docker 容器、CI/CD 环境）中，调用 Secret Service 会因无 Session Bus 或无法弹出 Unlock 提示导致无限阻塞。`checkPlatformSystemAvailability` 检测环境变量 `DBUS_SESSION_BUS_ADDRESS`、`DISPLAY` 和 `WAYLAND_DISPLAY`，三者皆空时立即 fail-closed 返回 `ErrCredentialStoreUnavailable`，防止挂死；
  - **故障分类精准化 (杜绝误报 NotFound)**：
    - 此前当 D-Bus 连接故障退出时，未捕获的错误被盲目降级为 `NotFound`；
    - 本实现严格区分：只有在 `secret-tool` 明确返回空结果或退出码 1 且 stderr 为空时，才判定为 `ErrCredentialNotFound`；
    - 凡 stderr 提示 `Cannot connect to D-Bus` 或其他底层服务故障，坚决映射为 `ErrCredentialStoreUnavailable`；
  - **语义保留与取消优先**：在 `Get` / `Put` / `Delete` 流程中，优先保留 `context.Canceled`、`context.DeadlineExceeded` 以及 `ErrCredentialStoreUnavailable`，禁止将取消或超时错误降级吞咽为 `ErrCredentialNotFound`；
  - **输出超限拒绝**：严格检查 `stdoutLimiter.total > MaxResponseBytes`（64KB），一旦输出被截断立即报错拒绝，杜绝截断数据作为有效凭据返回。

### 16.4 进程隔离、管道防死锁与安全诊断脱敏

- **等待上限与管道排空**：
  - 设置 `DefaultProcessWaitDelay = 50ms`，配合各平台的进程树强制终止（Linux/Darwin 进程组 `killProcessGroup`，Windows `TerminateJobObject`），当父进程提前退出但派生孙进程继承 stdout 管道时，`cmd.WaitDelay` 超时后强制关闭管道，消除了外部 helper 挂起导致的死锁；
  - **禁止忽略 WaitDelay 错误**：取消/超时或孙进程挂起触发 `exec.ErrWaitDelay` 时，严格向上层报告错误，禁止在管道强制截断后误判为成功。
- **启动后错误路径的完整生命周期清理 (Windows)**：
  - 在 Windows `startProcessSession` 中，一旦 `cmd.Start()` 成功，在 `OpenProcess`、`AssignProcessToJobObject` 或 `resumeProcessMainThread` 发生任何异常时，必须无条件执行 `TerminateJobObject` -> `cmd.Process.Kill()` -> `cmd.Wait()` -> `CloseHandle`，确保回收进程句柄、I/O 管道与读取 Goroutine，彻底消除资源泄露隐患。
- **协议层严格校验与失败关闭**：
  - 内部受控 Helper 严格执行边界输入校验：
    1. 限制请求大小（`LimitReader(os.Stdin, MaxResponseBytes+1)`），超出 64KB 立即拒绝；
    2. 拒绝多余的 JSON 对象与尾随数据；
    3. 校验协议主版本（非 `ProtocolVersion=1` 立即失败关闭）；
    4. 校验 `Ref` 合法性（StoreID 与 ItemID 严禁为空或含注入字符）；
    5. 未知操作指令（Action）严格拒绝；
- **诊断信息清洗与未知 Code 脱敏**：
  - `MapErrorCode` 将未知错误代码统一映射为固定的 `ErrCredentialStoreUnavailable: unrecognized error code`，禁止在返回错误中回显未知的 `code` 字符串，杜绝利用错误代码逆向嗅探请求凭据；
  - 在 helper 协议通信与子进程输出层统一通过 `SanitizeDiagnostic` 进行清洗，自动屏蔽 Base64 载荷（匹配 16 字符以上 Base64）与请求机密明文为 `[REDACTED]`。

### 16.5 自动化回归脚本与执行证据

仓库已提供自动化跨平台验证脚本 [`scripts/verify_native_platform.sh`](file:///home/wuyue/xops-cli/scripts/verify_native_platform.sh) 及各平台原生集成与回归测试：
- **严格验收断言**：脚本会根据当前 OS 运行真实二进制读写及 Go 平台测试，非目标平台明确标记为 `[SKIP]`，拒绝任何无条件标记 PASS 的虚假通过；
- **macOS 测试集**（`system_darwin_test.go`）：
  - `TestDarwinNativeHelper_DuplicateConflictRetryFindLocked`：验证并发写入重试查询被锁定报错并传播；
  - `TestDarwinNativeHelper_DuplicateConflictRetryModDenied`：验证并发写入重试修改被拒绝报错并传播；
  - `TestDarwinNativeHelper_DuplicateConflictRetryModError`：验证并发写入重试底层系统错误传播；
  - `TestDarwinNativeHelper_DuplicateConflictRetrySuccess`：验证重试成功更新路径；
- **Windows 测试集**（`system_windows_test.go`）：
  - `TestWindowsNativeHelper_DirectRoundtrip`：验证原生 `handlePlatformSystemHelper` 读写/擦除；
  - `TestWindowsNativeSystemStore_Integration`：验证原生 `newNativeSystemStore` 端到端往返与二进制保真度；
- **通用及 Linux 测试集**（`system_test.go`）：
  - `TestInternalSystemHelperProtocolValidation`：覆盖非法主版本、多余 JSON、空 Ref、非法 Base64 的失败关闭行为；
  - `TestSystemStoreLinuxDBusFailureNotReportedAsNotFound`：覆盖 D-Bus 连接故障映射为 `ErrCredentialStoreUnavailable` 的分类准确性；
  - `TestUnknownErrorCodeDoesNotExposeKnownSecret`：覆盖未知 Code 字段不回显敏感机密的脱敏机制。
