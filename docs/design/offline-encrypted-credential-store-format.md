# 离线凭据库格式与 KDF 协议 v1

- 状态：格式与 KDF 协议 v1 已冻结（2026-09-10），未发布
- 评估：[阶段 A 密码学安全评估](offline-encrypted-credential-store-security.md)
- 上位：[ADR-0002](../adr/0002-offline-encrypted-credential-store.md)
- 总体：[详细设计](offline-encrypted-credential-store.md)
- 冻结记录：[范围与兼容性规则](offline-encrypted-credential-store-v1-freeze.md)；依据[最终工程审查](../plans/offline-encrypted-credential-store-freeze-review.md)

本文件的精确编码与既有编号已冻结，编号不得复用。独立测试向量已重新生成并逐字节
核对一致；不兼容修改遵守冻结记录的版本演进规则。所有随机材料来自 crypto/rand，失败直接退出。

## 1. 编码规则与注册表

u8/u16/u32/u64 为无符号大端整数，i64 为二补码大端整数。所有长度指字节数。
LP(x) = u16(len(x)) || x；字段依表顺序连接，无对齐、无 padding、无省略字段。
解码先检查有界输入与整数运算再读取，禁止读到 EOF 后才检查文件是否超限。
枚举不接收未定义值；完整文件长度必须等于头长加载荷长，拒绝任何尾随字节。

| 标识 | 值 |
| --- | --- |
| 容器版本 | 1 |
| 主口令包裹套件 | 0x0001：Argon2id v0x13，m=65536 KiB/t=3/p=1/output=32，AES-256-GCM |
| 密钥文件包裹套件 | 0x0002：HKDF-SHA-256/output=32，AES-256-GCM |
| 条目套件 | 0x0001：AES-256-GCM，DEK=32，nonce=12，tag=16 |
| 预算认证套件 | 0x0001：HKDF-SHA-256 + HMAC-SHA-256，完整 32 字节 tag |
| meta magic | ASCII `XOPSMETA`，8 字节 |
| item magic | ASCII `XOPSITEM`，8 字节 |
| CURRENT magic | ASCII `XOPSCURR`，8 字节 |
| budget magic | ASCII `XOPSBUDG`，8 字节 |

不同用途使用独立编号空间；只能按明确文件类型解释，不根据一个 suite 值猜文件类型。
magic 表达类型，不能代替认证。公开字段暴露条目数量、身份和长度，不承诺元数据隐藏。

meta、item、CURRENT、budget 四种磁盘容器使用以下 16 字节前缀；维护 state
与 manifest 使用第 6 节各自的编码：

| 偏移 | 长度 | 字段 |
| --- | --- | --- |
| 0 | 8 | magic |
| 8 | 2 | format_version=1 |
| 10 | 2 | header_len，包含此前缀 |
| 12 | 4 | payload_len，含 AEAD/MAC tag（若有） |

全局 Ref 校验保持原契约；此后端 StoreID/ItemID 各为 1..1024 字节，按 Go string
原始字节保留，不额外 Unicode 规范化。先 Ref.Validate，再局部长度检查；不把
无效 UTF-8 的 ID 变换成替代字符。显示非文本 ID 时转义，格式不依赖 JSON 字符串。
文件名为 lowercase_hex(SHA256(ItemID bytes)) + `.enc`，认证后再次比较完整 ID。

## 2. vault.meta

| 前缀后顺序 | 长度 | 字段与约束 |
| --- | --- | --- |
| 1 | 2 | wrap_suite：1 或 2 |
| 2 | 2 | item_suite：1 |
| 3 | 16 | vault_id，随机 |
| 4 | 8 | dek_generation，非零 |
| 5 | 8 | vault_revision，非零 |
| 6 | 4 | argon_memory_kib：suite 1 为 65536，suite 2 为 0 |
| 7 | 4 | argon_iterations：suite 1 为 3，suite 2 为 0 |
| 8 | 1 | argon_parallelism：suite 1 为 1，suite 2 为 0 |
| 9 | 1 | salt_len：suite 1 为 16，suite 2 为 32 |
| 10 | salt_len | salt |
| 11 | 12 | nonce |
| 12 | 2 + S | LP(StoreID) |

header_len = 76 + salt_len + S，payload_len = 48，整文件不得超过 4096 字节。
payload 为 32 字节 DEK 的 AES-GCM 密文加 16 字节 tag。AAD 为完整 header 原始
字节（含前缀、nonce 与长度）；不允许重排字段后再认证。元数据内 item_suite 也认证。

suite 1 的包裹密钥直接使用 Argon2id 输出；suite 2 使用 HKDF-SHA-256：

```text
IKM  = 用户供应的原始 32 字节密钥
salt = 本封套的 32 字节 salt
info = LP(ASCII "XOps/encrypted-file/v1/key-file-wrap")
       || vault_id || LP(StoreID)
L    = 32
```

此处标签中的斜杠是固定 ASCII 字节，变量字段仍以长度明确编码，末尾无 NUL。
每次新包裹重新生成 salt 和 nonce，派生密钥只执行一次加密；同密文重试不再调用 Seal。
解包前可判定的非法格式先拒绝，GCM Open 失败统一 locked。认证前 meta 字段不可信。

## 3. 条目文件

| 前缀后顺序 | 长度 | 字段与约束 |
| --- | --- | --- |
| 1 | 2 | item_suite=1 |
| 2 | 16 | vault_id |
| 3 | 8 | dek_generation，非零 |
| 4 | 12 | nonce |
| 5 | 1 | expiry_present，0 或 1 |
| 6 | 8 | expires_unix_nano，i64；无到期时间时必须为 0 |
| 7 | 2 + S | LP(StoreID) |
| 8 | 2 + I | LP(ItemID) |

header_len = 67 + S + I；payload_len = secret_len + 16，secret_len 为 1..65536。
最大文件长度 67 + 1024 + 1024 + 65536 + 16 = 67667 字节。
AAD 为完整 header，密文仅包含 Secret.Value；ExpiresAt 是认证元数据，不能改变
而仍认证成功。首次 Put 要求期限可精确编码为 i64 Unix 纳秒并尚未过期，防止转换
溢出；恢复/重加密保留历史到期字段，不因已过期而改写或省略条目。

无到期时间要求 expiry_present=0 且 expires_unix_nano=0；有到期时 flag=1，
到期时间按 UTC 解释。Get 在 now >= ExpiresAt 时返回 not-found，不自动删除。
同值 Put 的幂等比较包含 Value 及到期时间。返回值由调用方独占并负责 Zero。

条目不包含发布修订号，允许同 DEK 的重包裹逐字节复制。读者必须校验 vault_id、
StoreID、ItemID 和当前 DEK 代次，不能仅以文件认证成功证明目标匹配。

## 4. CURRENT

前缀之后为 vault_id[16]、vault_revision u64、dek_generation u64、meta_sha256[32]。
header_len=80，payload_len=0，整文件恰好 80 字节。摘要覆盖完整 vault.meta，
包括包裹密文和 tag。路径由验证后的数字修订生成，不在指针中保存任意路径。

CURRENT 自身不是独立的 MAC 认证对象：读者必须检查目标 meta 摘要一致、身份/
代次/修订匹配，且 meta 成功认证或与已认证会话缓存的完整 meta 摘要相同。
只有摘要相符不构成可信身份；攻击者可以替换指针和旧 meta，因此仍无抗回滚保证。
未认证 inspect 不据此执行删除或选择解锁策略。

## 5. 预算记录

| 前缀后顺序 | 长度 | 字段 |
| --- | --- | --- |
| 1 | 2 | budget_suite=1 |
| 2 | 16 | vault_id |
| 3 | 8 | dek_generation |
| 4 | 8 | consumed，0..1048576 |
| 5 | 8 | sequence，非零，每次记录更新加一，溢出拒绝 |
| 6 | 2 + S | LP(StoreID) |

header_len=60+S，payload_len=32，为 HMAC-SHA-256(K_budget, header) 完整输出。
consumed 不可因删除或失败减少。90% 预警阈值为 ceil(1048576×0.9)=943719。
预算认证失败或耐久性不确定禁止新加密，不以现场文件数量重新估计次数。

```text
K_budget = HKDF-SHA-256(
  IKM=DEK, salt=vault_id,
  info=LP(ASCII "XOps/encrypted-file/v1/budget-mac")
       || LP(StoreID) || u64(dek_generation), L=32)
```

sequence 用于正常事务核对，不是外部可信计数器；完整旧记录回滚仍无法检测。
预算预留原子替换前先同步临时文件，再同步 key-state 对应目录，全部成功才执行
下一次条目加密。若新预算已发布但 sync 失败，不加密且不退额；重试先确认记录
并补同步，新的加密再预留下一额度。新代次初始 consumed=0、sequence=1。

## 6. 维护 state 与清单

外层 state 为严格 JSON 对象，仅允许 payload、source_mac、target_mac 三字段，
全部为标准带 padding 的 Base64 字符串；重复/未知字段、非规范 Base64 拒绝。
payload 是下面的规范二进制，不以 JSON 重序列化作为 MAC 输入；MAC 32 字节，
缺少某端密钥时该端值固定为空字符串。完整 state 不超过 16 KiB。

| payload 顺序 | 类型 |
| --- | --- |
| magic/version | ASCII `XOPSTXNS` / u16(1) |
| operation_id | 16 字节随机 ID，目录用 32 位 lowercase hex |
| operation / stage | u8 / u8 |
| source_vault / target_vault | 各 16 字节 |
| source_store / target_store | 各 LP，缺失源时长度零 |
| source_revision / target_revision | 各 u64 |
| source_generation / target_generation | 各 u64 |
| source_meta_hash / target_meta_hash | 各 32 字节 |
| source_manifest_root / target_manifest_root | 各 32 字节 |
| source_item_count / target_item_count | 各 u64，最大 1048576 |
| cleanup_count / cleanup_revisions | u16 / 严格升序的 u64 列表，最多 256 个 |

operation：1 init、2 rewrap、3 reencrypt、4 restore、5 clone、6 prune。
stage：1 prepared、2 building、3 verified、4 published、5 committed、6 cleanup_pending。
初始化无源时 source 身份、计数和摘要全零且 source_store 为空。尚未完成的目标
meta/清单摘要允许全零，仅限对应 prepared/building 阶段；发布前必须全量验证。
prune 使用当前库为两端，清理计划超过 256 个分为多次显式操作，不截断静默删除。

每端的 MAC 密钥使用该端 DEK，经 HKDF-SHA-256 派生：salt=该端 vault_id，
info=LP(ASCII "XOps/encrypted-file/v1/transaction-mac") || LP(该端 StoreID)
|| u64(该端 DEK 代次)，L=32；MAC 覆盖完整 payload。换 DEK 的事务在两端可用时
写出两个 MAC，恢复验证当前操作所依赖的端；删除源或目标前必须验证相应依赖。
单端 MAC 不能替代另一端条目认证或支持把来源未知的对象列为清理对象。

清单块名固定为 source-00000000.manifest 或 target-00000000.manifest 等八位
十进制编号。块为 ASCII `XOPSMANF` || u16(1) || u32(block_index) || u32(count)，
随后 count 个 LP(ItemID) || u32(file_size) || SHA256(file)[32]，每块最多 1 MiB。
条目跨块按 ItemID 原始字节严格升序，不重复；空清单使用零块。
清单根为 SHA256(ASCII "XOps/manifest/v1" || u32(block_count)
|| 按编号排列的各块 SHA256)。清单根在 state MAC 覆盖内，文件清单不含秘密。
遍历计数与文件大小都受限，超限输入先拒绝；大清单流式处理，不一次性装入内存。

state 与清单属于维护事务，不替代 Service 的配置 journal。目录均受安全路径
约束，不把清单字段拼成任意路径。过期条目仍属于源集合，不能因当前时间不同漏掉。

## 7. 私有 KDF 协议

入口参数固定为 `__xops_kdf_v1`，不接受附加 argv。协议版本 1，使用大端整数；
父子是同一二进制，版本不匹配失败，不做回退。工作阶段不读取文件或启动其他命令。

请求总长度 48+P，P 为口令字节数，最大 1024，总上限 2048：

| 偏移 | 长度 | 字段 |
| --- | --- | --- |
| 0 | 8 | ASCII `XOPSKDFQ` |
| 8 | 2 | version=1 |
| 10 | 4 | total_len=48+P，包含整个请求 |
| 14 | 1 | action=1，Argon2id |
| 15 | 4 | memory_kib=65536 |
| 19 | 4 | iterations=3 |
| 23 | 1 | parallelism=1 |
| 24 | 2 | output_len=32 |
| 26 | 16 | salt |
| 42 | 4 | argon_version=0x13 |
| 46 | 2 | password_len=P |
| 48 | P | 口令原始 UTF-8 字节 |

解锁不要求十二字符创建门槛，但仍拒绝空口令、无效 UTF-8、NUL/CR/LF 和超长
输入。父进程负责新建/更换时的强度门槛与两次确认；子进程不尝试推断请求用途。
读取长度前缀后，最多额外读一个字节确认 EOF；不能先无限 ReadAll 再检查。

响应总长度 17+K，成功 K=32、失败 K=0，总上限 256：

| 偏移 | 长度 | 字段 |
| --- | --- | --- |
| 0 | 8 | ASCII `XOPSKDFR` |
| 8 | 2 | version=1 |
| 10 | 4 | total_len=17+K |
| 14 | 1 | status |
| 15 | 2 | key_len=K |
| 17 | K | 派生密钥，仅成功存在 |

status：0 success、1 invalid_request、2 unsupported_version、3 resource_failure、
4 internal_failure。成功退出码 0；可编码失败退出码 1，父进程可解析合法错误帧用于
分类，但非零退出绝不能接受密钥。无法写响应时退出失败，由父进程归类进程错误。
异常退出不保证有响应，OOM kill 也不能仅凭退出信号确定；只有配额事件等可靠
证据才细分 resource_failure，否则保留 process_failure。

stderr 最多保留 4096 字节，不回显，超过后立即取消。stdout 超过声明长度或
协议上限、多帧、非 EOF 均拒绝；收到成功帧仍须等待零退出与任务有效性检查。
错误优先级：调用取消/超时 → 协议违规 → 已验证错误帧/进程失败 → 合法成功；
保留辅助收尾错误，不因丢失 EOF 或异常退出掩盖主 context 原因。

## 8. 编码核验与冻结依据

v1 冻结已核对以下独立复核向量：

1. 固定公开口令、salt、vault ID、StoreID、DEK、nonce 的主口令 meta 完整 hex。
2. 固定公开密钥文件的 HKDF info、派生密钥与包裹结果。
3. 含/不含 ExpiresAt 的条目完整 header/AAD/密文/tag。
4. budget 与双端 state 的派生输入、MAC、篡改拒绝样本。
5. 空/多块清单根、CURRENT 摘要、KDF 请求和成功/错误响应。

阶段 A 已通过独立 Python cryptography/系统 libargon2 生成公开固定向量，位于
`internal/credentialfile/format/testdata`，Go 测试核对完整编码与结果；不能把
自实现编码器输出当独立证据。向量和工程安全评估分别记录，详见[实施进度](../plans/offline-encrypted-credential-store-implementation.md)；这些验证不代表完整后端或第三方审计通过。

可直接核对的长度样例：S=7、I=32 时，主口令 meta header=99、整文件=147；
密钥文件 meta header=115、整文件=163；条目 header=106；budget header=67、
整文件=99；CURRENT=80；P=24 时 KDF 请求=72，成功响应=49、错误响应=17。

资源测试不得使用真实秘密或运行中的 受限资源测试环境 做破坏性实验。12 字节随机 nonce 的
2^20 次上限只提供碰撞概率预算，配套评估已纳入总认证块数、消息长度、认证失败
尝试、多密钥聚合及 HMAC/派生域分离；实现或上限改变时必须重新计算与审查。


## 阶段 D 归档与来源证书

transactions/<operationID> 在提交确认后原子移动至 revisions/<target>/commit。
归档保留现有 v1 state 与 manifest 格式。provenance-<20位旧修订>.state 复用
OpRewrap/OpReencrypt + Committed，Source 绑定旧修订完整端点，Target 绑定当前
端点；清理只信任当前 DEK 验证通过的目标 MAC，不把历史源 MAC 当成当前授权。
每次新发布验证旧证书并重签；prune 读取旧 meta 时再次比较 Source.MetaHash。

未发布目标重建时，可保留 abandoned-<20位目标修订>.state，内容为该目标的原事务，
以原源端 MAC 验证废弃目标身份；该记录只建立清理来源，不授权发布该目标。
清理使用独立 OpPrune 事务，最多 256 个 CleanupRevisions；完成后归档为
revisions/<current>/prune-<operationID>。CURRENT、meta、item、budget 和 MAC 的
字节编码、算法与参数均未改变。
