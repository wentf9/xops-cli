# 离线凭据库格式与接口 v1 冻结记录

- 状态：已冻结
- 生效日期：2026-09-10
- 依据：[最终工程审查](../plans/offline-encrypted-credential-store-freeze-review.md)通过
- 冻结对象：磁盘格式 v1、私有 KDF 协议 v1、encrypted-file 配置及 CLI/JSON 接口 v1
- 发布状态：未发布

## 1. 冻结基线

采用[格式与 KDF 协议规格](offline-encrypted-credential-store-format.md)、
[详细设计](offline-encrypted-credential-store.md)和[使用指南](../offline-encrypted-credentials.md)
描述的行为。冻结保留现有加密算法、文件编码、默认参数和执行语义。

| 对象 | 冻结内容 |
| --- | --- |
| 磁盘容器 | 版本 1；meta/item/CURRENT/budget 的 magic、头部、字段顺序/宽度和 AAD；state/manifest 的独立编码 |
| 加密与认证 | 包裹套件 1/2、条目套件 1、预算套件 1；完整标签、nonce 长度、HKDF 域分离字节与双端 MAC |
| 资源与字段边界 | ID 1..1024 字节、秘密 1..65536 字节、i64 纳秒 ExpiresAt、每 DEK 1048576 次、预警 943719、state 16 KiB、manifest 块 1 MiB、prune 每批 256 项 |
| KDF 帧 | 版本 1、入口 __xops_kdf_v1、固定 Argon2id v0x13/65536 KiB/3/1/32、请求/响应布局和状态编号 |
| 配置 | type/path/unlock/key_file、期限/缓存/只读/非交互字段及当前默认值；相对实际配置文件解析路径；none 默认策略 |
| 命令 | init/inspect/rewrap/reencrypt/resume/restore/clone/prune 的现有名称、参数、选项、默认值和恢复职责 |
| JSON | code/op/outcome、可选 inspection/revisions；applied/durable/changed 相互独立，stage 编号和元数据字段语义 |

固定独立向量 `internal/credentialfile/format/testdata/vectors.json` SHA-256：

```text
0991874cd848a7f6a6be96fef4d2d8843fed277e4d0c08e50284a6d188551ced
```

该文件作为不可改写的 v1 参考语料保留。新的版本或新增向量另建文件，不能随实现
修改而覆盖原向量，使既有兼容性测试失去独立性。TestFrozenV1ReferenceCorpus
固定该摘要，既有独立向量、边界与认证测试继续验证编码器/解析器。

## 2. 配置与 CLI 的具体约定

默认 timeout=10s、unlock_timeout=30s、prompt_timeout=2m、unlock_idle_ttl=5m
（最大 30m）、cache_ttl=0。显式零/负操作超时拒绝；cache_ttl=0 表示禁用缓存。
key-file 必须为独立 32 字节普通文件，允许当前用户/root、0400/0600 权限。
主口令只能通过隐藏输入取得，新口令至少十二个 Unicode 字符并二次确认。

所有管理子命令接受一个 StoreID 和 --json。inspect 的 --verify 默认 false；其余
维护命令的 --maintenance-timeout 默认 30m。rewrap/resume 的 --unlock、--key-file
选择目标材料；clone 的 --to 选择已配置且未初始化的目标；restore 要求显式
--from、源材料和 --backup-config；跨库 resume 使用显式 --from/--source-store，
--operation 可限定事务。prune 默认计划，--apply 才删除。不存在 --force 或口令值参数。

应用输出 JSON 结果时 code/op/outcome 必须存在；inspection/revisions 按结果省略。
命令进入 RunE 之前的选项解析、参数个数或启动失败仍沿用 CLI 错误输出，不能假设
所有失败都有 JSON。非零退出不表示没有已发生的修改，必须结合 outcome 判断。
修订号/代次为 uint64 JSON 整数；JSON 字段顺序和人类可读提示文案不属于冻结内容。

现有 code 集合保持：

```text
ok canceled timeout locked unsupported maintenance_required revision_changed
conflict corrupt resource_busy resource_exhausted unavailable read_only
key_usage_exhausted access_denied failed
```

取消/超时优先匹配；DurabilityError 保留底层原因和已发生的副作用。普通 Store API
的 sentinel 与 CLI code 不是一一同名，未分类错误使用 failed。
TestFrozenOfflineCommandOptions 和 TestFrozenOfflineJSONPreservesPartialCommit
覆盖现有选项、默认值和错误下的发布/耐久/清理区分。

## 3. 冻结后的变更规则

1. 不得在 v1 名义下改写已有字段布局、编码、身份绑定、套件含义或私有 KDF 帧语义。
   不兼容布局需要新版本，算法/参数组合需要新套件编号；既有编号不得复用。
2. 新实现必须继续通过原 v1 向量及兼容性测试。格式迁移必须显式、可恢复、读回验证，
   不能在普通 Get 或配置加载中静默转换，也不能通过失败后尝试弱算法实现兼容。
3. CLI/YAML 可增加向后兼容的可选项或元数据字段，不改变既有选项的含义和默认值。
   JSON 消费方应忽略不认识的附加元数据，并将未知 code 当作未识别结果处理。
   删除/重命名选项、改变必填字段或既有结果含义需新接口契约及明确迁移说明。
4. 如发现严重安全问题，可按 ADR 的算法退役策略提前拒绝不安全的读取/写入；必须
   记录影响、迁移或重新配置步骤，不能把冻结承诺解释为必须继续运行不安全算法。
5. 内部重构、错误文案、日志、依赖版本、测试实现及验证环境矩阵不作字节级冻结，
   但不得破坏上述格式与对外行为契约。内部 Go 类型不承诺 ABI 稳定。

## 4. 平台和发布边界

当前运行平台为 Linux amd64。文件系统类型不设白名单，由用户保证存储可靠性；
ext4/XFS/Btrfs 是已验证矩阵，不是准入列表。权限、挂载身份、锁、原子发布和
文件/目录同步要求保持不变。Windows/macOS 等未实现平台仍返回 unsupported。

冻结前证据包括独立向量、密码学工程评估、原生部署、三种文件系统共 42 个 KVM
断电恢复点和实际 CLI 离线演练。冻结回归验证独立向量与既有 CLI 契约，
验证范围详见审查记录。

go build ./...、go test ./...、普通及 integration/vaultpowercut lint 通过；
新增冻结回归三轮 race 通过，固定向量摘要保持不变。
