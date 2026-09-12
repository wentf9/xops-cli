# 内置离线加密凭据库详细设计

- 日期：2026-09-10
- 状态：设计已采纳，阶段 A–F 与冻结审查已完成，格式/接口 v1 已冻结，未发布；见[冻结记录](offline-encrypted-credential-store-v1-freeze.md)，上位约束来自 [ADR-0002](../adr/0002-offline-encrypted-credential-store.md)
- 进度：[实施记录](../plans/offline-encrypted-credential-store-implementation.md)
- 工程安全评估：[阶段 A 分析与假设](offline-encrypted-credential-store-security.md)
- 配套：[格式与内部协议 v1](offline-encrypted-credential-store-format.md)
- 证据：[受限资源环境 KDF 测量](../adr/0002-kdf-measurement.md)

## 1. 目标与交付边界

提供显式配置的 encrypted-file 后端，单个 XOps 二进制可在离线、无桌面密钥库
及无 pass/GPG 的机器上保存秘密。配置仍只包含 CredentialRef，普通新安装默认 none。
本设计不实现跨进程解锁服务、在线一致性备份、秘密撤销或可信抗回滚。

首个正式支持平台为 Linux amd64，文件系统可靠性由部署者保证，不按文件系统类型
拒绝访问。ext4、XFS、Btrfs 为主流本地文件系统验收范围，网络及特殊文件系统不做
专项适配或可靠性承诺。Windows、macOS 暂返回 unsupported。受限资源测试环境 不用于 OOM、故障注入
或存储破坏实验。Go 维持 1.26+，使用标准库和已存在的 x/crypto、x/sys 依赖。

文中格式、配置字段与命令选项已按冻结记录确认为 v1 契约；内部类型与实现组织可继续
重构，但不得破坏已冻结行为或削弱 ADR 的安全约束。

### 1.1 实施前确认记录

2026-09-10 用户采纳当前设计，包括以下兼容性与运行行为选择：

- 本后端 StoreID/ItemID 各最多 1024 字节，条目文件名使用 ItemID 的 SHA-256；
  不追溯收紧其他后端的全局 Ref 契约。
- 保留 Secret.ExpiresAt，以存在标记和 i64 Unix 纳秒编码，幂等比较包含到期时间。
- 模式转换先发布新包裹，再显式更新配置，接受期间暂不可访问；不隐式回滚或回退。
- 未完成维护事务期间允许认证读取当前库，阻止普通修改，要求恢复或处理旧事务。
- 无可用 cgroup 委派时不提权、不修改服务器配置，报告无硬限制，遵守固定参数、
  单并发和部署配额；需要硬保证的部署必须提供相应机制。
- 配套格式表的编号、字段与认证编码，以及本设计命令选项作为实施基线；测试与
  审查发现问题时修订设计并记录原因，不能将采纳等同于格式已冻结。

实施前行为选择已关闭，可以进入阶段 A；独立向量、安全审查及平台运行时验证
仍是冻结／发布门槛，不使用真实凭据替代测试数据。

## 2. 当前代码接入点

实现接入点如下：

| 当前实现 | 接入要求 |
| --- | --- |
| `pkg/credential/store.go` 的 Source/Store | 保持 Get/Put/Delete 签名，Store 实现不可变 ItemID 语义 |
| `pkg/credential/ref.go` | Ref 当前禁止路径分隔等字符但无长度上限；Secret 还带 ExpiresAt，不能丢弃 |
| `pkg/config/schema_v2.go` | 添加 Store 类型、路径、解锁及超时字段，保持严格未知字段检查 |
| `pkg/config/store_factory.go` | 新后端不能套用通用 CachedStore，否则命中缓存会跳过 CURRENT 校验 |
| `pkg/config/lazy_store.go` | 并发可创建多个对象，构造对象必须无资源；会话归进程 Runtime 所有 |
| `pkg/credential/service.go` | 继续 intent → Put/Get 验证 → 配置 CAS → Durable → 清理；Put 返回任何错误不得推进配置 |
| `pkg/credential/interaction.go` | 沿用 WithoutInteraction，缺省 UnlockProvider 拒绝交互 |
| `internal/credentialhelper` | 复用／抽取进程组和 Job 机制，不复用 JSON 协议或原样 stderr 诊断 |
| `cmd/cli/main.go` | 私有 KDF 分流先于 i18n.Init 和 cmd.Execute；检查依赖包 init 无输出和配置访问 |

后端位于 `internal/credentialfile`，格式、文件事务、维护操作与 Store 在该包内；
私有协议执行器位于 `internal/kdfhelper`。进程启动机制若抽取为公共内部包，必须
给原 helper 路径跑回归测试，不以复制未审查代码代替复用。

## 3. 所有权与依赖注入

进程组合根创建一个 credentialfile.Runtime，负责会话表、KDF 队列、timer 与 Close。
配置层通过新增 BuildRegistryWithOptions 注入 Runtime 和配置文件基准目录，现有
BuildRegistryFromConfig 保持兼容：没有 Runtime 时 encrypted-file 延迟访问报
unavailable，不能私建无人回收的全局 Runtime。原有后端行为不变。

职责分工（名称在实现中保持 Go 缩写惯例）：

| 对象 | 职责及所有者 |
| --- | --- |
| Runtime | 组合根持有，Context 生命周期贯穿 CLI/TUI/MCP；Close 取消并等待所有资源 |
| Store | 轻量配置句柄，无独立后台任务，实现 credential.Store |
| UnlockProvider | 由 CLI/TUI 注入隐藏输入与 Prompt Gate；接收 Context，返回独占字节材料 |
| KDFRunner | 受控进程执行 Argon2id；允许注入测试替身 |
| FileOps | 相对目录句柄的有界读、sync、发布与锁，便于确定性故障注入 |
| Admin | Init/Inspect/Rewrap/Reencrypt/Resume/Restore/Clone/Prune，不经普通 Get 偷做维护 |

会话以安全打开后的根目录设备号/inode、StoreID、已认证 vault ID 和配置指纹标识；
同一路径别名最终必须合并到相同物理库。不同解锁策略指向同一物理库时拒绝冲突，
不能合并成权限更宽的会话。配置重载先关闭旧配置对应会话，再接纳新句柄。
无资源的 lazy 构造落败对象可丢弃，真正资源只由 Runtime 单次创建和回收。

所有 Close 错误与主错误合并返回；pkg 不打印日志。主进程不能在 defer 回收前
直接 os.Exit。杀进程、关闭 pipe、Wait 失败均须记录为类型化收尾结果。

## 4. 配置与兼容

```yaml
credential:
  default_store: offline
  remember_prompted: ask
  stores:
    offline:
      type: encrypted-file
      path: ./credentials/offline
      unlock: prompt
      unlock_idle_ttl: 5m
      prompt_timeout: 2m
      unlock_timeout: 30s
      timeout: 10s
      cache_ttl: 0s
      read_only: false
```

key-file 模式要求 key_file 路径，prompt 模式拒绝该字段。相对 path/key_file 基于
实际配置文件目录，不基于 cwd；内存配置缺少基准时只允许绝对路径。该后端拒绝
command、args、prefix，不启动外部 helper。non_interactive=true 进一步禁止交互，
不能被单次请求覆盖；未设置也不自动授予交互，仍需注入 Provider 且请求允许。

YAML 原始字段必须保留“省略”和“显式零”区别。idle TTL 为 (0,30m]，默认 5m；
prompt/unlock/operation 超时默认 2m/30s/10s，显式非正值拒绝；cache_ttl 默认零，
负值拒绝。read_only 禁止普通写入及维护修改，不禁止元数据检查或认证读取。
新字段只对新后端采用新默认值，不改变旧后端的零值语义和序列化兼容性。

Ref 的全局契约暂不收紧；本后端建议 StoreID/ItemID 各最多 1024 字节，保留原始
字节不规范化，仍先调用 Ref.Validate。超长引用在初始化、导入／迁移预检阶段拒绝，
不得改动源配置或静默截断。该局部上限须在格式冻结时审查，不追溯影响其他后端。
文件名采用 SHA-256(ItemID 原始字节) 的 64 位小写 hex 加 .enc；完整 ItemID 存入
认证头部并比较，避免 NAME_MAX、特殊文件名和路径注入。ADR 中 <ItemID>.enc
表示条目映射，实施使用上述安全文件名；哈希冲突报冲突，不覆盖。

## 5. 解锁、缓存和交付边界

状态为 locked → unlocking → unlocked → locking → locked，closing 为终止状态。
每次 Get（含缓存命中）先拿库共享锁读取 CURRENT 和元数据摘要，确认与已认证
会话一致；文件读取失败、修订变化或会话过期均不能返回缓存秘密。

无会话时短暂读头后释放文件锁，再执行 Provider/KDF；完成后重新取锁校验头部
及修订未变，再认证 DEK。交互等待不持文件锁。非交互请求不能加入 prompt 解锁，
即使其他请求已经在输入；可以使用已解锁会话或加入 key-file 自动解锁。

同库首次访问合并任务，Context 不从首个等待者继承取消；每个请求独立等待。
全部等待者退出、显式锁定或 Runtime.Close 取消任务。旧任务完全回收前不替换。
首次解锁成功开始 idle timer，成功凭据操作续期，列表、doctor、失败及排队不续期。

缓存由会话内部持有，复用 credential.Cache 数据结构而非 CachedStore 装饰器。
默认容量 64、TTL 零禁用；保存 ExpiresAt，缓存失效时间不超过秘密期限和会话期限。
普通跨进程 Delete 不改变修订号，因此缓存命中还须确认目标条目仍存在且密文摘要
与缓存条目绑定摘要相同；首版有界读取文件计算摘要，不只比较 mtime/size。缺失
失效并返回 not-found，内容变化重新认证，不返回旧缓存。缓存节省解密，不保证省 I/O。
idle 到期必须主动清零，不依赖现有 lazy expiration；每会话最多一个可停止 timer，
Runtime 负责等待已执行的回调。失效 epoch 同时阻止在途请求回填和交付。

“交付”线性化点定义为：持文件共享锁与短暂会话锁，将验证后的独占结果标记为已
转交调用方，同时解除在途租约。锁定之前已转交的结果不撤回；尚未转交的结果必须
在 epoch 变化后清零并报 locked。函数返回前线程可能被抢占，不能承诺物理返回
时刻与锁定绝对排序。跨进程发布同样以该交付点和文件锁释放顺序判定。

锁定先改变状态/epoch、取消任务，再在不持会话锁时等待租约与 I/O 回收，最后清零
并报告完成。已建立 SSH 不断开。维护任务持有独立操作租约，但不能阻止 idle 到期；
需要时被取消并留下可恢复目标，后续由 resume 解锁继续。

## 6. Linux 文件访问与锁

Linux amd64 不设置文件系统类型白名单，不通过 fstatfs magic 或 mountinfo 名称判断
是否允许访问。打开后的句柄仍检查权限、所有者、设备号和 挂载 ID（优先 statx，旧内核使用 /proc/self/fdinfo）；库内子目录
必须与根保持同一设备及挂载，避免跨挂载替换与清理越界。缺少必要操作能力时返回
明确错误；不把“类型允许”当作耐久性证明，也不因取消白名单而降低路径或同步要求。

根及子目录 0700，库文件 0600，所有者为当前有效用户；密钥文件按 ADR 允许 root
所有的 0400/0600。安全打开使用目录句柄相对路径及 O_NOFOLLOW、O_CLOEXEC，
逐级检查目录不可被不受信任用户替换，拒绝符号链接与非普通文件。内核支持时使用
openat2 的 RESOLVE_BENEATH/NO_SYMLINKS；不支持时安全逐级 openat，不降低检查。
不接收任意 journal 路径，不在已打开根之外删除，普通流程不替换锁文件。

文件锁用独立打开的稳定 vault.lock，flock LOCK_SH/LOCK_EX|LOCK_NB 配合可取消
短时等待；不能直接复用当前 credential journal 的仅独占锁实现。进程内增加可取消
读写 gate，先取进程 gate，再取文件锁；释放逆序，失败关闭句柄。
短暂会话锁可在持文件锁时获取，但不能持会话锁等待文件锁。Registry/Repository
锁不跨本后端 I/O。涉及源/目标两个库时按已安全打开根的 (device, inode) 稳定排序取得锁，禁止反序；
该阶段 D 实现细化避免同一物理根的路径别名产生不同排序。

当前发布允许普通 Put/Delete，因此修订号不是内容快照版本。恢复 building/verified
任务时，必须重新核对源条目清单和内容摘要，不能只检查 vault_revision 未变。

## 7. 普通条目事务与预算

Get：共享锁 → 有界 CURRENT/meta 检查 → 有效会话 → 缓存或读取并认证条目 →
检查 Ref、代次与到期时间 → 交付判定。过期返回 not-found，不能自动删除；预算损坏
不妨碍独立认证的只读条目，但禁止写入与不安全清理。

Put：先验证 Secret 非空、最多 64 KiB、ExpiresAt 可编码且尚未过期，再解锁与取
独占锁。已存在时认证并常量时间比较 Value，同时比较 ExpiresAt，同值先补必要
file/dir sync 再成功；异值冲突，损坏不覆盖。该后端的幂等值包含到期时间。

不存在时：认证 budget → consumed+1 不超 2^20 → 新 budget 临时文件 sync →
原子替换并同步其父目录 → 生成 nonce 并加密 → 同目录临时条目写完 sync →
renameat2(RENAME_NOREPLACE) 发布 → items 目录 sync。不支持该原语时首版拒绝
写入，不回退覆盖式 rename。临时文件名为受控随机操作 ID，不含秘密。

预算 sync 失败时不执行加密；成功后崩溃也不退额度。文件系统违背成功 fsync 的
持久性属于支持边界，不能用本地记录证明抵抗整盘回滚。读取旧预算但有无法解释的
残留或认证失败时拒绝新加密，要求恢复，不据条目数重建 consumed。

Delete：由 Service 已确认全局解除引用且 Durable 后调用；Store 仍取独占锁、解锁
并校验预算/目标身份，删除后同步目录。目标不存在也同步必要父目录后成功。
保持现有 asset_delete 恢复语义，不依赖被删除实体仍在配置中。

使用 credentialfile.DurabilityError，携带 Op、Applied、Durable、Cause，保留 errors.Is/As；
Applied 为真不代表配置已提交。任何 Put 错误阻止 Service 配置 CAS，保留 intent；
清理错误保留上层 journal。不能导入 pkg/config.DurabilityError 造成层次循环依赖。

## 8. 维护与恢复

布局沿用 ADR：CURRENT、revisions/<revision>、key-state/<generation>、transactions。
数字目录规范为无前导零十进制正整数。分配编号在独占锁下检查现有目录与所有未决
事务，高于已经占用的编号；失败目标的 DEK 代次不重复使用。扫描只用于分配／诊断，
绝不用于猜测哪个目录是当前发布。单库首版只允许一个未决维护事务。

### 8.1 初始化与重包裹

init 允许不存在的配置路径或安全的空目录；安全创建根、稳定锁、父目录同步后取锁
重新确认无库。生成 vault ID、DEK、初始预算、meta 与事务，CURRENT 最后发布。
仅 lock 文件存在不等于完整库；Get 报 unavailable，resume 可以恢复初始化事务。

rewrap 先验证当前解锁材料，取得新材料，在独占锁内确认源未变；新 salt、新 nonce
包裹一次 DEK，复制条目密文字节（无硬链接），共享原预算。目标密文先存 meta，再
把其摘要记入事务，不把任何包裹密文或密钥放进 state。后续重试只能复用已有封套
或重新生成 salt/nonce，不能用相同派生密钥再加密。

配置 unlock/key_file 是部署预期，库内模式是已认证事实；不匹配时普通访问失败。
模式转换使用 --unlock 和 --key-file 明确目标，命令完成库发布后提示显式更新
配置；不隐式改默认 Store。两者更新间可能暂不可访问，resume 的显式材料输入
可检查已发布目标而不启用普通路径自动回退；配置更新失败不回滚库发布。

### 8.2 重加密与状态记录

取得材料后独占源库，冻结源清单，写 prepared，再 building，建立完整目标。
每个目标条目按预算预留规则写入，读回比较 Value 和 ExpiresAt。清单包含 ItemID、
密文 SHA-256、文件大小，按 ItemID 字节序排序；流式处理，不把全库明文放入内存。
新 DEK 需要当前解锁材料重新包裹，不能只从缓存 DEK 推导回主口令。

state 使用严格 JSON 外壳承载规范二进制 payload 和两端 MAC；payload 仅包含
operationID、操作类型、源/目标身份与修订、DEK 代次、meta 摘要、阶段、清单摘要
与清理对象编号；拒绝未知/重复字段和路径。
单文件最多 16 KiB，大清单分块存于事务目录（每块最多 1 MiB），条目数不超预算
上限。清单块摘要汇总为根摘要，state 的 MAC 从源 DEK 派生；初始化使用目标 DEK，
换 DEK 后保留源/目标各自 MAC，使恢复能验证所处阶段。精确编码见格式规格。
MAC 不能代替 CURRENT/源清单检查，不能借 journal 启用退役套件。

所有文件和目录 Durable 后记 verified，再按 ADR 切换 CURRENT；发布之前再核对
源和目标，切换后重新打开认证，完成 committed。不得用只看 state 的方式判成功。

| 退出／错误位置 | 恢复判定与动作 |
| --- | --- |
| intent 未耐久 | 不发布；孤立目录只展示为待检查，不自动选为当前 |
| building 部分条目 | 验证源清单；预算可靠才继续，否则新 DEK/新目标重建 |
| verified 但源仍当前 | 再验源内容与目标集合；一致才发布，变化则冲突 |
| CURRENT 已替换，state 仍 verified | 按 CURRENT/meta 验证目标，补 sync 与阶段，禁止重复切换 |
| CURRENT 替换或目录 sync 失败 | 保留源/目标，返回耐久性不确定；重开核实实际入口 |
| state 为 published，但 CURRENT 是源 | 不信任阶段推断耐久；重验事务并返回需恢复状态，不能自动回滚/切换 |
| 源修订或源条目已变 | 停止旧任务；保留现场，显式清理废弃目标后重开任务 |
| CURRENT 损坏或指向未知目标 | 普通访问失败；要求显式 restore，不取最大编号 |
| committed 后清理失败 | 当前库仍可读，未完成归档/清理前修改保持失败关闭，保留事务重试 |

未决事务期间普通读取可读经验证的 CURRENT，普通修改返回 maintenance-required，
防止暂停后的升级源持续变化；仍必须核对源清单以应对外部修改或旧程序。

### 8.3 恢复、克隆与清理

restore 从停写可信备份进入隔离目录，校验清单、配置引用、MAC/AEAD 和套件策略。
源工作副本需要可写 transactions 镜像标记；只读归档先复制到隔离目录，原归档保留。
同一原库保持身份，换 DEK 后才开放写入；目标已存在则拒绝，不能在线替换根或锁。
克隆为新 vault ID、显式目标 StoreID，重加密保留 ItemID。需要源和目标材料时
分开获取，主口令输入不进入日志。备份中的原始配置作为验证来源，不隐式写用户配置。

prune 默认只给计划，--apply 时在独占锁下重新计算；不得删除 CURRENT、未决事务
依赖、唯一可恢复目标或当前 DEK 的预算。只从已验证的提交关系选择旧目录，不能
仅按目录名大小删除未知目录。清理为逐对象 unlink/rmdir 与父目录 sync，不跟随链接。
旧预算仍被保留发布使用时一并保留；历史副本回滚不受支持，不能拿旧预算续写。

## 9. KDF 运行与资源

固定 Argon2id 65536 KiB/t=3/p=1/32 字节。私有参数为 __xops_kdf_v1，只允许
精确参数组合；直接调用 os.Executable 指向的可信二进制，不经过 shell/PATH 搜索。
不继承配置环境变量，stdin 单请求后 EOF，stdout 单响应后 EOF，stderr 有界排空。
读取、写入和取消任务均加入等待组；任何协议超量立即取消进程，不等满 timeout。

单 Runtime 一个运行名额，八个不同库排队；同库等待合并。非交互不加入人工输入。
先完成 Prompt 阶段再排 KDF，减少持有口令的时间；队列等待的口令独占保存并在
退出时清零，队列满不保留材料。父进程死后 Linux 用 Pdeathsig，并校验启动时
父 PID 未变化以关闭竞态；进程组清理覆盖派生子孙，实际 helper 禁止派生其他命令。

Linux 可用已委派 cgroup v2 时在开始 KDF 前设置 memory.max 与 memory.swap.max，
只有验证设置生效才称硬限制；没有委派权限不调用 sudo/systemd-run、不修改系统
配置，报告 hard_limit=false，以固定工作参数、单并发和部署配额约束。需要硬保证
的部署必须先提供可用机制；128 MiB 硬限额已通过真实 CLI 原生验收，见
[部署记录](../plans/offline-encrypted-credential-store-deployment.md)。不把 GOMEMLIMIT 当硬限制。
不把测试使用的 CPUQuota=10% 自动变为产品默认，避免人为拖长正常解锁。

预检读取可用的 MemAvailable 和当前 cgroup 祖先的有限 memory.max/current，取
可解释的最小余量。当前实现以 96 MiB（64 MiB 工作区加 32 MiB 余量）作为启动
预检门槛；预检不是硬限额，也不能保证观测后资源不变。无法读取指标须在能力报告中
说明，不宣称预检通过，不尝试危险的大内存探测。
跨平台硬限制、macOS 父进程回收留在支持该平台前完成，不以降级实现宣布支持。

## 10. CLI 与调用方接入

以下为已采纳的新增选项基线；仅非秘密的路径、模式和编号可出现在 argv。普通错误沿现有
CLI 非零退出机制，不另造与项目冲突的退出码；--json 返回稳定 code/op/outcome，
绝不输出秘密或子进程原文。缺少材料的非交互调用失败，--verify 不授予交互权限。

| 命令 | 选项及边界 |
| --- | --- |
| store init ID | 使用已配置 path/unlock；--maintenance-timeout 默认 30m；不修改默认 Store |
| store inspect ID | --verify、--json；默认未认证，仅有界读取元数据 |
| store rewrap ID | --unlock prompt\|key-file、--key-file PATH 指目标；省略模式表示保持；当前材料从原配置/隐藏输入取得 |
| store reencrypt ID | 当前模式重包裹新 DEK；--maintenance-timeout；不提供自由 KDF 参数 |
| store resume ID | --operation ID 可选，省略需唯一事务；--unlock/--key-file 可显式提供已发布目标材料 |
| store restore ID | --from PATH、--maintenance-timeout；目标必须未初始化，材料按源备份与目标配置分别处理 |
| store clone SOURCE | --to TARGET、--maintenance-timeout；目标已配置且未初始化 |
| store prune ID | --apply 才删除；--json 可输出无秘密计划；执行时重新校验 |

维护选项的超时必须正值；rewrap 模式转换成功后打印目标配置片段但不包含材料。
--key-file 与 prompt 冲突时拒绝。读检查使用普通 timeout；维护整体用 30m 默认
预算，仍服从调用方总 deadline，不让每条记录重置总时限。没有 --force。

| 调用方 | 集成要求 |
| --- | --- |
| CLI SSH/SFTP/SCP/exec | 共用组合根 Runtime，隐藏输入复用 Prompt Gate；defer Close |
| TUI | 一套 Runtime；当前进程锁定/解锁、退出等待回收，不回填秘密 |
| MCP/批处理/Playbook | WithoutInteraction，全路径禁止主口令提示，key-file 可自动解锁 |
| doctor | 默认不解锁/初始化/写探测秘密；锁定和不支持分别展示 |
| v1 migrate/finalize | 先已初始化目标，复用 Put/Get 验证；finalize 不删除新库/密钥文件 |
| 配置编辑/CSV 导入/任务覆盖 | 统一凭据引用语义，不绕过 Store 失败去提示服务器密码 |

## 11. 错误契约

复用 ErrCredentialStoreLocked/Unavailable、ErrCredentialAccessDenied、ErrCredentialNotFound、
ErrCredentialStoreReadOnly、ErrInvalidRef。格式层以 format.ErrCorrupt/ErrIdentity/
ErrUnsupported 分类，Store 层使用 ErrUnsupported、ErrConflict、ErrRevisionChanged、
ErrResourceBusy、ErrKeyUsageExhausted、ErrMaintenanceRequired、ErrClosed，KDF 资源
错误为 kdfhelper.ErrResource；耐久性结果使用 credentialfile.DurabilityError。
这些错误通过包级类型或 sentinel 暴露，config/cmd 不根据字符串判断。
context.Cause 与取消/超时必须可 errors.Is 识别。CLI 的 code 与 outcome 契约见
[冻结前审查记录](../plans/offline-encrypted-credential-store-freeze-review.md)。
包裹认证失败不区分坏口令与坏密文；条目认证失败是 corrupt，不返回 not-found。

## 12. 实施阶段与验收

| 阶段 | 交付 | 必须通过的验收 |
| --- | --- | --- |
| A 格式冻结 | 编码器/解析器、测试向量、字段上限 | 独立向量、fuzz、整数边界、AAD 替换、整体 GCM 审查 |
| B 文件层 | 安全路径、读写锁、预算、Put/Get/Delete | ext4/XFS/Btrfs 子进程退出、并发、sync 失败、无覆盖、预算不回退 |
| C KDF/会话 | 协议、受控进程、缓存及锁定 | 管道超量、结果后失败退出、取消竞争、timer/租约回收、内存实测 |
| D 维护 | init/rewrap/reencrypt/resume/restore/clone/prune | 上表每个故障点、源清单变化、同 DEK 预算共享、旧目录清理 |
| E 配置/调用方 | 类型、工厂、Runtime、命令与迁移 | 全调用链非交互、缓存不绕过修订、配置缺省/显式零、原后端回归 |
| F 发布 | 用户指南、验证矩阵 | 主流本地文件系统、离线单二进制、备份演练、build/test/race/lint |

每阶段核心逻辑必须有对应测试，不在真实凭据上做首次迁移。故障注入同时覆盖
模拟 FileOps 错误与真实子进程退出，后者不等同断电耐久性；必要时使用隔离 VM
断电实验验证文件系统保证。测试必须检查文件、pipe、进程和 goroutine 的最终回收。

## 13. 冻结前审查项

本方案行为选择已采纳，以下审查项已逐项对应实现与证据，结果见
[冻结前审查记录](../plans/offline-encrypted-credential-store-freeze-review.md)。
审查已闭环，格式/接口 v1 已按[冻结记录](offline-encrypted-credential-store-v1-freeze.md)正式冻结：

- 1024 字节局部 ID 上限、哈希文件名与现有导入/迁移契约相容性。
- Secret.ExpiresAt 的编码范围、常量时间值比较与过期行为回归。
- 格式/内部协议精确字节和独立完整测试向量、预算/状态 MAC 及 GCM 总安全界限。
- 源/目标材料与模式转换配置更新间隙，resume 不绕过套件和交互策略。
- Linux 句柄/挂载身份、主流本地文件系统 fsync 原语及 cgroup 能力报告；完整 helper 的内存与超时验收。
- 跨平台 ACL、父进程退出和目录耐久性证据未完成前，不扩展首版支持矩阵。


## 14. 阶段 D 存储布局细化

已提交的维护目录通过 RENAME_NOREPLACE 从 transactions 归档至当前修订的 commit，
其中保留 state、源/目标清单，以及 provenance-<20位旧修订>.state。provenance 复用
格式 v1 的已认证重包裹/重加密关系，目标 MAC 由当前 DEK 计算，源端点绑定旧 meta
摘要与 generation；不新增不受 MAC 保护的删除列表。换 DEK 时重新认证并重签关系。
prune 意图仍使用 OpPrune/CleanupPending；完成后归档到 prune-<operationID>。

管理 API 的 Applied 专指 CURRENT 发布，Changed 专指清理删除，Durable 独立表示
耐久确认；错误不抹去已完成副作用。首次 durable intent 前的孤立目录只供检查，
不提供自动猜测、覆盖或 force 清理路径。详细交付和复验命令见实施计划的阶段 D。

## 15. 阶段 E 接口细化

已实现接口沿用第 10 节，restore 增加必填 --backup-config，显式提供可信 v2
备份配置；--source-unlock/--source-key-file 描述源材料。跨库 resume 增加 --from
与 --source-store，不从日志自动加载路径。TUI Ctrl+L 锁定已打开的当前进程库，
Ctrl+U 在释放终端后解锁默认库；普通后台操作不发起主口令输入。
