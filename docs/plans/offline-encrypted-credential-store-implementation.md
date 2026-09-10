# 离线加密凭据库实施进度

- 更新：2026-09-10
- 依据：[详细设计](../design/offline-encrypted-credential-store.md)、[格式规格](../design/offline-encrypted-credential-store-format.md)
- 状态：阶段 A–F 已实现，部署与审查通过，格式与接口 v1 已冻结（2026-09-10）
- 验证记录：[原生部署与 KVM 断电验收](offline-encrypted-credential-store-deployment.md)
- 文件系统策略：取消类型白名单，主流本地 ext4/XFS/Btrfs 已完成回归及 42 个 KVM 断电点，见[兼容性记录](offline-encrypted-credential-store-filesystems.md)
- 冻结状态：[最终工程审查](offline-encrypted-credential-store-freeze-review.md)通过，原始字节身份去重问题已修复；[正式冻结记录](../design/offline-encrypted-credential-store-v1-freeze.md)已生效，尚未发布
- 边界验证：确定性边界测试与[密码学工程安全评估](../design/offline-encrypted-credential-store-security.md)已补齐，供阶段 A 验收复核

## 阶段 A 实现

`internal/credentialfile/format` 提供不接触文件系统的格式与密码学原语：

- 严格前缀、固定套件/KDF 参数及 ID/载荷长度检查。
- vault.meta 解析、DEK 包裹/解包、key-file HKDF 域分离。
- 条目 AES-GCM、完整身份绑定、到期时间保留与溢出拒绝、安全 ItemID 文件名映射。
- CURRENT 精确编码及元数据摘要匹配；匹配不等于认证或防回滚。
- 预算 HKDF/HMAC，计数范围校验；不在此层执行持久化预留。
- 严格 JSON/Base64 事务外壳、规范 payload、源/目标 MAC、状态与身份关系检查。
- 有界清单编解码、根摘要和流式验证器，检查连续块编号、跨块顺序及条目总数。

阶段 A 交付时 `internal/kdfhelper` 仅提供请求/响应编解码与材料清零；阶段 C 已
新增私有执行入口，见下文。格式包仍不创建库、生成随机材料、读取配置或注册 Store。
SealMeta/SealItem 是显式 nonce 的低层原语，调用方必须先生成新随机材料并满足
持久化预算；这些原语不作为可写后端直接使用。

测试数据位于 format/testdata/vectors.json。生成脚本使用 Python cryptography
和系统 libargon2，独立于 Go 编码器；Go 测试直接读取已提交的固定结果，不要求
Python 或 libargon2 作为运行时/测试依赖。所有材料公开且固定，只用于测试。
state 向量验证双端 MAC/编码，目标 meta 摘要为公开占位输入的摘要，不代表完整
可恢复库；文件存在性和逐条认证仍须由阶段 B/D 验证。

复核发现并修复了非 init 事务允许全零源清单根的问题，prepared/verified/committed
均有回归测试；空源集合要求真正的空清单摘要。还修正了截断套件字段的错误分类，
并拒绝 JSON null、重复字段及非规范 Base64。解码结果不借用输入秘密缓冲区。

## 验证记录

- 全仓 `go build ./...`、`go test ./...`、`golangci-lint run ./...` 通过。
- 新包重复 race 测试通过：`go test -race -count=3 ./internal/credentialfile/format ./internal/kdfhelper`。
- FuzzContainers、FuzzRecoveryFormats、FuzzProtocol 各执行 10 秒、两个 worker，未发现失败。
- 独立向量覆盖两种包裹、条目及到期字段、预算、CURRENT、双端 state、清单根和协议。
- 定向测试覆盖认证字节逐字节篡改、截断、尾随数据、跨身份替换、KDF 超限参数、
  预算上限、时间溢出、秘密独占与清零、清单集合边界。

测试可重跑，短时 fuzz 不是穷尽证明；Go race 不等于进程/文件生命周期验收。

## 阶段 A 评审缺口补齐

- 新增六类维护操作的合法双端认证往返；Restore/Clone/Prune 的身份、代次、修订
  与清理关系反例；清理列表 256 接受、257 编码与有效 MAC 解码拒绝。
- 新增 Source/Target.ItemCount 的 2^20 接受、超一编码和有效 MAC 解码拒绝；
  MaxUint64、零值与回卷关系、i64 Unix 纳秒两端及相邻溢出均有确定性测试。
- 验证两个 ID 与秘密同时达到上限时的最大条目，以及清单恰好 1 MiB 和超一字节。
- 工程安全评估涵盖 GCM 分组数、nonce 事件、伪造尝试、保守组合模型、多密钥、
  重包裹 salt、口令猜测及 HKDF/HMAC/摘要绑定；使用当前实际头部大小的有理数
  测试重算数值。独立只读复核未发现明确计算错误，不等同第三方安全认证。
- 验证覆盖固定算法、加密预算和已分配字节布局。

## 待完成阶段

| 阶段 | 当前状态 | 后续内容 |
| --- | --- | --- |
| A 冻结审查 | v1 已正式冻结 | 独立向量已固定，格式/协议及配置/CLI 契约的兼容性规则已记录 |
| B 文件层 | 实现及部署验证完成 | 安全打开、句柄/挂载身份、跨进程锁、预算耐久预留、Put/Get/Delete；F 已补充主流文件系统 KVM 断电验收 |
| C KDF 与会话 | 实现及本地验证完成 | 私有进程、Runtime/租约/缓存/idle lock、队列和 Linux 内存限额；正式组合根接入留到 E |
| D 维护 | 已实现，完成本地验证 | Init/Rewrap/Reencrypt/Resume/Restore/Clone/Prune；故障恢复、源清单、共享预算与清理边界 |
| E 配置与调用方 | 已实现，完成本地验证 | Schema/Registry、组合根 Runtime、CLI/TUI/MCP/迁移/GC |
| F 发布 | 部署验收与冻结完成，正式发布待完成 | 验收证据已齐备；剩余候选提交、产物绑定和发布检查 |

受限资源探针 salt 文本实际 17 字节，原记录错误已修正。格式 v1 独立向量使用
严格的 16 字节 salt；原性能数据不能当格式 v1 或完整 helper 的验收证据。

## 阶段 B 实现

`internal/credentialfile` 实现已有库的 Open/Get/Put/Delete/Close。Open 不创建目录或锁文件。
解锁通过注入的 KeySource 完成：KeySource 必须认证完整 meta 并返回独占 DEK 副本，
文件层使用后清零；nil 返回 locked。阶段 C 已通过 Runtime 路径加入会话、租约和交付栅栏。

Linux amd64 文件访问保留 statx mount ID 与设备号校验，不按文件系统类型限制访问。
目录句柄逐级 O_NOFOLLOW 打开，严格检查
所有者、0700/0600、普通文件、单硬链接与挂载边界；目录权限在操作时重新检查。
不支持的平台编译为显式 unsupported 实现，未因交叉编译成功宣布可用。

同物理库共享进程内可取消读写 gate，另使用稳定 vault.lock 的跨进程 flock。
锁等待、关闭和调用取消有确定退出路径；Close 等待所有活跃操作和取消回调，
关闭根句柄并释放 gate 引用。KeySource 在文件锁外执行，返回后重新检查完整
CURRENT/meta 摘要；改变时不使用旧材料继续操作。

写入先认证并耐久更新 budget，再分配 nonce 和加密，使用 RENAME_NOREPLACE
发布条目并同步目录。相同 Value/ExpiresAt 的重试补 file/dir sync，不消耗新预算；
不同值冲突。Delete 不退预算，缺失目标也补目录 sync。库级锁不替代 Service
的全局无引用确认，调用方仍必须保证先解除配置引用且 Durable。

DurabilityError 的 Op 区分 budget、put 和 delete。已应用未确认耐久时保留
Applied=true/Durable=false；sync 已成功后发生取消或关闭错误，也保留
Applied=true/Durable=true。若只有预算完成，错误标记 budget，不能解释为秘密
已经保存。独立复核发现的这两处取消/收尾边界遗漏均已修复并有定向测试。

阶段 B 后续评审发现的临时文件残留问题已修复：原先 openat 创建成功但权限等
校验失败时，路径清理未注册。修复将句柄打开与文件校验分离，创建成功
立即注册关闭、unlink 和目录 sync，再做校验；普通已存在文件的 open 禁止创建。
在独立测试子进程内设置受限 umask，覆盖 budget 与 item 临时文件校验失败，
确认无残留、恢复 umask 后可直接重试且预算不退还；O_EXCL 同名冲突不会删除
或覆盖预存在的文件。umask 不修改共享测试进程或任何服务器环境。

### 本地验证范围

- 环境：Linux 6.18.35.2-microsoft-standard-WSL2、amd64、ext4，Go 1.26.7。
- 使用 `-tags=integration` 的临时库，goleak 检查、原生文件系统调用及真实子进程
  退出验证。测试数据与生产配置隔离。
- 故障矩阵覆盖预算/条目的写入、file sync、发布、dir sync，ENOSPC、随机源失败、
  原语不支持、意外目标存在、取消及关闭错误。
- 多句柄和独立进程验证同值幂等、不同条目预算串行；进程在持锁和各发布阶段
  退出后，验证锁释放、可见性、不退额和未解释残留的失败关闭。
- 拒绝符号链接、FIFO、硬链接、不安全权限、超大文件、替换锁 inode；验证过期
  字段冲突、只读、调用取消、缺失库不初始化以及拒绝路径后的句柄数量不增加。
- 全仓 build/test/lint、integration 定向 lint，以及五次 integration race 测试。
  Windows amd64 / Darwin arm64 仅验证 unsupported 分支交叉编译。

重跑主要命令：

```sh
go test -tags=integration -race -count=5 ./internal/credentialfile
golangci-lint run --build-tags=integration ./internal/credentialfile/...
```

## 阶段 C 实现

### 私有 KDF 执行器

- `cmd/cli/main.go` 在语言初始化和 cmd.Execute 前分流精确参数 __xops_kdf_v1，
  不调用普通 CLI 初始化、配置加载或迁移。Go 包级初始化仍会创建静默日志对象，
  私有路径不输出日志、不使用该对象；实际二进制的 stdout 与协议向量逐字节一致。
- stdin/stdout 只使用匿名管道。子进程复制管道句柄并设置非阻塞模式后加入 Go poller，
  设置读写 deadline；不接受普通文件或终端作为私有协议载体。请求/响应、stderr
  均有界，超量取消进程，不回显诊断原文。
- 最小环境仅含 GOMAXPROCS=1、GOMEMLIMIT=96MiB 与非秘密的
  XOPS_INTERNAL_KDF_TIMEOUT。零 Runner.Timeout 继承调用方 deadline，未提供
  deadline 时默认 30 秒；子进程 I/O 预算与父进程预算一致，不将增加后的预算
  隐式截为 30 秒。协议格式没有增加秘密环境变量或改变帧编码。
- Linux 使用独立进程组与 Pdeathsig，并保持创建 OS 线程到 Wait 完成。先以
  waitid(WNOWAIT) 观察退出、保留 leader PID，再终止剩余进程组、调用 Cmd.Wait
  回收，避免先回收 leader 后误用已复用的进程组编号。
- 只有合法单响应、EOF、零退出和仍有效的上下文才接受密钥。失败响应可映射
  protocol/unsupported/resource/process 错误，任何异常都清零并丢弃密钥。
  取消和清理错误保留 cause，管道写任务、exec 复制任务和进程全部等待回收。

### Runtime 与会话

- 同一组合根共享一个 Runtime。OpenStore 根据安全打开后的物理根身份合并会话；
  同库不同解锁策略或 StoreID 拒绝冲突，Runtime 的映射锁不跨文件 I/O。
- 阶段 C 评审后的修复：打开操作在文件 I/O 前纳入 Runtime 的等待范围，Close
  拒绝新打开并等待所有在途打开清理。打开请求使用调用方与 Runtime 的合并取消
  信号，注册前重新检查；成功交付后的 Store 生命周期仅归 Runtime，不被打开
  请求后续取消误伤。
- 会话保留进程内已认证的 vault/revision/DEK 代次和摘要；旧修订、倒退代次及
  同修订不同摘要直接返回 revision-changed，不撤销较新的租约或解锁任务。
  刷新判断和撤销在同一互斥区内完成，避免检查后新会话被旧请求锁定。认证失败
  不推进该记录；记录跨 idle/显式锁定保留，但不提供跨进程或备份的可信抗回滚。
- 物理库首次解锁合并为一个任务；首个/单个等待者取消不影响其他等待者，全部
  取消会终止任务，旧任务回收后才重试。非交互请求不能加入 prompt 任务，根
  Context 与 SessionOptions 的禁止交互策略也不能被单次请求绕过。
- PromptProvider 由调用方注入；Runtime 提供串行提示 gate 和独立 prompt_timeout。
  KDF 排队与计算使用 unlock_timeout，一次只运行一个 KDF，最多八个额外任务排队。
  实际结果到达后再次检查 deadline，不接受忽略取消后迟到的派生结果。
- 每会话一个可等待的 timer 所有者循环，idle 期限到达时清除 DEK、缓存和摘要，
  撤销 epoch 并取消在途租约。Lock 只有在任务和租约回收后才完成；取消 Lock 的
  等待不等于回收完成，Runtime 继续持有清理责任。
- Runtime 管理的 Store 使用独占密钥租约执行文件操作，并在文件锁内检查 epoch、
  操作 deadline 和会话状态后交付。等待解锁完成的旧任务也不能越过新的锁定 epoch。
  原有 Applied/Durable 错误语义保持不变。
- 缓存位于会话内，默认禁用。命中前仍检查 CURRENT/meta 与真实条目密文摘要，
  不能因跨进程删除或篡改继续返回旧秘密。Put/Delete 前后失效对应项；成功操作
  才续期，缺失条目和失败请求不续期。
- key-file 模式安全逐级打开，接受当前用户/root 所有的普通 0400/0600 文件，
  长度必须为 32 字节；拒绝符号链接、硬链接及不安全权限。独立复核发现并关闭
  部分读取出错时缓冲区清零遗漏，故障 reader 检查实际缓冲区已清零。
- Store.Unlock/Lock 仅控制当前 Runtime 的进程内会话，不创建跨进程解锁服务。
  Windows/macOS API 保持可编译但返回 unsupported，尚未宣布运行时支持。

### 资源和原生证据

默认不提权、不依赖 systemd、不修改系统配置。可观察的 MemAvailable 与 cgroup
祖先 memory.max/current 取已知最小余量；96 MiB 为 Linux 实测后的保守启动
预检门槛（64 MiB 工作区加 32 MiB 余量），不是硬限制或对并发变化的保证。
Capabilities 标记是否有观测信息；无法完整观察的部署不能据此宣称内存一定充足。

配置已委派 CgroupParent 时，先验证 cgroup v2，再创建私有子组并设置/读回
memory.max=134217728、memory.swap.max=0。子进程加入成功前不发送 KDF 请求；
安装失败直接取消和回收，不回退软限制。memory.events 的 oom_kill 提供可靠的
资源错误分类依据；完成后删除私有子组。未配置时明确只有软目标和固定参数约束。

本地环境为 Linux 6.18.35.2-microsoft-standard-WSL2 / amd64，Go 1.26.7：

| 实际 XOps 二进制冷派生 | 墙钟秒 | 峰值 RSS KiB | 独立协议向量 |
| --- | --- | --- | --- |
| 1 | 0.25 | 79152 | 一致 |
| 2 | 0.19 | 79088 | 一致 |
| 3 | 0.20 | 79088 | 一致 |

冷派生测量未设置 CPU 配额，与受限资源测量不构成直接性能比较；三个样本未进行
显著性检验。实际二进制还在本地 128 MiB 私有 cgroup 下成功派生；超量测试只
对另一个受同样限额保护的测试 helper 分配内存，确认内核终止及资源错误，未影响
其他进程的配置或限额。原测试进程位于 init.scope，无法直接迁移到委派子树，
监督测试使用用户级 systemd unit，unit 与私有子组均完成回收。

父进程死亡测试在独立 supervisor 中设置 subreaper，确认 worker 收到 SIGKILL
并由 supervisor 回收，避免把僵尸进程留给共享测试进程。三次 integration race
覆盖 Runtime/Runner 与阶段 B 回归，goleak 验证 Go 任务退出。

常用验证命令：

```sh
go test -tags=integration -race -count=3 ./internal/credentialfile ./internal/kdfhelper
golangci-lint run --build-tags=integration ./internal/credentialfile/... ./internal/kdfhelper/...
```

委派内存测试在没有权限的普通环境会明确 skip，不能把 skip 当作硬限额验收。
另外在可迁移的用户级 unit 内执行 TestRunnerDelegatedMemoryLimit 并通过。
CLI/TUI/MCP 的 Runtime 组合根及维护命令已分别完成接入。


## 阶段 D 实现

### 管理 API 与事务

- Runtime.Init 仅创建不存在或安全空根；拒绝覆盖 CURRENT。Store 提供 Rewrap、
  Reencrypt、Resume、ResumeFrom、Clone、Restore、Prune，并已完成 CLI/YAML 工厂接入。
- Wrapping 显式传入目标模式、借用的口令或安全 key-file 路径。新口令至少十二个
  Unicode 字符，KDF 参数固定。KDF 在文件锁外执行；持锁后复核状态与 CURRENT。
  SessionOptions.NonInteractive、调用 Context 和 Runtime 的非交互约束均保留。
- 维护整体默认 30 分钟，仍受调用方更短 deadline 约束。正常升级使用会话租约；
  Resume 的显式材料注册独立撤销租约，不安装为普通缓存密钥。Lock/Close 能取消
  派生、锁等待和构建，并等待材料清零。逐条成功认证属于维护活动，可续 idle 期限。
- 源快照逐条认证并分块外部排序，最多持有少量清单块和单条秘密。完整清单绑定
  ItemID、文件大小和密文摘要；Resume 同时验证条目集合，能发现同修订 Put/Delete
  或外部修改。过期条目也保留 Value/ExpiresAt；普通 Get 仍返回 not-found。
- Rewrap 复制密文字节、不建硬链接，提前认证并共享原 generation 的预算。
  Reencrypt/Clone/Restore 使用新 DEK；预算先耐久预留，再生成 nonce 和加密，
  每条读回比较。目标条目、元数据、预算和目录同步后才记录 verified。
- CURRENT 是唯一发布入口。恢复会在持锁后复核事务原文、活动目录和实际 CURRENT；
  已发布而阶段落后时补验证/sync/提交，不再次切换。源内容变化、指针损坏或
  published 与实际源入口矛盾时保留现场并拒绝猜测。
- building/verified 目标的预算缺失、认证失败、计数小于条目数或存在预算临时残留，
  必须分配更高 generation/revision 和新 DEK 重建；不按条目数重建旧预算。
  已发布预算异常不能自动更换入口，需要显式恢复。
- MaintenanceResult.Applied 表示 CURRENT 已切换；Durable 单独表示已确认耐久。
  后续日志、归档或 Close 失败仍保留这两个字段。prune 的 Changed 独立表示已执行
  删除；部分清理失败返回 Op=prune 的 DurabilityError，不伪装为没有修改。

### 双根迁移与清理

- Clone 使用新 VaultID 和显式目标 StoreID，保留 ItemID。Restore 保持原身份、
  使用比源更高的代次与修订；required 参数由调用方提供可信备份配置中的引用，
  缺失或无法认证的引用阻止发布。存储 API 不自行加载或改写 YAML。
- 两者要求新目标；通过物理祖先检查拒绝同根、祖先或后代目录。双根锁按
  (device, inode) 排序，取代设计初稿的路径排序，避免别名造成锁顺序不一致。
- 源允许以只读条目句柄使用，但源根必须可写维护标记；停写备份应先复制到隔离
  工作目录，不能直接对只读挂载或唯一归档执行迁移。源 transactions 中保存镜像
  intent，在目标 intent 之前耐久写入，阻止暂停期间源的普通修改。恢复显式接收源
  句柄，不从 state 加载任意路径；覆盖或删除镜像前验证源身份、事务身份与 MAC。
- 已提交事务目录原子归档到 revisions/<target>/commit，并同步两个父目录，随后
  清除源镜像。CURRENT 仍指向可用库；未完成归档前普通修改保持 maintenance-required。
- 提交时以当前 DEK 签署旧修订 provenance 证书，绑定旧身份、代次和 meta 摘要；
  后续轮换重新认证并传递证书。prune 默认只给计划，apply 在锁内重新计算，每批
  最多 256 个目录。绝不按编号大小清理未知目录。
- 删除采用 fd-relative 的逐文件 unlink/rmdir/sync，拒绝链接和非预期布局。
  旧 meta 摘要必须匹配证书；删除旧预算前遍历保留修订检查 generation 引用，
  共享预算、当前预算及引用情况不明的预算均保留。cleanup_pending 可幂等 Resume，
  完成的清理意图归档为当前修订内的 prune-<operationID>。

### 验证与明确边界

- 公共固定向量与临时 ext4 库覆盖：基本七类操作、模式/非交互策略、过期值、
  配置引用缺失、跨库镜像误传、嵌套路径、源内容变化、共享预算、未知目录保护、
  部分删除结果、预算异常重建和 Lock 取消 Resume 派生。
- 子进程在 prepared/building/verified/published/committed、预算和条目写入/sync/
  发布、CURRENT 写入/sync/发布、归档处退出；重开验证秘密可读、普通修改可恢复、
  预算不被猜测或复用。错误注入另覆盖 Init、跨库与 prune 的中断路径。
- 首次 intent 耐久之前的孤立目录保持 maintenance-required，不能自动 Resume 或
  prune；需要人工检查原现场或从可信备份向新根恢复。初始化重建中未形成可认证
  提交关系的废弃目录同样保留。不把“存在目标文件”当成完整事务或清理授权。
- 进程退出和 KVM 断电分别验证。Linux amd64 的 ext4/XFS/Btrfs 已通过兼容性测试；
  Windows/macOS 保留 unsupported API。
- race 校验发现既有 idle 测试把 40ms 期限用于磁盘准备阶段，慢 fsync 会让
  Put 正确返回租约失效。测试改为准备完成后启动短期限，再验证真实 timer 清零；
  未放宽生产超时。

复验命令：

```sh
go build ./...
go test ./...
golangci-lint run ./...
golangci-lint run --build-tags=integration ./internal/credentialfile/... ./internal/kdfhelper/...
go test -tags=integration -race -count=3 ./internal/credentialfile ./internal/kdfhelper -timeout=180s
```

### 阶段 D 评审修复：预算恢复边界

- Building 状态尚未记录最终 Target.ItemCount；恢复在任何后续加密前枚举已发布
  目标条目，以实际数量复核认证预算下限。计数矛盾时使用新 DEK、新代次和新修订
  重建，不复用旧预算；临时条目不视作已发布条目。
- Committed 但仍处于活动事务中的目标，归档前也必须重新验证完整目标清单、
  条目及预算。预算缺失、损坏、临时残留或计数不足均保留事务并返回错误，
  保持 CURRENT 不变，不能仅凭阶段标记宣布恢复成功。
- 回归测试重放真实的初始预算，覆盖部分构建后仍有待写条目，以及 Committed
  后四种预算异常；验证新目标重建、条目完整性、事务保留和恢复后继续提交。

- 已归档恢复也在成功确认及清理源镜像之前认证当前预算、拒绝预算残留，并以
  当前条目数量检查预算下限。归档后允许正常 Put/Delete，因此不要求当前条目集合
  与历史提交清单一致。测试覆盖四种预算异常时保留源镜像，以及正常增删后的恢复。

## 阶段 E 实现

- Schema 增加 encrypted-file 与 path/unlock/key_file 和三种会话期限；YAML 区分
  省略与显式零，保留旧后端默认语义；路径相对于实际配置文件，局部引用长度预检。
- EncryptedRuntime 显式拥有 Runtime/句柄，Registry 和 Service 借用；延迟打开按
  配置去重，失败可重试，不套通用 CachedStore。命令主入口在成功及失败路径等待
  Close，SSH/SFTP/SCP/exec、导入、MCP、Playbook 与迁移共用工厂。
- 完成八种 store 子命令、元数据 JSON/认证状态、操作选择、维护总超时、源/目标
  独立材料。restore 使用显式 --backup-config 提取可信 v2 引用，跨库 resume 使用
  --from/--source-store/--source-unlock/--source-key-file，不加载日志中的路径。
- doctor 不解锁或写探测秘密。TUI Ctrl+L/Ctrl+U 控制当前进程会话，主口令解锁在
  Bubble Tea 释放终端后进行，普通 TUI 操作不发起主口令交互。非交互可使用已解锁
  会话；锁定后不得通过缓存交付或加入人工输入。
- 回归测试发现模式转换后立即 Resume 与异步清零竞争；维护 guard 现以可取消
  等待完成先前清零，再原子注册租约。保留 Lock 取消及收尾等待语义。
- 测试覆盖配置零值/错误字段/长度界限、路径基准、缓存与锁定、非交互冷/热会话、
  CLI 初始化/检查/轮换/恢复/克隆/prune、JSON、错误选项、迁移/finalize，以及 TUI
  控制回调。测试采用公开材料与隔离库。
- 使用与备份操作说明已记录于[离线库指南](../offline-encrypted-credentials.md)。

### 阶段 E 验证结果

- 全仓 go build、go test、golangci-lint，以及全仓 integration 标签 lint 通过。
- credentialfile/kdfhelper/config/tui 三轮 integration race 通过；cmd 三轮 race
  使用 `GORACE=atexit_sleep_ms=0` 移除测试子进程的退出等待后，三轮测试在
  180s 测试期限内通过（约 124s）。
- 共享注册表/非交互适配器测试两轮 race 通过。
- 真实 XOps 二进制在临时私有 ext4 目录完成 key-file 初始化、检查、重加密、
  resume 和 prune；伪终端完成主口令初始化、认证检查和重加密，确认输入不回显。
  无终端主口令访问返回 locked；v2 命令路径未生成 legacy secret.key。
- Windows amd64、Darwin arm64 的 CLI 交叉编译通过，仅证明 unsupported API
  组合完整，不构成平台原生运行支持。

### 阶段 E 评审修复

- 迁移预检拒绝所有已配置 encrypted-file key_file 与待清理 legacy 文件重叠；
  比较配置基准下的规范路径、符号链接解析路径及已有文件身份。finalize 在读取
  当前配置验证引用时及持配置锁删除前再次检查，保留密钥、备份和未完成状态。
- RecoveryNeedsSource 独立读取有界事务信息，不依赖目标 CURRENT 已存在；
  未发布 Clone/Restore 需要源材料，Init 不需要，未知或损坏状态返回错误。
  CLI 不再忽略检查错误，最终仍由 Resume 认证并持锁复核全部状态。
- 主口令提示使用 stderr，避免恢复时的隐藏输入提示污染 --json 标准输出。
- 回归覆盖迁移前拒绝、迁移后配置改指向旧密钥、链接别名、未发布跨库材料判断、
  Init 与损坏状态。实际二进制从原失败现场取得隐藏源主口令，通过真实 KDF 完成
  跨库恢复；所有测试材料公开，仅在本地临时目录运行。

## 阶段 F 实现

- 增加标准库 Python 驱动的离线单二进制/停写备份恢复验收脚本；实际在独立网络与
  mount namespace 执行，空 PATH 下完成 key-file、主口令 KDF、恢复后写入和清理。
- 独立工程审计发现并关闭 Prune 预算下限检查遗漏；首次与恢复清理均保留不可靠
  预算下的旧修订及事务。新增回归与独立原复现均通过。
- 补充支持矩阵、二进制和测试向量哈希、复跑命令及证据边界。详见
  [发布验收记录](offline-encrypted-credential-store-release.md)。
- 已完成原生桌面和无桌面环境验证、三种文件系统的 42 个 KVM 断电点及 v1 冻结。

### 阶段 F 演练校验补缺

新增仅用于验收的 offline-vault-verify 校验器，通过原配置引用 Get 并比较公开原值。
脚本在备份前记录原引用，恢复后独立验证引用和值，再进行后续 set；条目缺失或
密文篡改必须立即失败。标准库 Python 反例测试覆盖原误报场景，校验器不属于 XOps
运行依赖，不输出秘密。详见发布验收记录中的复跑步骤。
