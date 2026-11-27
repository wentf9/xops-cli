# XOps CLI 架构不变量、隐式契约与防漂移治理基线

> **确认基线**：`feat/openssh-compatibility` @ `e957386`（2026-11-23；相对 `e51c2e0` 完成 P7 全量 94 个架构根治提交，相对 `9d3648f` 共 120 个提交）。  
> **目标**：把 P0–P7（含 W0–W19 共 20 轮独立对抗审计）沉淀下来的**架构变更、全部不可破坏不变量、已显式化的隐式契约、剩余风险与编译期/CI 防漂移护栏**持久化为仓库治理规范。任何后续功能开发、重构或 AI 协作修改在触及对应子系统前均须核对本文档，严禁破坏已建立的结构性不变量。

---

## 1. 架构变更总览（P7 七大架构支柱）

P0–P6 阶段逐项修复了大量单点缺陷，但反复暴露出 8 类产生缺陷的**元机制（M1–M8）**：安全规则依赖人工记忆而非类型/可见性强制（M1）、身份键手工挑选字段（M2）、各调用方各自拼装 OS 文件/锁原语（M3）、用字符串哨兵表达三态语义（M4）、安全判定返回 `bool` 吞错放行（M5）、资源租约依赖调用方记得释放（M6）、持久化不变量散落在 `cmd` 层（M7）、以及仅按函数名匹配的脆弱守卫（M8）。

P7 遵循五条硬性架构原则——**类型即授权**、**规则唯一实现并由可见性强制**、**身份键由完整结构反射派生**、**零值与错误即拒绝**、**不变量在持久化写入边界强制**——在不保留历史兼容垫片的前提下落地七大架构支柱（A–G）：

| 支柱 | 对应元根因 | 新增 / 收敛的唯一权威入口 | 核心架构变更 |
| :--- | :--- | :--- | :--- |
| **A. 句柄优先文件系统与 ACL 内核** | M3 | `core/fsx/{regular,locked,replace,socket_slot,validate,fsx_unix,fsx_windows,fsx_other}.go`、`core/winsec/{handle_windows,windows,longpath,eval}.go` | 全仓收口裸路径文件读写、加锁、替换与控制套接字竞争，改用句柄优先 `O_NOFOLLOW` / `FILE_FLAG_OPEN_REPARSE_POINT`、`SameFile` 验证、`SocketSlot` 目录锁及 Windows 句柄级 Owner-Only DACL + `\\?\` 超长路径规范化。 |
| **B. 类型化单一传输门面** | M1, M2 | `core/sftp/{path_types,download,readdir,transfer,replace_local}.go`、`cmd/scp.go`、`cmd/sftpshell/shell.go` | 仅导出 `(*sftp.Client).Download`、`ReadValidatedDir`/`(*Client).ReadDir` 与 `UploadExact`/`Upload`；引入 `RemotePath`/`RemoteName`/`LocalTarget`/`LocalDest`；统一符号链接策略 `(b)`、NFC/NFD 与大小写折叠碰撞防御及 `fsx.ValidateLocalComponent`。 |
| **C. Merkle 计划摘要与 CAS 连接池** | M2, M6 | `core/ssh/{types_api,hop_digest,pool,proxy_chan_conn,mux_server,agent_forward,host_algorithms,connector_knownhosts,proxy}.go` | `ClientConfig` 唯一经 `NewClientConfig` 构造；`HopDigest` 递归纳入上游摘要并由 94 个结构体 `digest` tag 反射校验完备性；`connPool.Publish` 父代 CAS；keepalive 归 `PooledClient` 独有；`proxyChanConn` 90ms 有界关闭 + 非重入 `detachAndAbortRoot`；`HostKeyCallback`/`HostKeyAlgorithms` 共享单一加锁 `knownHostsDB`。 |
| **D. 单一选项代数与四层策略求解器** | M4, M3 | `core/ssh/{option_parser,ssh_options,path_list,algo_policy,proxy_setting,control_setting}.go`、`pkg/adapter/{policy_solver,control_target,ssh_adapter}.go`、`cmd/{ssh,ssh_control,mux_daemon_spec}.go` | 全仓唯一 `ssh.ParseOption` 解析器与结合律幺半群类型（`PathList`/`AlgoPolicy`/`ProxySetting`/`ControlSetting`）；唯一 `(*SSHAdapter).Resolve` 出口；显式 `config.NodeProvenance` 驱动拨号、`-f` 预检、`-O` 控制面与 `ControlPersist` 守护进程移交全平面一致性。 |
| **E. 失败关闭判定与 MCP 双阶段护栏** | M5, M2 | `core/verdict/verdict.go`、`core/ssh/endpoint.go`、`core/mcp/{guardrail,ports,runtime,remotefile,sshexec,tunnel}/**`、`internal/mcphost/host.go` | `verdict.Verdict` 零值强制 `Deny`；Tier-4 以 `ssh.Endpoint` 绑定 `(Host, Port)`；跨 OS UTF-8 `matchGuardrailGlob` + 最严 `NodeOverrides`；`gui` 探测绑定与 POSIX Bourne 解释器强校验；`file`/stdio `transfer` 双阶段路径规范化 + 信封绑定；HTTP `transfer`/stdio `tunnel` 全动作准入。 |
| **F. 写入边界全图不变量与作用域租约** | M6, M7 | `pkg/config/{validate,repository,doctor,pending_connection,credential_create,target,target_ref,provenance,schema_v2,private_key}.go`、`cmd/config/doctor_cmd.go`、`cmd/host/{add,edit,load}.go` | `Repository` 加载与提交双端强制 `ValidateGraph`（含跨命名空间 `ProxyJump` 环与 Schema v2 `StoreID`）；新增 `xops config doctor [--fix]`；`WithPendingNode`/`PendingLease` 作用域自动清理；Vault 先写后提交 + 5 位置引用计数 `DeleteAssets`；复用 `--identity` 模板严格隔离。 |
| **G. 编译期与 CI 静态防漂移护栏** | M8 | `.golangci.yml`、`scripts/check_core.py`、`internal/clicontract/{p4,p6,p7}_*_test.go`、28 个 `Fuzz*` 目标与 `-count=50` 模型并发测试 | 全仓启用 `forbidigo` + `depguard` + AST 守卫（`ClientConfig` 构造、`secpred` 裸 `bool` 吞错、Guardrail `switch` fail-closed）+ 零值反射表 + 幺半群代数律 + 独立 `core/` 抽离测试。 |

### 1.1 已永久删除的历史平行符号（禁止重新引入）

以下 **31 个**旧路径已在生产代码中彻底清零（由 §6.2 门禁持续约束），任何 PR 不得重新引入同名或等价平行路径：

- **传输层**：`(*sftp.Client).DownloadFile`、`(*sftp.Client).DownloadDirectory`、`prepareRemoteToRemoteFile`
- **连接池与主机密钥**：`connectionRouteKey`、`reuseJumpChainedTarget`、`startKeepAliveFor`、`validateTargetCompatibility`、`openKnownHostsFileNoFollow`、`unlinkControlSocketFileIfOurs`、`isLineageDescendantLocked`
- **选项、路由与作用域**：`SameHostAddress`、`MergeOptionLayers`、`EffectiveOptions`、`ParseOptionStrings`、`filterOpenSSHAllowListOption`、`appendNoneTerminatedRaw`、`splitCanonicalOptionKV`、`validateSafeRemoteHomeToken`、`ClassifyProxyJump`、`HasActiveProxyJump`、`ProxyJumpKind`
- **配置边界与校验**：`PrepareNodeContext`、`DiscardPendingNode`、`ConfirmNodeContext`、`persistPreparedNodeUpdate`、`validateCLIAlias`、`isProxyJumpHardValidationError`、`isControlTargetValidationError`、`checkJumpChainSelfLoop`、`checkControlJumpSelfLoop`、`checkPolicyJumpSelfLoop`

---

## 2. 全部不可破坏不变量（All Architectural Invariants）

### INV-A：文件系统句柄安全与 ACL 不变量（`core/fsx`, `core/winsec`）

- **`INV-A1`（禁止先 Stat 后 Open）**：`core/fsx` 之外禁止裸调用 `os.Open`、`os.OpenFile`、`os.ReadFile`、`os.Remove`、`os.RemoveAll`、`syscall.Flock`/`unix.Flock`、`windows.GetNamedSecurityInfo`/`SetNamedSecurityInfo`（`.golangci.yml:forbidigo` 强制）。常规文件读取统一使用 `fsx.OpenRegular` / `fsx.ReadAllBounded` / `fsx.OpenRegularUnbounded`；文件新建统一使用 `fsx.CreateExclusive`（Unix `O_CREAT|O_EXCL|O_NOFOLLOW` `0600`，Windows `CREATE_NEW` 创建即附带 Owner-Only SD，无“先建后加固”窗口）。
- **`INV-A2`（锁后必须验句柄同源）**：`fsx.OpenLocked` / `OpenLockedContext` 在获取 `flock` / `LockFileEx` 后，必须对已打开句柄 `Stat` 与路径 `Lstat` 执行 `os.SameFile` 校验，不一致则关闭重试（有界上限），且后续全部读写严格通过该句柄进行。
- **`INV-A3`（`SocketSlot` 单一所有权与固定释放序）**：控制套接字的 `Bind`、`ReplaceStale`、`Release` 全部在 `core/fsx/socket_slot.go` 的**同一把目录锁**（含 Windows 真实锁文件）内完成；`Release` 顺序固定为 `加目录锁 -> SameFile 校验 -> unlink -> 关闭 listener -> 释放目录锁`，确保活套接字永不被旧进程误删。
- **`INV-A4`（Windows 句柄级 DACL 与超长路径）**：`core/winsec` 所有安全描述符查询与写入均通过 `FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS` 句柄执行 `GetSecurityInfo`/`SetSecurityInfo` 并核验祖先重解析点；`OpenObjectHandleNoFollow`、`EnsureOwnerOnlyDirectory`、`GetFileAttributesNoFollow` 与 `core/mcp/transfer/journal_windows.go:replaceJournalFile` 在路径长度 `>= 248` UTF-16 码元时统一规范化为 `\\?\` / `\\?\UNC\...`。
- **`INV-A5`（零值 Limits/LockMode 失败关闭）**：`fsx.Limits{}`（`MaxBytes == 0`）与 `fsx.LockMode(0)` 必须直接返回 `fsx.ErrInvalidLimit` / `fsx.ErrInvalidLockMode`，绝不隐式放开字节上限或锁模式。

### INV-B：文件传输与路径安全不变量（`core/sftp`, `cmd/scp.go`, `cmd/sftpshell`）

- **`INV-B1`（单一类型化下载门面）**：外部包仅允许经 `(*sftp.Client).Download(ctx, RemotePath, LocalDest, DownloadOptions)` 下载。所有远端路径由 `sftp.ParseRemotePath` 构造，远端目录项名由 `sftp.ReadValidatedDir` / `(*Client).ReadDir`（`core/sftp/readdir.go`，全仓唯一允许直接调用 `*pkgsftp.Client.ReadDir` 的位置）经校验产出；传输代码中禁止对远端路径调用 `filepath.Base`（`.golangci.yml:forbidigo` 强制）。
- **`INV-B2`（符号链接下载策略 `(b)` 与折叠碰撞失败关闭）**：仅保留解析后严格留在 `localRoot` 内（`depth >= 0`）的相对 POSIX 符号链接；任何绝对目标、逃逸目标、链式软链逃逸、经 NFC/NFD + `cases.Fold`/`SimpleFold` 折叠后产生同级名称碰撞的软链，或 `os.ModeIrregular`（NTFS junction/FIFO/设备文件），均以 `sftp.ErrUnsafeDownloadSymlink` 失败关闭。
- **`INV-B3`（唯一本地组件校验与安全落盘）**：Windows 保留设备名（含 `COM¹–LPT³`）、NTFS ADS（`:$DATA`）、尾随点/空格与控制字符全仓唯一由 `core/fsx/validate.go:ValidateLocalComponent` 判定；下载临时文件以 `0600` 创建，权限位经 `.Perm()` 剥离 setuid/setgid/sticky，负大小 `Size() < 0` 一律返回 `sftp.ErrInvalidRemoteSize`。
- **`INV-B4`（精确目标上传与 `Lstat` 悬空软链覆盖检查）**：`cmd/scp.go` 与 `cmd/sftpshell/shell.go` 最多执行**一次**容器目录展开（`ParseRemoteUploadTarget`），随后以 `c.Lstat` 识别悬空远端软链执行 `--no-clobber`/覆盖确认，拒绝“文件覆盖已有目录/目录软链”，并调用 `(*sftp.Client).UploadExact` 防止 `core/sftp` 二次展开覆写深层同名文件。

### INV-C：SSH 连接池、多路复用、信道与主机密钥不变量（`core/ssh`, `internal/sshenv`）

- **`INV-C1`（`ClientConfig` 构造门控与全字段 Merkle 摘要）**：全仓非测试代码只能经 `core/ssh/types_api.go:NewClientConfig` 构造 `ClientConfig`（`TestP7_ClientConfigConstructedViaNewClientConfigOnly` 强制），且 `DigestClientConfig` 原始输入结果必须与 `NewClientConfig` 完全等价。`ClientConfig`、`Options`、`ControlConfig` 的每个字段必须显式标注 `digest:"include"` 或 `digest:"exclude,reason=..."`（`TestHopDigest_StructTagCompleteness` 强制）；每跳 `HopDigest` 递归纳入父跳摘要，确保任意上游变动必然刷新下游缓存键。
- **`INV-C2`（父代 CAS 发布、独立 Keepalive 与同步摘除）**：`connPool.Publish(key, next, expectParent)` 在同一把锁内校验 `next.parent` 为当前活跃代，拒绝陈旧拨号毒化池；被替换连接进入 `retired` 由 `CloseAll` 清理；keepalive 归 `PooledClient` 独有并随 retire/close 终止；`(*Client).Close()` / `Interrupt()` 同步摘除池索引并触发 `triggerEvictHook` 关闭关联 `MuxServer`。多跳复用前必须通过 `probeCachedIntermediateHops` 与 `SnapshotChain` 校验所有中间跳存活。
- **`INV-C3`（`proxyChanConn` 有界关闭与无 AB-BA 死锁升级）**：`proxyChanConn.Close` 最多等待 `90ms`（`defaultProxyChanCloseGrace`）后通过 `detachAndAbortRoot` 升级拆断卡死跳板根连接；活跃子孙通过从 `p.active` 删除认领，已退役子孙通过原子 `retiredAborted.CompareAndSwap(false, true)` 单赢者认领，且 `closeBatchDescendantsSkipping` 跳过 `child.hopConn.isClosing() == true` 的节点（同时仍触发 `stopKeepAlive` 与 `triggerEvictHook`），消除相互 `closeOnce.Do` 死锁且不误伤健康跳板。
- **`INV-C4`（`MuxServer` 优雅关闭与有界出站）**：`(*MuxServer).Shutdown` 固定按 `beforeTransportClose -> 释放 SocketSlot -> evictFromPool -> closeTransportBounded -> drainTrackedStreams` 执行；`MUX_C_PROXY` 包装 `physicalSSHConn`/`sshActivityConn`；Agent 转发使用引用计数 `agentForwardEpoch`；所有出站 `CloseWrite`/`Close`/`Reply` 与入站 pump 排空隔离并有界超时。
- **`INV-C5`（单一加锁 `O_NOFOLLOW` `knownHostsDB` 快照）**：`(*Connector).getHostKeyOptionsWithState` 在 `HostKeyCallback` 与 `HostKeyAlgorithms` 间复用同一个在 `knownHostsFileMutex` + `fsx.OpenLocked(..., LockShared, false, 0)` 下构建的 `*knownHostsDB` 快照（含 `StrictHostKeyChecking=no`）；自定义 `UserKnownHostsFile` 直接经 `OpenLocked` 打开（跳过 `os.ErrNotExist`，拒绝软链/目录/特殊文件），绝不对用户 `known_hosts` 使用 `FollowSymlinks()` 或 Windows 系统 SSH ACL 检查器。
- **`INV-C6`（未连接客户端零 Panic 与执行语义边界）**：`*Client`、`*PooledClient`、`SSHProxyDialer`、`getOrCreateAgentRouter` 等全部入口在 `Client == nil || Client.Conn == nil` 或 `ctx == nil` 时返回错误而不 panic；远程命令严格区分 `ExecutionNotStarted` / `ExecutionCompleted` / `ExecutionUnknown`，未知结果绝不自动重试；`*OutputError` 在终止路径去重不重复包装。

### INV-D：选项代数、来源分类与全平面一致求解不变量（`core/ssh`, `pkg/adapter`, `cmd/ssh*`）

- **`INV-D1`（唯一选项解析器与三态幺半群代数）**：CLI `-o`、OpenSSH 配置与 YAML 统一经 `core/ssh/option_parser.go:ParseOption` 解析；`PathList`（`Unset | Disabled | Set`）、`AlgoPolicy`（解析期即拒绝裸 `+`/`-`/`^` 与非法修饰符）、双槽 `ProxySetting`（`ProxyJump` 与 `ProxyCommand` 跨层遮蔽语义）与 `ControlSetting` 的 `Merge` 严格满足结合律、单位元与吸收律（由表驱动及 Fuzz 代数律测试保障）。`IdentityFile=none` 表达为 `PathList.IsDisabled()`，禁止退回默认 `~/.ssh/id_*` 或将 `password` 节点误升格为 `auto`。
- **`INV-D2`（显式 `NodeProvenance` 不可降格/越权重写）**：`pkg/config/provenance.go:NodeProvenance` 将连接严格划分为 `ProvenanceSavedManaged`、`ProvenanceOpenSSHVirtual`、`ProvenanceOpenSSHDerived` 与 `ProvenanceAdHocPending`：
  - 仅真正源自 OpenSSH `Host` 配置块的派生连接（`IsOpenSSHNodeID(baseNodeID)` + 非空 `OpenSSHAlias` + `SSHOptions == nil`）可为 `ProvenanceOpenSSHDerived`；
  - 从已保存节点经 `-l`/`-p`/`-o HostName`/`CanonicalizeHostname`/`NodeOpenSSHOrigin` 派生的未持久化会话，以及原始 `user@ip` 临时连接，**必须保持 `ProvenanceAdHocPending`**，在拨号、`-f` 预检、`-O` 控制面与 `ControlPersist` 后台守护移交（`cmd/ssh.go` + `cmd/mux_daemon_spec.go`）中**均禁止重写为 `"openssh:..."`**，始终执行 `filterNonVirtualTier4Options` 与 `(Host, Port)` 端点作用域裁剪。
- **`INV-D3`（四平面 `SessionAuth` 与策略求解一致）**：`(*SSHAdapter).Resolve` 为唯一四层策略出口（`Tier 1 CLI > Tier 2 Saved Node > Tier 3 Global > Tier 4 OpenSSH`）；`SessionAuth.{HostName,User,Port,ProxyJump,OriginalHost,CanonicalHost}` 在拨号、`-f` 预检（`buildProxyCommandPathChecker`）、`-O` 控制面（`check`/`exit`/`stop`/`forward`/`cancel`/`proxy`）及 `ControlPersist` 移交间保持一致；当 `CanonicalizeHostname` 触发且存在活跃 CLI `-o HostName` 时，`applyHostnameCanonicalization` 原地规范化 `o.cliHostName`/`o.HostName` 并保留 `OriginalHost`（`%n` 不变、`%h` 为规范主机名）。
- **`INV-D4`（正反向别名与白名单编码）**：`Node.Alias` 与 `Host.Alias` 在正向解析与反向回调（`BatchMode`、`Remember`、`UpdateAuth`、`DisableSessionControlSharing`、`OTP`/`ChallengeRule`）保持一致；`SendEnv -PATTERN` 在合并期移除已加入模式；`RemoteCommand`/`ProxyCommand`/`LocalCommand` 共用统一白名单 token 编码器。

### INV-E：失败关闭安全判定与 MCP 授权/护栏不变量（`core/verdict`, `core/mcp/**`, `internal/mcphost`）

- **`INV-E1`（零值即拒绝、错误即拒绝）**：`core/verdict.Verdict` 零值为 `Deny`（`0`），`verdict.Decide` 将任意非 nil 错误折叠为 `Deny`。全仓安全/策略谓词禁止以裸 `bool` 吞掉局部错误（`TestP7_SecurityPredicateAnalyzer_ZeroBareBoolErrSwallow` 强制）；`suspend_unix.go` 完整实现 POSIX 孤儿进程组谓词且任何 `Getsid`/`Getpgid` 失败均返回 `Deny`。
- **`INV-E2`（Tier-4 端点作用域强类型）**：Tier-4 匹配与回退键构造一律使用 `ssh.Endpoint`（规范化主机与 `[1..65535]` 端口，零值 `IsValid() == false` 且 `Equal == false`），禁止脱离端口仅按主机地址比对。
- **`INV-E3`（MCP 策略确定性与路径保护）**：`core/mcp/guardrail/glob.go:matchGuardrailGlob` 采用 OS 无关 $O(|P|\cdot|S|)$ UTF-8 rune 匹配（`*`/`?` 跨 `/`/`\`/`\n`）；`NodeOverrides` 遍历全部命中项取最严 `RiskLevel`（`min`），消除 Go map 迭代随机性；`ProtectedPaths` 先执行 POSIX 字面反斜杠保真匹配，再与 Win32 驱动器/扩展设备（`\\?\`、`\\.\`、`\??\`、`GLOBALROOT`、UNC、回环管理共享、ADS、尾随点空格）规范化结果取逻辑或；`WithGuardrail` 与 `Authorize` 的 `switch decision` 必须具备显式 fail-closed `default: return`。
- **`INV-E4`（MCP 执行绑定与 POSIX Bourne 强校验）**：`internal/mcphost` 的 `ProbeExecution`、`Run`、`OpenPTY` 及文件/传输操作全部校验 `permit.Binding().Validate(view)` 并经 `connectPlan` 在准入冻结的 `providerKey{}` 快照上拨号；`gui` 工具纳入 `prepareAndResolveExecution` 探测与 `{Input, Execution, PlanDigest}` 绑定；`RequirePOSIX` 与 `Filesystem` 在 `sshexec.Backend.Run` 与 `mcphost.backend.Run` 中统一以 `ports.ValidatePOSIXBournePlan` 校验有效解释器为 POSIX Bourne（`server+LaunchPOSIX` 或非 `LaunchUnknown` 下的 `sh`/`bash`/`zsh`），绝不仅检查 `LaunchDialect`。
- **`INV-E5`（MCP 双阶段路径规范化、信封防重放与零孤儿审计）**：
  - `file`（`read`/`write`/`patch`/`stat`）与 stdio `transfer`（`push`/`pull`）采用两阶段“词法预检 → `ports.Inspect` 规范化 → 规范范围授权 → `ports.Execute` 二次校验并钉死规范源与精确目标（`UploadExact` / `LocalDestFromTarget`）”管线，并对目录递归传输计算 `RecursivePaths` 后代保护路径；
  - 两步审批挑战 `pendingApproval` 绑定预检请求信封（`WithRequestEnvelope`：`ToolName`/`Action`/`NodeID`/`Scope`/`SnapshotDigest`/原始输入/策略），跨会话/跨工具/跨节点/跨路径令牌及拒绝/畸形 `InputResponses` 均在拨号 SSH 前拒绝并审计 `"denied"`；Round-2 探测失败立即 `InvalidatePendingApproval` 杜绝 SFTP 错误预言机；
  - `canonicalScopeEscalated` 在风险升格、策略收紧、非保护转保护及 `Protected-A -> Protected-B` 软链重定向（`diffScopePaths` 命中 `HasProtectedPath`）时强制重提示并撤销旧令牌；所有已写 `"authorized"` 的 `opID` 在成功、失败、升级或准入失败时均必须写入终态 `"executed"` / `"error"`，杜绝孤儿审计记录；
  - `requestToolApproval` 在 `< 2026-07-28` 与 `applyFallback` 分支前同样校验/消费携带的 `RequestState`/`InputResponses`；
  - HTTP `transfer`（`status`/`cancel`）与 stdio `tunnel`（`status`/`stop`，通过只读不触发 prune 的 `Manager.Inspect`）必须完整通过 `r.resolve -> guardrail.Authorize -> r.enter` 后才可暴露 `not_found` 或执行变更，并统一使用 `RecordAuthorizedContext` 保留 `AuditEntry.Binding`。

### INV-F：配置持久化图、租约与凭据原子性不变量（`pkg/config`, `pkg/credential`, `cmd/host`, `pkg/tui`）

- **`INV-F1`（写入与加载双端全图校验）**：`pkg/config.Repository` 加载与每次事务提交（含 `NewRepository`、`ImportOpenSSHHostsContext`、`cmd/init`、`host add/edit/load`、TUI、pending 确认与 `doctor --fix`）均强制执行 `ValidateGraph` 与 `ValidateSavedNodeJumpCycleWithOpenSSH`：
  - 拒绝任何已保存节点与 OpenSSH 跨命名空间 `ProxyJump` 环路；
  - 统一 `ValidateNodeAlias`（拒绝 `@`、`:`、控制字符、大小写不敏感 `openssh:` 前缀）；
  - 强制 `PassphraseRef != nil => KeyFingerprint != ""`，并对任意非空 `KeyFingerprint` 无条件拒绝非法控制/空白字符；
  - 在 Schema v2（`SchemaVersion >= 2`）或存在已配置存储时，对全部 5 处凭据引用字段（`Identity.LoginPasswordRef`、`Identity.PassphraseRef`、`Identity.OTP.TOTPSecretRef`、`ChallengeRule.SecretRef`、`Node.PrivilegePasswordRef`）强制校验 `StoreID` 存在于 `cfg.Credential.Stores`；
  - 非规范 `xops_config.yaml` 加载即 fail-closed 报错，修复唯一通过加锁 CAS 的 `xops config doctor --fix` 完成。
- **`INV-F2`（拨号前不落盘与作用域 Pending 租约）**：`cmd/{ssh,scp,exec,sftp}` 禁止拨号前写回已保存节点；会话级未持久化变更全部通过 `WithPendingNode(ctx, req, func(PendingLease) error)` 隔离，回调返回（含错误/取消/panic）未 `Confirm` 即自动清理，跨 unrelated commit 保留 `entry.isUpdate`；`FinalizePendingConnection` 在全部成功路径（新握手、池复用、ControlMaster 复用）统一确认。
- **`INV-F3`（Vault 先写后提交与 5 位置引用计数回收）**：新建带密文的主机/身份（`NodeCredentialCreate`、`IdentityCredentialCreate`）必须先写入并常量时间回读验证 Vault，再经 CAS 原子提交 `config.yaml`（Vault 锁定或失败时零悬空引用，提交失败仅补偿删除本次新建引用）；跨类型凭据切换与删除全部包裹在 `credential.Service.DeleteAssets` 中，经重新读盘的 `CheckRefUnreferenced` / `ConfigurationReferencesCredentialStore` 确认 5 处全无引用后才删除 Vault 资产；`Applied=true, Durable=false`（`DurabilityError`）严禁重试或删除任一凭据。
- **`INV-F4`（混合认证保留、别名主机隔离与模板不可变）**：`config.IsHybridAuthType`（`auto`/`otp`/`keyboard-interactive`）在密码/密钥更新、pending 确认、TUI 表单与 `host import` 预检（`verificationBundle`）中均保留混合 `AuthType` 及另一类凭据字段；`AllocateNodeHostRef` 与 `ensureMatchingHost` 绝不跨独立主机复写或劫持带 `Host.Alias` 的 `Host` 记录（共享 `HostRef` 分叉时清空 `host.Alias = nil`）；`xops host add/edit --identity/-I` 拒绝空模板名及与 `--user`/`--key`/内联 `user@` 混用，且 `host add -I` 直走 `CreateNodeContext` 绝不篡改复用模板或删除其 Vault 密文；`PrivateKeyFingerprint` 与 `cred set --passphrase` 经 `ssh.ParseIdentityPathSetting` 拒绝 `"none"`、`%` 模板、`${ENV}` 及未展开 `~user`。

### INV-G：编译期、Lint 与自动化防漂移护栏矩阵

| 防护层级 | 精确位置 / 命令 | 防止哪类架构漂移 |
| :--- | :--- | :--- |
| **静态封禁 (`forbidigo`)** | `.golangci.yml:24-38` | 禁止在 `core/fsx` 外裸用 `os.Open`/`OpenFile`/`ReadFile`/`Remove`/`RemoveAll`、`Flock`、`Get/SetNamedSecurityInfo`，禁止在传输代码对远端路径用 `filepath.Base`；全仓三平台 `0 issues`，合法例外受 43 处人工基线约束。 |
| **依赖边界 (`depguard` + 抽离测试)** | `.golangci.yml:39-50`、`scripts/check_core.py --race`、`scripts/test_check_core.py` | 强制 `core/**` 零 import `cmd/**`/`pkg/**`/`internal/**`，并抽离为独立 Go module 执行 `-race` 构建测试。 |
| **AST 构造与谓词守卫** | `internal/clicontract/p7_clientconfig_guard_test.go`、`p7_security_predicate_analyzer_test.go`、`p6_architecture_guards_test.go`、`p4_architecture_guards_test.go` | 全仓禁止绕过 `NewClientConfig` 构造 `ClientConfig`；全仓禁止安全谓词以裸 `bool` 吞错；强制 Guardrail `switch decision` 具备 fail-closed `default`；强制 `mcphost` 独占 `ConnectPlan`、禁止环境变量子进程认证读取、强校验选项表与文档一致性。 |
| **反射完备性与零值表** | `core/ssh/hop_digest_test.go:TestHopDigest_StructTagCompleteness` / `TestHopDigest_CoversEveryRegisteredOptionSpec`、`internal/clicontract/p7_zero_value_reflection_test.go` | 新增字段漏标 `digest` tag 或任意 14 个安全类型零值偏离最严 fail-closed 状态时 CI 必然失败。 |
| **代数律、Fuzz 与模型并发** | `core/ssh/{path_list,algo_policy,proxy_setting}_test.go`、28 个 `Fuzz*` 目标、`core/ssh/pool_model_test.go`、`core/fsx/socket_slot_test.go` | 覆盖幺半群结合律/单位元/吸收律、解析往返一致性、以及连接池/`SocketSlot`/SFTP `-race -count=50` 并发不变量。 |
| **双语文档与契约检查** | `npm run docs:check`（`scripts/docs/check-locales.mjs`） | 保证 `docs/{guide,reference,troubleshooting,development}` 与 `docs/en/...` 路径与契约严格同步。 |

---

## 3. 已修正的隐式契约对照表（Implicit -> Explicit）

下表记录 P7（W0–W19）中最容易引发跨层回归的隐式假设及其已落地的显式契约：

| 隐式假设（旧代码陷阱） | 真实失效 / 安全绕过后果 | 已修正的显式契约（源码位置） |
| :--- | :--- | :--- |
| **“路径先 `Stat`/`Lstat` 再 `Open`/`Remove` 是安全的”** | FIFO 阻塞、符号链接替换、Windows 重解析点绕过与误删活跃控制套接字（H7/H8/H9/MED-9） | 全部收口至 `core/fsx` 句柄原语（`OpenRegular`、`CreateExclusive`、`OpenLocked` `SameFile` 重试、`SocketSlot` 目录锁） |
| **“配置/参数中 `""` 与 `"none"` 可共用 `string` 语义”** | `IdentityFile=none` 回退默认密钥、密码节点被误推为 `auto`、多层合并丧失结合律（H3/MED-7） | `core/ssh/{path_list,proxy_setting,algo_policy,control_setting}.go` 显式三态与双槽代数类型 |
| **“安全判定出错时返回 `false` 或跳过即可”** | `if err == nil && ...` 将错误静默转成放行（`suspend_unix`、算法修饰符、空 CLI 选择器，MED-6/10/11） | `core/verdict.Verdict`（`Deny == 0`）+ `secpred` AST 守卫全仓零裸 `bool` 吞错 |
| **“OpenSSH `Host` 仅按主机地址就能判定归属”** | 同主机不同端口的 Tier-4 配置串用（H4）；已保存节点带 `-l`/`-p` 或规范化被误判为 `ProvenanceOpenSSHDerived` 从而执行未授信 `ProxyCommand`（`L3-18-H1`、`L3-19-H1`） | `core/ssh.Endpoint`（规范化 `(Host, Port)`）+ `pkg/config.NodeProvenance` 贯通拨号、`-f`、`-O` 与 `ControlPersist` 移交四平面 |
| **“`!isSaved && OpenSSHAlias != ""` 等价于 OpenSSH 来源”** | `ControlPersist` 移交把已保存/已保存派生节点重写为 `"openssh:..."`，丢失 Vault 凭据与 Tier-2 策略并放开 Tier-4（`L3-19-H1`） | `cmd/ssh.go:isOpenSSHProvenance` 与 `cmd/mux_daemon_spec.go:resolveMuxDaemonTargetForSpec` 严格依据 `ConnectionSnapshot.Provenance` 决策 |
| **“多跳连接池按 `nodeID + 单跳摘要` 缓存即足够”** | 上游跳板变更导致下游连接误复用、迟到旧代拨号毒化池、覆盖连接泄漏与 keepalive 误杀（H5/H6/MED-1/C16-H1） | Merkle `HopDigest` + 94 个反射 `digest` tag + 父代 CAS `Publish` + `PooledClient` 独有 keepalive + 非重入 `detachAndAbortRoot` |
| **“读 `known_hosts` 排序算法可直接复用全局读辅助函数”** | 用户 `known_hosts` 被无锁 + `FollowSymlinks()` 重读，在 Windows 触发强制锁 `ERROR_LOCK_VIOLATION` 或系统 ACL 误拒并引发 `ErrHostKeyMismatch`（`C18-M1`） | `core/ssh/host_algorithms.go:getHostKeyOptionsWithState` 在 `HostKeyCallback` 与 `HostKeyAlgorithms` 间共享单一加锁 `O_NOFOLLOW` `*knownHostsDB` |
| **“SFTP 路径检查交给调用方，容器展开每层各做一次无害”** | 绕过安全下载门面（H2）、悬空软链绕过 `--no-clobber`（`AB17-M3`）、三层 `ParseRemoteUploadTarget` 覆写同名子目录内文件（`AB18-M3`） | 唯一导出 `Download` + `ReadValidatedDir` + `UploadExact`；调用方最多展开一次并以 `Lstat` 校验悬空软链 |
| **“MCP 只需按词法路径或仅查 `LaunchDialect` 即可授权/执行”** | `filepath.Match` 受 OS 分隔符绕过（`AB16-H1`）；`gui` 在默认/OpenSSH Linux 节点 100% 失败且未校验 POSIX Bourne 解释器（`AB18-H1`）；软链与祖先目录绕过 `ProtectedPaths`（`AB18-M1`）；同会话挑战令牌跨节点重放与双提示/孤儿审计（`AB19-M1`/`L1`） | `matchGuardrailGlob` + 最严 `NodeOverrides` + `ports.ValidatePOSIXBournePlan` + 双阶段规范化/`WithRequestEnvelope`/`diffScopePaths` 重提示/零孤儿审计 + `UploadExact`/`LocalDestExact` 源与目标双钉死 |
| **“未存在的 transfer/tunnel ID 可在鉴权前直接返回 `not_found`”** | 绕过 Guardrail 策略拒绝/审批/审计并暴露任务存在性预言机（`AB17-M1`、`AB18-M2`） | `tool_transfer.go:authorizeTransferTask` 与 `tool_tunnel.go:authorizeTunnelTask` 先过 `r.resolve -> Authorize -> r.enter`，再暴露 `not_found` |
| **“CLI 参数校验可分散在命令层，创建凭据可先改 YAML 再写 Vault”** | 环路/坏引用落盘（MED-5）、Vault 锁定留下悬空引用（`L4-17-M3`）、`host add -I --key` 就地覆写复用模板并删光 Vault 密文（`L4-18-M1`） | `Repository` 双端 `ValidateGraph` + `NodeCredentialCreate`/`IdentityCredentialCreate` Vault 先写后提交 + `host add/edit -I` 互斥与直走 `CreateNodeContext` |
| **“CLI `-o HostName` 规范化后只需更新 `o.Host`”** | `o.effectiveHostName()` 随后用未规范化的 `o.cliHostName` 覆写回短主机名，破坏拨号与 `%h`（`L3-19-M2`） | `cmd/ssh.go:applyHostnameCanonicalization` 与 `probeTargetBackgroundSession` 原地回写活跃 `o.cliHostName`/`o.HostName` |

---

## 4. 剩余风险与诚实边界（Residual Risks & Honest Boundaries）

1. **跨平台原生运行时边界（高关注，交由 CI 原生 Runner 兜底）**  
   P7 在本机 Linux 原生环境已通过全部 `-race -shuffle=on`（47/47 包）、`check_core.py --race`、模型并发 `-count=50` 及 28/28 Fuzz（`98,047,092` 次执行），并在本机完成 `windows/amd64` 与 `darwin/amd64` 交叉编译（含测试二进制编译）和全仓三平台 `golangci-lint`（`0 issues`）。但 **Windows 原生 `CreateFile` / `LockFileEx` / Owner-Only DACL / `\\?\` 超长路径 / AF_UNIX 对端令牌** 以及 **macOS 原生 `kqueue` / `ForkLock` / Unix 套接字** 的运行时行为，必须以 GitHub Actions 原生 Windows/macOS runner 结果为最终验收依据（严禁将交叉编译等同于原生通过）。
2. **OpenSSH 语义差分覆盖边界**  
   选项合并与解析一致性由现有 `ssh -G` 差分套件和 `OptionSpec` 注册表覆盖；尚未纳入差分矩阵的冷门 OpenSSH 选项或新版本 OpenSSH 扩展语法仍需随特性演进补充差分用例。
3. **`//nolint` 例外人工审查基线**  
   截至 `e957386`，全仓生产代码共有 **`43` 处 `//nolint:forbidigo`**（集中于 `os.DevNull` 重定向、`/proc/self/fd` 与 TTY/PTY 字符设备、已校验随机临时文件/备份/journal 清理、以及 `internal/credentialfile`/`internal/vaultsys` 独立 dirfd 保险库内核）和 **`2` 处 `//nolint:secpred`**（`core/ssh/host_algorithms.go:453` 满足 `x/crypto/ssh.CertChecker.IsHostAuthority` 回调签名、`cmd/utils/exclude.go:967` 纯 `ParseAddr` 语法判定）。任何新增 `//nolint:forbidigo` 或 `//nolint:secpred` 均视为高风险架构例外，必须附具明确理由并经人工评审。
4. **已知低风险（`Low`）残余边缘项（0 High / 0 Medium）**
   - **`L3-20-L1`（`xops exec` / `xops scp` 下 `CanonicalizeHostname` + `-o HostName` 一致性）**：`cmd/exec.go`（`resolveExecHostTargetWithHint` / `buildTaskSessionAuth`）与 `cmd/scp.go`（`canonicalizePathInfo` / `appendScpSessionAuthOverrides`）在同时启用 `CanonicalizeHostname` 与活跃 CLI `-o HostName=<short>` 时，尚未像 `cmd/ssh.go:applyHostnameCanonicalization` 一样原地回写 `SessionAuth.HostName`，仅影响该组合下 `exec`/`scp` 与 `ssh -M` 间的 `%h` ControlPath 复用，无安全绕过。
   - **`L3-20-L2`（规范化 `ProvenanceOpenSSHDerived` 的 `ControlPersist` 移交保守复核）**：`cmd/ssh.go:checkOwnedMaster` / `hasActiveProxyCommandForMaster` 在复核规范化 `"openssh:<canon>"` 时未携带 Pass-1 `OriginalHost`；若 Pass-1 `Host <short>` 用 `ProxyCommand none` 遮蔽了 `Host *` 的 `ProxyCommand`，单遍复核会保守跳过后台驻留守护（严格 fail-closed，无未授信执行风险）。

---

## 5. 防架构漂移评审与验证清单

任何后续触及 `core/`、`pkg/config`、`pkg/adapter`、`internal/mcphost` 或 `cmd/{ssh*,scp,sftp*,host,config}` 的变更，提交前必须核对：

1. **禁止恢复已删除模式**：不得重新导出 `DownloadFile`/`DownloadDirectory`、`Prepare/Confirm/DiscardNodeContext`、`SameHostAddress`、`MergeOptionLayers` 等 §1.1 清单中的旧符号或等价旁路。
2. **新增字段同步标签与零值**：给 `ClientConfig`、`Options`、`ControlConfig` 或安全配置结构体加字段时，必须补 `digest` tag 并在 `p7_zero_value_reflection_test.go` 保持零值最严。
3. **来源与路径严禁字符串猜测**：不得用 `!isSaved`、`HasPrefix("openssh:")` 或裸 `filepath.Base` 替代 `NodeProvenance`、`TargetRef`、`RemotePath`、`Endpoint`。
4. **安全判定禁裸 `bool` 吞错**：返回 `(verdict.Verdict, error)` 或 `(..., error)`，不以 `//nolint:secpred` 规避真实错误传播。
5. **不变量留在写入与准入边界**：配置图规则进入 `ValidateGraph`；MCP 工具所有动作均须经过 `resolve -> Authorize -> enter -> RecordAuthorizedContext`。
6. **合并前必跑门禁**：
   ```sh
   go build ./...
   GOOS=windows GOARCH=amd64 go build ./... && GOOS=darwin GOARCH=amd64 go build ./...
   golangci-lint run --allow-parallel-runners --max-issues-per-linter=0 --max-same-issues=0 ./...
   GOOS=windows GOARCH=amd64 golangci-lint run --allow-parallel-runners --max-issues-per-linter=0 --max-same-issues=0 ./...
   GOOS=darwin GOARCH=amd64 golangci-lint run --allow-parallel-runners --max-issues-per-linter=0 --max-same-issues=0 ./...
   python3 -m unittest discover -s scripts -p test_check_core.py
   python3 scripts/check_core.py --race
   go test -race -shuffle=on -count=1 ./...
   npm run docs:check
   ```
