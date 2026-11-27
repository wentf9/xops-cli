# XOps v2 AI 协作与工程宪法（AGENTS.md）

> **当前工程态**：XOps v2 正式生产工程宪法（**v2.3.3 架构定型终稿**，Phase 0–5 全量 Clean-Room 架构已完整落地，持续演进恪守零历史兼容、编译期证明与强边界隔离）。  
> **架构基线与演进参考**：[docs/development/v2-architecture-rfc.md](docs/development/v2-architecture-rfc.md)（ADR-001 – ADR-016）与 [docs/development/v2-implementation-plan.md](docs/development/v2-implementation-plan.md)（Phase 0–5 含 Phase 2.5 Walking Skeleton，Gate G0/G0-R – G5）。

---

## 0. 最高工作准则

- **零 v1 历史兼容、严禁打补丁**：永久禁止在 XOps v2 代码库中引入任何 v1 兼容垫片、v1 迁移/读取代码、旧 API facade 或新旧双轨桥接（外部格式接入统一经 `ports.FormatImporter` / `inventory.ImportBundle` 扩展入口，100% 零 v1 代码）。仓库早期历史提交仅作客观领域规则只读参考，**禁止回流或拷贝旧架构结构**。
- **显式大于隐式、类型即证明**：严禁依赖注释、命名习惯或调用方自律维持安全/并发不变量；一切核心约束必须编码进 **Go 模块与包边界、私有构造器、封闭和类型、作用域闭包或自建编译器护栏 `tools/xopsvet`**。
- **事实核验铁律**：禁止凭名称猜测模块职责、编造符号、或宣称未执行的命令通过；关键引用须附 `路径:符号`（必要时附行号），无法确认时写「待验证」。
- **只读与编码边界**：调查、审查或文档任务默认只读，不修改源码/配置；启动任何编码或变更任务前，先明确目标模块/包、受影响的架构不变量、预期门禁与验证命令，并全量过闸验证（严禁跳过门禁或带病推进）。

---

## 1. 三模块物理隔离与单向依赖法则（ADR-001 – ADR-003, ADR-007, ADR-009）

仓库采用 **Go 1.27+ Multi-Module Workspace**（全仓 3 个 `go.mod` **严禁长期 `replace`**；开发与分支 CI 期对 `core/` 与 `tools/xopsvet/` 强制 `GOWORK=off` 独立验证，根 CLI 模块经 `go.work` 联合验证；遵循 Go Module SIV，`core/go.mod` 保持 `github.com/wentf9/xops-cli/core` 无 `/v2` 后缀，发布演进遵循 **`core/v1.0.0`** 及后续 `core/v1.x.y` Tag 锁定版本并执行三模块全量 `GOWORK=off` 验收）：

1. **`tools/xopsvet/`**（`tools/xopsvet/go.mod`）：独立自建静态分析器模块，隔离 `golang.org/x/tools` 依赖（双层混合 IR：AST/`inspect` ∥ `internal/vetssa` + 前置 `internal/secretfact` + 9 大正交分析器）。
2. **`core/`**（`core/go.mod`）：完全无宿主假设的六边形核心（供 `xops-cli` 与外部 `xops-mcp` 等宿主共同复用）。
   - **仅允许公开 6 个极简契约包**：`core/domain/...`、`core/ports`（含 `ScopedRootFS`、`OperatorReadFS`、`FormatImporter`、`core/ports/tck`）、`core/events`、`core/osfs`、**`core/conc`**（仅含零依赖 `Nursery` + `CtxMutex`，全仓唯一裸 `go` 白名单）、`core/engine`。
   - **100% 物理封锁于 `core/internal/`**：`foundation/{actor,trace}`（其中 `actor` 含 0 裸 `go` 纯内存 `actor.DualActor`，`trace` 纯内存非 I/O + 显式 `io.Reader` 熵注入）、`pool`、`gate`（独占定义 `Authorized[C]`）、`usecase/*`、`mcpruntime`（含 `protocol`/`tools`）、`sshnet/*`、`sim`。外部宿主与 CLI 均不得可见。
3. **根 CLI 模块**（根 `go.mod`）：
   - `internal/host/{store,openssh,vault,sys,audit}`：本机出站基础设施适配器，实现 `core/ports`。其中 `internal/host/vault` 按子包物理隔离为 `internal/host/vault/{offline,wincred,keychain,secretservice,helper}`（使 FFI/`unsafe` 后端的 `unsafe.Slice`/`uintptr->unsafe.Pointer` 永不触发 `vault/offline` Argon2id + XChaCha20-Poly1305 AEAD dirfd 的 `hasUnsafeVaultForge`），`internal/host/sys` 按子包隔离系统适配（含 `{agent,interact,sshfp,tun}`）；根 CLI `go.mod` 在 `CGO_ENABLED=0` 下批准引入纯 Go 系统适配依赖 `github.com/ebitengine/purego`（macOS `Security.framework`）与 `github.com/godbus/dbus/v5`（Linux Secret Service），所有句柄与符号地址必须存放于适配器结构体字段（0 `init()`、0 包级 `var`）。
   - `internal/entry/`：极薄入站驱动适配器，零业务逻辑：
     - **6 子包 CLI 命令族** `internal/entry/cli`（根调度器与 `BuildInfo`）、`internal/entry/cli/clikit`（退出码、全局参数、规范 JSON/v2 信封与窄接口底座）、`internal/entry/cli/cmdssh`（`ssh`/`exec`/`tunnel`/`mux`）、`internal/entry/cli/cmdtransfer`（`scp`/`sftp`）、`internal/entry/cli/cmdasset`（`hosts`/`creds`/`vault`/`config`）、`internal/entry/cli/cmdops`（`playbook`/`doctor`/`audit`/`mcp`/`tui`）；
     - **4 大独立交互与守护入口** `internal/entry/tui`（Bubble Tea v2 实时工作台）、`internal/entry/sftpshell`（交互式 SFTP Shell）、`internal/entry/mcpcmd`（MCP stdio / Streamable HTTP 宿主驱动）、`internal/entry/muxdaemon`（ControlMaster / ControlPersist 守护驱动）。
   - `cmd/xops`：全仓唯一完整组合根，零 `init()`、零全局单例（链接期只读构建元信息经 `-X 'main.buildVersion/buildCommit/buildTime'` + 六重门控 `//xops:buildvar` 接收并转为显式 `BuildInfo` 注入 `entry/cli`），统一按运行模式装配真实宿主适配器（CLI 模式注入 `ScopedRootFS` + `OperatorReadFS` + 终端/交互钩子；MCP 模式物理强制 `OperatorReadFS == nil` / `Interaction == nil` / `Terminal == nil`），退出时经逆序停机栈按 `Entry -> Engine/UseCases -> Pool -> Vault -> Store -> Audit -> Sys/Relay` 严格逆序关闭。

### 绝对禁止与受控的依赖方向（由 Go 模块与 `xopsvet/archbound` 机器强制）

- `core/domain/**`：**100% 纯函数数学核**（白名单：29 纯 stdlib + 官方纯数学包 `golang.org/x/text/unicode/norm`；子包独占：`core/domain/option` 放行 `"crypto/sha1"` 供 OpenSSH `%C`，`core/domain/secret` 放行 `"runtime/secret"` 供 `goexperiment.runtimesecret`），严禁导入 `context`、`os`、`net`、`os/exec`、`syscall`、`sync`、**`sync/atomic`**、`reflect`、`time.Now`、`math/rand`、`core/ports`、`core/events`、`core/osfs`、`core/conc`、`core/internal`；`core/domain/**` 测试源码同样物理禁止 `os`/`net`/`os/exec`/`sync`/`core/conc`/`sim`/`goleak`。
- `core/ports/**`（非 `tck`）：仅可依赖 `core/domain/**`；严禁依赖 `core/internal/**`、`core/osfs`、`core/conc` 或具体实现库（如 `golang.org/x/crypto/ssh`、`github.com/pkg/sftp`）。`core/ports/tck` 为测试契约夹具层（允许 `core/conc` 与 `goleak`，**0 生产可达**）。
- `core/osfs`：独占常规文件 OS 句柄、旁路锁、ACL、`os.Root`、本地 `AF_UNIX` `SocketSlot`/`ProbeStaleUnixSocket`/`DialUnixVerified` 及受验 Windows Named Pipe 客户端拨号 **`DialWindowsNamedPipeVerified(ctx, pipePath) (net.Conn, error)`**（强制 `OPEN_EXISTING`、`FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`、`FILE_TYPE_PIPE` 校验、`GetSecurityInfo(SE_KERNEL_OBJECT, OWNER|DACL)` + `WindowsACLPipeServerSafe` 阻断非受信任主体 `FILE_CREATE_PIPE_INSTANCE=0x04 | WRITE_DAC | WRITE_OWNER | GENERIC_ALL | GENERIC_WRITE` 同时放行 `LocalSystem` `openssh-ssh-agent` 的合法双工 `FILE_WRITE_DATA`，对 `archbound/osfs_net.go` 与 `core/ports` 零改动）；严禁导入 `net/*` 子包与 `os/exec`；允许导入 `"net"` 仅用于本地 `AF_UNIX` `SocketSlot`/`ProbeStaleUnixSocket` 与上述本地 Named Pipe `net.Conn` 契约，并由 `archbound/osfs_net.go` 实施**四道 fail-closed 符号防线**（18 项包级白名单 + 3 个含 `ctx` 受控方法 `(*net.Dialer).DialUnix`/`(*net.ListenConfig).Listen`/`(*net.ListenConfig).ListenPacket` 与 3 个包级 Unix 函数 `ListenUnix`/`ListenUnixgram`/`ResolveUnixAddr` 直接调用绑定及精确常量网络名 + 零同构克隆 `field.Pkg().Path() == "net"` / 全 `*ast.StructType` 零匿名嵌入 / `vetssa` 零接口与含 `any` 泛型擦除 + 完整类型树与复合字面量字段白名单）。
- `core/conc` 与 `core/internal/foundation/{actor,trace}`：**三层零例外共享纯内存非 I/O stdlib 约束**（禁止 `os`/`os/*`/`net`/`net/*`/`syscall`/`unsafe`/`reflect`/`math/rand`/`math/rand/*`/`crypto/rand`/`path/filepath`/`io/ioutil`/`log/syslog`/`plugin`/`embed`；生产 0 外部依赖，`actor` 0 裸 `go` 且生产不导 `core/conc`；`trace` 仓内仅允许导入 `core/domain/**` 与自身，`trace_test.go` 同样禁导 `crypto/rand`；全路径封死未登记的 `core/internal/foundation/*` 子包）。
- `core/engine`：**生产源码严禁导入 `core/ports/tck` 与 `core/internal/sim`**（仅装配真实传输 `sshnet`，确保 0 生产二进制可达 `tck` 与 `sim`；仿真装配直接走 **`core/engine/*_test.go`**）。
- `core/internal/pool`：**严禁导入 `core/internal/sshnet/**` 与 `core/osfs`**（仅依赖 `core/ports`，生产由 `core/engine` 注入 `sshnet`）。
- `core/internal/gate`：**严禁导入 `core/internal/pool` 与 `core/osfs`**（熔断经 `OnHaltFunc` 出站回调由 `core/engine` 接线至池 `controlCh`）。
- `core/internal/usecase/**`：仅可经 `core/conc`、`core/internal/{foundation,pool,gate}`、`core/events`、`core/ports` 工作；**严禁导入 `core/osfs` 或 `core/internal/sshnet`**。
- `core/internal/mcpruntime`：**物理禁止引用 `ports.OperatorReadFS`**（仅接收基于 `os.Root` 的 `ScopedRootFS`）。
- `internal/host/**`：仅可依赖 **`core/{domain,ports,osfs,conc}`**；严禁依赖 `core/engine` 或 `internal/entry/**`。
- `internal/entry/**`：仅可依赖 **`core/{domain,events,engine,conc}`**；**严禁导入 `internal/host/**` 与 `core/osfs`**。

---

## 2. 封装不变式、Go 1.27 规范与 Rust 式所有权纪律

- **Go 1.27+、代码注释、体量与复杂度红线（ADR-001, ADR-013, ADR-014）**：
  - 遵守 `gofmt` 与 Go 缩写规范（ID、URL、SSH、CLI、SFTP、TCP）；平台特异实现拆入 `_windows.go`/`_unix.go`/`_darwin.go` 构建标签文件（规避 `go/ssa` `optimizeBlocks` 剪枝不可达 `runtime.GOOS` 分支）；
  - **简体中文代码注释铁律**：保持充足、高质量的**简体中文**代码注释，便于后续人类阅读与维护——所有包说明（package doc）、导出类型/接口/函数/常量、关键私有状态机/并发原语/安全边界、非显而易见的算法步骤与不变式理由（“为何如此设计”）均须配清晰中文注释；**每次修改代码逻辑时必须同步更新对应注释，严禁遗留与实现不符的错误或过时注释**；
  - **单包生产代码上限 3,000 LOC**；**业务逻辑/状态机单文件上限 500 LOC**，纯声明式文件（显式命名 `*_spec.go`、`*_variants.go`、`*_codec.go`）上限 **800 LOC**；认知复杂度 **`gocognit <= 15`**；
  - **地道 Go 克制**：失败路径统一 `(T, error)`（禁泛化 `Result[T]`），`Option[T]` 仅限结构体区分“未设置 vs 零值”的可选值字段；
  - **`encoding/json/v2` 与 YAML 序列化铁律**：持久化/序列化 DTO（`Event`/`AuditEntry`/`MCP DTO`/持久化 `Config`，不含纯内存运行期构造参数）严禁裸用 `time.Duration`（统一用 `algebraic.Duration` 实现 `TextAppender`/`TextMarshaler`/`TextUnmarshaler`）；所有需序列化的全私有值对象必须实现 `TextAppender`/`TextMarshaler`；`SecretBox` 故意零编码接口以触发 `json/v2` 原生 `SemanticError`；规范编码统一开启 `Deterministic(true)`。
- **封闭代数数据类型（Sealed Sum Types）**：多态业务概念（`AuthMethod`、`ChallengeRule`、`NodeOrigin`、`ProxyRoute`、`ExecutionOutcome`、`ExitStatus`、`GuardrailDecision`、`StepAction`、`TransferState`、`Event`）全部采用含私有 `sealed*()` 方法的封闭接口，所有 `type switch` 穷尽覆盖（安全决策必具 fail-closed `default`）。
- **零值最严与不透明值类型**：核心域与安全类型**全字段私有**、仅经校验构造器产生，零值恒为 `Deny` / `Invalid` / `Unset` / `Disabled`。
- **代数结构统一求解**：OpenSSH 四层策略统一经 `core/domain/option` 幺半群与纯函数 `ResolveEffectivePolicy` 求解；安全判定（`Verdict` 交半格）与风险/决策（`RiskLevel`/`Decision` 并半格）采用交换/结合/幂等格折叠。
- **物理封死的能力证明、`O(1)` 崩溃对账与 `Halted` 熔断（ADR-008）**：
  - `Authorized[C]` **直接定义于 `core/internal/gate`**（内置正向门控 `valid bool` + `revoked *atomic.Bool`，Go 编译器原生封死外部构造），经**包级泛型函数 `gate.WithAuthorized[C](ctx, authorizer, req, run)`** 签发；严禁任何逃生口（禁 `nil` guardrail、禁 `Do(*pkgsftp.Client)`）。
  - 每个 `Engine` 持进程生命周期内核锁 `~/.xops/run/<ProcessInstanceID>.lock`，以**只追加协议（`+<opID>\n` / `-<opID>\n`，仅活跃集合归零或排空后才允许 `Truncate(0)`）**记录活跃未闭合 `OperationID`：干净启动 **O(1) 零扫描 `audit.jsonl`**；发现残留锁须先独占非阻塞 `TryLock` 确认原进程死亡、慢路径核对 `audit.jsonl` 后在短跨进程追加锁下补写 `AbortedByCrash`，再在持锁态截断清空 -> 关闭解锁 -> 删除（防 Windows 共享冲突）。`StrictAgentProfile` 下任何 `AuditPostWriteError` 立即进 **`Halted` 熔断态**，经 `OnHaltFunc` 吊销全部活跃 `ManagedHandle` 并拒绝一切新请求。
- **100% 作用域闭包（零命令式 `mustclose`）+ 结构化并发与双通道纯内存 Actor 连接池（ADR-009, ADR-011, ADR-015）**：
  - 全仓彻底废除命令式 `mustclose` 裸句柄：`Pool.WithLease`/`WithMultiLease`、`SecretVault.WithSecret` + `SecretBox.Use`、`ScopedRootFS.WithRoot`、`OperatorReadFS.WithOperatorRead`、`gate.WithAuthorized`（全部显式标注 `//xops:syncclosure` + `//xops:borrowed` 且带运行时失效哨兵）；跨请求长会话仅发世代句柄 `ManagedHandle[K](id, gen, binding)`。
  - **`actor.DualActor`**（位于 `core/internal/foundation/actor`，含 0 条裸 `go`、纯内存非 I/O stdlib）遵守 6 项硬规约：① 有界 `acquireCh`（对称 `acqMu+acqClosed+acqSenders` 入站发送者屏障，持锁外校验 `ctx.Err()`）+ 永不阻塞 `controlCh`（无界环形队列 + 1 缓冲唤醒，panic LIFO `defer` 调零分配 `ringQueue.reset()` 清空滞留指针）；② 主循环采用**两段式 `select`**（先非阻塞排空 `controlCh` 再阻塞监听双通道；`acquireCh` 支路排空 `controlCh` 后必须复核停机状态并转 `drainAndStopWithPending(req)` 保序排空；全停机路径统一确定性 `stopCh` 优先于 `ctx.Done()`）；③ 100% 纯内存非阻塞（零 `osfs` 锁/Audit/网络 I/O）；④ 控制面与数据面彻底分离（PTY/转发/10GiB 直走原子 `Epoch`+`ctx` 传输）；⑤ 嵌套序恒为 **`gate.WithAuthorized` 包裹 `pool.WithLease`**，且 `ReleaseLease` 发送必须监听 `actorDone`；⑥ `trace.LeaseScope` 为**全局单层不可重入连接租约作用域**，仅限连接池在进入用户回调 `fn(scopedCtx, sess)` 时注入（严禁 `gate`/`vault`/`osfs` 借用，不误伤多跳 DAG 拨号，`domain` 仅只读诊断标签），多租约走拓扑序 `WithMultiLease`；`trace` ID 生成采用纯 `TraceIDFromBytes`/`OpIDFromBytes` + 显式 `NewTraceIDFrom(io.Reader)`/`NewOpIDFrom(io.Reader)`（零隐式 `crypto/rand`）。
  - 全部后台协程受 **`core/conc.Nursery`**（显式拆分 `RunWait` Fork-Join 与 `RunScoped` 守护监督；废除私有哨兵，改用不可逆双吸收态单调状态机 `nurseryScopedCompleting` / `nurseryCanceled` + 锁外读取 `parentCtx.Err()` + `n.cancel(nil)` + 要求 `n.ctx.Err() != nil` 且拒绝吞噬 `singleUnwrapper` 的 `filterExpectedScopeCancel`）监督；`sshnet/dial` 中所有基于 `ssh.Channel` 的多跳连接强制封装 `core/conc.Nursery`（`RunScoped`）Cancel/Deadline Watchdog；可取消锁用 `core/conc.CtxMutex`。
- **双模态本地 FS、Windows 旁路锁与诚实安全边界（ADR-007, ADR-016）**：
  - `core/osfs` 写锁一律加在同 `os.Root` 下的旁路锁文件 `<name>.lock`，绝不对数据文件本身加锁后 `Root.Rename`。
  - `SecretBox` 为单协程借用（正向门控 `valid bool` + `wiped bool`），提供常量时间比对 **`Equal(other *SecretBox) bool`**（`crypto/subtle`）与入站构造 **`secret.WithBytes`**（仅标 `//xops:syncclosure` + `//xops:borrowed`，**禁标 `//xops:secretuse`**），销毁 `clear()` 零化，工程目标严格界定为阻断日志/审计/错误/事件/YAML/计划/摘要泄露与自有缓冲零化（不 fork `x/crypto/ssh`，由 `core/domain/secret` 独占 `"runtime/secret"` 预留 `goexperiment.runtimesecret` 钩子）。`sshnet/{dial,priv}`（`ssh.KeyboardInteractive` 挑战闭包 + `box.Use`、正向 SSH 通道写入白名单）与 `internal/host/vault/{offline,wincred,keychain,secretservice,helper}`（`vault/wincred` `CREDENTIALW`/`LazyProc.Call`、`vault/keychain` `purego.SyscallN`、`vault/secretservice` 专属 DH AES-128-CBC 与 `plain` D-Bus 回退、`vault/helper` `(ports.ProcessPort).Run` 仅 `stdin` 染毒）统一经 `secrettaint/sinks_narrow.go` 按精确子包门控的结构化受限窄模式钩子适配（仅非外置测试生产文件、0 `//nolint:`）。
  - 5 大多步高风险协议（`VaultSagaFSM`、`ApprovalFSM`、`TransferFSM`、`EnsureFSM`、`PendingEnrollFSM`）写成纯函数 Mealy 状态机；严分 `OutcomeUnknown`（禁重试）与 `Applied && !Durable`（禁重试禁删凭据）；SFTP 明确区分本机 `core/osfs` 原子语义与远端 SFTP v3 边界，并在写路径执行非截断打开 + `SSH_FXP_FSTAT` 类型/`(dev,ino)` 锚定比对 + 原子 `posix-rename@openssh.com`。
- **作用域化双层事件流（ADR-010）**：单次调用绑定隔离 `OperationStream`（确定性 EOF；`BlockWithContext` / `CoalesceLatest`）；审计走同步 Fail-Closed `AuditSink`；池与诊断走有界非阻塞 `SystemBus`（`DropAndCount`）。

---

## 3. 自建编译器护栏（`tools/xopsvet`）与白名单铁律（ADR-011）

全仓代码均须 0 违例通过 `tools/xopsvet` 全部 **9 大正交分析器**（依托 `internal/vetutil`、`internal/vetssa` 与前置 `internal/secretfact` 共享底座），严格落实**生产源码 vs 测试与 `core/ports/tck` 双层契约**：
- **`archbound`**：强制 §1 DAG（`core/engine` 生产禁导 `tck`/`sim`；`core/osfs` 四道 `net` 符号防线含零克隆/零匿名嵌入/`vetssa` 零擦除；`core/conc` 与 `foundation/{actor,trace}` 零例外纯非 I/O stdlib 且全路径封死 `FoundationOther`；`domain` 纯数学白名单含 `x/text/unicode/norm` 及 `option`/`secret` 独占项；`domain` 测试禁 I/O 与并发包；`mcpruntime` 禁 `OperatorReadFS`）。
- **`sumexhaust`**：类型优先 + 前置紧邻否定极性对偶（共享含数字边界的 `vetutil.SplitIdentTokens`）+ `new(T)`/`CompositeLit`/`error(nil)` 闭环；`LayerCorePortsTCK` 纳入 `inTest` 允许 `t.Fatal`/`t.Error`。
- **`linearlease`**：裸 `go` 唯一白名单 **`core/conc`**；彻底废除 `With*`/`Use` 命名猜测，仅认显式 `//xops:syncclosure`/`borrowed`/`secretuse` Fact + 精确 `(*secret.SecretBox).Use` + `runtime/secret.Do` + IIFE + 白名单同步 `iter.Seq`；基于 `vetssa` 覆盖 `new(borrowed)`/`append`/`comma-ok`/`<-ch`/`Defer`/`Go`/Loop `Phi`/写后子切片根分配反溯与 `CallerParam` 隔离。
- **`failclosed`**：零白名单、零弱化（禁吞噬新产生局部 `error` 返回裸 `bool`，精确豁免纯 `errors.Is`/`errors.AsType` 分类谓词；`zerovalue` 覆盖 `sync/atomic.Bool` 并实施前导否定前缀检查，禁止指针类型充当正向门控）。
- **`secretbox`**：专责 Rule 1（使用不入接口方法与签名的 `vetutil.ContainsValueType`，永不误杀 `ports.SecretVault`）+ Rule 3（5 包明文消费白名单）+ 全包 `*ast.StructType` 零匿名嵌入 + `vetssa.CheckNoErasure` 零接口/含 `any` 泛型擦除；经 `AllowMakeInterface` 联合精确豁免 `core/domain/secret` 白盒测试直调 `jsonv2.{Marshal,MarshalWrite,MarshalEncode}`（按调用点 `ResolvePos` 判测试）。
- **`secrettaint`**：聚焦 Rule 2 SSA 明文污点流：出参全面 Fail-Closed + 全局 `sinks.go` 精确符号级纯 AEAD 密码学消费表（不含 `argon2`/`AEAD.Open`/整包 `ssh`，`hash.Hash.Write` 验标准库 SSA 源头，`AEAD.Seal` 不染 `dst`）+ 未知回调全路径 Fail-Closed（`//xops:secretuse` 仅放行直接 `*ssa.Parameter` 并审计赋值站点）+ 合法放行嵌套同步 `box.Use`/`runtime/secret.Do` + 隔离非种子 `CallerParam` + `sinks_narrow.go` 按精确子包门控（仅非外置测试生产文件、0 `//nolint:`）的受限窄钩子（`vault/wincred` + `vault` 夹具 `CREDENTIALW` 作用域自有存储 + `LazyProc.Call`；`vault/keychain` `purego.SyscallN` 未染毒 arg 0 `fn uintptr`；`vault/secretservice` 专属 DH AES-128-CBC `crypto/cipher.NewCBCEncrypter` + `(cipher.BlockMode).CryptBlocks` 及 `plain` 回退 `dbusSecret.Value` 作用域自有存储 + `(dbus.BusObject|*dbus.Object).{CallWithContext,Call}` 仅限 `"org.freedesktop.Secret.Collection.CreateItem"` / `"org.freedesktop.Secret.Item.SetSecret"` 且 recv/`ctx`/`flags`/`method` 未染毒；`vault/helper` `(ports.ProcessPort).Run(ctx, spec, stdin)` 仅 arg 2 `stdin io.Reader` 许染毒且 recv/`ctx`/`spec` 未染毒）。
- **`osboundary`**：OS/env/exec 原语（含 `syscall.CreateProcess`/`unix.Exec`、`x/sys/{unix,windows}` 进程与环境变量 API）及 SSA Unix Listen（覆 `$thunk`/`$bound`/`Phi`/窄接口）仅查生产文件（`pkg.init` 按 `ResolvePos` 指令位置判测试）；`windows.CreateFile`、`windows.GetSecurityInfo`、`os.NewFile`、`unix.Fstat` 在 `core/osfs` 之外 **100% 封禁**（零动态路径校验器豁免）；在 `LayerHostSys`（`internal/host/sys/**` 非外置测试生产文件）仅放行直接调用 `golang.org/x/sys/unix.Open` 且 arg 0 为精确编译期字符串字面量 `"/dev/net/tun"`（Linux TUN/TAP，由 `TUNSETIFF` 校验）或 `"/dev/tty"`（Unix 管道 stdin 下 `InteractionPort` 控制终端，由 `term.IsTerminal`/`IoctlGetTermios` 校验）、置位 `O_CLOEXEC` 且不含 `O_CREAT`（`SSHFPLookupPort` 经注入的 `ports.OperatorReadFS` `SymlinkFollow` 读 `/etc/resolv.conf`，0 豁免；`TUNDevicePort` 支持 Linux `/dev/net/tun`、macOS `AF_SYSTEM` `utun`，Windows/FreeBSD 返回 `ports.ErrUnsupported` 并保留未导出 `driverOpener` 测试接缝）；SSA `RemotePath` 保持嵌套字段敏感（不染值构造器非远端字段）且全仓含测试与 `tck` 强制禁 `filepath.*`。
- **`noimplicit`**：禁 `init()`；禁可变包级 `var`（`new(expr)` & Map Key 纯度校验 + 保护全部包级 `error` 哨兵 + 仅特许 `cmd/xops` 六重门控只读 **`//xops:buildvar`** 且含测试零篡改）；禁 `trace` 外 `context.WithValue` 及 `Value(any) any`（含 `ChangeType`/`IsInvoke` 1 参 1 返，保留显式嵌入 `context.Context` 声明豁免）；禁匿名接口断言（含泛型 `IndexExpr`/`IndexListExpr`）；按文件强制 8 特权包生产源码外（含白盒 `*_test.go`）0 `//nolint:`；禁持久化/序列化 DTO 裸用 `time.Duration`（去全局 `*Config` 泛化误杀，顶层/嵌套统一可见性，先查 `TypeArgs()` 再按 JSON/YAML 语义判定停钻）。
- **`digestcover`**：编译期字段完整性检查，零 `reflect`。

### 特权白名单总表（明确区分「能力白名单」「生产源码」与「白盒/外置测试」）

| 特权能力 | 唯一合法白名单包（外置 `*_test` 一律剥夺特权） | 生产源码允许 `//nolint:` | 包内白盒 `*_test.go` 允许 `//nolint:` | 违规处理 |
| :--- | :--- | :---: | :---: | :--- |
| 裸 OS 文件 / 锁 / ACL / `os.Root` / 本地 `AF_UNIX` `SocketSlot` / 受验 Windows Named Pipe 拨号 (`DialWindowsNamedPipeVerified`) | `core/osfs` | 是 | **否** | 封装为安全句柄原语并过 `tck` |
| 裸 `go` 语句 | `core/conc`（仅含 `Nursery` + `CtxMutex`，全仓唯一） | 是 | **否** | 改用 `core/conc.Nursery` |
| `context.WithValue` / `ctx.Value` | `core/internal/foundation/trace` | 是 | **否** | 改用显式强类型函数参数 |
| `os.Getenv` / `exec.Command` / PTY / Console Relay / 窄常量 `unix.Open`（`"/dev/net/tun"`、`"/dev/tty"`） | `internal/host/sys`（含子包 `{agent,interact,sshfp,tun}`） | 是 | **否** | 通过 `core/ports` 接口注入 |
| 明文机密 `[]byte` 消费（生产路径，4 包） | `core/domain/secret`、`internal/host/vault`（含隔离后端子包 `{offline,wincred,keychain,secretservice,helper}`）、`core/internal/sshnet/dial`、`core/internal/sshnet/priv` | 是 | **否** | 其余全部代码仅传递 `SecretRef` 或经 `WithSecret` 借用 `*SecretBox` |
| 明文机密 `[]byte` 消费（仿真 Vault，第 5 包） | `core/internal/sim`（AES-GCM 密文仿真，0 生产可达，仍严格过规则 1/2） | **否** | **否** | 严禁被生产源码导入，禁止行内 `//nolint:` |
| 链接期只读构建元信息（`//xops:buildvar`） | `cmd/xops`（精确路径 + `package main` + 非测试 + 未导出单内置 `string`） | **否** | **否** | 封装为显式 `BuildInfo` 值结构体传入 `entry/cli`，禁止行内 `//nolint:` |

> 全仓允许行内 `//nolint:` 的仅限上述 **8 个特权包的生产源码文件**（`core/osfs`、`core/conc`、`core/internal/foundation/trace`、`internal/host/sys`、`internal/host/vault`、`core/internal/sshnet/dial`、`core/internal/sshnet/priv`、`core/domain/secret`）；其余全部包及**全仓所有测试文件（含 8 特权包白盒 `*_test.go`、外置 `*_test`、`cmd/xops`、`core/internal/sim`、`core/internal/foundation/actor`、`tools/xopsvet`）100% 禁止行内 `//nolint:`**。

---

## 4. 验证门禁与测试体系

- **契约、早验与确定性优先**：每个 `core/ports` 实现（含 `ScopedRootFS`/`OperatorReadFS`）必过 `core/ports/tck`；代数类型配结合/交换/幂等/零值属性与 Fuzz 测试；核心运行时与用例必过单种子可复现 DST（含 `O(1)` 崩溃对账、`Halted` 熔断、两段式 `actor.DualActor` 满邮箱、重入拦截、跳板 Watchdog 与 5 大全局不变量）；OpenSSH 对接 `ssh -G` 差分；三平台真实端到端回归持续验证 `cmd/xops` 完整链路。
- **平台诚实原则**：交叉编译与 lint 不等于原生平台测试通过；Windows（ConPTY、Handle DACL、旁路锁、`\\?\` 长路径、`AF_UNIX` 对端令牌、Named Pipe 核验）与 macOS（`kqueue`、Keychain、Unix 套接字、`utun`）行为以原生 Runner / VM 执行结果为准；三平台原生 CI 均须运行完整 `xopsvet`。
- **四端统一验证事实源（SSOT：`scripts/ci/verify.go`，`//go:build ignore`）**：外层不设 `GOWORK=off`，由 `verify.go` 在子进程内按模块显式设定（`tools/xopsvet` 与 `core/` 强制 `GOWORK=off`，根 CLI 默认清除 `GOWORK` 走 `go.work`，正式发版锁 `core/v1.0.0` Tag 及三模块独立发布验收时传 `--gowork-off`），全模块强制 `-race -shuffle=on`，并自检自身 `gofmt` 与根默认环境 `go vet`。

```sh
# 1. 全阶段标准门禁（含 verify.go 自检、replace 守卫、xopsvet 单测/自检/lint、core/ GOWORK=off 全检、根 CLI）
go run ./scripts/ci/verify.go --stage=all

# 2. 并发原语 50 轮随机压测与跨平台交叉编译 + 交叉 Lint
(cd core && GOWORK=off go test -race -shuffle=on -count=50 ./conc/... ./internal/foundation/...)
go run ./scripts/ci/verify.go --stage=cross

# 3. 确定性仿真门禁 (DST)、CI 脚本单测与文档校验
go run ./scripts/ci/verify.go --stage=dst
python3 -m unittest discover -s scripts -p test_ci_changes.py -v
npm run docs:check
```

---

## 5. 交付规范、Git 与操作安全

- **每次变更固定汇报**：修改摘要、目标模块/包与关联任务/议题、实际运行的命令及真实结果、未运行项及原因、剩余风险；修改代码须同步核对并刷新受影响的代码注释（零过时注释）。
- **文档语言规范**：**开发文档（`docs/development/**`）不再要求维护英文双语版本，仅保证简体中文文档准确完整即可**；面向用户的公开文档（`docs/{index.md,guide/**,reference/**,troubleshooting/**}` 与 `docs/en/{index.md,guide/**,reference/**,troubleshooting/**}`、`README.md` / `README_en.md`）与 `skills/xops-agent/**` 在对外契约变更时保持同步准确。
- **Git 纪律**：提交遵循 `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`, `ci:`；严禁未经明确授权执行 `git push`、合并主分支、强推、修改 CI 权限或绕过门禁。
- **远端安全红线**：代码开发与架构维护任务**不代表授权连接或操作任何真实用户主机/服务器**；所有 SSH/SFTP/Playbook/MCP 协议与护栏测试必须使用 `core/internal/sim`、TCK 或本地沙盒测试桩。
