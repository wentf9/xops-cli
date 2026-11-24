# XOps v2 AI 协作与工程宪法（AGENTS.md）

> **当前任务模式**：XOps v2 架构彻底重构（Clean-Room Rewrite，**v2.3.2 架构校准终稿**）。  
> **唯一权威设计源**：[docs/development/v2-architecture-rfc.md](docs/development/v2-architecture-rfc.md)（ADR-001 – ADR-016）与 [docs/development/v2-implementation-plan.md](docs/development/v2-implementation-plan.md)（Phase 0–5 含 Phase 2.5 Walking Skeleton，Gate G0–G5）。

---

## 0. 最高工作准则

- **零历史兼容、严禁打补丁**：严禁在新架构中引入任何 v1 兼容垫片、v1 迁移/读取代码、旧 API facade 或新旧双轨桥接（仅在配置导入层预留统一 `FormatImporter` / `ImportBundle` 扩展入口，100% 零 v1 代码）。仓库历史提交（如 `git show b15df20:<path>`）仅可作客观领域规则只读参考，**禁止直接拷贝旧代码结构**。
- **显式大于隐式、类型即证明**：严禁依赖注释、命名习惯或调用方自律维持安全/并发不变量；一切核心约束必须编码进 **Go 模块与包边界、私有构造器、封闭和类型、作用域闭包或自建编译器护栏 `tools/xopsvet`**。
- **事实核验铁律**：禁止凭名称猜测模块职责、编造符号、或宣称未执行的命令通过；关键引用须附 `路径:符号`（必要时附行号），无法确认时写「待验证」。
- **只读与编码边界**：调查、审查或文档任务默认只读，不修改源码/配置；启动任何编码任务前，先声明对应的实施计划任务 ID（`P?-T?`）、目标模块/包、预期门禁与验证命令，严格按 **Phase 0 → Phase 1 → Phase 2 → Phase 2.5 (Walking Skeleton) → Phase 3 ∥ Phase 4 → Phase 5** 顺序过闸推进（未过当前 Gate 不得开启下一阶段）。

---

## 1. 三模块物理隔离与单向依赖法则（ADR-001 – ADR-003, ADR-007, ADR-009）

仓库采用 **Go 1.27+ Multi-Module Workspace**（全仓 3 个 `go.mod` **严禁长期 `replace`**；开发与分支 CI 期对 `core/` 与 `tools/xopsvet/` 强制 `GOWORK=off` 独立验证，根 CLI 模块经 `go.work` 联合验证；遵循 Go Module SIV，`core/go.mod` 保持 `github.com/wentf9/xops-cli/core` 无 `/v2` 后缀，正式发版打 **`core/v1.0.0`** Tag 后锁定版本并补跑三模块全量 `GOWORK=off` 验收）：

1. **`tools/xopsvet/`**（`tools/xopsvet/go.mod`）：独立自建静态分析器模块，隔离 `golang.org/x/tools` 依赖。
2. **`core/`**（`core/go.mod`）：完全无宿主假设的六边形核心（供 `xops-cli` 与外部 `xops-mcp` 共同复用）。
   - **仅允许公开 6 个极简契约包**：`core/domain/...`、`core/ports`（含 `ScopedRootFS`、`OperatorReadFS`、`FormatImporter`、`core/ports/tck`）、`core/events`、`core/osfs`、**`core/conc`**（仅含零依赖 `Nursery` + `CtxMutex`，全仓唯一裸 `go` 白名单）、`core/engine`。
   - **100% 物理封锁于 `core/internal/`**：`foundation/{actor,trace}`（其中 `actor` 含 0 裸 `go` 纯内存 `actor.DualActor`）、`pool`、`gate`（独占定义 `Authorized[C]`）、`usecase/*`、`mcpruntime`、`sshnet/*`、`sim`。外部宿主与 CLI 均不得可见。
3. **根 CLI 模块**（根 `go.mod`）：
   - `internal/host/{store,openssh,vault,sys,audit}`：本机出站基础设施适配器，实现 `core/ports`。
   - `internal/entry/{cli,tui,sftpshell,mcpcmd,muxdaemon}`：极薄入站驱动适配器，零业务逻辑。
   - `cmd/xops`：全仓唯一组合根，零 `init()`、零全局单例（链接期只读构建元信息经 `-X 'main.buildVersion/buildCommit/buildTime'` + 六重门控 `//xops:buildvar` 接收并转为显式 `BuildInfo` 注入 `entry/cli`），负责注入 `ScopedRootFS` 与 `OperatorReadFS`，退出时按 `Entry -> Engine/UseCases -> Pool -> Vault -> Store -> Audit -> Sys/Relay` 严格逆序关闭。

### 绝对禁止与受控的依赖方向（由 Go 模块与 `xopsvet/archbound` 机器强制）

- `core/domain/**`：**100% 纯函数数学核**（白名单：29 纯 stdlib + 官方纯数学包 `golang.org/x/text/unicode/norm`；子包独占：`core/domain/option` 放行 `"crypto/sha1"` 供 OpenSSH `%C`，`core/domain/secret` 放行 `"runtime/secret"` 供 `goexperiment.runtimesecret`），严禁导入 `context`、`os`、`net`、`os/exec`、`syscall`、`sync`、**`sync/atomic`**、`reflect`、`time.Now`、`math/rand`、`core/ports`、`core/events`、`core/osfs`、`core/conc`、`core/internal`；`core/domain/**` 测试源码同样物理禁止 `os`/`net`/`os/exec`/`sync`/`core/conc`/`sim`/`goleak`。
- `core/ports/**`（非 `tck`）：仅可依赖 `core/domain/**`；严禁依赖 `core/internal/**`、`core/osfs`、`core/conc` 或具体实现库（如 `golang.org/x/crypto/ssh`、`github.com/pkg/sftp`）。`core/ports/tck` 为测试契约夹具层（允许 `core/conc` 与 `goleak`，**0 生产可达**）。
- `core/osfs`：严禁导入 `net/*` 子包与 `os/exec`；允许导入 `"net"` 仅用于本地 `AF_UNIX` `SocketSlot`/`ProbeStaleUnixSocket` 并由 `archbound/osfs_net.go` 实施三道 fail-closed 符号防线（包级白名单 + 7 通用 `network` 符号直接调用绑定与精确参数位 + 成员直接归属类型与省略类型字面量校验）。
- `core/conc` 与 `core/internal/foundation/actor`：均施加纯非 I/O stdlib 约束（生产 0 外部依赖，`actor` 0 裸 `go` 且生产不导 `core/conc`）。
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
  - 遵守 `gofmt` 与 Go 缩写规范（ID、URL、SSH、CLI、SFTP、TCP）；
  - **简体中文代码注释铁律**：保持充足、高质量的**简体中文**代码注释，便于后续人类阅读与维护——所有包说明（package doc）、导出类型/接口/函数/常量、关键私有状态机/并发原语/安全边界、非显而易见的算法步骤与不变式理由（“为何如此设计”）均须配清晰中文注释；**每次修改代码逻辑时必须同步更新对应注释，严禁遗留与实现不符的错误或过时注释**；
  - **单包生产代码上限 3,000 LOC**；**业务逻辑/状态机单文件上限 500 LOC**，纯声明式文件（显式命名 `*_spec.go`、`*_variants.go`、`*_codec.go`）上限 **800 LOC**；认知复杂度 **`gocognit <= 15`**；
  - **地道 Go 克制**：失败路径统一 `(T, error)`（禁泛化 `Result[T]`），`Option[T]` 仅限结构体区分“未设置 vs 零值”的可选值字段；
  - **`encoding/json/v2` 铁律**：Event/Audit/MCP/Config DTO 严禁裸用 `time.Duration`（统一用 `algebraic.Duration` 实现 `TextAppender`/`TextMarshaler`/`TextUnmarshaler`）；所有需序列化的全私有值对象必须实现 `TextAppender`/`TextMarshaler`；`SecretBox` 故意零编码接口以触发 `json/v2` 原生 `SemanticError`；规范编码统一开启 `Deterministic(true)`。
- **封闭代数数据类型（Sealed Sum Types）**：多态业务概念（`AuthMethod`、`ChallengeRule`、`NodeOrigin`、`ProxyRoute`、`ExecutionOutcome`、`ExitStatus`、`GuardrailDecision`、`StepAction`、`TransferState`、`Event`）全部采用含私有 `sealed*()` 方法的封闭接口，所有 `type switch` 穷尽覆盖（安全决策必具 fail-closed `default`）。
- **零值最严与不透明值类型**：核心域与安全类型**全字段私有**、仅经校验构造器产生，零值恒为 `Deny` / `Invalid` / `Unset` / `Disabled`。
- **代数结构统一求解**：OpenSSH 四层策略统一经 `core/domain/option` 幺半群与纯函数 `ResolveEffectivePolicy` 求解；安全判定（`Verdict` 交半格）与风险/决策（`RiskLevel`/`Decision` 并半格）采用交换/结合/幂等格折叠。
- **物理封死的能力证明、`O(1)` 崩溃对账与 `Halted` 熔断（ADR-008）**：
  - `Authorized[C]` **直接定义于 `core/internal/gate`**（Go 编译器原生封死外部构造），经**包级泛型函数 `gate.WithAuthorized[C](ctx, authorizer, req, run)`** 签发；严禁任何逃生口（禁 `nil` guardrail、禁 `Do(*pkgsftp.Client)`）。
  - 每个 `Engine` 持进程生命周期内核锁 `~/.xops/run/<ProcessInstanceID>.lock`，以**只追加协议（`+<opID>\n` / `-<opID>\n`，仅活跃集合归零或排空后才允许 `Truncate(0)`）**记录活跃未闭合 `OperationID`：干净启动 **O(1) 零扫描 `audit.jsonl`**；发现残留锁须先独占非阻塞 `TryLock` 确认原进程死亡、慢路径核对 `audit.jsonl` 后在短跨进程追加锁下补写 `AbortedByCrash`，再在持锁态截断清空 -> 关闭解锁 -> 删除（防 Windows 共享冲突）。`StrictAgentProfile` 下任何 `AuditPostWriteError` 立即进 **`Halted` 熔断态**，经 `OnHaltFunc` 吊销全部活跃 `ManagedHandle` 并拒绝一切新请求。
- **100% 作用域闭包（零命令式 `mustclose`）+ 结构化并发与双通道纯内存 Actor 连接池（ADR-009, ADR-011, ADR-015）**：
  - 全仓彻底废除命令式 `mustclose` 裸句柄：`Pool.WithLease`/`WithMultiLease`、`SecretVault.WithSecret` + `SecretBox.Use`、`ScopedRootFS.WithRoot`、`OperatorReadFS.WithOperatorRead`、`gate.WithAuthorized`（均带运行时失效哨兵）；跨请求长会话仅发世代句柄 `ManagedHandle[K](id, gen, binding)`。
  - **`actor.DualActor`**（位于 `core/internal/foundation/actor`，含 0 条裸 `go`、纯内存非 I/O stdlib）遵守 6 项硬规约：① 有界 `acquireCh`（对称 `acqMu+acqClosed+acqSenders` 入站发送者屏障，持锁外校验 `ctx.Err()`）+ 永不阻塞 `controlCh`（无界环形队列 + 1 缓冲唤醒，panic LIFO `defer` 清空滞留指针）；② 主循环采用**两段式 `select`**（先非阻塞排空 `controlCh` 再阻塞监听双通道）；③ 100% 纯内存非阻塞（零 `osfs` 锁/Audit/网络 I/O）；④ 控制面与数据面彻底分离（PTY/转发/10GiB 直走原子 `Epoch`+`ctx` 传输）；⑤ 嵌套序恒为 **`gate.WithAuthorized` 包裹 `pool.WithLease`**，且 `ReleaseLease` 发送必须监听 `actorDone`；⑥ `trace.LeaseScope` 为**全局单层不可重入连接租约作用域**，仅限连接池在进入用户回调 `fn(scopedCtx, sess)` 时注入（严禁 `gate`/`vault`/`osfs` 借用，不误伤多跳 DAG 拨号，`domain` 仅只读诊断标签），多租约走拓扑序 `WithMultiLease`。
  - 全部后台协程受 **`core/conc.Nursery`**（显式拆分 `RunWait` Fork-Join 与 `RunScoped` 守护监督 + 零弱化 `failclosed` 且拒绝吞噬 `singleUnwrapper` 的 `filterExpectedScopeCancel`）监督；`sshnet/dial` 中所有基于 `ssh.Channel` 的多跳连接强制封装 `core/conc.Nursery`（`RunScoped`）Cancel/Deadline Watchdog；可取消锁用 `core/conc.CtxMutex`。
- **双模态本地 FS、Windows 旁路锁与诚实安全边界（ADR-007, ADR-016）**：
  - `core/osfs` 写锁一律加在同 `os.Root` 下的旁路锁文件 `<name>.lock`，绝不对数据文件本身加锁后 `Root.Rename`。
  - `SecretBox` 为单协程借用（正向门控 `valid bool` + `wiped bool`），提供常量时间比对 **`Equal(other *SecretBox) bool`**（`crypto/subtle`）与入站构造 **`secret.WithBytes`**（仅标 `//xops:syncclosure` + `//xops:borrowed`，**禁标 `//xops:secretuse`**），销毁 `clear()` 零化，工程目标严格界定为阻断日志/审计/错误/事件/YAML/计划/摘要泄露与自有缓冲零化（不 fork `x/crypto/ssh`，由 `core/domain/secret` 独占 `"runtime/secret"` 预留 `goexperiment.runtimesecret` 钩子）。`P4-T1`（`ssh.KeyboardInteractiveChallenge`）与 `P4-T4`（Windows `CREDENTIALW`）经 `secrettaint/sinks.go` 受限窄消费器契约适配（0 `//nolint:`）。
  - 5 大多步高风险协议（`VaultSagaFSM`、`ApprovalFSM`、`TransferFSM`、`EnsureFSM`、`PendingEnrollFSM`）写成纯函数 Mealy 状态机；严分 `OutcomeUnknown`（禁重试）与 `Applied && !Durable`（禁重试禁删凭据）；SFTP 明确区分本机 `core/osfs` 原子语义与远端 SFTP v3 边界，并在写路径执行非截断打开 + `SSH_FXP_FSTAT` 类型/`(dev,ino)` 锚定比对 + 原子 `posix-rename@openssh.com`。
- **作用域化双层事件流（ADR-010）**：单次调用绑定隔离 `OperationStream`（确定性 EOF；`BlockWithContext` / `CoalesceLatest`）；审计走同步 Fail-Closed `AuditSink`；池与诊断走有界非阻塞 `SystemBus`（`DropAndCount`）。

---

## 3. 自建编译器护栏（`tools/xopsvet`）与白名单铁律（ADR-011）

全仓代码均须 0 违例通过 `tools/xopsvet` 全部 8 大精准分析器，严格落实**生产源码 vs 测试与 `core/ports/tck` 双层契约**：
- **`archbound`**：强制 §1 DAG（`core/engine` 生产禁导 `tck`/`sim`；`core/osfs` 三道 `net` 符号防线；`core/conc` 与 `foundation/actor` 纯非 I/O stdlib；`domain` 纯数学白名单含 `x/text/unicode/norm` 及 `option`/`secret` 独占项；`domain` 测试禁 I/O 与并发包；`mcpruntime` 禁 `OperatorReadFS`）。
- **`sumexhaust`**：类型优先 + 前置紧邻否定极性对偶 + `new(T)`/`CompositeLit`/`error(nil)` 闭环；`LayerCorePortsTCK` 纳入 `inTest` 允许 `t.Fatal`/`t.Error`。
- **`linearlease`**：裸 `go` 唯一白名单 **`core/conc`**（违规改用 `core/conc.Nursery`）；移除错误 `defer` 同步放行；`IsFreshLocalSliceAlloc` 封堵宽泛切片拷贝逃逸 + 局部闭包借用零逃逸。
- **`failclosed`**：零白名单、零弱化（禁吞噬新产生局部 `error` 返回裸 `bool`，精确豁免纯 `errors.Is`/`errors.AsType` 分类谓词）。
- **`secrettaint`**：类型级封禁 + 5 包明文消费白名单 + 单调并格回调集 + `IsFreshLocalSliceAlloc` + `boxsinks` 单遍流（含 Map Key & comma-ok）+ 同包具名 `FuncDecl` 递归污点追踪（不对 `len(plain)` 误报）。
- **`osboundary`**：OS/env/exec 原语仅检查生产文件（`!IsTestFile && Layer != LayerCorePortsTCK`）；`RemotePath` 禁调 `filepath.*` 全仓含测试与 `tck` 100% 强制。
- **`noimplicit`**：禁 `init()`；禁可变包级 `var`（仅特许 `cmd/xops` 精确路径 `package main` 非测试文件未导出单内置 `string` 六重门控只读 **`//xops:buildvar`**，且含 `cmd/xops/*_test.go` 零运行期篡改）；禁 `trace` 外 `context.WithValue`；禁匿名接口断言；禁 8 特权包外行内 `//nolint:`；禁 JSON v2 DTO 裸用 `time.Duration`。
- **`digestcover`**：编译期字段完整性检查，零 `reflect`。

### 特权白名单总表（明确区分「能力白名单」与「`//nolint:` 白名单」）

| 特权能力 | 唯一合法白名单包（外置 `*_test` 一律剥夺特权） | 允许 `//nolint:` | 违规处理 |
| :--- | :--- | :---: | :--- |
| 裸 OS 文件 / 锁 / ACL / `os.Root` / 本地 `AF_UNIX` `SocketSlot` | `core/osfs` | 是 | 封装为安全句柄原语并过 `tck` |
| 裸 `go` 语句 | `core/conc`（仅含 `Nursery` + `CtxMutex`，全仓唯一） | 是 | 改用 `core/conc.Nursery` |
| `context.WithValue` / `ctx.Value` | `core/internal/foundation/trace` | 是 | 改用显式强类型函数参数 |
| `os.Getenv` / `exec.Command` / PTY / Console Relay | `internal/host/sys` | 是 | 通过 `core/ports` 接口注入 |
| 明文机密 `[]byte` 消费（生产路径，4 包） | `core/domain/secret`、`internal/host/vault`、`core/internal/sshnet/dial`、`core/internal/sshnet/priv` | 是 | 其余全部代码仅传递 `SecretRef` 或经 `WithSecret` 借用 `*SecretBox` |
| 明文机密 `[]byte` 消费（仿真 Vault，第 5 包） | `core/internal/sim`（AES-GCM 密文仿真，0 生产可达，仍严格过规则 1/2） | **否** | 严禁被生产源码导入，禁止行内 `//nolint:` |
| 链接期只读构建元信息（`//xops:buildvar`） | `cmd/xops`（精确路径 + `package main` + 非测试 + 未导出单内置 `string`） | **否** | 封装为显式 `BuildInfo` 值结构体传入 `entry/cli`，禁止行内 `//nolint:` |

> 全仓允许行内 `//nolint:` 的生产特权包严格锁定为 **8 个**（`core/osfs`、`core/conc`、`core/internal/foundation/trace`、`internal/host/sys`、`internal/host/vault`、`core/internal/sshnet/dial`、`core/internal/sshnet/priv`、`core/domain/secret`）；其余全部包（含 `cmd/xops`、`core/internal/sim`、`core/internal/foundation/actor`、`tools/xopsvet` 及所有外置 `*_test`）**100% 禁止行内 `//nolint:`**。

---

## 4. 验证门禁与测试体系

- **契约、早验与确定性优先**：每个 `core/ports` 实现（含 `ScopedRootFS`/`OperatorReadFS`）必过 `core/ports/tck`；代数类型配结合/交换/幂等/零值属性与 Fuzz 测试；核心运行时与用例必过单种子可复现 DST（含 `O(1)` 崩溃对账、`Halted` 熔断、两段式 `actor.DualActor` 满邮箱、重入拦截、跳板 Watchdog 与 5 大全局不变量）；OpenSSH 对接 `ssh -G` 差分；`Gate G2.5 Walking Skeleton` 起即在原生三平台验证真实端到端链路。
- **平台诚实原则**：交叉编译与 lint 不等于原生平台测试通过；Windows（ConPTY、Handle DACL、旁路锁、`\\?\` 长路径、`AF_UNIX` 对端令牌）与 macOS（`kqueue`、Keychain、Unix 套接字）行为以原生 Runner / VM 执行结果为准。
- **标准验证入口（各阶段对应执行）**：

```sh
# 1. 构建、单测、自检并 lint 编译器护栏（统一使用绝对路径 + GOEXE 兼容 Windows/深层子包）
VETTOOL="$(pwd)/bin/xopsvet$(go env GOEXE)"
(cd tools/xopsvet \
  && GOWORK=off go test -race -shuffle=on -count=1 ./... \
  && GOWORK=off go build -o "$VETTOOL" ./cmd/xopsvet \
  && GOWORK=off go vet -vettool="$VETTOOL" ./... \
  && GOWORK=off golangci-lint run --max-issues-per-linter=0 --max-same-issues=0 ./...)

# 2. 独立模块 GOWORK=off 验证 core/（零反向耦合与零 replace 物理证明；Gate G0 含 50 轮并发随机压测）
(cd core \
  && GOWORK=off go build ./... \
  && GOWORK=off go vet -vettool="$VETTOOL" ./... \
  && GOWORK=off golangci-lint run --max-issues-per-linter=0 --max-same-issues=0 ./... \
  && GOWORK=off go test -race -shuffle=on -count=1 ./...)
# Gate G0 并发压测：
(cd core && GOWORK=off go test -race -shuffle=on -count=50 ./conc/... ./internal/foundation/...)

# 3. 验证根 CLI 宿主模块（未打 core/v1.0.0 Tag 的分支开发期通过 go.work；正式发版锁 Tag 后改 GOWORK=off）
go build ./... && go vet -vettool="$VETTOOL" ./... && golangci-lint run --max-issues-per-linter=0 --max-same-issues=0 ./... && go test -race -shuffle=on -count=1 ./...

# 4. 确定性仿真门禁 (DST)、CI 脚本单测与双语文档校验
(cd core && GOWORK=off XOPS_DST_SEEDS=10000 go test -race -count=1 -run '^TestDST_' ./...)
python3 -m unittest discover -s scripts -p test_ci_changes.py -v
npm run docs:check
```

---

## 5. 交付规范、Git 与操作安全

- **每次变更固定汇报**：修改摘要、对应任务 ID（`P?-T?`）与勾选状态更新、实际运行的命令及真实结果、未运行项及原因、剩余风险；修改代码须同步核对并刷新受影响的代码注释（零过时注释）。
- **文档语言规范**：**开发文档（`docs/development/**`）不再要求维护英文双语版本，仅保证简体中文文档准确完整即可**；仅面向用户的公开文档（`docs/{guide,reference,troubleshooting}/**` 与 `docs/en/{guide,reference,troubleshooting}/**`、`README.md` / `README_en.md`）在对外契约变更时保持中英双语同步。
- **Git 纪律**：提交遵循 `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`, `ci:`；严禁未经明确授权执行 `git push`、合并主分支、强推、修改 CI 权限或绕过门禁。
- **远端安全红线**：代码重构与架构维护任务**不代表授权连接或操作任何真实用户主机/服务器**；所有 SSH/SFTP/Playbook/MCP 协议与护栏测试必须使用 `core/internal/sim`、TCK 或本地沙盒测试桩。
