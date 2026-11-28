# XOps v2 AI 协作与工程维护指南（AGENTS.md）

> **定位**：XOps v2 生产开发与持续维护工程规范。  
> **活跃开发文档（简体中文）**：[开发索引](docs/development/index.md) · [文档维护](docs/development/docs.md) · [架构 RFC](docs/development/v2-architecture-rfc.md) · [实施计划](docs/development/v2-implementation-plan.md) · [多平台 CI](docs/development/v2-local-multiplatform-ci.md)  
> **历史归档**：[docs/development/archive/README.md](docs/development/archive/README.md)（只读历史参考，禁回流旧架构）。

## 1. 最高工作准则

- **事实核验铁律**：禁凭名猜测、编造符号或宣称未执行命令通过；关键引用附 `路径:符号`（必要时附行号），未确认写「待验证」。
- **只读与编码边界**：调查、审查、读文档默认只读；编码前明确目标包、受影响不变量与验证命令，全量过闸方算完成（严禁跳过门禁）。
- **零 v1 历史兼容**：永久禁止 v1 兼容垫片、旧格式读取/迁移或双轨桥接；外部格式统一经 `ports.FormatImporter` / `inventory.ImportBundle` 接入。
- **类型与护栏大于约定**：核心安全与并发不变量须编码进 Go 模块/包边界、私有构造器、封闭和类型、作用域闭包或 `tools/xopsvet`。
- **简体中文代码注释铁律**：包文档、导出符号、关键私有状态机/并发/安全边界与设计理由须配清晰简体中文注释；**改逻辑必同步更新注释，零过时注释**。

## 2. 三模块架构与单向依赖矩阵

**Go 1.27+**（`CGO_ENABLED=0`）三模块 Workspace（[go.work](go.work)），全仓 3 个 `go.mod` 与 `go.work` **永久 0 `replace`**；`core/go.mod` 遵 Go Module SIV（`github.com/wentf9/xops-cli/core` 无 `/v2` 后缀，根 [go.mod](go.mod) 当前锁 `core/v1.1.0`，演进发 `core/v1.x.y` Tag）：

1. **`tools/xopsvet/`**（[tools/xopsvet/go.mod](tools/xopsvet/go.mod)）：独立静态分析器模块（隔离 `golang.org/x/tools`），含 **10 大正交分析器**（含第 10 分析器 `i18nguard`）。
2. **`core/`**（[core/go.mod](core/go.mod)）：无宿主假设六边形核心。仅公开 6 包：`core/domain/...`（其中 `core/domain/i18n` 为绝对叶包，纯数据延迟本地化，无环内部叶包 `internal/{textalg,errchain,corecatalog/{common,domain,ports,runtime,usecase}}` 零仓内依赖且 `corecatalog/**` 生产仅导 `"slices"`）、`core/ports`（含 `ScopedRootFS`/`OperatorReadFS`/`FormatImporter`/`tck`）、`core/events`、`core/osfs`、`core/conc`（`Nursery`+`CtxMutex`，维持零仓内依赖不动摇）、`core/engine`；其余 100% 封锁于 `core/internal/`（`foundation/{actor,trace}`、`pool`、`gate`（含 `internal/reasonmsg`）、`usecase/*`、`mcpruntime/{protocol,tools}`、`sshnet/*`、`sim`）。
3. **根 CLI 模块**（[go.mod](go.mod)）：
   - `internal/i18n`（`LayerInternalI18n`）：根模块纯叶层词库与不可变 `Localizer`——含唯一六重门控只读 `embed.FS`（`embed_fs.go`）、无环内部叶包 `internal/rootcatalog`（零仓内依赖，生产仅导 `"slices"`）与 `locales/{en,zh}/*.yaml`（11 对镜像共 1,506 双语词条）；`archbound` 放行 `core/domain/**` 与 `core/conc`（供 `cross_layer_render_test.go` 校验全领域错误渲染），生产源码实际仅依赖 `core/domain/i18n`、`core/conc` 与 `internal/rootcatalog`，可被 `internal/host/**`、`internal/entry/**`、`cmd/xops` 单向引用。
   - `internal/host/{store,openssh,vault,sys,audit}`：实现 `core/ports`。`vault` 隔离 `{offline,wincred,keychain,secretservice,helper}`，`sys` 隔离 `{agent,interact,sshfp,tun}`（含 `locale*.go` 跨平台语种探测）；`CGO_ENABLED=0` 仅批 `purego`（macOS）与 `godbus/dbus/v5`（Linux），句柄存结构体字段（0 `init()`、0 包级 `var`）。
   - `internal/entry/`：极薄入站驱动，零业务逻辑——6 子包 CLI（`cli`、`cli/clikit`、`cli/cmdssh`、`cli/cmdtransfer`、`cli/cmdasset`、`cli/cmdops`）+ 4 独立入口（`tui`、`sftpshell`、`mcpcmd`、`muxdaemon`）。
   - `cmd/xops`：唯一组合根，0 `init()`、0 全局单例；`-X 'main.buildVersion/buildCommit/buildTime'` 经六重门控 `//xops:buildvar` 转 `cli.BuildInfo`；MCP 强制 `OperatorReadFS/Interaction/Terminal == nil`；退出按 LIFO 逆序关闭：`Entry -> Engine/UseCases -> Pool -> Vault -> Store -> Audit -> Sys/Relay`。

### 单向依赖边界速查表（`xopsvet/archbound` 强制；`base` = `core/{domain,ports,events,conc}` + `foundation/{actor,trace}`）

| 架构层 / 包 | 允许依赖 | 绝对禁止 |
| :--- | :--- | :--- |
| `core/domain/i18n`（及 `internal/**`） | 绝对叶包：主包仅导自身与 `internal/{textalg,errchain,corecatalog}`；`corecatalog` 路由仅导 `corecatalog/*`；叶包零仓内依赖（`corecatalog/**` 生产仅导 `"slices"`） | 同层其余 `core/domain/*`（含 `algebraic`）、任何非自身仓内包、外部三方包与非白名单 stdlib（叶包外置测试亦禁反向导入其他仓内包） |
| `core/domain/**` | 仅自身；29 纯 stdlib + `x/text/unicode/norm`（`option` 放 `crypto/sha1`，`secret` 放 `runtime/secret`） | `context`/`os`/`net`/`os/exec`/`syscall`/`sync`/`sync/atomic`/`reflect`/`time.Now`/`math/rand` 及非 `domain` 包；**测试同禁 I/O/`sync`/`conc`/`sim`/`goleak`** |
| `core/ports/**`（非 `tck`） | `core/domain/**` | `core/internal/**`/`osfs`/`conc`/`os/exec`/`syscall`/`unsafe`/实现库；`tck` 为测试夹具（许 `conc`/`goleak`，0 生产可达） |
| `core/events` | `core/domain/**` | `os`/`net`/`syscall`/`unsafe`/`crypto/tls`/外部库 |
| `core/osfs` | `core/{domain,ports}`、`x/sys/{unix,windows}`；受控 `"net"`（本地 `AF_UNIX` `SocketSlot`/`DialUnixVerified` + `DialWindowsNamedPipeVerified`） | `net/*`/`os/exec`/`crypto/tls`/`log/syslog`/`reflect`；`"net"` 须过四道 fail-closed 符号防线 |
| `core/conc` & `foundation/{actor,trace}` | 纯内存非 I/O stdlib（0 外部）；`conc` 仅自身（零仓内依赖），`actor` 依 `domain`+`foundation`（0 裸 `go`、生产不导 `conc`），`trace` 依 `domain`（显式 `io.Reader` 熵注入） | `os`/`net`/`syscall`/`unsafe`/`reflect`/`math/rand`/`crypto/rand`/`path/filepath`/`log`/`plugin`/`embed`；封死未登记 `foundation/*` |
| `core/internal/{pool,gate}` | `base` | `sshnet/**`/`osfs` 及 `pool`<->`gate` 互导（熔断由 `engine` 经 `gate.OnHaltFunc` 接线至 `pool`） |
| `core/internal/sshnet/**` | `base`、`core/osfs`、`x/crypto/ssh` | `pool`/`gate`/`usecase`/`mcpruntime`/`engine` |
| `core/internal/usecase/**` | `base`、`pool`、`gate` | `core/osfs`、`core/internal/sshnet/**`、`mcpruntime` |
| `core/internal/mcpruntime/**` | `base`、`gate`、`usecase/**` | **物理禁引 `ports.OperatorReadFS`**（仅用 `ScopedRootFS`），禁 `osfs`/`sshnet`/`pool` |
| `core/engine` | 已登记 `core/**`（装配 `sshnet`） | **生产禁导 `core/ports/tck` 与 `core/internal/sim`**（仿真走 `*_test.go`） |
| `internal/i18n`（及 `internal/rootcatalog`） | `LayerInternalI18n`：`archbound` 放行 `core/domain/**` 与 `core/conc`（供 `cross_layer_render_test.go` 校验全领域错误渲染）、自身、17 纯内存 stdlib（含只读 `embed`）与 `go.yaml.in/yaml/v3`（生产源码实际仅依赖 `core/domain/i18n`、`core/conc` 与无环叶包 `internal/rootcatalog`）；`internal/rootcatalog` 零仓内依赖（生产仅导 `"slices"`） | `os`/`net`/`os/exec`/非确定性 `time` 符号（`Now`/`Sleep`/`Local` 等）、`host/**`/`entry/**`/`cmd/xops`/`core/{ports,events,osfs,engine,internal/**}`、`tools/**` |
| `internal/host/**` | `core/{domain,ports,osfs,conc}`、`internal/i18n`、`internal/host/**` | `core/engine`、`internal/entry/**` |
| `internal/entry/**` | `core/{domain,events,engine,conc}`、`internal/i18n`、`internal/entry/**` | `internal/host/**`、`core/osfs`、`core/ports` |
| `cmd/xops` | `internal/{i18n,host,entry}` + `core` 公开 6 包 | 业务逻辑 |

## 3. 编码规范与核心不变量

- **体量、复杂度与平台**：遵 `gofmt` 与缩写规范（ID/URL/SSH/CLI/SFTP/TCP）；**单包 prod `<= 3,000 LOC`**，**逻辑单文件 `<= 500 LOC`**，声明式 `*_spec.go`/`*_variants.go`/`*_codec.go` **`<= 800 LOC`**，**`gocognit <= 15`**；平台差异拆 `_unix.go`/`_windows.go`/`_darwin.go`/`_linux.go`。
- **类型、代数与序列化**：
  - 失败用 `(T, error)`（禁泛化 `Result[T]`）；`algebraic.Option[T]` 仅作结构体可选值字段。
  - 多态概念（`AuthMethod`/`ChallengeRule`/`NodeOrigin`/`ProxyRoute`/`ExecutionOutcome`/`ExitStatus`/`GuardrailDecision`/`StepAction`/`TransferState`/`Event`）用含 `sealed*()` 的封闭和类型，`type switch` 穷尽且安全决策必含 fail-closed `default`。
  - 域与安全值对象全字段私有、经构造器校验，以 `valid bool` 保零值最严（`Deny`/`Invalid`/`Unset`/`Disabled`）；OpenSSH 策略经 `option` 幺半群 + `ResolveEffectivePolicy` 求解，判定/风险用半格折叠。
  - `encoding/json/v2` 与 YAML：序列化 DTO 禁裸 `time.Duration`（用 `algebraic.Duration`）；私有值对象实现 `TextAppender`/`TextMarshaler`；规范输出启 `Deterministic(true)`；`SecretBox` 零编码接口触发 `json/v2` 原生拒绝。
- **并发、Actor 与作用域闭包**：
  - 唯一裸 `go` 在 `core/conc`；后台协程全用 `conc.Nursery`（`RunWait`/`RunScoped`），可取消锁用 `conc.CtxMutex`，**0 `time.Sleep` 同步**；多跳 SSH 配 `Nursery`（`RunScoped`）Watchdog。
  - `actor.DualActor` 纯内存两段式 `select`（`controlCh` 优先于有界 `acquireCh`，停机确定性收口），控制面与数据面分离。
  - 100% 作用域闭包（零 `mustclose`）：`pool.WithLease`/`WithMultiLease`、`SecretVault.WithSecret`+`SecretBox.Use`、`ScopedRootFS.WithRoot`、`OperatorReadFS.WithOperatorRead`、`gate.WithAuthorized`（标 `//xops:syncclosure`+`//xops:borrowed` 带失效哨兵）；长会话发世代句柄 `plan.ManagedHandle[K]`。
  - 嵌套序恒为 **`gate.WithAuthorized` 包裹 `pool.WithLease`**；`trace.LeaseScope` 单层不可重入（多租约走 `WithMultiLease`）。
- **能力门控、安全边界与高风险协议**：
  - `gate.Authorized[C]` 独占于 `core/internal/gate`（`valid bool`+`revoked *atomic.Bool`），仅经 `gate.WithAuthorized[C]` 签发，零逃生口。
  - `SecretBox` 单协程借用，提供 `Equal` 与 `secret.WithBytes`，销毁 `clear()` 零化（阻断日志/审计/错误/事件/YAML/计划/摘要泄露，`domain/secret` 预留 `runtime/secret` 钩子）。
  - `core/osfs` 写锁加同 `os.Root` 旁路锁 `<name>.lock`（禁锁数据文件后 `Rename`）；Windows 删锁须持锁截断 -> 解锁 -> 删除。
  - `~/.xops/run/<ProcessInstanceID>.lock` 只追加（`+<opID>`/`-<opID>`）实现 **O(1) 崩溃对账**（残留锁先 `TryLock` 确认死亡再补写 `AbortedByCrash`）；`PolicyProfileStrictAgent`（`strict_agent`）下 `*ports.AuditPostWriteError` 立即不可逆进 **`Halted` 熔断**，经 `OnHaltFunc` 吊销全部活跃 `ManagedHandle` 并拒新请求。
  - 5 大纯 Mealy FSM（`VaultSagaFSM`/`ApprovalFSM`/`TransferFSM`/`EnsureFSM`/`PendingEnrollFSM`）严守：**`OutcomeUnknown` 禁重试；`Applied && !Durable` 禁重试禁删凭据**。
  - SFTP 非截断写 + `SSH_FXP_FSTAT` `(dev,ino)` 锚定 + 原子 `posix-rename@openssh.com`；事件流分层：`events.OperationStream`（EOF）、同步 Fail-Closed `ports.AuditSink`、有界非阻塞 `events.SystemBus`。
- **全仓国际化（i18n）、结构化错误与双轨渲染**：
  - 纯数据延迟渲染：`core/` 零文案库、零运行期 `Locale`，`err.Error()`/`audit.jsonl`/`events`/`ApprovalEnvelope.Digest()`/MCP 7 工具/OpenSSH `-O`/JSON 键与 `error_code` 恒为规范英文；人类界面（CLI/TUI `L` 热切/SFTP Shell/`InteractionPort`）在展示边界经 `internal/i18n.(*Localizer)` 延迟渲染，共享唯一折叠代数 `RenderErrorChain`/`CanonicalError` 并恒满足 `enLoc.RenderError(err) == err.Error()`。
  - 生产源码禁裸 `errors.New`/`fmt.Errorf` 及硬编码汉字/全角标点，统一走 `i18n.{Sentinel,E,EF,Wrap,WrapS,WrapSentinel,WrapSentinelDetail,DynamicDetailError}`；自定义具体 `error` 须实现 `LocalizableNode`（不嵌入 `error`）；门控原因经 `core/internal/gate/internal/reasonmsg` 投影，`DoctorFinding`/`openssh.StreamDiagnostic`/`inventory.ImportWarning` 走规范英文 + 可选结构化 `Message` 双轨。
  - 启动语种优先级：`--lang > XOPS_LANG > LC_ALL > LC_MESSAGES > LANG > OS 区域 > en`（`LC_ALL=C`/`POSIX` 截断为 `en`；命令感知 `ScanPreFlags` 避拦 `ssh`/`exec` 远端参数；`--help`/`version` 零触盘）。

## 4. 自建编译器护栏（`tools/xopsvet`）与特权白名单

全仓须 0 违例通过 `tools/xopsvet` **10 大分析器**：

| 分析器 | 核心职责 |
| :--- | :--- |
| `archbound` | 强制 §2 依赖矩阵、`domain` 纯数学、`core/domain/i18n` 绝对叶包、`LayerInternalI18n` 及 `i18n` 内部叶包无环防回流（含非确定性 `time` 封禁、`corecatalog`/`rootcatalog` 生产仅 `"slices"`）、`conc`/`foundation` 纯非 I/O、`osfs` 本地 `net` 防线、`mcpruntime` 禁引 `OperatorReadFS` |
| `sumexhaust` | 封闭和类型 `type switch` 穷尽与安全决策 fail-closed `default` |
| `linearlease` | `core/conc` 唯一裸 `go`；校验 `//xops:syncclosure`/`borrowed`/`secretuse` 不逃逸 |
| `failclosed` | 零白名单；禁吞局部 `error` 返裸 `bool`（豁免纯 `errors.Is`/`AsType`）；门控零值最严（含 `atomic.Bool`） |
| `secretbox` | 禁 `SecretBox` 越权存储/匿名嵌入/接口与 `any` 擦除；强制 5 包明文白名单 |
| `secrettaint` | SSA 明文污点追踪；出参 Fail-Closed；联动 `secretfact` 封死 `i18n` 全部 49 处 `SinkError` 汇点、汇点与 `//xops:syncclosure` 强互斥及闭包 `retMask != 0` 拦截（含局部捕获型 IIFE）；仅放行精确密码学与窄子包受控钩子（`vault/*`、`sshnet/{dial,priv}`），0 `//nolint:` |
| `osboundary` | 生产禁白名单外 OS/env/exec/Unix Listen 与句柄原语（`osfs` 外禁 `windows.CreateFile`/`GetSecurityInfo`/`os.NewFile`/`unix.Fstat`；`host/sys/**` 仅放行下表窄常量 `unix.Open` 含 `O_CLOEXEC` 无 `O_CREAT`）；全仓含测试禁 `filepath.*` 处理 `RemotePath` |
| `noimplicit` | 禁 `init()`、可变包级 `var`（仅豁免接口断言、不可变哨兵含 `i18n.Sentinel` 与跨包只读重导出、`cmd/xops` 六重门控 `//xops:buildvar`、`internal/i18n` 六重门控只读 `//go:embed embed.FS`）、`trace` 外 `context.WithValue`/`Value`、匿名接口断言、白名单外 `//nolint:`、序列化 DTO 裸 `time.Duration` |
| `digestcover` | 编译期校验 `WriteCanonical` 字段完整性，零 `reflect` |
| `i18nguard` | 规则 1（`MessageID` 强类型/属主/`*WithFallback` 门控、禁 `MessageIDInvalid` 与跨域错配）；规则 2（全仓禁裸 `errors.New`/`fmt.Errorf` 与底层 `string` 自定义错误，自定义 `error` 强制实现 `LocalizableNode`，永久白名单 `{core/domain/i18n, core/conc, core/internal/sim, core/ports/tck, tools/xopsvet}`）；规则 3（生产禁 `unicode.Han` 及 `U+3000..U+303F`/`U+FF00..U+FFEF` 全角标点）；规则 4（`WrapSentinelDetail`/`DynamicDetailError` 禁非空常量、`EF`/`WrapS` 禁 `common.detail` 及安全红线/具名业务哨兵禁泛化弱模板）；规则 5（`reason`/`detail`/`op` 禁非空常量，`field`/`kind`/`component`/`feature`/`expected`/`action` 禁空白字符散文） |

### 特权白名单总表（外置 `*_test` 一律剥夺特权）

| 能力 | 唯一合法白名单包 | 生产 `//nolint:` | 测试 `//nolint:` | 替代 |
| :--- | :--- | :---: | :---: | :--- |
| 裸 OS 文件/锁/ACL/`os.Root`/本地 `AF_UNIX`/Named Pipe | `core/osfs` | 允许 | **禁** | 封入 `osfs` 过 `tck` |
| 裸 `go` | `core/conc`（`Nursery`+`CtxMutex`） | 允许 | **禁** | `conc.Nursery` |
| `context.WithValue`/`Value` | `core/internal/foundation/trace` | 允许 | **禁** | 显式参数 |
| `Getenv`/`exec`/PTY/Relay/`unix.Open`（`"/dev/net/tun"`、`"/dev/tty"`） | `internal/host/sys`（含 4 子包） | 允许 | **禁** | `core/ports` 注入 |
| 明文 `[]byte` 消费（生产 4 包） | `core/domain/secret`、`internal/host/vault`（含 5 子包）、`core/internal/sshnet/{dial,priv}` | 允许 | **禁** | 传 `SecretRef`/借 `*SecretBox` |
| 明文 `[]byte` 消费（仿真第 5 包） | `core/internal/sim`（0 生产可达，过规则 1/2） | **禁** | **禁** | 禁生产导入 |
| 链接期只读构建变量（`//xops:buildvar`） | `cmd/xops`（六重门控：`package main` 非测试未导出 `string`） | **禁** | **禁** | 转 `cli.BuildInfo` |
| 只读嵌入词库（`//go:embed embed.FS`） | `internal/i18n`（六重门控：非测试未导出单 `embed.FS`、至多 1 个、禁改禁取址） | **禁** | **禁** | 经 `i18n.LoadCatalog()` 注入 |
| 裸 `errors.New`/`fmt.Errorf`（`i18nguard` 规则 2） | `core/domain/i18n`（主包）、`core/conc`（及非生产 `sim`/`tck`/`xopsvet`） | 仅 `core/conc` 允许 | **禁** | `i18n.{Sentinel,E,EF,Wrap,WrapS,WrapSentinel*}` |

> 仅上表标「允许」的 **8 个特权包生产源码**允许 `//nolint:`；**全仓所有测试文件（含特权包白盒 `*_test.go` 与外置 `*_test`）及所有其余包（含 `cmd/xops`、`internal/i18n`、`core/domain/i18n`、`core/internal/sim`、`foundation/actor`、`tools/xopsvet`）100% 禁 `//nolint:`**。

## 5. 常见维护变更指南

| 变更范围 | 必须联动项 | 必跑验证 |
| :--- | :--- | :--- |
| **CLI / 子入口**（`internal/entry/**`、`cmd/xops`） | 守 `entry` 边界；改对外命令/参数/JSON/MCP 契约同步双语用户文档与 `skills/xops-agent/**`（§7） | `verify.go --stage=all`（可先 `--stage=root`）+ `docs:check` / `docs:build` |
| **国际化词库 / 结构化错误**（`core/domain/i18n/**`、`internal/i18n/**`） | 保持 `CoreKeys()+RootKeys()` 与 `en`/`zh` YAML 100% 双射、`CanonicalFallback`/`rootFallback` 与 `en/*.yaml` 逐字一致、叶包零仓内依赖与 `i18nguard` 规则 1–5 零违例 | `verify.go --stage=all` + `--stage=cross` + `core/domain/i18n` Fuzz |
| **`core/ports` / 适配器**（`host/**`、`osfs`、`sshnet/**`） | 同步 `core/ports/tck`、各平台实现与 `core/internal/sim` 桩 | `verify.go --stage=all` + `--stage=cross`；涉 OS 原语补原生验证 |
| **`core/` 跨模块发版** | 日常走 `go.work`（0 `replace`）；发版：打 `core/v1.x.y` Tag → 根 `go.mod` 锁 `v1.x.y` → 独立验收 | `verify.go --stage=all --gowork-off`（`make verify-release`）+ `--stage=cross` + `--stage=dst` |
| **`tools/xopsvet/**`** | 补齐 `testdata` 正负例，验全仓 0 违例无误报 | `verify.go --stage=xopsvet` → `--stage=all` + `--stage=cross` |
| **文档 / Skill / CI 脚本** | 开发文档仅简体中文；用户文档中英同步，契约变更同步 `skills/xops-agent/**` | `npm run docs:check`（涉链接加 `docs:build`）+ `test_ci_changes.py` |

## 6. 统一验证命令与测试纪律

- **契约与确定性**：`ports` 实现必过 `tck`；代数类型配属性/Fuzz；运行期与用例过单种子 DST；OpenSSH 对接 `ssh -G` 差分；三平台回归验 `cmd/xops`。
- **平台诚实原则与 VM 靶机红线**：交叉编译、跨平台 `xopsvet` 与交叉 lint 不等于原生通过；Windows（ConPTY/DACL/旁路锁/`\\?\`/Named Pipe/`GetUserDefaultLocaleName`）、macOS（`kqueue`/Keychain/`utun`）、FreeBSD 以原生 Runner/VM 为准。本地 KVM 验收若遇 **VM 磁盘满（`no space left on device`）或靶机异常，立即停止并原样回报用户，严禁擅自 SSH 清理靶机或改动环境**。
- **验证 SSOT（[scripts/ci/verify.go](scripts/ci/verify.go)）**：外层不设 `GOWORK=off`，脚本按模块管控（`xopsvet`/`core` 强制 `GOWORK=off`，根 CLI 走 `go.work`，发版传 `--gowork-off`），强制 `-race -shuffle=on -count=1` 与 0 `replace`。

```sh
# 1. 全量三模块（make verify；可加 --stage=xopsvet|core|root、--pkg）
go run ./scripts/ci/verify.go --stage=all

# 2. Windows / macOS 交叉编译、跨平台 xopsvet（go vet -vettool）与交叉 Lint（make cross）
go run ./scripts/ci/verify.go --stage=cross

# 3. DST 仿真（默认 10000 种子，make dst）与并发原语 50 轮压测
go run ./scripts/ci/verify.go --stage=dst
(cd core && GOWORK=off go test -race -shuffle=on -count=50 ./conc/... ./internal/foundation/...)

# 4. 锁 core/v1.x.y Tag 后的三模块 GOWORK=off 发布验收（make verify-release）
go run ./scripts/ci/verify.go --stage=all --gowork-off

# 5. 本地 KVM 靶机原生验收（需 ~/.config/xops-local-ci/env；macOS 由 GitHub Actions macos-latest 补齐）
./scripts/local-ci/run.sh --gate g5 --auto-power

# 6. 文档校验 / 构建与 CI 脚本单测
npm run docs:check
npm run docs:build
python3 -m unittest discover -s scripts -p test_ci_changes.py -v
```

## 7. 文档规范、Git 纪律、远端安全与汇报格式

- **文档语言规范**：开发文档仅维护简体中文（`docs/development/` 保留 `index.md`/`docs.md`/`v2-architecture-rfc.md`/`v2-implementation-plan.md`/`v2-local-multiplatform-ci.md` 5 份，历史归档于 `docs/development/archive/`）；对外用户文档（`docs/{index.md,guide/**,reference/**,troubleshooting/**}`、`docs/en/**`、`README.md`/`README_en.md`）保持中英双语同步，对外契约变更时同步更新 `skills/xops-agent/**`。
- **Git 纪律**：Conventional Commits（`feat:`/`fix:`/`refactor:`/`test:`/`docs:`/`chore:`/`ci:`）；**严禁未授权 `git push`、合并主干、强推、修改 CI 权限或绕过门禁**。
- **远端安全红线**：开发维护**不代表授权连接或操作任何真实用户主机/服务器**；SSH/SFTP/Playbook/MCP 测试须用 `core/internal/sim`、TCK 或本地沙盒桩。
- **固定汇报格式**：① 修改摘要；② 目标模块/包与受影响契约；③ 实际运行命令与真实结果；④ 未运行项及原因；⑤ 剩余风险与中文注释同步核对结果。
