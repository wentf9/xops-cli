# 公共代码与 MCP 接口解耦设计

状态：公共依赖解耦及 CLI 直接使用 core 的迁移已实现。D1 公共叶子层及 D2 SSH/SFTP 主体位于 core；旧 Go API 兼容包装已移除。已提供显式 Environment、KeySource/KeyLease、HostKeyVerifier、InputBridge，以及 ConnectPlan/PlanConnection/RetirePlan。D3 的护栏、传输/隧道状态机、文件流适配器、ports 接口和 sshexec 执行适配器已建立；运行时主体已迁到 core/mcp/runtime；CLI 的配置、凭据和 OpenSSH 宿主适配位于 internal/mcphost；本地 SSH 环境和 Windows 输入桥位于 internal/sshenv。D4 的发布协调器、原子准入、提交结果屏障、依赖连接退役及非提交任务撤销已实现。D5 的私有授权绑定、journal v1/v2 读取和原连接提交交接已实现。D6 提供独立抽取和消费者验收入口；消费者固定版本及远端下载验证记录由 xops-mcp 的 docs/reuse-baseline.md 维护。基线为 `73892b0791e3222bbd08abee1f21ed067b1c41c8`。配套消费者为 [xops-mcp](https://github.com/wentf9/xops-mcp)，其 `docs/interface-decoupling.md` 记录服务端接入要求。

当前验证入口：`go test ./internal/clicontract` 检查 CLI 配置序列化与 MCP schema，`python3 scripts/check_core.py --race` 检查多平台依赖及已迁移子树的独立模块构建。schema fixture 已与基线远端 module 对照。已迁移核心通过 Linux 独立模块 race 测试；Windows amd64 原生非 race 验证覆盖 SSH/SFTP、ports、state、transfer、sshexec 及相关 runtime 文件任务测试。Windows/macOS 依赖检查及测试交叉构建通过。macOS 原生和 Windows race 不属于本轮已获得的证据。具体凭据库集成测试位于 `pkg/adapter`，使用公开接口验证真实后端；纯 SSH 及原生 sudo 测试随实现迁往 `core/ssh`。本地消费者验证不能代替发布后的远端版本验收。

2026-10-02 的接口解耦回归修复已通过 Linux 回归、竞态检查及 Windows amd64 测试交叉编译。Windows 原生验证环境不可达，本次修复没有新增原生执行证据；先前的原生结果仅对应当时的迁移状态。

ConnectPlan 返回显式租约，普通 Close 释放引用而不关闭其他租约正在使用的连接；RetirePlan 只停止缓存复用，不能代替 ExecutionGate 的权限/版本检查。连接计划包含完整有序跳板链和来源版本，执行期间不再读取父 connector 的可变 provider。

## 1. 目标与范围

公共代码必须能够整体抽到独立 Go module 维护。目标不止是允许 MCP 注入数据库，还包括清除公共层对 CLI 配置、业务模型、具体凭据库、终端 UI、个人目录和全局输出的反向依赖。

先在本仓库规划 `core/` 公共代码子树，沿用根 `go.mod`，保持 Go 1.26+。本阶段不创建第三个仓库或嵌套 module；通过独立模块抽取检查证明边界成立。未来抽出时只迁移该子树、模块元数据与测试，调整 import path 和应用适配器，不重新设计业务接口。

首个消费者仍是 `xops-mcp`，SQLite/PostgreSQL 和 Web 业务都在消费者侧。现有 CLI/TUI、stdio MCP、HTTP MCP、SSH/SFTP 和 Windows 输入行为需要继续兼容。HTTP 隧道、SOCKS、多租户和分布式运行不属于本次解耦。

## 2. 解耦前的依赖基线

| 当前位置 | 耦合 | 处理方向 |
| --- | --- | --- |
| `pkg/mcpserver/server.go` | 依赖 config、adapter、全量配置快照，内部创建 connector | 公共 runtime 消费小接口；internal/mcphost 装配 CLI 适配器 |
| `pkg/mcpserver/guardrail/{guardrail,policy}.go` | 策略类型定义在 config，审计默认写个人目录 | 中立策略值与显式审计注入 |
| `pkg/mcpserver/tool_ssh.go` | 多次查询 Node/Host/Identity，可混合不同版本 | 一次获取一致的展示或执行快照 |
| `pkg/mcpserver/tool_transfer.go`、`http_transfer.go` | 任务只绑定 NodeID/TargetID，再次按节点取连接 | 分离目标锁、连接代际和授权绑定 |
| `pkg/ssh/errors.go` | 为 ProxyCycle 的匹配引入整个 config 包 | 错误归属下沉，调用方直接使用 core/auth |
| `pkg/ssh/credential_recovery.go` | 直接识别 credential 包的存储错误 | 中立认证错误分类，保留现有恢复策略 |
| `pkg/ssh/connector.go`、`auth.go` | 自动取 home、known_hosts、私钥路径及 SSH_AUTH_SOCK | 宿主发现环境，核心消费显式来源 |
| `pkg/ssh/client.go`、`copy_stdin_windows.go` | 默认标准流，依赖 CLI internal/terminal | 显式交互 I/O 和可取消输入桥 |
| `pkg/logger` | 接口与全局彩色输出在同包，初始化访问终端 | 仅接口和 Nop 进入公共层 |

基线 `go list -deps ./pkg/ssh` 已包含 config、models、i18n 和具体加密凭据支持。添加新的构造函数并不能消除这些编译依赖；Go 会编译同包中的所有适用文件。

## 3. 目标包边界

```text
xops-cli/cmd + pkg/tui + internal/{mcphost,sshenv} + pkg/adapter ─┐
                                     ├──> xops-cli/core/*
xops-mcp/internal/adapters/xops ───────┘

core/mcp/runtime ──> core/mcp/guardrail, policy, transfer, tunnel
core/mcp/runtime + core/mcp/sshexec ──> core/mcp/ports
core/mcp/sshexec ──> core/mcp/remotefile + core/ssh + core/sftp
core/sftp ──> core/ssh ──> core/auth + core/log + core/concurrent
```

| 目标位置 | 公共职责 | 留在 CLI 的内容 |
| --- | --- | --- |
| `core/ssh` | 连接、跳板计划、命令、提权、远端 PTY、转发与生命周期 | 本地节点解析、交互提示实现、环境默认值 |
| `core/sftp` | 子系统、文件读写、权限、原子替换、传输取消 | 命令解析、进度展示、交互 shell |
| `core/auth` | 认证来源的中立错误/值契约 | Registry、具体 vault、解锁 UI、数据库密文格式 |
| `core/log` | DebugLogger 和 Nop | 全局 logger、颜色、标准流输出 |
| `core/concurrent` | 已实际复用的并发容器 | 无关 utils，不批量搬迁 |
| `core/mcp/runtime` | 唯一 MCP 工具/schema、协议、审批执行编排 | YAML 到运行参数的转换、默认文件路径 |
| `core/mcp/{policy,guardrail}` | 策略值、评估、审批挑战、审计事件 | 数据库策略查询、管理员身份管理 |
| `core/mcp/{transfer,tunnel}` | 现有任务状态机和生命周期 | Web API、SQL 存储、用户配置解析 |
| `core/mcp/sshexec` | 共享 SSH/SFTP 执行适配器 | CLI/数据库到快照的转换 |

硬约束：`core/**` 的生产代码、测试、fixture 和生成代码不得 import 本 module 的 `cmd/**`、`pkg/**` 或根 `internal/**`；不得依赖 `xops-mcp`。可依赖标准库、子树内包和列明的第三方协议库。公共类型不得暴露 `config.Configuration`、`models.Node`、`credential.Registry`、SQL/ORM 类型或 CLI flag 类型。

核心内部实现可以使用 `core/internal/**`，应用适配器不得跨 Go internal 边界导入它。跨包使用的并发容器直接从 `core/concurrent` 导入。

## 4. CLI 直接接入与单份实现

CLI、TUI、playbook 和应用适配器直接导入 `core/ssh`、`core/sftp`、`core/concurrent`、`core/auth`、`core/log` 与 `core/mcp/*`。`pkg/ssh`、`pkg/sftp`、`pkg/utils/concurrent`、`pkg/mcpserver` 及其子包已移除；不再维护旧 Go import path、类型别名、错误重导出或构造函数兼容性。

- `internal/sshenv.Discover` 发现个人目录、known_hosts、默认私钥、SSH agent、标准流和平台输入桥。CLI adapter 与 TUI 在构造 `core/ssh.Connector` 时显式注入环境，调用方提供的选项仍可覆盖默认值。
- `internal/mcphost.Config.RuntimeOptions` 将 CLI 配置、凭据解析器、审计路径和传输设置转换为核心选项。命令直接调用 `core/mcp/runtime.NewRuntime`、`Run`、`ServeHTTP` 和 `RecoverTransfers`，并拥有关闭责任。
- stdio 每次调用获取配置视图；HTTP 与恢复操作保留启动快照语义。配置的工具期限与 HTTP 默认 deny 策略继续生效。
- `pkg/config.Configuration.Guardrail` 直接使用 `core/mcp/policy.Config`。YAML 字段和持久化格式保持不变，AuditLog 的路径展开由 CLI 宿主负责。
- 共享错误直接从 `core/auth` 使用，按 `errors.Is`/`errors.As` 匹配；不通过错误字符串跨层传递语义。
- `pkg/logger` 保留 CLI 彩色输出与 `DefaultLogger`，诊断接口和 Nop 直接来自 `core/log`。配置管理、具体凭据库和 TUI 继续归应用层所有。
- 协议与核心行为测试跟随实现；CLI 配置、凭据、OpenSSH 和终端行为在应用层验证。`internal/clicontract` 保留配置序列化和 HTTP/stdio schema 基线；纯旧 Go API 编译兼容测试已删除。

新的服务端仅从 `core/*` 导入；消费者所有生产和测试依赖图均不得包含上游应用包。

## 5. MCP 运行时的四类依赖

以下接口已定义于 `core/mcp/ports`，辅助值类型在后表中约定。`core/mcp/runtime` 已通过 WithDependencies 接入这些接口；可替换状态来源与执行后端，但动态发布协调器和异步任务的持久绑定均已接入。接口独立成包使 runtime 与 sshexec 可以共用契约而不产生 import 环。

```go
type Dependencies struct {
	State      StateSource
	Gate       ExecutionGate
	NewBackend func(context.Context) (Backend, error)
	Audit      AuditSink
}

type StateSource interface {
	DomainID() string
	List(context.Context, NodeQuery) (InventorySnapshot, error)
	Resolve(context.Context, ResolveRequest) (OperationSnapshot, error)
}

type ExecutionGate interface {
	DomainID() string
	Enter(context.Context, Admission) (Permit, error)
}

type Permit interface {
	Context() context.Context
	Snapshot() OperationSnapshot
	Binding() Binding
	Phase() Phase
	Close() error
}

type AuditSink interface {
	Append(context.Context, AuditEvent) error
}
```

| 值类型 | 必备信息与限制 |
| --- | --- |
| `NodeQuery` / `ResolveRequest` | 标签/节点选择条件；需要多个节点时一次解析，禁止处理器各自取版本 |
| `InventorySnapshot` | 同版本的节点展示字段、策略与 revision；不含凭据、私钥路径或数据库实体 |
| `OperationSnapshot` | 规范节点 ID、目标/账号、完整跳板计划、认证/提权/信任引用及版本、策略快照；无明文机密 |
| `Binding` | scope、工具名、完整规范输入摘要、有关节点/链路版本、策略版本和用途；不以全库 revision 替代依赖版本 |
| `Admission` | OperationID、Binding、快照、阶段及期限；Previous 为同一操作的内存许可交接凭证，不进入协议或日志 |
| `AuditEvent` | 原审计字段加绑定摘要、阶段、结果与是否已执行；允许重试审计写入，但不能因此重试远端操作 |

StateSource 与 Gate 必须来自同一个版本发布域。构造时检查非空且相同的 DomainID；该只读方法不得执行 I/O。返回值采取防御性复制或只读封装，Runtime 再校验；外部 MCP 请求不得直接提供快照、Permit 或内部版本凭证。

策略随快照提供，避免单独读取 Inventory 和 Policy 后拼接出不存在的组合。每个快照独立解释 `NoElicitFallback`；省略时采用公共默认 `downgrade`，不能沿用运行时启动时的 `allow`。HTTP 宿主的默认 `deny` 仍作为显式策略值传入。数据库查询均在有期限的 context 下结束；不保持数据库事务等待用户审批，也不在原来无 context 的 `GetConfig` 中临时查询数据库。

AuditSink 构造时固定，运行中不调用无同步的 `SetAuditWriter` 更换共享对象。前置审计失败禁止执行；操作完成后的审计失败保留“已执行、不可重试”语义。收尾审计使用独立且有期限的 cleanup context，不能因请求已经取消而直接丢弃结果，也不能无限等待。数据库审计使用 context；不得用不可回收的 goroutine 包裹阻塞旧 writer 来伪造取消。

## 6. 执行后端与资源所有权

```go
type Backend interface {
	Run(context.Context, Permit, string, Command) (CommandResult, error)
	OpenFiles(context.Context, Permit, string) (FileSession, error)
	Inspect(context.Context, Permit, string, InspectRequest) (FileMetadata, error)
	OpenTransfer(context.Context, Permit, string) (TransferSession, error)
	Shutdown(context.Context) error
}
```

FileSession 保留共享 SFTP 的 Do、Upload、Download、CreatePrivateExclusive 和 Close 能力，并关联 Permit 与连接租约。它不暴露共享 SSH transport，关闭时同时释放子系统和租约。`core/mcp/remotefile.Remote` 提升原接口及结果值的可见性，保留 Inspect/Upload/Download/Commit/Remove/Close、初始独占创建结果和提交结果区分。流式读写由调用者提供可取消、有期限的 I/O。

Permit 决定可以访问的节点集合、版本和阶段。只读检查 Permit 只能调用 Inspect，不能通过 OpenFiles 获取写能力。Run/OpenFiles/OpenTransfer 必须验证执行用途，不能凭 NodeID 重新读取最新配置。后端必须同时服从调用 context 和 Permit 的取消/期限，不能因调用方传入较长 context 而绕过撤销。

跨节点操作在一个快照和 Permit 下绑定完整节点集合。stdio 隧道使用可选的独立 TunnelBackend，其运行参数包含已授权快照；每条隧道仍独占连接，禁止复用普通命令/传输的物理 SSH 连接。HTTP 不注册隧道工具。

所有权统一采用“借用业务服务，独占运行资源”：

| 资源 | 所有者 | 释放规则 |
| --- | --- | --- |
| StateSource、Gate、AuditSink、DB | 宿主应用 | Runtime 只借用；停止全部 runtime 后由宿主关闭 |
| NewBackend 返回的 Backend | 对应 Runtime | 每次返回独占 handle；构造后失败也必须回收 |
| MCP 会话、任务管理器、journal 锁 | Runtime | 禁止新任务，等待/取消活跃操作，完成状态结算后关闭 |
| Permit、SFTP 子系统、TransferRemote | 发起该阶段的调用方 | 成功获得后立即注册 defer，所有返回路径释放 |
| SSH 物理池 | Backend | 子系统关闭不等于物理连接关闭；旧代际引用归零后回收 |
| 隧道 connector | 单个隧道任务 | stop/TTL/断连/runtime 关闭均停止并等待退出 |

新入口提供 `Shutdown(ctx)`；原 `Close()` 使用配置的有界关闭期限委托。停机遵循现有传输的正常等待、强制中断、最终 journal 结算顺序；不能先关闭 DB/审计或释放 journal 锁。已进入提交的任务保留独立提交期限，结果不确定时记录 unknown。

## 7. SSH 侧的最小接口改造

1. **完整连接计划**：增加 `ConnectPlan(ctx, plan)` 路径。Plan 的每一跳包含非秘密连接参数、版本化认证/提权引用和信任版本。旧 `Connect(ctx, nodeID)` 由 legacy provider 转换；新路径不会按节点递归查询可变配置。提权及认证后的版本校验同样使用绑定视图，不能意外调用全局 provider。
2. **机密解析**：继续使用独立 SecretResolver 思路，请求绑定节点、目标、用途和版本。服务端凭据读取按版本返回或明确拒绝，不回退到最新凭据；无隐式 remember 写入。
3. **私钥来源**：注入 KeySource，返回具有 Signer 与 Close 的 KeyLease。数据库适配器解密/解析私钥，文件适配器接受显式路径；不把数据库私钥临时写到个人目录。所有失败/取消路径释放材料；不承诺 Go signer 内存可以全部确定清零。
4. **主机信任**：注入 HostKeyVerifier，参数包含节点、规范主机/端口、信任版本、实际远端和 public key。核心不读取个人 known_hosts，也不自动接受未知主机。CLI 适配器选择本地文件及交互确认，服务端适配器选择其信任存储。自定义 Verify 接收握手协调器控制、且带握手期限的 context；握手超时会同时取消数据库/网络核验，不能仅关闭 SSH socket 后留下核验任务。
5. **环境发现**：SSH_AUTH_SOCK、home 展开、默认终端流由宿主解析后传入。公共文件/agent 适配器可以保留，但其路径/连接必须显式指定。
6. **错误与日志**：将 SSH 实际使用的认证错误及循环跳板错误放入中立层，调用方直接导入中立错误并保留匹配语义；DebugLogger/Nop 与 CLI 彩色输出彻底分包。
7. **交互输入**：远端 PTY/提权协议仍在核心；本地终端输入复制通过可取消 InputBridge 注入。现有 Windows duplicate handle、VT 与 pipe 取消实现先留在 CLI adapter，保留原生测试。不能用 `io.Copy(os.Stdin, ...)` 替换现有退出逻辑。sudo/su 的命令输入及交互式提权交接同样传递操作 context 和注入的 InputBridge，取消时回收输入复制任务而不关闭借用的 stdin。

认证与输入桥的签名草案如下，`cryptoSSH` 表示 `golang.org/x/crypto/ssh`。KeyRequest/HostKeyRequest 都携带前述目标和版本绑定，不能只传一个可变的节点名。

```go
type KeySource interface {
	OpenKey(context.Context, KeyRequest) (KeyLease, error)
}

type KeyLease interface {
	Signer() cryptoSSH.Signer
	Close() error
}

type HostKeyVerifier interface {
	Verify(context.Context, HostKeyRequest, cryptoSSH.PublicKey) error
}

// HostKeyVerifier 可选实现；协商前按相同目标/信任版本选择算法。
type HostKeyAlgorithmSource interface {
	HostKeyAlgorithms(context.Context, HostKeyRequest) ([]string, error)
}

type InputBridge interface {
	Start(context.Context, InteractiveIO, io.Writer) (InputCopy, error)
}

type InputCopy interface {
	Wait(context.Context) error
	Close() error
}
```

InputCopy 只关闭自己拥有的副本/取消句柄，不关闭借来的标准流；Close 中断读取，Wait 在调用期限内完成。操作结束后先停止复制，再用独立的一秒清理预算等待退出，不把已经取消的操作 context 传给清理等待；清理超时和真实错误仍返回调用方。KeyLease 的所有权从成功返回起移交调用方。每条连接的来源作用域独立，不能通过修改进程环境切换两个 runtime 的凭据或终端。

固定主机公钥的宿主可用 HostKeyAlgorithmSource 解决服务器同时提供多个主机密钥算法时的协商问题。查询使用握手协调器 context 和握手期限，并携带 NodeID、Host、Port、User 与信任版本；协商前尚无实际 Remote/Hostname。算法必须来自 SSH 库的安全支持列表，空列表、查询失败或超时均拒绝连接，不回退到默认列表。RSA 公钥应选择 rsa-sha2-512/rsa-sha2-256。算法选择不能替代 Verify 对实际公钥的精确校验；未实现该可选接口的既有宿主继续使用库默认协商。

这些接口以具体消费者需求为界，不额外提供通用插件注册器、ORM repository 框架或任意协议执行器。

## 8. 审批、更新与缓存的一致性

```text
请求校验 → 一次解析快照 → 策略评估 → 必要的受限只读检查
       → 绑定完整输入/目标/策略并审批 → 前置审计
       → Gate.Enter 最后校验并登记 → 绑定连接执行 → 后置审计/释放
```

审批前不取得可变更远端的资源。先按策略拒绝明确禁止的请求；传输路径规范化所需的、允许进行的远端元数据查询使用短期只读 Permit，随后按检查结果重新评估规范路径并审批。不得持有该 Permit 等待用户回复。

Gate.Enter 与节点变更发布在同一短临界区内对“比较依赖版本并登记操作”排序。网络连接和数据库 I/O 不在该临界区执行。审批后、Enter 前的目标/身份/信任/策略变化导致明确的 stale binding 错误；重新解析与审批，不自动换目标执行。

数据库写入采用“阻止受影响的新准入 → 有期限事务 → 发布新视图并标记旧连接代际 → 恢复准入”。事务失败解除屏障；已提交但发布失败保持屏障并重新加载，不盲目重做变更。仅在事后异步发送失效事件不足以保证该语义。

普通编辑只影响之后准入的工作；已经准入的任务继续使用原目标，不跳到新目标。禁用/删除/凭据或信任撤销会停止新准入，并取消尚未提交的相关活动任务。远端已经开始的命令不能保证回滚，取消必须如实报告结果边界。

| 标识 | 定义 | 改动规则 |
| --- | --- | --- |
| NodeID | 稳定业务 ID | 编辑地址/用户名不改变；删除后不复用 ID |
| TargetID | 当前规范地址、默认端口和账号的目标锁键 | 保留既有语义；不包含凭据版本或 NodeID |
| ConnectionKey | scope、完整有序链、目标、认证/提权/信任版本 | 有关变更进入新代际；共享身份/跳板影响所有依赖节点 |
| Binding | 完整输入、规范节点集合、有关版本与策略版本的摘要 | 审批、执行、异步任务分别验证；不写入公开 schema |

只修改显示别名/标签时，是否改变 Binding 由该字段是否参与策略决定；不以全库 revision 让所有连接和审批失效。失效是引用管理：旧连接停止分配给新任务，活跃引用按完成/撤销策略退出；不通过全局 CloseAll 实现单节点编辑。

## 9. 异步传输与持久化兼容

准备、HTTP claim、上传提交、恢复/清理都需要绑定视图，不能只在 prepare 时校验。`transfer.Spec.TargetID` 继续负责目的地锁；Record.Authorization 另外持久化私有 Binding 和无秘密的版本引用。

- RequestDigest 继续表示原请求输入，保证同一 requestID 的幂等含义；另存 Binding，不能把“当前版本”混入原摘要后悄悄重建任务。
- 重试准备返回原任务。绑定失效的 ready 任务失效并拒绝新数据凭证；completed/unknown 的结果不因配置变更被重置。
- Claim 与 Gate 的执行准入共同通过后才能创建 SFTP 写能力；版本冲突不把旧 Token 用在新目标。
- 提交使用 Gate 的短期提交预约，与禁用/撤销排序；预约成功后的 journal 意图入盘区间也视为不可承诺取消的提交阶段。预约失败不发 rename；journal 入盘失败不发 rename并释放预约；超时或状态写入不确定时保持原有保守恢复规则。
- 只有提交预约和 BeginCommit 的持久化意图均成功才发送 rename。实际发送后保持独立 commit deadline；中断确认失败记录 unknown，禁止报告安全取消或自动重试。
- journal 升级到带明确版本的新格式。v1 记录仍可读取状态与维护 unknown 锁；缺少绑定的未完成任务不得按当前节点重放。未来未知版本应拒绝启动，不覆盖文件。
- recovery/cleanup 使用记录中的目标身份。无法证明仍是原目标或旧节点已删除时保留记录和阻断，不连接当前同名节点删除文件。使用新凭据进行恢复须明确授权并重新验证原目标。
- `transfer.Store` 虽已有接口，但没有 context；本轮沿用本地 journal，不直接将它实现为数据库查询。SQL 任务存储作为独立阶段设计。

Gate 只协调版本/撤销顺序，传输 manager 继续唯一拥有任务状态机和结果判定；不能各维护一份提交状态。

## 10. 实施拆分与退出条件

| 顺序 | xops-cli 工作 | 消费者/验收 |
| --- | --- | --- |
| D1 基线与叶子层 | 记录导出 API/schema；移动 logger 接口、实际公共容器、中立策略/错误；应用直接导入 core | 依赖图无反向依赖 |
| D2 SSH/SFTP | 移动唯一实现；显式凭据/信任/环境/输入桥；新增绑定 Plan 路径 | 非 CLI adapter 真实直连/跳板/提权/SFTP；CLI 行为和原生 Windows 回归 |
| D3 MCP 核心 | 移动 handlers/协议/状态机；注入 State、Gate、Backend、Audit；CLI 宿主独立装配 | 保持 HTTP/stdio 工具契约；启动失败和关闭顺序可控 |
| D4 动态视图 | 版本准入、连接代际、审批绑定、更新屏障 | 屏障控制的竞态测试，覆盖共享身份/跳板与撤销 |
| D5 持久任务 | prepare/claim/commit/recovery 接缝与 journal 双版本读取 | 旧格式 fixture、未知提交保护、撤销/提交交错 |
| D6 消费与抽取 | 不依赖 CLI 的公共测试夹具；独立模块抽取检查 | xops-mcp 改用 core 新入口，保持固定 module 版本 |

每步保持可构建和可回归；不能一次移动后留下多周不可编译状态。D3 可先使用保持旧语义的静态适配器；D4/D5 完成前新入口不宣称支持 Web 即时修改。数据库实现不塞入本轮上游改造。

## 11. 可抽取验收

1. 对 Linux/Windows/macOS 的 `core/...` 生产包和测试包进行 `go list -deps` 检查，禁止任何子树外的本仓库依赖；包含 build-tag 特定代码。
2. 静态检查 core 内的个人目录/环境发现、全局打印、默认标准流和隐式文件写入；显式 file/stdio transport 可以保留，路径或流必须由调用者提供。
3. 在临时目录仅复制 core、其 fixture 与许可证；生成独立 go.mod，把子树内部 import 前缀统一重写为测试 module，执行 tidy、build、test。禁止 `replace` 回原仓库，禁止 require 原 xops-cli module；核验最终依赖图与模块列表。
4. 核心单元测试、竞态测试及实际 SSH/SFTP fixture 随公共代码运行；需要 CLI 配置的应用集成测试留在根仓库，不混入核心。
5. 保留 CLI 全量 build/test/lint、MCP HTTP/stdio 契约及涉及的原生平台 gates；跨编译与原生运行分别报告。
6. xops-mcp 仅保留 core 消费测试；Linux/Windows/macOS 的全量生产与测试依赖图均禁止引入上游 core 之外的包。仍通过真实远端模块版本验证，不用本地 replace 代替发布验收。

抽取检查通过的含义是源码依赖闭合，不自动承诺 ABI、数据库、高可用或所有 OS 的实际运行支持。未来公共仓库建立后，CLI 与新服务的 adapter 升级依赖即可；避免公开 API 混用旧/新 module 中两套同名具名类型，必要时进行一轮协调版本升级。

## 12. 当前运行时接入与待办

公共 Runtime 通过 `WithDependencies` 接收 State/Gate/Backend factory/Audit，构造时校验发布域、策略和超时，部分构造失败也回收后端。普通 SSH/SFTP 工具一次解析快照并在审批后进入 Gate；库存列表返回同一次读取的展示和策略视图。NewRuntime 不加载 CLI 配置，不创建全局日志，不发现个人凭据或标准流。

HTTP 默认采用 `HTTPOptions.ToolTimeout`，公共 stdio 运行时默认工具期限为 5 分钟。`WithToolTimeout` 可显式覆盖两种模式的工具期限，不受选项顺序影响；HTTP 请求、SDK 中间件和工具处理器统一使用该有效值，并保留调用者更早的期限。请求体、流空闲、GET 会话以及文件传输和提交的期限仍独立配置。

动态宿主可使用 core/mcp/state.Coordinator 同时提供 StateSource 和 ExecutionGate。持久任务已接入同一准入域；数据库事务、稳定版本生成、凭据与信任存储仍由服务端适配器负责。

D4/D5 已覆盖更新屏障、数据库提交后发布/故障保持、连接代际回收、准备时持久绑定、claim/commit/recovery 原绑定校验和 journal 双版本读取。服务端数据库/Web 产品属于后续阶段；消费者依赖版本及升级验收由 xops-mcp 单独记录。

协议与网络测试已经随实现移到 core；具体凭据库及 OpenSSH 语义的测试留在应用层，通过公开 MCP 入口验证。Python 客户端唯一源码位于 core/mcp/transferclient，scripts/mcp/transfer.py 是保持单文件下载兼容的生成产物。修改源码后执行 `python3 scripts/check_core.py --sync-client`；抽取检查验证产物同步，并在独立模块中运行 Go 与 Python 测试。

## 13. 已实现的发布协调器

core/mcp/state.Coordinator 持有完整、不可变的状态视图。BeginUpdate 在数据库事务前暂停受影响节点的新准入，同时保留无关节点可用；BeginPersistence 标记提交结果可能不确定的边界。已知成功调用 ConfirmCommit，明确未应用调用 ConfirmRollback；结果不确定时保留屏障，先读取权威存储再作结论。Abort 只允许在持久化尝试前执行。

Publish 将状态发布、准入版本比较和执行登记按同一个内存锁排序。旧连接退役回调在锁外执行；回调或发布失败时 Pending 保持为 true，不能重复数据库事务，也不能解除受影响节点的屏障。确认已提交候选与存储一致后，可使用新的期限重试 Publish。Snapshot 是管理视图，可能包含已提交但仍待激活的版本。

普通地址编辑允许已准入操作继续使用旧目标；认证/信任变化、节点禁用或删除、策略变化会取消相关的非提交许可。已经准入的提交许可保留自己的期限，不能被普通配置发布误报为安全取消。此规则只协调许可，传输状态机仍负责远端结果判定，不能把它当作回滚保证。

共享跳板的认证、信任和连接参数在所有完整计划中保持一致，包括只存在于 Plan.Hops、没有独立 Targets 条目的跳板。初始化和发布都比较每个重复跳板身份；不能只更新一个依赖计划。新状态若遗漏依赖计划的更新会被拒绝；禁用跳板使下游节点不可用。已删除 ID 在协调器生命周期内不能复用，数据库适配器还须保证跨重启的不可复用性。墓碑校验覆盖活动计划中的每一跳；禁用节点可保留历史计划，但再次启用前必须移除所有已删除跳板引用。

缓存退役覆盖“准入已通过，但尚未建连”的窗口：旧操作可以完成，但新建的旧代际连接使用临时租约，不重新进入缓存。退役历史有上限；达到上限后该 connector 的新代际使用非缓存租约，避免忘记退役记录。

已增加同步屏障测试和真实 MCP/SSH 测试，覆盖审批后改目标、已准入调用不被重定向、持久化不确定、提交后发布失败、共享跳板旋转、撤销与提交许可、无锁网络退役回调、显示信息变更、别名/ID 冲突及容量回收。文件传输准备和隧道创建已读取调用时的策略，并在审批后重新准入；ready 文件任务在 claim/commit/recovery 时也校验持久绑定。

CLI 宿主适配器的隧道改由 TunnelBackend 执行。Enter 只冻结一次配置，同时用于绑定复核和私有 Permit context 中的拨号来源；后端据此创建独占 connector，不保留启动时的 runner 快照，也不在拨号前重新读取可变 Repository。配置更新后的新请求使用新视图，准入后的普通编辑不重定向旧请求。凭据来源保留在适配器私有上下文，不进入公开 OperationSnapshot。

隧道列表的完整处理链使用调用方 context 和同一个工具期限。已有任务的规范节点 ID 可直接识别，即使该节点已停用/删除；别名仍按当前库存解析。筛选结果在审批前固定，并按当前 metadata 策略授权，历史识别不授予执行权限。


## 14. 持久任务和提交交接

Runtime 用 PrepareBound 写入 v2 私有 journal，保存原始 OperationSnapshot 与 Binding；公共 Spec/Status 和 MCP schema 不增加内部版本字段。RequestDigest 只表示原客户端输入，Binding 的 InputDigest 包含规范路径、大小、摘要、覆盖标志和目标等最终 Spec。认证/提权版本按 base64 无损落盘，支持旧适配器使用的二进制 CAS 值；快照不存明文凭据。

完整持久记录上限为 64 KiB，包含授权快照。准备时额外按临时路径、最长状态名、时间戳、字节数、校验和及三个诊断字段的最大编码大小预留空间，不能只检查 ready 的大小。错误、警告和人工结算原因分别有 4096 字节的 JSON 内容预算；系统诊断安全截断，人工原因超限则拒绝。Manager 与 Journal 共用编码校验；超限或格式错误在调用 Store.Save 前返回，不会锁死存储或留下新任务。实际 Save 返回错误仍可能代表写入已生效，因此继续阻止新变更直到恢复。历史记录若已占满空间，启动时保留原磁盘证据并在内存中分类为 expired/failed/unknown，返回相应 warning；不会重放任务或丢失 unknown 目的地锁，也不会因此阻止整个服务启动。

准备重试先读取原记录。ready 记录必须重新准入才能轮换短期凭证，失效绑定只使 ready 失效；completed/unknown 等原结果保持不变。数据请求先通过原绑定的 TransferStart 准入，再 ClaimBound；旧 Token 无法对当前同名节点执行。

OpenTransfer 返回拥有原 SFTP 子系统与连接租约的 TransferSession。上传验证完成后先取得独立 Commit 许可，再由 Lease.ReserveCommit 在传输管理器的取消锁下完成预约，通过 TransferSession.ReserveCommit(ctx, permit) 在同一会话上交接权限，最后调用 BeginCommitBound 将意图入盘；全部成功才发送 rename。ClaimBound 单独接收原始请求 context 与流许可：预约完成前的任务取消、请求取消或期限耗尽都会阻止提交，预约完成后取消返回无法确认取消。不能因流许可在配置发布时被撤销，就把它等同于预约前的客户端取消。预约后的撤销不取消已准入提交，也不会重新认证或重建旧连接。流许可不能提交，提交许可不能再上传。

提交准入通过 Admission.Previous 携带当前 TransferStart 许可，在同一协调器内校验其归属、OperationID、Binding、存活状态和阶段，再原子替换原名额为 Commit。满容量时仍可交接，不能按可重复的操作 ID 放宽并发上限。旧许可在成功交接后失效，其 Close 不会释放新名额；跨操作、跨协调器及重放均拒绝。传输结束或失败后先释放流许可，再为临时文件清理申请 Recovery 准入。journal 失败不发送 rename；发送后失去确认仍记录 unknown。

提交日志故障测试覆盖写入前失败和已写入后返回错误两种情况：均不调用远端 rename，提交许可被释放，临时文件被清理，持久状态保留为未执行提交的失败结果。

清理和远程核验使用同一原始绑定的 Recovery 许可。节点删除、改址或认证/信任/策略变化使核验与清理失败并保留证据，不连接新目标。当前不提供使用新凭据绕过旧绑定的自动恢复入口；运维应核对原始目标并人工处理。v1 的未绑定记录仍可列出、分类并人工结算 unknown，但不会获得远程执行或清理能力；未知未来版本拒绝加载而不改写文件。原 Prepare/Retry/Claim 接口保留给独立旧状态机消费者，新 Runtime 只使用有绑定入口。

DomainID 和有关版本必须在同一部署跨重启保持稳定；无关显示变更不影响执行摘要。宿主不能以每次启动随机生成的域代替部署身份。服务端版本必须包括实际凭据材料和信任变化，不能只对数据库显示字段计数。

CLI 宿主适配器为完整跳板链派生稳定的凭据依赖摘要，覆盖身份引用、登录/口令/提权凭据引用、密钥指纹、旧密码字段和实际引用的存储配置。只读 Provider 即使没有 UpdateRef，也会通过 Target.Version 参与绑定；摘要不会冒充凭据写入用的 CAS token，不保存明文凭据。域内无关存储、别名和标签不进入该摘要。引用的 ItemID 按凭据存储契约保持不可变，轮换必须产生新引用。

## 15. 消费者和发布验收

xops-mcp 的 core 消费测试位于 internal/coreconsumer，internal/legacycompat 已删除。internal/dependencycheck 检查固定远端版本和三平台全量依赖图，所有上游依赖必须位于 core。scripts/check_core_consumer.py --upstream 可在临时目录建立本地替换并执行三平台依赖检查、build、race 和 lint；替换不写入任一仓库。探针覆盖 HTTP 鉴权、工具集合、命令、文件往返、动态禁用和资源回收。

上游提交推送到可下载的远端分支后，用 --version 指定精确 module 版本完成无 replace 验收，再升级消费者 go.mod/go.sum。固定提交可通过规范 pseudo-version 消费，无需为此创建正式发布 tag。消费者 CI 验证已提交的 pin；本地联调不能代替远端下载验收。


并发容器的性能与压力验收使用 `make bench` 和 `make stress`，目标为 `core/concurrent/...`。不再提供 `pkg/utils/concurrent` 兼容入口。

CLI 直接接入迁移的回归覆盖还包括 stdio 发布后读取新库存、HTTP/恢复保留启动库存、原审计路径、具体凭据库恢复及 Windows 输入桥。历史原生平台结果不作为本次迁移的原生执行证据。

## MCP HTTP 客户端认证接口

`runtime.HTTPOptions.TokenVerifier` 可接入宿主的多 Token 存储，与固定 `Token` 配置互斥。验证器必须在传入的有界 context 内返回 `auth.TokenInfo`，使用稳定且非空的 `UserID` 标识客户端，可在 `Extra["tokenID"]` 携带凭据标识。认证错误不直接回显底层诊断。

动态认证在调用宿主前获取独立的并发额度，上限为 `MaxRequests`；额度饱和时立即返回 HTTP 429 `authentication_limit`。验证回调返回后即释放额度，后续请求解析、SSE 和工具执行不占用认证额度。普通请求与控制消息仍分别使用原有的独立通道。并发、超时释放和控制消息回归见 `core/mcp/runtime/http_auth_admission_test.go`。

SDK 按 `UserID` 绑定会话。`runtime.ClientIdentityFromContext` 返回工具请求的客户端和 Token ID；内核使用客户端 ID 作为 operation Binding 和 transfer Scope，隔离任务重试、查询和取消。固定 Token 与 stdio 的原有作用域保持不变。已有的短期传输凭据继续按原授权绑定生效；认证回调不承诺中断已经准入的工作。

验证见 `core/mcp/runtime/http_identity_test.go`，包括两个客户端、脱离 HTTP 生命周期的工具身份、文件任务隔离、空身份和错误脱敏。
