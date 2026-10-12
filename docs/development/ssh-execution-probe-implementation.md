# SSH 执行环境探针实施记录

## 当前范围

已完成设计路线图的 **M1（Core 协议）、M2（Client 缓存）与 M3（CLI 添加/导入与诊断）**。Core 入口为
`(*ssh.Client).ProbeExecutionConfig(ctx)`，复用已经认证的连接，无需新建 TCP 连接或重新鉴权。

**待接入**：直接 SSH/exec 动态录入的凭据记忆生命周期、M4 的 Playbook script/ensure 及 SFTP cwd
懒加载。普通命令执行不会主动探测或在失败后重放；M3 对新节点持久化的推荐会参与后续配置解析。

## M3 接入与保存约束

- CLI `host add` / `host import` 默认开启探针，复用验证连接，在现有节点创建事务中保存 execution。
  导入沿用最多 16 个 worker 及同节点串行规则，警告在所有 worker 结束后按 CSV 顺序输出。
- `--no-probe` / `--probe=false` 禁用自动探针；`--skip-verify` 保证不连接、不探测。
  新节点支持 `--interpreter` / `--launch-dialect`；字段优先于推荐，不兼容时仅保存显式配置并警告。
  导入已有节点保留 execution，不触发自动重探，也不应用新节点的显式执行参数。
- `adapter.VerifyConnectionWithProbe` 区分认证错误与 `ProbeErr`，不持久化任何数据。
  `cmd/host` 决定是否使用成功推荐，探测失败不提升为认证失败。取消仍由持久化上下文阻止写入。
  探测连接通过独立的 provider 视图将目标及跳板的 execution 固定为 `server/unknown`，避免
  尚未补齐方言的显式解释器与全局配置提前合并失败。其他连接字段及 OpenSSH 回退原样委托，
  原 provider 与磁盘配置均不改写；认证、探测成功后再合并显式字段与推荐配置。
- `host probe <node-id-or-alias>` 使用已保存节点和凭据非交互式探测，默认仅输出表格。
  `--save` 通过 `Repository.UpdateNodeExecutionAtRefContext` 校验所选节点、Host、Identity 的版本，
  只替换该节点 execution，避免覆盖探测期间的并发编辑；不修改共享 Host、Identity 或凭据引用。
- 自动探测只接入 CLI 添加/导入，TUI 仍保留现有纯连接验证行为。

M3 测试覆盖连接复用（一次认证、多个 exec 通道）、成功与失败推荐（包括超时）、默认及禁用选项、
显式字段优先级、已有节点保护、保存冲突及配置隔离。添加和导入另通过真实 SSH 协议服务端验证
execution 与加密凭据均正确保存，且仅发生一次认证和两条探针 exec 请求。
另覆盖全局 POSIX 配置下添加/导入 PowerShell 节点，以及全局 Windows 配置下添加/导入 sh 节点，
均保留显式解释器、补齐探测方言且不改变全局配置。provider 单测验证目标/跳板的执行隔离与连接元数据保留。
录入测试的 HOME、USERPROFILE 与 SSH Agent 均隔离到测试环境，避免读取个人 SSH 配置、密钥与
known_hosts，或因回环端口复用造成主机密钥冲突。相关录入 Race 回归连续运行 5 次通过。

新诊断命令已在 `vm`（Windows CMD DefaultShell）运行验证，正确展示 `cmd`、
`[powershell, pwsh, cmd]` 与 `server` 推荐；该次验证未使用 `--save`。M3 的 `cmd/host` 测试程序
也在 `vm` 原生运行通过，覆盖新增添加/导入、诊断保存/冲突和真实 SSH 录入测试；远端临时程序已清理。
全局执行配置隔离修复后，四个跨方言录入回归场景及原有录入、保存/冲突测试再次在 `vm` 原生运行通过。

## API 与生命周期

- 第一阶段按 SSH banner 提示的顺序尝试 POSIX、CMD、PowerShell 外层语法。
  Banner 仅影响顺序，只有成功退出且匹配响应帧的命令才能确立方言。
- 第二阶段使用已知方言枚举 `bash`、`sh`、`powershell`、`pwsh`、`cmd`，要求完整结束帧。
  忽略普通欢迎词与 CRLF 噪声，拒绝重复帧、非法解释器、截断输出和非零退出的特征帧。
- 单条命令最多执行 2 秒，输出上限 16 KiB。整个探测工作最多 4 秒，另预留已有执行通道
  最多 1 秒的关闭宽限期。调用者的更短 deadline 或取消优先。
- 复用 `ExecuteCommand` 的有界输出、取消与通道关闭机制，不新增后台探测 goroutine。
  对端通道无法回收时沿用现有行为，中断共享 transport，可能影响该连接上的其他任务。
- 每个 Client 只执行一次探测，包括失败结果。并发调用共享该次尝试，等待者可独立取消；
  首个调用者取消会终止并缓存该次失败。重新连接后可重新探测。
- 返回值为深拷贝，解释器切片与 `Login` 指针均不共享；不改变 Client 的 `Execution()`，
  不写入配置文件。调用方必须先检查错误，再使用推荐配置。
- 失败通过 `ErrExecutionProbe` 识别，可继续用 `errors.Is` 检查取消或 deadline。
  已启动探测失败时保留诊断快照；入口参数无效或等待被取消时返回 nil 快照。

## 对设计协议的修正

原设计在阶段一通过 `cmd.exe /c`、`powershell.exe -Command` 判断外层方言，但这些程序可被
另一种外层 Shell 调用，成功执行仅证明程序存在。实现改为直接要求外层 Shell 展开
`%COMSPEC%` 或 `$PSVersionTable`，并验证展开值，避免将 PowerShell DefaultShell 误判为 CMD。

PowerShell 阶段二直接执行静态 PowerShell 查询，不依赖 `powershell.exe`，支持仅安装 pwsh 的
DefaultShell。此时不能凭 PowerShell 版本推断 Windows 或实际 Shell 路径，相关元数据留空。
POSIX 的 `RemoteShellPath` 来自 `$SHELL`，仅作环境元数据，不作为方言判断的唯一依据。

Review 后补充两项协议修正：POSIX 首探使用 `if :; then ...; fi` 语法保护，避免 Linux
PowerShell 7 同样支持 `$()`、`||` 且能调用外部 `printf` 时被误判为 POSIX；CMD 枚举在完整
结束帧之后显式执行 `exit /b 0`，避免最后一个可选解释器不存在时遗留 `where` 的失败退出码。
CMD 结束帧的 `echo` 使用括号包裹，避免命令分隔符前的空格进入特征帧。

CMD 保持设计推荐：存在 Windows PowerShell 时推荐 `server/cmd`，仅 CMD 时推荐 `cmd/cmd`。
PowerShell 外层优先推荐 `powershell`，仅有 Core 时推荐 `pwsh`。POSIX 优先 `bash`，其次
`sh`，两者均关闭 login；无受支持解释器时返回失败。所有成功推荐均经过 `Validate()`。

探针载荷只由静态常量及已有方言包装器生成，不插入节点字段、banner 或远端输出，不创建
远端文件，不请求 PTY，不做提权。后续持久化接入仍需遵守节点事务与显式配置优先级。

## 验证范围

`core/ssh/probe_test.go` 使用隔离 SSH 协议服务端验证 Linux、Alpine ash、Darwin、CMD、
PowerShell、pwsh DefaultShell、Windows banner 调度、畸形/噪声响应、失败缓存、连接隔离、
32 个并发调用的缓存与深拷贝、等待者取消、首个调用者主动取消、单命令及总流程超时和传输异常。

`core/ssh/probe_shell_test.go` 额外使用已安装的真实解释器执行载荷，通过模拟 SSH 通道验证完整
两阶段流程；未安装的解释器会明确跳过。Windows 的缺失解释器测试仅隔离子进程 PATH，分别
验证“仅 CMD”及“Windows PowerShell 存在、pwsh 缺失”时仍以 0 退出并输出完整帧。

2026-10-12 验证记录：

- Linux 本机：真实 sh、bash、PowerShell Core 7.4.6 通过两阶段测试。
- `vm` 节点：Windows 11（10.0.22631.6199）、OpenSSH for Windows 9.5，默认 Shell 为 CMD。
  将交叉编译的测试程序上传到临时目录后，原生运行 `-test.run '^TestProbe'` 全部通过；包括
  CMD、Windows PowerShell、PowerShell Core、缺失可选解释器及缓存/取消/超时测试。
  该节点未安装 sh/bash，对应原生子测试跳过。临时测试程序运行后已删除。
- 直接使用该节点现有凭据建立 SSH 连接，调用 `ProbeExecutionConfig` 成功返回 `cmd`、
  `[powershell, pwsh, cmd]`，推荐 `server/cmd`，约 196ms；再次调用复用同一时间戳的缓存。
  PowerShell 的原生测试使用子进程启动相应解释器，没有修改节点的 SSH DefaultShell。
- 本地构建、全量测试、Core Race 检查及全量 Lint 通过。

```bash
go build ./...
go test ./...
go test -race ./core/ssh ./core/testutil/sshfixture
go test -race ./cmd/host ./pkg/adapter ./pkg/config
golangci-lint run ./...
# 原生解释器回归测试；在目标平台运行，未安装的解释器会跳过
go test ./core/ssh -run '^TestProbeShell' -count=1 -v
```
