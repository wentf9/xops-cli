# SSH 执行环境探针实施记录

## 当前范围

已完成设计路线图的 **M1–M4**，包括 Core 协议、连接缓存、录入与诊断、受限操作懒加载。Core 入口为
`(*ssh.Client).ProbeExecutionConfig(ctx)`，复用已经认证的连接，无需新建 TCP 连接或重新鉴权。

普通命令执行不会因为执行失败而探测或重放。首次动态录入可在用户允许记忆凭据时单独触发录入探针；
script/ensure/cwd 的受限操作探测只缓存结果，录入探测则随新节点原子保存推荐配置。

## M4 与动态录入

- `NeedsExecutionProbe` 仅识别未指定解释器、未知方言且继承 login 的配置。任何显式解释器
  （包括 server）、已知方言或显式 login 均不会被覆盖。
- Playbook 无 shebang 的 script 可在上述缺省环境下探测；BOM、不支持的 shebang 和显式执行配置
  继续按原校验规则处理。白名单 shebang 不能证明外层方言，不额外触发探测。
- ensure 在检查之前探测并冻结配置，检查、action、复查使用相同配置。支持 bash/sh/zsh/fish，外层方言须为 posix/fish；
  Windows script/ensure 会在用户代码开始前拒绝，不做语法翻译。
- SFTP 非空 cwd 的 exec 在需要时探测。CMD 的普通推荐仍为 server，但受限操作会选用已安装的
  PowerShell/pwsh/cmd 适配器。空 cwd 的普通命令不探测。Windows SFTP 驱动器路径转换受 Windows
  适配器约束；跨平台 pwsh 使用自身 `$IsWindows` 在执行时选择路径，不依赖探测缓存，
  Linux pwsh 的 POSIX 路径不转换。`/C:` 驱动器根目录会转换成绝对路径 `C:/`。
- 缓存由物理连接的 PooledClient 共享，重新获取的 Client 包装对象也复用同一成功或失败结果。
  `CachedExecutionProbe` 不发起网络操作、不等待正在进行的探测，并返回深拷贝。
- 新增可选 Core `AuthenticatedConnectionConfirmer` 能力，在认证成功后、节点确认及凭据写入前
  接收已认证 Client，禁止保留/关闭它或执行用户命令。旧 ConnectionConfirmer 保持回退行为。
- CLI 仅在允许记忆凭据时启用 `WithEnrollmentProbing`。适配器再检查非交互、录入选项、Remember、
  pending 节点及缺省执行配置；已有节点、会话凭据、非交互批处理和显式配置均不探测。
  CLI 通过 `WithEnrollmentProbeExclusions` 按节点排除显式执行参数的目标，包括 `--interpreter`、
  `--launch-dialect`、`--login-shell` 和 `--no-login`（含显式 false）。排除不影响凭据记忆、
  正常节点录入及其他节点的探测策略；CLI 执行参数仅用于本次会话，不自动写入节点。
  认证失败不探测、不新增节点；探针失败只警告，继续原有认证成功录入。
  若底层传输已出现读写错误或关闭，Core 保留已确认节点，但返回连接错误，不记录凭据、
  不发布失效连接、不执行用户命令。该检查复用传输状态，不增加网络请求或监控 goroutine。
- `ConfirmNodeWithExecutionContext` 在原节点确认事务中加入推荐，不改变认证/提权字段版本，
  保留并发修改冲突和已应用但持久性不确定的错误语义；已确认的节点不会被后到探针覆盖。
  当前 Client 仅采用仓库实际发布的 execution，普通命令失败不重试。

M4 测试覆盖 sh-only script、ensure action/复查冻结、缓存共享、失败不派发用户代码、显式/非法脚本
不探测、Windows 拒绝 POSIX 工作流、SFTP POSIX/CMD/pwsh cwd、平台帧及动态记忆策略/原子保存。
`vm` 的真实 SFTP 批处理已验证 `/C:/Users/...` cwd 的自动探测与命令执行，退出码为 0。
M4 的 Core、adapter、SFTP、Playbook 四组相关测试已在 `vm` 原生执行，返回码均为 0；Core 组
包含原生 cmd.exe、Windows PowerShell 与 pwsh 载荷验证。其余工作流测试使用隔离 SSH 协议服务端，
不代表在 Windows 上执行了 POSIX 脚本。远端临时测试程序已全部清理。本地完整构建、全量测试、相关
包 Race 检查与全量 Lint 通过；Windows 原生回归未启用 Race。

M4 review 修复补充：断连录入回归连续运行 100 次通过；新增传输首个错误保持、失效连接不入池、
显式 pwsh 冷连接及驱动器根目录回归。`vm` 原生 Core、adapter、SFTP 回归均通过，
包含真实 pwsh 的带引号目录切换；Linux 原生 pwsh 验证同形 POSIX 路径保持不变。
测试程序及下载的便携解释器均已清理。CLI 覆盖参数回归覆盖 SSH 和交互式 exec 的
默认探测、显式参数排除、连接缓存与磁盘保存、凭据记忆及其他节点不受排除影响。
该 CLI 回归的 12 个场景在 `vm` 原生 Windows 上全部通过，临时程序已清理；新增回归的 Race、
完整构建、全量测试与 Lint 均通过。主机密钥记录使用测试专属临时文件。

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
- 单条命令最多执行 5 秒，输出上限 16 KiB。整个探测工作最多 12 秒，另预留已有执行通道
  最多 1 秒的关闭宽限期。调用者的更短 deadline 或取消优先。
- 复用 `ExecuteCommand` 的有界输出、取消与通道关闭机制，不新增后台探测 goroutine。
  对端通道无法回收时沿用现有行为，中断共享 transport，可能影响该连接上的其他任务。
- 每个 Connector 管理的 SSH 连接共享成功结果与非上下文错误的缓存，池中的 Client 包装对象共享缓存。
  并发调用共享当前尝试，等待者可独立取消；首个调用者取消或超时会结束该次尝试，
  后续调用可以在健康连接上发起一次新的有界探测。每次尝试独立持有结果与完成信号，旧等待者仍收到旧尝试的结果。非上下文错误需重新连接后才重新探测。
- 返回值为深拷贝，解释器切片与 `Login` 指针均不共享；不改变 Client 的 `Execution()`，
  不写入配置文件。调用方必须先检查错误，再使用推荐配置。
- 失败通过 `ErrExecutionProbe` 识别，可继续用 `errors.Is` 检查取消或 deadline。
  已启动探测失败时保留诊断快照；入口参数无效或等待被取消时返回 nil 快照。

## 对设计协议的修正

原设计在阶段一通过 `cmd.exe /c`、`powershell.exe -Command` 判断外层方言，但这些程序可被
另一种外层 Shell 调用，成功执行仅证明程序存在。实现改为直接要求外层 Shell 展开
`%COMSPEC%` 或 `$PSVersionTable`，并验证展开值，避免将 PowerShell DefaultShell 误判为 CMD。

PowerShell 阶段二直接执行静态 PowerShell 查询，不依赖 `powershell.exe`，支持仅安装 pwsh 的
DefaultShell。阶段一另输出 `[Environment]::OSVersion.Platform` 平台帧，明确识别 Windows_NT 或
Unix 平台；无有效平台帧时 OS 留空。Shell 路径仍留空，不凭 PowerShell 版本推断 OS 或路径。
POSIX 的 `RemoteShellPath` 来自 `$SHELL`，仅作环境元数据，不作为方言判断的唯一依据。

Review 后补充两项协议修正：POSIX 首探使用 `if :; then ...; fi` 语法保护，避免 Linux
PowerShell 7 同样支持 `$()`、`||` 且能调用外部 `printf` 时被误判为 POSIX；CMD 枚举在完整
结束帧之后显式执行 `exit /b 0`，避免最后一个可选解释器不存在时遗留 `where` 的失败退出码。
CMD 结束帧的 `echo` 使用括号包裹，避免命令分隔符前的空格进入特征帧。

CMD 保持设计推荐：存在 Windows PowerShell 时推荐 `server/cmd`，仅 CMD 时推荐 `cmd/cmd`。
PowerShell 外层优先推荐 `powershell`，仅有 Core 时推荐 `pwsh`。POSIX/fish 优先使用受支持且可用的远端默认 Shell（bash/sh/zsh/fish，ash/dash 映射 sh）；
确认 fish 方言时优先 fish，避免继承的 `$SHELL` 过期。默认 Shell 未知、不支持或不可用时才按bash → sh → zsh → fish 回退，均关闭 login；无受支持解释器时返回失败。所有成功推荐均经过 `Validate()`。

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
go test -race ./cmd/sftpshell ./pkg/playbook
golangci-lint run ./...
# 原生解释器回归测试；在目标平台运行，未安装的解释器会跳过
go test ./core/ssh -run '^TestProbeShell' -count=1 -v
```

fish ensure 使用 `function <随机结果帧名称> --on-event fish_exit` 和 `builtin printf` 输出检查退出码，保留正常退出与显式 `exit` 的语义。`exec` 替换进程或解析失败不产生结果帧，维持停止 action 的原有约束。fish 工作目录命令使用 `cd ...; and begin ... end` 保护整个复合程序。退出事件参考 [fish 文档](https://fishshell.com/docs/current/language.html#event)。

ensure 在 action 前拦截所有解释器的 126/127；fish 另拦截 121/123/124/125，防止命令展开或执行失败被当作条件不满足。显式返回保留码也采用同一保守策略。bash/sh/zsh 的工作目录载荷使用 `cd ... && { ...; }` 保护整个程序，与 fish 的条件代码块保持一致。fish 状态码参考[官方说明](https://fishshell.com/docs/current/language.html#the-status-variable)。

SFTP `exec` 通过 `ResolveWorkingDirectoryExecution` 解析本次 cwd 适配器。已保存的 `server/cmd`（含仅配置 cmd 方言）无需重新探测，临时派生 `cmd/cmd` 后应用 `cd /d` 与驱动器路径规范化，原始连接/节点配置保持不变。其余显式 server 方言不根据 `/C:` 等路径猜测平台。

CMD cwd 包装采用失败后退出的前置守卫 `cd /d "..." || exit /b & ...`。`exit /b` 不显式指定状态码，保留 cd 的失败 ERRORLEVEL；成功时跳过退出守卫，用户命令不另加括号或额外解释器层，因此 `rem` 注释、分组及显式退出码保留原有语义。已补充 Windows 原生 CMD 回归测试，并在 vm 节点用只读命令验证失败目录不会执行后续语句。退出指令参考 [Microsoft 文档](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/exit)。

CI 的探针测试按边界分层：原生 Shell 语法测试直接执行探针载荷与帧解析，不再通过本地子进程模拟 SSH 服务端并叠加生产探针预算；保留每个原生进程 10 秒的测试看门狗，移除无法跨进程保证 JIT 状态的 PowerShell 预热。状态机的总预算通过可注入执行器与 Go `testing/synctest` 虚拟时钟验证，直接使用生产总预算，不再真实等待 4.2 秒并假设第几次请求恰好超时。SSH 取消、缓存和协议错误仍由真实回环 SSH fixture 覆盖。生产 5 秒单命令/12 秒总预算保持不变。

Windows 的 Git/MSYS/WSL sh/bash 具有额外 argv 转换边界，不能充当原生 Unix 远端。Unix 解释器的原生语义测试仅在 Unix 主机运行；Linux CI 显式安装 fish/zsh，避免因缺少解释器跳过关键覆盖。Windows 客户端的 POSIX/fish 载荷仍通过真实回环 SSH 验证逐字节传输，Windows CMD/PowerShell 原生语法测试继续运行。测试失败会记录解释器绝对路径及进程耗时，便于区分执行环境与协议问题。

fish 解析错误回归使用未闭合的 `if true`，覆盖 fish 3/4 的普通与提权 ensure 路径。裸 `if` 在 Ubuntu 24.04 的 fish 3.7 中是返回状态 2 的帮助命令，不能作为跨版本语法错误样本。PowerShell 解释器枚举禁止模块自动加载：`Get-Command` 精确名称查找即使指定 `Application` 仍可能进入模块发现路径；查询期间临时设置全局 `PSModuleAutoLoadingPreference=None`，通过 `finally` 恢复原值，使用无需加载模块的 `[Console]::WriteLine` 输出帧。原生回归同时验证 PATH 程序发现、不会加载同名函数模块以及偏好恢复，不放宽现有超时。参考 [Get-Command 文档](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/get-command) 与 [PowerShell 命令发现实现](https://github.com/PowerShell/PowerShell/blob/master/src/System.Management.Automation/engine/GetCommandCommand.cs)。

Windows 主 CI 与兼容性矩阵将 `TestProbeShell*` 放在独立必跑步骤中，先于其余全量测试执行，避免原生运行时启动与其他包的 KDF/辅助进程争抢资源；全量阶段仅排除这些已经单独执行的用例。PowerShell 模块隔离回归先用正常环境启动运行时，再在待测枚举之前设置 PATH/PSModulePath，避免把 CLR 启动本身也置于缺失系统路径的环境。就绪、枚举开始和枚举结束帧可区分启动与枚举阻塞，10 秒进程看门狗保持不变。握手内部超时先于父超时的回归使用 `testing/synctest` 分别等待两个取消事件，验证 10ms/50ms 的虚拟时序及原始错误原因保留，不再用 100ms 的真实睡眠推测定时器回调已经执行。

CLI 入库探针回归分别为每次连接提供 10 秒操作预算，不再让两次独立入库共享同一截止时间；SSH fixture 使用覆盖准备及两次操作的生命周期预算，测试清理仍确定关闭连接和服务端。cmd 测试的凭据 helper 会重新执行测试二进制，race 构建默认每次退出等待 1 秒，不能把该测试运行时开销当成 SSH/凭据操作耗时。cmd TestMain 为子进程保留其他 GORACE 选项并追加 `atexit_sleep_ms=0`，CI 也统一设置此选项，与兼容性矩阵保持一致；race 检测继续启用，生产超时不变。

SFTP cwd 的 Connector 集成用例使用独立临时 known_hosts，并在清理时关闭 Connector，避免读取或修改开发者的默认信任库，也避免随机端口复用触发旧测试密钥冲突。
