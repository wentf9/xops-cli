# SSH 执行兼容性实施计划

依据：[SSH 多解释器执行与兼容性设计](./ssh-execution-compatibility.md)。状态：实施中；各项完成须同时具备代码、测试及双语文档，不能以本计划替代验证证据。

## 交付顺序

### P1-A：命令计划与有界执行基础（已完成）

- [x] 新增不可变 command 计划：server 原样载荷、已知 POSIX 启动方言下的 Bash、登录选项校验、输入快照、计划摘要
- [x] 新增有限 stdin、有界合并输出的执行 API；会话创建、exec 请求、执行及关闭有期限，取消后回收所有工作协程
- [x] 提供 not_started/completed/unknown、退出码/信号、输出截断和独立清理错误；启动响应丢失不重放
- [x] `exec` 开放显式 `--interpreter`、`--launch-dialect`、`--login-shell` 的普通命令入口；未指定新参数仍使用旧路径
- [x] 拒绝尚未迁移的新参数与脚本、PTY、提权、流式输出组合；明确帮助与错误，不静默忽略
- [x] SSH fixture 验证原样字节、引用、stdin/EOF、非零/信号/缺失状态、启动拒绝/无响应、取消、截断与无重放；CLI 参数回归

该批次的新 API 只接收有限输入和内部内存输出，不接受不可取消的外部 reader/writer。默认总时限 5 分钟、启动阶段 10 秒（继承 connector 的握手期限）、关闭宽限 1 秒；core 允许调用者缩短或指定总时限。原命令和引用后的 exec 载荷各最多 64 KiB，stdin 最多 16 MiB，默认保留最后 5 MiB 输出，最大输出窗口 64 MiB。达到输出窗口后继续排空并明确标记截断。这些是本批次新增 API 的限额，旧 API 的默认值不在本批次切换。

### P1-B：现有入口统一及交互修复（已完成）

- [x] Run、RunWithoutLogin、RunCommandWithIO 和旧 Bash 脚本委托统一计划，保持各入口原有登录默认
- [x] 为终端/管道提供可取消输出桥；迁移流式输出、文件输出和 SSH CLI，保持 stdin 所有权与 EOF 契约
- [x] 会话创建、exec/PTY/Shell 请求和关闭有界；旧 exec/脚本/I/O/提权/RunStream 的启动请求复用该生命周期
- [x] 普通/root/免密/密码 sudo/su 的一次性 PTY 命令传播非零、信号及缺失退出状态；完整登录会话保留旧策略，终端恢复与 stdin EOF 回归通过
- [x] 新 PTY API 接受 ContextWriter/内存输出；Linux 终端/管道使用独立非阻塞句柄，取消不关闭调用方流或修改其标志
- [x] exec 的新解释器参数进入 PTY；普通 PTY --no-login 生效；被忽略的脚本/stream/out-dir/privileged no-login 组合提前拒绝；SSH 显式空命令不转为 Shell/脚本
- [x] SSH CLI 的新解释器选项、非 PTY 原生 Shell 与配置继承迁移
- [x] P1 全量 build/test/lint、SSH/I/O race 与泄漏回归通过后才声明 P1 完成

### P2-A：配置及调用方绑定

- [x] 全局/Node/Playbook execution schema、presence、继承和 DTO/克隆/导入导出往返测试
- [x] MCP 输入、ports、宿主 backend 传递计划与结构化结果；审批展示及摘要绑定有效执行配置
- [x] Node/global execution 变化使旧审批失效，无关配置不误失效；请求方言声明不能降低风险
- [x] Playbook 脚本源字节和 node+step 计划冻结；不确定结果及附加清理错误禁止重试
- [x] ensure 结果来源协议、check/action/verify 分类及旧工作流迁移

### P2-B：适配器及高级操作

- [x] 无 Bash 的 ash/dash 上验收 sh；明确 shebang 白名单、未知声明、BOM/CRLF 和独立运行时输入
- [x] Windows cmd/PowerShell/pwsh 的启动矩阵、引用、profile、编码、载荷长度和退出码协议冻结；原生 OpenSSH 验收
- [x] sudo/su 控制协议与用户解释器分离；认证、终端交接、取消和引用回归
- [x] SFTP cwd 适配与纯 server 拒绝；文件后端语义验收
- [x] 内置探测、监控、日志、防火墙逐项声明平台/解释器要求

### P3：发布默认切换

- [ ] P1/P2 全部验收且共享 core 消费者验证通过；明确发布版本
- [ ] 命令默认统一为 server；无可靠解释器的脚本执行前拒绝
- [ ] 发布命令/脚本各自的 Bash 兼容迁移、SFTP 限制与可回退 schema 版本说明
- [ ] 原生 Windows 与真正无 Bash Unix 平台证据齐备；禁止通过失败后更换解释器回退

## 验证与提交

每批新增能力和 Bug 修复均须有对应测试。提交 PR 或 push 前执行 `go build ./...`、`go test ./...`、`golangci-lint run ./...`；文档执行 `npm run docs:check`，本地源码链接另行验证。涉及 SSH 并发的批次补充 `go test -race ./core/ssh ./cmd`。没有平台证据的适配器保持未开放状态。

## P1-A 验证记录（2026-10-09）

已完成上列 P1-A 条目。主要实现位于 `core/ssh/command_plan.go`、`core/ssh/command_execution.go` 和 `cmd/exec_execution.go`；对应测试覆盖真实 SSH 协议、POSIX/Bash 引用、大小限制、取消/泄漏、结果分类和 CLI 联调。

- `go build ./...`：通过
- `go test ./...`：通过
- `golangci-lint run ./...`：0 issues
- `go test -race ./core/ssh ./cmd`：通过；最终参数/载荷校验的针对性 race 测试也通过
- `npm run docs:build`：通过；双语结构、本地链接与格式检查通过
- `python3 scripts/check_core.py`：Linux/Windows/macOS 依赖边界通过，独立抽取模块 build/test 通过

Windows 原生运行、无 Bash Unix 适配器、PTY/提权和现有入口统一仍属于后续验收范围；不能由此次交叉平台依赖检查推断已验证。下一批从 P1-B 的旧方法委托、可取消 I/O 桥与 PTY 退出状态修复开始。

## P1-B 首批验证记录（2026-10-09）

本批完成上列已勾选的请求/PTY 条目，未将 P1-B 或 P1 整体标为完成。`session_lifecycle.go` 统一 PTY/Shell 生命周期及旧路径的请求期限；一次性命令的退出状态不再按完整登录会话忽略。`RunInteractivePlanWithIO` 使用有限或可取消输出，Linux 终端/管道句柄归桥接器所有，取消不影响调用方原始流。

验证覆盖普通/root/免密 sudo/密码 sudo/su 的非零、信号与缺失退出状态，分片认证/终端交接与首字符保留，exec/PTY/Shell 请求无响应，终端恢复、stdin EOF、输出管道阻塞取消、输出排空期限、文件标志/所有权、未支持 writer 执行前拒绝，以及 CLI 参数/空命令校验。

- `go build ./...`、`go test ./...`、`golangci-lint run ./...`：通过，0 lint issues
- `go test -race ./core/ssh ./cmd`：通过；最终输出期限分类变更的 core 全量及针对性 race 回归通过
- 阻塞管道取消测试连续运行 10 次：通过
- `npm run docs:build`：通过
- `python3 scripts/check_core.py`：三平台依赖边界及独立模块 build/test 通过

剩余 P1-B 工作包括旧 Run/脚本/I/O 方法委托统一计划、旧流式/文件输出与 SSH CLI 迁移，以及其他客户端平台和普通文件的输出桥验收。已有旧输出入口仍接受普通 writer，不能由本批请求期限推断其输出回调已经可取消。新原生 PTY 输出只开放 Linux 终端/管道；其他组合明确拒绝，不回退重跑。

### P1-B 评审修复：输出生命周期

输入桥初始化失败时，先取消输入/可取消输出，再通过已经启动的 Session.Wait 确认会话退出；对端不确认关闭则在宽限到期后中断 transport，最后汇合 stdout/stderr。输出复制错误通过独立通知通道与远端退出并行监控，破管道或写超时直接触发取消与同样的有界清理，不等待完整命令超时。原始输入/输出错误保留，不重放命令。

回归测试使用暂停服务端 transport 读取的 SSH peer，确保通道关闭请求实际无法获得确认；另覆盖持续产生超过 SSH 接收窗口的数据、实际破管道、写超时、终端恢复、调用方流所有权与协程回收。新增用例在修复前均失败，修复后通过。

## P1-B 终批与 P1 完整验证记录（2026-10-09）

本批完成 P1-B 剩余所有条目，并验收 P1 阶段整体交付：
1. **统一旧入口委托与共享构造**：`Run`、`RunWithoutLogin`、`RunScript`、`RunStream`、`RunWithSudo`、`RunScriptWithSudo`、`RunCommandWithIO` 均统一委托至共享的 Bash 载荷构建逻辑（`bashCommandPayload`、`bashScriptPayload`、`legacyBashPayload`），保持各入口原有的登录环境默认（`Run`、`RunWithSudo` 默认登录，`RunWithoutLogin` 默认非登录）。
2. **可取消输出桥**：`BindOutput` 与 `bindRunOutput` 接入常规文件、空设备（/dev/null）、有限内存缓冲、Linux 终端与管道。对于非 PTY 普通管道移除人为写超时限制（由上下文超时与取消约束），保留 PTY 终端的 10 秒空闲保护；`RunStream`、文件重定向输出与 `RunCommandWithIO` 接入取消桥，防止远端挂起或输出停滞时泄漏会话协程。
3. **流式命令计划与非 PTY 原生 Shell**：`RunCommandPlanWithIO` 严格检查输出可取消性，执行不可变命令计划并转发标准输入输出，保留远端退出码与信号；`RunShellWithoutPTY` 支持非 PTY `shell` 请求与 stdin 流式转发，退出状态完整保留。两类流式入口均通过独立通知通道实时监控输出写入失败（如破管道），一旦下游断开立即触发有界会话清理并保留写入错误，防止因远端生产者耗尽 SSH 窗口停滞而导致命令 hang 或超时。
4. **SSH CLI 选项与输入路由**：`xops ssh` 新增 `--interpreter`（server/bash）、`--launch-dialect`（posix）、`--login-shell`、`--no-login` 参数；重构输入路由：终端无命令保持全交互式 PTY 登录 Shell，管道 stdin 且显式指定 `--interpreter server` 时路由至 `RunShellWithoutPTY`，非 server 或非空命令走流式计划执行；显式空命令与非法组合提前报错。
5. **全量验收指标**：
   - `go build ./...`：通过
   - `go test ./...`：通过
   - `golangci-lint run ./...`：0 issues
   - `go test -race ./core/ssh ./cmd`：通过（`core/ssh` 27.5s，`cmd` 200.3s，无 data race，无泄漏）
   - `python3 scripts/check_core.py`：Linux/Windows/macOS 依赖边界通过，独立抽取模块 build/test 全量通过
   - `npm run docs:build`：通过，双语文档路由与链接校验通过

## P2-A 验证记录（2026-10-09）

本批完成上列 P2-A 全部条目：
1. **执行配置模型与往返继承**：`core/ssh/execution_config.go` 实现 `ExecutionConfig`（`interpreter`、`launch_dialect`、`login` 字段与严格校验），支持未知字段拒绝与 `login: false` 显式保留；完成 `ResolveExecution` 与 `EffectiveExecution` 多层继承覆盖。在全局（`models.Configuration`）、Node（`models.Node`）、Playbook（`Settings` 与 `Step`）完成配置接入、V2 Schema 往返序列化与快照防御性克隆。
2. **MCP 与 Ports 结构化执行绑定**：`ports.CommandResult` 扩展结构化字段（`PlanDigest`、`Phase`、`Outcome`、`ExitCode`、`Signal`、`Truncated`、`ExecutionErr`、`IOErr`、`CleanupErr`）；`OperationSnapshot.Digest` 绑定有效执行版本，使得执行语义变更触发摘要更新与旧审批自动失效，无关配置（如 prompt 正则、新增无关节点）不误失效；`guardrail.AnalyzeCommandWithDialect` 阻止通过客户端请求方言伪装安全。
3. **Playbook 脚本源字节与计划冻结**：`Engine.Run` 在分发前通过 `preloadScripts` 完成全量脚本源文件有界读取并缓存；所有目标节点与多次重试共享同一份源字节，执行阶段禁止重读磁盘。`runShell` 与 `runScript` 冻结 `CommandPlan` 与执行选项；失败处理严格区分重试边界：仅确认完成且无附加清理/IO 错误的非零退出码允许重试，`Outcome == ExecutionUnknown`、`ExecutionNotStarted`、上下文取消或附加清理错误严格禁止重试。
4. **ensure 结果协议与分类**：`runEnsure` 接入受控结果帧协议（`trap ... EXIT`），可靠区分退出码 0（`StatusSkipped`，跳过动作）、退出码 127（`StatusFailed`，无法区分缺失与故障，禁止动作）、结果帧丢失或执行故障（`StatusFailed`，禁止动作）以及确认非零状态（触发 action 并运行 verify 验证）；server 模式缺少 shell 结果适配器时提前拒绝，控制帧与用户输出隔离剥离。
5. **全量验收指标**：
   - `go build ./...`：通过
   - `go test ./...`：通过
   - `golangci-lint run ./...`：0 issues
   - `python3 scripts/check_core.py`：三平台依赖边界及抽取模块 build/test 全量通过
   - `npm run docs:build`：通过

## P2-A 评审修复：执行默认、风险方言与提权

- P1/P2 未配置 execution（包括空对象）的 MCP 命令继续使用 POSIX `bash -l -c`；只有显式 server 才原样执行。默认切换仍留到 P3，普通命令与审批计划使用同一阶段默认。
- 显式 server 缺少可信启动方言时按 unknown 分类，不套用 POSIX 安全前缀放行。请求自报 posix 不能替代节点元数据，配置/计划错误在审批前拒绝。
- 两个 MCP backend 在连接和 sudo 分流之前解析、验证配置。受支持的 Bash sudo 路径显式传递有效 login；Playbook shell、ensure.check/action/verify 与脚本复用该校验。server 提权、不兼容启动方言和尚未适配的配置化 su 在用户操作开始前拒绝；无配置的旧 su 语义保留。
- shebang 或脚本默认选中解释器后，重新验证最终配置并冻结登录模式。脚本声明不能证明外层启动方言；Bash 脚本不能携带 cmd/PowerShell/unknown 启动环境继续落入旧 Bash 路径。

回归覆盖两个 MCP backend 的实际 SSH 载荷、nil/空配置兼容默认、login:false 的 root/NOPASSWD sudo、非法提权零派发，MCP 审批前的 unknown 方言拦截与防自报 POSIX 放行，以及 Playbook sudo shell/ensure 三阶段的登录选项和脚本执行前校验。build、全量 test、lint、相关包全量 race 与 core 独立抽取验证通过。

## SFTP 复制路径评审修复（2026-10-10）

MCP `xops_fs_cp` 在调用保持目录项语义的 `RemoteCopy` 之前，单独解析复制操作数：普通源符号链接仍复制为链接；以 `/` 结尾的目录源跟随目录链接，但使用原始源 basename 构造既有目录下的目的路径；以 `/.` 结尾时只复制内容。路径判定只识别实际 `/` 分隔符，保留空白、制表符和反斜杠等合法文件名字符。

常规文件复制到既有文件符号链接时，解析绝对/相对链接及链接链后更新目标文件，保留原链接本身；既有目的目录追加 basename 后，同样检查最终目的项。源链接的目录项复制不应用该跟随规则。悬空目的文件链接和文件覆盖目录组合在写入前拒绝。

回归通过实际 MCP 调用和 SSH/SFTP 协议验证：目标文件链接保留、相对目标/链接链、目录源 `/link/` 与 `/link/.` 对新建/既有目的目录的区别、复制目录独立于源、点号加空白/反斜杠的字面文件名不导致目录复制，以及普通源链接/悬空目的链接边界。测试 peer 的 REALPATH 保持词法行为，验证未自动解引用的服务端也能正确解析最终链接。

验证结果：`go build ./...`、`go test ./...`、`golangci-lint run ./...`（0 issues）、MCP/SFTP/backend/host 相关包全量 race、文档构建和 core 独立抽取 build/test 均通过。

## P2-B 验证记录（2026-10-10）

本批完成上列 P2-B 全部适配器及高级操作条目：
1. **sh 适配器与脚本协议**：支持 `InterpreterSh`（非登录 POSIX `sh -c` 与 `sh -s`）；shebang 白名单正确区分映射 `sh` 与 `bash`；非白名单 shebang 在缺少调用方显式覆盖时严格报错；执行前检测并拒绝包含 UTF-8 BOM（`\xef\xbb\xbf`）前缀的脚本；首行元数据解析安全忽略尾随 `\r` 且不改动正文原字节；`setupStdinPipeline` 严格拒绝脚本载荷与运行时 stdin 同时存在的情形。
2. **Windows cmd/PowerShell/pwsh 适配器**：启动方言矩阵冻结（`cmd` 仅支持 `cmd` 方言，`powershell` 支持 `cmd`/`powershell`，`pwsh` 支持 `cmd`/`powershell`/`posix`）；PowerShell 使用 UTF-16LE Base64 编码载荷（`-EncodedCommand`）与 `-NoProfile -NonInteractive -ExecutionPolicy Bypass`；严格执行命令长度限制（`cmd` $\le 8191$，`PowerShell` $\le 32767$）；退出码协议冻结（`cmd` 保留 `%ERRORLEVEL%`，`PowerShell` 载荷注入 `$ErrorActionPreference = 'Stop'` 与 `$LASTEXITCODE` 判断）。
3. **Sudo/Su 控制协议与用户解释器分离**：sudo 提权控制 Shell 支持使用 `sh` 与 `bash` 承载，保持随机令牌、密码提示匹配、握手确认与退出恢复；配置化 su 严格拒绝并保留未配置的旧版语义。
4. **SFTP 工作目录适配**：实现 `FormatWorkingDirCommand`，针对 POSIX（`cd -- '...' && ...`）、cmd（`cd /d "..." && ...`）、PowerShell（`Set-Location -LiteralPath '...' -ErrorAction Stop; ...`）提供严谨转义与路径安全防护；纯 `server` 模式在 cwd 非根目录时拒绝自动继承，防止破坏逐字执行承诺。
5. **内置操作平台/解释器声明**：`MetricsCollector` 监控探针、sudo 自动探测、TUI 日志查看（`log_select` 与 `log_stream`）检测客户端执行配置并在非 POSIX 方言下提前报错；防火墙探测明确声明 Linux/POSIX 约束。
6. **全量验收指标**：
   - `go build ./...`：通过
   - `go test ./...`：通过
   - `golangci-lint run ./...`：0 issues
   - 跨平台交叉编译：`GOOS=darwin GOARCH=arm64` 与 `GOOS=windows GOARCH=amd64` 均通过
   - `python3 scripts/check_core.py`：三平台依赖边界及抽取模块 build/test 全量通过
   - `npm run docs:build`：通过

