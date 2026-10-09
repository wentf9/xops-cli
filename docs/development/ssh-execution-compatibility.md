# SSH 多解释器执行与兼容性设计

状态：分阶段实施中。源码分析基线为 `c1851bc`。P1-A 已实现有限 stdin/有界输出的 command 计划与 core 执行 API，以及 CLI exec 普通命令的显式 server/Bash 选项；P1-B 首批已补齐请求期限、PTY 退出状态和 exec 显式 PTY，并提供 Linux 终端/管道的可取消输出；旧入口的计划/输出迁移、SSH CLI 新参数、其他平台原生输出桥、执行配置、MCP 扩展字段和默认值切换仍待实施。进度与限制见[实施计划](./ssh-execution-implementation.md)，已安装版本以帮助信息为准。

目标是移除普通命令对 Bash 的隐式依赖，并统一 CLI、MCP、Playbook、SFTP 命令和提权路径的执行语义。当前版本的实际用法仍以[命令执行指南](../guide/exec.md)和已安装版本的帮助为准。

## 1. 目标与边界

普通命令最终默认使用 `server` 模式：将命令字符串原样放入 SSH `exec` 请求，由服务端配置的 Shell 或设备命令解释器处理。需要特定解释器、登录环境、脚本运行或提权时，显式选择相应能力。

| 纳入范围 | 不包含的承诺 |
| --- | --- |
| 无 Bash 的 Unix、Windows OpenSSH、支持 SSH exec 的设备 | 任意 POSIX 命令自动翻译成 PowerShell 或设备命令 |
| 明确的解释器、启动方言、登录环境与 PTY 选择 | 仅凭 SSH banner、`$SHELL` 或一次 `uname` 推断所有执行能力 |
| 统一命令、脚本、Shell 会话和提权的入口契约 | SSH 协议提供 argv、cwd 或通用远端进程管理 |
| 保留现有超时、取消、输出和凭据隔离 | 断连后证明远端进程已经终止，或跨网络 exactly-once 执行 |
| 为依赖登录 Bash 的自动化提供显式兼容配置 | 执行失败后自动换解释器重新运行 |

原样发送不等于绕过服务端 Shell。SSH `exec` 的载荷是一个字符串，而不是参数数组。Unix OpenSSH 通常交给用户配置的 Shell，Windows OpenSSH 取决于 `DefaultShell` 及其命令选项，受限账号还可能使用强制命令。只支持交互式 `shell` 的设备需要单独适配，不自动通过终端输入注入命令。

## 2. 当前实现与迁移面

| 入口 | 基线实现 | 迁移要求 |
| --- | --- | --- |
| `xops exec` 普通命令 | `Client.Run` 使用 `bash -l -c`，`--no-login` 改用 `bash -c` | 支持原样发送，明确旧登录环境差异 |
| `exec --shell FILE`、exec stdin 脚本 | `RunScript` 将内容送给 `bash -l -s` 或 `bash -s` | 分离脚本解释器与脚本输入，当前 shebang 不决定解释器 |
| `exec -x` | PTY 加 `RunInteractive` 的登录 Bash；基线未传递 `NoLoginShell`，且会吞掉命令的非零退出状态 | PTY 与解释器独立，修复退出状态传播，统一登录选项的校验与生效范围 |
| `ssh HOST COMMAND` | `RunCommandWithIO` 包装 `bash -c` | 原样命令与用户 stdin 分开处理 |
| 有终端的 `ssh HOST` | `ShellWithIO` 发送 SSH `shell` 请求 | 保留服务端 Shell 语义，不额外包装 |
| 无命令且 stdin 为管道的 `ssh HOST` | 空命令路径启动 Bash 读取输入 | 显式区分非 PTY Shell 会话与已指定解释器的脚本，不能发送空 exec 请求 |
| SFTP batch `exec` | POSIX `cd 'cwd' && ...` 加 `RunCommandWithIO` 的 Bash 包装 | 同时解决工作目录引用和解释器选择 |
| SFTP interactive `exec` | 直接发送 POSIX `cd 'cwd' && ...`，没有额外 Bash 包装 | 仍有 POSIX 方言假设，不能据此宣称通用跨平台 |
| MCP `xops_ssh_run` | ports/backend 最终调用 `Run` 或 `RunWithSudo` | 解析并绑定相同的执行选项 |
| Playbook shell、ensure | `Run` 或 `RunWithSudo` | shell、check、action 使用同一份有效配置 |
| Playbook script | 本地读取文件后通过 stdin 运行 | 不把它误当作已上传并保留 shebang 的远端可执行文件 |
| sudo/su、系统探测与流式监控 | 多处独立的 Bash 或 Unix 命令假设 | 单独声明能力并迁移，不能只修改 `Run` |

主要源码入口：

- [SSH Client 与 RunConfig](../../core/ssh/client.go)、[执行与提权](../../core/ssh/execute.go)
- [提权认证协议](../../core/ssh/privilege_exchange.go)、[登录提权的引用处理](../../core/ssh/privilege_terminal.go)
- [CLI exec](../../cmd/exec.go)、[CLI SSH](../../cmd/ssh.go)、[SFTP Shell](../../cmd/sftpshell/shell.go)
- [MCP 公共 backend](../../core/mcp/sshexec/backend.go)、[CLI 宿主 backend](../../internal/mcphost/host.go)、[Playbook runner](../../pkg/playbook/runner.go)

## 3. 统一执行模型

执行流程为：调用方输入 → 配置解析 → 不可变执行计划 → 必要的策略检查/审批 → SSH 会话执行 → 结果与清理。CLI 自身的执行授权与 MCP 护栏仍是独立体系。

`core/ssh` 负责计划校验、解释器适配和会话生命周期。CLI 配置、节点模型、命令参数、Playbook YAML 与 MCP schema 的转换保留在各自入口，不向 core 引入反向依赖。现有 `Run`、`RunScript`、`RunCommandWithIO`、交互与流式方法逐步委托统一实现，避免维护多套字符串包装逻辑。

### 3.1 操作种类

| 种类 | 协议与输入 | 规则 |
| --- | --- | --- |
| Command / server | 一个 SSH exec 字符串，另有可选 stdin | 不修改命令字节，不拼接 Shell、环境或 cwd；保留必要的协议输入校验 |
| Command / explicit interpreter | 解释器适配器构造 exec 请求 | 启动方言、用户解释器和登录模式必须属于受支持组合 |
| Script | 有限脚本内容、明确解释器、可选独立运行时输入 | 不等同于多行 server 命令；脚本来源与 stdin 所有权明确 |
| Shell session | SSH shell 请求，PTY 可选 | 不把无命令输入改成空 exec，也不隐式插入 Bash |

PTY 是独立的会话属性，不意味着交互式 Shell、登录 Shell 或 Bash。`exec -x` 执行一次命令，新模型必须传播其退出状态。基线普通与提权 PTY 命令会复用忽略 `ssh.ExitError` 的 Shell 逻辑；修复该行为列为 P1 的兼容例外，并在发布说明中明确。完整登录会话沿用现有 Shell 会话契约。

“原样”以入口构造完成的命令字符串为边界：`exec -c STRING` 保留 STRING 字节；位置参数和 `ssh HOST COMMAND...` 沿用当前以空格连接参数的规则，不能恢复本地 Shell 已移除的引号或承诺远端 argv 等价。计划形成后不 trim、重新分词或规范化换行。必须保留参数是否出现的信息：显式空命令报错，不转为读取脚本或启动 Shell；未提供命令才进入相应的输入路由。

### 3.2 执行计划的语义字段

以下为逻辑模型，不冻结具体 Go 类型名称：

| 字段 | 含义 |
| --- | --- |
| 操作种类 | command、script 或 shell session |
| 命令或脚本 | 原始内容；脚本使用受控的有限输入，避免为计划构造重复无界缓存 |
| 解释器 | `server`、`sh`、`bash`、`powershell`、`pwsh`、`cmd`；仅开放已实现并验证的适配器 |
| 启动方言 | 服务端如何解析生成的启动命令，例如 POSIX、PowerShell、cmd 或 unknown |
| 登录模式 | `inherit`、`enabled`、`disabled`；未指定与显式关闭必须可区分 |
| 工作目录 | 仅已知方言/适配器可实现；没有通用 SSH cwd 请求 |
| PTY、I/O 与期限 | 是否申请终端、stdin 所有权、输出策略、取消与超时 |
| 提权 | 独立的目标身份和 sudo/su 策略，不作为解释器字符串的任意前缀 |

`server` 允许启动方言为 unknown，因为不生成命令包装。指定解释器时，解释器本身与外层启动方言是两个维度：从 cmd 启动 PowerShell，与从 POSIX Shell 启动 PowerShell 的引用规则不同。未知或未支持的组合须在用户命令发送前报错。

POSIX `shellQuote` 不作为跨平台通用函数。PowerShell 的编码载荷、cmd 的命令选项、脚本退出状态等由各适配器定义并测试；编码不改变审批对象，也不构成保密。不得把路径、命令内容或未验证的解释器参数直接拼入启动模板。

每个开放的适配器须列出启动方言、command/script、login、cwd、PTY、提权和独立 stdin 的支持矩阵；未实现的格子明确拒绝，不把“支持 PowerShell”解释为支持任意组合。首期新 Bash 适配器在未设置 login 时使用非登录模式，`sh` 只开放非登录模式；legacy 入口通过显式兼容计划保留各自原行为。Windows 适配器开放前冻结可执行文件、启动参数、profile 策略、命令长度/编码限制及退出码映射；不能把这些差异留给调用方猜测。

### 3.3 会话生命周期与 I/O 所有权

统一层必须补齐基线的取消缺口，不能把现有 `startWithTimeout` 视为已覆盖所有阻塞阶段：

- 连接、会话创建、PTY 请求、exec/shell 请求、提权握手、输入输出、执行等待和关闭均受 context 与明确期限约束。请求阶段必须在调用 `Start`/`Shell`/`RequestPty` 前建立取消路径；服务端不回复请求也必须有界返回。交互会话可采用有界的请求、网络 I/O 和关闭期限，不以短命令的总时长限制代替交互策略。
- 取消先关闭本次 channel；关闭仍阻塞时允许中断其 transport。共享连接与 ProxyJump 的其他操作可能一同受影响：仅已发送且未取得终结结果的操作标记 unknown，未发送者保持 not_started，已取得结果者保持 completed 并附加连接或清理错误。淘汰损坏连接，不能透明重放。禁止通过修改共享 TCP deadline 无意改变其他会话的执行期限。
- 明确 borrowed/owned 输入输出。调用方的标准流不得被关闭；临时文件、复制句柄、会话与桥接器由创建方关闭并汇合协程。新 I/O 接口仅接受可确定完成或可取消的 reader/writer；适配阻塞终端/管道需提供取消桥，不能用遗留 goroutine 包装任意阻塞 `Write` 来假装支持取消。
- stdin EOF 只关闭发送方向，仍读取输出并等待退出结果。stdout/stderr 必须同时消费；达到缓存上限后按已选策略继续排空或明确终止，不能因停止读取而让远端阻塞。保留原有合并输出与流式输出契约，PTY 下不承诺独立 stderr 或二进制字节透明。
- 会话退出、输出收集失败和清理失败分别记录；输出截断必须可见。关闭 transport 不证明远端进程终止，也不能解决本地输出 writer 的阻塞；这些路径各自需要取消和测试证据。

## 4. 接口与配置提案

### 4.1 CLI

新增 `--interpreter`、`--launch-dialect`，新增 `--login-shell` 控制显式解释器的登录环境。启动方言取 `posix`、`powershell`、`cmd` 或 `unknown`；缺省从配置继承，否则为 unknown，不能由本地系统或内部解释器推断。`--shell` 已表示本地脚本文件，`--login`/`-l` 已表示 SSH 用户，两者不得重用。

以下示例描述最终接口，其中普通缓冲命令的 server/Bash 路径已在 P1-A 实现；P1-B 首批还开放了具有已验收输出能力的显式 PTY；sh 与脚本的新选项仍待实现。第一个示例显式写出最终目标默认值，以便在迁移期使用：

```bash
xops exec --host alpine-01 --interpreter server -c 'uname -a'
xops exec --host win-01 --interpreter server -c 'powershell.exe -NoProfile -Command Get-Date'
xops exec --host linux-01 --launch-dialect posix --interpreter bash --login-shell -c 'printf "%s\n" "$PATH"'
xops exec --host alpine-01 --launch-dialect posix --interpreter sh --shell ./check.sh
xops exec --host linux-01 --interpreter server -x top
```

`ssh HOST COMMAND` 使用相同的解释器选项。SFTP `exec` 继承会话对应节点的执行配置，必要的覆盖入口应复用同一模型，不另设隐式探测策略。

登录选项契约：

- `--no-login` 在兼容期继续表示原有非登录 Bash；未指定解释器时显式选择兼容 Bash 路径，不重新解释为 server。
- 显式 `--interpreter bash --no-login` 等价于关闭 Bash 登录模式；与 `--login-shell` 同时出现报错。
- `--no-login` 与显式 server、PowerShell、cmd 或 sh 组合报错，避免扩展旧参数的含义。新 sh 登录选项仅在适配器声明支持时接受。
- server 仅接受登录模式 `inherit`；显式启用或禁用登录模式均报错，因为 XOps 无法保证服务端是否读取启动文件。
- PowerShell profile 加载不是 POSIX login；不借用 `--login-shell` 表示 PowerShell profile。需要支持时定义独立且可验证的适配器配置。
- `-x` 使用相同的选项解析；不再忽略已设置的登录模式。

新选项保留 presence：`--login-shell=false` 表示显式 disabled；它与 `--login-shell=true` 一样不能用于 server。未同时指定解释器的 `--login-shell` 只调整已解析且支持 login 的解释器，不隐式选择 Bash。`--no-login` 的旧兼容路径连同 POSIX 启动假设一起固定；若节点已声明不兼容方言则报错。旧入口未启用新配置时保留原启动假设，新显式 Bash 请求仍必须具备已知启动方言。

### 4.2 配置继承

默认执行配置属于 Node，而不是单独的 Host 地址。同一地址的不同账号、端口或受限登录策略可以有不同的执行环境。

普通命令的拟议优先级：显式调用参数/Playbook step → Playbook settings → Node execution → 全局 execution → 当前发布阶段的默认值。CLI 普通命令和 MCP 调用跳过不适用的 Playbook 层。脚本还需处理 shebang，解释器选择顺序见第 5 节。

解释器与其专属选项应作为一致的配置解析：覆盖解释器时，不得意外继承原解释器的 `login: true`；不兼容的显式选项报错，未显式设置的专属选项重新采用新解释器默认。启动方言仍描述服务端，不能因切换内部解释器而自动改变。

配置必须保留“字段缺省”和“显式 false”的差别。core 接收解析后的配置，不读取全局 YAML。节点配置、版本和执行计划快照保持一致；不能从长期复用连接上的可变字段临时重读执行策略。

以下为拟议的 execution 对象，可位于 Node 或全局配置；Playbook settings/step 复用其语义。YAML 使用 `launch_dialect`，MCP JSON 对应 `launchDialect`；login 缺省映射为 inherit，布尔值映射为 enabled/disabled。未支持的枚举和字段必须报错。

```yaml
# 已知 POSIX 登录环境，保留普通命令的登录 Bash 行为
execution:
  interpreter: bash
  launch_dialect: posix
  login: true
```

```yaml
# 已确认 Windows OpenSSH 使用 cmd 启动命令，用户命令交给 pwsh
execution:
  interpreter: pwsh
  launch_dialect: cmd
```

调用参数声明的方言用于选择启动适配器，不自动成为 MCP 风险分析的可信平台证据。与已发布节点能力不一致、或缺乏可信元数据时，风险判断仍按不确定方言处理或由策略拒绝；不能通过请求中填写 `posix` 获得安全前缀放行。

### 4.3 core、MCP 与 Playbook

core 增加显式执行选项，旧 `WithLoginShell` 在迁移期映射为确定的 Bash 兼容语义。旧参数与新选项存在冲突时拒绝，不能依赖 option 应用顺序改变结果。

MCP `xops_ssh_run` 可增加可选 execution 对象，ports/backend 同步传递。缺省含义跟随第 9 节的发布阶段，不根据客户端是否发送新字段猜测兼容模式。客户端不得提交内部快照、许可或绑定摘要。

Playbook settings 和 step 可增加 execution 配置；shell、ensure.check/action 和 script 都必须应用解析结果。脚本解释器明确后，禁止以 `--var` 或模板替换执行阶段的已批准语义。

Playbook 在调度前固定工作流输入：完成变量渲染、有界读取本地脚本及内容摘要，再按 node+step 解析计划；目标相关变量在相应计划形成前展开。所有目标使用同一批脚本源字节，所有重试复用计划与内容，不能每次重新读取脚本路径。ensure 的 check/action/verify 也从该快照构造；修改文件或配置需要新的工作流执行，不能改变正在运行的计划。

## 5. 脚本、stdin 与 Shell 会话

新脚本模型的解释器选择顺序为：显式调用/Playbook step 配置 → Playbook settings 中明确指定的解释器 → 受支持的 shebang 声明 → Node execution → 全局 execution。最后两层只有非 server 的解释器可作为脚本默认；Node 为 server 不阻止使用已配置的全局脚本解释器。调用或工作流显式为脚本指定 server 则报错，不能忽略显式请求继续推断。

P1/P2 未指定新执行配置的旧脚本入口始终解析为 legacy Bash，继续忽略 shebang，不提前采用新推断规则；新执行配置包括调用、工作流、节点或全局的显式配置。P3 缺省脚本采用上述新模型，没有可靠解释器时在执行前报错，不能把 server 默认当成脚本解释器。

shebang 识别采用有限白名单：首期识别已支持的 `sh`、`bash` 路径或不带额外参数的 `/usr/bin/env sh|bash`；不解析任意 Shell 表达式或 `env -S`，不自动执行任意 shebang 参数。PowerShell/cmd 脚本优先显式指定解释器。扩展名可用于诊断，不单独决定解释器。

在新脚本模型中，“没有 shebang”和“声明了不支持的 shebang”必须区分：后者在没有调用/工作流显式解释器覆盖时直接报错，不能静默落到 Node/global Bash。例如 `#!/usr/bin/python3`、`#!/bin/bash -e` 和 `env -S` 不得被当作无声明脚本。若调用/工作流显式覆盖，按所选解释器执行原字节，不从 shebang 偷带参数。

| 输入场景 | 规则 |
| --- | --- |
| 命令加 stdin | stdin 是用户数据，不用来再次包装命令 |
| `exec --shell FILE` | FILE 来自客户端；脚本字节交给指定脚本适配器 |
| 无命令的 exec 管道输入 | 继续识别为脚本，但按上述规则解析解释器 |
| 无命令、非终端的 `ssh HOST` | 显式解释器存在时按脚本处理；server 模式发送无 PTY 的 SSH shell 请求，并转发 stdin/EOF |
| 脚本与运行时 stdin 同时存在 | 适配器需要独立承载方案；没有该能力时提前报错，不把两段输入直接拼接 |

上述输入规则描述统一层能力，不自动为每个 CLI 入口开启 stdin。基线 `exec -c` 不转发管道数据；P1 保留该行为。P2 若开放其运行时输入，必须提供显式选择并更新帮助；首期仅允许单节点消费实时输入，多节点请求在分发前拒绝，不能让多个协程竞争同一 stdin。已有无命令 exec 脚本输入可以在有界读取一次后，为各目标创建独立 reader。脚本读取必须有大小上限与取消期限，超限在远端执行前报错。密码输入、脚本来源和运行时数据须在读取前确定唯一所有者；冲突组合报错，不假设密码行后剩余内容可继续作为脚本或用户数据。

无命令 `ssh HOST` 的路由须区分阶段：P1/P2 没有新配置时保持原非终端 Bash 行为；新模型按有效解释器选择脚本或无 PTY shell。终端下的原生 Shell session 不继承普通命令的 interpreter/login 配置；显式要求非 server 解释器或 login 选项时报错，不能静默忽略或暗中改成 exec。无 PTY shell 的退出状态须保留，不能套用终端登录会话忽略非零状态的策略。

PowerShell 可使用经过定义的编码载荷或临时脚本文件；应验证终止/非终止错误、原生程序退出码、Unicode 和输出编码，不宣称行为天然等同于 Bash。临时文件必须私有、唯一创建，具有取消和失败时的有界清理路径，并报告无法确认的清理结果。

脚本不做无提示的 BOM 去除、换行转换或转码。shebang 识别可忽略首行行尾 CR 以读取元数据，但不得据此修改正文。BOM、CRLF 或编码不受所选适配器支持时，提供执行前诊断；任何显式转换须在摘要、审批和执行计划形成前完成。

## 6. 提权、工作目录与内置操作

### 6.1 Unix 提权

普通命令原样执行不等于实现 Windows UAC 或设备 enable 模式。首期提权继续限定于声明支持的 Unix sudo/su 组合；root 已是目标身份时不为提权引入额外 Bash。

提权控制脚本与用户解释器分离。现有 ready/ack 控制流程主要使用 POSIX `printf`、`read`、`test`、`unset` 等能力，可研究以 `/bin/sh` 承载；PTY 交接仍要求对应终端能力，例如 `stty`。当前 `sudoLoginScript` 使用 Bash ANSI-C 字面量处理 `sudo -i` 的二次解析，不能机械改成 sh。`su -c` 也需要考虑目标用户 Shell 的额外解析。

首期保留已验证的 Bash 登录提权适配器；POSIX sh 提权需在无 Bash 环境完成独立验收后开放。用户命令在 sudo/su 之后使用已解析的目标解释器，不能假设它与登录账号的 server Shell 相同。server 加提权时，必须先解析受支持的目标执行策略；无法确定时在执行前报错。

必须保留：

1. 只在识别认证提示后发送密码，免密路径不消费密码或用户 stdin。
2. elevated-ready → ack → 必要的终端 echo 恢复 → terminal-ready → 用户输入的顺序。
3. 密码、控制帧和 ack 不进入用户命令输入，不回显或写入日志。
4. 只在确认认证被拒绝且用户命令尚未开始时重试认证；提权失败不降级为普通身份执行。
5. 超时、取消、会话关闭、输入协程退出和本地终端恢复均有确定路径。

### 6.2 SFTP 工作目录与文件操作

SFTP 的目录状态与 SSH exec 的进程目录互不关联。纯 server 模式始终拒绝自动附加 cwd，即使启动方言已知，也不能一边承诺逐字发送，一边插入 `cd`。需要继承 SFTP 当前目录的 `exec` 必须显式选定可生成工作目录操作的解释器适配器；否则在发送用户命令前报告不支持该组合。

生成的 cwd 表达式和用户命令一起进入执行计划；POSIX、PowerShell、cmd 各自处理路径与失败传播。不能在 cwd 设置失败后继续执行用户命令，也不能在缺少适配时静默忽略 SFTP 当前目录。P3 默认切换的迁移说明须包含这项限制。

纯 SFTP 的列表、复制、移动、删除和传输不要求远端 Shell。MCP 当前通过 POSIX `cp -r`、`rm -rf` 实现的文件操作，应评估迁移到共享 SFTP 文件能力；迁移需覆盖目录递归、符号链接、覆盖策略、权限错误、取消和原有护栏绑定，不能直接假设两种后端完全等价。

### 6.3 内置探测与脚本

`RunWithoutLogin`、`RunStream`、自动 sudo 检测、监控探针、TUI 日志与防火墙生成命令逐项声明解释器和平台需求，不能随普通命令默认一起漂移。

server 普通执行不自动发送 `uname`、`command -v` 等探针。确有必要的能力检查必须独立、有界且适用于已知环境，不能通过用户命令的失败结果推断解释器，也不能为了检查而执行用户命令。缓存只能绑定实际目标、身份和配置版本，不能按地址跨用户复用。

## 7. MCP 审批、错误与重试

MCP 在审批前解析并冻结：原始命令、有效解释器、启动方言、登录模式、工作目录、提权策略及相关节点版本。同一份执行计划用于风险判断、审批展示、准入、backend 执行和审计；审批之后不能重读节点默认或切换方言。

绑定必须落到现有版本与摘要路径：`ports.OperationSnapshot.Digest` 当前不摘要全局 Revision，CLI 宿主的目标版本也只包含现有连接/凭据依赖。新增 execution 字段时，须把有效 Node/global 执行配置、影响载荷的适配器版本和最终计划摘要纳入绑定，并同步 state 的变更分类与准入校验。单独变化的全局执行默认同样可能使审批失效；被节点显式覆盖的无关全局字段变化不应误失效。执行配置版本与凭据更新令牌保持独立，不能借凭据变更掩盖执行语义变化。

审批展示可读的原始命令和有效语义；最终执行载荷或其摘要也应关联同一计划。编码命令不能绕过风险检查。风险分析必须声明覆盖的方言；未知 server 方言不得套用 POSIX 安全前缀规则自动判为安全，应按明确的不确定风险策略处理。CLI Skill 继续使用 CLI，不因 core 统一而继承 MCP 审批流程。

| 失败位置 | 处理 |
| --- | --- |
| 无效配置、不支持的解释器/提权/cwd 组合 | 发送用户命令前拒绝，报告缺失能力 |
| 认证明确拒绝且用户命令未开始 | 可按既有上限重试认证；不更换命令解释器 |
| 用户命令返回非零或 127 | 原样报告失败，不推断“没有执行过” |
| exec 请求发送后连接中断、超时或退出状态丢失 | 报告执行结果不确定及已收集输出；不承诺无副作用或已远端终止 |
| 本地取消或审计/清理失败 | 保留原执行结果与附加错误，不以自动重跑修复 |

统一层须提供结构化执行结果，不能仅返回字符串错误；基线 `ports.CommandResult` 的 `Connected` 和 MCP 的 `status: failed` 不足以支持上述分类。结果至少包含计划摘要、执行阶段、`not_started`/`completed`/`unknown`、可选退出码/信号、已收集输出及截断标记、执行错误和附加 I/O/清理错误，并贯穿 core、ports、MCP 与 Playbook。退出码缺省不等于 0，`completed` 仅表示收到了终结结果，不表示成功或没有副作用。

`not_started` 仅用于能够证明用户操作未开始的路径，例如本地校验失败或服务端明确拒绝启动请求。开始发送 exec/shell 请求后即按可能执行处理，不能等 `Start` 返回成功才标记；请求响应丢失也归为 unknown。收到退出状态后若只是输出排空、审计或清理失败，保留 completed 及退出结果，并禁止因附加错误重跑。信号退出须保留信号信息；缺失退出状态不能由 EOF、空输出或断连推断成功。旧 API 可映射到带类型的 error，但不可丢失用于禁止重试的分类。

单次执行尝试只发送一次用户操作，不提供隐式 Shell 回退。Playbook 中用户显式配置的 `retries` 是独立策略，不属于兼容性回退；每次重试使用同一有效解释器，已发送后结果不确定的失败不得被普通重试循环自动重放，需调用方核验后明确处理。网络和 Shell 协议不提供跨故障 exactly-once 保证。

Playbook `ensure` 还必须区分“检查确认不满足”和“检查未可靠完成”。基线实现会把 check 的任意错误转为 action；新模型仅在收到约定且可确认的“不满足”结果时进入 action。配置错误、解释器启动失败、超时、断连及退出状态不确定均停止该 ensure。不能仅凭任意非零退出码认定“不满足”；127 等无法区分命令缺失与启动失败的结果不自动触发修改。

P2 需确定并记录检查命令的结果契约及兼容迁移：例如将依赖 `nginx -v` 报错安装软件的检查，改为在已知 POSIX 环境中用 `command -v nginx` 明确表达存在性检查。即使有预期退出码，也必须先排除执行层故障；对 server 模式无法可靠区分的情况，停止并报告检查结果不确定。检查结果分类的实现及旧 ensure 用例迁移是 P3 的前置条件。

该限制同样适用于显式解释器：`completed + exit 1` 可能来自 Bash 登录启动文件或外层包装，并不能单独证明 check 返回“不满足”。允许进入 action 的组合必须有经过验证的检查结果协议，能确认已进入 check 且状态来自 check，例如受控包装与独立结果帧；控制信息不能混入用户输出或改变普通命令的原样契约。缺少该能力时拒绝该 ensure 组合或报告检查结果不确定，不靠预期退出码白名单放行。将此能力纳入适配器矩阵，并覆盖启动文件提前退出、外层启动失败和结果帧丢失的验收。

## 8. 兼容性风险与替代方案

| 方案 | 判断 |
| --- | --- |
| 全部 `bash` 替换成 `sh` | 仍无法覆盖 Windows/设备；会破坏 Bash 脚本、登录行为及提权引用 |
| 失败后依次尝试 Bash/sh/PowerShell | 可能重复副作用，且无法从退出码可靠判断是否执行 |
| 所有请求先自动探测 OS/Shell | 增加往返与限制，探针本身也可能不兼容；不用于普通 server 执行 |
| 只增加一个 raw 开关，其余入口各自包装 | 保留入口分歧和隐式依赖，无法统一维护 |
| server 默认加显式解释器适配 | 采用；把原始命令语义与需要生成命令的高级能力分开 |

默认切换会影响 `.bash_profile`、PATH、Bash 扩展、引用、启动输出和环境变量。兼容路径是明确配置 Bash 与登录模式，不通过自动判别“旧用户”或“Linux 主机”继续隐式包装。

## 9. 实施阶段与默认值迁移

| 阶段 | 交付范围 | 缺省行为及退出条件 |
| --- | --- | --- |
| P1：统一计划与显式 server | core 统一命令/I/O/PTY 路径、结构化结果与有界取消，CLI 可显式选择 server 与 Bash；原有方法委托统一层 | 未指定新选项时保持各入口基线行为，PTY 退出状态修复除外；原样请求、请求无响应、stdin、PTY 和旧模式回归通过 |
| P2：适配器与调用方迁移 | sh、Windows 适配器、脚本、提权、SFTP cwd；MCP/Playbook 配置与绑定；ensure 检查结果分类；内置操作逐项迁移 | 解释器默认仍兼容；未支持组合明确拒绝，平台与跨入口矩阵通过，公开契约和消费者同步 |
| P3：默认切换 | 普通命令的 CLI、MCP、Playbook 和 core 缺省统一为 server；发布迁移说明 | 在明确发布版本边界启用；依赖旧行为的节点/工作流可显式固定 Bash+login；无解释器脚本不猜测 |

P3 的版本号由验收后的发布计划指定，不预先声称任何已发布版本具有新默认。旧配置缺省、旧 MCP 请求缺省与新请求缺省在同一阶段遵循相同规则；只有显式配置保留旧行为。`--no-login` 的兼容解释按第 4 节保留，不能随默认切换改变含义。

配置或 MCP schema 变化须更新 `internal/clicontract` 的序列化/schema fixture、说明和消费者适配，同时覆盖 NodeV2/全局 DTO 的读写双向转换、克隆、导入导出及缺省/显式 false 的往返测试。共享 core 消费者需验证新字段的默认和绑定语义后再升级依赖。

兼容配置须按操作种类迁移：普通命令可用 Node/global Bash+login 固定；脚本中 shebang 的优先级高于 Node/global，仅设置节点 Bash 不能保留所有旧脚本语义。依赖旧脚本行为的工作流必须在调用或 Playbook settings/step 显式配置 Bash+login，并设置已知启动方言，覆盖 shebang；例如 `exec --interpreter bash --launch-dialect posix --login-shell --shell FILE`。P1/P2 只要启用新执行配置也要遵循此规则。

默认切换回退可使用上述显式配置，或回退到已支持 execution schema 的兼容版本。基线配置读取使用 `KnownFields(true)`，新增字段落盘后直接换回不支持它的旧二进制会拒绝整份配置；更早版本回退需先恢复对应备份或受控导出兼容配置，并验证语义差异。不能把“回退发布”当作任意版本均可直接降级，也不提供运行中失败回退。

当前状态：P1-A 已完成，P1-B 首批请求/PTY 改造已实现，旧方法与输出桥迁移仍在进行中，P2/P3 待实施；P1 尚未整体完成。本文描述最终契约，当前可用的 CLI 子集及限额以[执行指南](../guide/exec.md)和实施计划为准。

## 10. 验证与验收

| 维度 | 必须覆盖的证据 |
| --- | --- |
| SSH 请求 | server 字符串逐字保持；位置参数连接边界；显式空命令与未提供命令、shell 请求、PTY 与 exec 分开验证 |
| Unix 解释器 | 真正未安装 Bash 的 BusyBox ash、dash；显式 Bash 的 login/non-login |
| Windows | 原生 Windows OpenSSH 的 cmd/PowerShell 默认环境；显式 powershell.exe/pwsh；缺失解释器 |
| 引用与数据 | 单/双引号、反斜杠、换行、Unicode、`$HOME`、`$(...)`、`%VAR%`、`&`；内外解释器组合 |
| 脚本与 stdin | shebang、未知/带参数 shebang 拒绝及显式覆盖、BOM/CRLF、空脚本、EOF、运行时输入、二进制 stdin、大小/读取超时边界；多目标与重试不重读脚本；密码与 stdin 所有权冲突 |
| SFTP | batch/interactive exec 的 cwd，带空格/引号的目录，未知方言拒绝；纯文件操作不依赖 Bash |
| 提权 | root、NOPASSWD sudo、密码 sudo、sudo-rs、su、错密码后成功、免密输入保护、`sudo -i`/`su` 多层展开 |
| PTY 与生命周期 | 分片提示、错误 ack、握手前 EOF、首字符保留、echo/raw 恢复；普通/root/免密 sudo/密码 sudo/su 的 PTY 非零与信号退出；会话/PTY/exec/shell 请求无响应；阻塞输入输出的取消；共享 transport 被中断的影响；取消后无 goroutine/session 泄漏 |
| 执行结果 | 未启动/已完成/不确定跨入口不丢失；启动请求已发送但响应丢失；缺失退出状态；成功后输出/审计/清理失败不重跑；输出截断显式呈现 |
| 副作用次数 | 命令非零、127、启动后断连/超时不换解释器重放；Playbook 显式重试与结果不确定边界；ensure.check 执行层失败、登录启动文件提前退出及结果帧丢失不触发 action |
| 跨入口 | CLI、MCP、Playbook 和宿主 backend 使用同一计划；仅 Node/global execution 变化使旧审批失效，无关全局字段不误失效；请求中的方言不能降低风险分类 |
| 迁移 | P1/P2 旧入口行为及明确的退出码例外；P3 缺省统一、命令与脚本各自的 Bash 兼容配置、旧选项冲突、schema 往返及回退版本边界；中英契约一致 |

功能实现阶段运行 `go build ./...`、`go test ./...`、`golangci-lint run ./...`，并针对 SSH/I/O/提权运行相关 race 和集成测试。公共边界验证沿用[共享 core 设计](./shared-core-decoupling.md)的隔离抽取与消费者检查。

SSH fixture 可以证明发送了何种请求，不能代替真实 Shell 的解释行为。`/bin/sh` 链接到 Bash 的机器不能作为无 Bash 验证。交叉编译和 Wine 不能代替原生 Windows OpenSSH/PTY 验收；未取得的平台证据必须明确记录。文档/schema 检查通过不代表本设计已经实现。

协议依据：[RFC 4254 §5.3、§6.5、§6.10](https://www.rfc-editor.org/rfc/rfc4254.html) 分别定义 EOF、exec/shell 请求与退出状态；[Go SSH Session 文档](https://pkg.go.dev/golang.org/x/crypto/ssh#Session.Wait) 区分退出失败、退出状态缺失与 I/O 错误；[Windows OpenSSH 配置说明](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration) 说明 `DefaultShell` 配置。这些协议能力不替代本方案要求的适配器实机验证。
