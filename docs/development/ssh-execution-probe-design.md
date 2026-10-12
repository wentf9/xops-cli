# SSH 解释器与启动方言自动探测设计

**文档状态**：M1–M4 已实现（接入条件、协议修正与验证范围见[实施记录](./ssh-execution-probe-implementation.md)）

**依据文档**：[SSH 多解释器执行与兼容性设计](./ssh-execution-compatibility.md)、[SSH 执行兼容性实施计划](./ssh-execution-implementation.md)

**语言版本**：中文开发文档


---

## 1. 目标与边界

### 1.1 背景
在 `xops-cli` P3 阶段发布后，未显式指定执行配置的普通命令默认统一采用 `interpreter: server, launch_dialect: unknown, login: inherit`。该机制使得常规命令无需额外包装即可原生直通目标服务端的默认 Shell。

然而，对于高级自动化场景：
- **Playbook `script` 步骤**：要求已知的脚本解释器适配器（如 `bash` 或 `sh`），禁止使用 `server` 模式直接运行脚本；
- **Playbook `ensure` 检查步骤**：要求非 `server` 的受控 Shell 适配器以捕获退出状态控制帧；
- **SFTP `exec` 工作目录继承**：`server` 模式显式拒绝附加 `cwd`，必须具备已知的 `posix`、`cmd` 或 `powershell` 适配器；
- **Unix 提权 (`sudo`/`su`)**：在非 POSIX 方言或未配置执行环境下被严格拦截。

若完全依赖用户手动在节点（`nodes.<node>.execution`）或全局配置中静态维护 `interpreter` 与 `launch_dialect`，维护成本高且容易因配置不匹配（如在 Windows `cmd.exe` 节点配置 `posix` 方言）导致命令乱码或执行失败。

### 1.2 目标与非承诺范围

| 纳入范围 | 不包含的承诺 |
| :--- | :--- |
| 自动识别 SSH 服务端的外层启动方言（`posix`、`cmd`、`powershell`） | 仅凭 SSH Banner、`$SHELL` 或单次 `uname` 猜测全部环境能力 |
| 自动枚举目标节点已安装的可用解释器（`bash`、`sh`、`powershell`、`pwsh`、`cmd`） | 任意跨平台命令自动语法转译（如将 POSIX 管道自动翻译为 PowerShell） |
| 首次录入节点时自动执行探针并原子持久化至 Schema V2 配置 | 在用户命令执行失败后自动更换解释器重试 |
| 提供连接级内存缓存与受控的运行时按需懒加载机制 | 探针执行无视网络超时无限阻塞 |
| 探针全流程只读、无副作用、抗 MOTD/Banner 噪声干扰 | 允许探针在远端创建临时文件或遗留孤儿进程 |

---

## 2. 总体架构与四级接入模型

为了在“零配置便利性”与“网络延迟最小化”之间取得平衡，探测机制采用**四级接入模型**：

```
Level 1: 首次录入探测 (First Enrollment) ──► 录入新节点时触发，复用连通验证连接，原子持久化至 YAML
Level 2: 主动诊断探测 (Manual Diagnostic)──► xops host probe 命令触发，终端表格展示，可选 --save
Level 3: 运行时懒加载 (Lazy On-Demand)   ──► 仅当执行 script/ensure/cwd 遇到 unknown 时触发单次探测
Level 4: 连接级会话缓存 (Session Cache)   ──► 单次 SSH Client 生命周期内全局复用结果，0 额外网络 RTT
```

### 2.1 接入层级一：节点首次录入自动探测与持久化（核心重点）
针对“节点第一次被添加”这一关键生命周期事件，提供一次性探测与持久化固化机制：

1. **显式添加路径 (`xops host add` / `xops host load`)**：
   - 现有的 `cmd/host/add.go` 在未指定 `--skip-verify` 时，会通过 `verifyInventoryNode` 验证连接与凭据。
   - **连接复用优化**：在连接验证通过后，直接复用已认证的底层 `ssh.Client` 连接，在同一会话内执行两阶段探针，**不重复进行 TCP 握手与鉴权**，仅增加 1~2 次探针命令 RTT（约 20~80ms）。
   - **配置自动持久化**：将探针推荐的 `ExecutionConfig` 直接赋值给待创建节点的 `node.Execution`，通过 `repository.CreateNodeContext` 与节点其他字段（`HostRef`、`IdentityRef`、`Tags`）一次性原子写入 `schema_v2` YAML 文件。
   - **控制参数**：
     - `--probe`（默认开启）：自动探测并持久化配置；
     - `--no-probe`：跳过探测，`node.Execution` 保持 `nil`（即使用默认 `server` 模式）；
     - 若用户显式指定了 `--interpreter` 或 `--launch-dialect`，以用户显式指定为准，跳过对应字段探测。

2. **动态即时录入路径 (`xops exec --host ...` / `xops ssh ...`)**：
   - 当用户直接向未配置的新主机发起连接时，`repository.PrepareNodeContext` 返回 `res.Created == true`。
   - 若当前运行策略启用了凭据记忆或持久化（如 `--remember` 或已配置记住策略），则在首条命令执行前执行轻量探测，将生成的 `ExecutionConfig` 随节点元数据一同固化。

3. **批量导入路径 (`xops host load`)**：
   - 导入主机列表时，在并发验证线程池内并行执行探测；
   - 探测失败的主机平滑回退为未配置状态，不阻断批量主机的整体录入。

### 2.2 接入层级二：主动管理与诊断命令 (`xops host probe`)
- 提供显式诊断命令：`xops host probe <node-id>`；
- 输出人类可读的结构化表格，展示远端操作系统、外层 Shell 路径、可用解释器列表及推荐配置；
- 支持 `--save` 标志将推荐配置更新至本地配置文件。

### 2.3 接入层级三：运行时受限操作懒加载 (Lazy On-Demand Probing)
- 仅当且仅当发生以下情况，且节点当前有效配置为缺省的 `server` + `unknown` 时触发单次懒加载：
  - 执行 Playbook `script` 步骤且脚本没有 shebang，并且未指定解释器；不自动替换不支持的 shebang 或 BOM；
  - 执行 Playbook `ensure` 检查步骤（需要受控 Shell 捕获控制帧）；
  - 执行 SFTP `exec` 且带有非空工作目录 `cwd`。
- 探测成功后仅将配置缓存在当前运行进程的内存上下文中，不自动改写静态磁盘配置文件。
- 显式解释器（包括 `server`）、已知方言及显式 login 不被懒加载替换。script/ensure 当前仅支持 POSIX bash/sh。

### 2.4 接入层级四：连接级内存缓存 (Connection-Level Session Cache)
- Client 引用受并发锁保护的探测状态，连接池中的包装对象共享同一缓存；
- 同一个连接生命周期内，探测只执行一次。后续并发任务或连续的数十个步骤完全命中内存缓存，网络开销为 0。

---

## 3. 两阶段探测协议规范

SSH `exec` 的输入为裸字符串，远端使用默认登录 Shell 解析。探测必须严格拆分为具有前后依赖的两个阶段：

```
[建立已认证连接]
      │
      ▼
┌──────────────────────────────────────────────┐
│ 阶段 1: 外层启动方言 (LaunchDialect) 判定    │
│ 目标: 确定服务端默认命令解释器规范            │
│ 结果集: posix | cmd | powershell | unknown   │
└──────────────────────────────────────────────┘
      │
      ▼ (在已知的外层语法保护下构造内层指令)
┌──────────────────────────────────────────────┐
│ 阶段 2: 内层可用解释器 (Interpreters) 枚举    │
│ 目标: 检索系统环境内可调用的执行器            │
│ 候选集: bash, sh, powershell, pwsh, cmd      │
└──────────────────────────────────────────────┘
      │
      ▼
[推荐矩阵计算 -> 输出 ProbeResult]
```

### 3.1 阶段 1：外层启动方言判定

#### 3.1.1 握手先验引导（0 RTT）
检查 SSH 握手返回的 `sshClient.ServerVersion()`：
- 若包含 `OpenSSH_for_Windows` 或 `Microsoft:Windows`，状态机优先调度 **Windows 探针**；
- 否则优先调度 **POSIX 探针**。
绝大多数目标只需 1 次 SSH `exec` 请求即可命中。

#### 3.1.2 探针指令与响应状态机

1. **POSIX 首选探针**：
   ```sh
   if :; then printf '__XOPS_DIALECT_POSIX__:%s:%s\n' "$(uname -s 2>/dev/null || echo UNAME_FAIL)" "$SHELL"; fi
   ```
   - **POSIX 环境 (Linux/macOS/BSD/Alpine)**：`printf` 为内置命令，输出包含 `__XOPS_DIALECT_POSIX__:<OS>:<SHELL>`，退出码为 0。确认为 `LaunchPOSIX`。
   - **Windows cmd.exe**：`if/then` 语法不兼容，不接受为有效 POSIX 特征帧。
   - **PowerShell（含 Linux 上的 Core）**：`if :; then ...; fi` 语法不兼容，报错退出。不能仅使用 `printf`、`$()` 或 `||` 判断 POSIX，PowerShell 7 也能解析或调用这些结构。

2. **Windows CMD 备选探针**：
   ```cmd
   echo __XOPS_DIALECT_CMD__:%COMSPEC%
   ```
   - **Windows cmd.exe**：输出 `__XOPS_DIALECT_CMD__:C:\Windows\system32\cmd.exe`，退出码为 0。确认为 `LaunchCmd`。
   - **POSIX / PowerShell 环境**：输出中的 `%COMSPEC%` 未展开，不接受为有效特征帧。探测必须由外层 Shell 自身展开变量，不能通过调用内层 `cmd.exe` 判断外层方言。

3. **Windows PowerShell 备选探针**：
   ```powershell
   Write-Output ('__XOPS_DIALECT_POWERSHELL__:' + $PSVersionTable.PSVersion.ToString()); Write-Output ('__XOPS_PLATFORM__:' + [Environment]::OSVersion.Platform)
   ```
   - **PowerShell DefaultShell**：输出 `__XOPS_DIALECT_POWERSHELL__:<Version>`，退出码为 0。确认为 `LaunchPowerShell`。
   - **平台元数据**：`__XOPS_PLATFORM__:Win32NT` 明确标识 Windows；`Unix` 保留为 Unix 平台。不凭语言版本猜测操作系统。

4. **安全兜底**：
   若上述探针均在有界超时内未收到有效特征帧，结果标记为 `LaunchUnknown`。

---

### 3.2 阶段 2：内层可用解释器枚举

外层方言确立后，后续命令严格使用目标方言对应的转义与载荷生成机制，杜绝语法混淆。

三种方言统一使用逐行响应协议：每个可用解释器输出一行 `__XOPS_INTERP__:<name>`，最后输出
`__XOPS_INTERP_END__`。`<name>` 仅允许 `bash`、`sh`、`powershell`、`pwsh`、`cmd`，不接受逗号列表
或布尔键值格式。解析器忽略普通噪声行与 CRLF 差异，拒绝非法解释器、重复帧、结束帧之后的
解释器帧及缺失结束帧；非零退出或截断输出也视为枚举失败。

#### 3.2.1 当 `LaunchDialect == LaunchPOSIX`
通过 `sh -c` 执行单条无外部依赖的只读脚本（1 次 RTT）：
```sh
sh -c '
for i in bash sh powershell pwsh cmd; do
    if command -v "$i" >/dev/null 2>&1; then
        printf "__XOPS_INTERP__:%s\n" "$i"
    fi
done
printf "__XOPS_INTERP_END__\n"
'
```

标准 Linux（安装 bash/sh）的输出示例，对应 `[bash, sh]`：

```text
__XOPS_INTERP__:bash
__XOPS_INTERP__:sh
__XOPS_INTERP_END__
```

Alpine（仅安装 sh）的输出示例，对应 `[sh]`：

```text
__XOPS_INTERP__:sh
__XOPS_INTERP_END__
```

同时安装 PowerShell Core 的 Linux 输出示例，对应 `[bash, sh, pwsh]`：

```text
__XOPS_INTERP__:bash
__XOPS_INTERP__:sh
__XOPS_INTERP__:pwsh
__XOPS_INTERP_END__
```

#### 3.2.2 当 `LaunchDialect == LaunchCmd`
利用 `cmdCommandPayload` 构建带有脱字符 `^` 转义保护的指令：
```bat
cmd.exe /d /s /c "where bash.exe >nul 2>&1 && (echo __XOPS_INTERP__:bash) & where sh.exe >nul 2>&1 && (echo __XOPS_INTERP__:sh) & where powershell.exe >nul 2>&1 && (echo __XOPS_INTERP__:powershell) & where pwsh.exe >nul 2>&1 && (echo __XOPS_INTERP__:pwsh) & (echo __XOPS_INTERP__:cmd) & (echo __XOPS_INTERP_END__) & exit /b 0"
```
- **输出解析**：
  - `__XOPS_INTERP__:cmd` 必然存在；
  - 根据 `__XOPS_INTERP__:bash` / `sh` / `powershell` / `pwsh` 标记对应解释器可用；
  - 完整输出结束帧后显式以 0 退出，可选解释器缺失不应导致整次枚举失败。

#### 3.2.3 当 `LaunchDialect == LaunchPowerShell`
直接由已识别的外层 PowerShell 执行静态查询，不调用 `powershellCommandPayload`，也不要求
安装 `powershell.exe`，从而支持仅安装 pwsh 的 DefaultShell：

```powershell
foreach ($i in @('bash','sh','powershell','pwsh','cmd')) {
    if (Get-Command $i -CommandType Application -ErrorAction SilentlyContinue) {
        Write-Output ('__XOPS_INTERP__:' + $i)
    }
}
Write-Output '__XOPS_INTERP_END__'
```

仅安装 PowerShell Core 的输出示例，对应 `[pwsh]`：

```text
__XOPS_INTERP__:pwsh
__XOPS_INTERP_END__
```

---

### 3.3 推荐匹配矩阵

探测引擎根据组合特征推导推荐配置：

| 探测到的 LaunchDialect | 可用 Interpreters | 推荐 Interpreter | 推荐 Login | 适用场景与推荐理由 |
| :--- | :--- | :--- | :--- | :--- |
| **`posix`** | 包含 `bash`, `sh` | `bash` | `false` | 标准 Linux/macOS，具备完备的脚本和 ensure 适配能力 |
| **`posix`** | 仅 `sh` (无 bash) | `sh` | `false` | Alpine / 容器精简镜像，规避默认调用 bash 导致的 127 错误 |
| **`posix`** | 包含 `pwsh` | 用户可选 `pwsh` | `nil` | Linux 下运行 PowerShell Core 脚本 |
| **`cmd`** | 包含 `cmd`, `powershell` | `server` (可选 `powershell`) | `nil` | 基础命令直通 cmd；自动化工作流推荐 powershell |
| **`cmd`** | 仅 `cmd` | `cmd` / `server` | `nil` | 极简 Windows 环境 |
| **`powershell`** | 包含 `powershell` | `powershell` | `nil` | 原生 PowerShell 默认环境 |
| **`unknown`** | 任何或未检出 | `server` | `nil` | 安全兜底，维持当前直通行为 |

---

## 4. 数据结构与配置持久化

### 4.1 Go 数据模型 (`core/ssh/probe.go`)
遵循项目编码规范，所有网络、系统与工具缩写（`ID`、`SSH`、`CLI`、`URL`）必须全大写：

```go
package ssh

import "time"

// ProbeResult 记录针对单个 SSH 节点的探测诊断快照
type ProbeResult struct {
	// 核心探测结果
	DetectedDialect       LaunchDialect   `json:"detectedDialect" yaml:"detected_dialect"`
	AvailableInterpreters []Interpreter   `json:"availableInterpreters" yaml:"available_interpreters"`
	RecommendedInterpreter Interpreter   `json:"recommendedInterpreter" yaml:"recommended_interpreter"`

	// 推荐生成的执行配置（可直接合入 Node.Execution）
	SuggestedConfig       ExecutionConfig `json:"suggestedConfig" yaml:"suggested_config"`

	// 诊断辅助元数据
	RemoteOS              string          `json:"remoteOS" yaml:"remote_os"`                 // Linux, Darwin, Windows_NT
	RemoteShellPath       string          `json:"remoteShellPath" yaml:"remote_shell_path"` // /bin/bash, C:\Windows\system32\cmd.exe
	ServerVersion         string          `json:"serverVersion" yaml:"server_version"`       // SSH banner
	Duration              time.Duration   `json:"duration" yaml:"duration"`                 // 探测总耗时
	ProbedAt              time.Time       `json:"probedAt" yaml:"probed_at"`                 // 探测时间戳
}
```

### 4.2 Schema V2 YAML 持久化表现
首次录入节点并探测成功后，数据写入配置文件的格式：

```yaml
schema_version: 2
nodes:
  root@192.168.1.10:22:
    host_ref: 192.168.1.10:22
    identity_ref: root@192.168.1.10
    alias: [web-prod-01]
    tags: [web, prod]
    sudo_mode: auto
    # 首次添加时由探测引擎自动生成的持久化字段
    execution:
      interpreter: bash
      launch_dialect: posix
      login: false
```

- **持久化前合规校验**：数据写入前必须通过 `node.Execution.Validate()` 静态校验，防止生成非法组合（如 `bash` 搭配 `cmd` 方言）。

---

## 5. 健壮性与安全设计规约

探测流程必须严格遵循 `AGENTS.md` 中的红线要求：

1. **绝对禁止资源泄漏 (Zero Resource Leak)**：
   - 所有探针创建的 `ssh.Session` 必须使用 `defer c.closeSessionBounded(session)` 在有界宽限期内关闭；
   - 严禁启动任何无取消信号退出保障的后台 Goroutine。

2. **严格的超时与取消控制 (Strict Timeouts)**：
   - 单次探针命令设置 3.5 秒硬超时（`context.WithTimeout`）；
   - 全流程（阶段 1 + 阶段 2）总工作超时控制在 8 秒以内；
   - 支持系统上下文取消（如用户按下 `Ctrl+C`），收到信号后立即断开通道并回收会话。

3. **抗 MOTD 与登录横幅干扰 (Magic Framing)**：
   - 探针输出使用特征定界符（如 `__XOPS_DIALECT_*__` 与 `__XOPS_INTERP__:`）；
   - 解析器采用逐行过滤匹配，无视登录欢迎词、版权声明和最后登录提示等前置噪声行。

4. **命令注入免疫与无副作用**：
   - 探针命令必须全部为**静态常量字符串**，严禁动态拼接任何不受信的外部变量；
   - 探针仅执行系统级内置只读查询，严禁向远端磁盘创建临时文件或修改系统变量。

5. **失败安全与非阻塞降级 (Fail-Safe & Non-Blocking)**：
   - 首次添加节点时，核心任务是保证节点成功入库。若探针遭遇超时、网络黑洞或受限权限报错：
     - 输出 Warning 日志，不中断节点的添加保存；
     - 节点 `Execution` 字段置为 `nil`（安全回退至默认 `server` 模式）；
     - 用户后续可随时通过 `xops host probe <id> --save` 重新发起探测与固化。

---

## 6. 实施路线图与验收计划

### Milestone 1: Core 协议与探针引擎实现
- 新增 `core/ssh/probe.go`，实现两阶段探针命令构造、特征定界符提取与超时控制；
- 基于 `core/testutil/sshfixture` 构造模拟 SSH 服务端，覆盖 POSIX（含无 bash 的 ash 场景）、Windows CMD、Windows PowerShell 的状态机流转测试。

### Milestone 2: Client 集成与内存缓存
- 在 `core/ssh/client.go` 中引入并发安全缓存 `probeCache` 及 `ProbeExecutionConfig(ctx)` 方法；
- 编写并发安全与缓存命中测试，验证多协程下无重复网络 RTT。

### Milestone 3: 首次录入与 CLI 管理接入
- 在 `cmd/host/add.go` 与 `cmd/host/load.go` 中接入首次添加时的自动探测与配置持久化；
- 实现 `xops host probe <node-id>` 命令，支持表格展示与 `--save` 配置文件回写。

### Milestone 4: 运行时受控懒加载与回归测试
- 在 Playbook 脚本/ensure 执行前及 SFTP `cwd` 检查前接入受控懒加载；
- 验证全量编译、代码扫描与单元测试：
  ```bash
  go build ./...
  go test -race ./core/ssh ./cmd/host
  golangci-lint run ./...
  ```
