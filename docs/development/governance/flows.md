# 建议优先掌握的 4 条关键链路

以下是按 `master` @ `a12d52f` 源码核实的**符号级关键调用链与边界约束**。

## F1 CLI SSH 连通/执行

`cmd/cli/main.go:main` → `cmd/root.go:Execute`（构造 `config.NewEncryptedRuntime` 并注入 `utils.InstallCredentialRuntime`）→ `cmd/ssh.go:NewCmdSsh`（或 `cmd/exec.go:NewCmdExec`）→ `(*SshOptions).Validate` & `cmd/ssh_execution.go:(*SshOptions).prepareCommandPlan` → `(*SshOptions).runConnection` → `(*SshOptions).resolveNode`（`Repository.PrepareNodeContext` / `ReplaceNodeAtRefContext`）→ `(*SshOptions).buildAdapterOptions` → `pkg/adapter.NewSSHAdapter`（注入 `sshenv.Discover()`）→ `core/ssh.(*Connector).Connect` → `(*SshOptions).runCommand` / `runShell` → CLI 输出与 `defer` 资源回收。

- **普通 `ssh`、`exec`、交互 PTY、sudo 路径差异**：
  - `xops ssh`：无命令终端走 `Client.Shell` / `ShellWithSudo`；Linux 下无 sudo 普通命令走 `ssh.PlanCommand` + `Client.RunCommandPlanWithIO`，管道脚本且解释器为 `server` 走 `Client.RunShellWithoutPTY`；非 Linux 客户端或带 `--sudo` 回退至 `Client.RunCommandWithIO`（`cmd/ssh_execution.go:13` 限制 `xops ssh` 显式执行参数仅在 Linux 原生可取消输出下开放）。
  - `xops exec`：显式执行参数通过 `cmd/exec_execution.go:(*ExecOptions).executePlannedTask` 调用内存有界缓冲的 `Client.ExecuteCommand`（跨平台可用，返回 `CommandResult{Outcome, ExitCode, Signal, Output, Truncated, ExecutionErr, IOErr, CleanupErr}`）；交互式 `-x` 走 `RunInteractivePlanWithIO` 或 `RunInteractiveWithSudo`；脚本走 `RunScriptWithExecution` / `RunScriptWithSudoExecution`。
- **代表性测试**：`core/ssh/command_execution_test.go:TestExecuteCommandResults`、`cmd/ssh_execution_test.go`、`cmd/exec_execution_test.go`。

## F2 MCP 受控远程命令

`cmd/mcp.go:runMCPServer`（注入 `credential.WithoutInteraction(ctx)`）→ `internal/mcphost.Config.RuntimeOptions` → `core/mcp/runtime.NewRuntime` → `core/mcp/runtime/invocation.go:withOperation` → `(*Runtime).resolve`（`ports.StateSource.Resolve`）→ `(*Runtime).prepareExecution` & `resolveExecutionRisk` → `guardrail.WithGuardrail` → `(*Runtime).enter`（`ports.ExecutionGate.Enter` + `validateGrantedPermit`）→ `(*Runtime).commandResult` → `core/mcp/sshexec.(*Backend).Run` → `core/ssh`。

- **快照与准入边界**：
  - HTTP 与恢复模式在 `internal/mcphost/config.go:RuntimeOptions` 中调用 `Provider.Frozen()` 冻结启动快照，且默认 `NoElicitFallback = FallbackDeny`；stdio 模式每次调用实时解析。
  - 若节点需按需探测（`ssh.NeedsExecutionProbe`），`prepareExecution` 先以 `LaunchUnknown` 执行 `guardrail.EvaluateContext` 预检（若策略为 `Deny` 则零网络流量拒绝），通过后申请 `ports.Inspect` 阶段 Permit 执行 `ProbeExecution`，再由 `resolveExecutionRisk` 生成 `CommandPlan.Digest()` 纳入 `ports.Binding`。
  - 最终执行前经历双重校验：① `Gate.Enter`（CLI 下为 `internal/mcphost/host.go:(*host).Enter`，动态发布宿主为 `core/mcp/state.(*Coordinator).Enter`）重解析当前配置并验证 `admission.Binding.Validate(current)`；② `core/mcp/sshexec/backend.go:(*Backend).connection` 再次校验 `permit.Binding().Validate(view)` 与 `ports.Execute` 阶段，再通过 `connector.ConnectPlan(ctx, target.Plan)` 获取 `PlanConnection` 租约。
  - 在 `core/mcp/state.Coordinator` 中，凭据/信任变更、节点停用/删除、策略变更会撤销受影响的非提交阶段 Permit；已进入 `ports.Commit` 阶段的上传交接（通过 `Admission.Previous` 原子替换容量槽）不受撤销影响，直至自身 deadline 结束。
- **代表性测试**：`core/mcp/runtime/ports_integration_test.go:TestRuntimeRejectsChangedGateGrant`、`internal/mcphost/binding_test.go:TestCLIBindingInvalidatesOnExecutionChangeAndPreservesOnUnrelatedChange`、`core/mcp/state/handoff_test.go`。

## F3 凭据/配置更新

`cmd/credential*.go` 或 `cmd/host/*` / `pkg/adapter` → `pkg/credential.(*Service).Rotate` / `Create` / `Delete` / `Recover` → `pkg/config.(*RepositoryConfigUpdater).ApplyCredentialRefAtVersion` → `pkg/config.(*Repository).commitTransactionResult` → `pkg/config.(*defaultStore).Transact` & `internal/credentialfile` → `pkg/config.(*Repository).publish`。

- **双存储事务与异常分支权威状态**：
  1. `RecordIntent`（`StageIntent`）→ `putAndVerifySecret`（`store.Put` + `store.Get` 常量时间比对）：若失败，配置尚未变更，调用 `compensateNewRef` 删除新写入的孤儿凭据并移除 journal。
  2. `ApplyCredentialRefAtVersion`：
     - 若 `!outcome.Applied`（如 `ErrConfigConflict` 版本冲突或写入前失败）：权威配置未改变，安全调用 `compensateNewRef` 回滚新凭据。
     - 若 `outcome.Applied && !outcome.Durable`（返回 `DurabilityError`，即配置文件已替换且内存快照已发布，但父目录 `fsync` 失败）：**权威状态已改变**，推进 journal 至 `StageAppliedUncertain`，严禁盲目重试或删除新/旧任一凭据。
     - 若 `outcome.Applied && outcome.Durable`：推进 journal 至 `StageCommitted`，随后执行 `cleanupOldRefOnRotate`（先经 `CheckRefUnreferenced` 确认全局无引用后再删除旧凭据；若清理失败则返回 `CleanupError` 并标记 `StageCleanup` 留待 `Recover`/GC 处理，绝不回滚已提交配置）。
- **代表性测试**：`pkg/credential/service_test.go:TestService_FaultInjection_AppliedButParentDirSyncFailed`、`TestService_Rotate_AppliedUncertain_BothCredentialsPreserved`、`pkg/config/repository_credential_test.go`。

## F4 Playbook 批量执行

`cmd/play.go:(*PlayOptions).RunContext`（注入 `credential.WithoutInteraction` 与 `adapter.WithNonInteractive(true)`）→ `pkg/playbook.Load` → `pkg/playbook.(*Engine).Run`（`preloadScripts`、`snapshotExecution`、`resolveTargets`、`WorkerPool`）→ `(*Engine).runOnHost` → `(*Engine).runStep` → `(*Engine).dispatchStep`（`runShell` / `runScript` / `runCopy` / `runEnsure` / `runTemplate`）→ `core/ssh` 与 `core/sftp`。

- **快照冻结与禁止重试边界**：
  - `Engine.Run` 在任务派发前通过 `preloadScripts` 一次性读取并冻结所有本地脚本源字节，通过 `snapshotExecution` 冻结全局与目标节点 `ExecutionConfig`。
  - `runStep`（`pkg/playbook/runner.go:49`）仅在 `result.Retryable && result.Outcome == ssh.ExecutionCompleted && result.CleanupErr == nil && result.IOErr == nil` 时才允许重试；任何 `ExecutionUnknown`、`ExecutionNotStarted`、I/O 错误或通道清理错误均立即终止重试。
  - `runEnsure` 通过受控退出帧协议区分退出码 `0`（`StatusSkipped`）、保留错误码 `126`/`127`（及 fish 的 `121`/`123`/`124`/`125`，判定为 `StatusFailed` 且禁止执行 `action`）、帧缺失/超时/信号终止（`StatusFailed`）与普通非零退出（执行 `action` 并复查 `check`）。
- **代表性测试**：`pkg/playbook/execution_plan_test.go:TestPlaybook_ScriptSourceBytesFrozen`、`TestPlaybook_NonRetryableBoundaries`、`TestPlaybook_EnsureProtocol_*`。

## F5 可选：SCP/SFTP 与交互编辑器

`cmd/scp.go` → `core/sftp/transfer.go`；`cmd/sftp.go` → `cmd/sftpshell/shell.go` + `core/sftp`。TUI 则调查 `cmd/tui.go` → `pkg/tui/*` → `pkg/adapter` / `core/ssh`。细化跨 OS 终端所有权、ConPTY、信号与文件替换。

## 每条链路的验收模板

- 入口（命令/工具/API，真实符号）：
- 参数与显式/缺省行为：
- 目标与凭据由谁解析：
- 权限/校验边界：
- 不可变快照与状态所有权：
- I/O、网络资源、goroutine 与关闭所有者：
- 失败/取消/重试语义：
- 用例与 fixture（路径+测试名）：
- 与现有文档不一致的地方：
- 当前无法确认的假设：
