# Four Core Execution and Persistence Flows

The following symbol-level call chains and invariants are verified against `master` @ `a12d52f`.

## F1 CLI SSH Connectivity and Execution

`cmd/cli/main.go:main` → `cmd/root.go:Execute` (constructs `config.NewEncryptedRuntime` and installs `utils.InstallCredentialRuntime`) → `cmd/ssh.go:NewCmdSsh` (or `cmd/exec.go:NewCmdExec`) → `(*SshOptions).Validate` & `cmd/ssh_execution.go:(*SshOptions).prepareCommandPlan` → `(*SshOptions).runConnection` → `(*SshOptions).resolveNode` (`Repository.PrepareNodeContext` / `ReplaceNodeAtRefContext`) → `(*SshOptions).buildAdapterOptions` → `pkg/adapter.NewSSHAdapter` (injecting `sshenv.Discover()`) → `core/ssh.(*Connector).Connect` → `(*SshOptions).runCommand` / `runShell` → CLI output and `defer` cleanup.

- **Path differences across `ssh`, `exec`, interactive PTY, and `sudo`**:
  - `xops ssh`: Interactive terminals with no command invoke `Client.Shell` / `ShellWithSudo`; on Linux without sudo, ordinary commands use `ssh.PlanCommand` + `Client.RunCommandPlanWithIO`, and piped scripts with the `server` interpreter use `Client.RunShellWithoutPTY`; non-Linux clients or `--sudo` fall back to `Client.RunCommandWithIO` (`cmd/ssh_execution.go:13` restricts explicit execution flags on `xops ssh` to Linux where cancelable native output handles are implemented).
  - `xops exec`: Explicit execution flags route through `cmd/exec_execution.go:(*ExecOptions).executePlannedTask` to bounded in-memory `Client.ExecuteCommand` (available across platforms, returning `CommandResult{Outcome, ExitCode, Signal, Output, Truncated, ExecutionErr, IOErr, CleanupErr}`); interactive `-x` uses `RunInteractivePlanWithIO` or `RunInteractiveWithSudo`; scripts use `RunScriptWithExecution` / `RunScriptWithSudoExecution`.
- **Representative tests**: `core/ssh/command_execution_test.go:TestExecuteCommandResults`, `cmd/ssh_execution_test.go`, `cmd/exec_execution_test.go`.

## F2 MCP Controlled Remote Execution

`cmd/mcp.go:runMCPServer` (injecting `credential.WithoutInteraction(ctx)`) → `internal/mcphost.Config.RuntimeOptions` → `core/mcp/runtime.NewRuntime` → `core/mcp/runtime/invocation.go:withOperation` → `(*Runtime).resolve` (`ports.StateSource.Resolve`) → `(*Runtime).prepareExecution` & `resolveExecutionRisk` → `guardrail.WithGuardrail` → `(*Runtime).enter` (`ports.ExecutionGate.Enter` + `validateGrantedPermit`) → `(*Runtime).commandResult` → `core/mcp/sshexec.(*Backend).Run` → `core/ssh`.

- **Snapshots and admission boundaries**:
  - HTTP and recovery modes freeze the startup snapshot via `Provider.Frozen()` in `internal/mcphost/config.go:RuntimeOptions` and default `NoElicitFallback` to `FallbackDeny`; stdio mode resolves the current snapshot per call.
  - When on-demand probing is required (`ssh.NeedsExecutionProbe`), `prepareExecution` runs a conservative `LaunchUnknown` preflight via `guardrail.EvaluateContext` (aborting with zero network traffic on `Deny`), then acquires a `ports.Inspect` permit to call `ProbeExecution` before `resolveExecutionRisk` binds `CommandPlan.Digest()` into `ports.Binding`.
  - Final execution enforces two binding checks: (1) `Gate.Enter` (`internal/mcphost/host.go:(*host).Enter` in CLI mode, or `core/mcp/state.(*Coordinator).Enter` in dynamic hosts) re-resolves the current state and checks `admission.Binding.Validate(current)`; (2) `core/mcp/sshexec/backend.go:(*Backend).connection` re-verifies `permit.Binding().Validate(view)` and the `ports.Execute` phase before leasing a `PlanConnection` via `connector.ConnectPlan(ctx, target.Plan)`.
  - In `core/mcp/state.Coordinator`, credential/trust edits, node disablement/deletion, and policy changes revoke affected non-committing permits, whereas upload tasks handed off to `ports.Commit` (via `Admission.Previous`) remain valid until their commit deadline.
- **Representative tests**: `core/mcp/runtime/ports_integration_test.go:TestRuntimeRejectsChangedGateGrant`, `internal/mcphost/binding_test.go:TestCLIBindingInvalidatesOnExecutionChangeAndPreservesOnUnrelatedChange`, `core/mcp/state/handoff_test.go`.

## F3 Credential and Configuration Updates

`cmd/credential*.go` or `cmd/host/*` / `pkg/adapter` → `pkg/credential.(*Service).Rotate` / `Create` / `Delete` / `Recover` → `pkg/config.(*RepositoryConfigUpdater).ApplyCredentialRefAtVersion` → `pkg/config.(*Repository).commitTransactionResult` → `pkg/config.(*defaultStore).Transact` & `internal/credentialfile` → `pkg/config.(*Repository).publish`.

- **Dual-store transaction and authoritative failure states**:
  1. `RecordIntent` (`StageIntent`) → `putAndVerifySecret` (`store.Put` + constant-time `store.Get` readback): if this fails before configuration mutation, `compensateNewRef` deletes the unreferenced new credential and removes the journal entry.
  2. `ApplyCredentialRefAtVersion`:
     - If `!outcome.Applied` (e.g. `ErrConfigConflict` or pre-write error): authoritative configuration is unchanged; `compensateNewRef` safely deletes the new credential.
     - If `outcome.Applied && !outcome.Durable` (`DurabilityError`—the config file was replaced and published in memory, but parent-directory `fsync` failed): **authoritative state has changed**; the journal advances to `StageAppliedUncertain`, and neither the new nor old credential may be deleted or blindly retried.
     - If `outcome.Applied && outcome.Durable`: the journal advances to `StageCommitted`, followed by `cleanupOldRefOnRotate` (verifying `CheckRefUnreferenced` before deleting the old credential; cleanup failures return `CleanupError` and mark `StageCleanup` for later `Recover`/GC without rolling back the committed config).
- **Representative tests**: `pkg/credential/service_test.go:TestService_FaultInjection_AppliedButParentDirSyncFailed`, `TestService_Rotate_AppliedUncertain_BothCredentialsPreserved`, `pkg/config/repository_credential_test.go`.

## F4 Playbook Batch Orchestration

`cmd/play.go:(*PlayOptions).RunContext` (injecting `credential.WithoutInteraction` and `adapter.WithNonInteractive(true)`) → `pkg/playbook.Load` → `pkg/playbook.(*Engine).Run` (`preloadScripts`, `snapshotExecution`, `resolveTargets`, `WorkerPool`) → `(*Engine).runOnHost` → `(*Engine).runStep` → `(*Engine).dispatchStep` (`runShell` / `runScript` / `runCopy` / `runEnsure` / `runTemplate`) → `core/ssh` & `core/sftp`.

- **Snapshot freezing and non-retryable boundaries**:
  - Before dispatching tasks, `Engine.Run` reads and freezes all local script source bytes via `preloadScripts` and freezes global and node `ExecutionConfig` via `snapshotExecution`.
  - `runStep` (`pkg/playbook/runner.go:49`) retries only when `result.Retryable && result.Outcome == ssh.ExecutionCompleted && result.CleanupErr == nil && result.IOErr == nil`; any `ExecutionUnknown`, `ExecutionNotStarted`, I/O error, or cleanup error stops retries immediately.
  - `runEnsure` uses a controlled exit-frame protocol to distinguish exit `0` (`StatusSkipped`), reserved error codes `126`/`127` (plus `121`/`123`/`124`/`125` for fish, classified as `StatusFailed` without running `action`), missing frames/timeouts/signals (`StatusFailed`), and ordinary nonzero exits (running `action` and re-verifying `check`).
- **Representative tests**: `pkg/playbook/execution_plan_test.go:TestPlaybook_ScriptSourceBytesFrozen`, `TestPlaybook_NonRetryableBoundaries`, `TestPlaybook_EnsureProtocol_*`.

## F5 Optional: SCP/SFTP and Interactive Line Editor

`cmd/scp.go` → `core/sftp/transfer.go`; `cmd/sftp.go` → `cmd/sftpshell/shell.go` + `core/sftp`. For TUI: `cmd/tui.go` → `pkg/tui/*` → `pkg/adapter` / `core/ssh`.

## Per-Flow Acceptance Template

- Entry point (command/tool/API, exact symbol):
- Arguments and explicit vs. default behavior:
- Target and credential resolution owner:
- Authorization / validation boundary:
- Immutable snapshot and state ownership:
- I/O, network resources, goroutines, and close owner:
- Failure / cancellation / retry semantics:
- Tests and fixtures (path + test name):
- Discrepancies with existing docs:
- Unverified assumptions:
