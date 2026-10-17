# SSH Execution Compatibility Implementation Plan

Based on the [SSH execution and interpreter compatibility design](./ssh-execution-compatibility.md). Status: Phase P1 (P1-A, P1-B), P2 (P2-A, P2-B), and P3 are complete, with code, tests, and bilingual documentation verification records below.

## Delivery Order

### P1-A: Command Plans and Bounded Execution Foundations (Complete)

- [x] Add immutable command plans: unchanged server payloads, Bash with a known POSIX launch dialect, login-option validation, input snapshots, and plan digests
- [x] Add an execution API with finite stdin and bounded combined output; bound channel creation, exec requests, execution, and closure, and join every worker after cancellation
- [x] Provide not_started/completed/unknown, exit code/signal, output truncation, and separate cleanup errors; never replay after a lost startup response
- [x] Expose ordinary commands through explicit `exec --interpreter`, `--launch-dialect`, and `--login-shell` options; retain the old path when new options are absent
- [x] Reject new options combined with unmigrated scripts, PTY, escalation, or streaming output; explain restrictions in help and errors rather than silently ignoring options
- [x] Use SSH fixtures for unchanged bytes, quoting, stdin/EOF, nonzero/signal/missing status, startup rejection/unanswered requests, cancellation, truncation, and no replay; add CLI parameter regressions

This batch's new API accepts finite input and internal memory output only, without uncancelable external readers/writers. Defaults are a 5-minute total timeout, a 10-second startup timeout (inheriting the connector's handshake timeout), and a 1-second shutdown grace period. Core callers may shorten or specify the total timeout. Limits are 64 KiB each for the original command and quoted exec payload, 16 MiB of stdin, a default output window retaining the last 5 MiB, and a maximum output window of 64 MiB. At the window limit, continue draining and explicitly report truncation. These limits apply to the new API; this batch does not switch old API defaults.

### P1-B: Unify Existing Entry Points and Fix Interactive Execution (Complete)

- [x] Delegate Run, RunWithoutLogin, RunCommandWithIO, and legacy Bash scripts to unified plans while retaining their individual login defaults
- [x] Provide cancelable output bridges for terminals/pipes; migrate streaming/file output and SSH CLI while preserving stdin ownership and EOF contracts
- [x] Bound session creation, exec/PTY/Shell requests, and closure; legacy exec/script/I/O/escalation/RunStream startup requests share this lifecycle
- [x] Preserve nonzero, signal, and missing exit status for ordinary/root/passwordless/password sudo/su one-shot PTY commands; retain full login-session policy and pass terminal-restoration/stdin EOF regressions
- [x] Accept ContextWriter/memory output in the new PTY API; Linux terminals/pipes use independent nonblocking handles without closing caller streams or changing their flags on cancellation
- [x] Apply new exec interpreter options to PTY and honor ordinary PTY --no-login; reject ignored script/stream/out-dir/privileged no-login combinations before execution; explicit empty SSH commands do not become shells/scripts
- [x] Migrate SSH CLI interpreter options, non-PTY native shells, and configuration inheritance
- [x] Declare P1 complete only after full build/test/lint and SSH/I/O race and leak regressions pass

### P2-A: Configuration and Caller Bindings (Complete)

- [x] Global/Node/Playbook execution schemas, presence, inheritance, and DTO/clone/import/export round-trip tests
- [x] Pass plans and structured results through MCP input, ports, and host backends; show effective semantics in approval and bind execution configuration in digests
- [x] Node/global execution changes invalidate stale approvals without invalidating unrelated configuration; request-supplied dialects cannot lower risk
- [x] Freeze Playbook script-source bytes and node+step plans; prohibit retries for uncertain outcomes or additional cleanup failures
- [x] Define ensure result-source protocols, check/action/verify classification, and legacy workflow migration

### P2-B: Adapters and Advanced Operations (Complete)

- [x] Validate sh on ash/dash without Bash; define shebang allowlists, unknown declarations, BOM/CRLF, and independent runtime input
- [x] Freeze native Windows cmd/PowerShell/pwsh launch matrices, quoting, profiles, encoding, payload lengths, and exit-code protocols; validate native OpenSSH
- [x] Separate sudo/su control protocols from user interpreters; regress authentication, terminal handoff, cancellation, and quoting
- [x] Adapt SFTP cwd and reject pure server combinations; validate file-backend semantics
- [x] Declare platform/interpreter requirements for built-in probes, monitoring, logs, and firewall commands

### P3: Release the Default Switch (Complete)

- [x] Complete P1/P2 acceptance and shared-core consumer validation; assign the release version
- [x] Use server as the consistent ordinary-command default; reject scripts without a reliable interpreter before execution
- [x] Publish separate Bash compatibility migration for commands/scripts, SFTP restrictions, and rollback-compatible schema versions
- [x] Obtain native Windows and genuinely Bash-free Unix evidence; prohibit fallback to another interpreter after failure

## Explicit CLI Flag Combinations

`cmd/exec_execution.go:prepareCommandPlan` replaces the blanket rejection of `--shell`, `--sudo`, `--stream`, and `--out-dir` with operation-specific capability validation:

- Ordinary buffered commands retain immutable plans and `ExecuteCommand`. Streaming/file output reuses `Client.Run` output adapters, sending the frozen payload unchanged as `server/unknown` to avoid a second interpreter wrapper. The original command is still checked before execution to reject post-planning changes.
- File and stdin scripts use `ResolveScriptExecution`; an explicit interpreter overrides the shebang without transforming the body. Explicit-mode scripts are limited to 16 MiB, with bounded stdin reads that never close borrowed streams; ordinary commands retain their 64 KiB limit. Validation runs again after stdin is read so scripts cannot become ordinary commands accidentally.
- Non-interactive combinations have task-owned 5-minute contexts and default 5 MiB rolling result windows. Streaming and file output bypass result retention. Each task opens its log and closes it after execution/output cleanup, preserving close errors.
- `RunWithSudoExecution` accepts optional output settings, applying validated interpreter/dialect/login options last so output options cannot override the execution contract. `RunScriptWithExecution` also carries the resolved launch dialect. Existing call syntax still compiles, and CLI paths without explicit interpreter flags retain their behavior.
- `RunInteractiveWithSudoExecution` complements explicit non-interactive escalation. It reuses authentication and terminal handoff while carrying operation-local execution settings without changing the shared Client. Explicit PTY escalation uses a separate POSIX control shell instead of implicitly loading a login environment through legacy `sudo -i`. Exit status, first-input preservation, raw-mode activation after authentication, and terminal restoration before return remain required.
- Server/Windows interpreters remain unsupported for scripts and Unix escalation. PTY remains incompatible with scripts, multiple hosts, `--stream`, and `--out-dir`. Core configured-su capability checks, SSH trust, credential persistence, and retry policy are unchanged.

Regressions in `cmd/exec_combinations_test.go`, `cmd/exec_combination_errors_test.go`, `cmd/exec_interactive_unix_test.go`, `core/ssh/explicit_privilege_test.go`, and `explicit_privilege_linux_test.go` cover actual SSH request payloads, unchanged script bytes, escalation prefixes, per-host output/logs, nonzero status, blocked-output cancellation, stdin limits, unchanged shared configuration, and PTY authentication/input handoff/restoration. Protocol peers are fixtures and execute no real remote commands; cross-compilation does not replace native Windows/macOS acceptance.

## CLI Combination Review Fixes

- `runPrivilegeWithConfig` binds stream/file output before constructing its writer. Explicit privileged PTY execution strictly binds output before root/authentication dispatch. The binding owner passes cancellation into escalation; lower layers borrow existing bindings without releasing them again. Normal completion drains output/frames before release, whereas abort cancels output before joining workers. Pre-command su authentication retries retain bindings without replaying user code.
- `cmd/exec_input.go` reuses `internal/terminal.DuplicatePromptInput` for scripts. Cancellation interrupts only the owned duplicate, and cleanup joins the interruption callback before closure. Reads use the command context and a 5-minute preparation deadline; in-flight kernel filesystem calls may still have to finish. Explicit mode retains its 16 MiB limit: regular files are size-checked before reading, with limit-plus-one reads also covering growth. `--shell` rejects non-regular files; pipe scripts through stdin. Credential stdin and script stdin are rejected as conflicting before any bytes are consumed.
- Unix duplicates use `SyscallConn.Control` and `F_DUPFD_CLOEXEC`, retaining the fd instead of calling `File.Fd`, which can clear borrowed nonblocking flags. Cleanup neither closes caller input nor consumes later bytes.
- Script configuration preserves missing interpreter/dialect/login fields; setting only a dialect no longer explicitly selects server. Preflight validates supplied values and known unsupported script interpreters. `ResolveScriptExecution` resolves the actual script with node configuration, inheriting omitted fields and rejecting incompatible combinations before user-command dispatch. Existing ordinary-command defaults and `--no-login` compatibility behavior remain unchanged.

Regressions cover password-sudo command/script streams, blocked-output cancellation and file-error identity; root privileged PTY ContextWriter use and terminal restoration; script-read cancellation/ownership/limits and credential-stdin conflicts; and SSH-fixture validation of partial dialect/login/interpreter overrides. The five original review-overlay probes have corresponding repository regressions. Tests use synthetic credentials and local fixtures, never real servers.

## Validation and Submission

Every new capability and bug fix requires corresponding tests. Before a PR or push, run `go build ./...`, `go test ./...`, and `golangci-lint run ./...`. Run `npm run docs:check` for documentation and validate local source links separately. Batches affecting SSH concurrency also run `go test -race ./core/ssh ./cmd`. Adapters remain unavailable without platform evidence.

## P1-A Validation Record (2026-10-09)

The P1-A items above are complete. Main implementations are in `core/ssh/command_plan.go`, `core/ssh/command_execution.go`, and `cmd/exec_execution.go`. Corresponding tests cover real SSH protocol exchanges, POSIX/Bash quoting, size limits, cancellation/leaks, result classification, and CLI integration.

- `go build ./...`: passed
- `go test ./...`: passed
- `golangci-lint run ./...`: 0 issues
- `go test -race ./core/ssh ./cmd`: passed; targeted race tests for final parameter/payload validation also passed
- `npm run docs:build`: passed; bilingual structure, local links, and formatting checks passed
- `python3 scripts/check_core.py`: Linux/Windows/macOS dependency boundaries passed; the independently extracted module passed build/tests

Native Windows execution, Bash-free Unix adapters, PTY/escalation, and unification of existing entry points remain subsequent acceptance work. Cross-platform dependency inspection does not establish that validation. The next batch starts P1-B with legacy-method delegation, cancelable I/O bridges, and PTY exit-status fixes.

## First P1-B Batch Validation Record (2026-10-09)

This batch completes the checked request/PTY items above without declaring P1-B or P1 complete. `session_lifecycle.go` unifies PTY/Shell lifecycles and legacy request deadlines. One-shot command exits are no longer suppressed using full login-session policy. `RunInteractivePlanWithIO` uses finite or cancelable output; Linux terminal/pipe handles belong to the bridge and cancellation leaves the caller's original streams intact.

Validation covers ordinary/root/passwordless sudo/password sudo/su nonzero, signal, and missing exit status; fragmented authentication/terminal handoff and first-character preservation; unanswered exec/PTY/Shell requests; terminal restoration, stdin EOF, blocked output-pipe cancellation, output-drain deadlines, file flags/ownership, rejecting unsupported writers before execution, and CLI option/empty-command validation.

- `go build ./...`, `go test ./...`, `golangci-lint run ./...`: passed, 0 lint issues
- `go test -race ./core/ssh ./cmd`: passed; full core and targeted race regressions for the final output-deadline classification change passed
- Blocked-pipe cancellation test repeated 10 times: passed
- `npm run docs:build`: passed
- `python3 scripts/check_core.py`: three-platform dependency boundaries and isolated-module build/tests passed

Remaining P1-B work includes delegating legacy Run/script/I/O methods to unified plans, migrating legacy streaming/file output and SSH CLI, and validating output bridges for other client platforms and regular files. Legacy output entry points still accept ordinary writers; request deadlines do not establish that their output callbacks are cancelable. New native PTY output exposes only Linux terminals/pipes. Other combinations are explicitly rejected without fallback or replay.

### P1-B Review Fix: Output Lifecycle

If input-bridge initialization fails, cancel input/cancelable output and use the already-started Session.Wait to confirm session exit. If the peer never acknowledges closure, interrupt the transport after the grace period, then join stdout/stderr. Output-copy failures are monitored concurrently with remote completion through a separate notification channel. Broken pipes and write timeouts cancel the session and use the same bounded cleanup without waiting for the full command timeout. Retain the original input/output errors and never replay the command.

Regressions suspend server transport reads so that channel-close requests actually cannot be acknowledged. They also cover continued output beyond the SSH receive window, a real broken pipe, write timeouts, terminal restoration, caller stream ownership, and worker cleanup. The new cases failed before the fix and pass afterward.

## Final P1-B and Full P1 Validation Record (2026-10-09)

This batch completes all remaining P1-B items and accepts the full Phase P1 delivery:
1. **Unify legacy entry point delegation and builders**: `Run`, `RunWithoutLogin`, `RunScript`, `RunStream`, `RunWithSudo`, `RunScriptWithSudo`, and `RunCommandWithIO` all delegate to shared Bash payload construction helpers (`bashCommandPayload`, `bashScriptPayload`, `legacyBashPayload`), maintaining individual entry point login defaults (`Run` and `RunWithSudo` default to login; `RunWithoutLogin` defaults to non-login).
2. **Cancelable output bridges**: `BindOutput` and `bindRunOutput` bridge regular files, the null device (`/dev/null`), finite memory buffers, Linux terminals, and pipes. Non-PTY ordinary pipes do not use artificial write timeouts (bounded by context timeout and cancellation only), while retaining the 10-second idle write limit for PTY terminals; `RunStream`, file-redirected output, and `RunCommandWithIO` use the cancelable bridge to prevent goroutine leaks when output stalls.
3. **Streaming command plan execution and non-PTY native shells**: `RunCommandPlanWithIO` strictly checks output cancelability, executes immutable command plans while forwarding standard streams, and preserves remote exit codes and signals; `RunShellWithoutPTY` supports native non-PTY `shell` requests with streaming stdin and full exit status retention. Both streaming paths monitor output-copy failures independently; broken downstream pipes immediately trigger bounded session cleanup while preserving write errors, preventing remote producers from exhausting SSH window buffers and stalling execution.
4. **SSH CLI options and input routing**: `xops ssh` adds `--interpreter` (server/bash), `--launch-dialect` (posix), `--login-shell`, and `--no-login` flags; input routing is refactored: terminal input without a command opens a full interactive PTY login shell; piped stdin with `--interpreter server` routes to `RunShellWithoutPTY`; non-server interpreters or non-empty commands route through streaming plan execution; explicit empty commands and invalid option combinations are rejected before execution.
5. **Full acceptance metrics**:
   - `go build ./...`: passed
   - `go test ./...`: passed
   - `golangci-lint run ./...`: 0 issues
   - `go test -race ./core/ssh ./cmd`: passed (`core/ssh` 27.5s, `cmd` 200.3s, zero data races, zero goroutine leaks)
   - `python3 scripts/check_core.py`: Linux/Windows/macOS dependency boundaries passed; isolated extracted module build and tests passed
   - `npm run docs:build`: passed, bilingual documentation routes and link checks passed

## Phase P2-A Verification Record (2026-10-09)

This batch completes all items in Phase P2-A:
1. **Execution Configuration Schema & Inheritance**: `core/ssh/execution_config.go` implements `ExecutionConfig` (`interpreter`, `launch_dialect`, `login` with strict validation and unknown field rejection), preserving explicit `login: false`. `ResolveExecution` and `EffectiveExecution` establish consistent multi-tier inheritance across Global (`models.Configuration`), Node (`models.Node`), and Playbook (`Settings` and `Step`), covered by V2 schema round-trip and snapshot isolation tests.
2. **MCP Ports & Structured Execution Binding**: `ports.CommandResult` provides structured execution metadata (`PlanDigest`, `Phase`, `Outcome`, `ExitCode`, `Signal`, `Truncated`, `ExecutionErr`, `IOErr`, `CleanupErr`). `OperationSnapshot.Digest` includes effective execution versions, properly invalidating stale approvals when execution semantics change while preserving bindings when unrelated fields change. `guardrail.AnalyzeCommandWithDialect` prevents client-supplied dialects from artificially lowering command risk.
3. **Playbook Script-Source & Plan Freezing**: `Engine.Run` preloads and caches all script sources via `preloadScripts` prior to task dispatch; all target nodes and retry attempts share immutable script bytes without rereading disk files during execution. `runShell` and `runScript` freeze immutable command plans; retry logic strictly enforces non-retryable boundaries: uncertain outcomes (`Outcome == ExecutionUnknown`), unstarted executions (`ExecutionNotStarted`), canceled contexts, and additional cleanup/IO errors are prohibited from retrying.
4. **Ensure Result Protocol & Classification**: `runEnsure` integrates a controlled result-frame protocol (`trap ... EXIT`) that reliably differentiates exit code 0 (`StatusSkipped`, no action needed), exit code 127 (`StatusFailed`, cannot distinguish missing binary from startup failure, action prohibited), execution layer faults or lost result frames (`StatusFailed`, action prohibited), and confirmed non-zero exits (triggers remediation action followed by post-action verification). Server mode without supported shell adapters is rejected upfront, and control frames are stripped from user output.
5. **Full Acceptance Metrics**:
   - `go build ./...`: passed
   - `go test ./...`: passed
   - `golangci-lint run ./...`: 0 issues
   - `python3 scripts/check_core.py`: Linux/Windows/macOS boundaries and extracted module build/test passed
   - `npm run docs:build`: passed

## P2-A Review Fix: Execution Defaults, Risk Dialects, and Escalation

- In P1/P2, MCP commands without execution configuration (including an empty object) retain POSIX `bash -l -c`; only explicit server selection forwards commands unchanged. The default switch remains P3 work, and command/approval plans share the same stage defaults.
- Explicit server execution without trusted launch-dialect metadata is classified as unknown and cannot obtain a POSIX safe-prefix exemption. Request-supplied posix cannot replace node metadata; configuration/plan errors are rejected before approval.
- Both MCP backends resolve and validate execution before connecting or taking the sudo branch. Supported Bash sudo paths explicitly pass effective login mode; Playbook shell, ensure.check/action/verify, and scripts reuse this validation. Server escalation, incompatible launch dialects, and unimplemented configured su combinations are rejected before user operations start. Unconfigured legacy su semantics are preserved.
- After selecting an interpreter from a shebang or script default, revalidate the final configuration and freeze login mode. A script declaration does not prove the outer launch dialect; Bash scripts cannot carry cmd/PowerShell/unknown launch environments into a legacy Bash path.

Regressions cover actual SSH payloads in both MCP backends, nil/empty configuration defaults, login:false with root/NOPASSWD sudo, zero dispatch for unsupported escalation, unknown-dialect approval and rejection of self-asserted POSIX safety, and login propagation through Playbook sudo shell/ensure phases plus script preflight validation. Build, full tests, lint, full race tests for affected packages, and independent core extraction passed.

## SFTP Copy-Path Review Fix (2026-10-10)

Before calling the entry-preserving `RemoteCopy`, MCP `xops_fs_cp` resolves copy operands separately. Ordinary source symlinks remain links. A directory source ending in `/` follows directory symlinks while retaining the original basename for an existing destination directory; a source ending in `/.` copies contents directly. Path classification recognizes only actual `/` separators and preserves literal spaces, tabs, and backslashes in filenames.

For regular-file copies onto existing file symlinks, resolve absolute/relative targets and link chains, update the target file, and retain the original link. Apply the same check after appending a basename to an existing destination directory. Entry copies of source links do not use this dereferencing rule. Reject dangling destination file links and file-over-directory combinations before writing.

Regressions use actual MCP calls and SSH/SFTP protocol exchanges to verify destination-link preservation, relative targets/link chains, `/link/` versus `/link/.` with new/existing destinations, independent directory copies, literal dot-plus-whitespace/backslash filenames without accidental directory copies, and ordinary source-link/dangling destination-link boundaries. The test peer deliberately implements lexical REALPATH to cover servers that do not automatically dereference the final link.

Validation passed: `go build ./...`, `go test ./...`, `golangci-lint run ./...` (0 issues), full race tests for the affected MCP/SFTP/backend/host packages, documentation build, and isolated core build/tests.

## Phase P2-B Verification Record (2026-10-10)

This batch completes all items in Phase P2-B (Adapters & Advanced Operations):
1. **sh Adapter & Script Protocol**: Added support for `InterpreterSh` (non-login POSIX `sh -c` and `sh -s`); shebang allowlists correctly distinguish and map `sh` and `bash`; non-allowlisted shebangs are strictly rejected unless an explicit caller override is provided; scripts with UTF-8 BOM (`\xef\xbb\xbf`) prefixes are rejected before execution; the first-line metadata parser safely ignores trailing `\r` without altering original script payload bytes; `setupStdinPipeline` strictly rejects scripts when both script payloads and runtime stdin are supplied.
2. **Windows cmd/PowerShell/pwsh Adapters**: Launch dialect matrix is frozen (`cmd` only supports `cmd` dialect, `powershell` supports `cmd`/`powershell`, `pwsh` supports `cmd`/`powershell`/`posix`); PowerShell commands use UTF-16LE Base64 encoded payloads (`-EncodedCommand`) with `-NoProfile -NonInteractive -ExecutionPolicy Bypass`; outer PowerShell launch dialect explicitly appends `; exit $LASTEXITCODE` so child exit codes are faithfully returned without being mapped to 1; command length limits are validated according to the outer launch dialect (`LaunchCmd` enforces the cmd 8191 limit, `LaunchPowerShell`/`LaunchPOSIX` enforces 32767); cmd commands are wrapped in `cmd.exe /d /s /c "..."` to protect operators (`&&`, `&`, `|`) from outer cmd evaluation; exit code protocol is frozen (`cmd` preserves `%ERRORLEVEL%`, PowerShell injects `$ErrorActionPreference = 'Stop'` and `$LASTEXITCODE` checks).
3. **Sudo/Su Control Protocol & User Interpreter Separation**: sudo privilege escalation control shell supports both `sh` and `bash`, preserving random token handshakes, password prompt matching, and cleanup; configured su is strictly rejected while preserving unconfigured legacy su semantics.
4. **SFTP Working Directory & Execution Adaptation**: `SSHAdapter.GetConfig` merges and propagates node and global `Execution` configuration to `ClientConfig.Execution`, ensuring CLI-established SSH clients have full execution context; implemented `FormatWorkingDirCommand`, providing escaping and path security for POSIX (`cd -- '...' && ...`), cmd (`cd /d "..." && ...`), and PowerShell (`Set-Location -LiteralPath '...' -ErrorAction Stop; ...`); server passthrough rejects non-empty cwd unless SFTP can derive a temporary CMD adapter from known server/cmd, preventing silent directory loss; cmd mode strictly rejects working directories containing `%`, `!`, `^`, `"`, or newlines; both SFTP interactive and batch modes construct payloads via `ssh.PlanCommand` and dispatch to target interpreter adapters.
5. **Legacy Run APIs & Interpreter Boundaries**: Legacy APIs (`Run`, `RunScript`, `RunScriptWithExecution`, `RunWithSudo`, `RunScriptWithSudo`, and `RunCommandWithIO`) are strictly bounded to `bash` and `sh`, explicitly returning `ErrExecutionValidation` for any other interpreter to prevent silent fallback to Bash.
6. **Built-in Operations Platform/Interpreter Declarations**: `MetricsCollector` monitoring probes, automatic sudo detection, and TUI log viewers (`log_select` and `log_stream`) inspect client execution configuration and fail early on non-POSIX dialects; firewall inspection explicitly declares Linux/POSIX constraints.
7. **Full Acceptance Metrics**:
   - `go build ./...`: passed
   - `go test ./...`: passed
   - `golangci-lint run ./...`: 0 issues
   - Cross-compilation: `GOOS=darwin GOARCH=arm64` and `GOOS=windows GOARCH=amd64` passed
   - `python3 scripts/check_core.py`: Linux/Windows/macOS boundaries and extracted module build/test passed
   - `npm run docs:build`: passed

## Phase P2-B Review Fixes: cmd Two-Layer Quoting, SFTP Output Compatibility & Batch Login Semantics (2026-10-10)

1. **cmd Two-Layer Quoting, Operator Protection & Variable Expansion Guard**: Implemented `escapeCmdCommand` in `cmdCommandPayload` using a state machine tracking the outer cmd double quote state when wrapped in `cmd.exe /d /s /c "<payload>"`. When inner double quotes cause the outer cmd to toggle out of quote mode, inner operators (`&`, `|`, `<`, `>`, `(`, `)`, `^`) become exposed to outer parsing (such as `&` in `echo "A&B"` or directories containing `&`). Operators outside outer quotes are caret-escaped (`^&`), allowing outer cmd to consume the caret and pass the literal characters to the inner cmd interpreter. Furthermore, because outer cmd parses and expands `%VAR%` and `!VAR!` at command-line parse time before launching child processes, if variable contents include double quotes or operators (such as `set X="A&echo OUTSIDE&rem "`), expanding them alters outer quoting and breaks out of protection to execute arbitrary commands. Until reliable inner variable expansion mechanisms are implemented, all commands containing `%` or `!` variable expansions are uniformly rejected (`ErrExecutionValidation`). Unbalanced quotes and illegal newlines/null characters are rejected early. Validated via unit tests and native Wine execution probes.
2. **SFTP Unconfigured Execution Preserves Legacy Entry Points**: When `execution` is unconfigured (`execCfg == nil`), SFTP `handleExec` routes through legacy compatibility entry points: `RunInteractiveCmdWithIO` for interactive sessions and `RunCommandWithIO` for batch mode. This avoids strict cancelable output checks (`RunCommandPlanWithIO` / `RunInteractivePlanWithIO`) that reject non-Linux native files without context writers, ensuring terminal and pipe streams on macOS and Windows operate without errors.
3. **SFTP Batch Execution Retains Non-Login Default**: Batch mode without execution config executes via legacy `RunCommandWithIO` using non-login `bash -c`. When execution is configured without an explicit `login` parameter, Bash batch planning explicitly assigns `opts.Login = LoginDisabled`, avoiding `nil.CommandOptions()`'s default `LoginEnabled` (`bash -l -c`) which could alter PATH or insert login banners into batch output.

## Phase P3 Validation Record: Release Default Switch, Script Interception & Native Multi-Platform Evidence (2026-10-10)

This batch completes all release default switch and acceptance items for Phase P3:
1. **Release Default Unified to server**:
   - CLI (`xops exec`, `xops ssh`), MCP (`xops_ssh_run`), Playbook (`shell` step), and core (`CommandOptions`, `EffectiveInterpreter`) uniformly default unspecified or absent execution configurations to the `server` interpreter with `unknown` launch dialect and `inherit` login mode. The user's command string is delivered verbatim to the SSH `exec` channel, eliminating implicit remote Bash dependencies.
   - Explicit compatibility configurations: Nodes or workflows depending on legacy Bash environments can pin their behavior explicitly via `execution: { interpreter: bash, launch_dialect: posix, login: true }`. CLI `--no-login` retains its legacy contract (selecting the non-login Bash compatibility path when an interpreter is not specified).
   - The `server` interpreter strictly accepts only `Login == nil` (`inherit`); explicit `login: enabled/disabled/true/false` is statically rejected (`ErrExecutionValidation`). `ResolveExecution` safely drops parent `login` configurations when the child specifies `server`, preventing accidental inheritance of illegal login modes.
2. **Early Script Interception for Absent Interpreters**:
   - Script executions consistently route through `ssh.ResolveScriptExecution` before dispatch. Scripts without an explicit interpreter and without an allowlisted shebang (or with missing/unsupported shebangs) immediately return `ErrExecutionValidation: server interpreter cannot be used for scripts` and are rejected before execution, preventing raw `server` defaults from being misapplied to scripts.
3. **Privilege Escalation and SFTP Boundaries**:
   - Unix escalation (`sudo`/`su`) without an execution configuration preserves legacy Unix Bash escalation compatibility. Specifying `server` interpreter for escalation is strictly rejected before execution.
   - SFTP `exec` uniformly integrates with `FormatWorkingDirCommand` and `PlanCommand`. Other `server` configurations explicitly reject non-empty working directories, while known server/cmd uses a temporary SFTP CMD adapter (`server interpreter does not support inheriting working directory`), preventing relative path operations from executing erroneously in remote HOME directories; `cwd == ""` executes verbatim.
4. **Native Windows and Bash-Free Unix Platform Evidence**:
   - **Native Windows OpenSSH**:
     - Default mode: `./bin/xops ssh vm dir` and `./bin/xops exec --host vm -c dir` executed without flags, successfully listing directories in the remote default cmd.exe shell (exit status 0, eliminating `'bash' is not recognized as an internal or external command`).
     - Explicit interpreters: PowerShell (`Get-Date`), pwsh (`$PSVersionTable.PSVersion` outputting 7.6.6), and cmd (`echo HelloFromCmd`) all executed successfully with exit code verification.
     - Script rejection: Scripts without a shebang failed immediately with `server interpreter cannot be used for scripts` and were blocked locally.
   - **Bash-Free Unix Platform (Alpine Linux Docker container, BusyBox ash/sh only, verified absent bash)**:
     - Default mode: `./bin/xops ssh root@127.0.0.1:22222 uname -a` and `./bin/xops exec --host alpine-test -c 'uname -m'` (outputting x86_64) executed natively in ash without errors.
     - Script dispatch: A script with `#!/bin/sh` was delivered via stdin to `/bin/sh` and executed successfully (outputting `Running on Linux in shell sh`); a script with `#!/bin/bash` returned exit status 127 `sh: bash: not found`; scripts without a shebang were rejected locally.
5. **Full Acceptance Metrics**:
   - `go build ./...`: passed
   - `go test ./...`: all passed
   - `golangci-lint run ./...`: 0 issues
   - `python3 scripts/check_core.py`: Linux, Windows, macOS boundaries and extracted module build/test all passed
   - `npm run docs:build`: passed



