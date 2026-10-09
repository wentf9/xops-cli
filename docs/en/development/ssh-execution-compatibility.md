# SSH Interpreter and Execution Compatibility Design

Status: implementation in stages. The source analysis baseline is `c1851bc`. P1-A implements command plans and a core execution API with finite stdin/bounded output, plus explicit server/Bash options for ordinary CLI exec commands. Remaining execution configuration, script/PTY/escalation migration, MCP extension fields, and default changes are still proposed. See the [implementation plan](./ssh-execution-implementation.md) for progress and restrictions, and installed help for release availability.

The goal is to remove the implicit Bash dependency from ordinary commands and give CLI, MCP, Playbook, SFTP commands, and privilege escalation consistent execution semantics. For current usage, refer to the [command execution guide](../guide/exec.md) and the installed version's help.

## 1. Goals and Scope

The eventual default for ordinary commands is `server` mode: send the command string unchanged in an SSH `exec` request and let the server's configured shell or device command interpreter process it. Explicitly select the corresponding capability when a particular interpreter, login environment, script execution, or privilege escalation is required.

| In scope | Not promised |
| --- | --- |
| Unix without Bash, Windows OpenSSH, and devices supporting SSH exec | Automatic translation of arbitrary POSIX commands into PowerShell or device commands |
| Explicit interpreter, launch dialect, login environment, and PTY selection | Inferring every execution capability from an SSH banner, `$SHELL`, or a single `uname` call |
| Consistent entry-point contracts for commands, scripts, shell sessions, and privilege escalation | An argv array, cwd, or general remote process management provided by SSH |
| Existing timeout, cancellation, output, and credential isolation guarantees | Proof that remote processes have stopped after disconnection, or exactly-once execution across the network |
| Explicit compatibility configuration for automation that depends on login Bash | Automatically rerunning a failed command with another interpreter |

Sending a command unchanged does not bypass the server's shell. The SSH `exec` payload is a string, not an argument array. Unix OpenSSH normally passes it to the user's configured shell; Windows OpenSSH depends on `DefaultShell` and its command options. Restricted accounts may also use a forced command. Devices supporting only interactive `shell` sessions require separate adapters; commands are not automatically injected through terminal input.

## 2. Current Implementation and Migration Surface

| Entry point | Baseline implementation | Migration requirement |
| --- | --- | --- |
| Ordinary `xops exec` commands | `Client.Run` uses `bash -l -c`; `--no-login` switches to `bash -c` | Support unchanged command forwarding and document differences from the old login environment |
| `exec --shell FILE` and exec stdin scripts | `RunScript` sends content to `bash -l -s` or `bash -s` | Separate the script interpreter from script input; the current shebang does not select the interpreter |
| `exec -x` | PTY plus login Bash through `RunInteractive`; currently does not pass `NoLoginShell` and suppresses nonzero command exit statuses | Keep PTY independent of the interpreter, fix exit-status propagation, and apply consistent login-option validation and scope |
| `ssh HOST COMMAND` | `RunCommandWithIO` wraps the command in `bash -c` | Handle the unchanged command separately from user stdin |
| `ssh HOST` with a terminal | `ShellWithIO` sends an SSH `shell` request | Preserve server shell semantics without another wrapper |
| `ssh HOST` with no command and piped stdin | The empty-command path starts Bash to read input | Explicitly distinguish a non-PTY shell session from a script with a specified interpreter; do not send an empty exec request |
| SFTP batch `exec` | POSIX `cd 'cwd' && ...` plus the Bash wrapper in `RunCommandWithIO` | Address both working-directory quoting and interpreter selection |
| SFTP interactive `exec` | Sends POSIX `cd 'cwd' && ...` directly, without an extra Bash wrapper | Still assumes a POSIX dialect and cannot establish general cross-platform support |
| MCP `xops_ssh_run` | The ports/backend ultimately calls `Run` or `RunWithSudo` | Resolve and bind the same execution options |
| Playbook shell and ensure | `Run` or `RunWithSudo` | Use the same effective configuration for shell, check, and action |
| Playbook script | Reads a local file and runs its contents through stdin | Do not treat it as a remote executable that has been uploaded with its shebang preserved |
| sudo/su, system detection, and streaming monitoring | Separate Bash or Unix-command assumptions in multiple places | Declare and migrate their capabilities separately; changing only `Run` is insufficient |

Main source entry points:

- [SSH Client and RunConfig](../../../core/ssh/client.go), [execution and privilege escalation](../../../core/ssh/execute.go)
- [Privilege authentication protocol](../../../core/ssh/privilege_exchange.go), [quoting for login privilege escalation](../../../core/ssh/privilege_terminal.go)
- [CLI exec](../../../cmd/exec.go), [CLI SSH](../../../cmd/ssh.go), [SFTP shell](../../../cmd/sftpshell/shell.go)
- [Shared MCP backend](../../../core/mcp/sshexec/backend.go), [CLI host backend](../../../internal/mcphost/host.go), [Playbook runner](../../../pkg/playbook/runner.go)

## 3. Unified Execution Model

Execution proceeds through caller input → configuration resolution → immutable execution plan → required policy checks/approval → SSH session execution → results and cleanup. CLI execution authorization and MCP guardrails remain separate systems.

`core/ssh` owns plan validation, interpreter adapters, and the session lifecycle. Conversion of CLI configuration, node models, command arguments, Playbook YAML, and MCP schemas stays in their respective entry points, without introducing reverse dependencies into core. Existing `Run`, `RunScript`, `RunCommandWithIO`, interactive, and streaming methods gradually delegate to the unified implementation instead of maintaining separate string-wrapping logic.

### 3.1 Operation Kinds

| Kind | Protocol and input | Rules |
| --- | --- | --- |
| Command / server | One SSH exec string, with optional separate stdin | Do not change command bytes or prepend a shell, environment, or cwd; retain necessary protocol input validation |
| Command / explicit interpreter | An interpreter adapter constructs the exec request | The launch dialect, user interpreter, and login mode must form a supported combination |
| Script | Finite script content, an explicit interpreter, and optional separate runtime input | Not equivalent to a multiline server command; script source and stdin ownership must be explicit |
| Shell session | SSH shell request, with optional PTY | Do not turn missing command input into an empty exec request or implicitly insert Bash |

PTY is an independent session property. It does not imply an interactive shell, login shell, or Bash. `exec -x` executes one command, and the new model must propagate its exit status. In the baseline, ordinary and elevated PTY commands reuse shell logic that ignores `ssh.ExitError`. Fixing this behavior is a P1 compatibility exception and must be documented in the release notes. Full login sessions retain the existing shell-session contract.

"Unchanged" applies to the command string constructed by the entry point: `exec -c STRING` preserves the bytes of STRING; positional arguments and `ssh HOST COMMAND...` retain the existing space-joining rule. They cannot restore quotes removed by the local shell or promise equivalent remote argv. After plan construction, do not trim, retokenize, or normalize newlines. Preserve whether the command argument was supplied: an explicitly empty command is an error and must not switch to reading a script or starting a shell. Only an absent command enters the corresponding input route.

### 3.2 Semantic Fields in an Execution Plan

The following is a logical model, not a commitment to specific Go type names:

| Field | Meaning |
| --- | --- |
| Operation kind | command, script, or shell session |
| Command or script | Original content; scripts use controlled, finite input to avoid duplicate unbounded buffering when constructing the plan |
| Interpreter | `server`, `sh`, `bash`, `powershell`, `pwsh`, or `cmd`; expose only implemented and validated adapters |
| Launch dialect | How the server parses generated launch commands, such as POSIX, PowerShell, cmd, or unknown |
| Login mode | `inherit`, `enabled`, or `disabled`; unspecified and explicitly disabled must remain distinguishable |
| Working directory | Available only through a known dialect/adapter; SSH has no universal cwd request |
| PTY, I/O, and deadlines | Terminal allocation, stdin ownership, output policy, cancellation, and timeouts |
| Privilege escalation | A separate target identity and sudo/su policy, not an arbitrary prefix attached to an interpreter string |

`server` allows an unknown launch dialect because it generates no command wrapper. With an explicit interpreter, the interpreter and the outer launch dialect are separate dimensions: launching PowerShell from cmd requires different quoting from launching it through a POSIX shell. Unknown or unsupported combinations must fail before the user command is sent.

POSIX `shellQuote` is not a universal cross-platform function. Each adapter defines and tests PowerShell encoded payloads, cmd command options, script exit status, and related behavior. Encoding does not change the approval subject or provide confidentiality. Paths, command content, and unvalidated interpreter arguments must not be concatenated directly into launch templates.

Each available adapter must publish a support matrix covering launch dialect, command/script, login, cwd, PTY, escalation, and independent stdin. Unimplemented combinations are explicitly rejected; "PowerShell support" does not imply support for every combination. Initially, the new Bash adapter defaults to non-login mode when login is unspecified, and the sh adapter supports only non-login mode. Legacy entry points preserve their individual behavior through explicit compatibility plans. Before Windows adapters become available, define their executables, launch arguments, profile policies, command-length/encoding limits, and exit-code mappings; callers must not have to guess these differences.

### 3.3 Session Lifecycle and I/O Ownership

The unified layer must close cancellation gaps in the baseline. The existing `startWithTimeout` must not be treated as covering every blocking phase:

- Connection establishment, session creation, PTY requests, exec/shell requests, privilege handshakes, input/output, execution waits, and closure are all governed by context and explicit deadlines. Establish cancellation paths before calling `Start`/`Shell`/`RequestPty`; an unanswered server request must still return within a bound. Interactive sessions may use bounded request, network I/O, and closure deadlines; a short command's total-duration limit is not a substitute for an interactive-session policy.
- Cancellation first closes the current channel. If closure remains blocked, its transport may be interrupted. Other operations on a shared connection or ProxyJump may also be affected: mark only dispatched operations without a terminal result as unknown; undispatched operations remain not_started, and operations with a result remain completed with additional connection or cleanup errors. Discard the damaged connection without transparent replay. Do not unintentionally change other sessions' execution deadlines by modifying a shared TCP deadline.
- Distinguish borrowed and owned input/output. Do not close the caller's standard streams. The creator closes temporary files, duplicated handles, sessions, and bridges, and joins their goroutines. New I/O interfaces accept only readers/writers that can finish deterministically or be canceled. Adapting a blocking terminal or pipe requires a cancellation bridge; wrapping an arbitrary blocking `Write` in an abandoned goroutine does not provide cancellation.
- stdin EOF closes only the sending direction; continue reading output and waiting for the exit result. Consume stdout and stderr concurrently. At the buffer limit, continue draining or explicitly terminate according to the selected policy; stopping reads must not block the remote process. Preserve the existing combined-output and streaming-output contracts. With a PTY, do not promise separate stderr or binary byte transparency.
- Record session exit, output-collection failures, and cleanup failures separately; make output truncation visible. Closing the transport neither proves remote process termination nor resolves a blocked local output writer. Each path requires its own cancellation and test evidence.

## 4. Interface and Configuration Proposal

### 4.1 CLI

Add `--interpreter`, `--launch-dialect`, and `--login-shell`, with the latter controlling the login environment of an explicit interpreter. Launch dialect accepts `posix`, `powershell`, `cmd`, or `unknown`. If unspecified, inherit it from configuration or use unknown; do not infer it from the local OS or inner interpreter. `--shell` already denotes a local script file, and `--login`/`-l` already denotes the SSH user; neither may be repurposed.

The following examples describe the final interface. P1-A implements server/Bash for ordinary buffered commands; new options for sh, scripts, and PTY remain pending. The first example states the eventual default explicitly so that it can be used during migration:

```bash
xops exec --host alpine-01 --interpreter server -c 'uname -a'
xops exec --host win-01 --interpreter server -c 'powershell.exe -NoProfile -Command Get-Date'
xops exec --host linux-01 --launch-dialect posix --interpreter bash --login-shell -c 'printf "%s\n" "$PATH"'
xops exec --host alpine-01 --launch-dialect posix --interpreter sh --shell ./check.sh
xops exec --host linux-01 --interpreter server -x top
```

`ssh HOST COMMAND` uses the same interpreter options. SFTP `exec` inherits execution configuration from the session's node. Any necessary override interface should reuse the same model without introducing a separate implicit detection policy.

Login-option contract:

- During compatibility migration, `--no-login` continues to mean the existing non-login Bash behavior. Without an explicit interpreter, it selects the compatible Bash path rather than being reinterpreted as server mode.
- Explicit `--interpreter bash --no-login` disables Bash login mode. Combining it with `--login-shell` is an error.
- Combining `--no-login` with explicit server, PowerShell, cmd, or sh is an error, avoiding an expansion of the old option's meaning. New sh login options are accepted only when the adapter declares support.
- server accepts only login mode `inherit`. Explicitly enabling or disabling login mode is an error because XOps cannot guarantee whether the server reads startup files.
- PowerShell profile loading is not POSIX login. `--login-shell` does not control PowerShell profiles; support, if needed, requires separate, verifiable adapter configuration.
- `-x` uses the same option resolution and no longer ignores configured login mode.

New options preserve presence: `--login-shell=false` means explicitly disabled and, like `--login-shell=true`, cannot be used with server. Without an accompanying interpreter option, `--login-shell` only adjusts the resolved interpreter if it supports login; it does not implicitly select Bash. The legacy `--no-login` path also pins its POSIX launch assumption and fails if the node declares an incompatible dialect. Old entry points retain their original launch assumptions when new configuration is absent; a new explicit Bash request still requires a known launch dialect.

### 4.2 Configuration Inheritance

Default execution configuration belongs to a Node, not merely a Host address. Different accounts, ports, or restricted login policies at the same address may have different execution environments.

Proposed precedence for ordinary commands: explicit invocation parameters/Playbook step → Playbook settings → Node execution → global execution → defaults for the current release stage. Ordinary CLI commands and MCP calls skip inapplicable Playbook layers. Scripts also account for shebangs; section 5 defines their interpreter selection order.

Resolve the interpreter and its specific options as a coherent configuration. Overriding the interpreter must not accidentally inherit `login: true` from the previous interpreter. Incompatible explicit options are errors; unspecified interpreter-specific options return to the new interpreter's defaults. The launch dialect still describes the server and must not change automatically when the inner interpreter changes.

Configuration must preserve the difference between an absent field and explicit false. Core receives resolved configuration and does not read global YAML. Node configuration, versions, and execution-plan snapshots remain consistent; execution policy must not be reread ad hoc from mutable fields on a long-lived connection.

The following proposed execution object may appear in Node or global configuration; Playbook settings/steps reuse its semantics. YAML uses `launch_dialect`, corresponding to `launchDialect` in MCP JSON. An absent login field maps to inherit, and boolean values map to enabled/disabled. Unsupported enum values and fields are errors.

```yaml
# Known POSIX login environment; preserve login Bash for ordinary commands
execution:
  interpreter: bash
  launch_dialect: posix
  login: true
```

```yaml
# Windows OpenSSH is confirmed to launch commands through cmd; run user commands in pwsh
execution:
  interpreter: pwsh
  launch_dialect: cmd
```

A dialect declared in invocation parameters selects a launch adapter; it does not automatically become trusted platform evidence for MCP risk analysis. If it conflicts with published node capabilities or lacks trusted metadata, risk assessment still treats the dialect as uncertain or policy rejects it. Supplying `posix` in a request must not obtain a safe-prefix exemption.

### 4.3 Core, MCP, and Playbook

Core adds explicit execution options. During migration, the old `WithLoginShell` maps to defined Bash compatibility semantics. Conflicts between old parameters and new options are rejected; option application order must not change the result.

MCP `xops_ssh_run` may add an optional execution object, passed consistently through ports/backend. Its absence follows the release stages in section 9; compatibility mode is not inferred from whether a client sends the new fields. Clients must not submit internal snapshots, permits, or binding digests.

Playbook settings and steps may add execution configuration. shell, ensure.check/action, and script must all apply the resolved result. Once the script interpreter is defined, `--var` or template substitution must not replace approved semantics during execution.

Before scheduling, Playbook freezes workflow inputs: complete variable rendering, read local scripts within bounds, compute content digests, and then resolve plans per node+step. Expand target-dependent variables before constructing the corresponding plan. All targets use the same set of script-source bytes; every retry reuses the plan and content instead of rereading script paths. Construct ensure check/action/verify plans from the same snapshot. File or configuration changes require a new workflow execution and must not alter plans already running.

## 5. Scripts, stdin, and Shell Sessions

The new script model selects interpreters in this order: explicit invocation/Playbook step configuration → an interpreter explicitly specified in Playbook settings → supported shebang declaration → Node execution → global execution. Only non-server interpreters in the last two layers can serve as script defaults; a Node configured as server does not block a configured global script interpreter. Explicitly selecting server for a script in an invocation or workflow is an error; do not ignore the explicit request and continue inference.

In P1/P2, old script entry points without new execution configuration always resolve to legacy Bash and continue ignoring shebangs; they do not adopt the new inference rules early. New execution configuration includes explicit invocation, workflow, node, or global configuration. In P3, scripts use the new model by default and fail before execution if no reliable interpreter is available; the server default must not be treated as a script interpreter.

Shebang recognition uses a limited allowlist. Initially, it recognizes supported `sh` and `bash` paths or `/usr/bin/env sh|bash` without extra arguments. It does not parse arbitrary shell expressions or `env -S`, or automatically execute arbitrary shebang arguments. PowerShell/cmd scripts should preferentially specify the interpreter explicitly. File extensions may inform diagnostics but do not select the interpreter on their own.

In the new script model, distinguish an absent shebang from a declared but unsupported shebang. The latter fails unless an invocation/workflow explicitly overrides the interpreter; it must not silently fall back to Node/global Bash. For example, `#!/usr/bin/python3`, `#!/bin/bash -e`, and `env -S` must not be treated as scripts without a declaration. When an invocation/workflow explicitly overrides the interpreter, execute the original bytes with the selected interpreter without implicitly importing shebang arguments.

| Input scenario | Rules |
| --- | --- |
| Command with stdin | stdin is user data and is not used to wrap the command again |
| `exec --shell FILE` | FILE is client-local; script bytes are passed to the selected script adapter |
| Piped exec input with no command | Still recognized as a script, with the interpreter resolved according to the rules above |
| Non-terminal `ssh HOST` with no command | With an explicit interpreter, treat input as a script; in server mode, send an SSH shell request without a PTY and forward stdin/EOF |
| Script and runtime stdin both present | The adapter needs separate transport for each; otherwise fail beforehand instead of concatenating the two inputs |

These input rules describe unified-layer capabilities; they do not automatically enable stdin for every CLI entry point. The baseline `exec -c` does not forward piped data, and P1 preserves that behavior. If P2 adds runtime input, it must provide an explicit opt-in and update help. Initially, only a single node may consume live input; reject multi-node requests before dispatch rather than allowing goroutines to compete for the same stdin. Existing exec script input with no command may be read once within bounds, then supplied through an independent reader for each target. Script reads require size limits and cancellation deadlines; exceeding a limit fails before remote execution. Assign a single owner to password input, script sources, and runtime data before reading. Reject conflicting combinations instead of assuming that data after a password line remains available as script or user input.

Routing for `ssh HOST` with no command must distinguish release stages: P1/P2 retain the original non-terminal Bash behavior when new configuration is absent; the new model selects a script or non-PTY shell according to the effective interpreter. A native shell session with a terminal does not inherit interpreter/login configuration for ordinary commands. Explicitly requesting a non-server interpreter or login options is an error; do not silently ignore them or switch to exec. Preserve exit statuses from non-PTY shells rather than applying the terminal login-session policy that ignores nonzero statuses.

PowerShell may use a defined encoded payload or a temporary script file. Validate terminating/non-terminating errors, native program exit codes, Unicode, and output encoding rather than assuming Bash-equivalent behavior. Temporary files must be private and uniquely created, with bounded cleanup paths for cancellation and failure. Report cleanup outcomes that cannot be confirmed.

Scripts do not undergo silent BOM removal, newline conversion, or transcoding. Shebang recognition may ignore a trailing CR on the first line when reading metadata but must not modify the body on that basis. If the selected adapter does not support the BOM, CRLF, or encoding, provide diagnostics before execution. Any explicit conversion must occur before digests, approval, and the execution plan are formed.

## 6. Privilege Escalation, Working Directories, and Built-in Operations

### 6.1 Unix Privilege Escalation

Forwarding ordinary commands unchanged does not implement Windows UAC or device enable modes. Initial privilege escalation remains limited to declared supported Unix sudo/su combinations. When root is already the target identity, escalation must not introduce extra Bash wrapping.

Separate privilege control scripts from the user interpreter. The current ready/ack flow primarily uses POSIX capabilities such as `printf`, `read`, `test`, and `unset`; running it through `/bin/sh` can be investigated. PTY handoff still requires the corresponding terminal capabilities, such as `stty`. The current `sudoLoginScript` uses Bash ANSI-C literals to handle the second parsing pass in `sudo -i`; mechanically replacing Bash with sh is invalid. `su -c` also requires accounting for additional parsing by the target user's shell.

Initially retain the validated Bash login-escalation adapter. Enable POSIX sh escalation only after separate acceptance in an environment without Bash. After sudo/su, the user command uses the resolved target interpreter, which must not be assumed to match the login account's server shell. Combining server mode with escalation first requires resolving a supported target execution policy; if that cannot be determined, fail before execution.

The following must be preserved:

1. Send passwords only after recognizing an authentication prompt. Passwordless paths consume neither passwords nor user stdin.
2. Preserve the sequence elevated-ready → ack → required terminal echo restoration → terminal-ready → user input.
3. Passwords, control frames, and ack must not enter user command input, be echoed, or be logged.
4. Retry authentication only when rejection is confirmed and the user command has not started. Failed escalation must not fall back to execution as the ordinary user.
5. Timeouts, cancellation, session closure, input goroutine termination, and local terminal restoration all have deterministic paths.

### 6.2 SFTP Working Directories and File Operations

SFTP directory state is independent of the process directory used by SSH exec. Pure server mode always rejects automatic cwd handling, even when the launch dialect is known; it cannot promise byte-for-byte forwarding while inserting `cd`. An `exec` operation that needs to inherit the current SFTP directory must explicitly select an interpreter adapter capable of generating a working-directory operation. Otherwise, report the unsupported combination before sending the user command.

The generated cwd expression enters the execution plan together with the user command. POSIX, PowerShell, and cmd each handle path quoting and failure propagation. Do not execute the user command after a failed cwd change or silently ignore the current SFTP directory when an adapter is missing. P3 migration instructions must include this restriction.

Pure SFTP listing, copying, moving, deletion, and transfer do not require a remote shell. MCP file operations currently implemented through POSIX `cp -r` and `rm -rf` should be evaluated for migration to shared SFTP file capabilities. Migration must cover directory recursion, symbolic links, overwrite policy, permission errors, cancellation, and existing guardrail bindings; the two backends must not be assumed equivalent.

### 6.3 Built-in Detection and Scripts

`RunWithoutLogin`, `RunStream`, automatic sudo detection, monitoring probes, TUI logs, and generated firewall commands must individually declare interpreter and platform requirements. Their behavior must not drift along with the ordinary-command default.

Ordinary server execution does not automatically send probes such as `uname` or `command -v`. Necessary capability checks must be separate, bounded, and appropriate to a known environment. Interpreter selection must not be inferred from user-command failures, and user commands must not be executed as a probe. Caches may be bound only to the actual target, identity, and configuration version, not shared across users by address alone.

## 7. MCP Approval, Errors, and Retries

Before approval, MCP resolves and freezes the original command, effective interpreter, launch dialect, login mode, working directory, escalation policy, and relevant node versions. The same execution plan is used for risk assessment, approval display, admission, backend execution, and auditing. After approval, node defaults must not be reread and the dialect must not change.

Bindings must integrate with the existing version and digest paths: `ports.OperationSnapshot.Digest` currently does not hash the global Revision, and target versions in the CLI host include only existing connection/credential dependencies. When adding execution fields, include effective Node/global execution configuration, adapter versions that affect the payload, and the final plan digest in the binding; update state change classification and admission validation together. A change to global execution defaults alone may invalidate approval. Changes to unrelated global fields explicitly overridden by the node should not cause invalidation. Keep execution-configuration versions separate from credential-update tokens; credential changes must not conceal execution-semantic changes.

Approval displays the readable original command and its effective semantics. The final execution payload or its digest should also be associated with the same plan. Encoded commands must not bypass risk checks. Risk analysis must declare the dialects it covers. An unknown server dialect must not be automatically classified as safe using POSIX safe-prefix rules; it follows an explicit policy for uncertain risk. The CLI Skill continues to use the CLI and does not inherit MCP approval flows merely because core is unified.

| Failure point | Handling |
| --- | --- |
| Invalid configuration or unsupported interpreter/escalation/cwd combination | Reject before sending the user command and report the missing capability |
| Authentication explicitly rejected before the user command starts | Authentication may be retried within existing limits; do not change the command interpreter |
| User command returns a nonzero status or 127 | Report the failure unchanged; do not infer that execution never occurred |
| Connection loss, timeout, or missing exit status after the exec request is sent | Report an uncertain execution outcome and collected output; do not promise the absence of side effects or remote termination |
| Local cancellation or audit/cleanup failure | Preserve the original execution result and additional errors; do not repair the failure by automatically rerunning the command |

The unified layer must provide structured execution results rather than only string errors. The baseline `Connected` field in `ports.CommandResult` and MCP `status: failed` cannot support the classifications above. Results must include at least the plan digest, execution phase, `not_started`/`completed`/`unknown`, optional exit code/signal, collected output and a truncation flag, execution error, and additional I/O/cleanup errors. Preserve them across core, ports, MCP, and Playbook. An absent exit code is not zero; `completed` means only that a terminal result was received, not success or the absence of side effects.

Use `not_started` only where it is possible to prove that the user operation did not start, such as local validation failure or an explicit server rejection of the startup request. Once sending an exec/shell request begins, treat execution as possible; do not wait for `Start` to return successfully before marking it. A lost request response also yields unknown. If an exit status was received and only output draining, auditing, or cleanup failed, retain completed and the exit result, and prohibit replay caused by those additional errors. Preserve signal information for signal exits. Missing exit status must not be inferred as success from EOF, empty output, or disconnection. Old APIs may map results to typed errors, but must retain the classification needed to prohibit retries.

A single execution attempt sends the user operation only once and provides no implicit shell fallback. User-configured Playbook `retries` are a separate policy, not a compatibility fallback. Each retry uses the same effective interpreter. Failures with an uncertain outcome after dispatch must not be automatically replayed by the ordinary retry loop; callers must verify and explicitly handle them. Network and shell protocols do not provide an exactly-once guarantee across failures.

Playbook `ensure` must also distinguish a check that confirms an unmet condition from a check that did not complete reliably. The baseline turns any check error into an action. Under the new model, run the action only after receiving a defined and confirmable "condition not met" result. Configuration errors, interpreter startup failures, timeouts, disconnections, and uncertain exit statuses stop that ensure step. An arbitrary nonzero exit code does not establish an unmet condition; results such as 127 that cannot distinguish a missing command from startup failure must not automatically trigger changes.

P2 must define and document the check-result contract and compatibility migration. For example, replace a check that installs software when `nginx -v` fails with an explicit existence check using `command -v nginx` in a known POSIX environment. Even with an expected exit code, rule out execution-layer failures first. When server mode cannot reliably make that distinction, stop and report an uncertain check result. Implementing check-result classification and migrating old ensure use cases are prerequisites for P3.

This restriction also applies to explicit interpreters: `completed + exit 1` may come from a Bash login startup file or an outer wrapper and does not by itself prove that check returned "condition not met." Combinations that allow an action must have a validated check-result protocol confirming that check was entered and that the status came from check, for example through a controlled wrapper and separate result frames. Control information must not enter user output or change the unchanged-command contract for ordinary commands. Without this capability, reject that ensure combination or report an uncertain check result; an expected-exit-code allowlist is insufficient. Include this capability in the adapter matrix, and test early startup-file exits, outer-launch failures, and lost result frames.

## 8. Compatibility Risks and Alternatives

| Approach | Assessment |
| --- | --- |
| Replace every `bash` with `sh` | Still does not cover Windows/devices, and breaks Bash scripts, login behavior, and escalation quoting |
| Try Bash/sh/PowerShell in sequence after failure | May repeat side effects; exit codes cannot reliably establish whether execution occurred |
| Automatically detect OS/shell before every request | Adds round trips and restrictions, and probes themselves may be incompatible; not used for ordinary server execution |
| Add only a raw flag while other entry points keep their own wrappers | Preserves differences between entry points and implicit dependencies, preventing unified maintenance |
| Default to server with explicit interpreter adapters | Selected; separates original command semantics from advanced capabilities that generate commands |

The default switch affects `.bash_profile`, PATH, Bash extensions, quoting, startup output, and environment variables. Compatibility requires explicit Bash and login-mode configuration, not continued implicit wrapping based on automatically identifying an "old user" or "Linux host."

## 9. Implementation Stages and Default Migration

| Stage | Deliverables | Default behavior and exit criteria |
| --- | --- | --- |
| P1: Unified plan and explicit server | Core unifies command/I/O/PTY paths, structured results, and bounded cancellation; CLI supports explicit server and Bash selection; existing methods delegate to the unified layer | Without new options, preserve each entry point's baseline behavior except for the PTY exit-status fix; unchanged-request, unanswered-request, stdin, PTY, and legacy-mode regressions pass |
| P2: Adapters and caller migration | sh and Windows adapters, scripts, escalation, SFTP cwd; MCP/Playbook configuration and bindings; ensure check-result classification; individual migration of built-in operations | Interpreter defaults remain compatible; unsupported combinations are explicitly rejected, platform and cross-entry-point matrices pass, and public contracts and consumers are updated together |
| P3: Default switch | Ordinary-command defaults in CLI, MCP, Playbook, and core become server; publish migration instructions | Enable at a defined release boundary; nodes/workflows relying on old behavior can explicitly pin Bash+login; do not guess interpreters for scripts without one |

The release plan assigns the P3 version after acceptance. No released version is claimed in advance to have the new default. Missing fields in old configurations, old MCP requests, and new requests all follow the same rules within a stage; only explicit configuration preserves old behavior. The compatibility interpretation of `--no-login` remains as defined in section 4 and must not change with the default switch.

Configuration or MCP schema changes require updates to serialization/schema fixtures in `internal/clicontract`, documentation, and consumer adapters. Also cover bidirectional NodeV2/global DTO conversion, cloning, import/export, and round-trip tests for absent fields and explicit false. Shared-core consumers must verify the defaults and binding semantics of new fields before upgrading their dependency.

Migrate compatibility configuration by operation kind. Ordinary commands can be pinned through Node/global Bash+login configuration. For scripts, shebang takes precedence over Node/global configuration, so node-level Bash alone cannot preserve all legacy script semantics. Workflows depending on legacy scripts must explicitly configure Bash+login at the invocation or Playbook settings/step level, with a known launch dialect, to override the shebang; for example, `exec --interpreter bash --launch-dialect posix --login-shell --shell FILE`. This rule also applies in P1/P2 whenever new execution configuration is enabled.

Roll back the default switch through the explicit configuration above or a compatible release that already supports the execution schema. Baseline configuration loading uses `KnownFields(true)`: after new fields have been persisted, an older binary that does not support them rejects the entire configuration. Rolling back further requires restoring the corresponding backup or exporting compatible configuration through a controlled process and validating semantic differences. A release rollback does not imply direct downgrades to arbitrary versions, and there is no fallback after a running command fails.

Current status: P1-A command foundations are implemented; P1-B and P2/P3 remain pending. P1 is not complete as a whole. This document describes the final contract; see the [execution guide](../guide/exec.md) and implementation plan for the currently available CLI subset and limits.

## 10. Verification and Acceptance

| Dimension | Required evidence |
| --- | --- |
| SSH requests | Exact preservation of server strings; positional-argument joining boundaries; separate validation of explicit empty versus absent commands, shell requests, PTY, and exec |
| Unix interpreters | BusyBox ash and dash in environments where Bash is actually absent; explicit Bash login/non-login |
| Windows | Native Windows OpenSSH with cmd/PowerShell defaults; explicit powershell.exe/pwsh; missing interpreters |
| Quoting and data | Single/double quotes, backslashes, newlines, Unicode, `$HOME`, `$(...)`, `%VAR%`, and `&`; combinations of inner and outer interpreters |
| Scripts and stdin | Shebangs, rejection and explicit overrides of unknown/argument-bearing shebangs, BOM/CRLF, empty scripts, EOF, runtime input, binary stdin, size/read-timeout boundaries; no script rereads across targets or retries; password/stdin ownership conflicts |
| SFTP | cwd for batch/interactive exec, directories containing spaces/quotes, rejection of unknown dialects; pure file operations without a Bash dependency |
| Privilege escalation | root, NOPASSWD sudo, password sudo, sudo-rs, su, success after an incorrect password, passwordless input protection, and multiple expansion layers in `sudo -i`/`su` |
| PTY and lifecycle | Fragmented prompts, incorrect ack, EOF before handshake, first-character preservation, echo/raw restoration; nonzero and signal exits for ordinary/root/passwordless sudo/password sudo/su PTY commands; unanswered session/PTY/exec/shell requests; cancellation of blocked input/output; shared-transport interruption effects; no goroutine/session leaks after cancellation |
| Execution results | Not-started/completed/unknown outcomes preserved across entry points; startup request sent but response lost; missing exit status; no replay after output/audit/cleanup failures following success; visible output truncation |
| Side-effect count | No replay with another interpreter after nonzero status, 127, or disconnection/timeout after startup; boundaries for explicit Playbook retries and uncertain outcomes; ensure.check execution-layer failures, early login startup-file exits, and lost result frames do not trigger action |
| Entry-point consistency | CLI, MCP, Playbook, and host backends use the same plan; changes only to Node/global execution invalidate old approvals while unrelated global fields do not; request-supplied dialects cannot lower risk classification |
| Migration | P1/P2 legacy entry-point behavior and the explicit exit-status exception; P3 consistent defaults, separate Bash compatibility configuration for commands and scripts, old-option conflicts, schema round trips, rollback-version boundaries, and matching Chinese/English contracts |

During feature implementation, run `go build ./...`, `go test ./...`, and `golangci-lint run ./...`, plus relevant race and integration tests for SSH/I/O/escalation. Public-boundary validation follows the isolated extraction and consumer checks in the [shared-core design](./shared-core-decoupling.md).

SSH fixtures can prove which requests were sent, but cannot replace real-shell interpretation tests. A machine where `/bin/sh` links to Bash cannot establish operation without Bash. Cross-compilation and Wine cannot replace native Windows OpenSSH/PTY acceptance. Missing platform evidence must be explicitly recorded. Passing documentation/schema checks does not mean this design has been implemented.

Protocol references: [RFC 4254 sections 5.3, 6.5, and 6.10](https://www.rfc-editor.org/rfc/rfc4254.html) define EOF, exec/shell requests, and exit status respectively; the [Go SSH Session documentation](https://pkg.go.dev/golang.org/x/crypto/ssh#Session.Wait) distinguishes unsuccessful exits, missing exit status, and I/O errors; the [Windows OpenSSH configuration guide](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration) describes `DefaultShell`. These protocol capabilities do not replace the real-platform adapter validation required by this design.
