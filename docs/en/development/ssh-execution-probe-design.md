# SSH Interpreter and Launch Dialect Automated Probing Design

**Status**: Milestones M1–M4 implemented (see [implementation record](./ssh-execution-probe-implementation.md) for rollout criteria, protocol refinements, and verification scope).

**References**: [SSH Multi-Interpreter Execution and Compatibility Design](./ssh-execution-compatibility.md), [SSH Execution Compatibility Implementation Plan](./ssh-execution-implementation.md)

**Language**: English Development Documentation

---

## 1. Goals and Boundaries

### 1.1 Background
Following the P3 phase release of `xops-cli`, regular commands without an explicit execution configuration default to `interpreter: server, launch_dialect: unknown, login: inherit`. This mechanism allows standard commands to pass directly and natively to the remote server's default shell without extra wrapping.

However, advanced automation workflows impose stricter requirements:
- **Playbook `script` steps**: Require a known script interpreter adapter (such as `bash` or `sh`); direct script execution via `server` mode is rejected.
- **Playbook `ensure` inspection steps**: Require a controlled shell adapter other than `server` to capture exit status control frames.
- **SFTP `exec` working directory inheritance**: `server` mode explicitly rejects attaching a `cwd`; a known `posix`, `cmd`, or `powershell` adapter is required.
- **Unix privilege escalation (`sudo`/`su`)**: Strictly blocked under non-POSIX dialects or unconfigured execution environments.

Relying entirely on manual configuration of `interpreter` and `launch_dialect` in node profiles (`nodes.<node>.execution`) or global configs is high-overhead and error-prone (e.g. misconfiguring a POSIX dialect on a Windows `cmd.exe` node can cause garbled command output or execution errors).

### 1.2 In Scope vs. Non-Goals

| In Scope | Not Promised |
| :--- | :--- |
| Automatic identification of remote SSH server outer launch dialect (`posix`, `fish`, `csh`, `cmd`, `powershell`) | Inferring full environment capabilities solely from SSH Banner, `$SHELL`, or a single `uname` call |
| Automatic enumeration of installed interpreters on the target node (`bash`, `sh`, `zsh`, `fish`, `csh`, `tcsh`, `powershell`, `pwsh`, `cmd`) | Translating arbitrary cross-platform syntax (e.g. translating POSIX pipelines to PowerShell) |
| Automatic probing on initial node enrollment with atomic persistence to Schema V2 config | Automatically switching interpreters to retry user commands after failure |
| Connection-level session memory caching and controlled runtime on-demand lazy probing | Probing without network timeouts, blocking indefinitely |
| Read-only, side-effect-free, and MOTD/banner-noise-resilient probing lifecycle | Allowing probes to create temporary remote files or leave orphan processes |

---

## 2. Architecture and Four-Level Integration Model

To balance zero-config convenience with minimal network latency, probing uses a **four-level integration model**:

```
Level 1: First Enrollment   ──► Triggered on adding new nodes; reuses verification session; atomically saved to YAML
Level 2: Manual Diagnostic  ──► Triggered via `xops host probe`; renders tabular summary; optional `--save`
Level 3: Lazy On-Demand     ──► Triggered only when executing script/ensure/cwd against an unknown execution profile
Level 4: Session Cache      ──► Shared globally within a single SSH Client lifecycle; 0 extra network RTT
```

### 2.1 Level 1: First Enrollment Probing & Persistence (Core Focus)
Targets the critical lifecycle event when a node is added for the first time:

1. **Explicit Addition Paths (`xops host add` / `xops host load`)**:
   - `cmd/host/add.go` validates connection and credentials via `verifyInventoryNode` unless `--skip-verify` is supplied.
   - **Connection Reuse**: Directly reuses the authenticated underlying `ssh.Client` connection from verification to run the two-stage probe in the same session without repeating TCP handshakes or authentication, adding only 1–2 probe command RTTs (~20–80ms).
   - **Automatic Configuration Persistence**: Assigns the recommended `ExecutionConfig` directly to `node.Execution` of the pending node, committing atomically to `schema_v2` YAML alongside other fields (`HostRef`, `IdentityRef`, `Tags`).
   - **Flags**:
     - `--probe` (default true): Automatically probes and saves configuration.
     - `--no-probe`: Skips probing; `node.Execution` remains `nil` (default `server` mode).
     - Explicit `--interpreter` or `--launch-dialect` flags take precedence over recommended values and skip probing corresponding fields.

2. **Dynamic JIT Enrollment (`xops exec --host ...` / `xops ssh ...`)**:
   - When connecting to an unconfigured target host, `repository.PrepareNodeContext` returns `res.Created == true`.
   - If credential remembering is enabled (e.g. `--remember` or configured remember policy), a lightweight probe executes before the first command, saving the generated `ExecutionConfig` alongside node metadata.

3. **Batch Import Path (`xops host load`)**:
   - Executes probes concurrently across the verification pool during import.
   - Hosts where probing fails smoothly fall back to unconfigured state without aborting the overall batch import.

### 2.2 Level 2: Diagnostic Inspection (`xops host probe`)
- Provides explicit diagnostic command: `xops host probe <node-id>`.
- Displays human-readable tables detailing remote OS, outer shell path, available interpreters, and suggested configuration.
- Supports `--save` flag to write recommended configuration back into the local configuration file.

### 2.3 Level 3: Runtime Lazy On-Demand Probing
- Triggered if and only if the node's effective configuration is the default `server` + `unknown` and:
  - Running a Playbook `script` step without a shebang and without an explicit interpreter; unsupported shebangs or BOMs are not automatically substituted.
  - Running a Playbook `ensure` inspection step (requires a controlled shell for exit status capture).
  - Executing an SFTP `exec` with a non-empty `cwd`.
- Successfully probed configurations are cached in process memory only, without modifying static configuration files on disk.
- Explicit interpreters (including `server`), known dialects, and explicit login options are never overridden by lazy probing. `script` supports `bash`/`sh`/`zsh`/`fish`/`csh`/`tcsh` and `ensure` supports `bash`/`sh`/`zsh`/`fish` (falling back to an available `bash`/`sh`/`zsh`/`fish` under a `csh` outer dialect) with a `posix`/`fish`/`csh` outer dialect; fish ensure reports check status through a native exit event.

### 2.4 Level 4: Connection-Level Session Cache
- Clients share concurrent-safe probe state across pooled wrapper instances.
- Probing runs at most once per connection lifecycle. Subsequent concurrent tasks or sequential steps hit memory cache with zero network overhead.

---

## 3. Two-Stage Probing Protocol Specification

SSH `exec` receives a raw command string evaluated by the remote default login shell. Probing strictly splits into two sequential stages:

```
[Established Authenticated Connection]
      │
      ▼
┌────────────────────────────────────────────────────┐
│ Stage 1: Outer Launch Dialect Determination       │
│ Goal: Determine default server interpreter         │
│ Result: posix | fish | cmd | powershell | unknown │
└────────────────────────────────────────────────────┘
      │
      ▼ (Construct inner commands under verified outer syntax)
┌────────────────────────────────────────────────────┐
│ Stage 2: Inner Interpreter Enumeration             │
│ Goal: Locate usable execution binaries             │
│ Candidates: bash, sh, zsh, fish, powershell, pwsh, cmd │
└────────────────────────────────────────────────────┘
      │
      ▼
[Recommendation Matrix -> Emit ProbeResult]
```

### 3.1 Stage 1: Outer Launch Dialect Determination

#### 3.1.1 Banner Heuristic (0 RTT)
Inspects `sshClient.ServerVersion()` from the SSH handshake:
- If containing `OpenSSH_for_Windows` or `Microsoft:Windows`, prioritizes **Windows probes**.
- Otherwise prioritizes **POSIX probes**.
The majority of targets hit on the very first SSH `exec` request.

#### 3.1.2 Probing Commands and State Machine

1. **POSIX Primary Probe**:
   ```sh
   if :; then printf '__XOPS_DIALECT_POSIX__:%s:%s\n' "$(uname -s 2>/dev/null || echo UNAME_FAIL)" "$SHELL"; fi
   ```
   - **POSIX (Linux/macOS/BSD/Alpine)**: `printf` is built-in; output contains `__XOPS_DIALECT_POSIX__:<OS>:<SHELL>` with exit code 0. Confirmed as `LaunchPOSIX`.
   - **Windows cmd.exe**: Incompatible with `if/then`; rejected as an invalid POSIX frame.
   - **PowerShell (including Core on Linux)**: Incompatible with `if :; then ...; fi`; exits with error. POSIX cannot be detected using `printf`, `$()`, or `||` alone as PowerShell 7 can parse or invoke external commands with these constructs.

2. **Fish Fallback Probe**:
   ```fish
   if set -q FISH_VERSION; printf '__XOPS_DIALECT_FISH__:%s\n' "$FISH_VERSION"; printf '__XOPS_FISH_OS__:%s\n' (uname -s); printf '__XOPS_FISH_SHELL__:%s\n' "$SHELL"; end
   ```
   - **Fish DefaultShell**: `set -q FISH_VERSION` succeeds and outputs `__XOPS_DIALECT_FISH__:<Version>` along with OS/Shell metadata frames, exiting with 0. Confirmed as `LaunchFish`.

3. **Windows CMD Fallback Probe**:
   ```cmd
   echo __XOPS_DIALECT_CMD__:%COMSPEC%
   ```
   - **Windows cmd.exe**: Outputs `__XOPS_DIALECT_CMD__:C:\Windows\system32\cmd.exe` with exit code 0. Confirmed as `LaunchCmd`.
   - **POSIX / PowerShell**: `%COMSPEC%` is not expanded; rejected as an invalid frame. Variable expansion must occur in the outer shell itself, not by invoking an inner `cmd.exe`.

4. **Windows PowerShell Fallback Probe**:
   ```powershell
   Write-Output ('__XOPS_DIALECT_POWERSHELL__:' + $PSVersionTable.PSVersion.ToString()); Write-Output ('__XOPS_PLATFORM__:' + [Environment]::OSVersion.Platform)
   ```
   - **PowerShell DefaultShell**: Outputs `__XOPS_DIALECT_POWERSHELL__:<Version>` with exit code 0. Confirmed as `LaunchPowerShell`.
   - **Platform Metadata**: `__XOPS_PLATFORM__:Win32NT` marks Windows; `Unix` denotes Unix-like hosts. Does not guess operating systems from language versions alone.

5. **Safety Fallback**:
   If no valid frame is received within bounded timeouts, dialect marks as `LaunchUnknown`.

---

### 3.2 Stage 2: Inner Interpreter Enumeration

Once the outer dialect is established, subsequent commands strictly use payload generators and escaping mechanisms native to that dialect.

All four dialects use a line-by-line streaming protocol: each available interpreter emits `__XOPS_INTERP__:<name>`, followed by `__XOPS_INTERP_END__`. `<name>` is strictly limited to `bash`, `sh`, `zsh`, `fish`, `powershell`, `pwsh`, and `cmd`. Parsers ignore noise lines and CRLF variations, rejecting invalid interpreter names, duplicate frames, frames after the termination delimiter, or missing end delimiters; non-zero exit or truncated output is treated as enumeration failure.

#### 3.2.1 When `LaunchDialect == LaunchPOSIX` or `LaunchFish`
`LaunchPOSIX` executes without external dependencies (1 RTT):
```sh
for i in bash sh zsh fish powershell pwsh cmd; do
    if command -v "$i" >/dev/null 2>&1; then
        printf '__XOPS_INTERP__:%s\n' "$i"
    fi
done
printf '__XOPS_INTERP_END__\n'
```
`LaunchFish` enumerates via native fish loop and `command -q`:
```fish
for i in bash sh zsh fish powershell pwsh cmd; if command -q $i; printf '__XOPS_INTERP__:%s\n' $i; end; end; printf '__XOPS_INTERP_END__\n'
```

#### 3.2.2 When `LaunchDialect == LaunchCmd`
Constructs command with caret (`^`) escape protection via `cmdCommandPayload`:
```bat
cmd.exe /d /s /c "where bash.exe >nul 2>&1 && (echo __XOPS_INTERP__:bash) & where sh.exe >nul 2>&1 && (echo __XOPS_INTERP__:sh) & where zsh.exe >nul 2>&1 && (echo __XOPS_INTERP__:zsh) & where fish.exe >nul 2>&1 && (echo __XOPS_INTERP__:fish) & where powershell.exe >nul 2>&1 && (echo __XOPS_INTERP__:powershell) & where pwsh.exe >nul 2>&1 && (echo __XOPS_INTERP__:pwsh) & (echo __XOPS_INTERP__:cmd) & (echo __XOPS_INTERP_END__) & exit /b 0"
```

#### 3.2.3 When `LaunchDialect == LaunchPowerShell`
Executed directly by the verified outer PowerShell without invoking `powershellCommandPayload` or requiring `powershell.exe` (disabling module auto-loading via `$global:PSModuleAutoLoadingPreference = 'None'` and restoring it in `finally`), supporting pwsh-only DefaultShells:
```powershell
& {
    $previous = $global:PSModuleAutoLoadingPreference
    try {
        $global:PSModuleAutoLoadingPreference = 'None'
        foreach ($i in @('bash','sh','zsh','fish','powershell','pwsh','cmd')) {
            if (Get-Command $i -CommandType Application -ListImported -ErrorAction SilentlyContinue) {
                [Console]::WriteLine('__XOPS_INTERP__:' + $i)
            }
        }
        [Console]::WriteLine('__XOPS_INTERP_END__')
    } finally {
        $global:PSModuleAutoLoadingPreference = $previous
    }
}
```

---

### 3.3 Recommendation Matrix

The probing engine derives recommended configurations based on composite attributes:

| Detected LaunchDialect | Available Interpreters | Recommended Interpreter | Recommended Login | Use Case & Rationale |
| :--- | :--- | :--- | :--- | :--- |
| **`posix`** | Default bash/sh/zsh/fish is available | Remote default shell | `false` | Preserve the user's default environment; ash/dash map to sh |
| **`fish`** | contains `fish` | `fish` | `false` | Native fish probe overrides stale `$SHELL` |
| **`posix` / `fish`** | Default shell unknown, unsupported or unavailable | First available: bash → sh → zsh → fish | `false` | Deterministic fallback |
| **`posix`** | `sh` only (no bash) | `sh` | `false` | Alpine / minimal container images; prevents code 127 errors |
| **`posix`** | contains `pwsh` | User-selectable `pwsh` | `nil` | Executing PowerShell Core scripts under Linux |
| **`cmd`** | contains `cmd`, `powershell` | `server` (opt-in `powershell`) | `nil` | Basic commands pass through cmd; automation prefers powershell |
| **`cmd`** | `cmd` only | `cmd` / `server` | `nil` | Minimal Windows environments |
| **`powershell`** | contains `powershell` | `powershell` | `nil` | Native PowerShell default shell environments |
| **`unknown`** | any or undetected | `server` | `nil` | Safe fallback preserving existing passthrough behavior |

---

## 4. Data Structures and Configuration Persistence

### 4.1 Go Data Model (`core/ssh/probe.go`)
Following coding standards, all network, system, and tool abbreviations (`ID`, `SSH`, `CLI`, `URL`) are capitalized:

```go
package ssh

import "time"

// ProbeResult records diagnostic probe snapshots for an SSH node
type ProbeResult struct {
	DetectedDialect       LaunchDialect   `json:"detectedDialect" yaml:"detected_dialect"`
	AvailableInterpreters []Interpreter   `json:"availableInterpreters" yaml:"available_interpreters"`
	RecommendedInterpreter Interpreter   `json:"recommendedInterpreter" yaml:"recommended_interpreter"`

	SuggestedConfig       ExecutionConfig `json:"suggestedConfig" yaml:"suggested_config"`

	RemoteOS              string          `json:"remoteOS" yaml:"remote_os"`
	RemoteShellPath       string          `json:"remoteShellPath" yaml:"remote_shell_path"`
	ServerVersion         string          `json:"serverVersion" yaml:"server_version"`
	Duration              time.Duration   `json:"duration" yaml:"duration"`
	ProbedAt              time.Time       `json:"probedAt" yaml:"probed_at"`
}
```

### 4.2 Schema V2 YAML Persistence Representation
When a node is first enrolled and successfully probed:

```yaml
schema_version: 2
nodes:
  root@192.168.1.10:22:
    host_ref: 192.168.1.10:22
    identity_ref: root@192.168.1.10
    alias: [web-prod-01]
    tags: [web, prod]
    sudo_mode: auto
    execution:
      interpreter: bash
      launch_dialect: posix
      login: false
```

- **Validation Before Persistence**: Static validation passes via `node.Execution.Validate()` before writing, preventing invalid combinations (e.g. `bash` with `cmd` dialect).

---

## 5. Robustness and Security Constraints

Probing strictly adheres to project coding rules:

1. **Zero Resource Leak**:
   - All probe commands execute via `PlanCommand` + `c.ExecuteCommand(ctx, plan)` with bounded channel shutdown and worker joining (`defer c.closeSessionBounded(session)` for legacy session helpers).
   - No background goroutines without cancellation exits are launched.

2. **Strict Timeouts**:
   - Single probe commands use a 5-second hard timeout (`context.WithTimeout`).
   - The entire probe workflow (Stage 1 + Stage 2) is bounded within a 12-second overall budget.
   - Respects context cancellation (e.g. `Ctrl+C`), closing channels and reclaiming sessions immediately.

3. **Magic Framing Resistance**:
   - Output uses distinct delimiters (`__XOPS_DIALECT_*__` and `__XOPS_INTERP__:`).
   - Line-by-line filtering discards login banners, copyright notices, and last-login noise.

4. **Command Injection Immunity and No Side Effects**:
   - All probe command payloads are **static constant strings** without dynamic user concatenation.
   - Probes execute read-only queries, creating no remote temp files or environment mutations.

5. **Fail-Safe & Non-Blocking**:
   - The primary goal of node enrollment is saving valid node metadata. On timeout, network blackholes, or permission errors:
     - Warning logged without blocking node addition.
     - `Execution` field set to `nil` (safe fallback to `server` mode).
     - User can re-probe at any time using `xops host probe <id> --save`.

---

## 6. Implementation Roadmap

### Milestone 1: Core Protocol & Probe Engine
- Implemented `core/ssh/probe.go` with two-stage probing, delimiter extraction, and timeout controls.
- SSH protocol fixtures in `core/testutil/sshfixture` covering POSIX, Windows CMD, and PowerShell.

### Milestone 2: Client Integration & Session Cache
- Concurrent-safe `probeCache` and `ProbeExecutionConfig(ctx)` in `core/ssh/client.go`.
- Concurrency and cache hit tests ensuring zero redundant network RTTs.

### Milestone 3: First Enrollment & CLI Management
- Automated probing and persistence integrated in `cmd/host/add.go` and `cmd/host/load.go`.
- `xops host probe <node-id>` with tabular output and `--save` option.

### Milestone 4: Runtime Lazy Loading & Regression Tests
- Controlled lazy probing integrated for Playbook script/ensure and SFTP `cwd`.
- Full build, lint, and unit test suites verified:
  ```bash
  go build ./...
  go test -race ./core/ssh ./cmd/host
  golangci-lint run ./...
  ```
