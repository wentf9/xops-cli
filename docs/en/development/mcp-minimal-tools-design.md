# Minimalist All-in-One MCP Tool Architecture Refactoring Design

Status: Implemented. 

---

## 1. Background, Goals, and Confirmed Architectural Decisions

### 1.1 Current Pain Points
Currently, `core/mcp/runtime` registers **16 fine-grained MCP tools** (12 in stdio mode, 12 in HTTP mode; `internal/clicontract/testdata/mcp-stdio-tools.json` spans 1,194 lines, consuming ~4,500+ tokens on every conversation initialization):
1. **Context Window Bloat**: Granular filesystem and file tools (`xops_fs_ls`, `xops_fs_mkdir`, `xops_fs_touch`, `xops_fs_mv`, `xops_fs_rm`, `xops_fs_cp`, `xops_read_file`, `xops_write_file`) carry repetitive, verbose JSON schemas.
2. **Missing Primitives and Inefficient Interactions**:
   - `xops_ssh_run` only supports stateless one-off execution, lacking **persistent PTY sessions** (needed for background dev servers, interactive REPLs, or continuous log tailing) and **smart output compression**.
   - `xops_read_file` uses raw byte offsets (`offset`/`limit`) instead of line-numbered pagination; `xops_write_file` only overwrites or appends entire files, lacking token-efficient **`patch` blocks (with whitespace-insensitive fallback and syntax pre-checking)**.
   - No **Computer Use (`gui`)** primitive exists for remote desktop and browser automation.

### 1.2 Primary Refactoring Goal and Confirmed Decisions
Backward compatibility with legacy tool names is **deliberately dropped** in favor of **code elegance, orthogonality, and minimal context overhead**. Three key architectural decisions have been confirmed:

| Decision Area | Confirmed Choice | Core Constraints & Highlights |
| :--- | :--- | :--- |
| **1. Tool Matrix & Naming** | **Ultra-Minimalist (Option A)** | Drop the `xops_` prefix and adopt polymorphic `action` dispatch. Converge host operations into **`terminal`, `file`, `gui`, `transfer`**; converge uncovered multi-node and cross-network capabilities into **`nodes`** and polymorphic **`tunnel`**. Total stdio tools drop from 12 to **6** (HTTP mode drops to **5**). |
| **2. `terminal` Persistent Sessions** | **Native SSH PTY Session Pool (Option A)** | Maintain persistent SSH PTY channels in memory (`core/mcp/session`) **without requiring `tmux` on remote hosts**. Works out of the box on any POSIX node and cleans up deterministically on `Runtime.Shutdown`. |
| **3. Image Pipeline & Build Constraints** | **Strictly Zero-CGO Pure Go** | Keep `CGO_ENABLED=0` across all packages. Do not introduce C bindings (such as `libwebp` CGO wrappers), preserving cross-platform builds and CI parity across Linux, macOS, and Windows. |

---

## 2. Complete Tool Convergence Matrix

### 2.1 Legacy-to-New Tool Mapping

| New Tool | Transports | Absorbed / Replaced Legacy Tools | Disposition & Capability Upgrades |
| :--- | :--- | :--- | :--- |
| **`terminal`** | stdio & http | `xops_ssh_run`<br>`xops_fs_mkdir`, `xops_fs_touch`, `xops_fs_mv`, `xops_fs_rm`, `xops_fs_cp` | **Converged + Upgraded**: Unifies stateless execution (`session="once"`) and persistent PTY sessions (`session="<id>"`); injects non-interactive environment variables, handles control signals (`SIGINT`/`EOF`), and folds large outputs with `$HOME/.cache/xops-mcp/cmd-*.log` offloading. Deletes `tool_fs.go` SFTP wrappers. |
| **`file`** | stdio & http | `xops_read_file`<br>`xops_write_file`<br>`xops_fs_ls` | **Converged + Upgraded**: Polymorphic `action="read"\|"write"\|"patch"\|"stat"`. `read` returns line-numbered pages; `patch` applies `<<<< ==== >>>>` search/replace blocks with indentation-insensitive fallback and auto-linting; `stat` returns file metadata or noise-filtered directory trees. |
| **`gui`** | stdio & http | *(New Capability)* | **Added**: Supports `action="shot"\|"click"\|"double_click"\|"right_click"\|"move"\|"type"\|"key"\|"scroll"\|"drag"`, adaptive Wayland / X11 backend (supporting Linux/FreeBSD/Unix desktop environments and auto-detected `display`), 0–1000 normalized coordinates, `1280px` downscaling, and automatic post-action screenshot capture. |
| **`transfer`** | stdio & http | stdio: `xops_upload`, `xops_download`<br>http: `xops_prepare_upload`, `xops_prepare_download`, `xops_transfer_status`, `xops_transfer_cancel` | **Converged**: In stdio mode, streams files/directories via `direction="push"\|"pull"`; in HTTP mode, dispatches out-of-band streaming lifecycle actions (`prepare_push` / `prepare_pull` / `status` / `cancel`). |
| **`nodes`** | stdio & http | `xops_list_nodes` | **Retained & Streamlined**: Multi-node inventory discovery entry point, optionally filtered by `tag`. |
| **`tunnel`** | stdio only | `xops_tunnel_create`<br>`xops_tunnel_list`<br>`xops_tunnel_status`<br>`xops_tunnel_stop` | **Retained & Consolidated**: Merges the 4 SSH port-forwarding tools into a single polymorphic `tunnel(action="create"\|"list"\|"status"\|"stop")` tool. |

---

## 3. Ultra-Compact JSON Schema Specification (Micro-Descriptions)

### 3.1 Core 4 Primitives + 2 Retained Tools Schema Summary (Authoritative snapshots in `internal/clicontract/testdata/mcp-stdio-tools.json` and `mcp-http-tools.json`)

To keep the documentation from drifting against code-generated schemas, the generated contract snapshots (`go test ./internal/clicontract -update-mcp-contract`) are the single authoritative source for `inputSchema`, `outputSchema`, and `annotations`. The table below summarizes the input contract of each tool:

| Tool | Transports | Required Fields | Optional Fields | Summary |
| :--- | :--- | :--- | :--- | :--- |
| **`nodes`** | stdio & http | *(none)* | `tag` | List configured SSH nodes (optionally filtered by `tag`) |
| **`terminal`** | stdio & http | `nodeID` | `cmd`, `cwd`, `session`, `timeout`, `sudo`, `execution` | Run stateless commands (`session='once'`, supporting `sudo` and `execution` overrides including fish, zsh, and csh/tcsh, with automatic `cwd` adaptation on Windows server+cmd nodes) or interact with a persistent PTY session (persisting state in POSIX, fish, or csh/tcsh login shells; empty `cmd` to poll, or `SIGINT`/`EOF`/`SIGTERM`/`SIGKILL`) |
| **`file`** | stdio & http | `nodeID`, `action`, `path` | `content`, `range` | Unified SFTP file/directory operator: `read` (line-numbered, first 512 KiB), `write` (atomic replace; creates parent dirs), `patch` (`<<<< ==== >>>>` atomic replace, up to 512 KiB), `stat` (metadata or 2-level filtered tree). Normalizes Windows drive paths (e.g. `C:\...`) and strictly rejects drive roots (e.g. `/C:` as `Dangerous`); atomic replacement creates a new inode (use `terminal` when hard links or extended ACLs must be preserved) |
| **`gui`** | stdio & http | `nodeID`, `action` | `coord`, `text`, `display` | Visual desktop automation on remote Linux/FreeBSD/Unix nodes (X11, or Wayland with `ydotool`/`grim`): optional `display` (e.g. :0, :1; auto-detected when omitted), 0–1000 normalized coordinates, `<= 1280px` screenshot after every action; keyboard actions (`type`, `key`) are rated `Dangerous`; invoking `gui` on non-POSIX nodes returns an explicit error requiring a POSIX shell target (X11/Wayland) |
| **`transfer`** | stdio | `nodeID`, `direction`, `localPath`, `remotePath` | *(none)* | Stream files or directories between the local host and a remote node (`direction: "push" \| "pull"`), normalizing Windows drive paths and blocking drive roots |
| **`transfer`** | http | `action` | `nodeID`, `remotePath`, `requestID`, `transferID`, `size`, `sha256`, `overwrite` | Out-of-band HTTP streaming lifecycle (`action: "prepare_push" \| "prepare_pull" \| "status" \| "cancel"`), paired with `/v1/transfers/{id}/content`, normalizing Windows drive paths and blocking drive roots |
| **`tunnel`** | stdio only | `action` | `nodeID`, `tunnelID`, `requestID`, `mode`, `listenHost`, `listenPort`, `targetHost`, `targetPort`, `ttlSeconds`, `state` | Process-owned SSH TCP port-forwarding tunnels (`action: "create" \| "list" \| "status" \| "stop"`; `create` auto-generates a 16-byte hex `requestID` if omitted, and dynamic `listenPort: 0` backfills the allocated port) |

---

## 4. Detailed Engineering Mechanisms

### 4.1 `terminal`: Stateless Execution + Native SSH PTY Session Pool

#### 4.1.1 `session="once"` Stateless Execution & Non-Interactive Environment
1. **Working Directory & Environment Injection**:
   - Under `LaunchPOSIX` dialect, automatically prepend non-interactive environment variables so `apt`, `git`, and `systemctl` never hang waiting for pagers or prompts:
     ```sh
     export DEBIAN_FRONTEND=noninteractive GIT_TERMINAL_PROMPT=0 PAGER=cat SYSTEMD_PAGER=cat CI=true;
     ```
   - When `cwd` is provided, safely escape single quotes and prepend `cd -- '<escaped_cwd>' && `.
   - **Windows `server` + `cmd` Node `cwd` Support (R4)**: When the target node is configured with `interpreter="server"` and `launch_dialect="cmd"` (or `powershell`/`posix`), `DeriveWorkingDirectoryExecution` automatically derives the local execution configuration to safely format the command as `cd /d "<escaped_cwd>" || exit /b & <escaped_cmd>`, eliminating `server interpreter does not support inheriting working directory` errors.
   - **PowerShell CLIXML Progress Suppression & `launchDialect` Protection (R5)**: Prepend `$ProgressPreference = 'SilentlyContinue'; ` to wrapped PowerShell commands, completely suppressing verbose `#< CLIXML` progress stream noise from cmdlets like `Get-ComputerInfo` or `Invoke-WebRequest` in non-interactive SSH sessions. Furthermore, when the target node has a fixed entry `launchDialect` (such as `cmd`), runtime invocation protects this dialect from being overridden by request-specified parameters.
   - **Ubuntu `sudo-rs` Localized PAM Prompt Stripping (R6)**: For privileged command execution, `expandSudoPrompt` matches localized PAM challenge suffixes from `sudo-rs` (such as `[sudo: ...] 密码：` under `zh_CN.UTF-8`, supporting both ASCII `:` and UTF-8 full-width `：` / `\xef\xbc\x9a`) within a 64-byte bounded window, ensuring residual prompt characters do not contaminate command stdout/stderr.
2. **Smart Output Compression**:
   - **When `exit_code == 0` and output lines `> 60`**: Keep the first 15 lines and last 30 lines, replacing the middle with:
     `[... 380 lines omitted. Full log saved to /home/ops/.cache/xops-mcp/cmd-20261029T120000-8f9a1c2b3d4e.log ...]`
   - **When `exit_code != 0` and output lines `> 100`**: Preserve the first 20 lines and the last 80 lines of output.
   - **Remote Log Offloading**: When folding occurs, write the full untruncated output to `$HOME/.cache/xops-mcp/cmd-<time>-<random>.log` (directory `0700`, file created exclusively with mode `0600`; shared `/tmp` is never used, retaining at most the 32 newest logs) on the remote node.

#### 4.1.2 `session != "once"` Native SSH PTY Session Pool (`core/mcp/session`)
Without requiring `tmux` on the target host, `core/mcp/session` manages persistent SSH PTY sessions with bounded lifetimes:
1. **Isolation Key**: `SessionKey{Scope: string, NodeID: string, Name: string}`.
2. **PTY Initialization**:
   - Dial using the admitted `Permit`, open an `ssh.Session`, call `RequestPty("xterm-256color", 40, 120, ssh.TerminalModes{ssh.ECHO: 0, ssh.NOFLSH: 1})`, start `Shell()`, and initialize `stty -echo noflsh; PS1=''; export TERM=dumb NO_COLOR=1 ...`.
3. **Input Dispatch, Signals, and Incremental Output Collection**:
   - **Signals**: `"SIGINT"` writes `0x03` and sends `ssh.SIGINT`; `"EOF"` writes `0x04`; `"SIGTERM"` sends `ssh.SIGTERM`; `"SIGKILL"` sends `ssh.SIGKILL` and forcibly closes and removes the PTY session whether a command is running or the session is idle.
   - **Incremental RingBuffer & Sentinel/Timeout**: Collects incremental PTY output (stripping ANSI escape sequences and collapsing intra-line `\r` progress frames) until either the command sentinel (`___MCP_DONE_<token>_<code>___`, emitted via split `printf` arguments) completes, `timeout` elapses (default 5s, returning startup logs while keeping background processes alive), or the PTY closes (`outcome=unknown`).
4. **Resource Ownership & Cleanup**:
   - Idle sessions expire after a bounded TTL (default `30m`, `60m` while a command is running; only client `Execute` calls refresh activity, with a `12h` maximum session lifetime).
   - Sessions are bound to the target `Generation` (combining `ConnectionKey`, `Version`, and `ExecutionVersion`) and are lazily closed and recreated on the next call when node connection parameters, credentials, or execution settings change.
   - `Runtime.shutdown` invokes `sessionManager.Shutdown(ctx)` and waits for the reaper and all reader goroutines to exit cleanly (`goleak` verified).

---

### 4.2 `file`: Line-Numbered Read, Whitespace-Tolerant Patch, and Noise-Filtered Stat

1. **`action="read"`**: Parses 1-based `range` (`[start_line, end_line]`; defaults to the first 500 lines, reading at most 512 KiB into memory and marking `truncated` when exceeded), returning line-numbered text (`%4d | %s`) with `totalLines` metadata.
2. **`action="write"`**: Ensures parent directories exist (`MkdirAll`) when creating a new file and writes `content` via SFTP (using a private temporary file + `posix-rename` or SFTP v3 `Rename`), followed by syntax pre-checking.
3. **`action="patch"` (`core/mcp/patch`)**:
   - Parses one or more `<<<<\n[old]\n====\n[new]\n>>>>` blocks while preserving LF/CRLF style.
   - **Stage 1 (Exact Match)**: Requires a unique exact match; multiple matches return a disambiguation error.
   - **Stage 2 (Whitespace-Insensitive Fallback)**: Compares `strings.TrimSpace` line sequences; if uniquely matched, computes the base indentation delta and automatically aligns `[new]` to the file's original indentation level, reporting the count in `fuzzyBlocks`.
4. **Auto-Linting**: After `write` or `patch`, validates `.json` files in-memory via `json.Unmarshal` (zero network overhead) and populates `lintWarning` if a syntax error is detected.
5. **`action="stat"`**: Returns metadata for a single file, or a compact 2-level directory tree (up to 200 entries) that automatically filters noise directories (`.git`, `node_modules`, `__pycache__`, `.venv`, `venv`, `target`, `dist`, `build`).
6. **Windows Native SFTP Path Normalization & Drive Root Protection (R1)**:
   - **Path Normalization (`remotefile.NormalizeSFTPPath`)**: Detects Windows drive prefixes (e.g. `C:\...`, `c:/...`, `/C:\...`) and normalizes them into OpenSSH SFTP canonical form `/C:/...` (uppercase drive letter with forward slashes), while preserving standard POSIX paths unchanged.
   - **Drive Root Protection (`remotefile.IsRootPath`)**: Identifies `/` as well as drive roots (such as `/C:`, `C:\`, `C:/`). Both `file` (`read`, `write`, `patch`, `stat`) and `transfer` (`push`, `pull`, `prepare_push`, `prepare_pull`) operations block drive roots as `RiskDangerous` (`"root path access"`), and `transfer` Spec validation synchronously rejects drive roots.

---

### 4.3 `gui`: Adaptive X11 / Wayland & Zero-CGO Pure-Go Image Pipeline (`core/mcp/gui`)

1. **Display Environment Setup & Auto-Discovery (R3)**: Supports Linux/FreeBSD/Unix X11 and Linux Wayland desktop environments. Supports explicit `display` specification (e.g. `:0`, `:1`) or auto-detects active `/tmp/.X11-unix/X*` sockets (defaulting `DISPLAY` to `:0`).
   - **Wayland Auto-Discovery**: If `XDG_RUNTIME_DIR` is unset and `/run/user/$(id -u)` exists, sets `XDG_RUNTIME_DIR="/run/user/$(id -u)"`; if `WAYLAND_DISPLAY` is unset and `$XDG_RUNTIME_DIR/wayland-0` exists, automatically sets `WAYLAND_DISPLAY="wayland-0"`.
   - **Xauthority Fallback Probing**: When `$XAUTHORITY` is unset and `$HOME/.Xauthority` is missing, checks `$XDG_RUNTIME_DIR/.mutter-Xwaylandauth.*`, `$XDG_RUNTIME_DIR/gdm/Xauthority`, and `/run/user/$(id -u)/Xauthority`.
   - **Screenshot Utility Fallback**: Supports `gnome-screenshot -f "$tmp"` in addition to `grim`/`spectacle` + `ydotool` on Wayland and `maim`/`import`/`scrot` + `xdotool` on X11.
   - Uses `mktemp -d` to create a private `0700` temporary directory for screenshots and cleans it up upon exit.
2. **0–1000 Normalized Coordinate Mapping**: Maps `[x, y]` in $[0, 1000]$ linearly to physical screen resolution $(W, H)$.
3. **Mutating Action Screenshot Loop**: Mutating actions (`click`, `type`, `key`, `scroll`, `drag`) wait 500ms after injection and automatically capture and return an updated screenshot in the same round-trip.
4. **Zero-CGO Image Compression**: Passes WebP payloads through directly, or decodes PNG/JPEG in memory using pure-Go standard library packages and downscales the longest edge to at most `1280px` via pure-Go bilinear interpolation (JPEG quality 75), returning an MCP `ImageContent` payload with `CGO_ENABLED=0` compatibility across all target OSes.
5. **Diagnostic Error Output & Non-POSIX Protection (R3, R7)**:
   - **Bounded Diagnostic Output (R3)**: When remote execution exits with a non-zero code, sanitizes and appends up to 512 bytes of remote output to the error response, avoiding opaque exit code errors.
   - **Non-POSIX Clear Error (R7)**: Invoking `gui` on a non-POSIX node (e.g. Windows cmd/powershell) returns an explicit error indicating that a POSIX shell target (X11/Wayland) is required, rather than misleading filesystem command errors.

---

### 4.4 `tunnel`: Process-Owned SSH Port Forwarding & Dynamic Port Allocation (`core/mcp/tunnel`)

1. **Automatic `requestID` Generation (R2)**: When `action="create"` and `requestID` is omitted, the runtime automatically generates a 16-byte random hex string as the request ID, while preserving explicitly provided IDs for idempotent retries.
2. **Dynamic Port Backfill (R2)**: When `listenPort: 0` is specified, the manager binds an available TCP port and backfills the allocated port number into `status.ListenPort` (and `listenAddress`), allowing callers to immediately discover the bound port.

---

## 5. Guardrail Risk Classification & Package Layout

### 5.1 Action-Aware Guardrail (`core/mcp/guardrail`)
`guardrail.RiskInput` and `Classify` evaluate `(ToolName, Action)`:
- `nodes`: `Safe`
- `terminal`: `session="once"` uses `AnalyzeCommandWithDialect` (`Safe` / `Moderate` / `Dangerous` / `Deny`); `session != "once"` defaults to at least `Moderate`.
- `file`: `read`/`stat` base `Safe` + `AnalyzePaths` (normalizes Windows drive paths; sensitive system paths like `/etc`, `/root`, and `/c:/windows/system32/config` elevate to `Moderate`); `write`/`patch` base `Moderate` + `AnalyzePaths` (drive roots like `C:\` or `/C:`, `/`, or empty paths elevate directly to `Dangerous` with `"root path access"`).
- `gui`: `shot`/`move` -> `Safe`; mouse actions (`click`/`double_click`/`right_click`/`drag`/`scroll`) -> `Moderate`; keyboard actions (`type`/`key`) -> `Dangerous` (to prevent fragmented keystroke bypasses).
- `transfer`: `pull`/`prepare_pull`/`status`/`cancel` -> `Safe` + `AnalyzePaths` (normalizes Windows drive paths and blocks drive roots); `push`/`prepare_push` -> `Moderate` + `AnalyzePaths` (normalizes Windows drive paths and blocks drive roots).
- `tunnel`: `list`/`status` -> `Safe`; `stop` -> `Moderate`; `create` -> `Moderate` (loopback local) or `Dangerous` (non-loopback / remote); `requestID` is optional (auto-generated 16-byte hex if omitted); dynamic `listenPort: 0` backfills the allocated port.

### 5.2 Target Package Structure

```text
core/mcp/
├── patch/          # [New] <<<< ==== >>>> parser, exact & indentation-tolerant matcher
├── session/        # [New] Native SSH PTY session pool, sentinel/quiet-window reader, lifecycle cleanup
├── gui/            # [New] X11/Wayland driver script generator, 0-1000 coordinate mapper, pure-Go image pipeline
├── guardrail/      # [Refactored] Action-aware RiskInput and Classify
├── ports/          # [Streamlined] Trimmed FileSession; PTY session support
└── runtime/        # [Refactored] registry.go, output_fold.go, tool_{nodes,terminal,file,gui,transfer,tunnel}.go
```

---

## 6. Phased Implementation Plan & Validation Gate

1. **Phase 1**: Pure-Go subpackages (`core/mcp/patch`, `core/mcp/gui`, `core/mcp/runtime/output_fold.go`) with unit tests.
2. **Phase 2**: Native SSH PTY session pool (`core/mcp/session` & `core/ssh`) with concurrency and `goleak` tests.
3. **Phase 3**: Runtime tool replacement and action-aware `guardrail` integration; removal of legacy `tool_fs.go`, `tool_sftp.go`, and `tool_ssh.go`.
4. **Phase 4**: Contract fixture refresh (`-update-mcp-contract`) and full validation suite:
   ```bash
   python3 -m unittest discover -s scripts -p test_check_core.py
   python3 scripts/check_core.py --race
   CGO_ENABLED=0 go build ./...
   go test -race -shuffle=on -count=1 ./core/mcp/... ./core/ssh/... ./internal/mcphost ./internal/clicontract
   golangci-lint run ./...
   npm run docs:check
   ```

## Implementation Revisions (post code review)

The following constraints were added after nine rounds of implementation review and take precedence over the text above:

- **Persistent session outcome & output cleaning**: only an observed completion sentinel yields `outcome=completed` and an exit code; a wait timeout yields `status=running`, `outcome=unknown`; a session that ends before the sentinel (or is closed by `EOF`/`SIGKILL`, with `EOF` waiting up to 1s) yields `status=failed`, `outcome=unknown`, never with an exit code, and is evicted from the session pool. Opening a new (or recreated) persistent session sets `newSession=true` in the output. The sentinel is assembled from two `printf` arguments so an echoed command line cannot be mistaken for completion; malformed candidates are skipped. Output strips ANSI escape sequences and collapses intra-line `\r` progress frames.
- **Busy protection, non-blocking mutex & signal semantics**: sessions use `TryLock` for non-blocking execution locking; when another call holds the execution lock, concurrent commands or empty-`cmd` polls immediately return `ErrSessionInUse`; concurrent control signals (`SIGINT`/`EOF`/`SIGTERM`/`SIGKILL`) are delivered in flight only when a command is **actively running** (command payload writes and stdin-writing signals `SIGINT`/`EOF` are serialized by the per-session input lock `inputMu` so `SIGINT`/`EOF` are ordered strictly after the complete payload write, whereas SSH channel-request signals `SIGTERM`/`SIGKILL` do not acquire `inputMu` so they can still interrupt or forcibly close a session even if payload `Write` is blocked on SSH window flow control; the underlying `ptySession` also serializes SSH channel stdin writes and `stdin.Close()`—after `session.Close()` unblocks any in-flight write—under `writeMu` to avoid data races on `x/crypto/ssh` packet pools or `sentEOF`)—if the execution lock is held by an idle poll or another short operation, signaling also returns `ErrSessionInUse`; when no call is actively waiting but a previous command is still running in the background, submitting a new command returns `ErrSessionBusy`; signals or empty-`cmd` polls targeting a non-existent, expired, or reconfigured session return `ErrSessionNotFound` (including the eviction reason such as `reconfigured`) without dialing a new PTY. Sending `SIGINT`/`EOF`/`SIGTERM` clears the busy state only if the completion sentinel is observed during the settle window; if the foreground process ignores the signal, the session stays `StateRunning` (busy) so subsequent commands are never typed into its stdin. `SIGKILL` unconditionally closes and evicts the session from the pool whether it is busy or idle (even if the command emits its completion sentinel during the settle window). A pure `cwd` change (empty `cmd`) in a persistent session is rated `Moderate`.
- **Session lifecycle & quotas**: session `Generation` combines the target `ConnectionKey`, `Version`, and `ExecutionVersion` (alongside the `state.Coordinator` update barrier that drains in-flight permits, compared by equality) and is verified together with expiration under a single manager lock acquisition, closing and recreating stale sessions when node connection parameters, credentials, or execution settings change (if a reconfigured session is never called again, its underlying connection lease—like active tunnels—is retained at most until idle TTL expiration or `Shutdown`); at most 16 sessions per `Scope` and 64 globally, with quota slots reserved prior to `Dial` (guaranteed to be released via `defer` even on `Dial` errors or panics) and concurrent creation requests for the same `Key` and `Generation` deduplicated onto a single in-flight dial (waiting callers retry with their own dial only if the leader's own `context` was canceled or expired while the waiter's `context` remains valid; backend dial timeouts when the leader's `context` is still active fail all waiting callers immediately without serial retries); idle TTL (30m default, 60m while busy, refreshed only by client `Execute` calls, with a 12h max lifetime) is enforced by a background reaper and on-demand capacity sweeps joined by `Shutdown` so chatty background processes cannot keep abandoned sessions alive indefinitely. Persistent sessions reject `sudo`/`execution` and support POSIX, fish, and csh/tcsh login shells. Folded logs are stored in `$HOME/.cache/xops-mcp` (`0700` dir, `0600` exclusive files), retaining at most the 32 newest logs.
- **`file`**: validates `action` before opening SFTP; `write`/`patch` prefer atomic replacement via a private temporary file in the same directory plus `posix-rename` (or SFTP v3 `Rename` when creating a new file without `posix-rename`) preserving mode and ownership (`Chown`), noting that atomic replacement creates a new inode (use `terminal` when hard links or extended ACLs must be preserved); if temporary file creation is explicitly rejected by the server (e.g., `EEXIST`/`EACCES`), unowned paths are never removed; if the target already exists as a regular file and the server lacks `posix-rename`, the parent directory denies temporary file creation, or original ownership cannot be applied to the temporary file, it falls back to an in-place write on the verified regular file and sets `inPlace=true`; symbolic links are always refused; `patch` verifies size, mtime, and SHA-256 content hash before commit to avoid overwriting concurrent edits; files above 512 KiB are refused by `patch` and reported as `truncated` by `read`. Whitespace-tolerant matches are reported via `fuzzyBlocks`.
- **`gui`**: Linux/FreeBSD/Unix environments (X11, or Wayland with `ydotool`/`grim`). Supports explicit `display` parameter or active X11 socket auto-detection. Screenshots use a private `mktemp -d` directory with a 48 MiB output bound that fails on truncation; `type` and `key` are both rated `Dangerous` (preventing fragmented keystroke bypasses and requiring approval under the default policy), matched against blocked patterns, and shown in approval and audit details.
- **Ubuntu & Windows Platform Adaptations and Defect Hardening (R1 ~ R7)**:
  - **Path Normalization & Drive Root Protection (R1)**: `remotefile.NormalizeSFTPPath` normalizes Windows drive prefixes (`C:\...`, `c:/...`, `/C:\...`) into uppercase `/C:/...` with forward slashes while preserving POSIX paths; `remotefile.IsRootPath` identifies `/` and drive roots like `/C:`; `file`, `transfer`, `record.Spec`, and `guardrail.AnalyzePaths` intercept drive root access end-to-end as `RiskDangerous` (`"root path access"`), with added protections for sensitive Windows system directories (`/c:/windows/system32/config`, `/c:/windows/repair`).
  - **Tunnel Request ID Generation & Dynamic Port Backfill (R2)**: `tunnel` with `action="create"` automatically generates a 16-byte random hex idempotency key when `requestID` is omitted, while preserving explicitly provided IDs; when `listenPort: 0` is specified, the bound listener address is parsed to backfill the actual allocated port into `status.ListenPort`.
  - **GUI Diagnostic Output, Wayland Auto-Discovery & Non-POSIX Clear Error (R3, R7)**: Remote command execution errors append up to 512 bytes of sanitized remote stderr output; auto-discovers Wayland sockets (`/run/user/$(id -u)/wayland-0`) and Xauthority files (`.mutter-Xwaylandauth.*`, `gdm/Xauthority`); adds `gnome-screenshot` fallback; invoking `gui` on non-POSIX nodes returns an explicit error requiring a POSIX shell target (X11/Wayland).
  - **Windows `server` + `cmd` Node `cwd` Support (R4)**: For nodes configured with `interpreter="server"` and `launch_dialect="cmd"`, `DeriveWorkingDirectoryExecution` derives the local execution configuration to format commands as `cd /d "<cwd>" || exit /b & ...`.
  - **PowerShell CLIXML Progress Suppression & `launchDialect` Protection (R5)**: Prepend `$ProgressPreference = 'SilentlyContinue'; ` to wrapped PowerShell commands, suppressing `#< CLIXML` progress stream noise; when a target node has a fixed entry `launchDialect` (such as `cmd`), runtime invocation protects it against conflicting request parameters.
  - **Ubuntu `sudo-rs` Localized PAM Prompt Stripping (R6)**: `expandSudoPrompt` matches localized PAM challenge suffixes from `sudo-rs` (such as `[sudo: ...] 密码：` with ASCII `:` or UTF-8 full-width `：` / `\xef\xbc\x9a`) within a 64-byte bounded window, preventing prompt text from contaminating output streams.


