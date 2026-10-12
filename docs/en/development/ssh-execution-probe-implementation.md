# SSH Execution Probing Implementation Record

## Current Scope

Milestones **M1–M4** of the design roadmap are complete, covering the Core protocol, connection caching, enrollment & diagnostics, and lazy loading for restricted operations. The Core entry point is `(*ssh.Client).ProbeExecutionConfig(ctx)`, which reuses already authenticated connections without establishing new TCP connections or repeating authentication handshakes.

Standard command executions do not probe or replay upon failure. Initial dynamic enrollment triggers probing only when credential remembering is authorized; restricted operations (script/ensure/cwd) cache results in memory, whereas enrollment probing commits recommended configurations atomically alongside the new node.

## M4 and Dynamic Enrollment

- `NeedsExecutionProbe` identifies only configurations without an explicit interpreter, with an unknown dialect, and inheriting login mode. Any explicit interpreter (including `server`), known dialect, or explicit login setting is never overwritten.
- Playbook scripts without a shebang probe under the default environment above; BOMs, unsupported shebangs, and explicit execution configurations continue using existing validation rules. Whitelisted shebangs do not prove outer dialects and do not trigger extra probes.
- `ensure` probes and freezes configuration before inspection; check, action, and re-check steps share the identical configuration. Supports bash/sh/zsh/fish with a posix/fish outer dialect; Windows script/ensure steps are rejected before user code starts without syntax translation.
- SFTP exec with non-empty `cwd` probes as needed. CMD's default recommendation remains `server`, but restricted operations select installed PowerShell/pwsh/cmd adapters. Ordinary commands with empty `cwd` do not probe. Windows SFTP drive path conversion follows Windows adapter constraints; cross-platform pwsh uses its internal `$IsWindows` at execution time without relying on probe cache; Linux pwsh POSIX paths remain unchanged. The `/C:` drive root converts to absolute `C:/`.
- Caches are shared by the physical connection's PooledClient; newly obtained Client wrappers reuse identical success or failure results. `CachedExecutionProbe` does not initiate network calls, does not block on in-progress probes, and returns a deep copy.
- Added optional Core `AuthenticatedConnectionConfirmer` capability, receiving an authenticated Client after handshake success but before node confirmation and credential persistence, with retention, closure, or command execution prohibited. Legacy ConnectionConfirmer retains fallback behavior.
- CLI enables `WithEnrollmentProbing` only when credential remembering is authorized. The adapter checks non-interactive mode, enrollment flags, Remember policies, pending nodes, and default execution configs; existing nodes, session credentials, non-interactive batch runs, and explicit flags do not probe. CLI uses `WithEnrollmentProbeExclusions` to exclude targets with explicit CLI execution arguments, including `--interpreter`, `--launch-dialect`, `--login-shell`, and `--no-login` (including explicit false). Exclusions do not affect credential remembering or normal enrollment for other nodes.
- Transport read/write errors or closures preserve confirmed nodes but return connection errors without saving credentials, pooling invalid connections, or running user commands. This check reuses transport state without extra network requests or monitoring goroutines.
- `ConfirmNodeWithExecutionContext` appends recommendations to existing node confirmation transactions without altering credential/sudo field versions, preserving concurrency conflicts and uncertain persistence semantics; confirmed nodes are never overwritten by late probes.

## M3 Integration and Persistence Constraints

- CLI `host add` and `host import` enable probing by default, reusing verification connections and saving execution settings in existing node creation transactions. Import preserves up to 16 workers and serial rules per node; warnings are printed in CSV order after all workers complete.
- `--no-probe` / `--probe=false` disables automatic probing; `--skip-verify` guarantees no connection or probing. New nodes support `--interpreter` / `--launch-dialect`; explicit fields take precedence over recommendations, warning on incompatibility. Importing existing nodes preserves execution settings without re-probing.
- `adapter.VerifyConnectionWithProbe` differentiates authentication errors from `ProbeErr` without persisting data. `cmd/host` decides whether to adopt recommendations; probe failures are not promoted to authentication failures. Cancellation prevents writes via persistence contexts.
- `host probe <node-id-or-alias>` performs non-interactive probing using saved credentials, rendering tables by default. `--save` verifies node/Host/Identity versions via `Repository.UpdateNodeExecutionAtRefContext`, updating execution settings only without overwriting concurrent edits.
- Automatic probing applies only to CLI addition/import; TUI retains pure connection verification behavior.

## API and Lifecycle

- Stage 1 tests POSIX, CMD, and PowerShell outer syntax in the order suggested by the SSH banner. Banners influence test order only; only commands that exit successfully with matching response frames determine the dialect.
- Stage 2 enumerates `bash`, `sh`, `powershell`, `pwsh`, and `cmd` using the established dialect, requiring a complete termination frame. Discards banners and CRLF noise, rejecting duplicate frames, unknown interpreters, truncated output, or non-zero exit codes.
- Individual commands execute with a 5-second timeout and a 16 KiB output limit. The complete probe workflow is bounded by 12 seconds, reserving up to 1 second of channel shutdown grace. Shorter caller deadlines or cancellations take precedence.
- Reuses `ExecuteCommand`'s bounded output, cancellation, and channel teardown mechanisms without spawning background probing goroutines. Unreclaimable channels fall back to closing the transport.
- Probing executes once per Connector-managed connection; Clients in the pool share the cached result. Concurrent callers share the single attempt; waiters can cancel independently; the first caller canceling aborts and caches the failure. Reconnecting permits re-probing.
- Return values are deep copies; interpreter slices and `Login` pointers are unshared; does not mutate Client `Execution()` or configuration files. Callers must verify errors before consuming recommendations.
- Failures are identified by `ErrExecutionProbe`, compatible with `errors.Is` for cancellation or deadline inspection. Diagnostics are preserved when initiated probes fail; invalid arguments or canceled waiters return a nil snapshot.

## Protocol Refinements Relative to Design

The original design evaluated outer dialects in Stage 1 via `cmd.exe /c` or `powershell.exe -Command`, but these executables can be invoked from other outer shells. The implementation instead requires the outer shell to expand `%COMSPEC%` or `$PSVersionTable` directly and validates expanded values, preventing PowerShell DefaultShells from being misclassified as CMD.

PowerShell Stage 2 executes static queries directly without depending on `powershell.exe`, supporting pwsh-only DefaultShells. Stage 1 outputs `[Environment]::OSVersion.Platform` to distinguish Windows_NT from Unix. Shell paths remain empty without guessing OS or paths from PowerShell versions alone. POSIX `RemoteShellPath` originates from `$SHELL` as metadata.

Two further refinements following review: POSIX initial probe employs `if :; then ...; fi` syntax guards, preventing Linux PowerShell 7 (which supports `$()`, `||`, and external `printf`) from misidentification as POSIX; CMD enumeration executes explicit `exit /b 0` after termination frames, avoiding leftover `where` non-zero exit codes when optional interpreters are missing. CMD end frames enclose `echo` in parentheses to prevent trailing spaces before command separators from entering the frame.

CMD preserves design recommendations: `server/cmd` when Windows PowerShell is present, `cmd/cmd` when CMD alone exists. PowerShell outer shells recommend `powershell` first, or `pwsh` if only Core is available. POSIX/fish prefers the supported and available remote default shell (bash/sh/zsh/fish; ash/dash map to sh). A native fish dialect overrides stale `$SHELL` metadata. Unknown, unsupported or unavailable defaults fall back to bash → sh → zsh → fish, with login disabled; no supported interpreter is a probe failure. All successful recommendations pass `Validate()`.

Payloads are generated strictly from static constants and dialect wrappers without inserting node fields, banners, or remote output, without creating remote files, requesting PTYs, or escalating privileges.

## Verification Scope

`core/ssh/probe_test.go` uses isolated SSH protocol fixtures to verify Linux, Alpine ash, Darwin, CMD, PowerShell, pwsh DefaultShell, banner scheduling, malformed/noisy responses, failure caching, connection isolation, 32 concurrent calls with deep copies, waiter cancellation, initiator cancellation, command & overall timeouts, and transport errors.

`core/ssh/probe_shell_test.go` executes payloads using installed real interpreters over simulated SSH channels, validating the two-stage flow; uninstalled interpreters are skipped. Windows missing interpreter tests isolate subprocess PATH to verify CMD-only and PowerShell-without-pwsh scenarios exit with 0 and complete frames.

2026-10-12 Verification Record:

- Local Linux: Real sh, bash, and PowerShell Core 7.4.6 passed two-stage tests.
- `vm` host: Windows 11 (10.0.22631.6199), OpenSSH for Windows 9.5, CMD DefaultShell. Cross-compiled test binary passed native execution with `-test.run '^TestProbe'`.
- Native SSH connection established using existing credentials, `ProbeExecutionConfig` returned `cmd`, `[powershell, pwsh, cmd]`, recommending `server/cmd` in ~196ms; subsequent calls reused cache with identical timestamp.
- Local build, test suites, Core Race checks, and linting clean.

```bash
go build ./...
go test ./...
go test -race ./core/ssh ./core/testutil/sshfixture
go test -race ./cmd/host ./pkg/adapter ./pkg/config
go test -race ./cmd/sftpshell ./pkg/playbook
golangci-lint run ./...
# Native shell regression test; runs on target platform, skips uninstalled shells
go test ./core/ssh -run '^TestProbeShell' -count=1 -v
```

Fish ensure registers `function <random-frame-name> --on-event fish_exit` and uses `builtin printf` to report the check exit code, preserving normal completion and explicit `exit`. Exec replacement or parse failure emits no result frame, so actions remain blocked. Fish working-directory commands guard the whole compound program with `cd ...; and begin ... end`. See [fish events](https://fishshell.com/docs/current/language.html#event).

Ensure blocks statuses 126/127 for all interpreters and additionally 121/123/124/125 for fish before authorizing actions. Explicit reserved exits follow the same conservative policy. Bash/sh/zsh working-directory payloads guard the entire program with `cd ... && { ...; }`, matching the fish block behavior. See [fish status codes](https://fishshell.com/docs/current/language.html#the-status-variable).

SFTP exec resolves cwd through `ResolveWorkingDirectoryExecution`. Saved server/cmd (including a cmd-only dialect setting) derives a temporary cmd/cmd adapter without probing, then applies `cd /d` and drive-path normalization. The connection/node configuration is unchanged. Other explicit server dialects are not inferred from paths such as `/C:`.

CMD cwd payloads use an early-exit guard: `cd /d "..." || exit /b & ...`. Omitting an explicit exit code retains the failed cd ERRORLEVEL. On success, the guard is skipped and user code gets no extra grouping or interpreter layer, preserving rem comments, groups and explicit exit codes. Native Windows regression tests cover the guard; read-only commands on vm also verified that a failed directory prevents subsequent statements. See [Microsoft exit documentation](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/exit).
