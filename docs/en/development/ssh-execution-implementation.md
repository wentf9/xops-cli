# SSH Execution Compatibility Implementation Plan

Based on the [SSH execution and interpreter compatibility design](./ssh-execution-compatibility.md). Status: implementation in progress. Each completed item requires code, tests, and bilingual documentation; this plan does not replace validation evidence.

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

### P2-A: Configuration and Caller Bindings

- [ ] Global/Node/Playbook execution schemas, presence, inheritance, and DTO/clone/import/export round-trip tests
- [ ] Pass plans and structured results through MCP input, ports, and host backends; show effective semantics in approval and bind execution configuration in digests
- [ ] Node/global execution changes invalidate stale approvals without invalidating unrelated configuration; request-supplied dialects cannot lower risk
- [ ] Freeze Playbook script-source bytes and node+step plans; prohibit retries for uncertain outcomes or additional cleanup failures
- [ ] Define ensure result-source protocols, check/action/verify classification, and legacy workflow migration

### P2-B: Adapters and Advanced Operations

- [ ] Validate sh on ash/dash without Bash; define shebang allowlists, unknown declarations, BOM/CRLF, and independent runtime input
- [ ] Freeze native Windows cmd/PowerShell/pwsh launch matrices, quoting, profiles, encoding, payload lengths, and exit-code protocols; validate native OpenSSH
- [ ] Separate sudo/su control protocols from user interpreters; regress authentication, terminal handoff, cancellation, and quoting
- [ ] Adapt SFTP cwd and reject pure server combinations; validate file-backend semantics
- [ ] Declare platform/interpreter requirements for built-in probes, monitoring, logs, and firewall commands

### P3: Release the Default Switch

- [ ] Complete P1/P2 acceptance and shared-core consumer validation; assign the release version
- [ ] Use server as the consistent ordinary-command default; reject scripts without a reliable interpreter before execution
- [ ] Publish separate Bash compatibility migration for commands/scripts, SFTP restrictions, and rollback-compatible schema versions
- [ ] Obtain native Windows and genuinely Bash-free Unix evidence; prohibit fallback to another interpreter after failure

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
