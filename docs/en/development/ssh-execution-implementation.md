# SSH Execution Compatibility Implementation Plan

Based on the [SSH execution and interpreter compatibility design](./ssh-execution-compatibility.md). Status: implementation in progress. Each completed item requires code, tests, and bilingual documentation; this plan does not replace validation evidence.

## Delivery Order

### P1-A: Command Plans and Bounded Execution Foundations (Current Batch)

- [x] Add immutable command plans: unchanged server payloads, Bash with a known POSIX launch dialect, login-option validation, input snapshots, and plan digests
- [x] Add an execution API with finite stdin and bounded combined output; bound channel creation, exec requests, execution, and closure, and join every worker after cancellation
- [x] Provide not_started/completed/unknown, exit code/signal, output truncation, and separate cleanup errors; never replay after a lost startup response
- [x] Expose ordinary commands through explicit `exec --interpreter`, `--launch-dialect`, and `--login-shell` options; retain the old path when new options are absent
- [x] Reject new options combined with unmigrated scripts, PTY, escalation, or streaming output; explain restrictions in help and errors rather than silently ignoring options
- [x] Use SSH fixtures for unchanged bytes, quoting, stdin/EOF, nonzero/signal/missing status, startup rejection/unanswered requests, cancellation, truncation, and no replay; add CLI parameter regressions

This batch's new API accepts finite input and internal memory output only, without uncancelable external readers/writers. Defaults are a 5-minute total timeout, a 10-second startup timeout (inheriting the connector's handshake timeout), and a 1-second shutdown grace period. Core callers may shorten or specify the total timeout. Limits are 64 KiB each for the original command and quoted exec payload, 16 MiB of stdin, a default output window retaining the last 5 MiB, and a maximum output window of 64 MiB. At the window limit, continue draining and explicitly report truncation. These limits apply to the new API; this batch does not switch old API defaults.

### P1-B: Unify Existing Entry Points and Fix Interactive Execution

- [ ] Delegate Run, RunWithoutLogin, RunCommandWithIO, and legacy Bash scripts to unified plans while retaining their individual login defaults
- [ ] Provide cancelable output bridges for terminals/pipes; migrate streaming/file output and SSH CLI while preserving stdin ownership and EOF contracts
- [ ] Bound PTY/Shell request lifecycles; distinguish full login sessions from one-shot PTY commands and propagate exit status for ordinary/root/passwordless/password sudo/su commands
- [ ] Apply new CLI options to PTY execution; distinguish explicit empty commands from absent commands and define shell-session option scope
- [ ] Declare P1 complete only after full build/test/lint and SSH/I/O race and leak regressions pass

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
