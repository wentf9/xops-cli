# XOps Ownership Quick Reference

> Check this table first when locating a subsystem, then verify exact entry symbols with `rg` / `go list`. Directory ownership is an initial guide, not a substitute for symbol-level confirmation.

| Behavior to Change | Primary Investigation Location | Avoid Doing This | Required Linked Validation |
|---|---|---|---|
| CLI flags, help, argument validation | `cmd/root.go`, `cmd/*.go` | Changing `core/` APIs to patch CLI flag quirks | `cmd`, i18n, bilingual docs |
| Node / identity / ProxyJump selection & updates | `pkg/config/{target,provider,repository}.go`, `cmd/host/*` | Mutating config maps/files directly bypassing `Repository` | Conflicts, import/export, references, resolution |
| Password / key reference storage & migration | `pkg/credential/*`, `pkg/config/*`, `internal/credentialfile/*` | Writing plaintext secrets into YAML or logs | CAS, durability, cleanup/recovery, cross-OS |
| SSH connections, jump chains, reconnect, keepalive | `core/ssh/connector.go`, `plan.go` | Creating parallel connection pools in CLI/Playbook/MCP | Lifecycle, concurrency, host trust |
| Single remote command execution & shell probing | `core/ssh/command_*`, `execution_config.go`, `probe*.go` | Switching interpreters to retry after command failure | Outcome classification, OS interpreters, PTY/cancellation |
| Batch commands and scripts | `cmd/exec*.go`, `pkg/playbook/*` | Re-implementing execution pipelines outside `core/ssh` | Frozen scripts, no retry on `unknown` outcome |
| SFTP/SCP file transfer | `core/sftp/*`, `cmd/{scp,sftp}.go`, `cmd/sftpshell/*` | Building parallel transfer semantics in CLI vs. MCP | Atomic replacement, permissions, cancellation, resume |
| MCP tools / schemas | `core/mcp/runtime/*`, `core/mcp/ports/*` | Updating only schema fixtures or only CLI | `internal/clicontract`, MCP clients |
| MCP state admission / approvals | `core/mcp/{state,guardrail,ports}/*` | Bypassing permit, binding, or policy | Rejection paths, races, permission revocation |
| MCP host adaptation / HTTP mode | `internal/mcphost/*`, `cmd/mcp*.go` | Reading CLI config or global stdout from `core/` | Lifecycle, HTTP vs. stdio snapshot semantics |
| TUI / terminal input & line editing | `pkg/tui/*`, `cmd/sftpshell/*`, `internal/terminal/*` | Putting terminal UI state into shared `core/` | Real TTY / ConPTY / Windows |
| Cross-platform build / release | `Makefile`, `.github/workflows/*`, `scripts/*` | Treating cross-compilation as native execution proof | Linux / Windows / macOS CI |

## Red Line: Keep Three Categories of State Separate

- **Authoritative configuration state**: `pkg/config.Repository` owns disk persistence and revisions; `Provider` supplies in-memory read snapshots.
- **Connection / execution state**: `core/ssh.Connector` and execution plans / connection leases (`PlanConnection`) own transports, sessions, and reclamation; in `core/mcp`, operations must additionally hold a valid operation `Permit`.
- **Task / authorization state**: MCP bindings, permits, transfer journals, and approvals have their own lifecycle; holding an SSH connection never implies authorization to execute.

Draw a sequence diagram and inspect failure paths before making changes that cross these state boundaries.
