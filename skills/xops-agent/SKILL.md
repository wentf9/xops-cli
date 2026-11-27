---
name: xops-agent
description: Operate remote servers safely with XOps v2 CLI (--json, --policy, --lang) or its 7-tool sandboxed MCP server: manage Host/Identity/Node inventory and config imports, run single or batch commands and Playbook v2 workflows, inspect/edit/transfer files via atomic SFTP and resumable SCP, manage SSH tunnels and ControlMaster multiplexers, and enforce fail-closed guardrails and audit recovery.
---

# XOps v2 Operations

Use this skill when performing remote SSH/SFTP operations, inventory management, vault maintenance, tunnel/mux control, Playbook v2 automation, or MCP server administration with **XOps v2**.

## 1. Establish Environment and Policy First

1. **Verify binary & help**: Run `xops version --json` and `xops <command> --help` before relying on flag shapes. `xops version` and `--help` (with or without `--lang <en|zh>`) do not initialize Engine state or touch `~/.xops/`.
2. **Locate state directory**: XOps v2 stores strict `version: 2` YAML at `~/.xops/config.yaml`, vault data in `~/.xops/vault/`, audit logs in `~/.xops/audit.jsonl`, process locks in `~/.xops/run/`, and WAL journals in `~/.xops/journals/`. The environment variable **`XOPS_HOME`** overrides `~/.xops`. Never look for legacy v1 `xops_config.yaml` or `XOPS_CONFIG_DIR`.
3. **Prefer canonical `--json`, explicit `--policy`, and predictable `--lang`**:
   - Pass `--json` on non-interactive commands to parse deterministic JSON/v2 payloads (`ok`, `exit_code`, `error_code`, `do_not_retry`, `approval_challenge`, `reference_conflict`).
   - **Global `--lang <en|zh>` & `XOPS_LANG`**: Display language resolves per-process (zero config persistence, zero disk touch) in order `--lang > XOPS_LANG > LC_ALL > LC_MESSAGES > LANG > OS Locale > en` (Windows queries `GetUserDefaultLocaleName`; `LC_ALL=C`/`POSIX` explicitly resolves to `en` and blocks `LANG`). `--lang` uses command-aware last-wins scanning before `--` (and stops at `<target>` for `ssh`/`exec`, so remote args like `xops ssh web mytool --lang=fr` are never hijacked); invalid `--lang` values fail closed with exit code `2` (`usage_error`).
   - **Canonical English machine contract**: For agent parsing, always prefer `--json`—all JSON field names, enums, `error_code`, `do_not_retry`, `approval_challenge.reason`, `doctor --json` findings/`vault_note`, `config import --json` report warnings, `~/.xops/audit.jsonl`, and OpenSSH `-O` / `xops mux` control receipts are **invariant canonical English** regardless of `--lang` or `XOPS_LANG` (only human-facing CLI `error`/`diagnostic` text localizes; add `--lang en` if you also need English error prose).
   - CLI defaults to `--policy direct_operator`. Pass `--policy strict_agent` (or `--policy strict`) whenever guardrail thresholds, protected paths, or fail-closed audit circuit breaking are required.
   - Interactive `xops tui` (supports `--lang` and live uppercase `L` EN/ZH toggle) and interactive `xops sftp <target>` reject `--json`.
4. **Resolve targets before mutating**: Run `xops hosts list --json` (or `xops hosts resolve <target> --json`) and `xops doctor --json` before batch mutations. Confirm which machine hosts local files, `ssh-agent`, and listeners.

## 2. Choose the Right Workflow

Read only the reference file needed for your current task:

| Task | CLI Commands (v2) | MCP Tool Equivalent | Reference |
| --- | --- | --- | --- |
| Inventory CRUD, target resolution, DAG check, OpenSSH/CSV import, Vault & doctor | `hosts`, `config import`, `creds`/`vault`, `doctor` | `nodes` | [Inventory & Vault](references/inventory.md) |
| Remote exec, `sudo`/`su`/`doas`, batch fan-out, Playbook v2, audit & TUI | `exec`, `playbook`/`play`, `audit`, `tui` | `terminal_exec`, `terminal_session`, `gui` | [Execution, Playbooks & Audit](references/execution.md) |
| Atomic SFTP ops, FSTAT-anchored patch, resumable parallel SCP, WAL recovery | `sftp <op>`, `scp`, `sftp recover` | `file`, `transfer` | [Files & Transfers](references/files.md) |
| `-L`/`-R`/`-D`/StreamLocal/TUN tunnels, ControlMaster & `muxdaemon` | `ssh`, `tunnel`/`forward`, `mux` | `tunnel` | [Tunnels & Multiplexing](references/networking.md) |

## 3. Fail-Closed Safety Rules (Mandatory)

- **Zero plaintext secrets**: XOps v2 has **no** plaintext password CLI flags and forbids plaintext secret columns/fields in YAML and CSV. Use `xops creds` interactive enrollment (`enroll-password`, `enroll-key`, `set-node-privilege`, `rotate`), `<store>/<item>` references, `os_keychain`/`external_helper`, or `ssh-agent`. Never echo or log secret values.
- **Never blindly retry `ErrOutcomeUnknown` (`do_not_retry: true`)**:
  - Execution outcomes are strictly 3-state (`completed`, `not_started`, `unknown`). Only `not_started` guarantees zero remote execution.
  - When `--json` reports `"outcome_kind": "unknown"` or `"do_not_retry": true` (exit code `255`), or MCP returns `"uncertain": true` (`code: "uncertain_outcome"` or `"transfer_uncertain_commit"`, preserving the canonical English automatic-retry-forbidden warning), **stop and inspect remote state with read-only checks + `xops audit tail`** before deciding whether to re-run.
- **Never retry or delete credentials on `uncertain_durability`**:
  - When a `xops creds` saga returns `"uncertain_durability": true` (`Applied && !Durable`, `"do_not_retry": true`), do **not** retry the write or delete old/new vault items. Inspect disk state with `xops creds doctor --json` and `xops hosts list --json` first.
- **Handle `StrictAgentProfile` `Halted` (`engine_halted` / `gate_halted`)**:
  - Under `strict_agent`, any audit post-write failure irreversibly halts the Engine and revokes all active managed handles (MCP HTTP returns `503`).
  - Stop issuing new commands immediately, check disk space and `~/.xops/` owner-only permissions, run `xops audit reconcile --json` and `xops audit tail --limit 20`, and restart the long-lived process only after fixing storage health.
- **Respect MCP sandboxing (`OperatorReadFS == nil`) and canonical English MCP wire contract**:
  - `xops mcp serve` physically disables `OperatorReadFS` and accesses only `ScopedRootFS` (`--transfer-root` / `--artifact-root`).
  - Because `OperatorReadFS == nil`, `AuthPrivateKey` identities cannot read host key files directly in MCP mode (`ErrSignerUnavailable`). Load keys into **`ssh-agent`** (`SSH_AUTH_SOCK` or Windows `\\.\pipe\openssh-ssh-agent`) and use `kind: agent` (or `composite` with `agent`), or use an accessible Vault backend.
  - All **7 MCP tool** names, `tools/list` descriptions, JSON Schemas, JSON-RPC 2.0 error responses, `approval_challenge` envelope fields (`envelope`, `envelope_digest`, `escalated`, `reason`, `instructions`), and `OutcomeUnknown` responses (`uncertain: true`, automatic-retry-forbidden warning) are **invariant canonical English machine contracts**, unaffected by `--lang` or `XOPS_LANG`.
- **Respect two-step approvals (`approval_required`)**:
  - Under `no_elicit_fallback: challenge`, present the returned `approval_challenge.envelope` and `digest` (or `envelope_digest` in MCP; `approval_challenge.reason` is always canonical English) to the human operator and obtain explicit confirmation before resubmitting with `approval: { verdict, envelope_digest }`. Never forge or auto-approve challenges.

## 4. Verify and Report

After every mutation, verify the actual outcome (read back modified files via `xops sftp cat`/`stat`, confirm exit codes and per-node statuses, verify listener teardown for temporary tunnels) and report affected nodes, paths, revisions, audit `operation_id`s when relevant, and any unresolved uncertainty.
