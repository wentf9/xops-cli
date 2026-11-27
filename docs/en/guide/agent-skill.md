# Agent Skill and AI Overview

XOps v2 provides two complementary ways to connect AI assistants to remote servers with clear security boundaries:

1. **Built-in MCP Server (`xops mcp serve`)**: Designed for native MCP clients (Claude Desktop, Cursor, Codex, Antigravity). Exposes **7 strongly-typed discriminated tools**, defaults to the **`strict_agent`** circuit-breaking profile, and physically enforces **zero `OperatorReadFS`** (`ScopedRootFS`-only sandboxing).
2. **`xops-agent` Agent Skill**: Designed for CLI-capable coding and operations agents. Teaches the assistant how to invoke `xops` commands directly with canonical `--json`, `--policy`, and fail-closed safety practices.

## 1. MCP Server vs. Agent Skill

| Aspect | Built-in MCP Server (`xops mcp`) | `xops-agent` Skill (Direct CLI) |
| --- | --- | --- |
| Prerequisite | Run `xops mcp serve` (`stdio` or Streamable HTTP) | Only the `xops` binary and local config are needed |
| Default policy profile | `strict_agent` (risk guardrails + irreversible `Halted` circuit break on audit post-write failure) | CLI defaults to `direct_operator`; AI workflows can enforce `--policy strict_agent` or `--policy strict` |
| Local FS isolation | **Physically disables `OperatorReadFS`**; only `ScopedRootFS` (`--transfer-root` / `--artifact-root`) is accessible | Runs with the CLI process's file permissions (downloads and recursive uploads remain `ScopedRootFS`-sandboxed) |
| Private-key auth | Because `OperatorReadFS == nil`, `AuthPrivateKey` identities require keys preloaded in **`ssh-agent`** (or `kind: agent` / unlocked Vault) | Can read local private keys directly or use `ssh-agent` / Vault |
| Long-lived sessions | Managed handles for persistent PTY (`terminal_session`), 10 GiB WAL streaming (`transfer`), tunnels/mux (`tunnel`), and GUI (`gui`) | One-shot `exec`/`scp`/`sftp`/`playbook` plus process-owned `tunnel`/`mux` |
| Audit log | Synchronous `~/.xops/audit.jsonl` + O(1) startup crash reconciliation | Same capability-gated synchronous `~/.xops/audit.jsonl` logging |

## 2. Install the `xops-agent` Skill

### Option A: Using the `skills` CLI

```bash
npx skills add https://github.com/wentf9/xops-cli --skill xops-agent
```

### Option B: From a Source Checkout

```bash
make install-skill
```

This copies `skills/xops-agent/` into `~/.gemini/skills/xops-agent/`.

### Option C: Manual Installation

Copy the complete `skills/xops-agent/` directory (keeping `SKILL.md` and all 4 files under `references/`) into your agent's skills directory:

```text
skills/xops-agent/
├── SKILL.md
└── references/
    ├── inventory.md   # Inventory graph, config import, vault, and doctor
    ├── execution.md   # Single/batch exec, escalation, LaunchProfile, Playbook v2, audit
    ├── files.md       # Parallel resumable scp, single-shot atomic sftp, SFTP shell
    └── networking.md  # ssh -L/-R/-D/-w, tunnel, and ControlMaster mux
```

## 3. Safety Rules Enforced by `xops-agent`

The v2 skill aligns AI agents with XOps v2's fail-closed contracts:

1. **Prefer canonical `--json` and invariant English contracts**: Parse deterministic JSON/v2 responses, `error_code`, `do_not_retry`, and `approval_challenge` payloads instead of scraping human text. Regardless of `--lang <en|zh>` or `XOPS_LANG`, `--json` keys, `error_code`, `approval_challenge.reason`, `doctor --json` & `config import --json` diagnostics, and all 7 MCP tools' descriptions, JSON Schemas, JSON-RPC error payloads, and `OutcomeUnknown` automatic-retry-forbidden warnings remain **invariant canonical English machine contracts** (only human-facing CLI `--json` `error`/`diagnostic` text localizes).
2. **Use explicit policy profiles**: Pass `--policy strict_agent` or `--policy strict` whenever guardrail enforcement or human approval gates are required.
3. **Zero plaintext secrets**: Never pass passwords on CLI arguments or in YAML/CSV; manage secrets exclusively via `xops creds` and `<store>/<item>` references.
4. **Never blindly retry uncertain outcomes**: When `outcome_unknown` (`do_not_retry: true`) or `uncertain_durability` (`Applied && !Durable`) occurs, inspect remote or local state before taking any corrective action, and never delete credentials prematurely.
5. **Respect `engine_halted`**: Stop immediately on `engine_halted`, diagnose audit storage/permissions, and inspect via `xops audit reconcile` and `xops audit tail`.

## Related Documentation

- [MCP Server and HTTP Streaming](./mcp-http)
- [MCP 7-Tool Protocol Reference](../reference/mcp)
- [CLI Command Reference](../reference/)
