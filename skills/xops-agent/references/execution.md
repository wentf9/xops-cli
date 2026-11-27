# Remote Execution, Playbook v2, Guardrails, and Audit (XOps v2)

## Single-Target Execution (`xops exec`)

```bash
# Default launch profile: interpreter=server, login=inherit (zero remote Bash prerequisite)
xops exec --json web-01 -- uname -a
xops exec --workdir /srv/app --env APP_ENV=prod --timeout 30s --max-output-bytes 1048576 --json web-01 -- ./check.sh

# Explicit LaunchProfile matrix:
# --dialect:     posix | powershell | cmd | raw
# --interpreter: server | sh | bash | zsh | powershell | pwsh | cmd
# --login:       disabled | login | inherit
xops exec --dialect posix --interpreter bash --login disabled --json web-01 -- 'printf "%s\n" "$PATH"'
xops exec --dialect powershell --interpreter pwsh --json win-01 -- 'Get-Service | Select-Object -First 5'
xops exec --dialect cmd --interpreter cmd --json win-01 -- 'ver'
```

Always put XOps flags (`--json`, `--policy`, `--lang <en|zh>`, etc.) before `<target>` and separate remote flags with `--`; pre-scanning stops at `<target>` or `--`, so remote arguments such as `--lang=fr` pass through untouched. Default capture limit is 4 MiB (max 64 MiB); command length limit is 1 MiB.

### Single-Target Privilege Escalation

```bash
# Non-interactive with Vault secret reference (or node's configured privilege_password_ref)
xops exec --sudo --password-ref offline/web01-sudo --json web-01 -- systemctl status nginx
xops exec --sudo --privilege-user postgres --password-ref offline/web01-sudo --json web-01 -- id

# Interactive prompt (only when a human TTY is attached)
xops exec --sudo --prompt-password web-01 -- id
xops exec --su --prompt-password web-01 -- id
xops exec --doas --prompt-password web-01 -- id
```

Batch `xops exec` rejects `--sudo`/`--su`/`--doas`; use single-target invocations or Playbook v2 for multi-host orchestration.

## Concurrent Batch Execution (`xops exec`)

Passing `--all`, `--nodes`, `--tags`, or multiple `--target` values selects batch mode:

```bash
xops exec --tags web --exclude-nodes web-maint-01 --concurrency 5 --timeout 60s --json -- uptime
xops exec --nodes web-01,web-02 --concurrency 2 --stream --fail-fast -- df -h
xops exec --all --exclude-tags canary --out-dir ./batch-logs -- uname -r
xops exec --target web-01 --target deploy@192.0.2.20 --json -- hostname
```

`--out-dir` writes per-node stdout/stderr logs inside a `ScopedRootFS` sandbox directory.

## Three-State Outcomes, Exit Codes, and `do_not_retry`

- Exit codes: `0` success, `1` general/runtime error, `2` usage error, `128 + sig` remote POSIX signal, `255` SSH/auth/host-key/not-started/unknown/post-audit failure.
- `--json` returns `ExecOutcomeView` (all keys, `outcome_kind`, `exit_code`, `do_not_retry`, and `error_code` are invariant canonical English regardless of `--lang`/`XOPS_LANG`; only human-facing `diagnostic`/`error` text localizes):
  - `"outcome_kind": "completed"` — remote process finished with known exit status (`ok: true` only when exit code is 0 and no post-audit error occurred).
  - `"outcome_kind": "not_started"` — failed before remote execution started (safe to retry after fixing root cause).
  - `"outcome_kind": "unknown"` + `"do_not_retry": true` — **never blindly retry**; verify remote state with read-only checks and `xops audit tail` first.

## Playbook v2 (`xops playbook` / `xops play`)

Playbook v2 accepts strict YAML or JSON (`version: 2`, rejecting unknown keys, duplicate keys, YAML aliases, null actions, nested `ensure`, and tampered digests):

```yaml
version: 2
id: deploy-web
name: "Deploy Web"
on_error: fail_fast # fail_fast | continue | abort
target:
  tags: [web]
  exclude_nodes: [web-maint-01]
vars:
  app_port: "8080"
steps:
  - id: ensure-nginx
    action:
      kind: ensure
      check: { kind: shell, command: "command -v nginx >/dev/null 2>&1" }
      action: { kind: shell, command: "apt-get update && apt-get install -y nginx" }
      max_retries: 1
  - id: render-conf
    action:
      kind: template
      source: "./nginx.conf.tmpl"
      dest: "/etc/nginx/conf.d/app.conf"
      mode: "0644"
      overwrite: true
      atomic: true
  - id: reload
    action:
      kind: shell
      command: "systemctl reload nginx"
```

Step action kinds: `shell`, `script`, `copy`, `template`, `ensure` (no nested `ensure`).

```bash
# Offline AST/schema validation (zero Engine init, zero network)
xops playbook validate deploy.yaml --json

# Run playbook (supports --target override, --var KEY=VALUE, --concurrency, --timeout, --scoped-root, --symlink-policy, --policy)
xops playbook run deploy.yaml --var app_port=8081 --concurrency 2 --json
cat deploy.yaml | xops playbook run --stdin --policy strict --json
```

## Policy Profiles, Guardrails, and Audit (`xops audit`)

- `--policy direct_operator` (CLI default) | `strict` / `strict_operator` | `strict_agent` (MCP default; irreversible `Halted` circuit break on audit post-write failure).
- Query and reconcile `~/.xops/audit.jsonl` (always canonical English JSON/v2, unaffected by `--lang`/`XOPS_LANG`) and `~/.xops/run/*.lock`:

```bash
xops audit reconcile --json
xops audit tail --limit 20 --json
xops audit list --phase finalized --outcome outcome_unknown --node web-01 --json
xops audit inspect <operation_id> --json
```

## Interactive Interfaces & MCP Equivalents

- Interactive CLI tools (human terminal only, reject `--json`): `xops ssh <target>` and `xops tui [--node <id>] [--refresh 2s] [--no-alt-screen] [--lang <en|zh>]` (inside TUI, uppercase `L` live-toggles English/Chinese without triggering in `/` filter mode and syncs SSH takeover prompts; lowercase `l` starts log streaming).
- **MCP tools** (all tool descriptions, JSON Schemas, `approval_challenge` fields, JSON-RPC errors, and `OutcomeUnknown` automatic-retry-forbidden responses remain invariant canonical English regardless of `--lang`/`XOPS_LANG`):
  - `terminal_exec`: `exec`, `exec_privileged`, `probe_shell`, `batch_exec`, `run_playbook`.
  - `terminal_session`: managed persistent PTY (`open`, `read`, `write`, `resize`, `signal`, `inspect`, `close`).
  - `gui`: POSIX-validated remote GUI actions (`exec`, `open_session`, `inspect_session`, `close_session`; screenshots written inside `--artifact-root`).
  - Start MCP server (when explicitly requested): `xops mcp serve [--transport stdio|http] [--listen 127.0.0.1:8080] [--transfer-root <dir>] [--artifact-root <dir>]`. Remember MCP sets `OperatorReadFS == nil` (use `ssh-agent` for SSH keys).
