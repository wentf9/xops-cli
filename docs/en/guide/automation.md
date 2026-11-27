# Playbooks v2, Guardrails, and Audit

XOps v2 integrates declarative multi-node orchestration (`xops playbook` / `xops play`), capability-gated security guardrails (`PolicyProfile` + `policy.guardrail`), and synchronous fail-closed audit logging (`xops audit`) into one unified execution path.

## 1. Declarative Playbook v2

Playbook v2 accepts both **YAML** and strict **JSON** documents through the discriminated `core/domain/playbook` validator. Documents must declare `version: 2`; unknown fields, duplicate keys, YAML aliases, JSON `null` actions, nested `ensure`, and tampered digests are rejected fail-closed.

### Complete Example (`deploy.yaml`)

```yaml
version: 2
id: deploy-web
name: "Deploy Web Application"
description: "Install nginx, render config, and reload service"
on_error: fail_fast # fail_fast | continue | abort
target:
  tags: [web]
  exclude_nodes: [web-maint-01]
vars:
  app_port: "8080"
  env_name: "prod"
steps:
  - id: ensure-nginx
    name: "Ensure nginx package is installed"
    action:
      kind: ensure
      check:
        kind: shell
        command: "command -v nginx >/dev/null 2>&1"
      action:
        kind: shell
        command: "apt-get update && apt-get install -y nginx"
        timeout: 3m
      max_retries: 1

  - id: upload-conf
    name: "Render and atomically publish nginx config"
    action:
      kind: template
      source: "./templates/nginx.conf.tmpl"
      dest: "/etc/nginx/conf.d/app.conf"
      vars:
        listen_port: "8080"
      mode: "0644"
      overwrite: true
      atomic: true

  - id: copy-static
    name: "Copy release manifest"
    when_tags: [frontend]
    action:
      kind: copy
      source: "./manifest.json"
      dest: "/srv/www/manifest.json"
      mode: "0644"
      overwrite: true
      atomic: true

  - id: verify-script
    name: "Run post-deploy check script"
    on_error: continue
    action:
      kind: script
      source: "./scripts/verify.sh"
      args: ["--strict"]
      work_dir: "/srv/www"
      env:
        APP_ENV: "prod"
      timeout: 30s
```

### Five Sealed Step Actions (`action.kind`)

| `kind` | Required Fields | Optional Fields | Purpose |
| --- | --- | --- | --- |
| `shell` | `command` | `profile`, `work_dir`, `env`, `timeout` | Run a remote command |
| `script` | `source` | `symlink_policy`, `args`, `profile`, `work_dir`, `env`, `timeout` | Read a local script and run it remotely |
| `copy` | `source`, `dest` | `symlink_policy`, `mode` (3/4-digit octal e.g. `"0644"`), `overwrite`, `atomic` | Upload a local file to a remote path |
| `template` | `source`, `dest` | `symlink_policy`, `vars`, `mode`, `overwrite`, `atomic` | Render a local template and upload it remotely |
| `ensure` | `check`, `action` | `max_retries` | Idempotent convergence: run `action` and re-verify only when `check` fails (nested `ensure` is forbidden) |

### Error Policies (`on_error`)

- `fail_fast`: Stop remaining steps on the failing node while other nodes continue.
- `continue`: Record the failure and continue with subsequent steps on the same node.
- `abort`: Cancel remaining playbook work across all nodes immediately on the first failure.

### Validate and Run

```bash
# 1. Pure offline AST & schema validation (zero Engine init, zero network, prints canonical digest)
xops playbook validate deploy.yaml
xops playbook validate deploy.yaml --json

# 2. Execute playbook (--var overrides, --target selector override, --concurrency, --timeout, --scoped-root)
xops playbook run deploy.yaml --var app_port=8081 --concurrency 3
xops play run deploy.yaml --target web-01 --scoped-root ./release-bundle --json

# 3. Read playbook from stdin (--stdin or -)
cat deploy.yaml | xops playbook validate --stdin --json
cat deploy.yaml | xops playbook run --stdin --policy strict
```

> If any step enters `OutcomeUnknown`, the CLI exits non-zero and warns you to inspect actual remote state rather than blindly retrying.

## 2. Security Guardrails (`PolicyProfile` & `policy.guardrail`)

XOps v2 combines **policy profiles** (`PolicyProfile`) with declarative **guardrail rules** (`policy.guardrail`). Configure defaults in `~/.xops/config.yaml` and override per command with `--policy`:

| Profile | Default Scope | Behavior |
| --- | --- | --- |
| `direct_operator` | CLI default | Full audit trail + explicit `Deny` enforcement; skips risk-threshold approval prompts for direct human CLI runs |
| `strict` / `strict_operator` | Opt-in | Full risk thresholds, `node_overrides`, protected paths, and approval challenges; audit errors fail the call without permanently locking short-lived CLIs |
| `strict_agent` | MCP default | Full guardrails + irreversible **`Halted` circuit break** on any `AuditPostWriteError`, revoking all active managed handles and rejecting new calls |

### Guardrail Config Example (`~/.xops/config.yaml`)

```yaml
version: 2
policy:
  cli_default: direct_operator
  mcp_default: strict_agent
  guardrail:
    approval_threshold: moderate    # safe | moderate | dangerous | critical
    no_elicit_fallback: challenge   # deny (zero-value default) | challenge (two-step approval envelope)
    audit_log: ~/.xops/audit.jsonl
    approval_ttl: 5m                # range (0, 24h]
    protected_paths:
      - "/etc/**"
      - "/root/**"
      - "C:/Windows/**"
    node_overrides:
      "prod-*":
        approval_threshold: safe
        decision_floor: need_approval # allow | need_approval | deny
      "staging-*": moderate         # scalar shorthand sets approval_threshold
```

- Matching `protected_paths` elevates operation risk to at least `dangerous`.
- Multiple matching `node_overrides` fold via a join-semilattice (strictest rule always wins regardless of ordering).
- `no_elicit_fallback: deny` rejects approval-required operations in non-interactive sessions; `challenge` issues a replay-protected, TTL-bound `ApprovalEnvelope` (`envelope_digest`) for human review and two-step resubmission.

## 3. Audit Log and O(1) Crash Reconciliation (`xops audit`)

Every gated operation writes canonical JSON/v2 records (`denied`, `authorized`, `finalized`) to `~/.xops/audit.jsonl` coordinated via sidecar lock `audit.jsonl.lock`.

### O(1) Process-Lock Crash Reconciliation

- Each live Engine holds an OS kernel lock on `~/.xops/run/<ProcessInstanceID>.lock` using an append-only `+<opID>` / `-<opID>` protocol for active operations.
- **O(1) Clean Startup**: When no dead-process `.lock` files exist under `run/`, startup does zero scanning of `audit.jsonl`.
- **Crash Recovery**: Any leftover `.lock` file is probed via non-blocking `TryLock`; once confirmed dead, unclosed operations are verified against `audit.jsonl`, finalized with `outcome: aborted_by_crash` under `audit.jsonl.lock`, and the dead lock file is truncated, closed, and removed safely across Unix and Windows.

### Querying and Reconciling Audit Records

```bash
# Inspect recent or filtered audit records (list takes earliest matches; tail takes latest)
xops audit tail --limit 20
xops audit list --phase finalized --outcome outcome_unknown --json
xops audit list --node web-01 --trace-id <trace_id>

# Inspect the full lifecycle of a single operation
xops audit inspect <operation_id> --json

# Manually trigger crash-lock reconciliation (also runs automatically at CLI Engine & MCP startup)
xops audit reconcile --json
```
