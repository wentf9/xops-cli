# Command Execution and Batch Runs

`xops exec` handles single-target remote commands, single-target privilege escalation (`sudo`/`su`/`doas`), and concurrent multi-node batch execution with strict launch-profile validation and 3-state execution outcome tracking.

## 1. Single-Target Execution

```bash
# Basic usage (use -- to separate remote flags cleanly)
xops exec web-01 -- uname -a
xops exec -p 2222 -l deploy -J bastion 192.0.2.10 -- df -h

# Specify working directory, environment overrides, timeout, and output cap
xops exec --workdir /srv/app --env APP_ENV=prod --timeout 30s --max-output-bytes 1048576 web-01 -- ./healthcheck.sh

# Allocate (-t / -tt) or disable (-T) a pseudo-terminal
xops exec -t web-01 -- top -b -n 1

# Emit canonical JSON/v2 output (exit_code, outcome_kind, stdout, stderr, do_not_retry)
xops exec --json web-01 -- hostname
```

> Captured output defaults to **4 MiB** (configurable up to **64 MiB**) and command text is capped at **1 MiB**. Truncated captures explicitly set `truncated: true`.

## 2. Privilege Escalation (Single Target)

Single-target `xops exec` supports `--sudo`, `--su`, and `--doas`:

```bash
# Non-interactive escalation using a Vault secret reference (recommended)
xops exec --sudo --password-ref offline/web01-sudo web-01 -- systemctl status nginx

# Escalate to a specific target user (defaults to root)
xops exec --sudo --privilege-user postgres --password-ref offline/web01-sudo web-01 -- id

# Prompt interactively for the privilege password (zero plaintext CLI flags)
xops exec --sudo --prompt-password web-01 -- cat /etc/shadow
xops exec --su --prompt-password web-01 -- id
xops exec --doas --prompt-password web-01 -- id
```

- When a managed node already has `privilege_password_ref` configured (via `xops creds set-node-privilege --node <id> --store <store>`), omitting `--password-ref` automatically uses the node's binding.
- **Batch Mode Restriction**: Batch `xops exec` forbids `--sudo`/`--su`/`--doas` interactive escalation; use single-target invocations or [Playbook v2](./automation) for multi-host orchestration.

## 3. Concurrent Batch Execution

Passing `--all`, `--nodes`, `--tags`, or multiple `--target` values switches `xops exec` into concurrent batch mode:

```bash
# Fan out across a tag while excluding a maintenance node
xops exec --tags web --exclude-nodes web-maint-01 --concurrency 5 -- uptime

# Target explicit node IDs with live prefixed streaming (--stream) and --fail-fast
xops exec --nodes web-01,web-02,web-03 --concurrency 3 --stream --fail-fast -- df -h

# Target all managed nodes (excluding canary), writing per-node logs into a ScopedRootFS dir
xops exec --all --exclude-tags canary --out-dir ./batch-logs --timeout 1m -- uname -r

# Multiple explicit ad-hoc or alias targets
xops exec --target web-01 --target deploy@192.0.2.20 --json -- hostname
```

### Batch Selectors and Runtime Flags

| Flag | Description |
| --- | --- |
| `--all` | Select all managed nodes in inventory |
| `--nodes <id,...>` | Select managed nodes by ID (comma-separated, repeatable) |
| `--tags <tag,...>` | Select managed nodes by tag (comma-separated, repeatable) |
| `--target <spec,...>` | Explicit target specs (repeatable; >1 switches to batch mode) |
| `--exclude-nodes <id,...>` | Exclude specific node IDs in batch mode |
| `--exclude-tags <tag,...>` | Exclude nodes matching specific tags in batch mode |
| `--concurrency <n>` | Maximum concurrent nodes |
| `--fail-fast` | Cancel remaining pending nodes after the first failure |
| `--stream` | Stream live node-prefixed stdout/stderr lines |
| `--out-dir <dir>` | Write per-node stdout/stderr logs inside a `ScopedRootFS` directory |

## 4. Launch Profile Matrix (`LaunchProfile`)

By default, `xops exec` runs in **`interpreter: server` + `login: inherit`** passthrough mode, sending the command directly to the remote SSH shell with **zero Bash prerequisite** (works cleanly on Alpine, zsh, and Windows OpenSSH).

Override the profile explicitly with `--dialect`, `--interpreter`, and `--login`:

- `--dialect`: `posix` | `powershell` | `cmd` | `raw`
- `--interpreter`: `server` | `sh` | `bash` | `zsh` | `powershell` | `pwsh` | `cmd`
- `--login`: `disabled` | `login` | `inherit`

```bash
# Explicit POSIX bash (non-login vs. login)
xops exec --dialect posix --interpreter bash --login disabled web-01 -- 'echo "$PATH"'
xops exec --dialect posix --interpreter bash --login login web-01 -- 'env'

# Explicit PowerShell / pwsh / cmd on Windows OpenSSH targets
xops exec --dialect powershell --interpreter pwsh win-01 -- 'Get-Service | Select-Object -First 5'
xops exec --dialect cmd --interpreter cmd win-01 -- 'ver'
```

> Partially specified profiles are completed deterministically (e.g. `--interpreter bash` implies `dialect=posix, login=disabled`). Invalid combinations (such as `sh` with `login=login`, or `raw` with a non-`server` interpreter) fail closed with exit code `2` (`usage_error`).

## 5. Three-State Execution Outcomes & Exit Codes

XOps v2 models every remote execution as a closed 3-state sum type (`ExecutionOutcome`):

| `outcome_kind` | Meaning | Safe to Auto-Retry? | Exit Code / `do_not_retry` |
| --- | --- | :---: | --- |
| `completed` | Remote process terminated with an explicit exit code or POSIX signal | Depends on command idempotency | Normalized remote exit code (`0..255`) or `128 + signal`; forced non-zero if post-audit write fails |
| `not_started` | Failed before remote execution started (dial, auth, guardrail deny) | **Yes** | `255` (`ExitSSHError`) |
| `unknown` | Command started, then disconnected/timed out/lost status; remote effect is uncertain | **NO** | `255`, JSON sets `"do_not_retry": true` |

> **Safety Rule**: Never blindly replay mutating commands after `outcome_unknown` (`do_not_retry: true`). Inspect actual remote state with read-only checks and `xops audit tail` first.
