# CLI Command Reference

Complete summary of **XOps v2** commands, aliases, core flags, exit codes, canonical JSON/v2 error envelopes, and environment variables. Run `xops <command> --help` or `xops help <command>` to confirm exact flags on your installed binary.

## Global Flags

Accepted before or inside subcommand arguments:

| Flag | Description |
| --- | --- |
| `--json` (accepts `=true\|false`) | Emit canonical deterministic JSON/v2 (`Deterministic(true)`) on `stdout`; rejected by interactive `tui` and interactive `sftp <target>` |
| `--policy <profile>` | Policy profile: `direct_operator` (CLI default) \| `strict` / `strict_operator` \| `strict_agent` (MCP default) |
| `-F <configfile>` / `--ssh-config <file>` | Alternative per-user OpenSSH configuration file (`none` disables) |
| `-h` / `--help` | Show root or subcommand help |
| `-V` / `--version` | Print build version metadata without initializing Engine state |

## Top-Level Commands

| Command | Aliases | Purpose |
| --- | --- | --- |
| `ssh` | — | Interactive SSH shell, single command, `-L/-R/-D/-w` forwarding, or `-M/-S/-O/-f` mux control |
| `exec` | — | Single-target command, single-target escalation (`--sudo`/`--su`/`--doas`), or concurrent multi-node batch execution |
| `scp` | — | Resumable parallel chunked upload and download |
| `sftp` | — | Interactive SFTP shell or 15 single-shot atomic remote SFTP operations |
| `hosts` | `host`, `inventory` | Inventory queries, target resolution, Tarjan DAG validation, secret ref checks, and CAS CRUD |
| `creds` | `cred`, `vault` | Vault lifecycle (`init`/`unlock`/`lock`/`status`), doctor, interactive enrollment (`enroll-key`/`enroll-password`/`set-node-privilege`), rotation, and safe GC |
| `tunnel` | `forward` | Dedicated local (`-L`), remote (`-R`), dynamic SOCKS5 (`-D`), StreamLocal, and TUN (`-w`) forwarding |
| `mux` | — | OpenSSH-compatible ControlMaster multiplexing and `muxdaemon` lifecycle |
| `playbook` | `play` | Offline validation (`validate`) and execution (`run`) of declarative Playbook v2 (YAML/JSON) |
| `doctor` | — | Combined read-only inventory and vault health diagnostics |
| `audit` | — | O(1) crash-lock reconciliation (`reconcile`) and local `audit.jsonl` queries (`list`/`tail`/`inspect`) |
| `config` | — | List registered import formats (`formats`) and import external configs (`import --format openssh\|csv`) |
| `mcp` | — | Start the built-in 7-tool sandboxed MCP server (`stdio` or Streamable HTTP) |
| `tui` | — | Launch the Bubble Tea v2 interactive terminal workbench |
| `version` | `-V`, `--version` | Print version, commit, build time, and Go toolchain metadata without Engine init |
| `help` | `-h`, `--help` | Show root or topic help (`xops help <topic>`) |

## Quick Command Syntax Reference

### `ssh`, `tunnel`, `mux`

```text
xops ssh [flags] [user@]host [command [args...]]
  -p <port>  -l <user>  -i <key> (repeatable)  -J <jumps>  -o <K=V> (repeatable)
  -L/-R/-D/-w <spec> (repeatable)  --tun-mode point_to_point|ethernet
  -M (-MM)  -S <ctl_path>  -O check|forward|cancel|exit|stop|proxy
  -N  -f  -t (-tt)  -T  -F <cfg>  --policy <p>  --json

xops tunnel [start] [ssh-flags] (-L|-R|-D|-w <spec>)... <target>
xops tunnel local|remote|dynamic|tun [ssh-flags] <target> <spec>

xops mux start|check|forward|cancel|exit|stop|proxy|daemon [ssh-flags] [-S <socket>] [-f|--daemon] [-L/-R/-D/-w ...] <target>
```

### `exec`

```text
xops exec [flags] <target> [--] <command [args...]>
xops exec [flags] (--all | --nodes <id,...> | --tags <tag,...> | --target <t>...) -- <command [args...]>
  Batch:     --exclude-nodes  --exclude-tags  --concurrency <n>  --fail-fast  --stream  --out-dir <dir>
  Plan:      --timeout <dur>  --max-output-bytes <n>  --workdir <remote_path>  --env <K=V>
             --dialect posix|powershell|cmd|raw  --interpreter server|sh|bash|zsh|powershell|pwsh|cmd
             --login disabled|login|inherit
  Escalate:  --sudo | --su | --doas  --privilege-user <user>  --password-ref <s/i>  --prompt-password
```

### `scp` and `sftp`

```text
xops scp [flags] <local_src> [user@]host:<remote_dest>
xops scp [flags] [user@]host:<remote_src> <local_dest>
  -P <port>  -p|--preserve  -r|--recursive  -l  -i  -J  -o  -F
  --resume  --no-clobber  --expand-into-dir[=bool]  --symlink-policy reject|contained_relative|follow_operator_source
  --local-root <dir>  --perm <octal>  --chunk-size <bytes>  --concurrency <n>
  --max-files <n>  --max-bytes <n>  --expected-digest <sha256>

xops sftp [ssh-flags] [--dir <remote_dir>] <target>
xops sftp ls|stat|read|cat|write|patch|mkdir|mv|rename|rm|rmdir|chmod|realpath|readlink|recover [flags] ...
```

### `hosts`, `creds`, `config`

```text
xops hosts list [--kind nodes|hosts|identities|all] [--tag <tag>]
xops hosts get [--kind node|host|identity] <id>
xops hosts resolve [ssh-flags] <target>
xops hosts validate-dag
xops hosts check-secret-refs (--ref <store/item> | --store <store_id>)
xops hosts create-host|update-host|delete-host ...
xops hosts create-identity|update-identity|delete-identity ...
xops hosts create-node|update-node|delete-node ...

xops creds status|init|unlock|lock|doctor [--skip-probe]
xops creds refs|delete <store>/<item>
xops creds gc <store>/<item> [...]
xops creds enroll-key --id <id> --user <u> --key-path <path> --store <store> [--cert-path <p>] [--fingerprint <fp>] [--replace]
xops creds enroll-password --id <id> --user <u> (--store <store> | --ref <store>/<item>) [--replace] [--desc <d>] [--tag <tags>]
xops creds set-node-privilege --node <node_id> (--store <store> | --ref <store>/<item>) [--expected-revision <rev>]
xops creds rotate <old_store>/<item> (--store <store> | --new-ref <store>/<item>) [--expected-revision <rev>]

xops config formats
xops config import --format openssh|csv [--file <path> | --stdin] [--plan] [--dry-run] [--expected-revision <rev>] [--source-name <name>] [--symlink-policy <policy>]
```

### `playbook`, `doctor`, `audit`, `mcp`, `tui`

```text
xops playbook validate (<file> | --file <file> | --stdin) [--json]
xops playbook run [flags] (<file> | --file <file> | --stdin)
  --target <spec,...>  --concurrency <n>  --timeout <dur>  --var <K=V>  --scoped-root <dir>
  --symlink-policy <p>  --dialect <d>  --interpreter <i>  --login <m>

xops doctor [--scope all|inventory|vault] [--check-vault] [--check-keys] [--skip-vault-probe] [--json]

xops audit reconcile [--json]
xops audit list|tail [--limit N] [--phase denied|authorized|finalized] [--outcome ...] [--node <id>] [--op-id <id>] [--trace-id <id>] [--json]
xops audit inspect <operation_id> [--json]

xops mcp [serve] [--transport stdio|http] [--listen <addr>] [--transfer-root <dir>] [--artifact-root <dir>]
                 [--allow-non-loopback] [--allowed-origin <o>] [--allowed-host <h>]

xops tui [--node <id>] [--refresh <duration>] [--no-alt-screen]
```

## Exit Codes

| Code | Constant | Meaning |
| --- | --- | --- |
| `0` | `ExitOK` | Command succeeded |
| `1` | `ExitGeneral` | General runtime failure, unhealthy doctor report, inventory/vault error, or cleanup error |
| `2` | `ExitUsage` | Invalid subcommand, flag, or argument syntax |
| `128 + N` | `ExitSignalBase + sig` | Remote process terminated by POSIX signal (e.g. `137` = `SIGKILL`, `143` = `SIGTERM`) |
| `255` | `ExitSSHError` | SSH dial/auth failure, host-key rejection, `OutcomeNotStarted`, `OutcomeUnknown`, or post-audit failure |

## Canonical `--json` Error Envelope

When `--json` is enabled and a command fails, `stdout` always receives a deterministic JSON/v2 envelope:

```json
{
  "error": "detailed sanitized message",
  "error_code": "approval_required",
  "exit_code": 1,
  "ok": false,
  "approval_challenge": { "digest": "sha256:...", "escalated": false, "envelope": {} }
}
```

Standard `error_code` values: `usage_error`, `engine_halted`, `approval_required`, `approval_rejected`, `authorization_denied`, `not_found`, `already_exists`, `revision_conflict`, `still_referenced`, `import_conflict`, `uncertain_durability`, `outcome_unknown`, `vault_unavailable`, `vault_locked`, `secret_not_found`, `auth_failed`, `host_key_unknown`, `host_key_mismatch`, `host_key_revoked`, `dial_failed`, `remote_anchor_mismatch`, `patch_conflict`, `digest_mismatch`, `symlink_rejected`, `limit_exceeded`, `unsupported`, `canceled`, `timeout`.

## Environment Variables

| Variable | Purpose |
| --- | --- |
| `XOPS_HOME` | Override default `~/.xops` state directory (`config.yaml`, `vault/`, `audit.jsonl`, `run/`, `journals/`) |
| `HOME` / `USERPROFILE` | User home directory (resolves `~/.ssh/config` and default `~/.xops`) |
| `SSH_AUTH_SOCK` | Unix `ssh-agent` socket path (Windows automatically uses ACL-verified `\\.\pipe\openssh-ssh-agent`) |
| `DBUS_SESSION_BUS_ADDRESS` | D-Bus session bus address for Linux `os_keychain` (Secret Service) |
