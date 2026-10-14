# Agent Skill and capability overview

`xops-agent` teaches Skill-capable AI assistants (such as Claude Code, Codex, and Cursor) how to operate XOps CLI. After reading the skill instructions, the assistant runs `xops` commands directly in its own command environment and inspects the results.

Skill and MCP are independent workflows—using the Skill does not require running `xops mcp serve` or registering MCP tools.

## Quick installation and usage

First [install XOps](./getting-started) in the assistant's command environment and prepare SSH configuration, trusted host keys, and accessible credentials. Then install the Skill:

```bash
npx skills add https://github.com/wentf9/xops-cli --skill xops-agent
```

For manual installation, copy the complete [`skills/xops-agent/`](https://github.com/wentf9/xops-cli/tree/master/skills/xops-agent) directory into your client's skill directory, keeping `SKILL.md` and `references/` intact (updating files in this repository checkout does not automatically update copies installed elsewhere).

Once installed, you can ask the assistant to handle tasks in plain language:
- “Use xops-agent to check disk usage on all hosts tagged `web` and list any failed nodes.”
- “Read `web-01`'s application config, change the port, and verify the updated file.”
- “Distribute the local `assets` directory to hosts tagged `web` without overwriting existing files.”
- “Forward remote port 3000 through `web-01`, verify the web page, then close the tunnel.”
- “Turn these deployment steps into a Playbook and preview targets and step order with `--dry-run` first.”

**On-demand reference files inside the Skill**:

| File | Contents |
| --- | --- |
| `references/inventory.md` | Hosts, identities, tags, credentials, and offline-store maintenance |
| `references/execution.md` | Single-host/batch commands, scripts, Playbooks, interactive terminals, and local tools |
| `references/files.md` | Reading/writing files, directory operations, SCP/SFTP, and transfer verification |
| `references/networking.md` | Tunnel process management, firewalls, network diagnostics, and local forwarding |

## CLI capability overview

| Area | CLI entry points | Typical Skill workflow |
| --- | --- | --- |
| Initialization & OpenSSH import | `init` | Check existing config; initialize or import `~/.ssh/config` when needed |
| Hosts, identities, aliases & tags | `host`, `identity` | Query nodes, bulk-import CSV, add/edit/delete records, and manage tags |
| Credentials & offline vaults | `credential`, `identity credential` | Check store health, configure credentials, and run requested migrations, rotations, recovery, or cleanup |
| SSH connections & elevation | `ssh`, `exec --sudo` | Select identity, port, and ProxyJump; allocate a terminal or escalate via `sudo`/`su` |
| Single-host & batch commands | `exec` | Select targets by host, tag, or host file, bound concurrency, and inspect per-host output |
| File reading, writing & directories | `exec`, batch `sftp` | Read bounded content, write/append, list, create, copy, move, and remove |
| File & directory transfers | `scp`, `sftp` | Upload, download, relay between hosts, distribute by tag, set overwrite policy, and verify |
| SSH tunnels & proxies | `ssh -L/-R/-D -N` | Track tunnel processes/sessions, verify listeners and target services, stop, and confirm release |
| Declarative orchestration | `play` | Combine `shell`, `script`, `copy`, `ensure`, and `template` steps; preview with `--dry-run` before running |
| Firewall management | `firewall` | Inspect status/rules and manage ports, services, source rules, and reloads (adapts to firewalld/ufw/iptables/nftables) |
| Network diagnostics & local forwarding | `dns`, `ping`, `nc`, `forward` | Test DNS/ICMP/TCP from the CLI machine or set up local TCP/UDP relays |
| Interactive UI & encoding utilities | `tui`, `sudo`, `encode` | Visual terminal management, local elevation, and `base64`/`url`/`utf8`/`unicode` conversion |
| Service administration & discovery | `mcp serve/recover`, `version`, `help`, `completion` | Manage MCP services when explicitly requested or inspect CLI help |

> Note: `host import --template` exports a blank CSV template rather than your existing inventory; `encode` subcommands are `base64`, `url`, `utf8`, and `unicode` (there is no standalone `hex` subcommand). See the [command reference](../reference/) and `xops <command> --help` for full options.

## Execution semantics and operational boundaries

- **Native passthrough default (`server`)**: Ordinary commands are sent directly to the remote SSH shell without an implicit `bash -l -c` wrapper. Write command syntax for the target's actual shell (Windows hosts no longer require Bash just for default commands).
- **Explicit interpreters and inheritance**: Global config, nodes, Playbook `settings.execution`, and steps all accept `execution`. Explicit `bash`, `sh`, `zsh`, `fish`, `powershell`, `pwsh`, or `cmd` adapters require a compatible `launch_dialect` describing the **remote outer shell** (not the assistant's local OS). `--no-login` retains its non-login Bash compatibility meaning.
- **Scripts and on-demand probing**: Local scripts require a supported interpreter and known launch dialect (allowlisted `sh`/`bash`/`zsh`/`fish` shebangs select the interpreter but do not prove a POSIX outer dialect; scripts without a reliable interpreter or with a UTF-8 BOM fail before execution). Playbook `script`/`ensure` steps without a shebang and SFTP `exec` with a nonempty `cwd` probe unspecified execution settings on demand and cache the result per connection; explicit interpreters (including `server`) are never overridden (saved `server/cmd` derives a temporary CMD adapter for SFTP `cwd`, while other explicit `server` settings reject a nonempty `cwd`).
- **Entry-point flag restrictions**: Explicit CLI execution flags on `exec` cannot currently be combined with scripts, `--sudo`, `--stream`, or `--out-dir`; explicit CLI execution flags on `ssh` are currently supported on Linux clients.
- **Local environment & paths**: Local file paths and listener ports belong to **the machine running `xops`** (a container or remote sandbox is not the user's desktop). Batch SFTP splits arguments on whitespace—use properly quoted `scp` arguments or remote commands when paths contain spaces.

## Mapping MCP tools to CLI commands

When operating through the Skill, the assistant runs the CLI commands in the right column directly:

| MCP tool | Equivalent CLI workflow |
| --- | --- |
| `xops_list_nodes` | `xops host list` (optionally with `--tag`) |
| `xops_ssh_run` | `xops exec --host NODE -c COMMAND` (optionally with `--sudo`) |
| `xops_read_file` | Target-native text commands via `exec`; download large or binary files with `scp` |
| `xops_write_file` | Generate a local file and upload with `scp`, or run an explicit write/append via `exec` |
| `xops_fs_ls/mkdir/touch/cp/mv/rm` | Batch `sftp` or target-native file commands via `exec` (use the latter to create empty files) |
| Stdio `xops_upload/download` | Upload/download files and directories with `xops scp` or batch `sftp` |
| HTTP `xops_prepare_upload/download`, `xops_transfer_status/cancel` | Transfer directly with `xops scp`, check the exit status and destination file, and cancel by stopping the owned process |
| Stdio `xops_tunnel_create/list/status/stop` | `xops ssh -L/-R -N` (CLI also supports `-D` SOCKS5; manage lifecycle via the owned process/session) |

> **Lifecycle and authorization differences**: The CLI does not create MCP transfer IDs, tunnel IDs, or TTLs, and there is no `xops tunnel list` command; killing a transfer process does not roll back bytes already written. Skill-driven CLI commands follow the assistant's own command-execution authorization—clarify targets, overwrite scope, or network exposure first whenever they are ambiguous.
