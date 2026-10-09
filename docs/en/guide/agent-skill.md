# Agent Skill and capability overview

`xops-agent` teaches a Skill-capable Agent how to operate XOps. The Agent reads the instructions, runs `xops` in its command environment, and checks output and results. Skill and MCP are independent systems; this workflow requires neither registered MCP tools nor an MCP connection.

## Project capabilities

| Capability | CLI entry points | Skill workflow |
| --- | --- | --- |
| Initialization and OpenSSH import | `init` | Inspect existing configuration; initialize or choose an import source when needed. |
| Hosts, identities, aliases, and tags | `host`, `identity` | Resolve targets, import CSV, edit assets, and maintain tags. |
| Credentials and offline vaults | `credential`, `identity credential` | Check access, configure credentials, and perform requested migration, rotation, recovery, or cleanup. |
| SSH and privilege escalation | `ssh`, `exec --sudo` | Select identity, port, and ProxyJump; request a terminal or elevation when appropriate. |
| Single-host and batch commands | `exec` | Select hosts, tags, or a host file, bound concurrency, and inspect per-host results. |
| File editing and directory operations | `exec`, batch `sftp` | Read bounded content, write/append, list, create, copy, move, and delete. |
| File and directory transfers | `scp`, `sftp` | Upload, download, relay between hosts, distribute by tag, choose overwrite policy, and verify. |
| SSH tunnels and proxies | `ssh -L/-R/-D -N` | Track processes/sessions, inspect listeners and destination services, stop, and verify release. |
| Declarative tasks | `play` | Combine shell, script, copy, ensure, and template steps; preview and execute for selected targets. |
| Firewalls | `firewall` | Inspect state/rules and manage ports, services, source rules, and reloads. |
| Network diagnostics and local forwarding | `dns`, `ping`, `nc`, `forward` | Check DNS/ICMP/TCP from the CLI environment or create TCP/UDP relays. |
| Interactive and local utilities | `tui`, `sudo`, `encode` | Terminal management, local elevation, and Base64/URL/UTF-8/Unicode conversion. |
| Service administration and discovery | `mcp serve/recover`, `version`, `help`, `completion` | Use the CLI for explicitly requested service administration; ordinary Skill workflows do not depend on MCP. |

`host import --template` exports a CSV import template, not the existing host inventory. Encoding subcommands are `base64`, `url`, `utf8`, and `unicode`; there is no separate `hex` subcommand. Consult the [command reference](../reference/) and the installed version's `--help` for complete options.

## Performing MCP capabilities through the CLI

This table maps capabilities; the Skill executes the CLI workflows in the right column.

| MCP capability | Corresponding CLI workflow |
| --- | --- |
| `xops_list_nodes` | `xops host list`, optionally with `--tag`. |
| `xops_ssh_run` | `xops exec --host NODE -c COMMAND`, with `--sudo` when appropriate. |
| `xops_read_file` | Target-native text commands through `exec`; download large/binary files with `scp`. |
| `xops_write_file` | Generate a local file and upload with `scp`, or execute an explicit write/append through `exec`. |
| `xops_fs_ls/mkdir/touch/cp/mv/rm` | Batch `sftp` or target-native file commands through `exec`; use the latter for empty-file creation. |
| Stdio `xops_upload/download` | Upload/download files and directories with `xops scp` or batch SFTP. |
| HTTP `xops_prepare_upload/download`, `xops_transfer_status/cancel` | Transfer directly through the CLI, inspect the process, exit status, and destination file; cancel by stopping the owned process. |
| Stdio `xops_tunnel_create/list/status/stop` | `xops ssh -L/-R -N` with process/session tracking, connectivity checks, and process termination. |

Lifecycle semantics differ. The CLI creates no MCP transfer IDs, tunnel IDs, or TTLs, and has no commands such as `xops tunnel list`. Terminating a transfer process does not roll back bytes already written. CLI tunnels also support SOCKS5 with `-D`; MCP tunnels offer only stdio `-L/-R`.

Skill-driven CLI operations do not pass through MCP server risk assessment, approval forms, or auditing. They follow the Agent's own command-execution authorization controls. Existing task authorization carries forward; clarify targets, overwrite scope, or network exposure when materially unclear.

## Installation and use

[Install XOps](./getting-started) in the Agent's command environment, prepare SSH configuration, trusted host keys, and accessible credentials, then install the Skill:

```bash
npx skills add https://github.com/wentf9/xops-cli --skill xops-agent
```

For manual installation, copy the complete [`skills/xops-agent/`](https://github.com/wentf9/xops-cli/tree/master/skills/xops-agent) directory into the client's skill directory, preserving `SKILL.md` and `references/`. Updating files in this checkout does not automatically update copies installed elsewhere.

The entrypoint covers environment checks, task selection, and verification. Four references load as needed:

| File | Contents |
| --- | --- |
| `references/inventory.md` | Hosts, identities, tags, credentials, and offline-store maintenance. |
| `references/execution.md` | Single-host/batch commands, scripts, Playbooks, interactive and local tools. |
| `references/files.md` | Text editing, directory operations, SCP/SFTP, and transfer verification. |
| `references/networking.md` | Tunnel process management, firewalls, diagnostics, and forwarding. |

Example requests:

- “Use xops-agent to check disk usage on all hosts tagged web and list failed nodes.”
- “Read web-01's application configuration, change its port, and verify the file.”
- “Distribute the local assets directory to hosts tagged web without overwriting existing files.”
- “Forward port 3000 through web-01, verify the page, then close the tunnel.”
- “Turn these deployment steps into a Playbook and preview targets and step order first.”

Local files and listeners belong to the machine running the Agent's CLI commands; a container or remote sandbox is not the user's desktop. Batch SFTP splits arguments on whitespace; use properly quoted SCP operands or remote commands for paths containing spaces. See the [SFTP guide](./sftp), [SSH guide](./ssh), and Skill references for details.
