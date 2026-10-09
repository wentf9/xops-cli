---
name: xops-agent
description: Use the xops CLI to manage SSH hosts, run remote or batch commands, inspect and edit remote files, transfer data, create SSH tunnels, and automate operations with Playbooks. Apply when the user wants server operations or network diagnostics through XOps.
---

# XOps CLI operations

Perform host operations by running `xops` commands in the Agent's command environment. This skill works independently of MCP: it requires the CLI and its SSH configuration, not an MCP connection or MCP tool calls.

## Start with the execution environment

1. Run `xops --version` and the relevant `xops <command> --help`. Installed versions may differ from this reference. If the executable is missing, use the [installation guide](https://wentf9.github.io/xops-cli/guide/getting-started). Do not reinitialize an existing setup as a diagnostic step.
2. Identify where the command runs. Local paths, SSH keys, configuration, listeners, and downloads belong to that machine or container; they may not belong to the user's desktop. Default configuration is `~/.xops/xops_config.yaml`; an existing `XOPS_CONFIG_DIR` can select another configuration directory.
3. Resolve the requested hosts with `xops host list` or `xops host list --tag TAG`. Match node IDs, aliases, users, ports, and jump hosts before a batch operation. For `exec` and `scp`, `--host`, `--ifile`/`-I`, and `--tag` are mutually exclusive; choose one selector and use `--exclude` to narrow it. Preserve the user's intended target set.
4. Prepare trusted SSH host keys and credentials available to that process. Batch commands and Playbooks do not prompt for credential-store unlocks. Diagnose access with `xops credential doctor`; do not replace vaults or disable host-key verification to make a command run.

## Choose the command

Read only the reference relevant to the current task.

| Task | CLI workflow | Reference |
| --- | --- | --- |
| Discover hosts, manage aliases/tags, import CSV, edit identities or credentials | `host`, `identity`, `credential`, `init` | [Inventory and access](references/inventory.md) |
| Run a remote command, use sudo, inspect services/logs, execute across a group | `exec`, `exec --sudo`, `exec --tag` | [Execution and Playbooks](references/execution.md) |
| Run a local script remotely or orchestrate a deployment | `exec --shell`, `play` | [Execution and Playbooks](references/execution.md) |
| Read/write/append text, list/create/copy/move/delete remote paths | `exec` with target-native commands, or batch `sftp` | [Files and transfers](references/files.md) |
| Upload/download files and directories, relay between hosts, distribute to a tag | `scp`, batch `sftp` | [Files and transfers](references/files.md) |
| Create, inspect, and stop SSH forwarding | `ssh -L/-R/-D -N` plus owned process/session tracking | [Tunnels and networking](references/networking.md) |
| Manage firewalls, check DNS/ICMP/TCP, use netcat or a local TCP/UDP relay | `firewall`, `dns`, `ping`, `nc`, `forward` | [Tunnels and networking](references/networking.md) |
| Interactive SSH/TUI, local privilege elevation, text encoding | `ssh`, `exec -x`, `tui`, `sudo`, `encode` | [Execution and Playbooks](references/execution.md) |

Prefer `exec`, `scp`, and batch SFTP for unattended operations. Use terminal interfaces only when interaction is part of the task. XOps does not provide standalone CLI commands named `read_file`, `write_file`, `fs`, `upload`, `download`, or `tunnel`; compose the documented commands instead.

## Work within the requested scope

- Carry forward existing authorization. Ask only when a target, overwrite policy, privilege level, destructive effect, or additional network exposure is materially unclear or outside the authorized task.
- CLI execution does not inherit the MCP server's risk assessment, approval forms, or audit log. Follow the Agent's command-execution controls; the skill itself is guidance, not an enforcement layer.
- `xops exec` requires Bash in the remote SSH execution environment, including on Windows: commands use `bash -l -c`, or `bash -c` with `--no-login`. Invoking `powershell.exe` inside the command does not remove that wrapper. On targets without Bash, use SCP/SFTP for file operations: download, edit locally, upload, and verify through SFTP. SFTP's `exec` also requires Bash; use its file commands instead.
- Protect remote expansions from the local shell and quote for both shell layers when invoking another interpreter. Use script files for complex commands; passing a script to `exec` does not remove its Bash prerequisite.
- Keep credentials out of arguments, command history, logs, and responses. Use configured stores, SSH keys/agent, or supported stdin credential flags with a trusted secret source. Do not pass secret values as literal shell arguments.
- Use bounded execution for diagnostics and track any long-running session you create. For a timeout after a mutation starts, inspect resulting state before repeating it; do not blindly retry append, deployment, or overwrite operations.

## Verify the outcome

Check exit status and per-host failures, then verify the requested result: read back a file, compare its size/hash, probe a service, or check effective firewall rules. `--no-clobber` can succeed while skipping an existing file; a tunnel listener can start while its destination remains unreachable.

Report the affected hosts, paths, successful checks, failed targets, and remaining uncertainty. Retain the process handle for any tunnel the user wants left running; otherwise stop temporary sessions and verify cleanup. Do not claim MCP task IDs, TTLs, resumability, or atomic replacement guarantees for CLI operations.
