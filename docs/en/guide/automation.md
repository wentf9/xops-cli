# Playbooks and MCP

For Agent-driven CLI operations, see [Agent Skill and capability overview](./agent-skill). Skill workflows are independent of the MCP service interface described here.

`--var key=value` overrides YAML defaults consistently for step fields and external template files. Newly supplied variables and empty overrides are supported. Missing variables are errors; variable values are not recursively expanded.

## Playbooks

Playbooks combine shell, script, copy, ensure, and template steps in YAML. Save this read-only task as `check-hosts.yaml` to verify target selection and credentials:

```yaml
name: check-hosts
targets:
  tags: [web]
settings:
  concurrency: 2
  on_error: stop
steps:
  - name: uptime
    shell: uptime
```

```bash
xops play check-hosts.yaml
xops play --help
```

`stop` stops subsequent steps on the current host; `abort_all` cancels other host tasks after failure; `continue` allows subsequent steps on the current host. Check target tags and privilege configuration before running.

The current source supports execution configuration. Without it, MCP and Playbook commands retain login Bash defaults. An explicit server with an unknown launch dialect follows uncertain-risk policy and cannot receive a POSIX safe-prefix exemption. Escalation applies the resolved login option; unsupported server escalation and configured su combinations fail before execution. Selecting Bash through a shebang still requires a known POSIX launch dialect; cmd/PowerShell dialects cannot be discarded before running the script. See the [execution guide](./exec) for the available CLI execution options.

## MCP

```bash
xops mcp serve
```

MCP exposes host operations to AI clients. Set the client command to the full path of `xops` and its arguments to `["mcp", "serve"]`. Configure approval thresholds, blocked commands, protected paths, and audit logs in the configuration file's `guardrail` section.

Stdio tool calls have a five-minute default deadline. Set `mcp.tool_timeout`, for example `30m`, for longer calls; expiry cancels that invocation. Background SSH tunnels have their own TTL, and HTTP file transfers use their task deadlines.

When approval is requested, confirm `approved=true` in the client form. Refusal, cancellation or timeout stops the operation. Confirm again if approval expires or the operation's arguments change. If the client cannot display or submit the form, use a client that supports approval.

Prepare credentials and verified host keys before starting; MCP does not display terminal authentication or unlock prompts. If credentials are unavailable, check storage with `xops credential doctor` and restore access.

See the [MCP reference](../reference/commands/xops-mcp) for subcommands and options.

Stdio also provides [SSH tunnel tools](mcp-tunnels) to create, inspect and stop local (`-L`) and remote (`-R`) forwards.

[LAN HTTP setup, client file transfers and recovery](mcp-http).

`xops_fs_cp` copies through SFTP: ordinary source links remain links, directory source `link/` follows the directory while retaining `link` as the destination basename, and `link/.` copies contents directly. Copying a regular file onto an existing file link updates its target and preserves the link; dangling destination file links are rejected. Spaces and backslashes in paths are literal characters; only `/` is a separator.
