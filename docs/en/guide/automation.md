# Playbooks and MCP

XOps includes a declarative YAML task engine (`xops play`) and a built-in Model Context Protocol server (`xops mcp`).

> To let a Skill-capable AI assistant run `xops` CLI commands directly in its own shell (without running an MCP server), see [Agent Skill and capability overview](./agent-skill).

## Declarative Playbooks

Playbooks define multi-host workflows in YAML using `shell` (run commands), `script` (distribute and run local scripts), `copy` (upload files), `ensure` (check state and converge idempotently), and `template` (render and upload configuration files).

### 1. Quick start example

Save the following as `deploy-service.yaml`:

```yaml
name: deploy-service
targets:
  tags: [web]
settings:
  concurrency: 5
  on_error: stop
  execution:
    interpreter: bash
    launch_dialect: posix
    login: true
vars:
  http_port: "8080"
steps:
  - name: Check system uptime
    shell: uptime

  - name: Ensure Nginx is installed
    ensure:
      check: "nginx -v"
      action: "apt-get update && apt-get install -y nginx"
    sudo: true

  - name: Render and deploy configuration file
    template:
      src: "./nginx.conf.tmpl"
      dest: "/etc/nginx/nginx.conf"
    sudo: true

  - name: Restart service
    shell: "systemctl restart nginx"
    sudo: true
```

Preview and run the Playbook:

```bash
# Preview target hosts and steps without connecting or making changes
xops play deploy-service.yaml --dry-run

# Run the Playbook
xops play deploy-service.yaml

# Supply or override variables from the CLI (undefined template variables fail before execution)
xops play deploy-service.yaml --var http_port=8081

# Restrict execution to specific nodes
xops play deploy-service.yaml --limit web-01,web-02
```

### 2. Failure policies, retries, and execution settings

- **Failure policy (`settings.on_error`)**:
  - `stop` (default): Stop remaining steps on the failing host while other hosts continue.
  - `abort_all`: Cancel all active and pending host tasks immediately when any host fails.
  - `continue`: Ignore step failures on the current host and continue to its next step.
- **Safe retry boundary**: When `retries` is set on a step, XOps retries after `retry_delay` **only when remote execution is confirmed completed with no I/O or channel-cleanup errors**. If a connection drop leaves the remote outcome `unknown`, XOps never replays the step automatically. Local script files are read once and frozen in memory before tasks start.
- **Execution inheritance (`execution`)**: Set `interpreter` (`bash`, `sh`, `zsh`, `fish`, `powershell`, `pwsh`, `cmd`, or `server`) and `launch_dialect` per step (`step.execution`), per Playbook (`settings.execution`), or per node.

### 3. On-demand probing and exit-code guards for `script` and `ensure`

When no interpreter is specified and the launch dialect is unknown, **`script` steps without a shebang** and **`ensure` steps** run a bounded read-only probe once per SSH connection (cached in memory without modifying disk config or changing ordinary `shell` steps):
- **Supported shells**: `script` and `ensure` support `bash`, `sh`, `zsh`, and native `fish` (requiring a `posix` or `fish` outer launch dialect). If a Windows target is detected, XOps aborts before running user code rather than attempting syntax translation. Explicit interpreters (including `server`), UTF-8 BOMs, and non-allowlisted shebangs are never substituted automatically; allowlisted shebangs still require a known compatible outer dialect.
- **`ensure` convergence and reserved exit codes**:
  - `ensure` runs `check` first: exit `0` skips `action` (`StatusSkipped`); a confirmed ordinary nonzero exit (such as `false` returning `1`) runs `action` and then re-runs `check` to verify (using the exact same frozen execution config across `check`, `action`, and verification).
  - **Blocked error codes**: If `check` returns reserved error codes `126`/`127` (non-executable or command not found), fish execution-error codes `121`/`123`/`124`/`125`, hits a syntax error, times out, disconnects, or fails to emit its completion frame (for example, if `check` replaces the shell process via `exec`), the step fails immediately (`StatusFailed`) and **`action` is never executed**.

## MCP server integration

XOps includes an MCP server that lets AI clients such as Claude Desktop, Cursor, and Codex inspect inventory, run guarded commands, transfer files, and manage SSH tunnels.

```bash
# Start the default stdio MCP server
xops mcp serve
```

### 1. Client setup and guardrails

Configure your AI client to launch the absolute path to `xops` with arguments `["mcp", "serve"]`.

Under `guardrail` in `~/.xops/xops_config.yaml`, you can configure approval thresholds, blocked command patterns, protected file paths, and audit logs:
- **Interactive approvals**: Operations that meet or exceed the approval risk threshold trigger an approval prompt in the client (`approved=true` required); rejections, cancellations, or timeouts abort the operation before execution.
- **Timeouts and non-interactive credentials**: Stdio tool calls default to a 5-minute timeout (configurable via `mcp.tool_timeout`, e.g. `30m`). MCP runs strictly in non-interactive mode and never opens terminal password prompts or keyring unlock dialogs—run `xops credential doctor` beforehand to verify credential access.

### 2. Further MCP guides

- [MCP command reference](../reference/commands/xops-mcp)
- [MCP HTTP over LAN, streamed file transfers, and recovery](./mcp-http)
- [SSH tunnels over MCP stdio (`-L` / `-R`)](./mcp-tunnels)
