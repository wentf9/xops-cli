# Playbooks and MCP

XOps provides declarative task orchestration (Playbooks) for operations engineers and a Model Context Protocol (MCP) server for AI Agents, enabling seamless infrastructure automation.

For Agent-driven CLI operations, see [Agent Skill and capability overview](./agent-skill). Skill workflows are independent of the MCP service interface described here.

## Declarative Playbooks

Playbooks use YAML to define automation workflows, combining `shell`, `script`, `copy`, `ensure` (state convergence), and `template` (configuration rendering) steps, with concurrency and failure handling controls.

### Example Playbook

Save the following content as `deploy-service.yaml`:

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

Running the Playbook:

```bash
# Execute Playbook
xops play deploy-service.yaml

# Override variables from command line
xops play deploy-service.yaml --var http_port=8081

# Dry-run execution preview without making changes
xops play deploy-service.yaml --dry-run

# Restrict execution to a specific host
xops play deploy-service.yaml --limit web-01
```

### Error handling and execution environments

- **Failure handling policies (`on_error`)**:
  - `stop` (default): Stop subsequent steps on the failing host; other hosts continue uninterrupted;
  - `abort_all`: Cancel all active and pending host tasks immediately upon any host failure;
  - `continue`: Ignore step failures on the current host and proceed with remaining steps.
- **Variable overrides (`--var key=value`)**: Variables passed via CLI override YAML values of the same name and can be referenced in templates and command steps; undefined variables trigger validation errors.
- **Execution environment configuration (`execution`)**:
  - Configure default execution options (such as `interpreter: bash`, `powershell`, `cmd`, or `server`) in `settings.execution`;
  - Override execution per step using `execution` (for instance, using `interpreter: cmd` on a specific step targeting Windows hosts);
  - Unconfigured steps inherit settings hierarchically: step override > playbook settings > node configuration > system default.

### On-demand Playbook probing

With an unspecified interpreter and unknown launch dialect, scripts without a shebang and ensure
checks perform a bounded read-only probe before user code. One SSH connection shares the result,
including failures. Runtime probing does not write node configuration or change ordinary shell-step
defaults. Explicit interpreters (including `server`), BOMs and unsupported shebangs are not replaced.
An allowlisted bash/sh shebang still requires an already known compatible outer dialect.

Script and ensure adapters currently support POSIX bash/sh. A Windows detection fails before user code
without syntax translation. Ensure uses the same controlled configuration for check, action and verify;
probe failures never authorize an action or retry user work. Dry runs do not connect or probe.

## MCP service integration

```bash
xops mcp serve
```

XOps includes a built-in server adhering to the Model Context Protocol (MCP) standard, enabling seamless integration with AI clients like Claude Desktop and Cursor.

### Client configuration

Set the MCP server command in your AI client to the absolute path of `xops`, with arguments `["mcp", "serve"]`.

In `~/.xops/xops_config.yaml`, configure approval thresholds, blocked command rules, protected path policies, and audit logs under the `guardrail` section.

### Timeouts and long-running operations

- **Call timeout controls**: Stdio tool calls have a default timeout of 5 minutes. Adjust `mcp.tool_timeout` (e.g., `30m`) in your configuration for longer tasks.
- **Approval safety mechanisms**: When an operation triggers safety thresholds, the client prompts for approval with `approved=true`. Rejections, cancellations, or expired approvals terminate the operation cleanly.
- **Non-interactive credential access**: MCP operates in non-interactive mode and will not display terminal passphrase prompts or credential store unlock dialogues. Ensure target hosts have credentials configured or accessible. Use `xops credential doctor` to verify storage health.

See the [MCP reference](../reference/commands/xops-mcp) for subcommands and options. Advanced topics:
- [LAN HTTP setup, client file transfers and recovery](mcp-http)
- [MCP SSH tunnel tools](mcp-tunnels) (manage port forwarding dynamically via AI)
