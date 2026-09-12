# Playbooks and MCP

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

## MCP

```bash
xops mcp --help
```

MCP exposes host operations to AI clients with policy, approval, and audit controls. Enabling MCP does not mean all commands should be allowed. Non-interactive paths require credentials accessible without prompting. Repair an unavailable configured backend instead of bypassing the failure.

See the [MCP reference](../reference/commands/xops-mcp) for subcommands and options, and [Development](../development/) for architectural background.
