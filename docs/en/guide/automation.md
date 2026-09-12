# Playbooks and MCP

`--var key=value` overrides YAML defaults consistently for step fields and external template files. Newly supplied variables and empty overrides are supported. Missing variables are errors; variable values are not recursively expanded.

MCP approval requires `approved=true` in the confirmation form. Modern protocols use InputRequests round trips with single-use challenges bound to the session and complete tool input, expiring after two minutes; legacy protocols use elicitation. Configured fallback applies only when approval is explicitly unsupported. Protocol errors, rejection, cancellation and timeout never authorize execution. Approval requests and execution are audited separately.

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
xops mcp serve
```

MCP exposes host operations to AI clients. Set the client command to the full path of `xops` and its arguments to `["mcp", "serve"]`. Configure approval thresholds, blocked commands, protected paths, and audit logs in the configuration file's `guardrail` section.

Prepare credentials and verified host keys before starting; MCP does not display terminal authentication or unlock prompts. If credentials are unavailable, check storage with `xops credential doctor` and restore access.

See the [MCP reference](../reference/commands/xops-mcp) for subcommands and options.
