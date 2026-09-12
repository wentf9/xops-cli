# 🚀 XOps CLI

<div align="center">
  <h3>Manage remote hosts from your terminal</h3>

  <p>
    <img alt="Go Version" src="https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go" />
    <img alt="License" src="https://img.shields.io/badge/License-MIT-blue.svg" />
    <img alt="Platform" src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey" />
  </p>

[English](README_en.md) | [简体中文](README.md)

</div>

---

**XOps CLI** combines host management, SSH connections, file transfers, batch execution, and Playbooks in one terminal tool. Its **Model Context Protocol (MCP)** server also connects to AI clients with configurable approvals and auditing.

[User guide](https://wentf9.github.io/xops-cli/en/) · [Command reference](https://wentf9.github.io/xops-cli/en/reference/) · [Troubleshooting](docs/en/troubleshooting/index.md)

Documentation follows the current source and may include changes not yet released. Check `xops <command> --help` for options supported by your installed version.

### ✨ Key Features

- 🤖 **AI-Native (MCP Server)**: Built-in Model Context Protocol server with security guardrails, risk assessment, and policy controls.
- 🛡️ **Advanced SSH & TUI**: Supports OpenSSH configuration imports, jump hosts, tunnels, and agent forwarding. Includes a **Terminal UI (TUI)** for interactive management and an automated `sudo` mode.
- ⚡ **Batch Execution & Transfer**: Run commands or local scripts in parallel across multiple servers using tags. Effortless file distribution with built-in SCP/SFTP. The interactive SFTP shell reports connection loss and exits with a non-zero status.
- 🔄 **Declarative Orchestration (Playbook)**: YAML-based task orchestration combining shell, script, copy, ensure (idempotent state convergence), and template steps, with concurrency control and error handling strategies.
- 🗂️ **Inventory and Credentials**: Manage hosts, credentials (Identities), and tags. New installations save verified passwords and private-key passphrases in the built-in offline encrypted store. The store and its key file are created on first save. Use `--remember never` to disable automatic saving for a connection, or set `credential.remember_prompted: never` in your configuration to disable it globally.

See [credential storage](docs/en/guide/credentials.md) for storage options and backups, and [credential migration](docs/en/guide/migration.md) to upgrade an older configuration or switch stores.

#### 2. Inventory & Tags

```bash
# Import hosts from CSV and tag them as 'web'
xops host import hosts.csv --tag web

# Add a single host manually
xops host add --address 192.0.2.10 --user root --key ~/.ssh/id_ed25519 --alias web-01 --tags web

# List all hosts or tags
xops host list
xops host tags
```

`inventory` remains a compatibility alias for `host`, and `host load` remains an alias for `host import`. New scripts should use the canonical commands above.

#### 3. SSH & TUI

```bash
# Launch interactive TUI
xops tui

# Connect by alias
xops ssh web-01

# Connect with explicit user (reuses existing Host, strictly isolates Identity, inherits ProxyJump)
xops ssh test@192.0.2.20
xops ssh test@web-01

# OpenSSH-style with JumpHost and Identity file (direct jump requires FQDN/IP/host:port; single-label requires saved Node/Alias)
xops ssh -J bastion.example.com -i ~/.ssh/id_rsa root@192.0.2.13 # Direct jump (FQDN, 192.0.2.1, or jumphost:22)
xops ssh -J jumphost -i ~/.ssh/id_rsa root@192.0.2.13            # Alias jump (jumphost as existing node/alias)

# Connect and enter sudo shell
xops ssh --sudo web-01

```

#### 4. Batch Execution & File Transfer

```bash
# Execute 'uptime' on all 'web' servers
xops exec --tag web -c "uptime"

# Run a local script on remote servers with 5 parallel workers
xops exec --tag web --shell ./setup.sh --task 5

# Distribute a config file
xops scp ./config.conf --tag web --dest /etc/app/
```

Ordinary `exec` can read existing unlocked credentials from the Linux desktop keyring without `-x`.
Use `-x` for commands requiring an interactive remote terminal, such as `top` or `vim`.
Batch execution never prompts to unlock the keyring: a locked item returns `locked`.
Access to locked items requires desktop unlock. The calling process requires access to the desktop D-Bus session.

#### 5. Declarative Orchestration (Playbook)

YAML Playbooks support multi-stage deployment workflows with shell, script, copy, ensure, and template actions.

Example Playbook `deploy.yaml`:

```yaml
name: deploy-web
targets:
  tags: [web]
settings:
  concurrency: 2
  on_error: stop
vars:
  app_port: "8080"
steps:
  - name: "install nginx"
    ensure:
      check: "nginx -v"
      action: "apt-get install -y nginx"
    sudo: true
  - name: "render and distribute configuration"
    template:
      src: "./nginx.conf.tmpl"
      dest: "/etc/nginx/nginx.conf"
    sudo: true
  - name: "start nginx service"
    shell: "systemctl start nginx"
    sudo: true
```

`settings.on_error: abort_all` cancels the other in-flight host tasks when any host connection or step fails; `continue` only continues subsequent steps on the current host.

Run a Playbook:

```bash
# Run a Playbook and override/inject variables
xops play deploy.yaml --var app_port=8081

# Preview tasks without execution (Dry Run)
xops play deploy.yaml --dry-run

# Limit execution to specific host nodes
xops play deploy.yaml --limit web-01
```

#### 6. AI & MCP Integration

XOps features a built-in **Model Context Protocol (MCP)** server, supporting infrastructure queries and operations through MCP clients such as **Claude**.

**A. Start MCP Server:**

```bash
xops mcp serve
```

**B. Example: Configure Claude Desktop**
Example `claude_desktop_config.json` configuration:

```json
{
  "mcpServers": {
    "xops": {
      "command": "/usr/local/bin/xops",
      "args": ["mcp", "serve"]
    }
  }
}
```

**C. Security & Guardrails:**

- **Risk Analysis**: Automatically detects high-risk commands (e.g., `rm -rf /`).
- **Policy Control**: Configurable approval thresholds, blocked commands, and protected paths.
- **Audit Logs**: Records command execution for auditing.

#### 7. AI Agent Skill Integration

XOps provides an AI Agent Skill documenting CLI operations for server management and troubleshooting.

> [!CAUTION]
> **⚠️ Risk Warning**: This skill works by granting AI assistants the ability to execute `xops` commands. Since AI assistants (e.g., Claude Code) generate commands autonomously based on natural language, **this skill file itself does not contain mandatory server-side security guardrails**. When used in production, the AI may inadvertently execute high-risk commands. Production use requires command confirmation and review.

**Install the Skill:**
The generic `npx skills` installer supports clients with different skill directories.

XOps CLI installation:

```bash
curl -sSL https://raw.githubusercontent.com/wentf9/xops-cli/master/install.sh | bash
```

Skill installation:

```bash
npx skills add https://github.com/wentf9/xops-cli/master/skills/xops-agent
```

The skill documents host inspection and firewall management operations.

## 🌍 I18n

The `--lang` flag selects the language; the system locale supplies the default.

```bash
xops --lang en host list
xops --lang zh host list
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
