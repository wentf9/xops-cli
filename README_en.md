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

**XOps CLI** brings host management, SSH connections, file transfers, batch execution, and Playbook orchestration into one terminal tool. It also integrates with AI clients through the **Model Context Protocol (MCP)**, with configurable operation approvals and auditing.

[User guide](https://wentf9.github.io/xops-cli/en/) · [Command reference](https://wentf9.github.io/xops-cli/en/reference/) · [Troubleshooting](docs/en/troubleshooting/index.md)

The documentation follows the current source and may describe changes that have not yet been released. Use `xops <command> --help` to check the options supported by your installed version.

### ✨ Key Features

- 🤖 **AI-Native (MCP Server)**: A built-in Model Context Protocol server supports command risk assessment, approvals, and auditing.
- 🛡️ **Enhanced SSH & TUI**: Import OpenSSH configurations and use jump hosts, tunnels, and SSH agent forwarding. Includes a **Terminal User Interface (TUI)** and automatic sudo privilege escalation.
- ⚡ **Batch Execution & Transfer**: Run commands or local scripts concurrently across hosts selected by tags. Built-in SCP/SFTP supports bulk file distribution. The interactive SFTP shell reports a lost connection and exits with a nonzero status.
- 🔄 **Declarative Orchestration (Playbook)**: Define YAML workflows with shell, script, copy, ensure (idempotent convergence to a desired state), and template steps, with concurrency limits and failure policies.
- 🗂️ **Inventory & Credentials**: Manage hosts, authentication identities (Identity), and tags locally. Save verified passwords in the offline encrypted vault or another configured credential store, and use CSV templates for bulk imports and exports.
- 🌐 **Network & Security Tools**: Includes DNS lookups, Ping, Netcat (nc), Base64/Hex conversion, and a unified **firewall manager** that adapts to firewalld, ufw, iptables, and nftables.
- 🌍 **Internationalization (i18n)**: Supports Simplified Chinese and English, with automatic language selection based on the environment.

### 📦 Installation

Install a prebuilt release on Linux or macOS:

```bash
curl -sSL https://raw.githubusercontent.com/wentf9/xops-cli/master/install.sh | bash
```

Building from source requires Go 1.26 or newer. The Makefile supports Linux, macOS, and Windows:

```bash
git clone https://github.com/wentf9/xops-cli.git
cd xops-cli
make build
# Windows produces bin/xops.exe; use make windows on any platform to cross-compile
# Or build manually: go build -o xops ./cmd/cli/main.go
```

### 🚀 Quick Start

#### 1. Initialization

```bash
# Create the Schema v2 configuration at ~/.xops/xops_config.yaml without creating an encryption key
# Import non-wildcard Host entries from ~/.ssh/config by default; no remote connections are made
xops init

# Use a specific OpenSSH configuration, or skip importing entirely
xops init --ssh-config ~/.ssh/config.work
xops init --skip-ssh-import
```

Initialization can be repeated without overwriting existing nodes. Run `xops host list` afterward to inspect the imported nodes.

New installations save verified passwords and private-key passphrases in the built-in offline encrypted vault. The vault and its key file are created automatically on the first save. Add `--remember never` to disable automatic credential saving for one connection, or set `credential.remember_prompted: never` in the configuration to disable it globally.

New nodes discovered through SSH, SFTP, SCP, or exec are saved only after the SSH handshake and authentication succeed. Connection timeouts, refused connections, and authentication failures do not add nodes. Saving happens immediately after authentication, without waiting for a shell or remote command to succeed. Existing nodes are not deleted when a connection fails. Explicit additions and imports can use `--skip-verify` to save offline. `--remember` controls credential secrets and does not affect saving node details after successful authentication.

See [credential storage](docs/en/guide/credentials.md) for storage choices and backups, and [credential migration](docs/en/guide/migration.md) for upgrading old configurations or changing stores.

#### 2. Host & Inventory Management

```bash
# Import hosts from a CSV file and assign the 'web' tag
xops host import hosts.csv --tag web

# Manually add one host
xops host add --address 192.0.2.10 --user root --key ~/.ssh/id_ed25519 --alias web-01 --tags web

# List hosts or tags
xops host list
xops host tags
```

`inventory` remains a compatibility alias for `host`, and `host load` remains a compatibility alias for `host import`. Use the canonical commands above in new scripts.

Imports save only nodes that pass SSH verification by default, and failed rows are explicitly marked as not saved. `--skip-verify` saves directly without verification; `--save-on-verify-failure` saves even when verification fails. These options are mutually exclusive. Both `host add` and the TUI verify new nodes first and ask whether to save after a failure, defaulting to no. For offline addition, use `--skip-verify` in the CLI or select **Skip verification and save** in the TUI form.

#### 3. SSH Connections & TUI

```bash
# Launch the interactive management interface
xops tui

# Connect using an alias
xops ssh web-01

# Connect to the same host as a different user (reuses Host, isolates credentials, inherits ProxyJump)
xops ssh test@192.0.2.20
xops ssh test@web-01

# OpenSSH-style jump host and private key (direct jumps accept FQDN/IP/host:port; single labels require a saved Node/Alias)
xops ssh -J bastion.example.com -i ~/.ssh/id_rsa root@192.0.2.13 # Direct jump (FQDN, 192.0.2.1, or jumphost:22)
xops ssh -J jumphost -i ~/.ssh/id_rsa root@192.0.2.13            # Alias jump (jumphost is an existing node/alias)

# Connect with sudo privilege escalation
xops ssh --sudo web-01
```

#### 4. Batch Execution & File Distribution

```bash
# Run uptime concurrently on all hosts tagged 'web'
xops exec --tag web -c "uptime"

# Run a local script on remote hosts with a concurrency limit of 5
xops exec --tag web --shell ./setup.sh --task 5

# Distribute a configuration file to the target servers
xops scp ./config.conf --tag web --dest /etc/app/
```

Ordinary `exec` can read existing credentials from an unlocked Linux desktop keyring without `-x`.
Use `-x` for commands that need an interactive remote terminal, such as `top` or `vim`; ordinary batch execution does not prompt to unlock the keyring.
A locked keyring returns `locked` and must first be unlocked in the desktop session. The executing process needs access to that desktop's D-Bus session.

#### 5. Declarative Orchestration (Playbook)

Playbooks describe deployment tasks in YAML. Supported actions include shell, script, copy, ensure (converging to a desired state), and template.

Example `deploy.yaml`:

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
  - name: "Install nginx"
    ensure:
      check: "nginx -v"
      action: "apt-get install -y nginx"
    sudo: true
  - name: "Render and distribute configuration"
    template:
      src: "./nginx.conf.tmpl"
      dest: "/etc/nginx/nginx.conf"
    sudo: true
  - name: "Start the nginx service"
    shell: "systemctl start nginx"
    sudo: true
```

`settings.on_error: abort_all` cancels other active host tasks when a connection or step fails on any host. `continue` only allows subsequent steps on the current host to proceed.

Run a Playbook:

```bash
# Run the Playbook and supply or override variables
xops play deploy.yaml --var app_port=8081

# Preview the steps without executing them
xops play deploy.yaml --dry-run

# Limit execution to a specific node
xops play deploy.yaml --limit web-01
```

#### 6. AI & MCP Integration

XOps includes a **Model Context Protocol (MCP)** server that lets MCP clients such as **Claude** query and operate servers.

**A. Start the MCP server:**

```bash
xops mcp serve
```

LAN clients (Codex / Antigravity CLI) can use `xops mcp serve --transport http`. See the [HTTP MCP guide](docs/en/guide/mcp-http.md) for authentication, streamed file transfers and client limitations.

Stdio provides tools to create, inspect and stop SSH `-L/-R` tunnels. See [MCP SSH tunnels](docs/en/guide/mcp-tunnels.md).

**B. Example: Integrate with Claude Desktop**

Example configuration for `claude_desktop_config.json`:

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

**C. Security guardrails:**

- **Risk assessment**: Evaluates the risk of commands requested by AI clients, including potentially dangerous operations such as `rm -rf`.
- **Policy controls**: Configure approval thresholds, blocked commands, and protected paths.
- **Audit logs**: Record MCP tool calls and their outcomes for traceability.

#### 7. AI Agent Skill Integration

XOps provides an AI Agent Skill with CLI instructions for server management and troubleshooting.

> [!CAUTION]
> **⚠️ Risk warning**: This skill gives AI assistants the ability to execute `xops` commands. AI assistants such as Claude Code generate commands autonomously from natural-language instructions, and **the skill file itself does not enforce server-side security guardrails**. In production, an AI assistant may mistakenly run a dangerous command, such as `rm -rf`, or restart a service. Enable command execution confirmation and review commands before production use.

**Install the skill:**

Skill directories vary by client. The installation command uses the general-purpose `npx skills` tool.

Install XOps CLI:

```bash
curl -sSL https://raw.githubusercontent.com/wentf9/xops-cli/master/install.sh | bash
```

Install the skill:

```bash
npx skills add https://github.com/wentf9/xops-cli/master/skills/xops-agent
```

The skill includes instructions for checking host status and managing firewalls.

## 🌍 Internationalization / I18n

Select the language with `--lang`. If it is omitted, XOps detects the language from the system environment.

```bash
xops --lang en host list
xops --lang zh host list
```

## 📄 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
