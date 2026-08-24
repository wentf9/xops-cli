# 🚀 XOps CLI

<div align="center">
  <h3>Let AI manage remote hosts within explicit safety boundaries</h3>
  
  <p>
    <img alt="Go Version" src="https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go" />
    <img alt="License" src="https://img.shields.io/badge/License-MIT-blue.svg" />
    <img alt="Platform" src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey" />
  </p>

[English](README_en.md) | [简体中文](README.md)

</div>

---

**XOps CLI** combines host inventory, SSH, batch execution, and Playbooks with built-in **Model Context Protocol (MCP)** guardrails, allowing AI Agents to operate remote hosts within approval and audit boundaries.

### ✨ Key Features

- 🤖 **AI-Native (MCP Server)**: Built-in Model Context Protocol server with security guardrails, risk assessment, and policy controls. Bounded heartbeats automatically evict dead SSH connections from the long-lived pool, keeping AI-driven server management safe and reliable.
- 🛡️ **Advanced SSH & TUI**: Fully OpenSSH-compatible (JumpHosts, Tunnels, Agent Forwarding). Includes a beautiful **Terminal UI (TUI)** for interactive management and an automated `sudo` mode.
- ⚡ **Batch Execution & Transfer**: Run commands or local scripts in parallel across multiple servers using tags. Effortless file distribution with built-in SCP/SFTP. The interactive SFTP shell detects disconnects, wakes the active prompt, exits automatically, and returns a non-zero status when the network drops.
- 🔄 **Declarative Orchestration (Playbook)**: YAML-based task orchestration combining shell, script, copy, ensure (idempotent state convergence), and template steps, with concurrency control and error handling strategies.
- 🗂️ **Encrypted Inventory**: Manage hosts, credentials (Identities), and tags with AES encryption. Supports bulk import/export via CSV.
- 🌐 **Network & Sec Tools**: Integrated DNS lookup, Ping, Netcat (nc), Base64/Hex encoding, and a unified **Firewall Manager** (supports firewalld, ufw, iptables, nftables).
- 🌍 **Built-in i18n**: Native support for English and Simplified Chinese.

### 📦 Installation

Install a pre-built binary on Linux or macOS:

```bash
curl -sSL https://raw.githubusercontent.com/wentf9/xops-cli/master/install.sh | bash
```

Building from source requires Go 1.26 or higher:

```bash
git clone https://github.com/wentf9/xops-cli.git
cd xops-cli
make build
# or run manually: go build -o xops ./cmd/cli/main.go
```

### 🚀 Quick Start

#### 1. Initialize

```bash
# Create ~/.xops/xops_config.yaml and its encryption key.
# Concrete Hosts from ~/.ssh/config are imported without connecting to them.
xops init

# Use another OpenSSH config, or skip the import entirely.
xops init --ssh-config ~/.ssh/config.work
xops init --skip-ssh-import
```

The command is idempotent and never overwrites existing nodes. Run `xops host list` to review the result.

#### 2. Inventory & Tags

```bash
# Import hosts from CSV and tag them as 'web'
xops host import hosts.csv --tag web

# Add a single host manually
xops host add --address 192.168.1.10 --user root --key ~/.ssh/id_ed25519 --alias web-01 --tags web

# List all hosts or tags
xops host list
xops host tags
```

`inventory` remains a compatibility alias for `host`, and `host load` remains an alias for `host import`. New scripts should use the canonical commands above.

#### 3. SSH & TUI

```bash
# Launch interactive TUI
xops tui

# Connect by alias (auto-saves connection details)
xops ssh web-01

# OpenSSH-style with JumpHost and Identity file
xops ssh -J jumphost -i ~/.ssh/id_rsa root@192.168.1.13

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

#### 5. Declarative Orchestration (Playbook)

You can write YAML-formatted Playbooks to execute complex, multi-stage deployment workflows. It supports shell, script, copy, ensure (idempotent state convergence), and template actions.

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

Run a Playbook:

```bash
# Run a Playbook and override/inject variables
xops play deploy.yaml --var app_port=8081

# Preview tasks without execution (Dry Run)
xops play deploy.yaml --dry-run

# Limit execution to specific host nodes
xops play deploy.yaml --limit web-01
```

#### 6. AI & MCP Integration (Empower your AI Agent)

XOps features a built-in **Model Context Protocol (MCP)** server, allowing AI assistants like **Claude** to explore and manage your infrastructure under your control.

**A. Start MCP Server:**

```bash
xops mcp serve
```

**B. Example: Configure Claude Desktop**
Add the following to your `claude_desktop_config.json` to let Claude use XOps:

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
- **Policy Control**: Supports "Audit-only" or "Manual Approval" modes.
- **Audit Logs**: Full transparency on what the AI is doing on your servers.

#### 7. AI Agent Skill Integration

XOps comes with an out-of-the-box AI Agent Skill, empowering your terminal-based AI assistant with robust server management and troubleshooting capabilities.

> [!CAUTION]
> **⚠️ Risk Warning**: This skill works by granting AI assistants the ability to execute `xops` commands. Since AI assistants (e.g., Claude Code) generate commands autonomously based on natural language, **this skill file itself does not contain mandatory server-side security guardrails**. When used in production, the AI may inadvertently execute high-risk commands. Always enable the "confirm before execution" feature of your AI assistant and carefully review every command it plans to run.

**Install the Skill:**
Because different AI agents (Claude Code, Gemini CLI, etc.) use different skill installation directories, please use the generic `npx skills` tool for a standalone skill installation.

First, ensure you have installed the XOps CLI:

```bash
curl -sSL https://raw.githubusercontent.com/wentf9/xops-cli/master/install.sh | bash
```

Then, run the following command to install the AI extension skill:

```bash
npx skills add https://github.com/wentf9/xops-cli/master/skills/xops-agent
```

Once installed, simply ask your AI assistant to "check the status of the web servers" or "open port 3306 on the database host," and it will automatically leverage XOps to complete the task!

## 🌍 I18n

You can force the language using the `--lang` flag or set your system locale.  

```bash
xops --lang en host list
xops --lang zh host list
```

## 🤝 Contributing

Please read the [AGENTS.md](./AGENTS.md) for detailed development standards, coding conventions, and testing requirements.  

Run the complete local quality gate before submitting changes:

```bash
make verify
```

To reproduce the dependency tidiness check, race detection, randomized test order, and coverage generation used by GitHub Actions, run:

```bash
make ci
```

CI runs the full build, test suite, and golangci-lint on pushes to `master` and pull requests targeting `master`.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.  
