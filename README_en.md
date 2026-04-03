# 🚀 XOps CLI 

<div align="center">
  <h3>A Next-Generation, AI-Ready IT Operations Toolkit</h3>
  
  <p>
    <img alt="Go Version" src="https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go" />
    <img alt="License" src="https://img.shields.io/badge/License-MIT-blue.svg" />
    <img alt="Platform" src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey" />
  </p>

[English](README_en.md) | [简体中文](README.md)

</div>

---

**XOps CLI** is a powerful, modern CLI toolkit written in Go, designed to streamline and automate daily server management and IT operations. 

Beyond standard SSH and batch execution, XOps natively integrates the **Model Context Protocol (MCP)**, allowing AI Agents (like Claude) to directly interact with your infrastructure securely. It is the perfect bridge between AI assistants and your servers.

### ✨ Key Features

- 🤖 **AI-Native (MCP Server)**: Built-in Model Context Protocol server with security guardrails, risk assessment, and policy controls. Let AI Agents manage your servers safely.
- 🛡️ **Advanced SSH & TUI**: Fully OpenSSH-compatible (JumpHosts, Tunnels, Agent Forwarding). Includes a beautiful **Terminal UI (TUI)** for interactive management and an automated `sudo` mode.
- ⚡ **Batch Execution & Transfer**: Run commands or local scripts in parallel across multiple servers using tags. Effortless file distribution with built-in SCP/SFTP.
- 🗂️ **Encrypted Inventory**: Manage hosts, credentials (Identities), and tags with AES encryption. Supports bulk import/export via CSV.
- 🌐 **Network & Sec Tools**: Integrated DNS lookup, Ping, Netcat (nc), Base64/Hex encoding, and a unified **Firewall Manager** (supports firewalld, ufw, iptables, nftables).
- 🌍 **Built-in i18n**: Native support for English and Simplified Chinese.

### 📦 Installation

**Prerequisites:** Go 1.26 or higher.

```bash
git clone https://github.com/wentf9/xops-cli.git
cd xops-cli
make build
# or run manually: go build -o xops ./cmd/cli/main.go
```

### 🚀 Quick Start

#### 1. Inventory & Tags
```bash
# Import hosts from CSV and tag them as 'web'
xops loadHost hosts.csv -t web

# Add a single host manually
xops host add --name web-01 --address 192.168.1.10 --user root --tag web

# List all hosts or tags
xops host list
xops host tags
```

#### 2. SSH & TUI
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

#### 3. Batch Execution & File Transfer
```bash
# Execute 'uptime' on all 'web' servers
xops exec --tag web -c "uptime"

# Run a local script on remote servers with 5 parallel workers
xops exec --tag web --shell ./setup.sh --task 5

# Distribute a config file
xops scp ./config.conf --tag web --dest /etc/app/
```

#### 4. AI & MCP Integration (Empower your AI Agent)
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

#### 5. AI Agent Skill Integration
XOps comes with an out-of-the-box AI Agent Skill, empowering your terminal-based AI assistant with robust server management and troubleshooting capabilities.

> [!CAUTION]
> **⚠️ Risk Warning**: This skill works by granting AI assistants the ability to execute `xops` commands. Since AI assistants (e.g., Claude Code) generate commands autonomously based on natural language, **this skill file itself does not contain mandatory server-side security guardrails**. When used in production, the AI may inadvertently execute high-risk commands. Always enable the "confirm before execution" feature of your AI assistant and carefully review every command it plans to run.

**Install the Skill:**
Because different AI agents (Claude Code, Gemini CLI, etc.) use different skill installation directories, please use the generic `npx skills` tool for a standalone skill installation.

First, ensure you have installed the XOps CLI:
```bash
curl -sSL https://raw.githubusercontent.com/wentf9/xops-cli/main/install.sh | bash
```

Then, run the following command to install the AI extension skill:
```bash
npx skills add https://github.com/wentf9/xops-cli/main/skills/xops-agent
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

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.  
