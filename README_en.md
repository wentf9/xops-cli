# XOps CLI

<div align="center">
  <img src="docs/public/logo.svg" width="88" alt="XOps CLI Logo" />
  <h3>Modern Terminal Operations & AI Automation in a Single Binary</h3>
  <p><b>SSH / SFTP · Terminal UI · Offline Encrypted Vault · Parallel Batch Execution · YAML Playbooks · Guardrailed MCP Server & Agent Skill</b></p>

  <p>
    <img alt="Go Version" src="https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat-square&logo=go" />
    <img alt="Platform" src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-4c8bf5?style=flat-square" />
    <img alt="MCP Ready" src="https://img.shields.io/badge/AI-MCP%20%26%20Agent%20Skill-8A2BE2?style=flat-square" />
    <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/License-MIT-2ea44f?style=flat-square" /></a>
  </p>

  <p>
    <a href="https://wentf9.github.io/xops-cli/en/"><b>📖 Documentation</b></a> ·
    <a href="https://wentf9.github.io/xops-cli/en/guide/getting-started"><b>🚀 Getting Started</b></a> ·
    <a href="https://wentf9.github.io/xops-cli/en/reference/"><b>⌨️ Command Reference</b></a> ·
    <a href="docs/en/troubleshooting/index.md"><b>🔧 Troubleshooting</b></a> ·
    <a href="README.md"><b>简体中文</b></a>
  </p>
</div>

---

Tired of stitching together half a dozen tools just to manage remote servers?
- Editing `~/.ssh/config` by hand, or using `sshpass` and leaking plaintext passwords into your shell history?
- Setting up a heavyweight Python / Ansible environment when all you want is a single binary to run parallel commands, distribute files, and converge state across a fleet?
- Watching scripts break when hitting Alpine containers (no Bash), Windows OpenSSH (`cmd` / `PowerShell`), or `fish` / `zsh` hosts?
- Wanting AI assistants (Claude, Codex, Cursor) to help inspect and operate servers—without giving them an unguarded root shell?

**XOps CLI** packs all of this into **one self-contained Go binary**: zero remote dependencies, local encrypted credential storage by default, automatic remote shell probing, and first-class **MCP Server** (with risk guardrails, interactive approvals, and audit logs) plus an installable **AI Agent Skill**.

---

## ⚡ 30-Second Quick Start

```bash
# 1. Install prebuilt binary (Linux / macOS)
curl -sSL https://raw.githubusercontent.com/wentf9/xops-cli/master/install.sh | bash

# 2. Import your existing ~/.ssh/config (local read only, no remote connections, never overwrites existing nodes)
xops init

# 3. Connect to any host — saves the node and encrypts your password/passphrase locally only after auth succeeds
xops ssh root@192.0.2.10

# 4. Launch the interactive Terminal UI (SSH sessions, live system metrics, remote log search, tag management)
xops tui
```

> **Build from source** (requires Go 1.26+; Makefile supports Linux, macOS, and Windows natively):
> ```bash
> git clone https://github.com/wentf9/xops-cli.git && cd xops-cli && make build
> # Produces bin/xops.exe on Windows; run 'make windows' on any OS to cross-compile
> ```

---

## ✨ Why XOps CLI?

| Everyday Pain Point | How XOps CLI Solves It |
| --- | --- |
| **Plaintext passwords & repetitive prompts** | **Authenticate once, encrypted locally**: Verified login passwords, key passphrases, and `sudo`/`su` passwords are encrypted in `~/.xops/credentials/` (or OS Keychain / `pass` / external helpers). Plaintext secrets never touch YAML or shell history. |
| **Broken scripts on non-Bash or Windows hosts** | **Zero remote dependencies + Auto Shell Probing**: Commands default to native `server` passthrough without requiring Bash. On first enrollment, XOps reuses the authenticated connection to probe the outer dialect (`posix`/`fish`/`cmd`/`powershell`) and installed interpreters (`bash`/`sh`/`zsh`/`fish`/`powershell`/`pwsh`/`cmd`). |
| **Disconnect between interactive & batch tools** | **Scale from 1 host to 100**: Use the exact same inventory and credentials for interactive `xops ssh`, `xops tui`, and `xops sftp`, or fan out in parallel with `xops exec --tag web` and `xops scp --tag web`. |
| **Heavyweight orchestration for simple deployments** | **Declarative YAML Playbooks**: Combine `shell`, `script`, `copy`, `template`, and idempotent `ensure` (`check` → `action` → verify) steps. Strict 3-state outcome tracking (`not_started` / `completed` / `unknown`) guarantees uncertain network drops are never blindly replayed. |
| **Unsafe AI access to production servers** | **Dual AI Integration (MCP + Agent Skill)**: Built-in MCP server (`stdio` and LAN Streamable `HTTP`) with command risk analysis, interactive Elicitation approvals, protected path rules, and audit logs—plus the `xops-agent` Skill for direct CLI agents. |

---

## 🛠️ Feature Tour

### 1. Host Inventory, Auto-Probing & Encrypted Credentials

XOps separates network addresses (**Host**), authentication profiles (**Identity**), and connection targets (**Node**), so multiple accounts can share the same server cleanly:

```bash
# Bulk-import hosts from CSV with the 'web' tag (verifies SSH auth and probes remote shells by default)
xops host import hosts.csv --tag web

# Add a single host manually
xops host add --address 192.0.2.10 --user deploy --key ~/.ssh/id_ed25519 --alias web-01 --tags web

# List hosts/tags, or probe remote OS and available interpreters on saved nodes
xops host list
xops host probe web-01
xops host probe --all --save

# Inspect credential stores and health
xops credential store list
xops credential doctor
```

- **Verified before saving**: First connections via `ssh`, `sftp`, `scp`, or `exec` save a new node only after the SSH handshake and authentication succeed—connection timeouts or wrong passwords never leave junk entries.
- **Flexible saving policies**: Pass `--remember never` for a one-off session, or set `credential.remember_prompted: ask | never` globally. Use `--skip-verify` for offline additions/imports (or `--no-probe` to skip shell probing).
- Learn more: [Hosts & Identities](docs/en/guide/hosts.md) · [Credential Storage](docs/en/guide/credentials.md) · [Offline Vault](docs/en/guide/offline-store.md) · [Credential Migration](docs/en/guide/migration.md)

### 2. Enhanced SSH, Privilege Escalation & Interactive SFTP

```bash
# Connect via alias, or as a different user on the same host (reuses Host, isolates credentials)
xops ssh web-01
xops ssh audit@web-01

# Jump host traversal (multi-hop ProxyJump via IP/FQDN/host:port or saved node aliases)
xops ssh -J bastion.example.com -i ~/.ssh/id_rsa root@192.0.2.13

# No root SSH login required: connect as an ordinary user and escalate via sudo / sudo-rs / su
xops ssh --sudo web-01
xops exec -x --sudo web-01 id

# Port forwarding & dynamic SOCKS5 proxy (with smart keepalive and disconnect cleanup)
xops ssh -L 8080:127.0.0.1:80 -D 1080 -N web-01

# Interactive SFTP shell (multi-page Tab completion, Ctrl+R history search, cwd-aware 'exec')
xops sftp web-01
```

- Learn more: [SSH & Privilege Escalation](docs/en/guide/ssh.md) · [SFTP & File Transfer](docs/en/guide/sftp.md) · [Terminal UI (TUI)](docs/en/guide/tui.md)

### 3. Parallel Batch Execution & YAML Playbooks

```bash
# Run a command in parallel across all 'web' hosts (excluding a maintenance node)
xops exec --tag web --exclude web-maint-01 -c "uptime"

# Distribute and run a local script across hosts with concurrency of 5
xops exec --tag web --shell ./setup.sh --task 5

# Distribute a configuration file to a group of servers
xops scp ./config.conf --tag web --dest /etc/app/
```

Define idempotent deployments in YAML (`deploy.yaml`):

```yaml
name: deploy-web
targets:
  tags: [web]
settings:
  concurrency: 2
  on_error: stop # stop | abort_all | continue
vars:
  app_port: "8080"
steps:
  - name: "Ensure nginx is installed"
    ensure:
      check: "nginx -v"
      action: "apt-get update && apt-get install -y nginx"
    sudo: true

  - name: "Render and distribute configuration"
    template:
      src: "./nginx.conf.tmpl"
      dest: "/etc/nginx/nginx.conf"
    sudo: true

  - name: "Restart nginx service"
    shell: "systemctl restart nginx"
    sudo: true
```

```bash
# Preview the execution plan (dry run) and execute with variable overrides
xops play deploy.yaml --dry-run
xops play deploy.yaml --var app_port=8081 --limit web-01
```

- Learn more: [Command Execution](docs/en/guide/exec.md) · [Playbooks & Automation](docs/en/guide/automation.md)

### 4. AI Integration: MCP Server & Agent Skill

XOps offers two independent ways to integrate with AI assistants:

#### Option A: Built-in MCP Server (Claude Desktop / Cursor / Codex / Antigravity)

```bash
# Start local stdio MCP server (inventory, command execution, SFTP file tools, and -L/-R SSH tunnels)
xops mcp serve

# Start LAN Streamable HTTP MCP server (Bearer token auth + streamed multi-GiB file transfers)
xops mcp serve --transport http --listen 0.0.0.0:8080 \
  --public-url http://192.168.1.10:8080 --token-file ~/.xops/mcp.token
```

Add to `claude_desktop_config.json`:

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

- **Built-in Guardrails**: Evaluates command and path risk before execution, prompts for interactive client approval (`Elicitation`) on sensitive operations, invalidates permits if target settings change during approval, and writes structured audit logs.
- Learn more: [MCP HTTP & File Transfers](docs/en/guide/mcp-http.md) · [MCP SSH Tunnels](docs/en/guide/mcp-tunnels.md)

#### Option B: `xops-agent` Skill (Direct CLI Operation for Agents)

Install the [`xops-agent`](skills/xops-agent/SKILL.md) Skill so Skill-capable agents can operate `xops` directly in their shell without running an MCP server:

```bash
npx skills add https://github.com/wentf9/xops-cli --skill xops-agent
```

For manual installation, copy the complete `skills/xops-agent/` directory (preserving `SKILL.md` and `references/`). See the [Agent Skill Guide](docs/en/guide/agent-skill.md).

### 5. Built-in Network & Security Toolkit

No need to memorize distro-specific firewall syntax or install extra diagnostic utilities:
- **`xops firewall`**: Unified firewall management across `firewalld`, `ufw`, `iptables`, and `nftables` (status, ports, services, source rules, reload).
- **`xops dns` / `ping` / `nc` / `forward`**: Cross-platform DNS lookup, ICMP ping, TCP/UDP netcat, and local port forwarding.
- **`xops encode`**: Command-line `base64`, `url`, `utf8`, and `unicode` encoding/decoding.
- **Bilingual CLI (`i18n`)**: Automatically detects Simplified Chinese or English from your environment, or switch on the fly with `--lang zh` / `--lang en`.

---

## 📄 License

Released under the [MIT License](LICENSE). If XOps CLI makes your server operations or AI workflows easier, please consider giving the repo a **Star ⭐**!
