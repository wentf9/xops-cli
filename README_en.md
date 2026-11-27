# XOps CLI (v2)

<div align="center">
  <img src="docs/public/logo.svg" width="88" alt="XOps CLI Logo" />
  <h3>Single-Binary, Zero-Remote-Dependency SSH Operations & Guardrailed AI Automation</h3>
  <p><b>OpenSSH-Compatible CLI · Parallel Execution & Playbook v2 · Resumable SFTP/SCP · Bubble Tea v2 TUI Workbench · AEAD Encrypted Vault · 7-Tool Sandboxed MCP Server & Agent Skill</b></p>

  <p>
    <img alt="Go Version" src="https://img.shields.io/badge/Go-1.27+-00ADD8?style=flat-square&logo=go" />
    <img alt="Platform" src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-4c8bf5?style=flat-square" />
    <img alt="MCP Ready" src="https://img.shields.io/badge/AI-MCP%20%26%20Agent%20Skill-8A2BE2?style=flat-square" />
    <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/License-MIT-2ea44f?style=flat-square" /></a>
  </p>

  <p>
    <a href="https://wentf9.github.io/xops-cli/en/"><b>📖 Documentation</b></a> ·
    <a href="docs/en/guide/getting-started.md"><b>🚀 Quick Start</b></a> ·
    <a href="docs/en/reference/index.md"><b>⌨️ CLI Reference</b></a> ·
    <a href="docs/en/reference/config.md"><b>🧩 Config Schema v2</b></a> ·
    <a href="docs/en/reference/mcp.md"><b>🤖 MCP Reference</b></a> ·
    <a href="docs/en/troubleshooting/index.md"><b>🔧 Troubleshooting</b></a> ·
    <a href="README.md"><b>简体中文</b></a>
  </p>
</div>

---

**XOps v2** is a clean-room rewritten, single-binary cross-platform SSH/SFTP operations and AI automation platform built with Go 1.27+ (`CGO_ENABLED=0`):

- **OpenSSH-Native CLI & 4-Layer Option Precedence**: Supports standard flags (`-p/-l/-i/-J/-L/-R/-D/-w/-o/-O/-M/-S/-F/-t/-tt/-T/-N/-f`), deterministic 4-layer policy resolution (`CLI > Managed Node > XOps Global > ~/.ssh/config`), ControlMaster/ControlPersist multiplexing (`xops mux`), and local/remote/SOCKS5/StreamLocal/TUN tunnels (`xops tunnel`).
- **Graph Inventory & Multi-Backend Encrypted Vault**: Decouples **Host**, **Identity**, and **Node** with Tarjan jump-DAG cycle detection and CAS persistence in strict `version: 2` YAML (`~/.xops/config.yaml`, overridable via `XOPS_HOME`). Plaintext secrets are forbidden in both YAML and CLI flags; supports `offline_aead` (Argon2id + XChaCha20-Poly1305), native `os_keychain` (Windows Credential Manager / macOS Keychain / Linux Secret Service), `external_helper` (JSON v2 stdin/stdout), and `none`.
- **Batch Execution, Atomic SFTP & Declarative Playbook v2**: Single/batch concurrent command execution, privilege escalation (`--sudo`/`--su`/`--doas`), explicit launch profiles (`posix`/`powershell`/`cmd`/`raw` × `server`/`sh`/`bash`/`zsh`/`powershell`/`pwsh`/`cmd`), parallel resumable SCP, single-shot and interactive SFTP Shell, and declarative Playbook v2 (`shell`/`script`/`copy`/`template`/`ensure`). Strict 3-state execution outcomes flag uncertain network failures with `OutcomeUnknown` / `do_not_retry`.
- **Fail-Closed Guardrails, O(1) Audit Reconciliation & Sandboxed MCP**: Capability-gated execution with synchronous `audit.jsonl` logging and O(1) startup crash-lock reconciliation; built-in **7 strongly-typed discriminated MCP tools** over `stdio` and Streamable HTTP (plus a 10 GiB dual-generation WAL streaming endpoint), defaulting to `strict_agent` with fail-closed `Halted` circuit breaking and **zero `OperatorReadFS`** (`ScopedRootFS`-only sandboxing).
- **Native Bilingual Localization & Canonical English Machine Contracts**: Embedded in-memory English (`en`) and Simplified Chinese (`zh`) catalogs with zero persistence and zero disk touch on `--help`/`version`; supports global `--lang <en|zh>` and `XOPS_LANG` with deterministic precedence (`--lang > XOPS_LANG > LC_ALL > LC_MESSAGES > LANG > OS Locale > en`, where `LC_ALL=C`/`POSIX` explicitly resolves to `en` and blocks `LANG`, and Windows queries `GetUserDefaultLocaleName`); live TUI hot-switching via uppercase **`L`** (synced with SSH takeover prompts); and invariant canonical English for all machine contracts (`--json` field names & `error_code`, `doctor`/`config import` `--json` diagnostics & `approval_challenge.reason`, all 7 MCP tools & responses, `audit.jsonl`, and OpenSSH `-O` / `mux` control output).

---

## ⚡ Quick Start

### 1. Install or Build from Source

```bash
# Install prebuilt binary (Linux / macOS)
curl -fsSL https://raw.githubusercontent.com/wentf9/xops-cli/master/install.sh | bash
```

```powershell
# Install on Windows (PowerShell 5.1+, no admin privileges required)
irm https://raw.githubusercontent.com/wentf9/xops-cli/master/install.ps1 | iex
```

```bash
# Build from source (requires Go 1.27+; CGO_ENABLED=0 works natively on Linux, macOS, and Windows)
git clone https://github.com/wentf9/xops-cli.git && cd xops-cli && make build
./bin/xops version
```

### 2. Import Existing Inventory & Run Diagnostics

```bash
# Preview and import ~/.ssh/config (local parse only, zero remote connections; --format csv also supported)
xops config import --format openssh --file ~/.ssh/config --plan
xops config import --format openssh --file ~/.ssh/config

# List managed nodes and run read-only inventory/vault diagnostics
xops hosts list
xops doctor
```

### 3. Connect, Run Batch Commands & Launch TUI Workbench

```bash
# Connect via alias or OpenSSH flags & jump chains
xops ssh web-01
xops ssh -J bastion -i ~/.ssh/id_ed25519 deploy@192.0.2.10

# Run a command across tagged nodes concurrently with live streaming (add --json for canonical JSON/v2)
xops exec --tags web --exclude-nodes web-maint-01 --concurrency 5 --stream -- uptime

# Launch the Bubble Tea v2 terminal workbench (Hosts, Metrics, Logs, Operations + Enter SSH takeover + uppercase L live EN/ZH toggle)
xops tui
```

### 4. Global Flags and Bilingual Localization

All CLI commands accept uniform global flags: `--lang <en|zh>`, `--json`, `--policy <profile>`, `-F`/`--ssh-config <file>`, `-h`/`--help`, and `-V`/`--version`.

```bash
# Switch display language to Simplified Chinese or English (valid before or after subcommand, before '--', last-wins, zero persistence, zero disk touch on --help/version)
xops --lang zh --help
xops version --lang zh
XOPS_LANG=zh xops hosts list

# Remote arguments stay untouched: ssh and exec stop scanning --lang at the target host or '--'
xops ssh web-01 mytool --lang=fr
```

- **Locale Detection Precedence**: `--lang > XOPS_LANG > LC_ALL > LC_MESSAGES > LANG > OS Locale > en`. `LC_ALL=C` / `POSIX` explicitly resolves to `en` and blocks lower-priority `LANG`; Windows queries `GetUserDefaultLocaleName` when all locale env vars are blank; invalid `--lang` values (such as `--lang fr`) fail closed with exit code `2` (`usage_error`).
- **TUI Live Language Switch**: Press uppercase **`L`** inside `xops tui` to switch all views between English and Simplified Chinese immediately (distinct from lowercase `l` log streaming, never triggered in `/` filter mode, and synced with `Enter` interactive SSH takeover prompts).
- **Canonical English Machine Contracts**: Regardless of active display language, `--json` field names and `error_code` (only human-facing `error`/`diagnostic` strings localize, while `doctor --json` / `config import --json` diagnostic fields and `approval_challenge.reason` stay canonical English), all 7 MCP tool schemas/descriptions/responses, `~/.xops/audit.jsonl`, and OpenSSH `-O` / `mux` control output remain canonical English.

---

## 🛠️ Feature Overview

### 1. Inventory Graph, Unified Import & 4-Layer OpenSSH Policy

```bash
# Create Host, Identity, and Node with optional optimistic CAS (--expected-revision)
xops hosts create-host --id h-web1 --address 192.0.2.10:22 --tag web
xops hosts create-identity --id id-deploy --user deploy --auth-kind private_key --key-path ~/.ssh/id_ed25519
xops hosts create-node --id web-01 --host h-web1 --identity id-deploy --tag web --jump bastion

# Resolve effective connection plan (4-layer OpenSSH resolution + digest) and validate jump DAG
xops hosts resolve web-01 --json
xops hosts validate-dag

# Import from CSV (strictly rejects plaintext password/passphrase/secret columns)
xops config import --format csv --file ./hosts.csv --plan
xops config import --format csv --file ./hosts.csv
```

- See: [Hosts, Inventory & Imports](docs/en/guide/hosts.md) · [Config Schema v2 Reference](docs/en/reference/config.md)

### 2. Zero-Plaintext Vault & Multi-Backend Routing

```bash
# Initialize and inspect the offline AEAD vault (Argon2id + XChaCha20-Poly1305)
xops creds init
xops creds status
xops creds doctor

# Enroll passwords, encrypted private key passphrases, or node privilege secrets interactively
xops creds enroll-password --id id-app --user app --store offline
xops creds enroll-key --id id-key --user deploy --key-path ~/.ssh/id_ed25519 --store offline
xops creds set-node-privilege --node web-01 --store offline

# Atomic secret rotation and reference-checked garbage collection
xops creds rotate offline/old-item --store offline
xops creds gc offline/orphan-item
```

- See: [Credential Routing & Vault](docs/en/guide/credentials.md) · [Offline Encrypted Vault](docs/en/guide/offline-store.md)

### 3. SSH, Tunnels, ControlMaster Multiplexing & SFTP/SCP

```bash
# Single-target privilege escalation (sudo / su / doas) and explicit launch profiles
xops exec --sudo --password-ref offline/web01-sudo web-01 -- systemctl status nginx
xops exec --dialect powershell --interpreter pwsh win-01 -- 'Get-Process | Select-Object -First 5'

# Local (-L), remote (-R), dynamic SOCKS5 (-D), StreamLocal, TUN (-w) tunnels, and ControlMaster mux
xops tunnel local web-01 127.0.0.1:18080:127.0.0.1:80
xops ssh -M -f -N -S /tmp/xops-mux-web01.sock -o ControlPersist=10m web-01 &
xops mux check -S /tmp/xops-mux-web01.sock web-01

# Parallel resumable SCP and single-shot / interactive SFTP
xops scp -r --resume --concurrency 4 ./dist web-01:/srv/app/
xops sftp patch --old "debug=true" --new "debug=false" web-01 /srv/app/app.ini
xops sftp web-01
```

- See: [SSH, Tunnels & Multiplexing](docs/en/guide/ssh.md) · [Command Execution](docs/en/guide/exec.md) · [SFTP & SCP Transfers](docs/en/guide/sftp.md) · [Terminal Workbench (TUI)](docs/en/guide/tui.md)

### 4. Declarative Playbook v2, Guardrails & Audit

Define a declarative Playbook v2 (`deploy.yaml`; strict JSON is also accepted):

```yaml
version: 2
id: deploy-web
name: "Deploy Nginx Web Fleet"
on_error: fail_fast # fail_fast | continue | abort
target:
  tags: [web]
  exclude_nodes: [web-maint-01]
vars:
  app_port: "8080"
steps:
  - id: ensure-nginx
    name: "Ensure nginx is installed"
    action:
      kind: ensure
      check:
        kind: shell
        command: "nginx -v"
      action:
        kind: shell
        command: "apt-get update && apt-get install -y nginx"
  - id: render-conf
    name: "Render and atomically upload config"
    action:
      kind: template
      source: "./nginx.conf.tmpl"
      dest: "/etc/nginx/nginx.conf"
      mode: "0644"
      overwrite: true
      atomic: true
  - id: reload-nginx
    name: "Reload nginx"
    action:
      kind: shell
      command: "systemctl reload nginx"
```

```bash
# Offline AST & schema validation (zero Engine init, zero remote connections)
xops playbook validate deploy.yaml

# Execute playbook (supports --var, --target, --concurrency, --scoped-root, --policy, --json)
xops playbook run deploy.yaml --var app_port=8081 --concurrency 2 --json

# Inspect audit records and run O(1) cross-process crash-lock reconciliation
xops audit tail --limit 20
xops audit reconcile --json
```

- See: [Playbooks v2, Guardrails & Audit](docs/en/guide/automation.md)

### 5. AI Integration: 7-Tool Sandboxed MCP Server & `xops-agent` Skill

#### Option A: Built-in MCP Server (Claude Desktop / Cursor / Codex / Antigravity)

```bash
# stdio transport (defaults to strict_agent profile with zero OperatorReadFS)
xops mcp serve --transfer-root ~/.xops/transfers

# Streamable HTTP transport (loopback-only 127.0.0.1:8080 by default, DNS Rebinding/CSRF guard + 10 GiB streaming)
xops mcp serve --transport http --listen 127.0.0.1:8080 --transfer-root ~/.xops/transfers
```

> **Security Boundary Note**: MCP mode physically sets `OperatorReadFS == nil` and exposes only `ScopedRootFS` sandbox directories. Consequently, nodes configured with host private-key file paths (`AuthPrivateKey`) cannot read arbitrary files from host disk in MCP mode—**load your keys into `ssh-agent`** (or use `kind: agent` / an unlocked Vault backend) when connecting via MCP.

- See: [MCP Server & HTTP Streaming](docs/en/guide/mcp-http.md) · [MCP Tunnel & Mux Tools](docs/en/guide/mcp-tunnels.md) · [MCP 7-Tool Protocol Reference](docs/en/reference/mcp.md)

#### Option B: `xops-agent` Agent Skill

Let Skill-capable AI assistants operate `xops` directly via CLI (`--json` & `--policy`):

```bash
npx skills add https://github.com/wentf9/xops-cli --skill xops-agent
# Or from a source checkout
make install-skill
```

- See: [Agent Skill & AI Overview](docs/en/guide/agent-skill.md) · [`skills/xops-agent/SKILL.md`](skills/xops-agent/SKILL.md)

---

## 📄 License

Released under the [MIT License](LICENSE).
