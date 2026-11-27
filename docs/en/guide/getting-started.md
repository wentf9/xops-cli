# Installation and Quick Start

XOps v2 is a single-binary, zero-remote-dependency SSH/SFTP operations and guardrailed AI automation platform for Linux, macOS, and Windows (amd64 / arm64), built with pure Go 1.27+ (`CGO_ENABLED=0`).

## 1. Install

### Option A: Installer Scripts

**Linux / macOS**:

```bash
curl -fsSL https://raw.githubusercontent.com/wentf9/xops-cli/master/install.sh | bash
```

**Windows (PowerShell 5.1+, no administrator privileges required)**:

```powershell
irm https://raw.githubusercontent.com/wentf9/xops-cli/master/install.ps1 | iex
```

Prebuilt release archives are also available on [GitHub Releases](https://github.com/wentf9/xops-cli/releases).

### Option B: Build from Source

Requires **Go 1.27+** (the repository uses a Go Multi-Module Workspace with the binary entry point at `./cmd/xops`):

```bash
git clone https://github.com/wentf9/xops-cli.git
cd xops-cli
make build
```

The compiled binary is placed at `bin/xops` (`bin/xops.exe` on Windows). Cross-compile with `make linux`, `make linux-arm64`, `make darwin`, `make windows`, `make windows-arm64`, or `make release`.

### Verify Installation

```bash
xops version
xops version --json
```

> `xops version` (or `-V`/`--version`) renders link-time build metadata only; it **never initializes the core Engine or creates state files**.

## 2. Local State Directory and Configuration

XOps v2 stores private state under `~/.xops/` by default. Override this location with the **`XOPS_HOME`** environment variable:

| Path | Purpose |
| --- | --- |
| `~/.xops/config.yaml` | YAML vNext (`version: 2`) configuration: vault stores, guardrail policy, global OpenSSH options, and Host/Identity/Node inventory graph |
| `~/.xops/vault/` | Default offline AEAD vault directory (`vault.meta.json` + `items/<sha256>.enc`) |
| `~/.xops/audit.jsonl` | Synchronous fail-closed JSONL audit log (configurable via `policy.guardrail.audit_log`) |
| `~/.xops/run/<process_id>.lock` | Process-lifetime active operation lock for O(1) startup crash reconciliation |
| `~/.xops/journals/` | Dual-generation CRC32 WAL directory for resumable transfers up to 10 GiB |

When `~/.xops/config.yaml` does not exist yet, read-only commands load an empty inventory graph with zero side effects. Mutating commands create private directories and files with `0700`/`0600` permissions (or a protected Owner-Only DACL on Windows).

> XOps v2 **accepts only `version: 2` YAML**, decodes with strict `KnownFields(true)`, and rejects unknown keys, trailing multi-document YAML, and any plaintext password fields. See [Config Schema v2 Reference](../reference/config).

## 3. Import Existing Inventory

Import external definitions through the unified `xops config import` command (local parsing only, zero remote connections, with `--plan` conflict/DAG preview and `--dry-run`):

```bash
# List registered FormatImporter implementations (built-in: openssh, csv)
xops config formats

# 1. Preview ~/.ssh/config import plan and diagnostics without writing
xops config import --format openssh --file ~/.ssh/config --plan

# 2. Apply the import once reviewed
xops config import --format openssh --file ~/.ssh/config

# Or import from CSV (strictly rejects plaintext password/passphrase/secret columns)
xops config import --format csv --file ./hosts.csv --plan
xops config import --format csv --file ./hosts.csv
```

Or define assets directly from the CLI:

```bash
xops hosts create-host --id h-web1 --address 192.0.2.10:22 --tag web
xops hosts create-identity --id id-deploy --user deploy --auth-kind private_key --key-path ~/.ssh/id_ed25519
xops hosts create-node --id web-01 --host h-web1 --identity id-deploy --tag web
```

## 4. Initialize the Vault (Optional for Password / Encrypted Key Workflows)

If you authenticate purely via `ssh-agent` or unencrypted keys, you can skip vault initialization. To store login passwords, encrypted key passphrases, or `sudo`/`su`/`doas` privilege secrets:

```bash
# Interactively initialize the offline AEAD vault (Argon2id + XChaCha20-Poly1305)
xops creds init

# Inspect vault status and run full read-only diagnostics
xops creds status
xops doctor
```

See [Credential Routing and Vault](./credentials) and [Offline Encrypted Vault](./offline-store) for full lifecycle details.

## 5. First Connections and Daily Workflows

```bash
# 1. Inspect the resolved connection plan (4-layer OpenSSH option folding)
xops hosts resolve web-01

# 2. Interactive SSH session (standard OpenSSH flags supported)
xops ssh web-01
xops ssh -J bastion -i ~/.ssh/id_ed25519 deploy@192.0.2.10

# 3. Concurrent batch command with live prefixed streaming
xops exec --tags web --concurrency 4 --stream -- uptime

# 4. Transfer files and open the interactive SFTP shell
xops scp ./app.tar.gz web-01:/tmp/app.tar.gz
xops sftp web-01

# 5. Launch the Bubble Tea v2 interactive terminal workbench
xops tui
```

## 6. Global Flags

Almost every command supports these uniform global flags (either before or after the subcommand):

- `--json`: Emit canonical deterministic JSON/v2 on `stdout` (`Deterministic(true)`), including structured error envelopes on failure.
- `--policy <profile>`: Override the active security policy profile: `direct_operator` (CLI default), `strict` / `strict_operator`, or `strict_agent` (MCP default).
- `-F <configfile>` (or `--ssh-config <path>`): Override the OpenSSH configuration file path (`none` disables OpenSSH config loading).
- `-h` / `--help`, `xops help <command>`: Print exact usage help for any command.

## Next Steps

- [Hosts, Inventory, and Imports](./hosts) — Learn the Host/Identity/Node graph model, Tarjan jump-DAG validation, and 4-layer OpenSSH precedence.
- [SSH, Tunnels, and Multiplexing](./ssh) — Configure ProxyJump, port/SOCKS5/TUN tunnels, and ControlMaster daemons.
- [Playbooks v2, Guardrails, and Audit](./automation) — Run declarative Playbook v2 deployments with audit logging.
- [MCP Server and HTTP Streaming](./mcp-http) or [Agent Skill Overview](./agent-skill) — Integrate XOps with AI assistants.
