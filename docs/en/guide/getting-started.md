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

- `--lang <en|zh>`: Explicitly override the display language for this invocation (`en` English or `zh` Simplified Chinese; valid before or after the subcommand, before `--`, last-wins; see §7 below).
- `--json`: Emit canonical deterministic JSON/v2 on `stdout` (`Deterministic(true)`), including structured error envelopes on failure.
- `--policy <profile>`: Override the active security policy profile: `direct_operator` (CLI default), `strict` / `strict_operator`, or `strict_agent` (MCP default).
- `-F <configfile>` (or `--ssh-config <path>`): Override the OpenSSH configuration file path (`none` disables OpenSSH config loading).
- `-h` / `--help`, `xops help <command>`: Print exact usage help for any command (like `version`, zero Engine initialization and zero disk touch).

## 7. Language Settings and Localization (`--lang` / `XOPS_LANG`)

XOps v2 embeds pure in-memory **English (`en`)** and **Simplified Chinese (`zh`)** catalogs (`embed.FS`). Language selection is per-process and **never persisted to `~/.xops/config.yaml`** (all `zh*` tags such as `zh_CN`, `zh-Hans`, and `zh-TW` normalize to Simplified Chinese `zh`).

### Locale Detection Precedence

Startup performs zero subprocess calls (no `os/exec`) and zero disk I/O, resolving the active display language from highest to lowest priority:

```text
1. CLI flag --lang <en|zh> (or --lang=<en|zh>)
2. Environment variable XOPS_LANG
3. Environment variable LC_ALL
4. Environment variable LC_MESSAGES
5. Environment variable LANG
6. Platform OS locale (Windows queries kernel32 GetUserDefaultLocaleName; Unix/macOS return empty and rely solely on POSIX env vars)
7. Default fallback: en (English)
```

- **POSIX Override Semantics**: `LC_ALL=C` or `LC_ALL=POSIX` (including codeset/modifier suffixes such as `C.UTF-8`) explicitly resolves to `en` and **blocks** lower-priority `LANG` (for example, `LC_ALL=C LANG=zh_CN.UTF-8` resolves to `en`). The GNU `LANGUAGE` colon-separated list is intentionally ignored.
- **Fail-Closed CLI Flag vs. Safe Env Fallback**: An invalid or missing `--lang` value (such as `--lang fr` or `--lang C`) fails closed immediately with exit code `2` (`usage_error`), zero Engine init, and zero disk touch, rendering the error in the detected environment locale. By contrast, an unrecognized non-empty environment/OS locale tag safely falls back to `en` and stops fallthrough.
- **Command-Aware Scanning & Remote Passthrough**: `--lang` is accepted before or after a subcommand (including multi-level commands like `xops hosts --lang zh list` or `xops hosts list --lang zh`), uses **last-wins** semantics, and stops at `--`. For `xops ssh` and `xops exec`, scanning stops at the first positional argument (target host) or `--`, so remote command arguments such as `xops ssh web-01 mytool --lang=fr` are passed through untouched.

### Examples

```bash
# View localized help or version metadata (pure in-memory, zero Engine init or ~/.xops/ creation)
xops --lang zh --help
xops help ssh --lang zh
xops version --lang zh

# Enable Simplified Chinese for the current shell session
export XOPS_LANG=zh
xops hosts list
xops doctor

# Override back to English per command, or enforce POSIX LC_ALL=C
xops --lang en doctor
LC_ALL=C LANG=zh_CN.UTF-8 xops version

# Remote --lang flags pass through untouched without triggering XOps usage errors
xops ssh web-01 mytool --lang=fr
xops exec --lang zh web-01 -- echo --lang=fr
```

### Canonical English Machine Contracts

To guarantee stable parsing for scripts, CI pipelines, and AI agents, the following machine-facing outputs remain **invariant canonical English** regardless of `--lang` or `XOPS_LANG`:

- **CLI `--json` Output**: All JSON keys, enum values, `exit_code`, `do_not_retry`, and `error_code` constants remain canonical English. Only human-facing `error` and `diagnostic` strings localize to the active language, while `doctor --json` (diagnostic findings & `vault_note`), `config import --json` (import report & warnings), and `approval_challenge.reason` always stay canonical English.
- **MCP Server**: All 7 MCP tool names, descriptions, JSON Schemas, JSON-RPC error payloads, approval challenge envelopes, and `OutcomeUnknown` warnings stay canonical English.
- **Audit Log & OpenSSH Control Receipts**: `~/.xops/audit.jsonl` and OpenSSH `-O` / `xops mux` control text responses stay canonical English.
- **TUI Live Switching**: Inside `xops tui`, press uppercase **`L`** at any time to toggle between English and Simplified Chinese live (see [Terminal Workbench (TUI)](./tui)).

## Next Steps

- [Hosts, Inventory, and Imports](./hosts) — Learn the Host/Identity/Node graph model, Tarjan jump-DAG validation, and 4-layer OpenSSH precedence.
- [SSH, Tunnels, and Multiplexing](./ssh) — Configure ProxyJump, port/SOCKS5/TUN tunnels, and ControlMaster daemons.
- [Playbooks v2, Guardrails, and Audit](./automation) — Run declarative Playbook v2 deployments with audit logging.
- [MCP Server and HTTP Streaming](./mcp-http) or [Agent Skill Overview](./agent-skill) — Integrate XOps with AI assistants.
