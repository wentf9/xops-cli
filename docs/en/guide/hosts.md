# Hosts and identities

XOps manages network addresses (**Host**), authentication profiles (**Identity**), and connection targets (**Node**) as separate records. Multiple user accounts (such as `deploy` and `audit`) can share the same server address without mixing up credentials.

## Quick start

```bash
# Add a single host (verifies SSH authentication and probes the remote shell by default)
xops host add --address 192.0.2.10 --user deploy --key ~/.ssh/id_ed25519 --alias web-01 --tags web

# Bulk-import hosts from CSV and assign the 'web' tag
xops host import hosts.csv --tag web

# List hosts or tags
xops host list
xops host tags

# Export a blank CSV import template (does not export your existing inventory)
xops host import --template
```

`inventory` remains a compatibility alias for `host`, and `host load` remains an alias for `host import`; prefer `host` and `host import` in new scripts.

Connecting to an existing host with an explicit different username automatically reuses the `Host` record while creating a separate `Identity` and `Node`:

```bash
xops ssh deploy@web-01
xops ssh audit@192.0.2.10
```

Run `xops identity --help` for identity management commands, or `xops tui` to manage nodes visually in the [terminal interface](./tui).

## Verification policies for add and import

### 1. Adding a single node (`host add`)

By default, `host add` verifies the SSH connection before saving:
- **Verification succeeds**: Saves the node, credentials, and recommended execution profile.
- **Verification fails**: Prints the failure reason and asks `Save this node even though verification failed? [y/N]`. Only an explicit `y` or `yes` saves the node; pressing Enter, `n`, or closing input leaves it unsaved.
- **Offline addition (`--skip-verify`)**: In automated scripts or when the host is not yet reachable, pass `--skip-verify` to skip the connection check (configuration and credential-store validation still run). With `--skip-verify`, you can also save a node skeleton before configuring credentials:

```bash
xops host add --address 192.0.2.10 --user deploy --skip-verify
```

### 2. Bulk import (`host import`)

By default, each CSV row is verified over SSH and only rows that pass authentication are saved; failed rows report the node ID, reason, and `not saved` (if a failed row targets an existing node, its existing configuration and credentials remain untouched).

```bash
# Default: save only nodes that pass SSH verification
xops host import hosts.csv

# Offline import: make no SSH connections and save all valid rows directly
xops host import hosts.csv --skip-verify

# Keep failed rows: verify each row, but save failed nodes as well and mark them in the output
xops host import hosts.csv --save-on-verify-failure
```

- `--skip-verify` and `--save-on-verify-failure` are mutually exclusive. Any verification failure returns a nonzero exit status (including with `--save-on-verify-failure`); cancellation never forces a save.
- **Concurrency and ordering**: Different nodes are verified in parallel. Repeated rows for the same node run serially in CSV order—aliases accumulate, later successful rows can update credentials, and output is always printed in CSV row order.
- **IPv6 compatibility**: Imports match unbracketed IPv6 node IDs from older versions (such as `root@2001:db8::1:22`) and update them in place; newly created IPv6 nodes use brackets (such as `root@[2001:db8::1]:22`).

## Node execution configuration (`execution`)

### 1. Automatic probing and `host probe` diagnostics

When a new node passes authentication during `host add`, `host import`, or **an interactive first `ssh`/`exec` connection with credential remembering enabled**, XOps reuses that authenticated connection to detect the remote launch dialect and available interpreters (bounded within ~9 seconds, no second handshake) and saves the recommended `execution` settings with the node.

```bash
# Verify authentication while skipping the shell probe (--probe=false also works)
xops host add --address 192.0.2.10 --user deploy --key ~/.ssh/id_ed25519 --no-probe
xops host import hosts.csv --no-probe

# Set explicit interpreter or dialect (explicit flags override probe recommendations; applies only to new nodes on import)
xops host add --address 192.0.2.10 --user deploy --key ~/.ssh/id_ed25519 --interpreter sh --launch-dialect posix

# Diagnose a saved node (prints table only by default; add --save to update the node's execution settings)
xops host probe web-01
xops host probe web-01 --save

# Probe all saved nodes (excluding OpenSSH virtual nodes); add --save to persist each successful recommendation
xops host probe --all
xops host probe --all --save
```

**Probing rules and boundaries**:
- **Non-blocking on failure**: During `host add`/`import` or first-connection enrollment, a failed or timed-out probe emits a warning while still saving the authenticated node with `execution` left unspecified (TUI node additions, session-only credentials, non-interactive batch runs, and existing nodes during import do not auto-probe).
- **Explicit flag isolation**: `--skip-verify` also skips probing. Explicit `--interpreter` / `--launch-dialect` flags always take precedence (the probe connection itself uses an isolated `server/unknown` view, so even if global config defaults to `bash/posix`, a new node can specify `--interpreter powershell` and let probing fill in the Windows launch dialect). Passing `--interpreter`, `--launch-dialect`, `--login-shell`, or `--no-login` to `xops ssh` / `xops exec` applies to that session only and skips enrollment probing for the target node.
- **Recommendation order**:
  - **Unix / Linux (`posix` or `fish` dialect)**: Prefers the remote default shell reported in `$SHELL` if supported and available on `PATH` (`bash`, `sh`, `zsh`, or `fish`; `ash`/`dash` map to `sh`), with `login: false`. A native `fish` outer dialect probe takes priority over a stale inherited `$SHELL`; if the default shell is unknown or unavailable, XOps falls back in order: `bash` → `sh` → `zsh` → `fish`.
  - **Windows**: A CMD outer shell recommends `server/cmd` when Windows PowerShell is also installed (or `cmd/cmd` when only CMD is present); a PowerShell outer shell recommends `powershell` (or `pwsh` if only PowerShell Core is installed).
- **Shell support highlights**:
  - **`fish` (`launch_dialect: fish`)**: Supports commands, Playbook scripts (including `#!/usr/bin/env fish`), `ensure` checks, and passwordless/password `sudo` and `su` (using `/bin/sh` for the authentication handshake; see [SSH and privilege escalation](./ssh)).
  - **`zsh` (`launch_dialect: posix`)**: Supports commands, working directories, login mode, `#!/usr/bin/env zsh` scripts, `ensure` checks, and `sudo`/`su` (note that zsh is not 100% Bash-compatible; see [zsh compatibility](https://zsh.sourceforge.io/Doc/Release/Invocation.html#Compatibility)).
- **On-demand runtime probing**: Playbook scripts without a shebang, `ensure` checks, and SFTP `exec` with a nonempty `cwd` probe unspecified execution settings on demand and cache the result in connection memory without writing to disk.

### 2. Manual `execution` configuration

You can also configure `execution` globally or per node in `~/.xops/xops_config.yaml`:

```yaml
schema_version: 2
# Optional global execution default (defaults to server when omitted)
execution:
  interpreter: server

nodes:
  # Scenario 1: Minimal container / Alpine Linux (no Bash; use sh or server passthrough)
  alpine-01:
    host_ref: h_alpine
    identity_ref: id_root
    execution:
      interpreter: sh
      launch_dialect: posix

  # Scenario 2: Traditional Linux host that needs login profile variables
  web-prod-01:
    host_ref: h_web
    identity_ref: id_deploy
    execution:
      interpreter: bash
      launch_dialect: posix
      login: true

  # Scenario 3: Windows Server running commands via PowerShell
  win-ad-01:
    host_ref: h_win
    identity_ref: id_admin
    execution:
      interpreter: powershell
      launch_dialect: powershell
```

**Configuration precedence**: CLI flags > Playbook step `execution` > Playbook `settings.execution` > Node configuration (`node.execution`) > Global configuration (`cfg.execution`) > System default (`server`).

## Removed credential arguments

Plaintext flags `--password` and `--key-pass` (and their short forms) have been removed from `host add|edit` and `identity add|edit` to keep secrets out of command arguments and shell history; the legacy `loadHost` command has also been removed (use `xops host import`).

Use interactive prompts, `xops identity credential set`, or pipe secrets through `--password-stdin` (login password) and `--passphrase-stdin` (private-key passphrase):

```bash
# Update an identity's login password from stdin
xops identity edit admin --password-stdin

# Update a node's private key and key passphrase from stdin
xops host edit web-01 --key ~/.ssh/id_ed25519 --passphrase-stdin
```

- `--password-stdin` and `--passphrase-stdin` are mutually exclusive; `--password-stdin` cannot be combined with `--key`; on `host add`, neither stdin flag can be combined with `--identity`.
- Empty input is rejected before changes are saved. Omitting these flags when editing preserves existing credentials (unless you change the authentication method or private-key path).
