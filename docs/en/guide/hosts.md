# Hosts and identities

XOps separates network addresses (Host), authentication identities (Identity), and connection nodes (Node). Multiple user identities can share one address.

```bash
xops host add --address 192.0.2.10 --user deploy --key ~/.ssh/id_ed25519 --alias web-01 --tags web
xops host list
xops host tags
xops host import hosts.csv --tag web
```

See `xops host import --help` and repository examples for CSV format and options. `inventory` remains a compatibility alias for `host`; prefer `host` in new scripts.

## Verification policy for imports

By default, each CSV row is used to verify SSH authentication before its node and credentials are saved. A failed row reports the node ID, the failure, and that it was not saved. If the row targets an existing node, failed verification leaves its configuration and credentials unchanged.

Repeated rows for the same node are verified and saved in CSV order. Aliases accumulate, and a later successfully saved row can update the credentials. Different nodes are still processed concurrently. This ordering applies to all three verification modes, and results are always printed in CSV order.

IPv6 imports remain compatible with node IDs created by older versions without brackets, such as `root@2001:db8::1:22`. A match preserves and updates the existing node ID. Newly created IPv6 node IDs use brackets, such as `root@[2001:db8::1]:22`.

```bash
# Default: save only nodes that pass verification
xops host import hosts.csv
# Make no SSH connections and directly save all valid rows
xops host import hosts.csv --skip-verify
# Verify each row, but save it even if verification fails
xops host import hosts.csv --save-on-verify-failure
```

The two options are mutually exclusive. They also apply to `host load` and `inventory import`. A verification failure returns a nonzero exit status, including when `--save-on-verify-failure` is used. Cancellation never forces a save. Skipping verification only skips the connection check; configuration and credential-store validation still run.

## Adding one node

`host add` verifies the connection by default. If verification succeeds, it saves the node. If verification fails, it reports the reason and asks `Save this node even though verification failed? [y/N]`. Only an explicit `y` or `yes` saves the node; Enter, rejection, or an unreadable response leaves it unsaved. For unattended offline addition, specify:

```bash
xops host add --address 192.0.2.10 --user deploy --skip-verify
```

With `--skip-verify`, a node can be saved without a password, private key, or identity template and configured with credentials later. The TUI provides the same policy for adding a node; see the [terminal management interface](./tui).

An explicit different user reuses the Host with a separate Identity/Node, without inheriting another user's credentials:

```bash
xops ssh deploy@web-01
xops ssh audit@192.0.2.10
```

Use `xops identity --help` for identity operations, or `xops tui` for the [terminal management interface](./tui). Keep passwords out of shared command histories and documentation examples.

## Node execution configuration (`execution`)

### Automatic probing and diagnostics

For new nodes, `host add` and `host import` (including the `host load` alias) reuse the authenticated
verification connection to detect the launch dialect and available interpreters. The recommendation is
saved with the node. Probing takes at most approximately nine seconds; a failed probe reports a warning
and leaves execution unspecified without preventing an authenticated node from being saved. Existing
imported nodes are not automatically reprobed and retain their execution settings.

```bash
# Verify authentication while skipping the probe; --probe=false also works
xops host add --address 192.0.2.10 --user deploy --key ~/.ssh/id_ed25519 --no-probe
xops host import hosts.csv --no-probe
# Explicit fields take priority; import applies these flags only to new nodes
xops host add --address 192.0.2.10 --user deploy --key ~/.ssh/id_ed25519 --interpreter sh --launch-dialect posix
# Diagnose a saved node or alias without saving
xops host probe web-01
# Replace only this node's execution settings
xops host probe web-01 --save
# Probe all saved nodes; add --save to save each successful recommendation
xops host probe --all
xops host probe --all --save
```

`--all` cannot be combined with a node or alias. It probes every saved node in node ID order, excluding OpenSSH virtual nodes. Individual failures do not stop remaining probes; the command returns aggregated errors and a nonzero exit status at the end. Cancellation stops subsequent probes. An empty inventory only prints a message. `--all --save` saves successful recommendations individually; failed or concurrently edited nodes are preserved, and successful saves are not rolled back.

`--skip-verify` also skips probing. `--probe` and `--no-probe` are mutually exclusive. Explicit execution
fields are preserved; incompatible recommendations produce a warning and only the explicit fields are
saved. Failed probes never persist partial recommendations.

Probe connections use independent `server/unknown` settings for the target and jumps. Their configured
command execution settings do not affect connection setup. For example, global `bash/posix` defaults
do not prevent a new node from specifying only `--interpreter powershell` and having probing fill in
the Windows launch dialect. Global settings remain unchanged; credentials, host-key checks and jump
routes still apply.

`host probe` authenticates non-interactively with existing credentials and displays the remote OS,
shell path, SSH banner, launch dialect, available interpreters and recommendation. Unknown metadata is
shown as `-`. Only `--save` writes configuration; probe failures and concurrent node edits prevent saving
and return a nonzero exit status. Linux normally recommends bash, then sh, with login disabled. Windows
CMD with Windows PowerShell available still recommends `server/cmd`. Probing does not translate commands.

Direct SSH and interactive exec first connections also probe after authentication and before confirming
a new node when credential remembering is enabled and execution is unspecified. The recommendation is
saved atomically with enrollment. Session-only credentials, non-interactive exec batch tasks, saved nodes and
explicit execution settings do not trigger this path. Explicit CLI `--interpreter`, `--launch-dialect`,
`--login-shell` or `--no-login` (including an explicit false) skip enrollment probing for the target.
These flags apply to the current session; credential remembering and probing policy for other nodes
remain active. Probe failures warn while preserving normal
authenticated enrollment. An already disconnected transport fails connection acquisition without pooling
it or dispatching user work. TUI additions retain authentication-only verification.

Playbook scripts without a shebang, ensure checks and SFTP exec with a nonempty cwd can probe missing
execution settings on demand. These runtime results remain in the connection cache without disk writes;
explicit interpreter choices, including `server`, are preserved.

### Manual configuration

In addition to network addresses and authentication identities, you can configure execution parameters (such as interpreter, launch dialect, and login mode) per node in `~/.xops/xops_config.yaml`. This enables `xops exec`, `xops ssh`, Playbooks, and MCP to automatically pick the most suitable execution model:

```yaml
schema_version: 2
# Optional global execution defaults
execution:
  interpreter: server

nodes:
  # Scenario 1: Minimal container / Alpine Linux (no Bash, native execution)
  alpine-01:
    host_ref: h_alpine
    identity_ref: id_root
    execution:
      interpreter: server

  # Scenario 2: Traditional Linux host (loads personal login environment)
  web-prod-01:
    host_ref: h_web
    identity_ref: id_deploy
    execution:
      interpreter: bash
      launch_dialect: posix
      login: true

  # Scenario 3: Windows Server (executes commands via PowerShell)
  win-ad-01:
    host_ref: h_win
    identity_ref: id_admin
    execution:
      interpreter: powershell
      launch_dialect: powershell
```

- **Configuration precedence**: CLI flag > Playbook step override > Playbook settings > Node configuration (`node.execution`) > Global configuration (`cfg.execution`) > System default (`server`).
- **No manual flag required**: Once configured for a node, operations such as remote commands or piped script execution (`cat script.sh | xops ssh web-prod-01`) automatically use the matching interpreter and environment without having to specify `--interpreter` each time.


## Removed credential arguments

The plaintext arguments `--password` and `--key-pass`, including their short forms, have been removed from `host add|edit` and `identity add|edit`. Use `--password-stdin` for login passwords or `--passphrase-stdin` for private-key passphrases. These two options are mutually exclusive; `--password-stdin` cannot be combined with `--key`. With `host add`, neither stdin option can be combined with `--identity`.

For example, `xops identity edit admin --password-stdin` reads the replacement password from standard input; `xops host edit web --key ~/.ssh/id_ed25519 --passphrase-stdin` reads the key passphrase. Supply input through a trusted pipe or redirected file, keeping secret values out of command arguments and shell history. Empty input is rejected before inventory changes are saved. Omitting these flags on edits preserves the existing credentials unless the authentication method or key is changed.

Interactive password prompts and `xops identity credential set` remain available. The legacy `loadHost` command has been removed; use `xops host import`.
