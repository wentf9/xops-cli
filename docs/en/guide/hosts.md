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

## Removed credential arguments

The plaintext arguments `--password` and `--key-pass`, including their short forms, have been removed from `host add|edit` and `identity add|edit`. Use `--password-stdin` for login passwords or `--passphrase-stdin` for private-key passphrases. These two options are mutually exclusive; `--password-stdin` cannot be combined with `--key`. With `host add`, neither stdin option can be combined with `--identity`.

For example, `xops identity edit admin --password-stdin` reads the replacement password from standard input; `xops host edit web --key ~/.ssh/id_ed25519 --passphrase-stdin` reads the key passphrase. Supply input through a trusted pipe or redirected file, keeping secret values out of command arguments and shell history. Empty input is rejected before inventory changes are saved. Omitting these flags on edits preserves the existing credentials unless the authentication method or key is changed.

Interactive password prompts and `xops identity credential set` remain available. The legacy `loadHost` command has been removed; use `xops host import`.
