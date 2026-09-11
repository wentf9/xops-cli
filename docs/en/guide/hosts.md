# Hosts and identities

XOps separates network addresses (Host), authentication identities (Identity), and connection nodes (Node). Multiple user identities can share one address.

```bash
xops host add --address 192.0.2.10 --user deploy --key ~/.ssh/id_ed25519 --alias web-01 --tags web
xops host list
xops host tags
xops host import hosts.csv --tag web
```

See `xops host import --help` and repository examples for CSV format and options. `inventory` remains a compatibility alias for `host`; prefer `host` in new scripts.

An explicit different user reuses the Host with a separate Identity/Node, without inheriting another user's credentials:

```bash
xops ssh deploy@web-01
xops ssh audit@192.0.2.10
```

Use `xops identity --help` for identity operations, or `xops tui` for the terminal management interface. Keep passwords out of shared command histories and documentation examples.
