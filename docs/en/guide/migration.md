# Credential migration

Explicit migration converts legacy Schema v1 configurations into reference-based Schema v2. Preserve the old configuration, `secret.key`, and usable backups, and configure the destination backend first.

```bash
xops credential doctor
xops credential migrate --dry-run --to system
```

Dry-run writes no credentials or migration files. It prepares a plan and checks the read path, but does not prove write authorization.

After confirming the destination, run:

```bash
xops credential migrate --to system
```

Migration creates backups and verifies writes by reading them back. After interruption, resume according to migration state rather than manually deleting backups or state files. Verify SSH, SFTP, batch execution, and other real entry points before explicitly finalizing:

```bash
xops credential finalize-migration
```

`--to` can also name another configured destination. See the [migration design and operational record (Chinese)](https://github.com/wentf9/xops-cli/blob/master/docs/development/archive/credential-migration.md) for detailed recovery behavior and constraints.
