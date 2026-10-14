# Credential migration

Use `xops credential migrate` to upgrade legacy Schema v1 configurations to Schema v2, or to move credentials between Schema v2 storage backends. Run `xops credential migrate --help` to see all options in your installed build.

## Scenario 1: Upgrading a legacy (Schema v1) configuration

The automatic Schema v1 compatibility window (v0.12.0 and v0.13.0) has ended. CLI, TUI, MCP, and Playbook commands now accept only Schema v2 (files missing `schema_version` are also rejected as v1 with instructions to run `credential migrate`):
- **Do not edit `schema_version` by hand**: Simply changing `schema_version` to `2` in YAML will fail because Schema v2 rejects plaintext and `ENC:` fields—the migrator must move secrets into a credential store and replace them with references.
- **Back up first**: Back up your old configuration file and `secret.key` before migrating (if your v1 config has `ENC:` fields and `secret.key` is missing, restore `secret.key` from backup first; the migrator never generates a replacement legacy key).

```bash
# 1. Preview the migration plan (read-only; writes no files, credentials, or keys)
xops credential migrate --dry-run --to file

# 2. Run the migration (automatically adds the default offline 'file' store if no stores are configured yet)
xops credential migrate --to file

# 3. After verifying SSH, SFTP, exec, sudo/su, and Playbooks, clean up v1 backups and secret.key
xops credential finalize-migration
```

`finalize-migration` **only removes v1 legacy configuration backups and `secret.key`**; it never deletes credentials from any storage backend or removes v2 backend-migration backups.

## Scenario 2: Moving between Schema v2 backends

### 1. From the offline store to the system keyring or another backend

Changing `default_store` in YAML alone does not move existing credentials. To move credentials from the default `file` vault to `system`, `pass`, or `helper`:

**Step 1**: Add the destination backend under `credential.stores` in `~/.xops/xops_config.yaml` while keeping the existing `file` store entry and all current references intact:

```yaml
credential:
  default_store: file
  remember_prompted: always
  stores:
    file:
      type: encrypted-file
      path: credentials
      unlock: key-file
      key_file: credentials.key
    system:
      type: system
```

> The `system` backend requires an accessible, unlocked OS keyring (on Linux, `secret-tool`, an active user D-Bus session, and Secret Service are required). See [credential storage](./credentials) and [`xops_config.example.yaml`](https://github.com/wentf9/xops-cli/blob/master/xops_config.example.yaml) for `pass` and `helper` settings.

**Step 2**: Check store health and run the migration:

```bash
xops credential doctor
xops credential migrate --dry-run --to system
xops credential migrate --to system
```

- **Scope and atomic switch**: Migration copies all login password, private-key passphrase, and privilege password references used in the active configuration that are not yet in the destination (shared references are copied once; items already in the destination and unreferenced historical items are untouched). After writing and verifying read-backs, XOps checks for concurrent config edits and switches all references and `default_store` together (preserving `remember_prompted`).
- **What `--dry-run` checks**: Validates the migration plan and source reads without writing files, credentials, or keys and without testing destination write access. If a destination backend cannot preserve source credential expiry metadata, read-back verification aborts the switch.

### 2. Moving back to the offline store

Keep your `file` store configuration and key settings in place, then run:

```bash
xops credential migrate --dry-run --to file
xops credential migrate --to file
```

An existing `credentials.key` is reused automatically; a new key is generated only for a confirmed brand-new vault. If an existing vault has lost its key or has an unfinished transaction, follow the [offline recovery guide](./offline-store#backup-and-recovery) first.

## Resuming after interruptions, conflicts, and retained backups

- **Rerun the same command after an interruption**: If a migration is interrupted by a locked backend or timeout, fix backend access and **rerun the exact same command**. The migrator reuses recorded destination references and verifies already-written items; source credentials are never deleted on write errors or uncertain durability.
- **Use `--restart` after a concurrent config edit**: If another terminal modified the configuration during migration, confirm that the current configuration is the one you want to keep and start a fresh plan with `--restart` (applies only to real v2 migrations, cannot be combined with `--dry-run`, and never rolls back config or deletes previously written credentials):

```bash
xops credential migrate --to system --restart
```

- **Migration records and backups**:
  - V2 backend migrations save `<config>.backend-migration.json` and `<config>.v2.<source-config-digest>.bak` beside your configuration file (archived as `.backend-migration.json.<record-digest>.bak` on subsequent migrations or restarts). These files contain only metadata and references—never secret values.
  - V1 `.migration.json`, `.v1.bak`, and `.v1.key.bak` files are kept separately and never overwritten by v2 migrations.
  - **Source stores are preserved**: V2 migrations keep source store items and backups intact after switching; before manually deleting historical items from an old backend, verify that no other configurations or backups still reference them.
