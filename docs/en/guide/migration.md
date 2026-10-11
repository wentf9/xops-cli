# Credential migration

Run `xops credential migrate --help` to see the migration options available in your installed version.

## Compatibility ended: migrate legacy configuration explicitly

v0.12.0 and v0.13.0 were the two Schema v1 compatibility releases; that period has ended. Ordinary CLI, TUI, MCP, Playbook, and read-only configuration loading now accept only Schema v2. Legacy files without `schema_version` are also rejected as v1, with explicit migration guidance. Help and version commands remain configuration-independent; `credential migrate` and `credential finalize-migration` remain available.

Normal startup no longer automatically migrates, decrypts, or encrypts legacy credentials and never reads or creates the old `secret.key`. Rejection preserves the source configuration and key. Do not merely change `schema_version` to 2: v2 rejects plaintext and `ENC:` credential fields. The migrator must store secrets in a credential backend and create references.

Back up the old configuration and existing `secret.key`, then migrate explicitly to a configured writable destination. When backend configuration is absent, the migrator supplies the default offline `file` configuration; for an existing custom setup, ensure the destination is declared. Restore the original key from backup if encrypted legacy credentials have lost it; the migrator never generates a replacement legacy key:

```bash
xops credential migrate --dry-run --to file
xops credential migrate --to file
```

After validating SSH, SFTP, exec, escalation, and automation, explicitly remove the v1 configuration backup and legacy keys:

```bash
xops credential finalize-migration
```

This command only cleans v1 legacy material. It does not delete credentials from any backend or remove v2 backend migration backups.

## Move from offline storage to another backend

Add a destination to `credential.stores` in your existing configuration, preserving existing fields, stores, and references. For example, after adding `system`, the relevant section could be:

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

`system` requires an accessible, unlocked system credential store. Linux also requires `secret-tool`, a user D-Bus session, and Secret Service; installing the command alone does not make the service available. You can also target `pass` or `helper`; see [credential storage](./credentials) and the [configuration example](https://github.com/wentf9/xops-cli/blob/master/xops_config.example.yaml) for configuration and dependencies.

```bash
xops credential doctor
xops credential migrate --dry-run --to system
xops credential migrate --to system
```

Migration covers all login password, private-key passphrase, and privilege password references in the current configuration that are outside the destination. Shared references are copied once; references already in the destination remain unchanged. After writing and verifying reads, migration checks for configuration conflicts and switches all references and `default_store` together. It preserves `remember_prompted`. Changing `default_store` alone does not move existing credentials. Historical items without current configuration references are not migrated.

`--dry-run` writes no files, credentials, or keys. It checks the plan and read paths, not write authorization. An absent offline destination can pass planning; actual initialization occurs during migration writes. If a destination cannot preserve source credential expiry metadata, read-back verification rejects the switch.

## Return to offline storage

Keep the original `file` configuration, vault, and key, then run:

```bash
xops credential migrate --dry-run --to file
xops credential migrate --to file
```

An existing key-file is reused. Key generation is allowed only for a confirmed new vault. If an existing vault has lost its key or has an unfinished vault transaction, first follow the [offline recovery guide](./offline-store#backup-and-recovery).

## Interruptions, conflicts, and retained material

After interruption, fix backend access and rerun the same command. Migration reuses recorded destination references and checks existing contents. Write failures and uncertain durability never delete source credentials. If configuration switched before verification completed, rerunning verifies it again and confirms configuration durability.

Concurrent configuration edits cause a conflict and preserve the current configuration. After confirming that the current configuration is the version to keep, explicitly start a new plan:

```bash
xops credential migrate --to system --restart
```

`--restart` applies only to actual v2 migrations and cannot accompany `--dry-run`. It archives the previous plan and allocates new destination references from the current configuration. It does not roll back configuration or delete previously written credentials. For ordinary interruptions without configuration changes, rerun the original command without `--restart`.

V2 migration keeps `<config>.backend-migration.json` and `<config>.v2.<source-config-digest>.bak` beside the configuration. Subsequent migrations or restarts archive old records as `.backend-migration.json.<record-digest>.bak`. These files contain configuration metadata and references, never credential values. V1 `.migration.json`, `.v1.bak`, and `.v1.key.bak` files remain separate and are not overwritten. Resume an unverified v1 migration with its original command first; deleting legacy material is not required.

Source stores and backups remain after connection validation; this command provides no automatic source cleanup. Restoring old configuration also requires its source stores and keys, so backing up reference configuration alone is insufficient. Before manually deleting historical credentials, check references in other configurations and backups, then use the backend's management tools. `finalize-migration` is not a general backend cleanup command.
