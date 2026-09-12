# Credential migration

::: info Unreleased
Default offline storage, automatic upgrades, and v2 backend migration are implemented in the working branch. Final native validation on all six platforms remains pending. See [implementation progress](../development/credential-experience-plan).
:::

## Automatic legacy upgrades

Normal CLI entry points, including connections, TUI, MCP, and Playbook, automatically upgrade eligible Schema v1 configurations to reference-based Schema v2. Without an explicit backend, they use the default offline store. Explicit `none`, `remember_prompted: never`, or invocation-level `--remember never` disables automatic migration; explicit migration remains available. Success retains the old configuration and `secret.key`; failure retains current configuration and recovery material. Read-only commands do not trigger upgrades.

Startup automatic migration always disables credential interaction, including MCP, Playbook, batch commands, and TUI initialization. Stores requiring unlock or lacking a non-interactive guarantee produce a migration warning without terminal, pinentry, or system keyring prompts; current configuration and recovery material remain. Unlock the store and retry, or explicitly invoke migration.

You can also migrate legacy configuration explicitly to a configured writable destination:

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

An existing key-file is reused. Key generation is allowed only for a confirmed new vault. If an existing vault has lost its key or has an unfinished vault transaction, first follow the [offline recovery manual](https://github.com/wentf9/xops-cli/blob/master/docs/development/archive/offline-encrypted-credentials.md).

## Interruptions, conflicts, and retained material

After interruption, fix backend access and rerun the same command. Migration reuses recorded destination references and checks existing contents. Write failures and uncertain durability never delete source credentials. If configuration switched before verification completed, rerunning verifies it again and confirms configuration durability.

Concurrent configuration edits cause a conflict and preserve the current configuration. After confirming that the current configuration is the version to keep, explicitly start a new plan:

```bash
xops credential migrate --to system --restart
```

`--restart` applies only to actual v2 migrations and cannot accompany `--dry-run`. It archives the previous plan and allocates new destination references from the current configuration. It does not roll back configuration or delete previously written credentials. For ordinary interruptions without configuration changes, rerun the original command without `--restart`.

V2 migration keeps `<config>.backend-migration.json` and `<config>.v2.<source-config-digest>.bak` beside the configuration. Subsequent migrations or restarts archive old records as `.backend-migration.json.<record-digest>.bak`. These files contain configuration metadata and references, never credential values. V1 `.migration.json`, `.v1.bak`, and `.v1.key.bak` files remain separate and are not overwritten. Resume an unverified v1 migration with its original command first; deleting legacy material is not required.

Source stores and backups remain after connection validation; this command provides no automatic source cleanup. Restoring old configuration also requires its source stores and keys, so backing up reference configuration alone is insufficient. Before manually deleting historical credentials, check references in other configurations and backups, then use the backend's management tools. `finalize-migration` is not a general backend cleanup command.
