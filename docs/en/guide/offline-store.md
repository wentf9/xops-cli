# Offline credential storage

The offline store encrypts credentials locally on Linux, Windows, and macOS on amd64/arm64. New installations use a store named `file`, unlocked by a separate key file. See [credential storage](./credentials) for defaults and saving policies.

## Initialize and inspect

The default key-file store initializes automatically on first save. You can also initialize a configured store that has not yet been created:

```bash
xops credential store probe file
xops credential store init file
xops credential store inspect file
xops credential store inspect file --verify
```

`probe` uses temporary data to check file locking, atomic replacement, and synchronization. It does not read or write credentials and cannot guarantee data safety during power loss. Use reliable storage and keep backups.

`init` requires the store's parent directory to exist. A missing configured key file is created with 32 random bytes; an existing valid file is reused. Keep the key file outside the store directory. On Unix, it must belong to the current user or root and have permissions `0400` or `0600`; generated files use `0600`. Do not substitute links for key files.

`inspect` displays metadata by default. `--verify` authenticates metadata with the key or master password; it does not verify every credential. Reads, inspection, and unlocking neither initialize new stores nor create replacement keys for existing stores.

## Use a master password

To unlock manually when running XOps, add a password-based store under `credential.stores`:

```yaml
offline:
  type: encrypted-file
  path: credentials-offline
  unlock: prompt
  unlock_idle_ttl: 5m
```

Then initialize it:

```bash
xops credential store init offline
```

Enter a master password of at least twelve characters at the hidden prompt, then enter it again to confirm. Do not place the password in command arguments or environment variables. Initialization does not change the default store. Follow the [migration guide](./migration) to move existing credentials into it.

In the TUI, `Ctrl+U` unlocks the default offline store and `Ctrl+L` locks stores opened by the current process. Unlock state is not shared across processes. MCP, Playbooks, and batch execution do not prompt for a master password. Unattended jobs need a store accessible without prompting, such as key-file storage.

## Rotate keys and clean old revisions

```bash
# Change the unlock key; the target parent directory must exist
xops credential store rewrap file --unlock key-file --key-file /secure/xops-new.key

# Re-encrypt credentials with a new data encryption key
xops credential store reencrypt file

# Preview old revisions eligible for cleanup, then apply
xops credential store prune file
xops credential store prune file --apply
```

`rewrap` changes unlock material; `reencrypt` encrypts the stored data again. After changing the unlock method or key path, update configuration as instructed by the command. Retain the original key and backups until the new material is confirmed usable.

Maintenance commands default to a 30-minute timeout, adjustable with `--maintenance-timeout 45m`. Resume interrupted maintenance with `xops credential store resume file`. If unlock material changed before configuration was updated, supply the target material through `--unlock` and `--key-file`. Do not manually delete files left by an interrupted operation.

## Backup and recovery

Stop writes to the source store before backing up its configuration, entire directory, and unlock material. Keep key backups separate from store backups. To restore, copy the backup into a writable working directory and retain the original archive.

This example restores a store named `file`. In the current configuration, `file` must point to a new, uninitialized target directory with its target unlock material configured. Source and target directories must differ and cannot contain each other:

```bash
xops credential store restore file --from /backup/work/credentials \
  --source-unlock key-file --source-key-file /backup/work/credentials.key \
  --backup-config /backup/work/xops_config.yaml
```

`--backup-config` must be a trusted Schema v2 configuration backup used to verify credential references. Restore does not automatically import or replace your current host configuration. For a password-based source, use `--source-unlock prompt` and omit `--source-key-file`.

If recovery between stores is interrupted, specify the source directory and unlock material again:

```bash
xops credential store resume file --from /backup/work/credentials \
  --source-unlock key-file --source-key-file /backup/work/credentials.key
```

A new key cannot decrypt an existing store whose original key is lost. Preserve the original store. If unlock material cannot be recovered, credentials must be entered again.

See the [store command reference](../reference/commands/xops-credential-store) for all options and cloning operations.
