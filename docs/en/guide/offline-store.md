# Offline credential storage

The built-in offline credential store (`encrypted-file`) encrypts credentials locally on Linux, Windows, and macOS (amd64/arm64). New installations default to a store named `file`, unlocked with a separate key file (`credentials.key`). See [credential storage](./credentials) for default saving policies.

## Initialize and inspect

The default `key-file` store initializes automatically the first time a credential is saved. You can also probe and initialize a configured store manually:

```bash
# Check whether the target directory supports file locking, atomic rename, and sync (reads/writes no credentials)
xops credential store probe file

# Initialize the offline store manually (parent directory must already exist)
xops credential store init file

# View store metadata, or authenticate metadata integrity with the key/master password
xops credential store inspect file
xops credential store inspect file --verify
```

- **About `probe`**: Tests filesystem capabilities using temporary files without touching credentials. Passing a probe does not guarantee immunity to physical power loss—always use reliable storage and keep backups.
- **Key-file rules**: `init` creates a 32-byte random key file (`0600` permissions) if the configured key file does not exist, or reuses an existing valid key file. The key file must live outside the vault directory and must not be a symlink; on Unix it must be owned by the current user or `root` with mode `0400` or `0600`.
- **Read safety**: `inspect` (with or without `--verify`), ordinary reads, and unlock operations never initialize a new store or generate a replacement key for an existing store.

## Using a master password (`unlock: prompt`)

To require a manual master password instead of a key file, add a store with `unlock: prompt` under `credential.stores`:

```yaml
credential:
  default_store: offline
  stores:
    offline:
      type: encrypted-file
      path: credentials-offline
      unlock: prompt
      unlock_idle_ttl: 5m
```

Initialize the store and enter a master password of at least 12 characters twice at the hidden prompt (never pass the master password in command flags or environment variables):

```bash
xops credential store init offline
```

- Running `init` alone does not move existing credentials; follow the [migration guide](./migration) to migrate credentials from `file` into `offline`.
- **Unlock scope**: In the TUI, press `Ctrl+U` to unlock the default offline store and `Ctrl+L` to lock stores opened by the current process (unlock state is per-process and never shared across processes). MCP, Playbooks, and non-interactive batch runs never prompt for a master password—use `key-file` mode for unattended tasks.

## Key rotation and pruning old revisions

```bash
# Replace the unlock key or mode (the new key's parent directory must exist)
xops credential store rewrap file --unlock key-file --key-file /secure/xops-new.key

# Re-encrypt all stored credentials with a fresh data encryption key
xops credential store reencrypt file

# Preview historical revisions eligible for cleanup, then apply
xops credential store prune file
xops credential store prune file --apply
```

- **`rewrap` vs. `reencrypt`**: `rewrap` rotates the outer unlock material; `reencrypt` rotates the internal data encryption key and re-encrypts all records. After changing the unlock mode or key path, update `xops_config.yaml` as instructed by the command output, and keep your old key and backups until the new material is verified.
- **Timeouts and resuming**: Maintenance commands default to a 30-minute timeout (configurable via `--maintenance-timeout 45m`). If maintenance is interrupted, do not delete temporary files manually—run `xops credential store resume file` (passing `--unlock` and `--key-file` if the unlock material changed before you updated the config file).

## Backup and recovery

- **What to back up**: Stop writes to the source store, then back up **your configuration file**, **the entire vault directory**, and **the unlock key file**, keeping key backups separate from vault backups.
- **Restoring from backup**: Copy the backup into a writable working directory first while keeping your original backup intact. In your current configuration, point the target store (e.g. `file`) to a new, uninitialized directory with its target unlock settings configured (source and target directories must be distinct and cannot contain each other):

```bash
xops credential store restore file --from /backup/work/credentials \
  --source-unlock key-file --source-key-file /backup/work/credentials.key \
  --backup-config /backup/work/xops_config.yaml
```

- `--backup-config` must be a trusted Schema v2 configuration backup used to validate the credential references being restored (`restore` does not overwrite your current host inventory). If the source vault used a master password, pass `--source-unlock prompt` and omit `--source-key-file`.
- If a cross-store restore is interrupted, resume it with the same source flags:

```bash
xops credential store resume file --from /backup/work/credentials \
  --source-unlock key-file --source-key-file /backup/work/credentials.key
```

If an existing store's original key is lost and no backup exists, a newly generated key cannot decrypt the old vault—preserve the original directory, or re-enter your credentials if the unlock material cannot be recovered. See the [store command reference](../reference/commands/xops-credential-store) for all flags and `clone` usage.
