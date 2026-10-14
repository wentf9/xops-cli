# Credential storage

XOps stores login passwords, private-key passphrases, and `sudo`/`su` privilege passwords in dedicated credential stores. Your configuration file (`~/.xops/xops_config.yaml`) keeps only references to those items—never plaintext secrets or legacy `ENC:` fields.

New installations use the built-in offline encrypted store (`encrypted-file`) out of the box, without requiring a desktop keyring or external tools. Run `xops credential --help` to see all available subcommands.

## Default saving behavior

The first time a credential is saved, XOps automatically creates the `credentials/` directory and the `credentials.key` key file beside your configuration file (`~/.xops/` by default).
- **Verified before saving**: Login passwords are saved only after SSH authentication succeeds; private-key passphrases are saved only after they successfully unlock the key.
- **Saving policy**: `credential.remember_prompted` controls whether prompted secrets are saved automatically:

| Value | Behavior |
| --- | --- |
| `always` (default) | Save automatically after successful verification |
| `ask` | Ask whether to save after verification |
| `never` | Use for the current connection only; do not auto-save |

Override the policy for a single command without changing your global configuration:

```bash
xops ssh --remember never web-01
xops tui --remember ask
```

`never` only disables automatic saving during connections; explicit credential-form submissions and migration commands still work as usual. Schema v1 compatibility has ended—if you have a legacy configuration file, convert it first using the [migration guide](./migration).

## Choose and inspect a store

| Backend type | Purpose | Requirements |
| --- | --- | --- |
| `encrypted-file` | Built-in offline encrypted vault (default) | Linux, Windows, or macOS (amd64 / arm64) |
| `system` | OS native credential store / keyring | Accessible, unlocked system credential store |
| `pass` | Existing `pass` password store | `pass`, `gpg`, and an initialized password store |
| `helper` | Custom external credential service | External executable implementing the XOps credential protocol |
| `none` | Ephemeral interactive sessions | No credential persistence |

In the default setup, `file` is the store instance name and `encrypted-file` is its backend type (relative paths are resolved relative to the configuration file's directory):

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
```

See [`xops_config.example.yaml`](https://github.com/wentf9/xops-cli/blob/master/xops_config.example.yaml) for examples of other backends. List configured stores and check their status with:

```bash
xops credential store list
xops credential doctor
```

- **How `credential doctor` works**: `doctor` performs non-interactive read checks only—it does not initialize stores, open unlock prompts, or test write permissions. For an uninitialized default offline store that has no credential references yet and neither vault nor key file on disk, `doctor` reports `WARN (not initialized)` and exits cleanly without creating files. Missing stores that are already referenced by your config, partially initialized vaults, or unsafe file paths still report `FAIL`.
- **Switching stores**: Changing `default_store` alone does not move existing credentials; follow the [migration guide](./migration) to migrate between backends.

### Linux system keyring (`system`)

On Linux, the `system` backend requires `secret-tool` (`libsecret-tools` on Ubuntu/Debian), an active user D-Bus session, and Secret Service.
- Batch jobs (`exec`, `play`) and MCP never open desktop unlock dialogs; a locked keyring returns `locked` and must be unlocked in your desktop session first.
- When interactively deleting a node/identity or running `xops credential gc`, XOps requests an unlock for matching keyring items before deleting them. If you cancel the unlock, unlock only some of the keyrings where items reside, or the tool reports item errors on stderr (even with exit code 0, excluding normal `attribute.*` metadata), XOps retains the recovery journal so you can unlock the remaining keyrings and re-run `xops credential gc`.

## Authentication retries and temporary input

- **Password and passphrase retries**: Interactive connections allow up to 3 attempts when a server rejects a password or a key passphrase is wrong (if the private-key file itself is corrupted, repair or replace the file first).
- **Temporary input when a store is unavailable**: If a credential store is locked, unavailable, corrupted, or a record cannot be read, interactive commands can prompt for temporary input to complete the connection. XOps **never** overwrites unreadable records with temporary input or replaces a damaged vault or lost key. Non-interactive runs (MCP and batch execution) fail immediately until store access is restored.
- **Connections stay open on save failure**: If automatic saving fails after SSH authentication succeeds, the current session stays connected. Check the reported permission or configuration issue so you do not have to re-enter the password on future connections.

## Privilege passwords (`sudo` / `su`)

SSH login and `sudo`/`su` escalation are verified and stored separately:
- Passwordless `sudo` and valid cached `sudo` sessions do not ask for a password.
- Once a privilege password passes the escalation handshake, it can be saved according to policy even if the user command itself exits with a nonzero status (the command still reports failure).
- Privilege passwords allow up to 3 attempts. Once a user command may have started running, XOps never re-runs the command just to retry authentication. Interactive escalation requires a supported remote shell and `stty`.

## Backup and recovery

Always back up all three items together: **your configuration file**, **the entire credential-store directory**, and **its unlock key file** (keep key backups separate from vault backups). Backing up the configuration file alone cannot recover passwords. Reading, inspecting, or unlocking never generates a replacement key for an existing store—if the key is lost, you must restore the original key backup.

See [offline credential storage](./offline-store) for master-password vaults, key rotation, and restore commands.

## Removed plaintext flags

To keep secrets out of process listings and shell history, `--password`, `--passphrase`, `--suPwd`, and the firewall `--password/-w` flags have been removed:
- **SSH / SFTP / SCP / exec**: Use interactive prompts, saved credentials, or pipe secrets via `--password-stdin` / `--passphrase-stdin`.
- **Host and identity commands (`host` / `identity`)**: Use `--password-stdin`, `--passphrase-stdin`, or `xops identity credential set`; see [host and identity management](./hosts#removed-credential-arguments).
- **Flag boundaries**: `ssh` and `exec` reject unknown flags placed before the remote command; arguments after the remote command name or an explicit `--` separator are passed through unchanged.
