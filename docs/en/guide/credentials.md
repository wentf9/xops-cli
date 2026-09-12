# Credential storage

XOps keeps login passwords, private-key passphrases, and privilege passwords in credential stores. Configuration files contain references to those credentials. New installations use the built-in offline encrypted store without requiring a system keyring or external tools.

This page describes the current source. Check `xops credential --help` for options available in your installed version.

## Default saving behavior

On first save, XOps creates `credentials/` and the key file `credentials.key` beside the configuration file, under `~/.xops/` with the default configuration. Passwords are saved automatically only after successful authentication. Private-key passphrases must also successfully unlock their key.

`credential.remember_prompted` controls whether prompted credentials are saved:

| Value | Behavior |
| --- | --- |
| `always` (default) | Save after successful authentication |
| `ask` | Ask whether to save after authentication |
| `never` | Use for the current connection without automatic saving |

Override the policy for a single invocation without changing your configuration:

```bash
xops ssh --remember never web-01
xops tui --remember ask
```

`never` also disables automatic legacy upgrades. It does not block explicit credential-form submissions or migration commands. Explicit storage and saving policies in existing configurations are preserved.

## Choose a store

| Backend type | Purpose | Requirements |
| --- | --- | --- |
| `encrypted-file` | Built-in offline encryption, the default | Linux, Windows, or macOS on amd64/arm64 |
| `system` | Operating system credential store | An accessible, unlocked system store |
| `pass` | An existing pass password store | pass, GPG, and an initialized store |
| `helper` | An external credential service | An external program supporting the XOps credential protocol |
| `none` | Temporary interactive sessions | No credential persistence |

In the default configuration, `file` is the store name and `encrypted-file` is its backend type:

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

Relative paths resolve beside the configuration file. See the [configuration example](https://github.com/wentf9/xops-cli/blob/master/xops_config.example.yaml) for other backends. Check configured stores with:

```bash
xops credential store list
xops credential doctor
```

`doctor` checks non-interactive reads. It does not initialize offline stores, prompt for unlocking, or establish write permissions. Follow the [migration guide](./migration) to switch stores; changing `default_store` alone does not move existing credentials.

### Linux system keyring

The `system` backend requires `secret-tool` (`libsecret-tools` on Ubuntu/Debian), a user D-Bus session, and Secret Service. Start and unlock the desktop keyring before running XOps. Ordinary `exec` can read unlocked credentials without `-x`. Batch execution and MCP never open unlock dialogs.

## Authentication failures and temporary input

Interactive connections allow new input after a rejected password, with at most three attempts. Incorrect private-key passphrases also allow up to three attempts. Repair or replace a damaged private-key file before retrying.

If a credential store is locked, unavailable, damaged, or cannot read a record, an interactive connection can request temporary input. XOps does not overwrite unreadable records with that input or automatically replace damaged stores or lost keys. Non-interactive operations, including MCP and batch execution, return an error until credential access is restored.

If automatic saving fails after SSH authentication, the connection remains usable. Check the reported configuration or directory-permission problem. You may need to enter the credentials again next time.

## Privilege passwords

SSH login and sudo/su authentication are verified separately. Successful login does not establish successful escalation. Sudo passwords are stored separately from login passwords. Passwordless sudo and sudo with a valid authorization cache do not request a password.

A verified privilege password can be saved according to policy even if the command itself fails; the command still reports failure. Password retries are limited to three attempts. Commands that may already have started are not automatically repeated to retry authentication. Interactive escalation requires Bash and `stty` on the remote host.

## Backup and recovery

Back up the configuration file, the entire credential-store directory, and the corresponding unlock material. Keep key backups separate from store backups. Configuration alone cannot restore passwords. Reading, inspecting, and unlocking never create replacement keys; a lost key for an existing store requires the original key backup.

See [offline credential storage](./offline-store) for initialization, master passwords, key rotation, and recovery.
