# Credential storage

Schema v2 stores `CredentialRef` references in configuration instead of plaintext passwords. New installations use `none`, keeping entered passwords within the current session.

| Backend | Intended environment | Requirements |
| --- | --- | --- |
| `none` | Temporary interactive sessions | No secret persistence |
| `system` | Desktop operating systems | Accessible, unlocked OS credential store |
| `pass` | Linux administration | pass, GPG, and an initialized password store |
| `helper` | External credential systems | An implementation of the XOps helper protocol |
| `encrypted-file` | Explicit offline storage | 64-bit Linux, Windows, and macOS with separate unlock and recovery procedures |

See [xops_config.example.yaml](https://github.com/wentf9/xops-cli/blob/master/xops_config.example.yaml). Configure and check a backend before making it the default:

```bash
xops credential store list
xops credential doctor
```

An unavailable configured reference fails rather than silently falling back to another secret. Non-interactive paths such as MCP and batch execution do not silently display unlock prompts.

## Linux system backend

Requires `secret-tool` (`libsecret-tools` on Ubuntu/Debian), a user D-Bus session, and Secret Service. Doctor does not auto-start the service or unlock the store. Start your desktop keyring service before retrying if it is inactive.

## Offline storage

The offline store requires explicit initialization, unlocking, and recovery operations. Its v1 format/API is frozen, which does not mean a stable release has been published. Read the [existing offline store manual (Chinese)](https://github.com/wentf9/xops-cli/blob/master/docs/development/archive/offline-encrypted-credentials.md) first. Keep recovery material separate from store-file backups.

Doctor performs bounded non-interactive read checks, not write authorization checks. Offline metadata inspection does not imply an unlocked or fully verified store.

### Automatic or manual key files

With `unlock: key-file` and `key_file` configured, run `xops credential store init <storeID>`. A missing file is generated as 32 random bytes with mode 0600; an existing valid file is reused. Operations preparing new wrapping material, including rewrap, clone, and restore, support the same behavior. The parent directory must exist. Initialization and cross-vault operations require the key file outside the destination vault directory.

You can also create the file manually before initialization. In Bash:

```bash
(umask 077; set -C; openssl rand 32 > ~/.xops/offline.key)
```

Existing files must pass length, permission, ownership, and non-link checks. Invalid files are never repaired or overwritten automatically. Reads, unlock, doctor, and resume do not generate replacement keys: restore the original from backup if lost. A generated key survives later operation failures and is reused on retry. Back it up separately.

Run `xops credential store probe <storeID>` before initialization to check filesystem operations. See the [compatibility matrix](../development/compatibility).
