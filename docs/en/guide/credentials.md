# Credential storage

::: info Implementation in progress (unreleased)
Default offline configuration and automatic v1 upgrades are implemented in the working branch. SSH authentication recovery is now implemented; TUI authentication and automatic saving are integrated; general v2 backend migration is implemented; final native validation remains pending. See [implementation progress](../development/credential-experience-plan).
:::

Schema v2 stores `CredentialRef` references in configuration instead of plaintext passwords. New installations use store `file` (`encrypted-file`, `unlock: key-file`) with `remember_prompted: always`. Paths `credentials/` and `credentials.key` are relative to the configuration file. Use `--remember never` for one invocation or `remember_prompted: never` globally to disable saving and automatic upgrades. Existing explicit backend choices remain unchanged.

| Backend | Intended environment | Requirements |
| --- | --- | --- |
| `none` | Temporary interactive sessions | No secret persistence |
| `system` | Desktop operating systems | Accessible, unlocked OS credential store |
| `pass` | Linux administration | pass, GPG, and an initialized password store |
| `helper` | External credential systems | An implementation of the XOps helper protocol |
| `encrypted-file` | Default offline storage | 64-bit Linux, Windows, and macOS with separate unlock and recovery procedures |

See [xops_config.example.yaml](https://github.com/wentf9/xops-cli/blob/master/xops_config.example.yaml). Configure and check a backend before making it the default:

```bash
xops credential store list
xops credential doctor
```

Interactive CLI paths may report an unreadable reference and request temporary input without switching backends or overwriting the unreadable record. Non-interactive paths such as MCP and batch execution return errors without unlock prompts.

## Linux system backend

Requires `secret-tool` (`libsecret-tools` on Ubuntu/Debian), a user D-Bus session, and Secret Service. Doctor does not auto-start the service or unlock the store. Start your desktop keyring service before retrying if it is inactive.

## Offline storage

Key-file stores initialize on first write. Reads, doctor, and dry-run do not initialize. Lost keys and interrupted transactions require recovery, never replacement keys. Prompt-based stores retain explicit initialization and unlocking. Its v1 format/API is frozen, which does not mean a stable release has been published. Read the [existing offline store manual (Chinese)](https://github.com/wentf9/xops-cli/blob/master/docs/development/archive/offline-encrypted-credentials.md) first. Keep recovery material separate from store-file backups.

Doctor performs bounded non-interactive read checks, not write authorization checks. Offline metadata inspection does not imply an unlocked or fully verified store.

### Automatic or manual key files

With `unlock: key-file` and `key_file` configured, run `xops credential store init <storeID>`. A missing file is generated as 32 random bytes with mode 0600; an existing valid file is reused. Operations preparing new wrapping material, including rewrap, clone, and restore, support the same behavior. The parent directory must exist. Initialization and cross-vault operations require the key file outside the destination vault directory.

You can also create the file manually before initialization. In Bash:

```bash
(umask 077; set -C; openssl rand 32 > ~/.xops/offline.key)
```

Existing files must pass length, permission, ownership, and non-link checks. Invalid files are never repaired or overwritten automatically. Reads, unlock, doctor, and resume do not generate replacement keys: restore the original from backup if lost. A generated key survives later operation failures and is reused on retry. Back it up separately.

Run `xops credential store probe <storeID>` before initialization to check filesystem operations. See the [compatibility matrix](../development/compatibility).

## SSH authentication recovery (in progress, unreleased)

Interactive CLI password/auto authentication permits new input after server rejection, with at most three authentication attempts. Retries prompt directly instead of repeatedly reading an invalid stored password. Key/auto decryption retries only incorrect passphrases, at most three times; corrupt key formats do not repeatedly prompt. Passwords reach persistence only after a successful SSH handshake; passphrases must also have actually decrypted the corresponding key.

Missing, locked, unavailable, or inaccessible stored credentials allow temporary interactive input. Snapshot mismatches, cancellation, and timeouts do not enter this recovery path. Calls without interaction capability return errors.

If saving fails after SSH authentication, a notice is displayed and the connection remains usable. Authentication and privilege writeback tokens are disabled for that connection so uncertain configuration versions cannot authorize later overwrites. Unreadable existing records are not overwritten. Incompatible network target changes still prevent connection publication.

SSH and privilege authentication are verified independently. Successful SSH authentication does not prove successful privilege escalation; TUI behavior is described in the [TUI guide](./tui), with remaining platform gates in the implementation plan.

## Privilege credentials (unreleased)

Commands, scripts, and streaming IO distinguish successful sudo/su authentication from the user command's exit code. A verified password may be saved even when the command fails; the command's error still returns to the caller. Interactive password retries are limited to three attempts, and a command that might have started is not automatically repeated.

Passwords and command input are sent in separate phases. Passwordless/cached interactive sudo does not request or inject a password into stdin. Incorrect passwords are not saved. Sudo updates do not overwrite login records or reuse legacy SuPwd.

Interactive PTY shell/exec use the same bounded authentication retries. Password entry happens before local raw mode; keyboard input is forwarded only after remote echo is restored. The stdin reader and resize worker stop before terminal mode restoration. The remote handoff uses Bash and stty. See [implementation progress](../development/credential-experience-plan) for the remaining acceptance gates.

Corrupt offline data also permits temporary interactive input. The original error is retained, and damaged material and keys are not automatically replaced. If SSH, interactive exec, or single-target SCP cannot initialize persistence (for example, an unwritable journal directory), they report it, disable all automatic recording for that connection, and continue connecting. Non-interactive initialization still fails closed. A per-command or global never policy neither initializes persistence nor displays a saving-failure notice.
