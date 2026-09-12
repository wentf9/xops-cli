# Troubleshooting

## Passwords are not saved

Run `xops credential doctor` and check access permissions for the configuration directory, credential-store directory, and key file. Passing doctor checks establishes read access, not write permissions.

With `--remember never` or `credential.remember_prompted: never`, entered passwords are used only for the current connection. If automatic saving fails, an authenticated interactive connection remains usable. Fix the problem and reconnect to save the credentials.

## System keyring unavailable or locked

On Linux, the `system` backend requires `secret-tool`, a user D-Bus session, and Secret Service. Install `libsecret-tools` on Ubuntu/Debian if the tool is missing. Start and unlock your desktop keyring, then run `xops credential doctor`.

SSH sessions, scheduled jobs, or sessions belonging to another user may not have access to the desktop keyring. Unattended jobs can use the default key-file offline store. Follow the [migration guide](../guide/migration) to move existing credentials.

## Lost offline key or interrupted maintenance

Do not generate a new key over the old file. Existing stores require their original unlock material; recover the key from backup. After interrupted maintenance, preserve the store and related files. Follow the [offline storage guide](../guide/offline-store) to resume the operation or restore from backup.

## Host fingerprint prompt cannot be submitted

Run the command in an interactive terminal. Text prompts display input, accept Enter, and support Backspace. Hidden password input is expected. Enter `yes` after verifying the fingerprint, or `no` to reject it.

If submission still fails on Windows, update XOps and retry, recording the terminal type. `context canceled` means the operation was canceled. If you did not cancel it, retain the full sanitized error for troubleshooting.

## Unexpected input after an SFTP command

Wait for the remote command to finish and the SFTP prompt to return before entering another command. On Windows, update XOps and retry if the first character disappears or you see `read stdin failed: EOF`. If it persists, record your OS, terminal, XOps version, and reproduction steps.

A lost connection makes the SFTP shell exit with a failure status. Once networking is restored, reconnect with `xops sftp <node>`.

## Extra output from exec -x

`exec -x` returns to the local terminal when the command finishes. Output from the command and remote login startup scripts remains visible. Check remote Bash startup files for login banners or custom output. Use `xops ssh` for a complete interactive shell.

## Old Linux kernel: identify vault mount / function not implemented

Update XOps first. Some older kernels do not support its preferred mount-information query, so XOps attempts to read `/proc/self/fdinfo`. In containers or restricted environments, make sure procfs is accessible and supplies `mnt_id` information.

Run `xops credential store probe file` to check filesystem operations for the target directory. If it still fails, provide the kernel version, filesystem type, and mount configuration. Do not delete the credential store or key as a troubleshooting step.

## Ambiguous node or configuration conflict

If an address or alias matches several nodes, run `xops host list` and use an exact node ID. After a configuration conflict, reload the latest configuration and review changes made in other terminals before editing again.

## Report a problem

Include the command structure, XOps version, OS and terminal, expected behavior, and sanitized errors. Do not share passwords, private keys, unlock material, or full production configuration. Report problems through [GitHub Issues](https://github.com/wentf9/xops-cli/issues).
