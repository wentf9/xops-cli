# SSH and privilege escalation

Use `xops ssh` to open interactive shell sessions, run one-off remote commands, or set up port-forwarding tunnels.

```bash
# Connect via node alias
xops ssh web-01

# Connect with an explicit private key and username
xops ssh -i ~/.ssh/id_ed25519 deploy@192.0.2.10

# Connect through a jump host (ProxyJump)
xops ssh -J bastion.example.com deploy@192.0.2.10
```

Direct jump hosts accept an IP, FQDN, or `host:port`; a single-label jump name (such as `-J jumphost`) must already exist as a saved node or alias. Connecting to the same host as a different user keeps credentials isolated per user.

## Running remote commands and piped scripts

In addition to interactive logins, `xops ssh` can execute a single command or stream a local script over stdin:

```bash
# Run a remote command natively (defaults to server passthrough mode)
xops ssh web-01 uptime
xops ssh --host web-01 --interpreter server uname -a

# Run with an explicit interpreter and login mode (explicit execution flags on xops ssh currently require a Linux client)
xops ssh --host linux-01 --interpreter bash --launch-dialect posix --login-shell=false id
```

- **Interpreter selection**: Supports `--interpreter server` (default native passthrough), `bash`, `sh`, `zsh`, `fish`, `powershell`, `pwsh`, and `cmd` (note: CLI explicit execution flags on `xops ssh` rely on cancelable native output handles and are currently available on Linux clients; on Windows/macOS clients, configure [`execution` on the node](./hosts#node-execution-configuration-execution) or use `xops exec`).
- **Login environment**: `bash`, `zsh`, and `fish` support `--login-shell`; `--no-login` remains a Bash compatibility flag (non-login `bash -c`); `server` mode rejects login flags.
- **Input and shell routing**:
  - **Terminal with no command**: Opens an interactive PTY login shell.
  - **Piped stdin with no command (e.g. `cat script.sh | xops ssh web-01`)**: Routes according to the target node's execution config—if `server` (default), opens a non-PTY SSH shell session streaming stdin and preserving the remote exit code; if configured for `bash`, `sh`, `zsh`, or `fish`, launches that interpreter to read the script from stdin while honoring the node's login setting.
  - **Empty-command guard**: Passing an explicit empty command (e.g. `xops ssh web-01 ""`) fails immediately instead of opening an interactive shell.
- **Cancellation safety**: Pressing `Ctrl+C` or hitting a timeout cleanly terminates the SSH session and releases local terminal, pipe, and file handles.

## Automatic node saving on first connection

When `ssh`, `sftp`, `scp`, or `exec` connects to a new host for the first time, XOps prepares the node in memory and **saves the node, host, and identity only after the SSH handshake and authentication succeed**:
- Timeouts, refused connections, authentication failures, or cancellations before authentication leave no stale entries behind.
- Saving occurs before opening a shell or running a command, so a subsequent command failure does not delete an authenticated node (nor do connection failures remove existing saved nodes).
- `--remember never` only prevents saving password/passphrase secrets; authenticated node address details are still saved.

For example, if `xops ssh root@192.0.2.10` fails on default port 22, no `:22` node is created. If `xops ssh root@192.0.2.10:2222` then authenticates, only the `:2222` node is saved, and future commands that omit the port will match it automatically (if multiple ports are saved for the same host, specify the port or use a unique alias).

If saving the node fails, XOps reports the error and closes the connection before handing it to the caller; if the configuration file was replaced on disk but syncing its parent directory failed, the applied configuration is retained without rollback.

## Sudo / Su privilege escalation

```bash
# Open an elevated interactive shell
xops ssh --sudo web-01

# Run a single command with a PTY and privilege escalation
xops exec -x --sudo web-01 id
```

The node's `sudo_mode` controls how privileges are escalated (`auto`, `root`, passwordless `sudoer`, password `sudo`, or `su`):
- **Servers that disallow direct root SSH login**: Use `su` mode to log in over SSH as an ordinary user and switch to `root` inside the session without enabling `PermitRootLogin`.
- **Traditional `sudo` and `sudo-rs` compatibility**: Automated authentication strips remote password prompts and `sudo-rs` asterisk echoes (matching PAM `Password:` prompts with or without trailing spaces). If credentials are missing or rejected, XOps prompts securely. `exec -x --sudo` prints only the command output without extra root shell prompts.
- **Multi-shell escalation (`bash` / `sh` / `zsh` / `fish`)**:
  - Nodes configured with `launch_dialect: fish` + `interpreter: fish` (or `bash`/`sh`/`zsh`), or `launch_dialect: posix` + `interpreter: zsh`, support `xops ssh --sudo`, `xops exec --sudo`, and Playbook `sudo: true`.
  - The authentication handshake runs in a fixed `/bin/sh` control shell (`su` passes `-s /bin/sh`; see the [su manual](https://man7.org/linux/man-pages/man1/su.1.html)) before launching the target interpreter, keeping passwords, handshake tokens, and user `stdin` strictly separated.
  - CLI explicit `--interpreter` flags cannot currently be combined with `--sudo`; configure `execution` on the node or Playbook instead.

## Port forwarding and tunnels

```bash
# Local forward (-L): forward local 127.0.0.1:8080 to 127.0.0.1:80 from the remote server's perspective
xops ssh -L 8080:127.0.0.1:80 -N web-01

# Dynamic SOCKS5 proxy (-D): open a SOCKS5 proxy on local 127.0.0.1:1080
xops ssh -D 1080 -N web-01

# Remote forward (-R): forward remote 127.0.0.1:9000 to local 127.0.0.1:3000
xops ssh -R 9000:127.0.0.1:3000 -N web-01
```

- **Binding and verification timing**: `-L` and `-D` open SSH channels on demand when local connections arrive; `-R` requests remote listening immediately at startup (with independent 10-second setup and teardown deadlines) and exits with an error if the server refuses.
- **Per-connection error isolation**: Individual forwarding errors (such as `administratively prohibited` or an unreachable target port) are printed to `stderr` without tearing down the main SSH session or listener.
- **Keepalive and disconnect handling**: Sessions with `-L`, `-R`, `-D`, or `-N` actively monitor the connection—sending an SSH heartbeat after 15 seconds of idle traffic and declaring a timeout only after 10 consecutive seconds with neither a reply nor data progress. When the connection drops, XOps closes local listeners and exits with a nonzero status. Combine `-f -N` to run tunnels in the background.
