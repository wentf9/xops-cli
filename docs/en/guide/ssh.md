# SSH and privilege escalation

`xops ssh` provides full-featured SSH connectivity and remote session management, integrating node aliases, jump hosts, interpreter adaptations, elevated sessions, and reliable port forwarding tunnels.

```bash
# Connect quickly via node alias
xops ssh web-01

# Connect specifying private key and username
xops ssh -i ~/.ssh/id_ed25519 deploy@192.0.2.10

# Connect through a jump host (bastion)
xops ssh -J bastion.example.com deploy@192.0.2.10
```

A single-label jump host must already exist as a node or alias. Explicit users on the same host keep separate credentials.

## Command execution and interpreter adaptation

`xops ssh` supports running one-off remote commands directly (via positional arguments or following `--host`), with interpreter and login controls:

```bash
# Native remote command execution (default)
xops ssh web-01 uptime
xops ssh --host web-01 --interpreter server uname -a

# Explicit Bash execution with login shell controls
xops ssh --host linux-01 --interpreter bash --launch-dialect posix --login-shell=false id
```

- **Interpreter selection**: Supports `--interpreter server` (native execution, default), `bash`, `sh`, `zsh`, `fish`, `powershell`, `pwsh`, and `cmd`.
- **Login environment controls**: When using the `bash` interpreter, supports `--login-shell` (load login profile) and `--no-login` (do not load login profile); the `server` interpreter forwards commands directly and rejects login options.
- **Input stream and shell routing**:
  - **Interactive shell**: When no command is specified and stdin is a terminal, starts an interactive PTY login shell.
  - **Piped script streaming**: When no command is specified and stdin is piped (e.g. `cat script.sh | xops ssh web-01`), XOps routes automatically according to the target node's execution configuration:
    - If the node is `server` (default), starts a native non-PTY shell streaming the piped input;
    - If the node is configured for `bash` or `sh`, starts the target interpreter reading the input script from stdin, honoring the node's login configuration.
  - Explicit empty commands (e.g. `xops ssh web-01 ""`) are safely rejected and will not inadvertently open an interactive shell.
- **Cancelable output safety**: Command execution streams use cancelable output protection across terminals, pipes, regular files, and the null device. When interrupted by Ctrl+C or upon timeout, XOps cleanly terminates the SSH session and reclaims resources.

## Automatic node saving

When SSH, SFTP, SCP, or exec first connects to a new node, XOps prepares its connection details in memory. It saves the node, host, and identity only after the SSH handshake and authentication succeed. A timeout, refused connection, authentication failure, or cancellation before authentication creates no saved configuration. Saving another node cannot accidentally publish an unauthenticated pending node.

The save happens before opening a shell, executing a command, or starting a file transfer, so a later operation failure does not remove an authenticated node. Existing nodes remain saved after connection failures. Explicit additions and imports also verify by default and support `--skip-verify`; a failed `host add` asks whether to save, while imports support `--save-on-verify-failure`. `--remember never` only disables automatic saving of password-like secrets; successfully authenticated node details are still saved.

For example, if `xops ssh root@192.0.2.10` tries the default port 22 and fails, it leaves no `:22` node. If `xops ssh root@192.0.2.10:2222` then authenticates successfully, only the `:2222` node is saved, and a later command that omits the port can resolve to it. If multiple ports for the same host are genuinely saved, specify the port or a unique alias. Invalid nodes left by older versions must be removed manually.

If saving the node fails, XOps reports the error and closes the authenticated SSH connection before exposing it to the caller. If the configuration replacement was applied but syncing its directory failed, XOps does not automatically roll it back. Concurrent configuration changes are never overwritten.

## Privilege escalation

```bash
# Open an elevated interactive shell
xops ssh --sudo web-01

# Execute a command elevated directly
xops exec -x --sudo web-01 id
```

The node configuration selects the escalation method: root, passwordless sudo, password sudo, su, and other supported modes. Hosts that only permit ordinary-user SSH login can use su with the root password inside that connection. Root SSH login is not required.

`ssh --sudo` opens an elevated interactive shell. `exec -x --sudo` executes an elevated command directly, retaining PTY authentication without an extra root shell prompt or injected command echo. Validate custom su/PAM multi-step authentication and login scripts on the target system.

Password sudo supports both traditional sudo and sudo-rs. When available credentials supply the password automatically, remote password prompts and sudo-rs asterisk feedback are filtered out. The sudo-rs PAM `Password:` prompt is recognized with or without trailing spaces. Missing or rejected credentials still trigger a password prompt. Authentication errors and output from the elevated command remain visible.

Fish nodes support the same elevation modes. Save `launch_dialect: fish` in the node execution settings and select `interpreter: fish` (or bash/sh/zsh), then use `xops exec --host fish-01 --sudo -c 'id'`, `xops exec -x --host fish-01 --sudo -c 'id'`, or `xops ssh fish-01 --sudo`. Elevated Playbook fish scripts are also supported. A fixed `/bin/sh` handles authentication before starting the selected interpreter, keeping passwords, acknowledgements and user stdin separate. The fish path avoids `sudo -i` command concatenation; login mode belongs to the selected interpreter. For su, the target must support `-s /bin/sh` to pin the control shell ([su manual](https://man7.org/linux/man-pages/man1/su.1.html)). CLI explicit `--interpreter` flags still cannot be combined with `--sudo`; use node or Playbook execution settings.

For zsh, set `interpreter: zsh` and `launch_dialect: posix`. The same `--sudo` commands and Playbook elevation settings apply. Zsh shares the POSIX authentication protocol and supports sudo and su; its commands and scripts retain zsh semantics. Login mode selects `zsh -l`; su pins the control shell with `-s /bin/sh`.

## Port forwarding and tunnels

```bash
# Local port forwarding: forward local 8080 to 127.0.0.1:80 on remote server
xops ssh -L 8080:127.0.0.1:80 -N web-01

# Dynamic SOCKS5 proxy: open a SOCKS5 proxy on local port 1080
xops ssh -D 1080 -N web-01

# Remote port forwarding: forward remote port 9000 to local 127.0.0.1:3000
xops ssh -R 9000:127.0.0.1:3000 -N web-01
```

- **Lifecycle**: Tunnels close automatically when the session terminates. On connection drops or heartbeat timeouts, XOps closes local listeners and exits with a failure status.
- **Error diagnostics and isolation**: Forwarding failures are reported to stderr with the forwarding type and error details. If the server denies forwarding (e.g. `administratively prohibited`), the failed channel is closed while the primary session and listeners remain active.
- **Deferred binding and immediate verification**:
  - `-L` and `-D` request SSH channels only when local ports receive incoming connections;
  - `-R` requests remote listening immediately at startup, failing fast if the remote server rejects the request.
- **Bounded timeouts**: Remote listener establishment and shutdown have independent 10-second deadlines, safely freeing local and connection resources upon timeout or cancellation.
- **Keepalive and heartbeat monitoring**: Connections with `-L`, `-R`, `-D`, or `-N` are actively monitored. A heartbeat is sent if no remote data is received for 15 seconds; timeout is triggered only after 10 consecutive seconds without replies or data progress. Ongoing throughput resets timers automatically to avoid false timeouts under load.
