# SSH and privilege escalation

```bash
xops ssh web-01
xops ssh -i ~/.ssh/id_ed25519 deploy@192.0.2.10
xops ssh -J bastion.example.com deploy@192.0.2.10
```

A single-label jump host must already exist as a node or alias. Explicit users on the same host keep separate credentials.

## Command execution and interpreters

`xops ssh` supports executing remote commands (via positional arguments or following `--host`) with explicit interpreter and login controls:

```bash
xops ssh web-01 uptime
xops ssh --host web-01 --interpreter server uname -a
xops ssh --host linux-01 --interpreter bash --launch-dialect posix --login-shell=false id
```

- **Explicit interpreters**: Supports `--interpreter server` (unchanged SSH exec payload) and `--interpreter bash` (Bash payload wrapped under the known POSIX launch dialect).
- **Login controls**: Supports `--login-shell` and `--no-login` (mutually exclusive); `--interpreter server` rejects login options.
- **Input and shell routing**:
  - When no command is specified and stdin is a terminal, starts a full interactive PTY login shell.
  - When no command is specified and stdin is piped, starts a native non-PTY SSH shell executing streamed input only if `--interpreter server` is explicitly specified, preserving remote exit status and signals; non-server interpreters or unconfigured interpreters require a non-empty command.
  - Explicit empty commands (e.g. `xops ssh web-01 ""`) are rejected and never converted into interactive shells.
- **Cancelable outputs**: Streaming command execution uses cancelable output bridges across regular files, the null device, and (on Linux) terminals and pipes, cleanly interrupting and joining all goroutines on cancellation. Native cancelable output bridges on other platforms will follow in subsequent phases.

## Automatic node saving

When SSH, SFTP, SCP, or exec first connects to a new node, XOps prepares its connection details in memory. It saves the node, host, and identity only after the SSH handshake and authentication succeed. A timeout, refused connection, authentication failure, or cancellation before authentication creates no saved configuration. Saving another node cannot accidentally publish an unauthenticated pending node.

The save happens before opening a shell, executing a command, or starting a file transfer, so a later operation failure does not remove an authenticated node. Existing nodes remain saved after connection failures. Explicit additions and imports also verify by default and support `--skip-verify`; a failed `host add` asks whether to save, while imports support `--save-on-verify-failure`. `--remember never` only disables automatic saving of password-like secrets; successfully authenticated node details are still saved.

For example, if `xops ssh root@192.0.2.10` tries the default port 22 and fails, it leaves no `:22` node. If `xops ssh root@192.0.2.10:2222` then authenticates successfully, only the `:2222` node is saved, and a later command that omits the port can resolve to it. If multiple ports for the same host are genuinely saved, specify the port or a unique alias. Invalid nodes left by older versions must be removed manually.

If saving the node fails, XOps reports the error and closes the authenticated SSH connection before exposing it to the caller. If the configuration replacement was applied but syncing its directory failed, XOps does not automatically roll it back. Concurrent configuration changes are never overwritten.

## Privilege escalation

```bash
xops ssh --sudo web-01
xops exec -x --sudo web-01 id
```

The node configuration selects the escalation method: root, passwordless sudo, password sudo, su, and other supported modes. Hosts that only permit ordinary-user SSH login can use su with the root password inside that connection. Root SSH login is not required.

`ssh --sudo` opens an elevated interactive shell. `exec -x --sudo` executes an elevated command directly, retaining PTY authentication without an extra root shell prompt or injected command echo. Validate custom su/PAM multi-step authentication and login scripts on the target system.

Password sudo supports both traditional sudo and sudo-rs. When available credentials supply the password automatically, remote password prompts and sudo-rs asterisk feedback are filtered out. The sudo-rs PAM `Password:` prompt is recognized with or without trailing spaces. Missing or rejected credentials still trigger a password prompt. Authentication errors and output from the elevated command remain visible.

## Tunnels

```bash
xops ssh -L 8080:127.0.0.1:80 -N web-01
xops ssh -D 1080 -N web-01
```

Tunnels close when the session ends. See [Troubleshooting](../troubleshooting/) for connection, host key, and credential issues.

Individual forwarding connection failures are printed directly to standard error (stderr), including the forwarding type and original error, regardless of `--log-level`. Failures to connect to a destination also include its address. When the server rejects forwarding, the diagnostic includes the reason, such as `administratively prohibited`. The failed connection closes while the SSH session and forwarding listener keep running.

`-L` and `-D` request an SSH channel only when a client uses the forwarding port, so successfully starting a local listener does not mean the server permits forwarding. `-R` requests the remote listener during startup; if the server denies that request, the command reports an error and exits.

For `-R`, requesting the remote listener has a 10-second limit and respects caller cancellation. Closing the listener has its own 10-second limit. Canceling startup or exceeding either request limit interrupts the SSH connection and its shared ProxyJump transport to unblock operations and release resources. An acknowledged close does not require interrupting the shared connection.

With `-L`, `-R`, `-D`, or `-N`, XOps monitors the SSH connection. A keepalive is sent after 15 seconds without receiving remote data. While awaiting its reply, the probe times out only after 10 consecutive seconds without either a reply or receive progress. Forwarded data arriving over a slow link, including partially received SSH packets, refreshes that timeout so congestion delaying the keepalive reply does not interrupt an active connection. Writes accepted by local send buffers do not refresh it. ProxyJump tracks receive progress separately for each hop.

A lost connection or keepalive timeout closes the forwarding listeners and returns a failure status. Connections are not automatically reestablished; rerun the command after connectivity returns.
